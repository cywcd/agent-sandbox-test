#!/usr/bin/env python3
"""Dependency-free Landlock write-boundary probe. Contains no Yss Code source."""
import ctypes
import errno
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


libc = ctypes.CDLL(None, use_errno=True)
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446
PR_SET_NO_NEW_PRIVS = 38
ACCESS_EXECUTE = 1 << 0
ACCESS_WRITE_FILE = 1 << 1
ACCESS_READ_FILE = 1 << 2
ACCESS_READ_DIR = 1 << 3
ACCESS_REMOVE_DIR = 1 << 4
ACCESS_REMOVE_FILE = 1 << 5
ACCESS_MAKE_CHAR = 1 << 6
ACCESS_MAKE_DIR = 1 << 7
ACCESS_MAKE_REG = 1 << 8
ACCESS_MAKE_SOCK = 1 << 9
ACCESS_MAKE_FIFO = 1 << 10
ACCESS_MAKE_BLOCK = 1 << 11
ACCESS_MAKE_SYM = 1 << 12
ACCESS_REFER = 1 << 13
ACCESS_TRUNCATE = 1 << 14
READ = ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR
WRITE = ACCESS_WRITE_FILE | sum(1 << bit for bit in range(4, 13))


class RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class PathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int)]


def syscall(number, *args):
    result = libc.syscall(number, *args)
    if result < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return result


def allow(ruleset, path, access):
    fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    try:
        rule = PathBeneathAttr(access, fd)
        syscall(SYS_LANDLOCK_ADD_RULE, ruleset, 1, ctypes.byref(rule), 0)
    finally:
        os.close(fd)


def denied(operation):
    try:
        operation()
    except PermissionError as error:
        return error.errno in (errno.EACCES, errno.EPERM)
    return False


def main():
    if sys.platform != "linux":
        raise RuntimeError("Linux required")
    if os.uname().machine not in ("x86_64", "aarch64"):
        raise RuntimeError("Landlock syscall numbers need verification for this architecture")
    abi = syscall(SYS_LANDLOCK_CREATE_RULESET, None, 0, 1)
    if abi < 3:
        raise RuntimeError("Landlock ABI 3+ required to deny truncate")
    if len(sys.argv) == 1:
        with tempfile.TemporaryDirectory(prefix="native-probe-") as base:
            result = subprocess.run([sys.executable, __file__, "--child", base], check=False)
            if result.returncode:
                raise RuntimeError(f"Landlock probe failed: exit {result.returncode}")
        return
    if len(sys.argv) != 3 or sys.argv[1] != "--child":
        raise RuntimeError("Invalid probe arguments")
    base = sys.argv[2]
    if True:
        root = pathlib.Path(base)
        workspace = root / "workspace"
        outside = root / "outside"
        workspace.mkdir()
        outside.mkdir()
        (workspace / ".tmp").mkdir()
        rustc = shutil.which("rustc")
        if shutil.which("rustup"):
            located = subprocess.run(["rustup", "which", "rustc"], capture_output=True, text=True, timeout=10)
            if located.returncode == 0:
                rustc = located.stdout.strip()
        outside_file = outside / "protected.txt"
        outside_file.write_text("unchanged", encoding="utf8")
        (workspace / "escape").symlink_to(outside, target_is_directory=True)
        (workspace / "go.mod").write_text("module nativeprobe\n\ngo 1.20\n", encoding="utf8")
        (workspace / "sample_test.go").write_text("package nativeprobe\nimport \"testing\"\nfunc TestProbe(t *testing.T) {}\n", encoding="utf8")
        (workspace / "sample.rs").write_text("fn main() { std::fs::write(\"rust.txt\", \"ok\").unwrap(); }\n", encoding="utf8")
        (workspace / "Sample.java").write_text("class Sample { public static void main(String[] args) throws Exception { java.nio.file.Files.writeString(java.nio.file.Path.of(\"java.txt\"), \"ok\"); } }\n", encoding="utf8")
        handled = READ | WRITE | ACCESS_REFER | ACCESS_TRUNCATE
        rules = RulesetAttr(handled)
        ruleset = syscall(SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(rules), ctypes.sizeof(rules), 0)
        try:
            allow(ruleset, "/", READ)
            allow(ruleset, str(workspace), handled)
            allow(ruleset, "/dev/null", ACCESS_WRITE_FILE)
            if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
            syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0)
        finally:
            os.close(ruleset)
        (workspace / "allowed.txt").write_text("ok", encoding="utf8")
        checks = {
            "outside_create_denied": denied(lambda: (outside / "escape.txt").write_text("bad", encoding="utf8")),
            "outside_truncate_denied": denied(lambda: outside_file.write_text("bad", encoding="utf8")),
            "symlink_escape_denied": denied(lambda: (workspace / "escape" / "escape.txt").write_text("bad", encoding="utf8")),
        }
        child = subprocess.run([sys.executable, "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('bad')", str(outside / "child.txt")], capture_output=True, text=True)
        checks["child_inherits_denial"] = child.returncode != 0 and not (outside / "child.txt").exists()
        checks["outside_unchanged"] = outside_file.read_text(encoding="utf8") == "unchanged"
        launcher = pathlib.Path(__file__).with_name("linux_process.py")
        confined_code = """import json,pathlib,socket,sys
results = {}
pathlib.Path('confined.txt').write_text('ok')
try:
    pathlib.Path(sys.argv[1]).read_text()
    results['outside_read_denied'] = False
except PermissionError:
    results['outside_read_denied'] = True
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    results['udp_socket_denied'] = False
except PermissionError:
    results['udp_socket_denied'] = True
print(json.dumps(results))
sys.exit(0 if all(results.values()) else 1)
"""
        confined = subprocess.run([sys.executable, str(launcher), "--workspace", str(workspace), "--read-only", sys.prefix, "--", str(pathlib.Path(sys.executable).resolve()), "-c", confined_code, str(outside_file)], capture_output=True, text=True, timeout=20)
        checks["native_launcher_read_and_network_boundary"] = confined.returncode == 0 and json.loads(confined.stdout)["outside_read_denied"] and (workspace / "confined.txt").exists()
        if confined.returncode:
            print(confined.stderr, file=sys.stderr)
        fixture = pathlib.Path(__file__).with_name("mcp_write_server.py").resolve()
        server = subprocess.Popen([sys.executable, str(launcher), "--workspace", str(workspace), "--read-only", sys.prefix, "--read-only", str(fixture.parent), "--", str(pathlib.Path(sys.executable).resolve()), str(fixture)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            requests = [
                {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "write_sample", "arguments": {"path": str(workspace / "mcp.txt")}}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "write_sample", "arguments": {"path": str(outside / "mcp.txt")}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "inspect_boundary", "arguments": {"path": str(outside_file)}}},
            ]
            output, _ = server.communicate("".join(json.dumps(request) + "\n" for request in requests), timeout=10)
            responses = {item["id"]: item["result"] for item in map(json.loads, output.splitlines())}
            checks["mcp_handshake"] = responses[0]["serverInfo"]["name"] == "native-write-probe" and responses[1]["tools"][0]["name"] == "write_sample"
            allowed_result = responses[2]
            denied_result = responses[3]
            checks["mcp_workspace_write"] = not allowed_result.get("isError") and (workspace / "mcp.txt").read_text() == "mcp"
            checks["mcp_outside_denied"] = denied_result.get("isError") is True and not (outside / "mcp.txt").exists()
            checks["mcp_read_and_network_denied"] = all(json.loads(responses[4]["content"][0]["text"]).values())
        finally:
            server.kill()
            server.wait(timeout=5)
        env = os.environ.copy()
        env.update({"HOME": str(workspace), "TMPDIR": str(workspace / ".tmp"), "GOCACHE": str(workspace / "go-cache"), "GOPATH": str(workspace / "go-path"), "GOMODCACHE": str(workspace / "go-mod-cache"), "CARGO_HOME": str(workspace / "cargo-home")})
        toolchains = {
            "python": ([sys.executable, "-c", "open('python.txt', 'w').write('ok')"], "python.txt"),
            "node": (["node", "-e", "require('fs').writeFileSync('node.txt','ok')"], "node.txt"),
            "go": (["go", "test", "./..."], None),
            "rust": ([rustc or "rustc", "sample.rs", "-o", "rust-sample"], "rust-sample"),
            "java": (["javac", "Sample.java"], "Sample.class"),
        }
        results = {}
        for name, (command, output) in toolchains.items():
            if not shutil.which(command[0]):
                results[name] = "unavailable"
                continue
            result = subprocess.run(command, cwd=workspace, env=env, capture_output=True, text=True, timeout=90)
            results[name] = "passed" if result.returncode == 0 and (output is None or (workspace / output).exists()) else f"failed:{result.returncode}:{result.stderr[-200:]}"
            if results[name] == "passed" and name in ("rust", "java"):
                runtime = [str(workspace / "rust-sample")] if name == "rust" else ["java", "Sample"]
                executed = subprocess.run(runtime, cwd=workspace, env=env, capture_output=True, text=True, timeout=30)
                results[name] = "passed" if executed.returncode == 0 and (workspace / f"{name}.txt").exists() else f"failed:run:{executed.returncode}:{executed.stderr[-200:]}"
        print(json.dumps({"platform": sys.platform, "machine": os.uname().machine, "landlock_abi": abi, "checks": checks, "toolchains": results}, sort_keys=True))
        if not all(checks.values()):
            raise RuntimeError("Landlock boundary failed")
        if any(value.startswith("failed") for value in results.values()):
            raise RuntimeError("A toolchain failed inside Landlock")


if __name__ == "__main__":
    main()
