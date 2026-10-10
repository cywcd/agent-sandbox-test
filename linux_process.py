#!/usr/bin/env python3
"""Small generic native Linux launcher: Landlock + seccomp, no network."""
import argparse
import ctypes
import errno
import os
import pathlib
import sys

libc = ctypes.CDLL(None, use_errno=True)
READ = (1 << 0) | (1 << 2) | (1 << 3)
FS = (1 << 15) - 1


class Ruleset(ctypes.Structure):
    _fields_ = [("fs", ctypes.c_uint64), ("net", ctypes.c_uint64), ("scoped", ctypes.c_uint64)]


class Beneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("access", ctypes.c_uint64), ("fd", ctypes.c_int32)]


class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class Program(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint16), ("filters", ctypes.POINTER(Filter))]


def checked(result, label):
    if result < 0:
        raise OSError(ctypes.get_errno(), label)
    return result


def rule(ruleset, path, access):
    fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    try:
        item = Beneath(access, fd)
        checked(libc.syscall(445, ruleset, 1, ctypes.byref(item), 0), "landlock_add_rule")
    finally:
        os.close(fd)


def restrict(workspace, read_roots):
    machine = os.uname().machine
    if machine not in ("x86_64", "aarch64"):
        raise RuntimeError("Unsupported native architecture")
    abi = checked(libc.syscall(444, None, 0, 1), "landlock ABI")
    if abi < 6:
        raise RuntimeError("Landlock ABI 6+ required for process signal isolation")
    # Scope both outgoing signals and abstract UNIX socket connections.
    attr = Ruleset(FS, 3, 3)
    ruleset = checked(libc.syscall(444, ctypes.byref(attr), ctypes.sizeof(attr), 0), "landlock_create_ruleset")
    try:
        for path in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc/ld.so.cache", "/etc/alternatives", *read_roots]:
            if os.path.exists(path):
                resolved = str(pathlib.Path(path).resolve(strict=True))
                rights = READ if os.path.isdir(resolved) else (1 << 0) | (1 << 2)
                rule(ruleset, resolved, rights)
        rule(ruleset, workspace, FS)
        for path in ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"]:
            if os.path.exists(path):
                rule(ruleset, path, (1 << 1) | (1 << 2))
        checked(libc.prctl(38, 1, 0, 0, 0), "no_new_privs")
        checked(libc.syscall(446, ruleset, 0), "landlock_restrict_self")
    finally:
        os.close(ruleset)
    # Reject non-native ABIs, network sockets, privilege/namespace escapes,
    # process-group escape and alternate asynchronous syscall paths.
    arch = 0xC000003E if machine == "x86_64" else 0xC00000B7
    denied = ([41, 101, 165, 166, 272, 308, 310, 311, 321, 298, 250, 304, 425, 438, 112, 109]
              if machine == "x86_64" else [198, 117, 40, 39, 97, 268, 270, 271, 280, 241, 219, 265, 425, 438, 157, 154])
    instructions = [Filter(0x20, 0, 0, 4), Filter(0x15, 1, 0, arch), Filter(0x06, 0, 0, 0x80000000), Filter(0x20, 0, 0, 0)]
    if machine == "x86_64":
        instructions.extend([Filter(0x35, 0, 1, 0x40000000), Filter(0x06, 0, 0, 0x80000000)])
    for number in denied:
        instructions.extend([Filter(0x15, 0, 1, number), Filter(0x06, 0, 0, 0x00050000 | errno.EPERM)])
    instructions.append(Filter(0x06, 0, 0, 0x7FFF0000))
    array = (Filter * len(instructions))(*instructions)
    program = Program(len(instructions), array)
    checked(libc.prctl(22, 2, ctypes.byref(program), 0, 0), "seccomp filter")
    return abi


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--read-only", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or not os.path.isabs(command[0]):
        raise RuntimeError("Absolute executable required")
    workspace = str(pathlib.Path(args.workspace).resolve(strict=True))
    if workspace == "/" or not os.path.isdir(workspace):
        raise RuntimeError("A bounded workspace directory is required")
    # Own process group: descendants cannot escape it after seccomp installation.
    if os.getpgrp() != os.getpid():
        os.setsid()
    cache = pathlib.Path(workspace) / ".native-cache"
    temp = cache / "tmp"
    # Never follow project-controlled cache symlinks before confinement.
    workspace_fd = os.open(workspace, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        try:
            os.mkdir(".native-cache", mode=0o700, dir_fd=workspace_fd)
        except FileExistsError:
            pass
        cache_fd = os.open(".native-cache", os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=workspace_fd)
        try:
            try:
                os.mkdir("tmp", mode=0o700, dir_fd=cache_fd)
            except FileExistsError:
                pass
            temp_fd = os.open("tmp", os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=cache_fd)
            os.close(temp_fd)
        finally:
            os.close(cache_fd)
    finally:
        os.close(workspace_fd)
    env = {key: value for key, value in os.environ.items() if key in ("PATH", "LANG", "LC_ALL", "JAVA_HOME", "GOROOT")}
    env["PATH"] = str(pathlib.Path(command[0]).parent) + os.pathsep + env.get("PATH", "")
    env.update({"HOME": str(cache), "TMPDIR": str(temp), "CI": "1", "GIT_TERMINAL_PROMPT": "0", "GOCACHE": str(cache / "go"), "GOPATH": str(cache / "go-path"), "CARGO_HOME": str(cache / "cargo"), "PYTHONDONTWRITEBYTECODE": "1"})
    restrict(workspace, args.read_only)
    os.chdir(workspace)
    os.execve(command[0], command, env)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Native isolation unavailable: {error}", file=sys.stderr)
        sys.exit(125)
