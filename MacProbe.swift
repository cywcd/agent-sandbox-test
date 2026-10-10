import Foundation

let manager = FileManager.default
let home = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
let allowed = home.appendingPathComponent("Documents/ycode-native-probe.txt")
let outside = URL(fileURLWithPath: "/tmp/ycode-native-probe-outside-\(ProcessInfo.processInfo.processIdentifier).txt")
try manager.createDirectory(at: allowed.deletingLastPathComponent(), withIntermediateDirectories: true)
try "allowed".write(to: allowed, atomically: true, encoding: .utf8)
var outsideDenied = false
do {
    try "forbidden".write(to: outside, atomically: true, encoding: .utf8)
} catch {
    outsideDenied = true
}
let child = Process()
child.executableURL = URL(fileURLWithPath: "/bin/sh")
child.arguments = ["-c", "printf forbidden > \"$1\"", "--", outside.path]
child.standardOutput = Pipe()
child.standardError = Pipe()
try child.run()
child.waitUntilExit()
let childDenied = child.terminationStatus != 0 && !manager.fileExists(atPath: outside.path)
var checks: [String: Any] = [
    "platform": "darwin",
    "outside_create_denied": outsideDenied,
    "child_inherits_denial": childDenied,
    "container_write_allowed": manager.fileExists(atPath: allowed.path),
]
// The sample server inherits the signed parent's sandbox; no network entitlement.
let server = Process()
server.executableURL = URL(fileURLWithPath: CommandLine.arguments[1])
server.arguments = [Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/mcp_write_server.py").path]
let input = Pipe()
let output = Pipe()
let errors = Pipe()
server.standardInput = input
server.standardOutput = output
server.standardError = errors
server.currentDirectoryURL = allowed.deletingLastPathComponent()
server.environment = ["HOME": home.path, "TMPDIR": home.appendingPathComponent("tmp").path, "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"]
let requests: [[String: Any]] = [
    ["jsonrpc": "2.0", "id": 0, "method": "initialize", "params": ["protocolVersion": "2025-06-18"]],
    ["jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": ["name": "write_sample", "arguments": ["path": allowed.deletingLastPathComponent().appendingPathComponent("mcp.txt").path]]],
    ["jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": ["name": "write_sample", "arguments": ["path": outside.path]]],
    ["jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": ["name": "inspect_boundary", "arguments": ["path": CommandLine.arguments[2]]]],
]
try server.run()
let serverTimeout = DispatchWorkItem { if server.isRunning { server.terminate() } }
DispatchQueue.global().asyncAfter(deadline: .now() + 20, execute: serverTimeout)
for request in requests {
    input.fileHandleForWriting.write(try JSONSerialization.data(withJSONObject: request))
    input.fileHandleForWriting.write(Data([10]))
}
try input.fileHandleForWriting.close()
let serverOutput = output.fileHandleForReading.readDataToEndOfFile()
server.waitUntilExit()
serverTimeout.cancel()
var responses: [Int: [String: Any]] = [:]
for line in String(decoding: serverOutput, as: UTF8.self).split(separator: "\n") {
    if let response = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
       let id = response["id"] as? Int, let result = response["result"] as? [String: Any] {
        responses[id] = result
    }
}
checks["mcp_handshake"] = responses[0] != nil
checks["mcp_workspace_write"] = responses[1]?["isError"] == nil && manager.fileExists(atPath: allowed.deletingLastPathComponent().appendingPathComponent("mcp.txt").path)
checks["mcp_outside_write_denied"] = responses[2]?["isError"] as? Bool == true && !manager.fileExists(atPath: outside.path)
if let content = responses[3]?["content"] as? [[String: Any]], let text = content.first?["text"] as? String,
   let boundary = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Bool] {
    checks["mcp_read_and_network_denied"] = boundary.values.allSatisfy { $0 }
    checks["mcp_boundary_details"] = boundary
} else {
    checks["mcp_read_and_network_denied"] = false
}
if server.terminationStatus != 0 {
    fputs(String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self), stderr)
}
let data = try JSONSerialization.data(withJSONObject: checks, options: [.sortedKeys])
print(String(decoding: data, as: UTF8.self))
if checks.values.compactMap({ $0 as? Bool }).contains(false) { exit(1) }
