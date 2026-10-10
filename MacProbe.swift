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
let checks: [String: Any] = [
    "platform": "darwin",
    "outside_create_denied": outsideDenied,
    "child_inherits_denial": childDenied,
    "container_write_allowed": manager.fileExists(atPath: allowed.path),
]
let data = try JSONSerialization.data(withJSONObject: checks, options: [.sortedKeys])
print(String(decoding: data, as: UTF8.self))
if !outsideDenied || !childDenied { exit(1) }
