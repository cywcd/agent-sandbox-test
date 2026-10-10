import AppKit
import Foundation
import Darwin

// Generic native process broker. Contains no application business logic.
func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(125)
}
let args = Array(CommandLine.arguments.dropFirst())
if args == ["--home"] { print(NSHomeDirectory()); exit(0) }
if args.count == 2 && args[0] == "--authorize" {
    _ = NSApplication.shared
    NSApp.setActivationPolicy(.regular)
    NSApp.activate(ignoringOtherApps: true)
    let panel = NSOpenPanel()
    panel.canChooseDirectories = true
    panel.canChooseFiles = false
    panel.allowsMultipleSelection = false
    panel.message = "Select exactly the isolated working directory."
    panel.directoryURL = URL(fileURLWithPath: args[1])
    guard panel.runModal() == .OK, let selected = panel.url else { fail("Directory authorization cancelled") }
    guard selected.resolvingSymlinksInPath().path == URL(fileURLWithPath: args[1]).resolvingSymlinksInPath().path else { fail("Selected directory does not match the working directory") }
    do { print(try selected.bookmarkData(options: [.withSecurityScope], includingResourceValuesForKeys: nil, relativeTo: nil).base64EncodedString()) }
    catch { fail("Could not create scoped directory bookmark") }
    exit(0)
}
guard args.count >= 4 && args[0] == "--run" else { fail("Invalid native runner arguments") }
let workspace = URL(fileURLWithPath: args[1]).resolvingSymlinksInPath()
var scoped: URL?
if args[2] != "-" {
    guard args[2] == "--scoped", let encoded = ProcessInfo.processInfo.environment["NATIVE_WORKSPACE_BOOKMARK"],
          let data = Data(base64Encoded: encoded) else { fail("Invalid bookmark") }
    var stale = false
    do {
        let url = try URL(resolvingBookmarkData: data, options: [.withSecurityScope, .withoutUI], relativeTo: nil, bookmarkDataIsStale: &stale)
        guard !stale && url.startAccessingSecurityScopedResource() else { fail("Directory authorization expired") }
        scoped = url
        guard url.resolvingSymlinksInPath().path == workspace.path else { fail("Directory authorization mismatch") }
    } catch { fail("Directory authorization unavailable") }
} else {
    let home = URL(fileURLWithPath: NSHomeDirectory()).resolvingSymlinksInPath().path
    guard workspace.path.hasPrefix(home + "/Documents/worktrees/") else { fail("Working directory needs native authorization") }
}
defer { scoped?.stopAccessingSecurityScopedResource() }
let child = Process()
if getpgrp() != getpid() && setsid() == -1 { fail("Could not create native process group") }
child.executableURL = URL(fileURLWithPath: args[3])
child.arguments = Array(args.dropFirst(4))
child.currentDirectoryURL = workspace
child.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": workspace.path, "TMPDIR": workspace.path, "CI": "1", "GIT_TERMINAL_PROMPT": "0", "PYTHONDONTWRITEBYTECODE": "1"]
child.standardInput = FileHandle.standardInput
child.standardOutput = FileHandle.standardOutput
child.standardError = FileHandle.standardError
do { try child.run() } catch { fail("Native child could not start: \(error)") }
// Parent EOF/termination is handled by the sidecar's process-group cancellation.
child.waitUntilExit()
exit(child.terminationStatus)
