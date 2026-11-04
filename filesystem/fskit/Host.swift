import AppKit
import FSKit
import Security

// Copy SDK identity properties before crossing executor boundaries.
struct DiscoveryModule: Sendable {
    let bundleIdentifier: String
    let url: URL
    let isEnabled: Bool
}

struct DiscoveryInspection {
    // A transport limit, not an inventory truncation policy: oversized metadata
    // or output fails the entire inventory, including collision detection.
    static let transportBytes = 1_048_576
    struct InvalidMetadata: Error {}

    static func scalar(_ value: Any?) throws -> Any {
        guard let value else { return NSNull() }
        guard let string = value as? String,
              string.utf8.count <= transportBytes else { throw InvalidMetadata() }
        return string
    }

    static func metadata(_ url: URL) throws -> [String: Any] {
        let handle = try FileHandle(forReadingFrom: url.appendingPathComponent("Contents/Info.plist"))
        do {
            let data = try handle.read(upToCount: transportBytes + 1) ?? Data()
            guard data.count <= transportBytes,
                  let info = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
            else { throw InvalidMetadata() }
            try handle.close()
            return info
        } catch {
            // Either read/parse or close failure invalidates the entire inventory.
            do { try handle.close() } catch { throw InvalidMetadata() }
            throw error
        }
    }

    static func fields(_ info: [String: Any]) throws -> [String: Any] {
        let attributes: [String: Any]
        if let value = info["EXAppExtensionAttributes"] {
            guard let dictionary = value as? [String: Any] else { throw InvalidMetadata() }
            attributes = dictionary
        } else {
            attributes = [:]
        }
        return try ["short_name": scalar(attributes["FSShortName"]),
                    "version": scalar(info["CFBundleVersion"]),
                    "minimum_os": scalar(info["LSMinimumSystemVersion"]),
                    "access_policy": scalar(info["StallionFSAccessPolicy"])]
    }

    static func encode(_ value: [String: Any]) throws -> Data {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        guard data.count <= transportBytes else { throw InvalidMetadata() }
        return data
    }

    static func failure(_ reason: String) -> Data {
        // These constant keys and error labels are always valid, bounded JSON.
        Data("{\"error\":\"\(reason)\",\"ok\":false}".utf8)
    }

    fileprivate static func inspect(_ modules: [DiscoveryModule]) -> Data {
        do {
            var rows: [[String: Any]] = []
            var encodedBytes = 0
            for module in modules {
                var row = try fields(metadata(module.url))
                row["bundle_id"] = try scalar(module.bundleIdentifier)
                row["url"] = try scalar(module.url.path)
                row["enabled"] = module.isEnabled
                var code: SecStaticCode?
                var signature = SecStaticCodeCreateWithPath(module.url as CFURL, [], &code)
                var signing: CFDictionary?
                if signature == errSecSuccess, let code {
                    signature = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), nil)
                    if signature == errSecSuccess {
                        signature = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &signing)
                    }
                }
                let signed = signing as? [String: Any] ?? [:]
                row["signature_status"] = signature
                row["signing_identifier"] = try scalar(signed[kSecCodeInfoIdentifier as String])
                row["team_identifier"] = try scalar(signed[kSecCodeInfoTeamIdentifier as String])
                // Raw signing flags are diagnostic only; they are not caller or
                // resource write authority and are not needed for selection.
                let encoded = try encode(row)
                guard encodedBytes <= transportBytes - encoded.count else { throw InvalidMetadata() }
                encodedBytes += encoded.count
                rows.append(row)
            }
            return try encode(["ok": true, "protocol": 1, "modules": rows])
        } catch {
            return failure("invalid-or-unreadable-module-metadata")
        }
    }
}

// The completion gate never performs package I/O or signature validation. A
// delayed inspector cannot block the deadline or turn a late result into success.
@MainActor
final class DiscoveryCompletion {
    private var completed = false
    private var started = false
    private let deadline: DispatchTime
    private let output: @MainActor (Data, Int32) -> Void
    init(deadline: DispatchTime = .now() + 10,
         output: (@MainActor (Data, Int32) -> Void)? = nil) {
        self.deadline = deadline
        self.output = output ?? Self.write
    }
    private static func write(_ data: Data, _ status: Int32) {
        do {
            try FileHandle.standardOutput.write(contentsOf: data + Data([10]))
            exit(status)
        } catch {
            fputs("Discovery result could not be written\n", stderr)
            exit(1)
        }
    }
    func finish(_ data: Data, status: Int32) {
        guard !completed else { return }
        completed = true
        if DispatchTime.now() >= deadline {
            output(DiscoveryInspection.failure("timeout"), 1)
        } else {
            output(data, status)
        }
    }
    func timeout() { finish(DiscoveryInspection.failure("timeout"), status: 1) }
    func begin(_ inspect: @escaping @Sendable () -> Data) {
        guard !completed, !started else { return }
        guard DispatchTime.now() < deadline else { timeout(); return }
        started = true
        DispatchQueue.global(qos: .userInitiated).async {
            let data = inspect()
            DispatchQueue.main.async {
                let success = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["ok"] as? Bool == true
                self.finish(data, status: success ? 0 : 1)
            }
        }
    }
    func receive(_ modules: [DiscoveryModule]?, error: Error?) {
        guard !completed, !started else { return }
        if error != nil {
            finish(DiscoveryInspection.failure("fetch"), status: 1)
            return
        }
        guard let modules else {
            finish(DiscoveryInspection.failure("missing-inventory"), status: 1)
            return
        }
        begin { DiscoveryInspection.inspect(modules) }
    }
}

struct CommandReply: Sendable {
    let state: String
    let command: String
    let pathSetup: String
    let onPath: Bool

    static func decode(_ data: Data) throws -> CommandReply {
        guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let state = value["state"] as? String, ["missing", "installed", "conflict"].contains(state),
              let command = value["command"] as? String, let setup = value["path_setup"] as? String,
              let onPath = value["on_path"] as? Bool else { throw CommandFailure("Invalid command status") }
        return CommandReply(state: state, command: command, pathSetup: setup, onPath: onPath)
    }
}

struct CommandFailure: Error, Sendable {
    let message: String
    init(_ message: String) { self.message = message }
}

// Only the fixed sibling helper is launched. Locked buffers cap both captured streams.
final class CommandTask: @unchecked Sendable {
    private let process = Process()
    private let lock = NSLock()
    private var streams = [Data(), Data()]
    private var failure: String?
    private let terminationDeadline: DispatchTime

    init(deadline: DispatchTime = .now() + 30) { terminationDeadline = deadline }

    private func stop(_ message: String) {
        lock.lock()
        let first = failure == nil
        if first { failure = message }
        lock.unlock()
        if first && process.isRunning { process.terminate() }
    }

    private func read(_ handle: FileHandle, stream: Int) {
        do {
            while let data = try handle.read(upToCount: 8192), !data.isEmpty {
                lock.lock()
                let remaining = DiscoveryInspection.transportBytes - streams[stream].count
                streams[stream].append(data.prefix(remaining))
                lock.unlock()
                if data.count > remaining { stop("Command output exceeded its limit") }
            }
        } catch { stop("Command output could not be read") }
        do { try handle.close() } catch { stop("Command output could not be closed") }
    }

    func run(_ action: String, app: URL, progress: @escaping @Sendable (String) -> Void) -> Result<CommandReply, CommandFailure> {
        guard ["status", "install", "remove"].contains(action) else { return .failure(CommandFailure("Invalid command action")) }
        let output = Pipe(), errors = Pipe()
        process.executableURL = app.appendingPathComponent("Contents/Resources/Runtime/CLI/bin/stallionfs-python")
        process.arguments = ["--json", "command", action]
        process.currentDirectoryURL = app
        process.environment = ["HOME": FileManager.default.homeDirectoryForCurrentUser.path,
                               "PATH": ProcessInfo.processInfo.environment["PATH"] ?? "/usr/bin:/bin",
                               "LC_ALL": "C", "LANG": "C", "TMPDIR": NSTemporaryDirectory()]
        process.standardOutput = output
        process.standardError = errors
        do { try process.run() } catch { return .failure(CommandFailure("Command helper could not start: \(error.localizedDescription)")) }
        // Termination is a request. Keep ownership and wait for actual exit and stream EOF.
        let deadline = DispatchWorkItem { [self] in
            stop("Command setup timed out")
            progress("Command setup timed out; waiting for it to stop")
        }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: terminationDeadline, execute: deadline)
        let readers = DispatchGroup()
        for (index, handle) in [output.fileHandleForReading, errors.fileHandleForReading].enumerated() {
            readers.enter()
            DispatchQueue.global(qos: .utility).async { [self] in
                read(handle, stream: index)
                readers.leave()
            }
        }
        process.waitUntilExit()
        deadline.cancel()
        readers.wait()
        lock.lock()
        let captured = streams, reason = failure
        lock.unlock()
        if let reason { return .failure(CommandFailure(reason)) }
        if process.terminationStatus != 0 {
            let value = (try? JSONSerialization.jsonObject(with: captured[1])) as? [String: Any]
            return .failure(CommandFailure(value?["error"] as? String ?? "Command setup failed; refresh status"))
        }
        guard captured[1].isEmpty else { return .failure(CommandFailure("Unexpected command diagnostic; refresh status")) }
        do { return .success(try CommandReply.decode(captured[0])) }
        catch { return .failure(CommandFailure("Invalid command status; refresh status")) }
    }
}

@MainActor
final class CommandPanel: NSObject, NSApplicationDelegate, NSWindowDelegate {
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 620, height: 245),
                          styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
    private let status = NSTextField(wrappingLabelWithString: "")
    private let location = NSTextField(wrappingLabelWithString: "")
    private let setup = NSTextField(wrappingLabelWithString: "")
    private let install = NSButton(title: "Install Command", target: nil, action: nil)
    private let remove = NSButton(title: "Remove Command", target: nil, action: nil)
    private let refresh = NSButton(title: "Refresh", target: nil, action: nil)
    private var busy = false

    override init() {
        super.init()
        window.title = "Control Panel"
        window.isReleasedWhenClosed = false
        window.delegate = self
        for field in [location, setup] { field.isSelectable = true }
        install.target = self; install.action = #selector(installCommand)
        remove.target = self; remove.action = #selector(removeCommand)
        refresh.target = self; refresh.action = #selector(refreshStatus)
        let buttons = NSStackView(views: [install, remove, refresh])
        let content = NSStackView(views: [status, location, setup, buttons])
        content.orientation = .vertical
        content.alignment = .leading
        content.spacing = 12
        content.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16)
        window.contentView = content
        window.center()
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if busy { status.stringValue = "Command setup is still running" }
        return !busy
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if busy { status.stringValue = "Command setup is still running" }
        return busy ? .terminateCancel : .terminateNow
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    @objc private func installCommand() { perform("install") }
    @objc private func removeCommand() { perform("remove") }
    @objc func refreshStatus() { perform("status") }

    private func perform(_ action: String) {
        guard !busy else { return }
        busy = true
        install.isEnabled = false; remove.isEnabled = false; refresh.isEnabled = false
        status.stringValue = action == "status" ? "Checking command" : "Updating command"
        let app = Bundle.main.bundleURL
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            let result = CommandTask().run(action, app: app) { [self] message in
                DispatchQueue.main.async { [self] in status.stringValue = message }
            }
            DispatchQueue.main.async { [self] in
                busy = false; refresh.isEnabled = true
                switch result {
                case .success(let reply):
                    status.stringValue = ["missing": "Command is not installed", "installed": "Command installed",
                                          "conflict": "Command path contains another entry"][reply.state] ?? "Invalid command status"
                    location.stringValue = reply.command
                    setup.stringValue = "Shell setup (zsh/bash):\n" + reply.pathSetup
                    install.isEnabled = reply.state == "missing"
                    remove.isEnabled = reply.state == "installed"
                case .failure(let error):
                    status.stringValue = error.message
                    setup.stringValue = ""
                }
            }
        }
    }
}

#if !STALLION_HOST_CHECK
@main
#endif
struct Host {
    @MainActor
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments.first == "--discover-json" {
            let completion = DiscoveryCompletion()
            guard arguments == ["--discover-json"] else {
                completion.finish(DiscoveryInspection.failure("invalid-arguments"), status: 2)
                return
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 10) { completion.timeout() }
            FSClient.shared.fetchInstalledExtensions { modules, error in
                let observed = modules?.map {
                    DiscoveryModule(bundleIdentifier: $0.bundleIdentifier,
                                    url: $0.url, isEnabled: $0.isEnabled)
                }
                DispatchQueue.main.async { completion.receive(observed, error: error) }
            }
            dispatchMain()
        }
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        let panel = CommandPanel()
        app.delegate = panel
        panel.window.makeKeyAndOrderFront(nil)
        panel.refreshStatus()
        withExtendedLifetime(panel) { app.run() }
    }
}
