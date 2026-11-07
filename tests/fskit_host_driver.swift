import Foundation

private final class InspectionCount: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func increment() { lock.lock(); count += 1; lock.unlock() }
    func value() -> Int { lock.lock(); defer { lock.unlock() }; return count }
}

@main
struct HostDiscoveryChecks {
    @MainActor
    static func main() async throws {
        var results: [(Data, Int32)] = []
        func result() throws -> [String: Any] {
            precondition(results.count == 1)
            return try JSONSerialization.jsonObject(with: results[0].0) as! [String: Any]
        }
        let missing = DiscoveryCompletion { results.append(($0, $1)) }
        missing.receive(nil, error: nil)
        missing.receive([], error: nil)
        missing.timeout()
        let missingResult = try result()
        precondition(missingResult["error"] as? String == "missing-inventory")
        precondition(results[0].1 == 1)

        results = []
        let failed = DiscoveryCompletion { results.append(($0, $1)) }
        failed.receive(nil, error: NSError(domain: "test", code: 7))
        let fetchResult = try result()
        precondition(fetchResult["error"] as? String == "fetch")

        results = []
        let empty = DiscoveryCompletion { results.append(($0, $1)) }
        empty.receive([], error: nil)
        try await Task.sleep(for: .milliseconds(100))
        let emptyResult = try result()
        precondition(emptyResult["ok"] as? Bool == true)
        precondition((emptyResult["modules"] as? [Any])?.isEmpty == true)
        precondition(results[0].1 == 0)

        results = []
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let count = InspectionCount()
        let delayed = DiscoveryCompletion(deadline: .now() + .milliseconds(100)) {
            results.append(($0, $1))
        }
        delayed.begin {
            count.increment()
            entered.signal()
            release.wait()
            return Data("{\"ok\":true}".utf8)
        }
        delayed.begin { count.increment(); return Data("{\"ok\":true}".utf8) }
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(100)) { delayed.timeout() }
        // The background inspection is held beyond the deadline. Main-actor
        // suspension leaves the deadline queue free; it never waits on the gate.
        try await Task.sleep(for: .milliseconds(250))
        precondition(entered.wait(timeout: .now()) == .success)
        let timeoutResult = try result()
        precondition(timeoutResult["error"] as? String == "timeout")
        precondition(count.value() == 1)
        release.signal()
        try await Task.sleep(for: .milliseconds(100))
        delayed.receive([], error: nil)
        precondition(results.count == 1)
        precondition(count.value() == 1)

        let malformedValues: [Any] = [Data([0, 1]), Date(), ["nested"], ["nested": "value"], 7]
        for malformed in malformedValues {
            do {
                _ = try DiscoveryInspection.fields(["CFBundleVersion": malformed])
                preconditionFailure("Accepted a non-string scalar")
            } catch is DiscoveryInspection.InvalidMetadata { }
        }
        do {
            _ = try DiscoveryInspection.fields(["EXAppExtensionAttributes": Data([0])])
            preconditionFailure("Accepted malformed attributes")
        } catch is DiscoveryInspection.InvalidMetadata { }
        do {
            _ = try DiscoveryInspection.fields(["CFBundleVersion": String(repeating: "x", count: DiscoveryInspection.transportBytes + 1)])
            preconditionFailure("Accepted oversized metadata")
        } catch is DiscoveryInspection.InvalidMetadata { }
        do {
            _ = try DiscoveryInspection.encode(["a": String(repeating: "x", count: DiscoveryInspection.transportBytes)])
            preconditionFailure("Accepted oversized result")
        } catch is DiscoveryInspection.InvalidMetadata { }
        let escaped = "line\nquote\"slash\\é"
        let fields = try DiscoveryInspection.fields(["CFBundleVersion": escaped])
        let decoded = try JSONSerialization.jsonObject(with: DiscoveryInspection.encode(fields)) as! [String: Any]
        precondition(decoded["version"] as? String == escaped)
        let command = try CommandReply.decode(Data("{\"state\":\"installed\",\"command\":\"/fixture/bin/sfs\",\"path_setup\":\"export PATH=fixture\",\"on_path\":false}".utf8))
        precondition(command.state == "installed" && command.command == "/fixture/bin/sfs" && !command.onPath)
        for text in ["{}", "{\"state\":\"ready-to-update\"}", "{\"state\":7}", "not json"] {
            do {
                _ = try CommandReply.decode(Data(text.utf8))
                preconditionFailure("Accepted invalid command status")
            } catch { }
        }
        // Inert transport fixtures never invoke product setup or an installed app.
        let transport = FileManager.default.temporaryDirectory.appendingPathComponent("command-transport-\(UUID().uuidString)")
        let helper = transport.appendingPathComponent("Contents/Resources/Runtime/CLI/bin/stallionfs-python")
        try FileManager.default.createDirectory(at: transport, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(at: helper.deletingLastPathComponent(), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: transport) }
        func script(_ text: String) throws {
            try Data(("#!/bin/sh\n" + text + "\n").utf8).write(to: helper)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
        }
        try script("printf '%s\\n' '{\"state\":\"missing\",\"command\":\"fixture\",\"path_setup\":\"fixture\",\"on_path\":false}'")
        let success = await Task.detached { CommandTask().run("status", app: transport) { _ in } }.value
        guard case .success(let reply) = success else { preconditionFailure("Transport success refused") }
        precondition(reply.state == "missing")
        try script("exec /bin/sleep 10")
        let timed = await Task.detached {
            CommandTask(deadline: .now() + .milliseconds(100)).run("status", app: transport) { _ in }
        }.value
        guard case .failure(let timeout) = timed else { preconditionFailure("Transport deadline ignored") }
        precondition(timeout.message == "Command setup timed out")
        try script("exec /usr/bin/yes fixture")
        let capped = await Task.detached { CommandTask().run("status", app: transport) { _ in } }.value
        guard case .failure(let limit) = capped else { preconditionFailure("Transport cap ignored") }
        precondition(limit.message == "Command output exceeded its limit")
        print("PASS: discovery single completion, independent deadline, malformed metadata and bounded JSON")
    }
}
