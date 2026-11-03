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
        app.run()
    }
}
