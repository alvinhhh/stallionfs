import Foundation
import Darwin
@preconcurrency import FSKit
import SFSImage

enum StallionFileSystemIdentity: String, Sendable {
    case production = "stallionfs", privateDiagnostic = "sfsro27"
    init(extensionAttributes: Any?) throws {
        guard let attributes = extensionAttributes as? [String: Any],
              let name = attributes["FSShortName"] as? String,
              let identity = Self(rawValue: name) else { throw POSIXError(.EINVAL) }
        self = identity
    }
}
private final class StallionModuleBundleAnchor: NSObject {}

// Packaging reads the defined symbol from each executable architecture. Keep
// the marker and public factory selection in this single compile-time branch.
#if STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES
@_cdecl("stallionfs_factory_contextual_writes_v1")
public func stallionFactoryProfile() -> Int32 { 1 }
#else
@_cdecl("stallionfs_factory_read_only_v1")
public func stallionFactoryProfile() -> Int32 { 0 }
#endif
#if !STALLION_ADAPTER_CHECK
@main
#endif
struct StallionExtension: UnaryFileSystemExtension {
    // Resolve the module's identity once; the containing app is not an authority.
    private static let identity = Result {
        try StallionFileSystemIdentity(extensionAttributes:
            Bundle(for: StallionModuleBundleAnchor.self).object(forInfoDictionaryKey: "EXAppExtensionAttributes"))
    }
    var fileSystem: StallionFileSystem {
        Self.makeFileSystem(identity: Self.identity)
    }
    private static func makeFileSystem(identity: Result<StallionFileSystemIdentity, Error>) -> StallionFileSystem {
        StallionFileSystem(identity: identity, accessPolicy: stallionFactoryProfile() == 1 ? .contextualWrites : .readOnly)
    }
#if STALLION_ADAPTER_CHECK
    static func fileSystemForTesting(extensionAttributes: Any?) -> StallionFileSystem {
        makeFileSystem(identity: Result { try StallionFileSystemIdentity(extensionAttributes: extensionAttributes) })
    }
#endif
}
// A load keeps the exact core-open access selected before its handle exists.
// Only this file can construct a production admission after that open succeeds.
// Managed requests are structural same-account authority, not signed tokens.
struct ActivationOptions: Equatable {
    let operation: String
    let nonce: String
    static func parse(_ arguments: [String]) throws -> ActivationOptions? {
        guard arguments.count <= 64, arguments.allSatisfy({ $0.utf8.count <= 1024 }),
              arguments.reduce(0, { $0 + $1.utf8.count }) <= 4096 else { throw POSIXError(.E2BIG) }
        var fields: [String] = []
        var index = 0
        while index < arguments.count {
            guard arguments[index] == "-o", index + 1 < arguments.count else { throw POSIXError(.EINVAL) }
            fields += arguments[index + 1].split(separator: ",", omittingEmptySubsequences: false).map(String.init)
            index += 2
        }
        if fields.isEmpty || fields == ["ro"] || fields == ["ro", "owners"] { return nil }
        guard fields.count == 3, fields[0] == "rw", fields[1] == "owners",
              fields[2].hasPrefix("sfs_activation=") else { throw POSIXError(.EINVAL) }
        let ids = fields[2].dropFirst("sfs_activation=".count).split(separator: ".", omittingEmptySubsequences: false)
        guard ids.count == 2, hex(String(ids[0]), 32), hex(String(ids[1]), 32) else { throw POSIXError(.EINVAL) }
        return ActivationOptions(operation: String(ids[0]), nonce: String(ids[1]))
    }
    static func hex(_ value: String, _ length: Int) -> Bool {
        value.utf8.count == length && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}

func activationCleanupError(_ primary: Error, _ cleanup: Error) -> NSError {
    let first = primary as NSError
    var details = first.userInfo
    details[NSUnderlyingErrorKey] = first
    details[NSMultipleUnderlyingErrorsKey] = [first, cleanup]
    return NSError(domain: first.domain, code: first.code, userInfo: details)
}

final class ActivationDescriptors {
    private var descriptors: [Int32] = []
    func own(_ descriptor: Int32) throws -> Int32 {
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        descriptors.append(descriptor); return descriptor
    }
    func finish(_ primary: Error? = nil) throws {
        var cleanup: Error?
        for fd in descriptors.reversed() {
            if Darwin.close(fd) != 0 && cleanup == nil { cleanup = POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        }
        descriptors.removeAll()
        if let primary {
            if let cleanup { throw activationCleanupError(primary, cleanup) }
            throw primary
        }
        if let cleanup { throw cleanup }
    }
}

struct ManagedActivation {
#if STALLION_ADAPTER_CHECK
    nonisolated(unsafe) static var beforeTransferForTesting: (() throws -> Void)?
    nonisolated(unsafe) static var beforeWritableForTesting: (() throws -> Void)?
    nonisolated(unsafe) static var afterWritableForTesting: (() throws -> Void)?
#endif
    static func named(_ parent: Int32, _ name: String, _ fd: Int32) throws {
        var named = stat(), opened = stat()
        guard fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0, fstat(fd, &opened) == 0,
              named.st_dev == opened.st_dev, named.st_ino == opened.st_ino else { throw POSIXError(.ESTALE) }
    }
    static func checked(_ fd: Int32, directory: Bool) throws -> stat {
        var value = stat()
        guard fstat(fd, &value) == 0 else { throw POSIXError(.EIO) }
        guard value.st_uid == geteuid(), value.st_mode & 0o077 == 0,
              value.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG),
              directory ? value.st_mode & 0o700 == 0o700 : value.st_nlink == 1 else { throw POSIXError(.EACCES) }
        return value
    }
    static func number(_ value: String) throws -> UInt64 {
        guard let n = UInt64(value), String(n) == value else { throw POSIXError(.EINVAL) }; return n
    }
    static func promote(_ handle: OpaquePointer, expected: sfs_result, resource: FSPathURLResource,
                        scope: Bool, intent: ActivationOptions) throws {
        guard scope, resource.url.isFileURL, !resource.isRevoked else { throw POSIXError(.EACCES) }
        let owned = ActivationDescriptors()
        do {
            let parent = try owned.own(resource.url.withUnsafeFileSystemRepresentation { path in
                guard let path else { return -1 }; return Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            })
            let parentStat = try checked(parent, directory: true)
            let operations = try owned.own(openat(parent, "native-operations", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
            _ = try checked(operations, directory: true)
            let operation = try owned.own(openat(operations, intent.operation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
            _ = try checked(operation, directory: true)
            let attempt = try owned.own(openat(operation, "activation-" + intent.nonce, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
            _ = try checked(attempt, directory: true)
            let gate = try owned.own(openat(attempt, "gate", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC))
            _ = try checked(gate, directory: false)
            guard flock(gate, LOCK_SH | LOCK_NB) == 0 else { throw POSIXError(.EBUSY) }
            let lease = try owned.own(openat(attempt, "lease", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC))
            _ = try checked(lease, directory: false)
            let request = try owned.own(openat(attempt, "request", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC))
            let before = try checked(request, directory: false)
            guard before.st_size > 0 && before.st_size <= 1024 else { throw POSIXError(.E2BIG) }
            var bytes = [UInt8](repeating: 0, count: Int(before.st_size) + 1)
            let count = bytes.withUnsafeMutableBytes { pread(request, $0.baseAddress, $0.count, 0) }
            guard count == before.st_size else { throw POSIXError(.EIO) }
            bytes.removeLast()
            guard let text = String(bytes: bytes, encoding: .ascii), text.hasSuffix("\n") else { throw POSIXError(.EINVAL) }
            let f = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
            guard f.count == 19, f[18].isEmpty, f[0] == "stallionfs-activation-v1",
                  ["native-mount", "native-mounted-snapshot", "native-mounted-restore"].contains(f[1]),
                  f[2] == intent.operation, ActivationOptions.hex(f[3], 32),
                  f[4] == resource.url.lastPathComponent, ActivationOptions.hex(f[4], 32), f[5] == intent.nonce,
                  f[15] == "rw", f[16] == "owners", f[17] == "pending",
                  ActivationOptions.hex(f[10], 32), ActivationOptions.hex(f[12], 64),
                  try number(f[6]) == UInt64(parentStat.st_dev), try number(f[7]) == parentStat.st_ino,
                  try number(f[8]) == expected.device, try number(f[9]) == expected.inode,
                  try number(f[11]) == expected.generation, try number(f[13]) == expected.committed_end,
                  try number(f[14]) == expected.physical_end,
                  f[10] == rawBytes(expected.uuid).map({ String(format: "%02x", $0) }).joined(),
                  f[12] == rawBytes(expected.root_digest).map({ String(format: "%02x", $0) }).joined()
            else { throw POSIXError(.EACCES) }
            let after = try checked(request, directory: false)
            guard before.st_dev == after.st_dev, before.st_ino == after.st_ino, before.st_size == after.st_size,
                  before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
                  before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec, !resource.isRevoked else { throw POSIXError(.ESTALE) }
            try named(parent, "native-operations", operations)
            try named(operations, intent.operation, operation)
            try named(operation, "activation-" + intent.nonce, attempt)
            try named(attempt, "request", request)
            try named(attempt, "lease", lease)
            try named(attempt, "gate", gate)
#if STALLION_ADAPTER_CHECK
            try beforeTransferForTesting?()
#endif
            // Transfer point: complete intent under the shared gate plus a
            // live controller lease delegates ONE attempt. Later controller
            // exit does not revoke that transfer; original resource revocation
            // remains a separate mandatory gate throughout activation.
            guard flock(lease, LOCK_EX | LOCK_NB) != 0 else { throw POSIXError(.ESTALE) }
            guard errno == EWOULDBLOCK else { throw POSIXError(.EIO) }
            // Durable, exclusive consumption precedes writable backing acquisition.
            let claim = try owned.own(openat(attempt, "claim", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600))
            guard fsync(claim) == 0, fsync(attempt) == 0 else { throw POSIXError(.EIO) }
            guard !resource.isRevoked else { throw POSIXError(.EACCES) }
#if STALLION_ADAPTER_CHECK
            try beforeWritableForTesting?()
#endif
            let current = try owned.own(resource.url.withUnsafeFileSystemRepresentation { path in
                guard let path else { return -1 }; return Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            })
            let currentStat = try checked(current, directory: true)
            guard currentStat.st_dev == parentStat.st_dev, currentStat.st_ino == parentStat.st_ino,
                  !resource.isRevoked else { throw POSIXError(.ESTALE) }
            let rw = try owned.own(openat(current, "image.sfs", O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC))
#if STALLION_ADAPTER_CHECK
            try afterWritableForTesting?()
#endif
            let afterOpen = try owned.own(resource.url.withUnsafeFileSystemRepresentation { path in
                guard let path else { return -1 }; return Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            })
            let afterStat = try checked(afterOpen, directory: true)
            guard afterStat.st_dev == parentStat.st_dev, afterStat.st_ino == parentStat.st_ino,
                  !resource.isRevoked else { throw POSIXError(.ESTALE) }
            var anchor = expected, result = sfs_result(), cleanup: Int32 = 0
            let status = sfs_image_activate_pending(handle, afterOpen, rw, &anchor, &cleanup, &result)
            if status != SFS_OK {
                if cleanup != 0 { throw activationCleanupError(sfsError(status, result), POSIXError(POSIXErrorCode(rawValue: cleanup) ?? .EIO)) }
                throw sfsError(status, result)
            }
            guard !resource.isRevoked else { throw POSIXError(.EACCES) }
        } catch { try owned.finish(error); return }
        try owned.finish()
    }
}

struct ImageAdmission {
    enum Access: Equatable { case readOnly, pendingContextual, contextualWrites, fixtureWritable }
    let handle: OpaquePointer
    let anchor: sfs_result
    let access: Access
    fileprivate init(handle: OpaquePointer, anchor: sfs_result, access: Access) {
        self.handle = handle; self.anchor = anchor; self.access = access
    }
#if STALLION_ADAPTER_CHECK
    static func pendingForTesting(handle: OpaquePointer, anchor: sfs_result) -> ImageAdmission {
        ImageAdmission(handle: handle, anchor: anchor, access: .pendingContextual)
    }
    static func forTesting(handle: OpaquePointer, anchor: sfs_result, writable: Bool = false) -> ImageAdmission {
#if STALLION_WRITE_DIAGNOSTIC
        return ImageAdmission(handle: handle, anchor: anchor, access: writable ? .fixtureWritable : .readOnly)
#else
        precondition(!writable)
        return ImageAdmission(handle: handle, anchor: anchor, access: .readOnly)
#endif
    }
#endif
}
final class StallionFileSystem: FSUnaryFileSystem, FSUnaryFileSystemOperations, @unchecked Sendable {
    // The public entry point enables contextual writes only with both build flags.
    // Direct construction defaults to read-only.
    // Writable acquisition uses delivered caller context; data I/O additionally
    // requires the canonical item's retained write mode from a successful open.
    // Kernel cache/descriptor ordering still requires mounted qualification.
    enum AccessPolicy: Equatable { case readOnly, contextualWrites }
    private let identity: Result<StallionFileSystemIdentity, Error>
    private let accessPolicy: AccessPolicy
    init(identity: Result<StallionFileSystemIdentity, Error>, accessPolicy: AccessPolicy = .readOnly) {
#if STALLION_MOUNT_TRACE
        _ = MountTrace.shared
#endif
        self.identity = identity
        self.accessPolicy = accessPolicy
        super.init()
    }
    private let queue = DispatchQueue(label: "sfs.volume")
    private final class ResourceAdmission: @unchecked Sendable {
        let resource: FSPathURLResource
        let url: URL
        // Only the serial queue reads or changes ownership and its outcome.
        var volume: StallionVolume?
        var consumed = false
        var disposition: Error?
        init(_ resource: FSPathURLResource) { self.resource = resource; url = resource.url }
    }
    private enum Routing { case idle, opening(ResourceAdmission), live(ResourceAdmission) }
    // The lock protects routing identities, never core work or framework replies.
    private let routingLock = NSLock()
    private var routing = Routing.idle
    private var completed: ResourceAdmission?
    private let callbacks = CallbackBudget()
#if STALLION_ADAPTER_CHECK
    private var unloadAdmissionHook: (() -> Void)?
    private var loadConfigurationHook: (() -> Void)?
    func setLoadConfigurationHookForTesting(_ hook: (() -> Void)?) {
        routingLock.lock(); loadConfigurationHook = hook; routingLock.unlock()
    }
    func setUnloadAdmissionHookForTesting(_ hook: (() -> Void)?) {
        routingLock.lock(); unloadAdmissionHook = hook; routingLock.unlock()
    }
    func drainResourceWorkForTesting(_ reply: @escaping (Bool) -> Void) {
        queue.async(execute: DispatchWorkItem { reply(self.callbacks.isEmpty) })
    }
#endif
#if STALLION_WRITE_DIAGNOSTIC
    // Explicit, single-image binding supplied by the disposable-image harness.
    // The default extension initializer supplies no binding and stays read-only.
    var diagnosticUUID: UUID?
#endif
    private func enqueue(rejected: (Error) -> Void, _ block: @escaping () -> Void) {
        guard callbacks.acquire(4096) else { rejected(POSIXError(.EAGAIN)); return }
        queue.async(execute: DispatchWorkItem { defer { self.callbacks.release(4096) }; block() })
    }
    private func boundedResource(_ resource: FSResource) -> Bool {
        guard let path = resource as? FSPathURLResource else { return true }
        return path.url.absoluteString.utf8.count <= 4096
    }
    private func open(_ path: FSPathURLResource, access: ImageAdmission.Access = .readOnly, expectedUUID: UUID? = nil) throws -> (ImageAdmission, Bool) {
        guard !path.isRevoked && path.url.isFileURL else { throw POSIXError(.EACCES) }
        let scoped = path.url.startAccessingSecurityScopedResource()
        var handle: OpaquePointer?, r = sfs_result()
        do {
            let status: sfs_status
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
            if access == .pendingContextual {
                status = sfs_image_open_pending(path.url.path, "image.sfs", &handle, &r)
            } else if access != .readOnly {
                guard path.isWritable else { throw POSIXError(.EACCES) }
                status = sfs_image_open(path.url.path, "image.sfs", &handle, &r)
            } else { status = sfs_image_open_readonly(path.url.path, "image.sfs", &handle, &r) }
#else
            status = sfs_image_open_readonly(path.url.path, "image.sfs", &handle, &r)
#endif
            guard status == SFS_OK, let opened = handle else { throw sfsError(status, r) }
            var information = sfs_image_information()
            let infoStatus = sfs_image_get_information(opened, &information, &r)
            guard infoStatus == SFS_OK else { throw sfsError(infoStatus, r) }
            guard information.major == 0 && information.minor == 6 && information.root_inode == 1 else { throw POSIXError(.ENOTSUP) }
            let anchor = information.committed; var root = sfs_metadata_entry()
            if access == .fixtureWritable {
                guard let expected = expectedUUID,
                    rawBytes(anchor.uuid) == withUnsafeBytes(of: expected.uuid, { Array($0) }) else { throw POSIXError(.EACCES) }
            }
            let stat = sfs_image_stat_metadata(opened, 0, 1, &root, &r)
            guard stat == SFS_OK else { throw sfsError(stat, r) }
            guard !path.isRevoked && anchorMatches(r, anchor) && root.entry.inode == 1 && root.entry.kind == SFS_DIRECTORY && root.link_count == 1 else { throw POSIXError(.EIO) }
            return (ImageAdmission(handle: opened, anchor: anchor, access: access), scoped)
        } catch {
            var closeFailure: Error?
            if let owned = handle { handle = nil; let status = sfs_image_close(owned, &r); if status != SFS_OK { closeFailure = sfsError(status, r) } }
            if scoped { path.url.stopAccessingSecurityScopedResource() }
            if let closeFailure {
                let first = error as NSError
                throw NSError(domain: first.domain, code: first.code, userInfo: [NSUnderlyingErrorKey: closeFailure])
            }
            throw error
        }
    }
    func probeResource(resource: FSResource, replyHandler: @escaping (FSProbeResult?, Error?) -> Void) {
        if case .failure(let error) = identity { replyHandler(nil, error); return }
        guard boundedResource(resource) else { replyHandler(nil, POSIXError(.ENAMETOOLONG)); return }
        enqueue(rejected: { replyHandler(nil, $0) }) {
        guard let path = resource as? FSPathURLResource else { replyHandler(.notRecognized, nil); return }
        do {
            let (opened, scoped) = try self.open(path)
            let handle = opened.handle, anchor = opened.anchor
            var r = sfs_result(); let status = sfs_image_close(handle, &r)
            if scoped { path.url.stopAccessingSecurityScopedResource() }
            guard status == SFS_OK else { throw sfsError(status, r) }
            let b = rawBytes(anchor.uuid)
            let uuid = UUID(uuid: (b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]))
            replyHandler(.usableButLimited(name: "StallionFS", containerID: FSContainerIdentifier(uuid: uuid)), nil)
        } catch {
            if (error as NSError).domain == NSPOSIXErrorDomain && (error as NSError).code == Int(ENOENT) { replyHandler(.notRecognized, nil) }
            else { replyHandler(nil, error) }
        }
    } }
    func loadResource(resource: FSResource, options: FSTaskOptions, replyHandler: @escaping (FSVolume?, Error?) -> Void) {
        loadResource(resource: resource, arguments: options.taskOptions, replyHandler: replyHandler)
    }
    // Shared decoder also permits direct checks without fabricating FSTaskOptions,
    // whose public initializer is unavailable in the SDK.
    func loadResource(resource: FSResource, force: Bool, replyHandler: @escaping (FSVolume?, Error?) -> Void) {
        loadResource(resource: resource, arguments: force ? ["-f"] : [], replyHandler: replyHandler)
    }
    func loadResource(resource: FSResource, arguments: [String], replyHandler: @escaping (FSVolume?, Error?) -> Void) {
#if STALLION_MOUNT_TRACE
        let trace = MountTrace.shared, load = trace.id(), callback = trace.id()
        trace.emit(1, 1, load: load, callback: callback, value: UInt64(min(arguments.count, 65)))
        let originalReply = replyHandler
#endif
        guard arguments.count <= 64 && arguments.allSatisfy({ $0.utf8.count <= 1024 }) else {
#if STALLION_MOUNT_TRACE
            trace.emit(3, 1, load: load, callback: callback, stage: .arguments, error: POSIXError(.E2BIG))
#endif
            replyHandler(nil, POSIXError(.E2BIG)); return
        }
        let force = arguments.contains("-f"), readOnly = arguments.contains("--rdonly")
#if STALLION_MOUNT_TRACE
        var entryStage: MountTrace.Stage = .identity
        let replyHandler: (FSVolume?, Error?) -> Void = { result, error in
            trace.emit(3, 1, load: load, callback: callback, stage: entryStage, error: error)
            originalReply(result, error)
        }
#endif
        let identity: StallionFileSystemIdentity
        do { identity = try self.identity.get() }
        catch { replyHandler(nil, error); return }
#if STALLION_MOUNT_TRACE
        entryStage = .resourceSize
#endif
        guard boundedResource(resource) else { replyHandler(nil, POSIXError(.ENAMETOOLONG)); return }
#if STALLION_MOUNT_TRACE
        entryStage = .resourceType
#endif
        guard let path = resource as? FSPathURLResource else { replyHandler(nil, POSIXError(.EINVAL)); return }
#if STALLION_MOUNT_TRACE
        entryStage = .force
#endif
        guard !force else { replyHandler(nil, POSIXError(.ENOTSUP)); return }
#if STALLION_MOUNT_TRACE
        entryStage = .enqueue
#endif
        guard callbacks.acquire(4096) else { replyHandler(nil, POSIXError(.EAGAIN)); return }
#if STALLION_MOUNT_TRACE
        entryStage = .routing
#endif
        routingLock.lock()
        guard case .idle = routing else {
            routingLock.unlock(); callbacks.release(4096); replyHandler(nil, POSIXError(.EINVAL)); return
        }
        let context = ResourceAdmission(path)
        routing = .opening(context)
#if STALLION_ADAPTER_CHECK
        let configurationHook = loadConfigurationHook
#endif
        routingLock.unlock()
        queue.async(execute: DispatchWorkItem {
        defer { self.callbacks.release(4096) }
#if STALLION_MOUNT_TRACE
        trace.emit(2, 1, load: load, callback: callback, value: (path.isWritable ? 1 : 0) | (path.isRevoked ? 2 : 0) | 4)
        var stage: MountTrace.Stage = .open
        let replyHandler: (FSVolume?, Error?) -> Void = { result, error in
            trace.emit(3, 1, load: load, callback: callback, stage: stage, error: error)
            originalReply(result, error)
        }
#endif
        do {
            // --rdonly wins before open, even over a private fixture binding.
            let expected: UUID?
#if STALLION_WRITE_DIAGNOSTIC
            expected = self.diagnosticUUID
#else
            expected = nil
#endif
            let access: ImageAdmission.Access
            if readOnly { access = .readOnly }
            else if expected != nil {
                guard path.isWritable else { throw POSIXError(.EACCES) }
                access = .fixtureWritable
            } else if self.accessPolicy == .contextualWrites {
#if STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES
                access = .pendingContextual
#else
                throw POSIXError(.ENOTSUP)
#endif
            } else { access = .readOnly }
#if STALLION_MOUNT_TRACE
            trace.emit(4, 1, load: load, callback: callback, value: access == .readOnly ? 0 : access == .contextualWrites ? 1 : 2)
#endif
            let (opened, scoped) = try self.open(path, access: access, expectedUUID: expected)
            let loaded = StallionVolume(identity: identity, admission: opened, resource: path, scope: scoped, queue: self.queue)
#if STALLION_MOUNT_TRACE
            loaded.mountTraceLoad = load
            stage = .enable
#endif
#if STALLION_ADAPTER_CHECK
            configurationHook?()
#endif
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
            if access == .fixtureWritable {
                do { try loaded.enableAdmittedWrites() }
                catch {
                    let cleanup = loaded.unload()
                    if let closeFailure = cleanup.error {
                        let first = error as NSError
                        throw NSError(domain: first.domain, code: first.code, userInfo: [NSUnderlyingErrorKey: closeFailure])
                    }
                    throw error
                }
            }
#endif
            context.volume = loaded
            self.finishOpening(context, live: true)
#if STALLION_MOUNT_TRACE
            stage = .complete
#endif
            self.containerStatus = .ready; replyHandler(loaded, nil)
        } catch {
            self.finishOpening(context, live: false)
            replyHandler(nil, error)
        }
    }) }
    private func finishOpening(_ context: ResourceAdmission, live: Bool) {
        routingLock.lock()
        guard case .opening(let current) = routing, current === context else {
            routingLock.unlock(); preconditionFailure("Resource admission reservation changed")
        }
        routing = live ? .live(context) : .idle
        routingLock.unlock()
    }
    func unloadResource(resource: FSResource, options: FSTaskOptions, replyHandler: @escaping (Error?) -> Void) {
        unloadResource(resource: resource, replyHandler: replyHandler)
    }
    func unloadResource(resource: FSResource, replyHandler: @escaping (Error?) -> Void) {
        guard boundedResource(resource) else { replyHandler(POSIXError(.ENAMETOOLONG)); return }
        guard let path = resource as? FSPathURLResource else { replyHandler(POSIXError(.EINVAL)); return }
        guard callbacks.acquire(4096) else { replyHandler(POSIXError(.EAGAIN)); return }
        routingLock.lock()
        let selected: ResourceAdmission?
        switch routing {
        case .live(let current): selected = current.url == path.url ? current : nil
        case .idle: selected = completed?.url == path.url ? completed : nil
        case .opening: selected = nil
        }
#if STALLION_ADAPTER_CHECK
        let hook = unloadAdmissionHook
#endif
        routingLock.unlock()
        guard let context = selected else {
            callbacks.release(4096); replyHandler(POSIXError(.EINVAL)); return
        }
#if STALLION_ADAPTER_CHECK
        hook?()
#endif
        queue.async(execute: DispatchWorkItem {
        defer { self.callbacks.release(4096) }
        if context.consumed { replyHandler(context.disposition); return }
        guard let volume = context.volume else { preconditionFailure("Live resource has no volume") }
        let unloaded = volume.unload()
        guard unloaded.consumed else { replyHandler(unloaded.error); return }
        context.disposition = unloaded.error; context.consumed = true; context.volume = nil
        self.routingLock.lock()
        if case .live(let current) = self.routing, current === context {
            self.routing = .idle; self.completed = context
        }
        self.routingLock.unlock()
        replyHandler(context.disposition)
    }) }
}
