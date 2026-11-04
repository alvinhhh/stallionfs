import Foundation
@preconcurrency import FSKit
import SFSImage

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
    var fileSystem: StallionFileSystem {
        StallionFileSystem(accessPolicy: stallionFactoryProfile() == 1 ? .contextualWrites : .readOnly)
    }
}
// A load keeps the exact core-open access selected before its handle exists.
// Only this file can construct a production admission after that open succeeds.
struct ImageAdmission {
    enum Access: Equatable { case readOnly, contextualWrites, fixtureWritable }
    let handle: OpaquePointer
    let anchor: sfs_result
    let access: Access
    fileprivate init(handle: OpaquePointer, anchor: sfs_result, access: Access) {
        self.handle = handle; self.anchor = anchor; self.access = access
    }
#if STALLION_ADAPTER_CHECK
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
    private let accessPolicy: AccessPolicy
    init(accessPolicy: AccessPolicy = .readOnly) {
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
            if access != .readOnly {
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
    func loadResource(resource: FSResource, arguments: [String], replyHandler: @escaping (FSVolume?, Error?) -> Void) {
        guard arguments.count <= 64 && arguments.allSatisfy({ $0.utf8.count <= 1024 }) else { replyHandler(nil, POSIXError(.E2BIG)); return }
        loadResource(resource: resource, force: arguments.contains("-f"), readOnly: arguments.contains("--rdonly"), replyHandler: replyHandler)
    }
    func loadResource(resource: FSResource, force: Bool, replyHandler: @escaping (FSVolume?, Error?) -> Void) {
        loadResource(resource: resource, force: force, readOnly: false, replyHandler: replyHandler)
    }
    private func loadResource(resource: FSResource, force: Bool, readOnly: Bool, replyHandler: @escaping (FSVolume?, Error?) -> Void) {
        guard boundedResource(resource) else { replyHandler(nil, POSIXError(.ENAMETOOLONG)); return }
        guard let path = resource as? FSPathURLResource else { replyHandler(nil, POSIXError(.EINVAL)); return }
        guard !force else { replyHandler(nil, POSIXError(.ENOTSUP)); return }
        guard callbacks.acquire(4096) else { replyHandler(nil, POSIXError(.EAGAIN)); return }
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
                access = path.isWritable ? .contextualWrites : .readOnly
#else
                throw POSIXError(.ENOTSUP)
#endif
            } else { access = .readOnly }
            let (opened, scoped) = try self.open(path, access: access, expectedUUID: expected)
            let loaded = StallionVolume(admission: opened, resource: path, scope: scoped, queue: self.queue)
#if STALLION_ADAPTER_CHECK
            configurationHook?()
#endif
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
            if access != .readOnly {
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
