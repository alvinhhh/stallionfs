import Foundation
@preconcurrency import FSKit
import SFSImage

#if !STALLION_ADAPTER_CHECK
@main
#endif
struct StallionExtension: UnaryFileSystemExtension {
    var fileSystem: StallionFileSystem { StallionFileSystem() }
}
final class StallionFileSystem: FSUnaryFileSystem, FSUnaryFileSystemOperations, @unchecked Sendable {
    private let queue = DispatchQueue(label: "sfs.readonly")
    private var resource: FSPathURLResource?
    private var volume: StallionVolume?
    private var unloadedURL: URL?
    private var disposition: Error?
    private let callbacks = CallbackBudget()
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
    private func open(_ path: FSPathURLResource, writing: Bool = false) throws -> (OpaquePointer, sfs_result, Bool) {
        guard !path.isRevoked && path.url.isFileURL else { throw POSIXError(.EACCES) }
        let scoped = path.url.startAccessingSecurityScopedResource()
        var handle: OpaquePointer?, r = sfs_result()
        do {
            let status: sfs_status
#if STALLION_WRITE_DIAGNOSTIC
            if writing {
                guard diagnosticUUID != nil && path.isWritable else { throw POSIXError(.EACCES) }
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
#if STALLION_WRITE_DIAGNOSTIC
            if writing {
                guard let expected = diagnosticUUID,
                    rawBytes(anchor.uuid) == withUnsafeBytes(of: expected.uuid, { Array($0) }) else { throw POSIXError(.EACCES) }
            }
#endif
            let stat = sfs_image_stat_metadata(opened, 0, 1, &root, &r)
            guard stat == SFS_OK else { throw sfsError(stat, r) }
            guard !path.isRevoked && anchorMatches(r, anchor) && root.entry.inode == 1 && root.entry.kind == SFS_DIRECTORY && root.link_count == 1 else { throw POSIXError(.EIO) }
            return (opened, anchor, scoped)
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
            let (handle, anchor, scoped) = try self.open(path)
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
        guard options.taskOptions.count <= 64 && options.taskOptions.allSatisfy({ $0.utf8.count <= 1024 }) else { replyHandler(nil, POSIXError(.E2BIG)); return }
        loadResource(resource: resource, force: options.taskOptions.contains("-f"), replyHandler: replyHandler)
    }
    func loadResource(resource: FSResource, force: Bool, replyHandler: @escaping (FSVolume?, Error?) -> Void) {
        guard boundedResource(resource) else { replyHandler(nil, POSIXError(.ENAMETOOLONG)); return }
        enqueue(rejected: { replyHandler(nil, $0) }) {
        guard self.resource == nil && self.unloadedURL == nil, let path = resource as? FSPathURLResource else { replyHandler(nil, POSIXError(.EINVAL)); return }
        guard !force else { replyHandler(nil, POSIXError(.ENOTSUP)); return }
        do {
            var writing = false
#if STALLION_WRITE_DIAGNOSTIC
            writing = self.diagnosticUUID != nil
#endif
            let (handle, anchor, scoped) = try self.open(path, writing: writing)
            let loaded = StallionVolume(handle: handle, resource: path, scope: scoped, anchor: anchor, queue: self.queue)
#if STALLION_WRITE_DIAGNOSTIC
            if let expected = self.diagnosticUUID {
                do { try loaded.enableWriteDiagnostic(expectedUUID: expected) }
                catch { _ = loaded.unload(); throw error }
            }
#endif
            self.resource = path; self.volume = loaded; self.containerStatus = .ready; replyHandler(loaded, nil)
        } catch { replyHandler(nil, error) }
    } }
    func unloadResource(resource: FSResource, options: FSTaskOptions, replyHandler: @escaping (Error?) -> Void) {
        unloadResource(resource: resource, replyHandler: replyHandler)
    }
    func unloadResource(resource: FSResource, replyHandler: @escaping (Error?) -> Void) {
        guard boundedResource(resource) else { replyHandler(POSIXError(.ENAMETOOLONG)); return }
        enqueue(rejected: { replyHandler($0) }) {
        guard let path = resource as? FSPathURLResource else { replyHandler(POSIXError(.EINVAL)); return }
        if self.unloadedURL == path.url { replyHandler(self.disposition); return }
        guard path.url == self.resource?.url, let volume = self.volume else { replyHandler(POSIXError(.EINVAL)); return }
        let unloaded = volume.unload()
        guard unloaded.consumed else { replyHandler(unloaded.error); return }
        self.disposition = unloaded.error; self.unloadedURL = path.url; self.volume = nil; self.resource = nil
        replyHandler(self.disposition)
    } }
}
