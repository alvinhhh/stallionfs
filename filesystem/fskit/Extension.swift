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
    private func enqueue(_ block: @escaping () -> Void) { queue.async(execute: DispatchWorkItem(block: block)) }
    private func open(_ path: FSPathURLResource) throws -> (OpaquePointer, sfs_result, Bool) {
        guard !path.isRevoked && path.url.isFileURL else { throw POSIXError(.EACCES) }
        let scoped = path.url.startAccessingSecurityScopedResource()
        var handle: OpaquePointer?, r = sfs_result()
        do {
            let status = sfs_image_open_readonly(path.url.path, "image.sfs", &handle, &r)
            guard status == SFS_OK, let opened = handle else { throw sfsError(status, r) }
            guard anchorMatches(r) else { throw POSIXError(.EACCES) }
            let anchor = r; var root = sfs_metadata_entry()
            let stat = sfs_image_stat_metadata(opened, 0, 1, &root, &r)
            guard stat == SFS_OK else { throw sfsError(stat, r) }
            guard !path.isRevoked && anchorMatches(r) && root.entry.inode == 1 && root.entry.kind == SFS_DIRECTORY && root.link_count == 1 else { throw POSIXError(.EIO) }
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
    func probeResource(resource: FSResource, replyHandler: @escaping (FSProbeResult?, Error?) -> Void) { enqueue {
        guard let path = resource as? FSPathURLResource else { replyHandler(.notRecognized, nil); return }
        do {
            let (handle, _, scoped) = try self.open(path)
            var r = sfs_result(); let status = sfs_image_close(handle, &r)
            if scoped { path.url.stopAccessingSecurityScopedResource() }
            guard status == SFS_OK else { throw sfsError(status, r) }
            let b = FixtureIdentity.uuid
            let uuid = UUID(uuid: (b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]))
            replyHandler(.usableButLimited(name: "SFS read-only experiment", containerID: FSContainerIdentifier(uuid: uuid)), nil)
        } catch {
            if (error as NSError).domain == NSPOSIXErrorDomain && (error as NSError).code == Int(ENOENT) { replyHandler(.notRecognized, nil) }
            else { replyHandler(nil, error) }
        }
    } }
    func loadResource(resource: FSResource, options: FSTaskOptions, replyHandler: @escaping (FSVolume?, Error?) -> Void) { enqueue {
        guard self.resource == nil && self.unloadedURL == nil, let path = resource as? FSPathURLResource else { replyHandler(nil, POSIXError(.EINVAL)); return }
        guard !options.taskOptions.contains("-f") else { replyHandler(nil, POSIXError(.ENOTSUP)); return }
        do {
            let (handle, anchor, scoped) = try self.open(path)
            let loaded = StallionVolume(handle: handle, resource: path, scope: scoped, anchor: anchor, queue: self.queue)
            self.resource = path; self.volume = loaded; self.containerStatus = .ready; replyHandler(loaded, nil)
        } catch { replyHandler(nil, error) }
    } }
    func unloadResource(resource: FSResource, options: FSTaskOptions, replyHandler: @escaping (Error?) -> Void) { enqueue {
        guard let path = resource as? FSPathURLResource else { replyHandler(POSIXError(.EINVAL)); return }
        if self.unloadedURL == path.url { replyHandler(self.disposition); return }
        guard path.url == self.resource?.url, let volume = self.volume else { replyHandler(POSIXError(.EINVAL)); return }
        self.disposition = volume.unload(); self.unloadedURL = path.url; self.volume = nil; self.resource = nil
        replyHandler(self.disposition)
    } }
}
