import Foundation
@preconcurrency import FSKit
import Darwin
import CryptoKit
import Security
import OSLog
import SFSImage

func sfsError(_ status: sfs_status, _ result: sfs_result, missing: Int32 = ENOENT) -> Error {
    let code: Int32
    switch status {
    case SFS_NOT_FOUND: code = missing
    case SFS_INVALID: code = EINVAL
    case SFS_BUSY: code = EBUSY
    case SFS_UNSUPPORTED: code = ENOTSUP
    case SFS_NOMEM: code = ENOMEM
    case SFS_LIMIT: code = EFBIG
    case SFS_IO: code = result.system_errno > 0 ? result.system_errno : EIO
    default: code = EIO
    }
    return NSError(domain: NSPOSIXErrorDomain, code: Int(code))
}
func rawBytes<T>(_ tuple: T) -> [UInt8] { withUnsafeBytes(of: tuple) { Array($0) } }
func anchorMatches(_ result: sfs_result) -> Bool {
    rawBytes(result.uuid) == FixtureIdentity.uuid && result.generation == FixtureIdentity.generation &&
    rawBytes(result.root_digest) == FixtureIdentity.digest
}
func component(_ data: Data, xattr: Bool = false) throws {
    guard data.count <= 255 else { throw POSIXError(.ENAMETOOLONG) }
    guard !data.isEmpty && !data.contains(0) && (xattr || !data.contains(47)) else { throw POSIXError(.EINVAL) }
}
func itemIdentifier(_ inode: UInt64) throws -> FSItem.Identifier {
    let (value, overflow) = inode.addingReportingOverflow(1)
    guard inode > 0 && !overflow, let id = FSItem.Identifier(rawValue: value) else { throw POSIXError(.EOVERFLOW) }
    return id
}
func checkedTime(_ value: sfs_timestamp) throws -> timespec {
    guard let seconds = Int(exactly: value.seconds), value.nanoseconds < 1_000_000_000 else { throw POSIXError(.EOVERFLOW) }
    return timespec(tv_sec: seconds, tv_nsec: Int(value.nanoseconds))
}
func validateWanted(_ mask: Int) throws {
    guard mask & ~0x33fff == 0 else { throw POSIXError(.ENOTSUP) }
}
func checkedLinks(_ value: UInt64) throws -> UInt32 {
    guard let links = UInt32(exactly: value) else { throw POSIXError(.EOVERFLOW) }
    return links
}
func validateDirectoryLayout(_ cookie: UInt64, _ verifier: UInt64) throws {
    guard cookie == 0 && verifier == 0 else { throw POSIXError(.ENOTSUP) }
}
final class StallionItem: FSItem {
    let inode: UInt64
    init(_ inode: UInt64) { self.inode = inode; super.init() }
}

final class StallionVolume: FSVolume, FSVolume.Operations, FSVolume.ReadWriteOperations,
    FSVolume.XattrOperations, FSVolume.OpenCloseHandler, FSVolume.AccessCheckHandler, @unchecked Sendable {
    enum State: Int { case inactive, active, mounted, terminal }
    struct ParentEvidence { var core: UInt64?; var mapped: UInt64? }
    enum EnumerationStop: UInt64 { case eof = 1, refused = 2, error = 3 }
    struct Record {
        let sequence: UInt64, operation: UInt64, inode: UInt64, mask: UInt64, allocation: UInt64
        let uid: Int64, error: Int64, state: Int64
        let cookie: UInt64, verifier: UInt64, returnedVerifier: UInt64, acceptedCookie: UInt64, stop: UInt64
        let coreParent: UInt64, coreParentValid: UInt64, mappedParent: UInt64, mappedParentValid: UInt64
        let accepted: Int64, reclaim: Int64
    }
    let queue: DispatchQueue
    private var handle: OpaquePointer?
    private let resource: FSPathURLResource
    private var scope: Bool
    let owner: uid_t
    let anchor: sfs_result
    private var state = State.inactive
    private var failure: Error?
    private var items: [UInt64: StallionItem] = [:]
    private var nonce: [UInt8] = []
    private var records: [Record] = []
    private var sequence: UInt64 = 0
    private var overflow = false
    private var emitted = false
    init(handle: OpaquePointer, resource: FSPathURLResource, scope: Bool, anchor: sfs_result, queue: DispatchQueue) {
        self.handle = handle; self.resource = resource; self.scope = scope; self.anchor = anchor
        self.queue = queue; owner = geteuid()
        let bytes = FixtureIdentity.uuid
        let uuid = UUID(uuid: (bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5],bytes[6],bytes[7],bytes[8],bytes[9],bytes[10],bytes[11],bytes[12],bytes[13],bytes[14],bytes[15]))
        super.init(volumeID: .init(uuid: uuid), volumeName: FSFileName(string: "SFS read-only experiment"))
        records.reserveCapacity(4096); record(0)
    }
    func enqueue(_ block: @escaping () -> Void) { queue.async(execute: DispatchWorkItem(block: block)) }
    private func record(_ op: UInt64, _ inode: UInt64 = 0, mask: UInt64 = 0, allocation: UInt64 = 0, uid: Int64 = -1, error: Error? = nil,
                        cookie: UInt64 = 0, verifier: UInt64 = 0, returnedVerifier: UInt64 = 0,
                        acceptedCookie: UInt64 = 0, stop: UInt64 = 0,
                        parents: ParentEvidence = ParentEvidence(), accepted: Int64 = -1, reclaim: Int64 = -1) {
        guard !emitted else { return }
        sequence &+= 1
        guard records.count < 4096 else { overflow = true; return }
        records.append(Record(sequence: sequence, operation: op, inode: inode, mask: mask, allocation: allocation,
                              uid: uid, error: Int64((error as NSError?)?.code ?? 0), state: Int64(state.rawValue),
                              cookie: cookie, verifier: verifier, returnedVerifier: returnedVerifier, acceptedCookie: acceptedCookie, stop: stop,
                              coreParent: parents.core ?? 0, coreParentValid: parents.core == nil ? 0 : 1,
                              mappedParent: parents.mapped ?? 0, mappedParentValid: parents.mapped == nil ? 0 : 1,
                              accepted: accepted, reclaim: reclaim))
    }
    private func emit() {
        guard !emitted else { return }; emitted = true
        let logger = Logger(subsystem: "com.alvinhhh.stallionfs.private27.module", category: "experiment")
        for r in records {
            let line = "SFS06 r=\(r.sequence) op=\(r.operation) i=\(r.inode) m=\(r.mask) a=\(r.allocation) u=\(r.uid) e=\(r.error) s=\(r.state) c=\(r.cookie) v=\(r.verifier) rv=\(r.returnedVerifier) ac=\(r.acceptedCookie) stop=\(r.stop) cp=\(r.coreParent) cv=\(r.coreParentValid) mp=\(r.mappedParent) mv=\(r.mappedParentValid) pack=\(r.accepted) reclaim=\(r.reclaim)"
            logger.notice("\(line, privacy: .public)")
        }
        let end = "SFS06 end=\(sequence) count=\(records.count) overflow=\(overflow ? 1 : 0)"
        logger.notice("\(end, privacy: .public)")
    }
    private func latch(_ error: Error) { if failure == nil { failure = error } }
    private func check(_ status: sfs_status, _ result: sfs_result, missing: Int32 = ENOENT) throws {
        guard status == SFS_OK else {
            let error = sfsError(status, result, missing: missing)
            if [SFS_IO, SFS_CORRUPT, SFS_RECOVERY_REQUIRED, SFS_OUTCOME_UNKNOWN, SFS_POISONED].contains(status) { latch(error) }
            throw error
        }
        guard anchorMatches(result) else { let error = POSIXError(.EACCES); latch(error); throw error }
    }
    private func ready(mounted: Bool = false) throws -> OpaquePointer {
        if let failure { throw failure }
        guard !resource.isRevoked else { let error = POSIXError(.EACCES); latch(error); throw error }
        guard let handle, state == .active || state == .mounted, !mounted || state == .mounted else { throw POSIXError(.ENXIO) }
        return handle
    }
    private func id(_ item: FSItem) throws -> UInt64 {
        guard let own = item as? StallionItem, items[own.inode] === own else { throw POSIXError(.EINVAL) }
        return own.inode
    }
    private func canonical(_ inode: UInt64) -> StallionItem {
        if let item = items[inode] { return item }
        let item = StallionItem(inode); items[inode] = item; return item
    }
    private func metadata(_ inode: UInt64) throws -> sfs_metadata_entry {
        let h = try ready(); var m = sfs_metadata_entry(), r = sfs_result()
        try check(sfs_image_stat_metadata(h, 0, inode, &m, &r), r)
        guard let expected = FixtureIdentity.entries.first(where: { $0.inode == inode }),
            m.entry.inode == inode && m.link_count == expected.links && m.entry.kind.rawValue == expected.kind &&
            m.entry.parent == expected.parent && (inode == 1 ||
                Data(rawBytes(m.entry.name).prefix(m.entry.name_length)) == Data(expected.name.utf8)) else {
            let error = POSIXError(.EIO); latch(error); throw error
        }
        return m
    }
    private func checkedAlias(_ entry: sfs_entry, parent: UInt64) throws {
        let name = Data(rawBytes(entry.name).prefix(entry.name_length))
        guard entry.parent == parent && FixtureIdentity.names.contains(where: {
            $0.parent == parent && $0.inode == entry.inode && $0.kind == entry.kind.rawValue && Data($0.name.utf8) == name
        }) else { let error = POSIXError(.EIO); latch(error); throw error }
    }
    private func type(_ kind: sfs_kind) throws -> FSItem.ItemType {
        switch kind { case SFS_FILE: return .file; case SFS_DIRECTORY: return .directory; case SFS_SYMLINK: return .symlink; default: throw POSIXError(.EIO) }
    }
    private func attributes(_ inode: UInt64, _ request: FSItem.GetAttributesRequest, parents: inout ParentEvidence) throws -> FSItem.Attributes {
        let mask = request.wantedAttributes.rawValue; try validateWanted(mask)
        let m = try metadata(inode), a = FSItem.Attributes(); a.invalidateAllProperties()
        parents.core = m.entry.parent
        let links = try checkedLinks(m.link_count)
        if request.isAttributeWanted(.type) { a.type = try type(m.entry.kind) }
        if request.isAttributeWanted(.mode) { a.mode = m.mode }
        if request.isAttributeWanted(.linkCount) { a.linkCount = links }
        if request.isAttributeWanted(.uid) { a.uid = m.uid }
        if request.isAttributeWanted(.gid) { a.gid = m.gid }
        if request.isAttributeWanted(.flags) { a.flags = m.flags }
        if request.isAttributeWanted(.size) { a.size = m.entry.size }
        // shortcut: fixed-fixture allocation hypothesis, replace only after native observation review.
        if request.isAttributeWanted(.allocSize) { a.allocSize = m.referenced_data_bytes }
        if request.isAttributeWanted(.fileID) { a.fileID = try itemIdentifier(inode) }
        if request.isAttributeWanted(.parentID) { a.parentID = inode == 1 ? .parentOfRoot : try itemIdentifier(m.entry.parent) }
        if request.isAttributeWanted(.accessTime) { a.accessTime = try checkedTime(m.access) }
        if request.isAttributeWanted(.modifyTime) { a.modifyTime = try checkedTime(m.modification) }
        if request.isAttributeWanted(.changeTime) { a.changeTime = try checkedTime(m.change) }
        if request.isAttributeWanted(.birthTime) { a.birthTime = try checkedTime(m.birth) }
        if request.isAttributeWanted(.supportsLimitedXAttrs) { a.supportsLimitedXAttrs = false }
        if request.isAttributeWanted(.inhibitKernelOffloadedIO) { a.inhibitKernelOffloadedIO = true }
        if request.isAttributeWanted(.parentID) { parents.mapped = a.parentID.rawValue }
        return a
    }
    var maximumLinkCount: Int { Int(UInt32.max) }
    var maximumNameLength: Int { 255 }
    var restrictsOwnershipChanges: Bool { true }
    var truncatesLongNames: Bool { false }
    var maximumFileSize: UInt64 { UInt64(sfs_fskit_file_max()) }
    var maximumXattrSize: Int { Int(sfs_fskit_file_max()) }
    var isOpenCloseInhibited: Bool { false }
    var isAccessCheckInhibited: Bool { false }
    var requestedMountOptions: FSVolume.MountOptions { [.readOnly] }
    var supportedVolumeCapabilities: FSVolume.SupportedCapabilities {
        let c = FSVolume.SupportedCapabilities(); c.caseFormat = .sensitive
        c.supportsHardLinks = true; c.supportsSymbolicLinks = true; c.supportsSparseFiles = true
        c.supports64BitObjectIDs = true; c.supportsJournal = false; c.supportsActiveJournal = false
        c.doesNotSupportVolumeSizes = true; c.doesNotSupportSettingFilePermissions = true; c.doesNotSupportImmutableFiles = true
        return c
    }
    var volumeStatistics: FSStatFSResult {
        let s = FSStatFSResult(fileSystemTypeName: "sfsro27"); s.blockSize = 4096; s.ioSize = 4096; return s
    }
    func activate(options: FSTaskOptions, replyHandler: @escaping (FSItem?, Error?) -> Void) { activate(replyHandler: replyHandler) }
    func activate(replyHandler: @escaping (FSItem?, Error?) -> Void) { enqueue {
        let previous = self.state
        do {
            if let failure = self.failure { throw failure }
            guard self.state != .terminal && self.handle != nil else { throw POSIXError(.ENXIO) }
            if self.state == .inactive { self.state = .active }
            _ = try self.metadata(1); let root = self.canonical(1); self.record(1); replyHandler(root, nil)
        } catch { if previous == .inactive { self.state = .inactive }; self.record(1, error: error); replyHandler(nil, error) }
    } }
    func mount(options: FSTaskOptions, replyHandler: @escaping (Error?) -> Void) { mount(arguments: options.taskOptions, replyHandler: replyHandler) }
    func mount(arguments: [String], replyHandler: @escaping (Error?) -> Void) { enqueue {
        do {
            guard !arguments.contains("-f") else { throw POSIXError(.ENOTSUP) }
            guard self.state != .inactive else { throw POSIXError(.EINVAL) }
            _ = try self.ready()
            if self.state != .mounted {
                var bytes = [UInt8](repeating: 0, count: 16)
                guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw POSIXError(.EIO) }
                self.nonce = bytes; self.state = .mounted
            }
            self.record(2); replyHandler(nil)
        } catch { self.record(2, error: error); replyHandler(error) }
    } }
    func unmount(replyHandler: @escaping () -> Void) { enqueue {
        self.nonce.removeAll(keepingCapacity: false)
        sfs_image_clear_read_cache(self.handle)
        if self.state == .mounted { self.state = .active }
        self.record(3, error: self.failure); replyHandler()
    } }
    func deactivate(options: FSDeactivateOptions, replyHandler: @escaping (Error?) -> Void) { enqueue {
        let error = self.failure ?? (self.state == .mounted ? POSIXError(.EBUSY) : nil)
        if error == nil && self.state != .terminal { self.state = .inactive }
        self.record(4, error: error); replyHandler(error)
    } }
    func synchronize(flags: FSSyncFlags, replyHandler: @escaping (Error?) -> Void) { enqueue {
        self.record(5, error: self.failure); replyHandler(self.failure)
    } }
    // The unary owner calls this on the same queue; close consumes even on error.
    func unload() -> Error? {
        if state == .terminal { return failure }
        state = .terminal; nonce.removeAll(); let owned = handle; handle = nil
        if let owned { var r = sfs_result(); let status = sfs_image_close(owned, &r); if status != SFS_OK { latch(sfsError(status, r)) } }
        if scope { scope = false; resource.url.stopAccessingSecurityScopedResource() }
        items.removeAll(); record(6, error: failure); emit(); return failure
    }
    func getAttributes(_ request: FSItem.GetAttributesRequest, of item: FSItem, replyHandler: @escaping (FSItem.Attributes?, Error?) -> Void) { enqueue {
        var parents = ParentEvidence(), inode: UInt64 = 0
        let mask = UInt64(bitPattern: Int64(request.wantedAttributes.rawValue))
        do {
            inode = try self.id(item); let a = try self.attributes(inode, request, parents: &parents)
            self.record(10, inode, mask: mask, allocation: request.isAttributeWanted(.allocSize) ? a.allocSize : 0, parents: parents)
            replyHandler(a, nil)
        } catch { parents.mapped = nil; self.record(10, inode, mask: mask, error: error, parents: parents); replyHandler(nil, error) }
    } }
    func lookupItem(named name: FSFileName, inDirectory directory: FSItem, replyHandler: @escaping (FSItem?, FSFileName?, Error?) -> Void) { enqueue {
        do {
            let parent = try self.id(directory), m = try self.metadata(parent)
            guard m.entry.kind == SFS_DIRECTORY else { throw POSIXError(.ENOTDIR) }
            try component(name.data); let inode: UInt64; let returned: FSFileName
            if name.data == Data(".".utf8) { inode = parent; returned = name }
            else if name.data == Data("..".utf8) { inode = parent == 1 ? 1 : m.entry.parent; returned = name }
            else {
                var e = sfs_entry(), r = sfs_result(); let h = try self.ready()
                let status = name.data.withUnsafeBytes { sfs_image_lookup(h, 0, parent, $0.baseAddress, $0.count, &e, &r) }
                try self.check(status, r); inode = e.inode
                guard e.parent == parent && e.name_length == name.data.count && Data(rawBytes(e.name).prefix(e.name_length)) == name.data else { let error = POSIXError(.EIO); self.latch(error); throw error }
                try self.checkedAlias(e, parent: parent)
                returned = FSFileName(data: Data(rawBytes(e.name).prefix(e.name_length)))
            }
            _ = try self.metadata(inode); self.record(11, inode); replyHandler(self.canonical(inode), returned, nil)
        } catch { self.record(11, error: error); replyHandler(nil, nil, error) }
    } }
    func reclaimItem(_ item: FSItem, replyHandler: @escaping (Error?) -> Void) { enqueue {
        do {
            let inode = try self.id(item)
            let eligible = item.tryReclaim { if inode != 1 && self.items[inode] === item { self.items.removeValue(forKey: inode) } }
            self.record(12, inode, reclaim: eligible ? 1 : 0); replyHandler(nil)
        } catch { self.record(12, error: error); replyHandler(error) }
    } }
    func readSymbolicLink(_ item: FSItem, replyHandler: @escaping (FSFileName?, Error?) -> Void) { enqueue {
        do {
            let inode = try self.id(item); _ = try self.ready(mounted: true)
            let m = try self.metadata(inode); guard m.entry.kind == SFS_SYMLINK else { throw POSIXError(.EINVAL) }
            var bytes = [UInt8](repeating: 0, count: 4096), count = 0, r = sfs_result(); let h = try self.ready()
            let status = sfs_image_readlink(h, 0, inode, &bytes, bytes.count, &count, &r)
            if status == SFS_LIMIT { throw POSIXError(.EIO) }; try self.check(status, r)
            guard count > 0 && count <= bytes.count && !bytes.prefix(count).contains(0) else { throw POSIXError(.EIO) }
            self.record(13, inode); replyHandler(FSFileName(data: Data(bytes.prefix(count))), nil)
        } catch { self.record(13, error: error); replyHandler(nil, error) }
    } }
    private func directoryVerifier(_ parent: UInt64, attributes: Bool) throws -> UInt64 {
        guard nonce.count == 16 else { throw POSIXError(.ENXIO) }
        var bytes = Data("SFS-RO27-DIR-V2".utf8); bytes.append(contentsOf: nonce)
        bytes.append(contentsOf: FixtureIdentity.uuid)
        var generation = anchor.generation.bigEndian
        withUnsafeBytes(of: &generation) { bytes.append(contentsOf: $0) }
        bytes.append(contentsOf: FixtureIdentity.digest)
        var view: UInt64 = 0
        withUnsafeBytes(of: &view) { bytes.append(contentsOf: $0) }
        var directory = parent.bigEndian
        withUnsafeBytes(of: &directory) { bytes.append(contentsOf: $0) }
        bytes.append(attributes ? 1 : 0)
        let hash = SHA256.hash(data: bytes), value = hash.prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        return ((value & 0x3fff_ffff_ffff_ffff) << 1) | 0x8000_0000_0000_0000 | (attributes ? 1 : 0)
    }
    typealias DirectoryPack = (FSFileName, FSItem.ItemType, FSItem.Identifier, FSDirectoryCookie, FSItem.Attributes?) -> Bool
    func enumerateDirectory(_ directory: FSItem, startingAt cookie: FSDirectoryCookie,
                            verifier: FSDirectoryVerifier, attributes request: FSItem.GetAttributesRequest?,
                            packer: FSDirectoryEntryPacker, replyHandler: @escaping (FSDirectoryVerifier, Error?) -> Void) {
        enumerateDirectory(directory, startingAt: cookie, verifier: verifier, attributes: request, pack: {
            packer.packEntry(name: $0, itemType: $1, itemID: $2, nextCookie: $3, attributes: $4)
        }, replyHandler: replyHandler)
    }
    // Both callers enter the same serialized body; the packing closure is synchronous.
    func enumerateDirectory(_ directory: FSItem, startingAt cookie: FSDirectoryCookie,
                            verifier: FSDirectoryVerifier, attributes request: FSItem.GetAttributesRequest?,
                            pack: @escaping DirectoryPack, replyHandler: @escaping (FSDirectoryVerifier, Error?) -> Void) { enqueue {
        var returned: UInt64 = 0, accepted: UInt64 = 0, parent: UInt64 = 0
        let mask = UInt64(bitPattern: Int64(request?.wantedAttributes.rawValue ?? 0))
        func finish(_ reason: EnumerationStop, _ error: Error? = nil) {
            self.record(14, parent, mask: mask, error: error, cookie: cookie.rawValue, verifier: verifier.rawValue,
                        returnedVerifier: returned, acceptedCookie: accepted, stop: reason.rawValue)
            replyHandler(FSDirectoryVerifier(returned), error)
        }
        do {
            try validateDirectoryLayout(FSDirectoryCookie.initial.rawValue, FSDirectoryVerifier.initial.rawValue)
            let h = try self.ready(mounted: true); parent = try self.id(directory)
            let m = try self.metadata(parent)
            guard m.entry.kind == SFS_DIRECTORY else { throw POSIXError(.ENOTDIR) }
            if let request { try validateWanted(request.wantedAttributes.rawValue) }
            returned = try self.directoryVerifier(parent, attributes: request != nil)
            let start = cookie.rawValue
            guard (start == FSDirectoryCookie.initial.rawValue &&
                   (verifier == FSDirectoryVerifier.initial || verifier.rawValue == returned)) ||
                (start != FSDirectoryCookie.initial.rawValue && verifier.rawValue == returned) else { throw FSError(.invalidDirectoryCookie) }
            guard !(3...16).contains(start) && (request == nil || (start != 1 && start != 2)) else { throw FSError(.invalidDirectoryCookie) }
            if request == nil && start < 2 {
                for dot in (Int(start) + 1)...2 {
                    let inode = dot == 1 ? parent : parent == 1 ? 1 : m.entry.parent
                    let packed = pack(FSFileName(string: dot == 1 ? "." : ".."), .directory,
                                      try itemIdentifier(inode), FSDirectoryCookie(UInt64(dot)), nil)
                    self.record(22, inode, accepted: packed ? 1 : 0)
                    guard packed else { finish(.refused); return }; accepted = UInt64(dot)
                }
            }
            var cursor = sfs_cookie(), r = sfs_result()
            if start > 2 {
                let status = FixtureIdentity.digest.withUnsafeBufferPointer {
                    sfs_image_resume_after_position(h, 0, self.anchor.generation, $0.baseAddress, parent, start, &cursor, &r)
                }
                if [SFS_INVALID, SFS_NOT_FOUND, SFS_STATE].contains(status) { throw FSError(.invalidDirectoryCookie) }
                try self.check(status, r)
            }
            let bound = FixtureIdentity.names.filter { $0.parent == parent }.count
            for _ in 0...bound {
                var e = sfs_entry(), found: Int32 = 0, position: UInt64 = 0
                let status = sfs_image_next_position(h, 0, parent, &cursor, &e, &position, &found, &r)
                try self.check(status, r)
                if found == 0 { finish(.eof); return }
                try self.checkedAlias(e, parent: parent)
                var parents = ParentEvidence()
                do {
                    let attrs = try request.map { try self.attributes(e.inode, $0, parents: &parents) }
                    let packed = pack(FSFileName(data: Data(rawBytes(e.name).prefix(e.name_length))),
                                      try self.type(e.kind), try itemIdentifier(e.inode), FSDirectoryCookie(position), attrs)
                    self.record(22, e.inode, mask: mask, allocation: request?.isAttributeWanted(.allocSize) == true ? attrs!.allocSize : 0,
                                parents: parents, accepted: packed ? 1 : 0)
                    guard packed else { finish(.refused); return }; accepted = position
                } catch {
                    parents.mapped = nil; self.record(22, e.inode, mask: mask, error: error, parents: parents)
                    throw error
                }
            }
            let error = POSIXError(.EIO); self.latch(error); throw error
        } catch { finish(.error, error) }
    } }
#if STALLION_ADAPTER_CHECK
    func capturedRecords() -> [Record] { records }
#endif
    func openItem(_ item: FSItem, modes: FSVolume.OpenModes, context: FSContext, replyHandler: @escaping @Sendable (Error?) -> Void) { enqueue {
        do {
            _ = try self.ready(mounted: true); let inode = try self.id(item), m = try self.metadata(inode)
            guard context.effectiveUserID == Int(self.owner) else { throw POSIXError(.EACCES) }
            if modes.contains(.write) { throw POSIXError(.EROFS) }
            guard modes == .read && m.entry.kind == SFS_FILE else { throw POSIXError(.EINVAL) }
            self.record(15, inode, mask: UInt64(modes.rawValue), uid: Int64(context.effectiveUserID)); replyHandler(nil)
        } catch { self.record(15, mask: UInt64(modes.rawValue), uid: Int64(context.effectiveUserID), error: error); replyHandler(error) }
    } }
    func closeItem(_ item: FSItem, modes: FSVolume.OpenModes, context: FSContext, replyHandler: @escaping @Sendable (Error?) -> Void) { enqueue {
        do {
            _ = try self.ready(); let inode = try self.id(item)
            guard context.effectiveUserID == Int(self.owner) else { throw POSIXError(.EACCES) }
            guard modes.isEmpty || modes == .read else { throw POSIXError(.EROFS) }
            self.record(16, inode, mask: UInt64(modes.rawValue), uid: Int64(context.effectiveUserID)); replyHandler(nil)
        } catch { self.record(16, uid: Int64(context.effectiveUserID), error: error); replyHandler(error) }
    } }
    func checkAccess(to item: FSItem, requestedAccess access: FSVolume.AccessMask, context: FSContext,
                     replyHandler: @escaping @Sendable (FSCheckAccessResult?, Error?) -> Void) { enqueue {
        do {
            let inode = try self.id(item), m = try self.metadata(inode)
            var allowed: FSVolume.AccessMask = [.readData, .readAttributes, .readXattr]
            if m.entry.kind == SFS_DIRECTORY { allowed.insert(.search) }
            guard context.effectiveUserID == Int(self.owner) && access.subtracting(allowed).isEmpty else { throw POSIXError(.EACCES) }
            guard let result = FSCheckAccessResult(accessAllowed: true) else { throw POSIXError(.EIO) }
            self.record(17, inode, mask: UInt64(access.rawValue), uid: Int64(context.effectiveUserID)); replyHandler(result, nil)
        } catch { self.record(17, mask: UInt64(access.rawValue), uid: Int64(context.effectiveUserID), error: error); replyHandler(nil, error) }
    } }
    func read(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer,
              replyHandler: @escaping (Int, Error?) -> Void) { enqueue {
        var count = 0
        do {
            let h = try self.ready(mounted: true), inode = try self.id(item), m = try self.metadata(inode)
            guard m.entry.kind == SFS_FILE && offset >= 0 && length >= 0 else { throw POSIXError(.EINVAL) }
            var r = sfs_result()
            let status = try buffer.withUnsafeMutableBytes { bytes -> sfs_status in
                guard length <= bytes.count else { throw POSIXError(.EINVAL) }
                return sfs_image_read(h, 0, inode, UInt64(offset), bytes.baseAddress, length, &count, &r)
            }
            guard count >= 0 && count <= length else { count = 0; throw POSIXError(.EIO) }
            try self.check(status, r); self.record(18, inode); replyHandler(count, nil)
        } catch { self.record(18, error: error); replyHandler(count, error) }
    } }
    func getXattr(named name: FSFileName, of item: FSItem, replyHandler: @escaping (Data?, Error?) -> Void) { enqueue {
        do {
            let h = try self.ready(mounted: true), inode = try self.id(item); _ = try self.metadata(inode); try component(name.data, xattr: true)
            var size: UInt64 = 0, r = sfs_result()
            let status = name.data.withUnsafeBytes { sfs_image_xattr_size(h, 0, inode, $0.baseAddress, $0.count, &size, &r) }
            try self.check(status, r, missing: ENOATTR)
            guard let length = Int(exactly: size) else { throw POSIXError(.E2BIG) }
            if length == 0 { self.record(19, inode); replyHandler(Data(), nil); return }
            guard let memory = malloc(length) else { throw POSIXError(.ENOMEM) }
            var transferred = false; defer { if !transferred { free(memory) } }
            var count = 0
            let readStatus = name.data.withUnsafeBytes { sfs_image_read_xattr(h, 0, inode, $0.baseAddress, $0.count, 0, memory, length, &count, &r) }
            if readStatus == SFS_LIMIT { throw POSIXError(.ERANGE) }; try self.check(readStatus, r, missing: ENOATTR)
            guard count == length else { throw POSIXError(.EIO) }
            let value = Data(bytesNoCopy: memory, count: count, deallocator: .free); transferred = true
            self.record(19, inode); replyHandler(value, nil)
        } catch { self.record(19, error: error); replyHandler(nil, error) }
    } }
    func listXattrs(of item: FSItem, replyHandler: @escaping ([FSFileName]?, Error?) -> Void) { enqueue {
        do {
            let h = try self.ready(mounted: true), inode = try self.id(item); _ = try self.metadata(inode)
            var names: [FSFileName] = [], after = Data(), total = 0, r = sfs_result()
            while true {
                var entry = sfs_xattr_entry(), found: Int32 = 0
                let status = FixtureIdentity.digest.withUnsafeBufferPointer { digest in after.withUnsafeBytes {
                    sfs_image_next_xattr(h, 0, self.anchor.generation, digest.baseAddress, inode,
                        after.isEmpty ? nil : $0.baseAddress, $0.count, &entry, &found, &r)
                } }
                try self.check(status, r); if found == 0 { break }
                guard entry.name_length > 0 && entry.name_length <= 255 else { throw POSIXError(.EIO) }
                let next = Data(rawBytes(entry.name).prefix(entry.name_length)); try component(next, xattr: true)
                guard after.isEmpty || after.lexicographicallyPrecedes(next) else { throw POSIXError(.EIO) }
                let (newTotal, overflow) = total.addingReportingOverflow(next.count + 1)
                guard !overflow else { throw POSIXError(.E2BIG) }; total = newTotal
                names.append(FSFileName(data: next)); after = next
            }
            self.record(20, inode); replyHandler(names, nil)
        } catch { self.record(20, error: error); replyHandler(nil, error) }
    } }
    private func refuse(_ reply: @escaping (Error) -> Void) { enqueue { let error = POSIXError(.EROFS); self.record(21, error: error); reply(error) } }
    func setAttributes(_ attributes: FSItem.SetAttributesRequest, on item: FSItem, replyHandler: @escaping (FSItem.Attributes?, Error?) -> Void) { refuse { replyHandler(nil, $0) } }
    func createItem(named name: FSFileName, type: FSItem.ItemType, inDirectory directory: FSItem, attributes: FSItem.SetAttributesRequest, replyHandler: @escaping (FSItem?, FSFileName?, Error?) -> Void) { refuse { replyHandler(nil, nil, $0) } }
    func createSymbolicLink(named name: FSFileName, inDirectory directory: FSItem, attributes: FSItem.SetAttributesRequest, linkContents: FSFileName, replyHandler: @escaping (FSItem?, FSFileName?, Error?) -> Void) { refuse { replyHandler(nil, nil, $0) } }
    func createLink(to item: FSItem, named name: FSFileName, inDirectory directory: FSItem, replyHandler: @escaping (FSFileName?, Error?) -> Void) { refuse { replyHandler(nil, $0) } }
    func removeItem(_ item: FSItem, named name: FSFileName, fromDirectory directory: FSItem, replyHandler: @escaping (Error?) -> Void) { refuse { replyHandler($0) } }
    func renameItem(_ item: FSItem, inDirectory sourceDirectory: FSItem, named sourceName: FSFileName, to destinationName: FSFileName, inDirectory destinationDirectory: FSItem, overItem: FSItem?, replyHandler: @escaping (FSFileName?, Error?) -> Void) { refuse { replyHandler(nil, $0) } }
    func write(contents: Data, to item: FSItem, at offset: off_t, replyHandler: @escaping (Int, Error?) -> Void) { refuse { replyHandler(0, $0) } }
    func setXattr(named name: FSFileName, to value: Data?, on item: FSItem, policy: FSVolume.SetXattrPolicy, replyHandler: @escaping (Error?) -> Void) { refuse { replyHandler($0) } }
}
