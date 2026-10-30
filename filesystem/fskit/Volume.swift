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
    case SFS_EXISTS: code = EEXIST
    case SFS_INVALID: code = EINVAL
    case SFS_BUSY: code = EBUSY
    case SFS_UNSUPPORTED: code = ENOTSUP
    case SFS_NOMEM: code = ENOMEM
    // Read callbacks translate their known buffer limits at the call site.
    // An unspecified core limit does not establish a file-size failure.
    case SFS_LIMIT:
        code = result.limit_reason == SFS_LIMIT_APPEND_CAPACITY ? ENOSPC :
            result.limit_reason == SFS_LIMIT_FILE_SIZE ? EFBIG : EOVERFLOW
    case SFS_IO, SFS_OUTCOME_UNKNOWN, SFS_TIME_UNAVAILABLE:
        code = result.system_errno > 0 ? result.system_errno : EIO
    default: code = EIO
    }
    return NSError(domain: NSPOSIXErrorDomain, code: Int(code))
}
func rawBytes<T>(_ tuple: T) -> [UInt8] { withUnsafeBytes(of: tuple) { Array($0) } }
func anchorMatches(_ result: sfs_result, _ anchor: sfs_result) -> Bool {
    rawBytes(result.uuid) == rawBytes(anchor.uuid) && result.device == anchor.device && result.inode == anchor.inode &&
    result.generation == anchor.generation && result.committed_end == anchor.committed_end &&
    rawBytes(result.root_digest) == rawBytes(anchor.root_digest)
}
enum ReadOnlyLimits {
    static let xattrValue = 1024 * 1024
    static let xattrListBytes = 64 * 1024
    static let xattrListCount = 1024
    static let activeItems = 4096
    static let callbacks = 256
    static let retainedBytes = 8 * 1024 * 1024
    static let callbackOverhead = 4096
}
// Admission happens on the caller's thread before a DispatchWorkItem exists.
// The charge includes payload bytes plus a conservative per-callback allowance;
// it is an adapter budget, not a bound on opaque FSKit/kernel allocations.
final class CallbackBudget: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0, bytes = 0
    func acquire(_ payload: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard payload >= 0, payload <= ReadOnlyLimits.retainedBytes - ReadOnlyLimits.callbackOverhead else { return false }
        let charge = payload + ReadOnlyLimits.callbackOverhead
        guard count < ReadOnlyLimits.callbacks, charge <= ReadOnlyLimits.retainedBytes - bytes else { return false }
        count += 1; bytes += charge; return true
    }
    func release(_ payload: Int) {
        lock.lock(); defer { lock.unlock() }
        count -= 1; bytes -= payload + ReadOnlyLimits.callbackOverhead
        precondition(count >= 0 && bytes >= 0)
    }
    var isEmpty: Bool {
        lock.lock(); defer { lock.unlock() }
        return count == 0
    }
}
func checkedXattrLength(_ size: UInt64) throws -> Int {
    guard size <= UInt64(ReadOnlyLimits.xattrValue) else { throw POSIXError(.E2BIG) }
    return Int(size)
}
func checkedXattrListTotal(_ total: Int, count: Int, next: Int) throws -> Int {
    guard count < ReadOnlyLimits.xattrListCount, next > 0,
        next < ReadOnlyLimits.xattrListBytes, total <= ReadOnlyLimits.xattrListBytes - next - 1 else { throw POSIXError(.E2BIG) }
    return total + next + 1
}
func checkOwnerMode(_ m: sfs_metadata_entry, owner: uid_t, uid: Int, access: FSVolume.AccessMask) throws {
    guard uid == Int(owner) && m.uid == owner else { throw POSIXError(.EACCES) }
    var allowed: FSVolume.AccessMask = [.readAttributes]
    if m.mode & 0o400 != 0 { allowed.formUnion([.readData, .readXattr]) }
    if m.entry.kind == SFS_DIRECTORY && m.mode & 0o100 != 0 { allowed.insert(.search) }
    guard access.subtracting(allowed).isEmpty else { throw POSIXError(.EACCES) }
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
#if STALLION_WRITE_DIAGNOSTIC
    var retainedModes: FSVolume.OpenModes = []
#endif
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
    private enum Admission { case open, draining, unmounted, terminal }
    private let submissionLock = NSLock()
    private var admission = Admission.open
    private var pendingUnmountReplies = 0
    private var handle: OpaquePointer?
    private let resource: FSPathURLResource
    private var scope: Bool
    let owner: uid_t
    private(set) var anchor: sfs_result
#if STALLION_WRITE_DIAGNOSTIC
    // Only the private diagnostic build can enable writing; even it defaults RO.
    private(set) var diagnosticWritable = false
    struct DeliveryFailure {
        let code: Int, sequence: UInt64, durableGeneration: UInt64
        let result: sfs_result
        var error: Error { NSError(domain: NSPOSIXErrorDomain, code: code) }
    }
    struct WriteRecord {
        let sequence: UInt64, operation: UInt64, inode: UInt64, offset: UInt64, length: UInt64, mask: UInt64
        let started: UInt64, finished: UInt64, generation: UInt64
        let count: Int, code: Int, result: sfs_result
    }
    struct WriteCounters {
        var callbacks: UInt64 = 0, bytes: UInt64 = 0, chunks: UInt64 = 0, commits: UInt64 = 0
        var writes: UInt64 = 0, resizes: UInt64 = 0, deliveredBytes: UInt64 = 0
        var recordFences: UInt64 = 0, recordSuccess: UInt64 = 0, commitFences: UInt64 = 0, commitSuccess: UInt64 = 0
        var refused: UInt64 = 0, syncs: UInt64 = 0, overflow = false
    }
    private var deliveryFailure: DeliveryFailure?
    private var lastCoreFailure: sfs_result?
    private var diagnosticSequence: UInt64 = 0
    private var diagnosticTraceSequence: UInt64 = 0
    private var diagnosticDurable: UInt64 = 0
    private var writeCounters = WriteCounters()
    private var writeRecords: [WriteRecord] = []
    private func controlRecordLocked(_ operation: UInt64, inode: UInt64 = 0, mask: UInt64, error: Error?, entry: Bool = false) {
        guard writeRecords.count < 4096 else { writeCounters.overflow = true; return }
        saturated(&diagnosticTraceSequence)
        let now = DispatchTime.now().uptimeNanoseconds
        writeRecords.append(WriteRecord(sequence: diagnosticTraceSequence, operation: (entry ? 2000 : 1000) + operation,
            inode: inode, offset: 0, length: 0, mask: mask, started: now, finished: now,
            generation: diagnosticDurable, count: 0, code: (error as NSError?)?.code ?? 0,
            result: deliveryFailure?.result ?? sfs_result()))
    }
    private func controlEntry(_ operation: UInt64, item: FSItem, mask: UInt64 = 0) {
        guard diagnosticWritable else { return }
        submissionLock.lock()
        controlRecordLocked(operation, inode: (item as? StallionItem)?.inode ?? 0, mask: mask, error: nil, entry: true)
        submissionLock.unlock()
    }
    // All diagnostic counters/first-error state use submissionLock; the trace
    // stores at most 4096 fixed records, with no paths, names or file bytes.
    private func saturated(_ value: inout UInt64, by amount: UInt64 = 1) {
        let (next, overflow) = value.addingReportingOverflow(amount)
        value = overflow ? UInt64.max : next
    }
    private func deliveryError() -> Error? {
        submissionLock.lock(); defer { submissionLock.unlock() }; return deliveryFailure?.error
    }
    private func rememberDeliveryLocked(_ error: Error, _ result: sfs_result = sfs_result()) {
        if deliveryFailure == nil {
            // A first-error observation has its own sequence, independent of
            // how many later callbacks were already admitted while it ran.
            saturated(&diagnosticSequence)
            deliveryFailure = DeliveryFailure(code: (error as NSError).code, sequence: diagnosticSequence,
                durableGeneration: diagnosticDurable, result: result)
        }
    }
    private func rememberDelivery(_ error: Error, _ result: sfs_result = sfs_result()) {
        submissionLock.lock(); rememberDeliveryLocked(error, result); submissionLock.unlock()
    }
    func enableWriteDiagnostic(expectedUUID: UUID) throws {
        guard state == .inactive, rawBytes(anchor.uuid) == withUnsafeBytes(of: expectedUUID.uuid, { Array($0) }),
              resource.isWritable && !resource.isRevoked else { throw POSIXError(.EACCES) }
        diagnosticWritable = true; diagnosticDurable = anchor.generation; writeRecords.reserveCapacity(4096)
    }
    func diagnosticSnapshot() -> (WriteCounters, [WriteRecord], DeliveryFailure?) {
        submissionLock.lock(); defer { submissionLock.unlock() }
        if [diagnosticSequence, diagnosticTraceSequence, writeCounters.callbacks, writeCounters.bytes,
            writeCounters.writes, writeCounters.resizes, writeCounters.deliveredBytes,
            writeCounters.chunks, writeCounters.commits, writeCounters.recordFences, writeCounters.recordSuccess,
            writeCounters.commitFences, writeCounters.commitSuccess, writeCounters.refused, writeCounters.syncs].contains(UInt64.max) {
            writeCounters.overflow = true
        }
        return (writeCounters, writeRecords, deliveryFailure)
    }
#if STALLION_ADAPTER_CHECK
    var diagnosticBeforeCommit: (() -> Void)?
    var diagnosticAfterChunk: ((Int) -> Void)?
    var diagnosticAfterSizeCommit: (() -> Void)?
    func diagnosticCloseForTesting(_ item: FSItem) { (item as? StallionItem)?.retainedModes = [] }
#endif
#endif
    private let callbacks = CallbackBudget()
    private let itemLimit: Int
#if STALLION_ADAPTER_CHECK
    private(set) var xattrAllocations = 0
#endif
    private var state = State.inactive
    private var failure: Error?
    private var items: [UInt64: StallionItem] = [:]
    private var nonce: [UInt8] = []
    private var records: [Record] = []
    private var sequence: UInt64 = 0
    private var overflow = false
    private var emitted = false
    init(handle: OpaquePointer, resource: FSPathURLResource, scope: Bool, anchor: sfs_result, queue: DispatchQueue,
         itemLimit: Int = ReadOnlyLimits.activeItems) {
        precondition(itemLimit > 0 && itemLimit <= ReadOnlyLimits.activeItems)
        self.itemLimit = itemLimit
        self.handle = handle; self.resource = resource; self.scope = scope; self.anchor = anchor
        self.queue = queue; owner = geteuid()
        let bytes = rawBytes(anchor.uuid)
        let uuid = UUID(uuid: (bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5],bytes[6],bytes[7],bytes[8],bytes[9],bytes[10],bytes[11],bytes[12],bytes[13],bytes[14],bytes[15]))
        super.init(volumeID: .init(uuid: uuid), volumeName: FSFileName(string: "StallionFS"))
        records.reserveCapacity(4096); record(0)
    }
    func enqueue(retainedBytes: Int = 0, maintenance: Bool = false,
                 dataOperation: Bool = false, writeOperation: Bool = false,
                 syncOperation: Bool = false, syncFlags: UInt64 = 0, validationError: Error? = nil,
                 rejected: (Error) -> Void, _ block: @escaping () -> Void) {
        submissionLock.lock()
        var error: Error?
        if let validationError { error = validationError }
        else if admission == .terminal { error = POSIXError(.ENXIO) }
        else if !maintenance && admission != .open { error = POSIXError(admission == .draining ? .EAGAIN : .ENXIO) }
        else if !callbacks.acquire(retainedBytes) { error = POSIXError(.EAGAIN) }
        else { error = nil }
#if STALLION_WRITE_DIAGNOSTIC
        if diagnosticWritable {
            if syncOperation {
                saturated(&writeCounters.syncs); controlRecordLocked(5, mask: syncFlags, error: nil, entry: true)
            }
            if dataOperation {
                saturated(&diagnosticSequence); saturated(&writeCounters.callbacks)
                if writeOperation {
                    saturated(&writeCounters.writes); saturated(&writeCounters.deliveredBytes, by: UInt64(retainedBytes))
                } else { saturated(&writeCounters.resizes) }
            }
            // A previous delivery failure blocks mutation without consuming a
            // ticket. Undo a successful reservation before rejecting it.
            if dataOperation, let first = deliveryFailure, error == nil {
                callbacks.release(retainedBytes); error = first.error
            }
            if let rejectedError = error, dataOperation {
                saturated(&writeCounters.refused); rememberDeliveryLocked(rejectedError)
            }
            if syncOperation, let first = deliveryFailure {
                if error == nil { callbacks.release(retainedBytes) }
                error = first.error
            }
            if syncOperation, let error { controlRecordLocked(5, mask: syncFlags, error: error) }
        }
#endif
        guard error == nil else { submissionLock.unlock(); rejected(error!); return }
        // Reservation and submission are atomic against the unmount cutoff.
        queue.async(execute: DispatchWorkItem { defer { self.callbacks.release(retainedBytes) }; block() })
        submissionLock.unlock()
    }
#if STALLION_ADAPTER_CHECK
    func enqueue(_ block: @escaping () -> Void) { queue.async(execute: DispatchWorkItem(block: block)) }
#endif
    private func record(_ op: UInt64, _ inode: UInt64 = 0, mask: UInt64 = 0, allocation: UInt64 = 0, uid: Int64 = -1, error: Error? = nil,
                        cookie: UInt64 = 0, verifier: UInt64 = 0, returnedVerifier: UInt64 = 0,
                        acceptedCookie: UInt64 = 0, stop: UInt64 = 0,
                        parents: ParentEvidence = ParentEvidence(), accepted: Int64 = -1, reclaim: Int64 = -1) {
#if STALLION_WRITE_DIAGNOSTIC
        if diagnosticWritable && [1, 2, 3, 4, 5, 6, 12, 15, 16].contains(op) {
            submissionLock.lock(); controlRecordLocked(op, inode: inode, mask: mask, error: error); submissionLock.unlock()
        }
#endif
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
#if STALLION_WRITE_DIAGNOSTIC
            if diagnosticWritable { lastCoreFailure = result }
#endif
            if result.poisoned != 0 || [SFS_IO, SFS_CORRUPT, SFS_RECOVERY_REQUIRED, SFS_OUTCOME_UNKNOWN, SFS_POISONED].contains(status) { latch(error) }
            throw error
        }
        guard anchorMatches(result, anchor) else { let error = POSIXError(.ESTALE); latch(error); throw error }
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
    private func canonical(_ inode: UInt64) throws -> StallionItem {
        if let item = items[inode] { return item }
        guard items.count < itemLimit else { throw POSIXError(.ENFILE) }
        let item = StallionItem(inode); items[inode] = item; return item
    }
    private func metadata(_ inode: UInt64) throws -> sfs_metadata_entry {
        let h = try ready(); var m = sfs_metadata_entry(), r = sfs_result()
        try check(sfs_image_stat_metadata(h, 0, inode, &m, &r), r)
        guard m.entry.inode == inode && m.link_count > 0 else {
            let error = POSIXError(.EIO); latch(error); throw error
        }
        return m
    }
    private func checkedAlias(_ entry: sfs_entry, parent: UInt64) throws {
        let name = Data(rawBytes(entry.name).prefix(entry.name_length))
        guard entry.parent == parent && entry.inode > 1 && entry.name_length <= 255 &&
            name != Data(".".utf8) && name != Data("..".utf8) else { let error = POSIXError(.EIO); latch(error); throw error }
        try component(name)
        _ = try type(entry.kind)
        // Core lookup/next_position checks exact name membership, including aliases.
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
        // Referenced data cells only: excludes metadata and xattrs, and can be shared.
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
    var maximumXattrSize: Int { ReadOnlyLimits.xattrValue }
    var isOpenCloseInhibited: Bool { false }
    var isAccessCheckInhibited: Bool { false }
    var requestedMountOptions: FSVolume.MountOptions {
#if STALLION_WRITE_DIAGNOSTIC
        if diagnosticWritable { return [] }
#endif
        return [.readOnly]
    }
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
    func activate(replyHandler: @escaping (FSItem?, Error?) -> Void) { enqueue(maintenance: true, rejected: { replyHandler(nil, $0) }) {
        let previous = self.state
        do {
            if let failure = self.failure { throw failure }
            guard self.state != .terminal && self.handle != nil else { throw POSIXError(.ENXIO) }
            if self.state == .inactive { self.state = .active }
            _ = try self.metadata(1); let root = try self.canonical(1); self.record(1); replyHandler(root, nil)
        } catch { if previous == .inactive { self.state = .inactive }; self.record(1, error: error); replyHandler(nil, error) }
    } }
    func mount(options: FSTaskOptions, replyHandler: @escaping (Error?) -> Void) { mount(arguments: options.taskOptions, replyHandler: replyHandler) }
    func mount(arguments: [String], replyHandler: @escaping (Error?) -> Void) {
        guard arguments.count <= 64 && arguments.allSatisfy({ $0.utf8.count <= 1024 }) else { replyHandler(POSIXError(.E2BIG)); return }
        enqueue(retainedBytes: arguments.reduce(0) { $0 + $1.utf8.count }, maintenance: true, rejected: { replyHandler($0) }) {
        do {
            guard !arguments.contains("-f") else { throw POSIXError(.ENOTSUP) }
            guard self.state != .inactive else { throw POSIXError(.EINVAL) }
            _ = try self.ready()
            var bytes = [UInt8](repeating: 0, count: 16)
            if self.state != .mounted {
                guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw POSIXError(.EIO) }
            }
            self.submissionLock.lock()
            guard self.pendingUnmountReplies == 0 && self.admission != .terminal else {
                self.submissionLock.unlock(); throw POSIXError(.EBUSY)
            }
            if self.state != .mounted { self.nonce = bytes; self.state = .mounted }
            self.admission = .open; self.submissionLock.unlock()
            self.record(2); replyHandler(nil)
        } catch { self.record(2, error: error); replyHandler(error) }
    } }
    // Framework lifecycle completions are separate control work: O(pending
    // unmounts), not part of the bounded ordinary/maintenance request budget.
    // Each reply runs after all earlier accepted work, including reentrant calls.
    func unmount(replyHandler: @escaping () -> Void) {
        submissionLock.lock()
#if STALLION_WRITE_DIAGNOSTIC
        if diagnosticWritable { controlRecordLocked(3, mask: 0, error: nil, entry: true) }
#endif
        pendingUnmountReplies += 1
        if admission != .terminal { admission = .draining }
        queue.async(execute: DispatchWorkItem {
            if self.state != .terminal {
                self.nonce.removeAll(keepingCapacity: false)
                sfs_image_clear_read_cache(self.handle)
                if self.state == .mounted { self.state = .active }
            }
            self.submissionLock.lock()
            self.pendingUnmountReplies -= 1
            if self.pendingUnmountReplies == 0 && self.admission != .terminal { self.admission = .unmounted }
            self.submissionLock.unlock()
            self.record(3, error: self.failure); replyHandler()
        })
        submissionLock.unlock()
    }
    func deactivate(options: FSDeactivateOptions, replyHandler: @escaping (Error?) -> Void) { enqueue(maintenance: true, rejected: { replyHandler($0) }) {
        self.submissionLock.lock()
        var error: Error? = self.failure ?? (self.state == .mounted || self.pendingUnmountReplies != 0 ? POSIXError(.EBUSY) : nil)
#if STALLION_WRITE_DIAGNOSTIC
        error = self.deliveryFailure?.error ?? error
#endif
        if error == nil && self.state != .terminal { self.state = .inactive }
        self.submissionLock.unlock()
        self.record(4, error: error); replyHandler(error)
    } }
    func synchronize(flags: FSSyncFlags, replyHandler: @escaping (Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC
        if diagnosticWritable {
            let invalid: Error? = [FSSyncFlags.wait, .dWait, .noWait].contains(flags) ? nil : POSIXError(.EINVAL)
            enqueue(maintenance: true, syncOperation: true, syncFlags: UInt64(bitPattern: Int64(flags.rawValue)), validationError: invalid, rejected: { replyHandler($0) }) {
                var error = self.deliveryError() ?? self.failure
                if error == nil {
                    do {
                        let h = try self.ready(); var info = sfs_image_information(), r = sfs_result()
                        try self.check(sfs_image_get_information(h, &info, &r), r)
                        guard r.transaction_active == 0 else { throw POSIXError(.EIO) }
                    } catch let caught { self.latch(caught); self.rememberDelivery(caught, self.lastCoreFailure ?? sfs_result()); error = caught }
                }
                // Recheck under the same lock used by prequeue rejection.
                error = self.deliveryError() ?? error
                self.record(5, mask: UInt64(bitPattern: Int64(flags.rawValue)), error: error); replyHandler(error)
            }
            return
        }
#endif
        enqueue(maintenance: true, rejected: { replyHandler($0) }) {
        self.record(5, error: self.failure); replyHandler(self.failure)
    } }
    // Queue-only. Busy is nonconsuming; a close error still consumes ownership.
    func unload() -> (consumed: Bool, error: Error?) {
        submissionLock.lock()
#if STALLION_WRITE_DIAGNOSTIC
        if diagnosticWritable { controlRecordLocked(6, mask: 0, error: nil, entry: true) }
        if diagnosticWritable, let first = deliveryFailure { latch(first.error) }
#endif
        if state == .terminal {
#if STALLION_WRITE_DIAGNOSTIC
            if diagnosticWritable { controlRecordLocked(6, mask: 1, error: failure) }
#endif
            submissionLock.unlock(); return (true, failure)
        }
        guard pendingUnmountReplies == 0 && callbacks.isEmpty else {
#if STALLION_WRITE_DIAGNOSTIC
            if diagnosticWritable { controlRecordLocked(6, mask: 0, error: POSIXError(.EBUSY)) }
#endif
            submissionLock.unlock(); return (false, POSIXError(.EBUSY))
        }
        admission = .terminal; submissionLock.unlock()
        state = .terminal; nonce.removeAll(); let owned = handle; handle = nil
        if let owned { var r = sfs_result(); let status = sfs_image_close(owned, &r); if status != SFS_OK { latch(sfsError(status, r)) } }
        if scope { scope = false; resource.url.stopAccessingSecurityScopedResource() }
        items.removeAll(); record(6, error: failure); emit(); return (true, failure)
    }
    func getAttributes(_ request: FSItem.GetAttributesRequest, of item: FSItem, replyHandler: @escaping (FSItem.Attributes?, Error?) -> Void) { enqueue(rejected: { replyHandler(nil, $0) }) {
        var parents = ParentEvidence(), inode: UInt64 = 0
        let mask = UInt64(bitPattern: Int64(request.wantedAttributes.rawValue))
        do {
            inode = try self.id(item); let a = try self.attributes(inode, request, parents: &parents)
            self.record(10, inode, mask: mask, allocation: request.isAttributeWanted(.allocSize) ? a.allocSize : 0, parents: parents)
            replyHandler(a, nil)
        } catch { parents.mapped = nil; self.record(10, inode, mask: mask, error: error, parents: parents); replyHandler(nil, error) }
    } }
    func lookupItem(named name: FSFileName, inDirectory directory: FSItem, replyHandler: @escaping (FSItem?, FSFileName?, Error?) -> Void) {
        do { try component(name.data) } catch { replyHandler(nil, nil, error); return }
        enqueue(retainedBytes: name.data.count, rejected: { replyHandler(nil, nil, $0) }) {
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
            _ = try self.metadata(inode); let item = try self.canonical(inode); self.record(11, inode); replyHandler(item, returned, nil)
        } catch { self.record(11, error: error); replyHandler(nil, nil, error) }
    } }
    func reclaimItem(_ item: FSItem, replyHandler: @escaping (Error?) -> Void) {
        reclaim(item, attempt: { item.tryReclaim($0) }, replyHandler: replyHandler)
    }
    private func reclaim(_ item: FSItem, attempt: @escaping (@escaping () -> Void) -> Bool,
                         replyHandler: @escaping (Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC
        controlEntry(12, item: item)
#endif
        enqueue(maintenance: true, rejected: {
#if STALLION_WRITE_DIAGNOSTIC
            if self.diagnosticWritable {
                self.submissionLock.lock(); self.controlRecordLocked(12, mask: 0, error: $0); self.submissionLock.unlock()
            }
#endif
            replyHandler($0)
        }) {
        do {
            let inode = try self.id(item)
            let eligible = attempt { if inode != 1 && self.items[inode] === item { self.items.removeValue(forKey: inode) } }
            self.record(12, inode, reclaim: eligible ? 1 : 0); replyHandler(nil)
        } catch { self.record(12, error: error); replyHandler(error) }
    } }
#if STALLION_ADAPTER_CHECK
    // Exercises adapter cleanup without claiming an installed SDK reclaim.
    func reclaimForTesting(_ item: FSItem, eligible: Bool, replyHandler: @escaping (Error?) -> Void) {
        reclaim(item, attempt: { cleanup in if eligible { cleanup() }; return eligible }, replyHandler: replyHandler)
    }
#endif
    func readSymbolicLink(_ item: FSItem, replyHandler: @escaping (FSFileName?, Error?) -> Void) { enqueue(rejected: { replyHandler(nil, $0) }) {
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
        bytes.append(contentsOf: rawBytes(anchor.uuid))
        var generation = anchor.generation.bigEndian
        withUnsafeBytes(of: &generation) { bytes.append(contentsOf: $0) }
        bytes.append(contentsOf: rawBytes(anchor.root_digest))
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
                            pack: @escaping DirectoryPack, replyHandler: @escaping (FSDirectoryVerifier, Error?) -> Void) { enqueue(rejected: { replyHandler(.initial, $0) }) {
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
                let status = rawBytes(self.anchor.root_digest).withUnsafeBufferPointer {
                    sfs_image_resume_after_position(h, 0, self.anchor.generation, $0.baseAddress, parent, start, &cursor, &r)
                }
                if [SFS_INVALID, SFS_NOT_FOUND, SFS_STATE].contains(status) { throw FSError(.invalidDirectoryCookie) }
                try self.check(status, r)
            }
            while true {
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
        } catch { finish(.error, error) }
    } }
#if STALLION_ADAPTER_CHECK
    func capturedRecords() -> [Record] { records }
    func activeItemCount() -> Int { items.count }
#endif
    func openItem(_ item: FSItem, modes: FSVolume.OpenModes, context: FSContext, replyHandler: @escaping @Sendable (Error?) -> Void) { enqueue(rejected: { replyHandler($0) }) {
        do {
            _ = try self.ready(mounted: true); let inode = try self.id(item), m = try self.metadata(inode)
            guard context.effectiveUserID == Int(self.owner) else { throw POSIXError(.EACCES) }
#if STALLION_WRITE_DIAGNOSTIC
            if self.diagnosticWritable {
                guard !modes.isEmpty && modes.subtracting([.read, .write]).isEmpty && m.entry.kind == SFS_FILE else { throw POSIXError(.EINVAL) }
                if modes.contains(.write) { try self.writableMetadata(inode) }
                if modes.contains(.read) { try self.ownerAccess(m, inode: inode, access: .readData, uid: context.effectiveUserID) }
                (item as! StallionItem).retainedModes.formUnion(modes)
                self.record(15, inode, mask: UInt64(modes.rawValue), uid: Int64(context.effectiveUserID)); replyHandler(nil); return
            }
#endif
            if modes.contains(.write) { throw POSIXError(.EROFS) }
            guard modes == .read && m.entry.kind == SFS_FILE else { throw POSIXError(.EINVAL) }
            try self.ownerAccess(m, inode: inode, access: .readData, uid: context.effectiveUserID)
            self.record(15, inode, mask: UInt64(modes.rawValue), uid: Int64(context.effectiveUserID)); replyHandler(nil)
        } catch { self.record(15, mask: UInt64(modes.rawValue), uid: Int64(context.effectiveUserID), error: error); replyHandler(error) }
    } }
    func closeItem(_ item: FSItem, modes: FSVolume.OpenModes, context: FSContext, replyHandler: @escaping @Sendable (Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC
        controlEntry(16, item: item, mask: UInt64(modes.rawValue))
#endif
        enqueue(maintenance: true, rejected: {
#if STALLION_WRITE_DIAGNOSTIC
            if self.diagnosticWritable {
                self.submissionLock.lock(); self.controlRecordLocked(16, mask: UInt64(modes.rawValue), error: $0); self.submissionLock.unlock()
            }
#endif
            replyHandler($0)
        }) {
        do {
            _ = try self.ready(); let inode = try self.id(item)
            guard context.effectiveUserID == Int(self.owner) else { throw POSIXError(.EACCES) }
#if STALLION_WRITE_DIAGNOSTIC
            if self.diagnosticWritable {
                guard modes.subtracting([.read, .write]).isEmpty else { throw POSIXError(.EINVAL) }
                (item as! StallionItem).retainedModes = modes
                self.record(16, inode, mask: UInt64(modes.rawValue), uid: Int64(context.effectiveUserID)); replyHandler(nil); return
            }
#endif
            guard modes.isEmpty || modes == .read else { throw POSIXError(.EROFS) }
            self.record(16, inode, mask: UInt64(modes.rawValue), uid: Int64(context.effectiveUserID)); replyHandler(nil)
        } catch { self.record(16, uid: Int64(context.effectiveUserID), error: error); replyHandler(error) }
    } }
    func checkAccess(to item: FSItem, requestedAccess access: FSVolume.AccessMask, context: FSContext,
                     replyHandler: @escaping @Sendable (FSCheckAccessResult?, Error?) -> Void) { enqueue(rejected: { replyHandler(nil, $0) }) {
        do {
            let inode = try self.id(item), m = try self.metadata(inode)
            try self.ownerAccess(m, inode: inode, access: access, uid: context.effectiveUserID)
            guard let result = FSCheckAccessResult(accessAllowed: true) else { throw POSIXError(.EIO) }
            self.record(17, inode, mask: UInt64(access.rawValue), uid: Int64(context.effectiveUserID)); replyHandler(result, nil)
        } catch { self.record(17, mask: UInt64(access.rawValue), uid: Int64(context.effectiveUserID), error: error); replyHandler(nil, error) }
    } }
    private func ownerAccess(_ m: sfs_metadata_entry, inode: UInt64, access: FSVolume.AccessMask, uid: Int) throws {
        var readAccess = access
#if STALLION_WRITE_DIAGNOSTIC
        let writeAccess: FSVolume.AccessMask = [.writeData, .appendData]
        if diagnosticWritable && !access.intersection(writeAccess).isEmpty {
            guard uid == Int(owner), m.uid == owner, m.entry.kind == SFS_FILE,
                  m.mode & 0o200 != 0, m.mode & 0o6000 == 0 else { throw POSIXError(.EACCES) }
            readAccess.subtract(writeAccess)
        }
#endif
        try checkOwnerMode(m, owner: owner, uid: uid, access: readAccess)
        // Opaque ACL storage is not ACL evaluation. Refuse rather than grant an
        // owner-mode shortcut when the native security descriptor is present.
        let name = Data("com.apple.system.Security".utf8)
        var size: UInt64 = 0, r = sfs_result(); let h = try ready()
        let status = name.withUnsafeBytes { sfs_image_xattr_size(h, 0, inode, $0.baseAddress, $0.count, &size, &r) }
        if status == SFS_NOT_FOUND { return }
        try check(status, r); throw POSIXError(.ENOTSUP)
    }
    func read(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer,
              replyHandler: @escaping (Int, Error?) -> Void) {
        guard length >= 0 && offset >= 0 && length <= buffer.length else { replyHandler(0, POSIXError(.EINVAL)); return }
        enqueue(retainedBytes: buffer.length, rejected: { replyHandler(0, $0) }) {
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
    func getXattr(named name: FSFileName, of item: FSItem, replyHandler: @escaping (Data?, Error?) -> Void) {
        do { try component(name.data, xattr: true) } catch { replyHandler(nil, error); return }
        enqueue(retainedBytes: name.data.count, rejected: { replyHandler(nil, $0) }) {
        do {
            let h = try self.ready(mounted: true), inode = try self.id(item); _ = try self.metadata(inode); try component(name.data, xattr: true)
            var size: UInt64 = 0, r = sfs_result()
            let status = name.data.withUnsafeBytes { sfs_image_xattr_size(h, 0, inode, $0.baseAddress, $0.count, &size, &r) }
            try self.check(status, r, missing: ENOATTR)
            let length = try checkedXattrLength(size)
            if length == 0 { self.record(19, inode); replyHandler(Data(), nil); return }
#if STALLION_ADAPTER_CHECK
            self.xattrAllocations += 1
#endif
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
    func listXattrs(of item: FSItem, replyHandler: @escaping ([FSFileName]?, Error?) -> Void) { enqueue(rejected: { replyHandler(nil, $0) }) {
        do {
            let h = try self.ready(mounted: true), inode = try self.id(item); _ = try self.metadata(inode)
            var names: [FSFileName] = [], after = Data(), total = 0, r = sfs_result()
            while true {
                var entry = sfs_xattr_entry(), found: Int32 = 0
                let status = rawBytes(self.anchor.root_digest).withUnsafeBufferPointer { digest in after.withUnsafeBytes {
                    sfs_image_next_xattr(h, 0, self.anchor.generation, digest.baseAddress, inode,
                        after.isEmpty ? nil : $0.baseAddress, $0.count, &entry, &found, &r)
                } }
                try self.check(status, r); if found == 0 { break }
                guard entry.name_length > 0 && entry.name_length <= 255 else { throw POSIXError(.EIO) }
                let next = Data(rawBytes(entry.name).prefix(entry.name_length)); try component(next, xattr: true)
                guard after.isEmpty || after.lexicographicallyPrecedes(next) else { throw POSIXError(.EIO) }
                total = try checkedXattrListTotal(total, count: names.count, next: next.count)
                names.append(FSFileName(data: next)); after = next
            }
            self.record(20, inode); replyHandler(names, nil)
        } catch { self.record(20, error: error); replyHandler(nil, error) }
    } }
    // Refusal retains no caller payload and never waits for queue capacity.
    private func refuse(_ reply: (Error) -> Void) { reply(POSIXError(.EROFS)) }
    func setAttributes(_ attributes: FSItem.SetAttributesRequest, on item: FSItem, replyHandler: @escaping (FSItem.Attributes?, Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC
        if diagnosticWritable { diagnosticSetAttributes(attributes, item: item, reply: replyHandler); return }
#endif
        refuse { replyHandler(nil, $0) }
    }
    func createItem(named name: FSFileName, type: FSItem.ItemType, inDirectory directory: FSItem, attributes: FSItem.SetAttributesRequest, replyHandler: @escaping (FSItem?, FSFileName?, Error?) -> Void) { refuse { replyHandler(nil, nil, $0) } }
    func createSymbolicLink(named name: FSFileName, inDirectory directory: FSItem, attributes: FSItem.SetAttributesRequest, linkContents: FSFileName, replyHandler: @escaping (FSItem?, FSFileName?, Error?) -> Void) { refuse { replyHandler(nil, nil, $0) } }
    func createLink(to item: FSItem, named name: FSFileName, inDirectory directory: FSItem, replyHandler: @escaping (FSFileName?, Error?) -> Void) { refuse { replyHandler(nil, $0) } }
    func removeItem(_ item: FSItem, named name: FSFileName, fromDirectory directory: FSItem, replyHandler: @escaping (Error?) -> Void) { refuse { replyHandler($0) } }
    func renameItem(_ item: FSItem, inDirectory sourceDirectory: FSItem, named sourceName: FSFileName, to destinationName: FSFileName, inDirectory destinationDirectory: FSItem, overItem: FSItem?, replyHandler: @escaping (FSFileName?, Error?) -> Void) { refuse { replyHandler(nil, $0) } }
    func write(contents: Data, to item: FSItem, at offset: off_t, replyHandler: @escaping (Int, Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC
        if diagnosticWritable { diagnosticWrite(contents, item: item, offset: offset, reply: replyHandler); return }
#endif
        refuse { replyHandler(0, $0) }
    }
    func setXattr(named name: FSFileName, to value: Data?, on item: FSItem, policy: FSVolume.SetXattrPolicy, replyHandler: @escaping (Error?) -> Void) { refuse { replyHandler($0) } }
#if STALLION_WRITE_DIAGNOSTIC
    @discardableResult private func writableMetadata(_ inode: UInt64) throws -> sfs_metadata_entry {
        if let error = deliveryError() { throw error }
        let m = try metadata(inode)
        guard m.entry.kind == SFS_FILE else { throw POSIXError(.EINVAL) }
        try ownerAccess(m, inode: inode, access: .writeData, uid: Int(owner))
        return m
    }
    private func observeWrite(_ operation: UInt64, inode: UInt64, offset: UInt64, length: UInt64,
                              started: UInt64, count: Int, error: Error?, result: sfs_result) {
        submissionLock.lock(); defer { submissionLock.unlock() }
        if writeRecords.count == 4096 { writeCounters.overflow = true; return }
        saturated(&diagnosticTraceSequence)
        writeRecords.append(WriteRecord(sequence: diagnosticTraceSequence, operation: operation, inode: inode,
            offset: offset, length: length, mask: 0, started: started, finished: DispatchTime.now().uptimeNanoseconds,
            generation: anchor.generation, count: count, code: (error as NSError?)?.code ?? 0, result: result))
    }
    private func accountCommit(_ r: sfs_result) {
        submissionLock.lock(); defer { submissionLock.unlock() }
        saturated(&writeCounters.commits)
        if r.fence_attempted & 1 != 0 { saturated(&writeCounters.recordFences) }
        if r.fence_succeeded & 1 != 0 { saturated(&writeCounters.recordSuccess) }
        if r.fence_attempted & 2 != 0 { saturated(&writeCounters.commitFences) }
        if r.fence_succeeded & 2 != 0 { saturated(&writeCounters.commitSuccess) }
    }
    // This wrapper owns the only transaction; no previously acknowledged work
    // is staged. The original receipt survives abort/verification failures.
    private func mutate(_ body: (OpaquePointer, inout sfs_result) throws -> Void,
                        receipt: inout sfs_result) throws {
        let h = try ready(mounted: true), before = anchor
        var began = false, committed = false
        do {
            let begin = sfs_image_begin(h, &receipt)
            if begin == SFS_STATE { let e = POSIXError(.EIO); latch(e); throw e }
            try check(begin, receipt); began = true
            try body(h, &receipt)
#if STALLION_ADAPTER_CHECK
            diagnosticBeforeCommit?()
#endif
            let status = sfs_image_commit(h, &receipt); accountCommit(receipt)
            guard status == SFS_OK else {
                let e = sfsError(status, receipt)
                if receipt.poisoned != 0 || status == SFS_UNSUPPORTED { latch(e) }
                throw e
            }
            committed = true
            guard rawBytes(receipt.uuid) == rawBytes(before.uuid), receipt.device == before.device,
                  receipt.inode == before.inode, before.generation != UInt64.max,
                  receipt.generation == before.generation + 1, receipt.transaction_active == 0,
                  receipt.committed_end > before.committed_end,
                  receipt.poisoned == 0, receipt.fence_attempted == 3, receipt.fence_succeeded == 3 else {
                let e = POSIXError(.EIO); latch(e); throw e
            }
            anchor = receipt
            submissionLock.lock(); diagnosticDurable = receipt.generation; submissionLock.unlock()
        } catch {
            let original = receipt
            if original.poisoned != 0 || [SFS_IO, SFS_CORRUPT, SFS_RECOVERY_REQUIRED, SFS_OUTCOME_UNKNOWN, SFS_POISONED, SFS_UNSUPPORTED].contains(original.status) {
                latch(error)
            } else if began && !committed && failure == nil {
                var cleanup = sfs_result(), information = sfs_image_information()
                let aborted = sfs_image_abort(h, &cleanup)
                if (aborted != SFS_OK && aborted != SFS_STATE) || cleanup.transaction_active != 0 || cleanup.poisoned != 0 {
                    latch(POSIXError(.EIO))
                } else {
                    let checked = sfs_image_get_information(h, &information, &cleanup)
                    if checked != SFS_OK || cleanup.transaction_active != 0 || !anchorMatches(cleanup, before) { latch(POSIXError(.EIO)) }
                }
            }
            receipt = original; rememberDelivery(error, original); throw error
        }
    }
    private func diagnosticWrite(_ contents: Data, item: FSItem, offset: off_t, reply: @escaping (Int, Error?) -> Void) {
        let start = DispatchTime.now().uptimeNanoseconds
        var validation: Error?
        if offset < 0 { validation = POSIXError(.EINVAL) }
        else if UInt64(offset) > maximumFileSize || UInt64(contents.count) > maximumFileSize - UInt64(offset) { validation = POSIXError(.EFBIG) }
        enqueue(retainedBytes: contents.count, dataOperation: true, writeOperation: true, validationError: validation, rejected: { reply(0, $0) }) {
            var receipt = sfs_result(), inode: UInt64 = 0
            if self.failure == nil { self.lastCoreFailure = nil }
            do {
                _ = try self.ready(mounted: true); inode = try self.id(item); try self.writableMetadata(inode)
                self.submissionLock.lock(); self.saturated(&self.writeCounters.bytes, by: UInt64(contents.count)); self.submissionLock.unlock()
                if !contents.isEmpty {
                    try self.mutate({ h, r in
                        try contents.withUnsafeBytes { bytes in
                            var at = 0
                            while at < bytes.count {
                                let amount = min(65536, bytes.count - at)
                                self.submissionLock.lock(); self.saturated(&self.writeCounters.chunks); self.submissionLock.unlock()
                                let status = sfs_image_write(h, inode, UInt64(offset) + UInt64(at), bytes.baseAddress!.advanced(by: at), amount, &r)
                                try self.check(status, r); at += amount
#if STALLION_ADAPTER_CHECK
                                self.diagnosticAfterChunk?(at)
#endif
                            }
                        }
                    }, receipt: &receipt)
                }
                self.observeWrite(1, inode: inode, offset: UInt64(offset), length: UInt64(contents.count), started: start, count: contents.count, error: nil, result: receipt)
                reply(contents.count, nil)
            } catch {
                receipt = self.lastCoreFailure ?? receipt
                self.rememberDelivery(error, receipt)
                self.observeWrite(1, inode: inode, offset: UInt64(offset), length: UInt64(contents.count), started: start, count: 0, error: error, result: receipt)
                reply(0, error)
            }
        }
    }
    // All 18 SDK27 fields are classified before mutation; no guessed mask.
    static func sizeRequestError(_ a: FSItem.SetAttributesRequest) -> Error? {
        let fields: [FSItem.Attribute] = [.type, .mode, .linkCount, .uid, .gid, .flags, .size, .allocSize,
            .fileID, .parentID, .accessTime, .modifyTime, .changeTime, .birthTime, .backupTime, .addedTime,
            .supportsLimitedXAttrs, .inhibitKernelOffloadedIO]
        return sizeRequestError(valid: fields.filter { a.isValid($0) })
    }
    static func sizeRequestError(valid: [FSItem.Attribute]) -> Error? {
        let computed: [FSItem.Attribute] = [.type, .linkCount, .allocSize, .fileID, .parentID, .changeTime, .supportsLimitedXAttrs, .inhibitKernelOffloadedIO]
        let disabled: [FSItem.Attribute] = [.mode, .uid, .gid, .flags, .accessTime, .modifyTime, .birthTime]
        if computed.contains(where: { valid.contains($0) }) { return POSIXError(.EINVAL) }
        if disabled.contains(where: { valid.contains($0) }) { return POSIXError(.ENOTSUP) }
        // addedTime and backupTime have no representation and stay unconsumed.
        return nil
    }
    private func diagnosticSetAttributes(_ a: FSItem.SetAttributesRequest, item: FSItem,
                                         reply: @escaping (FSItem.Attributes?, Error?) -> Void) {
        let start = DispatchTime.now().uptimeNanoseconds
        a.consumedAttributes = []
        let hasSize = a.isValid(.size), validation = Self.sizeRequestError(a)
        enqueue(dataOperation: hasSize, validationError: validation, rejected: { reply(nil, $0) }) {
            var receipt = sfs_result(), inode: UInt64 = 0
            if self.failure == nil { self.lastCoreFailure = nil }
            do {
                _ = try self.ready(mounted: true); inode = try self.id(item); let m = try self.metadata(inode)
                if hasSize && m.entry.kind == SFS_FILE {
                    guard a.size <= self.maximumFileSize else { throw POSIXError(.EFBIG) }
                    try self.writableMetadata(inode)
                    if a.size != m.entry.size {
                        try self.mutate({ h, r in try self.check(sfs_image_resize(h, inode, a.size, &r), r) }, receipt: &receipt)
                    }
                    a.consumedAttributes = [.size]
#if STALLION_ADAPTER_CHECK
                    self.diagnosticAfterSizeCommit?()
#endif
                }
                let request = FSItem.GetAttributesRequest()
                request.wantedAttributes = [.size, .allocSize, .modifyTime, .changeTime, .fileID]
                var parents = ParentEvidence()
                let result = try self.attributes(inode, request, parents: &parents)
                self.observeWrite(2, inode: inode, offset: 0, length: hasSize ? a.size : 0, started: start, count: 0, error: nil, result: receipt)
                reply(result, nil)
            } catch {
                receipt = self.lastCoreFailure ?? receipt
                if hasSize { self.rememberDelivery(error, receipt) }
                // If size was consumed, it already committed. Do not abort it.
                if !a.consumedAttributes.isEmpty { self.latch(error) }
                self.observeWrite(2, inode: inode, offset: 0, length: hasSize ? a.size : 0, started: start, count: 0, error: error, result: receipt)
                reply(nil, error)
            }
        }
    }
#endif
}
