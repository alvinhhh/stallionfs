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
            result.limit_reason == SFS_LIMIT_FILE_SIZE ? EFBIG :
            result.limit_reason == SFS_LIMIT_PIN_RESOURCES ? ENFILE : EOVERFLOW
    case SFS_IO, SFS_OUTCOME_UNKNOWN, SFS_TIME_UNAVAILABLE:
        code = result.system_errno > 0 ? result.system_errno : EIO
    default: code = EIO
    }
    return NSError(domain: NSPOSIXErrorDomain, code: Int(code))
}
func rawBytes<T>(_ tuple: T) -> [UInt8] { withUnsafeBytes(of: tuple) { Array($0) } }
func sameBytes<T>(_ lhs: T, _ rhs: T) -> Bool {
    withUnsafeBytes(of: lhs) { a in withUnsafeBytes(of: rhs) { b in
        memcmp(a.baseAddress!, b.baseAddress!, a.count) == 0
    } }
}
func anchorMatches(_ result: sfs_result, _ anchor: sfs_result) -> Bool {
    sameBytes(result.uuid, anchor.uuid) && result.device == anchor.device && result.inode == anchor.inode &&
    result.generation == anchor.generation && result.committed_end == anchor.committed_end &&
    sameBytes(result.root_digest, anchor.root_digest)
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
#if STALLION_CONTEXT_HANDLERS && (STALLION_WRITE_DIAGNOSTIC || STALLION_CONTEXT_WRITES) && STALLION_ADAPTER_CHECK
    var snapshotForTesting: (Int, Int) {
        lock.lock(); defer { lock.unlock() }; return (count, bytes)
    }
#endif
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
struct CallerIdentity {
    let uid: Int, gid: Int
    init(uid: Int, gid: Int) { self.uid = uid; self.gid = gid }
    init(_ context: FSContext) { uid = context.effectiveUserID; gid = context.effectiveGroupID }
}
// Owner-only profile: a group or root identity never grants an exception.
func checkOwnerPolicy(_ m: sfs_metadata_entry, owner: uid_t, caller: CallerIdentity,
                      access: FSVolume.AccessMask, writable: Bool, hasACL: Bool) throws {
    guard uid_t(exactly: caller.uid) != nil, gid_t(exactly: caller.gid) != nil else { throw POSIXError(.EACCES) }
    var readAccess = access
    let writes: FSVolume.AccessMask = [.writeData, .appendData]
    if writable && !access.intersection(writes).isEmpty {
        guard caller.uid == Int(owner), m.uid == owner, m.entry.kind == SFS_FILE,
              m.mode & 0o200 != 0, m.mode & 0o6000 == 0 else { throw POSIXError(.EACCES) }
        readAccess.subtract(writes)
    }
    try checkOwnerMode(m, owner: owner, uid: caller.uid, access: readAccess)
    guard !hasACL else { throw POSIXError(.ENOTSUP) }
}
#if STALLION_CONTEXT_HANDLERS && (STALLION_WRITE_DIAGNOSTIC || STALLION_CONTEXT_WRITES)
func checkXattrOwnerPolicy(_ m: sfs_metadata_entry, owner: uid_t, caller: CallerIdentity) throws {
    guard uid_t(exactly: caller.uid) != nil, gid_t(exactly: caller.gid) != nil,
          caller.uid == Int(owner), m.uid == owner else { throw POSIXError(.EACCES) }
    guard m.entry.kind == SFS_FILE, m.flags == 0 else { throw POSIXError(.ENOTSUP) }
    guard m.mode & 0o200 != 0, m.mode & 0o7000 == 0 else { throw POSIXError(.EACCES) }
}
func writableXattrName(_ bytes: Data) throws {
    try component(bytes, xattr: true)
    // These names require security, ACL or compression semantics not supplied
    // by opaque storage. Other Apple and vendor names remain ordinary values.
    let unsupported = ["com.apple.acl.text", "com.apple.decmpfs", "com.apple.macl", "com.apple.provenance"]
    guard !bytes.starts(with: "com.apple.system.".utf8),
          !unsupported.contains(where: { bytes.elementsEqual($0.utf8) }) else { throw POSIXError(.ENOTSUP) }
}
func checkLinkParentPolicy(_ m: sfs_metadata_entry, owner: uid_t, caller: CallerIdentity) throws {
    guard uid_t(exactly: caller.uid) != nil, gid_t(exactly: caller.gid) != nil,
          caller.uid == Int(owner), m.uid == owner else { throw POSIXError(.EACCES) }
    guard m.entry.kind == SFS_DIRECTORY else { throw POSIXError(.ENOTDIR) }
    guard m.link_count > 0 else { throw POSIXError(.ENOENT) }
    guard m.flags == 0 else { throw POSIXError(.ENOTSUP) }
    guard m.mode & 0o300 == 0o300, m.mode & 0o7000 == 0 else { throw POSIXError(.EACCES) }
}
func checkLinkCount(_ count: UInt64) throws {
    guard count < UInt64(UInt32.max) else { throw POSIXError(.EMLINK) }
}
#endif
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
struct LastKnownParent {
    let item: ObjectIdentifier
    let pin: sfs_pin
    let inode: UInt64
    let kind: sfs_kind
    let parent: UInt64
}
final class StallionItem: FSItem {
    let inode: UInt64
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
    var retainedModes: FSVolume.OpenModes = []
    var pin: sfs_pin?
    var reclaimed = false
    var lastKnownParent: LastKnownParent?
#endif
    init(_ inode: UInt64) { self.inode = inode; super.init() }
}

// The two interfaces share Objective-C selectors and must never coexist.
#if STALLION_CONTEXT_HANDLERS
extension StallionVolume: FSVolume.Handler, FSVolume.ReadWriteHandler, FSVolume.XattrHandler {}
#else
extension StallionVolume: FSVolume.Operations, FSVolume.ReadWriteOperations, FSVolume.XattrOperations {}
#endif
final class StallionVolume: FSVolume, FSVolume.OpenCloseHandler, FSVolume.AccessCheckHandler, @unchecked Sendable {
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
    private let selectedAccess: ImageAdmission.Access
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
    // Required write state is shared; optional tracing never authorizes access.
    private var tracingEnabled: Bool { selectedAccess == .fixtureWritable }
    private static let writablePinBytes: UInt64 = 8 * 1024 * 1024
    private(set) var writesEnabled = false
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
        guard tracingEnabled else { return }
        guard writeRecords.count < 4096 else { writeCounters.overflow = true; return }
        saturated(&diagnosticTraceSequence)
        let now = DispatchTime.now().uptimeNanoseconds
        writeRecords.append(WriteRecord(sequence: diagnosticTraceSequence, operation: (entry ? 2000 : 1000) + operation,
            inode: inode, offset: 0, length: 0, mask: mask, started: now, finished: now,
            generation: diagnosticDurable, count: 0, code: (error as NSError?)?.code ?? 0,
            result: deliveryFailure?.result ?? sfs_result()))
    }
    private func controlEntry(_ operation: UInt64, item: FSItem, mask: UInt64 = 0) {
        guard writesEnabled else { return }
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
    func enableAdmittedWrites() throws {
        guard selectedAccess != .readOnly, state == .inactive,
              resource.isWritable && !resource.isRevoked, items.isEmpty, !writesEnabled,
              let handle else { throw POSIXError(.EACCES) }
#if !(STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        guard selectedAccess == .fixtureWritable else { throw POSIXError(.ENOTSUP) }
#endif
        // selectedAccess comes from the successful core open, never from pin
        // configuration, which is also legal for ordinary read-only handles.
        var r = sfs_result()
        try check(sfs_image_pin_configure(handle, UInt32(itemLimit), Self.writablePinBytes, &r), r)
        items.reserveCapacity(itemLimit)
        writesEnabled = true; diagnosticDurable = anchor.generation
        if tracingEnabled { writeRecords.reserveCapacity(4096) }
    }
#if STALLION_WRITE_DIAGNOSTIC
    var diagnosticWritable: Bool { writesEnabled }
    func enableWriteDiagnostic(expectedUUID: UUID) throws {
        guard selectedAccess == .fixtureWritable,
              rawBytes(anchor.uuid) == withUnsafeBytes(of: expectedUUID.uuid, { Array($0) }) else { throw POSIXError(.EACCES) }
        try enableAdmittedWrites()
    }
    func diagnosticSnapshot() -> (WriteCounters, [WriteRecord], DeliveryFailure?) {
        submissionLock.lock(); defer { submissionLock.unlock() }
        if [diagnosticSequence, diagnosticTraceSequence, writeCounters.callbacks, writeCounters.bytes,
            writeCounters.writes, writeCounters.resizes, writeCounters.deliveredBytes,
            writeCounters.chunks, writeCounters.commits, writeCounters.recordFences, writeCounters.recordSuccess,
            writeCounters.commitFences, writeCounters.commitSuccess, writeCounters.refused, writeCounters.syncs].contains(UInt64.max) {
            writeCounters.overflow = true
        }
        // Never export the live array's COW storage: a retained snapshot must
        // not force observeWrite to allocate when appending after commit.
        let copied = Array<WriteRecord>(unsafeUninitializedCapacity: writeRecords.count) { storage, initialized in
            for record in writeRecords {
                storage.baseAddress!.advanced(by: initialized).initialize(to: record)
                initialized += 1
            }
        }
        return (writeCounters, copied, deliveryFailure)
    }
#endif
#if STALLION_ADAPTER_CHECK
    func diagnosticTraceStorageForTesting() -> (address: UInt, capacity: Int, count: Int) {
        submissionLock.lock(); defer { submissionLock.unlock() }
        return writeRecords.withUnsafeBufferPointer { buffer in
            let address = buffer.baseAddress.map { UInt(bitPattern: UnsafeRawPointer($0)) } ?? 0
            return (address, writeRecords.capacity, writeRecords.count)
        }
    }
    var diagnosticBeforeCommit: (() -> Void)?
    var diagnosticAfterChunk: ((Int) -> Void)?
    var diagnosticAfterSizeCommit: (() -> Void)?
    var diagnosticBeforePrepare: (() throws -> Void)?
    func diagnosticCloseForTesting(_ item: FSItem) { (item as? StallionItem)?.retainedModes = [] }
    func diagnosticCloseModesForTesting(_ item: FSItem, modes: FSVolume.OpenModes) throws {
        try closeModes(item, modes: modes)
    }
    func ownsForTesting(_ item: FSItem) -> Bool { (try? id(item)) != nil }
    func diagnosticReadForTesting(_ item: FSItem, length: Int) throws -> Data {
        guard length >= 0 && length <= 65536 else { throw POSIXError(.EINVAL) }
        let h = try ready(mounted: true), inode = try id(item)
        guard try metadata(inode).entry.kind == SFS_FILE else { throw POSIXError(.EINVAL) }
        var data = Data(count: length), count = 0, r = sfs_result()
        let status = try data.withUnsafeMutableBytes { bytes in
            try readTarget(h, inode: inode, offset: 0, data: bytes.baseAddress, length: length, count: &count, receipt: &r)
        }
        try check(status, r); guard count >= 0 && count <= length else { throw POSIXError(.EIO) }
        data.count = count; return data
    }
    func diagnosticMutationForTesting(_ body: (OpaquePointer, inout sfs_result) throws -> Void) throws {
        var r = sfs_result()
        let _: Bool = try mutate(body, prepare: { _, _ in true }, receipt: &r)
    }
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
#if STALLION_CONTEXT_HANDLERS && (STALLION_WRITE_DIAGNOSTIC || STALLION_CONTEXT_WRITES)
    private enum CreateOwnership { case reserved, transaction, discarded, promoted }
    struct CreateOutcome {
        var beginAttempted = false, beginSucceeded = false, commitAttempted = false, commitSucceeded = false
        var abortAttempted = false, releaseAttempted = false, discarded = false
        var original = sfs_result(), begin = sfs_result(), commit = sfs_result()
        var cleanup = sfs_result(), verification = sfs_result(), release = sfs_result()
        var verificationAttempted = false
    }
    private struct PendingCreate {
        var pin: sfs_pin?, inode: UInt64 = 0
        var ticket = true, quarantined = false
        var ownership = CreateOwnership.reserved
        var outcome = CreateOutcome()
    }
    private var pendingCreate: PendingCreate?
#if STALLION_ADAPTER_CHECK
    var createStageForTesting: ((String, StallionItem?) throws -> Void)?
    var createAbortForTesting: ((OpaquePointer, inout sfs_result) -> sfs_status)?
    var createReleaseForTesting: ((OpaquePointer, sfs_pin, inout sfs_result) -> sfs_status)?
    var createCommitReceiptForTesting: ((inout sfs_result) -> Void)?
    private(set) var createOutcomeForTesting = CreateOutcome()
    private(set) var createTokenForTesting: sfs_pin?
    var createStateForTesting: (pending: Bool, quarantine: Bool, ticket: Int) {
        (pendingCreate != nil, pendingCreate?.quarantined == true, pendingCreate?.ticket == true ? 1 : 0)
    }
#endif
#endif
    private var nonce: [UInt8] = []
    private var records: [Record] = []
    private var sequence: UInt64 = 0
    private var overflow = false
    private var emitted = false
    init(admission: ImageAdmission, resource: FSPathURLResource, scope: Bool, queue: DispatchQueue,
         itemLimit: Int = ReadOnlyLimits.activeItems) {
        precondition(itemLimit > 0 && itemLimit <= ReadOnlyLimits.activeItems)
        self.itemLimit = itemLimit
        self.handle = admission.handle; self.resource = resource; self.scope = scope; self.anchor = admission.anchor
        selectedAccess = admission.access
        self.queue = queue; owner = geteuid()
        let bytes = rawBytes(admission.anchor.uuid)
        let uuid = UUID(uuid: (bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5],bytes[6],bytes[7],bytes[8],bytes[9],bytes[10],bytes[11],bytes[12],bytes[13],bytes[14],bytes[15]))
        super.init(volumeID: .init(uuid: uuid), volumeName: FSFileName(string: "StallionFS"))
        if selectedAccess != .contextualWrites { records.reserveCapacity(4096) }
        record(0)
    }
#if STALLION_ADAPTER_CHECK
    // Status from the real core policy, not a mount-options approximation.
    func coreReadOnlyForTesting() -> Bool {
        guard let handle else { return false }
        var result = sfs_result()
        let status = sfs_image_begin(handle, &result)
        if status == SFS_OK {
            var cleanup = sfs_result()
            precondition(sfs_image_abort(handle, &cleanup) == SFS_OK && cleanup.transaction_active == 0)
        }
        return status == SFS_STATE && result.transaction_active == 0 && result.poisoned == 0
    }
    func openForTesting(_ item: FSItem, modes: FSVolume.OpenModes, caller: CallerIdentity, reply: @escaping (Error?) -> Void) {
        openHandler(item, modes: modes, caller: caller, reply: reply)
    }
    func closeForTesting(_ item: FSItem, modes: FSVolume.OpenModes, caller: CallerIdentity, reply: @escaping (Error?) -> Void) {
        closeHandler(item, modes: modes, caller: caller, reply: reply)
    }
    func accessForTesting(_ item: FSItem, access: FSVolume.AccessMask, caller: CallerIdentity, reply: @escaping (FSCheckAccessResult?, Error?) -> Void) {
        accessHandler(item, requestedAccess: access, caller: caller, reply: reply)
    }
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
    func retainedModesForTesting(_ item: FSItem) throws -> FSVolume.OpenModes { try ownedItem(item).retainedModes }
#endif
#endif
    func enqueue(retainedBytes: Int = 0, maintenance: Bool = false,
                 dataOperation: Bool = false, writeOperation: Bool = false, namespaceOperation: Bool = false,
                 syncOperation: Bool = false, syncFlags: UInt64 = 0, validationError: Error? = nil,
                 rejected: (Error) -> Void, _ block: @escaping () -> Void) {
        submissionLock.lock()
        var error: Error?
        if let validationError { error = validationError }
        else if admission == .terminal { error = POSIXError(.ENXIO) }
        else if !maintenance && admission != .open { error = POSIXError(admission == .draining ? .EAGAIN : .ENXIO) }
        else if !callbacks.acquire(retainedBytes) { error = POSIXError(.EAGAIN) }
        else { error = nil }
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        if writesEnabled {
            if syncOperation && tracingEnabled {
                saturated(&writeCounters.syncs); controlRecordLocked(5, mask: syncFlags, error: nil, entry: true)
            }
            if dataOperation && tracingEnabled {
                saturated(&diagnosticSequence); saturated(&writeCounters.callbacks)
                if writeOperation {
                    saturated(&writeCounters.writes); saturated(&writeCounters.deliveredBytes, by: UInt64(retainedBytes))
                } else { saturated(&writeCounters.resizes) }
            }
            // A previous delivery failure blocks mutation without consuming a
            // ticket. Undo a successful reservation before rejecting it.
#if STALLION_CONTEXT_HANDLERS
            let blocksDelivery = dataOperation || namespaceOperation
#else
            let blocksDelivery = dataOperation
#endif
            if blocksDelivery, let first = deliveryFailure, error == nil {
                callbacks.release(retainedBytes); error = first.error
            }
            if let rejectedError = error, dataOperation {
                if tracingEnabled { saturated(&writeCounters.refused) }
                rememberDeliveryLocked(rejectedError)
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
        guard selectedAccess != .contextualWrites else { return }
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        if writesEnabled && [1, 2, 3, 4, 5, 6, 12, 15, 16].contains(op) {
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
        guard selectedAccess != .contextualWrites else { return }
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
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
            if writesEnabled { lastCoreFailure = result }
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
    private func ownedItem(_ item: FSItem) throws -> StallionItem {
        guard let own = item as? StallionItem, items[own.inode] === own else { throw POSIXError(.EINVAL) }
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        if writesEnabled { guard !own.reclaimed else { throw POSIXError(.EINVAL) } }
#endif
#if STALLION_CONTEXT_HANDLERS && (STALLION_WRITE_DIAGNOSTIC || STALLION_CONTEXT_WRITES)
        guard pendingCreate?.inode != own.inode else { throw POSIXError(.EINVAL) }
#endif
        return own
    }
    private func id(_ item: FSItem) throws -> UInt64 {
        let own = try ownedItem(item)
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        if writesEnabled { guard own.pin != nil else { throw POSIXError(.EINVAL) } }
#endif
        return own.inode
    }
    private func canonical(_ inode: UInt64) throws -> StallionItem {
#if STALLION_CONTEXT_HANDLERS && (STALLION_WRITE_DIAGNOSTIC || STALLION_CONTEXT_WRITES)
        guard pendingCreate?.inode != inode else { throw POSIXError(.EINVAL) }
        let pendingTickets = pendingCreate?.ticket == true ? 1 : 0
        if let item = items[inode] { return item }
        guard items.count + pendingTickets < itemLimit else { throw POSIXError(.ENFILE) }
#else
        if let item = items[inode] { return item }
        guard items.count < itemLimit else { throw POSIXError(.ENFILE) }
#endif
        let item = StallionItem(inode)
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        if writesEnabled {
            let h = try ready(); var pin = sfs_pin(), r = sfs_result()
            try check(sfs_image_pin_acquire(h, inode, &pin, &r), r); item.pin = pin
        }
#endif
        items[inode] = item; return item
    }
    private func metadata(_ inode: UInt64) throws -> sfs_metadata_entry {
        let h = try ready(); var m = sfs_metadata_entry(), r = sfs_result()
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        if writesEnabled, let item = items[inode] {
            let pin = try token(inode); var value = sfs_pin_stat()
            try check(sfs_image_pin_stat(h, pin, &value, &r), r)
            try validatePinMetadata(value, inode: item.inode); return value.metadata
        }
#endif
        try check(sfs_image_stat_metadata(h, 0, inode, &m, &r), r)
        guard m.entry.inode == inode && m.link_count > 0 else {
            let error = POSIXError(.EIO); latch(error); throw error
        }
        return m
    }
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
    private func token(_ inode: UInt64) throws -> sfs_pin {
        guard let item = items[inode], !item.reclaimed, let pin = item.pin else { throw POSIXError(.EINVAL) }
        return pin
    }
    private func validatePinMetadata(_ value: sfs_pin_stat, inode: UInt64) throws {
        let m = value.metadata
        guard m.entry.inode == inode, (value.linked != 0) == (m.link_count > 0),
              value.linked != 0 || (m.entry.parent == 0 && m.entry.name_length == 0) else {
            let e = POSIXError(.EIO); latch(e); throw e
        }
    }
    private func transactionMetadata(_ h: OpaquePointer, inode: UInt64, receipt: inout sfs_result) throws -> sfs_metadata_entry {
        var value = sfs_pin_stat()
        try check(sfs_image_pin_stat_transaction(h, try token(inode), &value, &receipt), receipt)
        guard receipt.transaction_active != 0 else { throw POSIXError(.EIO) }
        try validatePinMetadata(value, inode: inode); return value.metadata
    }
    // Memory-only ownership cleanup, including after poison or revocation.
    // Called inside tryReclaim's block, or for the activation-owned root at deactivate.
    private func releaseItem(_ item: StallionItem) -> Error? {
        guard items[item.inode] === item, !item.reclaimed else { return POSIXError(.EINVAL) }
        let token = item.pin
        item.reclaimed = true; item.pin = nil; item.retainedModes = []; item.lastKnownParent = nil
        items.removeValue(forKey: item.inode)
        guard let pin = token, let handle else {
            let e = POSIXError(.EINVAL); latch(e); rememberDelivery(e); return e
        }
        var r = sfs_result(); let status = sfs_image_pin_release(handle, pin, &r)
        if status == SFS_OK && anchorMatches(r, anchor) { return nil }
        let e = status == SFS_OK ? POSIXError(.ESTALE) as Error : sfsError(status, r)
        latch(e); rememberDelivery(e, r); return e
    }
    private func closeModes(_ item: FSItem, modes: FSVolume.OpenModes) throws {
        let own = try ownedItem(item)
        guard own.pin != nil, modes.subtracting([.read, .write]).isEmpty,
              modes.subtracting(own.retainedModes).isEmpty else { throw POSIXError(.EINVAL) }
        own.retainedModes = modes
    }
#endif
    private func readTarget(_ h: OpaquePointer, inode: UInt64, offset: UInt64,
                            data: UnsafeMutableRawPointer?, length: Int, count: inout Int,
                            receipt: inout sfs_result) throws -> sfs_status {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        if writesEnabled { return sfs_image_pin_read(h, try token(inode), offset, data, length, &count, &receipt) }
#endif
        return sfs_image_read(h, 0, inode, offset, data, length, &count, &receipt)
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
        return try attributes(try metadata(inode), request, parents: &parents)
    }
#if STALLION_CONTEXT_HANDLERS
    private func attributes(_ m: sfs_metadata_entry, _ request: FSItem.GetAttributesRequest, parents: inout ParentEvidence) throws -> FSItem.Attributes {
        try validateWanted(request.wantedAttributes.rawValue)
        return try populateAttributes(m, request, parents: &parents)
    }
    private func detachedParent(_ m: sfs_metadata_entry, candidate: LastKnownParent?) throws -> UInt64 {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        guard writesEnabled, m.link_count == 0, m.entry.parent == 0, m.entry.name_length == 0,
              let item = items[m.entry.inode], let pin = try ownedItem(item).pin,
              let witness = candidate ?? item.lastKnownParent,
              witness.item == ObjectIdentifier(item), witness.inode == m.entry.inode, witness.kind == m.entry.kind,
              sameBytes(witness.pin, pin), witness.parent > 0, witness.parent != m.entry.inode else { throw POSIXError(.ENOTSUP) }
        return witness.parent
#else
        throw POSIXError(.ENOTSUP)
#endif
    }
    private func populateAttributes(_ m: sfs_metadata_entry, _ request: FSItem.GetAttributesRequest, parents: inout ParentEvidence, includeResultPolicy: Bool = false, detachedParent candidate: LastKnownParent? = nil) throws -> FSItem.Attributes {
        let inode = m.entry.inode, a = FSItem.Attributes(); a.invalidateAllProperties()
        parents.core = m.link_count == 0 ? nil : m.entry.parent
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
        if request.isAttributeWanted(.parentID) {
            if m.link_count > 0 { a.parentID = inode == 1 ? .parentOfRoot : try itemIdentifier(m.entry.parent) }
            else { a.parentID = try itemIdentifier(detachedParent(m, candidate: candidate)) }
        }
        if request.isAttributeWanted(.accessTime) { a.accessTime = try checkedTime(m.access) }
        if request.isAttributeWanted(.modifyTime) { a.modifyTime = try checkedTime(m.modification) }
        if request.isAttributeWanted(.changeTime) { a.changeTime = try checkedTime(m.change) }
        if request.isAttributeWanted(.birthTime) { a.birthTime = try checkedTime(m.birth) }
        if includeResultPolicy || request.isAttributeWanted(.supportsLimitedXAttrs) { a.supportsLimitedXAttrs = false }
        if includeResultPolicy || request.isAttributeWanted(.inhibitKernelOffloadedIO) { a.inhibitKernelOffloadedIO = true }
        if request.isAttributeWanted(.parentID) { parents.mapped = a.parentID.rawValue }
        return a
    }
#else
    private func attributes(_ m: sfs_metadata_entry, _ request: FSItem.GetAttributesRequest, parents: inout ParentEvidence) throws -> FSItem.Attributes {
        try validateWanted(request.wantedAttributes.rawValue)
        let inode = m.entry.inode, a = FSItem.Attributes(); a.invalidateAllProperties()
        parents.core = m.link_count == 0 ? nil : m.entry.parent
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
        if request.isAttributeWanted(.parentID) {
            guard m.link_count > 0 else { throw POSIXError(.ENOTSUP) }
            a.parentID = inode == 1 ? .parentOfRoot : try itemIdentifier(m.entry.parent)
        }
        if request.isAttributeWanted(.accessTime) { a.accessTime = try checkedTime(m.access) }
        if request.isAttributeWanted(.modifyTime) { a.modifyTime = try checkedTime(m.modification) }
        if request.isAttributeWanted(.changeTime) { a.changeTime = try checkedTime(m.change) }
        if request.isAttributeWanted(.birthTime) { a.birthTime = try checkedTime(m.birth) }
        if request.isAttributeWanted(.supportsLimitedXAttrs) { a.supportsLimitedXAttrs = false }
        if request.isAttributeWanted(.inhibitKernelOffloadedIO) { a.inhibitKernelOffloadedIO = true }
        if request.isAttributeWanted(.parentID) { parents.mapped = a.parentID.rawValue }
        return a
    }
#endif
    var maximumLinkCount: Int { Int(UInt32.max) }
    var maximumNameLength: Int { 255 }
    var restrictsOwnershipChanges: Bool { true }
    var truncatesLongNames: Bool { false }
    var maximumFileSize: UInt64 { UInt64(sfs_fskit_file_max()) }
    var maximumXattrSize: Int { ReadOnlyLimits.xattrValue }
    var isOpenCloseInhibited: Bool { false }
    var isAccessCheckInhibited: Bool { false }
    var requestedMountOptions: FSVolume.MountOptions {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        if writesEnabled { return [] }
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
#if !STALLION_CONTEXT_HANDLERS || STALLION_ADAPTER_CHECK
    func activate(options: FSTaskOptions, replyHandler: @escaping (FSItem?, Error?) -> Void) { activate(replyHandler: replyHandler) }
    func activate(replyHandler: @escaping (FSItem?, Error?) -> Void) { activateBody(prepare: { $0 }, reply: replyHandler) }
#endif
    private func activateBody<T>(prepare: @escaping (StallionItem) throws -> T, reply: @escaping (T?, Error?) -> Void) {
        enqueue(maintenance: true, rejected: { reply(nil, $0) }) {
            let previous = self.state
            do {
                if let failure = self.failure { throw failure }
                guard self.state != .terminal && self.handle != nil else { throw POSIXError(.ENXIO) }
                if self.state == .inactive { self.state = .active }
                _ = try self.metadata(1)
                let result = try self.canonicalResult(1, prepare: prepare)
                self.record(1); reply(result, nil)
            } catch { if previous == .inactive { self.state = .inactive }; self.record(1, error: error); reply(nil, error) }
        }
    }
    private func canonicalResult<T>(_ inode: UInt64, prepare: (StallionItem) throws -> T) throws -> T {
        let existed = items[inode] != nil, item = try canonical(inode)
        do { return try prepare(item) }
        catch {
            if !existed {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
                if writesEnabled { _ = releaseItem(item) }
                else { items.removeValue(forKey: inode) }
#else
                items.removeValue(forKey: inode)
#endif
            }
            throw error
        }
    }
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
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        if writesEnabled { controlRecordLocked(3, mask: 0, error: nil, entry: true) }
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
        let busy = self.state == .mounted || self.pendingUnmountReplies != 0
        var error: Error? = self.failure ?? (busy ? POSIXError(.EBUSY) : nil)
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        error = self.deliveryFailure?.error ?? error
        if self.writesEnabled {
            self.submissionLock.unlock()
            guard self.state != .terminal else { replyHandler(error); return }
            // FSKit has reclaimed every other item before deactivation. A root
            // still retained for the activation lifetime is released here.
            let root = self.items[1]
            guard !busy && self.items.count == (root == nil ? 0 : 1) else {
                self.record(4, error: POSIXError(.EBUSY)); replyHandler(error ?? POSIXError(.EBUSY)); return
            }
            if let root { let cleanup = self.releaseItem(root); error = error ?? cleanup }
            self.state = .inactive
            self.record(4, error: error); replyHandler(error); return
        }
#endif
        if error == nil && self.state != .terminal { self.state = .inactive }
        self.submissionLock.unlock()
        self.record(4, error: error); replyHandler(error)
    } }
    func synchronize(flags: FSSyncFlags, replyHandler: @escaping (Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        if writesEnabled {
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
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        if writesEnabled { controlRecordLocked(6, mask: 0, error: nil, entry: true) }
        if writesEnabled, let first = deliveryFailure { latch(first.error) }
#endif
        if state == .terminal {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
            if writesEnabled { controlRecordLocked(6, mask: 1, error: failure) }
#endif
            submissionLock.unlock(); return (true, failure)
        }
        guard pendingUnmountReplies == 0 && callbacks.isEmpty else {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
            if writesEnabled { controlRecordLocked(6, mask: 0, error: POSIXError(.EBUSY)) }
#endif
            submissionLock.unlock(); return (false, POSIXError(.EBUSY))
        }
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        if writesEnabled && (state != .inactive || !items.isEmpty) {
            submissionLock.unlock(); return (false, failure ?? POSIXError(.EBUSY))
        }
#endif
#if STALLION_CONTEXT_HANDLERS && (STALLION_WRITE_DIAGNOSTIC || STALLION_CONTEXT_WRITES)
        if let pendingCreate, !pendingCreate.quarantined {
            submissionLock.unlock(); return (false, failure ?? POSIXError(.EBUSY))
        }
#endif
        admission = .terminal; submissionLock.unlock()
        state = .terminal; nonce.removeAll(); let owned = handle; handle = nil
        if let owned { var r = sfs_result(); let status = sfs_image_close(owned, &r); if status != SFS_OK { latch(sfsError(status, r)) } }
#if STALLION_CONTEXT_HANDLERS && (STALLION_WRITE_DIAGNOSTIC || STALLION_CONTEXT_WRITES)
        pendingCreate = nil // Close consumes the table, including unresolved reservations.
#endif
        if scope { scope = false; resource.url.stopAccessingSecurityScopedResource() }
        items.removeAll(); record(6, error: failure); emit(); return (true, failure)
    }
#if !STALLION_CONTEXT_HANDLERS || STALLION_ADAPTER_CHECK
    func getAttributes(_ request: FSItem.GetAttributesRequest, of item: FSItem, replyHandler: @escaping (FSItem.Attributes?, Error?) -> Void) {
        getAttributesBody({ request }, item: item, caller: nil, prepare: { $0 }, reply: replyHandler)
    }
    func lookupItem(named name: FSFileName, inDirectory directory: FSItem, replyHandler: @escaping (FSItem?, FSFileName?, Error?) -> Void) {
        lookupBody(name, directory: directory, caller: nil, prepare: { item, name, _ in (item as FSItem, name) }) { result, error in
            replyHandler(result?.0, result?.1, error)
        }
    }
#endif
#if STALLION_CONTEXT_HANDLERS
    private func getAttributesBody<T>(_ makeRequest: @escaping () throws -> FSItem.GetAttributesRequest, item: FSItem, caller: CallerIdentity?,
                                     requirements: ResultRequirements? = nil,
                                     prepare: @escaping (FSItem.Attributes) throws -> T, reply: @escaping (T?, Error?) -> Void) {
        enqueue(rejected: { reply(nil, $0) }) {
            var parents = ParentEvidence(), inode: UInt64 = 0
            var mask: UInt64 = 0
            do {
                let request = try makeRequest(); mask = UInt64(bitPattern: Int64(request.wantedAttributes.rawValue))
                inode = try self.id(item); let m = try self.metadata(inode)
                if let caller { try self.ownerAccess(m, inode: inode, access: .readAttributes, caller: caller) }
                let a: FSItem.Attributes
                if let requirements { a = try self.preparedResultAttributes(m, request, requirements, parents: &parents) }
                else { a = try self.attributes(m, request, parents: &parents) }
                let result = try prepare(a)
                self.record(10, inode, mask: mask, allocation: request.isAttributeWanted(.allocSize) ? a.allocSize : 0, parents: parents)
                reply(result, nil)
            } catch { parents.mapped = nil; self.record(10, inode, mask: mask, error: error, parents: parents); reply(nil, error) }
        }
    }
#else
    private func getAttributesBody<T>(_ makeRequest: @escaping () throws -> FSItem.GetAttributesRequest, item: FSItem, caller: CallerIdentity?,
                                     prepare: @escaping (FSItem.Attributes) throws -> T, reply: @escaping (T?, Error?) -> Void) {
        enqueue(rejected: { reply(nil, $0) }) {
            var parents = ParentEvidence(), inode: UInt64 = 0
            var mask: UInt64 = 0
            do {
                let request = try makeRequest(); mask = UInt64(bitPattern: Int64(request.wantedAttributes.rawValue))
                inode = try self.id(item); let m = try self.metadata(inode)
                if let caller { try self.ownerAccess(m, inode: inode, access: .readAttributes, caller: caller) }
                let a = try self.attributes(m, request, parents: &parents), result = try prepare(a)
                self.record(10, inode, mask: mask, allocation: request.isAttributeWanted(.allocSize) ? a.allocSize : 0, parents: parents)
                reply(result, nil)
            } catch { parents.mapped = nil; self.record(10, inode, mask: mask, error: error, parents: parents); reply(nil, error) }
        }
    }
#endif
    private func lookupBody<T>(_ name: FSFileName, directory: FSItem, caller: CallerIdentity?,
                               prepare: @escaping (StallionItem, FSFileName, sfs_metadata_entry) throws -> T, reply: @escaping (T?, Error?) -> Void) {
        do { try component(name.data) } catch { reply(nil, error); return }
        enqueue(retainedBytes: name.data.count, rejected: { reply(nil, $0) }) {
        do {
            let parent = try self.id(directory), m = try self.metadata(parent)
            guard m.entry.kind == SFS_DIRECTORY else { throw POSIXError(.ENOTDIR) }
            guard m.link_count > 0 else { throw POSIXError(.ENOENT) }
            if let caller { try self.ownerAccess(m, inode: parent, access: .search, caller: caller) }
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
            let target = try (inode == parent ? m : self.metadata(inode))
            let result = try self.canonicalResult(inode) { try prepare($0, returned, target) }
            self.record(11, inode); reply(result, nil)
        } catch { self.record(11, error: error); reply(nil, error) }
    } }
    func reclaimItem(_ item: FSItem, replyHandler: @escaping (Error?) -> Void) {
        reclaim(item, attempt: { item.tryReclaim($0) }, replyHandler: replyHandler)
    }
    private func reclaim(_ item: FSItem, attempt: @escaping (@escaping () -> Void) -> Bool,
                         replyHandler: @escaping (Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        controlEntry(12, item: item)
#endif
        enqueue(maintenance: true, rejected: {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
            if self.writesEnabled {
                self.submissionLock.lock(); self.controlRecordLocked(12, mask: 0, error: $0); self.submissionLock.unlock()
            }
#endif
            replyHandler($0)
        }) {
        do {
            let inode = try self.ownedItem(item).inode
            var cleanupError: Error?
            let eligible = attempt {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
                if self.writesEnabled {
                    cleanupError = self.releaseItem(item as! StallionItem); return
                }
#endif
                if inode != 1 && self.items[inode] === item { self.items.removeValue(forKey: inode) }
            }
            self.record(12, inode, error: cleanupError, reclaim: eligible ? 1 : 0); replyHandler(eligible ? cleanupError : nil)
        } catch { self.record(12, error: error); replyHandler(error) }
    } }
#if STALLION_ADAPTER_CHECK
    // Exercises adapter cleanup without claiming an installed SDK reclaim.
    func reclaimForTesting(_ item: FSItem, eligible: Bool, replyHandler: @escaping (Error?) -> Void) {
        reclaim(item, attempt: { cleanup in if eligible { cleanup() }; return eligible }, replyHandler: replyHandler)
    }
#endif
#if !STALLION_CONTEXT_HANDLERS || STALLION_ADAPTER_CHECK
    func readSymbolicLink(_ item: FSItem, replyHandler: @escaping (FSFileName?, Error?) -> Void) {
        readlinkBody(item, caller: nil, prepare: { name, _ in name }, reply: replyHandler)
    }
#endif
    private func readlinkBody<T>(_ item: FSItem, caller: CallerIdentity?,
                                 prepare: @escaping (FSFileName, sfs_metadata_entry) throws -> T, reply: @escaping (T?, Error?) -> Void) { enqueue(rejected: { reply(nil, $0) }) {
        do {
            let inode = try self.id(item); _ = try self.ready(mounted: true)
            let m = try self.metadata(inode)
            if let caller { try self.ownerAccess(m, inode: inode, access: .readData, caller: caller) }
            guard m.entry.kind == SFS_SYMLINK else { throw POSIXError(.EINVAL) }
            var bytes = [UInt8](repeating: 0, count: 4096), count = 0, r = sfs_result(); let h = try self.ready()
            let status: sfs_status
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
            if self.writesEnabled { status = sfs_image_pin_readlink(h, try self.token(inode), &bytes, bytes.count, &count, &r) }
            else { status = sfs_image_readlink(h, 0, inode, &bytes, bytes.count, &count, &r) }
#else
            status = sfs_image_readlink(h, 0, inode, &bytes, bytes.count, &count, &r)
#endif
            if status == SFS_LIMIT { throw POSIXError(.EIO) }; try self.check(status, r)
            guard count > 0 && count <= bytes.count && !bytes.prefix(count).contains(0) else { throw POSIXError(.EIO) }
            let result = try prepare(FSFileName(data: Data(bytes.prefix(count))), m)
            self.record(13, inode); reply(result, nil)
        } catch { self.record(13, error: error); reply(nil, error) }
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
#if !STALLION_CONTEXT_HANDLERS || STALLION_ADAPTER_CHECK
    func enumerateDirectory(_ directory: FSItem, startingAt cookie: FSDirectoryCookie,
                            verifier: FSDirectoryVerifier, attributes request: FSItem.GetAttributesRequest?,
                            packer: FSDirectoryEntryPacker, replyHandler: @escaping (FSDirectoryVerifier, Error?) -> Void) {
        enumerateDirectory(directory, startingAt: cookie, verifier: verifier, attributes: request, pack: {
            packer.packEntry(name: $0, itemType: $1, itemID: $2, nextCookie: $3, attributes: $4)
        }, replyHandler: replyHandler)
    }
#endif
    // Both callers enter the same serialized body; the packing closure is synchronous.
    func enumerateDirectory(_ directory: FSItem, startingAt cookie: FSDirectoryCookie,
                            verifier: FSDirectoryVerifier, attributes request: FSItem.GetAttributesRequest?,
                            pack: @escaping DirectoryPack, caller: CallerIdentity? = nil, requestForPacking: @escaping (FSItem.GetAttributesRequest?) throws -> FSItem.GetAttributesRequest? = { $0 }, replyHandler: @escaping (FSDirectoryVerifier, Error?) -> Void) { enqueue(rejected: { replyHandler(.initial, $0) }) {
        var returned: UInt64 = 0, accepted: UInt64 = 0, parent: UInt64 = 0
        var mask: UInt64 = 0
        func finish(_ reason: EnumerationStop, _ error: Error? = nil) {
            self.record(14, parent, mask: mask, error: error, cookie: cookie.rawValue, verifier: verifier.rawValue,
                        returnedVerifier: returned, acceptedCookie: accepted, stop: reason.rawValue)
            replyHandler(FSDirectoryVerifier(returned), error)
        }
        do {
            let request = try requestForPacking(request)
            mask = UInt64(bitPattern: Int64(request?.wantedAttributes.rawValue ?? 0))
            try validateDirectoryLayout(FSDirectoryCookie.initial.rawValue, FSDirectoryVerifier.initial.rawValue)
            let h = try self.ready(mounted: true); parent = try self.id(directory)
            let m = try self.metadata(parent)
            if let caller { try self.ownerAccess(m, inode: parent, access: [.readData, .search], caller: caller) }
            guard m.entry.kind == SFS_DIRECTORY else { throw POSIXError(.ENOTDIR) }
            guard m.link_count > 0 else { throw POSIXError(.ENOENT) }
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
    func openItem(_ item: FSItem, modes: FSVolume.OpenModes, context: FSContext, replyHandler: @escaping @Sendable (Error?) -> Void) {
        openHandler(item, modes: modes, caller: CallerIdentity(context), reply: replyHandler)
    }
    private func openHandler(_ item: FSItem, modes: FSVolume.OpenModes, caller: CallerIdentity, reply: @escaping (Error?) -> Void) { enqueue(rejected: { reply($0) }) {
        do {
            _ = try self.ready(mounted: true); let inode = try self.id(item), m = try self.metadata(inode)
            guard caller.uid == Int(self.owner) else { throw POSIXError(.EACCES) }
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
            if self.writesEnabled {
                guard !modes.isEmpty && modes.subtracting([.read, .write]).isEmpty && m.entry.kind == SFS_FILE else { throw POSIXError(.EINVAL) }
                if modes.contains(.write) { try self.ownerAccess(m, inode: inode, access: .writeData, caller: caller) }
                if modes.contains(.read) { try self.ownerAccess(m, inode: inode, access: .readData, caller: caller) }
                (item as! StallionItem).retainedModes.formUnion(modes)
                self.record(15, inode, mask: UInt64(modes.rawValue), uid: Int64(caller.uid)); reply(nil); return
            }
#endif
            if modes.contains(.write) { throw POSIXError(.EROFS) }
            guard modes == .read && m.entry.kind == SFS_FILE else { throw POSIXError(.EINVAL) }
            try self.ownerAccess(m, inode: inode, access: .readData, caller: caller)
            self.record(15, inode, mask: UInt64(modes.rawValue), uid: Int64(caller.uid)); reply(nil)
        } catch { self.record(15, mask: UInt64(modes.rawValue), uid: Int64(caller.uid), error: error); reply(error) }
    } }
    func closeItem(_ item: FSItem, modes: FSVolume.OpenModes, context: FSContext, replyHandler: @escaping @Sendable (Error?) -> Void) {
        closeHandler(item, modes: modes, caller: CallerIdentity(context), reply: replyHandler)
    }
    private func closeHandler(_ item: FSItem, modes: FSVolume.OpenModes, caller: CallerIdentity, reply: @escaping (Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        controlEntry(16, item: item, mask: UInt64(modes.rawValue))
#endif
        enqueue(maintenance: true, rejected: {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
            if self.writesEnabled {
                self.submissionLock.lock(); self.controlRecordLocked(16, mask: UInt64(modes.rawValue), error: $0); self.submissionLock.unlock()
            }
#endif
            reply($0)
        }) {
        do {
            let inode = try self.ownedItem(item).inode
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
            if self.writesEnabled {
                try self.closeModes(item, modes: modes)
                self.record(16, inode, mask: UInt64(modes.rawValue), uid: Int64(caller.uid)); reply(nil); return
            }
#endif
            guard modes.isEmpty || modes == .read else { throw POSIXError(.EROFS) }
            self.record(16, inode, mask: UInt64(modes.rawValue), uid: Int64(caller.uid)); reply(nil)
        } catch { self.record(16, uid: Int64(caller.uid), error: error); reply(error) }
    } }
    func checkAccess(to item: FSItem, requestedAccess access: FSVolume.AccessMask, context: FSContext,
                     replyHandler: @escaping @Sendable (FSCheckAccessResult?, Error?) -> Void) {
        accessHandler(item, requestedAccess: access, caller: CallerIdentity(context), reply: replyHandler)
    }
    private func accessHandler(_ item: FSItem, requestedAccess access: FSVolume.AccessMask, caller: CallerIdentity,
                               reply: @escaping (FSCheckAccessResult?, Error?) -> Void) { enqueue(rejected: { reply(nil, $0) }) {
        do {
            let inode = try self.id(item), m = try self.metadata(inode)
            try self.ownerAccess(m, inode: inode, access: access, caller: caller)
#if STALLION_CONTEXT_HANDLERS
            let result = try self.handlerResult(FSCheckAccessResult.self) { FSCheckAccessResult(accessAllowed: true) }
#else
            guard let result = FSCheckAccessResult(accessAllowed: true) else { throw POSIXError(.EIO) }
#endif
            self.record(17, inode, mask: UInt64(access.rawValue), uid: Int64(caller.uid)); reply(result, nil)
        } catch { self.record(17, mask: UInt64(access.rawValue), uid: Int64(caller.uid), error: error); reply(nil, error) }
    } }
    private func ownerAccess(_ m: sfs_metadata_entry, inode: UInt64, access: FSVolume.AccessMask, caller: CallerIdentity) throws {
        var writable = false
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        writable = writesEnabled
#endif
#if STALLION_CONTEXT_HANDLERS && (STALLION_WRITE_DIAGNOSTIC || STALLION_CONTEXT_WRITES)
        if writesEnabled && access.contains(.writeXattr) {
            try checkXattrOwnerPolicy(m, owner: owner, caller: caller)
            try ownerAccess(m, inode: inode, access: access.subtracting(.writeXattr), caller: caller)
            return
        }
        if writesEnabled && m.entry.kind == SFS_DIRECTORY && access.contains(.addFile) {
            try checkLinkParentPolicy(m, owner: owner, caller: caller)
            // The reduced request still passes the existing owner and ACL checks.
            try ownerAccess(m, inode: inode, access: access.subtracting(.addFile), caller: caller)
            return
        }
#endif
        try checkOwnerPolicy(m, owner: owner, caller: caller, access: access, writable: writable, hasACL: false)
        // Opaque security descriptors are not an implemented ACL evaluator.
        let name = Data("com.apple.system.Security".utf8)
        var size: UInt64 = 0, r = sfs_result(); let h = try ready()
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        let pin: sfs_pin?
        if writesEnabled { pin = try token(inode) } else { pin = nil }
#endif
        let status = name.withUnsafeBytes { bytes -> sfs_status in
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
            if let pin { return sfs_image_pin_xattr_size(h, pin, bytes.baseAddress, bytes.count, &size, &r) }
#endif
            return sfs_image_xattr_size(h, 0, inode, bytes.baseAddress, bytes.count, &size, &r)
        }
        if status == SFS_NOT_FOUND { return }
        try check(status, r)
        try checkOwnerPolicy(m, owner: owner, caller: caller, access: access, writable: writable, hasACL: true)
    }
#if !STALLION_CONTEXT_HANDLERS
    func read(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer,
              replyHandler: @escaping (Int, Error?) -> Void) {
        readBody(from: item, at: offset, length: length, into: buffer, prepare: { count, _ in count }, failedRead: replyHandler) { replyHandler($0 ?? 0, $1) }
    }
#endif
    private func readBody<T>(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer,
                             prepare: @escaping (Int, sfs_metadata_entry) throws -> T, failedRead: ((Int, Error?) -> Void)? = nil,
                             reply: @escaping (T?, Error?) -> Void) {
        guard length >= 0 && offset >= 0 && length <= buffer.length else { reply(nil, POSIXError(.EINVAL)); return }
        enqueue(retainedBytes: buffer.length, rejected: { reply(nil, $0) }) {
        var count = 0
        do {
            let h = try self.ready(mounted: true), inode = try self.id(item), m = try self.metadata(inode)
            guard m.entry.kind == SFS_FILE && offset >= 0 && length >= 0 else { throw POSIXError(.EINVAL) }
            var r = sfs_result()
            let status = try buffer.withUnsafeMutableBytes { bytes -> sfs_status in
                guard length <= bytes.count else { throw POSIXError(.EINVAL) }
                return try self.readTarget(h, inode: inode, offset: UInt64(offset), data: bytes.baseAddress, length: length, count: &count, receipt: &r)
            }
            guard count >= 0 && count <= length else { count = 0; throw POSIXError(.EIO) }
            try self.check(status, r); let result = try prepare(count, m)
            self.record(18, inode); reply(result, nil)
        } catch {
            self.record(18, error: error)
            if let failedRead { failedRead(count, error) } else { reply(nil, error) }
        }
    } }
#if !STALLION_CONTEXT_HANDLERS || STALLION_ADAPTER_CHECK
    func getXattr(named name: FSFileName, of item: FSItem, replyHandler: @escaping (Data?, Error?) -> Void) {
        getXattrBody(named: name, of: item, caller: nil, prepare: { $0 }, reply: replyHandler)
    }
    func listXattrs(of item: FSItem, replyHandler: @escaping ([FSFileName]?, Error?) -> Void) {
        listXattrsBody(of: item, caller: nil, prepare: { $0 }, reply: replyHandler)
    }
#endif
    private func getXattrBody<T>(named name: FSFileName, of item: FSItem, caller: CallerIdentity?,
                                 prepare: @escaping (Data) throws -> T, reply: @escaping (T?, Error?) -> Void) {
        do { try component(name.data, xattr: true) } catch { reply(nil, error); return }
        enqueue(retainedBytes: name.data.count, rejected: { reply(nil, $0) }) {
        do {
            let h = try self.ready(mounted: true), inode = try self.id(item); let m = try self.metadata(inode)
            if let caller { try self.ownerAccess(m, inode: inode, access: .readXattr, caller: caller) }; try component(name.data, xattr: true)
            var size: UInt64 = 0, r = sfs_result()
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
            let sizePin: sfs_pin?
            if self.writesEnabled { sizePin = try self.token(inode) } else { sizePin = nil }
#endif
            let status = name.data.withUnsafeBytes { bytes -> sfs_status in
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
                if let sizePin { return sfs_image_pin_xattr_size(h, sizePin, bytes.baseAddress, bytes.count, &size, &r) }
#endif
                return sfs_image_xattr_size(h, 0, inode, bytes.baseAddress, bytes.count, &size, &r)
            }
            try self.check(status, r, missing: ENOATTR)
            let length = try checkedXattrLength(size)
            if length == 0 { self.record(19, inode); reply(try prepare(Data()), nil); return }
#if STALLION_ADAPTER_CHECK
            self.xattrAllocations += 1
#endif
            guard let memory = malloc(length) else { throw POSIXError(.ENOMEM) }
            var transferred = false; defer { if !transferred { free(memory) } }
            var count = 0
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
            let readPin: sfs_pin?
            if self.writesEnabled { readPin = try self.token(inode) } else { readPin = nil }
#endif
            let readStatus = name.data.withUnsafeBytes { bytes -> sfs_status in
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
                if let readPin { return sfs_image_pin_read_xattr(h, readPin, bytes.baseAddress, bytes.count, 0, memory, length, &count, &r) }
#endif
                return sfs_image_read_xattr(h, 0, inode, bytes.baseAddress, bytes.count, 0, memory, length, &count, &r)
            }
            if readStatus == SFS_LIMIT { throw POSIXError(.ERANGE) }; try self.check(readStatus, r, missing: ENOATTR)
            guard count == length else { throw POSIXError(.EIO) }
            let value = Data(bytesNoCopy: memory, count: count, deallocator: .free); transferred = true
            self.record(19, inode); reply(try prepare(value), nil)
        } catch { self.record(19, error: error); reply(nil, error) }
    } }
    private func listXattrsBody<T>(of item: FSItem, caller: CallerIdentity?,
                                  prepare: @escaping ([FSFileName]) throws -> T, reply: @escaping (T?, Error?) -> Void) { enqueue(rejected: { reply(nil, $0) }) {
        do {
            let h = try self.ready(mounted: true), inode = try self.id(item); let m = try self.metadata(inode)
            if let caller { try self.ownerAccess(m, inode: inode, access: .readXattr, caller: caller) }
            var names: [FSFileName] = [], after = Data(), total = 0, r = sfs_result()
            while true {
                var entry = sfs_xattr_entry(), found: Int32 = 0
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
                let pin: sfs_pin?
                if self.writesEnabled { pin = try self.token(inode) } else { pin = nil }
#endif
                let status = rawBytes(self.anchor.root_digest).withUnsafeBufferPointer { digest in after.withUnsafeBytes {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
                    if let pin { return sfs_image_pin_next_xattr(h, pin, self.anchor.generation, digest.baseAddress,
                        after.isEmpty ? nil : $0.baseAddress, $0.count, &entry, &found, &r) }
#endif
                    return sfs_image_next_xattr(h, 0, self.anchor.generation, digest.baseAddress, inode,
                        after.isEmpty ? nil : $0.baseAddress, $0.count, &entry, &found, &r)
                } }
                try self.check(status, r); if found == 0 { break }
                guard entry.name_length > 0 && entry.name_length <= 255 else { throw POSIXError(.EIO) }
                let next = Data(rawBytes(entry.name).prefix(entry.name_length)); try component(next, xattr: true)
                guard after.isEmpty || after.lexicographicallyPrecedes(next) else { throw POSIXError(.EIO) }
                total = try checkedXattrListTotal(total, count: names.count, next: next.count)
                names.append(FSFileName(data: next)); after = next
            }
            self.record(20, inode); reply(try prepare(names), nil)
        } catch { self.record(20, error: error); reply(nil, error) }
    } }
    // Refusal retains no caller payload and never waits for queue capacity.
    private func refuse(_ reply: (Error) -> Void) { reply(POSIXError(.EROFS)) }
#if !STALLION_CONTEXT_HANDLERS
    func setAttributes(_ attributes: FSItem.SetAttributesRequest, on item: FSItem, replyHandler: @escaping (FSItem.Attributes?, Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC
        if writesEnabled && selectedAccess == .fixtureWritable {
            let request = FSItem.GetAttributesRequest(); request.wantedAttributes = [.size, .allocSize, .modifyTime, .changeTime, .fileID]
            setWritableAttributes(attributes, item: item, caller: nil, request: { request }, prepare: { $0 }, reply: replyHandler); return
        }
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
        if writesEnabled && selectedAccess == .fixtureWritable { performWrite(contents, item: item, offset: offset, prepare: { count, _ in count }) { replyHandler($0 ?? 0, $1) }; return }
#endif
        refuse { replyHandler(0, $0) }
    }
    func setXattr(named name: FSFileName, to value: Data?, on item: FSItem, policy: FSVolume.SetXattrPolicy, replyHandler: @escaping (Error?) -> Void) { refuse { replyHandler($0) } }
#endif
#if STALLION_CONTEXT_HANDLERS
    private static func validateCallerWanted(_ wanted: FSItem.Attribute) throws {
        try validateWanted(wanted.rawValue)
        guard wanted.rawValue & ~0x3fff == 0 else { throw POSIXError(.ENOTSUP) }
    }
    private struct ResultRequirements {
        let type: FSVolumeHandlerResult.Type
        let caller: FSItem.Attribute
        let sdk: FSItem.Attribute
        init(_ type: FSVolumeHandlerResult.Type, explicit: FSItem.Attribute = []) {
            self.type = type; caller = explicit
            sdk = type.requestedAttributes.wantedAttributes
        }
        func request() throws -> FSItem.GetAttributesRequest {
            try StallionVolume.validateCallerWanted(caller)
            let request = FSItem.GetAttributesRequest()
            request.wantedAttributes = sdk.union(caller)
            return request
        }
    }
    private static func requireResultValidity(_ attributes: FSItem.Attributes, sdk: FSItem.Attribute, caller: FSItem.Attribute) throws {
        try requireValid(attributes, sdk)
        try requireValid(attributes, caller)
    }
    private static func requireValid(_ attributes: FSItem.Attributes, _ required: FSItem.Attribute) throws {
        let raw = UInt(bitPattern: required.rawValue)
        for index in 0..<UInt.bitWidth {
            let bit = UInt(1) << index
            if raw & bit != 0 && !attributes.isValid(FSItem.Attribute(rawValue: Int(bitPattern: bit))) {
                throw POSIXError(.ENOTSUP)
            }
        }
    }
#if STALLION_ADAPTER_CHECK
    var rejectResultForTesting: ((String) -> Bool)?
    var preparedAttributesForTesting: ((String, FSItem.Attributes) -> Void)?
    static func resultRequestForTesting(_ type: FSVolumeHandlerResult.Type, explicit: FSItem.Attribute = []) throws -> FSItem.GetAttributesRequest {
        try ResultRequirements(type, explicit: explicit).request()
    }
    static func requireValidForTesting(_ attributes: FSItem.Attributes, required: FSItem.Attribute) throws {
        try requireValid(attributes, required)
    }
    static func requireResultValidityForTesting(_ attributes: FSItem.Attributes, sdk: FSItem.Attribute, caller: FSItem.Attribute) throws {
        try validateCallerWanted(caller)
        try requireResultValidity(attributes, sdk: sdk, caller: caller)
    }
#endif
    private func handlerResult<T: FSVolumeHandlerResult>(_ type: T.Type, _ construct: () -> T?) throws -> T {
        let result = construct()
#if STALLION_ADAPTER_CHECK
        if rejectResultForTesting?(String(describing: type)) == true { throw POSIXError(.EIO) }
#endif
        guard let result else { throw POSIXError(.EIO) }
        return result
    }
    private func preparedResultAttributes(_ m: sfs_metadata_entry, _ request: FSItem.GetAttributesRequest,
                                          _ requirements: ResultRequirements, parents: inout ParentEvidence, detachedParent: LastKnownParent? = nil) throws -> FSItem.Attributes {
        try Self.validateCallerWanted(requirements.caller)
        guard request.wantedAttributes == requirements.sdk.union(requirements.caller) else { throw POSIXError(.EIO) }
        // SDK result snapshots may supply additional truthful policy attributes.
        let attributes = try populateAttributes(m, request, parents: &parents, includeResultPolicy: true, detachedParent: detachedParent)
#if STALLION_ADAPTER_CHECK
        preparedAttributesForTesting?(String(describing: requirements.type), attributes)
#endif
        try Self.requireResultValidity(attributes, sdk: requirements.sdk, caller: requirements.caller)
        return attributes
    }
    private func resultAttributes(_ m: sfs_metadata_entry, _ type: FSVolumeHandlerResult.Type,
                                  explicit: FSItem.Attribute = []) throws -> FSItem.Attributes {
        let requirements = ResultRequirements(type, explicit: explicit)
        var parents = ParentEvidence()
        return try preparedResultAttributes(m, requirements.request(), requirements, parents: &parents)
    }
    func activateVolume(options: FSTaskOptions, replyHandler: @escaping (FSActivateResult?, Error?) -> Void) {
        activateHandler(replyHandler: replyHandler)
    }
    private func activateHandler(replyHandler: @escaping (FSActivateResult?, Error?) -> Void) {
        activateBody(prepare: { root in
            return try self.handlerResult(FSActivateResult.self) { FSActivateResult(rootItem: root) }
        }, reply: replyHandler)
    }
    func deactivateVolume(options: FSDeactivateOptions, replyHandler: @escaping (Error?) -> Void) {
        deactivate(options: options, replyHandler: replyHandler)
    }
    func lookupItem(named name: FSFileName, in directory: FSItem, context: FSContext,
                    replyHandler: @escaping (FSLookupItemResult?, Error?) -> Void) {
        lookupHandler(name, directory: directory, caller: CallerIdentity(context), reply: replyHandler)
    }
    private func lookupHandler(_ name: FSFileName, directory: FSItem, caller: CallerIdentity,
                               reply: @escaping (FSLookupItemResult?, Error?) -> Void) {
        lookupBody(name, directory: directory, caller: caller, prepare: { item, returned, m in
            let attributes = try self.resultAttributes(m, FSLookupItemResult.self)
            return try self.handlerResult(FSLookupItemResult.self) {
                FSLookupItemResult(foundItem: item, itemName: returned, itemAttributes: attributes)
            }
        }, reply: reply)
    }
    func getAttributes(_ request: FSItem.GetAttributesRequest, of item: FSItem, context: FSContext,
                       replyHandler: @escaping (FSGetAttributesResult?, Error?) -> Void) {
        getAttributesHandler(request, item: item, caller: CallerIdentity(context), reply: replyHandler)
    }
    private func getAttributesHandler(_ request: FSItem.GetAttributesRequest, item: FSItem, caller: CallerIdentity,
                                      reply: @escaping (FSGetAttributesResult?, Error?) -> Void) {
        let explicit = request.wantedAttributes
        let requirements = ResultRequirements(FSGetAttributesResult.self, explicit: explicit)
        getAttributesBody({ try requirements.request() }, item: item, caller: caller, requirements: requirements, prepare: { attributes in
            return try self.handlerResult(FSGetAttributesResult.self) { FSGetAttributesResult(attributes: attributes) }
        }, reply: reply)
    }
    func readSymbolicLink(_ item: FSItem, context: FSContext, replyHandler: @escaping (FSReadSymlinkResult?, Error?) -> Void) {
        readlinkHandler(item, caller: CallerIdentity(context), reply: replyHandler)
    }
    private func readlinkHandler(_ item: FSItem, caller: CallerIdentity, reply: @escaping (FSReadSymlinkResult?, Error?) -> Void) {
        readlinkBody(item, caller: caller, prepare: { name, m in
            let attributes = try self.resultAttributes(m, FSReadSymlinkResult.self)
            return try self.handlerResult(FSReadSymlinkResult.self) { FSReadSymlinkResult(contents: name, symlinkAttributes: attributes) }
        }, reply: reply)
    }
    func enumerateDirectory(_ directory: FSItem, startingAt cookie: FSDirectoryCookie,
                            verifier: FSDirectoryVerifier, attributes request: FSItem.GetAttributesRequest?,
                            packer: FSDirectoryEntryPacker, context: FSContext,
                            replyHandler: @escaping (FSEnumerateDirectoryResult?, Error?) -> Void) {
        enumerateHandler(directory, startingAt: cookie, verifier: verifier, attributes: request, caller: CallerIdentity(context), pack: {
            packer.packEntry(name: $0, itemType: $1, itemID: $2, nextCookie: $3, attributes: $4)
        }, reply: replyHandler)
    }
    private func enumerateHandler(_ directory: FSItem, startingAt cookie: FSDirectoryCookie,
                                  verifier: FSDirectoryVerifier, attributes request: FSItem.GetAttributesRequest?,
                                  caller: CallerIdentity, pack: @escaping DirectoryPack,
                                  reply: @escaping (FSEnumerateDirectoryResult?, Error?) -> Void) {
        enumerateDirectory(directory, startingAt: cookie, verifier: verifier, attributes: request, pack: pack, caller: caller,
            requestForPacking: { explicit in
                guard let explicit else { return nil }
                let copied = FSItem.GetAttributesRequest()
                copied.wantedAttributes = explicit.wantedAttributes
                try Self.validateCallerWanted(copied.wantedAttributes)
                return copied
            }) { verifier, error in
            if let error { reply(nil, error); return }
            do { reply(try self.handlerResult(FSEnumerateDirectoryResult.self) { FSEnumerateDirectoryResult(verifier: verifier.rawValue) }, nil) }
            catch { reply(nil, error) }
        }
    }
    func getXattr(named name: FSFileName, of item: FSItem, context: FSContext,
                  replyHandler: @escaping (FSGetXattrResult?, Error?) -> Void) {
        getXattrHandler(name, item: item, caller: CallerIdentity(context), reply: replyHandler)
    }
    private func getXattrHandler(_ name: FSFileName, item: FSItem, caller: CallerIdentity, reply: @escaping (FSGetXattrResult?, Error?) -> Void) {
        getXattrBody(named: name, of: item, caller: caller, prepare: { value in
            return try self.handlerResult(FSGetXattrResult.self) { FSGetXattrResult(xattrValue: value) }
        }, reply: reply)
    }
    func listXattrs(of item: FSItem, context: FSContext, replyHandler: @escaping (FSListXattrsResult?, Error?) -> Void) {
        listXattrsHandler(item, caller: CallerIdentity(context), reply: replyHandler)
    }
    private func listXattrsHandler(_ item: FSItem, caller: CallerIdentity, reply: @escaping (FSListXattrsResult?, Error?) -> Void) {
        listXattrsBody(of: item, caller: caller, prepare: { names in
            return try self.handlerResult(FSListXattrsResult.self) { FSListXattrsResult(xattrNames: names) }
        }, reply: reply)
    }
    func read(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer,
              replyHandler: @escaping (FSReadFileResult?, Error?) -> Void) {
        readBody(from: item, at: offset, length: length, into: buffer, prepare: { count, m in
            let attributes = try self.resultAttributes(m, FSReadFileResult.self)
            return try self.handlerResult(FSReadFileResult.self) { FSReadFileResult(bytesRead: count, itemAttributes: attributes) }
        }, reply: replyHandler)
    }
    // The item-level grant comes only from successful contextual open. FSKit's
    // descriptor rejection, cached writeback and mapping-close ordering still
    // require mounted qualification; no caller identity is synthesized here.
    func write(contents: Data, to item: FSItem, at offset: off_t, replyHandler: @escaping (FSWriteFileResult?, Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        if writesEnabled {
            let requirements = ResultRequirements(FSWriteFileResult.self)
            var request: FSItem.GetAttributesRequest?
            performWrite(contents, item: item, offset: offset, admit: {
                request = try requirements.request()
            }, prepare: { count, m in
                guard let request else { throw POSIXError(.EIO) }
                var parents = ParentEvidence()
                let attributes = try self.preparedResultAttributes(m, request, requirements, parents: &parents)
                return try self.handlerResult(FSWriteFileResult.self) { FSWriteFileResult(bytesWritten: count, itemAttributes: attributes, freeSpace: nil) }
            }, reply: replyHandler); return
        }
#endif
        refuse { replyHandler(nil, $0) }
    }
    func setAttributes(_ attributes: FSItem.SetAttributesRequest, on item: FSItem, context: FSContext,
                       replyHandler: @escaping (FSSetAttributesResult?, Error?) -> Void) {
        setAttributesHandler(attributes, item: item, caller: CallerIdentity(context), reply: replyHandler)
    }
    private func setAttributesHandler(_ attributes: FSItem.SetAttributesRequest, item: FSItem, caller: CallerIdentity,
                                      reply: @escaping (FSSetAttributesResult?, Error?) -> Void) {
        attributes.consumedAttributes = []
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        if writesEnabled {
            let requirements = ResultRequirements(FSSetAttributesResult.self, explicit: [.size, .allocSize, .modifyTime, .changeTime, .fileID])
            setWritableAttributes(attributes, item: item, caller: caller, requirements: requirements,
                request: { try requirements.request() }, prepare: { a in
                    return try self.handlerResult(FSSetAttributesResult.self) { FSSetAttributesResult(attributes: a, freeSpace: nil) }
                }, reply: reply); return
        }
#endif
        refuse { reply(nil, $0) }
    }
    func createItem(named name: FSFileName, type: FSItem.ItemType, in directory: FSItem, attributes: FSItem.SetAttributesRequest, context: FSContext, replyHandler: @escaping (FSCreateItemResult?, Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        createItemHandler(name, type: type, directory: directory, attributes: attributes, caller: CallerIdentity(context), reply: replyHandler)
#else
        refuse { replyHandler(nil, $0) }
#endif
    }
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
    private enum CreateInput {
        case item(FSItem.ItemType)
        case symbolicLink(Data)
        var target: Data? {
            if case .symbolicLink(let bytes) = self { return bytes }
            return nil
        }
    }
    private struct CreateAttributes {
        let kind: sfs_kind
        let initial: sfs_metadata_initial
        let consumed: FSItem.Attribute
        init(_ attributes: FSItem.SetAttributesRequest, input: CreateInput, caller: CallerIdentity, owner: uid_t) throws {
            let modeKind: UInt32
            switch input {
            case .item(.file): kind = SFS_FILE; modeKind = UInt32(S_IFREG)
            case .item(.directory): kind = SFS_DIRECTORY; modeKind = UInt32(S_IFDIR)
            case .symbolicLink: kind = SFS_SYMLINK; modeKind = UInt32(S_IFLNK)
            default: throw POSIXError(.ENOTSUP)
            }
            let unsupported: [FSItem.Attribute] = [.type, .linkCount, .allocSize, .fileID, .parentID,
                .accessTime, .modifyTime, .changeTime, .birthTime, .backupTime, .addedTime,
                .supportsLimitedXAttrs, .inhibitKernelOffloadedIO]
            guard !unsupported.contains(where: { attributes.isValid($0) }),
                  attributes.isValid(.mode), attributes.isValid(.uid), attributes.isValid(.gid) else { throw POSIXError(.ENOTSUP) }
            guard let uid = uid_t(exactly: caller.uid), let gid = gid_t(exactly: caller.gid),
                  uid == owner, attributes.uid == uid, attributes.gid == gid else { throw POSIXError(.EACCES) }
            let mode = attributes.mode, kind = mode & UInt32(S_IFMT)
            guard kind == 0 || kind == modeKind else { throw POSIXError(.EINVAL) }
            guard mode & ~(UInt32(S_IFMT) | 0o777) == 0 else { throw POSIXError(.ENOTSUP) }
            var used: FSItem.Attribute = [.mode, .uid, .gid]
            if attributes.isValid(.flags) { guard attributes.flags == 0 else { throw POSIXError(.ENOTSUP) }; used.insert(.flags) }
            if attributes.isValid(.size) { guard self.kind != SFS_SYMLINK, attributes.size == 0 else { throw POSIXError(.ENOTSUP) }; used.insert(.size) }
            var value = sfs_metadata_initial()
            value.mode = modeKind | (mode & 0o777); value.uid = uid; value.gid = gid
            initial = value; consumed = used
        }
    }
    private func finishFailedCreate(_ item: StallionItem?, error: Error) {
        guard var pending = pendingCreate else { return }
        // Only this never-returned item can be removed. A quarantined record
        // owns token/accounting facts, not a retained Swift item.
        if !pending.ticket {
            guard let item, items[pending.inode] === item else {
                pending.quarantined = true; pendingCreate = pending; latch(POSIXError(.EIO)); return
            }
            items.removeValue(forKey: pending.inode); pending.ticket = true
        }
        item?.pin = nil; item?.reclaimed = true; item?.retainedModes = []; item?.lastKnownParent = nil
        if let pin = pending.pin {
            switch pending.ownership {
            case .discarded: break // Abort/automatic discard already retired it.
            case .reserved, .promoted:
                if let handle {
                    var receipt = sfs_result()
                    pending.outcome.releaseAttempted = true
                    let status: sfs_status
#if STALLION_ADAPTER_CHECK
                    if let injected = createReleaseForTesting { status = injected(handle, pin, &receipt) }
                    else { status = sfs_image_pin_release(handle, pin, &receipt) }
#else
                    status = sfs_image_pin_release(handle, pin, &receipt)
#endif
                    pending.outcome.release = receipt
                    // A promoted pin survives C success even when Swift rejected
                    // the receipt. Memory-only release must not compare old anchor.
                    if status != SFS_OK { pending.quarantined = true; latch(sfsError(status, receipt)) }
                } else { pending.quarantined = true; latch(POSIXError(.EIO)) }
            case .transaction:
                pending.quarantined = true; latch(POSIXError(.EIO))
            }
        }
#if STALLION_ADAPTER_CHECK
        createOutcomeForTesting = pending.outcome
#endif
        pendingCreate = pending.quarantined ? pending : nil
        rememberDelivery(error, pending.outcome.original)
    }
    private func createItemHandler(_ name: FSFileName, type: FSItem.ItemType, directory: FSItem,
                                   attributes: FSItem.SetAttributesRequest, caller: CallerIdentity,
                                   reply: @escaping (FSCreateItemResult?, Error?) -> Void) {
        createEntryHandler(name, input: .item(type), directory: directory, attributes: attributes, caller: caller,
                           resultType: FSCreateItemResult.self, construct: { item, name, child, parent in
            FSCreateItemResult(newItem: item, newItemName: name, newItemAttributes: child, directoryAttributes: parent, freeSpace: nil)
        }, reply: reply)
    }
    private func createSymlinkHandler(_ name: FSFileName, directory: FSItem, attributes: FSItem.SetAttributesRequest,
                                      linkContents: FSFileName, caller: CallerIdentity,
                                      reply: @escaping (FSCreateSymlinkResult?, Error?) -> Void) {
        // FSFileName may already have truncated a NUL suffix. Only delivered bytes are available here.
        createEntryHandler(name, input: .symbolicLink(linkContents.data), directory: directory, attributes: attributes, caller: caller,
                           resultType: FSCreateSymlinkResult.self, construct: { item, name, child, parent in
            FSCreateSymlinkResult(newItem: item, newItemName: name, newItemAttributes: child, directoryAttributes: parent, freeSpace: nil)
        }, reply: reply)
    }
    private func createEntryHandler<Result: FSCreateItemResult>(_ name: FSFileName, input: CreateInput, directory: FSItem,
                                   attributes: FSItem.SetAttributesRequest, caller: CallerIdentity, resultType: Result.Type,
                                   construct: @escaping (StallionItem, FSFileName, FSItem.Attributes, FSItem.Attributes) -> Result?,
                                   reply: @escaping (Result?, Error?) -> Void) {
        attributes.consumedAttributes = []
        guard writesEnabled else { refuse { reply(nil, $0) }; return }
        let bytes = name.data, target = input.target
        let charge = bytes.count.addingReportingOverflow(target?.count ?? 0)
        let values: CreateAttributes
        do {
            try component(bytes)
            guard bytes != Data(".".utf8), bytes != Data("..".utf8) else { throw POSIXError(.EINVAL) }
            if let target {
                guard target.count <= Int(SFS_SYMLINK_MAX) else { throw POSIXError(.ENAMETOOLONG) }
                guard !target.isEmpty && !target.contains(0) else { throw POSIXError(.EINVAL) }
            }
            guard !charge.overflow else { throw POSIXError(.E2BIG) }
            values = try CreateAttributes(attributes, input: input, caller: caller, owner: owner)
        } catch { reply(nil, error); return }
        enqueue(retainedBytes: charge.partialValue, namespaceOperation: true, rejected: { reply(nil, $0) }) {
            var receipt = sfs_result(), created: StallionItem?
            var ownsPending = false
            do {
                if let error = self.deliveryError() { throw error }
#if STALLION_ADAPTER_CHECK
                try self.createStageForTesting?("preflight", nil)
#endif
                let h = try self.ready(mounted: true)
                guard self.resource.isWritable else { throw POSIXError(.EACCES) }
                let parent = try self.id(directory), parentMetadata = try self.metadata(parent)
                try checkLinkParentPolicy(parentMetadata, owner: self.owner, caller: caller)
                try self.ownerAccess(parentMetadata, inode: parent, access: values.kind == SFS_DIRECTORY ? .search : [.addFile, .search], caller: caller)
                var found = sfs_entry()
                let status = bytes.withUnsafeBytes { sfs_image_lookup(h, 0, parent, $0.baseAddress, $0.count, &found, &receipt) }
                if status != SFS_NOT_FOUND { try self.check(status, receipt); throw POSIXError(.EEXIST) }
                guard anchorMatches(receipt, self.anchor) else { let e = POSIXError(.ESTALE); self.latch(e); throw e }
                let requirements = ResultRequirements(resultType), request = try requirements.request()
                guard self.pendingCreate == nil, self.items.count < self.itemLimit else { throw POSIXError(.ENFILE) }
                self.pendingCreate = PendingCreate(); ownsPending = true
                var pin = sfs_pin()
                let reserved = sfs_image_pin_reserve(h, &pin, &receipt)
                if reserved == SFS_OK { self.pendingCreate?.pin = pin }
                self.pendingCreate?.outcome.original = receipt
                try self.check(reserved, receipt)
#if STALLION_ADAPTER_CHECK
                self.createTokenForTesting = pin
                try self.createStageForTesting?("reserved", nil)
#endif
                let result = try self.mutate({ h, r in
#if STALLION_ADAPTER_CHECK
                    try self.createStageForTesting?("before-add", nil)
#endif
                    var initial = values.initial, inode: UInt64 = 0
                    let status = bytes.withUnsafeBytes { name -> sfs_status in
                        if let target {
                            return target.withUnsafeBytes { sfs_image_symlink_metadata(h, parent, name.baseAddress, name.count,
                                                                                     $0.baseAddress, $0.count, &initial, &inode, &r) }
                        }
                        return sfs_image_add_metadata(h, parent, name.baseAddress, name.count, values.kind, &initial, &inode, &r)
                    }
                    try self.check(status, r)
                    self.pendingCreate?.inode = inode
#if STALLION_ADAPTER_CHECK
                    try self.createStageForTesting?("added", nil)
#endif
                    _ = try itemIdentifier(inode)
                    let item = StallionItem(inode); item.pin = pin; created = item
#if STALLION_ADAPTER_CHECK
                    try self.createStageForTesting?("allocated", item)
#endif
                    try self.check(sfs_image_pin_bind(h, pin, inode, &r), r)
#if STALLION_ADAPTER_CHECK
                    try self.createStageForTesting?("bound", item)
#endif
                    guard self.items[inode] == nil else { throw POSIXError(.EIO) }
                    self.items[inode] = item; self.pendingCreate?.ticket = false
#if STALLION_ADAPTER_CHECK
                    try self.createStageForTesting?("inserted", item)
#endif
                }, prepare: { h, r in
                    guard let item = created else { throw POSIXError(.EIO) }
                    let child = try self.transactionMetadata(h, inode: item.inode, receipt: &r)
                    let directoryMetadata = try self.transactionMetadata(h, inode: parent, receipt: &r)
                    var childEvidence = ParentEvidence(), parentEvidence = ParentEvidence()
                    let childAttributes = try self.preparedResultAttributes(child, request, requirements, parents: &childEvidence)
                    let parentAttributes = try self.preparedResultAttributes(directoryMetadata, request, requirements, parents: &parentEvidence)
                    return try self.handlerResult(resultType) { construct(item, name, childAttributes, parentAttributes) }
                }, receipt: &receipt)
#if STALLION_ADAPTER_CHECK
                self.createOutcomeForTesting = self.pendingCreate!.outcome
#endif
                self.pendingCreate = nil
                attributes.consumedAttributes = values.consumed
                reply(result, nil)
            } catch {
                if ownsPending { self.finishFailedCreate(created, error: error) }
                reply(nil, error)
            }
        }
    }
#if STALLION_ADAPTER_CHECK
    func createVisibilityForTesting(_ item: StallionItem) -> Bool {
        (try? ownedItem(item)) == nil && (try? canonical(item.inode)) == nil
    }
    func createResultForTesting(_ name: FSFileName, type: FSItem.ItemType = .file, directory: FSItem,
                                attributes: FSItem.SetAttributesRequest, caller: CallerIdentity,
                                reply: @escaping (FSCreateItemResult?, Error?) -> Void) {
        createItemHandler(name, type: type, directory: directory, attributes: attributes, caller: caller, reply: reply)
    }
    func symlinkResultForTesting(_ name: FSFileName, directory: FSItem, attributes: FSItem.SetAttributesRequest,
                                 linkContents: FSFileName, caller: CallerIdentity,
                                 reply: @escaping (FSCreateSymlinkResult?, Error?) -> Void) {
        createSymlinkHandler(name, directory: directory, attributes: attributes, linkContents: linkContents, caller: caller, reply: reply)
    }
#endif
#endif
    func createSymbolicLink(named name: FSFileName, in directory: FSItem, attributes: FSItem.SetAttributesRequest, linkContents: FSFileName, context: FSContext, replyHandler: @escaping (FSCreateSymlinkResult?, Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        createSymlinkHandler(name, directory: directory, attributes: attributes, linkContents: linkContents, caller: CallerIdentity(context), reply: replyHandler)
#else
        refuse { replyHandler(nil, $0) }
#endif
    }
    func createLink(to item: FSItem, named name: FSFileName, in directory: FSItem, context: FSContext, replyHandler: @escaping (FSCreateLinkResult?, Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        createLinkHandler(item, name: name, directory: directory, caller: CallerIdentity(context), reply: replyHandler)
#else
        refuse { replyHandler(nil, $0) }
#endif
    }
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
    private func createLinkHandler(_ item: FSItem, name: FSFileName, directory: FSItem, caller: CallerIdentity,
                                   reply: @escaping (FSCreateLinkResult?, Error?) -> Void) {
        guard writesEnabled else { refuse { reply(nil, $0) }; return }
        let bytes = name.data
        var validation: Error?
        do {
            try component(bytes)
            guard bytes != Data(".".utf8), bytes != Data("..".utf8) else { throw POSIXError(.EINVAL) }
        } catch { validation = error }
        enqueue(retainedBytes: bytes.count, namespaceOperation: true, validationError: validation, rejected: { reply(nil, $0) }) {
            var receipt = sfs_result()
            do {
                if let error = self.deliveryError() { throw error }
#if STALLION_ADAPTER_CHECK
                self.linkPreflightForTesting?()
#endif
                let h = try self.ready(mounted: true)
                guard self.resource.isWritable else { throw POSIXError(.EACCES) }
                let source = try self.id(item), parent = try self.id(directory)
                let sourceMetadata = try self.metadata(source), parentMetadata = try self.metadata(parent)
                guard sourceMetadata.link_count > 0 else { throw POSIXError(.ENOENT) }
                guard sourceMetadata.entry.kind == SFS_FILE || sourceMetadata.entry.kind == SFS_SYMLINK else { throw POSIXError(.ENOTSUP) }
                guard sourceMetadata.flags == 0, parentMetadata.flags == 0 else { throw POSIXError(.ENOTSUP) }
                guard sourceMetadata.mode & 0o6000 == 0 else { throw POSIXError(.EACCES) }
                try self.ownerAccess(sourceMetadata, inode: source, access: .readAttributes, caller: caller)
                try checkLinkParentPolicy(parentMetadata, owner: self.owner, caller: caller)
                try self.ownerAccess(parentMetadata, inode: parent, access: [.addFile, .search], caller: caller)
                try checkLinkCount(sourceMetadata.link_count)
                var found = sfs_entry()
                let status = bytes.withUnsafeBytes { sfs_image_lookup(h, 0, parent, $0.baseAddress, $0.count, &found, &receipt) }
                if status != SFS_NOT_FOUND { try self.check(status, receipt); throw POSIXError(.EEXIST) }
                guard anchorMatches(receipt, self.anchor) else { let error = POSIXError(.ESTALE); self.latch(error); throw error }
                let requirements = ResultRequirements(FSCreateLinkResult.self), request = try requirements.request()
                let result = try self.mutate({ h, r in
                    let status = bytes.withUnsafeBytes { sfs_image_link(h, source, parent, $0.baseAddress, $0.count, &r) }
                    try self.check(status, r)
                }, prepare: { h, r in
                    let sourceMetadata = try self.transactionMetadata(h, inode: source, receipt: &r)
                    let parentMetadata = try self.transactionMetadata(h, inode: parent, receipt: &r)
                    var sourceEvidence = ParentEvidence(), parentEvidence = ParentEvidence()
                    let linked = try self.preparedResultAttributes(sourceMetadata, request, requirements, parents: &sourceEvidence)
                    let parentAttributes = try self.preparedResultAttributes(parentMetadata, request, requirements, parents: &parentEvidence)
                    return try self.handlerResult(FSCreateLinkResult.self) {
                        FSCreateLinkResult(linkName: name, linkAttributes: linked, directoryAttributes: parentAttributes, freeSpace: nil)
                    }
                }, receipt: &receipt)
                reply(result, nil)
            } catch { reply(nil, error) }
        }
    }
#if STALLION_ADAPTER_CHECK
    var linkPreflightForTesting: (() -> Void)?
    func linkResultForTesting(_ item: FSItem, name: FSFileName, directory: FSItem, caller: CallerIdentity,
                              reply: @escaping (FSCreateLinkResult?, Error?) -> Void) {
        createLinkHandler(item, name: name, directory: directory, caller: caller, reply: reply)
    }
    func linkAccessForTesting(_ item: FSItem, access: FSVolume.AccessMask, caller: CallerIdentity) throws {
        let inode = try id(item)
        try ownerAccess(metadata(inode), inode: inode, access: access, caller: caller)
    }
    var linkBudgetForTesting: (Int, Int) { callbacks.snapshotForTesting }
#endif
#endif
    func removeItem(_ item: FSItem, named name: FSFileName, from directory: FSItem, context: FSContext, replyHandler: @escaping (FSRemoveItemResult?, Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        removeItemHandler(item, name: name, directory: directory, caller: CallerIdentity(context), reply: replyHandler)
#else
        refuse { replyHandler(nil, $0) }
#endif
    }
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
    private func removeItemHandler(_ item: FSItem, name: FSFileName, directory: FSItem, caller: CallerIdentity,
                                   reply: @escaping (FSRemoveItemResult?, Error?) -> Void) {
        guard writesEnabled else { refuse { reply(nil, $0) }; return }
        let bytes = name.data
        var validation: Error?
        do {
            try component(bytes)
            guard bytes != Data(".".utf8), bytes != Data("..".utf8) else { throw POSIXError(.EINVAL) }
        } catch { validation = error }
        enqueue(retainedBytes: bytes.count, namespaceOperation: true, validationError: validation, rejected: { reply(nil, $0) }) {
            var receipt = sfs_result()
            do {
                if let error = self.deliveryError() { throw error }
                let h = try self.ready(mounted: true)
                guard self.pendingCreate == nil else { throw POSIXError(.EBUSY) }
#if STALLION_ADAPTER_CHECK
                self.removePreflightForTesting?()
#endif
                guard self.resource.isWritable else { throw POSIXError(.EACCES) }
                let source = try self.id(item), parent = try self.id(directory)
                let sourceMetadata = try self.metadata(source), parentMetadata = try self.metadata(parent)
                guard sourceMetadata.link_count > 0 else { throw POSIXError(.ENOENT) }
                guard source != 1, sourceMetadata.entry.kind == SFS_FILE || sourceMetadata.entry.kind == SFS_SYMLINK || sourceMetadata.entry.kind == SFS_DIRECTORY else { throw POSIXError(.ENOTSUP) }
                guard sourceMetadata.flags == 0, parentMetadata.flags == 0 else { throw POSIXError(.ENOTSUP) }
                guard sourceMetadata.mode & 0o6000 == 0 else { throw POSIXError(.EACCES) }
                try self.ownerAccess(sourceMetadata, inode: source, access: .readAttributes, caller: caller)
                try checkLinkParentPolicy(parentMetadata, owner: self.owner, caller: caller)
                try self.ownerAccess(parentMetadata, inode: parent, access: .search, caller: caller)
                var found = sfs_entry()
                let status = bytes.withUnsafeBytes { sfs_image_lookup(h, 0, parent, $0.baseAddress, $0.count, &found, &receipt) }
                try self.check(status, receipt)
                guard found.inode == source else { throw POSIXError(.ESTALE) }
                if sourceMetadata.entry.kind == SFS_DIRECTORY {
                    // One bounded read; expected-inode unlink rechecks emptiness inside the transaction.
                    var cursor = sfs_cookie(), child = sfs_entry(), present: Int32 = 0
                    try self.check(sfs_image_next(h, 0, source, &cursor, &child, &present, &receipt), receipt)
                    guard anchorMatches(receipt, self.anchor) else { let error = POSIXError(.ESTALE); self.latch(error); throw error }
                    guard present == 0 else { throw POSIXError(.ENOTEMPTY) }
                }
                let requirements = ResultRequirements(FSRemoveItemResult.self), request = try requirements.request()
                let sourceItem = try self.ownedItem(item)
                // This verified removal relationship is not a live core namespace parent.
                let removedParent = sourceMetadata.link_count == 1 ? LastKnownParent(item: ObjectIdentifier(sourceItem),
                    pin: try self.token(source), inode: source, kind: sourceMetadata.entry.kind, parent: parent) : nil
#if STALLION_ADAPTER_CHECK
                self.removeMutationForTesting = true
                defer { self.removeMutationForTesting = false }
#endif
                let result = try self.mutate({ h, r in
                    let status = bytes.withUnsafeBytes { sfs_image_unlink_expected(h, parent, $0.baseAddress, $0.count, source, &r) }
                    try self.check(status, r)
                }, prepare: { h, r in
                    let sourceMetadata = try self.transactionMetadata(h, inode: source, receipt: &r)
                    let parentMetadata = try self.transactionMetadata(h, inode: parent, receipt: &r)
                    if let removedParent { _ = try self.detachedParent(sourceMetadata, candidate: removedParent) }
                    var sourceEvidence = ParentEvidence(), parentEvidence = ParentEvidence()
                    let removed = try self.preparedResultAttributes(sourceMetadata, request, requirements, parents: &sourceEvidence, detachedParent: removedParent)
                    let parentAttributes = try self.preparedResultAttributes(parentMetadata, request, requirements, parents: &parentEvidence)
                    return try self.handlerResult(FSRemoveItemResult.self) {
                        FSRemoveItemResult(itemAttributes: removed, directoryAttributes: parentAttributes, freeSpace: nil)
                    }
                }, receipt: &receipt)
                if let removedParent {
                    guard self.items[source] === sourceItem, let pin = sourceItem.pin,
                          !sourceItem.reclaimed, sameBytes(pin, removedParent.pin) else {
                        let error = POSIXError(.ESTALE); self.latch(error); self.rememberDelivery(error, receipt); throw error
                    }
                    sourceItem.lastKnownParent = removedParent
                }
                reply(result, nil)
            } catch { reply(nil, error) }
        }
    }
#if STALLION_ADAPTER_CHECK
    private var removeMutationForTesting = false
    var removePreflightForTesting: (() -> Void)?
    var removeCommitReceiptForTesting: ((sfs_result, inout sfs_result) -> Void)?
    func removeResultForTesting(_ item: FSItem, name: FSFileName, directory: FSItem, caller: CallerIdentity,
                                reply: @escaping (FSRemoveItemResult?, Error?) -> Void) {
        removeItemHandler(item, name: name, directory: directory, caller: caller, reply: reply)
    }
#endif
#endif
    func renameItem(_ item: FSItem, inDirectory sourceDirectory: FSItem, named sourceName: FSFileName, to destinationName: FSFileName, inDirectory destinationDirectory: FSItem, overItem: FSItem?, context: FSContext, replyHandler: @escaping (FSRenameItemResult?, Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        renameItemHandler(item, sourceDirectory: sourceDirectory, sourceName: sourceName, destinationName: destinationName,
                          destinationDirectory: destinationDirectory, overItem: overItem, caller: CallerIdentity(context), reply: replyHandler)
#else
        refuse { replyHandler(nil, $0) }
#endif
    }
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
    private func renameItemHandler(_ item: FSItem, sourceDirectory: FSItem, sourceName: FSFileName,
                                   destinationName: FSFileName, destinationDirectory: FSItem, overItem: FSItem?,
                                   caller: CallerIdentity, reply: @escaping (FSRenameItemResult?, Error?) -> Void) {
        guard writesEnabled else { refuse { reply(nil, $0) }; return }
        let oldBytes = sourceName.data, newBytes = destinationName.data
        let charge = oldBytes.count.addingReportingOverflow(newBytes.count)
        var validation: Error?
        do {
            guard !charge.overflow else { throw POSIXError(.E2BIG) }
            for bytes in [oldBytes, newBytes] {
                try component(bytes)
                guard bytes != Data(".".utf8), bytes != Data("..".utf8) else { throw POSIXError(.EINVAL) }
            }
        } catch { validation = error }
        enqueue(retainedBytes: charge.overflow ? Int.max : charge.partialValue, namespaceOperation: true,
                validationError: validation, rejected: { reply(nil, $0) }) {
            var receipt = sfs_result()
            do {
                if let error = self.deliveryError() { throw error }
                let h = try self.ready(mounted: true)
                guard self.pendingCreate == nil else { throw POSIXError(.EBUSY) }
#if STALLION_ADAPTER_CHECK
                self.renamePreflightForTesting?()
#endif
                guard self.resource.isWritable else { throw POSIXError(.EACCES) }
                let source = try self.id(item), oldParent = try self.id(sourceDirectory), newParent = try self.id(destinationDirectory)
                let sourceMetadata = try self.metadata(source), oldMetadata = try self.metadata(oldParent), newMetadata = try self.metadata(newParent)
                guard sourceMetadata.link_count > 0 else { throw POSIXError(.ENOENT) }
                guard source != 1,
                      sourceMetadata.entry.kind == SFS_FILE || sourceMetadata.entry.kind == SFS_DIRECTORY || sourceMetadata.entry.kind == SFS_SYMLINK else { throw POSIXError(.ENOTSUP) }
                if sourceMetadata.entry.kind == SFS_DIRECTORY && sourceMetadata.link_count != 1 { throw POSIXError(.ENOTSUP) }
                guard sourceMetadata.flags == 0, oldMetadata.flags == 0, newMetadata.flags == 0 else { throw POSIXError(.ENOTSUP) }
                guard sourceMetadata.mode & 0o7000 == 0 else { throw POSIXError(.EACCES) }
                try self.ownerAccess(sourceMetadata, inode: source, access: .readAttributes, caller: caller)
                try checkLinkParentPolicy(oldMetadata, owner: self.owner, caller: caller)
                try self.ownerAccess(oldMetadata, inode: oldParent, access: .search, caller: caller)
                try checkLinkParentPolicy(newMetadata, owner: self.owner, caller: caller)
                try self.ownerAccess(newMetadata, inode: newParent, access: .search, caller: caller)
                var found = sfs_entry()
                let oldStatus = oldBytes.withUnsafeBytes { sfs_image_lookup(h, 0, oldParent, $0.baseAddress, $0.count, &found, &receipt) }
                try self.check(oldStatus, receipt)
                guard found.inode == source else { throw POSIXError(.ESTALE) }
                let suppliedVictim = try overItem.map { try self.ownedItem($0) }
                if let suppliedVictim { _ = try self.token(suppliedVictim.inode) }
                let newStatus = newBytes.withUnsafeBytes { sfs_image_lookup(h, 0, newParent, $0.baseAddress, $0.count, &found, &receipt) }
                if newStatus != SFS_NOT_FOUND { try self.check(newStatus, receipt) }
                guard anchorMatches(receipt, self.anchor) else { let error = POSIXError(.ESTALE); self.latch(error); throw error }
                let requirements = ResultRequirements(FSRenameItemResult.self), request = try requirements.request()
                func prepared(_ movedMetadata: sfs_metadata_entry, _ sourceParentMetadata: sfs_metadata_entry,
                              _ destinationParentMetadata: sfs_metadata_entry, _ victimMetadata: sfs_metadata_entry? = nil,
                              _ removedParent: LastKnownParent? = nil) throws -> FSRenameItemResult {
                    var movedEvidence = ParentEvidence(), oldEvidence = ParentEvidence(), newEvidence = ParentEvidence(), victimEvidence = ParentEvidence()
                    let moved = try self.preparedResultAttributes(movedMetadata, request, requirements, parents: &movedEvidence)
                    let oldDirectory = try self.preparedResultAttributes(sourceParentMetadata, request, requirements, parents: &oldEvidence)
                    let newDirectory = try self.preparedResultAttributes(destinationParentMetadata, request, requirements, parents: &newEvidence)
                    let overwritten = try victimMetadata.map { try self.preparedResultAttributes($0, request, requirements, parents: &victimEvidence, detachedParent: removedParent) }
                    return try self.handlerResult(FSRenameItemResult.self) {
                        FSRenameItemResult(newName: FSFileName(data: newBytes), renamedItemAttributes: moved,
                                           sourceDirectoryAttributes: oldDirectory, destinationDirectoryAttributes: newDirectory,
                                           overItemAttributes: overwritten, freeSpace: nil)
                    }
                }
                // Renaming a name onto itself or another name of the same inode removes nothing.
                // It must not enter mutate's generation/append-growth contract or publish a witness.
                if newStatus == SFS_OK && found.inode == source {
                    guard suppliedVictim == nil || suppliedVictim === item else { throw POSIXError(.ESTALE) }
                    let result = try prepared(sourceMetadata, oldMetadata, newMetadata)
                    guard self.resource.isWritable && !self.resource.isRevoked else { throw POSIXError(.EACCES) }
                    reply(result, nil); return
                }
                let victim: StallionItem?, victimMetadata: sfs_metadata_entry?
                if newStatus == SFS_NOT_FOUND {
                    guard suppliedVictim == nil else { throw POSIXError(.ESTALE) }
                    victim = nil; victimMetadata = nil
                } else {
                    guard let suppliedVictim else { throw POSIXError(.EEXIST) }
                    guard suppliedVictim.inode == found.inode else { throw POSIXError(.ESTALE) }
                    let metadata = try self.metadata(suppliedVictim.inode)
                    guard metadata.link_count > 0 else { throw POSIXError(.ENOENT) }
                    guard suppliedVictim.inode != 1, metadata.entry.kind == SFS_FILE || metadata.entry.kind == SFS_SYMLINK || metadata.entry.kind == SFS_DIRECTORY else { throw POSIXError(.ENOTSUP) }
                    guard metadata.flags == 0 else { throw POSIXError(.ENOTSUP) }
                    guard metadata.mode & 0o6000 == 0 else { throw POSIXError(.EACCES) }
                    try self.ownerAccess(metadata, inode: suppliedVictim.inode, access: .readAttributes, caller: caller)
                    if sourceMetadata.entry.kind == SFS_DIRECTORY && metadata.entry.kind != SFS_DIRECTORY { throw POSIXError(.ENOTDIR) }
                    if sourceMetadata.entry.kind != SFS_DIRECTORY && metadata.entry.kind == SFS_DIRECTORY { throw POSIXError(.EISDIR) }
                    if metadata.entry.kind == SFS_DIRECTORY {
                        guard metadata.link_count == 1 else { throw POSIXError(.ENOTSUP) }
                        var cursor = sfs_cookie(), child = sfs_entry(), present: Int32 = 0
                        try self.check(sfs_image_next(h, 0, suppliedVictim.inode, &cursor, &child, &present, &receipt), receipt)
                        guard present == 0 else { throw POSIXError(.ENOTEMPTY) }
                    }
                    victim = suppliedVictim; victimMetadata = metadata
                }
                let removedParent: LastKnownParent?
                if let victim, let victimMetadata, victimMetadata.link_count == 1 {
                    removedParent = LastKnownParent(item: ObjectIdentifier(victim), pin: try self.token(victim.inode),
                                                   inode: victim.inode, kind: victimMetadata.entry.kind, parent: newParent)
                } else { removedParent = nil }
#if STALLION_ADAPTER_CHECK
                self.renameMutationForTesting = true
                defer { self.renameMutationForTesting = false }
#endif
                let result = try self.mutate({ h, r in
                    let status = oldBytes.withUnsafeBytes { old in newBytes.withUnsafeBytes { new in
                        sfs_image_rename_replace(h, oldParent, old.baseAddress, old.count, source,
                                                 newParent, new.baseAddress, new.count, victim?.inode ?? 0, &r)
                    } }
                    try self.check(status, r)
                }, prepare: { h, r in
                    let movedMetadata = try self.transactionMetadata(h, inode: source, receipt: &r)
                    let sourceParentMetadata = try self.transactionMetadata(h, inode: oldParent, receipt: &r)
                    let destinationParentMetadata = try self.transactionMetadata(h, inode: newParent, receipt: &r)
                    let overwritten = try victim.map { try self.transactionMetadata(h, inode: $0.inode, receipt: &r) }
                    if let removedParent, let overwritten { _ = try self.detachedParent(overwritten, candidate: removedParent) }
                    return try prepared(movedMetadata, sourceParentMetadata, destinationParentMetadata, overwritten, removedParent)
                }, receipt: &receipt)
                if let victim, let removedParent {
                    guard self.items[victim.inode] === victim, let pin = victim.pin, !victim.reclaimed,
                          sameBytes(pin, removedParent.pin) else {
                        let error = POSIXError(.ESTALE); self.latch(error); self.rememberDelivery(error, receipt); throw error
                    }
                    victim.lastKnownParent = removedParent
                }
                reply(result, nil)
            } catch { reply(nil, error) }
        }
    }
#if STALLION_ADAPTER_CHECK
    private var renameMutationForTesting = false
    var renamePreflightForTesting: (() -> Void)?
    var renameCommitReceiptForTesting: ((sfs_result, inout sfs_result) -> Void)?
    func renameResultForTesting(_ item: FSItem, sourceDirectory: FSItem, sourceName: FSFileName,
                                destinationName: FSFileName, destinationDirectory: FSItem, overItem: FSItem? = nil,
                                caller: CallerIdentity, reply: @escaping (FSRenameItemResult?, Error?) -> Void) {
        renameItemHandler(item, sourceDirectory: sourceDirectory, sourceName: sourceName, destinationName: destinationName,
                          destinationDirectory: destinationDirectory, overItem: overItem, caller: caller, reply: reply)
    }
#endif
#endif
    func setXattr(named name: FSFileName, to value: Data?, on item: FSItem, policy: FSVolume.SetXattrPolicy, context: FSContext, replyHandler: @escaping (FSSetXattrResult?, Error?) -> Void) {
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        setXattrHandler(name, value: value, item: item, policy: policy, caller: CallerIdentity(context), reply: replyHandler)
#else
        refuse { replyHandler(nil, $0) }
#endif
    }
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
    private func setXattrHandler(_ name: FSFileName, value: Data?, item: FSItem, policy: FSVolume.SetXattrPolicy,
                                 caller: CallerIdentity, reply: @escaping (FSSetXattrResult?, Error?) -> Void) {
        guard writesEnabled else { refuse { reply(nil, $0) }; return }
        // FSFileName has already applied its constructor's NUL termination.
        // Keep exactly the delivered bytes; xattr names are not path components.
        let bytes = name.data, length = value?.count ?? 0
        let charge = bytes.count.addingReportingOverflow(length)
        var validation: Error?
        do {
            try writableXattrName(bytes)
            _ = try checkedXattrLength(UInt64(length))
            guard !charge.overflow else { throw POSIXError(.E2BIG) }
            switch policy {
            case .alwaysSet, .mustCreate, .mustReplace:
                guard value != nil else { throw POSIXError(.EINVAL) }
            case .delete: break
            @unknown default: throw POSIXError(.EINVAL)
            }
        } catch { validation = error }
        enqueue(retainedBytes: charge.overflow ? Int.max : charge.partialValue, namespaceOperation: true,
                validationError: validation, rejected: { reply(nil, $0) }) {
            var receipt = sfs_result()
            do {
                if let error = self.deliveryError() { throw error }
                let h = try self.ready(mounted: true)
                guard self.pendingCreate == nil else { throw POSIXError(.EBUSY) }
                guard self.resource.isWritable else { throw POSIXError(.EACCES) }
                let inode = try self.id(item), m = try self.metadata(inode), pin = try self.token(inode)
                try self.ownerAccess(m, inode: inode, access: .writeXattr, caller: caller)
                var information = sfs_image_information()
                try self.check(sfs_image_get_information(h, &information, &receipt), receipt)
                guard receipt.transaction_active == 0 else { throw POSIXError(.EBUSY) }
                var size: UInt64 = 0
                let status = bytes.withUnsafeBytes { sfs_image_pin_xattr_size(h, pin, $0.baseAddress, $0.count, &size, &receipt) }
                if status != SFS_NOT_FOUND { try self.check(status, receipt) }
                // A missing attribute still has a committed identity receipt.
                guard anchorMatches(receipt, self.anchor) else { let error = POSIXError(.ESTALE); self.latch(error); throw error }
                guard receipt.transaction_active == 0, receipt.poisoned == 0 else { throw POSIXError(.EIO) }
                let exists = status == SFS_OK
                if policy == .mustCreate && exists { throw POSIXError(.EEXIST) }
                if (policy == .mustReplace || policy == .delete) && !exists { throw POSIXError(.ENOATTR) }
                let result = try self.mutate({ h, r in
                    let changed = bytes.withUnsafeBytes { name -> sfs_status in
                        if policy == .delete { return sfs_image_pin_remove_xattr(h, pin, name.baseAddress, name.count, &r) }
                        return value!.withUnsafeBytes { data in
                            sfs_image_pin_set_xattr(h, pin, name.baseAddress, name.count, data.baseAddress, data.count, &r)
                        }
                    }
                    try self.check(changed, r, missing: ENOATTR)
                }, prepare: { _, _ in
                    try self.handlerResult(FSSetXattrResult.self) { FSSetXattrResult(freeSpace: nil) }
                }, receipt: &receipt)
                reply(result, nil)
            } catch { reply(nil, error) }
        }
    }
#if STALLION_ADAPTER_CHECK
    func setXattrResultForTesting(_ name: FSFileName, value: Data?, item: FSItem, policy: FSVolume.SetXattrPolicy,
                                  caller: CallerIdentity, reply: @escaping (FSSetXattrResult?, Error?) -> Void) {
        setXattrHandler(name, value: value, item: item, policy: policy, caller: caller, reply: reply)
    }
#endif
#endif
#endif
#if STALLION_ADAPTER_CHECK
    // Direct checks use pure caller values; these are not framework entry points
    // and do not establish that the kernel supplied any particular FSContext.
    func writeCountForTesting(contents: Data, to item: FSItem, at offset: off_t, replyHandler: @escaping (Int, Error?) -> Void) {
#if STALLION_CONTEXT_HANDLERS
        write(contents: contents, to: item, at: offset) { replyHandler($0 == nil ? 0 : contents.count, $1) }
#else
        write(contents: contents, to: item, at: offset, replyHandler: replyHandler)
#endif
    }
    func setAttributesValueForTesting(_ attributes: FSItem.SetAttributesRequest, on item: FSItem, caller: CallerIdentity,
                                      replyHandler: @escaping (FSItem.Attributes?, Error?) -> Void) {
#if STALLION_CONTEXT_HANDLERS
        var prepared: FSItem.Attributes?
        let prior = preparedAttributesForTesting
        preparedAttributesForTesting = { name, value in
            prior?(name, value)
            if name == "FSSetAttributesResult" { prepared = value }
        }
        setAttributesHandler(attributes, item: item, caller: caller) { result, error in
            self.preparedAttributesForTesting = prior
            replyHandler(result == nil ? nil : prepared, error)
        }
#else
        setAttributes(attributes, on: item, replyHandler: replyHandler)
#endif
    }
    func refusedMutationForTesting(replyHandler: (Error?) -> Void) { refuse { replyHandler($0) } }
#if STALLION_CONTEXT_HANDLERS
    func activateResultForTesting(replyHandler: @escaping (FSActivateResult?, Error?) -> Void) { activateHandler(replyHandler: replyHandler) }
    func lookupResultForTesting(_ name: String, directory: FSItem, caller: CallerIdentity, replyHandler: @escaping (FSLookupItemResult?, Error?) -> Void) {
        lookupHandler(FSFileName(string: name), directory: directory, caller: caller, reply: replyHandler)
    }
    func attributesResultForTesting(_ request: FSItem.GetAttributesRequest, item: FSItem, caller: CallerIdentity, replyHandler: @escaping (FSGetAttributesResult?, Error?) -> Void) {
        getAttributesHandler(request, item: item, caller: caller, reply: replyHandler)
    }
    func readlinkResultForTesting(_ item: FSItem, caller: CallerIdentity, replyHandler: @escaping (FSReadSymlinkResult?, Error?) -> Void) {
        readlinkHandler(item, caller: caller, reply: replyHandler)
    }
    func xattrResultForTesting(_ item: FSItem, caller: CallerIdentity, replyHandler: @escaping (FSGetXattrResult?, Error?) -> Void) {
        getXattrHandler(FSFileName(string: "note"), item: item, caller: caller, reply: replyHandler)
    }
    func xattrsResultForTesting(_ item: FSItem, caller: CallerIdentity, replyHandler: @escaping (FSListXattrsResult?, Error?) -> Void) {
        listXattrsHandler(item, caller: caller, reply: replyHandler)
    }
    func enumerationResultForTesting(_ directory: FSItem, startingAt cookie: FSDirectoryCookie = .initial,
                                     verifier: FSDirectoryVerifier = .initial, attributes: FSItem.GetAttributesRequest? = nil,
                                     caller: CallerIdentity, pack: @escaping DirectoryPack,
                                     replyHandler: @escaping (FSEnumerateDirectoryResult?, Error?) -> Void) {
        enumerateHandler(directory, startingAt: cookie, verifier: verifier, attributes: attributes, caller: caller, pack: pack, reply: replyHandler)
    }
    // Constructor-only: no fabricated FSMutableFileDataBuffer or kernel read call.
    func readResultConstructorForTesting(_ item: FSItem) throws -> FSReadFileResult {
        let a = try resultAttributes(metadata(id(item)), FSReadFileResult.self)
        return try handlerResult(FSReadFileResult.self) { FSReadFileResult(bytesRead: 0, itemAttributes: a) }
    }
#endif
#endif
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
#if STALLION_WRITE_DIAGNOSTIC
    // Contextless write callbacks have no caller identity. This is only the
    // existing disposable-image admission policy, not client authorization.
    @discardableResult private func fixtureWritableMetadata(_ inode: UInt64) throws -> sfs_metadata_entry {
        guard selectedAccess == .fixtureWritable else { throw POSIXError(.EROFS) }
        if let error = deliveryError() { throw error }
        let m = try metadata(inode)
        guard m.entry.kind == SFS_FILE else { throw POSIXError(.EINVAL) }
        try ownerAccess(m, inode: inode, access: .writeData, caller: CallerIdentity(uid: Int(owner), gid: Int(getegid())))
        return m
    }
#endif
    private func observeWrite(_ operation: UInt64, inode: UInt64, offset: UInt64, length: UInt64,
                              started: UInt64, count: Int, error: Error?, result: sfs_result) {
        guard tracingEnabled else { return }
        submissionLock.lock(); defer { submissionLock.unlock() }
        if writeRecords.count == 4096 { writeCounters.overflow = true; return }
        saturated(&diagnosticTraceSequence)
        writeRecords.append(WriteRecord(sequence: diagnosticTraceSequence, operation: operation, inode: inode,
            offset: offset, length: length, mask: 0, started: started, finished: DispatchTime.now().uptimeNanoseconds,
            generation: anchor.generation, count: count, code: (error as NSError?)?.code ?? 0, result: result))
    }
    private func accountCommit(_ r: sfs_result) {
        guard tracingEnabled else { return }
        submissionLock.lock(); defer { submissionLock.unlock() }
        saturated(&writeCounters.commits)
        if r.fence_attempted & 1 != 0 { saturated(&writeCounters.recordFences) }
        if r.fence_succeeded & 1 != 0 { saturated(&writeCounters.recordSuccess) }
        if r.fence_attempted & 2 != 0 { saturated(&writeCounters.commitFences) }
        if r.fence_succeeded & 2 != 0 { saturated(&writeCounters.commitSuccess) }
    }
    // This wrapper owns the only transaction; no previously acknowledged work
    // is staged. The original receipt survives abort/verification failures.
    private func mutate<T>(_ body: (OpaquePointer, inout sfs_result) throws -> Void,
                           prepare: (OpaquePointer, inout sfs_result) throws -> T,
                           receipt: inout sfs_result) throws -> T {
        let h = try ready(mounted: true), before = anchor
        var began = false, committed = false
        do {
#if STALLION_CONTEXT_HANDLERS
            pendingCreate?.outcome.beginAttempted = true
#endif
            let begin = sfs_image_begin(h, &receipt)
#if STALLION_CONTEXT_HANDLERS
            pendingCreate?.outcome.begin = receipt
            if begin == SFS_OK {
                pendingCreate?.outcome.beginSucceeded = true
                pendingCreate?.ownership = .transaction
            } else if receipt.poisoned != 0 && receipt.transaction_active == 0 &&
                        [SFS_IO, SFS_CORRUPT, SFS_RECOVERY_REQUIRED, SFS_UNSUPPORTED].contains(begin) {
                pendingCreate?.ownership = .discarded; pendingCreate?.outcome.discarded = true
            }
#endif
            if begin == SFS_STATE { let e = POSIXError(.EIO); latch(e); throw e }
            try check(begin, receipt); began = true
            try body(h, &receipt)
#if STALLION_ADAPTER_CHECK
            try diagnosticBeforePrepare?()
#endif
            let prepared = try prepare(h, &receipt)
#if STALLION_ADAPTER_CHECK
            diagnosticBeforeCommit?()
#endif
            guard resource.isWritable && !resource.isRevoked else { throw POSIXError(.EACCES) }
#if STALLION_CONTEXT_HANDLERS
            pendingCreate?.outcome.commitAttempted = true
            let status = sfs_image_commit(h, &receipt)
            pendingCreate?.outcome.commit = receipt
            if status == SFS_OK {
                pendingCreate?.ownership = .promoted; pendingCreate?.outcome.commitSucceeded = true
            }
            accountCommit(receipt)
#if STALLION_ADAPTER_CHECK
            if pendingCreate != nil, status == SFS_OK { createCommitReceiptForTesting?(&receipt) }
            if removeMutationForTesting, status == SFS_OK {
                let committedReceipt = receipt
                removeCommitReceiptForTesting?(committedReceipt, &receipt)
            }
            if renameMutationForTesting, status == SFS_OK {
                let committedReceipt = receipt
                renameCommitReceiptForTesting?(committedReceipt, &receipt)
            }
#endif
#else
            let status = sfs_image_commit(h, &receipt); accountCommit(receipt)
#endif
            guard status == SFS_OK else {
                let e = sfsError(status, receipt)
                if receipt.poisoned != 0 || status == SFS_UNSUPPORTED { latch(e) }
                throw e
            }
            committed = true
            guard sameBytes(receipt.uuid, before.uuid), receipt.device == before.device,
                  receipt.inode == before.inode, before.generation != UInt64.max,
                  receipt.generation == before.generation + 1, receipt.transaction_active == 0,
                  receipt.committed_end > before.committed_end,
                  receipt.poisoned == 0, receipt.fence_attempted == 3, receipt.fence_succeeded == 3 else {
                let e = POSIXError(.EIO); latch(e); throw e
            }
#if STALLION_CONTEXT_HANDLERS
            pendingCreate?.outcome.original = receipt
#endif
            anchor = receipt
            submissionLock.lock(); diagnosticDurable = receipt.generation; submissionLock.unlock()
            return prepared
        } catch {
            let original = receipt
#if STALLION_CONTEXT_HANDLERS
            pendingCreate?.outcome.original = original
            if pendingCreate?.outcome.beginSucceeded == true && pendingCreate?.outcome.commitSucceeded == false && original.transaction_active == 0 {
                pendingCreate?.ownership = .discarded; pendingCreate?.outcome.discarded = true
            }
#endif
            if original.poisoned != 0 || [SFS_IO, SFS_CORRUPT, SFS_RECOVERY_REQUIRED, SFS_OUTCOME_UNKNOWN, SFS_POISONED, SFS_UNSUPPORTED].contains(original.status) {
                latch(error)
            } else if began && !committed && failure == nil {
                var cleanup = sfs_result(), information = sfs_image_information()
#if STALLION_CONTEXT_HANDLERS
                let aborted: sfs_status
                pendingCreate?.outcome.abortAttempted = true
#if STALLION_ADAPTER_CHECK
                if pendingCreate != nil, let injected = createAbortForTesting { aborted = injected(h, &cleanup) }
                else { aborted = sfs_image_abort(h, &cleanup) }
#else
                aborted = sfs_image_abort(h, &cleanup)
#endif
                pendingCreate?.outcome.cleanup = cleanup
                if (aborted == SFS_OK || aborted == SFS_STATE) && cleanup.transaction_active == 0 {
                    pendingCreate?.ownership = .discarded; pendingCreate?.outcome.discarded = true
                }
#else
                let aborted = sfs_image_abort(h, &cleanup)
#endif
                if (aborted != SFS_OK && aborted != SFS_STATE) || cleanup.transaction_active != 0 || cleanup.poisoned != 0 {
                    latch(POSIXError(.EIO))
                } else {
                    let checked = sfs_image_get_information(h, &information, &cleanup)
#if STALLION_CONTEXT_HANDLERS
                    pendingCreate?.outcome.verificationAttempted = true
                    pendingCreate?.outcome.verification = cleanup
#endif
                    if checked != SFS_OK || cleanup.transaction_active != 0 || !anchorMatches(cleanup, before) { latch(POSIXError(.EIO)) }
                }
            }
            receipt = original; rememberDelivery(error, original); throw error
        }
    }
    private func performWrite<T>(_ contents: Data, item: FSItem, offset: off_t,
                                    admit: @escaping () throws -> Void = {}, prepare: @escaping (Int, sfs_metadata_entry) throws -> T, reply: @escaping (T?, Error?) -> Void) {
        let start = DispatchTime.now().uptimeNanoseconds
        var validation: Error?
        if offset < 0 { validation = POSIXError(.EINVAL) }
        else if UInt64(offset) > maximumFileSize || UInt64(contents.count) > maximumFileSize - UInt64(offset) { validation = POSIXError(.EFBIG) }
        enqueue(retainedBytes: contents.count, dataOperation: true, writeOperation: true, validationError: validation, rejected: { reply(nil, $0) }) {
            var receipt = sfs_result(), inode: UInt64 = 0
            if self.failure == nil { self.lastCoreFailure = nil }
            do {
                _ = try self.ready(mounted: true); inode = try self.id(item)
                let m: sfs_metadata_entry
                if self.selectedAccess == .contextualWrites {
                    if let error = self.deliveryError() { throw error }
                    let own = try self.ownedItem(item)
                    guard own.retainedModes.contains(.write) else { throw POSIXError(.EACCES) }
                    m = try self.metadata(inode)
                    guard m.entry.kind == SFS_FILE else { throw POSIXError(.EINVAL) }
                } else {
#if STALLION_WRITE_DIAGNOSTIC
                    m = try self.fixtureWritableMetadata(inode)
#else
                    throw POSIXError(.EROFS)
#endif
                }
                try admit()
                let pin = try self.token(inode)
                if self.tracingEnabled {
                    self.submissionLock.lock(); self.saturated(&self.writeCounters.bytes, by: UInt64(contents.count)); self.submissionLock.unlock()
                }
                let result: T
                if !contents.isEmpty {
                    result = try self.mutate({ h, r in
                        try contents.withUnsafeBytes { bytes in
                            var at = 0
                            while at < bytes.count {
                                let amount = min(65536, bytes.count - at)
                                if self.tracingEnabled {
                                    self.submissionLock.lock(); self.saturated(&self.writeCounters.chunks); self.submissionLock.unlock()
                                }
                                let status = sfs_image_pin_write(h, pin, UInt64(offset) + UInt64(at), bytes.baseAddress!.advanced(by: at), amount, &r)
                                try self.check(status, r); at += amount
#if STALLION_ADAPTER_CHECK
                                self.diagnosticAfterChunk?(at)
#endif
                            }
                        }
                    }, prepare: { h, r in
#if STALLION_CONTEXT_HANDLERS
                        return try prepare(contents.count, self.transactionMetadata(h, inode: inode, receipt: &r))
#else
                        return try prepare(contents.count, m)
#endif
                    }, receipt: &receipt)
                } else { result = try prepare(0, m) }
                self.observeWrite(1, inode: inode, offset: UInt64(offset), length: UInt64(contents.count), started: start, count: contents.count, error: nil, result: receipt)
                reply(result, nil)
            } catch {
                receipt = self.lastCoreFailure ?? receipt
                self.rememberDelivery(error, receipt)
                self.observeWrite(1, inode: inode, offset: UInt64(offset), length: UInt64(contents.count), started: start, count: 0, error: error, result: receipt)
                reply(nil, error)
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
#if STALLION_CONTEXT_HANDLERS
    private func setWritableAttributes<T>(_ a: FSItem.SetAttributesRequest, item: FSItem, caller: CallerIdentity,
                                            requirements: ResultRequirements? = nil,
                                            request makeRequest: @escaping () throws -> FSItem.GetAttributesRequest, prepare: @escaping (FSItem.Attributes) throws -> T,
                                            reply: @escaping (T?, Error?) -> Void) {
        let start = DispatchTime.now().uptimeNanoseconds
        a.consumedAttributes = []
        let hasSize = a.isValid(.size), validation = Self.sizeRequestError(a)
        enqueue(dataOperation: hasSize, validationError: validation, rejected: { reply(nil, $0) }) {
            var receipt = sfs_result(), inode: UInt64 = 0
            if self.failure == nil { self.lastCoreFailure = nil }
            do {
                _ = try self.ready(mounted: true); inode = try self.id(item); let m = try self.metadata(inode)
                let regularSize = hasSize && m.entry.kind == SFS_FILE
                if regularSize, let error = self.deliveryError() { throw error }
                try self.ownerAccess(m, inode: inode, access: regularSize ? .writeData : .readAttributes, caller: caller)
                let request = try makeRequest()
                if let requirements { try Self.validateCallerWanted(requirements.caller) }
                else { try validateWanted(request.wantedAttributes.rawValue) }
                var parents = ParentEvidence()
                func snapshot(_ metadata: sfs_metadata_entry) throws -> FSItem.Attributes {
                    if let requirements { return try self.preparedResultAttributes(metadata, request, requirements, parents: &parents) }
                    return try self.attributes(metadata, request, parents: &parents)
                }
                let result: T
                if regularSize {
                    guard a.size <= self.maximumFileSize else { throw POSIXError(.EFBIG) }
                    if a.size != m.entry.size {
                        let pin = try self.token(inode)
                        result = try self.mutate({ h, r in
                            try self.check(sfs_image_pin_resize(h, pin, a.size, &r), r)
                        }, prepare: { h, r in
                            let pending = try self.transactionMetadata(h, inode: inode, receipt: &r)
                            return try prepare(snapshot(pending))
                        }, receipt: &receipt)
                    } else { result = try prepare(snapshot(m)) }
                    a.consumedAttributes = [.size]
#if STALLION_ADAPTER_CHECK
                    self.diagnosticAfterSizeCommit?()
#endif
                } else { result = try prepare(snapshot(m)) }
                self.observeWrite(2, inode: inode, offset: 0, length: hasSize ? a.size : 0, started: start, count: 0, error: nil, result: receipt)
                reply(result, nil)
            } catch {
                receipt = self.lastCoreFailure ?? receipt
                if hasSize { self.rememberDelivery(error, receipt) }
                self.observeWrite(2, inode: inode, offset: 0, length: hasSize ? a.size : 0, started: start, count: 0, error: error, result: receipt)
                reply(nil, error)
            }
        }
    }
#else
    private func setWritableAttributes<T>(_ a: FSItem.SetAttributesRequest, item: FSItem, caller: CallerIdentity?,
                                            request makeRequest: @escaping () throws -> FSItem.GetAttributesRequest, prepare: @escaping (FSItem.Attributes) throws -> T,
                                            reply: @escaping (T?, Error?) -> Void) {
        let start = DispatchTime.now().uptimeNanoseconds
        a.consumedAttributes = []
        let hasSize = a.isValid(.size), validation = Self.sizeRequestError(a)
        enqueue(dataOperation: hasSize, validationError: validation, rejected: { reply(nil, $0) }) {
            var receipt = sfs_result(), inode: UInt64 = 0
            if self.failure == nil { self.lastCoreFailure = nil }
            do {
                _ = try self.ready(mounted: true); inode = try self.id(item); let m = try self.metadata(inode)
                let regularSize = hasSize && m.entry.kind == SFS_FILE
                if regularSize, let error = self.deliveryError() { throw error }
                if let caller { try self.ownerAccess(m, inode: inode, access: regularSize ? .writeData : .readAttributes, caller: caller) }
                let request = try makeRequest(); try validateWanted(request.wantedAttributes.rawValue)
                var parents = ParentEvidence()
                let result: T
                if regularSize {
                    guard a.size <= self.maximumFileSize else { throw POSIXError(.EFBIG) }
                    if caller == nil { try self.fixtureWritableMetadata(inode) }
                    if a.size != m.entry.size {
                        let pin = try self.token(inode)
                        result = try self.mutate({ h, r in
                            try self.check(sfs_image_pin_resize(h, pin, a.size, &r), r)
                        }, prepare: { h, r in
                            let pending = try self.transactionMetadata(h, inode: inode, receipt: &r)
                            return try prepare(self.attributes(pending, request, parents: &parents))
                        }, receipt: &receipt)
                    } else { result = try prepare(self.attributes(m, request, parents: &parents)) }
                    a.consumedAttributes = [.size]
#if STALLION_ADAPTER_CHECK
                    self.diagnosticAfterSizeCommit?()
#endif
                } else { result = try prepare(self.attributes(m, request, parents: &parents)) }
                self.observeWrite(2, inode: inode, offset: 0, length: hasSize ? a.size : 0, started: start, count: 0, error: nil, result: receipt)
                reply(result, nil)
            } catch {
                receipt = self.lastCoreFailure ?? receipt
                if hasSize { self.rememberDelivery(error, receipt) }
                self.observeWrite(2, inode: inode, offset: 0, length: hasSize ? a.size : 0, started: start, count: 0, error: error, result: receipt)
                reply(nil, error)
            }
        }
    }
#endif
#endif
}
