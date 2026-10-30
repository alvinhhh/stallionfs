// Direct real-core callbacks on owned disposable images; no installed routing.
import Foundation
@preconcurrency import FSKit
import SFSImage
import Darwin

@_silgen_name("sfs_diag_fault") func fault(_ kind: Int32, _ nth: Int32)
@_silgen_name("sfs_diag_hit") func hits() -> Int32
@_silgen_name("sfs_diag_fences") func fences() -> Int32
func need(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() { fatalError(message) }
}
#if STALLION_CONTEXT_HANDLERS && STALLION_RESULT_MASK_TRACE
func resultMaskTrace(_ text: String) {
    let bytes = Array(("RESULT_MASK " + text + "\n").utf8)
    bytes.withUnsafeBytes { buffer in
        var offset = 0
        while offset < buffer.count {
            let written = Darwin.write(STDERR_FILENO, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
            if written < 0 && errno == EINTR { continue }
            need(written > 0, "result mask trace write failed")
            offset += written
        }
    }
}
#endif
func code(_ error: Error?) -> Int { (error as NSError?)?.code ?? 0 }
func wait<T>(_ operation: (@escaping (T) -> Void) -> Void) -> T {
    let done = DispatchSemaphore(value: 0); var result: T?
    operation { result = $0; done.signal() }
    need(done.wait(timeout: .now() + 20) == .success, "callback timed out")
    return result!
}
func uuid(_ r: sfs_result) -> UUID {
    let b = rawBytes(r.uuid)
    return UUID(uuid: (b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]))
}
struct Fixture {
    let url: URL
    let id: UInt64
    let identity: UUID
    init(_ parent: URL, _ name: String, mode: UInt32 = 0o600, acl: Bool = false, owner: uid_t = geteuid(), extra: Bool = false, sourceFlags: UInt32 = 0, rootFlags: UInt32 = 0, rootMode: UInt32 = 0o700, rootACL: Bool = false, directory: Bool = false, capacity: UInt64 = 16 * 1024 * 1024) throws {
        fault(0, 0); url = parent.appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        var h: OpaquePointer?, r = sfs_result(), m = sfs_metadata_initial(), inode: UInt64 = 0
        m.mode = UInt32(S_IFDIR) | rootMode; m.uid = geteuid(); m.gid = getegid(); m.flags = rootFlags
        need(sfs_image_create_metadata_version(url.path, "image.sfs", capacity, 6, &m, &h, &r) == SFS_OK, "create disposable")
        need(sfs_image_begin(h, &r) == SFS_OK, "begin producer")
        m.mode = UInt32(S_IFREG) | mode; m.uid = owner; m.flags = sourceFlags
        need(sfs_image_add_metadata(h, 1, "file", 4, SFS_FILE, &m, &inode, &r) == SFS_OK, "create regular")
        let fileID = inode; id = fileID
        need(sfs_image_link(h, inode, 1, "alias", 5, &r) == SFS_OK, "create alias")
        need(sfs_image_set_xattr(h, fileID, "note", 4, "value", 5, &r) == SFS_OK, "regular opaque xattr")
        if extra { need(sfs_image_add_metadata(h, 1, "extra", 5, SFS_FILE, &m, &inode, &r) == SFS_OK, "extra capacity operand") }
        m.mode = UInt32(S_IFLNK) | 0o700; m.uid = geteuid(); m.flags = 0
        need(sfs_image_symlink_metadata(h, 1, "link", 4, "file", 4, &m, &inode, &r) == SFS_OK, "create symlink")
        if directory {
            m.mode = UInt32(S_IFDIR) | 0o700
            need(sfs_image_add_metadata(h, 1, "dir", 3, SFS_DIRECTORY, &m, &inode, &r) == SFS_OK, "namespace fixture directory")
        }
        if rootACL { need(sfs_image_set_xattr(h, 1, "com.apple.system.Security", 25, nil, 0, &r) == SFS_OK, "parent security descriptor") }
        if acl {
            let key = Data("com.apple.system.Security".utf8)
            need(key.withUnsafeBytes { sfs_image_set_xattr(h, fileID, $0.baseAddress, $0.count, nil, 0, &r) } == SFS_OK, "create security descriptor")
        }
        need(sfs_image_write(h, id, 0, "original", 8, &r) == SFS_OK, "producer data")
        need(sfs_image_commit(h, &r) == SFS_OK, "producer commit"); identity = uuid(r)
        need(sfs_image_close(h, &r) == SFS_OK, "producer close")
    }
    func contents() -> Data {
        fault(0, 0); var h: OpaquePointer?, r = sfs_result(), m = sfs_metadata_entry()
        need(sfs_image_open_readonly(url.path, "image.sfs", &h, &r) == SFS_OK, "reopen selected image")
        need(sfs_image_stat_metadata(h, 0, id, &m, &r) == SFS_OK && m.entry.size <= 2 * 1024 * 1024, "reopened size")
        var bytes = Data(count: Int(m.entry.size)), offset = 0
        while offset < bytes.count {
            var count = 0; let length = min(65536, bytes.count - offset)
            let status = bytes.withUnsafeMutableBytes { sfs_image_read(h, 0, id, UInt64(offset), $0.baseAddress!.advanced(by: offset), length, &count, &r) }
            need(status == SFS_OK && count == length, "reopened bytes"); offset += count
        }
        need(sfs_image_close(h, &r) == SFS_OK, "reopen close"); return bytes
    }
}
final class Mounted {
    let volume: StallionVolume, root: FSItem, file: FSItem, alias: FSItem, link: FSItem
    let coreHandle: OpaquePointer
    let resource: FSPathURLResource
    init(_ fixture: Fixture, writable: Bool = true, itemLimit: Int = ReadOnlyLimits.activeItems) throws {
        fault(0, 0); var h: OpaquePointer?, r = sfs_result()
        let opened = writable ? sfs_image_open(fixture.url.path, "image.sfs", &h, &r) : sfs_image_open_readonly(fixture.url.path, "image.sfs", &h, &r)
        need(opened == SFS_OK, "open adapter")
        coreHandle = h!
        resource = FSPathURLResource(url: fixture.url, writable: writable)
        volume = StallionVolume(handle: h!, resource: resource, scope: false, anchor: r, queue: DispatchQueue(label: "sfs.write.test"), itemLimit: itemLimit)
        if writable { try volume.enableWriteDiagnostic(expectedUUID: fixture.identity) }
        let v = volume
        let activated: (FSItem?, Error?) = wait { done in v.activate { done(($0, $1)) } }
        need(activated.1 == nil, "activate"); root = activated.0!
        let mounted: Error? = wait { v.mount(arguments: [], replyHandler: $0) }; need(mounted == nil, "mount callback")
        func lookup(_ name: String, _ parent: FSItem) -> FSItem {
            let result: (FSItem?, Error?) = wait { done in v.lookupItem(named: FSFileName(string: name), inDirectory: parent) { done(($0, $2)) } }
            need(result.1 == nil, "lookup"); return result.0!
        }
        file = lookup("file", root); alias = lookup("alias", root); link = lookup("link", root)
        need(file === alias, "aliases share canonical item")
    }
    func write(_ data: Data, at offset: off_t = 0, alias: Bool = false) -> (Int, Error?) {
        wait { done in volume.writeCountForTesting(contents: data, to: alias ? self.alias : file, at: offset) { done(($0, $1)) } }
    }
    func set(_ request: FSItem.SetAttributesRequest, item: FSItem? = nil) -> (FSItem.Attributes?, Error?) {
        wait { done in volume.setAttributesValueForTesting(request, on: item ?? file, caller: CallerIdentity(uid: Int(geteuid()), gid: Int(getegid()))) { done(($0, $1)) } }
    }
    func size(_ value: UInt64, item: FSItem? = nil) -> (FSItem.Attributes?, Error?) {
        let a = FSItem.SetAttributesRequest(); a.size = value; return set(a, item: item)
    }
    func sync(_ flags: FSSyncFlags = .wait) -> Error? { wait { volume.synchronize(flags: flags, replyHandler: $0) } }
    func serial(_ body: @escaping () -> Void) {
        let _: Bool = wait { done in volume.enqueue { body(); done(true) } }
    }
    func close() {
        fault(0, 0)
        let _: Bool = wait { done in volume.unmount { done(true) } }
        if volume.diagnosticWritable {
            for item in [file, link] {
                let owned: Bool = wait { done in volume.enqueue { done(self.volume.ownsForTesting(item)) } }
                if owned { let error: Error? = wait { volume.reclaimForTesting(item, eligible: true, replyHandler: $0) }; need(error == nil, "controlled item cleanup") }
            }
            let _: Error? = wait { volume.deactivate(options: [], replyHandler: $0) }
        }
        let consumed: Bool = wait { done in volume.enqueue { done(self.volume.unload().consumed) } }
        need(consumed, "quiescent unload consumes ownership")
    }
}

func successfulWrites(_ parent: URL) throws {
    let f = try Fixture(parent, "writes"), m = try Mounted(f), v = m.volume
    let generation = v.anchor.generation
    var cookie = FSDirectoryCookie.initial
    let old: (FSDirectoryVerifier, Error?) = wait { done in
        v.enumerateDirectory(m.root, startingAt: .initial, verifier: .initial, attributes: nil,
            pack: { _, _, _, next, _ in cookie = next; return false }) { done(($0, $1)) }
    }
    let data = Data((0..<150_003).map { UInt8($0 % 251) })
    let result = m.write(data, at: 13, alias: true)
    need(result.0 == data.count && result.1 == nil, "streamed delivered callback")
    let counts = v.diagnosticSnapshot().0
    need(counts.chunks == 3 && counts.commits == 1 && counts.recordSuccess == 1 && counts.commitSuccess == 1, "one commit with two real fences")
    need(v.anchor.generation == generation + 1 && m.file === m.alias, "commit transition and identity")
    let stale: (FSDirectoryVerifier, Error?) = wait { done in v.enumerateDirectory(m.root, startingAt: cookie, verifier: old.0, attributes: nil, pack: { _,_,_,_,_ in false }) { done(($0,$1)) } }
    need(stale.1 != nil, "data commit invalidates verifier")
    for flags in [FSSyncFlags.wait, .dWait, .noWait] { need(m.sync(flags) == nil, "ordered synchronization") }
    need(v.diagnosticSnapshot().0.commits == 1, "sync makes no empty commit")
    m.serial { v.diagnosticCloseForTesting(m.file) }
    need(m.write(Data([9]), at: 3).1 == nil, "delivered write remains valid after retained modes close")
    let same = FSItem.SetAttributesRequest(); same.size = UInt64(data.count + 13)
    let before = v.anchor.generation
    need(m.set(same).1 == nil && same.consumedAttributes == [.size] && v.anchor.generation == before, "same-size no-op")
    need(m.size(19).1 == nil && m.size(35).1 == nil, "shrink and sparse regrow")
    m.close()
    var expected = Data("original".utf8); expected[3] = 9
    expected.append(Data(repeating: 0, count: 5)); expected.append(data.prefix(6)); expected.append(Data(repeating: 0, count: 16))
    need(f.contents() == expected, "reopened exact bytes and zero tail")
    let ro = try Mounted(f, writable: false)
    need(code(ro.write(Data([1])).1) == Int(EROFS), "unbound diagnostic build stays read-only")
    ro.close()
}

func attributes(_ parent: URL) throws -> [Int] {
    typealias Setter = (FSItem.SetAttributesRequest) -> Void
    let fields: [(FSItem.Attribute, Setter, Int)] = [
        (.type, { $0.type = .file }, Int(EINVAL)), (.mode, { $0.mode = 0o600 }, Int(ENOTSUP)),
        (.linkCount, { $0.linkCount = 2 }, Int(EINVAL)), (.uid, { $0.uid = geteuid() }, Int(ENOTSUP)),
        (.gid, { $0.gid = getegid() }, Int(ENOTSUP)), (.flags, { $0.flags = 0 }, Int(ENOTSUP)),
        (.size, { $0.size = 17 }, 0), (.allocSize, { $0.allocSize = 0 }, Int(EINVAL)),
        (.fileID, { $0.fileID = FSItem.Identifier(rawValue: 3)! }, Int(EINVAL)),
        (.parentID, { $0.parentID = FSItem.Identifier(rawValue: 2)! }, Int(EINVAL)),
        (.accessTime, { $0.accessTime = timespec(tv_sec: 1, tv_nsec: 0) }, Int(ENOTSUP)),
        (.modifyTime, { $0.modifyTime = timespec(tv_sec: 1, tv_nsec: 0) }, Int(ENOTSUP)),
        (.changeTime, { $0.changeTime = timespec(tv_sec: 1, tv_nsec: 0) }, Int(EINVAL)),
        (.birthTime, { $0.birthTime = timespec(tv_sec: 1, tv_nsec: 0) }, Int(ENOTSUP)),
        (.backupTime, { $0.backupTime = timespec(tv_sec: 1, tv_nsec: 0) }, 0),
        (.addedTime, { $0.addedTime = timespec(tv_sec: 1, tv_nsec: 0) }, 0),
        (.supportsLimitedXAttrs, { $0.supportsLimitedXAttrs = true }, Int(EINVAL)),
        (.inhibitKernelOffloadedIO, { $0.inhibitKernelOffloadedIO = true }, Int(EINVAL))
    ]
    need(fields.count == 18, "SDK27 finite attribute table")
    var unavailable = Set<Int>()
    let f = try Fixture(parent, "attributes")
    for (field, set, error) in fields {
        need(code(StallionVolume.sizeRequestError(valid: [field])) == error, "finite policy covers every SDK field")
        need(code(StallionVolume.sizeRequestError(valid: [.size, field])) == error, "finite policy covers every mixed request")
        for mixed in [false, true] {
            let m = try Mounted(f), a = FSItem.SetAttributesRequest(), before = m.volume.anchor.generation
            if mixed { a.size = before + 40 }; set(a)
            if field == .size { a.size = before + 40 }
            let constructed = a.isValid(field)
            if !constructed {
                need([FSItem.Attribute.supportsLimitedXAttrs, .inhibitKernelOffloadedIO].contains(field), "unexpected unconstructible SDK field")
                unavailable.insert(field.rawValue)
            }
            let expectedError = constructed ? error : 0
            let result = m.set(a), usesSize = expectedError == 0 && (mixed || field == .size)
            let valid = fields.filter { a.isValid($0.0) }.map { $0.0.rawValue }
            need(code(result.1) == expectedError, "attribute field=\(field.rawValue) mixed=\(mixed) valid=\(valid) expected=\(expectedError) actual=\(code(result.1))")
            need(a.consumedAttributes == (usesSize ? [.size] : []), "exact consumed fields")
            need(m.volume.anchor.generation == before + (usesSize ? 1 : 0), "no mutation on rejected mask")
            need(m.volume.diagnosticSnapshot().0.commits == (usesSize ? 1 : 0), "attribute commit count")
            if mixed && expectedError != 0 { need(code(m.sync()) == expectedError, "recognized size failure sticks") }
            m.close()
        }
    }
    let m = try Mounted(f), before = m.volume.anchor
    for item in [m.root, m.link] {
        let a = FSItem.SetAttributesRequest(); a.size = UInt64.max
        let result = m.set(a, item: item)
        need(result.0 != nil && result.1 == nil && a.consumedAttributes.isEmpty, "nonregular size ignored with prepared result")
        need(anchorMatches(m.volume.anchor, before) && m.volume.diagnosticSnapshot().0.commits == 0, "ignored nonregular size leaves anchor and commit count unchanged")
    }
    need(m.set(FSItem.SetAttributesRequest()).1 == nil && anchorMatches(m.volume.anchor, before), "empty checked no-op")
    m.close()
    let oversized = try Mounted(f)
    need(code(oversized.size(UInt64.max).1) == Int(EFBIG) && code(oversized.sync()) == Int(EFBIG), "size bound sticky")
    oversized.close()
    let precedence = try Mounted(f), combined = FSItem.SetAttributesRequest()
    combined.size = 20; combined.mode = 0o600; combined.type = .file
    need(code(precedence.set(combined).1) == Int(EINVAL) && combined.consumedAttributes.isEmpty, "computed field precedes disabled field")
    precedence.close()
    return unavailable.sorted()
}

func failures(_ parent: URL) throws {
    // Actual append/short/zero/fence/slot I/O failures, not LIMIT substitutes.
    let cases: [(Int32, Int32, Int, sfs_status, sfs_phase)] = [
        (1,1,Int(ENOSPC),SFS_IO,SFS_PHASE_RECORDS), (2,1,Int(ENOSPC),SFS_IO,SFS_PHASE_RECORDS),
        (3,1,Int(EIO),SFS_IO,SFS_PHASE_RECORDS), (4,1,Int(ENOSPC),SFS_IO,SFS_PHASE_RECORD_BARRIER),
        (5,1,Int(ENOSPC),SFS_OUTCOME_UNKNOWN,SFS_PHASE_SLOT1),
        (4,2,Int(ENOSPC),SFS_OUTCOME_UNKNOWN,SFS_PHASE_COMMIT_BARRIER)
    ]
    for (index, test) in cases.enumerated() {
        let f = try Fixture(parent, "failure-\(index)"), m = try Mounted(f)
        let before = m.volume.anchor.generation
        fault(test.0, test.1); let result = m.write(Data(repeating: 3, count: 70000))
        need(hits() > 0 && result.0 == 0 && code(result.1) == test.2, "injected host errno")
        let sticky = m.volume.diagnosticSnapshot().2!
        need(sticky.result.status == test.3 && sticky.result.phase == test.4 && sticky.result.system_errno == test.2, "original terminal disposition")
        need(sticky.result.poisoned != 0 && sticky.durableGeneration == before, "old known receipt retained")
        fault(0,0)
        need(code(m.write(Data([1])).1) == test.2 && code(m.sync()) == test.2, "later operations retain first failure")
        m.serial { try! m.volume.diagnosticCloseModesForTesting(m.file, modes: []) }
        m.close()
        if test.3 == SFS_IO { need(f.contents() == Data("original".utf8), "definitely unpublished image remains old") }
        else {
            var handle: OpaquePointer?, receipt = sfs_result()
            let status = sfs_image_open_readonly(f.url.path, "image.sfs", &handle, &receipt)
            if status == SFS_OK {
                need(sfs_image_close(handle, &receipt) == SFS_OK, "unknown reopen close")
                let actual = f.contents()
                need(actual == Data("original".utf8) || actual == Data(repeating: 3, count: 70000), "unknown publication selects whole old/new")
            } else { need(status == SFS_RECOVERY_REQUIRED && handle == nil, "unknown publication requires explicit recovery") }
        }
    }
    for atCommit in [false, true] {
        let f = try Fixture(parent, atCommit ? "commit-memory" : "second-clock"), m = try Mounted(f)
        need(m.write(Data("accepted".utf8)).1 == nil, "earlier callback accepted")
        let before = m.volume.anchor.generation
        m.serial {
            // Target the real cold reconciliation allocation, independent of
            // whether a warm commit can reuse its metadata cache storage.
            if atCommit { m.volume.diagnosticBeforeCommit = { [coreHandle = m.coreHandle] in
                sfs_image_clear_read_cache(coreHandle); fault(7,1)
            } }
            else { m.volume.diagnosticAfterChunk = { _ in fault(6,1) } }
        }
        let result = m.write(Data(repeating: 2, count: 150000))
        need(result.0 == 0 && code(result.1) == Int(atCommit ? ENOMEM : ENXIO), "whole callback rejected")
        let original = m.volume.diagnosticSnapshot().2!.result
        need(original.transaction_active == (atCommit ? 0 : 1) && original.poisoned == 0, "discarded and active abort branches")
        need(m.volume.anchor.generation == before && code(m.sync()) == code(result.1), "prior committed receipt survives")
        m.close(); need(f.contents() == Data("accepted".utf8), "earlier acknowledgment survives rejected callback")
    }
    let f = try Fixture(parent, "postcommit"), m = try Mounted(f)
    m.serial { m.volume.diagnosticAfterSizeCommit = { fault(8,1) } }
    let a = FSItem.SetAttributesRequest(); a.size = 70
    let before = m.volume.anchor.generation, result = m.set(a)
    need(result.0?.size == 70 && result.1 == nil && hits() == 0 && a.consumedAttributes == [.size] && m.volume.anchor.generation == before + 1, "prebuilt size reply needs no postcommit fetch")
    m.close(); need(f.contents().count == 70, "prepared reply matches committed resize")
    let rolloverFixture = try Fixture(parent, "rollover"), rollover = try Mounted(rolloverFixture)
    need(rollover.write(Data("accepted".utf8)).1 == nil, "rollover prior callback")
    rollover.serial { rollover.volume.diagnosticAfterChunk = { bytes in if bytes == 1024 * 1024 { fault(1,1) } } }
    let failedRollover = rollover.write(Data(repeating: 5, count: 1024 * 1024 + 65536))
    need(failedRollover.0 == 0 && code(failedRollover.1) == Int(ENOSPC) && hits() != 0, "rollover append error rejects whole callback")
    rollover.close(); need(rolloverFixture.contents() == Data("accepted".utf8), "rollover preserves prior acknowledgment")
    let shortFixture = try Fixture(parent, "short-success"), short = try Mounted(shortFixture)
    fault(9,0); need(short.write(Data("complete".utf8)).1 == nil && hits() > 0, "short writes completed exactly")
    short.close(); need(shortFixture.contents() == Data("complete".utf8), "short-write exact data")
    let unsupportedFixture = try Fixture(parent, "unexpected-unsupported"), unsupported = try Mounted(unsupportedFixture)
    unsupported.serial { unsupported.volume.diagnosticBeforeCommit = { fault(10,1) } }
    need(code(unsupported.write(Data([1])).1) == Int(ENOTSUP) && hits() > 0, "unexpected core unsupported")
    let terminal = unsupported.volume.diagnosticSnapshot().2!
    need(terminal.result.status == SFS_UNSUPPORTED && terminal.result.poisoned != 0 && code(unsupported.sync()) == Int(ENOTSUP), "unsupported is terminal with original receipt")
    let request = FSItem.GetAttributesRequest(); request.wantedAttributes = [.size]
    let blocked: (FSItem.Attributes?, Error?) = wait { done in unsupported.volume.getAttributes(request, of: unsupported.file) { done(($0,$1)) } }
    need(blocked.0 == nil && code(blocked.1) == Int(ENOTSUP), "terminal unsupported closes ordinary core access")
    unsupported.close(); need(unsupportedFixture.contents() == Data("original".utf8), "unexpected unsupported never publishes")
}

func admission(_ parent: URL) throws {
    let f = try Fixture(parent, "admission"), m = try Mounted(f), v = m.volume
    let held = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
    v.enqueue { held.signal(); need(release.wait(timeout: .now() + 20) == .success, "release held owner") }
    need(held.wait(timeout: .now() + 20) == .success, "held serial queue")
    let a = FSItem.GetAttributesRequest(); a.wantedAttributes = [.fileID]
    let replies = DispatchGroup()
    for _ in 0..<ReadOnlyLimits.callbacks { replies.enter(); v.getAttributes(a, of: m.file) { _, _ in replies.leave() } }
    var rejected = 0
    v.writeCountForTesting(contents: Data([1]), to: m.file, at: 0) { count, error in
        need(count == 0 && code(error) == Int(EAGAIN), "prequeue failure")
        rejected += 1
        // Reentrant sync must see the error before the rejection callback.
        v.synchronize(flags: .wait) { need(code($0) == Int(EAGAIN), "sync cannot overtake failure latch") }
    }
    need(rejected == 1 && v.diagnosticSnapshot().2?.code == Int(EAGAIN), "exact immediate refusal")
    release.signal(); need(replies.wait(timeout: .now() + 20) == .success, "accepted work drains")
    for flag in [FSSyncFlags.wait, .dWait, .noWait] { need(code(m.sync(flag)) == Int(EAGAIN), "later sync preserves prequeue error") }
    let observed = v.diagnosticSnapshot()
    need(observed.0.syncs == 4 && observed.1.filter { $0.operation == 1005 && $0.code == Int(EAGAIN) }.count == 4, "rejected sync arrivals/outcomes observed")
    for flag in [FSSyncFlags.wait, .dWait, .noWait] {
        need(observed.1.contains { $0.operation == 2005 && $0.mask == UInt64(flag.rawValue) } && observed.1.contains { $0.operation == 1005 && $0.mask == UInt64(flag.rawValue) && $0.code == Int(EAGAIN) }, "every sticky sync flag has entry/completion")
    }
    m.close(); need(f.contents() == Data("original".utf8), "saturation retains no writes")
    let overflow = try Mounted(f)
    for _ in 0..<4097 { need(overflow.write(Data()).1 == nil, "zero write trace operand") }
    let snapshot = overflow.volume.diagnosticSnapshot()
    need(snapshot.1.count == 4096 && snapshot.0.overflow && snapshot.0.commits == 0, "bounded trace overflow")
    overflow.close()
    let bytes = try Mounted(f)
    need(code(bytes.write(Data(count: ReadOnlyLimits.retainedBytes)).1) == Int(EAGAIN), "whole payload budget before retention")
    need(bytes.volume.diagnosticSnapshot().0.commits == 0, "oversized payload never reaches core")
    bytes.close()
    let racing = try Mounted(f), completed = DispatchGroup()
    for offset in [off_t(-1), off_t.max] {
        completed.enter()
        DispatchQueue.global().async(execute: DispatchWorkItem {
            racing.volume.writeCountForTesting(contents: Data([1]), to: racing.file, at: offset) { count, error in
                need(count == 0 && [Int(EINVAL), Int(EFBIG)].contains(code(error)), "concurrent prequeue failure"); completed.leave()
            }
        })
    }
    need(completed.wait(timeout: .now() + 20) == .success, "first-error race finishes")
    let first = racing.volume.diagnosticSnapshot().2!
    need([Int(EINVAL), Int(EFBIG)].contains(first.code) && code(racing.sync()) == first.code, "first observed error survives concurrent refusal")
    racing.close()
}

func lifetimeAndBinding(_ parent: URL) throws {
    let f = try Fixture(parent, "lifetime")
    let resource = FSPathURLResource(url: f.url, writable: true)
    let unbound = StallionFileSystem()
    let loaded: (FSVolume?, Error?) = wait { done in unbound.loadResource(resource: resource, force: false) { done(($0,$1)) } }
    need(loaded.1 == nil && (loaded.0 as! StallionVolume).requestedMountOptions.contains(.readOnly), "public default resource remains read-only")
#if STALLION_CONTEXT_HANDLERS
    let unboundVolume = loaded.0 as! StallionVolume
    let refusedLink: (FSCreateLinkResult?, Error?) = wait { done in
        unboundVolume.linkResultForTesting(StallionItem(2), name: FSFileName(string: "new-name"), directory: StallionItem(1),
            caller: CallerIdentity(uid: Int(geteuid()), gid: Int(getegid()))) { done(($0,$1)) }
    }
    need(refusedLink.0 == nil && code(refusedLink.1) == Int(EROFS), "writable generic resource without UUID cannot link")
#endif
    let unloaded: Error? = wait { unbound.unloadResource(resource: resource, replyHandler: $0) }; need(unloaded == nil, "unbound unload")
    let wrong = StallionFileSystem(); wrong.diagnosticUUID = UUID()
    let denied: (FSVolume?, Error?) = wait { done in wrong.loadResource(resource: resource, force: false) { done(($0,$1)) } }
    need(denied.0 == nil && code(denied.1) == Int(EACCES), "wrong UUID binding refused")
    let bound = StallionFileSystem(); bound.diagnosticUUID = f.identity
    let readonlyResource = FSPathURLResource(url: f.url, writable: false)
    let deniedMode: (FSVolume?, Error?) = wait { done in bound.loadResource(resource: readonlyResource, force: false) { done(($0,$1)) } }
    need(deniedMode.0 == nil && code(deniedMode.1) == Int(EACCES), "resource writable gate")
    let m = try Mounted(f), v = m.volume
    let held = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), drained = DispatchSemaphore(value: 0)
    v.enqueue { held.signal(); need(release.wait(timeout: .now() + 20) == .success, "lifecycle release") }
    need(held.wait(timeout: .now() + 20) == .success, "hold lifecycle owner")
    var written = false
    v.writeCountForTesting(contents: Data("durable!".utf8), to: m.file, at: 0) { count, error in
        need(count == 8 && error == nil, "accepted write completes before unmount")
        let busy = v.unload(); need(!busy.consumed && code(busy.error) == Int(EBUSY), "write reply keeps handle ownership")
        written = true
    }
    v.unmount { need(written, "unmount drains accepted write"); drained.signal() }
    release.signal(); need(drained.wait(timeout: .now() + 20) == .success, "drain write lifecycle")
    let ordered = v.diagnosticSnapshot().1
    let writeRecord = ordered.last { $0.operation == 1 }!, unmountRecord = ordered.last { $0.operation == 1003 }!
    need(writeRecord.sequence < unmountRecord.sequence && writeRecord.finished <= unmountRecord.finished, "shared write/lifecycle sequence and timestamps")
    need(m.sync() == nil, "maintenance sync after unmount")
    let trace = v.diagnosticSnapshot().1
    let busy = trace.last { $0.operation == 1006 && $0.code == Int(EBUSY) }!
    let syncEntry = trace.last { $0.operation == 2005 }!, syncDone = trace.last { $0.operation == 1005 }!
    need(writeRecord.sequence < busy.sequence && busy.sequence < unmountRecord.sequence && unmountRecord.sequence < syncEntry.sequence && syncEntry.sequence < syncDone.sequence, "write busy-unload unmount sync causal trace")
    let reclaim: Error? = wait { v.reclaimForTesting(m.file, eligible: true, replyHandler: $0) }
    need(reclaim == nil, "post-unmount controlled reclaim")
    let remounted: Error? = wait { v.mount(arguments: [], replyHandler: $0) }; need(remounted == nil, "remount after completed drain")
    m.close(); need(f.contents() == Data("durable!".utf8), "lifetime retains durable callback")
}

func retainedTraceSnapshot(_ parent: URL) throws {
    let f = try Fixture(parent, "trace-snapshot"), m = try Mounted(f), v = m.volume
    func values(_ records: [StallionVolume.WriteRecord]) -> [[UInt64]] {
        records.map { record in
            let r = record.result
            let fields: [UInt64] = [record.sequence, record.operation, record.inode, record.offset, record.length, record.mask,
                record.started, record.finished, record.generation, UInt64(bitPattern: Int64(record.count)), UInt64(bitPattern: Int64(record.code)),
                UInt64(r.status.rawValue), UInt64(r.phase.rawValue), UInt64(bitPattern: Int64(r.system_errno)),
                r.generation, r.committed_end, r.physical_end, r.device, r.inode,
                UInt64(r.coverage.rawValue), UInt64(r.incomplete_reason.rawValue), UInt64(r.limit_reason.rawValue),
                UInt64(r.fence_attempted), UInt64(r.fence_succeeded), UInt64(bitPattern: Int64(r.transaction_active)), UInt64(bitPattern: Int64(r.poisoned))]
            return fields + rawBytes(r.uuid).map(UInt64.init) + rawBytes(r.root_digest).map(UInt64.init)
        }
    }
    let live = v.diagnosticTraceStorageForTesting(), saved = v.diagnosticSnapshot()
    let savedValues = values(saved.1), savedCallbacks = saved.0.callbacks, savedCommits = saved.0.commits
    let exportedAddress = saved.1.withUnsafeBufferPointer { UInt(bitPattern: UnsafeRawPointer($0.baseAddress!)) }
    need(live.count > 0 && live.capacity >= 4096 && exportedAddress != live.address, "snapshot owns storage independent of reserved live trace")
    withExtendedLifetime(saved) {
        need(m.write(Data("snapshot".utf8)).1 == nil, "write while exported snapshot remains retained")
        need(m.size(13).1 == nil, "resize while same snapshot remains retained")
        let after = v.diagnosticTraceStorageForTesting(), current = v.diagnosticSnapshot()
        need(after.address == live.address && after.capacity == live.capacity && after.count == live.count + 2, "postcommit appends keep original reserved trace buffer")
        need(values(saved.1) == savedValues && saved.0.callbacks == savedCallbacks && saved.0.commits == savedCommits, "retained snapshot contents stay unchanged")
        need(current.1.count == after.count && values(current.1).starts(with: savedValues), "new trace preserves complete old records")
        need(current.1.suffix(2).map(\.operation) == [1, 2] && current.1.suffix(2).allSatisfy { $0.code == 0 }, "write and resize trace outcomes remain correct")
        need(current.0.commits == savedCommits + 2 && current.0.callbacks == savedCallbacks + 2, "live counters reflect both commits")
    }
    m.close()
    need(f.contents() == Data("snapshot".utf8) + Data(repeating: 0, count: 5), "retained trace does not change saved file contents")
}

func preparedReplyFailure(_ parent: URL) throws {
    let f = try Fixture(parent, "prepare-failure"), m = try Mounted(f)
    need(m.write(Data("accepted".utf8)).1 == nil, "preparation baseline accepted")
    let before = m.volume.anchor.generation
    // A throwing preparation seam models a fallible conversion/admission step;
    // it is not evidence of a recoverable Swift allocator or SDK constructor OOM.
    m.serial { m.volume.diagnosticBeforePrepare = { throw POSIXError(.ENOMEM) } }
    let a = FSItem.SetAttributesRequest(); a.size = 128
    let result = m.set(a)
    need(result.0 == nil && code(result.1) == Int(ENOMEM) && a.consumedAttributes.isEmpty, "precommit preparation error consumes no fields")
    need(m.volume.anchor.generation == before && code(m.sync()) == Int(ENOMEM), "preparation preserves committed anchor and first error")
    m.serial {
        var r = sfs_result(), info = sfs_image_information()
        need(sfs_image_get_information(m.coreHandle, &info, &r) == SFS_OK && r.transaction_active == 0 && r.generation == before, "preparation abort completed")
        try! m.volume.diagnosticCloseModesForTesting(m.file, modes: [])
    }
    m.close(); need(f.contents() == Data("accepted".utf8), "preparation never publishes resize")
}

func detachedTokenRoutes(_ parent: URL) throws {
    let f = try Fixture(parent, "detached-routes"), m = try Mounted(f), v = m.volume
    let originalToken = (m.file as! StallionItem).pin!
    // Only this direct helper edits names through C; no adapter namespace
    // callback is enabled and no installed unlink routing is claimed.
    m.serial {
        try! v.diagnosticMutationForTesting { h, r in
            need(sfs_image_unlink_expected(h, 1, "file", 4, f.id, &r) == SFS_OK, "drop first alias")
            need(sfs_image_unlink_expected(h, 1, "alias", 5, f.id, &r) == SFS_OK, "drop final alias")
            need(sfs_image_unlink_expected(h, 1, "link", 4, (m.link as! StallionItem).inode, &r) == SFS_OK, "drop symlink name")
        }
        need(try! v.diagnosticReadForTesting(m.file, length: 64) == Data("original".utf8), "adapter shared read helper uses detached token")
    }
    let request = FSItem.GetAttributesRequest(); request.wantedAttributes = [.size, .linkCount, .fileID]
    let st: (FSItem.Attributes?, Error?) = wait { done in v.getAttributes(request, of: m.alias) { done(($0,$1)) } }
    need(st.1 == nil && st.0?.size == 8 && st.0?.linkCount == 0 && m.alias === m.file, "detached aliases retain canonical object and metadata")
    let parentRequest = FSItem.GetAttributesRequest(); parentRequest.wantedAttributes = [.parentID]
    let unavailable: (FSItem.Attributes?, Error?) = wait { done in v.getAttributes(parentRequest, of: m.file) { done(($0,$1)) } }
    need(unavailable.0 == nil && code(unavailable.1) == Int(ENOTSUP), "detached parent is unavailable")
    let value: (Data?, Error?) = wait { done in v.getXattr(named: FSFileName(string: "note"), of: m.file) { done(($0,$1)) } }
    let names: ([FSFileName]?, Error?) = wait { done in v.listXattrs(of: m.alias) { done(($0,$1)) } }
    need(value.1 == nil && value.0 == Data("value".utf8) && names.1 == nil && names.0?.map(\.data) == [Data("note".utf8)], "detached xattr token routes")
    let target: (FSFileName?, Error?) = wait { done in v.readSymbolicLink(m.link) { done(($0,$1)) } }
    need(target.1 == nil && target.0?.data == Data("file".utf8), "detached symlink token route")
#if STALLION_CONTEXT_HANDLERS
    if FSWriteFileResult.requestedAttributes.isAttributeWanted(.parentID) || FSSetAttributesResult.requestedAttributes.isAttributeWanted(.parentID) {
        let before = v.anchor
        let denied = FSWriteFileResult.requestedAttributes.isAttributeWanted(.parentID) ? m.write(Data("detached".utf8)).1 : m.size(11).1
        need(code(denied) == Int(ENOTSUP) && anchorMatches(v.anchor, before), "required detached parent refuses before commit")
        m.serial { need(try! v.diagnosticReadForTesting(m.file, length: 64) == Data("original".utf8), "detached preparation refusal preserves bytes") }
        m.close(); return
    }
#endif
    need(m.write(Data("detached".utf8), alias: true).1 == nil, "detached write through alias")
    let resized = m.size(11); need(resized.1 == nil && resized.0?.size == 11, "detached precommit size reply")
    m.serial { need(try! v.diagnosticReadForTesting(m.file, length: 64) == Data("detached".utf8) + Data(repeating: 0, count: 3), "detached resize/read bytes") }
    for name in ["file", "alias", "link"] {
        let missing: (FSItem?, Error?) = wait { done in v.lookupItem(named: FSFileName(string: name), inDirectory: m.root) { done(($0,$2)) } }
        need(missing.0 == nil && code(missing.1) == Int(ENOENT), "no namespace resurrection")
    }
#if STALLION_CONTEXT_HANDLERS
    // Pure refusal body; actual contextual selectors require a kernel FSContext.
    let refused: Error? = wait { v.refusedMutationForTesting(replyHandler: $0) }
    let xattrRefused: Error? = wait { v.refusedMutationForTesting(replyHandler: $0) }
#else
    let refused: Error? = wait { v.removeItem(m.file, named: FSFileName(string: "file"), fromDirectory: m.root, replyHandler: $0) }
    let xattrRefused: Error? = wait { v.setXattr(named: FSFileName(string: "note"), to: Data(), on: m.file, policy: .alwaysSet, replyHandler: $0) }
#endif
    need(code(refused) == Int(EROFS) && code(xattrRefused) == Int(EROFS), "namespace and xattr setter stay refused in private mode")
    let no: Error? = wait { v.reclaimForTesting(m.file, eligible: false, replyHandler: $0) }; need(no == nil, "false reclaim replies nil")
    m.serial { need(v.ownsForTesting(m.file) && (m.file as! StallionItem).pin != nil, "false reclaim retains ownership") }
    let yes: Error? = wait { v.reclaimForTesting(m.file, eligible: true, replyHandler: $0) }; need(yes == nil, "controlled successful detached reclaim")
    m.serial {
        var r = sfs_result(), st = sfs_pin_stat()
        need(!v.ownsForTesting(m.file) && (m.file as! StallionItem).pin == nil && sfs_image_pin_stat(m.coreHandle, originalToken, &st, &r) == SFS_INVALID, "successful reclaim releases exactly one core token")
    }
    m.close()
    var h: OpaquePointer?, r = sfs_result(), entry = sfs_entry()
    need(sfs_image_open_readonly(f.url.path, "image.sfs", &h, &r) == SFS_OK, "detached reopen")
    need(sfs_image_stat(h, 0, f.id, &entry, &r) == SFS_NOT_FOUND, "detached inode remains outside committed namespace")
    need(sfs_image_close(h, &r) == SFS_OK, "detached reopen close")
}

func pinOwnershipLimits(_ parent: URL) throws {
    let f = try Fixture(parent, "pin-capacity", extra: true), m = try Mounted(f, itemLimit: 3), v = m.volume
    let full: (FSItem?, Error?) = wait { done in v.lookupItem(named: FSFileName(string: "extra"), inDirectory: m.root) { done(($0,$2)) } }
    need(full.0 == nil && code(full.1) == Int(ENFILE), "finite canonical and core pin capacity")
    let alias: (FSItem?, Error?) = wait { done in v.lookupItem(named: FSFileName(string: "alias"), inDirectory: m.root) { done(($0,$2)) } }
    need(alias.1 == nil && alias.0 === m.file, "full capacity still reuses canonical alias")
    let before = (m.file as! StallionItem).pin!
    let retained: Error? = wait { v.reclaimForTesting(m.file, eligible: false, replyHandler: $0) }; need(retained == nil, "lookup/reclaim false boundary")
    let released: Error? = wait { v.reclaimForTesting(m.file, eligible: true, replyHandler: $0) }; need(released == nil, "capacity release")
    let again: (FSItem?, Error?) = wait { done in v.lookupItem(named: FSFileName(string: "file"), inDirectory: m.root) { done(($0,$2)) } }
    need(again.1 == nil && again.0 !== m.file, "lookup after reclaim has new canonical owner")
    let next = (again.0 as! StallionItem).pin!
    need(next.slot == before.slot && next.incarnation > before.incarnation, "new ownership cannot reuse old token")
    let request = FSItem.GetAttributesRequest(); request.wantedAttributes = [.size]
    let stale: (FSItem.Attributes?, Error?) = wait { done in v.getAttributes(request, of: m.file) { done(($0,$1)) } }
    need(stale.0 == nil && code(stale.1) == Int(EINVAL), "stale FSItem cannot resolve new owner")
    let done: Error? = wait { v.reclaimForTesting(again.0!, eligible: true, replyHandler: $0) }; need(done == nil, "new owner cleanup")
    let _: Bool = wait { signal in v.unmount { signal(true) } }
    let busy: Error? = wait { v.deactivate(options: [], replyHandler: $0) }; need(code(busy) == Int(EBUSY), "deactivate retains root while nonroot survives")
    let busyUnload: Bool = wait { done in v.enqueue { done(v.unload().consumed) } }; need(!busyUnload, "busy unload retains handle and pins")
    m.close()
    let allocation = try Fixture(parent, "pin-allocation")
    var h: OpaquePointer?, r = sfs_result()
    need(sfs_image_open(allocation.url.path, "image.sfs", &h, &r) == SFS_OK, "allocation fixture open")
    let volume = StallionVolume(handle: h!, resource: FSPathURLResource(url: allocation.url, writable: true), scope: false, anchor: r, queue: DispatchQueue(label: "sfs.pin.allocation"))
    fault(7, 1)
    do { try volume.enableWriteDiagnostic(expectedUUID: allocation.identity); fatalError("pin allocation should fail before exposure") }
    catch { need(code(error) == Int(ENOMEM) && hits() == 1 && !volume.diagnosticWritable, "pin configuration NOMEM stays unexposed") }
    fault(0, 0)
    let consumed: Bool = wait { done in volume.enqueue { done(volume.unload().consumed) } }; need(consumed, "failed configuration handle consumed")
}

func reclaimErrorAndRoot(_ parent: URL) throws {
    let f = try Fixture(parent, "reclaim-error"), m = try Mounted(f), v = m.volume
    // Corrupt only the adapter's private test token; no SDK state is fabricated.
    m.serial { (m.file as! StallionItem).pin = sfs_pin() }
    let error: Error? = wait { v.reclaimForTesting(m.file, eligible: true, replyHandler: $0) }
    need(code(error) == Int(EINVAL), "release failure is retained as terminal evidence")
    m.serial {
        need(!v.ownsForTesting(m.file), "failed release never reinserts reclaimed item")
        try! v.diagnosticCloseModesForTesting(m.link, modes: [])
    }
    need(code(m.sync()) == Int(EINVAL), "release error sticks")
    m.close()
    let rootFixture = try Fixture(parent, "root-lifetime"), rootMount = try Mounted(rootFixture), rootVolume = rootMount.volume
    let token = (rootMount.root as! StallionItem).pin!
    let rejected: Error? = wait { rootVolume.reclaimForTesting(rootMount.root, eligible: false, replyHandler: $0) }; need(rejected == nil, "false root reclaim")
    rootMount.serial { need(rootVolume.ownsForTesting(rootMount.root), "false root reclaim keeps activation token") }
    let accepted: Error? = wait { rootVolume.reclaimForTesting(rootMount.root, eligible: true, replyHandler: $0) }; need(accepted == nil, "successful root reclaim consumes activation owner")
    let activated: (FSItem?, Error?) = wait { done in rootVolume.activate { done(($0,$1)) } }
    need(activated.1 == nil && activated.0 !== rootMount.root, "reactivation reacquires root")
    rootMount.serial {
        var r = sfs_result(), st = sfs_pin_stat()
        need(sfs_image_pin_stat(rootMount.coreHandle, token, &st, &r) == SFS_INVALID, "old root token stays invalid")
    }
    rootMount.close()
    let retainedFixture = try Fixture(parent, "activation-root"), retained = try Mounted(retainedFixture), rv = retained.volume
    let retainedToken = (retained.root as! StallionItem).pin!
    let _: Bool = wait { done in rv.unmount { done(true) } }
    for item in [retained.file, retained.link] {
        let error: Error? = wait { rv.reclaimForTesting(item, eligible: true, replyHandler: $0) }; need(error == nil, "nonroot reclaim before deactivate")
    }
    let deactivated: Error? = wait { rv.deactivate(options: [], replyHandler: $0) }; need(deactivated == nil, "deactivate releases activation-owned root")
    retained.serial {
        var r = sfs_result(), st = sfs_pin_stat()
        need(!rv.ownsForTesting(retained.root) && sfs_image_pin_stat(retained.coreHandle, retainedToken, &st, &r) == SFS_INVALID, "activation root released without data access")
    }
    let next: (FSItem?, Error?) = wait { done in rv.activate { done(($0,$1)) } }
    need(next.1 == nil && next.0 !== retained.root, "next activation owns fresh root")
    let mounted: Error? = wait { rv.mount(arguments: [], replyHandler: $0) }; need(mounted == nil, "reactivated volume mounts")
    retained.close()
}

#if STALLION_CONTEXT_HANDLERS
// These values exercise policy only; FSContext.init is unavailable.
func contextualPolicyValues() throws {
    let owner = geteuid(), caller = CallerIdentity(uid: Int(owner), gid: Int(getegid()))
    var m = sfs_metadata_entry(); m.uid = owner; m.gid = getegid(); m.mode = 0o600; m.entry.kind = SFS_FILE
    try checkOwnerPolicy(m, owner: owner, caller: caller, access: [.readData, .writeData], writable: true, hasACL: false)
    try checkOwnerPolicy(m, owner: owner, caller: CallerIdentity(uid: Int(owner), gid: Int(getegid()) + 1), access: .readData, writable: false, hasACL: false)
    func denied(_ expected: Int32, _ body: () throws -> Void) {
        do { try body(); need(false, "policy unexpectedly granted access") }
        catch { need(code(error) == Int(expected), "policy denial code") }
    }
    for foreign in [CallerIdentity(uid: Int(owner) + 1, gid: caller.gid), CallerIdentity(uid: -1, gid: caller.gid), CallerIdentity(uid: caller.uid, gid: -1)] {
        denied(EACCES) { try checkOwnerPolicy(m, owner: owner, caller: foreign, access: .readAttributes, writable: true, hasACL: false) }
    }
    if owner != 0 { denied(EACCES) { try checkOwnerPolicy(m, owner: owner, caller: CallerIdentity(uid: 0, gid: 0), access: .readData, writable: true, hasACL: false) } }
    denied(ENOTSUP) { try checkOwnerPolicy(m, owner: owner, caller: caller, access: .readData, writable: false, hasACL: true) }
    denied(EACCES) { try checkOwnerPolicy(m, owner: owner, caller: caller, access: .writeData, writable: false, hasACL: false) }
    m.mode = 0o6600
    denied(EACCES) { try checkOwnerPolicy(m, owner: owner, caller: caller, access: .writeData, writable: true, hasACL: false) }
    m.entry.kind = SFS_DIRECTORY; m.mode = 0o400
    denied(EACCES) { try checkOwnerPolicy(m, owner: owner, caller: caller, access: .search, writable: false, hasACL: false) }
    m.mode = 0o100
    try checkOwnerPolicy(m, owner: owner, caller: caller, access: .search, writable: false, hasACL: false)
    denied(EACCES) { try checkOwnerPolicy(m, owner: owner, caller: caller, access: [.readData, .search], writable: false, hasACL: false) }
    m.mode = 0o500
    try checkOwnerPolicy(m, owner: owner, caller: caller, access: [.readData, .search], writable: false, hasACL: false)
}
func unknownCallerAttribute() -> FSItem.Attribute {
    for index in 0..<UInt.bitWidth {
        let bit = UInt(1) << index
        if bit & UInt(0x3ffff) == 0 { return FSItem.Attribute(rawValue: Int(bitPattern: bit)) }
    }
    fatalError("an undeclared caller attribute is required for this case")
}
func incompleteSnapshot(_ original: FSItem.Attributes) -> FSItem.Attributes {
    let a = FSItem.Attributes(); a.invalidateAllProperties()
    if original.isValid(.type) { a.type = original.type }
    if original.isValid(.mode) { a.mode = original.mode }
    if original.isValid(.linkCount) { a.linkCount = original.linkCount }
    if original.isValid(.uid) { a.uid = original.uid }
    if original.isValid(.gid) { a.gid = original.gid }
    if original.isValid(.flags) { a.flags = original.flags }
    if original.isValid(.allocSize) { a.allocSize = original.allocSize }
    if original.isValid(.fileID) { a.fileID = original.fileID }
    if original.isValid(.parentID) { a.parentID = original.parentID }
    if original.isValid(.accessTime) { a.accessTime = original.accessTime }
    if original.isValid(.modifyTime) { a.modifyTime = original.modifyTime }
    if original.isValid(.changeTime) { a.changeTime = original.changeTime }
    if original.isValid(.birthTime) { a.birthTime = original.birthTime }
    // Preserve the result policy while deliberately omitting size.
    a.supportsLimitedXAttrs = false
    a.inhibitKernelOffloadedIO = true
    return a
}
func completenessRefused(_ attributes: FSItem.Attributes, required: FSItem.Attribute) {
    do { try StallionVolume.requireValidForTesting(attributes, required: required); need(false, "incomplete snapshot accepted") }
    catch { need(code(error) == Int(ENOTSUP), "incomplete snapshot refusal") }
}
func checkPreparedAttributes(_ a: FSItem.Attributes, _ m: sfs_metadata_entry, required: FSItem.Attribute, exact: Bool = false) {
    let fields: [FSItem.Attribute] = [.type, .mode, .linkCount, .uid, .gid, .flags, .size, .allocSize, .fileID, .parentID,
        .accessTime, .modifyTime, .changeTime, .birthTime, .supportsLimitedXAttrs, .inhibitKernelOffloadedIO]
    try! StallionVolume.requireValidForTesting(a, required: required)
    for field in fields {
        if required.contains(field) { need(a.isValid(field), "required SDK attribute populated") }
        if exact { need(a.isValid(field) == required.contains(field), "only explicit entry attributes populated") }
    }
    if a.isValid(.type) { need(a.type == (m.entry.kind == SFS_FILE ? .file : m.entry.kind == SFS_DIRECTORY ? .directory : .symlink), "type") }
    if a.isValid(.mode) { need(a.mode == m.mode, "mode") }
    if a.isValid(.linkCount) { need(UInt64(a.linkCount) == m.link_count, "link count") }
    if a.isValid(.uid) { need(a.uid == m.uid, "uid") }
    if a.isValid(.gid) { need(a.gid == m.gid, "gid") }
    if a.isValid(.flags) { need(a.flags == m.flags, "flags") }
    if a.isValid(.size) { need(a.size == m.entry.size, "size") }
    if a.isValid(.allocSize) { need(a.allocSize == m.referenced_data_bytes, "allocation") }
    if a.isValid(.fileID) { need(a.fileID == (try! itemIdentifier(m.entry.inode)), "file identifier") }
    if a.isValid(.parentID) { need(m.link_count > 0 && a.parentID == (m.entry.inode == 1 ? .parentOfRoot : try! itemIdentifier(m.entry.parent)), "parent identifier") }
    func time(_ actual: timespec, _ expected: sfs_timestamp) {
        need(actual.tv_sec == expected.seconds && actual.tv_nsec == expected.nanoseconds, "timestamp")
    }
    if a.isValid(.accessTime) { time(a.accessTime, m.access) }
    if a.isValid(.modifyTime) { time(a.modifyTime, m.modification) }
    if a.isValid(.changeTime) { time(a.changeTime, m.change) }
    if a.isValid(.birthTime) { time(a.birthTime, m.birth) }
    if a.isValid(.supportsLimitedXAttrs) { need(!a.supportsLimitedXAttrs, "xattr capability") }
    if a.isValid(.inhibitKernelOffloadedIO) { need(a.inhibitKernelOffloadedIO, "I/O routing attribute") }
}
func contextualResults(_ parent: URL) throws {
    let f = try Fixture(parent, "handler-results"), m = try Mounted(f), v = m.volume
    let caller = CallerIdentity(uid: Int(geteuid()), gid: Int(getegid()))
    let resultTypes: [FSVolumeHandlerResult.Type] = [FSLookupItemResult.self, FSGetAttributesResult.self,
        FSReadSymlinkResult.self, FSReadFileResult.self, FSWriteFileResult.self, FSSetAttributesResult.self]
    let resultMasks = resultTypes.map { ($0, $0.requestedAttributes.wantedAttributes) }
#if STALLION_RESULT_MASK_TRACE
    // Record all six actual snapshots before the first strict union check.
    for (type, original) in resultMasks {
        let raw = UInt(bitPattern: original.rawValue)
        resultMaskTrace("\(type) original=0x\(String(raw, radix: 16)) outside_caller_readable=0x\(String(raw & ~UInt(0x3fff), radix: 16)) explicit=0x140")
    }
#endif
    for (type, original) in resultMasks {
        let union = try StallionVolume.resultRequestForTesting(type, explicit: [.size, .fileID])
        need(union.wantedAttributes == original.union([.size, .fileID]) && type.requestedAttributes.wantedAttributes == original, "subclass mask union leaves SDK object unchanged")
        for index in 0..<UInt.bitWidth {
            let bit = UInt(1) << index
            if UInt(bitPattern: original.rawValue) & bit != 0 && bit & UInt(0x3fff) == 0 {
                do { _ = try StallionVolume.resultRequestForTesting(type, explicit: FSItem.Attribute(rawValue: Int(bitPattern: bit))); need(false, "SDK-owned requirement accepted as caller field") }
                catch { need(code(error) == Int(ENOTSUP), "caller and SDK authority remain separate") }
            }
        }
    }
    for unsupported in [unknownCallerAttribute(), .backupTime, .addedTime, .supportsLimitedXAttrs, .inhibitKernelOffloadedIO, [.size, .supportsLimitedXAttrs], [.size, .inhibitKernelOffloadedIO]] {
        do { _ = try StallionVolume.resultRequestForTesting(FSWriteFileResult.self, explicit: unsupported); need(false, "unsupported mandatory field") }
        catch { need(code(error) == Int(ENOTSUP), "unsupported result request refused") }
    }
    // Constructor-only access coverage; no fabricated FSContext or client claim.
    need(FSCheckAccessResult(accessAllowed: true) != nil && FSCheckAccessResult(accessAllowed: false) != nil, "actual access constructors")
    var retained: [(FSItem.Attributes, sfs_metadata_entry, FSItem.Attribute)] = []
    var captured: [String: FSItem.Attributes] = [:], commitStarted = false
    m.serial {
        v.preparedAttributesForTesting = { name, attributes in need(!commitStarted, "attributes prepared before commit"); captured[name] = attributes }
        v.diagnosticBeforeCommit = { commitStarted = true }
        v.rejectResultForTesting = { _ in need(!commitStarted, "SDK result constructed before commit"); return false }
    }
    let activated: (FSActivateResult?, Error?) = wait { done in v.activateResultForTesting { done(($0,$1)) } }
    need(activated.0 != nil && activated.1 == nil, "actual activation constructor")
    for name in ["file", "alias"] {
        let result: (FSLookupItemResult?, Error?) = wait { done in v.lookupResultForTesting(name, directory: m.root, caller: caller) { done(($0,$1)) } }
        need(result.0 != nil && result.1 == nil, "actual lookup constructor")
    }
    let request = FSItem.GetAttributesRequest(); request.wantedAttributes = [.size, .fileID, .parentID, .mode, .uid, .gid, .linkCount, .flags, .allocSize, .accessTime, .modifyTime, .changeTime, .birthTime]
    let attributes: (FSGetAttributesResult?, Error?) = wait { done in v.attributesResultForTesting(request, item: m.file, caller: caller) { done(($0,$1)) } }
    need(attributes.0 != nil && attributes.1 == nil, "actual attribute constructor and explicit mask")
    for rejected in [unknownCallerAttribute(), .backupTime, .addedTime, .supportsLimitedXAttrs, .inhibitKernelOffloadedIO, [.size, .supportsLimitedXAttrs], [.size, .inhibitKernelOffloadedIO]] {
        let unsupported = FSItem.GetAttributesRequest(); unsupported.wantedAttributes = rejected
        let denied: (FSGetAttributesResult?, Error?) = wait { done in v.attributesResultForTesting(unsupported, item: m.file, caller: caller) { done(($0,$1)) } }
        need(denied.0 == nil && code(denied.1) == Int(ENOTSUP) && unsupported.wantedAttributes == rejected, "actual contextual caller-mask refusal is atomic")
    }
    m.serial {
        let complete = captured["FSGetAttributesResult"]!, required = FSGetAttributesResult.requestedAttributes.wantedAttributes
        try! StallionVolume.requireValidForTesting(complete, required: required)
        let omitted = incompleteSnapshot(complete), invalidated = incompleteSnapshot(complete)
        invalidated.invalidateAllProperties()
        need(!omitted.isValid(.size) && FSGetAttributesResult(attributes: omitted) != nil && FSGetAttributesResult(attributes: invalidated) != nil,
             "real incomplete constructors do not establish completeness on this runtime")
        completenessRefused(omitted, required: required)
        completenessRefused(invalidated, required: required)
        need(!required.contains(.backupTime) && !complete.isValid(.backupTime), "absent synthetic additional requirement")
        completenessRefused(complete, required: required.union(.backupTime))
        // These synthetic masks cover the shared production guard, not an observed SDK requirement.
        let callerOnly = FSItem.Attributes()
        callerOnly.invalidateAllProperties()
        callerOnly.fileID = complete.fileID
        need(callerOnly.isValid(.fileID) && !callerOnly.isValid(.size), "synthetic SDK fields valid while caller-only size is missing")
        do {
            try StallionVolume.requireResultValidityForTesting(callerOnly, sdk: .fileID, caller: .size)
            need(false, "production two-mask guard accepted missing caller-only size")
        } catch { need(code(error) == Int(ENOTSUP), "caller-only completeness refusal") }
        callerOnly.size = complete.size
        need(callerOnly.isValid(.size), "caller-only size supplied from real metadata")
        try! StallionVolume.requireResultValidityForTesting(callerOnly, sdk: .fileID, caller: .size)
        need(FSGetAttributesResult.requestedAttributes.wantedAttributes == required, "synthetic requirement leaves SDK request unchanged")
        try! StallionVolume.requireValidForTesting(complete, required: required)
    }
    let link: (FSReadSymlinkResult?, Error?) = wait { done in v.readlinkResultForTesting(m.link, caller: caller) { done(($0,$1)) } }
    let xattr: (FSGetXattrResult?, Error?) = wait { done in v.xattrResultForTesting(m.file, caller: caller) { done(($0,$1)) } }
    let names: (FSListXattrsResult?, Error?) = wait { done in v.xattrsResultForTesting(m.file, caller: caller) { done(($0,$1)) } }
    need(link.0 != nil && link.1 == nil && xattr.0 != nil && xattr.1 == nil && names.0 != nil && names.1 == nil, "actual readlink/xattr constructors")
    func enumeration(_ request: FSItem.GetAttributesRequest?, start: UInt64 = 0, verifier: UInt64 = 0,
                     capacity: Int = 32) -> ([Data], [UInt64], UInt64, Error?) {
        var names: [Data] = [], cookies: [UInt64] = []
        let wanted = request?.wantedAttributes
        let listed: (FSEnumerateDirectoryResult?, Error?) = wait { done in
            v.enumerationResultForTesting(m.root, startingAt: FSDirectoryCookie(start), verifier: FSDirectoryVerifier(verifier),
                attributes: request, caller: caller, pack: { name, _, itemID, next, attributes in
                    guard names.count < capacity else { return false }
                    if let wanted {
                        need(attributes != nil, "explicit enumeration supplies attributes, even for an empty mask")
                        var metadata = sfs_metadata_entry(), result = sfs_result()
                        need(itemID.rawValue > 1, "entry identifier has a real core inode")
                        need(sfs_image_stat_metadata(m.coreHandle, 0, itemID.rawValue - 1, &metadata, &result) == SFS_OK, "entry metadata source")
                        checkPreparedAttributes(attributes!, metadata, required: wanted, exact: true)
                        retained.append((attributes!, metadata, wanted))
                    } else { need(attributes == nil, "nil enumeration preserves attribute-free entries") }
                    names.append(name.data); cookies.append(next.rawValue); return true
                }) { done(($0,$1)) }
        }
        need((listed.0 != nil) == (listed.1 == nil), "actual enumeration result or error")
        let record: StallionVolume.Record = wait { done in v.enqueue { done(v.capturedRecords().last!) } }
        need(record.operation == 14 && record.cookie == start && record.verifier == verifier &&
             record.acceptedCookie == (cookies.last ?? 0), "contextual enumeration cookies")
        need(request?.wantedAttributes == wanted, "enumeration leaves caller mask unchanged")
        return (names, cookies, record.returnedVerifier, listed.1)
    }
    let nilEntries = enumeration(nil)
    need(nilEntries.3 == nil && Array(nilEntries.0.prefix(2)) == [Data(".".utf8), Data("..".utf8)] &&
         Array(nilEntries.1.prefix(2)) == [1, 2] && nilEntries.0.count == 5, "nil enumeration includes dot entries")
    let page = enumeration(nil, capacity: 1)
    let rest = enumeration(nil, start: page.1.last!, verifier: page.2)
    need(page.3 == nil && rest.3 == nil && page.0 + rest.0 == nilEntries.0 && page.1 + rest.1 == nilEntries.1, "contextual pagination resumes without skipped entries")
    let empty = FSItem.GetAttributesRequest(); empty.wantedAttributes = []
    let emptyEntries = enumeration(empty)
    let explicit = FSItem.GetAttributesRequest(); explicit.wantedAttributes = FSItem.Attribute(rawValue: 0x3fff)
    let explicitEntries = enumeration(explicit)
    need(emptyEntries.3 == nil && explicitEntries.3 == nil && emptyEntries.0 == Array(nilEntries.0.dropFirst(2)) &&
         explicitEntries.0 == emptyEntries.0 && explicitEntries.1 == emptyEntries.1 && emptyEntries.1.allSatisfy { $0 > 16 }, "explicit empty and full masks omit dot entries")
    let wrongVerifier = enumeration(explicit, start: nilEntries.1.last!, verifier: nilEntries.2)
    need(wrongVerifier.3 != nil && wrongVerifier.0.isEmpty, "attribute mode cannot reuse nil-enumeration verifier")
    for unsupported in [unknownCallerAttribute(), .backupTime, .addedTime, .supportsLimitedXAttrs, .inhibitKernelOffloadedIO, [.size, .supportsLimitedXAttrs], [.size, .inhibitKernelOffloadedIO]] {
        let invalid = FSItem.GetAttributesRequest(); invalid.wantedAttributes = unsupported
        let refused = enumeration(invalid)
        need(code(refused.3) == Int(ENOTSUP) && refused.0.isEmpty, "unsupported explicit entry mask refused before packing")
    }
    m.serial {
        _ = try! v.readResultConstructorForTesting(m.file)
        for (name, item) in [("FSLookupItemResult", m.file), ("FSGetAttributesResult", m.file), ("FSReadSymlinkResult", m.link), ("FSReadFileResult", m.file)] {
            var stat = sfs_pin_stat(), r = sfs_result()
            need(sfs_image_pin_stat(m.coreHandle, (item as! StallionItem).pin!, &stat, &r) == SFS_OK, "constructor metadata source")
            let type = resultTypes.first { String(describing: $0) == name }!
            let explicit: FSItem.Attribute = name == "FSGetAttributesResult" ? request.wantedAttributes : []
            let required = type.requestedAttributes.wantedAttributes.union(explicit)
            checkPreparedAttributes(captured[name]!, stat.metadata, required: required)
            retained.append((captured[name]!, stat.metadata, required))
        }
    }
    need(m.write(Data("changed!".utf8)).1 == nil && commitStarted, "actual write result survives commit")
    m.serial {
        var stat = sfs_pin_stat(), r = sfs_result()
        need(sfs_image_pin_stat(m.coreHandle, (m.file as! StallionItem).pin!, &stat, &r) == SFS_OK, "committed write metadata")
        checkPreparedAttributes(captured["FSWriteFileResult"]!, stat.metadata, required: FSWriteFileResult.requestedAttributes.wantedAttributes)
        retained.append((captured["FSWriteFileResult"]!, stat.metadata, FSWriteFileResult.requestedAttributes.wantedAttributes))
        commitStarted = false
    }
    let resized = m.size(19)
    need(resized.1 == nil && resized.0?.size == 19 && commitStarted, "actual size result survives commit")
    m.serial {
        var stat = sfs_pin_stat(), r = sfs_result()
        need(sfs_image_pin_stat(m.coreHandle, (m.file as! StallionItem).pin!, &stat, &r) == SFS_OK, "committed size metadata")
        checkPreparedAttributes(captured["FSSetAttributesResult"]!, stat.metadata, required: FSSetAttributesResult.requestedAttributes.wantedAttributes)
        for (attributes, metadata, required) in retained {
            checkPreparedAttributes(attributes, metadata, required: required)
        }
        v.preparedAttributesForTesting = nil; v.diagnosticBeforeCommit = nil; v.rejectResultForTesting = nil
    }
    let foreign = CallerIdentity(uid: caller.uid + 1, gid: caller.gid)
    let deniedLookup: (FSLookupItemResult?, Error?) = wait { done in v.lookupResultForTesting("file", directory: m.root, caller: foreign) { done(($0,$1)) } }
    let deniedRead: (FSGetAttributesResult?, Error?) = wait { done in v.attributesResultForTesting(request, item: m.file, caller: foreign) { done(($0,$1)) } }
    let deniedList: (FSEnumerateDirectoryResult?, Error?) = wait { done in v.enumerationResultForTesting(m.root, caller: foreign, pack: { _,_,_,_,_ in need(false, "denied listing must not pack"); return true }) { done(($0,$1)) } }
    need(code(deniedLookup.1) == Int(EACCES) && code(deniedRead.1) == Int(EACCES) && code(deniedList.1) == Int(EACCES), "shared contextual bodies deny foreign values")
    m.close()
}
func queuedResizeAfterIncompleteSnapshot(_ parent: URL) throws {
    let f = try Fixture(parent, "queued-incomplete"), m = try Mounted(f), v = m.volume, before = m.volume.anchor
    let held = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), replies = DispatchGroup()
    let request = FSItem.SetAttributesRequest(); request.size = 29
    var firstPrepared = false, laterPrepared = false, constructed = false, cleared = false
    v.enqueue {
        v.preparedAttributesForTesting = { name, attributes in
            if name == "FSWriteFileResult" { firstPrepared = true; attributes.invalidateAllProperties() }
        }
        v.rejectResultForTesting = { _ in constructed = true; return false }
        held.signal(); need(release.wait(timeout: .now() + 20) == .success, "release incomplete-snapshot queue")
    }
    need(held.wait(timeout: .now() + 20) == .success, "hold queue before completeness failure")
    replies.enter()
    v.writeCountForTesting(contents: Data("rejected".utf8), to: m.file, at: 0) { count, error in
        need(count == 0 && code(error) == Int(ENOTSUP) && firstPrepared, "first queued write fails completeness")
        v.preparedAttributesForTesting = { _, _ in laterPrepared = true }
        cleared = true; replies.leave()
    }
    replies.enter()
    v.setAttributesValueForTesting(request, on: m.file, caller: CallerIdentity(uid: Int(geteuid()), gid: Int(getegid()))) { attributes, error in
        need(cleared && attributes == nil && code(error) == Int(ENOTSUP), "already-queued resize retains first completeness error")
        replies.leave()
    }
    release.signal(); need(replies.wait(timeout: .now() + 20) == .success, "queued completeness callbacks finish")
    need(!laterPrepared && !constructed && request.consumedAttributes.isEmpty && anchorMatches(v.anchor, before) &&
         v.diagnosticSnapshot().0.commits == 0 && code(m.sync()) == Int(ENOTSUP), "cleared injection still blocks later preparation/commit")
    m.serial { need(try! v.diagnosticReadForTesting(m.file, length: 64) == Data("original".utf8), "queued completeness failure preserves bytes") }
    m.close(); need(f.contents() == Data("original".utf8), "queued completeness failure preserves reopened bytes")
}
func rejectedHandlerResults(_ parent: URL) throws {
    let payloadFixture = try Fixture(parent, "reject-no-attributes"), payload = try Mounted(payloadFixture)
    let payloadCaller = CallerIdentity(uid: Int(geteuid()), gid: Int(getegid()))
    let payloadAnchor = payload.volume.anchor
    let payloadCount: Int = wait { done in payload.volume.enqueue { done(payload.volume.activeItemCount()) } }
    for operation in ["FSActivateResult", "FSGetXattrResult", "FSListXattrsResult", "FSEnumerateDirectoryResult"] {
        var reached = false
        payload.serial { payload.volume.rejectResultForTesting = { type in reached = reached || type == operation; return type == operation } }
        let rejected: (Bool, Error?) = wait { done in
            switch operation {
            case "FSActivateResult": payload.volume.activateResultForTesting { done(($0 == nil, $1)) }
            case "FSGetXattrResult": payload.volume.xattrResultForTesting(payload.file, caller: payloadCaller) { done(($0 == nil, $1)) }
            case "FSListXattrsResult": payload.volume.xattrsResultForTesting(payload.file, caller: payloadCaller) { done(($0 == nil, $1)) }
            default: payload.volume.enumerationResultForTesting(payload.root, caller: payloadCaller, pack: { _,_,_,_,_ in true }) { done(($0 == nil, $1)) }
            }
        }
        need(reached && rejected.0 && code(rejected.1) == Int(EIO), "attribute-free actual result rejection")
        payload.serial {
            need(payload.volume.activeItemCount() == payloadCount && payload.volume.ownsForTesting(payload.root) &&
                 anchorMatches(payload.volume.anchor, payloadAnchor) && payload.volume.diagnosticSnapshot().0.commits == 0,
                 "attribute-free result failure preserves ownership and anchor")
        }
    }
    payload.serial { payload.volume.rejectResultForTesting = nil }; payload.close()
    need(payloadFixture.contents() == Data("original".utf8), "attribute-free result failure preserves reopened bytes")
    let lookupFixture = try Fixture(parent, "reject-lookup", extra: true), lookup = try Mounted(lookupFixture, itemLimit: 4)
    let caller = CallerIdentity(uid: Int(geteuid()), gid: Int(getegid()))
    let retainedCount: Int = wait { done in lookup.volume.enqueue { done(lookup.volume.activeItemCount()) } }
    lookup.serial { lookup.volume.preparedAttributesForTesting = { _, attributes in attributes.invalidateAllProperties() } }
    for name in ["extra", "alias"] {
        let rejected: (FSLookupItemResult?, Error?) = wait { done in lookup.volume.lookupResultForTesting(name, directory: lookup.root, caller: caller) { done(($0,$1)) } }
        need(rejected.0 == nil && code(rejected.1) == Int(ENOTSUP), "lookup completeness refusal")
        lookup.serial { need(lookup.volume.activeItemCount() == retainedCount && lookup.volume.ownsForTesting(lookup.file), "completeness failure preserves canonical ownership") }
    }
    let rootRequest = FSItem.GetAttributesRequest(); rootRequest.wantedAttributes = [.size]
    let rejectedRoot: (FSGetAttributesResult?, Error?) = wait { done in lookup.volume.attributesResultForTesting(rootRequest, item: lookup.root, caller: caller) { done(($0,$1)) } }
    need(rejectedRoot.0 == nil && code(rejectedRoot.1) == Int(ENOTSUP), "root completeness refusal")
    lookup.serial {
        need(lookup.volume.activeItemCount() == retainedCount && lookup.volume.ownsForTesting(lookup.root), "root ownership survives incomplete snapshot")
        lookup.volume.preparedAttributesForTesting = nil
    }
    lookup.serial { lookup.volume.rejectResultForTesting = { $0 == "FSLookupItemResult" } }
    for name in ["extra", "alias"] {
        let rejected: (FSLookupItemResult?, Error?) = wait { done in lookup.volume.lookupResultForTesting(name, directory: lookup.root, caller: caller) { done(($0,$1)) } }
        need(rejected.0 == nil && code(rejected.1) == Int(EIO), "lookup constructor rejection")
        lookup.serial { need(lookup.volume.activeItemCount() == retainedCount && lookup.volume.ownsForTesting(lookup.file), "failed lookup releases only newly acquired ownership") }
    }
    lookup.serial { lookup.volume.rejectResultForTesting = nil }
    let retried: (FSLookupItemResult?, Error?) = wait { done in lookup.volume.lookupResultForTesting("extra", directory: lookup.root, caller: caller) { done(($0,$1)) } }
    need(retried.0 != nil && retried.1 == nil, "failed lookup returned its finite pin slot")
    let extra: (FSItem?, Error?) = wait { done in lookup.volume.lookupItem(named: FSFileName(string: "extra"), inDirectory: lookup.root) { done(($0,$2)) } }
    let released: Error? = wait { lookup.volume.reclaimForTesting(extra.0!, eligible: true, replyHandler: $0) }
    need(released == nil, "release recovered lookup ownership"); lookup.close()
    for operation in ["write", "write-empty", "resize", "resize-same", "resize-root"] {
        let f = try Fixture(parent, "incomplete-\(operation)"), m = try Mounted(f), v = m.volume, before = v.anchor
        let resultType = operation.hasPrefix("write") ? "FSWriteFileResult" : "FSSetAttributesResult"
        var prepared = false, constructed = false, committed = false
        m.serial {
            v.preparedAttributesForTesting = { name, attributes in
                if name == resultType { prepared = true; attributes.invalidateAllProperties() }
            }
            v.rejectResultForTesting = { name in if name == resultType { constructed = true }; return false }
            v.diagnosticBeforeCommit = { committed = true }
        }
        let request = FSItem.SetAttributesRequest(); request.size = operation == "resize-same" ? 8 : 29
        let error: Error?
        if operation.hasPrefix("write") { error = m.write(operation == "write-empty" ? Data() : Data("rejected".utf8)).1 }
        else { error = m.set(request, item: operation == "resize-root" ? m.root : m.file).1 }
        need(prepared && !constructed && !committed && code(error) == Int(ENOTSUP) && anchorMatches(v.anchor, before), "completeness precedes result and commit")
        need(request.consumedAttributes.isEmpty && v.diagnosticSnapshot().0.commits == 0 && code(m.sync()) == Int(ENOTSUP), "incomplete snapshot has no consumption or commit and keeps primary error")
        m.serial { need(try! v.diagnosticReadForTesting(m.file, length: 64) == Data("original".utf8), "completeness failure preserves acknowledged bytes") }
        m.close(); need(f.contents() == Data("original".utf8), "completeness failure preserves reopened bytes")
    }
    for operation in ["FSWriteFileResult", "FSSetAttributesResult"] {
        let f = try Fixture(parent, "reject-\(operation)"), m = try Mounted(f), v = m.volume, before = v.anchor
        var reached = false
        m.serial { v.rejectResultForTesting = { type in reached = reached || type == operation; return type == operation } }
        let request = FSItem.SetAttributesRequest(); request.size = 29
        let error = operation == "FSWriteFileResult" ? m.write(Data("rejected".utf8)).1 : m.set(request).1
        need(reached && code(error) == Int(EIO) && anchorMatches(v.anchor, before), "actual result preparation rejection aborts")
        need(request.consumedAttributes.isEmpty && v.diagnosticSnapshot().0.commits == 0 && code(m.sync()) == Int(EIO), "no consumption or commit; primary preparation error retained")
        m.serial { need(try! v.diagnosticReadForTesting(m.file, length: 64) == Data("original".utf8), "result failure preserves committed bytes") }
        m.close(); need(f.contents() == Data("original".utf8), "result failure preserves reopened bytes")
    }
    for operation in ["FSWriteFileResult", "FSSetAttributesResult"] {
        let f = try Fixture(parent, "revoke-\(operation)"), m = try Mounted(f), v = m.volume, before = v.anchor
        m.serial { v.rejectResultForTesting = { type in if type == operation { m.resource.revoke() }; return false } }
        let request = FSItem.SetAttributesRequest(); request.size = 31
        let error = operation == "FSWriteFileResult" ? m.write(Data("revoked!".utf8)).1 : m.set(request).1
        need(code(error) == Int(EACCES) && anchorMatches(v.anchor, before) && request.consumedAttributes.isEmpty && v.diagnosticSnapshot().0.commits == 0, "revocation after actual result construction refuses commit")
        m.close(); need(f.contents() == Data("original".utf8), "revoked resource cleans up and preserves bytes")
    }
    let f = try Fixture(parent, "foreign-size"), m = try Mounted(f), before = m.volume.anchor
    let request = FSItem.SetAttributesRequest(); request.size = 25
    let denied: (FSItem.Attributes?, Error?) = wait { done in m.volume.setAttributesValueForTesting(request, on: m.file, caller: CallerIdentity(uid: Int(geteuid()) + 1, gid: Int(getegid()))) { done(($0,$1)) } }
    need(code(denied.1) == Int(EACCES) && request.consumedAttributes.isEmpty && anchorMatches(m.volume.anchor, before), "actual size body denies foreign pure identity")
    m.close(); need(f.contents() == Data("original".utf8), "foreign size leaves bytes unchanged")
}
#endif

func queuedResizeAfterDeliveryFailure(_ parent: URL) throws {
    // Both requests enter the queue before any delivery failure exists. Cover
    // changed and unchanged size, since neither may consume size after failure.
    for size in [UInt64(29), UInt64(8)] {
        let f = try Fixture(parent, "queued-resize-\(size)"), m = try Mounted(f), v = m.volume
        need(m.write(Data("accepted".utf8)).1 == nil, "queued-failure acknowledged baseline")
        let before = v.anchor, counters = v.diagnosticSnapshot().0
        let held = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let replies = DispatchGroup(), request = FSItem.SetAttributesRequest()
        request.size = size
        var cleared = false
        v.enqueue {
            v.diagnosticBeforePrepare = { throw POSIXError(.ENOMEM) }
            held.signal(); need(release.wait(timeout: .now() + 20) == .success, "release queued-failure owner")
        }
        need(held.wait(timeout: .now() + 20) == .success, "hold queue before admitting write and resize")
        replies.enter()
        v.writeCountForTesting(contents: Data("rejected".utf8), to: m.file, at: 0) { count, error in
            need(count == 0 && code(error) == Int(ENOMEM), "first queued write fails during preparation")
            v.diagnosticBeforePrepare = nil; cleared = true
            replies.leave()
        }
        replies.enter()
        v.setAttributesValueForTesting(request, on: m.file, caller: CallerIdentity(uid: Int(geteuid()), gid: Int(getegid()))) { attributes, error in
            need(cleared && attributes == nil && code(error) == Int(ENOMEM), "queued resize preserves first failure after injection is removed")
            need(request.consumedAttributes.isEmpty, "queued failed resize never consumes size")
            replies.leave()
        }
        let admitted = v.diagnosticSnapshot().0
        need(admitted.callbacks == counters.callbacks + 2 && admitted.refused == counters.refused,
             "both callbacks admitted before first delivery failure")
        release.signal()
        need(replies.wait(timeout: .now() + 20) == .success, "queued failures complete")
        need(anchorMatches(v.anchor, before) && v.diagnosticSnapshot().0.commits == counters.commits,
             "queued failed resize adds no commit or anchor change")
        need(code(m.sync()) == Int(ENOMEM) && v.diagnosticSnapshot().2?.code == Int(ENOMEM), "primary queued error remains sticky")
        m.serial { need(try! v.diagnosticReadForTesting(m.file, length: 64) == Data("accepted".utf8), "queued failure preserves acknowledged bytes") }
        m.close(); need(f.contents() == Data("accepted".utf8), "reopened queued failure preserves acknowledged bytes")
    }
}

#if STALLION_CONTEXT_HANDLERS
func namespaceLink(_ m: Mounted, _ item: FSItem? = nil, name: Data = Data("new-name".utf8),
                   directory: FSItem? = nil, caller: CallerIdentity? = nil) -> (FSCreateLinkResult?, Error?) {
    wait { done in m.volume.linkResultForTesting(item ?? m.file, name: FSFileName(data: name), directory: directory ?? m.root,
        caller: caller ?? CallerIdentity(uid: Int(geteuid()), gid: Int(getegid()))) { done(($0,$1)) } }
}
func namespaceLookup(_ m: Mounted, _ name: String, directory: FSItem? = nil) -> FSItem {
    let found: (FSItem?, Error?) = wait { done in m.volume.lookupItem(named: FSFileName(string: name), inDirectory: directory ?? m.root) { done(($0,$2)) } }
    need(found.1 == nil && found.0 != nil, "namespace lookup"); return found.0!
}
func namespaceMetadata(_ m: Mounted, _ item: FSItem) -> sfs_metadata_entry {
    var value = sfs_metadata_entry()
    m.serial { var r = sfs_result(); need(sfs_image_stat_metadata(m.coreHandle, 0, (item as! StallionItem).inode, &value, &r) == SFS_OK, "namespace committed metadata") }
    return value
}
func namespaceAbsent(_ m: Mounted, _ name: String = "new-name") {
    m.serial {
        var r = sfs_result(), e = sfs_entry(), info = sfs_image_information()
        let bytes = Data(name.utf8)
        need(bytes.withUnsafeBytes { sfs_image_lookup(m.coreHandle, 0, 1, $0.baseAddress, $0.count, &e, &r) } == SFS_NOT_FOUND, "no alias publication")
        need(sfs_image_get_information(m.coreHandle, &info, &r) == SFS_OK && r.transaction_active == 0, "no pending transaction")
        need(m.volume.ownsForTesting(m.file) && m.volume.ownsForTesting(m.root) && m.volume.activeItemCount() == 3,
             "namespace keeps canonical ownership and item count")
    }
    let budget = m.volume.linkBudgetForTesting
    need(budget.0 == 0 && budget.1 == 0, "namespace releases callback and name-byte charge")
}
func namespaceReopened(_ f: Fixture, _ name: String, parent: UInt64 = 1, inode: UInt64?) {
    fault(0,0); var h: OpaquePointer?, r = sfs_result(), entry = sfs_entry()
    need(sfs_image_open_readonly(f.url.path, "image.sfs", &h, &r) == SFS_OK, "namespace reopen")
    let bytes = Data(name.utf8), status = bytes.withUnsafeBytes { sfs_image_lookup(h, 0, parent, $0.baseAddress, $0.count, &entry, &r) }
    if let inode { need(status == SFS_OK && entry.inode == inode && Data(rawBytes(entry.name).prefix(entry.name_length)) == bytes, "reopened acknowledged alias") }
    else { need(status == SFS_NOT_FOUND, "reopened refused alias absent") }
    need(sfs_image_close(h, &r) == SFS_OK, "namespace reopen close")
}
func contextualLinks(_ parent: URL) throws {
    let required = FSCreateLinkResult.requestedAttributes.wantedAttributes
#if STALLION_RESULT_MASK_TRACE
    let raw = UInt(bitPattern: required.rawValue)
    resultMaskTrace("FSCreateLinkResult original=0x\(String(raw, radix: 16)) outside_caller_readable=0x\(String(raw & ~UInt(0x3fff), radix: 16)) explicit=0x0")
#endif
    let caller = CallerIdentity(uid: Int(geteuid()), gid: Int(getegid()))
    // Same-parent and cross-parent links share existing items even at the item cap.
    for cross in [false, true] {
        let f = try Fixture(parent, "namespace-success-\(cross)", mode: 0o400, directory: cross)
        let m = try Mounted(f, itemLimit: cross ? 4 : 3), v = m.volume
        let destination = cross ? namespaceLookup(m, "dir") : m.root
        let aliasName = cross ? String(repeating: "n", count: 255) : "Hard-Link-Ω"
        if cross { need(code(namespaceLink(m,destination).1) == Int(ENOTSUP), "nonroot directory link refusal") }
        var snapshots: [FSItem.Attributes] = [], commitStarted = false
        m.serial {
            v.preparedAttributesForTesting = { name, value in
                if name == "FSCreateLinkResult" { need(!commitStarted, "both role snapshots precommit"); snapshots.append(value) }
            }
            v.rejectResultForTesting = { name in if name == "FSCreateLinkResult" { need(snapshots.count == 2 && !commitStarted, "real link constructor precommit") }; return false }
            v.diagnosticBeforeCommit = { commitStarted = true }
            try! v.linkAccessForTesting(destination, access: [.addFile, .search], caller: caller)
            let refused: [FSVolume.AccessMask] = [.addSubdirectory, .delete, [.addFile, .delete]]
            for access in refused {
                do { try v.linkAccessForTesting(destination, access: access, caller: caller); need(false, "link policy granted unrelated mutation") }
                catch { need(code(error) == Int(EACCES), "other access bits remain refused") }
            }
        }
        let originalPin = (m.file as! StallionItem).pin!, retainedTrace = v.diagnosticSnapshot().1
        let result = namespaceLink(m, name: Data(aliasName.utf8), directory: destination)
        need(result.0 != nil && result.1 == nil && snapshots.count == 2 && commitStarted, "actual link result success")
        let linkedMetadata = namespaceMetadata(m, m.file), parentMetadata = namespaceMetadata(m, destination)
        checkPreparedAttributes(snapshots[0], linkedMetadata, required: required)
        checkPreparedAttributes(snapshots[1], parentMetadata, required: required)
        need(linkedMetadata.link_count == 3 && namespaceLookup(m, aliasName, directory: destination) === m.file,
             "hardlink preserves canonical identity at capacity")
        need(sameBytes(originalPin, (m.file as! StallionItem).pin!), "link preserves source token")
        let originalSnapshots = snapshots
        m.serial { v.preparedAttributesForTesting = nil; v.rejectResultForTesting = nil; v.diagnosticBeforeCommit = nil }
        need(namespaceLink(m, m.link, name: Data("symbolic-alias".utf8), directory: destination).1 == nil,
             "symlink hardlink without target traversal")
        need(namespaceLookup(m, "symbolic-alias", directory: destination) === m.link, "symlink canonical alias")
        need(namespaceLink(m,name:Data("later-alias".utf8),directory:destination).1 == nil && namespaceMetadata(m,m.file).link_count == 4,
             "later link changes real source metadata")
        checkPreparedAttributes(originalSnapshots[0], linkedMetadata, required: required)
        checkPreparedAttributes(originalSnapshots[1], parentMetadata, required: required)
        need(retainedTrace.count <= v.diagnosticSnapshot().1.count, "retained trace remains independent")
        let target: (FSFileName?, Error?) = wait { done in v.readSymbolicLink(m.link) { done(($0,$1)) } }
        need(target.1 == nil && target.0?.data == Data("file".utf8), "hardlinked symlink contents")
        let xattr: (Data?, Error?) = wait { done in v.getXattr(named: FSFileName(string: "note"), of: m.file) { done(($0,$1)) } }
        need(xattr.1 == nil && xattr.0 == Data("value".utf8), "hardlink preserves opaque xattrs")
        let parentID = (destination as! StallionItem).inode, symlinkID = (m.link as! StallionItem).inode
        if cross { let e: Error? = wait { v.reclaimForTesting(destination, eligible: true, replyHandler: $0) }; need(e == nil, "release retained test directory") }
        m.close(); namespaceReopened(f, aliasName, parent: parentID, inode: f.id)
        namespaceReopened(f, "symbolic-alias", parent: parentID, inode: symlinkID)
        namespaceReopened(f, "later-alias", parent: parentID, inode: f.id)
        need(f.contents() == Data("original".utf8), "readonly-mode source data unchanged")
    }
    let invalid = try Fixture(parent, "namespace-preflight", extra: true), m = try Mounted(invalid), v = m.volume
    var staged = false
    m.serial { v.diagnosticBeforePrepare = { staged = true } }
    let before = v.anchor
    for (bytes, expected) in [(Data(), EINVAL), (Data([0]), EINVAL), (Data("a/b".utf8), EINVAL),
                              (Data(".".utf8), EINVAL), (Data("..".utf8), EINVAL), (Data(repeating: 97, count: 256), ENAMETOOLONG),
                              (Data("alias".utf8), EEXIST)] {
        need(code(namespaceLink(m, name: bytes).1) == Int(expected), "precise component/duplicate refusal")
    }
    need(code(namespaceLink(m, m.root).1) == Int(ENOTSUP), "root hardlink refusal")
    need(code(namespaceLink(m, directory: m.file).1) == Int(ENOTDIR), "non-directory destination refusal")
    need(code(namespaceLink(m, StallionItem(invalid.id)).1) == Int(EINVAL), "foreign item identity refusal")
    need(code(namespaceLink(m, directory: StallionItem(1)).1) == Int(EINVAL), "foreign directory identity refusal")
    let stale = namespaceLookup(m, "extra")
    let reclaimed: Error? = wait { v.reclaimForTesting(stale, eligible: true, replyHandler: $0) }; need(reclaimed == nil, "stale operand setup")
    need(code(namespaceLink(m, stale).1) == Int(EINVAL), "reclaimed operand refusal")
    for identity in [CallerIdentity(uid: caller.uid + 1, gid: caller.gid), CallerIdentity(uid: -1, gid: caller.gid), CallerIdentity(uid: caller.uid, gid: -1)] {
        need(code(namespaceLink(m, caller: identity).1) == Int(EACCES), "foreign or unrepresentable caller refusal")
    }
    if geteuid() != 0 { need(code(namespaceLink(m, caller: CallerIdentity(uid: 0, gid: 0)).1) == Int(EACCES), "root is not owner bypass") }
    for count in [UInt64(UInt32.max), UInt64.max] {
        do { try checkLinkCount(count); need(false, "link limit accepted") } catch { need(code(error) == Int(EMLINK), "pure link limit") }
    }
    try checkLinkCount(UInt64(UInt32.max) - 1)
    var pureParent = namespaceMetadata(m,m.root); pureParent.flags = UInt32.max
    do { try checkLinkParentPolicy(pureParent,owner:geteuid(),caller:caller); need(false,"pure unknown flags granted") }
    catch { need(code(error) == Int(ENOTSUP),"pure policy input flags refused; not an image format case") }
    need(!staged && anchorMatches(v.anchor, before) && v.diagnosticSnapshot().0.commits == 0, "preflight before transaction")
    namespaceAbsent(m); m.close()
    // Representable creation flags and real ACL/mode metadata, not invented flags.
    for index in 0..<9 {
        let f = try Fixture(parent, "namespace-policy-\(index)", mode: index == 4 ? 0o6600 : 0o600, acl: index == 2,
            owner: index == 8 ? geteuid() + 1 : geteuid(), sourceFlags: index == 0 ? 1 : 0, rootFlags: index == 1 ? 0x8000 : 0,
            rootMode: index == 5 ? 0o500 : index == 6 ? 0o600 : index == 7 ? 0o1700 : 0o700, rootACL: index == 3)
        let m = try Mounted(f), v = m.volume, before = v.anchor
        var prepared = false
        m.serial { v.diagnosticBeforePrepare = { prepared = true } }
        let expected = index < 4 ? ENOTSUP : EACCES
        need(code(namespaceLink(m).1) == Int(expected) && !prepared && anchorMatches(v.anchor, before), "real namespace policy refusal")
        if [1,3,5,6,7].contains(index) {
            m.serial {
                do { try v.linkAccessForTesting(m.root, access: .addFile, caller: caller); need(false, "private addFile bypass") }
                catch { need(code(error) == Int(expected), "same parent policy in access check") }
            }
        }
        namespaceAbsent(m); m.close(); namespaceReopened(f, "new-name", inode: nil)
    }
    // The alias cannot resurrect a detached source retained by a live pin.
    let detachedFixture = try Fixture(parent, "namespace-detached"), detached = try Mounted(detachedFixture)
    detached.serial { try! detached.volume.diagnosticMutationForTesting { h,r in
        need(sfs_image_unlink_expected(h, 1, "file", 4, detachedFixture.id, &r) == SFS_OK, "detach first name")
        need(sfs_image_unlink_expected(h, 1, "alias", 5, detachedFixture.id, &r) == SFS_OK, "detach final name")
    } }
    let detachedAnchor = detached.volume.anchor
    need(code(namespaceLink(detached).1) == Int(ENOENT) && anchorMatches(detached.volume.anchor, detachedAnchor), "detached source refused")
    namespaceAbsent(detached); detached.close()
    let roFixture = try Fixture(parent, "namespace-readonly"), ro = try Mounted(roFixture, writable: false)
    need(code(namespaceLink(ro).1) == Int(EROFS), "no UUID/write authority refuses link"); ro.close()
    let revokedFixture = try Fixture(parent,"namespace-revoked"), revoked = try Mounted(revokedFixture), revokedAnchor = revoked.volume.anchor
    revoked.resource.revoke()
    need(code(namespaceLink(revoked).1) == Int(EACCES) && anchorMatches(revoked.volume.anchor,revokedAnchor),"revoked link preflight refusal")
    revoked.close(); namespaceReopened(revokedFixture,"new-name",inode:nil)
    try namespaceResultFailures(parent, required: required)
    try namespaceDeliveryGates(parent)
}

func namespaceResultFailures(_ parent: URL, required: FSItem.Attribute) throws {
    // Each metadata role fails the production completeness check independently.
    need(!required.isEmpty, "actual link result has completeness requirements")
    for rejectedRole in 0..<2 {
        let f = try Fixture(parent, "namespace-incomplete-\(rejectedRole)"), m = try Mounted(f), v = m.volume, before = v.anchor
        var role = 0, constructed = false
        let sourcePin = (m.file as! StallionItem).pin!, parentPin = (m.root as! StallionItem).pin!
        m.serial {
            v.preparedAttributesForTesting = { name,a in if name == "FSCreateLinkResult" {
                if role == rejectedRole { a.invalidateAllProperties() }; role += 1
            } }
            v.rejectResultForTesting = { _ in constructed = true; return false }
        }
        let result = namespaceLink(m)
        need(result.0 == nil && code(result.1) == Int(ENOTSUP) && !constructed && role == rejectedRole + 1,
             "individual role completeness before constructor")
        need(anchorMatches(v.anchor,before) && v.diagnosticSnapshot().0.commits == 0 &&
             sameBytes(sourcePin,(m.file as! StallionItem).pin!) && sameBytes(parentPin,(m.root as! StallionItem).pin!), "incomplete link rollback and tokens")
        namespaceAbsent(m); m.close(); namespaceReopened(f,"new-name",inode:nil)
    }
    for mode in 0..<4 {
        let f = try Fixture(parent,"namespace-prepare-\(mode)"), m = try Mounted(f), v = m.volume, before = v.anchor
        var reached = false
        m.serial {
            if mode < 2 { v.rejectResultForTesting = { name in
                if name == "FSCreateLinkResult" { reached = true; if mode == 1 { m.resource.revoke() }; return mode == 0 }; return false
            } }
            else if mode == 2 { v.diagnosticBeforeCommit = { sfs_image_clear_read_cache(m.coreHandle); fault(7,1) } }
        }
        if mode == 3 { fault(1,1) }
        let result = namespaceLink(m)
        let expected = mode == 0 ? EIO : mode == 1 ? EACCES : mode == 2 ? ENOMEM : ENOSPC
        need(result.0 == nil && code(result.1) == Int(expected) && (mode >= 2 || reached) && anchorMatches(v.anchor,before), "prepared result/resource/allocation/append refusal")
        if mode >= 2 { need(hits() > 0, "real core fault reached") }
        fault(0,0)
        if mode < 3 { namespaceAbsent(m) }
        m.close(); namespaceReopened(f,"new-name",inode:nil)
    }
    // Real append-capacity exhaustion; at most 32 links in a 32-cell image.
    let capacityFixture = try Fixture(parent,"namespace-capacity",capacity:128 * 1024), capacityMount = try Mounted(capacityFixture)
    var acknowledged: [String] = [], exhausted = false
    for index in 0..<32 {
        let name = "capacity-\(index)", before = capacityMount.volume.anchor
        let result = namespaceLink(capacityMount,name:Data(name.utf8))
        if let error = result.1 {
            let first = capacityMount.volume.diagnosticSnapshot().2!
            need(result.0 == nil && code(error) == Int(ENOSPC) && first.result.status == SFS_LIMIT &&
                 first.result.limit_reason == SFS_LIMIT_APPEND_CAPACITY && anchorMatches(capacityMount.volume.anchor,before),
                 "real append capacity refusal retains last acknowledged anchor")
            namespaceAbsent(capacityMount,name); exhausted = true; break
        }
        need(result.0 != nil,"capacity case acknowledged result"); acknowledged.append(name)
    }
    need(exhausted,"bounded image reaches append capacity")
    capacityMount.close()
    for name in acknowledged { namespaceReopened(capacityFixture,name,inode:capacityFixture.id) }
    namespaceReopened(capacityFixture,"capacity-\(acknowledged.count)",inode:nil)
    for fence in [Int32(1), Int32(2)] {
        let f = try Fixture(parent,"namespace-fence-\(fence)"), m = try Mounted(f), v = m.volume, before = v.anchor
        fault(4,fence); let result = namespaceLink(m)
        need(result.0 == nil && code(result.1) == Int(ENOSPC) && hits() > 0, "namespace fence error")
        let failure = v.diagnosticSnapshot().2!
        need(failure.result.status == (fence == 1 ? SFS_IO : SFS_OUTCOME_UNKNOWN) &&
             failure.result.phase == (fence == 1 ? SFS_PHASE_RECORD_BARRIER : SFS_PHASE_COMMIT_BARRIER) &&
             failure.result.poisoned != 0 && anchorMatches(v.anchor,before), "primary fence disposition retained")
        fault(0,0); need(code(namespaceLink(m).1) == Int(ENOSPC), "sticky fence error")
        m.close()
        if fence == 1 { namespaceReopened(f,"new-name",inode:nil) }
        // Unknown publication is deliberately not described as a rolled-back alias.
    }
}

func namespaceDeliveryGates(_ parent: URL) throws {
    let f = try Fixture(parent,"namespace-queued"), m = try Mounted(f), v = m.volume, before = v.anchor
    let held = DispatchSemaphore(value:0), release = DispatchSemaphore(value:0), replies = DispatchGroup()
    var preflight = 0, cleared = false
    v.enqueue {
        v.diagnosticBeforePrepare = { throw POSIXError(.ENOMEM) }
        v.linkPreflightForTesting = { preflight += 1 }
        held.signal(); need(release.wait(timeout:.now()+20) == .success,"release namespace queue")
    }
    need(held.wait(timeout:.now()+20) == .success,"hold namespace queue")
    replies.enter(); v.writeCountForTesting(contents:Data([1]),to:m.file,at:0) { count,error in
        need(count == 0 && code(error) == Int(ENOMEM),"preceding preparation error")
        v.diagnosticBeforePrepare = nil; cleared = true; replies.leave()
    }
    let bytes = Data("queued-name".utf8), caller = CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))
    replies.enter(); v.linkResultForTesting(m.file,name:FSFileName(data:bytes),directory:m.root,caller:caller) { result,error in
        need(cleared && result == nil && code(error) == Int(ENOMEM),"queued link returns first error after injection cleared"); replies.leave()
    }
    let charged = v.linkBudgetForTesting
    need(charged.0 == 2 && charged.1 == 2 * ReadOnlyLimits.callbackOverhead + 1 + bytes.count,"both callbacks charged before first failure")
    need(v.diagnosticSnapshot().0.callbacks == 1 && v.diagnosticSnapshot().0.resizes == 0,"namespace is not data/resize")
    release.signal(); need(replies.wait(timeout:.now()+20) == .success,"queued namespace callbacks finish")
    m.serial { need(preflight == 0,"queued error checked before namespace preflight") }
    let admissionHeld = DispatchSemaphore(value:0), admissionRelease = DispatchSemaphore(value:0)
    v.enqueue { admissionHeld.signal(); need(admissionRelease.wait(timeout:.now()+20) == .success,"release already-failed queue") }
    need(admissionHeld.wait(timeout:.now()+20) == .success,"hold queue for admission refusal")
    need(code(namespaceLink(m).1) == Int(ENOMEM),"already-latched error replies without entering held queue")
    let afterRefusal = v.linkBudgetForTesting
    need(afterRefusal.0 == 0 && afterRefusal.1 == 0,"admission returns any acquired name-byte ticket")
    admissionRelease.signal()
    m.serial { need(preflight == 0,"no namespace preflight after admission refusal") }
    need(anchorMatches(v.anchor,before) && v.diagnosticSnapshot().0.commits == 0,"no later preflight or commit")
    namespaceAbsent(m,"queued-name"); namespaceAbsent(m); m.close()
    namespaceReopened(f,"queued-name",inode:nil); need(f.contents() == Data("original".utf8),"queued failure reopened bytes")
    let fullFixture = try Fixture(parent,"namespace-saturation"), full = try Mounted(fullFixture)
    let entered = DispatchSemaphore(value:0), resume = DispatchSemaphore(value:0), drained = DispatchGroup()
    full.volume.enqueue { entered.signal(); need(resume.wait(timeout:.now()+20) == .success,"release full namespace queue") }
    need(entered.wait(timeout:.now()+20) == .success,"hold full namespace queue")
    for _ in 0..<ReadOnlyLimits.callbacks {
        drained.enter(); full.volume.enqueue(retainedBytes:0,rejected:{ _ in need(false,"fill namespace callback budget") }) { drained.leave() }
    }
    let chargedBefore = full.volume.linkBudgetForTesting
    need(code(namespaceLink(full).1) == Int(EAGAIN),"namespace callback saturation refusal")
    let chargedAfter = full.volume.linkBudgetForTesting
    need(chargedBefore.0 == chargedAfter.0 && chargedBefore.1 == chargedAfter.1 && full.volume.diagnosticSnapshot().0.callbacks == 0,
         "saturation adds no ticket or data counter")
    resume.signal(); need(drained.wait(timeout:.now()+20) == .success,"drain namespace budget")
    namespaceAbsent(full); full.close(); namespaceReopened(fullFixture,"new-name",inode:nil)
}
#endif

@main struct Driver {
    static func main() throws {
        need(CommandLine.arguments.count == 2, "owned empty parent required")
        let parent = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
#if STALLION_CONTEXT_HANDLERS
        try contextualPolicyValues(); try contextualResults(parent); try rejectedHandlerResults(parent); try queuedResizeAfterIncompleteSnapshot(parent); try contextualLinks(parent)
#endif
        try successfulWrites(parent); let unavailable = try attributes(parent)
        try failures(parent); try admission(parent); try lifetimeAndBinding(parent)
        try queuedResizeAfterDeliveryFailure(parent)
        try retainedTraceSnapshot(parent); try preparedReplyFailure(parent); try detachedTokenRoutes(parent)
        try pinOwnershipLimits(parent); try reclaimErrorAndRoot(parent)
        for (index, spec) in [(UInt32(0o400), false, geteuid()), (UInt32(0o6600), false, geteuid()), (UInt32(0o600), true, geteuid()), (UInt32(0o600), false, geteuid() + 1)].enumerated() {
            let f = try Fixture(parent, "access-\(index)", mode: spec.0, acl: spec.1, owner: spec.2), m = try Mounted(f)
            need(code(m.write(Data([1])).1) == Int(spec.1 ? ENOTSUP : EACCES), "owner-mode/setid/ACL write refusal")
            m.close(); need(f.contents() == Data("original".utf8), "denied image unchanged")
        }
        print("PASS existing-file diagnostic real-core writes, attributes, failures and admission")
        print("UNQUALIFIED installed default-cache routing and syscall error propagation")
        print("SDK unconstructible capability request fields: \(unavailable.map(String.init).joined(separator: ","))")
#if STALLION_CONTEXT_HANDLERS && STALLION_RESULT_MASK_TRACE
        print("PASS contextual hardlinks, two-role results, refusal, rollback and queued delivery gates")
#endif
    }
}
