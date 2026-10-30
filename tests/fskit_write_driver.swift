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
    init(_ parent: URL, _ name: String, mode: UInt32 = 0o600, acl: Bool = false, owner: uid_t = geteuid()) throws {
        fault(0, 0); url = parent.appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        var h: OpaquePointer?, r = sfs_result(), m = sfs_metadata_initial(), inode: UInt64 = 0
        m.mode = UInt32(S_IFDIR) | 0o700; m.uid = geteuid(); m.gid = getegid()
        need(sfs_image_create_metadata_version(url.path, "image.sfs", 16 * 1024 * 1024, 6, &m, &h, &r) == SFS_OK, "create disposable")
        need(sfs_image_begin(h, &r) == SFS_OK, "begin producer")
        m.mode = UInt32(S_IFREG) | mode; m.uid = owner
        need(sfs_image_add_metadata(h, 1, "file", 4, SFS_FILE, &m, &inode, &r) == SFS_OK, "create regular")
        let fileID = inode; id = fileID
        need(sfs_image_link(h, inode, 1, "alias", 5, &r) == SFS_OK, "create alias")
        m.mode = UInt32(S_IFLNK) | 0o700; m.uid = geteuid()
        need(sfs_image_symlink_metadata(h, 1, "link", 4, "file", 4, &m, &inode, &r) == SFS_OK, "create symlink")
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
    init(_ fixture: Fixture, writable: Bool = true) throws {
        fault(0, 0); var h: OpaquePointer?, r = sfs_result()
        let opened = writable ? sfs_image_open(fixture.url.path, "image.sfs", &h, &r) : sfs_image_open_readonly(fixture.url.path, "image.sfs", &h, &r)
        need(opened == SFS_OK, "open adapter")
        volume = StallionVolume(handle: h!, resource: FSPathURLResource(url: fixture.url, writable: writable), scope: false, anchor: r, queue: DispatchQueue(label: "sfs.write.test"))
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
        wait { done in volume.write(contents: data, to: alias ? self.alias : file, at: offset) { done(($0, $1)) } }
    }
    func set(_ request: FSItem.SetAttributesRequest, item: FSItem? = nil) -> (FSItem.Attributes?, Error?) {
        wait { done in volume.setAttributes(request, on: item ?? file) { done(($0, $1)) } }
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
        let _: Bool = wait { done in volume.enqueue { _ = self.volume.unload(); done(true) } }
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
    let m = try Mounted(f), before = m.volume.anchor.generation
    for item in [m.root, m.link] {
        let a = FSItem.SetAttributesRequest(); a.size = UInt64.max
        need(m.set(a, item: item).1 == nil && a.consumedAttributes.isEmpty, "nonregular size ignored")
    }
    need(m.set(FSItem.SetAttributesRequest()).1 == nil && m.volume.anchor.generation == before, "empty checked no-op")
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
            if atCommit { m.volume.diagnosticBeforeCommit = { fault(7,1) } }
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
    need(result.0 == nil && code(result.1) == Int(EIO) && a.consumedAttributes == [.size] && m.volume.anchor.generation == before + 1, "postcommit fetch failure remains committed")
    m.close(); need(f.contents().count == 70, "postcommit failure does not undo resize")
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
    v.write(contents: Data([1]), to: m.file, at: 0) { count, error in
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
            racing.volume.write(contents: Data([1]), to: racing.file, at: offset) { count, error in
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
    v.write(contents: Data("durable!".utf8), to: m.file, at: 0) { count, error in
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

@main struct Driver {
    static func main() throws {
        need(CommandLine.arguments.count == 2, "owned empty parent required")
        let parent = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try successfulWrites(parent); let unavailable = try attributes(parent)
        try failures(parent); try admission(parent); try lifetimeAndBinding(parent)
        for (index, spec) in [(UInt32(0o400), false, geteuid()), (UInt32(0o6600), false, geteuid()), (UInt32(0o600), true, geteuid()), (UInt32(0o600), false, geteuid() + 1)].enumerated() {
            let f = try Fixture(parent, "access-\(index)", mode: spec.0, acl: spec.1, owner: spec.2), m = try Mounted(f)
            need(code(m.write(Data([1])).1) == Int(spec.1 ? ENOTSUP : EACCES), "owner-mode/setid/ACL write refusal")
            m.close(); need(f.contents() == Data("original".utf8), "denied image unchanged")
        }
        print("PASS existing-file diagnostic real-core writes, attributes, failures and admission")
        print("UNQUALIFIED installed default-cache routing and syscall error propagation")
        print("SDK unconstructible capability request fields: \(unavailable.map(String.init).joined(separator: ","))")
    }
}
