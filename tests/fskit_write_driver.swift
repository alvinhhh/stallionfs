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
    init(_ parent: URL, _ name: String, mode: UInt32 = 0o600, acl: Bool = false, owner: uid_t = geteuid(), extra: Bool = false) throws {
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
        need(sfs_image_set_xattr(h, fileID, "note", 4, "value", 5, &r) == SFS_OK, "regular opaque xattr")
        if extra { need(sfs_image_add_metadata(h, 1, "extra", 5, SFS_FILE, &m, &inode, &r) == SFS_OK, "extra capacity operand") }
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
    let coreHandle: OpaquePointer
    init(_ fixture: Fixture, writable: Bool = true, itemLimit: Int = ReadOnlyLimits.activeItems) throws {
        fault(0, 0); var h: OpaquePointer?, r = sfs_result()
        let opened = writable ? sfs_image_open(fixture.url.path, "image.sfs", &h, &r) : sfs_image_open_readonly(fixture.url.path, "image.sfs", &h, &r)
        need(opened == SFS_OK, "open adapter")
        coreHandle = h!
        volume = StallionVolume(handle: h!, resource: FSPathURLResource(url: fixture.url, writable: writable), scope: false, anchor: r, queue: DispatchQueue(label: "sfs.write.test"), itemLimit: itemLimit)
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
    need(m.write(Data("detached".utf8), alias: true).1 == nil, "detached write through alias")
    let resized = m.size(11); need(resized.1 == nil && resized.0?.size == 11, "detached precommit size reply")
    m.serial { need(try! v.diagnosticReadForTesting(m.file, length: 64) == Data("detached".utf8) + Data(repeating: 0, count: 3), "detached resize/read bytes") }
    for name in ["file", "alias", "link"] {
        let missing: (FSItem?, Error?) = wait { done in v.lookupItem(named: FSFileName(string: name), inDirectory: m.root) { done(($0,$2)) } }
        need(missing.0 == nil && code(missing.1) == Int(ENOENT), "no namespace resurrection")
    }
    let refused: Error? = wait { v.removeItem(m.file, named: FSFileName(string: "file"), fromDirectory: m.root, replyHandler: $0) }
    let xattrRefused: Error? = wait { v.setXattr(named: FSFileName(string: "note"), to: Data(), on: m.file, policy: .alwaysSet, replyHandler: $0) }
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

@main struct Driver {
    static func main() throws {
        need(CommandLine.arguments.count == 2, "owned empty parent required")
        let parent = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try successfulWrites(parent); let unavailable = try attributes(parent)
        try failures(parent); try admission(parent); try lifetimeAndBinding(parent)
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
    }
}
