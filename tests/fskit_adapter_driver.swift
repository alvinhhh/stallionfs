import Foundation
@preconcurrency import FSKit
import SFSImage
import Darwin

@_silgen_name("sfs_hooks_reset") func hooksReset()
@_silgen_name("sfs_hooks_reads") func hooksReads() -> UInt64
@_silgen_name("sfs_hooks_writes") func hooksWrites() -> UInt64
@_silgen_name("sfs_hooks_closes") func hooksCloses() -> UInt64
@_silgen_name("sfs_hooks_fail_close") func hooksFailClose()
@_silgen_name("sfs_hooks_fail_read") func hooksFailRead()
@_silgen_name("sfs_hooks_fixture_writes") func hooksFixtureWrites(_ allowed: Int32)

func need(_ ok: @autoclosure () -> Bool, _ label: String) {
    guard ok() else { fatalError(label) }
}
func wait<T>(_ call: (@escaping (T) -> Void) -> Void) -> T {
    let done = DispatchSemaphore(value: 0)
    var result: T?
    call { result = $0; done.signal() }
    need(done.wait(timeout: .now() + 10) == .success, "callback timeout")
    return result!
}
func code(_ error: Error?) -> Int { (error as NSError?)?.code ?? 0 }
// Historical fixture assertions are test inputs, never production admission.
func anchorMatches(_ result: sfs_result) -> Bool {
    rawBytes(result.uuid) == FixtureIdentity.uuid && result.generation == FixtureIdentity.generation &&
    rawBytes(result.root_digest) == FixtureIdentity.digest
}
// Direct source regression schedules; no OS mount or SDK routing is involved.
func unmountOrderingChecks(_ volume: StallionVolume, root: FSItem) {
    func remount() {
        let error: Error? = wait { volume.mount(arguments: [], replyHandler: $0) }
        need(error == nil, "lifecycle regression remount")
    }
    let attributes = FSItem.GetAttributesRequest(); attributes.wantedAttributes = [.fileID]
    let finished = DispatchGroup()
    var operationReplied = false, queuedReplied = false, unmountReplies = 0
    let lifecycleCount = ReadOnlyLimits.callbacks + 1
    for _ in 0..<lifecycleCount { finished.enter() }
    let first: (FSDirectoryVerifier, Error?) = wait { done in
        volume.enumerateDirectory(root, startingAt: .initial, verifier: .initial, attributes: attributes,
            pack: { _, _, _, _, _ in
                // This mounted callback is admitted before either unmount.
                volume.enumerateDirectory(root, startingAt: .initial, verifier: .initial, attributes: attributes,
                    pack: { _, _, _, _, _ in false }) { _, error in
                        need(error == nil, "accepted mounted callback completes before drain")
                        queuedReplied = true
                    }
                for _ in 0..<lifecycleCount {
                    volume.unmount {
                        need(operationReplied && queuedReplied, "no unmount acknowledgement inside unfinished pack or before accepted work")
                        unmountReplies += 1; finished.leave()
                    }
                }
                need(unmountReplies == 0, "packer reentry defers every lifecycle reply")
                return false
            }) { verifier, error in
                operationReplied = true; done((verifier, error))
            }
    }
    need(first.1 == nil && finished.wait(timeout: .now() + 10) == .success, "packer reentry drains")
    let _: Bool = wait { done in volume.enqueue { need(unmountReplies == lifecycleCount, "more than ordinary budget lifecycle exact replies"); done(true) } }
    let closedAdmission: (FSItem.Attributes?, Error?) = wait { done in volume.getAttributes(attributes, of: root) { done(($0, $1)) } }
    need(closedAdmission.0 == nil && code(closedAdmission.1) == Int(ENXIO), "ordinary admission stays closed after unmount")
    let sync: Error? = wait { volume.synchronize(flags: .wait, replyHandler: $0) }
    let reclaim: Error? = wait { volume.reclaimItem(root, replyHandler: $0) }
    need(sync == nil && reclaim == nil, "bounded sync and reclaim remain usable after unmount")
    remount()

    let held = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), drained = DispatchSemaphore(value: 0)
    volume.enqueue { held.signal(); release.wait() }
    need(held.wait(timeout: .now() + 10) == .success, "lifecycle saturation queue held")
    var acceptedReplies = 0, lifecycleReply = false
    volume.getAttributes(attributes, of: root) { _, error in
        need(error == nil, "reply reentry operation completed")
        acceptedReplies += 1
        volume.unmount {
            need(acceptedReplies == ReadOnlyLimits.callbacks, "saturated accepted callbacks all precede drain")
            lifecycleReply = true; drained.signal()
        }
        need(!lifecycleReply, "reply reentry never acknowledges inline")
    }
    for _ in 1..<ReadOnlyLimits.callbacks {
        volume.getAttributes(attributes, of: root) { _, error in
            need(error == nil, "pre-drain accepted callback remains admitted"); acceptedReplies += 1
        }
    }
    var overflowReplies = 0
    volume.getAttributes(attributes, of: root) { _, error in
        need(code(error) == Int(EAGAIN), "ordinary budget saturation remains bounded"); overflowReplies += 1
    }
    need(overflowReplies == 1, "saturation rejected before queue submission")
    release.signal(); need(drained.wait(timeout: .now() + 10) == .success, "lifecycle barrier bypasses saturated ordinary budget")
    let _: Bool = wait { done in volume.enqueue { need(overflowReplies == 1, "no delayed overflow duplicate"); done(true) } }
    remount()

    let offQueueHeld = DispatchSemaphore(value: 0), offQueueRelease = DispatchSemaphore(value: 0)
    let pendingReplied = DispatchSemaphore(value: 0), unmountStarted = DispatchSemaphore(value: 0)
    let offQueueDone = DispatchSemaphore(value: 0)
    volume.enqueue { offQueueHeld.signal(); offQueueRelease.wait() }
    need(offQueueHeld.wait(timeout: .now() + 10) == .success, "offqueue drain held")
    volume.enumerateDirectory(root, startingAt: .initial, verifier: .initial, attributes: attributes,
        pack: { _, _, _, _, _ in false }) { _, error in
            need(error == nil, "offqueue accepted mounted callback finishes"); pendingReplied.signal()
        }
    DispatchQueue(label: "sfs.offqueue.unmount").async(execute: DispatchWorkItem {
        unmountStarted.signal()
        volume.unmount {
            need(pendingReplied.wait(timeout: .now()) == .success, "offqueue unmount replies after accepted work")
            offQueueDone.signal()
        }
    })
    need(unmountStarted.wait(timeout: .now() + 10) == .success, "offqueue unmount started")
    need(offQueueDone.wait(timeout: .now()) == .timedOut, "offqueue unmount cannot reply past held operation")
    offQueueRelease.signal(); need(offQueueDone.wait(timeout: .now() + 10) == .success, "offqueue drain completes")
    remount()

    let crossing = DispatchGroup(); crossing.enter(); crossing.enter()
    let entered: Bool = wait { done in volume.getAttributes(attributes, of: root) { _, error in
        need(error == nil, "crossing callback admitted")
        volume.mount(arguments: []) { error in
            need(code(error) == Int(EBUSY), "older queued mount cannot reopen past newer unmount"); crossing.leave()
        }
        volume.unmount { crossing.leave() }
        let busy = volume.unload()
        need(!busy.consumed && code(busy.error) == Int(EBUSY), "inline unload cannot consume a pending drain or callback")
        volume.getAttributes(attributes, of: root) { value, error in
            need(value == nil && code(error) == Int(EAGAIN), "cutoff refuses new ordinary work before queue submission")
        }
        done(true)
    } }
    need(entered && crossing.wait(timeout: .now() + 10) == .success, "mount/unload crossing drains")
    remount()

    // Concurrent submitters race the same admission lock as unmount. Every
    // accepted mounted callback must finish before acknowledgement; others fail
    // before scheduling. No timing-based assumption selects a winning thread.
    let raceHeld = DispatchSemaphore(value: 0), raceRelease = DispatchSemaphore(value: 0)
    volume.enqueue { raceHeld.signal(); raceRelease.wait() }
    need(raceHeld.wait(timeout: .now() + 10) == .success, "admission race held")
    let submitters = DispatchGroup(), replies = DispatchGroup(), start = DispatchSemaphore(value: 0), raceLock = NSLock()
    var acknowledged = false, replyCount = 0
    for _ in 0..<4 {
        submitters.enter()
        DispatchQueue(label: "sfs.admission.race").async(execute: DispatchWorkItem {
            start.wait()
            for _ in 0..<16 {
                replies.enter()
                volume.enumerateDirectory(root, startingAt: .initial, verifier: .initial, attributes: attributes,
                    pack: { _, _, _, _, _ in false }) { _, error in
                        raceLock.lock()
                        if error == nil { need(!acknowledged, "accepted race callback precedes unmount acknowledgement") }
                        else { need([Int(EAGAIN), Int(ENXIO)].contains(code(error)), "race refusal is an admission error") }
                        replyCount += 1; raceLock.unlock(); replies.leave()
                    }
            }
            submitters.leave()
        })
    }
    for _ in 0..<4 { start.signal() }
    let raceUnmount = DispatchSemaphore(value: 0)
    volume.unmount { raceLock.lock(); acknowledged = true; raceLock.unlock(); raceUnmount.signal() }
    raceRelease.signal()
    need(submitters.wait(timeout: .now() + 10) == .success && replies.wait(timeout: .now() + 10) == .success &&
         raceUnmount.wait(timeout: .now() + 10) == .success, "admission race completes")
    need(replyCount == 64, "admission race replies exactly once")
    remount()
}

func resourceUnloadChecks(_ url: URL) {
    let owner = StallionFileSystem(), path = FSPathURLResource(url: url, writable: false)
    let loaded: (FSVolume?, Error?) = wait { done in owner.loadResource(resource: path, force: false) { done(($0, $1)) } }
    need(loaded.1 == nil && loaded.0 is StallionVolume, "resource owner loads real image")
    let volume = loaded.0 as! StallionVolume
    let root: (FSItem?, Error?) = wait { done in volume.activate { done(($0, $1)) } }
    let mounted: Error? = wait { volume.mount(arguments: [], replyHandler: $0) }
    need(root.0 != nil && root.1 == nil && mounted == nil, "owned resource mounted helper")
    let request = FSItem.GetAttributesRequest(); request.wantedAttributes = [.fileID]
    hooksReset()
    let busyInReply: Bool = wait { done in volume.getAttributes(request, of: root.0!) { _, error in
        let result = volume.unload()
        need(error == nil && !result.consumed && code(result.error) == Int(EBUSY) && hooksCloses() == 0,
             "callback budget alone makes unload nonconsuming")
        done(true)
    } }
    need(busyInReply, "resource retained inside reply")
    let held = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), busyReply = DispatchSemaphore(value: 0)
    let ordinaryReply = DispatchSemaphore(value: 0), unmounted = DispatchSemaphore(value: 0)
    volume.enqueue { held.signal(); release.wait() }
    need(held.wait(timeout: .now() + 10) == .success, "owned queue held")
    owner.unloadResource(resource: path) { error in
        need(code(error) == Int(EBUSY) && hooksCloses() == 0, "owner busy unload retains handle and scope")
        busyReply.signal()
    }
    volume.getAttributes(request, of: root.0!) { _, error in need(error == nil, "accepted owned work survives busy unload"); ordinaryReply.signal() }
    volume.unmount { unmounted.signal() }
    release.signal()
    need(busyReply.wait(timeout: .now() + 10) == .success && ordinaryReply.wait(timeout: .now() + 10) == .success &&
         unmounted.wait(timeout: .now() + 10) == .success, "owner busy crossing drains")
    var competing: OpaquePointer?, result = sfs_result()
    need(sfs_image_open_readonly(url.path, "image.sfs", &competing, &result) == SFS_BUSY && competing == nil,
         "nonconsumed owner retains exclusive resource lock")
    let beforeClose = hooksCloses()
    let closed: Error? = wait { owner.unloadResource(resource: path, replyHandler: $0) }
    need(closed == nil && hooksCloses() == beforeClose + 2, "retry owner unload consumes once")
    let duplicate: Error? = wait { owner.unloadResource(resource: path, replyHandler: $0) }
    need(duplicate == nil && hooksCloses() == beforeClose + 2, "owner disposition retained without duplicate close")
    hooksReset()
    let _: Bool = wait { done in volume.unmount { done(true) } }
    need(hooksReads() == 0 && hooksWrites() == 0 && hooksCloses() == 0, "terminal unmount replies without touching consumed handle")
}

func generalNamespaceChecks(_ parent: URL) throws {
    var permissions = sfs_metadata_entry(); permissions.uid = geteuid(); permissions.entry.kind = SFS_FILE
    do { try checkOwnerMode(permissions, owner: geteuid(), uid: Int(geteuid()), access: .readData); fatalError("mode 000 owner grant") }
    catch { need(code(error) == Int(EACCES), "stored read mode enforced") }
    permissions.mode = 0o400
    try checkOwnerMode(permissions, owner: geteuid(), uid: Int(geteuid()), access: .readData)
    do { try checkOwnerMode(permissions, owner: geteuid(), uid: Int(geteuid()), access: .execute); fatalError("unqualified execute grant") }
    catch { need(code(error) == Int(EACCES), "file execution denied") }
    permissions.entry.kind = SFS_DIRECTORY; permissions.mode = 0o100
    try checkOwnerMode(permissions, owner: geteuid(), uid: Int(geteuid()), access: .search)
    do { try checkOwnerMode(permissions, owner: geteuid(), uid: Int(geteuid()) + 1, access: .search); fatalError("foreign owner grant") }
    catch { need(code(error) == Int(EACCES), "foreign user denied") }
    // All images are fresh, real 0.6 core images; no FixtureIdentity input.
    func make(_ label: String, minor: UInt32 = 6) throws -> URL {
        hooksReset(); hooksFixtureWrites(1); defer { hooksFixtureWrites(0) }
        let url = parent.appendingPathComponent(label, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        var h: OpaquePointer?, r = sfs_result(), m = sfs_metadata_initial()
        m.mode = UInt32(S_IFDIR) | 0o700; m.uid = geteuid(); m.gid = getegid()
        need(sfs_image_create_metadata_version(url.path, "image.sfs", 64 * 1024 * 1024, minor, &m, &h, &r) == SFS_OK, "general image create")
        if minor == 6 {
            need(sfs_image_begin(h, &r) == SFS_OK, "general begin")
            m.mode = UInt32(S_IFREG) | 0o600
            var first: UInt64 = 0
            for i in 0..<80 {
                var inode: UInt64 = 0; let name = Data(String(format: "ordinary-%03d", i).utf8)
                need(name.withUnsafeBytes { sfs_image_add_metadata(h, 1, $0.baseAddress, $0.count, SFS_FILE, &m, &inode, &r) } == SFS_OK, "general add")
                if i == 0 { first = inode }
            }
            let alias = Data("another-alias".utf8)
            need(alias.withUnsafeBytes { sfs_image_link(h, first, 1, $0.baseAddress, $0.count, &r) } == SFS_OK, "general alias")
            need(sfs_image_commit(h, &r) == SFS_OK, "general namespace commit")
            need(sfs_image_begin(h, &r) == SFS_OK, "duplicate transaction")
            need(alias.withUnsafeBytes { sfs_image_link(h, first, 1, $0.baseAddress, $0.count, &r) } == SFS_EXISTS, "duplicate exact alias")
            need(sfs_image_abort(h, &r) == SFS_OK, "duplicate transaction abort")
            need(sfs_image_begin(h, &r) == SFS_OK, "general xattr begin")
            let large = Data(repeating: 7, count: ReadOnlyLimits.xattrValue + 1)
            let key = Data("large".utf8)
            need(key.withUnsafeBytes { k in large.withUnsafeBytes {
                sfs_image_set_xattr(h, first, k.baseAddress, k.count, $0.baseAddress, $0.count, &r)
            } } == SFS_OK, "large real xattr")
            for i in 0..<300 {
                let name = Data((String(format: "list-%04d-", i) + String(repeating: "q", count: 240)).utf8)
                need(name.withUnsafeBytes { sfs_image_set_xattr(h, first, $0.baseAddress, $0.count, nil, 0, &r) } == SFS_OK, "aggregate real xattrs")
            }
            need(sfs_image_commit(h, &r) == SFS_OK, "general xattr commit")
        }
        need(sfs_image_close(h, &r) == SFS_OK, "general producer close")
        return url
    }
    let urls = try [make("general-a"), make("general-b")]
    hooksReset()
    var volumes: [StallionVolume] = [], roots: [FSItem] = [], anchors: [sfs_result] = []
    for url in urls {
        var h: OpaquePointer?, r = sfs_result(), info = sfs_image_information()
        need(sfs_image_open_readonly(url.path, "image.sfs", &h, &r) == SFS_OK, "general open")
        need(sfs_image_get_information(h, &info, &r) == SFS_OK && info.minor == 6, "general information")
        let v = StallionVolume(handle: h!, resource: FSPathURLResource(url: url, writable: false), scope: false,
                              anchor: info.committed, queue: DispatchQueue(label: "sfs.general"), itemLimit: 2)
        let activated: (FSItem?, Error?) = wait { done in v.activate { done(($0, $1)) } }
        need(activated.0 != nil && activated.1 == nil, "general activation")
        let mounted: Error? = wait { v.mount(arguments: [], replyHandler: $0) }; need(mounted == nil, "general mount")
        volumes.append(v); roots.append(activated.0!); anchors.append(info.committed)
    }
    need(rawBytes(anchors[0].uuid) != rawBytes(anchors[1].uuid), "independent UUIDs admitted")
    need(anchors[0].generation != FixtureIdentity.generation || rawBytes(anchors[0].root_digest) != FixtureIdentity.digest, "nonfixture receipt")
    let v = volumes[0], root = roots[0]
    func lookup(_ name: String) -> (FSItem?, FSFileName?, Error?) {
        wait { done in v.lookupItem(named: FSFileName(string: name), inDirectory: root) { done(($0, $1, $2)) } }
    }
    let file = lookup("ordinary-000"); need(file.0 != nil && file.2 == nil, "arbitrary name admitted")
    let alias = lookup("another-alias"); need(alias.0 === file.0 && alias.2 == nil, "canonical generic alias at item cap")
    let saturated = lookup("ordinary-001"); need(saturated.0 == nil && code(saturated.2) == Int(ENFILE), "item cap before publication")
    need(code(lookup("missing").2) == Int(ENOENT), "missing exact name")
    need(code(lookup("a/b").2) == Int(EINVAL), "invalid component before scheduling")
    let before: Int = wait { done in v.enqueue { done(v.xattrAllocations) } }
    let large: (Data?, Error?) = wait { done in v.getXattr(named: FSFileName(string: "large"), of: file.0!) { done(($0, $1)) } }
    let after: Int = wait { done in v.enqueue { done(v.xattrAllocations) } }
    need(large.0 == nil && code(large.1) == Int(E2BIG) && before == after, "large value rejected before allocation")
    let list: ([FSFileName]?, Error?) = wait { done in v.listXattrs(of: file.0!) { done(($0, $1)) } }
    need(list.0 == nil && code(list.1) == Int(E2BIG), "aggregate list cap no partial publication")
    do { _ = try checkedXattrListTotal(1024, count: ReadOnlyLimits.xattrListCount, next: 1); fatalError("count cap bypass") } catch { need(code(error) == Int(E2BIG), "count cap error") }
    let request = FSItem.GetAttributesRequest(); request.wantedAttributes = [.fileID]
    var cookie: UInt64 = 0, verifier: UInt64 = 0, names: [Data] = []
    for _ in 0..<83 {
        var page: [Data] = []
        let reply: (FSDirectoryVerifier, Error?) = wait { done in
            v.enumerateDirectory(root, startingAt: FSDirectoryCookie(cookie), verifier: FSDirectoryVerifier(verifier), attributes: request,
                pack: { name, _, _, next, _ in
                    if !page.isEmpty { return false }; page.append(name.data); cookie = next.rawValue; return true
                }) { done(($0, $1)) }
        }
        need(reply.1 == nil, "multi-page generic enumeration"); verifier = reply.0.rawValue
        if page.isEmpty { break }; names += page
    }
    need(names.count == 81 && Set(names).count == 81, "streamed directory beyond fixture count")
    let foreign: (FSDirectoryVerifier, Error?) = wait { done in
        volumes[1].enumerateDirectory(roots[1], startingAt: FSDirectoryCookie(cookie), verifier: FSDirectoryVerifier(verifier), attributes: request,
                                     pack: { _, _, _, _, _ in fatalError("foreign cookie packed") }) { done(($0, $1)) }
    }
    need(foreign.1 != nil, "cross-image cookie refused")
    // Hold the queue, fill its real admission budget, and verify exactly one
    // synchronous rejection with no delayed duplicate callback after drain.
    let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
    v.enqueue { entered.signal(); release.wait() }
    need(entered.wait(timeout: .now() + 10) == .success, "queue held")
    let group = DispatchGroup(), lock = NSLock(); var replies = 0, rejected = 0
    for _ in 0...ReadOnlyLimits.callbacks {
        group.enter()
        v.getAttributes(request, of: root) { _, error in
            lock.lock(); replies += 1; if code(error) == Int(EAGAIN) { rejected += 1 }; lock.unlock(); group.leave()
        }
    }
    need(replies == 1 && rejected == 1, "one immediate queue saturation reply")
    release.signal(); need(group.wait(timeout: .now() + 10) == .success, "queue drained")
    let drained: Bool = wait { done in v.enqueue { done(true) } }; need(drained && replies == ReadOnlyLimits.callbacks + 1 && rejected == 1, "exact replies after drain")
    let budget = CallbackBudget()
    need(budget.acquire(ReadOnlyLimits.retainedBytes - ReadOnlyLimits.callbackOverhead), "byte budget admitted")
    need(!budget.acquire(0), "byte saturation independently enforced")
    budget.release(ReadOnlyLimits.retainedBytes - ReadOnlyLimits.callbackOverhead)
    need(budget.acquire(0), "byte budget released"); budget.release(0)
    unmountOrderingChecks(v, root: root)
    let reclaim: Error? = wait { v.reclaimItem(file.0!, replyHandler: $0) }; need(reclaim == nil, "reclaim callback")
    let count: Int = wait { done in v.enqueue { done(v.activeItemCount()) } }
    let reclaimed: StallionVolume.Record = wait { done in v.enqueue { done(v.capturedRecords().last!) } }
    need(count == (reclaimed.reclaim == 1 ? 1 : 2), "capacity released only after successful tryReclaim")
    // A direct FSItem need not be SDK-reclaimable without kernel bookkeeping.
    // Keep that observed branch, then exercise the same adapter cleanup through
    // a controlled SDK boundary. This is not a successful installed reclaim.
    if reclaimed.reclaim == 0 {
        need(code(lookup("ordinary-001").2) == Int(ENFILE), "SDK refusal retains item capacity")
        let refused: Error? = wait { volumeDone in v.reclaimForTesting(file.0!, eligible: false, replyHandler: volumeDone) }
        need(refused == nil && code(lookup("ordinary-001").2) == Int(ENFILE), "controlled refusal retains capacity")
        let released: Error? = wait { volumeDone in v.reclaimForTesting(file.0!, eligible: true, replyHandler: volumeDone) }
        need(released == nil, "controlled successful reclaim reply")
    }
    need(lookup("ordinary-001").2 == nil, "successful cleanup restores item capacity")
    for volume in volumes {
        let _: Bool = wait { done in volume.unmount { done(true) } }
        let closed = wait { done in volume.enqueue { done(volume.unload()) } }; need(closed.consumed && closed.error == nil, "general consumed close")
    }
    need(hooksWrites() == 0, "general mounted callbacks never write")
    resourceUnloadChecks(urls[0])
    // Damage the selected commit's final root cell, preserving the slot pair.
    let damaged = try FileHandle(forUpdating: urls[1].appendingPathComponent("image.sfs"))
    try damaged.seek(toOffset: anchors[1].committed_end - 1)
    let original = try damaged.read(upToCount: 1)!
    try damaged.seek(toOffset: anchors[1].committed_end - 1)
    try damaged.write(contentsOf: Data([original[0] ^ 0xff])); try damaged.close()
    let corruptFS = StallionFileSystem()
    let corrupt: (FSProbeResult?, Error?) = wait { done in
        corruptFS.probeResource(resource: FSPathURLResource(url: urls[1], writable: false)) { done(($0, $1)) }
    }
    need(corrupt.0 == nil && code(corrupt.1) == Int(EIO), "corrupt root refused without fixture fallback")
    let legacy = try make("general-legacy", minor: 5), fs = StallionFileSystem()
    let unsupported: (FSProbeResult?, Error?) = wait { done in fs.probeResource(resource: FSPathURLResource(url: legacy, writable: false)) { done(($0, $1)) } }
    need(unsupported.0 == nil && code(unsupported.1) == Int(ENOTSUP), "unsupported mounted format refused")
    need(code(sfsError(SFS_EXISTS, sfs_result())) == Int(EEXIST), "exact duplicate error")
    need(code(sfsError(SFS_LIMIT, sfs_result())) == Int(EOVERFLOW), "unclassified limit does not invent EFBIG")
}

@main struct Driver {
    static func main() throws {
        need(CommandLine.arguments.count == 2, "one fixture parent")
        let url = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let path = FSPathURLResource(url: url, writable: false)
        let fileSystem = StallionFileSystem()
        let probe: (FSProbeResult?, Error?) = wait { done in fileSystem.probeResource(resource: path) { done(($0, $1)) } }
        need(probe.0 != nil && probe.1 == nil, "independent readonly probe")
        var handle: OpaquePointer?, r = sfs_result()
        need(sfs_image_open_readonly(url.path, "image.sfs", &handle, &r) == SFS_OK && handle != nil && anchorMatches(r), "real readonly admission")
        need(r.coverage == SFS_COVERAGE_ROOT_ONLY, "root-only admission")
        let queue = DispatchQueue(label: "sfs.offline")
        let volume = StallionVolume(handle: handle!, resource: path, scope: false, anchor: r, queue: queue)
        let inactive: Error? = wait { done in volume.mount(arguments: [], replyHandler: done) }
        need(inactive != nil, "inactive mount refused")
        let rootReply: (FSItem?, Error?) = wait { done in volume.activate { done(($0, $1)) } }
        need(rootReply.0 != nil && rootReply.1 == nil, "activation root")
        let root = rootReply.0!
        let duplicate: (FSItem?, Error?) = wait { done in volume.activate { done(($0, $1)) } }
        need(root === duplicate.0, "canonical duplicate root")
        let mounted: Error? = wait { done in volume.mount(arguments: ["--rdonly"], replyHandler: done) }
        need(mounted == nil && volume.requestedMountOptions.contains(.readOnly), "readonly mounted helper")
        let request = FSItem.GetAttributesRequest(); request.wantedAttributes = FSItem.Attribute(rawValue: 0x33fff)
        let attrs: (FSItem.Attributes?, Error?) = wait { done in volume.getAttributes(request, of: root) { done(($0, $1)) } }
        need(attrs.1 == nil && attrs.0?.fileID == .rootDirectory && attrs.0?.parentID == .parentOfRoot, "root projection")
        request.wantedAttributes = FSItem.Attribute(rawValue: 1 << 62)
        let unknown: (FSItem.Attributes?, Error?) = wait { done in volume.getAttributes(request, of: root) { done(($0, $1)) } }
        need(unknown.0 == nil && code(unknown.1) == Int(ENOTSUP), "unknown wanted refusal")
        request.wantedAttributes = []
        let zero: (FSItem.Attributes?, Error?) = wait { done in volume.getAttributes(request, of: root) { done(($0, $1)) } }
        need(zero.0 != nil && zero.1 == nil, "zero wanted allowed")
        var files: [String: FSItem] = [:]
        for name in ["empty", "resource", "sparse-resource", "data", "data-resource", "opaque", "link", "dir"] {
            let reply: (FSItem?, FSFileName?, Error?) = wait { done in
                volume.lookupItem(named: FSFileName(string: name), inDirectory: root) { done(($0, $1, $2)) }
            }
            need(reply.2 == nil && reply.0 != nil && reply.1?.data == Data(name.utf8), "real lookup \(name)")
            files[name] = reply.0
        }
        let link: (FSFileName?, Error?) = wait { done in volume.readSymbolicLink(files["link"]!) { done(($0, $1)) } }
        need(link.1 == nil && link.0?.data == Data("data".utf8), "real symlink")
        let resource: (Data?, Error?) = wait { done in volume.getXattr(named: FSFileName(string: "com.apple.ResourceFork"), of: files["resource"]!) { done(($0, $1)) } }
        need(resource.1 == nil && resource.0?.count == 8193, "binary xattr")
        need(resource.0!.enumerated().allSatisfy { $0.element == UInt8(($0.offset * 37 + 11) & 255) }, "exact binary xattr")
        let absent: (Data?, Error?) = wait { done in volume.getXattr(named: FSFileName(string: "absent"), of: files["empty"]!) { done(($0, $1)) } }
        need(absent.0 == nil && code(absent.1) == Int(ENOATTR), "missing xattr")
        let names: ([FSFileName]?, Error?) = wait { done in volume.listXattrs(of: files["opaque"]!) { done(($0, $1)) } }
        need(names.1 == nil && names.0?.map(\.data) == [Data("org.alvin.sfs-allocation".utf8)], "raw list xattrs")
        request.wantedAttributes = [.allocSize, .size, .mode, .uid, .gid, .linkCount]
        for (name, size, allocation) in [("resource", 0, 0), ("sparse-resource", 16385, 0), ("data", 8193, 12288), ("data-resource", 8193, 12288)] {
            let a: (FSItem.Attributes?, Error?) = wait { done in volume.getAttributes(request, of: files[name]!) { done(($0, $1)) } }
            need(a.1 == nil && a.0?.size == UInt64(size) && a.0?.allocSize == UInt64(allocation) && a.0?.linkCount == (name == "data-resource" ? 3 : 1), "experimental allocation \(name)")
        }
        let rootAlias: (FSItem?, FSFileName?, Error?) = wait { done in
            volume.lookupItem(named: FSFileName(string: "data-resource-alias"), inDirectory: root) { done(($0, $1, $2)) }
        }
        let dirAlias: (FSItem?, FSFileName?, Error?) = wait { done in
            volume.lookupItem(named: FSFileName(string: "data-resource-alias"), inDirectory: files["dir"]!) { done(($0, $1, $2)) }
        }
        need(rootAlias.2 == nil && dirAlias.2 == nil && rootAlias.0 === files["data-resource"] && dirAlias.0 === rootAlias.0,
             "same and cross-parent aliases share canonical item")
        need(rootAlias.1?.data == Data("data-resource-alias".utf8) && dirAlias.1?.data == rootAlias.1?.data, "actual alias saved names")
        let aliasRequest = FSItem.GetAttributesRequest(); aliasRequest.wantedAttributes = [.fileID, .parentID, .linkCount]
        for item in [files["data-resource"]!, rootAlias.0!, dirAlias.0!] {
            let a: (FSItem.Attributes?, Error?) = wait { done in volume.getAttributes(aliasRequest, of: item) { done(($0, $1)) } }
            need(a.1 == nil && a.0?.fileID.rawValue == 7 && a.0?.parentID.rawValue == 2 && a.0?.linkCount == 3,
                 "representative alias projection hypothesis")
            let x: (Data?, Error?) = wait { done in volume.getXattr(named: FSFileName(string: "com.apple.ResourceFork"), of: item) { done(($0, $1)) } }
            need(x.1 == nil && x.0 == resource.0, "shared alias xattr")
        }
        need(volume.maximumLinkCount == Int(UInt32.max) && volume.supportedVolumeCapabilities.supportsHardLinks, "isolated alias hypothesis capabilities")
        try validateDirectoryLayout(FSDirectoryCookie.initial.rawValue, FSDirectoryVerifier.initial.rawValue)
        for pair in [(UInt64(1), UInt64(0)), (UInt64(0), UInt64(1))] {
            do { try validateDirectoryLayout(pair.0, pair.1); fatalError("incompatible initial layout accepted") } catch {}
        }
        do { _ = try checkedLinks(UInt64(UInt32.max) + 1); fatalError("link overflow accepted") } catch {}
        let maximumLinks = try checkedLinks(UInt64(UInt32.max))
        need(maximumLinks == UInt32.max, "exact maximum link conversion")
        struct Packed { let name: Data; let inode: UInt64; let cookie: UInt64; let parent: UInt64?; let links: UInt32? }
        func enumeration(_ directory: FSItem, _ start: UInt64 = FSDirectoryCookie.initial.rawValue,
                         _ verifier: UInt64 = FSDirectoryVerifier.initial.rawValue,
                         _ attributes: FSItem.GetAttributesRequest? = nil, _ capacity: Int = 32) -> ([Packed], UInt64, Error?) {
            var packed: [Packed] = [], refusedPack = false
            let reply: (FSDirectoryVerifier, Error?) = wait { done in
                volume.enumerateDirectory(directory, startingAt: FSDirectoryCookie(start), verifier: FSDirectoryVerifier(verifier),
                    attributes: attributes, pack: { name, _, inode, cookie, attrs in
                        guard packed.count < capacity else { refusedPack = true; return false }
                        packed.append(Packed(name: name.data, inode: inode.rawValue, cookie: cookie.rawValue,
                                             parent: attributes?.isAttributeWanted(.parentID) == true ? attrs?.parentID.rawValue : nil,
                                             links: attributes?.isAttributeWanted(.linkCount) == true ? attrs?.linkCount : nil))
                        return true
                    }) { done(($0, $1)) }
            }
            if [Int(EAGAIN), Int(ENXIO)].contains(code(reply.1)) {
                need(packed.isEmpty && reply.0.rawValue == 0, "admission rejection has no packing or verifier")
                return (packed, reply.0.rawValue, reply.1)
            }
            let diagnostic: StallionVolume.Record = wait { done in volume.enqueue { done(volume.capturedRecords().last!) } }
            need(diagnostic.operation == 14 && diagnostic.cookie == start && diagnostic.verifier == verifier &&
                 diagnostic.returnedVerifier == reply.0.rawValue && diagnostic.acceptedCookie == (packed.last?.cookie ?? 0),
                 "actual terminal enumeration diagnostics")
            need(diagnostic.stop == (reply.1 != nil ? 3 : refusedPack ? 2 : 1), "finite terminal reason")
            return (packed, reply.0.rawValue, reply.1)
        }
        let refused = enumeration(root, 0, 0, nil, 0)
        need(refused.0.isEmpty && refused.1 != 0 && refused.2 == nil, "zero packer stops at first dot")
        let dots = enumeration(root, 0, 0, nil, 1)
        need(dots.0.map(\.name) == [Data(".".utf8)] && dots.0[0].cookie == 1, "one dot accepted")
        let dotRetry = enumeration(root, 1, dots.1, nil, 1)
        need(dotRetry.0.map(\.name) == [Data("..".utf8)] && dotRetry.0[0].cookie == 2, "refused dot retried")
        let all = enumeration(root)
        let expectedRoot = FixtureIdentity.names.filter { $0.parent == 1 }.map { Data($0.name.utf8) }.sorted { $0.lexicographicallyPrecedes($1) }
        need(all.2 == nil && all.0.map(\.name) == [Data(".".utf8), Data("..".utf8)] + expectedRoot, "full root alias rows and dots")
        let first = enumeration(root, 0, 0, aliasRequest, 1)
        let zeroAttributes = enumeration(root, 0, 0, aliasRequest, 0)
        need(first.2 == nil && first.0.count == 1 && zeroAttributes.0.isEmpty && zeroAttributes.2 == nil, "attribute pack refusal")
        let retry = enumeration(root, 0, first.1, aliasRequest, 1)
        need(retry.0[0].name == first.0[0].name && retry.0[0].cookie == first.0[0].cookie, "failed pack retry unchanged")
        let childFirst = enumeration(files["dir"]!, 0, 0, aliasRequest, 1)
        var paged = first.0, last = first.0[0].cookie
        for _ in 0..<9 {
            let page = enumeration(root, last, first.1, aliasRequest, 1)
            need(page.2 == nil, "root pagination")
            if page.0.isEmpty { break }
            paged += page.0; last = page.0[0].cookie
        }
        need(paged.map(\.name) == expectedRoot && Set(paged.map(\.cookie)).count == 9, "no alias omission or duplicate position")
        let aliases = paged.filter { $0.inode == 7 }
        need(aliases.count == 2 && aliases.allSatisfy { $0.parent == 2 && $0.links == 3 }, "packed representative parent and shared ID")
        let childNext = enumeration(files["dir"]!, childFirst.0[0].cookie, childFirst.1, aliasRequest)
        need(childNext.2 == nil && (childFirst.0 + childNext.0).map(\.name) == [Data("child".utf8), Data("data-resource-alias".utf8)], "interleaved parent continuation")
        let end = enumeration(root, last, first.1, aliasRequest)
        need(end.0.isEmpty && end.1 == first.1 && end.2 == nil, "zero entry EOF preserves verifier")
        for token in [UInt64(1), 2, 3, 16, UInt64.max] {
            let bad = enumeration(root, token, first.1, aliasRequest)
            need(bad.0.isEmpty && bad.2 != nil, "malformed or attribute dot position")
        }
        for bad in [enumeration(root, last, first.1 ^ 2, aliasRequest),
                    enumeration(root, last, all.1, aliasRequest),
                    enumeration(files["dir"]!, last, first.1, aliasRequest)] {
            need(bad.0.isEmpty && bad.2 != nil, "stale mode or parent verifier")
        }
        let unknownEnumeration = FSItem.GetAttributesRequest(); unknownEnumeration.wantedAttributes = FSItem.Attribute(rawValue: 1 << 62)
        let badMask = enumeration(root, 0, 0, unknownEnumeration)
        need(badMask.0.isEmpty && badMask.1 == 0 && code(badMask.2) == Int(ENOTSUP), "mask refused before verifier/output")
        let evidence: [StallionVolume.Record] = wait { done in volume.enqueue { done(volume.capturedRecords()) } }
        need(evidence.contains { $0.operation == 22 && $0.accepted == 0 && $0.coreParentValid == 1 && $0.mappedParentValid == 1 }, "refused attributes recorded as attempt")
        need(evidence.contains { $0.operation == 10 && $0.mask == 0 && $0.coreParentValid == 1 && $0.mappedParentValid == 0 }, "unrequested parent remains invalid")
        need(evidence.filter { $0.operation == 10 && $0.error != 0 }.allSatisfy { $0.mappedParentValid == 0 }, "failed getter has no returned parent")
        let write: (Int, Error?) = wait { done in volume.writeCountForTesting(contents: Data([1]), to: files["data"]!, at: 0) { done(($0, $1)) } }
        need(write.0 == 0 && code(write.1) == Int(EROFS), "write refused")
#if STALLION_CONTEXT_HANDLERS
        let set: Error? = wait { done in volume.refusedMutationForTesting(replyHandler: done) }
#else
        let set: Error? = wait { done in volume.setXattr(named: FSFileName(string: "x"), to: Data(), on: files["empty"]!, policy: .alwaysSet, replyHandler: done) }
#endif
        need(code(set) == Int(EROFS), "set xattr refused")
        hooksReset()
        let _: Bool = wait { done in volume.unmount { done(true) } }
        need(hooksReads() == 0 && hooksWrites() == 0 && hooksCloses() == 0, "unmount memory-only")
        let _: Bool = wait { done in volume.unmount { done(true) } }
        let unmountedEnumeration = enumeration(root)
        need(unmountedEnumeration.0.isEmpty && unmountedEnumeration.1 == 0 && code(unmountedEnumeration.2) == Int(ENXIO), "early enumeration error has zero returned verifier")
        var competitor: OpaquePointer?, busy = sfs_result()
        need(sfs_image_open_readonly(url.path, "image.sfs", &competitor, &busy) == SFS_BUSY && competitor == nil, "unmount retains lock")
        let remount: Error? = wait { done in volume.mount(arguments: [], replyHandler: done) }
        need(remount == nil, "same-handle remount")
        let oldSession = enumeration(root, last, first.1, aliasRequest)
        need(oldSession.0.isEmpty && oldSession.2 != nil, "old session refused after purge/remount")
        let freshSession = enumeration(root, 0, 0, aliasRequest)
        need(freshSession.2 == nil && freshSession.1 != first.1 && freshSession.0.map(\.name) == expectedRoot, "fresh session checked refill")
        let after: (FSItem.Attributes?, Error?) = wait { done in volume.getAttributes(request, of: files["data"]!) { done(($0, $1)) } }
        need(after.1 == nil && hooksReads() > 0, "purged checked reload")
        let _: Bool = wait { done in volume.unmount { done(true) } }
        hooksReset()
        let deactivated: Error? = wait { done in volume.deactivate(options: [], replyHandler: done) }
        need(deactivated == nil && hooksReads() == 0 && hooksCloses() == 0, "deactivate memory-only")
        let reactivate: (FSItem?, Error?) = wait { done in volume.activate { done(($0, $1)) } }
        need(reactivate.0 === root && reactivate.1 == nil, "root retained across activation")
        hooksReset(); hooksFailClose()
        let closed: Error? = wait { done in volume.enqueue { done(volume.unload().error) } }
        need(code(closed) == Int(EIO), "consumed close failure")
        let closeCount = hooksCloses()
        let again: Error? = wait { done in volume.enqueue { done(volume.unload().error) } }
        need(code(again) == Int(EIO) && hooksCloses() == closeCount, "duplicate unload no retry")
        need(sfs_image_open_readonly(url.path, "image.sfs", &competitor, &busy) == SFS_OK, "lock released after close error")
        need(sfs_image_close(competitor, &busy) == SFS_OK, "competitor close")
        need(hooksWrites() == 0, "no image mutation")
        // A fresh real handle isolates the read-failure case from close-error injection.
        var poisonedHandle: OpaquePointer?, poisonedAnchor = sfs_result()
        need(sfs_image_open_readonly(url.path, "image.sfs", &poisonedHandle, &poisonedAnchor) == SFS_OK &&
             poisonedHandle != nil && anchorMatches(poisonedAnchor), "fatal case readonly admission")
        let poisoned = StallionVolume(handle: poisonedHandle!, resource: path, scope: false,
                                      anchor: poisonedAnchor, queue: DispatchQueue(label: "sfs.offline.fatal"))
        let poisonRoot: (FSItem?, Error?) = wait { done in poisoned.activate { done(($0, $1)) } }
        need(poisonRoot.0 != nil && poisonRoot.1 == nil, "fatal case activation")
        let poisonMount: Error? = wait { done in poisoned.mount(arguments: [], replyHandler: done) }
        need(poisonMount == nil, "fatal case mount")
        let poisonFile: (FSItem?, FSFileName?, Error?) = wait { done in
            poisoned.lookupItem(named: FSFileName(string: "data"), inDirectory: poisonRoot.0!) { done(($0, $1, $2)) }
        }
        need(poisonFile.0 != nil && poisonFile.2 == nil, "fatal case real child lookup")
        let _: Bool = wait { done in poisoned.unmount { done(true) } }
        let poisonAfterPurge: Error? = wait { poisoned.mount(arguments: [], replyHandler: $0) }
        need(poisonAfterPurge == nil, "poison test remount before uncached read")
        hooksReset(); hooksFailRead()
        let readFailure: (FSItem.Attributes?, Error?) = wait { done in
            poisoned.getAttributes(request, of: poisonFile.0!) { done(($0, $1)) }
        }
        need(readFailure.0 == nil && code(readFailure.1) == Int(EIO) && hooksReads() > 0,
             "uncached read failure mapped")
        let failedAttributes: StallionVolume.Record = wait { done in poisoned.enqueue { done(poisoned.capturedRecords().last!) } }
        need(failedAttributes.operation == 10 && failedAttributes.error == Int64(EIO) && failedAttributes.coreParentValid == 0 &&
             failedAttributes.mappedParentValid == 0, "failed stat cannot fabricate parent evidence")
        hooksReset()
        let _: Bool = wait { done in poisoned.unmount { done(true) } }
        let poisonDeactivate: Error? = wait { done in poisoned.deactivate(options: [], replyHandler: done) }
        let poisonActivate: (FSItem?, Error?) = wait { done in poisoned.activate { done(($0, $1)) } }
        let poisonRemount: Error? = wait { done in poisoned.mount(arguments: [], replyHandler: done) }
        let poisonSync: Error? = wait { done in poisoned.synchronize(flags: .wait, replyHandler: done) }
        need(code(poisonDeactivate) == Int(EIO) && poisonActivate.0 == nil && code(poisonActivate.1) == Int(EIO) &&
             code(poisonRemount) == Int(EIO) && code(poisonSync) == Int(EIO), "first fatal error retained")
        need(hooksReads() == 0 && hooksWrites() == 0 && hooksCloses() == 0, "purge cannot revive or perform I/O")
        let poisonClose: Error? = wait { done in poisoned.enqueue { done(poisoned.unload().error) } }
        let poisonCloseCount = hooksCloses()
        let poisonDuplicate: Error? = wait { done in poisoned.enqueue { done(poisoned.unload().error) } }
        need(code(poisonClose) == Int(EIO) && code(poisonDuplicate) == Int(EIO) &&
             poisonCloseCount > 0 && hooksCloses() == poisonCloseCount, "fatal case consumed terminal close")
        competitor = nil
        need(sfs_image_open_readonly(url.path, "image.sfs", &competitor, &busy) == SFS_OK && competitor != nil,
             "fatal case lock released")
        need(sfs_image_close(competitor, &busy) == SFS_OK && hooksWrites() == 0, "fatal case final close and no writes")
        // A separate handle preserves the getter-failure case and isolates a checked prefix failure.
        var prefixHandle: OpaquePointer?, prefixAnchor = sfs_result()
        need(sfs_image_open_readonly(url.path, "image.sfs", &prefixHandle, &prefixAnchor) == SFS_OK &&
             prefixHandle != nil && anchorMatches(prefixAnchor), "prefix case readonly admission")
        let borrowedPrefixHandle = prefixHandle!
        let prefixVolume = StallionVolume(handle: borrowedPrefixHandle, resource: path, scope: false,
                                          anchor: prefixAnchor, queue: DispatchQueue(label: "sfs.offline.prefix"))
        let prefixRoot: (FSItem?, Error?) = wait { done in prefixVolume.activate { done(($0, $1)) } }
        need(prefixRoot.0 != nil && prefixRoot.1 == nil, "prefix case activation")
        let prefixMount: Error? = wait { done in prefixVolume.mount(arguments: [], replyHandler: done) }
        need(prefixMount == nil, "prefix case mount")
        var prefixRows: [Packed] = [], prefixPacks = 0
        let prefixReply: (FSDirectoryVerifier, Error?) = wait { done in
            prefixVolume.enumerateDirectory(prefixRoot.0!, startingAt: FSDirectoryCookie.initial,
                verifier: FSDirectoryVerifier.initial, attributes: aliasRequest, pack: { name, _, inode, cookie, attrs in
                    prefixPacks += 1
                    need(prefixPacks == 1 && name.data == Data("data".utf8) && inode.rawValue == 6 &&
                         cookie.rawValue >= 17 && attrs?.parentID.rawValue == 2 && attrs?.linkCount == 1,
                         "only first checked real prefix reaches packer")
                    prefixRows.append(Packed(name: name.data, inode: inode.rawValue, cookie: cookie.rawValue,
                                             parent: attrs?.parentID.rawValue, links: attrs?.linkCount))
                    // The C calls have returned. Stay on the volume queue without another enqueue or wait.
                    hooksReset()
                    sfs_image_clear_read_cache(borrowedPrefixHandle)
                    need(hooksReads() == 0 && hooksWrites() == 0 && hooksCloses() == 0, "prefix purge is quiescent memory-only")
                    hooksFailRead()
                    return true
                }) { done(($0, $1)) }
        }
        need(prefixPacks == 1 && prefixRows.count == 1 && code(prefixReply.1) == Int(EIO) && prefixReply.0.rawValue != 0 &&
             hooksReads() == 1 && hooksWrites() == 0 && hooksCloses() == 0, "next checked read fails after accepted prefix")
        let acceptedPrefix = prefixRows[0].cookie
        let prefixEvidence: [StallionVolume.Record] = wait { done in prefixVolume.enqueue {
            let snapshot = prefixVolume.capturedRecords(); hooksReset(); done(snapshot)
        } }
        need(prefixEvidence.map(\.operation) == [0, 1, 2, 22, 14], "exact prefix attempt and terminal records")
        let packedPrefix = prefixEvidence[3], failedPrefix = prefixEvidence[4]
        need(packedPrefix.inode == 5 && packedPrefix.error == 0 && packedPrefix.accepted == 1 &&
             packedPrefix.coreParentValid == 1 && packedPrefix.coreParent == 1 &&
             packedPrefix.mappedParentValid == 1 && packedPrefix.mappedParent == 2, "accepted attribute attempt uses checked projection")
        need(failedPrefix.inode == 1 && failedPrefix.error == Int64(EIO) && failedPrefix.stop == 3 &&
             failedPrefix.cookie == FSDirectoryCookie.initial.rawValue && failedPrefix.verifier == FSDirectoryVerifier.initial.rawValue &&
             failedPrefix.returnedVerifier == prefixReply.0.rawValue && failedPrefix.acceptedCookie == acceptedPrefix,
             "failed terminal records actual verifier and accepted prefix")
        var retryPacks = 0
        let prefixRetry: (FSDirectoryVerifier, Error?) = wait { done in
            prefixVolume.enumerateDirectory(prefixRoot.0!, startingAt: FSDirectoryCookie(acceptedPrefix),
                verifier: prefixReply.0, attributes: aliasRequest, pack: { _, _, _, _, _ in
                    retryPacks += 1; return true
                }) { done(($0, $1)) }
        }
        need(retryPacks == 0 && prefixRows.count == 1 && prefixRows[0].cookie == acceptedPrefix &&
             code(prefixRetry.1) == Int(EIO) && prefixRetry.0.rawValue == 0 &&
             hooksReads() == 0 && hooksWrites() == 0 && hooksCloses() == 0, "fatal prefix error remains latched before I/O or packing")
        let prefixClose: ([StallionVolume.Record], Error?, [StallionVolume.Record]) = wait { done in prefixVolume.enqueue {
            let before = prefixVolume.capturedRecords()
            let error = prefixVolume.unload().error // One consuming API call closes image and auxiliary-parent descriptors.
            done((before, error, prefixVolume.capturedRecords()))
        } }
        prefixHandle = nil // The borrowed pointer is never used after consuming unload.
        need(prefixClose.0.map(\.operation) == [0, 1, 2, 22, 14, 14] &&
             prefixClose.2.map(\.operation) == [0, 1, 2, 22, 14, 14, 6], "exact retry and consuming-close records")
        let retryEvidence = prefixClose.0[5]
        need(retryEvidence.cookie == acceptedPrefix && retryEvidence.verifier == prefixReply.0.rawValue &&
             retryEvidence.returnedVerifier == prefixRetry.0.rawValue && retryEvidence.acceptedCookie == 0 &&
             retryEvidence.stop == 3 && retryEvidence.error == Int64(EIO), "latched retry terminal reflects actual empty error reply")
        need(code(prefixClose.1) == Int(EIO) && prefixClose.2[6].error == Int64(EIO) &&
             hooksReads() == 0 && hooksWrites() == 0 && hooksCloses() == 2,
             "one consuming unload closes both owned descriptors and retains original EIO")
        try component(Data([255, 46])); try component(Data([47, 255]), xattr: true)
        do { try component(Data([47])); fatalError("slash accepted") } catch {}
        do { _ = try itemIdentifier(UInt64.max); fatalError("ID overflow accepted") } catch {}
        try generalNamespaceChecks(url)
        print("PASS: real-core namespace, aliases, pagination, resource limits, reclaim, lifecycle ordering, read-only refusal and consumed close")
        print("UNTESTED: kernel access routing, packer/buffer delivery, kernel reclaim counts, acquired security scope and signed lifecycle")
    }
}
