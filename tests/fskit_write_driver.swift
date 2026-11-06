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
@MainActor func factoryPolicyChecks(_ parent: URL) throws {
    let fixture = try Fixture(parent,"factory-readonly")
    let image = fixture.url.appendingPathComponent("image.sfs"), before = try Data(contentsOf:image)
#if STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES
    let modes = [1,2]
#else
    let modes = [0,1,2]
#endif
    let fs = StallionExtension().fileSystem
    for mode in modes {
        let resource = FSPathURLResource(url:fixture.url,writable:mode != 2)
        let loaded: (FSVolume?,Error?) = wait { done in fs.loadResource(resource:resource,arguments:mode == 1 ? ["--rdonly"] : []) { done(($0,$1)) } }
        need(loaded.0 != nil && loaded.1 == nil,"public factory readonly load")
        let volume = loaded.0 as! StallionVolume
        let coreRO: Bool = wait { done in volume.enqueue { done(volume.coreReadOnlyForTesting()) } }
        need(coreRO && volume.requestedMountOptions.contains(.readOnly),"public factory readonly core and mount request")
        let active: (FSItem?,Error?) = wait { done in volume.activate { done(($0,$1)) } };need(active.1 == nil,"public factory readonly activation")
        let mounted: Error? = wait { volume.mount(arguments:[],replyHandler:$0) };need(mounted == nil,"public factory readonly mount")
        let written: Error? = wait { done in volume.write(contents:Data([1]),to:active.0!,at:0) { done($1) } }
        need(code(written)==Int(EROFS),"public factory readonly mutation denied")
        let _: Bool = wait { done in volume.unmount { done(true) } }
        let deactivated: Error? = wait { volume.deactivate(options:[],replyHandler:$0) };need(deactivated == nil,"public factory readonly deactivation")
        let unloaded: Error? = wait { fs.unloadResource(resource:resource,replyHandler:$0) };need(unloaded == nil,"public factory readonly unload")
        let again: (FSVolume?,Error?) = wait { done in fs.loadResource(resource:resource,arguments:mode == 1 ? ["--rdonly"] : []) { done(($0,$1)) } }
        need(again.1 == nil && again.0 !== volume,"same public factory and resource reopen with new ownership")
        let fresh = again.0 as! StallionVolume
        let freshRO: Bool = wait { done in fresh.enqueue { done(fresh.coreReadOnlyForTesting()) } }
        need(freshRO && fresh.requestedMountOptions.contains(.readOnly),"reopened factory retains readonly selection")
        let freshClose: Error? = wait { fs.unloadResource(resource:resource,replyHandler:$0) };need(freshClose == nil,"fresh readonly ownership consumed")
        let after = try Data(contentsOf:image);need(after==before,"public factory denied mutation preserves image")
    }
    let revoked = FSPathURLResource(url:fixture.url,writable:true);revoked.revoke()
    let denied: (FSVolume?,Error?) = wait { done in fs.loadResource(resource:revoked,arguments:[]) { done(($0,$1)) } }
    need(denied.0 == nil && code(denied.1)==Int(EACCES),"public factory revoked resource denied")
    let after = try Data(contentsOf:image);need(after==before,"revoked load preserves image")
#if STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES
    let configurationResource = FSPathURLResource(url:fixture.url,writable:true)
    fs.setLoadConfigurationHookForTesting { configurationResource.revoke() }
    let failedConfiguration: (FSVolume?,Error?) = wait { done in fs.loadResource(resource:configurationResource,arguments:[]) { done(($0,$1)) } }
    fs.setLoadConfigurationHookForTesting(nil)
    need(failedConfiguration.0 == nil && code(failedConfiguration.1)==Int(EACCES),"failed writable configuration consumes fresh handle")
    let healthy = FSPathURLResource(url:fixture.url,writable:true)
    let recovered: (FSVolume?,Error?) = wait { done in fs.loadResource(resource:healthy,arguments:[]) { done(($0,$1)) } }
    need(recovered.1 == nil && recovered.0 != nil,"same factory recovers after configuration failure")
    let recoveredClose: Error? = wait { fs.unloadResource(resource:healthy,replyHandler:$0) };need(recoveredClose == nil,"recovered fresh handle closes")
    try accessPolicyChecks(parent,factory:true)
#endif
}

@MainActor func accessPolicyChecks(_ parent: URL, factory: Bool = false) throws {
    func makeFileSystem() -> StallionFileSystem {
        factory ? StallionExtension().fileSystem : StallionFileSystem(accessPolicy:.contextualWrites)
    }
    let f = try Fixture(parent,"access-policy"), resource = FSPathURLResource(url: f.url,writable: true)
    let image = f.url.appendingPathComponent("image.sfs"), before = try Data(contentsOf:image)
    func load(_ fs: StallionFileSystem, _ args: [String] = []) -> (FSVolume?,Error?) {
        wait { done in fs.loadResource(resource:resource,arguments:args) { done(($0,$1)) } }
    }
    func close(_ fs: StallionFileSystem, _ volume: StallionVolume, _ root: FSItem? = nil, _ file: FSItem? = nil, expectedError: Int = 0) {
        let _: Bool = wait { done in volume.unmount { done(true) } }
#if STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES
        if let file {
            let error: Error? = wait { volume.reclaimForTesting(file,eligible:true,replyHandler:$0) }
            need(error == nil,"admission operand reclaimed")
        }
#endif
        let error: Error? = wait { volume.deactivate(options:[],replyHandler:$0) }
        need(code(error) == expectedError,"admission deactivation preserves delivery outcome")
        let unloaded: Error? = wait { fs.unloadResource(resource:resource,replyHandler:$0) }
        need(code(unloaded) == expectedError,"admission unload consumes handle and preserves outcome")
    }
    // SDK FSTaskOptions.init is unavailable. Exercise its exact shared decoder;
    // installed task delivery is a separate qualification requirement.
    for mode in 0..<3 {
        let fs = mode == 0 ? StallionFileSystem() : makeFileSystem()
#if STALLION_WRITE_DIAGNOSTIC
        if mode == 2 { fs.diagnosticUUID = f.identity }
#endif
        let reply = load(fs,["--rdonly"])
        need(reply.1 == nil && reply.0 != nil,"explicit readonly dominates every opt-in")
        let volume = reply.0 as! StallionVolume
        let coreRO: Bool = wait { done in volume.enqueue { done(volume.coreReadOnlyForTesting()) } }
        need(coreRO && volume.requestedMountOptions.contains(.readOnly),"readonly core policy and mount request")
#if STALLION_WRITE_DIAGNOSTIC || (STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES)
        do { try volume.enableAdmittedWrites(); fatalError("readonly load promoted") }
        catch { need(code(error)==Int(EACCES),"immutable admission rejects promotion") }
#endif
        let activated: (FSItem?,Error?) = wait { done in volume.activate { done(($0,$1)) } }
        need(activated.1 == nil,"readonly activation")
        let mounted: Error? = wait { volume.mount(arguments:[],replyHandler:$0) };need(mounted == nil,"readonly mount")
        let write: Error? = wait { done in
#if STALLION_CONTEXT_HANDLERS
            volume.write(contents:Data([1]),to:activated.0!,at:0) { done($1) }
#else
            volume.write(contents:Data([1]),to:activated.0!,at:0) { done($1) }
#endif
        }
        need(code(write)==Int(EROFS),"readonly data callback refused")
        close(fs,volume)
        let after = try Data(contentsOf:image)
        need(after==before,"readonly load unchanged through unload")
    }
    let force = load(makeFileSystem(),["--rdonly","-f"])
    need(force.0 == nil && code(force.1)==Int(ENOTSUP),"force remains refused before any open")
    let revoked = FSPathURLResource(url:f.url,writable:true);revoked.revoke()
    let revokedReply: (FSVolume?,Error?)=wait { done in makeFileSystem().loadResource(resource:revoked,arguments:["--rdonly"]) { done(($0,$1)) } }
    need(revokedReply.0 == nil && code(revokedReply.1)==Int(EACCES),"revoked resource refuses even explicit readonly")
#if STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES
    let roResource=FSPathURLResource(url:f.url,writable:false), roFS=makeFileSystem()
    let roReply: (FSVolume?,Error?)=wait { done in roFS.loadResource(resource:roResource,arguments:[]) { done(($0,$1)) } }
    need(roReply.1 == nil && (roReply.0 as! StallionVolume).requestedMountOptions.contains(.readOnly),"nonwritable production resource falls back to readonly")
    let roUnload: Error?=wait { roFS.unloadResource(resource:roResource,replyHandler:$0) };need(roUnload == nil,"nonwritable resource unload")
#endif
    let fs = makeFileSystem(), reply = load(fs)
#if STALLION_CONTEXT_HANDLERS && STALLION_CONTEXT_WRITES
    need(reply.1 == nil && reply.0 != nil,"explicit contextual mutation admission")
    let v = reply.0 as! StallionVolume
    need(v.volumeID.uuid==f.identity && !v.requestedMountOptions.contains(.readOnly),"stored volume identity and admitted mode")
    let coreRO: Bool = wait { done in v.enqueue { done(v.coreReadOnlyForTesting()) } }
    need(!coreRO,"mutation admission uses actual writable core")
    var competing: OpaquePointer?, receipt = sfs_result()
    need(sfs_image_open(f.url.path,"image.sfs",&competing,&receipt)==SFS_BUSY && competing == nil,"same-inode exclusive ownership retained")
    let active: (FSItem?,Error?) = wait { done in v.activate { done(($0,$1)) } };need(active.1 == nil,"mutation activation")
    let mounted: Error? = wait { v.mount(arguments:[],replyHandler:$0) };need(mounted == nil,"mutation mount")
    let found: (FSItem?,FSFileName?,Error?) = wait { done in v.lookupItem(named:FSFileName(string:"file"),inDirectory:active.0!) { done(($0,$1,$2)) } }
    need(found.2 == nil,"mutation file lookup")
    let caller = CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))
    let newAttributes=FSItem.SetAttributesRequest();newAttributes.mode=UInt32(S_IFREG)|0o600;newAttributes.uid=geteuid();newAttributes.gid=getegid()
    let created: (FSCreateItemResult?,Error?)=wait { done in v.createResultForTesting(FSFileName(string:"created-no-grant"),directory:active.0!,attributes:newAttributes,caller:caller) { done(($0,$1)) } }
    need(created.0 != nil && created.1 == nil,"contextual creation succeeds")
    let createdLookup: (FSItem?,FSFileName?,Error?)=wait { done in v.lookupItem(named:FSFileName(string:"created-no-grant"),inDirectory:active.0!) { done(($0,$1,$2)) } }
    let createdModes: FSVolume.OpenModes=wait { done in v.enqueue { done(try! v.retainedModesForTesting(createdLookup.0!)) } }
    need(createdModes.isEmpty,"create and lookup do not mint write authority")
    let createdRelease: Error?=wait { v.reclaimForTesting(createdLookup.0!,eligible:true,replyHandler:$0) };need(createdRelease == nil,"unopened create pin reclaimed")
    let createdAgain: (FSItem?,FSFileName?,Error?)=wait { done in v.lookupItem(named:FSFileName(string:"created-no-grant"),inDirectory:active.0!) { done(($0,$1,$2)) } }
    need(createdAgain.0 !== createdLookup.0,"reclaimed canonical item is replaced")
    let staleOpen: Error?=wait { v.openForTesting(createdLookup.0!,modes:.write,caller:caller,reply:$0) }
    let recreatedModes: FSVolume.OpenModes=wait { done in v.enqueue { done(try! v.retainedModesForTesting(createdAgain.0!)) } }
    need(code(staleOpen)==Int(EINVAL) && recreatedModes.isEmpty,"stale item cannot grant authority to replacement")
    let createdAgainRelease: Error?=wait { v.reclaimForTesting(createdAgain.0!,eligible:true,replyHandler:$0) };need(createdAgainRelease == nil,"replacement create pin reclaimed")
    let changed: (FSSetXattrResult?,Error?) = wait { done in v.setXattrResultForTesting(FSFileName(string:"vendor.admission"),value:Data([0,255]),item:found.0!,policy:.mustCreate,caller:caller) { done(($0,$1)) } }
    need(changed.0 != nil && changed.1 == nil && v.anchor.generation>2,"contextual xattr mutation commits")
    let item = found.0!, foreign = CallerIdentity(uid:Int(geteuid())+1,gid:Int(getegid())+1)
    func modes() -> FSVolume.OpenModes {
        wait { done in v.enqueue { done(try! v.retainedModesForTesting(item)) } }
    }
    need(modes().isEmpty,"lookup never grants open modes")
    let checked: (FSCheckAccessResult?,Error?)=wait { done in v.accessForTesting(item,access:.writeData,caller:caller) { done(($0,$1)) } }
    need(checked.0 != nil && checked.1 == nil && modes().isEmpty,"successful access check never grants open modes")
    let deniedOpen: Error?=wait { v.openForTesting(item,modes:[.read,.write],caller:foreign,reply:$0) }
    need(code(deniedOpen)==Int(EACCES) && modes().isEmpty,"foreign mixed open fails without partial grant")
    let opened: Error?=wait { v.openForTesting(item,modes:[.read,.write],caller:caller,reply:$0) }
    need(opened == nil && modes()==[.read,.write],"authorized open grants all modes only on success")
    let foreignExisting: Error?=wait { v.openForTesting(item,modes:[.read,.write],caller:foreign,reply:$0) }
    need(code(foreignExisting)==Int(EACCES) && modes()==[.read,.write],"failed foreign acquisition preserves existing writer grant")
    let written: (FSWriteFileResult?,Error?)=wait { done in v.write(contents:Data("changed!".utf8),to:item,at:0) { done(($0,$1)) } }
    need(written.0 != nil && written.1 == nil,"retained write admission uses shared real-core commit")
    let reduced: Error?=wait { v.closeForTesting(item,modes:.write,caller:foreign,reply:$0) }
    need(reduced == nil && modes() == .write,"different closing caller may reduce retained modes")
    let increased: Error?=wait { v.closeForTesting(item,modes:[.read,.write],caller:foreign,reply:$0) }
    need(code(increased)==Int(EINVAL) && modes() == .write,"close cannot add a mode")
    let readBack: Data=wait { done in v.enqueue { done(try! v.diagnosticReadForTesting(item,length:8)) } }
    need(readBack==Data("changed!".utf8),"existing contextless read remains usable for write-only retained mode")
    let readOpen: Error?=wait { v.openForTesting(item,modes:.read,caller:caller,reply:$0) }
    need(readOpen == nil && modes()==[.read,.write],"later authorized open unions modes")
    let readOnlyClose: Error?=wait { v.closeForTesting(item,modes:.read,caller:foreign,reply:$0) }
    need(readOnlyClose == nil && modes() == .read,"last write grant removed before later data")
    let durable = v.anchor
    let refused: (FSWriteFileResult?,Error?) = wait { done in v.write(contents:Data([1]),to:item,at:0) { done(($0,$1)) } }
    need(refused.0 == nil && code(refused.1)==Int(EACCES) && anchorMatches(v.anchor,durable),"write without retained write fails before mutation")
    let finalClose: Error?=wait { v.closeForTesting(item,modes:[],caller:foreign,reply:$0) }
    need(finalClose == nil && modes().isEmpty,"final close clears retained authority despite delivery failure")
#if STALLION_WRITE_DIAGNOSTIC
    need(v.diagnosticSnapshot().1.isEmpty,"production policy does not allocate diagnostic trace")
#endif
    let trace: [StallionVolume.Record]=wait { done in v.enqueue { done(v.capturedRecords()) } }
    need(trace.isEmpty,"nonfixture policy leaves optional trace empty")
    close(fs,v,active.0,found.0,expectedError:Int(EACCES))
    let reopened = fs
    let probe: (FSProbeResult?,Error?) = wait { done in reopened.probeResource(resource:resource) { done(($0,$1)) } }
    need(probe.1 == nil && probe.0?.containerID?.uuid==f.identity,"persistent container identity after commit")
    let again = load(reopened,["--rdonly"]);need(again.1 == nil,"read-only reopen after mutation")
    let rv = again.0 as! StallionVolume
    need(rv.volumeID.uuid==f.identity && anchorMatches(rv.anchor,durable),"reopened committed identity and generation")
    let reopenedRoot: (FSItem?,Error?) = wait { done in rv.activate { done(($0,$1)) } }
    need(reopenedRoot.1 == nil,"reopened activation")
    let reopenedMount: Error? = wait { rv.mount(arguments:[],replyHandler:$0) };need(reopenedMount == nil,"reopened mount")
    let persisted: (FSItem?,FSFileName?,Error?) = wait { done in rv.lookupItem(named:FSFileName(string:"created-no-grant"),inDirectory:reopenedRoot.0!) { done(($0,$1,$2)) } }
    need(persisted.0 != nil && persisted.2 == nil,"created entry persists through unload and reopen")
    close(reopened,rv,reopenedRoot.0,persisted.0)
    need(f.contents()==Data("changed!".utf8),"retained write persists through unload and reopen")
    let deniedFixture=try Fixture(parent,"access-policy-denied",mode:0o400)
    let deniedFS=makeFileSystem(), deniedResource=FSPathURLResource(url:deniedFixture.url,writable:true)
    let deniedLoad: (FSVolume?,Error?)=wait { done in deniedFS.loadResource(resource:deniedResource,arguments:[]) { done(($0,$1)) } }
    need(deniedLoad.1 == nil,"readonly inode in writable volume admitted")
    let deniedVolume=deniedLoad.0 as! StallionVolume
    let deniedRoot: (FSItem?,Error?)=wait { done in deniedVolume.activate { done(($0,$1)) } }
    let deniedMount: Error?=wait { deniedVolume.mount(arguments:[],replyHandler:$0) };need(deniedMount == nil,"denied-open model mount")
    let deniedFile: (FSItem?,FSFileName?,Error?)=wait { done in deniedVolume.lookupItem(named:FSFileName(string:"file"),inDirectory:deniedRoot.0!) { done(($0,$1,$2)) } }
    let readGranted: Error?=wait { deniedVolume.openForTesting(deniedFile.0!,modes:.read,caller:caller,reply:$0) };need(readGranted == nil,"read acquisition authorized")
    let mixed: Error?=wait { deniedVolume.openForTesting(deniedFile.0!,modes:[.read,.write],caller:caller,reply:$0) }
    let stillRead: FSVolume.OpenModes=wait { done in deniedVolume.enqueue { done(try! deniedVolume.retainedModesForTesting(deniedFile.0!)) } }
    need(code(mixed)==Int(EACCES) && stillRead == .read,"mixed-mode authorization failure retains exact old grant")
    let deniedClose: Error?=wait { deniedVolume.closeForTesting(deniedFile.0!,modes:[],caller:foreign,reply:$0) };need(deniedClose == nil,"read grant cleared")
    let _: Bool=wait { done in deniedVolume.unmount { done(true) } }
    let released: Error?=wait { deniedVolume.reclaimForTesting(deniedFile.0!,eligible:true,replyHandler:$0) };need(released == nil,"denied-open item reclaimed")
    let deactivated: Error?=wait { deniedVolume.deactivate(options:[],replyHandler:$0) };need(deactivated == nil,"denied-open model deactivated")
    let deniedUnload: Error?=wait { deniedFS.unloadResource(resource:deniedResource,replyHandler:$0) };need(deniedUnload == nil,"denied-open model consumed")
    need(deniedFixture.contents()==Data("original".utf8),"denied opens preserve file bytes")
    let partial=try Fixture(parent,"access-policy-partial",mode:0o200)
    let partialFS=makeFileSystem(), partialResource=FSPathURLResource(url:partial.url,writable:true)
    let partialLoad: (FSVolume?,Error?)=wait { done in partialFS.loadResource(resource:partialResource,arguments:[]) { done(($0,$1)) } };need(partialLoad.1 == nil,"partly authorized fixture load")
    let partialVolume=partialLoad.0 as! StallionVolume
    let partialRoot: (FSItem?,Error?)=wait { done in partialVolume.activate { done(($0,$1)) } }
    let partialMount: Error?=wait { partialVolume.mount(arguments:[],replyHandler:$0) };need(partialMount == nil,"partly authorized model mount")
    let partialFile: (FSItem?,FSFileName?,Error?)=wait { done in partialVolume.lookupItem(named:FSFileName(string:"file"),inDirectory:partialRoot.0!) { done(($0,$1,$2)) } }
    let writeCheck: (FSCheckAccessResult?,Error?)=wait { done in partialVolume.accessForTesting(partialFile.0!,access:.writeData,caller:caller) { done(($0,$1)) } }
    need(writeCheck.0 != nil && writeCheck.1 == nil,"write part independently authorized")
    let partialOpen: Error?=wait { partialVolume.openForTesting(partialFile.0!,modes:[.read,.write],caller:caller,reply:$0) }
    let partialModes: FSVolume.OpenModes=wait { done in partialVolume.enqueue { done(try! partialVolume.retainedModesForTesting(partialFile.0!)) } }
    need(code(partialOpen)==Int(EACCES) && partialModes.isEmpty,"failed read check after successful write check never publishes partial grant")
    let _: Bool=wait { done in partialVolume.unmount { done(true) } }
    let partialRelease: Error?=wait { partialVolume.reclaimForTesting(partialFile.0!,eligible:true,replyHandler:$0) };need(partialRelease == nil,"partly authorized item reclaimed")
    let partialDeactivate: Error?=wait { partialVolume.deactivate(options:[],replyHandler:$0) };need(partialDeactivate == nil,"partly authorized model deactivated")
    let partialClose: Error?=wait { partialFS.unloadResource(resource:partialResource,replyHandler:$0) };need(partialClose == nil,"partly authorized model consumed")
    need(partial.contents()==Data("original".utf8),"partly authorized open preserves bytes")
    let other = try Fixture(parent,"access-policy-other")
    need(other.identity != f.identity,"independent image has its own stored identity")
    let otherFS=makeFileSystem(), otherResource=FSPathURLResource(url:other.url,writable:true)
    let otherReply: (FSVolume?,Error?)=wait { done in otherFS.loadResource(resource:otherResource,arguments:[]) { done(($0,$1)) } }
    need(otherReply.1 == nil && (otherReply.0 as! StallionVolume).volumeID.uuid==other.identity,"second image needs no fixture-specific rebuild")
    let otherVolume=otherReply.0 as! StallionVolume
    let otherRoot: (FSItem?,Error?)=wait { done in otherVolume.activate { done(($0,$1)) } }
    let otherMount: Error?=wait { otherVolume.mount(arguments:[],replyHandler:$0) };need(otherMount == nil,"second image model mount")
    let otherFile: (FSItem?,FSFileName?,Error?)=wait { done in otherVolume.lookupItem(named:FSFileName(string:"file"),inDirectory:otherRoot.0!) { done(($0,$1,$2)) } }
    let otherBefore=otherVolume.anchor
    let neverOpened: (FSWriteFileResult?,Error?)=wait { done in otherVolume.write(contents:Data([1]),to:otherFile.0!,at:0) { done(($0,$1)) } }
    need(neverOpened.0 == nil && code(neverOpened.1)==Int(EACCES) && anchorMatches(otherVolume.anchor,otherBefore),"lookup alone cannot authorize data write")
    let _: Bool=wait { done in otherVolume.unmount { done(true) } }
    let otherRelease: Error?=wait { otherVolume.reclaimForTesting(otherFile.0!,eligible:true,replyHandler:$0) };need(otherRelease == nil,"unopened item reclaimed after refusal")
    let otherDeactivate: Error?=wait { otherVolume.deactivate(options:[],replyHandler:$0) };need(code(otherDeactivate)==Int(EACCES),"never-opened failure retained through deactivate")
    let otherClose: Error?=wait { otherFS.unloadResource(resource:otherResource,replyHandler:$0) };need(code(otherClose)==Int(EACCES),"second image consuming close preserves first delivery failure")
    need(other.contents()==Data("original".utf8),"never-opened data write leaves bytes unchanged")
#else
    need(reply.0 == nil && code(reply.1)==Int(ENOTSUP),"missing contextual mutation build cannot enable production policy")
#endif
}

#if STALLION_WRITE_DIAGNOSTIC
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
        volume = StallionVolume(admission: .forTesting(handle: h!, anchor: r, writable: writable), resource: resource, scope: false, queue: DispatchQueue(label: "sfs.write.test"), itemLimit: itemLimit)
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
    need(code(refused) == Int(EROFS) && code(xattrRefused) == Int(EROFS), "contextless and pure refusal paths remain read-only")
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
    let volume = StallionVolume(admission: .forTesting(handle: h!, anchor: r, writable: true), resource: FSPathURLResource(url: allocation.url, writable: true), scope: false, queue: DispatchQueue(label: "sfs.pin.allocation"))
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
func checkPreparedAttributes(_ a: FSItem.Attributes, _ m: sfs_metadata_entry, required: FSItem.Attribute, exact: Bool = false, retainedParent: UInt64? = nil) {
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
    if a.isValid(.parentID) {
        if m.link_count > 0 { need(a.parentID == (m.entry.inode == 1 ? .parentOfRoot : try! itemIdentifier(m.entry.parent)), "current namespace parent identifier") }
        else { need(retainedParent != nil && a.parentID == (try! itemIdentifier(retainedParent!)), "verified retained parent identifier distinct from detached core metadata") }
    }
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

#if STALLION_CONTEXT_HANDLERS
func creationAttributes(_ mode: UInt32 = 0o600) -> FSItem.SetAttributesRequest {
    let request = FSItem.SetAttributesRequest(); request.mode = mode; request.uid = geteuid(); request.gid = getegid(); return request
}
// Fresh real metadata fixtures, independent of the existing-file helper's operands.
final class CreationMount {
    let url: URL, volume: StallionVolume, resource: FSPathURLResource, coreHandle: OpaquePointer
    let root: FSItem
    var directory: FSItem?, returned: [FSItem] = []
    init(_ parent: URL, _ name: String, capacity: UInt64 = 1024 * 1024, directory: Bool = false,
         rootMode: UInt32 = 0o700, rootFlags: UInt32 = 0, rootOwner: uid_t = geteuid(), acl: Bool = false,
         writable: Bool = true, enable: Bool = true, limit: Int = 4) throws {
        fault(0,0); url = parent.appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        var h: OpaquePointer?, r = sfs_result(), initial = sfs_metadata_initial(), inode: UInt64 = 0
        initial.mode = UInt32(S_IFDIR) | rootMode; initial.uid = rootOwner; initial.gid = getegid(); initial.flags = rootFlags
        need(sfs_image_create_metadata_version(url.path,"image.sfs",capacity,6,&initial,&h,&r) == SFS_OK,"creation fixture")
        if directory || acl {
            need(sfs_image_begin(h,&r) == SFS_OK,"creation fixture begin")
            if directory {
                initial.mode = UInt32(S_IFDIR) | 0o700; initial.uid = geteuid(); initial.flags = 0
                need(sfs_image_add_metadata(h,1,"dir",3,SFS_DIRECTORY,&initial,&inode,&r) == SFS_OK,"existing creation parent")
            }
            if acl { need(sfs_image_set_xattr(h,1,"com.apple.system.Security",25,nil,0,&r) == SFS_OK,"creation parent ACL") }
            need(sfs_image_commit(h,&r) == SFS_OK,"creation fixture commit")
        }
        let identity = uuid(r)
        need(sfs_image_close(h,&r) == SFS_OK,"creation producer close")
        let status = writable ? sfs_image_open(url.path,"image.sfs",&h,&r) : sfs_image_open_readonly(url.path,"image.sfs",&h,&r)
        need(status == SFS_OK,"creation fixture open"); coreHandle = h!
        resource = FSPathURLResource(url:url,writable:writable)
        volume = StallionVolume(admission:.forTesting(handle:h!,anchor:r,writable:writable),resource:resource,scope:false,queue:DispatchQueue(label:"sfs.create.test"),itemLimit:limit)
        let v = volume
        if writable && enable { try v.enableWriteDiagnostic(expectedUUID:identity) }
        let activation: (FSItem?,Error?) = wait { done in v.activate { done(($0,$1)) } }
        need(activation.1 == nil && activation.0 != nil,"create activation"); root = activation.0!
        let mounted: Error? = wait { v.mount(arguments:[],replyHandler:$0) }; need(mounted == nil,"create mount")
        if directory { self.directory = lookup("dir"); returned.append(self.directory!) }
    }
    func serial(_ body: @escaping () -> Void) { let _: Bool = wait { done in volume.enqueue { body(); done(true) } } }
    func lookup(_ name: String, parent: FSItem? = nil) -> FSItem {
        let found: (FSItem?,Error?) = wait { done in volume.lookupItem(named:FSFileName(string:name),inDirectory:parent ?? root) { done(($0,$2)) } }
        need(found.1 == nil && found.0 != nil,"created lookup error=\(code(found.1))"); return found.0!
    }
    func create(_ name: String = "new", request: FSItem.SetAttributesRequest? = nil, parent: FSItem? = nil,
                type: FSItem.ItemType = .file, caller: CallerIdentity? = nil) -> (FSCreateItemResult?,Error?,StallionItem?) {
        let a = request ?? creationAttributes(); var item: StallionItem?
        var prior: ((String,StallionItem?) throws -> Void)?
        serial {
            prior = self.volume.createStageForTesting
            self.volume.createStageForTesting = { stage,value in
                if stage == "inserted" { item = value }
                try prior?(stage,value)
            }
        }
        let result: (FSCreateItemResult?,Error?) = wait { done in volume.createResultForTesting(FSFileName(string:name),type:type,
            directory:parent ?? root,attributes:a,caller:caller ?? CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { done(($0,$1)) } }
        serial { self.volume.createStageForTesting = prior }
        if result.0 != nil, let item { returned.append(item) }
        return (result.0,result.1,result.0 == nil ? nil : item)
    }
    func metadata(_ item: FSItem) -> sfs_metadata_entry {
        var m = sfs_metadata_entry()
        serial { var r = sfs_result(); need(sfs_image_stat_metadata(self.coreHandle,0,(item as! StallionItem).inode,&m,&r) == SFS_OK,"created metadata") }
        return m
    }
    func absent(_ name: String = "new") {
        serial { var entry = sfs_entry(), r = sfs_result(); let bytes = Data(name.utf8)
            need(bytes.withUnsafeBytes { sfs_image_lookup(self.coreHandle,0,1,$0.baseAddress,$0.count,&entry,&r) } == SFS_NOT_FOUND,"unpublished create absent")
        }
    }
    func state(_ count: Int, cap: Int = 4) {
        serial {
            let state = self.volume.createStateForTesting
            need(!state.pending && !state.quarantine && state.ticket == 0 && self.volume.activeItemCount() == count,"published/clean pending and map accounting")
            // Count the remaining real slots without trusting an adapter counter.
            var reservations: [sfs_pin] = [], r = sfs_result()
            for _ in 0..<(cap - count) { var pin = sfs_pin(); need(sfs_image_pin_reserve(self.coreHandle,&pin,&r) == SFS_OK,"expected free pin slot"); reservations.append(pin) }
            var extra = sfs_pin()
            need(sfs_image_pin_reserve(self.coreHandle,&extra,&r) == SFS_LIMIT && r.limit_reason == SFS_LIMIT_PIN_RESOURCES,"exact live pin count")
            for pin in reservations { need(sfs_image_pin_release(self.coreHandle,pin,&r) == SFS_OK,"release accounting probe reservation") }
        }
        let charge = volume.linkBudgetForTesting; need(charge.0 == 0 && charge.1 == 0,"create callback charge released")
    }
    func reclaim(_ item: FSItem) -> Error? { wait { volume.reclaimForTesting(item,eligible:true,replyHandler:$0) } }
    func close() {
        fault(0,0)
        let _: Bool = wait { done in volume.unmount { done(true) } }
        if volume.diagnosticWritable {
            for item in returned {
                var owned = false; serial { owned = self.volume.ownsForTesting(item) }
                if owned { _ = reclaim(item) } // A terminal transaction can make memory release BUSY.
            }
            let _: Error? = wait { volume.deactivate(options:[],replyHandler:$0) }
        }
        serial { need(self.volume.unload().consumed,"creation consume-close"); need(!self.volume.createStateForTesting.pending,"close clears quarantine") }
    }
    func reopened(_ name: String = "new", parent: UInt64 = 1, inode: UInt64?, bytes expectedBytes: Data? = nil) {
        fault(0,0); var h: OpaquePointer?, r = sfs_result(), entry = sfs_entry()
        need(sfs_image_open_readonly(url.path,"image.sfs",&h,&r) == SFS_OK,"creation reopen")
        let bytes = Data(name.utf8), status = bytes.withUnsafeBytes { sfs_image_lookup(h,0,parent,$0.baseAddress,$0.count,&entry,&r) }
        if let inode { need(status == SFS_OK && entry.inode == inode,"durable created identity") }
        else { need(status == SFS_NOT_FOUND,"reopened nonpublication") }
        if let expectedBytes, let inode {
            var bytes = Data(count:expectedBytes.count), count = 0
            need(bytes.withUnsafeMutableBytes { sfs_image_read(h,0,inode,0,$0.baseAddress,$0.count,&count,&r) } == SFS_OK && count == expectedBytes.count && bytes == expectedBytes,"reopened created data")
        }
        need(sfs_image_close(h,&r) == SFS_OK,"creation reopened close")
    }
}
func contextualCreates(_ parent: URL) throws {
    let required = FSCreateItemResult.requestedAttributes.wantedAttributes
#if STALLION_RESULT_MASK_TRACE
    let raw = UInt(bitPattern:required.rawValue)
    resultMaskTrace("FSCreateItemResult original=0x\(String(raw,radix:16)) outside_caller_readable=0x\(String(raw & ~UInt(0x3fff),radix:16)) explicit=0x0")
#endif
    let m = try CreationMount(parent,"create-reuse",directory:true), v = m.volume
    m.state(2)
    var snapshots: [FSItem.Attributes] = [], committed = false, constructors = 0
    m.serial {
        v.createStageForTesting = { stage,item in if stage == "inserted" {
            need(item != nil && v.createVisibilityForTesting(item!),"pending item hidden from both canonical return paths")
        } }
        v.preparedAttributesForTesting = { name,a in if name == "FSCreateItemResult" { need(!committed,"create snapshot precommit"); snapshots.append(a) } }
        v.rejectResultForTesting = { name in if name == "FSCreateItemResult" { need(snapshots.count == 2 && !committed,"real create constructor precommit"); constructors += 1 }; return false }
        v.diagnosticBeforeCommit = { committed = true }
    }
    let a = creationAttributes(); a.size = 0; a.flags = 0
    let first = m.create("first",request:a)
    need(first.0 != nil && first.1 == nil && first.2 != nil,"actual create result error=\(code(first.1)) item=\(first.2 != nil) roles=\(snapshots.count) constructors=\(constructors) commitAttempted=\(v.createOutcomeForTesting.commitAttempted) committed=\(v.createOutcomeForTesting.commitSucceeded)")
    need(a.consumedAttributes == [.mode,.uid,.gid,.size,.flags] && constructors == 1,"exact successful creation consumption")
    let firstItem = first.2!, firstPin = firstItem.pin!, firstMetadata = m.metadata(firstItem), firstParent = m.metadata(m.root), retained = snapshots
    checkPreparedAttributes(retained[0],firstMetadata,required:required); checkPreparedAttributes(retained[1],firstParent,required:required)
    need(firstMetadata.mode == UInt32(S_IFREG) | 0o600 && firstMetadata.entry.size == 0 && firstMetadata.link_count == 1 && firstMetadata.uid == geteuid() && firstMetadata.gid == getegid() && firstMetadata.flags == 0,"truthful empty child")
    m.state(3)
    m.serial { v.diagnosticBeforeCommit = nil; v.rejectResultForTesting = nil; v.preparedAttributesForTesting = nil }
    let linked: (FSCreateLinkResult?,Error?) = wait { done in v.linkResultForTesting(firstItem,name:FSFileName(string:"first-alias"),directory:m.root,
        caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { done(($0,$1)) } }
    need(linked.0 != nil && linked.1 == nil && m.lookup("first-alias") === firstItem,"first alias remains canonical")
    let written: (Int,Error?) = wait { done in v.writeCountForTesting(contents:Data("created".utf8),to:firstItem,at:0) { done(($0,$1)) } }
    need(written.0 == 7 && written.1 == nil,"new item uses existing write path")
    let resize = FSItem.SetAttributesRequest(); resize.size = 9
    let resized: (FSItem.Attributes?,Error?) = wait { done in v.setAttributesValueForTesting(resize,on:firstItem,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { done(($0,$1)) } }
    need(resized.0 != nil && resized.1 == nil && resize.consumedAttributes == [.size],"new item uses existing resize path")
    snapshots = []
    m.serial { v.preparedAttributesForTesting = { name,a in if name == "FSCreateItemResult" { snapshots.append(a) } } }
    let b = creationAttributes(UInt32(S_IFREG) | 0o640), second = m.create("second",request:b,parent:m.directory)
    need(second.0 != nil && second.1 == nil && second.2 != nil && b.consumedAttributes == [.mode,.uid,.gid],"second same-mount create error=\(code(second.1))")
    let secondItem = second.2!, secondID = secondItem.inode, secondPin = secondItem.pin!, parentID = (m.directory as! StallionItem).inode
    need(secondItem !== firstItem && secondID != firstItem.inode && m.metadata(secondItem).mode == UInt32(S_IFREG) | 0o640,"distinct real created identity and normalized full mode")
    checkPreparedAttributes(snapshots[0],m.metadata(secondItem),required:required); checkPreparedAttributes(snapshots[1],m.metadata(m.directory!),required:required)
    m.state(4)
    let fullAnchor = v.anchor, full = m.create("full")
    need(full.0 == nil && code(full.1) == Int(ENFILE) && anchorMatches(fullAnchor,v.anchor),"create item capacity preflight")
    m.state(4); need(m.reclaim(secondItem) == nil,"reclaim second created item"); m.state(3)
    snapshots = []
    let third = m.create("third",parent:m.directory)
    need(third.0 != nil && third.1 == nil && third.2 != nil,"third same-mount create error=\(code(third.1))")
    let thirdItem = third.2!
    need(thirdItem !== firstItem && thirdItem !== secondItem && thirdItem.inode != firstItem.inode && thirdItem.inode != secondID && thirdItem.pin!.slot == secondPin.slot && thirdItem.pin!.incarnation > secondPin.incarnation,"reclaim reuses only the slot with a fresh token and distinct inode/object")
    checkPreparedAttributes(snapshots[0],m.metadata(thirdItem),required:required); checkPreparedAttributes(snapshots[1],m.metadata(m.directory!),required:required)
    m.state(4)
    need(m.lookup("first") === firstItem && m.lookup("first-alias") === firstItem && sameBytes(firstPin,firstItem.pin!),"first aliases survive consecutive creates/reclaim")
    m.serial { need((try! v.diagnosticReadForTesting(firstItem,length:9)) == Data("created".utf8) + Data([0,0]),"first bytes survive creation state reuse") }
    checkPreparedAttributes(retained[0],firstMetadata,required:required); checkPreparedAttributes(retained[1],firstParent,required:required)
    withExtendedLifetime(first.0) {}
    m.close(); m.reopened("first",inode:firstItem.inode,bytes:Data("created".utf8) + Data([0,0])); m.reopened("first-alias",inode:firstItem.inode)
    m.reopened("second",parent:parentID,inode:secondID); m.reopened("third",parent:parentID,inode:thirdItem.inode)
    try creationRefusals(parent)
    try creationFailures(parent,required:required)
    try creationDelivery(parent)
}
func creationRefusals(_ parent: URL) throws {
    let m = try CreationMount(parent,"create-refusals"), v = m.volume, before = v.anchor
    let unsupported: [(FSItem.Attribute,(FSItem.SetAttributesRequest)->Void)] = [
        (.type,{$0.type = .file}),(.linkCount,{$0.linkCount = 1}),(.allocSize,{$0.allocSize = 0}),
        (.fileID,{$0.fileID = FSItem.Identifier(rawValue:3)!}),(.parentID,{$0.parentID = FSItem.Identifier(rawValue:2)!}),
        (.accessTime,{$0.accessTime = timespec(tv_sec:1,tv_nsec:0)}),(.modifyTime,{$0.modifyTime = timespec(tv_sec:1,tv_nsec:0)}),
        (.changeTime,{$0.changeTime = timespec(tv_sec:1,tv_nsec:0)}),(.birthTime,{$0.birthTime = timespec(tv_sec:1,tv_nsec:0)}),
        (.backupTime,{$0.backupTime = timespec(tv_sec:1,tv_nsec:0)}),(.addedTime,{$0.addedTime = timespec(tv_sec:1,tv_nsec:0)})]
    for (field,set) in unsupported {
        let a = creationAttributes(); set(a); need(a.isValid(field),"construct explicit unsupported creation field")
        let result = m.create(request:a)
        need(result.0 == nil && code(result.1) == Int(ENOTSUP) && a.consumedAttributes.isEmpty,"atomic unsupported creation request")
    }
    for missing in 0..<3 {
        let a = FSItem.SetAttributesRequest(); if missing != 0 { a.mode = 0o600 }; if missing != 1 { a.uid = geteuid() }; if missing != 2 { a.gid = getegid() }
        need(code(m.create(request:a).1) == Int(ENOTSUP) && a.consumedAttributes.isEmpty,"missing required creation field")
    }
    for (mode,expected) in [(UInt32(0o4600),ENOTSUP),(UInt32(S_IFDIR) | 0o700,EINVAL),(UInt32(1)<<31,ENOTSUP)] {
        need(code(m.create(request:creationAttributes(mode)).1) == Int(expected),"unsupported/conflicting creation mode")
    }
    for field in [FSItem.Attribute.flags,.size,.uid,.gid] {
        let a = creationAttributes()
        if field == .flags { a.flags = 1 }; if field == .size { a.size = 1 }; if field == .uid { a.uid = geteuid() + 1 }; if field == .gid { a.gid = getegid() + 1 }
        need(code(m.create(request:a).1) == Int(field == .uid || field == .gid ? EACCES : ENOTSUP) && a.consumedAttributes.isEmpty,"unsupported value without mutation")
    }
    for type in [FSItem.ItemType.symlink] { need(code(m.create(type:type).1) == Int(ENOTSUP),"other creation types refused") }
    for name in ["", ".", "..", "bad/name", String(repeating:"n",count:256)] {
        need(code(m.create(name).1) == Int(name.utf8.count > 255 ? ENAMETOOLONG : EINVAL),"invalid create component")
    }
    for caller in [CallerIdentity(uid:-1,gid:Int(getegid())),CallerIdentity(uid:Int(geteuid()),gid:-1),CallerIdentity(uid:Int(geteuid()) + 1,gid:Int(getegid()))] {
        need(code(m.create(caller:caller).1) == Int(EACCES),"actual caller value admission")
    }
    need(anchorMatches(v.anchor,before),"all attribute refusals precede mutation"); m.state(1); m.absent()
    let created = m.create("exists"), acknowledged = v.anchor
    need(created.0 != nil && created.1 == nil,"valid create after preflight refusals")
    need(code(m.create("exists").1) == Int(EEXIST) && anchorMatches(acknowledged,v.anchor),"EEXIST before reservation/begin")
    need(code(m.create(parent:created.2!).1) == Int(ENOTDIR),"non-directory parent")
    need(code(m.create(parent:StallionItem(1)).1) == Int(EINVAL),"foreign canonical parent")
    need(m.reclaim(created.2!) == nil && code(m.create(parent:created.2!).1) == Int(EINVAL),"reclaimed parent identity refused")
    m.state(1); m.close(); m.reopened(inode:nil); m.reopened("exists",inode:created.2!.inode)
    for spec in 0..<7 {
        let policy = try CreationMount(parent,"create-policy-\(spec)",rootMode:spec == 0 ? 0o500 : spec == 1 ? 0o1700 : 0o700,
            rootFlags:spec == 2 ? 1 : 0,rootOwner:spec == 3 ? geteuid() + 1 : geteuid(),acl:spec == 4,
            writable:spec != 5,enable:spec != 6)
        let error = policy.create().1
        need(code(error) == Int(spec == 2 || spec == 4 ? ENOTSUP : spec >= 5 ? EROFS : EACCES),"parent policy/write gate")
        policy.close(); policy.reopened(inode:nil)
    }
    let revoked = try CreationMount(parent,"create-revoked"), revokedAnchor = revoked.volume.anchor
    revoked.resource.revoke()
    need(code(revoked.create().1) == Int(EACCES) && anchorMatches(revokedAnchor,revoked.volume.anchor),"revocation before create reservation")
    revoked.close(); revoked.reopened(inode:nil)
    let readonly = try CreationMount(parent,"create-read-mode")
    let result = readonly.create(request:creationAttributes(0o400))
    need(result.0 != nil && result.1 == nil && result.2 != nil,"initial read-only mode is honored")
    let written: (Int,Error?) = wait { done in readonly.volume.writeCountForTesting(contents:Data([1]),to:result.2!,at:0) { done(($0,$1)) } }
    need(written.0 == 0 && code(written.1) == Int(EACCES),"new file owner write permission enforced"); readonly.close(); readonly.reopened(inode:result.2!.inode)
}
func creationFailures(_ parent: URL, required: FSItem.Attribute) throws {
    for stage in ["reserved","before-add","added","allocated","bound","inserted"] {
        let m = try CreationMount(parent,"create-stage-\(stage)"), v = m.volume, before = v.anchor
        weak var unreturned: StallionItem?
        m.serial { v.createStageForTesting = { point,item in if point == stage { unreturned = item; throw POSIXError(.ENOMEM) } } }
        let a = creationAttributes(), result = m.create(request:a)
        need(result.0 == nil && code(result.1) == Int(ENOMEM) && a.consumedAttributes.isEmpty && anchorMatches(before,v.anchor),"creation stage rollback \(stage)")
        let outcome = v.createOutcomeForTesting
        need(outcome.releaseAttempted == (stage == "reserved") && outcome.discarded == (stage != "reserved") && !outcome.commitSucceeded,"stage-specific pin cleanup")
        m.serial { need(unreturned == nil,"unreturned failed item not retained") }
        m.state(1); m.absent(); m.close(); m.reopened(inode:nil)
    }
    need(!required.isEmpty,"actual creation result requirements")
    for role in 0..<2 {
        let m = try CreationMount(parent,"create-incomplete-\(role)"), v = m.volume; var seen = 0, constructed = false
        m.serial {
            v.preparedAttributesForTesting = { name,a in if name == "FSCreateItemResult" { if seen == role { a.invalidateAllProperties() }; seen += 1 } }
            v.rejectResultForTesting = { _ in constructed = true; return false }
        }
        let result = m.create()
        need(result.0 == nil && code(result.1) == Int(ENOTSUP) && seen == role + 1 && !constructed,"each role completeness before actual constructor")
        m.state(1); m.absent(); m.close(); m.reopened(inode:nil)
    }
    for scenario in 0..<7 {
        let m = try CreationMount(parent,"create-failure-\(scenario)"), v = m.volume, before = v.anchor; var constructor = false
        m.serial {
            if scenario == 0 { v.rejectResultForTesting = { name in if name == "FSCreateItemResult" { constructor = true; return true }; return false } }
            if scenario == 1 { v.diagnosticBeforeCommit = { m.resource.revoke() } }
            if scenario == 2 { v.diagnosticBeforeCommit = { sfs_image_clear_read_cache(m.coreHandle); fault(7,1) } }
            if scenario == 6 { v.createCommitReceiptForTesting = { $0.fence_succeeded = 0 } }
        }
        if scenario == 3 { fault(1,1) }; if scenario == 4 || scenario == 5 { fault(4,Int32(scenario - 3)) }
        let a = creationAttributes(), result = m.create(request:a), outcome = v.createOutcomeForTesting
        let expected = scenario == 1 ? EACCES : scenario == 2 ? ENOMEM : (3...5).contains(scenario) ? ENOSPC : EIO
        need(result.0 == nil && code(result.1) == Int(expected) && a.consumedAttributes.isEmpty && anchorMatches(before,v.anchor),"create failure scenario \(scenario) actual=\(code(result.1))")
        if scenario == 0 { need(constructor,"real failable constructor exercised before rejection") }
        if (2...5).contains(scenario) { need(hits() > 0,"actual core fault reached") }
        if scenario == 6 {
            need(outcome.commitSucceeded && outcome.commit.status == SFS_OK && outcome.commit.fence_succeeded == 3 && !outcome.abortAttempted && outcome.releaseAttempted && outcome.release.status == SFS_OK && v.diagnosticSnapshot().0.commitSuccess == 1,"promoted pin release and actual fence accounting after rejected successful receipt")
        } else { need(outcome.discarded && !outcome.releaseAttempted && !outcome.commitSucceeded,"discarded reservation never released again") }
        if scenario == 4 { need(outcome.original.status == SFS_IO && outcome.original.fence_attempted == 1,"first fence known failure receipt") }
        if scenario == 5 { need(outcome.original.status == SFS_OUTCOME_UNKNOWN && outcome.original.fence_attempted == 3,"unknown publication receipt preserved") }
        fault(0,0)
        if scenario < 3 { m.state(1); m.absent() }
        let token = v.createTokenForTesting!
        if scenario == 6 { m.serial { var r = sfs_result(), value = sfs_pin_stat(); need(sfs_image_pin_stat(m.coreHandle,token,&value,&r) == SFS_INVALID,"promoted never-returned token was already released") } }
        m.close()
        if scenario == 6 { m.reopened(inode:2) }
        else if scenario != 5 { m.reopened(inode:nil) } // Unknown publication is never called absence.
    }
    for capacity in [UInt64(16384),UInt64(20480)] {
        let m = try CreationMount(parent,"create-limit-\(capacity)",capacity:capacity,limit:2), v = m.volume
        m.serial { var info = sfs_image_information(), r = sfs_result()
            need(sfs_image_get_information(m.coreHandle,&info,&r) == SFS_OK && r.committed_end == 16384 && info.append_headroom == capacity - 16384,"real root-only capacity setup")
        }
        let result = m.create(), outcome = v.createOutcomeForTesting
        need(result.0 == nil && code(result.1) == Int(ENOSPC) && outcome.original.status == SFS_LIMIT,"actual append limit")
        need(outcome.beginAttempted && outcome.beginSucceeded == (capacity == 20480) && outcome.discarded == (capacity == 20480) && outcome.releaseAttempted == (capacity == 16384),"begin LIMIT retains versus mutation LIMIT discards")
        m.state(1,cap:2); m.absent(); m.close(); m.reopened(inode:nil)
    }
    let fatal = try CreationMount(parent,"create-begin-discard"), path = fatal.url.appendingPathComponent("image.sfs").path
    fatal.serial { fatal.volume.createStageForTesting = { stage,_ in if stage == "reserved" { need(chmod(path,0o400) == 0,"owned fixture identity failure setup") } } }
    let failed = fatal.create(), outcome = fatal.volume.createOutcomeForTesting
    need(chmod(path,0o600) == 0,"restore owned fixture mode")
    need(failed.0 == nil && code(failed.1) == Int(EINVAL) && outcome.beginAttempted && !outcome.beginSucceeded && outcome.discarded && !outcome.releaseAttempted,"begin read failure discards live reservation")
    fatal.close(); fatal.reopened(inode:nil)
    let exhausted = try CreationMount(parent,"create-pin-exhaustion"), e = exhausted.volume
    var heldPins: [sfs_pin] = []
    exhausted.serial { var r = sfs_result(); for _ in 0..<3 { var pin = sfs_pin(); need(sfs_image_pin_reserve(exhausted.coreHandle,&pin,&r) == SFS_OK,"occupy actual core slots"); heldPins.append(pin) } }
    need(code(exhausted.create().1) == Int(ENFILE) && !e.createOutcomeForTesting.beginAttempted && !e.createOutcomeForTesting.releaseAttempted,"core pin failure with free adapter capacity")
    exhausted.serial { var r = sfs_result(); for pin in heldPins { need(sfs_image_pin_release(exhausted.coreHandle,pin,&r) == SFS_OK,"release separately owned reservations") } }
    exhausted.state(1); exhausted.close(); exhausted.reopened(inode:nil)
    let quarantine = try CreationMount(parent,"create-release-quarantine"), q = quarantine.volume
    var releases = 0
    quarantine.serial {
        q.createStageForTesting = { stage,_ in if stage == "reserved" { throw POSIXError(.ENOMEM) } }
        q.createReleaseForTesting = { _,_,r in releases += 1; r.status = SFS_BUSY; return SFS_BUSY }
    }
    need(code(quarantine.create().1) == Int(ENOMEM),"primary error survives synthetic release BUSY")
    quarantine.serial { let state = q.createStateForTesting; need(state.pending && state.quarantine && state.ticket == 1 && q.activeItemCount() == 1 && releases == 1,"bounded token-only release quarantine") }
    need(code(quarantine.create("later").1) == Int(ENOMEM) && releases == 1,"no automatic retry after quarantine")
    quarantine.close(); quarantine.reopened(inode:nil)
}
func creationDelivery(_ parent: URL) throws {
    let saturated = try CreationMount(parent,"create-saturation"), enteredFull = DispatchSemaphore(value:0), resumeFull = DispatchSemaphore(value:0), drained = DispatchGroup()
    saturated.volume.enqueue { enteredFull.signal(); need(resumeFull.wait(timeout:.now()+20) == .success,"resume saturated creation queue") }
    need(enteredFull.wait(timeout:.now()+20) == .success,"hold saturated creation queue")
    for _ in 0..<ReadOnlyLimits.callbacks { drained.enter(); saturated.volume.enqueue(rejected:{ _ in need(false,"fill creation budget") }) { drained.leave() } }
    let refused: (FSCreateItemResult?,Error?) = wait { done in saturated.volume.createResultForTesting(FSFileName(string:"new"),directory:saturated.root,attributes:creationAttributes(),caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { done(($0,$1)) } }
    need(refused.0 == nil && code(refused.1) == Int(EAGAIN) && saturated.volume.linkBudgetForTesting.0 == ReadOnlyLimits.callbacks,"saturated create admission adds no ticket")
    resumeFull.signal(); need(drained.wait(timeout:.now()+20) == .success,"drain saturation")
    saturated.state(1); saturated.close(); saturated.reopened(inode:nil)
    for quarantine in [false,true] {
        let m = try CreationMount(parent,"create-queued-\(quarantine)",directory:quarantine), v = m.volume, before = v.anchor
        let entered = DispatchSemaphore(value:0), resume = DispatchSemaphore(value:0), replies = DispatchGroup()
        var preflights = 0, cleared = false
        weak var unreturned: StallionItem?
        v.enqueue {
            v.createStageForTesting = { stage,item in if stage == "preflight" { preflights += 1 }; if stage == "inserted" { unreturned = item; throw POSIXError(.ENOMEM) } }
            if quarantine { v.createAbortForTesting = { _,r in r.status = SFS_IO; r.transaction_active = 1; r.system_errno = EIO; return SFS_IO } }
            entered.signal(); need(resume.wait(timeout:.now()+20) == .success,"resume create queue")
        }
        need(entered.wait(timeout:.now()+20) == .success,"hold create queue")
        let first = creationAttributes(), next = creationAttributes(), caller = CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))
        replies.enter(); v.createResultForTesting(FSFileName(string:"first"),directory:m.root,attributes:first,caller:caller) { result,error in
            need(result == nil && code(error) == Int(ENOMEM),"first create primary failure")
            v.createStageForTesting = nil; v.createAbortForTesting = nil; cleared = true; replies.leave()
        }
        replies.enter(); v.createResultForTesting(FSFileName(string:"next"),directory:m.root,attributes:next,caller:caller) { result,error in
            need(cleared && result == nil && code(error) == Int(ENOMEM),"queued create preserves earlier error after injection cleared"); replies.leave()
        }
        let charged = v.linkBudgetForTesting
        need(charged.0 == 2 && charged.1 == 2 * ReadOnlyLimits.callbackOverhead + 9,"both create callbacks admitted before failure")
        resume.signal(); need(replies.wait(timeout:.now()+20) == .success,"drain create replies")
        m.serial {
            let state = v.createStateForTesting
            need(preflights == 1 && first.consumedAttributes.isEmpty && next.consumedAttributes.isEmpty && anchorMatches(before,v.anchor),"queued guard before second reservation/begin")
            need(state.pending == quarantine && state.quarantine == quarantine && state.ticket == (quarantine ? 1 : 0) && v.activeItemCount() == (quarantine ? 2 : 1) && unreturned == nil,"no unpublished object retention or double ticket")
            if quarantine { need(v.createOutcomeForTesting.cleanup.status == SFS_IO && !v.createOutcomeForTesting.discarded,"synthetic unresolved abort evidence retained") }
        }
        let held = DispatchSemaphore(value:0), release = DispatchSemaphore(value:0)
        v.enqueue { held.signal(); need(release.wait(timeout:.now()+20) == .success,"release failed create queue") }
        need(held.wait(timeout:.now()+20) == .success,"hold already failed queue")
        let refused: (FSCreateItemResult?,Error?) = wait { done in v.createResultForTesting(FSFileName(string:"again"),directory:m.root,attributes:creationAttributes(),caller:caller) { done(($0,$1)) } }
        need(refused.0 == nil && code(refused.1) == Int(ENOMEM) && v.linkBudgetForTesting.0 == 0 && v.linkBudgetForTesting.1 == 0,"admission returns charge without entering held queue")
        release.signal(); m.serial {}
        if !quarantine { m.state(1); m.absent("first"); m.absent("next") }
        else {
            need(v.diagnosticSnapshot().2?.code == Int(ENOMEM),"secondary abort error does not replace primary delivery failure")
            let _: Bool = wait { done in v.unmount { done(true) } }
            let _: Error? = wait { v.deactivate(options:[],replyHandler:$0) }
            m.serial { need(!v.unload().consumed && v.activeItemCount() == 2,"quarantine cannot close beneath returned parent") }
            need(code(m.reclaim(m.directory!)) == Int(EBUSY),"actual transaction blocks SDK-reclaimed parent pin release")
            m.serial { need(!v.ownsForTesting(m.directory!) && v.activeItemCount() == 1,"BUSY release never resurrects reclaimed item") }
        }
        m.close(); m.reopened("first",inode:nil); m.reopened("next",inode:nil)
    }
}
#endif

#if STALLION_CONTEXT_HANDLERS
func removal(_ m: Mounted, _ item: FSItem? = nil, name: Data = Data("file".utf8), directory: FSItem? = nil,
             caller: CallerIdentity? = nil) -> (FSRemoveItemResult?,Error?) {
    wait { done in m.volume.removeResultForTesting(item ?? m.file,name:FSFileName(data:name),directory:directory ?? m.root,
        caller:caller ?? CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { done(($0,$1)) } }
}
func removalState(_ m: Mounted, count: Int = 3) {
    m.serial {
        let state = m.volume.createStateForTesting
        need(!state.pending && !state.quarantine && state.ticket == 0 && m.volume.activeItemCount() == count,"removal never owns creation state or changes returned map")
        need(m.volume.ownsForTesting(m.file) && m.volume.ownsForTesting(m.link) && m.volume.ownsForTesting(m.root),"removal preserves returned ownership")
        var r = sfs_result(), information = sfs_image_information(), pin = sfs_pin()
        need(sfs_image_get_information(m.coreHandle,&information,&r) == SFS_OK && r.transaction_active == 0,"removal transaction drained")
        need(sfs_image_pin_reserve(m.coreHandle,&pin,&r) == SFS_LIMIT && r.limit_reason == SFS_LIMIT_PIN_RESOURCES,"removal at exact existing pin capacity")
        need(!m.volume.createOutcomeForTesting.beginAttempted && !m.volume.createOutcomeForTesting.releaseAttempted,"no creation outcome or cleanup for existing operands")
    }
    need(m.volume.linkBudgetForTesting.0 == 0 && m.volume.linkBudgetForTesting.1 == 0,"removal charge drained")
}
func removalName(_ m: Mounted, _ name: String, parent: UInt64 = 1, inode: UInt64?) {
    m.serial {
        var r = sfs_result(), entry = sfs_entry(); let bytes = Data(name.utf8)
        let status = bytes.withUnsafeBytes { sfs_image_lookup(m.coreHandle,0,parent,$0.baseAddress,$0.count,&entry,&r) }
        if let inode { need(status == SFS_OK && entry.inode == inode,"exact remaining name") }
        else { need(status == SFS_NOT_FOUND,"acknowledged removed name absent") }
    }
}
func contextualRemovals(_ parent: URL) throws {
    let required = FSRemoveItemResult.requestedAttributes.wantedAttributes
#if STALLION_RESULT_MASK_TRACE
    let raw = UInt(bitPattern:required.rawValue)
    resultMaskTrace("FSRemoveItemResult original=0x\(String(raw,radix:16)) outside_caller_readable=0x\(String(raw & ~UInt(0x3fff),radix:16)) explicit=0x0")
#endif
    for cross in [false,true] {
        let f = try Fixture(parent,"remove-success-\(cross)",directory:cross), m = try Mounted(f,itemLimit:cross ? 4 : 3), v = m.volume
        let destination = cross ? namespaceLookup(m,"dir") : m.root, destinationID = (destination as! StallionItem).inode
        need(namespaceLink(m,name:Data("third".utf8),directory:destination).1 == nil,"prepare third regular name")
        need(namespaceLink(m,m.link,name:Data("symbolic-extra".utf8),directory:destination).1 == nil,"prepare symlink alias")
        need(namespaceLink(m,m.link,name:Data("symbolic-keep".utf8)).1 == nil,"prepare retained symlink alias")
        let file = m.file as! StallionItem, link = m.link as! StallionItem, filePin = file.pin!, linkPin = link.pin!
        var snapshots: [FSItem.Attributes] = [], prepared = false, constructed = 0
        m.serial {
            file.retainedModes = [.read,.write]
            v.createStageForTesting = { _,_ in need(false,"removal entered creation stage") }
            v.createAbortForTesting = { _,_ in need(false,"removal entered creation abort"); return SFS_IO }
            v.createReleaseForTesting = { _,_,_ in need(false,"removal entered creation release"); return SFS_IO }
            v.createCommitReceiptForTesting = { _ in need(false,"removal entered creation receipt hook") }
            v.preparedAttributesForTesting = { name,a in if name == "FSRemoveItemResult" { need(!prepared,"removal snapshots precede commit"); snapshots.append(a) } }
            v.rejectResultForTesting = { name in if name == "FSRemoveItemResult" { need(snapshots.count == 2 && !prepared,"actual remove constructor precommit"); constructed += 1 }; return false }
            v.diagnosticBeforeCommit = { prepared = true }
        }
        let first = removal(m)
        need(first.0 != nil && first.1 == nil && constructed == 1 && snapshots.count == 2,"actual remove result error=\(code(first.1)) roles=\(snapshots.count) constructors=\(constructed)")
        let childMetadata = namespaceMetadata(m,m.file), parentMetadata = namespaceMetadata(m,m.root), retained = snapshots
        need(childMetadata.link_count == 2 && file.lastKnownParent == nil,"nonfinal removal uses current metadata without a historical witness")
        checkPreparedAttributes(retained[0],childMetadata,required:required); checkPreparedAttributes(retained[1],parentMetadata,required:required)
        func removeAndCheck(_ item: FSItem, _ name: String, _ directory: FSItem) {
            let priorConstructors = constructed
            m.serial { snapshots = []; prepared = false }
            let result = removal(m,item,name:Data(name.utf8),directory:directory)
            need(result.0 != nil && result.1 == nil && prepared && snapshots.count == 2 && constructed == priorConstructors + 1,"consecutive real removal result error=\(code(result.1))")
            checkPreparedAttributes(snapshots[0],namespaceMetadata(m,item),required:required)
            checkPreparedAttributes(snapshots[1],namespaceMetadata(m,directory),required:required)
        }
        removeAndCheck(m.file,"third",destination)
        need(file.lastKnownParent == nil && namespaceMetadata(m,file).entry.parent == 1,"remaining alias parent wins over removed cross-directory edge")
        removeAndCheck(m.link,"symbolic-extra",destination)
        removeAndCheck(m.link,"link",m.root)
        m.serial { v.preparedAttributesForTesting = nil; v.rejectResultForTesting = nil; v.diagnosticBeforeCommit = nil }
        need(namespaceLookup(m,"alias") === file && namespaceLookup(m,"symbolic-keep") === link,"remaining names retain canonical objects")
        need(sameBytes(filePin,file.pin!) && sameBytes(linkPin,link.pin!) && file.retainedModes == [.read,.write],"removal leaves pins/open modes unchanged")
        m.serial { need(try! v.diagnosticReadForTesting(file,length:64) == Data("original".utf8),"removal preserves bytes") }
        let xattr: (Data?,Error?) = wait { done in v.getXattr(named:FSFileName(string:"note"),of:file) { done(($0,$1)) } }
        let target: (FSFileName?,Error?) = wait { done in v.readSymbolicLink(link) { done(($0,$1)) } }
        need(xattr.0 == Data("value".utf8) && xattr.1 == nil && target.0?.data == Data("file".utf8) && target.1 == nil,"remaining file xattr and symlink target")
        checkPreparedAttributes(retained[0],childMetadata,required:required); checkPreparedAttributes(retained[1],parentMetadata,required:required)
        removalState(m,count:cross ? 4 : 3)
        withExtendedLifetime(first.0) {}
        if cross { let e: Error? = wait { v.reclaimForTesting(destination,eligible:true,replyHandler:$0) }; need(e == nil,"reclaim removal destination") }
        m.close(); namespaceReopened(f,"file",inode:nil); namespaceReopened(f,"third",parent:destinationID,inode:nil)
        namespaceReopened(f,"alias",inode:f.id); namespaceReopened(f,"link",inode:nil)
        namespaceReopened(f,"symbolic-extra",parent:destinationID,inode:nil); namespaceReopened(f,"symbolic-keep",inode:link.inode)
    }
    let noData = try Fixture(parent,"remove-no-data-permission",mode:0), noDataMount = try Mounted(noData,itemLimit:3)
    need(removal(noDataMount).1 == nil,"unlink does not require source data read/write permission")
    removalState(noDataMount); noDataMount.close(); namespaceReopened(noData,"file",inode:nil); need(noData.contents() == Data("original".utf8),"remaining unreadable inode bytes unchanged")
    try removalFinalLinks(parent,required:required)
    try removalRefusals(parent)
    try removalFailures(parent,required:required)
    try removalQueued(parent)
    try removalCreationIntegration(parent)
}
func removalFinalLinks(_ parent: URL, required: FSItem.Attribute) throws {
    for symlink in [false,true] {
        let f = try Fixture(parent,"remove-final-\(symlink)",extra:true), m = try Mounted(f,itemLimit:4), v = m.volume
        let other = namespaceLookup(m,"extra") as! StallionItem
        if !symlink { need(removal(m,name:Data("alias".utf8)).1 == nil,"prepare final regular name") }
        let item = (symlink ? m.link : m.file) as! StallionItem, name = symlink ? "link" : "file", token = item.pin!
        var prepared = false, constructed = false, snapshots: [FSItem.Attributes] = []
        m.serial {
            item.retainedModes = symlink ? [] : [.read,.write]
            need(item.lastKnownParent == nil,"no historical witness on linked item")
            v.diagnosticBeforePrepare = { need(item.lastKnownParent == nil,"candidate is not published while transaction pending"); prepared = true }
            v.preparedAttributesForTesting = { type,a in if type == "FSRemoveItemResult" { need(item.lastKnownParent == nil,"removed snapshot uses private transaction candidate only"); snapshots.append(a) } }
            v.rejectResultForTesting = { type in if type == "FSRemoveItemResult" { constructed = true }; return false }
            v.diagnosticBeforeCommit = { need(item.lastKnownParent == nil,"no witness before verified commit") }
        }
        let result = removal(m,item,name:Data(name.utf8))
        need(result.0 != nil && result.1 == nil && prepared && constructed && snapshots.count == 2,"real SDK final unlink result succeeds without reducing requested attributes")
        removalName(m,name,inode:nil)
        var detached = sfs_metadata_entry(), witness: LastKnownParent?
        m.serial {
            var r = sfs_result(), value = sfs_pin_stat()
            need(v.ownsForTesting(item) && sameBytes(token,item.pin!) && sfs_image_pin_stat(m.coreHandle,token,&value,&r) == SFS_OK,"same held item and token survive final unlink")
            detached = value.metadata; witness = item.lastKnownParent
            need(value.linked == 0 && detached.link_count == 0 && detached.entry.parent == 0 && detached.entry.name_length == 0,"core remains namespace-detached")
            need(witness != nil && witness!.item == ObjectIdentifier(item) && witness!.inode == item.inode && sameBytes(witness!.pin,token) && witness!.parent == 1,"verified relationship published only after successful commit")
            v.preparedAttributesForTesting = nil; v.rejectResultForTesting = nil; v.diagnosticBeforePrepare = nil; v.diagnosticBeforeCommit = nil
        }
        checkPreparedAttributes(snapshots[0],detached,required:required,retainedParent:1)
        checkPreparedAttributes(snapshots[1],namespaceMetadata(m,m.root),required:required)
        let request = FSItem.GetAttributesRequest(); request.wantedAttributes = [.size,.linkCount,.fileID,.parentID]
        func get() -> (FSGetAttributesResult?,Error?) {
            wait { done in v.attributesResultForTesting(request,item:item,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { done(($0,$1)) } }
        }
        let actual = get(); need(actual.0 != nil && actual.1 == nil,"held get result satisfies complete actual SDK request")
        for invalid in 0..<3 {
            m.serial {
                if invalid == 0 { item.lastKnownParent = nil }
                else if invalid == 1 { item.lastKnownParent = LastKnownParent(item:ObjectIdentifier(other),pin:token,inode:other.inode,kind:detached.entry.kind,parent:1) }
                else { item.lastKnownParent = LastKnownParent(item:ObjectIdentifier(item),pin:other.pin!,inode:item.inode,kind:detached.entry.kind,parent:1) }
            }
            let refused = get(); need(refused.0 == nil && code(refused.1) == Int(ENOTSUP),"missing/wrong-source/wrong-real-pin witness cannot supply parent")
            m.serial { item.lastKnownParent = witness }
        }
        need(code(namespaceLink(m,item).1) == Int(ENOENT),"historical relationship cannot relink detached source")
        if symlink {
            let target: (FSFileName?,Error?) = wait { done in v.readSymbolicLink(item) { done(($0,$1)) } }
            let actual: (FSReadSymlinkResult?,Error?) = wait { done in v.readlinkResultForTesting(item,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { done(($0,$1)) } }
            need(target.1 == nil && target.0?.data == Data("file".utf8) && actual.0 != nil && actual.1 == nil,"held symlink content and full contextual result")
        } else {
            need(m.write(Data("detached".utf8)).1 == nil,"held contextual write succeeds with verified informational parent")
            let resized = m.size(11); need(resized.1 == nil && resized.0?.size == 11,"held contextual resize succeeds with actual result requirements")
            m.serial {
                need(try! v.diagnosticReadForTesting(item,length:64) == Data("detached".utf8) + Data(repeating:0,count:3),"held token read observes committed write/resize")
                _ = try! v.readResultConstructorForTesting(item) // Actual result constructor; SDK buffer routing remains separate.
            }
        }
        let no: Error? = wait { v.reclaimForTesting(item,eligible:false,replyHandler:$0) }; need(no == nil,"false reclaim retains held item")
        m.serial { need(v.ownsForTesting(item) && sameBytes(token,item.pin!) && item.lastKnownParent != nil,"false reclaim retains exact witness binding") }
        let yes: Error? = wait { v.reclaimForTesting(item,eligible:true,replyHandler:$0) }; need(yes == nil,"normal detached reclaim")
        m.serial { var r = sfs_result(), value = sfs_pin_stat(); need(!v.ownsForTesting(item) && item.lastKnownParent == nil && sfs_image_pin_stat(m.coreHandle,token,&value,&r) == SFS_INVALID,"true reclaim clears witness and retires pin exactly once") }
        let extra: Error? = wait { v.reclaimForTesting(other,eligible:true,replyHandler:$0) }; need(extra == nil,"reclaim other real witness-test operand")
        withExtendedLifetime(result.0) {}
        m.close(); namespaceReopened(f,name,inode:nil)
    }
}
func removalRefusals(_ parent: URL) throws {
    let f = try Fixture(parent,"remove-preflight",extra:true,directory:true), m = try Mounted(f,itemLimit:5), v = m.volume
    let directory = namespaceLookup(m,"dir"), stale = namespaceLookup(m,"extra"), before = v.anchor
    var staged = false
    m.serial { v.diagnosticBeforePrepare = { staged = true } }
    for (bytes,expected) in [(Data(),EINVAL),(Data([0]),EINVAL),(Data("a/b".utf8),EINVAL),(Data(".".utf8),EINVAL),(Data("..".utf8),EINVAL),(Data(repeating:97,count:256),ENAMETOOLONG),(Data("absent".utf8),ENOENT),(Data("link".utf8),ESTALE)] {
        need(code(removal(m,name:bytes).1) == Int(expected),"precise removal name/identity refusal")
    }
    need(code(removal(m,m.root).1) == Int(ENOTSUP),"root removal excluded")
    need(code(removal(m,directory:m.file).1) == Int(ENOTDIR),"non-directory parent refusal")
    need(code(removal(m,StallionItem(f.id)).1) == Int(EINVAL) && code(removal(m,directory:StallionItem(1)).1) == Int(EINVAL),"foreign canonical identities refused")
    let otherFixture = try Fixture(parent,"remove-cross-volume"), other = try Mounted(otherFixture,itemLimit:3)
    need(code(removal(m,other.file).1) == Int(EINVAL) && code(removal(m,directory:other.root).1) == Int(EINVAL),"actual other-volume operands refused despite equal inode numbers")
    other.close(); namespaceReopened(otherFixture,"file",inode:otherFixture.id)
    let reclaimed: Error? = wait { v.reclaimForTesting(stale,eligible:true,replyHandler:$0) }; need(reclaimed == nil,"prepare reclaimed removal operand")
    need(code(removal(m,stale,name:Data("extra".utf8)).1) == Int(EINVAL),"reclaimed operand refused")
    for caller in [CallerIdentity(uid:Int(geteuid())+1,gid:Int(getegid())),CallerIdentity(uid:-1,gid:Int(getegid())),CallerIdentity(uid:Int(geteuid()),gid:-1)] {
        need(code(removal(m,caller:caller).1) == Int(EACCES),"removal caller validation")
    }
    m.serial { let deniedAccess: [FSVolume.AccessMask] = [.delete,.deleteChild]; for access in deniedAccess {
        do { try v.linkAccessForTesting(m.root,access:access,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))); need(false,"standalone delete grant widened") }
        catch { need(code(error) == Int(EACCES),"standalone removal access remains refused") }
    } }
    need(!staged && anchorMatches(before,v.anchor) && v.diagnosticSnapshot().0.commits == 0,"all preflight refusals precede transaction")
    let released: Error? = wait { v.reclaimForTesting(directory,eligible:true,replyHandler:$0) }; need(released == nil,"release refusal directory")
    m.close(); namespaceReopened(f,"file",inode:f.id)
    for index in 0..<9 {
        let fixture = try Fixture(parent,"remove-policy-\(index)",mode:index == 4 ? 0o6600 : 0o600,acl:index == 2,
            owner:index == 8 ? geteuid()+1 : geteuid(),sourceFlags:index == 0 ? 1 : 0,rootFlags:index == 1 ? 0x8000 : 0,
            rootMode:index == 5 ? 0o500 : index == 6 ? 0o600 : index == 7 ? 0o1700 : 0o700,rootACL:index == 3)
        let mount = try Mounted(fixture,itemLimit:3), anchor = mount.volume.anchor
        need(code(removal(mount).1) == Int(index < 4 ? ENOTSUP : EACCES) && anchorMatches(anchor,mount.volume.anchor) && mount.volume.diagnosticSnapshot().0.commits == 0,"actual removal metadata policy refusal")
        removalState(mount); mount.close(); namespaceReopened(fixture,"file",inode:fixture.id)
    }
    let roFixture = try Fixture(parent,"remove-readonly"), ro = try Mounted(roFixture,writable:false)
    need(code(removal(ro).1) == Int(EROFS),"unbound/RO removal refused"); ro.close()
    let revokedFixture = try Fixture(parent,"remove-revoked"), revoked = try Mounted(revokedFixture,itemLimit:3)
    revoked.resource.revoke(); need(code(removal(revoked).1) == Int(EACCES),"revoked removal refused"); revoked.close(); namespaceReopened(revokedFixture,"file",inode:revokedFixture.id)
}
func removalFailures(_ parent: URL, required: FSItem.Attribute) throws {
    need(!required.isEmpty,"actual removal result requirements")
    for directory in [false,true] {
    for rejectedRole in 0..<2 {
        let f = try Fixture(parent,"remove-incomplete-\(directory)-\(rejectedRole)",directory:directory), m = try Mounted(f,itemLimit:directory ? 4 : 3), v = m.volume, before = v.anchor
        let item = (directory ? namespaceLookup(m,"dir") : m.file) as! StallionItem, name = directory ? "dir" : "file"
        let token = item.pin!; var role = 0, constructed = false
        m.serial { v.preparedAttributesForTesting = { name,a in if name == "FSRemoveItemResult" { need(item.lastKnownParent == nil,"failed role preparation does not publish witness"); if role == rejectedRole { a.invalidateAllProperties() }; role += 1 } }
            v.rejectResultForTesting = { _ in constructed = true; return false }
        }
        let result = removal(m,item,name:Data(name.utf8))
        need(result.0 == nil && code(result.1) == Int(ENOTSUP) && role == rejectedRole+1 && !constructed && anchorMatches(before,v.anchor),"both removal roles fail before constructor and commit")
        need(sameBytes(token,item.pin!) && item.lastKnownParent == nil,"rollback retains external pin without publishing witness")
        removalName(m,name,inode:item.inode); removalState(m,count:directory ? 4 : 3); if directory { need(wait { v.reclaimForTesting(item,eligible:true,replyHandler:$0) } == nil,"reclaim retained directory after constructor refusal") }; m.close(); namespaceReopened(f,name,inode:item.inode)
    }
    for scenario in 0..<8 {
        let f = try Fixture(parent,"remove-failure-\(directory)-\(scenario)",capacity:scenario == 7 ? 160 * 1024 : 16 * 1024 * 1024,directory:directory), m = try Mounted(f,itemLimit:directory ? 4 : 3), v = m.volume
        let item = (directory ? namespaceLookup(m,"dir") : m.file) as! StallionItem, name = directory ? "dir" : "file"
        if scenario == 6 {
            let retained = removal(m,m.link,name:Data("link".utf8))
            need(retained.0 != nil && retained.1 == nil && (m.link as! StallionItem).lastKnownParent != nil,"prepare real committed witness before consumed-error reclaim")
        }
        let before = v.anchor, commitsBefore = v.diagnosticSnapshot().0.commitSuccess
        let token = item.pin!; var constructed = false, originalCommit = sfs_result(), capacityReceipt = sfs_result()
        m.serial {
            v.preparedAttributesForTesting = { name,_ in if name == "FSRemoveItemResult" { need(item.lastKnownParent == nil,"fault result preparation keeps witness private") } }
            v.createStageForTesting = { _,_ in need(false,"removal failure entered creation") }
            v.createAbortForTesting = { _,_ in need(false,"removal abort used creation hook"); return SFS_IO }
            v.createReleaseForTesting = { _,_,_ in need(false,"removal released through creation hook"); return SFS_IO }
            v.createCommitReceiptForTesting = { _ in need(false,"removal receipt used creation hook") }
            if scenario == 0 { v.rejectResultForTesting = { name in if name == "FSRemoveItemResult" { constructed = true; return true }; return false } }
            if scenario == 1 { v.diagnosticBeforeCommit = { m.resource.revoke() } }
            if scenario == 2 { v.diagnosticBeforeCommit = { sfs_image_clear_read_cache(m.coreHandle); fault(7,1) } }
            if scenario == 6 { v.removeCommitReceiptForTesting = { original,receipt in originalCommit = original; receipt.fence_succeeded = 0 } }
            if scenario == 7 { v.diagnosticBeforePrepare = {
                // A bounded real capacity failure after the removal edit, in its same transaction.
                let bytes = Data(repeating:7,count:65536)
                for part in 0..<2 {
                    var writeReceipt = sfs_result()
                    let status = bytes.withUnsafeBytes { sfs_image_write(m.coreHandle,f.id,UInt64(part * bytes.count),$0.baseAddress,$0.count,&writeReceipt) }
                    if status != SFS_OK {
                        capacityReceipt = writeReceipt
                        need(status == SFS_LIMIT && capacityReceipt.limit_reason == SFS_LIMIT_APPEND_CAPACITY,"real precommit capacity exhaustion")
                        throw sfsError(status,capacityReceipt)
                    }
                }
                need(false,"bounded128KiB write intent did not reach actual append capacity")
            } }
        }
        if scenario == 3 { fault(1,1) }; if scenario == 4 || scenario == 5 { fault(4,Int32(scenario-3)) }
        let result = removal(m,item,name:Data(name.utf8)), expected = scenario == 1 ? EACCES : scenario == 2 ? ENOMEM : [3,4,5,7].contains(scenario) ? ENOSPC : EIO
        need(result.0 == nil && code(result.1) == Int(expected) && anchorMatches(before,v.anchor),"removal failure scenario \(scenario) actual=\(code(result.1))")
        if scenario == 0 { need(constructed,"actual constructor reached before injected rejection") }
        if (2...5).contains(scenario) { need(hits() > 0,"real removal core fault reached") }
        if scenario == 4 || scenario == 5 { let first = v.diagnosticSnapshot().2!
            need(first.result.status == (scenario == 4 ? SFS_IO : SFS_OUTCOME_UNKNOWN) && first.result.poisoned != 0,"known versus unknown removal fence outcome")
        }
        fault(0,0)
        m.serial { let state = v.createStateForTesting; need(!state.pending && !state.quarantine && state.ticket == 0 && v.ownsForTesting(item) && sameBytes(token,item.pin!) && item.lastKnownParent == nil && !v.createOutcomeForTesting.beginAttempted,"failure retains returned pin and never publishes candidate witness") }
        if scenario < 3 || scenario == 7 { removalName(m,name,inode:item.inode); removalState(m,count:directory ? 4 : 3) }
        if scenario == 6 {
            need(originalCommit.status == SFS_OK && originalCommit.fence_succeeded == 3 && originalCommit.transaction_active == 0 && v.diagnosticSnapshot().0.commitSuccess == commitsBefore + 1,"original successful C receipt and accounting survive adapter rejection")
            let _: Bool = wait { done in v.unmount { done(true) } }
            let _: Error? = wait { v.deactivate(options:[],replyHandler:$0) }
            m.serial { need(!v.unload().consumed && v.activeItemCount() == (directory ? 4 : 3),"cannot close beneath returned removal operands") }
            need((m.link as! StallionItem).lastKnownParent != nil,"prior committed witness retained until actual reclaim")
            for item in (directory ? [m.file,m.link,item] : [m.file,m.link]) {
                let pin = (item as! StallionItem).pin!
                let error: Error? = wait { v.reclaimForTesting(item,eligible:true,replyHandler:$0) }
                need(code(error) == Int(ESTALE),"consumed pin release can report old-anchor ESTALE")
                m.serial { var r = sfs_result(), value = sfs_pin_stat(); need(!v.ownsForTesting(item) && (item as! StallionItem).pin == nil && (item as! StallionItem).lastKnownParent == nil && sfs_image_pin_stat(m.coreHandle,pin,&value,&r) == SFS_INVALID,"ESTALE consumes pin and witness without retry or reinsertion") }
            }
            need(v.diagnosticSnapshot().2?.code == Int(EIO),"cleanup error preserves primary receipt failure")
        }
        if directory && scenario != 6 { need(wait { v.reclaimForTesting(item,eligible:true,replyHandler:$0) } == nil,"reclaim retained directory after removal fault") }
        m.close()
        if scenario == 6 { namespaceReopened(f,name,inode:nil); namespaceReopened(f,"alias",inode:f.id); namespaceReopened(f,"link",inode:nil) }
        else if scenario != 5 { namespaceReopened(f,name,inode:item.inode); need(f.contents() == Data("original".utf8),"known failure reopened original data") }
        // OUTCOME_UNKNOWN has no asserted disk presence or absence.
    }
    }
}
func removalQueued(_ parent: URL) throws {
    let staleFixture = try Fixture(parent,"remove-stale-replacement",extra:true), stale = try Mounted(staleFixture,itemLimit:4), v = stale.volume
    let replacement = namespaceLookup(stale,"extra") as! StallionItem
    let held = DispatchSemaphore(value:0), resume = DispatchSemaphore(value:0), replies = DispatchGroup()
    var substituted = false, afterSubstitution = v.anchor
    v.enqueue { held.signal(); need(resume.wait(timeout:.now()+20) == .success,"resume stale removal queue") }
    need(held.wait(timeout:.now()+20) == .success,"hold stale removal queue")
    v.enqueue {
        try! v.diagnosticMutationForTesting { h,r in
            need(sfs_image_unlink_expected(h,1,"file",4,staleFixture.id,&r) == SFS_OK,"fixture replaces old exact name")
            need(sfs_image_link(h,replacement.inode,1,"file",4,&r) == SFS_OK,"fixture installs different existing inode")
        }
        afterSubstitution = v.anchor; substituted = true
    }
    replies.enter(); v.removeResultForTesting(stale.file,name:FSFileName(string:"file"),directory:stale.root,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { result,error in
        need(substituted && result == nil && code(error) == Int(ESTALE) && anchorMatches(afterSubstitution,v.anchor),"queued stale identity cannot remove committed replacement"); replies.leave()
    }
    resume.signal(); need(replies.wait(timeout:.now()+20) == .success,"stale callback done")
    removalName(stale,"file",inode:replacement.inode); removalName(stale,"alias",inode:staleFixture.id); removalState(stale,count:4)
    let reclaimed: Error? = wait { v.reclaimForTesting(replacement,eligible:true,replyHandler:$0) }; need(reclaimed == nil,"reclaim replacement operand")
    stale.close(); namespaceReopened(staleFixture,"file",inode:replacement.inode); namespaceReopened(staleFixture,"alias",inode:staleFixture.id)
    for precedingFailure in [false,true] {
        let f = try Fixture(parent,"remove-queued-\(precedingFailure)"), m = try Mounted(f,itemLimit:3), volume = m.volume, before = volume.anchor
        let entered = DispatchSemaphore(value:0), release = DispatchSemaphore(value:0), finished = DispatchGroup()
        var firstDone = false, preflights = 0
        volume.enqueue {
            if precedingFailure { volume.diagnosticBeforePrepare = { throw POSIXError(.ENOMEM) } }
            volume.removePreflightForTesting = { preflights += 1 }
            entered.signal(); need(release.wait(timeout:.now()+20) == .success,"resume double removal queue")
        }
        need(entered.wait(timeout:.now()+20) == .success,"hold double removal queue")
        let caller = CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))
        finished.enter()
        if precedingFailure {
            volume.writeCountForTesting(contents:Data([1]),to:m.file,at:0) { count,error in
                need(count == 0 && code(error) == Int(ENOMEM),"earlier write preparation fails")
                volume.diagnosticBeforePrepare = nil; firstDone = true; finished.leave()
            }
        } else {
            volume.removeResultForTesting(m.file,name:FSFileName(string:"file"),directory:m.root,caller:caller) { result,error in
                need(result != nil && error == nil,"first queued exact removal succeeds"); firstDone = true; finished.leave()
            }
        }
        finished.enter(); volume.removeResultForTesting(m.file,name:FSFileName(string:"file"),directory:m.root,caller:caller) { result,error in
            need(firstDone && result == nil && code(error) == Int(precedingFailure ? ENOMEM : ENOENT),"second queued removal preserves failure or missing-name outcome"); finished.leave()
        }
        let charged = volume.linkBudgetForTesting
        need(charged.0 == 2 && charged.1 == 2 * ReadOnlyLimits.callbackOverhead + (precedingFailure ? 5 : 8),"queued removal exact retained-byte charges")
        release.signal(); need(finished.wait(timeout:.now()+20) == .success,"queued removals complete")
        m.serial { need(preflights == (precedingFailure ? 0 : 2),"queued sticky failure precedes removal preflight") }
        if precedingFailure {
            need(anchorMatches(before,volume.anchor) && volume.diagnosticSnapshot().0.commits == 0,"failed predecessor prevents any removal commit")
            let admissionHeld = DispatchSemaphore(value:0), admissionRelease = DispatchSemaphore(value:0)
            volume.enqueue { admissionHeld.signal(); need(admissionRelease.wait(timeout:.now()+20) == .success,"release sticky removal admission queue") }
            need(admissionHeld.wait(timeout:.now()+20) == .success,"hold sticky removal admission queue")
            need(code(removal(m).1) == Int(ENOMEM) && volume.linkBudgetForTesting.0 == 0 && volume.linkBudgetForTesting.1 == 0,"already-latched removal fails without queue or leaked charge")
            admissionRelease.signal(); m.serial {}
        } else { need(volume.diagnosticSnapshot().0.commits == 1,"missing second removal adds no commit") }
        removalName(m,"file",inode:precedingFailure ? f.id : nil); removalState(m); m.close()
        namespaceReopened(f,"file",inode:precedingFailure ? f.id : nil); need(f.contents() == Data("original".utf8),"queued removal preserves surviving bytes")
    }
    let fullFixture = try Fixture(parent,"remove-saturation"), full = try Mounted(fullFixture,itemLimit:3)
    let entered = DispatchSemaphore(value:0), release = DispatchSemaphore(value:0), drained = DispatchGroup()
    full.volume.enqueue { entered.signal(); need(release.wait(timeout:.now()+20) == .success,"resume saturated removal queue") }
    need(entered.wait(timeout:.now()+20) == .success,"hold saturated removal queue")
    for _ in 0..<ReadOnlyLimits.callbacks { drained.enter(); full.volume.enqueue(rejected:{ _ in need(false,"fill removal budget") }) { drained.leave() } }
    let charged = full.volume.linkBudgetForTesting
    need(code(removal(full).1) == Int(EAGAIN) && full.volume.linkBudgetForTesting.0 == charged.0 && full.volume.linkBudgetForTesting.1 == charged.1,"saturated removal adds no ticket")
    release.signal(); need(drained.wait(timeout:.now()+20) == .success,"drain removal saturation")
    removalState(full); full.close(); namespaceReopened(fullFixture,"file",inode:fullFixture.id)
}
func removalCreationIntegration(_ parent: URL) throws {
    for mode in 0..<3 {
        let m = try CreationMount(parent,"remove-after-create-\(mode)"), v = m.volume
        let initial = m.create("published")
        need(initial.0 != nil && initial.1 == nil && initial.2 != nil,"published created removal operand")
        let item = initial.2!, token = item.pin!, caller = CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))
        let linked: (FSCreateLinkResult?,Error?) = wait { done in v.linkResultForTesting(item,name:FSFileName(string:"kept"),directory:m.root,caller:caller) { done(($0,$1)) } }
        need(linked.0 != nil && linked.1 == nil,"created operand nonfinal alias")
        let before = v.anchor, held = DispatchSemaphore(value:0), release = DispatchSemaphore(value:0), done = DispatchGroup()
        var nextItem: StallionItem?, createReplied = false, preflights = 0, outcomeAfterCreate = v.createOutcomeForTesting
        let attrs = creationAttributes()
        v.enqueue {
            v.createStageForTesting = { stage,value in
                if stage == "inserted" { if mode == 0 { nextItem = value }; if mode != 0 { throw POSIXError(.ENOMEM) } }
            }
            if mode == 2 { v.createAbortForTesting = { _,r in r.status = SFS_IO; r.transaction_active = 1; r.system_errno = EIO; return SFS_IO } }
            v.removePreflightForTesting = { preflights += 1; let state = v.createStateForTesting; need(!state.pending && state.ticket == 0,"queued successful creation clears publication state before removal") }
            held.signal(); need(release.wait(timeout:.now()+20) == .success,"resume creation/removal queue")
        }
        need(held.wait(timeout:.now()+20) == .success,"hold creation/removal queue")
        done.enter(); v.createResultForTesting(FSFileName(string:"next"),directory:m.root,attributes:attrs,caller:caller) { result,error in
            need(mode == 0 ? result != nil && error == nil : result == nil && code(error) == Int(ENOMEM),"preceding creation outcome")
            if mode == 0 { need(nextItem != nil,"returned second actual inode"); m.returned.append(nextItem!) }
            outcomeAfterCreate = v.createOutcomeForTesting
            v.createStageForTesting = { _,_ in need(false,"queued removal entered creation stage") }
            v.createAbortForTesting = { _,_ in need(false,"queued removal retried creation abort"); return SFS_IO }
            v.createReleaseForTesting = { _,_,_ in need(false,"queued removal retried creation release"); return SFS_IO }
            createReplied = true; done.leave()
        }
        done.enter(); v.removeResultForTesting(item,name:FSFileName(string:"published"),directory:m.root,caller:caller) { result,error in
            need(createReplied && (mode == 0 ? result != nil && error == nil : result == nil && code(error) == Int(ENOMEM)),"removal sees preceding creation outcome without cleanup"); done.leave()
        }
        need(v.linkBudgetForTesting.0 == 2 && v.linkBudgetForTesting.1 == 2 * ReadOnlyLimits.callbackOverhead + 13,"creation and removal charged before either executes")
        release.signal(); need(done.wait(timeout:.now()+20) == .success,"creation/removal callbacks finish")
        m.serial {
            let state = v.createStateForTesting
            need(preflights == (mode == 0 ? 1 : 0) && state.pending == (mode == 2) && state.quarantine == (mode == 2) && state.ticket == (mode == 2 ? 1 : 0),"removal leaves exact creation cleanup/quarantine state")
            need(v.ownsForTesting(item) && sameBytes(token,item.pin!) && v.createOutcomeForTesting.beginAttempted == outcomeAfterCreate.beginAttempted && v.createOutcomeForTesting.releaseAttempted == outcomeAfterCreate.releaseAttempted && sameBytes(v.createOutcomeForTesting.original,outcomeAfterCreate.original),"returned operand and prior creation receipt unaffected")
        }
        need(v.linkBudgetForTesting.0 == 0 && v.linkBudgetForTesting.1 == 0,"creation/removal budget fully released")
        if mode == 0 { m.state(3); m.absent("published"); need(m.lookup("kept") === item,"published item remains canonical after removal") }
        else { need(anchorMatches(before,v.anchor) && attrs.consumedAttributes.isEmpty,"failed creation blocks queued removal mutation") }
        if mode == 1 { m.state(2) }
        withExtendedLifetime(initial.0) {}
        m.close(); m.reopened("published",inode:mode == 0 ? nil : item.inode); m.reopened("kept",inode:item.inode)
        m.reopened("next",inode:mode == 0 ? nextItem!.inode : nil)
    }
}
#endif

#if STALLION_CONTEXT_HANDLERS
func directoryNames(_ h: OpaquePointer, _ parent: UInt64, _ expected: [String]) {
    var cookie = sfs_cookie(), r = sfs_result(), names: [String] = []
    for index in 0...expected.count {
        var entry = sfs_entry(), found: Int32 = 0
        need(sfs_image_next(h,0,parent,&cookie,&entry,&found,&r) == SFS_OK,"directory enumeration")
        if index == expected.count { need(found == 0,"no hidden or fabricated directory names") }
        else { need(found == 1,"expected directory child"); names.append(String(decoding:rawBytes(entry.name).prefix(entry.name_length),as:UTF8.self)) }
    }
    need(names.sorted() == expected.sorted(),"exact directory names")
}
func directoryMetadata(_ value: sfs_metadata_entry, parent: UInt64, mode: UInt32) {
    need(value.entry.kind == SFS_DIRECTORY && value.entry.parent == parent && value.mode == UInt32(S_IFDIR) | mode &&
         value.entry.size == 0 && value.referenced_data_bytes == 0 && value.link_count == 1 && value.flags == 0 &&
         value.uid == geteuid() && value.gid == getegid(),"truthful directory kind/mode/parent/size/extents/link/owner")
}
func contextualDirectories(_ parent: URL) throws {
    let m = try CreationMount(parent,"directory-reuse"), v = m.volume, required = FSCreateItemResult.requestedAttributes.wantedAttributes
    var snapshots: [FSItem.Attributes] = [], beforeCommit = true, constructors = 0
    m.serial {
        v.removeCommitReceiptForTesting = { _,_ in need(false,"directory creation entered removal receipt hook") }
        v.preparedAttributesForTesting = { name,a in if name == "FSCreateItemResult" { need(beforeCommit,"directory snapshots before commit"); snapshots.append(a) } }
        v.rejectResultForTesting = { name in if name == "FSCreateItemResult" { need(beforeCommit && snapshots.count == 2,"actual directory constructor precommit"); constructors += 1 }; return false }
        v.diagnosticBeforeCommit = { beforeCommit = false }
    }
    let attributes = creationAttributes(0o700); attributes.size = 0; attributes.flags = 0
    let first = m.create("A",request:attributes,type:.directory)
    need(first.0 != nil && first.1 == nil && first.2 != nil && constructors == 1 && snapshots.count == 2,"actual directory result error=\(code(first.1)) roles=\(snapshots.count)")
    need(attributes.consumedAttributes == [.mode,.uid,.gid,.size,.flags],"explicit zero directory attributes consumed")
    let a = first.2!, original = snapshots, aMetadata = m.metadata(a), rootMetadata = m.metadata(m.root)
    directoryMetadata(aMetadata,parent:1,mode:0o700)
    checkPreparedAttributes(original[0],aMetadata,required:required); checkPreparedAttributes(original[1],rootMetadata,required:required)
    m.serial { directoryNames(m.coreHandle,a.inode,[]) }; m.state(2)
    func create(_ name: String, _ parent: FSItem, _ mode: UInt32, _ type: FSItem.ItemType) -> StallionItem {
        let prior = constructors
        m.serial { snapshots = []; beforeCommit = true }
        let attributes = creationAttributes(mode), result = m.create(name,request:attributes,parent:parent,type:type)
        need(result.0 != nil && result.1 == nil && result.2 != nil && constructors == prior+1 && snapshots.count == 2 && attributes.consumedAttributes == [.mode,.uid,.gid],"nested actual result error=\(code(result.1))")
        checkPreparedAttributes(snapshots[0],m.metadata(result.2!),required:required); checkPreparedAttributes(snapshots[1],m.metadata(parent),required:required)
        return result.2!
    }
    let b = create("B",a,UInt32(S_IFDIR) | 0o750,.directory)
    directoryMetadata(m.metadata(b),parent:a.inode,mode:0o750)
    m.serial { directoryNames(m.coreHandle,b.inode,[]); directoryNames(m.coreHandle,a.inode,["B"]) }; m.state(3)
    let file = create("file",b,0o600,.file), oldPin = file.pin!
    need(m.metadata(file).entry.kind == SFS_FILE,"nested regular-file branch preserved"); m.state(4)
    let fullAnchor = v.anchor, full = m.create("full",request:creationAttributes(0o700),parent:b,type:.directory)
    need(full.0 == nil && code(full.1) == Int(ENFILE) && anchorMatches(fullAnchor,v.anchor),"directory capacity before reserve")
    m.state(4); need(m.reclaim(file) == nil,"reclaim nested file without deleting durable name"); m.state(3)
    let c = create("C",b,0o700,.directory)
    need(c.inode != file.inode && c.inode != a.inode && c.inode != b.inode && c.pin!.slot == oldPin.slot && c.pin!.incarnation > oldPin.incarnation,"directory uses freed slot with fresh real identity")
    directoryMetadata(m.metadata(a),parent:1,mode:0o700); directoryMetadata(m.metadata(b),parent:a.inode,mode:0o750); directoryMetadata(m.metadata(c),parent:b.inode,mode:0o700)
    m.serial { directoryNames(m.coreHandle,1,["A"]); directoryNames(m.coreHandle,a.inode,["B"]); directoryNames(m.coreHandle,b.inode,["C","file"]); directoryNames(m.coreHandle,c.inode,[]) }
    need(m.lookup("A") === a && m.lookup("B",parent:a) === b && m.lookup("C",parent:b) === c,"nested directory canonical identities")
    m.state(4)
    checkPreparedAttributes(original[0],aMetadata,required:required); checkPreparedAttributes(original[1],rootMetadata,required:required)
    withExtendedLifetime(first.0) {}
    m.close(); m.reopened("A",inode:a.inode); m.reopened("B",parent:a.inode,inode:b.inode); m.reopened("file",parent:b.inode,inode:file.inode); m.reopened("C",parent:b.inode,inode:c.inode)
    var reopened: OpaquePointer?, receipt = sfs_result()
    need(sfs_image_open_readonly(m.url.path,"image.sfs",&reopened,&receipt) == SFS_OK,"directory metadata reopen")
    for (item,parentID,mode) in [(a,UInt64(1),UInt32(0o700)),(b,a.inode,UInt32(0o750)),(c,b.inode,UInt32(0o700))] {
        var metadata = sfs_metadata_entry(); need(sfs_image_stat_metadata(reopened,0,item.inode,&metadata,&receipt) == SFS_OK,"reopened directory metadata")
        directoryMetadata(metadata,parent:parentID,mode:mode)
    }
    directoryNames(reopened!,a.inode,["B"]); directoryNames(reopened!,b.inode,["C","file"]); directoryNames(reopened!,c.inode,[])
    need(sfs_image_close(reopened,&receipt) == SFS_OK,"directory metadata reopen close")
    try directoryRefusals(parent); try directoryFailures(parent); try directoryQueuedFailure(parent); try directoryRemovals(parent)
}
func directoryRemovalRefusals(_ parent: URL) throws {
    for variant in 0..<12 {
        let f = try Fixture(parent,"directory-remove-refusal-\(variant)",rootMode:variant == 6 ? 0o500 : variant == 7 ? 0o600 : 0o700,rootACL:variant == 8,directory:true)
        let m = try Mounted(f,writable:variant != 5,itemLimit:4), v = m.volume
        let directory = namespaceLookup(m,"dir") as! StallionItem, token = directory.pin, before = v.anchor, commits = v.diagnosticSnapshot().0.commits
        if variant == 4 { m.resource.revoke() }
        if variant >= 10 { let e: Error? = wait { v.reclaimForTesting(directory,eligible:true,replyHandler:$0) }; need(e == nil,"prepare reclaimed directory operand") }
        let item: FSItem = variant == 0 ? StallionItem(directory.inode) : variant == 11 ? m.file : directory
        let parentItem: FSItem = variant == 1 ? StallionItem(1) : variant == 11 ? directory : m.root
        let caller = CallerIdentity(uid:Int(geteuid()) + (variant == 9 ? 1 : 0),gid:Int(getegid()))
        let name = variant == 2 || variant == 11 ? "file" : variant == 3 ? "missing" : "dir"
        let result: (FSRemoveItemResult?,Error?) = wait { done in v.removeResultForTesting(item,name:FSFileName(string:name),directory:parentItem,caller:caller) { done(($0,$1)) } }
        let expected = [EINVAL,EINVAL,ESTALE,ENOENT,EACCES,EROFS,EACCES,EACCES,ENOTSUP,EACCES,EINVAL,EINVAL][variant]
        need(result.0 == nil && code(result.1) == Int(expected) && anchorMatches(before,v.anchor) && commits == v.diagnosticSnapshot().0.commits,"directory removal ownership, identity, access and resource refusal before mutation")
        if variant != 5 && variant < 10 {
            m.serial { need(v.ownsForTesting(directory) && sameBytes(token!,directory.pin!),"directory refusal retains exact returned token") }
            let e: Error? = wait { v.reclaimForTesting(directory,eligible:true,replyHandler:$0) }; need(e == nil,"reclaim refused directory operand")
        }
        m.close(); namespaceReopened(f,"dir",inode:directory.inode); need(f.contents() == Data("original".utf8),"directory refusal preserves unrelated file bytes")
    }
}
func directoryRemovalQueued(_ parent: URL) throws {
    let m = try CreationMount(parent,"directory-remove-queued"), v = m.volume
    let created = m.create("dir",request:creationAttributes(0o700),type:.directory)
    need(created.0 != nil && created.1 == nil && created.2 != nil,"queued directory removal source")
    let directory = created.2!, token = directory.pin!, held = DispatchSemaphore(value:0), resume = DispatchSemaphore(value:0), done = DispatchGroup()
    var afterChild = v.anchor, child: UInt64 = 0, committed = false
    v.enqueue { held.signal(); need(resume.wait(timeout:.now()+20) == .success,"resume queued child insertion") }
    need(held.wait(timeout:.now()+20) == .success,"hold queue before directory removal")
    v.enqueue {
        try! v.diagnosticMutationForTesting { h,r in
            var metadata = sfs_metadata_initial(); metadata.mode = UInt32(S_IFREG) | 0o600; metadata.uid = geteuid(); metadata.gid = getegid()
            need(sfs_image_add_metadata(h,directory.inode,"child",5,SFS_FILE,&metadata,&child,&r) == SFS_OK,"queued real child insertion")
            need(sfs_image_write(h,child,0,"retained",8,&r) == SFS_OK,"queued child contents")
        }
        afterChild = v.anchor; committed = true
    }
    done.enter(); v.removeResultForTesting(directory,name:FSFileName(string:"dir"),directory:m.root,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { result,error in
        need(committed && result == nil && code(error) == Int(ENOTEMPTY) && anchorMatches(afterChild,v.anchor),"queued directory observes committed child before removal begin"); done.leave()
    }
    resume.signal(); need(done.wait(timeout:.now()+20) == .success,"queued directory removal completes")
    m.serial { need(v.ownsForTesting(directory) && sameBytes(token,directory.pin!),"queued nonempty refusal retains directory ownership"); directoryNames(m.coreHandle,directory.inode,["child"]) }
    m.close(); m.reopened("dir",inode:directory.inode); m.reopened("child",parent:directory.inode,inode:child,bytes:Data("retained".utf8))
}
func directoryRemovals(_ parent: URL) throws {
    try directoryRemovalRefusals(parent); try directoryRemovalQueued(parent)
    let caller = CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))
    let required = FSRemoveItemResult.requestedAttributes.wantedAttributes
    for populated in [false,true] {
        let m = try CreationMount(parent,"directory-remove-\(populated)"), v = m.volume
        let parentResult = m.create("parent",request:creationAttributes(0o700),type:.directory)
        need(parentResult.0 != nil && parentResult.1 == nil && parentResult.2 != nil,"create nonroot verified removal parent")
        let parentDirectory = parentResult.2!, parentID = parentDirectory.inode
        let made = m.create("dir",request:creationAttributes(0o700),parent:parentDirectory,type:.directory)
        need(made.0 != nil && made.1 == nil && made.2 != nil,"create actual directory removal operand")
        let directory = made.2!, token = directory.pin!
        var child: StallionItem?
        let payload = Data("retained-child".utf8)
        if populated {
            let created = m.create("child",parent:directory)
            need(created.0 != nil && created.1 == nil && created.2 != nil,"create nonempty removal child")
            child = created.2!
            let written: (Int,Error?) = wait { done in v.writeCountForTesting(contents:payload,to:child!,at:0) { done(($0,$1)) } }
            need(written.0 == payload.count && written.1 == nil,"write retained nonempty child")
        }
        func remove(_ item: FSItem, _ name: String, _ parent: FSItem) -> (FSRemoveItemResult?,Error?) {
            wait { done in v.removeResultForTesting(item,name:FSFileName(string:name),directory:parent,caller:caller) { done(($0,$1)) } }
        }
        let before = v.anchor, commits = v.diagnosticSnapshot().0.commits
        if let child {
            let childToken = child.pin!, denied = remove(directory,"dir",parentDirectory)
            need(denied.0 == nil && code(denied.1) == Int(ENOTEMPTY) && anchorMatches(before,v.anchor) && commits == v.diagnosticSnapshot().0.commits,"nonempty directory refused before mutation")
            m.serial {
                directoryNames(m.coreHandle,1,["parent"]); directoryNames(m.coreHandle,parentID,["dir"]); directoryNames(m.coreHandle,directory.inode,["child"])
                need(v.ownsForTesting(directory) && v.ownsForTesting(child) && sameBytes(token,directory.pin!) && sameBytes(childToken,child.pin!),"nonempty refusal retains both returned tokens")
                need(try! v.diagnosticReadForTesting(child,length:payload.count) == payload,"nonempty refusal retains child bytes")
            }
            let childRemoval = remove(child,"child",directory)
            need(childRemoval.0 != nil && childRemoval.1 == nil,"remove child through actual contextual result")
            need(m.reclaim(child) == nil,"reclaim removed child once")
            m.serial { directoryNames(m.coreHandle,directory.inode,[]) }
        }
        var attributes: [FSItem.Attributes] = [], constructed = false, prepared = false
        m.serial {
            v.preparedAttributesForTesting = { name,a in if name == "FSRemoveItemResult" { need(!prepared && directory.lastKnownParent == nil,"directory result candidate is private before commit"); attributes.append(a) } }
            v.rejectResultForTesting = { name in if name == "FSRemoveItemResult" { constructed = true }; return false }
            v.diagnosticBeforeCommit = { need(directory.lastKnownParent == nil,"directory witness remains unpublished before commit"); prepared = true }
        }
        let removed = remove(directory,"dir",parentDirectory)
        need(removed.0 != nil && removed.1 == nil && constructed && prepared && attributes.count == 2,"actual empty directory removal constructs complete SDK result")
        var detached = sfs_metadata_entry()
        m.serial {
            var value = sfs_pin_stat(), r = sfs_result()
            need(v.ownsForTesting(directory) && directory.lastKnownParent != nil && sameBytes(token,directory.pin!) && sfs_image_pin_stat(m.coreHandle,token,&value,&r) == SFS_OK,"removed directory retains the same owned token")
            detached = value.metadata
            need(value.linked == 0 && detached.link_count == 0 && detached.entry.kind == SFS_DIRECTORY && detached.entry.parent == 0 && detached.entry.name_length == 0,"truthful detached directory metadata")
            directoryNames(m.coreHandle,parentID,[])
        }
        checkPreparedAttributes(attributes[0],detached,required:required,retainedParent:parentID); checkPreparedAttributes(attributes[1],m.metadata(parentDirectory),required:required)
        m.serial { v.preparedAttributesForTesting = nil; v.rejectResultForTesting = nil; v.diagnosticBeforeCommit = nil }
        let parentRemoved = remove(parentDirectory,"parent",m.root)
        need(parentRemoved.0 != nil && parentRemoved.1 == nil && m.reclaim(parentDirectory) == nil,"former parent can itself be removed and reclaimed")
        let wanted = FSItem.GetAttributesRequest(); wanted.wantedAttributes = [.fileID,.linkCount,.size,.parentID]
        let observed: (FSItem.Attributes?,Error?) = wait { done in v.getAttributes(wanted,of:directory) { done(($0,$1)) } }
        need(observed.1 == nil && observed.0?.linkCount == 0 && observed.0?.size == 0 && observed.0?.parentID == (try! itemIdentifier(parentID)),"held parent relationship survives former-parent removal/reclaim")
        let actualHeld: (FSGetAttributesResult?,Error?) = wait { done in v.attributesResultForTesting(wanted,item:directory,caller:caller) { done(($0,$1)) } }
        need(actualHeld.0 != nil && actualHeld.1 == nil,"held directory satisfies untouched current SDK result requirements")
        for name in [".","..","child"] {
            let found: (FSItem?,Error?) = wait { done in v.lookupItem(named:FSFileName(string:name),inDirectory:directory) { done(($0,$2)) } }
            need(found.0 == nil && code(found.1) == Int(ENOENT),"detached directory cannot be a lookup namespace parent")
        }
        var packed = false
        let enumeration: Error? = wait { done in v.enumerateDirectory(directory,startingAt:.initial,verifier:.initial,attributes:nil,pack:{ _,_,_,_,_ in packed = true; return true }) { done($1) } }
        need(!packed && code(enumeration) == Int(ENOENT),"detached directory cannot enumerate a namespace")
        need(code(m.create("invalid",parent:directory).1) == Int(ENOENT),"detached directory cannot accept new children")
        let linked: (FSCreateLinkResult?,Error?) = wait { done in v.linkResultForTesting(directory,name:FSFileName(string:"alias"),directory:m.root,caller:caller) { done(($0,$1)) } }
        need(linked.0 == nil && code(linked.1) == Int(ENOENT),"detached directory cannot be relinked")
        let retained: Error? = wait { v.reclaimForTesting(directory,eligible:false,replyHandler:$0) }
        need(retained == nil,"false reclaim leaves detached directory retained")
        m.serial { need(v.ownsForTesting(directory) && sameBytes(token,directory.pin!) && directory.lastKnownParent != nil,"false reclaim retains directory token and witness") }
        need(m.reclaim(directory) == nil,"true reclaim releases detached directory exactly once")
        m.serial { var value = sfs_pin_stat(), r = sfs_result(); need(!v.ownsForTesting(directory) && directory.pin == nil && directory.lastKnownParent == nil && sfs_image_pin_stat(m.coreHandle,token,&value,&r) == SFS_INVALID,"reclaimed detached directory token invalidated") }
        need(code(m.reclaim(directory)) == Int(EINVAL),"second reclaim cannot release directory again")
        m.state(1); withExtendedLifetime(removed.0) {}
        m.close(); m.reopened("parent",inode:nil)
        var reopened: OpaquePointer?, receipt = sfs_result(), absent = sfs_metadata_entry()
        need(sfs_image_open_readonly(m.url.path,"image.sfs",&reopened,&receipt) == SFS_OK,"reopen removed directory lifecycle")
        for inode in [directory.inode,parentID] {
            need(sfs_image_stat_metadata(reopened,0,inode,&absent,&receipt) == SFS_NOT_FOUND,"removed directory inode durably absent without looking through a deleted parent")
        }
        need(sfs_image_close(reopened,&receipt) == SFS_OK,"close removed directory lifecycle inspection")
    }
}
func directoryRefusals(_ parent: URL) throws {
    let caller = CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))
    for mode in [UInt32(0o500),UInt32(0o600)] {
        let m = try CreationMount(parent,"directory-mode-\(mode)"), v = m.volume
        let result = m.create(request:creationAttributes(mode),type:.directory)
        need(result.0 != nil && result.1 == nil && result.2 != nil,"restrictive initial directory mode is honored")
        let item = result.2!, before = v.anchor
        need(code(m.create("child",parent:item).1) == Int(EACCES),"restrictive parent denies nested file")
        need(code(m.create("child",request:creationAttributes(0o700),parent:item,type:.directory).1) == Int(EACCES),"restrictive parent denies nested directory")
        let linked: (FSCreateLinkResult?,Error?) = wait { done in v.linkResultForTesting(item,name:FSFileName(string:"alias"),directory:m.root,caller:caller) { done(($0,$1)) } }
        need(code(linked.1) == Int(ENOTSUP),"created directory hardlink remains refused")
        let size = FSItem.SetAttributesRequest(); size.size = UInt64.max
        let ignored: (FSItem.Attributes?,Error?) = wait { done in v.setAttributesValueForTesting(size,on:item,caller:caller) { done(($0,$1)) } }
        need(ignored.0 != nil && ignored.1 == nil && size.consumedAttributes.isEmpty && anchorMatches(before,v.anchor),"created directory size remains ignored and unconsumed")
        m.serial { do { try v.linkAccessForTesting(m.root,access:.addSubdirectory,caller:caller); need(false,"standalone addSubdirectory grant expanded") } catch { need(code(error) == Int(EACCES),"standalone directory grant remains refused") } }
        m.state(2)
        let write: (Int,Error?) = wait { done in v.writeCountForTesting(contents:Data([1]),to:item,at:0) { done(($0,$1)) } }
        need(write.0 == 0 && code(write.1) == Int(EINVAL) && anchorMatches(before,v.anchor),"directory data write refused")
        m.close(); m.reopened(inode:item.inode)
    }
    let m = try CreationMount(parent,"directory-preflight"), v = m.volume, before = v.anchor
    var reserved = false
    m.serial { v.createStageForTesting = { stage,_ in if stage == "reserved" { reserved = true } } }
    for missing in 0..<3 {
        let a = FSItem.SetAttributesRequest(); if missing != 0 { a.mode = 0o700 }; if missing != 1 { a.uid = geteuid() }; if missing != 2 { a.gid = getegid() }
        need(code(m.create(request:a,type:.directory).1) == Int(ENOTSUP) && a.consumedAttributes.isEmpty,"directory requires explicit mode and IDs")
    }
    for (mode,error) in [(UInt32(S_IFREG)|0o700,EINVAL),(UInt32(0o1700),ENOTSUP),(UInt32(0o4700),ENOTSUP),(UInt32(1)<<31,ENOTSUP)] {
        let a = creationAttributes(mode); need(code(m.create(request:a,type:.directory).1) == Int(error) && a.consumedAttributes.isEmpty,"directory mode mismatch/special/unknown refusal")
    }
    for field in 0..<6 {
        let a = creationAttributes(0o700)
        if field == 0 { a.uid = geteuid()+1 }; if field == 1 { a.gid = getegid()+1 }; if field == 2 { a.flags = 1 }; if field == 3 { a.size = 1 }; if field == 4 { a.type = .directory }; if field == 5 { a.birthTime = timespec(tv_sec:1,tv_nsec:0) }
        need(code(m.create(request:a,type:.directory).1) == Int(field < 2 ? EACCES : ENOTSUP) && a.consumedAttributes.isEmpty,"directory unsupported mixture is atomic")
    }
    for identity in [CallerIdentity(uid:caller.uid+1,gid:caller.gid),CallerIdentity(uid:-1,gid:caller.gid),CallerIdentity(uid:caller.uid,gid:-1)] {
        need(code(m.create(request:creationAttributes(0o700),type:.directory,caller:identity).1) == Int(EACCES),"directory caller identity refusal")
    }
    need(code(m.create(request:creationAttributes(0o700),parent:StallionItem(1),type:.directory).1) == Int(EINVAL),"directory foreign parent refusal")
    need(!reserved && anchorMatches(before,v.anchor),"directory scalar refusals precede reservation"); m.state(1); m.absent()
    let valid = m.create("valid",request:creationAttributes(0o700),type:.directory)
    need(valid.0 != nil && valid.1 == nil && valid.2 != nil,"valid directory after preflight refusals")
    let acknowledged = v.anchor
    need(code(m.create("valid",request:creationAttributes(0o700),type:.directory).1) == Int(EEXIST) && anchorMatches(acknowledged,v.anchor),"directory duplicate refusal")
    let file = m.create("file"); need(file.2 != nil && file.1 == nil,"directory refusal regular parent setup")
    need(code(m.create(request:creationAttributes(0o700),parent:file.2!,type:.directory).1) == Int(ENOTDIR),"directory non-directory parent")
    need(m.reclaim(valid.2!) == nil && code(m.create(request:creationAttributes(0o700),parent:valid.2!,type:.directory).1) == Int(EINVAL),"directory reclaimed parent refusal")
    m.close(); m.reopened("valid",inode:valid.2!.inode); m.reopened(inode:nil)
    for spec in 0..<7 {
        let p = try CreationMount(parent,"directory-policy-\(spec)",rootMode:spec == 0 ? 0o500 : spec == 1 ? 0o1700 : 0o700,
            rootFlags:spec == 2 ? 1 : 0,rootOwner:spec == 3 ? geteuid()+1 : geteuid(),acl:spec == 4,writable:spec != 5,enable:spec != 6)
        let a = creationAttributes(0o700), anchor = p.volume.anchor
        let result = p.create(request:a,type:.directory)
        need(result.0 == nil && code(result.1) == Int(spec == 2 || spec == 4 ? ENOTSUP : spec >= 5 ? EROFS : EACCES) && a.consumedAttributes.isEmpty && anchorMatches(anchor,p.volume.anchor),"directory real parent/write policy")
        p.close(); p.reopened(inode:nil)
    }
    let revoked = try CreationMount(parent,"directory-revoked"), revokedAnchor = revoked.volume.anchor
    revoked.resource.revoke(); need(code(revoked.create(request:creationAttributes(0o700),type:.directory).1) == Int(EACCES) && anchorMatches(revokedAnchor,revoked.volume.anchor),"directory revoked resource preflight")
    revoked.close(); revoked.reopened(inode:nil)
}
func directoryFailures(_ parent: URL) throws {
    for role in 0..<2 {
        let m = try CreationMount(parent,"directory-incomplete-\(role)",directory:role == 1), v = m.volume, before = v.anchor
        var seen = 0, constructed = false
        m.serial {
            v.removeCommitReceiptForTesting = { _,_ in need(false,"directory abort used removal receipt hook") }
            v.preparedAttributesForTesting = { name,a in if name == "FSCreateItemResult" { if seen == role { a.invalidateAllProperties() }; seen += 1 } }
            v.rejectResultForTesting = { _ in constructed = true; return false }
        }
        let a = creationAttributes(0o700), result = m.create(request:a,parent:m.directory,type:.directory)
        need(result.0 == nil && code(result.1) == Int(ENOTSUP) && seen == role+1 && !constructed && a.consumedAttributes.isEmpty && anchorMatches(before,v.anchor),"each directory role invalidation rolls back before constructor")
        let outcome = v.createOutcomeForTesting; need(outcome.discarded && !outcome.releaseAttempted,"directory failed reserved pin discarded once")
        m.state(role == 1 ? 2 : 1); m.close(); m.reopened(parent:role == 1 ? (m.directory as! StallionItem).inode : 1,inode:nil)
    }
    for scenario in 0..<5 {
        let m = try CreationMount(parent,"directory-failure-\(scenario)"), v = m.volume, before = v.anchor
        var constructed = false
        m.serial {
            v.removeCommitReceiptForTesting = { _,_ in need(false,"directory fault used removal receipt hook") }
            if scenario == 0 { v.rejectResultForTesting = { name in if name == "FSCreateItemResult" { constructed = true; return true }; return false } }
            if scenario == 1 { v.diagnosticBeforeCommit = { m.resource.revoke() } }
            if scenario == 4 { v.createCommitReceiptForTesting = { $0.fence_succeeded = 0 } }
        }
        if scenario == 2 || scenario == 3 { fault(4,Int32(scenario-1)) }
        let a = creationAttributes(0o700), result = m.create(request:a,type:.directory), outcome = v.createOutcomeForTesting
        need(result.0 == nil && code(result.1) == Int(scenario == 1 ? EACCES : scenario == 2 || scenario == 3 ? ENOSPC : EIO) && a.consumedAttributes.isEmpty && anchorMatches(before,v.anchor),"directory failure scenario \(scenario) actual=\(code(result.1))")
        if scenario == 0 { need(constructed,"actual directory constructor before injected rejection") }
        if scenario == 2 || scenario == 3 { need(hits() > 0 && outcome.original.status == (scenario == 2 ? SFS_IO : SFS_OUTCOME_UNKNOWN),"directory actual fence outcome") }
        fault(0,0)
        if scenario == 4 {
            need(outcome.commitSucceeded && outcome.commit.status == SFS_OK && outcome.commit.fence_succeeded == 3 && outcome.releaseAttempted && outcome.release.status == SFS_OK && !outcome.abortAttempted,"directory promoted release after actual C success")
            let token = v.createTokenForTesting!
            m.serial { var r = sfs_result(), stat = sfs_pin_stat(); need(sfs_image_pin_stat(m.coreHandle,token,&stat,&r) == SFS_INVALID && v.activeItemCount() == 1 && !v.createStateForTesting.pending,"unreturned directory pin released once without quarantine") }
        } else { need(outcome.discarded && !outcome.releaseAttempted,"directory discard never double releases") }
        m.close()
        if scenario == 4 {
            m.reopened(inode:2)
            var h: OpaquePointer?, r = sfs_result(), metadata = sfs_metadata_entry()
            need(sfs_image_open_readonly(m.url.path,"image.sfs",&h,&r) == SFS_OK && sfs_image_stat_metadata(h,0,2,&metadata,&r) == SFS_OK,"durable directory after rejected successful receipt")
            directoryMetadata(metadata,parent:1,mode:0o700); directoryNames(h!,2,[]); need(sfs_image_close(h,&r) == SFS_OK,"promoted directory reopen close")
        } else if scenario != 3 { m.reopened(inode:nil) }
    }
    for capacity in [UInt64(16384),UInt64(20480)] {
        let m = try CreationMount(parent,"directory-limit-\(capacity)",capacity:capacity,limit:2), v = m.volume
        m.serial { var info = sfs_image_information(), r = sfs_result(); need(sfs_image_get_information(m.coreHandle,&info,&r) == SFS_OK && r.committed_end == 16384 && info.append_headroom == capacity-16384,"directory capacity setup geometry") }
        let result = m.create(request:creationAttributes(0o700),type:.directory), outcome = v.createOutcomeForTesting
        need(result.0 == nil && code(result.1) == Int(ENOSPC) && outcome.original.status == SFS_LIMIT && outcome.original.limit_reason == SFS_LIMIT_APPEND_CAPACITY,"actual directory append capacity refusal")
        need(outcome.beginAttempted && outcome.beginSucceeded == (capacity == 20480) && outcome.discarded == (capacity == 20480) && outcome.releaseAttempted == (capacity == 16384),"directory begin reservation versus mutation discard")
        m.state(1,cap:2); m.absent(); m.close(); m.reopened(inode:nil)
    }
}
func directoryQueuedFailure(_ parent: URL) throws {
    let m = try CreationMount(parent,"directory-queued"), v = m.volume, before = v.anchor
    let held = DispatchSemaphore(value:0), release = DispatchSemaphore(value:0), finished = DispatchGroup()
    var preflights = 0, cleared = false
    v.enqueue { v.createStageForTesting = { stage,_ in if stage == "preflight" { preflights += 1 }; if stage == "inserted" { throw POSIXError(.ENOMEM) } }
        held.signal(); need(release.wait(timeout:.now()+20) == .success,"resume queued directory")
    }
    need(held.wait(timeout:.now()+20) == .success,"hold queued directory")
    let caller = CallerIdentity(uid:Int(geteuid()),gid:Int(getegid())), first = creationAttributes(), next = creationAttributes(0o700)
    finished.enter(); v.createResultForTesting(FSFileName(string:"first"),directory:m.root,attributes:first,caller:caller) { result,error in
        need(result == nil && code(error) == Int(ENOMEM),"preceding file creation fails"); v.createStageForTesting = nil; cleared = true; finished.leave()
    }
    finished.enter(); v.createResultForTesting(FSFileName(string:"next"),type:.directory,directory:m.root,attributes:next,caller:caller) { result,error in
        need(cleared && result == nil && code(error) == Int(ENOMEM),"queued directory preserves first failure after injection cleared"); finished.leave()
    }
    need(v.linkBudgetForTesting.0 == 2 && v.linkBudgetForTesting.1 == 2 * ReadOnlyLimits.callbackOverhead + 9,"both kind callbacks admitted and charged")
    release.signal(); need(finished.wait(timeout:.now()+20) == .success,"queued directory replies")
    m.serial { need(preflights == 1 && first.consumedAttributes.isEmpty && next.consumedAttributes.isEmpty && anchorMatches(before,v.anchor),"queued error precedes directory reservation/begin") }
    m.state(1); m.absent("first"); m.absent("next"); m.close(); m.reopened("first",inode:nil); m.reopened("next",inode:nil)
}
#endif

#if STALLION_CONTEXT_HANDLERS
// Owned real-core setup; rename itself always uses the contextual adapter path.
final class RenameFixture {
    let mount: CreationMount, from: StallionItem, to: StallionItem, item: StallionItem
    let child: StallionItem?
    let target: Data?
    init(_ parent: URL, _ name: String, directory: Bool = false, target: Data? = nil) throws {
        let m = try CreationMount(parent,name,limit:6); mount = m
        self.target = target
        m.serial {
            try! m.volume.diagnosticMutationForTesting { h,r in
                var initial = sfs_metadata_initial(), a: UInt64 = 0, b: UInt64 = 0, inode: UInt64 = 0
                initial.mode = UInt32(S_IFDIR) | 0o700; initial.uid = geteuid(); initial.gid = getegid()
                need(sfs_image_add_metadata(h,1,"A",1,SFS_DIRECTORY,&initial,&a,&r) == SFS_OK,"rename source parent fixture")
                need(sfs_image_add_metadata(h,1,"B",1,SFS_DIRECTORY,&initial,&b,&r) == SFS_OK,"rename destination parent fixture")
                if target == nil {
                    initial.mode = directory ? UInt32(S_IFDIR) | 0o700 : UInt32(S_IFREG) | 0o600
                    need(sfs_image_add_metadata(h,a,"old",3,directory ? SFS_DIRECTORY : SFS_FILE,&initial,&inode,&r) == SFS_OK,"rename source fixture")
                    if directory {
                        initial.mode = UInt32(S_IFREG) | 0o600
                        let directoryID = inode
                        need(sfs_image_add_metadata(h,directoryID,"child",5,SFS_FILE,&initial,&inode,&r) == SFS_OK,"nonempty moved directory fixture")
                    }
                    need(sfs_image_write(h,inode,0,"original",8,&r) == SFS_OK,"rename retained data fixture")
                }
            }
        }
        let a = m.lookup("A") as! StallionItem, b = m.lookup("B") as! StallionItem
        let source: StallionItem
        if let target {
            let created = createSymlink(m,FSFileName(data:target),name:"old",parent:a)
            need(created.0 != nil && created.1 == nil && created.2 != nil,"contextually created rename symlink")
            source = created.2!
        } else { source = m.lookup("old",parent:a) as! StallionItem }
        let nested = directory ? m.lookup("child",parent:source) as? StallionItem : nil
        from = a; to = b; item = source; child = nested
        m.returned.append(contentsOf:[a,b]); if target == nil { m.returned.append(source) }
        if let nested { m.returned.append(nested) }
    }
    func rename(_ old: String = "old", _ new: String = "new", source: FSItem? = nil,
                from oldParent: FSItem? = nil, to newParent: FSItem? = nil, over: FSItem? = nil,
                caller: CallerIdentity? = nil) -> (FSRenameItemResult?,Error?) {
        wait { done in mount.volume.renameResultForTesting(source ?? item,sourceDirectory:oldParent ?? from,sourceName:FSFileName(string:old),
            destinationName:FSFileName(string:new),destinationDirectory:newParent ?? to,overItem:over,
            caller:caller ?? CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { done(($0,$1)) } }
    }
    func names(_ old: String?, _ new: String?, newParent: UInt64? = nil) {
        mount.serial {
            var e = sfs_entry(), r = sfs_result()
            for (parent,name,present) in [(self.from.inode,"old",old != nil),(newParent ?? self.to.inode,new ?? "new",new != nil)] {
                let bytes = Data(name.utf8), status = bytes.withUnsafeBytes { sfs_image_lookup(self.mount.coreHandle,0,parent,$0.baseAddress,$0.count,&e,&r) }
                need(present ? status == SFS_OK && e.inode == self.item.inode : status == SFS_NOT_FOUND,"rename exact committed names")
            }
        }
    }
    func unchanged(_ before: sfs_result) {
        need(anchorMatches(before,mount.volume.anchor),"rename refusal/rollback preserves anchor")
        names("old",nil); mount.state(child == nil ? 4 : 5,cap:6)
        if let target { mount.serial { symlinkBytes(self.mount.coreHandle,self.item.inode,target) } }
    }
    func reopened(_ name: String = "old", parent: UInt64? = nil) {
        if let target { symlinkReopened(mount,name,parent:parent ?? from.inode,inode:item.inode,target:target) }
        else { mount.reopened(name,parent:parent ?? from.inode,inode:item.inode,bytes:child == nil ? Data("original".utf8) : nil) }
    }
}
func contextualRenames(_ parent: URL) throws {
    let required = FSRenameItemResult.requestedAttributes.wantedAttributes
#if STALLION_RESULT_MASK_TRACE
    let raw = UInt(bitPattern:required.rawValue)
    resultMaskTrace("FSRenameItemResult original=0x\(String(raw,radix:16)) outside_caller_readable=0x\(String(raw & ~UInt(0x3fff),radix:16)) explicit=0x0")
#endif
    let cases: [(Bool,Data?)] = [(false,nil),(true,nil),(false,Data("../target".utf8)),
                                (false,Data("/missing/absolute".utf8)),(false,Data([0xff,47,0x80]))]
    for (index,entry) in cases.enumerated() {
        let (directory,target) = entry
        let f = try RenameFixture(parent,"rename-success-\(index)",directory:directory,target:target), m = f.mount, v = m.volume
        let operands = [f.item,f.from,f.to], tokens = operands.map { $0.pin! }
        var snapshots: [FSItem.Attributes] = [], beforeCommit = true, constructors = 0
        m.serial {
            f.item.retainedModes = directory || target != nil ? [] : [.read,.write]
            v.createStageForTesting = { _,_ in need(false,"rename entered creation") }
            v.createCommitReceiptForTesting = { _ in need(false,"rename entered creation receipt") }
            v.removeCommitReceiptForTesting = { _,_ in need(false,"rename entered removal receipt") }
            v.preparedAttributesForTesting = { name,a in if name == "FSRenameItemResult" { need(beforeCommit,"rename snapshots precommit"); snapshots.append(a) } }
            v.rejectResultForTesting = { name in if name == "FSRenameItemResult" { need(beforeCommit && snapshots.count == 3,"actual rename constructor has three prepared roles"); constructors += 1 }; return false }
            v.diagnosticBeforeCommit = { beforeCommit = false }
        }
        func move(_ old: String,_ new: String,_ oldParent: FSItem,_ newParent: FSItem) -> FSRenameItemResult {
            let prior = constructors; m.serial { snapshots = []; beforeCommit = true }
            let result = f.rename(old,new,from:oldParent,to:newParent)
            need(result.1 == nil && result.0 != nil && constructors == prior+1 && snapshots.count == 3 && !beforeCommit,"actual rename result error=\(code(result.1)) roles=\(snapshots.count) constructors=\(constructors)")
            need(snapshots[0] !== snapshots[1] && snapshots[0] !== snapshots[2] && snapshots[1] !== snapshots[2],"three independent role snapshots even for same parent")
            for (a,item) in zip(snapshots,[f.item,oldParent,newParent]) { checkPreparedAttributes(a,m.metadata(item),required:required) }
            need(m.lookup(new,parent:newParent) === f.item,"rename preserves canonical object")
            if let target {
                let metadata = m.metadata(f.item)
                need(metadata.entry.kind == SFS_SYMLINK && metadata.entry.size == UInt64(target.count) && metadata.link_count == 1 && metadata.entry.parent == (newParent as! StallionItem).inode,"rename preserves symlink metadata and new parent")
                symlinkReadback(m,f.item,target)
            }
            m.serial { var entry = sfs_entry(), r = sfs_result(); let bytes = Data(old.utf8)
                need(bytes.withUnsafeBytes { sfs_image_lookup(m.coreHandle,0,(oldParent as! StallionItem).inode,$0.baseAddress,$0.count,&entry,&r) } == SFS_NOT_FOUND,"old renamed name absent")
            }
            m.state(directory ? 5 : 4,cap:6); return result.0!
        }
        let first = move("old","same",f.from,f.from), retained = snapshots
        let retainedMetadata = [m.metadata(f.item),m.metadata(f.from),m.metadata(f.from)]
        _ = move("same","cross",f.from,f.to)
        _ = move("cross","root-move",f.to,m.root)
        _ = move("root-move","final",m.root,f.from)
        for (a,metadata) in zip(retained,retainedMetadata) { checkPreparedAttributes(a,metadata,required:required) }
        for (item,token) in zip(operands,tokens) { need(sameBytes(item.pin!,token),"rename never replaces returned pins") }
        need(f.item.retainedModes == (directory || target != nil ? [] : [.read,.write]),"rename preserves retained open modes")
        let dataItem = f.child ?? f.item
        m.serial { if target == nil { need(try! v.diagnosticReadForTesting(dataItem,length:16) == Data("original".utf8),"moved data survives") }
            directoryNames(m.coreHandle,f.from.inode,["final"]); directoryNames(m.coreHandle,f.to.inode,[])
            if directory { directoryNames(m.coreHandle,f.item.inode,["child"]) }
        }
        if let child = f.child { need(m.lookup("child",parent:f.item) === child && m.metadata(child).entry.parent == f.item.inode,"descendant canonical parent survives move"); directoryMetadata(m.metadata(f.item),parent:f.from.inode,mode:0o700) }
        withExtendedLifetime(first) {}
        m.close(); m.reopened("old",parent:f.from.inode,inode:nil); f.reopened("final")
        if let child = f.child { m.reopened("child",parent:f.item.inode,inode:child.inode,bytes:Data("original".utf8)) }
        var h: OpaquePointer?, r = sfs_result(), value = sfs_metadata_entry()
        need(sfs_image_open_readonly(m.url.path,"image.sfs",&h,&r) == SFS_OK && sfs_image_stat_metadata(h,0,f.item.inode,&value,&r) == SFS_OK && value.entry.parent == f.from.inode && value.link_count == 1,"reopened moved metadata")
        if directory { directoryMetadata(value,parent:f.from.inode,mode:0o700) }
        need(sfs_image_close(h,&r) == SFS_OK,"rename metadata reopen close")
    }
    try renameRefusals(parent); try renamePolicies(parent); try renameFailures(parent,required:required); try renameQueued(parent)
}
func renameRefusals(_ parent: URL) throws {
    for symlink in [false,true] {
    let f = try RenameFixture(parent,"rename-refusals-\(symlink)",target:symlink ? Data("../target".utf8) : nil), m = f.mount, v = m.volume, before = v.anchor
    var prepared = false
    m.serial { v.diagnosticBeforePrepare = { prepared = true } }
    need(code(f.rename(over:f.item).1) == Int(ENOTSUP),"rename overwrite parameter refused")
    need(code(f.rename("old","old",to:f.from).1) == Int(EEXIST),"same path refused")
    need(code(f.rename(source:f.to).1) == Int(ESTALE),"wrong actual source identity refused")
    need(code(f.rename("missing").1) == Int(ENOENT),"missing old name refused")
    need(code(f.rename(source:m.root).1) == Int(ENOTSUP),"root rename refused")
    need(code(f.rename(from:f.item).1) == Int(ENOTDIR) && code(f.rename(to:f.item).1) == Int(ENOTDIR),"both rename parents must be directories")
    for role in 0..<3 {
        let foreign = StallionItem(role == 0 ? f.item.inode : role == 1 ? f.from.inode : f.to.inode)
        need(code(f.rename(source:role == 0 ? foreign : nil,from:role == 1 ? foreign : nil,to:role == 2 ? foreign : nil).1) == Int(EINVAL),"foreign rename operand \(role)")
    }
    for name in ["", ".", "..", "bad/name", String(repeating:"n",count:256)] {
        let expected = name.utf8.count > 255 ? ENAMETOOLONG : EINVAL
        need(code(f.rename(name).1) == Int(expected) && code(f.rename("old",name).1) == Int(expected),"both rename components validated")
    }
    for caller in [CallerIdentity(uid:-1,gid:0),CallerIdentity(uid:Int(geteuid()),gid:-1),CallerIdentity(uid:Int(geteuid())+1,gid:Int(getegid()))] {
        need(code(f.rename(caller:caller).1) == Int(EACCES),"rename contextual identity")
    }
    need(!prepared,"preflight errors never reach prepare"); f.unchanged(before)
    m.serial { v.diagnosticBeforePrepare = nil }
    for role in 0..<3 {
        let old: StallionItem = role == 0 ? f.item : role == 1 ? f.from : f.to
        need(m.reclaim(old) == nil,"reclaim rename operand")
        need(code(f.rename(source:role == 0 ? old : m.lookup("old",parent:m.lookup("A")),from:role == 1 ? old : m.lookup("A"),to:role == 2 ? old : m.lookup("B")).1) == Int(EINVAL),"reclaimed rename operand \(role)")
        // Restore canonical map ownership only through a real lookup; retain every newly returned object for cleanup.
        let replacement = role == 0 ? m.lookup("old",parent:m.lookup("A")) : m.lookup(role == 1 ? "A" : "B")
        m.returned.append(replacement)
    }
    m.close(); f.reopened()
    }
    let aliases = try Fixture(parent,"rename-types"), a = try Mounted(aliases,itemLimit:3)
    a.serial {
        try! a.volume.diagnosticMutationForTesting { h,r in
            need(sfs_image_link(h,(a.link as! StallionItem).inode,1,"link-alias",10,&r) == SFS_OK,"true second symlink name fixture")
        }
        var r = sfs_result()
        var metadata = sfs_metadata_entry()
        need(sfs_image_stat_metadata(a.coreHandle,0,(a.link as! StallionItem).inode,&metadata,&r) == SFS_OK && metadata.link_count == 2,"observe committed multiply linked symlink before rename")
    }
    let beforeAliases = a.volume.anchor
    for item in [a.file,a.link] {
        let result: (FSRenameItemResult?,Error?) = wait { done in a.volume.renameResultForTesting(item,sourceDirectory:a.root,sourceName:FSFileName(string:item === a.file ? "file" : "link"),destinationName:FSFileName(string:"new"),destinationDirectory:a.root,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { done(($0,$1)) } }
        need(result.0 == nil && code(result.1) == Int(ENOTSUP) && anchorMatches(beforeAliases,a.volume.anchor),"multiply named source rename refused")
    }
    a.serial { var entry = sfs_entry(), metadata = sfs_metadata_entry(), r = sfs_result()
        for name in ["link","link-alias"] { let bytes = Data(name.utf8)
            need(bytes.withUnsafeBytes { sfs_image_lookup(a.coreHandle,0,1,$0.baseAddress,$0.count,&entry,&r) } == SFS_OK && entry.inode == (a.link as! StallionItem).inode,"both refused symlink names retain identity")
        }
        need(sfs_image_lookup(a.coreHandle,0,1,"new",3,&entry,&r) == SFS_NOT_FOUND,"multiply linked rename does not publish destination")
        need(sfs_image_stat_metadata(a.coreHandle,0,(a.link as! StallionItem).inode,&metadata,&r) == SFS_OK && metadata.link_count == 2,"refused symlink keeps both links")
        symlinkBytes(a.coreHandle,(a.link as! StallionItem).inode,Data("file".utf8))
    }
    a.close(); namespaceReopened(aliases,"file",inode:aliases.id)
    for name in ["link","link-alias"] { namespaceReopened(aliases,name,inode:(a.link as! StallionItem).inode) }
    var reopened: OpaquePointer?, receipt = sfs_result(), linkedMetadata = sfs_metadata_entry()
    need(sfs_image_open_readonly(aliases.url.path,"image.sfs",&reopened,&receipt) == SFS_OK &&
         sfs_image_stat_metadata(reopened,0,(a.link as! StallionItem).inode,&linkedMetadata,&receipt) == SFS_OK && linkedMetadata.link_count == 2,"reopened refused symlink retains both links")
    symlinkBytes(reopened!,(a.link as! StallionItem).inode,Data("file".utf8))
    need(sfs_image_close(reopened,&receipt) == SFS_OK,"close hardlinked symlink readback")
    for descendant in [false,true] {
        let cycle = try RenameFixture(parent,"rename-cycle-\(descendant)",directory:true), c = cycle.mount, anchor = c.volume.anchor
        // Core checks run after begin; they must make no namespace edits. The adapter still remembers the delivery error.
        let result = descendant ? cycle.rename("A","descendant",source:cycle.from,from:c.root,to:cycle.item) : cycle.rename("old","self",to:cycle.item)
        need(result.0 == nil && code(result.1) == Int(EINVAL),"self/descendant cycle rejected by core")
        let first = c.volume.diagnosticSnapshot().2!
        need(first.result.status == SFS_INVALID && first.result.transaction_active != 0,"cycle refusal is inside transaction before cleanup")
        cycle.unchanged(anchor)
        c.serial { directoryNames(c.coreHandle,cycle.item.inode,["child"]) }
        need(code(cycle.rename().1) == Int(EINVAL) && anchorMatches(anchor,c.volume.anchor),"sticky cycle delivery error blocks later rename despite nonterminal core rollback")
        c.close(); c.reopened("old",parent:cycle.from.inode,inode:cycle.item.inode); c.reopened("new",parent:cycle.to.inode,inode:nil)
    }
}
func renamePolicies(_ parent: URL) throws {
    // Source and each distinct parent are independently denied; no shared-parent shortcut.
    for symlink in [false,true] {
    for role in 0..<3 { for policy in 0..<(role == 0 ? 4 : 6) {
        let f = try RenameFixture(parent,"rename-policy-\(symlink)-\(role)-\(policy)",target:symlink ? Data("../target".utf8) : nil), m = f.mount, v = m.volume
        let operand = role == 0 ? f.item : role == 1 ? f.from : f.to
        m.serial { try! v.diagnosticMutationForTesting { h,r in
            if policy == 3 { need(sfs_image_set_xattr(h,operand.inode,"com.apple.system.Security",25,nil,0,&r) == SFS_OK,"rename ACL policy setup") }
            else {
                var change = sfs_metadata_update()
                if policy == 0 { change.fields = UInt32(SFS_META_UID.rawValue); change.uid = geteuid()+1 }
                else if policy == 1 { change.fields = UInt32(SFS_META_FLAGS.rawValue); change.flags = 1 }
                else { change.fields = UInt32(SFS_META_MODE.rawValue); change.mode = role == 0 ? UInt32(symlink ? S_IFLNK : S_IFREG) | 0o6600 : UInt32(S_IFDIR) | (policy == 2 ? 0o1700 : policy == 4 ? 0o500 : 0o600) }
                need(sfs_image_set_metadata(h,operand.inode,&change,&r) == SFS_OK,"rename metadata policy setup")
            }
        } }
        let before = v.anchor, result = f.rename()
        need(result.0 == nil && code(result.1) == Int(policy == 1 || policy == 3 ? ENOTSUP : EACCES),"rename isolated role policy \(role)/\(policy)")
        f.unchanged(before); m.close(); f.reopened()
    } }
    }
    for spec in 0..<3 {
        let f = try RenameFixture(parent,"rename-gate-\(spec)"), m = f.mount
        if spec == 2 { let before = m.volume.anchor; m.resource.revoke(); need(code(f.rename().1) == Int(EACCES) && anchorMatches(before,m.volume.anchor),"revoked rename gate"); m.close() }
        else {
            m.close(); var h: OpaquePointer?, r = sfs_result()
            let status = spec == 0 ? sfs_image_open_readonly(m.url.path,"image.sfs",&h,&r) : sfs_image_open(m.url.path,"image.sfs",&h,&r)
            need(status == SFS_OK,"rename unbound gate open")
            let resource = FSPathURLResource(url:m.url,writable:spec != 0), v = StallionVolume(admission:.forTesting(handle:h!,anchor:r),resource:resource,scope:false,queue:DispatchQueue(label:"sfs.rename.gate"))
            let activation: (FSItem?,Error?) = wait { done in v.activate { done(($0,$1)) } }; need(activation.1 == nil,"rename gate activate")
            let mounted: Error? = wait { v.mount(arguments:[],replyHandler:$0) }; need(mounted == nil,"rename gate mount")
            let result: (FSRenameItemResult?,Error?) = wait { done in v.renameResultForTesting(activation.0!,sourceDirectory:activation.0!,sourceName:FSFileName(string:"A"),destinationName:FSFileName(string:"new"),destinationDirectory:activation.0!,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { done(($0,$1)) } }
            need(result.0 == nil && code(result.1) == Int(EROFS) && anchorMatches(r,v.anchor),"RO or missing exact UUID refuses before operands")
            let _: Bool = wait { done in v.unmount { done(true) } }
            let consumed: Bool = wait { done in v.enqueue { done(v.unload().consumed) } }; need(consumed,"unbound rename gate close")
        }
        m.reopened("old",parent:f.from.inode,inode:f.item.inode,bytes:Data("original".utf8))
    }
}
func renameFailures(_ parent: URL, required: FSItem.Attribute) throws {
    need(!required.isEmpty,"actual rename requirements must be observed")
    for symlink in [false,true] {
    for role in 0..<3 {
        let f = try RenameFixture(parent,"rename-incomplete-\(symlink)-\(role)",target:symlink ? Data("../target".utf8) : nil), m = f.mount, v = m.volume, before = v.anchor
        let token = f.item.pin!
        var index = 0, constructed = false
        m.serial { v.preparedAttributesForTesting = { name,a in if name == "FSRenameItemResult" { if index == role { a.invalidateAllProperties() }; index += 1 } }
            v.rejectResultForTesting = { _ in constructed = true; return false }
        }
        let result = f.rename()
        need(result.0 == nil && code(result.1) == Int(ENOTSUP) && index == role+1 && !constructed,"rename role \(role) fails completeness before constructor")
        f.unchanged(before)
        m.serial { need(v.ownsForTesting(f.item) && sameBytes(token,f.item.pin!),"incomplete rename result preserves returned pin") }
        m.close(); f.reopened(); m.reopened("new",parent:f.to.inode,inode:nil)
    }
    for scenario in 0..<4 {
        let f = try RenameFixture(parent,"rename-failure-\(symlink)-\(scenario)",target:symlink ? Data("../target".utf8) : nil), m = f.mount, v = m.volume, before = v.anchor
        let token = f.item.pin!; var constructed = false
        m.serial {
            v.createCommitReceiptForTesting = { _ in need(false,"rename failure creation receipt") }; v.removeCommitReceiptForTesting = { _,_ in need(false,"rename failure removal receipt") }
            v.rejectResultForTesting = { name in if name == "FSRenameItemResult" { constructed = true; return scenario == 0 }; return false }
            if scenario == 1 { v.diagnosticBeforeCommit = { m.resource.revoke() } }
            if scenario >= 2 { v.diagnosticBeforeCommit = { fault(4,Int32(scenario-1)) } }
        }
        let result = f.rename()
        need(result.0 == nil && code(result.1) == Int(scenario == 0 ? EIO : scenario == 1 ? EACCES : ENOSPC) && constructed && anchorMatches(before,v.anchor),"rename failure \(scenario) error=\(code(result.1)) actual constructor reached")
        if scenario >= 2 { need(hits() > 0 && v.diagnosticSnapshot().2?.result.status == (scenario == 2 ? SFS_IO : SFS_OUTCOME_UNKNOWN),"actual rename fence failure versus uncertain outcome") }
        fault(0,0)
        m.serial { need(v.ownsForTesting(f.item) && sameBytes(token,f.item.pin!) && !v.createStateForTesting.pending && !v.createStateForTesting.quarantine,"rename failures never clean up returned pins") }
        if scenario < 2 { f.unchanged(before) }
        m.close()
        if scenario != 3 { f.reopened(); m.reopened("new",parent:f.to.inode,inode:nil) }
        // OUTCOME_UNKNOWN is retained without asserting either durable namespace.
    }
    }
    // Root-only plus one empty file commits eight cells: 4 initial + inode/name/namespace/commit.
    // At heights hi=hn=1, rename reserves delete6 + insert9 + inode1 + namespace/commit2 =18 cells.
    for capacity in [UInt64(32768),UInt64(36864)] {
        let m = try CreationMount(parent,"rename-limit-\(capacity)",capacity:capacity,limit:2), v = m.volume
        let created = m.create("old"); need(created.0 != nil && created.1 == nil && created.2 != nil,"capacity rename source creation")
        let item = created.2!, before = v.anchor
        m.serial { var info = sfs_image_information(), r = sfs_result(); need(sfs_image_get_information(m.coreHandle,&info,&r) == SFS_OK && r.committed_end == 32768 && info.append_headroom == capacity-32768,"rename actual fixture geometry zero/one free cell") }
        let result: (FSRenameItemResult?,Error?) = wait { done in v.renameResultForTesting(item,sourceDirectory:m.root,sourceName:FSFileName(string:"old"),destinationName:FSFileName(string:"new"),destinationDirectory:m.root,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { done(($0,$1)) } }
        let receipt = v.diagnosticSnapshot().2!.result
        need(result.0 == nil && code(result.1) == Int(ENOSPC) && receipt.status == SFS_LIMIT && receipt.limit_reason == SFS_LIMIT_APPEND_CAPACITY && receipt.phase == SFS_PHASE_ADMISSION && receipt.transaction_active == 0 && anchorMatches(before,v.anchor),"real begin/rename reservation capacity failure")
        m.state(2,cap:2); m.close(); m.reopened("old",inode:item.inode); m.reopened("new",inode:nil)
    }
}
func renameQueued(_ parent: URL) throws {
    for symlink in [false,true] {
    for occupied in [false,true] {
        let f = try RenameFixture(parent,"rename-stale-\(symlink)-\(occupied)",target:symlink ? Data("../target".utf8) : nil), m = f.mount, v = m.volume
        let token = f.item.pin!
        let held = DispatchSemaphore(value:0), release = DispatchSemaphore(value:0), finished = DispatchGroup()
        var replacement: UInt64 = 0, substituted = false, after = v.anchor
        v.enqueue { held.signal(); need(release.wait(timeout:.now()+20) == .success,"resume stale rename queue") }
        need(held.wait(timeout:.now()+20) == .success,"hold stale rename queue")
        v.enqueue {
            try! v.diagnosticMutationForTesting { h,r in
                if !occupied { need(sfs_image_rename_replace(h,f.from.inode,"old",3,f.item.inode,f.from.inode,"retained",8,0,&r) == SFS_OK,"move retained original away from stale name") }
                var initial = sfs_metadata_initial(); initial.mode = UInt32(S_IFREG) | 0o600; initial.uid = geteuid(); initial.gid = getegid()
                let name = occupied ? "new" : "old"
                need(sfs_image_add_metadata(h,occupied ? f.to.inode : f.from.inode,name,3,SFS_FILE,&initial,&replacement,&r) == SFS_OK,"commit real stale name replacement")
            }
            after = v.anchor; substituted = true
        }
        finished.enter(); v.renameResultForTesting(f.item,sourceDirectory:f.from,sourceName:FSFileName(string:"old"),destinationName:FSFileName(string:"new"),destinationDirectory:f.to,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { result,error in
            need(substituted && result == nil && code(error) == Int(occupied ? EEXIST : ESTALE) && anchorMatches(after,v.anchor),"queued exact source/absent target rechecked"); finished.leave()
        }
        release.signal(); need(finished.wait(timeout:.now()+20) == .success,"stale rename reply")
        m.serial { need(v.ownsForTesting(f.item) && sameBytes(token,f.item.pin!),"queued refusal preserves canonical source pin"); if let target = f.target { symlinkBytes(m.coreHandle,f.item.inode,target) } }
        m.state(4,cap:6); m.close()
        m.reopened(occupied ? "new" : "old",parent:occupied ? f.to.inode : f.from.inode,inode:replacement)
        f.reopened(occupied ? "old" : "retained")
    }
    let f = try RenameFixture(parent,"rename-queued-failure-\(symlink)",target:symlink ? Data("../target".utf8) : nil), m = f.mount, v = m.volume, before = v.anchor
    let held = DispatchSemaphore(value:0), release = DispatchSemaphore(value:0), finished = DispatchGroup()
    var cleared = false, preflights = 0
    v.enqueue { v.diagnosticBeforePrepare = { throw POSIXError(.ENOMEM) }; v.renamePreflightForTesting = { preflights += 1 }; held.signal(); need(release.wait(timeout:.now()+20) == .success,"resume queued rename") }
    need(held.wait(timeout:.now()+20) == .success,"hold queued rename")
    finished.enter()
    if symlink {
        v.renameResultForTesting(f.item,sourceDirectory:f.from,sourceName:FSFileName(string:"old"),destinationName:FSFileName(string:"first"),destinationDirectory:f.to,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { result,error in
            need(result == nil && code(error) == Int(ENOMEM),"preceding symlink rename error retained"); v.diagnosticBeforePrepare = nil; cleared = true; finished.leave()
        }
    } else {
        v.writeCountForTesting(contents:Data([1]),to:f.item,at:0) { count,error in
            need(count == 0 && code(error) == Int(ENOMEM),"preceding write error retained"); v.diagnosticBeforePrepare = nil; cleared = true; finished.leave()
        }
    }
    finished.enter(); v.renameResultForTesting(f.item,sourceDirectory:f.from,sourceName:FSFileName(string:"old"),destinationName:FSFileName(string:"new"),destinationDirectory:f.to,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { result,error in
        need(cleared && result == nil && code(error) == Int(ENOMEM),"queued rename blocked after injection cleared"); finished.leave()
    }
    need(v.linkBudgetForTesting.0 == 2 && v.linkBudgetForTesting.1 == 2 * ReadOnlyLimits.callbackOverhead + (symlink ? 14 : 7),"both callback payloads charged")
    release.signal(); need(finished.wait(timeout:.now()+20) == .success,"queued rename replies")
    m.serial { need(preflights == (symlink ? 1 : 0),"queued delivery guard before later rename preflight") }; f.unchanged(before); m.close(); f.reopened()
    }
    let arithmetic = CallbackBudget()
    need(!arithmetic.acquire(Int.max) && arithmetic.isEmpty,"overflow-sized retained payload cannot enter budget")
    let b = try RenameFixture(parent,"rename-budget"), bm = b.mount, bv = bm.volume
    let stopped = DispatchSemaphore(value:0), resume = DispatchSemaphore(value:0), replies = DispatchGroup()
    let old = String(repeating:"s",count:255), new = String(repeating:"d",count:255)
    bv.enqueue { stopped.signal(); need(resume.wait(timeout:.now()+20) == .success,"resume saturated rename queue") }
    need(stopped.wait(timeout:.now()+20) == .success,"hold saturated rename queue")
    // The adapter-only hold is uncharged; 256 queued renames fill the callback slots.
    for _ in 0..<ReadOnlyLimits.callbacks {
        replies.enter(); bv.renameResultForTesting(b.item,sourceDirectory:b.from,sourceName:FSFileName(string:old),destinationName:FSFileName(string:new),destinationDirectory:b.to,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { result,error in
            need(result == nil && code(error) == Int(ENOENT),"bounded maximum-component rename returns missing source"); replies.leave()
        }
    }
    need(bv.linkBudgetForTesting.0 == ReadOnlyLimits.callbacks && bv.linkBudgetForTesting.1 == ReadOnlyLimits.callbacks * ReadOnlyLimits.callbackOverhead + ReadOnlyLimits.callbacks*510,"both maximum names charged at slot boundary")
    need(code(b.rename(old,new).1) == Int(EAGAIN),"saturated rename rejected synchronously")
    resume.signal(); need(replies.wait(timeout:.now()+20) == .success,"bounded saturated rename drain")
    bm.state(4,cap:6); b.names("old",nil); bm.close()
}
#endif

#if STALLION_CONTEXT_HANDLERS
func createSymlink(_ m: CreationMount, _ target: FSFileName, name: String = "new", parent: FSItem? = nil,
                   attributes: FSItem.SetAttributesRequest? = nil, caller: CallerIdentity? = nil) -> (FSCreateSymlinkResult?,Error?,StallionItem?) {
    var item: StallionItem?, prior: ((String,StallionItem?) throws -> Void)?
    m.serial { prior = m.volume.createStageForTesting; m.volume.createStageForTesting = { stage,value in
        if stage == "inserted" { item = value }; try prior?(stage,value)
    } }
    let result: (FSCreateSymlinkResult?,Error?) = wait { done in m.volume.symlinkResultForTesting(FSFileName(string:name),directory:parent ?? m.root,
        attributes:attributes ?? creationAttributes(0o700),linkContents:target,caller:caller ?? CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { done(($0,$1)) } }
    m.serial { m.volume.createStageForTesting = prior }
    if result.0 != nil, let item { m.returned.append(item) }
    return (result.0,result.1,result.0 == nil ? nil : item)
}
func symlinkBytes(_ h: OpaquePointer, _ inode: UInt64, _ expected: Data) {
    var r = sfs_result(), bytes = Data(count:4096), count = 0
    need(bytes.withUnsafeMutableBytes { sfs_image_readlink(h,0,inode,$0.baseAddress,$0.count,&count,&r) } == SFS_OK && count == expected.count && bytes.prefix(count) == expected,"raw exact stored target without terminator")
}
func symlinkReopened(_ m: CreationMount, _ name: String = "new", parent: UInt64 = 1, inode: UInt64, target: Data) {
    m.reopened(name,parent:parent,inode:inode)
    var h: OpaquePointer?, r = sfs_result(), metadata = sfs_metadata_entry()
    need(sfs_image_open_readonly(m.url.path,"image.sfs",&h,&r) == SFS_OK && sfs_image_stat_metadata(h,0,inode,&metadata,&r) == SFS_OK,"symlink reopen metadata")
    need(metadata.entry.kind == SFS_SYMLINK && metadata.entry.size == UInt64(target.count) && metadata.referenced_data_bytes == 4096 && metadata.link_count == 1 && metadata.entry.parent == parent,"truthful target size/allocation/links/parent")
    symlinkBytes(h!,inode,target); need(sfs_image_close(h,&r) == SFS_OK,"symlink reopen close")
}
func symlinkReadback(_ m: CreationMount, _ item: StallionItem, _ target: Data) {
    let result: (FSReadSymlinkResult?,Error?) = wait { done in m.volume.readlinkResultForTesting(item,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { done(($0,$1)) } }
    need(result.0 != nil && result.1 == nil,"actual contextual readlink constructor error=\(code(result.1))")
    // Result classes expose no target getter. This is the same readlinkBody's legacy return, correlated with raw storage.
    let legacy: (FSFileName?,Error?) = wait { done in m.volume.readSymbolicLink(item) { done(($0,$1)) } }
    need(legacy.1 == nil && legacy.0?.data == target,"shared readlink body exact delivered bytes")
    m.serial { symlinkBytes(m.coreHandle,item.inode,target) }
}
func contextualSymlinkCreation(_ parent: URL) throws {
    let required = FSCreateSymlinkResult.requestedAttributes.wantedAttributes
#if STALLION_RESULT_MASK_TRACE
    let raw = UInt(bitPattern:required.rawValue)
    resultMaskTrace("FSCreateSymlinkResult original=0x\(String(raw,radix:16)) outside_caller_readable=0x\(String(raw & ~UInt(0x3fff),radix:16)) explicit=0x0")
#endif
    let targets = [Data("missing".utf8),Data("/missing/absolute".utf8),Data("../a/./b".utf8),Data("目标/é".utf8),Data([0xff,0xfe,47,0x80]),Data([120]),Data(repeating:120,count:4096)]
    for (index,expected) in targets.enumerated() {
        let target = FSFileName(data:expected); need(target.data == expected,"observe non-NUL FSFileName input bytes")
        let m = try CreationMount(parent,"symlink-target-\(index)"), v = m.volume, attributes = creationAttributes(index % 2 == 0 ? 0o700 : UInt32(S_IFLNK) | 0o750)
        attributes.flags = 0
        var snapshots: [FSItem.Attributes] = [], beforeCommit = true, constructors = 0
        m.serial {
            v.preparedAttributesForTesting = { name,a in if name == "FSCreateSymlinkResult" { need(beforeCommit,"symlink snapshots precommit"); snapshots.append(a) } }
            v.rejectResultForTesting = { name in if name == "FSCreateSymlinkResult" { need(beforeCommit && snapshots.count == 2,"concrete symlink constructor has two complete roles"); constructors += 1 }; return false }
            v.diagnosticBeforeCommit = { beforeCommit = false }
            v.removeCommitReceiptForTesting = { _,_ in need(false,"symlink creation entered removal receipt hook") }
        }
        let first = createSymlink(m,target,attributes:attributes)
        need(first.0 != nil && first.1 == nil && first.2 != nil && constructors == 1 && snapshots.count == 2 && !beforeCommit,"actual symlink result error=\(code(first.1)) roles=\(snapshots.count) constructors=\(constructors)")
        let item = first.2!, childMetadata = m.metadata(item), parentMetadata = m.metadata(m.root)
        need(snapshots[0] !== snapshots[1] && childMetadata.entry.kind == SFS_SYMLINK && childMetadata.entry.size == UInt64(expected.count) && childMetadata.referenced_data_bytes == 4096 && childMetadata.mode == UInt32(S_IFLNK) | (attributes.mode & 0o777) && childMetadata.uid == geteuid() && childMetadata.gid == getegid() && childMetadata.flags == 0 && childMetadata.link_count == 1,"actual symlink metadata")
        need(attributes.consumedAttributes == [.mode,.uid,.gid,.flags],"only explicitly supported symlink fields consumed")
        checkPreparedAttributes(snapshots[0],childMetadata,required:required); checkPreparedAttributes(snapshots[1],parentMetadata,required:required)
        need(m.lookup("new") === item,"new symlink canonical identity"); symlinkReadback(m,item,expected); m.state(2)
        let ignored = FSItem.SetAttributesRequest(); ignored.size = UInt64.max
        let resized: (FSItem.Attributes?,Error?) = wait { done in v.setAttributesValueForTesting(ignored,on:item,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { done(($0,$1)) } }
        need(resized.1 == nil && ignored.consumedAttributes.isEmpty,"existing symlink resize-ignore behavior preserved")
        checkPreparedAttributes(snapshots[0],childMetadata,required:required); withExtendedLifetime(first.0) {}
        m.close(); symlinkReopened(m,inode:item.inode,target:expected)
    }
    // The public constructor discards the suffix BEFORE the callback; do not label this a callback NUL rejection.
    let truncated = FSFileName(data:Data([97,0,98])); need(truncated.data == Data([97]),"observe documented NUL truncation to delivered prefix")
    let t = try CreationMount(parent,"symlink-truncated"), result = createSymlink(t,truncated)
    need(result.0 != nil && result.1 == nil && result.2 != nil,"create only delivered prefix"); symlinkReadback(t,result.2!,truncated.data)
    t.close(); symlinkReopened(t,inode:result.2!.inode,target:Data([97]))
    try symlinkReuse(parent,required:required); try symlinkRefusals(parent); try symlinkFailures(parent); try symlinkQueued(parent)
}
func symlinkReuse(_ parent: URL, required: FSItem.Attribute) throws {
    let m = try CreationMount(parent,"symlink-reuse",directory:true,limit:5), v = m.volume, target = FSFileName(string:"../missing")
    var snapshots: [FSItem.Attributes] = []
    m.serial { v.preparedAttributesForTesting = { name,a in if name == "FSCreateSymlinkResult" { snapshots.append(a) } } }
    let first = createSymlink(m,target,name:"first")
    need(first.0 != nil && first.1 == nil && first.2 != nil && snapshots.count == 2,"first reusable symlink result error=\(code(first.1))")
    let item = first.2!
    let retained = snapshots, original = [m.metadata(item),m.metadata(m.root)], token = item.pin!
    m.state(3,cap:5)
    let file = m.create("file",parent:m.directory!); need(file.0 != nil && file.1 == nil && file.2 != nil,"ordinary file interleaved with symlink"); m.state(4,cap:5)
    let second = createSymlink(m,target,name:"second",parent:m.directory!,attributes:creationAttributes(UInt32(S_IFLNK) | 0o700))
    need(second.0 != nil && second.1 == nil && second.2 != nil && second.2! !== item,"nonroot full-mode symlink"); m.state(5,cap:5)
    let before = v.anchor, full = createSymlink(m,target,name:"full")
    need(full.0 == nil && code(full.1) == Int(ENFILE) && anchorMatches(before,v.anchor),"symlink cap before reservation")
    let freed = file.2!.pin!; need(m.reclaim(file.2!) == nil,"reclaim interleaved file slot"); m.state(4,cap:5)
    let directory = m.create("nested",request:creationAttributes(0o700),parent:m.directory!,type:.directory)
    need(directory.0 != nil && directory.1 == nil && directory.2!.pin!.slot == freed.slot && directory.2!.pin!.incarnation > freed.incarnation,"directory reuses slot after symlink state"); m.state(5,cap:5)
    let secondToken = second.2!.pin!; need(m.reclaim(second.2!) == nil,"reclaim second symlink slot"); m.state(4,cap:5)
    let third = createSymlink(m,target,name:"third",parent:directory.2!)
    need(third.0 != nil && third.1 == nil && third.2 != nil && third.2!.inode != item.inode && third.2!.inode != second.2!.inode && third.2!.pin!.slot == secondToken.slot && third.2!.pin!.incarnation > secondToken.incarnation,"symlink reuses only slot with fresh real identity")
    need(m.lookup("first") === item && sameBytes(token,item.pin!),"first canonical identity survives interleaving")
    symlinkReadback(m,item,target.data); symlinkReadback(m,third.2!,target.data); m.state(5,cap:5)
    for (a,metadata) in zip(retained,original) { checkPreparedAttributes(a,metadata,required:required) }
    withExtendedLifetime(first.0) {}
    m.close(); symlinkReopened(m,"first",inode:item.inode,target:target.data); symlinkReopened(m,"second",parent:(m.directory as! StallionItem).inode,inode:second.2!.inode,target:target.data)
    symlinkReopened(m,"third",parent:directory.2!.inode,inode:third.2!.inode,target:target.data)
}
func symlinkRefusals(_ parent: URL) throws {
    let m = try CreationMount(parent,"symlink-refusals"), v = m.volume, target = FSFileName(string:"target"), before = v.anchor
    var reserved = false
    m.serial { v.createStageForTesting = { stage,_ in if stage == "reserved" { reserved = true } } }
    let empty = FSFileName(data:Data([0,120])); need(empty.data.isEmpty,"leading NUL delivers empty target")
    for (contents,expected) in [(FSFileName(data:Data()),EINVAL),(empty,EINVAL),(FSFileName(data:Data(repeating:120,count:4097)),ENAMETOOLONG)] {
        let a = creationAttributes(0o700); need(code(createSymlink(m,contents,attributes:a).1) == Int(expected) && a.consumedAttributes.isEmpty,"invalid delivered target before reserve")
    }
    for size in [UInt64(0),UInt64(6),UInt64.max] { let a = creationAttributes(0o700); a.size = size; need(code(createSymlink(m,target,attributes:a).1) == Int(ENOTSUP) && a.consumedAttributes.isEmpty,"every supplied symlink size refused") }
    for missing in 0..<3 {
        let a = FSItem.SetAttributesRequest(); if missing != 0 { a.mode = 0o700 }; if missing != 1 { a.uid = geteuid() }; if missing != 2 { a.gid = getegid() }
        need(code(createSymlink(m,target,attributes:a).1) == Int(ENOTSUP) && a.consumedAttributes.isEmpty,"explicit required symlink fields")
    }
    for mode in [UInt32(S_IFREG)|0o700,UInt32(S_IFDIR)|0o700] { need(code(createSymlink(m,target,attributes:creationAttributes(mode)).1) == Int(EINVAL),"conflicting symlink mode kind") }
    for mode in [UInt32(0o1700),UInt32(0o2700),UInt32(0o4700),UInt32(1)<<31] { need(code(createSymlink(m,target,attributes:creationAttributes(mode)).1) == Int(ENOTSUP),"special/unknown symlink mode") }
    for field in 0..<5 {
        let a = creationAttributes(0o700)
        if field == 0 { a.uid = geteuid()+1 }; if field == 1 { a.gid = getegid()+1 }; if field == 2 { a.flags = 1 }; if field == 3 { a.type = .symlink }; if field == 4 { a.birthTime = timespec(tv_sec:1,tv_nsec:0) }
        need(code(createSymlink(m,target,attributes:a).1) == Int(field < 2 ? EACCES : ENOTSUP) && a.consumedAttributes.isEmpty,"symlink explicit unsupported/mismatched attributes")
    }
    for caller in [CallerIdentity(uid:-1,gid:0),CallerIdentity(uid:Int(geteuid()),gid:-1),CallerIdentity(uid:Int(geteuid())+1,gid:Int(getegid()))] { need(code(createSymlink(m,target,caller:caller).1) == Int(EACCES),"symlink actual caller validation") }
    for name in ["", ".", "..", "bad/name", String(repeating:"n",count:256)] { need(code(createSymlink(m,target,name:name).1) == Int(name.utf8.count > 255 ? ENAMETOOLONG : EINVAL),"link name remains component") }
    need(code(createSymlink(m,target,parent:StallionItem(1)).1) == Int(EINVAL),"foreign symlink parent")
    need(code(m.create(type:.symlink).1) == Int(ENOTSUP),"ordinary createItem still has no target")
    need(!reserved && anchorMatches(before,v.anchor),"all symlink preflight errors before reserve"); m.state(1); m.absent()
    m.serial { v.createStageForTesting = nil }
    let first = createSymlink(m,target); need(first.0 != nil && first.1 == nil && first.2 != nil,"valid symlink after refusal sequence")
    let committed = v.anchor
    need(code(createSymlink(m,target).1) == Int(EEXIST) && code(createSymlink(m,target,parent:first.2!).1) == Int(ENOTDIR) && anchorMatches(committed,v.anchor),"occupied/non-directory symlink parent refusal")
    need(m.reclaim(first.2!) == nil && code(createSymlink(m,target,parent:first.2!).1) == Int(EINVAL),"reclaimed symlink parent refused")
    m.close(); symlinkReopened(m,inode:first.2!.inode,target:target.data)
    for spec in 0..<8 {
        let p = try CreationMount(parent,"symlink-policy-\(spec)",rootMode:spec == 0 ? 0o500 : spec == 1 ? 0o600 : spec == 2 ? 0o1700 : 0o700,
            rootFlags:spec == 3 ? 1 : 0,rootOwner:spec == 4 ? geteuid()+1 : geteuid(),acl:spec == 5,writable:spec != 6,enable:spec != 7)
        need(code(createSymlink(p,target).1) == Int(spec == 3 || spec == 5 ? ENOTSUP : spec >= 6 ? EROFS : EACCES),"symlink isolated parent/write policy")
        p.close(); p.reopened(inode:nil)
    }
    let restrictive = try CreationMount(parent,"symlink-restrictive"), link = createSymlink(restrictive,target,attributes:creationAttributes(0o200))
    need(link.0 != nil && link.1 == nil && link.2 != nil,"explicit restrictive symlink mode retained")
    let read: (FSReadSymlinkResult?,Error?) = wait { done in restrictive.volume.readlinkResultForTesting(link.2!,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))) { done(($0,$1)) } }
    need(read.0 == nil && code(read.1) == Int(EACCES),"creation does not grant contextual readlink")
    restrictive.serial { symlinkBytes(restrictive.coreHandle,link.2!.inode,target.data) }
    restrictive.close(); symlinkReopened(restrictive,inode:link.2!.inode,target:target.data)
}
func symlinkFailures(_ parent: URL) throws {
    let target = FSFileName(string:"../target")
    for role in 0..<2 {
        let m = try CreationMount(parent,"symlink-incomplete-\(role)"), v = m.volume, before = v.anchor
        var seen = 0, constructed = false
        m.serial { v.preparedAttributesForTesting = { name,a in if name == "FSCreateSymlinkResult" { if seen == role { a.invalidateAllProperties() }; seen += 1 } }; v.rejectResultForTesting = { _ in constructed = true; return false } }
        let a = creationAttributes(0o700), result = createSymlink(m,target,attributes:a)
        need(result.0 == nil && code(result.1) == Int(ENOTSUP) && seen == role+1 && !constructed && a.consumedAttributes.isEmpty && anchorMatches(before,v.anchor),"symlink role invalid before concrete constructor")
        m.state(1); m.absent(); m.close(); m.reopened(inode:nil)
    }
    for stage in ["added","bound"] {
        let m = try CreationMount(parent,"symlink-stage-\(stage)"), v = m.volume
        weak var unreturned: StallionItem?
        m.serial { v.createStageForTesting = { observed,item in if observed == stage { unreturned = item; throw POSIXError(.ENOMEM) } } }
        let a = creationAttributes(0o700), result = createSymlink(m,target,attributes:a), outcome = v.createOutcomeForTesting
        need(result.0 == nil && code(result.1) == Int(ENOMEM) && a.consumedAttributes.isEmpty && outcome.discarded && !outcome.releaseAttempted && unreturned == nil,"symlink stage cleanup without double release or object retention")
        m.state(1); m.absent(); m.close(); m.reopened(inode:nil)
    }
    for scenario in 0..<5 {
        let m = try CreationMount(parent,"symlink-failure-\(scenario)"), v = m.volume, before = v.anchor
        var constructed = false
        m.serial {
            v.removeCommitReceiptForTesting = { _,_ in need(false,"symlink entered removal receipt") }
            if scenario == 0 { v.rejectResultForTesting = { name in if name == "FSCreateSymlinkResult" { constructed = true; return true }; return false } }
            if scenario == 1 { v.diagnosticBeforeCommit = { m.resource.revoke() } }
            if scenario == 4 { v.createCommitReceiptForTesting = { $0.fence_succeeded = 0 } }
        }
        if scenario == 2 || scenario == 3 { fault(4,Int32(scenario-1)) }
        let a = creationAttributes(0o700), result = createSymlink(m,target,attributes:a), outcome = v.createOutcomeForTesting
        need(result.0 == nil && code(result.1) == Int(scenario == 1 ? EACCES : scenario == 2 || scenario == 3 ? ENOSPC : EIO) && a.consumedAttributes.isEmpty && anchorMatches(before,v.anchor),"symlink failure \(scenario) error=\(code(result.1))")
        if scenario == 0 { need(constructed,"real concrete constructor precedes injected symlink failure") }
        if scenario == 2 || scenario == 3 { need(hits() > 0 && outcome.original.status == (scenario == 2 ? SFS_IO : SFS_OUTCOME_UNKNOWN),"actual symlink first/second fence disposition") }
        fault(0,0)
        if scenario == 4 {
            need(outcome.commitSucceeded && outcome.commit.status == SFS_OK && outcome.commit.fence_succeeded == 3 && !outcome.abortAttempted && outcome.releaseAttempted && outcome.release.status == SFS_OK,"promoted symlink pin released without abort after actual C success")
            let token = v.createTokenForTesting!
            m.serial { var r = sfs_result(), value = sfs_pin_stat(); need(sfs_image_pin_stat(m.coreHandle,token,&value,&r) == SFS_INVALID && !v.createStateForTesting.pending && v.activeItemCount() == 1,"unreturned promoted symlink token consumed") }
        } else { need(outcome.discarded && !outcome.releaseAttempted,"discarded symlink reservation not released twice") }
        m.close()
        if scenario == 4 { symlinkReopened(m,inode:2,target:target.data) }
        else if scenario != 3 { m.reopened(inode:nil) }
    }
    for capacity in [UInt64(16384),UInt64(20480),UInt64(40960)] {
        let m = try CreationMount(parent,"symlink-limit-\(capacity)",capacity:capacity,limit:2), v = m.volume
        m.serial { var info = sfs_image_information(), r = sfs_result(); need(sfs_image_get_information(m.coreHandle,&info,&r) == SFS_OK && r.committed_end == 16384 && info.append_headroom == capacity-16384,"actual symlink root-only capacity geometry") }
        let contents = FSFileName(data:Data(repeating:120,count:4096)); need(contents.data.count == 4096,"actual max target delivered")
        let a = creationAttributes(0o700), result = createSymlink(m,contents,attributes:a), outcome = v.createOutcomeForTesting
        if capacity == 40960 {
            need(result.0 != nil && result.1 == nil && result.2 != nil && v.anchor.committed_end == 40960,"six symlink cells fit exact capacity")
            m.state(2,cap:2); m.close(); symlinkReopened(m,inode:result.2!.inode,target:contents.data)
        } else {
            need(result.0 == nil && code(result.1) == Int(ENOSPC) && outcome.original.status == SFS_LIMIT && outcome.original.limit_reason == SFS_LIMIT_APPEND_CAPACITY && a.consumedAttributes.isEmpty,"actual symlink append capacity failure")
            need(outcome.beginSucceeded == (capacity == 20480) && outcome.discarded == (capacity == 20480) && outcome.releaseAttempted == (capacity == 16384),"symlink begin reservation versus mutation discard")
            m.state(1,cap:2); m.absent(); m.close(); m.reopened(inode:nil)
        }
    }
    let q = try CreationMount(parent,"symlink-release-quarantine"), v = q.volume
    q.serial { v.createStageForTesting = { stage,_ in if stage == "reserved" { throw POSIXError(.ENOMEM) } }; v.createReleaseForTesting = { _,_,r in r.status = SFS_IO; r.system_errno = EIO; return SFS_IO } }
    let failure = createSymlink(q,target)
    q.serial { need(failure.0 == nil && code(failure.1) == Int(ENOMEM) && v.createStateForTesting.pending && v.createStateForTesting.quarantine && v.createStateForTesting.ticket == 1 && v.activeItemCount() == 1 && v.createOutcomeForTesting.release.status == SFS_IO,"primary symlink failure plus unresolved release quarantine") }
    q.close(); q.reopened(inode:nil)
}
func symlinkQueued(_ parent: URL) throws {
    for quarantine in [false,true] {
        let m = try CreationMount(parent,"symlink-queued-\(quarantine)",directory:quarantine), v = m.volume, before = v.anchor
        let held = DispatchSemaphore(value:0), resume = DispatchSemaphore(value:0), replies = DispatchGroup()
        var preflights = 0, cleared = false
        weak var unreturned: StallionItem?
        v.enqueue {
            v.createStageForTesting = { stage,item in if stage == "preflight" { preflights += 1 }; if stage == "inserted" { unreturned = item; throw POSIXError(.ENOMEM) } }
            if quarantine { v.createAbortForTesting = { _,r in r.status = SFS_IO; r.transaction_active = 1; r.system_errno = EIO; return SFS_IO } }
            held.signal(); need(resume.wait(timeout:.now()+20) == .success,"resume symlink queue")
        }
        need(held.wait(timeout:.now()+20) == .success,"hold symlink queue")
        let caller = CallerIdentity(uid:Int(geteuid()),gid:Int(getegid())), first = creationAttributes(0o700), next = creationAttributes(0o700), target = FSFileName(string:"../target")
        replies.enter(); v.symlinkResultForTesting(FSFileName(string:"first"),directory:m.root,attributes:first,linkContents:target,caller:caller) { result,error in
            need(result == nil && code(error) == Int(ENOMEM),"first symlink failure"); v.createStageForTesting = nil; v.createAbortForTesting = nil; cleared = true; replies.leave()
        }
        replies.enter(); v.symlinkResultForTesting(FSFileName(string:"next"),directory:m.root,attributes:next,linkContents:target,caller:caller) { result,error in
            need(cleared && result == nil && code(error) == Int(ENOMEM),"queued symlink preserves first error after injection cleared"); replies.leave()
        }
        need(v.linkBudgetForTesting.0 == 2 && v.linkBudgetForTesting.1 == 2*ReadOnlyLimits.callbackOverhead + 9 + 2*target.data.count,"both names and targets charged")
        resume.signal(); need(replies.wait(timeout:.now()+20) == .success,"symlink queue drained")
        m.serial { let state = v.createStateForTesting
            need(preflights == 1 && first.consumedAttributes.isEmpty && next.consumedAttributes.isEmpty && anchorMatches(before,v.anchor) && state.pending == quarantine && state.quarantine == quarantine && state.ticket == (quarantine ? 1 : 0) && unreturned == nil,"symlink queued guard and token-only cleanup")
            if quarantine { need(v.createOutcomeForTesting.cleanup.status == SFS_IO && !v.createOutcomeForTesting.discarded,"unresolved symlink abort receipt") }
        }
        need(v.linkBudgetForTesting.0 == 0 && v.linkBudgetForTesting.1 == 0,"symlink queue releases all charges")
        m.close(); m.reopened("first",inode:nil); m.reopened("next",inode:nil)
    }
    let m = try CreationMount(parent,"symlink-budget"), v = m.volume
    let held = DispatchSemaphore(value:0), resume = DispatchSemaphore(value:0), replies = DispatchGroup()
    let name = FSFileName(string:String(repeating:"n",count:255)), target = FSFileName(data:Data(repeating:120,count:4096)), caller = CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))
    need(name.data.count == 255 && target.data.count == 4096,"maximum delivered name/target")
    v.enqueue { held.signal(); need(resume.wait(timeout:.now()+20) == .success,"resume saturated symlink queue") }
    need(held.wait(timeout:.now()+20) == .success,"hold saturated symlink queue")
    var successes = 0, duplicates = 0
    for _ in 0..<ReadOnlyLimits.callbacks {
        replies.enter(); v.symlinkResultForTesting(name,directory:m.root,attributes:creationAttributes(0o700),linkContents:target,caller:caller) { result,error in
            need((result != nil && error == nil) || (result == nil && code(error) == Int(EEXIST)),"first max symlink succeeds and later duplicate names refuse"); if result != nil { successes += 1 } else { duplicates += 1 }; replies.leave()
        }
    }
    need(v.linkBudgetForTesting.0 == 256 && v.linkBudgetForTesting.1 == 2_162_432,"exact max name+target callback bound")
    let refused: (FSCreateSymlinkResult?,Error?) = wait { done in v.symlinkResultForTesting(name,directory:m.root,attributes:creationAttributes(0o700),linkContents:target,caller:caller) { done(($0,$1)) } }
    need(refused.0 == nil && code(refused.1) == Int(EAGAIN),"saturated symlink admission refuses without charge")
    resume.signal(); need(replies.wait(timeout:.now()+20) == .success,"bounded symlink admission drain")
    need(successes == 1 && duplicates == 255,"exact saturated symlink outcomes")
    let item = m.lookup(String(repeating:"n",count:255)) as! StallionItem; m.returned.append(item)
    m.state(2); symlinkReadback(m,item,target.data); m.close(); symlinkReopened(m,String(repeating:"n",count:255),inode:item.inode,target:target.data)
}
#endif

#if STALLION_CONTEXT_HANDLERS
func setXattr(_ m: Mounted, name: FSFileName = FSFileName(string: "note"), value: Data?,
              policy: FSVolume.SetXattrPolicy = .alwaysSet, item: FSItem? = nil,
              caller: CallerIdentity? = nil) -> (FSSetXattrResult?, Error?) {
    wait { done in m.volume.setXattrResultForTesting(name, value: value, item: item ?? m.file, policy: policy,
        caller: caller ?? CallerIdentity(uid: Int(geteuid()), gid: Int(getegid()))) { done(($0,$1)) } }
}
func coreXattr(_ h: OpaquePointer, inode: UInt64, name: Data, view: sfs_view = 0, pin: sfs_pin? = nil) -> Data? {
    var r = sfs_result(), size: UInt64 = 0
    let status = name.withUnsafeBytes { bytes -> sfs_status in
        if let pin { return sfs_image_pin_xattr_size(h,pin,bytes.baseAddress,bytes.count,&size,&r) }
        return sfs_image_xattr_size(h,view,inode,bytes.baseAddress,bytes.count,&size,&r)
    }
    if status == SFS_NOT_FOUND { return nil }
    need(status == SFS_OK && size <= UInt64(ReadOnlyLimits.xattrValue),"checked xattr size")
    var data = Data(count:Int(size)), count = 0
    let read = name.withUnsafeBytes { bytes in data.withUnsafeMutableBytes { output -> sfs_status in
        if let pin { return sfs_image_pin_read_xattr(h,pin,bytes.baseAddress,bytes.count,0,output.baseAddress,output.count,&count,&r) }
        return sfs_image_read_xattr(h,view,inode,bytes.baseAddress,bytes.count,0,output.baseAddress,output.count,&count,&r)
    } }
    need(read == SFS_OK && count == data.count,"exact complete binary xattr"); return data
}
func reopenedXattr(_ f: Fixture, name: Data = Data("note".utf8), view: sfs_view = 0) -> Data? {
    fault(0,0); var h: OpaquePointer?, r = sfs_result()
    need(sfs_image_open_readonly(f.url.path,"image.sfs",&h,&r) == SFS_OK,"xattr reopen")
    let value = coreXattr(h!,inode:f.id,name:name,view:view)
    need(sfs_image_close(h,&r) == SFS_OK,"xattr reopen close"); return value
}
func xattrMetadataUnchanged(_ before: sfs_metadata_entry, _ after: sfs_metadata_entry) {
    need(before.entry.inode == after.entry.inode && before.entry.parent == after.entry.parent &&
         before.entry.kind == after.entry.kind && before.entry.size == after.entry.size &&
         before.entry.name_length == after.entry.name_length && sameBytes(before.entry.name,after.entry.name) &&
         before.mode == after.mode && before.uid == after.uid && before.gid == after.gid && before.flags == after.flags &&
         before.link_count == after.link_count && before.referenced_data_bytes == after.referenced_data_bytes,
         "xattr preserves identity, data allocation, link count and permissions")
    for (a,b) in [(before.birth,after.birth),(before.access,after.access),(before.modification,after.modification)] {
        need(a.seconds == b.seconds && a.nanoseconds == b.nanoseconds,"xattr preserves other times")
    }
}
func contextualXattrValues(_ parent: URL) throws {
    let f = try Fixture(parent,"xattr-values"), m = try Mounted(f), v = m.volume
    var oldView: sfs_view = 0
    m.serial { try! v.diagnosticMutationForTesting { h,r in
        need(sfs_image_snapshot(h,"before-xattr",12,&oldView,&r) == SFS_OK,"committed xattr snapshot")
    } }
    let before = namespaceMetadata(m,m.file), binary = Data([0,255,1,0,128])
    let result = setXattr(m,value:binary,policy:.mustReplace)
    need(result.0 != nil && result.1 == nil,"real set-xattr result")
    let after = namespaceMetadata(m,m.alias); xattrMetadataUnchanged(before,after)
    need(after.change.seconds != before.change.seconds || after.change.nanoseconds != before.change.nanoseconds,"xattr updates ctime")
    m.serial {
        need(coreXattr(m.coreHandle,inode:f.id,name:Data("note".utf8)) == binary,"hardlink alias xattr")
        need(coreXattr(m.coreHandle,inode:f.id,name:Data("note".utf8),view:oldView) == Data("value".utf8),"snapshot retains previous xattr")
        try! v.linkAccessForTesting(m.file,access:[.writeXattr,.readAttributes],caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid())))
        let refused: [FSVolume.AccessMask] = [[.writeXattr,.delete],[.writeXattr,.writeSecurity]]
        for mask in refused {
            do { try v.linkAccessForTesting(m.file,access:mask,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))); need(false,"xattr granted unrelated access") }
            catch { need(code(error) == Int(EACCES),"mixed xattr mask delegates unrelated bits") }
        }
    }
    let absent = FSFileName(string:"org.example.binary"), anchor = v.anchor, commits = v.diagnosticSnapshot().0.commits
    for policy in [FSVolume.SetXattrPolicy.mustReplace,.delete] {
        need(code(setXattr(m,name:absent,value:policy == .delete ? nil : binary,policy:policy).1) == Int(ENOATTR),"missing attribute policy")
    }
    need(code(setXattr(m,value:binary,policy:.mustCreate).1) == Int(EEXIST),"create existing attribute")
    for policy in [FSVolume.SetXattrPolicy.alwaysSet,.mustCreate,.mustReplace] {
        need(code(setXattr(m,name:absent,value:nil,policy:policy).1) == Int(EINVAL),"nil is not an empty set")
    }
    need(anchorMatches(v.anchor,anchor) && v.diagnosticSnapshot().0.commits == commits && v.diagnosticSnapshot().2 == nil,"policy failures neither commit nor poison delivery")
    let unchanged = namespaceMetadata(m,m.file)
    need(unchanged.change.seconds == after.change.seconds && unchanged.change.nanoseconds == after.change.nanoseconds,"policy failure preserves ctime")
    need(setXattr(m,name:absent,value:Data(),policy:.mustCreate).1 == nil,"empty attribute creates")
    m.serial { need(coreXattr(m.coreHandle,inode:f.id,name:absent.data) == Data(),"empty attribute remains present") }
    need(setXattr(m,name:absent,value:binary,policy:.mustReplace).1 == nil,"replace empty attribute")
    need(setXattr(m,name:absent,value:Data([9]),policy:.delete).1 == nil,"delete ignores supplied value")
    need(setXattr(m,value:nil,policy:.delete).1 == nil,"nil delete")
    need(setXattr(m,value:binary,policy:.mustCreate).1 == nil,"create after delete")
    let names: [Data] = [Data("com.apple.FinderInfo".utf8),Data("com.apple.quarantine".utf8),Data("com.apple.ResourceFork".utf8),
        Data("org.example/value".utf8),Data(".".utf8),Data("..".utf8),Data([0xc3,0xa9]),Data([0x65,0xcc,0x81]),Data([0xff]),Data(repeating:120,count:255)]
    var delivered: [(Data,Data)] = []
    for raw in names {
        try writableXattrName(raw)
        let name = FSFileName(data:raw), value = name.data == Data("com.apple.FinderInfo".utf8) ? Data(repeating:7,count:32) : binary
        need(setXattr(m,name:name,value:value).1 == nil,"ordinary delivered opaque name accepted")
        delivered.append((name.data,value))
        m.serial { need(coreXattr(m.coreHandle,inode:f.id,name:name.data) == value,"delivered name bytes roundtrip") }
    }
    let truncated = FSFileName(data:Data([97,0,98]))
    need(truncated.data == Data([97]) && setXattr(m,name:truncated,value:binary).1 == nil,"callback receives constructor's NUL prefix only")
    for (bytes,expected) in [(Data(),EINVAL),(Data([97,0,98]),EINVAL),(Data(repeating:97,count:256),ENAMETOOLONG)] {
        do { try writableXattrName(bytes); need(false,"raw invalid name accepted") }
        catch { need(code(error) == Int(expected),"raw-name validator independently rejects") }
    }
    let large = FSFileName(string:"large"), limit = Data(repeating:0xa5,count:ReadOnlyLimits.xattrValue)
    need(setXattr(m,name:large,value:limit).1 == nil,"one MiB boundary accepted")
    let largeAnchor = v.anchor
    need(code(setXattr(m,name:large,value:Data(count:ReadOnlyLimits.xattrValue+1)).1) == Int(E2BIG) &&
         code(setXattr(m,name:large,value:Data(count:ReadOnlyLimits.xattrValue+1),policy:.delete).1) == Int(E2BIG) && anchorMatches(largeAnchor,v.anchor),"set and ignored delete data stay bounded")
    m.close()
    need(reopenedXattr(f) == binary && reopenedXattr(f,view:oldView) == Data("value".utf8),"reopened current and historical values")
    for (name,value) in delivered { need(reopenedXattr(f,name:name) == value,"reopened ordinary xattr bytes") }
    need(reopenedXattr(f,name:large.data) == limit && reopenedXattr(f,name:absent.data) == nil && f.contents() == Data("original".utf8),"reopened value limit, deletion and unchanged file bytes")
}
func contextualXattrRefusals(_ parent: URL) throws {
    for index in 0..<5 {
        let f = try Fixture(parent,"xattr-policy-\(index)",mode:index == 0 ? 0o400 : index == 1 ? 0o1600 : 0o600,
            acl:index == 2,owner:index == 3 ? geteuid()+1 : geteuid(),sourceFlags:index == 4 ? 1 : 0)
        let m = try Mounted(f), v = m.volume, anchor = v.anchor
        let expected = [EACCES,EACCES,ENOTSUP,EACCES,ENOTSUP][index]
        need(code(setXattr(m,value:Data([1])).1) == Int(expected),"xattr mode/ACL/owner/flags refusal")
        m.serial { do { try v.linkAccessForTesting(m.file,access:.writeXattr,caller:CallerIdentity(uid:Int(geteuid()),gid:Int(getegid()))); need(false,"access check bypassed xattr policy") }
            catch { need(code(error) == Int(expected),"access and setter share xattr policy") } }
        need(anchorMatches(v.anchor,anchor) && v.diagnosticSnapshot().0.commits == 0,"refused xattr unchanged")
        m.close(); need(reopenedXattr(f) == Data("value".utf8),"refused xattr persists original")
    }
    let f = try Fixture(parent,"xattr-refusals",directory:true), m = try Mounted(f), v = m.volume, anchor = v.anchor
    for name in ["com.apple.system.Security","com.apple.system.anything","com.apple.acl.text","com.apple.decmpfs","com.apple.macl","com.apple.provenance"] {
        need(code(setXattr(m,name:FSFileName(string:name),value:Data()).1) == Int(ENOTSUP),"unsupported policy metadata refused")
    }
    for caller in [CallerIdentity(uid:Int(geteuid())+1,gid:Int(getegid())),CallerIdentity(uid:-1,gid:Int(getegid())),CallerIdentity(uid:Int(geteuid()),gid:-1)] {
        need(code(setXattr(m,value:Data(),caller:caller).1) == Int(EACCES),"foreign/unrepresentable xattr caller")
    }
    if geteuid() != 0 { need(code(setXattr(m,value:Data(),caller:CallerIdentity(uid:0,gid:0)).1) == Int(EACCES),"root has no xattr owner bypass") }
    let directory = namespaceLookup(m,"dir")
    for item in [m.root,m.link,directory] { need(code(setXattr(m,value:Data(),item:item).1) == Int(ENOTSUP),"nonregular xattr target refused") }
    need(code(setXattr(m,value:Data(),item:StallionItem(f.id)).1) == Int(EINVAL),"foreign canonical item refused")
    m.serial { var r = sfs_result(); need(sfs_image_begin(m.coreHandle,&r) == SFS_OK,"active transaction refusal setup") }
    need(code(setXattr(m,value:Data()).1) == Int(EBUSY),"xattr cannot enter an existing transaction")
    m.serial { var r = sfs_result(); need(sfs_image_abort(m.coreHandle,&r) == SFS_OK,"original transaction remains caller-owned") }
    need(anchorMatches(v.anchor,anchor) && v.diagnosticSnapshot().0.commits == 0,"preflight refusals never mutate")
    let released: Error? = wait { v.reclaimForTesting(m.file,eligible:true,replyHandler:$0) }
    need(released == nil && code(setXattr(m,value:Data()).1) == Int(EINVAL),"reclaimed target refused")
    let directoryReleased: Error? = wait { v.reclaimForTesting(directory,eligible:true,replyHandler:$0) }
    need(directoryReleased == nil,"release retained xattr refusal directory")
    m.close(); need(reopenedXattr(f) == Data("value".utf8),"all refusals preserve original")
    let roFixture = try Fixture(parent,"xattr-readonly"), ro = try Mounted(roFixture,writable:false)
    need(code(setXattr(ro,value:Data()).1) == Int(EROFS),"unbound readonly contextual setter refused"); ro.close()
    let detachedFixture = try Fixture(parent,"xattr-detached"), detached = try Mounted(detachedFixture)
    detached.serial { try! detached.volume.diagnosticMutationForTesting { h,r in
        need(sfs_image_unlink_expected(h,1,"file",4,detachedFixture.id,&r) == SFS_OK &&
             sfs_image_unlink_expected(h,1,"alias",5,detachedFixture.id,&r) == SFS_OK,"controlled core detach; no contextual final unlink")
    } }
    need(setXattr(detached,value:Data([0,255]),policy:.mustReplace).1 == nil,"detached pin xattr mutation")
    detached.serial {
        need(coreXattr(detached.coreHandle,inode:detachedFixture.id,name:Data("note".utf8),pin:(detached.file as! StallionItem).pin!) == Data([0,255]),"detached value isolated")
        var r = sfs_result(), e = sfs_entry()
        need(sfs_image_lookup(detached.coreHandle,0,1,"file",4,&e,&r) == SFS_NOT_FOUND &&
             sfs_image_lookup(detached.coreHandle,0,1,"alias",5,&e,&r) == SFS_NOT_FOUND,"xattr does not resurrect names")
    }
    need(setXattr(detached,value:nil,policy:.delete).1 == nil,"detached xattr delete"); detached.close()
}
func contextualXattrFailures(_ parent: URL) throws {
    for mode in 0..<8 {
        let f = try Fixture(parent,"xattr-failure-\(mode)"), m = try Mounted(f), v = m.volume, anchor = v.anchor
        m.serial {
            if mode == 0 { v.rejectResultForTesting = { $0 == "FSSetXattrResult" } }
            if mode == 1 { v.diagnosticBeforeCommit = { m.resource.revoke() } }
            if mode == 2 { v.diagnosticBeforePrepare = { sfs_image_clear_read_cache(m.coreHandle); fault(8,1) } }
        }
        if mode == 3 { fault(7,1) }
        if mode == 4 { fault(1,1) }
        if mode == 5 || mode == 6 { fault(4,Int32(mode-4)) }
        if mode == 7 { fault(6,1) }
        let result = setXattr(m,value:Data([8,0,255]))
        let expected = mode == 0 || mode == 2 ? EIO : mode == 1 ? EACCES : mode == 3 ? ENOMEM : mode == 7 ? ENXIO : ENOSPC
        need(result.0 == nil && code(result.1) == Int(expected) && anchorMatches(v.anchor,anchor),"xattr failure never acknowledges a result")
        if mode >= 2 { need(hits() > 0,"real core fault reached") }
        if mode == 5 || mode == 6 {
            let failure = v.diagnosticSnapshot().2!
            need(failure.result.status == (mode == 5 ? SFS_IO : SFS_OUTCOME_UNKNOWN) &&
                 failure.result.phase == (mode == 5 ? SFS_PHASE_RECORD_BARRIER : SFS_PHASE_COMMIT_BARRIER) &&
                 failure.result.poisoned != 0,"original xattr fence receipt retained")
            fault(0,0); need(code(setXattr(m,value:Data()).1) == Int(ENOSPC),"xattr fence failure stays sticky")
        }
        if mode == 0 {
            m.serial { var r = sfs_result(), info = sfs_image_information()
                need(sfs_image_get_information(m.coreHandle,&info,&r) == SFS_OK && r.transaction_active == 0 && anchorMatches(r,anchor),"result failure verified abort") }
            need(code(m.sync()) == Int(EIO),"xattr constructor failure survives sync")
        }
        fault(0,0); m.close()
        let persisted = reopenedXattr(f)
        if mode != 6 { need(persisted == Data("value".utf8),"failed xattr leaves acknowledged value") }
        else { need(persisted == Data("value".utf8) || persisted == Data([8,0,255]),"unknown xattr publication is one complete state") }
        need(f.contents() == Data("original".utf8),"xattr fault never changes file data")
    }
    let f = try Fixture(parent,"xattr-capacity",capacity:128*1024), m = try Mounted(f), anchor = m.volume.anchor
    let result = setXattr(m,value:Data(count:ReadOnlyLimits.xattrValue))
    need(result.0 == nil && code(result.1) == Int(ENOSPC) && anchorMatches(m.volume.anchor,anchor),"real xattr append capacity refuses atomically")
    let failure = m.volume.diagnosticSnapshot().2!
    need(failure.result.status == SFS_LIMIT && failure.result.limit_reason == SFS_LIMIT_APPEND_CAPACITY,"capacity receipt preserves limit reason")
    m.close(); need(reopenedXattr(f) == Data("value".utf8),"capacity failure preserves original xattr")
}
func contextualXattrQueue(_ parent: URL) throws {
    let f = try Fixture(parent,"xattr-queue"), m = try Mounted(f), v = m.volume
    let held = DispatchSemaphore(value:0), release = DispatchSemaphore(value:0), replies = DispatchGroup()
    let caller = CallerIdentity(uid:Int(geteuid()),gid:Int(getegid())), name = FSFileName(string:"race"), data = Data([0,255])
    var outcomes: [Int] = []
    v.enqueue { held.signal(); need(release.wait(timeout:.now()+20) == .success,"release xattr policy race") }
    need(held.wait(timeout:.now()+20) == .success,"hold xattr queue")
    for _ in 0..<2 {
        replies.enter(); v.setXattrResultForTesting(name,value:data,item:m.file,policy:.mustCreate,caller:caller) { result,error in
            need((result != nil) == (error == nil),"xattr result and error exclusive"); outcomes.append(code(error)); replies.leave()
        }
    }
    let deletedName = FSFileName(string:"note")
    replies.enter(); v.setXattrResultForTesting(deletedName,value:data,item:m.file,policy:.delete,caller:caller) { result,error in
        need(result != nil && error == nil,"queued delete ignores retained value"); replies.leave()
    }
    let charged = v.linkBudgetForTesting
    need(charged.0 == 3 && charged.1 == 2*(ReadOnlyLimits.callbackOverhead+name.data.count+data.count) +
         ReadOnlyLimits.callbackOverhead+deletedName.data.count+data.count,"queued xattrs charge name and value, including ignored delete bytes")
    release.signal(); need(replies.wait(timeout:.now()+20) == .success,"both xattr policies finish")
    m.serial {}
    need(outcomes == [0,Int(EEXIST)] && v.linkBudgetForTesting.0 == 0 && v.linkBudgetForTesting.1 == 0,"serialized create-only policy and ticket release")
    m.close(); need(reopenedXattr(f,name:name.data) == data && reopenedXattr(f) == nil,"policy-race winner and deletion persist")
    let failedFixture = try Fixture(parent,"xattr-queued-failure"), failed = try Mounted(failedFixture), fv = failed.volume, anchor = fv.anchor
    let entered = DispatchSemaphore(value:0), resume = DispatchSemaphore(value:0), done = DispatchGroup()
    fv.enqueue { fv.diagnosticBeforePrepare = { throw POSIXError(.ENOMEM) }; entered.signal(); need(resume.wait(timeout:.now()+20) == .success,"release failing xattr queue") }
    need(entered.wait(timeout:.now()+20) == .success,"hold failing xattr queue")
    for index in 0..<2 {
        done.enter(); fv.setXattrResultForTesting(FSFileName(string:"note"),value:data,item:failed.file,policy:.alwaysSet,caller:caller) { result,error in
            need(result == nil && code(error) == Int(ENOMEM),"queued xattr returns first failure")
            if index == 0 { fv.diagnosticBeforePrepare = nil }; done.leave()
        }
    }
    resume.signal(); need(done.wait(timeout:.now()+20) == .success,"drain failing xattr queue")
    need(anchorMatches(fv.anchor,anchor) && fv.diagnosticSnapshot().0.commits == 0 && code(failed.sync()) == Int(ENOMEM),"no later xattr commit after delivery failure")
    failed.serial {}
    need(fv.linkBudgetForTesting.0 == 0 && fv.linkBudgetForTesting.1 == 0,"failed xattr tickets returned")
    failed.close(); need(reopenedXattr(failedFixture) == Data("value".utf8),"queued failure preserves reopened xattr")
    let budgetFixture = try Fixture(parent,"xattr-admission"), budgetMount = try Mounted(budgetFixture), bv = budgetMount.volume
    let blocked = DispatchSemaphore(value:0), unblock = DispatchSemaphore(value:0), drained = DispatchGroup()
    bv.enqueue { blocked.signal(); need(unblock.wait(timeout:.now()+20) == .success,"release saturated xattr queue") }
    need(blocked.wait(timeout:.now()+20) == .success,"hold saturated xattr queue")
    for _ in 0..<ReadOnlyLimits.callbacks {
        drained.enter(); bv.enqueue(rejected:{ _ in need(false,"fill xattr callback budget") }) { drained.leave() }
    }
    let full = bv.linkBudgetForTesting
    need(code(setXattr(budgetMount,value:data).1) == Int(EAGAIN) && bv.linkBudgetForTesting.0 == full.0 &&
         bv.linkBudgetForTesting.1 == full.1,"xattr saturation rejects without consuming a ticket")
    unblock.signal(); need(drained.wait(timeout:.now()+20) == .success,"drain saturated xattr queue")
    let cutoff = DispatchSemaphore(value:0), continueCutoff = DispatchSemaphore(value:0), completed = DispatchGroup()
    bv.enqueue { cutoff.signal(); need(continueCutoff.wait(timeout:.now()+20) == .success,"release xattr unmount cutoff") }
    need(cutoff.wait(timeout:.now()+20) == .success,"hold xattr before unmount")
    completed.enter(); bv.setXattrResultForTesting(FSFileName(string:"note"),value:data,item:budgetMount.file,policy:.alwaysSet,caller:caller) { result,error in
        need(result != nil && error == nil,"precutoff xattr commits"); completed.leave()
    }
    completed.enter(); bv.unmount { completed.leave() }
    need(code(setXattr(budgetMount,value:data,policy:.delete).1) == Int(EAGAIN),"postcutoff xattr immediately refused")
    continueCutoff.signal(); need(completed.wait(timeout:.now()+20) == .success,"xattr and ordered unmount complete")
    need(code(setXattr(budgetMount,value:data).1) == Int(ENXIO) && bv.linkBudgetForTesting.0 == 0 &&
         bv.linkBudgetForTesting.1 == 0,"unmounted xattr refuses and releases all tickets")
    budgetMount.close(); need(reopenedXattr(budgetFixture) == data,"only precutoff xattr persists")
}
#endif

#endif
@main struct Driver {
    static func main() throws {
        if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--factory-policy" {
            try factoryPolicyChecks(URL(fileURLWithPath:CommandLine.arguments[2],isDirectory:true))
            print("PASS public factory access selection, refusal and persistence")
            return
        }
        if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--access-policy" {
            try accessPolicyChecks(URL(fileURLWithPath:CommandLine.arguments[2],isDirectory:true))
            print("PASS immutable read-only selection, contextual open grants and retained-write delivery")
            return
        }
#if STALLION_WRITE_DIAGNOSTIC
#if STALLION_CONTEXT_HANDLERS
        if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--xattr-unhooked" {
            try contextualXattrValues(URL(fileURLWithPath:CommandLine.arguments[2],isDirectory:true))
            print("PASS contextual xattr policies, binary values and persistence with unhooked core")
            return
        }
        if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--xattr-focused" {
            let parent = URL(fileURLWithPath:CommandLine.arguments[2],isDirectory:true)
            try contextualXattrValues(parent); try contextualXattrRefusals(parent); try contextualXattrFailures(parent); try contextualXattrQueue(parent)
            print("PASS contextual xattr policies, authorization, failure atomicity and queued admission")
            return
        }
#endif
        need(CommandLine.arguments.count == 2, "owned empty parent required")
        let parent = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
#if STALLION_CONTEXT_HANDLERS
        try contextualPolicyValues(); try contextualResults(parent); try rejectedHandlerResults(parent); try queuedResizeAfterIncompleteSnapshot(parent); try contextualLinks(parent); try contextualCreates(parent); try contextualRemovals(parent); try contextualDirectories(parent); try contextualRenames(parent); try contextualSymlinkCreation(parent)
        try contextualXattrValues(parent); try contextualXattrRefusals(parent); try contextualXattrFailures(parent); try contextualXattrQueue(parent)
#endif
        try successfulWrites(parent); let unavailable = try attributes(parent)
        try failures(parent); try admission(parent); try lifetimeAndBinding(parent); try accessPolicyChecks(parent)
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
#if STALLION_CONTEXT_HANDLERS
        print("RMDIR requested mask: 0x\(String(UInt(bitPattern: FSRemoveItemResult.requestedAttributes.wantedAttributes.rawValue),radix:16)); final-link branch: actual-result success")
#endif
#if STALLION_CONTEXT_HANDLERS && STALLION_RESULT_MASK_TRACE
        print("PASS contextual hardlinks, two-role results, refusal, rollback and queued delivery gates")
        print("PASS contextual empty-file creation, publication reuse, two-role results and outcome-specific cleanup")
        print("PASS contextual exact-ID removal, two-role results, returned ownership and failure gates")
        print("PASS contextual empty directories, nesting, publication reuse and kind-specific failures")
        print("PASS contextual non-overwriting rename, three-role results, exact identities and rollback")
        print("PASS contextual symbolic-link creation, exact target bytes and shared publication cleanup")
#endif
#else
        fatalError("only --access-policy is available without private diagnostics")
#endif
    }
}
