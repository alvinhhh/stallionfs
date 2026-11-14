import Foundation
import FSKit
import SFSImage
import Darwin

func demand(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() { fatalError(message) }
}
func anchorJSON(_ r: sfs_result) -> [String: Any] {
    ["generation":r.generation,"root_digest":rawBytes(r.root_digest).map{String(format:"%02x",$0)}.joined(),
     "committed_end":r.committed_end,"physical_end":r.physical_end,"device":r.device,"inode":r.inode,
     "uuid":rawBytes(r.uuid).map{String(format:"%02x",$0)}.joined()]
}
@main struct ActivationDriver {
    static func main() throws {
        let args=CommandLine.arguments
        let root=URL(fileURLWithPath:args[2],isDirectory:true)
        if args[1] == "prepare" || args[1] == "trace-options" {
            var initial=sfs_metadata_initial(); initial.mode=UInt32(S_IFDIR)|0o700; initial.uid=geteuid(); initial.gid=getegid()
            var handle:OpaquePointer?, r=sfs_result()
            demand(sfs_image_create_metadata_version(root.path,"image.sfs",1048576,6,&initial,&handle,&r)==SFS_OK,"create")
            let output=anchorJSON(r); demand(sfs_image_close(handle,&r)==SFS_OK,"close creation")
            if args[1] == "prepare" {
                print(String(data:try JSONSerialization.data(withJSONObject:output,options:[.sortedKeys]),encoding:.utf8)!);return
            }
        }
        if args[1] == "options" {
            let good=["-o","rw,owners,sfs_activation="+String(repeating:"1",count:32)+"."+String(repeating:"2",count:32)]
            let parsed = try ActivationOptions.parse(good); demand(parsed != nil,"canonical")
            for bad in [good+["-o","ro"],good+["-o","rw"],["-o","rw,owners"],["-o","rw,noowners"],["--rdonly"],["-u"],["-o","rw,owners,"],["-o"],good+["-o","update"],good+["-o","remount"],good+["-o","rdonly"]] {
                do { _=try ActivationOptions.parse(bad);fatalError("accepted malformed options") } catch {}
            }
            let absent = try ActivationOptions.parse([]); demand(absent == nil,"absent readonly")
            let readonly = try ActivationOptions.parse(["-o","ro,owners"]); demand(readonly == nil,"explicit readonly")
            print("PASS complete activation options");return
        }
        var h:OpaquePointer?, r=sfs_result()
        demand(sfs_image_open_pending(root.path,"image.sfs",&h,&r)==SFS_OK,"pending")
        let original=r, resource=FSPathURLResource(url:root,writable:false)
        let mode=args[1], options=Array(args.dropFirst(3))
        let success = mode == "success" || mode == "close-after-transfer"
        let queue=DispatchQueue(label:"activation-test")
        // The scope-success boolean is an explicit fixture double. No grant or
        // mounted-runtime claim follows; actual file descriptors are real.
        let volume=StallionVolume(identity:.production,admission:.pendingForTesting(handle:h!,anchor:r),resource:resource,
                                  scope:mode != "no-scope",queue:queue)
        demand(volume.requestedMountOptions.contains(.readOnly),"pending mode is readonly before activation")
        demand(!volume.supportedVolumeCapabilities.doesNotSupportSettingFilePermissions,"implemented permission capability is truthful before activation")
        demand(volume.coreReadOnlyForTesting(),"pending core refuses transaction before activation")
#if STALLION_MOUNT_TRACE
        if mode == "trace-options" {
            for arguments in [["-o"], ["--rdonly"], ["-o","rw,noowners"], Array(repeating:"x",count:65)] {
                MountTrace.shared.resetForTesting(); var replies = 0
                volume.activateArgumentsForTesting(arguments) { item,error in
                    demand(item == nil && error != nil,"malformed activation rejected"); replies += 1
                }
                let rows = MountTrace.shared.recordsForTesting()
                let entry = rows.filter { $0.contains(" e=1 o=2 ") }, reply = rows.filter { $0.contains(" e=3 o=2 ") }
                demand(replies == 1 && entry.count == 1 && reply.count == 1,"trace callback and reply closure")
                demand(reply[0].contains(" s=9 ") && entry[0].split(separator:" ")[7] == reply[0].split(separator:" ")[7],"trace argument stage and matching callback")
            }
            let done = DispatchSemaphore(value:0)
            queue.async { let closed = volume.unload(); demand(closed.consumed && closed.error == nil,"unchanged pending handle closed"); done.signal() }
            demand(done.wait(timeout:.now()+10) == .success,"trace fixture close")
            print("PASS malformed activation trace closure"); return
        }
#endif
        var writeBoundaries = 0, writableOpened = 0
        func transferPause() throws {
            try Data().write(to:root.appendingPathComponent("transfer-waiting"))
            let deadline = Date().addingTimeInterval(5)
            while !FileManager.default.fileExists(atPath:root.appendingPathComponent("transfer-release").path) {
                demand(Date() < deadline,"transfer release deadline"); usleep(1000)
            }
        }
        if mode == "cancel-before-transfer" { ManagedActivation.beforeTransferForTesting = transferPause }
        ManagedActivation.beforeWritableForTesting = {
            writeBoundaries += 1
            if mode == "close-after-transfer" { try transferPause() }
            if mode == "denied-rw" {
                demand(geteuid() != 0,"effective write-denial fixture requires non-root UID")
                demand(chmod(root.appendingPathComponent("image.sfs").path,0o400) == 0,"remove fixture write permission")
            }
            if mode == "revoke-after-claim" { resource.revoke() }
        }
        ManagedActivation.afterWritableForTesting = { writableOpened += 1 }
        let completed=DispatchSemaphore(value:0)
        let duplicate=DispatchSemaphore(value:0), queued=DispatchSemaphore(value:0), unmounted=DispatchSemaphore(value:0)
        var drained = 0
        let drainCase = ["fail-after-promotion", "fail-result", "fail-result-cleanup", "revoke-after-promotion", "revoke-after-result"].contains(mode)
        let concurrent = DispatchGroup()
        volume.activationResultBoundaryForTesting = {
            DispatchQueue.concurrentPerform(iterations:8) { _ in
                demand(volume.requestedMountOptions.contains(.readOnly),"no early writable publication during result preparation")
                if mode == "revoke-after-result" {
                    volume.write(contents:Data([1]),to:FSItem(),at:-1) { (result: FSWriteFileResult?, error: Error?) in
                        demand(result == nil && error != nil,"concurrent invalid data callback refused")
                    }
                }
                concurrent.enter()
                volume.synchronize(flags:.wait) { error in
                    demand((error == nil) == success,"queued callback sees final admission outcome"); concurrent.leave()
                }
            }
            if mode == "revoke-after-result" { resource.revoke() }
        }
        if mode == "fail-result" || mode == "fail-result-cleanup" { volume.rejectResultForTesting = { $0 == "FSActivateResult" } }
        if mode == "fail-result-cleanup" {
            volume.releaseItemForTesting = { handle,pin,result in
                demand(sfs_image_pin_release(handle,pin,&result) == SFS_OK,"actual root pin released")
                result.system_errno = ENOSPC; return SFS_IO
            }
        }
        if drainCase {
            volume.activationBoundaryForTesting = {
                volume.activateArgumentsForTesting(options) { item,error in demand(item == nil && error != nil,"queued duplicate refused");drained += 1;duplicate.signal() }
                volume.synchronize(flags:.wait) { error in demand(error != nil,"queued callback observes terminal failure");drained += 1;queued.signal() }
                volume.unmount { drained += 1; unmounted.signal() }
                let busy = volume.unload()
                demand(!busy.consumed && (busy.error as NSError?)?.code == Int(EBUSY), "ordinary unload still busy under callbacks")
                if mode == "fail-after-promotion" { throw POSIXError(.ECANCELED) }
                if mode == "revoke-after-promotion" { resource.revoke() }
            }
        }
        if mode == "revoked" { resource.revoke() }
        let reply: (Bool, Error?) -> Void = { hasResult,error in
            if success {
                demand(error == nil && hasResult,"managed activation success")
                demand(!volume.requestedMountOptions.contains(.readOnly),"admitted writable mode")
                volume.activateArgumentsForTesting(options) { duplicateItem,duplicateError in
                    demand(duplicateItem == nil && duplicateError != nil,"duplicate activation denied")
                    duplicate.signal()
                }
            } else {
                demand(!hasResult && error != nil,"activation refusal")
                if mode == "fail-result-cleanup" {
                    let first = error! as NSError
                    let errors = first.userInfo[NSMultipleUnderlyingErrorsKey] as? [NSError]
                    demand(first.code == Int(EIO) && errors?.count == 2 && errors?[0].code == Int(EIO) && errors?[1].code == Int(ENOSPC),"constructor error remains primary with cleanup detail")
                }
                demand(volume.activationConsumedForTesting,"close precedes activation error reply")
                if drainCase { demand(drained == 3,"all admitted replies finish before close and failed activation reply") }
                demand(volume.requestedMountOptions.contains(.readOnly),"terminal volume advertises no writable admission")
                var refused = false
                volume.activateArgumentsForTesting(options) { item,error in
                    demand(item == nil && (error as NSError?)?.code == Int(ENXIO),"terminal admission rejects reuse");refused = true
                }
                demand(refused,"terminal admission synchronous refusal")
                if mode == "denied-rw" {
                    demand((error as NSError?)?.code == Int(EACCES),"actual writable open denied by OS")
                    demand(chmod(root.appendingPathComponent("image.sfs").path,0o600) == 0,"restore owned fixture mode after failure")
                }
                var other:OpaquePointer?, receipt=sfs_result()
                demand(sfs_image_open_readonly(root.path,"image.sfs",&other,&receipt)==SFS_OK,"original lock released before reply")
                demand(sfs_image_close(other,&receipt)==SFS_OK,"competitor closed")
                demand(anchorMatches(receipt,original),"failed activation never writes backing")
            }
            completed.signal()
        }
        if mode == "fail-result" || mode == "fail-result-cleanup" {
            volume.activateResultForTesting(arguments:options) { result,error in reply(result != nil,error) }
        } else { volume.activateArgumentsForTesting(options) { item,error in reply(item != nil,error) } }
        demand(completed.wait(timeout:.now()+10) == .success,"activation reply deadline")
        demand(concurrent.wait(timeout:.now()+10) == .success,"concurrent callbacks complete")
        if success {
            demand(duplicate.wait(timeout:.now()+10) == .success,"duplicate callback")
            let done=DispatchSemaphore(value:0)
            volume.deactivate(options:[]) { error in
                demand(error == nil,"deactivation")
                queue.async { let result=volume.unload(); demand(result.consumed && result.error == nil,"checked close");done.signal() }
            }
            demand(done.wait(timeout:.now()+10) == .success,"close deadline")
        } else if drainCase {
            demand(duplicate.wait(timeout:.now()+10) == .success && queued.wait(timeout:.now()+10) == .success && unmounted.wait(timeout:.now()+10) == .success,"queued callbacks drain")
        }
        let expectedBoundary = ["success", "close-after-transfer", "fail-after-promotion", "fail-result", "fail-result-cleanup", "revoke-after-promotion", "revoke-after-result", "denied-rw", "revoke-after-claim"].contains(mode) ? 1 : 0
        let expectedOpened = ["success", "close-after-transfer", "fail-after-promotion", "fail-result", "fail-result-cleanup", "revoke-after-promotion", "revoke-after-result"].contains(mode) ? 1 : 0
        demand(writeBoundaries == expectedBoundary && writableOpened == expectedOpened, "observed writable boundary and successful OS opens")
        print("PASS activation \(mode)")
    }
}
