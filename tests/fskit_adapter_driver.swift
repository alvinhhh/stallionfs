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
        let write: (Int, Error?) = wait { done in volume.write(contents: Data([1]), to: files["data"]!, at: 0) { done(($0, $1)) } }
        need(write.0 == 0 && code(write.1) == Int(EROFS), "write refused")
        let set: Error? = wait { done in volume.setXattr(named: FSFileName(string: "x"), to: Data(), on: files["empty"]!, policy: .alwaysSet, replyHandler: done) }
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
        let closed: Error? = wait { done in volume.enqueue { done(volume.unload()) } }
        need(code(closed) == Int(EIO), "consumed close failure")
        let closeCount = hooksCloses()
        let again: Error? = wait { done in volume.enqueue { done(volume.unload()) } }
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
        let poisonClose: Error? = wait { done in poisoned.enqueue { done(poisoned.unload()) } }
        let poisonCloseCount = hooksCloses()
        let poisonDuplicate: Error? = wait { done in poisoned.enqueue { done(poisoned.unload()) } }
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
            let error = prefixVolume.unload() // One consuming API call closes image and auxiliary-parent descriptors.
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
        print("PASS: real-core helper admission, alias positions/packing/projection diagnostics, attributes, lookup, xattrs, readonly refusal, purge/remount and consumed close")
        print("UNTESTED: kernel context dispatch, packer/buffer delivery, tryReclaim return counts, acquired security scope and signed lifecycle")
    }
}
