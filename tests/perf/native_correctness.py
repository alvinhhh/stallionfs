"""Complete snapshots and explicit loss reports for owned benchmark fixtures.

Snapshotting reads file contents and may change access times. It is not an atomic
filesystem snapshot. Allocation observations do not identify shared APFS extents.
"""
import base64
import ctypes
import errno
from functools import cache
import gzip
import hashlib
import io
import json
import os
import stat
import struct
import sys


FIELDS = ("kind", "mode", "uid", "gid", "mtime_ns", "flags", "xattrs", "acl",
          "size", "sha256", "symlink_bytes", "special_type", "rdev")
EXCLUDED = {
    "atime_ns": "Reading contents may update access time; retained as an observation.",
    "atime_after_read_ns": "Access time observed after validation reads.",
    "ctime_ns": "Creating a copy changes inode change time.",
    "birthtime_ns": "Recorded when exposed by the platform; not a required copy attribute.",
    "device_inode": "Compared separately for clone independence.",
    "allocated_bytes": "Allocation may differ across filesystems and shared extents.",
    "holes": "Gated separately by sparse_preserved; unknown observations never establish preservation.",
    "link_count": "Only hardlink groups within the fixture are compared.",
    "clone_attributes": "Sharing identifiers, flags and reference counts can change after cloning; compared separately using post-copy observations.",
}


class _AttrList(ctypes.Structure):
    _fields_ = [("bitmapcount", ctypes.c_uint16), ("reserved", ctypes.c_uint16),
                ("common", ctypes.c_uint32), ("volume", ctypes.c_uint32),
                ("directory", ctypes.c_uint32), ("file", ctypes.c_uint32), ("fork", ctypes.c_uint32)]


def _parse_clone_attributes(raw):
    """Decode the fixed, four-byte-aligned FSOPT_PACK_INVAL_ATTRS response."""
    if len(raw) != 44 or struct.unpack_from("<I", raw)[0] != 44:
        raise ValueError("Unexpected clone attribute buffer length")
    masks = struct.unpack_from("<5I", raw, 4)
    if masks[0] != 0x80000000 or any(masks[1:4]) or masks[4] & ~0x1300:
        raise ValueError("Unexpected clone attribute masks")
    result = {"raw_hex": raw.hex(), "returned_masks": dict(zip(
        ("common", "volume", "directory", "file", "fork"), masks))}
    for name, bit, value in zip(("clone_id", "extended_flags", "clone_refcount"),
                               (0x100, 0x200, 0x1000), struct.unpack_from("<QQI", raw, 24)):
        result[name] = value if masks[4] & bit else None
    result["available"] = masks[4] == 0x1300
    return result


def _clone_attributes(fd):
    """Observe the already-open regular file; unsupported attributes stay unknown."""
    if sys.platform != "darwin" or sys.byteorder != "little":
        return {"available": False, "unavailable": "Requires little-endian Darwin"}
    libc = _darwin_metadata_api()
    # ATTR_CMN_RETURNED_ATTRS plus CLONEID, EXT_FLAGS, CLONE_REFCNT.
    request = _AttrList(5, 0, 0x80000000, 0, 0, 0, 0x1300)
    buffer = ctypes.create_string_buffer(44)
    ctypes.set_errno(0)
    # FSOPT_PACK_INVAL_ATTRS | FSOPT_ATTR_CMN_EXTENDED.
    if libc.fgetattrlist(fd, ctypes.byref(request), buffer, len(buffer), 0x28):
        code = ctypes.get_errno() or errno.EIO
        if code not in {errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL}:
            raise OSError(code, "Cannot read clone attributes")
        return {"available": False, "error_number": code, "raw_hex": bytes(buffer).hex(),
                "unavailable": "Clone attributes unsupported"}
    return _parse_clone_attributes(bytes(buffer))


@cache
def _darwin_metadata_api():
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libc.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.listxattr.restype = ctypes.c_ssize_t
    libc.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
                            ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    libc.getxattr.restype = ctypes.c_ssize_t
    libc.acl_get_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.acl_get_link_np.restype = ctypes.c_void_p
    libc.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    libc.acl_to_text.restype = ctypes.c_void_p
    libc.acl_free.argtypes = [ctypes.c_void_p]
    libc.acl_free.restype = ctypes.c_int
    libc.fgetattrlist.argtypes = [ctypes.c_int, ctypes.POINTER(_AttrList), ctypes.c_void_p,
                                 ctypes.c_size_t, ctypes.c_ulong]
    libc.fgetattrlist.restype = ctypes.c_int
    return libc


def _acl(path):
    """Read the final entry's extended ACL, including a symlink's own ACL."""
    if sys.platform != "darwin":
        return {"text_hex": None, "unavailable": "No supported no-follow ACL reader on this platform"}
    libc = _darwin_metadata_api()
    ctypes.set_errno(0)
    acl = libc.acl_get_link_np(os.fsencode(path), 0x00000100)  # ACL_TYPE_EXTENDED, sys/acl.h
    if not acl:
        error = ctypes.get_errno()
        if error == errno.ENOENT:  # Darwin reports no extended ACL this way.
            return {"text_hex": None, "unavailable": None}
        if error in {errno.ENOTSUP, errno.EOPNOTSUPP}:
            return {"text_hex": None, "unavailable": f"acl_get_link_np: errno {error}"}
        raise OSError(error or errno.EIO, "Cannot read extended ACL", os.fsdecode(path))
    text = None
    try:
        length = ctypes.c_ssize_t()
        ctypes.set_errno(0)
        text = libc.acl_to_text(acl, ctypes.byref(length))
        if not text:
            raise OSError(ctypes.get_errno() or errno.EIO, "Cannot serialize extended ACL", os.fsdecode(path))
        if length.value < 0:
            raise RuntimeError("Invalid ACL text length")
        return {"text_hex": ctypes.string_at(text, length.value).hex(), "unavailable": None}
    finally:
        # Free both allocations even if the first release reports an error.
        release_error = None
        for pointer in (text, acl):
            if pointer:
                ctypes.set_errno(0)
                if libc.acl_free(pointer):
                    release_error = ctypes.get_errno() or errno.EIO
        if release_error:
            raise OSError(release_error, "Cannot release ACL allocation")


def _xattrs(path):
    """Return every name/value as hex, without following the final symlink."""
    if hasattr(os, "listxattr"):
        return {os.fsencode(name).hex(): os.getxattr(path, name, follow_symlinks=False).hex()
                for name in sorted(os.listxattr(path, follow_symlinks=False), key=os.fsencode)}
    if sys.platform != "darwin":
        raise NotImplementedError("No no-follow extended-attribute API is available")
    libc = _darwin_metadata_api()
    encoded = os.fsencode(path)

    def checked(result):
        if result < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), os.fsdecode(path))
        return result

    length = checked(libc.listxattr(encoded, None, 0, 1))  # XATTR_NOFOLLOW
    names = ctypes.create_string_buffer(length)
    actual = checked(libc.listxattr(encoded, names, length, 1))
    if actual != length or (actual and names.raw[actual - 1] != 0):
        raise RuntimeError("Extended-attribute names changed while snapshotting")
    result = {}
    for name in sorted(names.raw[:actual].split(b"\0")[:-1]):
        length = checked(libc.getxattr(encoded, name, None, 0, 0, 1))
        value = ctypes.create_string_buffer(length)
        actual = checked(libc.getxattr(encoded, name, value, length, 0, 1))
        if actual != length:
            raise RuntimeError("Extended-attribute value changed while snapshotting")
        result[name.hex()] = value.raw[:actual].hex()
    return result


def _holes(fd, size):
    if not hasattr(os, "SEEK_DATA") or not hasattr(os, "SEEK_HOLE"):
        return {"ranges": None, "unavailable": "SEEK_DATA/SEEK_HOLE unavailable"}
    position, holes = 0, []
    while position < size:
        try:
            data = os.lseek(fd, position, os.SEEK_DATA)
        except OSError as exc:
            if exc.errno == errno.ENXIO:
                holes.append([position, size])
                break
            if exc.errno in {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}:
                return {"ranges": None, "unavailable": f"SEEK_DATA: errno {exc.errno}"}
            raise
        if not position <= data < size:
            raise RuntimeError("Invalid SEEK_DATA offset")
        if data > position:
            holes.append([position, data])
        try:
            hole = os.lseek(fd, data, os.SEEK_HOLE)
        except OSError as exc:
            if exc.errno in {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}:
                return {"ranges": None, "unavailable": f"SEEK_HOLE: errno {exc.errno}"}
            raise
        if not data < hole <= size:
            raise RuntimeError("Invalid SEEK_HOLE offset")
        position = hole
    return {"ranges": holes, "unavailable": None}


def _stable(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, getattr(info, "st_flags", None))


def snapshot(root, *, allow_special=False, observe_sharing=False):
    """Read a stable fixture; opt-in special entries are metadata-only, never opened."""
    root = os.fsencode(os.fspath(root))
    entries, links = {}, {}
    buffer = bytearray(1024 * 1024)
    view = memoryview(buffer)

    def visit(path, relative):
        before = os.lstat(path)
        kind = ("file" if stat.S_ISREG(before.st_mode) else
                "directory" if stat.S_ISDIR(before.st_mode) else
                "symlink" if stat.S_ISLNK(before.st_mode) else None)
        if kind is None and allow_special and stat.S_IFMT(before.st_mode) in {
                stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK}:
            kind = "special"
        if kind is None:
            raise ValueError(f"Unsupported fixture type: {os.fsdecode(relative)}")
        row = {"kind": kind, "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid,
               "gid": before.st_gid, "mtime_ns": before.st_mtime_ns,
               "atime_ns": before.st_atime_ns, "ctime_ns": before.st_ctime_ns,
               "birthtime_ns": getattr(before, "st_birthtime_ns", None),
               "flags": getattr(before, "st_flags", None),
               "device_inode": [before.st_dev, before.st_ino],
               "link_count": before.st_nlink,
               "allocated_bytes": before.st_blocks * 512,
               "xattrs": _xattrs(path), "acl": _acl(path)}
        if kind == "file":
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            with os.fdopen(fd, "rb", buffering=0) as stream:
                if _stable(os.fstat(stream.fileno())) != _stable(before):
                    raise RuntimeError("File changed before reading")
                digest = hashlib.sha256()
                while count := stream.readinto(buffer):
                    digest.update(view[:count])
                row.update(size=before.st_size, sha256=digest.hexdigest(),
                           holes=_holes(stream.fileno(), before.st_size))
                if observe_sharing:
                    row["clone_attributes"] = _clone_attributes(stream.fileno())
                if _stable(os.fstat(stream.fileno())) != _stable(before):
                    raise RuntimeError("File changed while reading")
        elif kind == "symlink":
            row["symlink_bytes"] = os.readlink(path).hex()
        elif kind == "special":
            row.update(special_type=stat.S_IFMT(before.st_mode), rdev=before.st_rdev)
        else:
            with os.scandir(path) as children:
                names = sorted(child.name for child in children)
            for name in names:
                visit(os.path.join(path, name), relative + b"/" + name if relative else name)
        if kind != "directory":
            links.setdefault((before.st_dev, before.st_ino), []).append(os.fsdecode(relative))
        after = os.lstat(path)
        if _stable(after) != _stable(before):
            raise RuntimeError(f"Fixture changed while snapshotting: {os.fsdecode(relative)}")
        row["atime_after_read_ns"] = after.st_atime_ns
        entries[os.fsdecode(relative)] = row

    visit(root, b"")
    return {"entries": dict(sorted(entries.items())),
            "hardlink_groups": sorted(sorted(group) for group in links.values() if len(group) > 1),
            "unavailable_fields": (["flags"] if any(row["flags"] is None for row in entries.values()) else [])
                                  + (["acl"] if any(row["acl"]["unavailable"] for row in entries.values()) else []),
            "excluded_from_copy_equality": EXCLUDED.copy(),
            "physical_sharing": ("Data-stream clone attributes recorded; resource-fork sharing and disk savings are not measured."
                                 if observe_sharing else
                                 "Not measured; inode and st_blocks do not establish APFS extent sharing.")}


def _differences(expected, actual):
    differences = []
    for path in sorted(expected["entries"].keys() | actual["entries"].keys()):
        left, right = expected["entries"].get(path), actual["entries"].get(path)
        if left is None or right is None:
            differences.append({"path": path, "field": "entry", "expected": left, "actual": right})
            continue
        for field in FIELDS:
            if left.get(field) != right.get(field):
                differences.append({"path": path, "field": field,
                                    "expected": left.get(field), "actual": right.get(field)})
    if expected["hardlink_groups"] != actual["hardlink_groups"]:
        differences.append({"path": None, "field": "hardlink_groups",
                            "expected": expected["hardlink_groups"], "actual": actual["hardlink_groups"]})
    return differences


def _sparse_preserved(expected, actual):
    unknown = False
    for path in expected["entries"].keys() | actual["entries"].keys():
        left, right = expected["entries"].get(path), actual["entries"].get(path)
        if not ((left and left["kind"] == "file") or (right and right["kind"] == "file")):
            continue
        if left is None or right is None or left["kind"] != right["kind"]:
            return False
        a, b = left["holes"]["ranges"], right["holes"]["ranges"]
        if a is None or b is None:
            unknown = True
        elif a != b:
            return False
    return None if unknown else True


def compare(expected, actual, baseline=None):
    """Compare metadata/content projection; also require sparse_preserved for acceptance.

    Baseline equivalence never erases source losses. Unknown metadata fails strict
    equality; unknown hole ranges yield None, not evidence of sparse preservation.
    """
    losses = _differences(expected, actual)
    baseline_losses = _differences(expected, baseline) if baseline is not None else None
    versus_baseline = _differences(baseline, actual) if baseline is not None else None
    sparse = []
    for path, left in expected["entries"].items():
        right = actual["entries"].get(path)
        if left["kind"] == "file" and right is not None and right["kind"] == "file":
            if left["allocated_bytes"] != right["allocated_bytes"] or left["holes"] != right["holes"]:
                sparse.append({"path": path,
                               "expected": {key: left[key] for key in ("allocated_bytes", "holes")},
                               "actual": {key: right[key] for key in ("allocated_bytes", "holes")}})
    complete = not expected["unavailable_fields"] and not actual["unavailable_fields"]
    baseline_complete = complete and baseline is not None and not baseline["unavailable_fields"]
    return {"strict_equal": not losses and complete, "candidate_losses": losses,
            "baseline_losses": baseline_losses, "candidate_vs_baseline": versus_baseline,
            "baseline_equivalent": not versus_baseline and baseline_complete if baseline is not None else None,
            "adjudication": ("unverifiable_metadata" if not complete else
                             "strict_match" if not losses else
                             "matches_baseline_with_losses" if baseline_complete and not versus_baseline else
                             "differs_from_baseline" if baseline is not None else "mismatch"),
            "sparse_preserved": _sparse_preserved(expected, actual),
            "baseline_sparse_preserved": _sparse_preserved(expected, baseline) if baseline is not None else None,
            "candidate_vs_baseline_sparse_preserved": _sparse_preserved(baseline, actual) if baseline is not None else None,
            "sparse_observation_differences": sparse,
            "unavailable_fields": {"expected": expected["unavailable_fields"],
                                   "actual": actual["unavailable_fields"],
                                   "baseline": baseline["unavailable_fields"] if baseline is not None else None},
            "excluded_fields": EXCLUDED.copy()}


def verify_source(before, after):
    """Report source replacement or metadata changes, excluding read-induced atime."""
    result = compare(before, after)
    result["source_identity_changes"] = []
    for path, entry in before["entries"].items():
        observed = after["entries"].get(path)
        if observed is not None:
            for field in ("device_inode", "ctime_ns", "birthtime_ns", "link_count"):
                if entry[field] != observed[field]:
                    result["source_identity_changes"].append({"path": path, "field": field,
                                                             "expected": entry[field], "actual": observed[field]})
    result["unchanged"] = (result["strict_equal"] and result["sparse_preserved"] is True
                           and not result["source_identity_changes"])
    return result


def verify_move(before, after):
    """Require every moved entry to retain its original device and inode."""
    result = compare(before, after)
    result["move_identity_changes"] = [
        {"path": path, "expected": before["entries"].get(path, {}).get("device_inode"),
         "actual": after["entries"].get(path, {}).get("device_inode")}
        for path in sorted(before["entries"].keys() | after["entries"].keys())
        if (path not in before["entries"] or path not in after["entries"] or
            before["entries"][path]["device_inode"] != after["entries"][path]["device_inode"])]
    result["move_identity"] = not result["move_identity_changes"]
    return result


def verify_clone(source, destination, baseline=None):
    """Compare snapshots and report every entry still sharing a source inode."""
    result = compare(source, destination, baseline)
    source_inodes = {tuple(entry["device_inode"]) for entry in source["entries"].values()}
    result["shared_source_inodes"] = [path for path, entry in destination["entries"].items()
                                      if tuple(entry["device_inode"]) in source_inodes]
    result["independent_clone"] = not result["shared_source_inodes"]
    return result


def clone_sharing(source_after, destination):
    """Adjudicate sequential post-copy data-stream observations on stable owned files."""
    counts = dict(shared=0, not_shared=0, unknown=0, not_applicable=0)
    exceptions, digest, compressed = [], hashlib.sha256(), io.BytesIO()
    byte_count = 0
    with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0) as encoded:
        for path in sorted(source_after["entries"].keys() | destination["entries"].keys()):
            left, right = source_after["entries"].get(path), destination["entries"].get(path)
            if not any(entry and entry["kind"] == "file" for entry in (left, right)):
                continue
            pair = {"path": path, "source": left and left.get("clone_attributes"),
                    "destination": right and right.get("clone_attributes"),
                    "source_identity": left and left["device_inode"],
                    "destination_identity": right and right["device_inode"]}
            if not left or not right or left["kind"] != right["kind"]:
                status, reason = "not_shared", "Regular-file path mismatch"
            elif (left["device_inode"][0] != right["device_inode"][0]
                  or left["device_inode"] == right["device_inode"]
                  or left["size"] != right["size"] or left["sha256"] != right["sha256"]):
                status, reason = "not_shared", "Pair requires independent identical files on one device"
            elif left["size"] == 0 or all(entry["holes"]["ranges"] == [[0, entry["size"]]] for entry in (left, right)):
                status, reason = "not_applicable", "Empty or observed holes-only data stream"
            elif not all(value and value.get("available") is True and value.get("clone_id")
                         for value in (pair["source"], pair["destination"])):
                status, reason = "unknown", "Missing attributes or zero clone identifier"
            else:
                shared = (pair["source"]["clone_id"] == pair["destination"]["clone_id"]
                          and all(value["extended_flags"] & 0x40 for value in (pair["source"], pair["destination"])))
                status = "shared" if shared else "not_shared"
                reason = "Matching nonzero clone IDs and full-sharing flags" if shared else "Full data-stream sharing not observed"
            pair.update(status=status, reason=reason)
            counts[status] += 1
            line = json.dumps(pair, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            encoded.write(line)
            digest.update(line)
            byte_count += len(line)
            if status != "shared": exceptions.append({"path": path, "status": status, "reason": reason})
    outcome = (False if counts["not_shared"] else
               None if counts["unknown"] or not counts["shared"] else True)
    return {"full_data_stream_sharing": outcome, "counts": counts, "exceptions": exceptions,
            "observations_gzip_b64": base64.b64encode(compressed.getvalue()).decode("ascii"),
            "observations_sha256": digest.hexdigest(), "observations_bytes": byte_count,
            "observations_encoding": "UTF-8 JSON Lines, gzip with mtime=0, then base64; digest and length describe uncompressed bytes.",
            "scope": "Data-bearing regular-file streams only; empty and holes-only streams are not positive evidence. No resource-fork or disk-space savings claim.",
            "evidence": "Encoded records retain every pair, including positive raw attributes and returned masks. Sequential observations are not atomic."}
