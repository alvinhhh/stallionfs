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
from contextlib import contextmanager, nullcontext


DOCS_ENTRIES = 5107
DOCS_LOGICAL_BYTES = 116777216
DOCS_MAX_FILE = 8 * 1024 * 1024


class SnapshotBudget:
    """Opt-in limits for explicit observation buffers, not Python heap or RSS.

    Callers release retained snapshots explicitly. Native ACL getters may allocate
    opaque objects before their sizes can be queried; these limits cannot bound
    those internal allocations or exclude concurrent namespace replacement.
    """
    def __init__(self):
        self.live = 0
        self.snapshots = {}

    def begin(self):
        return {'bytes': 0, 'paths': 0, 'holes': 0, 'released': False}

    def reserve(self, ticket, size):
        if type(size) is not int or size < 0 or ticket['released']:
            raise ValueError('Invalid snapshot reservation')
        if ticket['bytes'] + size > 8 * 1024 * 1024 or self.live + size > 32 * 1024 * 1024:
            raise ValueError('Snapshot observation budget exceeded')
        ticket['bytes'] += size
        self.live += size

    @contextmanager
    def temporary(self, ticket, size):
        self.reserve(ticket, size)
        try:
            yield
        finally:
            ticket['bytes'] -= size
            self.live -= size

    def discard(self, ticket):
        if not ticket['released']:
            self.live -= ticket['bytes']; ticket['bytes'] = 0; ticket['released'] = True

    def retain(self, snapshot, ticket):
        self.snapshots[id(snapshot)] = (snapshot, ticket)
        return snapshot

    def release(self, snapshot):
        if snapshot is not None:
            item = self.snapshots.pop(id(snapshot))
            if item[0] is not snapshot: raise ValueError('Snapshot ownership changed')
            self.discard(item[1])

    def path(self, ticket, encoded):
        if len(encoded) > 1024 or ticket['paths'] + len(encoded) > 1024 * 1024:
            raise ValueError('Snapshot path budget exceeded')
        # Inventory, decoded keys, sorted names and later retained references.
        self.reserve(ticket, 4 * len(encoded))
        ticket['paths'] += len(encoded)


def docs_shape(entries):
    """The existing enriched docs shape; raw destinations may have split aliases."""
    if len(entries) != DOCS_ENTRIES:
        raise ValueError('Unexpected docs entry count')
    kinds = [row['kind'] for row in entries.values()]
    files = [row for row in entries.values() if row['kind'] == 'file']
    classes = {}
    for name, row in entries.items():
        depth = name.count('/') + bool(name) - (row['kind'] != 'directory')
        if depth > 2: raise ValueError('Unexpected docs depth')
        if row['kind'] == 'file':
            key = tuple(row['device_inode']); classes[key] = classes.get(key, 0) + 1
    if (kinds.count('file') != 5002 or kinds.count('directory') != 105
            or len(files) + 105 != len(entries)
            or sum(row['size'] for row in files) != DOCS_LOGICAL_BYTES
            or max(row['size'] for row in files) != DOCS_MAX_FILE
            or max(classes.values()) > 2):
        raise ValueError('Unexpected docs fixture shape')


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
    libc.acl_size.argtypes = [ctypes.c_void_p]
    libc.acl_size.restype = ctypes.c_ssize_t
    libc.fgetattrlist.argtypes = [ctypes.c_int, ctypes.POINTER(_AttrList), ctypes.c_void_p,
                                 ctypes.c_size_t, ctypes.c_ulong]
    libc.fgetattrlist.restype = ctypes.c_int
    return libc


def _acl(path, *, budget=None, ticket=None):
    """Read the final entry's extended ACL, including a symlink's own ACL."""
    if sys.platform == "linux":
        if stat.S_ISLNK(os.lstat(path).st_mode):
            return {"unavailable": None, "unsupported": "Linux symlinks do not have POSIX ACLs"}
        result = {"access_hex": None, "unavailable": None}
        names = [("access_hex", "system.posix_acl_access")]
        if stat.S_ISDIR(os.lstat(path).st_mode):
            result["default_hex"] = None
            names.append(("default_hex", "system.posix_acl_default"))
        for key, name in names:
            try:
                result[key] = os.getxattr(path, name, follow_symlinks=False).hex()
            except OSError as error:
                if error.errno == errno.ENODATA: continue
                if error.errno not in {errno.ENOTSUP, errno.EOPNOTSUPP}: raise
                result["unavailable"] = f"POSIX ACL xattr: errno {error.errno}"
        return result
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
        if budget is not None:
            ctypes.set_errno(0)
            size = libc.acl_size(acl)
            error = ctypes.get_errno()
            if size < 0: raise OSError(error or errno.EIO, 'Cannot size extended ACL')
            if not 0 < size <= 65536: raise ValueError('ACL observation budget exceeded')
        length = ctypes.c_ssize_t()
        ctypes.set_errno(0)
        text = libc.acl_to_text(acl, ctypes.byref(length))
        if not text:
            raise OSError(ctypes.get_errno() or errno.EIO, "Cannot serialize extended ACL", os.fsdecode(path))
        if length.value < 0:
            raise RuntimeError("Invalid ACL text length")
        if budget is not None:
            if length.value > 65536: raise ValueError('ACL observation budget exceeded')
            budget.reserve(ticket, 2 * length.value)
        with budget.temporary(ticket, 2 * length.value) if budget is not None else nullcontext():
            return {"text_hex": ctypes.string_at(text, length.value).hex(), "unavailable": None}
    finally:
        # Free both allocations even if the first release reports an error.
        primary = sys.exc_info()[1]
        release_error = None
        for pointer in (text, acl):
            if pointer:
                ctypes.set_errno(0)
                if libc.acl_free(pointer):
                    release_error = ctypes.get_errno() or errno.EIO
        if release_error and (budget is None or primary is None):
            raise OSError(release_error, "Cannot release ACL allocation")


def _xattrs(path, *, budget=None, ticket=None):
    """Return every name/value as hex, without following the final symlink."""
    if budget is None and hasattr(os, "listxattr"):
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
    if budget is not None and length > 65536: raise ValueError('Xattr names budget exceeded')
    with budget.temporary(ticket, 3 * length) if budget is not None else nullcontext():
        names = ctypes.create_string_buffer(length)
        actual = checked(libc.listxattr(encoded, names, length, 1))
        if actual != length or (actual and names.raw[actual - 1] != 0):
            raise RuntimeError("Extended-attribute names changed while snapshotting")
        result = {}
        for name in sorted(names.raw[:actual].split(b"\0")[:-1]):
            length = checked(libc.getxattr(encoded, name, None, 0, 0, 1))
            if budget is not None:
                if length > 1048576: raise ValueError('Xattr value budget exceeded')
                budget.reserve(ticket, 2 * (len(name) + length))
            with budget.temporary(ticket, 2 * length) if budget is not None else nullcontext():
                value = ctypes.create_string_buffer(length)
                try:
                    actual = checked(libc.getxattr(encoded, name, value, length, 0, 1))
                    if actual != length:
                        raise RuntimeError("Extended-attribute value changed while snapshotting")
                    result[name.hex()] = value.raw[:actual].hex()
                finally:
                    if budget is not None: del value
        if budget is not None:
            del names
            if result: del name
        return result


def _holes(fd, size, *, budget=None, ticket=None):
    if not hasattr(os, "SEEK_DATA") or not hasattr(os, "SEEK_HOLE"):
        return {"ranges": None, "unavailable": "SEEK_DATA/SEEK_HOLE unavailable"}
    position, holes = 0, []
    def append(start, end):
        if budget is not None:
            if ticket['holes'] >= 2 * DOCS_ENTRIES: raise ValueError('Sparse observation budget exceeded')
            budget.reserve(ticket, 64); ticket['holes'] += 1
        holes.append([start, end])
    while position < size:
        try:
            data = os.lseek(fd, position, os.SEEK_DATA)
        except OSError as exc:
            if exc.errno == errno.ENXIO:
                append(position, size)
                break
            if exc.errno in {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}:
                return {"ranges": None, "unavailable": f"SEEK_DATA: errno {exc.errno}"}
            raise
        if not position <= data < size:
            raise RuntimeError("Invalid SEEK_DATA offset")
        if data > position:
            append(position, data)
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


def _inventory_signature(info):
    return (_stable(info), info.st_nlink, getattr(info, 'st_birthtime_ns', None), getattr(info, 'st_gen', None))


def _bounded_inventory(root, budget, ticket, docs):
    """Stat-only admission in the existing reader; no metadata or data reads."""
    observed = {}; logical = 0; device = None
    def visit(path, relative, depth):
        nonlocal logical, device
        if len(observed) >= DOCS_ENTRIES: raise ValueError('Snapshot entry budget exceeded')
        budget.path(ticket, relative)
        budget.reserve(ticket, 512)  # Bounded scalar/clone/digest observation slots.
        info = os.lstat(path)
        if device is None: device = info.st_dev
        if info.st_dev != device: raise ValueError('Snapshot crosses a device')
        kind = ('file' if stat.S_ISREG(info.st_mode) else 'directory' if stat.S_ISDIR(info.st_mode)
                else 'symlink' if stat.S_ISLNK(info.st_mode) else None)
        if kind is None or depth > 2 + (kind != 'directory'):
            raise ValueError('Unsupported snapshot shape')
        if kind == 'file':
            if not 0 <= info.st_size <= DOCS_MAX_FILE: raise ValueError('Snapshot file budget exceeded')
            logical += info.st_size
            if logical > DOCS_LOGICAL_BYTES: raise ValueError('Snapshot logical budget exceeded')
        if kind == 'symlink' and not 0 <= info.st_size <= 1024:
            raise ValueError('Snapshot symlink budget exceeded')
        item = {'info': info, 'kind': kind, 'names': []}; observed[relative] = item
        if kind == 'directory':
            with os.scandir(path) as children:
                for child in children:
                    if len(observed) + len(item['names']) >= DOCS_ENTRIES:
                        raise ValueError('Snapshot entry budget exceeded')
                    name = child.name
                    if len(relative) + bool(relative) + len(name) > 1024:
                        raise ValueError('Snapshot path budget exceeded')
                    budget.reserve(ticket, 2 * len(name))
                    item['names'].append(name)
            item['names'].sort()
            for name in item['names']:
                visit(os.path.join(path, name), relative + b'/' + name if relative else name, depth + 1)
        if _inventory_signature(os.lstat(path)) != _inventory_signature(info):
            raise RuntimeError('Fixture changed during stat admission')
    visit(root, b'', 0)
    if docs:
        docs_shape({os.fsdecode(name): {'kind': row['kind'], 'size': row['info'].st_size,
                    'device_inode': [row['info'].st_dev, row['info'].st_ino]} for name, row in observed.items()})
    return observed


def snapshot(root, *, allow_special=False, observe_sharing=False, budget=None, docs=False):
    if budget is None:
        if docs: raise ValueError('Docs snapshot requires an observation budget')
        return _snapshot(root, allow_special=allow_special, observe_sharing=observe_sharing)
    ticket = budget.begin()
    try:
        result = _snapshot(root, allow_special=allow_special, observe_sharing=observe_sharing,
                           budget=budget, ticket=ticket, docs=docs)
        return budget.retain(result, ticket)
    except BaseException:
        budget.discard(ticket)
        raise


def _snapshot(root, *, allow_special=False, observe_sharing=False, budget=None, ticket=None, docs=False):
    """Read a stable fixture; opt-in special entries are metadata-only, never opened."""
    root = os.fspath(root)
    if budget is not None and len(root) > 4096: raise ValueError('Snapshot root path budget exceeded')
    root = os.fsencode(root)
    if budget is not None:
        if len(root) > 4096: raise ValueError('Snapshot root path budget exceeded')
        budget.reserve(ticket, 4 * len(root))
    entries, links = {}, {}
    inventory = _bounded_inventory(root, budget, ticket, docs) if budget is not None else None
    if budget is not None: budget.reserve(ticket, 1024 * 1024)
    buffer = bytearray(1024 * 1024)
    view = memoryview(buffer)

    def visit(path, relative):
        before = os.lstat(path)
        if inventory is not None:
            admitted = inventory.get(relative)
            if admitted is None or _inventory_signature(before) != _inventory_signature(admitted['info']):
                raise RuntimeError('Fixture changed after stat admission')
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
               "xattrs": (_xattrs(path, budget=budget, ticket=ticket) if budget is not None else _xattrs(path)),
               "acl": (_acl(path, budget=budget, ticket=ticket) if budget is not None else _acl(path))}
        if kind == "file":
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            with os.fdopen(fd, "rb", buffering=0) as stream:
                if _stable(os.fstat(stream.fileno())) != _stable(before):
                    raise RuntimeError("File changed before reading")
                digest = hashlib.sha256()
                offset = 0
                while count := stream.readinto(view[:min(len(buffer), before.st_size - offset + 1)]
                                               if budget is not None else buffer):
                    if budget is not None and offset + count > before.st_size:
                        raise RuntimeError('File grew beyond admitted size')
                    digest.update(view[:count])
                    offset += count
                if budget is not None and offset != before.st_size:
                    raise RuntimeError('File shrank below admitted size')
                row.update(size=before.st_size, sha256=digest.hexdigest(),
                           holes=(_holes(stream.fileno(), before.st_size, budget=budget, ticket=ticket)
                                  if budget is not None else _holes(stream.fileno(), before.st_size)))
                if observe_sharing:
                    row["clone_attributes"] = _clone_attributes(stream.fileno())
                if _stable(os.fstat(stream.fileno())) != _stable(before):
                    raise RuntimeError("File changed while reading")
        elif kind == "symlink":
            if budget is not None: budget.reserve(ticket, 4 * before.st_size)
            row["symlink_bytes"] = os.readlink(path).hex()
        elif kind == "special":
            row.update(special_type=stat.S_IFMT(before.st_mode), rdev=before.st_rdev)
        else:
            with os.scandir(path) as children:
                if inventory is None:
                    names = sorted(child.name for child in children)
                else:
                    names = []
                    for child in children:
                        if len(names) >= len(admitted['names']): raise RuntimeError('Directory changed after admission')
                        names.append(child.name)
                    names.sort()
                    if names != admitted['names']: raise RuntimeError('Directory changed after admission')
            for name in names:
                visit(os.path.join(path, name), relative + b"/" + name if relative else name)
        if kind != "directory":
            links.setdefault((before.st_dev, before.st_ino), []).append(os.fsdecode(relative))
        after = os.lstat(path)
        if _stable(after) != _stable(before):
            raise RuntimeError(f"Fixture changed while snapshotting: {os.fsdecode(relative)}")
        if inventory is not None and _inventory_signature(after) != _inventory_signature(admitted['info']):
            raise RuntimeError('Fixture changed after stat admission')
        row["atime_after_read_ns"] = after.st_atime_ns
        entries[os.fsdecode(relative)] = row

    visit(root, b"")
    capabilities = {"platform": sys.platform,
                    "flags": sys.platform == "darwin", "resource_fork": sys.platform == "darwin",
                    "acl": ("Darwin extended ACL" if sys.platform == "darwin" else
                            "Linux POSIX access/default ACL xattrs; no symlink ACL" if sys.platform == "linux" else None)}
    return {"entries": dict(sorted(entries.items())),
            "metadata_capabilities": capabilities,
            "unsupported_fields": ({"flags": "Darwin st_flags is not a Linux copy property",
                                     "resource_fork": "User xattrs are not Darwin resource forks",
                                     "symlink_acl": "Linux symlinks do not have POSIX ACLs"}
                                    if sys.platform == "linux" else {}),
            "hardlink_groups": sorted(sorted(group) for group in links.values() if len(group) > 1),
            "unavailable_fields": (["flags"] if sys.platform != "linux" and any(row["flags"] is None for row in entries.values()) else [])
                                  + (["acl"] if any(row["acl"]["unavailable"] for row in entries.values()) else []),
            "excluded_from_copy_equality": EXCLUDED.copy(),
            "physical_sharing": ("Not measured; inode and st_blocks do not establish physical sharing."
                                 if sys.platform == "linux" else
                                 "Data-stream clone attributes recorded; resource-fork sharing and disk savings are not measured."
                                 if observe_sharing else
                                 "Not measured; inode and st_blocks do not establish APFS extent sharing.")}


def _differences(expected, actual):
    differences = []
    if expected.get("metadata_capabilities") != actual.get("metadata_capabilities"):
        differences.append({"path": None, "field": "metadata_capabilities",
                            "expected": expected.get("metadata_capabilities"),
                            "actual": actual.get("metadata_capabilities")})
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


def clone_sharing(source_after, destination, *, summary_only=False, budget=None, ticket=None):
    """Adjudicate sequential post-copy data-stream observations on stable owned files."""
    if budget is not None and not summary_only:
        raise ValueError('Budgeted sharing requires a bounded summary')
    counts = dict(shared=0, not_shared=0, unknown=0, not_applicable=0)
    exceptions, digest, compressed = [], hashlib.sha256(), None if summary_only else io.BytesIO()
    byte_count = 0
    with (nullcontext(None) if summary_only else gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0)) as encoded:
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
            with budget.temporary(ticket, 8 * (len(os.fsencode(path)) + 1024)) if budget is not None else nullcontext():
                line = json.dumps(pair, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                if encoded is not None: encoded.write(line)
                digest.update(line)
                byte_count += len(line)
                if budget is not None: del line
            if not summary_only and status != "shared": exceptions.append({"path": path, "status": status, "reason": reason})
    outcome = (False if counts["not_shared"] else
               None if counts["unknown"] or not counts["shared"] else True)
    if summary_only:
        return {'full_data_stream_sharing': outcome, 'counts': counts,
                'observations_sha256': digest.hexdigest(), 'observations_bytes': byte_count,
                'scope': 'All data-bearing regular-file pairs evaluated; raw observations remain private.'}
    return {"full_data_stream_sharing": outcome, "counts": counts, "exceptions": exceptions,
            "observations_gzip_b64": base64.b64encode(compressed.getvalue()).decode("ascii"),
            "observations_sha256": digest.hexdigest(), "observations_bytes": byte_count,
            "observations_encoding": "UTF-8 JSON Lines, gzip with mtime=0, then base64; digest and length describe uncompressed bytes.",
            "scope": "Data-bearing regular-file streams only; empty and holes-only streams are not positive evidence. No resource-fork or disk-space savings claim.",
            "evidence": "Encoded records retain every pair, including positive raw attributes and returned masks. Sequential observations are not atomic."}
