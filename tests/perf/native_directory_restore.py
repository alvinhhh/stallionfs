"""Confined first-recipe reconstruction experiment; never a production backend.

Stable source is required. Held identities detect replacement; pathname link/unlink
cannot exclude the same user racing its own namespace. No cancellation bound or
filesystem-lock-duration guarantee follows from the enclosing process deadline.
"""
import ctypes
import errno
import hashlib
import os
import stat
import sys

import native_correctness as correct

MAX_ENTRIES = 18
TRACKED = 0x40
BLOCKING = stat.UF_IMMUTABLE | stat.UF_APPEND
ALLOWED_FLAGS = TRACKED | BLOCKING
ROW_FIELDS = set(correct.FIELDS) | set(correct.EXCLUDED)
COMMON_REQUIRED = {'kind', 'mode', 'uid', 'gid', 'mtime_ns', 'atime_ns', 'ctime_ns',
                   'birthtime_ns', 'flags', 'device_inode', 'link_count', 'allocated_bytes', 'acl', 'xattrs'}


class RestoreError(Exception):
    """Only fixed codes may leave this module; never paths or native messages."""


ADMISSION_PHASES = frozenset(('ops_binding', 'roots', 'schema', 'entry_identity',
    'acl', 'payload', 'symlink', 'source_closure', 'complete', 'unknown'))
REFUSAL_CODES = frozenset(('restoration_refused', 'platform_unavailable', 'acl_unavailable',
    'acl_changed', 'payload_changed', 'identity_changed', 'source_changed', 'native_error',
    'api_unavailable', 'admission_error'))


def error_number(error):
    value = error.errno if isinstance(error, OSError) else None
    return value if type(value) is int and 0 < value <= 65535 else None


class AdmissionError(RestoreError):
    def __init__(self, report):
        super().__init__('restoration_admission_failed')
        self.report = dict(report, close=dict(report['close']))


def refusal_report(error, phase='unknown', close=None):
    code = (str(error) if isinstance(error, RestoreError) else 'native_error' if isinstance(error, OSError)
            else 'api_unavailable' if isinstance(error, AttributeError) else 'admission_error')
    return {'status': 'refused', 'phase': phase if phase in ADMISSION_PHASES else 'unknown',
        'refusal_code': code if code in REFUSAL_CODES else 'admission_error', 'errno': error_number(error),
        'close': dict(close) if close is not None else {'status': 'unknown', 'attempts': 0, 'failures': 0, 'errno': None}}


def need(condition, code='restoration_refused'):
    if not condition:
        raise RestoreError(code)


def identity(info):
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def signature(info):
    return (identity(info), info.st_mode, info.st_uid, info.st_gid, info.st_size,
            info.st_nlink, info.st_flags, info.st_mtime_ns, info.st_ctime_ns,
            getattr(info, 'st_birthtime', None), getattr(info, 'st_gen', None))


def relative(name):
    need(type(name) is str and '\x00' not in name and not name.startswith('/'))
    if name:
        need(all(part and part not in ('.', '..') for part in name.split('/')))
    return name.rsplit('/', 1) if '/' in name else ('', name)


def plan(source, destination, owner):
    """Compute selectors from full verified metadata, never the safe projection."""
    for snapshot in (source, destination):
        need(type(snapshot) is dict and snapshot.get('unavailable_fields') == [])
        need(type(snapshot.get('entries')) is dict and 0 < len(snapshot['entries']) <= MAX_ENTRIES)
    left, right = source['entries'], destination['entries']
    need(left.keys() == right.keys() and '' in left and left['']['kind'] == 'directory')
    need(source.get('metadata_capabilities') == destination.get('metadata_capabilities'))
    source_classes, destination_classes = {}, {}
    for name in sorted(left):
        relative(name)
        a, b = left[name], right[name]
        for row in (a, b):
            need(type(row) is dict and COMMON_REQUIRED <= row.keys() and row.keys() <= ROW_FIELDS)
            need(row['kind'] in ('file', 'directory', 'symlink') and row['uid'] == owner)
            need(type(row['mode']) is int and not row['mode'] & (stat.S_ISUID | stat.S_ISGID))
            need(type(row['mtime_ns']) is int and type(row['ctime_ns']) is int and type(row['gid']) is int)
            need(type(row['flags']) is int and row['flags'] >= 0 and not row['flags'] & ~ALLOWED_FLAGS)
            need(type(row['device_inode']) is list and len(row['device_inode']) == 2
                 and all(type(value) is int and value >= 0 for value in row['device_inode']))
            need(type(row['link_count']) is int and row['link_count'] > 0)
            need(type(row['acl']) is dict and set(row['acl']) == {'text_hex', 'unavailable'}
                 and row['acl']['unavailable'] is None)
        need(a['kind'] == b['kind'])
        need(a['kind'] != 'directory' or not a['flags'] & BLOCKING)
        need(not (a['flags'] ^ b['flags']) & ~TRACKED and not b['flags'] & TRACKED & ~a['flags'])
        for field in correct.FIELDS:
            if field in ('acl', 'flags') or (field == 'mtime_ns' and a['kind'] == 'directory'):
                continue
            need(a.get(field) == b.get(field))
        if a['kind'] == 'file':
            need(all({'size', 'sha256', 'holes'} <= row.keys() and type(row['size']) is int
                     and 0 <= row['size'] <= 32 * 1024 * 1024 and type(row['holes']) is dict
                     and 'ranges' in row['holes'] for row in (a, b)))
            need(a['holes']['ranges'] is not None and a['holes']['ranges'] == b['holes']['ranges'])
        if a['kind'] == 'symlink':
            need(all(type(row.get('symlink_bytes')) is str for row in (a, b)))
        if a['kind'] != 'directory':
            source_classes.setdefault(tuple(a['device_inode']), []).append(name)
            destination_classes.setdefault(tuple(b['device_inode']), []).append(name)
    need(sum(row.get('size', 0) for row in left.values() if row['kind'] == 'file') <= 32 * 1024 * 1024)
    source_inodes = {tuple(row['device_inode']) for row in left.values()}
    need(not source_inodes.intersection(tuple(row['device_inode']) for row in right.values()))
    need(all(row['device_inode'][0] == left['']['device_inode'][0] for row in (*left.values(), *right.values())))
    for names in destination_classes.values():
        # A merged class would need a new inode; splitting is deliberately absent.
        need(len({tuple(left[name]['device_inode']) for name in names}) == 1)
        need(all(right[name]['link_count'] == len(names) for name in names), 'destination_external_alias')
    aliases, canonical = [], []
    for names in source_classes.values():
        first = min(names); canonical.append(first)
        need(len(names) == 1 or not left[first]['flags'] & BLOCKING)
        need(all(left[name]['link_count'] >= len(names) for name in names))  # intentional outside source aliases
        for name in names:
            need(all(left[name].get(field) == left[first].get(field) for field in correct.FIELDS))
            if right[name]['device_inode'] != right[first]['device_inode']:
                need(not (right[name]['flags'] | right[first]['flags']) & BLOCKING)
                aliases.append((first, name))
    directories = sorted((name for name in left if left[name]['kind'] == 'directory'),
                         key=lambda name: (name.count('/') + bool(name), name), reverse=True)
    objects = sorted(canonical) + directories
    # Canonical metadata is sufficient only after the complete class plan qualifies.
    return {'aliases': aliases, 'objects': objects, 'directories': directories,
            'flags': [name for name in objects if left[name]['flags'] != right[name]['flags']],
            'acl': [name for name in objects if left[name]['acl'] != right[name]['acl']]}


class DarwinOps:
    """Small descriptor-only setters; no pathname metadata fallback."""
    def __init__(self):
        need(sys.platform == 'darwin' and hasattr(os, 'O_SYMLINK'), 'platform_unavailable')
        self.libc = ctypes.CDLL(None, use_errno=True)
        pointer, integer, size = ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t
        for name, arguments, result in (
            ('fchflags', [integer, ctypes.c_uint32], integer),
            ('acl_get_fd_np', [integer, integer], pointer), ('acl_init', [integer], pointer),
            ('acl_free', [pointer], integer), ('acl_to_text', [pointer, ctypes.POINTER(ctypes.c_ssize_t)], pointer),
            ('acl_valid', [pointer], integer), ('acl_set_fd_np', [integer, pointer, integer], integer),
            ('acl_get_entry', [pointer, integer, ctypes.POINTER(pointer)], integer),
            ('acl_get_tag_type', [pointer, ctypes.POINTER(integer)], integer),
            ('acl_get_flagset_np', [pointer, ctypes.POINTER(pointer)], integer),
            ('acl_get_flag_np', [pointer, integer], integer),
            ('acl_get_permset_mask_np', [pointer, ctypes.POINTER(ctypes.c_uint64)], integer),
            ('flistxattr', [integer, pointer, size, integer], ctypes.c_ssize_t),
            ('fgetxattr', [integer, ctypes.c_char_p, pointer, size, ctypes.c_uint32, integer], ctypes.c_ssize_t),
        ):
            function = getattr(self.libc, name); function.argtypes = arguments; function.restype = result

    @staticmethod
    def checked(value):
        if value < 0:
            raise OSError(ctypes.get_errno() or errno.EIO, 'descriptor operation failed')
        return value

    def call(self, function, *arguments):
        ctypes.set_errno(0)
        return self.checked(function(*arguments))

    def free(self, pointer):
        primary = sys.exc_info()[1]
        try:
            self.call(self.libc.acl_free, pointer)
        except BaseException:
            # Preserve the original failure and its captured errno.
            if primary is None:
                raise

    def acl(self, fd):
        ctypes.set_errno(0)
        acl = self.libc.acl_get_fd_np(fd, 0x100)
        failure = ctypes.get_errno()
        if not acl and failure == errno.ENOENT:
            ctypes.set_errno(0)
            acl = self.libc.acl_init(0)
            failure = ctypes.get_errno()
        if not acl:
            raise OSError(failure or errno.EIO, 'ACL unavailable')
        return acl

    def acl_text(self, acl):
        length = ctypes.c_ssize_t()
        ctypes.set_errno(0)
        text = self.libc.acl_to_text(acl, ctypes.byref(length))
        failure = ctypes.get_errno()
        if not text:
            raise OSError(failure or errno.EIO, 'ACL serialization unavailable')
        try:
            need(0 <= length.value <= 16384, 'acl_unavailable')
            return ctypes.string_at(text, length.value).hex()
        finally:
            self.free(text)

    def admit_acl(self, fd, row):
        acl = self.acl(fd)
        try:
            self.call(self.libc.acl_valid, acl)
            text = self.acl_text(acl)
            global_flags = ctypes.c_void_p()
            self.call(self.libc.acl_get_flagset_np, acl, ctypes.byref(global_flags))
            for bit in (1, 1 << 17):
                need(self.call(self.libc.acl_get_flag_np, global_flags, bit) == 0)
            # No-ACL and a validated empty representation are equivalent only for
            # this admission read; final copy equality keeps its original rules.
            if row['acl']['text_hex'] is not None:
                need(text == row['acl']['text_hex'], 'acl_changed')
            entry = ctypes.c_void_p(); index = 0; count = 0
            while True:
                ctypes.set_errno(0)
                result = self.libc.acl_get_entry(acl, index, ctypes.byref(entry))
                if result:
                    need(ctypes.get_errno() == errno.EINVAL, 'acl_unavailable')
                    break
                count += 1; need(count <= 128)
                tag = ctypes.c_int(); flags = ctypes.c_void_p(); permissions = ctypes.c_uint64()
                self.call(self.libc.acl_get_tag_type, entry, ctypes.byref(tag))
                self.call(self.libc.acl_get_flagset_np, entry, ctypes.byref(flags))
                self.call(self.libc.acl_get_permset_mask_np, entry, ctypes.byref(permissions))
                need(tag.value == 1 and not permissions.value & ~(2 | 128 | 512 | 2048 | (1 << 20)))
                for bit in (16, 32, 64, 128, 256):
                    value = self.call(self.libc.acl_get_flag_np, flags, bit); need(value == 0)
                index = -1
            need(row['acl']['text_hex'] is not None or count == 0, 'acl_changed')
        finally:
            self.free(acl)

    def copy_acl(self, source, destination):
        acl = self.acl(source)
        try:
            self.call(self.libc.acl_valid, acl)
            self.call(self.libc.acl_set_fd_np, destination, acl, 0x100)
        finally:
            self.free(acl)

    def flags(self, fd, flags):
        self.call(self.libc.fchflags, fd, flags)

    def payload(self, fd, row):
        # Read every xattr on the held object, including the resource fork.
        length = self.call(self.libc.flistxattr, fd, None, 0, 0); need(length <= 65536)
        names = ctypes.create_string_buffer(max(length, 1))
        need(self.call(self.libc.flistxattr, fd, names, length, 0) == length)
        need(not length or names.raw[length - 1] == 0)
        attributes = {}
        for name in filter(None, names.raw[:length].split(b'\x00')):
            length = self.call(self.libc.fgetxattr, fd, name, None, 0, 0, 0); need(length <= 1048576)
            value = ctypes.create_string_buffer(max(length, 1))
            need(self.call(self.libc.fgetxattr, fd, name, value, length, 0, 0) == length)
            need(name.hex() not in attributes)
            attributes[name.hex()] = value.raw[:length].hex()
        need(attributes == row['xattrs'], 'payload_changed')
        if row['kind'] == 'file':
            digest = hashlib.sha256(); offset = 0
            while data := os.pread(fd, 65536, offset):
                offset += len(data); need(offset <= row['size'], 'payload_changed'); digest.update(data)
            need(offset == row['size'] and digest.hexdigest() == row['sha256'], 'payload_changed')
            need(correct._holes(fd, row['size'])['ranges'] == row['holes']['ranges'], 'payload_changed')

    def times(self, fd, mtime):
        class Timespec(ctypes.Structure):
            _fields_ = [('seconds', ctypes.c_long), ('nanoseconds', ctypes.c_long)]
        times = (Timespec * 2)(Timespec(0, -2), Timespec(*divmod(mtime, 1000000000)))  # Darwin UTIME_OMIT
        function = self.libc.futimens
        function.argtypes = [ctypes.c_int, ctypes.POINTER(Timespec)]; function.restype = ctypes.c_int
        self.call(function, fd, times)

    open = staticmethod(os.open)
    close = staticmethod(os.close)
    fstat = staticmethod(os.fstat)
    named = staticmethod(lambda parent, name: os.stat(name, dir_fd=parent, follow_symlinks=False))
    mode = staticmethod(os.fchmod)
    unlink = staticmethod(lambda parent, name: os.unlink(name, dir_fd=parent))
    link = staticmethod(lambda parent, name, target, alias: os.link(name, alias, src_dir_fd=parent,
        dst_dir_fd=target, follow_symlinks=False))
    readlink = staticmethod(lambda parent, name: os.fsencode(os.readlink(name, dir_fd=parent)).hex())


class Session:
    """Bounded owned FD inventory, retained across the existing native helper."""
    def __init__(self, base, source, parent, expected, *, ops=None, cancelled=None):
        self.cancelled = cancelled if cancelled is not None else lambda: False
        self.expected = expected; self.source = {}; self.destination = {}; self.owned = []
        self.changed_flags = {}; self.changed_modes = {}; self.failure = None; self.bindings = []
        self.operation = 'not_started'; self.operation_phase = 'preflight'
        self.summary = {'status': 'not_started', 'mutation_attempts': 0, 'alias_replacements': 0,
                        'acl_repairs': 0, 'tracking_repairs': 0, 'directory_times': 0,
                        'recovery': 'not_needed'}
        self.close_outcome = {'status': 'not_needed', 'attempts': 0, 'failures': 0, 'errno': None}
        self.admission = {'status': 'refused', 'phase': 'ops_binding', 'refusal_code': None, 'errno': None,
                          'close': self.close_outcome}
        try:
            self.ops = ops if ops is not None else DarwinOps()
            self.admission['phase'] = 'roots'
            self.root = self.take(self.ops.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC))
            info = self.ops.fstat(self.root)
            need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
            self.source_root = self.take(self.ops.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                                       dir_fd=self.root))
            self.parent = self.take(self.ops.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                                 dir_fd=self.root))
            self.pins = [(fd, self.ops.fstat(fd)) for fd in (self.root, self.source_root, self.parent)]
            self.bindings = [(self.root, source, self.source_root), (self.root, parent, self.parent)]
            self.capture(self.source_root, expected, self.source)
            self.admission.update(status='complete', phase='complete')
        except BaseException as error:
            # Capture the primary errno before close can change thread errno.
            report = refusal_report(error, self.admission['phase'], self.close_outcome)
            self.close()
            report['close'] = dict(self.close_outcome)
            raise AdmissionError(report) from None

    def admission_report(self):
        # Admission is constructor-only; close covers this session's retained FDs.
        return dict(self.admission, close=dict(self.close_outcome))

    def note_admission(self, phase):
        if self.admission['status'] != 'complete':
            self.admission['phase'] = phase

    def take(self, fd):
        self.owned.append(fd); self.close_outcome['status'] = 'deferred'; return fd

    def capture(self, root, snapshot, records):
        self.note_admission('schema')
        need(snapshot.get('unavailable_fields') == [] and 0 < len(snapshot['entries']) <= MAX_ENTRIES)
        total = 0
        for row in snapshot['entries'].values():
            need(type(row) is dict and COMMON_REQUIRED <= row.keys() and row.keys() <= ROW_FIELDS)
            need(row['kind'] in ('directory', 'file', 'symlink') and row['uid'] == os.geteuid())
            need(type(row['mode']) is int and not row['mode'] & (stat.S_ISUID | stat.S_ISGID))
            need(type(row['flags']) is int and row['flags'] >= 0 and not row['flags'] & ~ALLOWED_FLAGS)
            if row['kind'] == 'file':
                need(type(row.get('size')) is int and 0 <= row['size'] <= 32 * 1024 * 1024)
                total += row['size']
        need(total <= 32 * 1024 * 1024)
        for name in sorted(snapshot['entries'], key=lambda name: (name.count('/') + bool(name), name)):
            self.note_admission('entry_identity')
            parent, leaf = relative(name); row = snapshot['entries'][name]
            parent_fd = records[parent]['fd'] if name else root
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
            flags |= os.O_SYMLINK if row['kind'] == 'symlink' else os.O_NOFOLLOW
            if row['kind'] == 'directory': flags |= os.O_DIRECTORY
            fd = self.take(self.ops.open(leaf, flags, dir_fd=parent_fd)) if name else root
            self.note_admission('entry_identity')
            info = self.ops.fstat(fd)
            need((info.st_dev, info.st_ino) == tuple(row['device_inode']) and stat.S_IMODE(info.st_mode) == row['mode']
                 and info.st_uid == row['uid'] and info.st_gid == row['gid'] and info.st_nlink == row['link_count']
                 and info.st_flags == row['flags'] and info.st_mtime_ns == row['mtime_ns']
                 and info.st_ctime_ns == row['ctime_ns'], 'identity_changed')
            need((stat.S_ISDIR(info.st_mode) if row['kind'] == 'directory' else
                  stat.S_ISREG(info.st_mode) if row['kind'] == 'file' else stat.S_ISLNK(info.st_mode)), 'identity_changed')
            self.note_admission('acl')
            self.ops.admit_acl(fd, row)
            self.note_admission('payload')
            self.ops.payload(fd, row)
            self.note_admission('symlink')
            if row['kind'] == 'symlink': need(self.ops.readlink(parent_fd, leaf) == row['symlink_bytes'])
            self.note_admission('entry_identity')
            after = self.ops.fstat(fd)
            need(signature(after) == signature(info), 'identity_changed')
            entry_id = f'e{sorted(snapshot["entries"]).index(name) + 1:04}'
            records[name] = {'fd': fd, 'info': after, 'parent': parent_fd, 'leaf': leaf, 'entry_id': entry_id}
        self.note_admission('source_closure')
        self.check(records, source=records is self.source)

    def check(self, records, *, source=False):
        for name, record in records.items():
            info = self.ops.fstat(record['fd'])
            self.note_difference(record, record['info'], info, 'source_held' if source else 'destination_held')
            need(signature(info) == signature(record['info']), 'source_changed' if source else 'identity_changed')
            if name:
                named = self.ops.named(record['parent'], record['leaf'])
                self.note_difference(record, info, named, 'source_named' if source else 'destination_named')
                need(signature(named) == signature(info), 'source_changed' if source else 'identity_changed')
        for fd, before in self.pins:
            now = self.ops.fstat(fd)
            need(identity(now) == identity(before) and now.st_mode == before.st_mode
                 and now.st_uid == before.st_uid and now.st_gid == before.st_gid
                 and now.st_flags == before.st_flags, 'identity_changed')
        for parent, name, fd in self.bindings:
            need(identity(self.ops.named(parent, name)) == identity(self.ops.fstat(fd)), 'identity_changed')

    def preflight(self):
        need(not self.cancelled(), 'restoration_cancelled')
        self.check(self.source, source=True); self.check(self.destination)
        counts = {}
        for record in self.destination.values():
            if not stat.S_ISDIR(record['info'].st_mode):
                key = identity(record['info']); counts[key] = counts.get(key, 0) + 1
        for record in self.destination.values():
            if not stat.S_ISDIR(record['info'].st_mode):
                need(record['info'].st_nlink == counts[identity(record['info'])], 'destination_external_alias')

    def note_difference(self, record, before, after, check, allowed=(), parent_nlink=None):
        # Only project a failed comparison already required by the guards.
        fields = [('identity', identity(before), identity(after)),
            ('generation', getattr(before, 'st_gen', None), getattr(after, 'st_gen', None)),
            ('birthtime', getattr(before, 'st_birthtime', None), getattr(after, 'st_birthtime', None))]
        for field in ('st_mode', 'st_uid', 'st_gid', 'st_size', 'st_nlink', 'st_flags', 'st_mtime_ns', 'st_ctime_ns'):
            if field not in allowed or field == 'st_nlink' and parent_nlink is not None:
                expected = before.st_nlink + parent_nlink if field == 'st_nlink' and parent_nlink is not None else getattr(before, field)
                fields.append((field.removeprefix('st_'), expected, getattr(after, field)))
        for field, expected, actual in fields:
            if expected != actual:
                self.summary.setdefault('failure_context', {'operation': self.operation,
                    'phase': self.operation_phase, 'check': check, 'entry_id': record.get('entry_id'), 'field': field})
                break

    def refresh(self, records, allowed, *, parent_nlink=None):
        for record in records:
            before, after = record['info'], self.ops.fstat(record['fd'])
            permitted = allowed(record) if callable(allowed) else allowed
            delta = parent_nlink[1] if parent_nlink is not None and record is parent_nlink[0] else None
            self.note_difference(record, before, after, 'refresh', permitted, delta)
            need(identity(after) == identity(before), 'identity_changed')
            need(getattr(after, 'st_gen', None) == getattr(before, 'st_gen', None)
                 and getattr(after, 'st_birthtime', None) == getattr(before, 'st_birthtime', None), 'identity_changed')
            for key in ('st_mode', 'st_uid', 'st_gid', 'st_size', 'st_nlink', 'st_flags', 'st_mtime_ns', 'st_ctime_ns'):
                if key == 'st_nlink' and delta is not None:
                    need(after.st_nlink == before.st_nlink + delta, 'identity_changed')
                else:
                    need(key in permitted or getattr(before, key) == getattr(after, key), 'identity_changed')
            record['info'] = after

    def mutate(self, call, records, allowed, *, operation='metadata_setter', parent_nlink=None):
        self.operation = operation; self.operation_phase = 'preflight'
        self.preflight(); self.summary['mutation_attempts'] += 1
        self.operation_phase = 'native_call'; call()
        self.operation_phase = 'refresh'
        self.refresh(records, allowed, parent_nlink=parent_nlink)
        self.operation_phase = 'postflight'
        self.preflight()

    def restore(self, destination_snapshot, output='output'):
        self.summary['status'] = 'incomplete'
        self.operation = 'destination_capture'; self.operation_phase = 'preflight'
        try:
            derived = plan(self.expected, destination_snapshot, os.geteuid())
            need('/' not in output and output not in ('', '.', '..'))
            destination = self.take(self.ops.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                                 dir_fd=self.parent))
            self.bindings.append((self.parent, output, destination))
            self.capture(destination, destination_snapshot, self.destination)
            self.preflight()
            # Every setter/alias has a qualified selector before the first change.
            needed_parents = {relative(alias)[0] for _, alias in derived['aliases']}
            for name in needed_parents:
                record = self.destination[name]; original = stat.S_IMODE(record['info'].st_mode)
                if original & 0o300 != 0o300:
                    self.changed_modes[record['fd']] = original
                    self.mutate(lambda r=record, mode=original: self.ops.mode(r['fd'], mode | 0o300),
                                [record], {'st_mode', 'st_ctime_ns'})
            for canonical, name in derived['aliases']:
                first, victim = self.destination[canonical], self.destination[name]
                parent = self.destination[relative(name)[0]]
                # The plan admits blockers only on singleton metadata targets.
                need(not victim['info'].st_flags & BLOCKING and not first['info'].st_flags & BLOCKING)
                same = [r for r in self.destination.values() if identity(r['info']) == identity(first['info'])]
                old_class = [r for r in self.destination.values() if identity(r['info']) == identity(victim['info'])]
                def remove():
                    self.ops.unlink(victim['parent'], victim['leaf'])
                    # The removed held inode is no longer a named destination member.
                    del self.destination[name]
                self.mutate(remove, old_class + [parent], lambda record:
                    {'st_size', 'st_mtime_ns', 'st_ctime_ns'} if record is parent else {'st_nlink', 'st_ctime_ns'},
                    operation='alias_unlink', parent_nlink=(parent, -1))
                remaining = sum(identity(record['info']) == identity(victim['info'])
                                for record in self.destination.values())
                need(self.ops.fstat(victim['fd']).st_nlink == remaining, 'destination_external_alias')
                self.preflight()
                try:
                    self.ops.named(victim['parent'], victim['leaf'])
                except OSError as error:
                    need(error.errno == errno.ENOENT, 'identity_changed')
                else:
                    raise RestoreError('identity_changed')
                self.operation = 'alias_link'; self.operation_phase = 'preflight'
                self.preflight()
                self.summary['mutation_attempts'] += 1
                self.operation_phase = 'native_call'
                self.ops.link(first['parent'], first['leaf'], victim['parent'], victim['leaf'])
                self.operation_phase = 'refresh'
                self.refresh(same + [parent], lambda record:
                    {'st_size', 'st_mtime_ns', 'st_ctime_ns'} if record is parent else {'st_nlink', 'st_ctime_ns'},
                    parent_nlink=(parent, 1))
                replacement = dict(first, parent=victim['parent'], leaf=victim['leaf'], entry_id=victim['entry_id'])
                self.destination[name] = replacement
                self.operation_phase = 'postflight'
                self.preflight(); self.summary['alias_replacements'] += 1
            for name in derived['flags']:
                record = self.destination[name]; original = record['info'].st_flags
                self.changed_flags[record['fd']] = original
                if original & BLOCKING:
                    self.mutate(lambda r=record: self.ops.flags(r['fd'], original & ~BLOCKING),
                                [record], {'st_flags', 'st_ctime_ns'})
                expected = self.expected['entries'][name]['flags']
                related = [r for r in self.destination.values() if identity(r['info']) == identity(record['info'])]
                self.mutate(lambda r=record, flags=expected: self.ops.flags(r['fd'], flags & ~BLOCKING),
                            related, {'st_flags', 'st_ctime_ns'})
                self.summary['tracking_repairs'] += 1
            for name in derived['acl']:
                record = self.destination[name]
                self.mutate(lambda: self.ops.copy_acl(self.source[name]['fd'], record['fd']),
                            [r for r in self.destination.values() if identity(r['info']) == identity(record['info'])], {'st_ctime_ns'})
                self.summary['acl_repairs'] += 1
            for name in derived['directories']:
                record = self.destination[name]; mode = self.expected['entries'][name]['mode']
                if stat.S_IMODE(record['info'].st_mode) != mode:
                    self.mutate(lambda r=record, mode=mode: self.ops.mode(r['fd'], mode), [record], {'st_mode', 'st_ctime_ns'})
                mtime = self.expected['entries'][name]['mtime_ns']
                if record['info'].st_mtime_ns != mtime:
                    def set_time(r=record, value=mtime):
                        before_atime = self.ops.fstat(r['fd']).st_atime_ns
                        self.ops.times(r['fd'], value)
                        need(self.ops.fstat(r['fd']).st_atime_ns == before_atime, 'atime_changed')
                    self.mutate(set_time, [record], {'st_mtime_ns', 'st_ctime_ns'})
                    self.summary['directory_times'] += 1
            # Restore exact blocking state only after all forward metadata work.
            for name in derived['objects']:
                record = self.destination[name]; flags = self.expected['entries'][name]['flags']
                if record['info'].st_flags != flags:
                    self.mutate(lambda r=record, flags=flags: self.ops.flags(r['fd'], flags),
                                [r for r in self.destination.values() if identity(r['info']) == identity(record['info'])],
                                {'st_flags', 'st_ctime_ns'})
            self.preflight()
            self.summary['status'] = 'restored_pending_final_verifiers'
        except BaseException as error:
            self.failure = error
            self.summary.setdefault('failure_context', {'operation': self.operation,
                'phase': self.operation_phase, 'check': 'unclassified', 'entry_id': None, 'field': None})
            self.summary['error'] = str(error) if isinstance(error, RestoreError) else 'restoration_operation_failed'
            self.summary['status'] = 'incomplete'
            self.recover()
        return dict(self.summary)

    def recover(self):
        # Stop forward repairs. Recovery can affect ONLY the still-held admitted
        # inodes, regardless of whether names moved; never a pathname fallback.
        self.summary['recovery'] = 'complete'
        for fd, original in reversed(list(self.changed_flags.items())):
            try:
                now = self.recovery_identity(fd)
                # Preserve newly enabled tracking; clearing it can strand a
                # document ID. Recovery restores only the original blockers.
                self.ops.flags(fd, (now.st_flags & ~BLOCKING) | (original & BLOCKING))
            except BaseException:
                self.summary['recovery'] = 'incomplete'
        for fd, mode in reversed(list(self.changed_modes.items())):
            try:
                self.recovery_identity(fd)
                self.ops.mode(fd, mode)
            except BaseException:
                self.summary['recovery'] = 'incomplete'

    def recovery_identity(self, fd):
        record = next(r for r in self.destination.values() if r['fd'] == fd)
        now = self.ops.fstat(fd)
        need(identity(now) == identity(record['info']) and now.st_uid == os.geteuid()
             and now.st_gid == record['info'].st_gid and not now.st_flags & ~ALLOWED_FLAGS)
        need(stat.S_IMODE(self.ops.fstat(self.root).st_mode) == 0o700)
        for parent, name, opened in self.bindings:
            need(identity(self.ops.named(parent, name)) == identity(self.ops.fstat(opened)))
        accounted = 0
        for name, other in self.destination.items():
            if identity(other['info']) == identity(now):
                if name: need(identity(self.ops.named(other['parent'], other['leaf'])) == identity(now))
                accounted += 1
        if not stat.S_ISDIR(now.st_mode): need(now.st_nlink == accounted)
        return now

    def close(self):
        while self.owned:
            self.close_outcome['attempts'] += 1
            try:
                self.ops.close(self.owned.pop())
            except BaseException as error:
                self.close_outcome['failures'] += 1
                if self.close_outcome['errno'] is None:
                    self.close_outcome['errno'] = error_number(error)
        self.close_outcome['status'] = ('incomplete' if self.close_outcome['failures'] else
                                       'complete' if self.close_outcome['attempts'] else 'not_needed')
        self.summary['close'] = dict(self.close_outcome)
        if self.close_outcome['failures']:
            self.summary.update(status='incomplete', error='restoration_close_failed')
        return self.close_outcome['failures'] == 0
