"""Confined small-recipe reconstruction experiment; never a production backend.

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


def profile_limits(profile):
    need(profile in ('small', 'docs'))
    return ((MAX_ENTRIES, 32 * 1024 * 1024, 32 * 1024 * 1024) if profile == 'small' else
            (correct.DOCS_ENTRIES, correct.DOCS_LOGICAL_BYTES, correct.DOCS_MAX_FILE))


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


def owned_setid_leaf(snapshot, name, owner):
    row = snapshot['entries'][name]
    return (owner == os.geteuid() and row['kind'] == 'file' and row['uid'] == owner and row['gid'] == os.getegid()
            and row['link_count'] == 1 and sum(other['device_inode'] == row['device_inode']
                for other in snapshot['entries'].values()) == 1)


def plan(source, destination, owner, *, profile='small'):
    """Compute selectors from full verified metadata, never the safe projection."""
    maximum, logical, file_size = profile_limits(profile)
    for snapshot in (source, destination):
        need(type(snapshot) is dict and snapshot.get('unavailable_fields') == [])
        need(type(snapshot.get('entries')) is dict and 0 < len(snapshot['entries']) <= maximum)
        if profile == 'docs': correct.docs_shape(snapshot['entries'])
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
            need(type(row['mode']) is int)
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
            if field in ('acl', 'flags', 'mode') or (field == 'mtime_ns' and a['kind'] == 'directory'):
                continue
            need(a.get(field) == b.get(field))
        if a['kind'] == 'file':
            need(all({'size', 'sha256', 'holes'} <= row.keys() and type(row['size']) is int
                     and 0 <= row['size'] <= file_size and type(row['holes']) is dict
                     and 'ranges' in row['holes'] for row in (a, b)))
            need(a['holes']['ranges'] is not None and a['holes']['ranges'] == b['holes']['ranges'])
        if a['kind'] == 'symlink':
            need(all(type(row.get('symlink_bytes')) is str for row in (a, b)))
        if a['kind'] != 'directory':
            source_classes.setdefault(tuple(a['device_inode']), []).append(name)
            destination_classes.setdefault(tuple(b['device_inode']), []).append(name)
    need(sum(row.get('size', 0) for row in left.values() if row['kind'] == 'file') <= logical)
    source_inodes = {tuple(row['device_inode']) for row in left.values()}
    need(not source_inodes.intersection(tuple(row['device_inode']) for row in right.values()))
    need(all(row['device_inode'][0] == left['']['device_inode'][0] for row in (*left.values(), *right.values())))
    modes = []
    for name, a in left.items():
        b = right[name]
        if a['mode'] != b['mode'] or (a['mode'] | b['mode']) & 0o6000:
            need(owned_setid_leaf(source, name, owner) and owned_setid_leaf(destination, name, owner))
            need(b['mode'] in (a['mode'], a['mode'] & ~0o6000))
            if a['mode'] != b['mode']: modes.append(name)
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
    return {'aliases': aliases, 'objects': objects, 'directories': directories, 'modes': modes,
            'flags': [name for name in objects if left[name]['flags'] != right[name]['flags']],
            'acl': [name for name in objects if left[name]['acl'] != right[name]['acl']]}


class DarwinOps:
    """Small descriptor-only setters; no pathname metadata fallback."""
    def __init__(self, *, budget=None):
        need(sys.platform == 'darwin' and hasattr(os, 'O_SYMLINK'), 'platform_unavailable')
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.budget = budget
        pointer, integer, size = ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t
        for name, arguments, result in (
            ('fchflags', [integer, ctypes.c_uint32], integer),
            ('acl_get_fd_np', [integer, integer], pointer), ('acl_init', [integer], pointer),
            ('acl_free', [pointer], integer), ('acl_to_text', [pointer, ctypes.POINTER(ctypes.c_ssize_t)], pointer),
            ('acl_size', [pointer], ctypes.c_ssize_t),
            ('acl_copy_ext', [pointer, pointer, ctypes.c_ssize_t], ctypes.c_ssize_t),
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

    def acl_binary(self, acl):
        length = self.call(self.libc.acl_size, acl)
        need(0 < length <= 16384, 'acl_unavailable')
        data = ctypes.create_string_buffer(length)
        need(self.call(self.libc.acl_copy_ext, data, acl, length) == length, 'acl_unavailable')
        return data.raw

    def acl_fingerprint(self, fd):
        # Complete public serialization, kept private for one fixture's cleanup.
        acl = self.acl(fd)
        try:
            self.call(self.libc.acl_valid, acl)
            return self.acl_binary(acl)
        finally:
            self.free(acl)

    def clear_fixture_acl(self, fd):
        ctypes.set_errno(0)
        acl = self.libc.acl_init(0); failure = ctypes.get_errno()
        if not acl: raise OSError(failure or errno.EIO, 'ACL unavailable')
        try:
            self.call(self.libc.acl_valid, acl)
            empty = self.acl_binary(acl)
            self.call(self.libc.acl_set_fd_np, fd, acl, 0x100)
            need(self.acl_fingerprint(fd) == empty, 'acl_changed')
        finally:
            self.free(acl)

    def flags(self, fd, flags):
        self.call(self.libc.fchflags, fd, flags)

    def payload(self, fd, row):
        budget = getattr(self, 'budget', None)
        ticket = budget.begin() if budget is not None else None
        try:
            return self._payload(fd, row, budget, ticket)
        finally:
            if budget is not None: budget.discard(ticket)

    def _payload(self, fd, row, budget, ticket):
        # Read every xattr on the held object, including the resource fork.
        length = self.call(self.libc.flistxattr, fd, None, 0, 0); need(length <= 65536)
        names = ctypes.create_string_buffer(max(length, 1))
        need(self.call(self.libc.flistxattr, fd, names, length, 0) == length)
        need(not length or names.raw[length - 1] == 0)
        attributes = {}
        for name in filter(None, names.raw[:length].split(b'\x00')):
            length = self.call(self.libc.fgetxattr, fd, name, None, 0, 0, 0); need(length <= 1048576)
            if budget is not None: budget.reserve(ticket, 4 * (len(name) + length))
            value = ctypes.create_string_buffer(max(length, 1))
            need(self.call(self.libc.fgetxattr, fd, name, value, length, 0, 0) == length)
            need(name.hex() not in attributes)
            attributes[name.hex()] = value.raw[:length].hex()
        need(attributes == row['xattrs'], 'payload_changed')
        if row['kind'] == 'file':
            digest = hashlib.sha256(); offset = 0
            while data := os.pread(fd, min(65536, row['size'] - offset + 1) if budget is not None else 65536, offset):
                offset += len(data); need(offset <= row['size'], 'payload_changed'); digest.update(data)
            need(offset == row['size'] and digest.hexdigest() == row['sha256'], 'payload_changed')
            holes = (correct._holes(fd, row['size'], budget=budget, ticket=ticket) if budget is not None
                     else correct._holes(fd, row['size']))
            need(holes['ranges'] == row['holes']['ranges'], 'payload_changed')

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
    """Private stable-source experiment with bounded operation-local descriptors.

    Inactive names are reopened and checked, not continuously pinned. Sequential
    checks and final verifiers do not provide an atomic namespace snapshot or
    exclude same-user replacement/restore races between lease windows.
    """
    def __init__(self, base, source, parent, expected, *, ops=None, cancelled=None, profile='small', budget=None):
        self.cancelled = cancelled if cancelled is not None else lambda: False
        self.expected = expected; self.source = {}; self.destination = {}
        self.owned = []; self.uncertain = []; self.bindings = []; self.pins = []
        self.sources = []; self.targets = []; self.source_classes = {}; self.destination_classes = {}
        self.changed_flags = {}; self.changed_modes = {}; self.failure = None
        self.operation = 'not_started'; self.operation_phase = 'preflight'
        self.counts = dict(open_attempts=0, opened=0, close_attempts=0, closed=0,
                           fstat=0, named=0, peak=0, live=0, uncertain=0)
        self.summary = {'status': 'not_started', 'mutation_attempts': 0, 'alias_replacements': 0,
                        'acl_repairs': 0, 'tracking_repairs': 0, 'directory_times': 0, 'mode_repairs': 0,
                        'recovery': 'not_needed', 'lease_counts': self.counts}
        self.close_outcome = {'status': 'not_needed', 'attempts': 0, 'failures': 0, 'errno': None}
        self.admission = {'status': 'refused', 'phase': 'ops_binding', 'refusal_code': None, 'errno': None,
                          'close': self.close_outcome}
        self.profile = profile; self.budget = budget; self.buffer_ticket = None
        try:
            profile_limits(profile)
            need(profile != 'docs' or isinstance(budget, correct.SnapshotBudget))
            if budget is not None:
                self.buffer_ticket = budget.begin()
                # ACL serialization, xattr-name parsing and two streaming chunks.
                budget.reserve(self.buffer_ticket, 512 * 1024)
            self.ops = ops if ops is not None else DarwinOps(budget=budget) if budget is not None else DarwinOps()
            self.note_admission('roots')
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            self.root = self.open(base, flags)
            info = self.fstat(self.root)
            need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
            self.source_root = self.open(source, flags, dir_fd=self.root)
            self.parent = self.open(parent, flags, dir_fd=self.root)
            self.pins = [(fd, self.fstat(fd)) for fd in (self.root, self.source_root, self.parent)]
            self.bindings = [(self.root, source, self.source_root), (self.root, parent, self.parent)]
            self.capture(self.source_root, expected, self.source)
            self.source_classes = self.classes(self.source)
            self.admission.update(status='complete', phase='complete')
        except BaseException as error:
            report = refusal_report(error, self.admission['phase'], self.close_outcome)
            self.close(); report['close'] = dict(self.close_outcome)
            raise AdmissionError(report) from None

    def admission_report(self):
        return dict(self.admission, close=dict(self.close_outcome))

    def note_admission(self, phase):
        if self.admission['status'] != 'complete': self.admission['phase'] = phase

    def open(self, name, flags, *, dir_fd=None):
        need(not self.uncertain, 'restoration_close_failed')
        need(not self.cancelled(), 'restoration_cancelled')
        self.counts['open_attempts'] += 1
        fd = self.ops.open(name, flags, dir_fd=dir_fd) if dir_fd is not None else self.ops.open(name, flags)
        need(fd not in self.owned, 'identity_changed')
        self.owned.append(fd); self.counts['opened'] += 1
        self.counts['live'] = len(self.owned)
        self.counts['peak'] = max(self.counts['peak'], len(self.owned))
        self.close_outcome['status'] = 'deferred'
        return fd

    def fstat(self, fd):
        self.counts['fstat'] += 1
        return self.ops.fstat(fd)

    def named(self, parent, name):
        self.counts['named'] += 1
        return self.ops.named(parent, name)

    def release(self, descriptors):
        primary = sys.exc_info()[1]
        failed = False
        for fd in reversed(descriptors):
            need(fd in self.owned, 'identity_changed')
            self.owned.remove(fd)
            self.counts['close_attempts'] += 1; self.close_outcome['attempts'] += 1
            try:
                self.ops.close(fd); self.counts['closed'] += 1
            except BaseException as error:
                failed = True; self.uncertain.append(fd)
                self.close_outcome['failures'] += 1
                if self.close_outcome['errno'] is None: self.close_outcome['errno'] = error_number(error)
            self.counts['live'] = len(self.owned); self.counts['uncertain'] = len(self.uncertain)
        if failed:
            self.close_outcome['status'] = 'incomplete'
            if primary is None: raise RestoreError('restoration_close_failed')

    @staticmethod
    def classes(records):
        result = {}
        for name, record in records.items():
            if not stat.S_ISDIR(record['info'].st_mode): result.setdefault(identity(record['info']), set()).add(name)
        return result

    def note_difference(self, record, before, after, check, allowed=(), parent_nlink=None):
        fields = [('identity', identity(before), identity(after)),
            ('generation', getattr(before, 'st_gen', None), getattr(after, 'st_gen', None)),
            ('birthtime', getattr(before, 'st_birthtime', None), getattr(after, 'st_birthtime', None))]
        for field in ('st_mode', 'st_uid', 'st_gid', 'st_size', 'st_nlink', 'st_flags', 'st_mtime_ns', 'st_ctime_ns'):
            if field not in allowed or field == 'st_nlink' and parent_nlink is not None:
                value = before.st_nlink + parent_nlink if field == 'st_nlink' and parent_nlink is not None else getattr(before, field)
                fields.append((field.removeprefix('st_'), value, getattr(after, field)))
        for field, expected, actual in fields:
            if expected != actual:
                self.summary.setdefault('failure_context', {'operation': self.operation,
                    'phase': self.operation_phase, 'check': check, 'entry_id': record.get('entry_id'), 'field': field})
                break

    def compare(self, record, info, check, *, source=False):
        self.note_difference(record, record['info'], info, check)
        need(signature(info) == signature(record['info']), 'source_changed' if source else 'identity_changed')

    def anchors(self, *, recovery=False):
        need(stat.S_IMODE(self.fstat(self.root).st_mode) == 0o700, 'identity_changed')
        for fd, before in self.pins:
            now = self.fstat(fd)
            need(identity(now) == identity(before) and now.st_mode == before.st_mode and
                 now.st_uid == before.st_uid and now.st_gid == before.st_gid and now.st_flags == before.st_flags,
                 'identity_changed')
        for parent, name, fd in self.bindings:
            need(identity(self.named(parent, name)) == identity(self.fstat(fd)), 'identity_changed')
        if not recovery and '' in self.source:
            self.compare(self.source[''], self.fstat(self.source_root), 'source_held', source=True)

    def chain(self, records, root, name):
        """Borrow the anchor; only nonroot components belong to this chain."""
        frames = []; current = root; prefix = ''
        try:
            if '' in records: self.compare(records[''], self.fstat(root), 'ancestor', source=records is self.source)
            for component in name.split('/') if name else ():
                parent = current; prefix = component if not prefix else prefix + '/' + component
                record = records[prefix]
                current = self.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                frame = {'fd': current, 'parent': parent, 'leaf': component, 'record': record}
                frames.append(frame)
                self.compare(record, self.fstat(current), 'ancestor', source=records is self.source)
                self.compare(record, self.named(parent, component), 'ancestor_named', source=records is self.source)
            return current, frames
        except BaseException:
            self.release([frame['fd'] for frame in frames]); raise

    def row_matches(self, info, row):
        need((info.st_dev, info.st_ino) == tuple(row['device_inode']) and stat.S_IMODE(info.st_mode) == row['mode']
             and info.st_uid == row['uid'] and info.st_gid == row['gid'] and info.st_nlink == row['link_count']
             and info.st_flags == row['flags'] and info.st_mtime_ns == row['mtime_ns']
             and info.st_ctime_ns == row['ctime_ns'], 'identity_changed')
        need((stat.S_ISDIR(info.st_mode) if row['kind'] == 'directory' else
              stat.S_ISREG(info.st_mode) if row['kind'] == 'file' else stat.S_ISLNK(info.st_mode)), 'identity_changed')

    def capture(self, root, snapshot, records):
        self.note_admission('schema')
        maximum, logical, file_size = profile_limits(self.profile)
        need(snapshot.get('unavailable_fields') == [] and 0 < len(snapshot['entries']) <= maximum)
        if self.profile == 'docs': correct.docs_shape(snapshot['entries'])
        if self.budget is not None:
            self.budget.reserve(self.buffer_ticket, 4 * sum(len(os.fsencode(name)) for name in snapshot['entries']))
        total = 0
        for name, row in snapshot['entries'].items():
            need(type(row) is dict and COMMON_REQUIRED <= row.keys() and row.keys() <= ROW_FIELDS)
            need(row['kind'] in ('directory', 'file', 'symlink') and row['uid'] == os.geteuid())
            need(type(row['mode']) is int)
            if row['mode'] & 0o6000: need(owned_setid_leaf(snapshot, name, os.geteuid()))
            need(type(row['flags']) is int and row['flags'] >= 0 and not row['flags'] & ~ALLOWED_FLAGS)
            if row['kind'] == 'file':
                need(type(row.get('size')) is int and 0 <= row['size'] <= file_size); total += row['size']
        need(total <= logical)
        ids = {name: f'e{index + 1:04}' for index, name in enumerate(sorted(snapshot['entries']))}
        for name in sorted(snapshot['entries'], key=lambda item: (item.count('/') + bool(item), item)):
            self.note_admission('entry_identity'); parent_name, leaf = relative(name); row = snapshot['entries'][name]
            parent, frames = self.chain(records, root, parent_name) if name else (root, [])
            fd = None
            try:
                flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
                flags |= os.O_SYMLINK if row['kind'] == 'symlink' else os.O_NOFOLLOW
                if row['kind'] == 'directory': flags |= os.O_DIRECTORY
                fd = self.open(leaf, flags, dir_fd=parent) if name else root
                info = self.fstat(fd); self.row_matches(info, row)
                self.note_admission('acl'); self.ops.admit_acl(fd, row)
                self.note_admission('payload'); self.ops.payload(fd, row)
                self.note_admission('symlink')
                if row['kind'] == 'symlink': need(self.ops.readlink(parent, leaf) == row['symlink_bytes'])
                self.note_admission('entry_identity'); after = self.fstat(fd)
                need(signature(after) == signature(info), 'identity_changed')
                if name: need(signature(self.named(parent, leaf)) == signature(after), 'identity_changed')
                records[name] = {'info': after, 'parent_name': parent_name, 'leaf': leaf, 'name': name, 'entry_id': ids[name]}
            finally:
                self.release(([frame['fd'] for frame in frames] + [fd]) if name and fd is not None else [frame['fd'] for frame in frames])
        self.note_admission('source_closure'); self.verify_tree(records, root)

    def lease(self, records, root, name, *, keep_chain=True):
        record = records[name]; parent, frames = self.chain(records, root, record['parent_name']) if name else (root, [])
        fd = None
        try:
            mode = record['info'].st_mode
            flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | (os.O_SYMLINK if stat.S_ISLNK(mode) else os.O_NOFOLLOW)
            if stat.S_ISDIR(mode): flags |= os.O_DIRECTORY
            fd = self.open(record['leaf'], flags, dir_fd=parent) if name else root
            self.compare(record, self.fstat(fd), 'source_held' if records is self.source else 'destination_held', source=records is self.source)
            if name: self.compare(record, self.named(parent, record['leaf']), 'source_named' if records is self.source else 'destination_named', source=records is self.source)
            result = {'record': record, 'fd': fd, 'parent': parent, 'frames': frames, 'named': True, 'owns': bool(name)}
            if not keep_chain:
                self.release([frame['fd'] for frame in frames]); result.update(frames=[], parent=None)
            return result
        except BaseException:
            pending = [frame['fd'] for frame in frames if frame['fd'] in self.owned]
            if name and fd is not None and fd in self.owned: pending.append(fd)
            self.release(pending); raise

    def release_lease(self, lease):
        pending = [frame['fd'] for frame in lease['frames']]
        if lease['owns']: pending.append(lease['fd'])
        lease.update(frames=[], parent=None, owns=False)
        self.release(pending)

    def verify_tree(self, records, root):
        # Bounded complete inventory checkpoints, never called inside mutate().
        self.anchors()
        for name in records:
            lease = self.lease(records, root, name)
            self.release_lease(lease)

    def class_names(self, lease):
        return self.destination_classes.get(identity(lease['record']['info']), set())

    def check_lease(self, lease, *, source=False):
        record = lease['record']; info = self.fstat(lease['fd'])
        self.compare(record, info, 'source_held' if source else 'destination_held', source=source)
        if lease['named'] and record['name']:
            self.compare(record, self.named(lease['parent'], record['leaf']), 'source_named' if source else 'destination_named', source=source)
        for frame in lease['frames']:
            self.compare(frame['record'], self.fstat(frame['fd']), 'ancestor', source=source)
            self.compare(frame['record'], self.named(frame['parent'], frame['leaf']), 'ancestor_named', source=source)
        if not source and not stat.S_ISDIR(info.st_mode):
            need(info.st_nlink == len(self.class_names(lease)), 'destination_external_alias')

    def preflight(self, *, rebind=True):
        need(not self.uncertain, 'restoration_close_failed')
        need(not self.cancelled(), 'restoration_cancelled'); self.anchors()
        if rebind and self.sources:
            canonical = self.sources[-1]
            if len(self.sources) > 1 or canonical['parent'] is None:
                self.release([frame['fd'] for frame in canonical['frames']]); canonical.update(frames=[], parent=None)
                active_names = {lease['record']['name'] for lease in self.targets if lease['named']}
                names = set().union(*(self.class_names(lease) for lease in self.targets))
                for name in sorted(names - active_names):
                    record = self.destination[name]
                    parent, frames = self.chain(self.destination, self.destination_root, record['parent_name'])
                    try: self.compare(record, self.named(parent, record['leaf']), 'destination_named')
                    finally: self.release([frame['fd'] for frame in frames])
                for lease in self.sources:
                    record = lease['record']
                    parent, frames = self.chain(self.source, self.source_root, record['parent_name']) if record['name'] else (self.source_root, [])
                    lease.update(parent=parent, frames=frames)
                    try: self.check_lease(lease, source=True)
                    finally:
                        if lease is not canonical:
                            self.release([frame['fd'] for frame in frames]); lease.update(frames=[], parent=None)
        for lease in self.sources:
            if lease['parent'] is None:
                self.compare(lease['record'], self.fstat(lease['fd']), 'source_held', source=True)
            else: self.check_lease(lease, source=True)
        for lease in self.targets: self.check_lease(lease)
        need(not self.cancelled(), 'restoration_cancelled')

    def refresh(self, lease, allowed=(), *, parent_delta=None):
        record = lease['record']; before = record['info']; after = self.fstat(lease['fd'])
        self.note_difference(record, before, after, 'refresh', allowed, parent_delta)
        need(identity(before) == identity(after) and getattr(before, 'st_gen', None) == getattr(after, 'st_gen', None)
             and getattr(before, 'st_birthtime', None) == getattr(after, 'st_birthtime', None), 'identity_changed')
        for field in ('st_mode', 'st_uid', 'st_gid', 'st_size', 'st_nlink', 'st_flags', 'st_mtime_ns', 'st_ctime_ns'):
            if field == 'st_nlink' and parent_delta is not None:
                need(after.st_nlink == before.st_nlink + parent_delta, 'identity_changed')
            else: need(field in allowed or getattr(before, field) == getattr(after, field), 'identity_changed')
        # Only destination state advances, and only following this known own call.
        for name in self.destination_classes.get(identity(before), ()):
            self.destination[name]['info'] = after
        record['info'] = after

    def mutate(self, operation, call, changed):
        self.operation = operation; self.operation_phase = 'preflight'; self.preflight()
        self.summary['mutation_attempts'] += 1; self.operation_phase = 'native_call'; call()
        self.operation_phase = 'refresh'
        for lease, allowed, delta in changed: self.refresh(lease, allowed, parent_delta=delta)
        self.operation_phase = 'postflight'; self.preflight(rebind=False)

    def begin_class(self, names, canonical):
        self.sources = []
        for name in [*sorted(set(names) - {canonical}), canonical]:
            self.sources.append(self.lease(self.source, self.source_root, name, keep_chain=False))
        self.targets = [self.lease(self.destination, self.destination_root, canonical)]

    def end_class(self):
        need(not self.changed_flags and not self.changed_modes, 'restoration_refused')
        leases, self.targets, self.sources = [*self.targets, *self.sources], [], []
        for lease in reversed(leases): self.release_lease(lease)

    def parent_lease(self, target):
        record = self.destination[target['record']['parent_name']]
        return {'record': record, 'fd': target['parent'], 'parent': None, 'frames': target['frames'], 'named': False, 'owns': False}

    def alias(self, canonical, name):
        first = self.targets[0]
        victim = self.lease(self.destination, self.destination_root, name); self.targets.append(victim)
        parent = self.parent_lease(victim); original = stat.S_IMODE(parent['record']['info'].st_mode)
        if original & 0o300 != 0o300:
            self.changed_modes[parent['fd']] = (parent, original)
            self.mutate('parent_mode', lambda: self.ops.mode(parent['fd'], original | 0o300),
                        [(parent, {'st_mode', 'st_ctime_ns'}, None)])
        old_key = identity(victim['record']['info'])
        def remove():
            self.ops.unlink(victim['parent'], victim['record']['leaf'])
            self.destination_classes[old_key].remove(name)
            del self.destination[name]; victim['named'] = False
        self.mutate('alias_unlink', remove, [(victim, {'st_nlink', 'st_ctime_ns'}, -1),
                    (parent, {'st_size', 'st_mtime_ns', 'st_ctime_ns'}, -1)])
        try: self.named(victim['parent'], victim['record']['leaf'])
        except OSError as error: need(error.errno == errno.ENOENT, 'identity_changed')
        else: raise RestoreError('identity_changed')
        def link():
            self.ops.link(first['parent'], first['record']['leaf'], victim['parent'], victim['record']['leaf'])
            replacement = dict(first['record'], name=name, parent_name=victim['record']['parent_name'],
                               leaf=victim['record']['leaf'], entry_id=victim['record']['entry_id'])
            self.destination[name] = replacement
            self.destination_classes.setdefault(identity(first['record']['info']), set()).add(name)
        self.mutate('alias_link', link, [(first, {'st_nlink', 'st_ctime_ns'}, 1),
                    (parent, {'st_size', 'st_mtime_ns', 'st_ctime_ns'}, 1)])
        replacement = self.destination[name]
        self.compare(replacement, self.named(victim['parent'], replacement['leaf']), 'destination_named')
        self.preflight(rebind=False); self.summary['alias_replacements'] += 1
        if parent['fd'] in self.changed_modes:
            self.mutate('parent_mode_restore', lambda: self.ops.mode(parent['fd'], original),
                        [(parent, {'st_mode', 'st_ctime_ns'}, None)])
            del self.changed_modes[parent['fd']]
        self.targets.pop(); self.release_lease(victim)

    def metadata(self, name):
        target = self.targets[0]; source = self.sources[-1]; expected = self.expected['entries'][name]
        original = target['record']['info'].st_flags
        if original & BLOCKING:
            need(not stat.S_ISDIR(target['record']['info'].st_mode) and len(self.class_names(target)) == 1)
            self.changed_flags[target['fd']] = (target, original)
            self.mutate('flags_unblock', lambda: self.ops.flags(target['fd'], original & ~BLOCKING),
                        [(target, {'st_flags', 'st_ctime_ns'}, None)])
        if target['record']['info'].st_flags != expected['flags'] & ~BLOCKING:
            self.mutate('tracking', lambda: self.ops.flags(target['fd'], expected['flags'] & ~BLOCKING),
                        [(target, {'st_flags', 'st_ctime_ns'}, None)])
            self.summary['tracking_repairs'] += 1
        if name in self.derived['acl']:
            self.mutate('acl', lambda: self.ops.copy_acl(source['fd'], target['fd']), [(target, {'st_ctime_ns'}, None)])
            self.summary['acl_repairs'] += 1
        if name in self.derived['modes']:
            self.changed_modes[target['fd']] = (target, stat.S_IMODE(target['record']['info'].st_mode))
            def file_mode():
                self.ops.mode(target['fd'], expected['mode'])
                applied = self.fstat(target['fd'])
                need(stat.S_ISREG(applied.st_mode) and stat.S_IMODE(applied.st_mode) == expected['mode'],
                     'identity_changed')
            self.mutate('file_mode', file_mode, [(target, {'st_mode', 'st_ctime_ns'}, None)])
            del self.changed_modes[target['fd']]
            self.summary['mode_repairs'] += 1
        if stat.S_ISDIR(target['record']['info'].st_mode):
            if stat.S_IMODE(target['record']['info'].st_mode) != expected['mode']:
                self.mutate('directory_mode', lambda: self.ops.mode(target['fd'], expected['mode']),
                            [(target, {'st_mode', 'st_ctime_ns'}, None)])
            if target['record']['info'].st_mtime_ns != expected['mtime_ns']:
                def times():
                    before = self.fstat(target['fd']).st_atime_ns
                    self.ops.times(target['fd'], expected['mtime_ns'])
                    need(self.fstat(target['fd']).st_atime_ns == before, 'atime_changed')
                self.mutate('directory_time', times, [(target, {'st_mtime_ns', 'st_ctime_ns'}, None)])
                self.summary['directory_times'] += 1
        if target['record']['info'].st_flags != expected['flags']:
            self.mutate('flags_restore', lambda: self.ops.flags(target['fd'], expected['flags']),
                        [(target, {'st_flags', 'st_ctime_ns'}, None)])
        self.changed_flags.pop(target['fd'], None)

    def restore(self, destination_snapshot, output='output'):
        self.summary['status'] = 'incomplete'; self.operation = 'destination_capture'; self.operation_phase = 'preflight'
        try:
            self.derived = plan(self.expected, destination_snapshot, os.geteuid(), profile=self.profile)
            need('/' not in output and output not in ('', '.', '..'))
            self.destination_root = self.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent)
            self.bindings.append((self.parent, output, self.destination_root))
            self.capture(self.destination_root, destination_snapshot, self.destination)
            self.destination_classes = self.classes(self.destination)
            self.verify_tree(self.source, self.source_root)
            groups = {min(names): names for names in self.source_classes.values()}
            for canonical, names in sorted(groups.items()):
                aliases = [name for first, name in self.derived['aliases'] if first == canonical]
                if not aliases: continue
                self.begin_class(names, canonical)
                for name in aliases: self.alias(canonical, name)
                self.end_class()
            # Complete each admitted inode before releasing its recovery handles.
            for canonical, names in sorted(groups.items()):
                if not any(canonical in self.derived[field] for field in ('flags', 'acl', 'modes')):
                    continue
                self.begin_class(names, canonical); self.metadata(canonical); self.end_class()
            for name in self.derived['directories']:
                self.begin_class({name}, name); self.metadata(name); self.end_class()
            self.verify_tree(self.source, self.source_root)
            self.verify_tree(self.destination, self.destination_root)
            self.summary['status'] = 'restored_pending_final_verifiers'
        except BaseException as error:
            self.failure = error
            self.summary.setdefault('failure_context', {'operation': self.operation, 'phase': self.operation_phase,
                                                       'check': 'unclassified', 'entry_id': None, 'field': None})
            self.summary['error'] = str(error) if isinstance(error, RestoreError) else 'restoration_operation_failed'
            self.summary['status'] = 'incomplete'; self.recover()
        finally:
            # Error recovery never opens a fresh pathname or retries an alias edit.
            for lease in [*self.targets, *self.sources]:
                try: self.release_lease(lease)
                except BaseException:
                    self.summary['status'] = 'incomplete'
                    self.summary.setdefault('error', 'restoration_close_failed')
            self.targets = []; self.sources = []
        return dict(self.summary)

    def recovery_identity(self, lease):
        self.anchors(recovery=True)
        record = lease['record']; now = self.fstat(lease['fd'])
        need(identity(now) == identity(record['info']) and now.st_uid == os.geteuid()
             and now.st_gid == record['info'].st_gid and not now.st_flags & ~ALLOWED_FLAGS)
        for frame in lease['frames']:
            info = self.fstat(frame['fd'])
            need(identity(info) == identity(frame['record']['info']), 'identity_changed')
            need(identity(self.named(frame['parent'], frame['leaf'])) == identity(info), 'identity_changed')
        if lease['named'] and record['name']:
            need(identity(self.named(lease['parent'], record['leaf'])) == identity(now), 'identity_changed')
        if not stat.S_ISDIR(now.st_mode): need(now.st_nlink == len(self.class_names(lease)), 'destination_external_alias')
        return now

    def recover(self):
        # Discharge held temporary/failed-mode and blocker obligations only;
        # completed alias/ACL repairs are not a transactional tree rollback.
        self.summary['recovery'] = 'complete'
        for lease, original in reversed(list(self.changed_modes.values())):
            try:
                self.recovery_identity(lease); self.ops.mode(lease['fd'], original)
                restored = self.recovery_identity(lease)
                need(stat.S_IMODE(restored.st_mode) == original, 'identity_changed')
            except BaseException: self.summary['recovery'] = 'incomplete'
        for lease, original in reversed(list(self.changed_flags.values())):
            try:
                now = self.recovery_identity(lease)
                self.ops.flags(lease['fd'], (now.st_flags & ~BLOCKING) | (original & BLOCKING))
            except BaseException: self.summary['recovery'] = 'incomplete'
        self.changed_flags.clear(); self.changed_modes.clear()

    def close(self):
        try: self.release(list(self.owned))
        except BaseException: pass
        self.close_outcome['status'] = ('incomplete' if self.uncertain else 'complete' if self.close_outcome['attempts'] else 'not_needed')
        self.summary['close'] = dict(self.close_outcome)
        if self.uncertain:
            self.summary['status'] = 'incomplete'
            self.summary.setdefault('error', 'restoration_close_failed')
        if self.buffer_ticket is not None:
            self.budget.discard(self.buffer_ticket); self.buffer_ticket = None
        return not self.uncertain
