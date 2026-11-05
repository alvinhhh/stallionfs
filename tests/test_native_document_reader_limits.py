"""Reader admission and allocation ordering with tiny in-memory filesystem fakes."""
from contextlib import ExitStack
from copy import deepcopy
import ctypes
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest import mock
import weakref

SPEC = importlib.util.spec_from_file_location('document_reader_under_test',
    Path(__file__).parent / 'perf/native_correctness.py')
reader = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(reader)


def info(kind=stat.S_IFREG, *, inode=2, size=3, device=7):
    return SimpleNamespace(st_mode=kind | 0o640, st_dev=device, st_ino=inode,
        st_uid=501, st_gid=20, st_size=size, st_mtime_ns=10, st_ctime_ns=11,
        st_atime_ns=12, st_flags=0, st_nlink=1, st_blocks=0, st_rdev=0,
        st_birthtime_ns=1, st_gen=1)


class Directory:
    def __init__(self, names): self.names = names
    def __enter__(self): return iter(SimpleNamespace(name=name) for name in self.names)
    def __exit__(self, *_): return False


class Stream:
    def __init__(self, data): self.data = data; self.offset = 0; self.closed = False; self.reads = []
    def __enter__(self): return self
    def __exit__(self, *_): self.closed = True; return False
    def fileno(self): return 91
    def readinto(self, target):
        self.reads.append(len(target))
        count = min(len(target), len(self.data) - self.offset)
        target[:count] = self.data[self.offset:self.offset + count]
        self.offset += count
        return count


class TinyReader:
    """The real reader sees stat/scandir/open interfaces, never real paths or FDs."""
    def __init__(self, entries=None, data=b'abc'):
        self.entries = entries or {b'/fixture': info(stat.S_IFDIR, inode=1, size=0),
                                   b'/fixture/file': info()}
        self.data = data; self.streams = []; self.allocations = []; self.stat_calls = []
        self.buffers = bytearray
        self.stack = ExitStack()

    def __enter__(self):
        patch = self.stack.enter_context
        def lstat(path):
            self.stat_calls.append(path)
            return deepcopy(self.entries[path])
        def scandir(path):
            prefix = path + b'/'
            return Directory(sorted(name[len(prefix):] for name in self.entries
                if name.startswith(prefix) and b'/' not in name[len(prefix):]))
        def opening(path, flags):
            self.assert_opened = path
            assert flags & (os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC) == (os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            self.current = path
            return 91
        def fdopen(fd, mode, buffering):
            assert (fd, mode, buffering) == (91, 'rb', 0)
            stream = Stream(self.data); self.streams.append(stream); return stream
        def allocate(size):
            self.allocations.append(size)
            # Preserve the requested-size observation without allocating MiB.
            return self.buffers(8)
        self.lstat = patch(mock.patch.object(reader.os, 'lstat', side_effect=lstat))
        self.scandir = patch(mock.patch.object(reader.os, 'scandir', side_effect=scandir))
        self.open = patch(mock.patch.object(reader.os, 'open', side_effect=opening))
        self.fdopen = patch(mock.patch.object(reader.os, 'fdopen', side_effect=fdopen))
        self.fstat = patch(mock.patch.object(reader.os, 'fstat', side_effect=lambda _fd: deepcopy(self.entries[self.current])))
        self.xattrs = patch(mock.patch.object(reader, '_xattrs', return_value={}))
        self.acl = patch(mock.patch.object(reader, '_acl', return_value={'text_hex': None, 'unavailable': None}))
        self.holes = patch(mock.patch.object(reader, '_holes', return_value={'ranges': [], 'unavailable': None}))
        self.allocate = patch(mock.patch.object(reader, 'bytearray', side_effect=allocate, create=True))
        return self

    def __exit__(self, *arguments): return self.stack.__exit__(*arguments)


class ReaderLimits(unittest.TestCase):
    def test_oversized_acl_objects_text_and_xattr_names_stop_before_copy_or_buffer_allocation(self):
        for fault in ('acl_object', 'acl_text', 'acl_error', 'xattr_names'):
            with self.subTest(fault=fault):
                budget = reader.SnapshotBudget(); ticket = budget.begin()
                library = SimpleNamespace(acl_get_link_np=mock.Mock(return_value=100),
                    acl_size=mock.Mock(return_value=65537 if fault == 'acl_object' else 16),
                    acl_free=mock.Mock(return_value=0), listxattr=mock.Mock(return_value=65537))
                def text(_acl, length):
                    ctypes.cast(length, ctypes.POINTER(ctypes.c_ssize_t))[0] = 65537
                    return 200
                library.acl_to_text = mock.Mock(side_effect=text)
                if fault == 'acl_error':
                    def failed_size(_acl):
                        ctypes.set_errno(errno.EACCES); return -1
                    def failed_free(_pointer):
                        ctypes.set_errno(errno.EBUSY); return -1
                    library.acl_size.side_effect = failed_size
                    library.acl_free.side_effect = failed_free
                with mock.patch.object(reader.sys, 'platform', 'darwin'), \
                        mock.patch.object(reader, '_darwin_metadata_api', return_value=library), \
                        mock.patch.object(reader.ctypes, 'create_string_buffer', side_effect=AssertionError('oversized buffer')) as allocate, \
                        mock.patch.object(reader.ctypes, 'string_at', side_effect=AssertionError('oversized copy/hex')) as copy:
                    try:
                        with self.assertRaises(OSError if fault == 'acl_error' else ValueError) as raised:
                            if fault == 'xattr_names': reader._xattrs(b'/fixture', budget=budget, ticket=ticket)
                            else: reader._acl(b'/fixture', budget=budget, ticket=ticket)
                        allocate.assert_not_called(); copy.assert_not_called()
                        if fault == 'acl_error': self.assertEqual(raised.exception.errno, errno.EACCES)
                        if fault == 'acl_object': library.acl_to_text.assert_not_called()
                        if fault.startswith('acl'):
                            self.assertEqual(library.acl_free.call_args_list,
                                ([mock.call(200)] if fault == 'acl_text' else []) + [mock.call(100)])
                    finally: budget.discard(ticket)
                self.assertEqual(budget.live, 0)

    def test_xattr_value_overflow_growth_and_aggregate_exhaustion_refuse_before_hex(self):
        real_buffer = ctypes.create_string_buffer
        for fault in ('value_limit', 'value_growth', 'aggregate'):
            with self.subTest(fault=fault):
                budget = reader.SnapshotBudget(); ticket = budget.begin(); allocated = []
                if fault == 'aggregate': budget.reserve(ticket, 8 * 1024 * 1024)
                class NoCopy:
                    @property
                    def raw(self): raise AssertionError('changed xattr converted before length check')
                def allocate(size):
                    allocated.append(size)
                    return real_buffer(size) if size == 2 else NoCopy()
                def names(_path, buffer, length, options):
                    self.assertEqual(options, 1)
                    if buffer is not None:
                        self.assertEqual(length, 2); ctypes.memmove(buffer, b'k\0', 2)
                    return 2
                def value(_path, name, buffer, length, position, options):
                    self.assertEqual((name, position, options), (b'k', 0, 1))
                    if buffer is None: return 1048577 if fault == 'value_limit' else 3
                    self.assertEqual(length, 3); return 4
                library = SimpleNamespace(listxattr=mock.Mock(side_effect=names),
                                          getxattr=mock.Mock(side_effect=value))
                with mock.patch.object(reader.sys, 'platform', 'darwin'), \
                        mock.patch.object(reader, '_darwin_metadata_api', return_value=library), \
                        mock.patch.object(reader.ctypes, 'create_string_buffer', side_effect=allocate):
                    try:
                        with self.assertRaises(RuntimeError if fault == 'value_growth' else ValueError):
                            reader._xattrs(b'/fixture', budget=budget, ticket=ticket)
                        self.assertEqual(allocated, [] if fault == 'aggregate' else [2, 3] if fault == 'value_growth' else [2])
                        if fault == 'aggregate': library.getxattr.assert_not_called()
                        else: self.assertEqual(library.getxattr.call_count, 2 if fault == 'value_growth' else 1)
                    finally: budget.discard(ticket)
                self.assertEqual(budget.live, 0)

        budget = reader.SnapshotBudget(); ticket = budget.begin(); values = []
        def allocate(size):
            if size == 3 and values:
                self.assertIsNone(values[-1](), 'previous xattr buffer remains live at next allocation')
            buffer = real_buffer(size)
            if size == 3: values.append(weakref.ref(buffer))
            return buffer
        def names(_path, buffer, length, options):
            self.assertEqual(options, 1)
            if buffer is not None:
                self.assertEqual(length, 4); ctypes.memmove(buffer, b'a\0b\0', 4)
            return 4
        def value(_path, name, buffer, length, position, options):
            self.assertIn(name, (b'a', b'b')); self.assertEqual((position, options), (0, 1))
            if buffer is not None:
                self.assertEqual(length, 3); ctypes.memmove(buffer, b'abc', 3)
            return 3
        library = SimpleNamespace(listxattr=names, getxattr=value)
        with mock.patch.object(reader.sys, 'platform', 'darwin'), \
                mock.patch.object(reader, '_darwin_metadata_api', return_value=library), \
                mock.patch.object(reader.ctypes, 'create_string_buffer', side_effect=allocate):
            try:
                self.assertEqual(reader._xattrs(b'/fixture', budget=budget, ticket=ticket),
                                 {'61': '616263', '62': '616263'})
                self.assertEqual(len(values), 2)
                self.assertTrue(all(value() is None for value in values))
            finally: budget.discard(ticket)
        self.assertEqual(budget.live, 0)

    def test_full_stat_inventory_refuses_size_count_depth_and_device_before_any_data_or_metadata_read(self):
        for fault in ('file', 'logical', 'count', 'depth', 'device', 'path'):
            with self.subTest(fault=fault):
                entries = {b'/fixture': info(stat.S_IFDIR, inode=1, size=0),
                           b'/fixture/a': info(inode=2, size=1), b'/fixture/b': info(inode=3, size=1)}
                if fault == 'file': entries[b'/fixture/b'].st_size = 9
                elif fault == 'logical': entries[b'/fixture/b'].st_size = 8
                elif fault == 'depth':
                    entries[b'/fixture/b'] = info(stat.S_IFDIR, inode=3, size=0)
                    entries[b'/fixture/b/c'] = info(stat.S_IFDIR, inode=4, size=0)
                    entries[b'/fixture/b/c/d'] = info(stat.S_IFDIR, inode=5, size=0)
                elif fault == 'device': entries[b'/fixture/b'].st_dev = 8
                elif fault == 'path': entries[b'/fixture/' + b'x' * 1025] = entries.pop(b'/fixture/b')
                budget = reader.SnapshotBudget()
                with TinyReader(entries) as fake, mock.patch.object(reader, 'DOCS_MAX_FILE', 8), \
                        mock.patch.object(reader, 'DOCS_LOGICAL_BYTES', 8), \
                        mock.patch.object(reader, 'DOCS_ENTRIES', 2 if fault == 'count' else 8), \
                        mock.patch.object(reader.hashlib, 'sha256', side_effect=AssertionError('hash before complete stat admission')):
                    with self.assertRaises(ValueError): reader.snapshot('/fixture', budget=budget)
                    fake.open.assert_not_called(); fake.xattrs.assert_not_called(); fake.acl.assert_not_called()
                    self.assertEqual(fake.allocations, [])
                self.assertEqual(budget.live, 0)

    def test_sparse_range_quota_refuses_before_another_range_or_seek_is_retained(self):
        budget = reader.SnapshotBudget(); ticket = budget.begin()
        with mock.patch.object(reader, 'DOCS_ENTRIES', 1), \
                mock.patch.object(reader.os, 'lseek', side_effect=[1, 2, 3, 4, 5]) as seek:
            try:
                with self.assertRaises(ValueError): reader._holes(91, 7, budget=budget, ticket=ticket)
                self.assertEqual(seek.call_count, 5)
            finally: budget.discard(ticket)
        self.assertEqual(budget.live, 0)

    def test_growth_shrink_and_post_read_identity_change_never_retain_a_partial_snapshot(self):
        for fault, data in (('growth', b'abcd'), ('growth_at_eof', b'abcd'),
                            ('shrink', b'ab'), ('identity', b'abc'),
                            ('directory', b'abc'), ('after_admission', b'abc')):
            with self.subTest(fault=fault):
                budget = reader.SnapshotBudget()
                with TinyReader(data=data) as fake:
                    if fault == 'growth_at_eof': fake.buffers = lambda _size: bytearray(3)
                    if fault == 'identity':
                        calls = []
                        def statting(_fd):
                            value = deepcopy(fake.entries[fake.current]); calls.append(1)
                            if len(calls) > 1: value.st_ctime_ns += 1
                            return value
                        fake.fstat.side_effect = statting
                    elif fault == 'directory':
                        scans, scanning = [], fake.scandir.side_effect
                        def growing(path):
                            if path == b'/fixture':
                                scans.append(1)
                                if len(scans) > 1: return Directory([b'file', b'late'])
                            return scanning(path)
                        fake.scandir.side_effect = growing
                    elif fault == 'after_admission':
                        original = fake.lstat.side_effect
                        def replaced(path):
                            value = original(path)
                            if fake.allocations and path == b'/fixture': value.st_ctime_ns += 1
                            return value
                        fake.lstat.side_effect = replaced
                    digest = mock.Mock(wraps=hashlib.sha256())
                    with mock.patch.object(reader.hashlib, 'sha256', return_value=digest):
                        with self.assertRaises(RuntimeError): reader.snapshot('/fixture', budget=budget)
                    if fault in ('growth', 'directory', 'after_admission'): digest.update.assert_not_called()
                    if fault in ('directory', 'after_admission'): fake.open.assert_not_called()
                    else:
                        self.assertTrue(fake.streams[0].closed)
                        self.assertEqual(fake.streams[0].reads,
                            {'growth': [4], 'growth_at_eof': [3, 1],
                             'shrink': [4, 2], 'identity': [4, 1]}[fault])
                self.assertEqual(budget.live, 0); self.assertEqual(budget.snapshots, {})

    def test_retained_snapshot_exhaustion_stops_allocation_and_release_restores_admission(self):
        budget = reader.SnapshotBudget(); retained = []
        with TinyReader() as fake:
            for _ in range(40):
                before = len(fake.allocations)
                try: value = reader.snapshot('/fixture', budget=budget)
                except ValueError:
                    self.assertEqual(len(fake.allocations), before)
                    break
                self.assertEqual(value['entries']['file']['sha256'], hashlib.sha256(b'abc').hexdigest())
                retained.append(value)
            else: self.fail('live retained-snapshot quota was never enforced')
            self.assertGreater(len(retained), 1)
            saved = deepcopy(retained[0])
            with self.assertRaises(KeyError): budget.release(deepcopy(retained[0]))
            self.assertEqual(retained[0], saved)
            released = retained.pop(); budget.release(released)
            replacement = reader.snapshot('/fixture', budget=budget); retained.append(replacement)
            with self.assertRaises(KeyError): budget.release(released)
            for value in retained: budget.release(value)
        self.assertEqual(budget.live, 0); self.assertEqual(budget.snapshots, {})

    def test_default_snapshot_bypasses_new_budget_and_keeps_special_metadata_observations(self):
        entries = {b'/fixture': info(stat.S_IFIFO, inode=3, size=0)}
        with TinyReader(entries) as fake, \
                mock.patch.object(reader, '_bounded_inventory', side_effect=AssertionError('opt-in admission on default path')):
            value = reader.snapshot('/fixture', allow_special=True)
            self.assertEqual(value['entries']['']['kind'], 'special')
            self.assertEqual(fake.xattrs.call_args, mock.call(b'/fixture'))
            self.assertEqual(fake.acl.call_args, mock.call(b'/fixture'))
            fake.open.assert_not_called()
        with mock.patch.object(reader, '_snapshot', side_effect=AssertionError('docs read without required budget')):
            with self.assertRaises(ValueError): reader.snapshot('/fixture', docs=True)


if __name__ == '__main__': unittest.main()
