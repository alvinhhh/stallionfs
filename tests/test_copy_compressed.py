"""Real Darwin compression preservation through both native copy strategies.

Reads may update atime. The observer never writes or restores source metadata.
Auto conservatively materializes flagged files; this test does not prove cloning.
"""
from contextlib import ExitStack
import ctypes
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import struct
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import unittest


MACOS_13 = sys.platform == 'darwin' and int(platform.mac_ver()[0].split('.')[0]) >= 13
LIMIT = 1024 * 1024
UF_COMPRESSED = 0x20
DECMPFS = b'com.apple.decmpfs'
RESOURCE_FORK = b'com.apple.ResourceFork'
TEST_XATTR = b'com.stallionfs.test.compressed-copy'
TEST_VALUE = b'ordinary metadata'
NAMES = ('nested/inline.bin', 'nested/resource.bin')
TREE = ('.', 'nested', *NAMES)


def metadata(info):
    # Atime is excluded before the first observation; no restoration is attempted.
    result = {key: getattr(info, 'st_' + key) for key in
              ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'flags',
               'blocks', 'mtime_ns', 'ctime_ns')}
    if hasattr(info, 'st_birthtime_ns'):
        result['birthtime_ns'] = info.st_birthtime_ns
    else:
        result['birthtime'] = info.st_birthtime
    if hasattr(info, 'st_gen'):
        result['generation'] = info.st_gen
    return result


class DescriptorObserver:
    """Bounded, read-only Darwin descriptor APIs, including hidden compression xattrs."""

    def __init__(self):
        lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        self.listxattr, self.getxattr = lib.flistxattr, lib.fgetxattr
        self.listxattr.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        self.getxattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p,
                                 ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
        self.listxattr.restype = self.getxattr.restype = ctypes.c_ssize_t
        self.acl_get, self.acl_init = lib.acl_get_fd_np, lib.acl_init
        self.acl_valid, self.acl_size = lib.acl_valid, lib.acl_size
        self.acl_copy, self.acl_free = lib.acl_copy_ext, lib.acl_free
        self.acl_get_entry = lib.acl_get_entry
        self.acl_get.argtypes, self.acl_get.restype = [ctypes.c_int, ctypes.c_int], ctypes.c_void_p
        self.acl_init.argtypes, self.acl_init.restype = [ctypes.c_int], ctypes.c_void_p
        self.acl_valid.argtypes, self.acl_valid.restype = [ctypes.c_void_p], ctypes.c_int
        self.acl_size.argtypes, self.acl_size.restype = [ctypes.c_void_p], ctypes.c_ssize_t
        self.acl_copy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ssize_t]
        self.acl_copy.restype = ctypes.c_ssize_t
        self.acl_free.argtypes, self.acl_free.restype = [ctypes.c_void_p], ctypes.c_int
        self.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
        self.acl_get_entry.restype = ctypes.c_int

    @staticmethod
    def checked(value, maximum):
        if value < 0:
            code = ctypes.get_errno() or errno.EIO
            raise OSError(code, os.strerror(code))
        if value > maximum:
            raise AssertionError('Descriptor observation exceeds fixture bound')
        return value

    def attributes(self, fd, options):
        size = self.checked(self.listxattr(fd, None, 0, options), LIMIT)
        buffer = ctypes.create_string_buffer(max(1, size))
        used = self.checked(self.listxattr(fd, buffer, size, options), LIMIT)
        raw = buffer.raw[:used]
        if used != size or (raw and not raw.endswith(b'\0')):
            raise AssertionError('Xattr listing changed or is malformed')
        names = raw[:-1].split(b'\0') if raw else []
        if any(not name for name in names) or len(names) != len(set(names)):
            raise AssertionError('Duplicate or empty xattr name')
        result, remaining = {}, LIMIT - used
        for name in sorted(names):
            size = self.checked(self.getxattr(fd, name, None, 0, 0, options), remaining)
            buffer = ctypes.create_string_buffer(max(1, size))
            actual = self.checked(self.getxattr(fd, name, buffer, size, 0, options), remaining)
            if actual != size:
                raise AssertionError('Xattr value length changed')
            result[name] = buffer.raw[:actual]
            remaining -= actual
        return result

    def acl(self, fd, require_entry=False):
        ctypes.set_errno(0)
        acl = self.acl_get(fd, 0x100)  # Darwin ACL_TYPE_EXTENDED.
        if not acl:
            code = ctypes.get_errno()
            if code != errno.ENOENT:
                raise OSError(code or errno.EIO, 'Cannot read fixture ACL')
            acl = self.acl_init(0)
            if not acl:
                raise OSError(ctypes.get_errno() or errno.EIO, 'Cannot create empty ACL representation')
        try:
            self.checked(self.acl_valid(acl), 0)
            if require_entry:
                entry = ctypes.c_void_p()
                ctypes.set_errno(0)
                if self.acl_get_entry(acl, 0, ctypes.byref(entry)):  # Darwin ACL_FIRST_ENTRY.
                    code = ctypes.get_errno() or errno.EIO
                    if code == errno.EINVAL:  # End of a validated Darwin ACL.
                        raise AssertionError('Seeded fixture ACL has no entries')
                    raise OSError(code, 'Cannot read first fixture ACL entry')
                if not entry.value:
                    raise AssertionError('Seeded fixture ACL entry is missing')
            size = self.checked(self.acl_size(acl), 65536)
            if not size:
                raise AssertionError('Empty ACL external representation')
            buffer = ctypes.create_string_buffer(size)
            used = self.checked(self.acl_copy(buffer, acl, size), size)
            if used != size:
                raise AssertionError('ACL external representation changed size')
            # Preserve ACE order and ACL/inheritance flags; never sort or normalize entries.
            return buffer.raw[:used]
        finally:
            self.checked(self.acl_free(acl), 0)

    @staticmethod
    def logical(fd, size):
        if not 0 <= size <= LIMIT:
            raise AssertionError('Logical size exceeds fixture bound')
        parts, offset = [], 0
        while offset < size:
            part = os.pread(fd, min(65536, size - offset), offset)
            if not part:
                raise AssertionError('Unexpected logical EOF')
            parts.append(part)
            offset += len(part)
        if os.pread(fd, 1, offset):
            raise AssertionError('Logical bytes exceed declared size')
        return b''.join(parts)

    @staticmethod
    def sparse(fd, size):
        result, offset = [], 0
        while offset < size:
            if len(result) >= 1024:
                raise AssertionError('Sparse range count exceeds fixture bound')
            try:
                data = os.lseek(fd, offset, os.SEEK_DATA)
            except OSError as error:
                if error.errno == errno.ENXIO:
                    break
                raise
            hole = os.lseek(fd, data, os.SEEK_HOLE)
            if not offset <= data < hole <= size:
                raise AssertionError('Invalid sparse data range')
            result.append((data, hole))
            offset = hole
        return result

    def snapshot(self, root, tree=True, require_acl_entry=False):
        result, handles = {}, {}
        names = TREE if tree else ('.',)
        with ExitStack() as cleanup:
            for name in names:
                path = root if name == '.' else root / name
                before = path.lstat()
                directory = tree and name in ('.', 'nested')
                expected = stat.S_ISDIR if directory else stat.S_ISREG
                if not expected(before.st_mode) or before.st_uid != os.geteuid():
                    raise AssertionError(f'Unexpected fixture type or owner: {name}')
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                fd = os.open(path, flags | (os.O_DIRECTORY if directory else 0))
                cleanup.callback(os.close, fd)
                if metadata(before) != metadata(os.fstat(fd)):
                    raise AssertionError(f'Fixture changed before opening: {name}')
                handles[name] = (path, fd, metadata(before), directory)
            for name, (path, fd, before, directory) in handles.items():
                row = {'metadata': before, 'acl': self.acl(fd, require_entry=require_acl_entry),
                       'ordinary': self.attributes(fd, 0), 'raw': self.attributes(fd, 0x20)}
                if directory:
                    members = sorted(os.listdir(fd))
                    expected = ['nested'] if name == '.' else ['inline.bin', 'resource.bin']
                    if members != expected:
                        raise AssertionError(f'Unexpected directory membership: {name}: {members!r}')
                    row['members'] = members
                else:
                    if before['nlink'] != 1:
                        raise AssertionError(f'Unexpected fixture hardlink: {name}')
                    row['logical'] = self.logical(fd, before['size'])
                    row['sparse'] = self.sparse(fd, before['size'])
                result[name] = row
            # Recheck every bound descriptor and path after all verification reads.
            for name, (path, fd, before, directory) in handles.items():
                if not before == metadata(os.fstat(fd)) == metadata(path.lstat()):
                    raise AssertionError(f'Fixture metadata changed during observation: {name}')
                if directory and sorted(os.listdir(fd)) != result[name]['members']:
                    raise AssertionError(f'Directory membership changed during observation: {name}')
        return result


@unittest.skipUnless(MACOS_13, 'Compressed-file copy requires macOS 13 or newer')
class CompressedCopy(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='stallionfs-compressed-copy-')).resolve()
        info = self.base.lstat()
        self.identity = (info.st_dev, info.st_ino, info.st_uid)
        self.assertEqual(info.st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
        self.observer = DescriptorObserver()

    def tearDown(self):
        result = self._outcome.result
        if any(case is self or getattr(case, 'test_case', None) is self
               for case, _ in (*result.failures, *result.errors)):
            print(f'Failed compressed-copy test; retaining {self.base}', file=sys.stderr)
            return
        info = self.base.lstat()
        if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino, info.st_uid) != self.identity:
            raise RuntimeError(f'Fixture identity changed; retaining {self.base}')
        shutil.rmtree(self.base)

    def fixture(self):
        tar = Path('/usr/bin/bsdtar')
        if not tar.is_file():
            self.skipTest('/usr/bin/bsdtar is unavailable; cannot create real compressed files')
        source = self.base / 'source'
        source.mkdir(mode=0o700)
        (source / 'nested').mkdir(mode=0o750)
        block = b''.join(hashlib.sha256(i.to_bytes(4, 'little')).digest() for i in range(256))
        payloads = (b'A' * 32768, block * 128)
        archive = self.base / 'fixture.tar'
        with archive.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as bundle:
                for name, payload in zip(NAMES, payloads):
                    entry = tarfile.TarInfo(name)
                    entry.size, entry.mode = len(payload), 0o640
                    entry.uid, entry.gid, entry.mtime = os.geteuid(), os.getegid(), 1_700_000_000
                    bundle.addfile(entry, io.BytesIO(payload))
        child = subprocess.run([str(tar), '-x', '--hfsCompression', '-f', str(archive),
                                '-C', str(source), *NAMES], capture_output=True, timeout=30)
        diagnostic = child.stderr.decode('utf-8', 'replace')
        if (child.returncode and 'hfscompression' in diagnostic.lower()
                and any(message in diagnostic.lower() for message in
                        ('unknown option', 'unrecognized option', 'unsupported option'))):
            self.skipTest(f'bsdtar does not support --hfsCompression: {diagnostic.strip()}')
        self.assertEqual(child.returncode, 0, diagnostic)
        self.assertEqual(child.stderr, b'', diagnostic)
        self.assertEqual(child.stdout, b'')
        observed = self.observer.snapshot(source)
        unavailable = []
        for name, payload, encoding in zip(NAMES, payloads, (3, 4)):
            row = observed[name]
            self.assertEqual(row['logical'], payload, name)
            flags = row['metadata']['flags']
            header = row['raw'].get(DECMPFS)
            if not flags & UF_COMPRESSED:
                self.assertIsNone(header, f'{name}: decmpfs exists without UF_COMPRESSED')
                self.assertNotIn(RESOURCE_FORK, row['raw'],
                                 f'{name}: unexpected resource fork without UF_COMPRESSED')
                unavailable.append(f'{name}: UF_COMPRESSED absent (flags={flags:#x})')
                continue
            self.assertIsNotNone(header, f'{name}: missing decmpfs header')
            self.assertGreaterEqual(len(header), 16, name)
            magic, actual, size = struct.unpack('<IIQ', header[:16])
            self.assertEqual(magic, 0x636d7066, name)
            self.assertEqual(size, len(payload), name)
            self.assertIn(actual, (3, 4), f'{name}: unclassified compression representation')
            if actual == 3:
                self.assertGreater(len(header), 16, name)
                self.assertNotEqual(header[16], 0xff, f'{name}: uncompressed inline payload')
            if actual == 4:
                self.assertTrue(row['raw'].get(RESOURCE_FORK), f'{name}: missing resource fork')
            if actual != encoding:
                unavailable.append(f'{name}: flags={flags:#x}, decmpfs={(magic, actual, size)!r}; '
                                   f'expected type {encoding}')
        if unavailable:
            self.skipTest('bsdtar compression fixture unavailable: ' + '; '.join(unavailable))
        return source

    def enrich(self, paths):
        # Fixture setup only. No mutating API is available through DescriptorObserver.
        lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        setting = lib.fsetxattr
        setting.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p,
                            ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
        setting.restype = ctypes.c_int
        for path in paths:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                if setting(fd, TEST_XATTR, TEST_VALUE, len(TEST_VALUE), 0, 0):
                    code = ctypes.get_errno() or errno.EIO
                    raise OSError(code, 'Cannot seed ordinary fixture xattr')
            finally:
                os.close(fd)
        child = subprocess.run(['/bin/chmod', '+a', 'everyone allow readattr,readextattr',
                                *(str(path) for path in paths)], capture_output=True, timeout=15)
        self.assertEqual(child.returncode, 0, child.stderr)
        for path in paths:
            os.utime(path, ns=(1_600_000_000_000_000_000, 1_700_000_000_123_456_789))

    def assert_destination(self, before, destination):
        observed = self.observer.snapshot(destination)
        self.assertEqual(set(before), set(observed))
        required = ('mode', 'uid', 'gid', 'mtime_ns', 'flags')
        for name, original in before.items():
            copied = observed[name]
            for field in required:
                self.assertEqual(original['metadata'][field], copied['metadata'][field], (name, field))
            if 'logical' in original:
                self.assertEqual(original['metadata']['size'], copied['metadata']['size'], name)
            for field in ('logical', 'sparse', 'members', 'acl', 'ordinary', 'raw'):
                self.assertEqual(original.get(field), copied.get(field), (name, field))
        source_ids = {(row['metadata']['dev'], row['metadata']['ino']) for row in before.values()}
        copied_ids = [(row['metadata']['dev'], row['metadata']['ino']) for row in observed.values()]
        self.assertEqual(len(set(copied_ids)), len(copied_ids))
        self.assertFalse(source_ids.intersection(copied_ids))
        return set(copied_ids)

    def copy_once(self, launcher, strategy, source, before, sentinel, sentinel_before):
        destination = self.base / strategy
        command = [str(launcher), '--json', 'copy', '--strategy', strategy, '--jobs', '1',
                   '--', str(source), str(destination)]
        self.assertFalse(os.path.lexists(destination))
        self.assertEqual(sentinel_before, self.observer.snapshot(sentinel, tree=False))
        # This final observation checks for setup/verification drift before the copy call.
        self.assertEqual(before, self.observer.snapshot(source))
        child = subprocess.run(command, capture_output=True, text=True, timeout=30,
                               env={**os.environ, 'PATH': '/usr/bin:/bin'})
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(child.stderr, '')
        expected = {'source': str(source), 'destination': str(destination)}
        if strategy == 'auto':
            expected['strategy'] = 'auto'
        self.assertEqual(json.loads(child.stdout), expected)
        identities = self.assert_destination(before, destination)
        self.assertEqual(before, self.observer.snapshot(source))
        self.assertEqual(sentinel_before, self.observer.snapshot(sentinel, tree=False))
        return identities

    def test_nested_inline_and_resource_fork_preserved_by_both_strategies(self):
        launcher = Path(sysconfig.get_path('scripts')) / 'sfs'
        self.assertTrue(launcher.is_file(), f'Install the candidate native launcher before this test: {launcher}')
        source = self.fixture()
        sentinel = self.base / 'outside-sentinel'
        sentinel.write_bytes(b'outside source tree; unchanged by either copy')
        paths = [source, source / 'nested', *(source / name for name in NAMES), sentinel]
        self.enrich(paths)
        before = self.observer.snapshot(source, require_acl_entry=True)
        sentinel_before = self.observer.snapshot(sentinel, tree=False, require_acl_entry=True)
        for row in (*before.values(), *sentinel_before.values()):
            self.assertEqual(row['ordinary'].get(TEST_XATTR), TEST_VALUE)
        for name, encoding in zip(NAMES, (3, 4)):
            self.assertTrue(before[name]['metadata']['flags'] & UF_COMPRESSED)
            self.assertEqual(struct.unpack('<IIQ', before[name]['raw'][DECMPFS][:16]),
                             (0x636d7066, encoding, before[name]['metadata']['size']))
        materialized = self.copy_once(launcher, 'materialized', source, before, sentinel, sentinel_before)
        automatic = self.copy_once(launcher, 'auto', source, before, sentinel, sentinel_before)
        self.assertFalse(materialized.intersection(automatic))


if __name__ == '__main__':
    unittest.main()
