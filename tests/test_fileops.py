"""Focused file-operation regression checks.

Optional: STALLIONFS_TEST_IMAGES=1 enables a disposable APFS mount test.
"""
from concurrent.futures import ThreadPoolExecutor
import errno
import fcntl
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import unittest

from stallionfs import _scan
from stallionfs.core import run


def descriptors():
    found = set()
    for fd in range(1024):
        try:
            fcntl.fcntl(fd, fcntl.F_GETFD)
            found.add(fd)
        except OSError:
            pass
    return found


class FileOperations(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='stallionfs-fileops-')).resolve()

    def tearDown(self):
        if any(Path(m['path']).is_relative_to(self.base) for m in _scan.mounts()):
            raise RuntimeError(f'Unexpected mounted volume; retaining {self.base}')
        for parent, directories, _ in os.walk(self.base, followlinks=False):
            os.chmod(parent, 0o700)
        shutil.rmtree(self.base)

    def fixture(self, name='source'):
        source = self.base / name
        source.mkdir()
        for i in range(8):
            directory = source / f'directory-{i}'
            directory.mkdir()
            for j in range(3):
                (directory / f'file-{j}').write_bytes(bytes([j]) * 73)
        (source / 'dangling').symlink_to('missing')
        (source / 'outside').symlink_to(self.base / 'external')
        (source / 'space \n café 🐎').write_bytes(b'names are bytes')
        return source

    def test_clone_files_links_exclusive_destination_and_isolation(self):
        source = self.fixture()
        external = self.base / 'external'
        external.write_bytes(b'outside stays untouched')
        original = source / 'directory-0/file-0'
        os.link(original, source / 'hardlink')
        for jobs in (1, 4):
            with self.subTest(jobs=jobs):
                target = self.base / f'copy-{jobs}'
                _scan.clone(source, target, jobs=jobs)
                self.assertEqual(_scan.scan(target), _scan.scan(source))
                self.assertEqual(os.readlink(target / 'outside'), str(external))
                self.assertEqual(os.readlink(target / 'dangling'), 'missing')
                with self.assertRaises(FileExistsError):
                    _scan.clone(source, target, jobs=jobs)
                (target / 'directory-0/file-0').write_bytes(b'changed')
                self.assertEqual(original.read_bytes(), b'\0' * 73)
                self.assertEqual((target / 'hardlink').read_bytes(), b'\0' * 73)
                self.assertEqual(external.read_bytes(), b'outside stays untouched')
        for source_name in ('directory-0/file-0', 'dangling'):
            target = self.base / ('single-' + Path(source_name).name)
            _scan.clone(source / source_name, target)
            if target.is_symlink(): self.assertEqual(os.readlink(target), 'missing')
            else: self.assertEqual(target.read_bytes(), original.read_bytes())
        with self.assertRaises(OSError):
            _scan.clone(source, source / 'recursive')
        self.assertFalse((source / 'recursive').exists())
        os.mkfifo(source / 'unsupported')
        with self.assertRaises(OSError) as raised:
            _scan.clone(source, self.base / 'special')
        self.assertEqual(raised.exception.errno, errno.ENOTSUP)

    def test_directory_clone_checks_parent_mode_and_acl(self):
        source = self.base / 'source'; source.mkdir()
        (source / 'file').write_bytes(b'original')
        parent = self.base / 'parent'; parent.mkdir(mode=0o700)
        user = pwd.getpwuid(os.getuid()).pw_name
        mutation = 'add_file,add_subdirectory,delete_child'
        cases = [('shared', 0o777, None, False),
                 ('sticky', 0o1777, None, True),
                 ('deny', 0o700, 'group:everyone deny delete_child', True),
                 ('current-user', 0o700, f'user:{user} allow {mutation}', True),
                 ('other-principal', 0o700, f'group:everyone allow {mutation}', False)]
        try:
            for name, mode, acl, allowed in cases:
                with self.subTest(parent=name):
                    run(['/bin/chmod', '-N', parent])
                    parent.chmod(mode)
                    if acl: run(['/bin/chmod', '+a', acl, parent])
                    target = parent / name
                    if allowed:
                        _scan.clone(source, target)
                        self.assertEqual((target / 'file').read_bytes(), b'original')
                    else:
                        with self.assertRaises(PermissionError): _scan.clone(source, target)
                        self.assertFalse(target.exists())
                    if name == 'shared':
                        _scan.clone(source / 'file', parent / 'leaf')
                        self.assertEqual((parent / 'leaf').read_bytes(), b'original')
        finally:
            run(['/bin/chmod', '-N', parent])
            parent.chmod(0o700)

    def test_remove_links_open_inodes_and_concurrent_calls(self):
        external = self.base / 'external'
        external.write_bytes(b'kept')
        roots = [self.fixture(f'source-{i}') for i in range(3)]
        os.link(external, roots[0] / 'hardlink')
        os.mkfifo(roots[0] / 'fifo')
        before = descriptors()
        with (roots[0] / 'directory-0/file-0').open('rb') as opened:
            with ThreadPoolExecutor(max_workers=3) as pool:
                list(pool.map(lambda path: _scan.delete(path, recursive=True), roots))
            self.assertEqual(opened.read(), b'\0' * 73)
            self.assertEqual(os.fstat(opened.fileno()).st_nlink, 0)
        self.assertEqual(descriptors(), before)
        self.assertTrue(all(not root.exists() for root in roots))
        self.assertEqual(external.read_bytes(), b'kept')
        self.assertEqual(external.stat().st_nlink, 1)
        alias = self.base / 'alias'
        alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(OSError): _scan.delete(str(alias) + '/', recursive=True)
        self.assertTrue(alias.is_symlink())
        _scan.delete(alias, recursive=True)
        self.assertFalse(alias.is_symlink())
        self.assertTrue(external.exists())
        for candidate in ('/', str(self.base) + '/.', str(self.base) + '/..'):
            with self.assertRaises(OSError): _scan.delete(candidate, recursive=True)
        with self.assertRaises(FileNotFoundError): _scan.delete(self.base / 'missing')
        _scan.delete(self.base / 'missing', missing_ok=True)
        with self.assertRaises(FileNotFoundError):
            _scan.delete(self.base / 'missing-parent/file', missing_ok=True)

    def test_move_no_clobber_replace_exchange_and_link_identity(self):
        a, b = self.base / 'a', self.base / 'b'
        a.write_bytes(b'a'); b.write_bytes(b'b')
        a_id, b_id = a.stat().st_ino, b.stat().st_ino
        with self.assertRaises(FileExistsError): _scan.move(a, b)
        self.assertEqual((a.read_bytes(), b.read_bytes()), (b'a', b'b'))
        _scan.move(a, b, exchange=True)
        self.assertEqual((a.stat().st_ino, b.stat().st_ino), (b_id, a_id))
        with self.assertRaises(ValueError): _scan.move(a, b, replace=True, exchange=True)
        _scan.move(a, b, replace=True)
        self.assertFalse(a.exists()); self.assertEqual(b.read_bytes(), b'b')
        alias = self.base / 'alias'; alias.symlink_to(b)
        moved = self.base / 'moved'
        _scan.move(alias, moved)
        self.assertTrue(moved.is_symlink()); self.assertEqual(b.read_bytes(), b'b')

    def test_errors_close_descriptors_and_invalid_jobs_do_not_mutate(self):
        source = self.fixture()
        denied = source / 'directory-0'
        denied.chmod(0)
        before = descriptors()
        try:
            for operation in (lambda p: _scan.delete(p, recursive=True), lambda p: _scan.clone(p, self.base / 'blocked')):
                with self.assertRaises(PermissionError): operation(source)
                self.assertEqual(descriptors(), before)
            with self.assertRaises(PermissionError): _scan.delete(source, recursive=True, missing_ok=True)
            self.assertEqual(descriptors(), before)
        finally:
            denied.chmod(0o700)
        def snapshot():
            return {str(path.relative_to(source)): (path.lstat().st_mode,
                    os.readlink(path) if path.is_symlink() else path.read_bytes() if path.is_file() else None)
                    for path in source.rglob('*')}
        expected = snapshot()
        for jobs in (0, 5, -1, 2**32 + 1, -(2**32) + 1, 2**64 + 1):
            for operation in (lambda: _scan.delete(source, recursive=True, jobs=jobs),
                              lambda: _scan.clone(source, self.base / 'invalid', jobs=jobs)):
                with self.subTest(jobs=jobs), self.assertRaises((ValueError, OverflowError)): operation()
                self.assertTrue(source.exists())
                self.assertEqual(snapshot(), expected)
                self.assertFalse((self.base / 'invalid').exists())

    def test_python_cli_commands_do_not_initialize_a_store(self):
        store = self.base / 'must-not-exist'
        def cli(*arguments):
            return subprocess.run([sys.executable, '-m', 'stallionfs', '--root', str(store), *map(str, arguments)],
                                  capture_output=True, text=True, timeout=15, cwd=self.base)
        source = self.base / 'file'; source.write_bytes(b'file')
        copy = self.base / 'copy'; moved = self.base / 'moved'
        for arguments in (('clone', source, copy), ('move', copy, moved), ('delete', moved), ('volumes',)):
            result = cli(*arguments)
            self.assertEqual(result.returncode, 0, result.stderr)
        (self.base / '--source').write_bytes(b'dash filename')
        result = cli('--json', 'clone', '--', '--source', '--destination')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'source': '--source', 'destination': '--destination'})
        self.assertEqual((self.base / '--destination').read_bytes(), b'dash filename')
        self.assertFalse(store.exists())
        self.assertEqual(source.read_bytes(), b'file')

    def test_native_swaps_enospc_no_fallback_cancellation_and_fd_cleanup(self):
        tests = Path(__file__).resolve().parent
        source = tests.parent / 'stallionfs'
        object_file, executable = self.base / 'tree.o', self.base / 'native-faults'
        common = [*shlex.split(os.environ.get('CC', 'cc')), '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                  '-pthread', '-I', str(source), *shlex.split(os.environ.get('CFLAGS', ''))]
        replacements = ['openat', 'fstat', 'fclonefileat', 'unlinkat', 'pthread_create', 'pthread_join']
        subprocess.run([*common, *(f'-D{name}=stallion_test_{name}' for name in replacements),
                        '-c', str(source / '_tree.c'), '-o', str(object_file)], check=True, timeout=30)
        subprocess.run([*common, str(tests / 'native_faults.c'), str(object_file), '-o', str(executable)],
                       check=True, timeout=30)
        subprocess.run([str(executable), str(self.base)], check=True, timeout=30)

    @unittest.skipUnless(os.environ.get('STALLIONFS_TEST_IMAGES') == '1', 'Enable disposable APFS mount check')
    def test_actual_mounted_subtree_refused_and_cross_volume_clone_move_fail(self):
        from stallionfs import images
        seed = self.fixture()
        (seed / 'outside').unlink()
        (seed / 'outside').symlink_to('directory-0/file-0')
        image = self.base / 'test.sparseimage'
        victim = self.base / 'victim'; victim.mkdir(mode=0o700)
        sentinel = victim / 'sentinel'; sentinel.write_bytes(b'kept')
        point = victim / 'mounted'
        images.build(seed, image, 1)
        try:
            repo = images.attach(image, point)
            expected = dict(files=1, directories=1, symlinks=0, other=0, logical_bytes=4, skipped_mounts=1)
            self.assertEqual(_scan.scan(victim), expected)
            self.assertEqual(_scan.scan(victim, bulk=False), expected)
            launcher = Path(sysconfig.get_path('scripts')) / 'stallionfs'
            scanned = subprocess.run([str(launcher), '--json', 'scan', str(victim)],
                                     capture_output=True, text=True, timeout=15)
            self.assertEqual(scanned.returncode, 0, scanned.stderr)
            self.assertEqual(json.loads(scanned.stdout), expected)
            for path in (victim, point):
                with self.assertRaises(OSError): _scan.delete(path, recursive=True)
            self.assertEqual(sentinel.read_bytes(), b'kept')
            with self.assertRaises(OSError) as raised:
                _scan.clone(victim, self.base / 'contains-mount')
            self.assertIn(raised.exception.errno, (errno.EXDEV, errno.EBUSY))
            target = self.base / 'cross-volume-copy'
            with self.assertRaises(OSError) as raised: _scan.clone(repo / 'directory-0/file-0', target)
            self.assertEqual(raised.exception.errno, errno.EXDEV)
            self.assertFalse(target.exists())
            with self.assertRaises(OSError) as raised: _scan.move(repo / 'directory-0/file-0', target)
            self.assertEqual(raised.exception.errno, errno.EXDEV)
            self.assertEqual((repo / 'directory-0/file-0').read_bytes(), b'\0' * 73)
        finally:
            state = images.mounted(image)
            if state is not None: images.detach(image, state['mountpoint'] or point)
            if images.mounted(image) is not None: raise RuntimeError(f'Retaining attached image {image}')


if __name__ == '__main__':
    unittest.main()
