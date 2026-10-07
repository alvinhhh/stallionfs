"""Native scanner checks; install with `python -m pip install -e .` first."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from stallionfs._scan import mounts, scan


def reference(root):
    result = dict(files=0, directories=0, symlinks=0, other=0, logical_bytes=0, skipped_mounts=0)
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            st = (Path(parent) / name).lstat()
            if stat.S_ISREG(st.st_mode):
                result['files'] += 1
                result['logical_bytes'] += st.st_size
            elif stat.S_ISDIR(st.st_mode):
                result['directories'] += 1
            elif stat.S_ISLNK(st.st_mode):
                result['symlinks'] += 1
            else:
                result['other'] += 1
    return result


class Scan(unittest.TestCase):
    def test_mount_records_have_absolute_paths_and_typed_flags(self):
        records = mounts()
        self.assertIn('/', [record['path'] for record in records])
        for record in records:
            self.assertTrue(isinstance(record['path'], str) and os.path.isabs(record['path']))
            self.assertIsInstance(record['device'], str)
            self.assertIsInstance(record['filesystem'], str)
            self.assertIsInstance(record['readonly'], bool)
            self.assertIsInstance(record['ignore_ownership'], bool)
            self.assertIsInstance(record['owner'], int)
            self.assertGreaterEqual(record['owner'], 0)

    def test_bulk_matches_reference_and_parallel_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / 'empty'
            for i in range(40):
                nested.mkdir()
                nested = nested / str(i)
            for i in range(2200):  # More than one native buffer of directory entries.
                (root / f'file-{i}').write_bytes(b'x' * (i % 1024))
            (root / 'space \n café 🐎').write_bytes(b'hello')
            with (root / 'sparse').open('wb') as stream:
                stream.truncate(1 << 30)
            os.link(root / 'sparse', root / 'hard-link')
            (root / 'outside').symlink_to('/')
            (root / 'directory-link').symlink_to('empty', target_is_directory=True)
            (root / 'dangling').symlink_to('absent')
            os.mkfifo(root / 'pipe')
            expected = reference(root)
            self.assertEqual(scan(root), expected)
            self.assertEqual(scan(root, bulk=False), expected)
            with ThreadPoolExecutor(max_workers=4) as pool:
                self.assertEqual(list(pool.map(scan, [root] * 8)), [expected] * 8)
            self.assertEqual(reference(root), expected)

    def test_errors_and_no_storage_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'file').touch()
            (root / 'link').symlink_to(root, target_is_directory=True)
            for target in ('absent', 'file', 'link'):
                with self.assertRaises(OSError):
                    scan(root / target)
            for bulk in (False, True):
                for suffix in ('', '/', '///'):
                    with self.subTest(bulk=bulk, suffix=suffix):
                        with self.assertRaises(OSError): scan(str(root / 'link') + suffix, bulk=bulk)
                        self.assertEqual(scan(str(root) + suffix, bulk=bulk), reference(root))
            with self.assertRaises(ValueError):
                scan(str(root) + '\0suffix')
            denied = root / 'denied'
            denied.mkdir()
            denied.chmod(0)
            try:
                with self.assertRaises(PermissionError):
                    scan(root)
            finally:
                denied.chmod(0o700)
            store = root / 'must-not-exist'
            process = subprocess.run([sys.executable, '-m', 'stallionfs', '--root', str(store),
                                      '--json', 'scan', str(root)], capture_output=True, text=True)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(json.loads(process.stdout), reference(root))
            self.assertFalse(store.exists())

    def test_native_cancellation_close_errors_and_no_partial_cli_totals(self):
        tests = Path(__file__).resolve().parent
        source = tests.parent / 'stallionfs'
        with tempfile.TemporaryDirectory(prefix='stallionfs-scan-faults-') as temporary:
            base = Path(temporary).resolve()
            object_file, driver, launcher = base / 'walk.o', base / 'faults', base / 'stallionfs'
            common = ['cc', '-O2', '-Wall', '-Wextra', '-Werror', '-I', str(source)]
            replacements = ('open', 'fstat', 'close', 'closedir', 'getattrlistbulk')
            subprocess.run([*common, *(f'-D{name}=stallion_test_{name}' for name in replacements),
                            '-c', str(source / '_walk.c'), '-o', str(object_file)], check=True, timeout=30)
            subprocess.run([*common, str(tests / 'native_scan_faults.c'), str(object_file), '-o', str(driver)],
                           check=True, timeout=30)
            subprocess.run([str(driver), str(base)], check=True, timeout=15)
            subprocess.run([*common, '-DSTALLION_TEST_CLI', str(tests / 'native_scan_faults.c'),
                            str(source / '_main.c'), str(source / '_tree.c'), str(object_file),
                            '-o', str(launcher)], check=True, timeout=30)
            fixture = base / 'fixture'; fixture.mkdir(); (fixture / 'file').write_bytes(b'counted before signal')
            for options in ([], ['--json']):
                interrupted = subprocess.run([str(launcher), *options, 'scan', str(fixture)],
                                             capture_output=True, text=True, timeout=15)
                self.assertEqual(interrupted.returncode, 130, interrupted.stderr)
                self.assertEqual(interrupted.stdout, '')
                self.assertTrue(interrupted.stderr)


if __name__ == '__main__':
    unittest.main()
