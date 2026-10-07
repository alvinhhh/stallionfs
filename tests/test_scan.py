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

from stallionfs._scan import scan


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


if __name__ == '__main__':
    unittest.main()
