"""Integration checks for the installed native launcher and its Python helper."""
import os
from pathlib import Path
import subprocess
import sys
import sysconfig
import tempfile
import unittest

from stallionfs import __version__


@unittest.skipUnless(sys.platform == 'darwin', 'Native launcher requires macOS')
class InstalledCLI(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='stallionfs CLI ')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.launcher = Path(sysconfig.get_path('scripts')) / 'stallionfs'
        self.assertTrue(self.launcher.is_file(), f'Installed launcher missing: {self.launcher}')
        self.assertTrue(os.access(self.launcher, os.X_OK))
        with self.launcher.open('rb') as stream:
            self.assertIn(stream.read(4), (bytes.fromhex('cffaedfe'), bytes.fromhex('feedfacf'),
                                          bytes.fromhex('cafebabe'), bytes.fromhex('bebafeca'),
                                          bytes.fromhex('cafebabf'), bytes.fromhex('bfbafeca')))
        self.environment = {**os.environ, 'PATH': '/usr/bin:/bin',
                            'STALLIONFS_HOME': str(self.base / 'unused-store')}

    def command(self, *arguments, launcher=None, status=0):
        result = subprocess.run([str(launcher or self.launcher), *arguments], cwd=self.base,
                                env=self.environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, status, result.stderr)
        return result

    def test_native_file_operations_with_literal_leading_dashes(self):
        source = self.base / '--source'; source.mkdir(mode=0o700)
        (source / 'file').write_bytes(b'original')
        (source / 'dangling').symlink_to('missing')
        for jobs in ('-18446744073709551615', '0', '5'):
            with self.subTest(jobs=jobs):
                self.command('clone', '--jobs', jobs, '--', '--source', '--invalid', status=2)
                self.command('delete', '--jobs', jobs, '-r', '--', '--source', status=2)
                self.assertFalse((self.base / '--invalid').exists())
                self.assertEqual((source / 'file').read_bytes(), b'original')
                self.assertEqual(os.readlink(source / 'dangling'), 'missing')
        self.command('clone', '--', '--source', '--copy')
        copied = self.base / '--copy'
        first = copied / 'file'; second = self.base / '--other'
        second.write_bytes(b'other')
        self.assertEqual(first.read_bytes(), b'original')
        self.assertEqual(os.readlink(copied / 'dangling'), 'missing')
        first_inode, second_inode = first.stat().st_ino, second.stat().st_ino
        self.command('move', '--', '--copy/file', '--other', status=1)
        self.assertEqual((first.read_bytes(), second.read_bytes()), (b'original', b'other'))
        self.command('move', '--exchange', '--', '--copy/file', '--other')
        self.assertEqual((first.stat().st_ino, second.stat().st_ino), (second_inode, first_inode))
        self.assertEqual((first.read_bytes(), second.read_bytes()), (b'other', b'original'))
        self.command('move', '--', '--other', '--moved')
        self.assertFalse(second.exists())
        self.assertEqual((self.base / '--moved').stat().st_ino, first_inode)
        self.command('delete', '-r', '--', '--copy')
        self.command('delete', '--', '--moved')
        self.assertFalse(copied.exists())
        self.assertFalse((self.base / '--moved').exists())
        self.assertEqual((source / 'file').read_bytes(), b'original')
        volumes = [line.split('\t', 2) for line in self.command('volumes').stdout.splitlines()]
        self.assertTrue(any(len(row) == 3 and row[2] == '/' for row in volumes))
        self.assertTrue(all(len(row) == 3 and row[1] in ('read-only', 'writable') for row in volumes))
        self.assertFalse((self.base / 'unused-store').exists())

    def test_helper_dispatch_from_installed_and_symlinked_launcher(self):
        alias = self.base / 'linked launcher'
        alias.symlink_to(self.launcher)
        for launcher in (self.launcher, alias):
            with self.subTest(launcher=str(launcher)):
                self.assertEqual(self.command('--version', launcher=launcher).stdout.strip(), __version__)
                help_text = self.command('--help', launcher=launcher).stdout
                for name in ('clone', 'move', 'delete', 'volumes'):
                    self.assertIn(name, help_text)
                self.assertIn('--jobs', self.command('clone', '--help', launcher=launcher).stdout)
        self.assertFalse((self.base / 'unused-store').exists())


if __name__ == '__main__':
    unittest.main()
