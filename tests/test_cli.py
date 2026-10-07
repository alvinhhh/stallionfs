"""Integration checks for the installed native launcher and its Python helper."""
import os
import json
from pathlib import Path
import shutil
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

    def command(self, *arguments, launcher=None, status=0, environment=None):
        result = subprocess.run([str(launcher or self.launcher), *arguments], cwd=self.base,
                                env=environment or self.environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, status, result.stderr)
        return result

    def native_only(self):
        directory = self.base / 'without helper'; directory.mkdir(mode=0o700)
        launcher = directory / 'stallionfs'
        shutil.copy2(self.launcher, launcher)
        self.assertFalse((directory / 'stallionfs-python').exists())
        return launcher

    def test_native_json_roundtrip_errors_and_no_helper(self):
        launcher = self.native_only()
        source = '--source café 🐎 "\\\t\n\x01'
        destination = '--copy café 🐎 "\\\t\n\x02'
        moved = '--moved café 🐎 "\\\t\n\x03'
        (self.base / source).write_bytes(b'original')
        store = self.base / 'unused-store'
        result = self.command('--root=' + str(store), '--json', 'clone', '--jobs=1', '--',
                              source, destination, launcher=launcher)
        self.assertEqual(json.loads(result.stdout), {'source': source, 'destination': destination})
        result = self.command('--json', '--root', str(store), 'move', '--', destination, moved,
                              launcher=launcher)
        self.assertEqual(json.loads(result.stdout), {'source': destination, 'destination': moved})
        self.assertEqual((self.base / moved).read_bytes(), b'original')
        result = self.command('--json', 'delete', '--', moved, launcher=launcher)
        self.assertEqual(json.loads(result.stdout), {'path': moved})
        self.assertFalse((self.base / moved).exists())
        volumes = json.loads(self.command('--json', 'volumes', launcher=launcher).stdout)
        self.assertTrue(any(row['path'] == '/' for row in volumes))
        for row in volumes:
            self.assertEqual(set(row), {'path', 'device', 'filesystem', 'readonly', 'ignore_ownership', 'owner'})
            self.assertIsInstance(row['readonly'], bool)
            self.assertIsInstance(row['ignore_ownership'], bool)
            self.assertIsInstance(row['owner'], int)
        bad_name = os.fsdecode(b'missing-\xff-\xc0\xaf-\xed\xa0\x80-\xf4\x90\x80\x80-\xf0\x9f-"\\\n')
        failed = self.command('--json', 'move', '--', bad_name, 'never-created',
                              launcher=launcher, status=1)
        self.assertEqual(failed.stdout, '')
        self.assertIn(os.fsencode(bad_name), os.fsencode(json.loads(failed.stderr)['error']))
        self.assertFalse((self.base / 'never-created').exists())
        invalid = self.command('--json', 'clone', '--jobs=5', '--', source, 'invalid',
                               launcher=launcher, status=2)
        self.assertEqual(invalid.stdout, '')
        self.assertFalse(invalid.stderr.lstrip().startswith('{'))
        self.assertFalse((self.base / 'invalid').exists())
        self.assertEqual((self.base / source).read_bytes(), b'original')
        self.assertFalse(store.exists())

    def test_native_scan_counts_failures_and_closed_output(self):
        from stallionfs._scan import scan
        launcher = self.native_only()
        source = self.base / '--scan café 🐎'; source.mkdir(mode=0o700)
        (source / 'empty').mkdir()
        (source / 'second').mkdir()
        (source / 'second' / 'nested').write_bytes(b'worker')
        (source / 'file').write_bytes(b'abc')
        with (source / 'sparse').open('wb') as stream: stream.truncate(1 << 20)
        os.link(source / 'file', source / 'hardlink')
        (source / 'dangling').symlink_to('absent')
        (source / 'outside').symlink_to('/')
        os.mkfifo(source / 'fifo')
        expected = scan(source)
        output = self.command('--root', str(self.base / 'unused-store'), '--json',
                              'scan', '--', source.name, launcher=launcher)
        self.assertEqual(json.loads(output.stdout), expected)
        for options in (('--jobs', '1'), ('--jobs=2',), ('--jobs', '4')):
            output = self.command('--json', 'scan', *options, '--', source.name, launcher=launcher)
            self.assertEqual(json.loads(output.stdout), expected)
        for jobs in ('0', '5', '-1', '4294967297', '-18446744073709551615'):
            output = self.command('--json', 'scan', '--jobs=' + jobs, '--', source.name,
                                  launcher=launcher, status=2)
            self.assertEqual(output.stdout, '')
        output = self.command('scan', '--', source.name, launcher=launcher)
        self.assertEqual(output.stdout, f"{expected['files']} files, {expected['directories']} directories, "
                         f"{expected['symlinks']} symlinks, {expected['other']} other entries\n"
                         f"{expected['logical_bytes']} logical bytes; {expected['skipped_mounts']} nested volumes skipped\n")
        denied = source / 'denied'; denied.mkdir(); denied.chmod(0)
        try:
            failed = self.command('--json', 'scan', '--', source.name, launcher=launcher, status=1)
            self.assertEqual(failed.stdout, '')
            self.assertIsInstance(json.loads(failed.stderr)['error'], str)
        finally:
            denied.chmod(0o700)
        for arguments in (('--json', 'scan', '--', source.name), ('--json', 'volumes')):
            read_fd, write_fd = os.pipe()
            os.close(read_fd)
            try:
                result = subprocess.run([str(launcher), *arguments], cwd=self.base,
                                        env=self.environment, stdout=write_fd, stderr=subprocess.PIPE, timeout=15)
            finally:
                os.close(write_fd)
            self.assertNotEqual(result.returncode, 0, 'Output failure was reported as success')
        self.assertFalse((self.base / 'unused-store').exists())

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
                self.assertIn('--jobs', self.command('scan', '--help', launcher=launcher).stdout)
        home = self.base / 'home'; home.mkdir()
        fixture = home / 'fixture'; fixture.mkdir(); (fixture / 'file').write_bytes(b'abc')
        result = self.command('--json', 'scan', '--jobs', '1', '~/fixture',
                              environment={**self.environment, 'HOME': str(home)})
        self.assertEqual(json.loads(result.stdout), dict(files=1, directories=0, symlinks=0,
                                                        other=0, logical_bytes=3, skipped_mounts=0))
        self.assertFalse((self.base / 'unused-store').exists())


if __name__ == '__main__':
    unittest.main()
