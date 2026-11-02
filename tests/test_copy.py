"""Ordinary-copy contracts on small, owned disposable fixtures.

STALLIONFS_TEST_IMAGES=1 additionally enables actual cross-volume qualification.
"""
import errno
import fcntl
from functools import partial
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import stat
import struct
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from unittest import mock


UF_TRACKED = getattr(stat, 'UF_TRACKED', 0x00000040)
MACOS_13 = sys.platform == 'darwin' and int(platform.mac_ver()[0].split('.')[0]) >= 13


@unittest.skipUnless(MACOS_13, 'Ordinary copy requires macOS 13 or newer')
class OrdinaryCopy(unittest.TestCase):
    copy_strategy = None

    @classmethod
    def setUpClass(cls):
        from stallionfs import _scan, copy
        if __package__:
            from .test_fileops import compile_native_faults, descriptors
        else:
            from test_fileops import compile_native_faults, descriptors
        perf = str(Path(__file__).parent / 'perf')
        sys.path.insert(0, perf)
        cls.addClassCleanup(sys.path.remove, perf)
        import native_correctness
        import native_fixtures
        cls.public_copy = staticmethod(copy)
        cls.copy = staticmethod(copy if cls.copy_strategy is None else partial(copy, strategy=cls.copy_strategy))
        cls.compile_native_faults = staticmethod(compile_native_faults)
        cls.native = _scan
        cls.descriptors = staticmethod(descriptors)
        cls.checks = native_correctness
        cls.fixtures = native_fixtures

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='stallionfs-copy-')).resolve()
        info = self.base.stat()
        self.base_identity = (info.st_dev, info.st_ino, info.st_uid)
        self.image = None
        self.image_command_failed = False

    def tearDown(self):
        result = self._outcome.result
        if any(case is self or getattr(case, 'test_case', None) is self
               for case, _ in (*result.failures, *result.errors)):
            print(f'Failed copy test; retaining {self.base}', file=sys.stderr)
            return
        info = self.base.lstat()
        if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino, info.st_uid) != self.base_identity:
            raise RuntimeError(f'Fixture identity changed; retaining {self.base}')
        if self.image is not None:
            from stallionfs import images
            if self.image_command_failed or images.mounted(self.image) is not None:
                raise RuntimeError(f'Image attachment not known detached; retaining {self.base}')
        if any(Path(m['path']).is_relative_to(self.base) for m in self.native.mounts()):
            raise RuntimeError(f'Unexpected mounted volume; retaining {self.base}')
        for parent, _, _ in os.walk(self.base, followlinks=False):
            os.chmod(parent, 0o700)
        shutil.rmtree(self.base)

    def assert_preserved(self, before, destination):
        observed = self.checks.snapshot(destination)
        report = self.checks.compare(before, observed)
        self.assertTrue(report['strict_equal'], report)
        self.assertIs(report['sparse_preserved'], True, report)
        source_inodes = {tuple(row['device_inode']) for row in before['entries'].values()}
        self.assertFalse(source_inodes & {tuple(row['device_inode']) for row in observed['entries'].values()})
        return observed

    def eligible_child(self, source):
        child = source / 'eligible-auto'
        with child.open('xb') as stream:
            stream.write(b'x')
            stream.seek(8 * 1024 * 1024 - 1)
            stream.write(b'y')
            stream.flush()
            fcntl.fcntl(stream.fileno(), 99, struct.pack('=IIqq', 0, 0, 1024 * 1024, 6 * 1024 * 1024))
            os.fsync(stream.fileno())
        self.fixtures.enrich_metadata(child, receipt={})
        subprocess.run(['/bin/chmod', '-N', str(child)], check=True, capture_output=True, timeout=15)
        child.chmod(0o640)
        os.chflags(child, 0)
        entry = self.checks.snapshot(child)['entries']['']
        self.assertEqual(entry['uid'], os.geteuid())
        self.assertEqual(entry['mode'], 0o640)
        self.assertEqual(entry['flags'], 0)
        self.assertIsNone(entry['acl']['unavailable'])
        acl_text = bytes.fromhex(entry['acl'].get('text_hex') or '')
        self.assertTrue(all(line.startswith(b'!#') for line in acl_text.splitlines()), acl_text)
        self.assertTrue(all(entry['xattrs'].get(name.hex()) == value.hex()
                            for name, value in self.fixtures.METADATA_XATTRS.items()))
        self.assertLess(entry['allocated_bytes'], entry['size'])
        self.assertTrue(any(start <= 1024 * 1024 and end >= 7 * 1024 * 1024
                            for start, end in entry['holes']['ranges']))
        return child

    def test_root_file_preserves_enriched_metadata_and_source(self):
        source = self.base / 'source'
        source.write_bytes(bytes(range(256)) * 16)
        receipt = self.fixtures.enrich_metadata(source, receipt={})
        os.chflags(source, stat.UF_NODUMP)
        os.utime(source, ns=(1_600_000_000_000_000_000, 1_700_000_000_123_456_789))
        source.chmod(0o750)
        before = self.checks.snapshot(source)
        self.assertTrue(self.fixtures.verify_metadata_coverage(before, receipt)['populated'])
        self.assertEqual(before['entries']['']['mode'], 0o750)
        self.assertEqual(before['entries']['']['flags'], stat.UF_NODUMP)
        self.assertIs(self.public_copy, self.native.copy)
        destination = self.base / 'destination'
        self.assertIsNone(self.copy(source, destination))
        self.assert_preserved(before, destination)
        self.assertTrue(self.checks.verify_source(before, self.checks.snapshot(source))['unchanged'])
        destination.write_bytes(b'changed')
        self.assertEqual(source.read_bytes(), bytes(range(256)) * 16)

    def test_tracked_files_preserve_flags_for_each_mode_and_entrypoint(self):
        for flags in (0, UF_TRACKED):
            for mode in (0o600, 0o640, 0o644):
                source = self.base / f'source-{flags}-{mode:o}'
                source.mkdir(mode=0o750)
                file = source / 'data'
                file.write_bytes(bytes(range(256)) * 16)
                file.chmod(mode)
                os.chflags(file, flags)
                os.utime(file, ns=(1_600_000_000_000_000_000, 1_700_000_000_123_456_789))
                for kind, operand in (('file', file), ('tree', source)):
                    with self.subTest(flags=flags, mode=oct(mode), kind=kind):
                        before = self.checks.snapshot(operand)
                        destination = self.base / f'copy-{flags}-{mode:o}-{kind}'
                        self.copy(operand, destination, jobs=1)
                        self.assert_preserved(before, destination)
                        self.assertTrue(self.checks.verify_source(before, self.checks.snapshot(operand))['unchanged'])

    def test_tracked_tree_preserves_metadata_hardlinks_and_blocking_flags(self):
        source = self.base / 'source'
        source.mkdir(mode=0o750)
        nested = source / 'nested'
        nested.mkdir()
        file = nested / 'data'
        file.write_bytes(bytes(range(256)) * 16)
        os.link(file, nested / 'alias')
        outside = self.base / 'outside'
        outside.write_bytes(b'outside remains unchanged')
        link = nested / 'link'
        link.symlink_to(outside)
        receipt = self.fixtures.enrich_metadata(source, receipt={})
        for path in (source, nested, file, link):
            try:
                os.chflags(path, path.lstat().st_flags | UF_TRACKED, follow_symlinks=False)
            except OSError as error:
                self.skipTest(f'Tracked {"symlink" if path == link else "file/directory"} fixture unavailable: {error}')
        protected = []
        try:
            for name, flag in (('immutable', stat.UF_IMMUTABLE), ('append', stat.UF_APPEND)):
                path = nested / name
                path.write_bytes(b'protected content')
                os.chflags(path, UF_TRACKED | flag)
                protected.append(path)
            before = self.checks.snapshot(source)
            outside_before = self.checks.snapshot(outside)
            self.assertTrue(self.fixtures.verify_metadata_coverage(before, receipt)['populated'])
            for jobs in (1, 2, 4):
                with self.subTest(jobs=jobs):
                    destination = self.base / f'copy-{jobs}'
                    self.copy(source, destination, jobs=jobs)
                    protected.extend(destination / 'nested' / path.name for path in protected[:2])
                    self.assert_preserved(before, destination)
                    self.assertEqual((destination / 'nested/data').stat().st_ino,
                                     (destination / 'nested/alias').stat().st_ino)
                    self.assertEqual((destination / 'nested/data').stat().st_nlink, 2)
                    self.assertTrue(self.checks.verify_source(before, self.checks.snapshot(source))['unchanged'])
            self.assertTrue(self.checks.verify_source(outside_before, self.checks.snapshot(outside))['unchanged'])
        finally:
            for path in protected:
                if path.exists():
                    os.chflags(path, path.stat().st_flags & ~(stat.UF_IMMUTABLE | stat.UF_APPEND))

    def test_privileged_mode_bits_when_fixture_supported(self):
        source = self.base / 'source'
        source.write_bytes(b'original')
        os.chown(source, -1, os.getegid())
        self.assertEqual(source.stat().st_gid, os.getegid())
        source.chmod(0o6750)
        self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o6750)
        before = self.checks.snapshot(source)
        destination = self.base / 'destination'
        self.copy(source, destination)
        self.assert_preserved(before, destination)

    def test_root_file_parent_acl_guards_data_and_resource_fork_before_creation(self):
        source = self.base / 'private-source'
        source.write_bytes(b'private content')
        source.chmod(0o600)
        subprocess.run(['/usr/bin/xattr', '-w', 'com.apple.ResourceFork', 'private resource fork', str(source)],
                       check=True, capture_output=True, timeout=15)
        before = self.checks.snapshot(source)
        user = pwd.getpwuid(os.getuid()).pw_name
        cases = [('clean', None, True),
                 ('parent-read', 'everyone allow read,readextattr', True),
                 ('owner-inherit', f'user:{user} allow read,readextattr,file_inherit', True),
                 ('foreign-read-inherit', 'everyone allow read,file_inherit', False),
                 ('foreign-xattr-inherit', 'everyone allow readextattr,file_inherit', False)]
        for name, acl, allowed in cases:
            with self.subTest(parent=name):
                parent = self.base / name
                parent.mkdir(mode=0o755)
                if acl:
                    subprocess.run(['/bin/chmod', '+a', acl, str(parent)],
                                   check=True, capture_output=True, timeout=15)
                destination = parent / 'copy'
                if allowed:
                    self.copy(source, destination, jobs=1)
                    self.assert_preserved(before, destination)
                else:
                    with self.assertRaises(PermissionError):
                        self.copy(source, destination, jobs=1)
                    self.assertFalse(os.path.lexists(destination))
        self.assertTrue(self.checks.verify_source(before, self.checks.snapshot(source))['unchanged'])

    def test_root_symlink_copies_its_own_metadata_without_following(self):
        outside = self.base / 'outside'
        outside.write_bytes(b'outside stays untouched')
        outside_before = self.checks.snapshot(outside)
        for name, target in (('dangling', b'absent\n\xff'), ('external', os.fsencode(outside))):
            with self.subTest(link=name):
                source = self.base / name
                os.symlink(target, os.fsencode(source))
                subprocess.run(['/usr/bin/xattr', '-s', '-w', 'user.stallionfs-test', 'link metadata', str(source)],
                               check=True, capture_output=True, timeout=15)
                subprocess.run(['/bin/chmod', '-h', '+a', 'everyone allow read', str(source)],
                               check=True, capture_output=True, timeout=15)
                os.utime(source, ns=(1_600_000_000_000_000_000, 1_700_000_000_987_654_321), follow_symlinks=False)
                before = self.checks.snapshot(source)
                self.assertTrue(before['entries']['']['xattrs'])
                self.assertTrue(before['entries']['']['acl']['text_hex'])
                destination = self.base / (name + '-copy')
                self.copy(source, destination, jobs=1)
                self.assert_preserved(before, destination)
                self.assertEqual(os.readlink(os.fsencode(destination)), target)
                self.assertTrue(self.checks.verify_source(before, self.checks.snapshot(source))['unchanged'])
        self.assertTrue(self.checks.verify_source(outside_before, self.checks.snapshot(outside))['unchanged'])

    def test_tree_preserves_sparse_metadata_and_internal_hardlinks_for_each_job_count(self):
        source = self.base / 'source'
        source.mkdir(mode=0o750)
        for name in ('a', 'b', 'c'):
            (source / name).mkdir()
        (source / 'a/file').write_bytes(b'original')
        (source / 'a/link').symlink_to('absent-target')
        for directory in ('b', 'c'):
            for name in ('file', 'link'):
                os.link(source / 'a' / name, source / directory / name, follow_symlinks=False)
        os.link(source / 'a/file', self.base / 'external-file')
        os.link(source / 'a/link', self.base / 'external-link', follow_symlinks=False)
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'sentinel').write_bytes(b'untouched')
        (source / 'outside').symlink_to(outside, target_is_directory=True)
        (source / 'space \n café 🐎').write_bytes(b'names are bytes')
        receipt = self.fixtures.enrich_metadata(source, receipt={})
        eligible = self.eligible_child(source)
        os.link(eligible, source / 'b/eligible-alias')
        os.link(eligible, self.base / 'external-eligible')
        (source / 'a').chmod(0o500)
        source.chmod(0o550)
        os.utime(source, ns=(1_600_000_000_000_000_000, 1_700_000_000_123_456_789))
        before = self.checks.snapshot(source)
        self.assertTrue(self.fixtures.verify_metadata_coverage(before, receipt)['populated'])
        outside_before = self.checks.snapshot(outside)
        for jobs in range(1, 5):
            with self.subTest(jobs=jobs):
                destination = self.base / f'copy-{jobs}'
                descriptors = self.descriptors()
                self.copy(source, destination, jobs=jobs)
                self.assertEqual(self.descriptors(), descriptors)
                self.assert_preserved(before, destination)
                for name in ('file', 'link'):
                    self.assertEqual((destination / 'a' / name).lstat().st_nlink, 3)
                    self.assertEqual((source / 'a' / name).lstat().st_nlink, 4)
                self.assertEqual((destination / 'eligible-auto').stat().st_ino,
                                 (destination / 'b/eligible-alias').stat().st_ino)
                self.assertEqual((destination / 'eligible-auto').stat().st_nlink, 2)
                self.assertEqual(eligible.stat().st_nlink, 3)
                with (destination / 'b/eligible-alias').open('r+b') as stream:
                    stream.write(b'z')
                with (destination / 'eligible-auto').open('rb') as stream:
                    self.assertEqual(stream.read(1), b'z')
                with eligible.open('rb') as stream:
                    self.assertEqual(stream.read(1), b'x')
                (destination / 'b/file').write_bytes(b'changed')
                self.assertEqual((destination / 'c/file').read_bytes(), b'changed')
                self.assertEqual((source / 'a/file').read_bytes(), b'original')
                self.assertTrue(self.checks.verify_source(before, self.checks.snapshot(source))['unchanged'])
        self.assertTrue(self.checks.verify_source(outside_before, self.checks.snapshot(outside))['unchanged'])

    def test_existing_destinations_are_never_merged_replaced_or_followed(self):
        source = self.base / 'source'
        source.mkdir()
        (source / 'file').write_bytes(b'original')
        file = self.base / 'file'
        file.write_bytes(b'keep')
        directory = self.base / 'directory'
        directory.mkdir()
        (directory / 'sentinel').write_bytes(b'keep')
        link = self.base / 'link'
        link.symlink_to(directory, target_is_directory=True)
        dangling = self.base / 'dangling'
        dangling.symlink_to('missing')
        for destination in (file, directory, link, dangling):
            before = self.checks.snapshot(destination)
            for operand in (source, source / 'file'):
                with self.subTest(destination=destination.name, source=operand.name):
                    with self.assertRaises(FileExistsError):
                        self.copy(operand, destination)
                    self.assertTrue(self.checks.verify_source(before, self.checks.snapshot(destination))['unchanged'])
        self.assertEqual(sorted(path.name for path in directory.iterdir()), ['sentinel'])

    def test_destination_inside_source_is_rejected_through_parent_alias(self):
        source = self.base / 'source'
        source.mkdir()
        (source / 'file').write_bytes(b'original')
        alias = self.base / 'alias'
        alias.symlink_to(source, target_is_directory=True)
        before = self.checks.snapshot(source)
        for destination in (source / 'copy', alias / 'copy'):
            with self.subTest(destination=destination), self.assertRaises(OSError):
                self.copy(source, destination)
            self.assertFalse(os.path.lexists(destination))
        self.assertTrue(self.checks.verify_source(before, self.checks.snapshot(source))['unchanged'])

    def test_directory_parent_mode_and_acl_guards(self):
        source = self.base / 'source'
        source.mkdir()
        (source / 'file').write_bytes(b'original')
        parent = self.base / 'parent'
        parent.mkdir(mode=0o700)
        user = pwd.getpwuid(os.getuid()).pw_name
        mutation = 'add_file,add_subdirectory,delete_child'
        cases = [('shared', 0o777, None, False), ('sticky', 0o1777, None, True),
                 ('deny', 0o700, 'group:everyone deny delete_child', True),
                 ('current-user', 0o700, f'user:{user} allow {mutation}', True),
                 ('other-principal', 0o700, f'group:everyone allow {mutation}', False)]
        try:
            for name, mode, acl, allowed in cases:
                with self.subTest(parent=name):
                    subprocess.run(['/bin/chmod', '-N', str(parent)], check=True, capture_output=True, timeout=15)
                    parent.chmod(mode)
                    if acl:
                        subprocess.run(['/bin/chmod', '+a', acl, str(parent)], check=True, capture_output=True, timeout=15)
                    destination = parent / name
                    if allowed:
                        self.copy(source, destination)
                        self.assertEqual((destination / 'file').read_bytes(), b'original')
                    else:
                        with self.assertRaises(PermissionError):
                            self.copy(source, destination)
                        self.assertFalse(destination.exists())
        finally:
            subprocess.run(['/bin/chmod', '-N', str(parent)], check=True, capture_output=True, timeout=15)
            parent.chmod(0o700)

    def test_invalid_jobs_and_missing_operands_do_not_create_a_destination(self):
        source = self.base / 'source'
        source.write_bytes(b'original')
        destination = self.base / 'destination'
        before = self.checks.snapshot(source)
        descriptors = self.descriptors()
        for jobs in (0, 5, -1, 2**32 + 1, -(2**32) + 1, 2**64 + 1):
            with self.subTest(jobs=jobs), self.assertRaises((ValueError, OverflowError)):
                self.copy(source, destination, jobs=jobs)
            self.assertFalse(os.path.lexists(destination))
        for strategy in ('', 'clone', 'AUTO', 'materialised', 'auto\x00'):
            with self.subTest(strategy=strategy), self.assertRaises(ValueError):
                self.public_copy(source, destination, strategy=strategy)
            self.assertFalse(os.path.lexists(destination))
        for strategy in (None, 1, b'auto'):
            with self.subTest(strategy=strategy), self.assertRaises(TypeError):
                self.public_copy(source, destination, strategy=strategy)
            self.assertFalse(os.path.lexists(destination))
        with self.assertRaises(FileNotFoundError):
            self.copy(self.base / 'missing', destination)
        with self.assertRaises(FileNotFoundError):
            self.copy(source, self.base / 'missing-parent/destination')
        self.assertEqual(self.descriptors(), descriptors)
        self.assertFalse(os.path.lexists(destination))
        self.assertFalse((self.base / 'missing-parent').exists())
        self.assertTrue(self.checks.verify_source(before, self.checks.snapshot(source))['unchanged'])

    def test_special_file_error_keeps_partial_tree_and_releases_descriptors(self):
        source = self.base / 'source'
        source.mkdir()
        (source / 'file').write_bytes(b'original')
        os.mkfifo(source / 'fifo')
        before = self.checks.snapshot(source, allow_special=True)
        for jobs in (1, 4):
            destination = self.base / f'partial-{jobs}'
            descriptors = self.descriptors()
            with self.assertRaises(OSError) as raised:
                self.copy(source, destination, jobs=jobs)
            self.assertEqual(raised.exception.errno, errno.ENOTSUP)
            self.assertTrue(destination.is_dir(), 'Partial destination was removed')
            self.assertEqual(self.descriptors(), descriptors)
        self.assertTrue(self.checks.verify_source(before, self.checks.snapshot(source, allow_special=True))['unchanged'])
        with self.assertRaises(OSError) as raised:
            self.copy(source / 'fifo', self.base / 'unsupported-leaf')
        self.assertEqual(raised.exception.errno, errno.ENOTSUP)
        self.assertFalse(os.path.lexists(self.base / 'unsupported-leaf'))

    def test_native_and_python_cli_dispatch_json_errors_and_no_store(self):
        installed = Path(sysconfig.get_path('scripts')) / 'stallionfs'
        self.assertTrue(installed.is_file(), f'Installed launcher missing: {installed}')
        standalone = self.base / 'native-only'
        standalone.mkdir(mode=0o700)
        launcher = standalone / 'stallionfs'
        shutil.copy2(installed, launcher)
        self.assertFalse((standalone / 'stallionfs-python').exists())
        environment = {**os.environ, 'PATH': '/usr/bin:/bin'}
        for name, command in (('native', [str(launcher)]), ('python', [sys.executable, '-I', '-m', 'stallionfs'])):
            with self.subTest(cli=name):
                source = '--source café 🐎 "\\\t\n\x01'
                path = self.base / source
                path.write_bytes(b'original')
                store = self.base / (name + '-unused-store')
                def cli(*arguments):
                    return subprocess.run([*command, '--root', str(store), '--json', *arguments], cwd=self.base,
                                          env=environment, capture_output=True, text=True, timeout=15)
                forms = [()] if self.copy_strategy is None else [
                    ('--strategy=' + self.copy_strategy,), ('--strategy', self.copy_strategy)]
                for index, options in enumerate(forms):
                    destination = '--' + name + f'-copy-{index} "\\\t\n\x02'
                    with self.subTest(options=options):
                        result = cli('copy', *options, '--jobs=2', '--', source, destination)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        expected = {'source': source, 'destination': destination}
                        if self.copy_strategy == 'auto':
                            expected['strategy'] = 'auto'
                        self.assertEqual(json.loads(result.stdout), expected)
                        self.assertEqual((self.base / destination).read_bytes(), b'original')
                options = forms[0]
                for jobs in ('0', '5', '-1', '4294967297'):
                    result = cli('copy', *options, '--jobs=' + jobs, '--', source, '--invalid')
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, '')
                    self.assertFalse((self.base / '--invalid').exists())
                for arguments in (('--strategy=clone', '--', source, '--invalid'),
                                  ('--strategy', 'AUTO', '--', source, '--invalid'),
                                  ('--strategy=', '--', source, '--invalid'), ('--strategy',)):
                    with self.subTest(arguments=arguments):
                        result = cli('copy', *arguments)
                        self.assertEqual(result.returncode, 2, result.stderr)
                        self.assertEqual(result.stdout, '')
                        self.assertFalse(os.path.lexists(self.base / '--invalid'))
                result = cli('clone', '--strategy=auto', '--', source, '--invalid')
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertFalse(os.path.lexists(self.base / '--invalid'))
                for operands in ((source, destination), ('missing', 'never-created')):
                    result = cli('copy', *options, '--', *operands)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stdout, '')
                    self.assertIsInstance(json.loads(result.stderr)['error'], str)
                self.assertEqual(path.read_bytes(), b'original')
                self.assertFalse((self.base / 'never-created').exists())
                self.assertFalse(store.exists())

    def _bounded_image_command(self, *args):
        from stallionfs import images
        timeout = 10 if args[:2] == ('/usr/bin/hdiutil', 'info') else 60
        try:
            result = subprocess.run([str(a) for a in args], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, umask=0o077,
                                    timeout=timeout)
            if result.returncode:
                raise images._error(f'{args[0]} failed ({result.returncode}): '
                                    + result.stderr.decode(errors='replace').strip())
            return result.stdout
        except BaseException:
            self.image_command_failed = True
            raise

    @unittest.skipUnless(os.environ.get('STALLIONFS_TEST_IMAGES') == '1', 'Enable disposable APFS cross-volume check')
    def test_actual_cross_volume_copy_preserves_metadata_and_clone_move_still_refuse(self):
        from stallionfs import images
        inherited = self.base / 'inherited-group'
        inherited.write_bytes(b'ownership must be preserved')
        inherited_before = self.checks.snapshot(inherited)
        group = os.getegid()
        groups = {*os.getgroups(), os.getgid(), group}
        os.chown(self.base, -1, group)
        bounded = mock.patch.object(images, '_command', side_effect=self._bounded_image_command)
        bounded.start()
        self.addCleanup(bounded.stop)
        seed = self.base / 'seed'
        seed.mkdir(mode=0o700)
        image = self.image = self.base / 'copy.sparseimage'
        source = self.base / 'source'
        source.mkdir(mode=0o700)
        receipt = self.fixtures.enrich_metadata(source, receipt={})
        self.eligible_child(source)
        before = self.checks.snapshot(source)
        self.assertEqual({row['gid'] for row in before['entries'].values()}, {group})
        self.assertTrue(self.fixtures.verify_metadata_coverage(before, receipt)['populated'])
        fault_executable = self.compile_native_faults(self.base) if self.copy_strategy == 'auto' else None
        victim = self.base / 'victim'
        victim.mkdir(mode=0o700)
        point = victim / 'mounted'
        print(f'Copy image fixture: {self.base}; identity={self.base_identity}; image={image}; mount={point}',
              file=sys.stderr)
        images.build(seed, image, 1)
        try:
            repo = images.attach(image, point)
            print(f'Copy devices: source={source.stat().st_dev}; destination={repo.stat().st_dev}; '
                  f'attachment={images.mounted(image)}', file=sys.stderr)
            self.assertNotEqual(source.stat().st_dev, repo.stat().st_dev)
            self.assertEqual(repo.stat().st_gid, group)
            inherited_gid = inherited_before['entries']['']['gid']
            if os.geteuid() != 0 and inherited_gid not in groups and repo.stat().st_gid != inherited_gid:
                unsupported = repo / 'unsupported-group'
                self.assertFalse(os.path.lexists(unsupported))
                with self.assertRaises(OSError) as raised:
                    self.copy(inherited, unsupported)
                self.assertIn(raised.exception.errno, (errno.ENOTSUP, errno.EPERM, errno.EACCES))
                self.assertTrue(self.checks.verify_source(inherited_before, self.checks.snapshot(inherited))['unchanged'])
            else:
                print(f'Unsupported-group refusal unexercised: inherited gid={inherited_gid}; groups={sorted(groups)}',
                      file=sys.stderr)
            self.copy(source, repo / 'copied', jobs=4)
            self.assert_preserved(before, repo / 'copied')
            self.copy(repo / 'copied', self.base / 'returned', jobs=1)
            self.assert_preserved(before, self.base / 'returned')
            if fault_executable is not None:
                verified = repo / 'fault-verified-copy'
                subprocess.run([str(fault_executable), str(self.base), '--auto-cross-volume',
                                str(source), str(verified)], check=True, timeout=30)
                self.assert_preserved(before, verified)
            for operation in (self.native.clone, self.native.move):
                with self.subTest(operation=operation.__name__), self.assertRaises(OSError) as raised:
                    operation(source, repo / 'refused')
                self.assertEqual(raised.exception.errno, errno.EXDEV)
                self.assertFalse((repo / 'refused').exists())
            with self.assertRaises(OSError) as raised:
                self.copy(victim, self.base / 'nested-mount-copy')
            self.assertIn(raised.exception.errno, (errno.EXDEV, errno.EBUSY))
            self.assertTrue(self.checks.verify_source(before, self.checks.snapshot(source))['unchanged'])
        finally:
            if not self.image_command_failed:
                state = images.mounted(image)
                if state is not None:
                    if state['mountpoint'] != str(point):
                        raise RuntimeError(f'Unexpected attachment; retaining {image}: {state}')
                    images.detach(image, point)
                if images.mounted(image) is not None:
                    raise RuntimeError(f'Retaining attached image {image}')


class MaterializedCopy(OrdinaryCopy):
    copy_strategy = 'materialized'


class AutoCopy(OrdinaryCopy):
    copy_strategy = 'auto'


class CopyFixtureSafety(unittest.TestCase):
    def fixture(self):
        case = OrdinaryCopy('test_root_file_preserves_enriched_metadata_and_source')
        case.setUp()
        case._outcome = mock.Mock(result=unittest.TestResult())
        case.native = mock.Mock()
        case.native.mounts.return_value = []
        self.addCleanup(shutil.rmtree, case.base, ignore_errors=True)
        return case

    def test_failed_test_and_subtest_fixtures_are_retained(self):
        for subtest in (False, True):
            case = self.fixture()
            failed = mock.Mock(test_case=case) if subtest else case
            case._outcome.result.failures.append((failed, 'failure'))
            with mock.patch('sys.stderr'):
                case.tearDown()
            self.assertTrue(case.base.is_dir())
            case.native.mounts.assert_not_called()

    def test_cleanup_requires_known_detached_image(self):
        from stallionfs import images
        for command_failed, attachment in ((True, None), (False, {'mountpoint': None}), (False, None)):
            case = self.fixture()
            case.image = case.base / 'copy.sparseimage'
            case.image_command_failed = command_failed
            with mock.patch.object(images, 'mounted', return_value=attachment) as mounted:
                if command_failed or attachment is not None:
                    with self.assertRaises(RuntimeError):
                        case.tearDown()
                    self.assertTrue(case.base.is_dir())
                else:
                    case.tearDown()
                    self.assertFalse(case.base.exists())
                if command_failed:
                    mounted.assert_not_called()
                else:
                    mounted.assert_called_once_with(case.image)

    def test_image_command_bounds_and_timeout_retention(self):
        case = self.fixture()
        for command, timeout in ((('/usr/bin/hdiutil', 'info', '-plist'), 10),
                                 (('/usr/bin/ditto', 'source', 'destination'), 60)):
            with mock.patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess(command, 0, b'output', b'')) as run:
                self.assertEqual(case._bounded_image_command(*command), b'output')
                self.assertEqual(run.call_args.kwargs['timeout'], timeout)
        with mock.patch.object(subprocess, 'run', side_effect=subprocess.TimeoutExpired('owned-command', 60)):
            with self.assertRaises(subprocess.TimeoutExpired):
                case._bounded_image_command('/usr/bin/hdiutil', 'create')
        self.assertTrue(case.image_command_failed)


class CopyRuntimeDiscovery(unittest.TestCase):
    def test_older_runtime_case_is_discovered_only_before_macos_13(self):
        for system, version, expected in (('darwin', '12.7.6', True),
                                          ('darwin', '13.0', False),
                                          ('darwin', '26.0', False),
                                          ('linux', '', False)):
            with self.subTest(system=system, version=version):
                spec = importlib.util.spec_from_file_location('copy_runtime_discovery', __file__)
                module = importlib.util.module_from_spec(spec)
                with mock.patch.object(sys, 'platform', system), \
                     mock.patch.object(platform, 'mac_ver', return_value=(version, ('', '', ''), '')):
                    spec.loader.exec_module(module)
                cases = unittest.defaultTestLoader.loadTestsFromModule(module)
                legacy_cases = [case for group in cases for case in group
                                if type(case).__name__ == 'OlderCopyRuntime']
                self.assertEqual(len(legacy_cases), int(expected))
                if expected:
                    self.assertFalse(getattr(type(legacy_cases[0]), '__unittest_skip__', False))


if sys.platform == 'darwin' and not MACOS_13:
    class OlderCopyRuntime(unittest.TestCase):
        def test_copy_is_unavailable_without_mutation(self):
            from stallionfs import copy
            with tempfile.TemporaryDirectory(prefix='stallionfs-copy-old-') as directory:
                source = Path(directory) / 'source'
                destination = Path(directory) / 'destination'
                source.write_bytes(b'original')
                for options in ({}, {'strategy': 'materialized'}, {'strategy': 'auto'}):
                    with self.subTest(options=options), self.assertRaises(OSError) as raised:
                        copy(source, destination, **options)
                    self.assertEqual(raised.exception.errno, errno.ENOTSUP)
                    self.assertFalse(destination.exists())
                self.assertEqual(source.read_bytes(), b'original')


if __name__ == '__main__':
    unittest.main()
