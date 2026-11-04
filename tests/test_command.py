"""Command setup uses only disposable homes and inert app fixtures."""
from contextlib import redirect_stderr, redirect_stdout
import fcntl
import io
import json
import os
from pathlib import Path
import shlex
import stat
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

from stallionfs import _bundle, _command, __main__
from test_bundled_runtime import PrivateFixture

REAL_ACL = _command._acl
REAL_HOME = _command._home


class CommandLinks(PrivateFixture):
    def setUp(self):
        super().setUp()
        self.home = self.root / 'Home With Spaces'
        self.home.mkdir(mode=0o700)
        self.app, self.module = self.bundle('Applications/StallionFS.app')
        self.target = self.app / 'Contents/Resources/Runtime/CLI/bin/sfs'
        for item in (patch.object(_command, '_home', return_value=self.home),
                     patch.object(_command, 'APP', self.app),
                     patch.object(_bundle, '__file__', str(self.module)),
                     patch.object(_command, '_acl')):
            item.start()
            self.addCleanup(item.stop)
        self.bin = self.home / '.local/bin'
        self.link = self.bin / 'sfs'

    def make_bin(self):
        self.bin.mkdir(mode=0o755, parents=True)

    def test_status_is_observational_and_reports_exact_path_setup(self):
        before = set(self.root.rglob('*'))
        with patch.dict(os.environ, {'PATH': '/usr/bin:/bin'}):
            result = _command.run('status')
        self.assertEqual(result['state'], 'missing')
        self.assertFalse(result['on_path'])
        self.assertEqual(result['path_setup'], 'export PATH=' + shlex.quote(str(self.bin)) + ':"$PATH"')
        self.assertEqual(set(self.root.rglob('*')), before)
        self.assertFalse(self.bin.exists())

    def test_setup_idempotency_and_owned_removal_do_not_chmod_existing_directories(self):
        self.make_bin()
        original_mode = stat.S_IMODE(self.bin.stat().st_mode)
        with patch.object(os, 'chmod', side_effect=AssertionError('chmod')), \
                patch.object(os, 'fchmod', side_effect=AssertionError('fchmod')):
            self.assertEqual(_command.run('install')['state'], 'installed')
            identity = self.link.lstat().st_ino
            self.assertEqual(_command.run('install')['state'], 'installed')
            self.assertEqual(self.link.lstat().st_ino, identity)
            self.assertEqual(_command.run('remove')['state'], 'missing')
            self.assertEqual(_command.run('remove')['state'], 'missing')
        self.assertEqual(stat.S_IMODE(self.bin.stat().st_mode), original_mode)
        self.assertFalse(os.path.lexists(self.link))
        self.assertTrue(self.target.is_file())

    def test_missing_parent_setup_creates_only_command_directories_and_link(self):
        self.assertEqual(_command.run('install')['command'], str(self.link))
        self.assertEqual(self.link.readlink(), self.target)
        self.assertEqual(set(path.name for path in self.bin.iterdir()), {'sfs', _command.LOCK})
        self.assertFalse((self.home / 'Library').exists())

    def test_foreign_files_and_dangling_or_previous_targets_are_never_replaced_or_removed(self):
        self.make_bin()
        for value in (None, self.root / 'missing', self.root / 'Old App.app/bin/sfs'):
            with self.subTest(target=value):
                if value is None: self.link.write_bytes(b'foreign file')
                else: self.link.symlink_to(value)
                before = self.link.lstat()
                self.assertEqual(_command.run('status')['state'], 'conflict')
                for action in ('install', 'remove'):
                    with self.assertRaises(ValueError): _command.run(action)
                    self.assertEqual(self.link.lstat().st_ino, before.st_ino)
                if value is None: self.assertEqual(self.link.read_bytes(), b'foreign file')
                else: self.assertEqual(self.link.readlink(), value)
                self.link.unlink()

    def test_same_target_with_other_uid_is_not_owned(self):
        self.make_bin()
        self.link.symlink_to(self.target)
        original = _command._link
        def other_owner(fd):
            identity, _, target = original(fd)
            return identity, os.getuid() + 1, target
        with patch.object(_command, '_link', side_effect=other_owner):
            self.assertEqual(_command.run('status')['state'], 'conflict')
            with self.assertRaises(ValueError): _command.run('remove')
        self.assertTrue(self.link.is_symlink())

    def test_unsafe_parent_and_acl_refusals_do_not_touch_existing_entries(self):
        self.make_bin()
        self.link.write_bytes(b'keep')
        self.bin.chmod(0o775)
        with self.assertRaises(ValueError): _command.run('install')
        self.bin.chmod(0o755)
        with patch.object(_command, '_acl', side_effect=PermissionError('fixture ACL refusal')):
            with self.assertRaises(OSError): _command.run('remove')
        self.assertEqual(self.link.read_bytes(), b'keep')

    def test_directory_alias_is_refused(self):
        self.make_bin()
        retained = self.home / 'retained'
        self.bin.rename(retained)
        self.bin.symlink_to(retained)
        with self.assertRaises(OSError): _command.run('install')
        self.assertFalse((retained / 'sfs').exists())

    def test_relocated_or_transient_app_never_creates_command_parent(self):
        moved = self.root / 'Translocated With Spaces.app'
        self.app.rename(moved)
        with patch.object(_bundle, '__file__', str(moved / self.module.relative_to(self.app))):
            with self.assertRaisesRegex(ValueError, 'Applications'): _command.run('install')
        self.assertFalse(self.bin.exists())

    def test_target_change_before_mutation_is_refused(self):
        original = _command._target
        calls = []
        def changed():
            calls.append(None)
            if len(calls) == 2: self.target.write_bytes(b'changed fixture')
            return original()
        with patch.object(_command, '_target', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'target changed'): _command.run('install')
        self.assertFalse(os.path.lexists(self.link))

    def test_existing_mutation_lock_refuses_concurrent_install(self):
        self.make_bin()
        with (self.bin / _command.LOCK).open('w') as lock:
            (self.bin / _command.LOCK).chmod(0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, 'in use'): _command.run('install')
            self.assertFalse(os.path.lexists(self.link))
        self.assertEqual(_command.run('install')['state'], 'installed')

    def test_interruption_after_link_creation_is_visible_and_recoverable(self):
        with patch.object(os, 'fsync', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): _command.run('install')
        self.assertEqual(self.link.readlink(), self.target)
        self.assertEqual(_command.run('status')['state'], 'installed')
        self.assertEqual(_command.run('install')['state'], 'installed')
        self.assertEqual(_command.run('remove')['state'], 'missing')

    def test_leaf_replacement_before_remove_is_retained(self):
        _command.run('install')
        original, calls = _command._link, []
        def changed(fd):
            calls.append(None)
            if len(calls) == 2:
                self.link.unlink()
                self.link.write_bytes(b'replacement')
            return original(fd)
        with patch.object(_command, '_link', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'entry changed'): _command.run('remove')
        self.assertEqual(self.link.read_bytes(), b'replacement')

    def test_entry_created_during_install_is_not_overwritten(self):
        original = os.symlink
        def replaced(target, name, *, dir_fd):
            self.link.write_bytes(b'concurrent entry')
            return original(target, name, dir_fd=dir_fd)
        with patch.object(os, 'symlink', side_effect=replaced):
            with self.assertRaises(FileExistsError): _command.run('install')
        self.assertEqual(self.link.read_bytes(), b'concurrent entry')

    def test_parent_replacement_during_setup_is_refused(self):
        self.make_bin()
        retained = self.home / 'retained'
        original, calls = _command._check_directories, []
        def changed(held):
            calls.append(None)
            if len(calls) == 2:
                self.bin.rename(retained)
                self.bin.mkdir(mode=0o700)
            return original(held)
        with patch.object(_command, '_check_directories', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'replaced'): _command.run('install')
        self.assertFalse(os.path.lexists(self.link))
        self.assertFalse(os.path.lexists(retained / 'sfs'))

    def test_cli_status_precedes_store_and_ignores_store_environment(self):
        store = self.root / 'never-create-store'
        core = SimpleNamespace(Store=Mock(side_effect=AssertionError('Store initialized')))
        output = io.StringIO()
        with patch.dict(sys.modules, {'stallionfs.core': core}), \
                patch.dict(os.environ, {'STALLIONFS_HOME': str(store)}), redirect_stdout(output):
            self.assertEqual(__main__.main(['--json', 'command', 'status']), 0)
        self.assertEqual(json.loads(output.getvalue())['state'], 'missing')
        core.Store.assert_not_called()
        self.assertFalse(store.exists())
        self.assertFalse(self.bin.exists())

    def test_cli_rejects_store_root_for_command_setup(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            __main__.main(['--root', str(self.root / 'store'), 'command', 'install'])
        self.assertEqual(error.exception.code, 2)
        self.assertFalse(self.bin.exists())

    def test_native_acl_check_delegates_without_relaxation(self):
        native = SimpleNamespace(_protected_directory_fd=Mock())
        with patch.dict(sys.modules, {'stallionfs._scan': native}), \
                patch.object(_command, '_acl', wraps=REAL_ACL):
            _command._acl(31)
        native._protected_directory_fd.assert_called_once_with(31, False)

    def test_home_comes_from_os_record_not_environment(self):
        with patch('pwd.getpwuid', return_value=SimpleNamespace(pw_dir=str(self.home))), \
                patch.dict(os.environ, {'HOME': str(self.root / 'unrelated')}):
            self.assertEqual(REAL_HOME(), self.home)

    def test_acl_error_closes_every_opened_directory(self):
        original, opened = os.open, []
        def recorded(*args, **kwargs):
            fd = original(*args, **kwargs)
            opened.append(fd)
            return fd
        with patch.object(os, 'open', side_effect=recorded), \
                patch.object(_command, '_acl', side_effect=PermissionError('fixture ACL refusal')):
            with self.assertRaises(OSError): _command.run('status')
        for fd in opened:
            with self.assertRaises(OSError): os.fstat(fd)
