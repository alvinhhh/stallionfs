"""Prepare publication checks using real Git without the macOS runtime."""
import importlib
from pathlib import Path
import shutil
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

class Prepare(unittest.TestCase):
    def setUp(self):
        self.package = '_prepare_test_' + str(id(self))
        package = ModuleType(self.package)
        package.__path__ = [str(Path(__file__).resolve().parents[1] / 'stallionfs')]
        modules = {self.package: package}
        scan = ModuleType(self.package + '._scan')
        scan._private_directory = lambda path: None
        modules[scan.__name__] = scan
        refs = ModuleType(self.package + '._native_create_git')
        refs.inspect_refs = lambda repo: ['HEAD']
        refs.PSEUDO = set()
        modules[refs.__name__] = refs
        isolated = patch.dict(sys.modules, modules)
        isolated.start(); self.addCleanup(isolated.stop)
        self.core = importlib.import_module(self.package + '.core')
        self.temp = tempfile.TemporaryDirectory(prefix='sfs-prepare-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.source = self.base / 'source'
        self.source.mkdir()
        environment = patch(self.package + '._bundle.git_environment',
                            side_effect=lambda env, **kwargs: (shutil.which('git'), env))
        environment.start(); self.addCleanup(environment.stop)
        self.core.git(self.source, 'init', '-b', 'main')
        self.core.git(self.source, 'config', 'user.name', 'Test')
        self.core.git(self.source, 'config', 'user.email', 'test@example.invalid')
        (self.source / 'file').write_text('original\n')
        self.core.git(self.source, 'add', 'file')
        self.core.git(self.source, 'commit', '-m', 'Fixture')
        self.store = self.core.Store(self.base / 'storage')

    def prepare(self, command=()):
        with patch.object(self.core.sys, 'platform', 'darwin'):
            return self.store.prepare(self.source, key='test-v1', command=command)

    def test_staged_change_with_worktree_matching_head_is_refused(self):
        command = [sys.executable, '-c',
                   "from pathlib import Path; import subprocess; "
                   "Path('file').write_text('staged\\n'); "
                   "subprocess.run(['git', 'add', 'file'], check=True); "
                   "Path('file').write_text('original\\n')"]
        with self.assertRaisesRegex(self.core.StallionError, 'Preparation changed tracked files or HEAD'):
            self.prepare(command)
        self.assertEqual(list((self.store.root / 'seeds').iterdir()), [])
        repo, = (self.store.root / 'staging').glob('*/repo')
        self.assertEqual(self.core.git(repo, 'diff', 'HEAD', '--'), '')
        self.assertTrue(self.core.git(repo, 'diff', '--cached', 'HEAD', '--'))

    def assert_refused(self, script):
        command = [sys.executable, '-c', 'from pathlib import Path; import os, subprocess; ' + script]
        with self.assertRaisesRegex(self.core.StallionError, 'Preparation changed tracked file'):
            self.prepare(command)
        self.assertEqual(list((self.store.root / 'seeds').iterdir()), [])
        repo, = (self.store.root / 'staging').glob('*/repo')
        return repo

    def test_change_hidden_by_index_flag_is_refused(self):
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag=flag):
                repo = self.assert_refused(
                    f"subprocess.run(['git', 'update-index', '{flag}', 'file'], check=True); "
                    "Path('file').write_text('changed\\n')")
                self.assertEqual(self.core.git(repo, 'diff', 'HEAD', '--'), '')
                shutil.rmtree(repo.parent)

    def test_mode_change_hidden_by_filemode_config_is_refused(self):
        repo = self.assert_refused(
            "subprocess.run(['git', 'config', 'core.filemode', 'false'], check=True); "
            "os.chmod('file', 0o755)")
        self.assertEqual(self.core.git(repo, 'diff', 'HEAD', '--'), '')

    def test_tracked_file_replaced_by_symlink_is_refused(self):
        self.assert_refused(
            "Path('copy').write_text('original\\n'); "
            "subprocess.run(['git', 'update-index', '--assume-unchanged', 'file'], check=True); "
            "os.remove('file'); os.symlink('copy', 'file')")

    def test_checkout_conversion_matching_head_is_published(self):
        (self.source / '.gitattributes').write_text('file text eol=crlf\n')
        self.core.git(self.source, 'add', '.gitattributes')
        self.core.git(self.source, 'commit', '-m', 'Line endings')
        seed = self.prepare()
        repo = self.store.root / 'seeds' / seed['id'] / 'repo'
        self.assertEqual((repo / 'file').read_bytes(), b'original\r\n')

    def test_change_hidden_by_line_ending_conversion_is_refused(self):
        (self.source / '.gitattributes').write_text('file text eol=crlf\n')
        self.core.git(self.source, 'add', '.gitattributes')
        self.core.git(self.source, 'commit', '-m', 'Line endings')
        self.assert_refused(
            "subprocess.run(['git', 'update-index', '--assume-unchanged', 'file'], check=True); "
            "Path('file').write_bytes(b'changed\\r\\n')")

    def test_clean_index_and_untracked_output_are_published(self):
        for command in ((), [sys.executable, '-c', "from pathlib import Path; Path('output').write_text('built')"]):
            with self.subTest(command=command):
                seed = self.prepare(command)
                repo = self.store.root / 'seeds' / seed['id'] / 'repo'
                self.assertEqual(self.core.git(repo, 'diff', '--cached', 'HEAD', '--'), '')
                if command:
                    self.assertEqual((repo / 'output').read_text(), 'built')
