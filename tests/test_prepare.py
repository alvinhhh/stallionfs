"""Prepare publication checks using real Git without the macOS runtime."""
import hashlib
import importlib
import json
import os
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
        refs.inspect_refs = lambda repo, *, allow_shallow=False: ['HEAD']
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

    def prepare(self, command=(), *, image_size=None):
        with patch.object(self.core.sys, 'platform', 'darwin'):
            return self.store.prepare(self.source, key='test-v1', command=command, image_size=image_size)

    def test_image_prepare_rebuilds_legacy_seed_and_then_uses_cache(self):
        folder_seed = self.prepare()
        # The legacy image recipe added only backend and capacity to the folder spec.
        legacy_spec = {key: value for key, value in folder_seed.items()
                       if key not in ('id', 'created', 'cached')}
        legacy_spec.update(backend='image', capacity_gib=1)
        legacy_id = hashlib.sha256(json.dumps(legacy_spec, sort_keys=True).encode()).hexdigest()
        legacy_path = self.store.root / 'seeds' / legacy_id
        legacy_path.mkdir(mode=0o700)
        legacy_metadata = {'id': legacy_id, **legacy_spec, 'created': 0}
        self.core.write_json(legacy_path / 'meta.json', legacy_metadata)
        legacy_image = legacy_path / 'workspace.sparseimage'
        legacy_image.write_bytes(b'legacy image fixture')

        def build_image(repo, destination, capacity_gib):
            self.assertEqual((repo / 'file').read_bytes(), b'original\n')
            self.assertEqual(capacity_gib, 1)
            destination.write_bytes(b'new image fixture')

        with patch(self.package + '.images.build', side_effect=build_image) as build, \
                patch.object(self.core, 'remove_tree', side_effect=shutil.rmtree):
            seed = self.prepare(image_size=1)
            self.assertFalse(seed['cached'])
            self.assertNotEqual(seed['id'], legacy_id)
            self.assertEqual(seed['format'], 1)
            self.assertEqual(self.prepare(image_size=1), {**seed, 'cached': True})
        build.assert_called_once()
        self.assertEqual(self.store.object('seeds', legacy_id), (legacy_path, legacy_metadata))
        self.assertEqual(legacy_image.read_bytes(), b'legacy image fixture')

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

    def test_unusual_tracked_names_matching_head_are_published(self):
        names = ('carriage\rreturn', 'line\nfeed', 'trailing space ', 'quote"back\\slash', 'caf\u00e9')
        for name in names:
            (self.source / name).write_bytes(os.fsencode(name))
        self.core.git(self.source, 'add', '--', *names)
        self.core.git(self.source, 'commit', '-m', 'Names')
        seed = self.prepare()
        repo = self.store.root / 'seeds' / seed['id'] / 'repo'
        self.assertEqual([(repo / name).read_bytes() for name in names], [os.fsencode(name) for name in names])

    def test_clean_index_and_untracked_output_are_published(self):
        for command in ((), [sys.executable, '-c', "from pathlib import Path; Path('output').write_text('built')"]):
            with self.subTest(command=command):
                seed = self.prepare(command)
                repo = self.store.root / 'seeds' / seed['id'] / 'repo'
                self.assertEqual(self.core.git(repo, 'diff', '--cached', 'HEAD', '--'), '')
                if command:
                    self.assertEqual((repo / 'output').read_text(), 'built')
