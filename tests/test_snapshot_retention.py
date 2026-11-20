"""Snapshot retention admission without the macOS image runtime."""
import importlib
from pathlib import Path
import shutil
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch


class SnapshotRetention(unittest.TestCase):
    def setUp(self):
        self.package = '_snapshot_retention_' + str(id(self))
        package = ModuleType(self.package)
        package.__path__ = [str(Path(__file__).resolve().parents[1] / 'stallionfs')]
        scan = ModuleType(self.package + '._scan')
        scan._private_directory = lambda path: None
        isolated = patch.dict(sys.modules, {self.package: package, scan.__name__: scan})
        isolated.start()
        self.addCleanup(isolated.stop)
        self.core = importlib.import_module(self.package + '.core')
        self.lifecycle = importlib.import_module(self.package + '.lifecycle')
        self.images = importlib.import_module(self.package + '.images')
        temporary = tempfile.TemporaryDirectory(prefix='sfs-snapshot-retention-')
        self.addCleanup(temporary.cleanup)
        self.store = self.core.Store(Path(temporary.name).resolve() / 'store')
        self.workspace = 'a' * 32
        self.path = self.store.root / 'workspaces' / self.workspace
        self.path.mkdir(mode=0o700)
        self.image = self.path / 'workspace.sparseimage'
        self.image.write_bytes(b'owned synthetic image')
        (self.path / 'volume').mkdir(mode=0o700)
        self.core.write_json(self.path / 'meta.json', {
            'id': self.workspace, 'commit': 'b' * 40, 'backend': 'image'})
        self.attached = True
        self.enterContext(patch.object(self.images, 'mounted', side_effect=lambda image:
            {'mountpoint': str(self.path / 'volume')} if self.attached else None))
        self.detach = self.enterContext(patch.object(self.images, 'detach', side_effect=self.unmount))
        self.enterContext(patch.object(self.images, 'flush'))
        self.mount = self.enterContext(patch.object(self.store, '_mount', side_effect=self.remount))
        self.enterContext(patch.object(self.store, '_standalone_git'))
        self.enterContext(patch.object(self.store, '_no_mounts'))
        self.clone = self.enterContext(patch.object(self.store, '_clone_payload', side_effect=
            lambda source, target, meta: shutil.copyfile(source, target)))

    def unmount(self, *args):
        self.attached = False

    def remount(self, *args):
        self.attached = True
        return {'path': str(self.path / 'volume' / 'repo')}

    def test_full_retention_refuses_without_detaching_workspace(self):
        for index in range(self.lifecycle.RETENTION_COUNT):
            (self.store.root / 'recovery' / f'{index:032x}').mkdir(mode=0o700)
        with self.assertRaisesRegex(self.core.StallionError, 'retention limit'):
            self.store.snapshot(self.workspace)
        self.assertTrue(self.attached, 'refused snapshot unmounted the workspace')
        self.detach.assert_not_called()
        self.mount.assert_not_called()
        self.clone.assert_not_called()
        self.assertEqual(list((self.store.root / 'snapshots').iterdir()), [])
        self.assertEqual(list((self.store.root / 'staging').iterdir()), [])

    def test_empty_retention_captures_and_restores_mount(self):
        result = self.store.snapshot(self.workspace)
        self.assertTrue(self.attached)
        self.detach.assert_called_once()
        self.mount.assert_called_once()
        self.assertEqual(self.store.snapshots(self.workspace)[0]['id'], result['id'])
        saved = self.store.root / 'snapshots' / result['id'] / self.image.name
        self.assertEqual(saved.read_bytes(), self.image.read_bytes())

    def test_capture_validation_error_does_not_clone_or_detach(self):
        with patch.object(self.store, '_standalone_git', side_effect=self.core.StallionError('invalid Git')):
            with self.assertRaisesRegex(self.core.StallionError, 'invalid Git'):
                self.store.snapshot(self.workspace)
        self.assertTrue(self.attached)
        self.detach.assert_not_called()
        self.clone.assert_not_called()
        self.assertEqual(list((self.store.root / 'snapshots').iterdir()), [])
