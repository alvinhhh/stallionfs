"""Restored compound history and hosting admission on owned image fixtures."""
import copy
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from stallionfs import core, _native, _native_binding as binding, _native_recovery as recovery
import test_stallionfs as fixtures


class CompoundBinding(unittest.TestCase):
    setUp = fixtures.Workspaces.setUp
    prepare = fixtures.Workspaces.prepare
    native_creation_fixture = fixtures.Workspaces.native_creation_fixture
    native_controller_fixture = fixtures.Workspaces.native_controller_fixture
    compound_controller_fixture = fixtures.Workspaces.compound_controller_fixture

    def test_restored_history_enrolls_and_resolves_without_replaying_bridge(self):
        seed = self.prepare()
        unlink = Path.unlink
        for action in ('snapshot', 'rollback'):
            with self.subTest(action=action), self.compound_controller_fixture() as state:
                created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
                workspace = created['id']; path = Path(created['path']).parent.parent
                if action == 'rollback': self.store.snapshot(workspace, name='base', quiescent=True)
                journal = self.store.root / 'journals' / (workspace + '.json')
                def command(operation=None):
                    options = dict(quiescent=True, continue_operation=operation)
                    if action == 'snapshot': return self.store.snapshot(workspace, name='base', **options)
                    return self.store.rollback(workspace, 'base', **options)
                def die(candidate, *args, **kwargs):
                    if candidate == journal: raise SystemExit('before journal removal')
                    return unlink(candidate, *args, **kwargs)
                with patch.object(core, 'native_operation', wraps=core.native_operation) as bridge:
                    with patch.object(Path, 'unlink', die), patch.object(recovery, '_retain_compound_failure'):
                        with self.assertRaises(SystemExit): command()
                        first = core.read_json(journal)
                        self.assertEqual(first['outcome'], 'complete')
                        state['rows'].clear()
                        with self.assertRaises(SystemExit): command(first['id'])
                        second = core.read_json(journal)
                    state['rows'].clear()
                    final = command(first['id'])['native_operation']
                    self.assertEqual(bridge.call_count, 1)
                    self.assertEqual(len(final['remount_attempts']), 3)
                    for index, prior in enumerate((first, second)):
                        self.assertEqual(final['remount_attempts'][index]['final_evidence'], prior['final_evidence'])
                    metadata = core.read_json(path / 'meta.json')
                    binding.completed_operation(final, path, metadata, final['id'])
                    self.store.unmount(workspace)
                    # The fake mounted repository is absent from the real backing
                    # directory after withdrawal; no OS mount is performed.
                    shutil.rmtree(path / 'volume/repo')
                    archive = path / 'native-operations' / final['id'] / 'record.json'
                    originals = {p: p.read_bytes() for p in path.glob('native-operations/*/record.json')}
                    immutable = {p: p.read_bytes() for p in (path / 'meta.json', path / 'native-create.json', path / 'native-install.json')}
                    (path / binding.NAME).unlink()
                    _native.recover_install(self.store, path, metadata)
                    self.assertEqual(core.read_json(path / binding.NAME)['anchor'], final['committed_anchor'])
                    current = _native.recover_install(self.store, path, metadata)
                    self.assertEqual(current, final['target'])
                    # An older successful attempt cannot supply the latest
                    # terminal child evidence during historical admission.
                    bad = copy.deepcopy(final)
                    latest = len(bad['remount_attempts']) - 1
                    for helper in bad['helpers']:
                        if helper.get('stage') == 'remount' and helper.get('attempt') == latest and helper['label'] == 'mount':
                            helper.update(outcome='error', returncode=1)
                    _native._persist(archive, bad)
                    with self.assertRaises(core.StallionError):
                        binding.completed_operation(bad, path, metadata, bad['id'])
                    (path / binding.NAME).unlink()
                    with self.assertRaises(core.StallionError): _native.recover_install(self.store, path, metadata)
                    self.assertFalse((path / binding.NAME).exists())
                    archive.write_bytes(originals[archive])
                    self.assertEqual(_native.recover_install(self.store, path, metadata), current)
                    epoch = (path / binding.NAME).read_bytes()
                    self.assertEqual(_native.recover_install(self.store, path, metadata), current)
                    self.assertEqual(epoch, (path / binding.NAME).read_bytes())
                    self.assertEqual(originals, {p: p.read_bytes() for p in originals})
                    self.assertEqual(immutable, {p: p.read_bytes() for p in immutable})
                    self.assertEqual(bridge.call_count, 1)


if __name__ == '__main__': unittest.main()
