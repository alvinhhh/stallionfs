"""Completed history and publication recovery on owned fixtures."""
import contextlib
import copy
import subprocess
import tempfile
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch
from stallionfs import core, _native, _native_binding as binding, _native_recovery as recovery
import test_native_binding as base


class BindingHistory(unittest.TestCase):
    def setUp(self):
        self.h = base.HostingBinding('test_device_renumber_resolves_mount_and_creation_without_rewriting_history')
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        self.f, self.store, self.path, self.meta = self.h.f, self.h.store, self.h.path, self.h.meta
        proof = self.f.read(self.path / 'native-install.json')
        proof.update(first_mount_attempted=True, first_use={'accepted': True, 'operation': '8' * 32,
            'write_probe': {'complete': True, 'path': str(self.path / 'volume/repo' / ('.stallionfs-write-' + '9' * 32))}})
        self.f.save(self.path / 'native-install.json', proof)
        target = binding.historical_target(self.path, self.meta)
        self.f.save(self.path / 'native-mount.json', {'state': 'absent', 'target': target,
            'operation': '8' * 32, 'current_guard': _native.guarded(target)})

    def completed(self, action):
        target = binding.historical_target(self.path, self.meta)
        details = {'bridge_attempted': True}
        if action != 'native-catalog-observe': details['name'] = 'saved'
        if action == 'native-restore': details['recovery_name'] = 'recovery-saved'
        op = _native.Operation(self.store, self.path, action, target, details=details)
        receipt = dict(status=0, poisoned=False, transaction_active=False,
                       device=target['file'][0], inode=target['file'][1], uuid=target['uuid'],
                       physical_end=self.f.anchor['committed_end'], **self.f.anchor)
        mutation = action != 'native-catalog-observe'
        op.record['native_image_result'] = dict(ok=True,
            operation={'native-catalog-observe': 'snapshots', 'native-snapshot': 'snapshot',
                       'native-restore': 'restore'}[action],
            committed=mutation, commit_attempted=mutation, outcome='committed' if mutation else 'not_committed',
            close_attempted=True, guard_close_errno=0, path_errno=0, error_code=0,
            interrupted=False, deadline_expired=False, abort_attempted=False,
            snapshot=details.get('name'), recovery=details.get('recovery_name'), snapshots=[],
            receipt=dict(receipt), close_receipt=dict(receipt))
        op.finish()
        recovery.validate_intent(self.path.name, op.record)
        self.assertFalse(op.journal.exists())
        self.assertEqual(op.record['outcome'], 'complete')
        self.assertFalse(op.record['child_pending'])
        return op

    def check_history(self, mode):
        if mode != 'bound': self.h.sidecar.unlink()
        original = self.h.historical_bytes()
        for action in ('native-catalog-observe', 'native-snapshot', 'native-restore'):
            op = self.completed(action)
            archived = (op.directory / 'record.json').read_bytes()
            lifecycle = (self.f.root / 'lifecycle' / (self.path.name + '.json')).read_bytes()
            try:
                with self.subTest(mode=mode, operation=action):
                    if mode == 'adopt':
                        with self.h.renumber():
                            result = self.h.adopt()
                        self.assertEqual(result['status'], 'current-image-adopted', result)
                    elif mode == 'bound':
                        with self.h.renumber():
                            target = _native.recover_install(self.store, self.path, self.meta)
                            self.assertEqual(target['file'], self.f.ident(self.path / 'image.sfs'))
                    else:
                        target = _native.recover_install(self.store, self.path, self.meta)
                        self.assertEqual(target['file'], self.f.ident(self.path / 'image.sfs'))
                self.assertEqual(archived, (op.directory / 'record.json').read_bytes())
                self.assertEqual(lifecycle, (self.f.root / 'lifecycle' / (self.path.name + '.json')).read_bytes())
            finally:
                shutil.rmtree(op.directory)
                if mode != 'bound' and self.h.sidecar.exists(): self.h.sidecar.unlink()
            self.assertEqual(original, self.h.historical_bytes())

    def test_completed_catalog_history_allows_same_device_legacy_enrollment(self):
        self.check_history('legacy')

    def test_completed_catalog_history_allows_bound_device_renumber(self):
        self.check_history('bound')

    def test_completed_catalog_history_allows_explicit_current_adoption(self):
        self.check_history('adopt')

    def test_bound_epoch_does_not_freeze_anchor_after_later_write(self):
        before = self.h.sidecar.read_bytes()
        self.f.guard_anchor = dict(self.f.anchor, generation=3, committed_end=32768, root_digest='c' * 64)
        (self.path / 'image.sfs').write_bytes(b'later supported image contents, owned synthetic guard')
        for changed in (False, True):
            with self.subTest(renumbered=changed), self.h.renumber() if changed else contextlib.nullcontext():
                target = _native.recover_install(self.store, self.path, self.meta)
                self.assertEqual(target['file'], self.f.ident(self.path / 'image.sfs'))
        self.assertEqual(before, self.h.sidecar.read_bytes())

    def test_new_guard_target_does_not_reinterpret_historical_receipt(self):
        proof = self.f.read(self.path / 'native-install.json')
        historical = binding.historical_target(self.path, self.meta)
        self.assertTrue(_native._consumed(proof['guard'], historical, self.f.anchor))
        with self.h.renumber():
            current = _native.recover_install(self.store, self.path, self.meta)
            self.assertFalse(_native._consumed(proof['guard'], current, self.f.anchor))
            self.assertEqual(self.f.continuation()['status'], 'already-installed')

    def test_legacy_same_device_enrolls_without_rewriting_original_receipts(self):
        self.h.sidecar.unlink()
        original = self.h.historical_bytes()
        _native.recover_install(self.store, self.path, self.meta)
        self.assertTrue(self.h.sidecar.exists())
        self.assertEqual(original, self.h.historical_bytes())

    def test_completed_snapshot_allows_current_unmount_rebaseline_after_renumber(self):
        op = self.completed('native-snapshot')
        # A public unmount obtains recover_install before creating its fresh guard.
        with self.h.renumber():
            _native.unmount_locked(self.store, self.path, self.meta)

    def test_incomplete_unknown_and_mismatched_history_refuses_all_admissions(self):
        original_binding = self.h.sidecar.read_bytes()
        for action in recovery.CATALOG:
            op = self.completed(action)
            original = copy.deepcopy(op.record)
            changes = [('outcome', 'incomplete'), ('child_pending', True),
                       ('operation', 'native-retire'), ('operation', 'native-purge'),
                       ('operation', 'unknown'), ('bridge_attempted', False),
                       ('native_image_result', {'ok': True, 'operation': action})]
            for key in ('ok', 'close_attempted', 'commit_attempted', 'committed'):
                changes.append(('native_image_result', dict(original['native_image_result'],
                                **{key: not original['native_image_result'][key]})))
            for key, value in (('outcome', 'unknown'), ('guard_close_errno', 5), ('path_errno', 5),
                               ('interrupted', True), ('deadline_expired', True), ('error_code', 5),
                               ('snapshot', 'different'), ('recovery', 'different'), ('close_receipt', None)):
                changes.append(('native_image_result', dict(original['native_image_result'], **{key: value})))
            receipt = dict(original['native_image_result']['close_receipt'], device=999)
            changes.append(('native_image_result', dict(original['native_image_result'], close_receipt=receipt)))
            changes.append(('target', dict(original['target'], component='other.sfs')))
            changes.append(('target', dict(original['target'], file=[999, original['target']['file'][1]])))
            for key, value in changes:
                self.f.save(op.directory / 'record.json', dict(original, **{key: value}))
                for mode in ('legacy', 'bound', 'adopt'):
                    with self.subTest(action=action, field=key, value=value, mode=mode):
                        if self.h.sidecar.exists(): self.h.sidecar.unlink()
                        if mode == 'bound':
                            self.h.sidecar.write_bytes(original_binding); self.h.sidecar.chmod(0o600)
                            # A replacement sidecar needs its actual publication inode.
                            b = self.f.read(self.h.sidecar)
                            b['publication_file_id'] = self.h.sidecar.stat().st_ino
                            self.f.save(self.h.sidecar, b)
                        with self.h.renumber() if mode != 'legacy' else contextlib.nullcontext():
                            if mode == 'adopt': self.assertEqual(self.h.adopt()['status'], 'blocked')
                            else:
                                with self.assertRaises(core.StallionError):
                                    _native.recover_install(self.store, self.path, self.meta)
                        if mode != 'bound': self.assertFalse(self.h.sidecar.exists())
            shutil.rmtree(op.directory)

    def test_completed_catalog_advanced_anchor_allows_enrollment_and_adoption(self):
        for mode in ('legacy', 'adopt'):
            for action in recovery.CATALOG:
                with self.subTest(mode=mode, action=action):
                    if self.h.sidecar.exists(): self.h.sidecar.unlink()
                    op = self.completed(action)
                    anchor = dict(self.f.anchor, generation=3, committed_end=32768, root_digest='a' * 64)
                    for key in ('receipt', 'close_receipt'):
                        op.record['native_image_result'][key].update(anchor, physical_end=anchor['committed_end'])
                    self.f.save(op.directory / 'record.json', op.record)
                    self.f.guard_anchor = anchor
                    with self.h.renumber() if mode == 'adopt' else contextlib.nullcontext():
                        if mode == 'adopt': self.assertEqual(self.h.adopt()['status'], 'current-image-adopted')
                        else: _native.recover_install(self.store, self.path, self.meta)
                    self.assertEqual(self.f.read(self.h.sidecar)['anchor'], anchor)
                    shutil.rmtree(op.directory)
                    self.f.guard_anchor = self.f.anchor

    def test_complete_offline_compound_history_and_incomplete_phase(self):
        for action in recovery.COMPOUND:
            op = self.completed('native-snapshot' if action == recovery.COMPOUND[0] else 'native-restore')
            op.record.update(operation=action, phase='final-verified', originally_mounted=False,
                             bridge_returned=True, profile='production', host=str(_native.HOST),
                             unmount_attempts=[], remount_attempts=[], committed_anchor=self.f.anchor,
                             final_evidence={'observation': None})
            binding.completed_operation(op.record, self.path, self.meta, op.record['id'])
            mounted = copy.deepcopy(op.record)
            row = {'filesystem': 'stallionfs', 'path': str(self.path / 'volume')}
            mounted.update(originally_mounted=True, accepted_mount=row, final_evidence={'observation': row},
                           unmount_attempts=[{'launched': True}], remount_attempts=[{
                               'launched': True, 'guard': _native.guarded(mounted['target']),
                               'qualified': {'profile': 'production', 'host': str(_native.HOST), 'filesystem': 'stallionfs'},
                               'evidence': {'usable': True, 'repo': str(self.path / 'volume/repo'), 'observation': row}}])
            for stage in ('unmount', 'remount'):
                commands = [('verify-package', _native.package_argv(_native.HOST)),
                            ('discover', [str(_native.HOST), '--discover-json'])]
                commands.append(('unmount', ['/sbin/umount', str(self.path / 'volume')]) if stage == 'unmount'
                                else ('mount', ['/sbin/mount', '-F', '-t', 'stallionfs', str(self.path), str(self.path / 'volume')]))
                for label, argv in commands:
                    mounted['helpers'].append(dict(stage=stage, attempt=0, label=label, argv=argv, child_pending=False,
                        reaped=True, pid=123, returncode=0, outcome='success', stdout='/fixture/stdout', stderr='/fixture/stderr'))
            binding.completed_operation(mounted, self.path, self.meta, mounted['id'])
            for change in ({'outcome': 'unknown'}, {'outcome': 'error', 'returncode': 1}):
                bad = copy.deepcopy(mounted); bad['helpers'][-1].update(change)
                with self.assertRaises(core.StallionError):
                    binding.completed_operation(bad, self.path, self.meta, bad['id'])
            for change in ({'phase': 'committed'}, {'bridge_returned': False},
                           {'native_image_result': {}}, {'final_evidence': {'observation': {}}},
                           {'child_pending': True}):
                with self.subTest(action=action, change=change), self.assertRaises(core.StallionError):
                    binding.completed_operation(dict(op.record, **change), self.path, self.meta, op.record['id'])
            shutil.rmtree(op.directory)

    def test_completed_mount_and_unmount_need_terminal_helpers_and_close(self):
        target = binding.historical_target(self.path, self.meta)
        guard = _native.guarded(target)
        def helper(label):
            return dict(label=label, child_pending=False, pid=123, returncode=0, reaped=True,
                        argv=['/fixture/' + label], stdout='/fixture/stdout', stderr='/fixture/stderr',
                        outcome='success')
        for action, absent in (('native-mount', False), ('native-unmount', False), ('native-unmount', True)):
            record = dict(workspace=self.path.name, id='7' * 32, target=target, operation=action,
                          outcome='complete', child_pending=False, current_guard=guard,
                          observed_mount={} if action == 'native-mount' else None)
            if action == 'native-mount':
                record.update(mount_attempted=True, helpers=[helper(k) for k in ('verify-package', 'discover', 'mount')])
            else:
                record.update(already_absent=absent, before_mount=None if absent else {},
                              helpers=[] if absent else [helper('unmount')])
            binding.completed_operation(record, self.path, self.meta, record['id'])
            for field in ('current_guard', 'observed_mount', 'child_pending', 'helpers'):
                bad = copy.deepcopy(record); bad.pop(field)
                with self.subTest(action=action, absent=absent, field=field), self.assertRaises(core.StallionError):
                    binding.completed_operation(bad, self.path, self.meta, record['id'])
            if record['helpers']:
                for change in ({'reaped': False}, {'child_pending': True}, {'outcome': 'unknown'},
                               {'outcome': 'error', 'returncode': 1}):
                    bad = copy.deepcopy(record); bad['helpers'][-1].update(change)
                    with self.subTest(action=action, change=change), self.assertRaises(core.StallionError):
                        binding.completed_operation(bad, self.path, self.meta, record['id'])

    def test_real_bridge_receipts_validate_against_each_historical_target(self):
        from stallionfs import _image
        with tempfile.TemporaryDirectory(prefix='sfs-history-') as name:
            root = Path(name).resolve(); directory = root / 'workspaces' / self.path.name
            directory.mkdir(parents=True, mode=0o700)
            fixture = root / 'fixture'
            subprocess.run(['xcrun', 'clang', '-O1', '-Ifilesystem', 'tests/native_image_fixture.c',
                            'filesystem/image.c', '-o', str(fixture)], check=True, capture_output=True)
            subprocess.run([str(fixture), 'seed', str(directory)], check=True, capture_output=True)
            target = dict(directory=str(directory), component='image.sfs',
                          parent=base.recovery.pair(directory.stat()), file=None)
            target.update(_image.inspect(target)['identity'])
            metadata = {'native_image': {'uuid': target['uuid'], 'object': target['parent'], 'file': target['file']}}
            for action, method, args in (('native-snapshot', 'snapshot', ('saved',)),
                    ('native-catalog-observe', 'snapshots', ()), ('native-restore', 'restore', ('saved', 'recovery-saved'))):
                result = getattr(_image, method)(target, *args)
                self.assertTrue(result['ok'], result)
                record = dict(workspace=directory.name, id='7' * 32, target=target, operation=action,
                              outcome='complete', child_pending=False, helpers=[], bridge_attempted=True,
                              native_image_result=result)
                if args: record['name'] = args[0]
                if len(args) == 2: record['recovery_name'] = args[1]
                binding.completed_operation(record, directory, metadata, record['id'])



class BindingPublicationRecovery(unittest.TestCase):
    def test_successful_creation_retry_completes_missing_binding_after_publication_interrupt(self):
        f = base.fixtures.CreateRecovery('test_success_repeated_calls_and_guarded_rename_syncs')
        f.setUp(); self.addCleanup(f.doCleanups)
        with patch.object(binding, 'publish', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): f.continuation()
        self.assertFalse(f.journal.exists())
        self.assertFalse((f.final / binding.NAME).exists())
        originals = {name: (f.final / name).read_bytes() for name in ('meta.json', 'native-create.json', 'native-install.json')}
        result = f.continuation()
        self.assertEqual(result['status'], 'installed-unmounted', result)
        self.assertEqual(originals, {name: (f.final / name).read_bytes() for name in originals})
        self.assertTrue((f.final / binding.NAME).exists(), 'successful exact creation retry returned without hosting binding')
        h = base.HostingBinding(); h.path = f.final
        store = core.Store.__new__(core.Store); store.root = f.root
        with h.renumber():
            target = _native.recover_install(store, f.final, f.read(f.final / 'meta.json'))
            self.assertEqual(target['file'], f.ident(f.final / 'image.sfs'))
        self.assertEqual(originals, {name: (f.final / name).read_bytes() for name in originals})

    def test_retry_after_publication_preserves_epoch_and_receipts(self):
        f = base.fixtures.CreateRecovery('test_success_repeated_calls_and_guarded_rename_syncs')
        f.setUp(); self.addCleanup(f.doCleanups)
        publish = binding.publish
        def interrupted(*args):
            publish(*args)
            raise KeyboardInterrupt
        with patch.object(binding, 'publish', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt): f.continuation()
        self.assertFalse(f.journal.exists())
        before = {name: (f.final / name).read_bytes() for name in
                  (binding.NAME, 'meta.json', 'native-create.json', 'native-install.json')}
        for _ in range(2):
            self.assertEqual(f.continuation()['status'], 'installed-unmounted')
            self.assertEqual(before, {name: (f.final / name).read_bytes() for name in before})

    def test_missing_binding_retry_requires_consumed_guard_before_success(self):
        f = base.fixtures.CreateRecovery('test_success_repeated_calls_and_guarded_rename_syncs')
        f.setUp(); self.addCleanup(f.doCleanups)
        with patch.object(binding, 'publish', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): f.continuation()
        self.assertFalse(f.journal.exists())
        before = {name: (f.final / name).read_bytes() for name in
                  ('meta.json', 'native-create.json', 'native-install.json')}
        with patch.object(_native, 'guarded', side_effect=core.StallionError('close failed')):
            self.assertEqual(f.continuation()['status'], 'blocked')
        self.assertFalse((f.final / binding.NAME).exists())
        self.assertEqual(before, {name: (f.final / name).read_bytes() for name in before})
        self.assertEqual(f.continuation()['status'], 'installed-unmounted')
        self.assertTrue((f.final / binding.NAME).exists())

if __name__ == '__main__': unittest.main()
