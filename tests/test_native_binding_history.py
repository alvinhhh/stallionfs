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
            repository = Path(__file__).resolve().parents[1]
            compiled = subprocess.run(['xcrun', 'clang', '-O1', '-I' + str(repository / 'filesystem'),
                            str(repository / 'tests/native_image_fixture.c'),
                            str(repository / 'filesystem/image.c'), '-o', str(fixture)],
                            cwd=root, capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
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

class ResolvedMountHistory(unittest.TestCase):
    def setUp(self):
        import json
        self.wire = json.loads((Path(__file__).parent / 'fixtures/native-resolved-mount-history.json').read_text())
        self.path = Path(self.wire['mount']['target']['directory'])
        target = self.wire['mount']['target']
        self.meta = {'controller_profile': 'production', 'native_image': {
            'uuid': target['uuid'], 'object': target['parent'], 'file': target['file']}}

    def validate(self, wire=None):
        wire = wire or self.wire
        return binding.archive_anchor({wire[k]['id']: wire[k] for k in ('mount', 'unmount')},
                                      self.path, self.meta, wire['marker'])

    def test_full_legacy_shape_and_both_mount_spellings(self):
        for flag in (False, True):
            wire = copy.deepcopy(self.wire)
            if flag: wire['mount']['helpers'][-1]['argv'].insert(1, '-F')
            before = copy.deepcopy(wire)
            self.assertEqual(self.validate(wire), wire['unmount']['current_guard'])
            self.assertEqual(wire, before)
            with self.assertRaises(core.StallionError):
                binding.completed_operation(wire['mount'], self.path, self.meta, wire['mount']['id'])

    def test_protocol_gate_and_modern_transport(self):
        for member in ('mount', 'unmount'):
            for version in (1, 4, None, True, '2', '3', 2.0):
                wire = copy.deepcopy(self.wire); wire[member]['protocol'] = version
                with self.subTest(member=member, version=version), self.assertRaises(core.StallionError):
                    self.validate(wire)
        for version in (2, 3):
            wire = copy.deepcopy(self.wire)
            for member in ('mount', 'unmount'): wire[member]['protocol'] = version
            for h in wire['mount']['helpers']:
                h.update(streams_eof=True, streams_durable=True, output_bytes=0)
            self.validate(wire)
            for index in range(3):
                for field, values in {'streams_eof': [None, False], 'streams_durable': [None, False],
                    'output_bytes': [None, True, 1.0, -1, 2097153], 'interrupted': [False, True],
                    'stop_errors': [[]], 'collector_error': [None], 'stream_close_errors': [[]],
                    'receipt_error': [None]}.items():
                    for value in values:
                        bad = copy.deepcopy(wire)
                        if value is None and field in ('streams_eof', 'streams_durable', 'output_bytes'):
                            bad['mount']['helpers'][index].pop(field)
                        else: bad['mount']['helpers'][index][field] = value
                        with self.subTest(version=version, index=index, field=field, value=value), self.assertRaises(core.StallionError):
                            self.validate(bad)

    def test_invalid_pair_fields_and_edges(self):
        cases = {
            'mount': {'workspace': ['9'*32], 'id': ['9'*32], 'operation': ['native-unmount','native-purge'],
                'outcome': ['unknown','prepared'], 'previous_unresolved': [{}, {'id':'3'*32}],
                'mount_attempted': [False, None], 'observed_mount': [{}, 'missing'], 'child_pending': [True]},
            'unmount': {'operation': ['native-mount','native-purge'], 'outcome': ['incomplete','unknown'],
                'already_absent': [False], 'before_mount': [{}, 'missing'], 'observed_mount': [{}, 'missing'],
                'child_pending': [True], 'previous_unresolved': [None, {}, {'id':'3'*32}]}}
        for member, fields in cases.items():
            for field, values in fields.items():
                for value in values:
                    wire = copy.deepcopy(self.wire)
                    if value == 'missing': wire[member].pop(field)
                    else: wire[member][field] = value
                    with self.subTest(member=member, field=field, value=value), self.assertRaises(core.StallionError):
                        self.validate(wire)
        for field, value in [('id','9'*32), ('operation','native-unmount'), ('outcome','complete'),
                             ('record','/other/record.json'), ('extra',True)]:
            wire = copy.deepcopy(self.wire); wire['unmount']['previous_unresolved'][field] = value
            with self.subTest(reference=field), self.assertRaises(core.StallionError): self.validate(wire)
        for member in ('mount','unmount'):
            for field in ('target','current_guard'):
                for key, value in ({'directory':'/other', 'component':'other', 'uuid':'9'*32,
                                     'file':[101,300], 'parent':[101,200]} if field == 'target' else
                                    {'device':101,'inode':301,'uuid':'9'*32,'core_consumed':False,
                                     'parent_close_errno':5,'poisoned':True,'transaction_active':True,
                                     'root_digest':'6'*64,'generation':3}).items():
                    wire = copy.deepcopy(self.wire); wire[member][field][key] = value
                    with self.subTest(member=member, field=field, key=key), self.assertRaises(core.StallionError): self.validate(wire)

    def test_helpers_argv_and_ambiguous_incoming_edges(self):
        for index in range(3):
            for field,value in [('reaped',False),('child_pending',True),('outcome','unknown'),
                                ('outcome','not-launched'),('pid',None),('returncode',0 if index==2 else 72)]:
                wire=copy.deepcopy(self.wire); wire['mount']['helpers'][index][field]=value
                with self.subTest(index=index,field=field), self.assertRaises(core.StallionError):self.validate(wire)
        argv=self.wire['mount']['helpers'][-1]['argv']
        for bad in [[],argv[:-1],argv+['extra']] + [argv[:i]+['wrong']+argv[i+1:] for i in range(len(argv))]:
            wire=copy.deepcopy(self.wire);wire['mount']['helpers'][-1]['argv']=bad
            with self.subTest(argv=bad), self.assertRaises(core.StallionError):self.validate(wire)
        for ref in ({'id':'2'*32}, {'record':self.wire['unmount']['previous_unresolved']['record']}):
            extra=copy.deepcopy(self.wire['unmount']);extra.update(id='8'*32,previous_unresolved=ref)
            records={self.wire[k]['id']:self.wire[k] for k in ('mount','unmount')};records[extra['id']]=extra
            with self.assertRaises(core.StallionError):binding.archive_anchor(records,self.path,self.meta,self.wire['marker'])
        wire=copy.deepcopy(self.wire);wire['mount']['helpers'].reverse()
        with self.assertRaises(core.StallionError):self.validate(wire)

    def test_marker_replacement_keeps_successor_anchor_in_conflicts(self):
        for key,value in [('root_digest','6'*64),('committed_end',40000000)]:
            wire=copy.deepcopy(self.wire);wire['marker']['operation']='8'*32
            wire['marker']['current_guard'][key]=value
            with self.assertRaisesRegex(core.StallionError,'conflicting-anchors'):self.validate(wire)
        wire=copy.deepcopy(self.wire);wire['marker']['operation']='8'*32
        self.validate(wire)
        wire['marker']['current_guard'].update(generation=3,root_digest='6'*64)
        self.assertEqual(self.validate(wire)['generation'],3)
        wire['marker']['operation']=wire['unmount']['id']
        with self.assertRaises(core.StallionError):self.validate(wire)

    def owned(self):
        h=BindingHistory();h.setUp();self.addCleanup(h.doCleanups)
        target=binding.historical_target(h.path,h.meta)
        guard=_native.guarded(target)
        wire=copy.deepcopy(self.wire)
        old=str(self.path)
        def translate(value):
            if type(value) is str:return value.replace(old,str(h.path)).replace(self.path.name,h.path.name)
            if type(value) is dict:return {k:translate(v) for k,v in value.items()}
            if type(value) is list:return [translate(v) for v in value]
            return value
        wire=translate(wire)
        for member in wire:
            wire[member]['target']=copy.deepcopy(target);wire[member]['current_guard']=copy.deepcopy(guard)
        (h.path/'native-operations').mkdir(mode=0o700)
        for member in ('mount','unmount'):
            directory=h.path/'native-operations'/wire[member]['id'];directory.mkdir(parents=True,mode=0o700)
            h.f.save(directory/'record.json',wire[member])
        h.f.save(h.path/'native-mount.json',wire['marker'])
        return h

    def test_owned_enrollment_translation_adoption_and_byte_preservation(self):
        for mode in ('legacy','bound','adopt'):
            h=self.owned()
            if mode!='bound':h.h.sidecar.unlink()
            paths=[h.path/n for n in ('meta.json','native-create.json','native-install.json','native-mount.json')]
            paths+=list((h.path/'native-operations').glob('*/record.json'))
            before={p:p.read_bytes() for p in paths}
            with self.subTest(mode=mode), h.h.renumber() if mode!='legacy' else contextlib.nullcontext():
                if mode=='adopt':
                    self.assertEqual(h.h.adopt()['status'],'current-image-adopted')
                    sidecar=h.h.sidecar.read_bytes()
                    self.assertTrue(h.h.adopt()['already_adopted'])
                    self.assertEqual(sidecar,h.h.sidecar.read_bytes())
                else:_native.recover_install(h.store,h.path,h.meta)
            self.assertEqual(before,{p:p.read_bytes() for p in paths})

    def test_owned_pending_mount_and_fresh_guard_failure_prevent_publication(self):
        for mode in ('journal','mounted','unknown','guard','interrupt','unrelated'):
            h=self.owned();h.h.sidecar.unlink()
            if mode=='journal':h.f.save(h.f.journal,{'operation':'native-unmount'})
            if mode in ('mounted','unknown'):
                marker=h.f.read(h.path/'native-mount.json');marker['state']=mode;h.f.save(h.path/'native-mount.json',marker)
            if mode=='unrelated':
                row=copy.deepcopy(self.wire['unmount']);row.update(id='8'*32,outcome='incomplete')
                directory=h.path/'native-operations'/row['id'];directory.mkdir(mode=0o700);h.f.save(directory/'record.json',row)
            error=KeyboardInterrupt if mode=='interrupt' else core.StallionError('guard failed')
            ctx=patch.object(_native,'guarded',side_effect=error) if mode in ('guard','interrupt') else contextlib.nullcontext()
            with self.subTest(mode=mode),ctx:
                if mode=='interrupt':
                    with self.assertRaises(KeyboardInterrupt):h.h.adopt()
                else:self.assertEqual(h.h.adopt()['status'],'blocked')
            self.assertFalse(h.h.sidecar.exists())

    def test_common_bad_close_anchor_and_marker_target_refuse(self):
        for field,value in [('core_consumed',False),('status',5),('parent_close_errno',5),
                            ('generation',-1),('root_digest','invalid'),('transaction_active',True)]:
            wire=copy.deepcopy(self.wire)
            for member in wire:wire[member]['current_guard'][field]=value
            with self.subTest(field=field),self.assertRaises(core.StallionError):self.validate(wire)
        for field,value in [('parent',[101,200]),('directory','/other'),('component','other.sfs')]:
            wire=copy.deepcopy(self.wire);wire['marker']['target'][field]=value
            with self.subTest(field=field),self.assertRaises(core.StallionError):self.validate(wire)

    def test_later_completed_catalog_selects_newer_close(self):
        h=self.owned()
        op=h.completed('native-snapshot')
        newer=dict(h.f.anchor,generation=3,committed_end=32768,root_digest='a'*64)
        for key in ('receipt','close_receipt'):
            op.record['native_image_result'][key].update(newer,physical_end=32768)
        h.f.save(op.directory/'record.json',op.record)
        h.f.guard_anchor=newer
        h.h.sidecar.unlink()
        _native.recover_install(h.store,h.path,h.meta)
        self.assertEqual(h.f.read(h.h.sidecar)['anchor'],newer)

    def test_owned_later_unmount_marker_still_admits_original_pair(self):
        h=self.owned()
        original={p:p.read_bytes() for p in (h.path/'native-operations').glob('*/record.json')}
        # Exercise the public already-absent unmount, which replaces the marker.
        _native.unmount_locked(h.store,h.path,h.meta)
        self.assertNotEqual(h.f.read(h.path/'native-mount.json')['operation'],self.wire['unmount']['id'])
        h.h.sidecar.unlink()
        _native.recover_install(h.store,h.path,h.meta)
        self.assertEqual(original,{p:p.read_bytes() for p in original})

    def test_exceptional_guard_scalar_schema_on_each_witness_and_shared(self):
        scopes = [('mount',), ('unmount',), ('marker',), ('mount', 'unmount', 'marker')]
        for members in scopes:
            for field in ('status', 'parent_close_errno', 'device', 'inode', 'generation',
                          'committed_end', 'physical_end', 'core_consumed', 'poisoned', 'transaction_active'):
                original = self.wire['mount']['current_guard'][field]
                values = [None, str(original), float(original), True, False, -1, 1 << 64, 0.5]
                if field in ('status', 'parent_close_errno'): values += [1, 5]
                for value in values:
                    if type(value) is type(original) and value == original: continue
                    wire = copy.deepcopy(self.wire)
                    for member in members: wire[member]['current_guard'][field] = value
                    with self.subTest(members=members, field=field, value=value, kind=type(value).__name__):
                        with self.assertRaises(core.StallionError): self.validate(wire)
                wire = copy.deepcopy(self.wire)
                for member in members: wire[member]['current_guard'].pop(field)
                if field != 'physical_end':
                    with self.subTest(members=members, missing=field), self.assertRaises(core.StallionError):
                        self.validate(wire)

    def test_exceptional_target_scalar_schema_on_each_witness_and_shared(self):
        for members in [('mount',), ('unmount',), ('marker',), ('mount', 'unmount', 'marker')]:
            for field in ('parent', 'file'):
                for index in (0, 1):
                    original = self.wire['mount']['target'][field][index]
                    for value in (float(original), True, False, str(original), -1, None, 0.5):
                        wire = copy.deepcopy(self.wire)
                        for member in members: wire[member]['target'][field][index] = value
                        with self.subTest(members=members, field=field, index=index, value=value):
                            with self.assertRaises(core.StallionError): self.validate(wire)

    def test_full_evidence_comparison_preserves_nested_scalar_types(self):
        for field in ('target', 'current_guard'):
            wire = copy.deepcopy(self.wire)
            for member in wire: wire[member][field]['extra'] = {'nested': [0, {'value': 1}]}
            self.validate(wire)
            for member in ('mount', 'unmount', 'marker'):
                for value in (True, 1.0):
                    bad = copy.deepcopy(wire)
                    bad[member][field]['extra']['nested'][1]['value'] = value
                    with self.subTest(field=field, member=member, value=value):
                        with self.assertRaises(core.StallionError): self.validate(bad)

    def test_malformed_evidence_refuses_before_owned_binding_publication(self):
        cases = [('mount', 'target', 'file'), ('mount', 'current_guard', 'generation'),
                 ('all', 'current_guard', 'status'), ('all', 'current_guard', 'parent_close_errno'),
                 ('all', 'current_guard', 'device'), ('all', 'current_guard', 'inode'),
                 ('marker', 'target', 'parent')]
        for member, section, field in cases:
            h = self.owned(); h.h.sidecar.unlink()
            paths = {k: h.path/'native-operations'/self.wire[k]['id']/'record.json'
                     for k in ('mount', 'unmount')}
            paths['marker'] = h.path/'native-mount.json'
            for key in paths if member == 'all' else (member,):
                row = h.f.read(paths[key])
                if section == 'target': row[section][field][0] = float(row[section][field][0])
                else: row[section][field] = False if field == 'status' else float(row[section][field])
                h.f.save(paths[key], row)
            before = {p: p.read_bytes() for p in paths.values()}
            with self.subTest(member=member, section=section, field=field):
                with patch.object(binding, 'publish', wraps=binding.publish) as publish:
                    self.assertEqual(h.h.adopt()['status'], 'blocked')
                    publish.assert_not_called()
                self.assertFalse(h.h.sidecar.exists())
                self.assertEqual(before, {p: p.read_bytes() for p in paths.values()})

    def test_guard_string_schema_and_anchor_boundaries(self):
        for members in [('mount',), ('unmount',), ('marker',), ('mount', 'unmount', 'marker')]:
            for field in ('uuid', 'root_digest'):
                for value in (None, False, 0, 1.0, [], {}, 'invalid'):
                    wire = copy.deepcopy(self.wire)
                    for member in members: wire[member]['current_guard'][field] = value
                    with self.subTest(members=members, field=field, value=value):
                        with self.assertRaises(core.StallionError): self.validate(wire)
        for generation in (0, (1 << 64) - 1):
            wire = copy.deepcopy(self.wire)
            for member in wire: wire[member]['current_guard']['generation'] = generation
            self.assertEqual(self.validate(wire)['generation'], generation)

class ResolvedHistoryBudgets(unittest.TestCase):
    def fixture(self):
        source = ResolvedMountHistory()
        source.setUp()
        self.addCleanup(source.doCleanups)
        h = source.owned()
        h.h.sidecar.unlink()
        return h, source

    def test_history_budget_boundaries_and_publication_order(self):
        from stallionfs import _native_create_recovery as admission
        for member in ('mount', 'unmount', 'marker', 'additional'):
            for budget in ('document', 'scoped', 'aggregate'):
                with self.subTest(member=member, budget=budget):
                    h, source = self.fixture()
                    if member == 'additional':
                        op = h.completed('native-snapshot')
                        selected = op.directory / 'record.json'
                    elif member == 'marker': selected = h.path / 'native-mount.json'
                    else: selected = h.path / 'native-operations' / source.wire[member]['id'] / 'record.json'
                    # Valid JSON whitespace makes the selected evidence the largest
                    # document without changing its schema or archive eligibility.
                    selected.write_bytes(selected.read_bytes() + b' ' * 32768)
                    before = {p: p.read_bytes() for p in h.f.root.rglob('*.json')}
                    a = admission.Admission(h.store.root)
                    try:
                        reads = []
                        original_read = a.read
                        def observed_read(path):
                            value = original_read(path)
                            reads.append((path, a.bytes))
                            return value
                        with patch.object(a, 'read', side_effect=observed_read):
                            binding.exclusions(h.store, a, h.path, h.meta)
                        total = a.bytes
                    finally: a.close()
                    size = selected.stat().st_size
                    limit = total if budget == 'aggregate' else size
                    def scope(value):
                        if budget == 'scoped': return core.json_read_limit(value)
                        return patch.object(admission, 'MAX_TOTAL_BYTES' if budget == 'aggregate' else 'MAX_DOCUMENT_BYTES', value)
                    # Exact limits admit the complete archive set.
                    a = admission.Admission(h.store.root)
                    try:
                        with scope(limit): binding.exclusions(h.store, a, h.path, h.meta)
                    finally: a.close()
                    # Enrollment shares evidence reads with exclusions; for the
                    # aggregate case measure that prefix without bypassing reads.
                    a = admission.Admission(h.store.root)
                    try:
                        binding.evidence(a, h.path, h.meta)
                        prefix = a.bytes
                    finally: a.close()
                    exhausted = next(count for path, count in reads if path == selected) - 1 + prefix if budget == 'aggregate' else limit - 1
                    with scope(exhausted), \
                         patch.object(_native, 'guarded', side_effect=AssertionError('guard reached')), \
                         patch.object(binding, 'publish', side_effect=AssertionError('publication reached')), \
                         patch.object(_native, '_persist', side_effect=AssertionError('history write')):
                        a = admission.Admission(h.store.root)
                        try:
                            with self.assertRaises(admission.Refusal) as caught:
                                binding.enroll(h.store, a, h.path, h.meta, adopt=True)
                            self.assertIsInstance(caught.exception, core.MetadataLimitError)
                            self.assertEqual(caught.exception.code, 'read-budget' if budget == 'aggregate' else 'document-budget')
                            self.assertIn(caught.exception.path, [str(p) for p in before])
                            self.assertEqual(caught.exception.path, str(selected))
                            diagnostic = admission.diagnostic(caught.exception)
                            self.assertEqual(diagnostic['code'], caught.exception.code)
                            self.assertEqual(diagnostic['path'], str(selected))
                        finally: a.close()
                        if budget != 'aggregate':
                            result = h.h.adopt()
                            self.assertEqual(result['status'], 'blocked')
                            self.assertEqual(result['code'], 'document-budget')
                            self.assertEqual(result['path'], str(selected))
                    self.assertFalse(h.h.sidecar.exists())
                    self.assertEqual(before, {p: p.read_bytes() for p in h.f.root.rglob('*.json')})

    def test_malformed_history_remains_nonbudget_refusal(self):
        from stallionfs import _native_create_recovery as admission
        for members in (('mount',), ('marker',), ('mount', 'unmount', 'marker')):
            h, source = self.fixture()
            for member in members:
                path = h.path / 'native-mount.json' if member == 'marker' else h.path / 'native-operations' / source.wire[member]['id'] / 'record.json'
                row = h.f.read(path); row['current_guard']['status'] = False; h.f.save(path, row)
            before = {p: p.read_bytes() for p in h.f.root.rglob('*.json')}
            with self.subTest(members=members), patch.object(_native, 'guarded', side_effect=AssertionError('guard')), patch.object(binding, 'publish', side_effect=AssertionError('publish')):
                a = admission.Admission(h.store.root)
                try:
                    with self.assertRaises(admission.Refusal) as caught:
                        binding.enroll(h.store, a, h.path, h.meta, adopt=True)
                    self.assertNotIsInstance(caught.exception, core.MetadataLimitError)
                    self.assertEqual(caught.exception.code, 'binding-resolution-guard')
                finally: a.close()
            self.assertEqual(before, {p: p.read_bytes() for p in h.f.root.rglob('*.json')})

    def test_public_pending_purge_history_budget_never_writes_failure(self):
        import test_stallionfs
        from stallionfs import _native_purge as purge, _native_create_recovery as admission
        case = test_stallionfs.Workspaces()
        case.setUp(); self.addCleanup(case.doCleanups)
        seed = case.prepare()
        with case.native_controller_fixture(), case.native_wall_clock() as now:
            workspace, path = case.native_purge_fixture(seed, now)
            record = case.store.purge('trash', workspace)['native_operation']
            _native._persist(case.store.root / 'journals' / (workspace + '.json'), record)
        h, source = self.fixture()
        a = admission.Admission(h.store.root)
        try:
            binding.exclusions(h.store, a, h.path, h.meta)
            total = a.bytes
        finally: a.close()
        before = {p: p.read_bytes() for root in (h.f.root, case.store.root) for p in root.rglob('*.json')}
        # Inject at the pending-purge ingress seam. The admission
        # itself loads and validates complete real-shaped owned history.
        def history(*args):
            a = admission.Admission(h.store.root)
            try: binding.exclusions(h.store, a, h.path, h.meta)
            finally: a.close()
            self.fail('history budget did not refuse')
        with patch.object(admission, 'MAX_TOTAL_BYTES', total - 1), \
             patch.object(purge, 'parents', side_effect=history), \
             patch.object(purge, 'failure', side_effect=AssertionError('failure write')), \
             patch.object(_native, '_persist', side_effect=AssertionError('history write')), \
             patch.object(_native, 'guarded', side_effect=AssertionError('guard')), \
             patch.object(binding, 'publish', side_effect=AssertionError('publication')):
            with self.assertRaises(admission.Refusal) as caught:
                case.store.purge('trash', workspace, yes=True)
            self.assertIsInstance(caught.exception, core.MetadataLimitError)
            self.assertEqual(caught.exception.code, 'read-budget')
            self.assertTrue(hasattr(caught.exception, 'native_candidate_result'))
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        self.assertTrue((path / 'image.sfs').exists())
