"""Compound restart control flow with an owned fake namespace; no real mounts."""
from contextlib import contextmanager, nullcontext
import copy
import errno
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

from stallionfs import core, _native, _native_recovery as recovery
import test_stallionfs as fixtures


class CompoundRestartGaps(unittest.TestCase):
    native_controller_fixture = fixtures.Workspaces.native_controller_fixture
    compound_controller_fixture = fixtures.Workspaces.compound_controller_fixture

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='compound-phase-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.store = core.Store(self.base / 'store')

    @contextmanager
    def native_creation_fixture(self):
        # The reused namespace fixture needs an executor discriminator only.
        # No creation or admitted Git runtime is requested by these tests.
        yield {'executable': sys.executable}

    @contextmanager
    def scenario(self, action):
        workspace = uuid.uuid4().hex
        path = self.store.root / 'workspaces' / workspace
        path.mkdir(mode=0o700)
        (path / 'volume/repo').mkdir(parents=True, mode=0o700)
        image = path / 'image.sfs'
        image.write_bytes(b'opaque regular fixture; never opened by native image code')
        image.chmod(0o600)
        ident = lambda value: [value.stat().st_dev, value.stat().st_ino]
        target = {'directory': str(path), 'component': 'image.sfs', 'parent': ident(path),
                  'file': ident(image), 'uuid': '5' * 32}
        anchor = {'generation': 2, 'root_digest': '4' * 64, 'committed_end': 16384}
        receipt = dict(status=0, poisoned=False, transaction_active=False,
                       device=target['file'][0], inode=target['file'][1], uuid=target['uuid'], **anchor)
        guard_receipt = dict(receipt, core_consumed=True, parent_close_errno=0)
        # Explicit doubles: these receipts describe the simulated guard/bridge,
        # never an actual image transaction or close.
        catalog = ['base'] if action == 'rollback' else []
        def mutate(bound, operation, *names):
            self.assertEqual(bound, target)
            self.assertFalse(state['rows'])
            self.assertEqual(operation, 'restore' if action == 'rollback' else 'snapshot')
            retained = core.read_json(self.store.root / 'journals' / (workspace + '.json'))
            self.assertEqual(retained['phase'], 'bridge-attempted')
            self.assertTrue(_native._consumed(retained['offline_admission'], target))
            self.assertTrue(guard.call_count)
            catalog.append(names[1] if operation == 'restore' else names[0])
            return dict(ok=True, committed=True, commit_attempted=True, outcome='committed',
                        close_attempted=True, guard_close_errno=0, path_errno=0,
                        interrupted=False, deadline_expired=False, operation=operation,
                        snapshot=names[0], recovery=names[1] if operation == 'restore' else None,
                        receipt=copy.deepcopy(receipt), close_receipt=copy.deepcopy(receipt))
        with self.compound_controller_fixture() as state:
            metadata = {'id': workspace, 'backend': 'native-image', 'ownership': 'store-created',
                        'state': 'installed', 'controller_profile': 'production', 'native_host': str(_native.HOST)}
            _native._persist(path / 'meta.json', metadata)
            _native._persist(path / 'native-install.json', {'complete': True, 'first_mount_attempted': True})
            row = {'path': str(path / 'volume'), 'filesystem': 'stallionfs', 'device': 'fixture',
                   'owner': os.getuid(), 'readonly': False, 'ignore_ownership': False, 'flags': 0, 'fsid': [71, 0]}
            state['rows'][row['path']] = row
            _native._persist(path / 'native-mount.json', {'state': 'mounted', 'target': target,
                              'profile': 'production', 'observation': row})
            with patch.object(recovery, 'ready', return_value=target), \
                 patch.object(_native, 'installed_target', return_value=target), \
                 patch.object(self.store, '_reconcile'), patch.object(self.store, '_open'), \
                 patch.object(_native, '_usable', return_value=str(path / 'volume/repo')), \
                 patch.object(_native, 'guarded', return_value=guard_receipt) as guard, \
                 patch.object(core, 'native_operation', side_effect=mutate) as bridge, \
                 patch('os.kill') as kill, patch('os.waitpid') as waitpid:
                def command(operation_id=None):
                    kwargs = {'quiescent': True, 'continue_operation': operation_id}
                    if action == 'snapshot':
                        return self.store.snapshot(workspace, name='base', **kwargs)
                    return self.store.rollback(workspace, 'base', **kwargs)
                yield dict(workspace=workspace, path=path, target=target, state=state, command=command,
                           journal=self.store.root / 'journals' / (workspace + '.json'),
                           guard=guard, bridge=bridge, catalog=catalog, action=action, metadata=metadata)
                kill.assert_not_called()
                waitpid.assert_not_called()

    def interrupt(self, case, phase):
        if phase == 'prepared':
            with patch.object(recovery, '_unmount_compound', side_effect=OSError(errno.EIO, 'before withdrawal')):
                with self.assertRaisesRegex(OSError, 'before withdrawal'): case['command']()
        elif phase == 'remount-attempted':
            with patch.object(recovery, '_verify_final', side_effect=OSError(errno.EIO, 'before final verification')):
                with self.assertRaisesRegex(OSError, 'before final verification'): case['command']()
        else:
            unlink = Path.unlink
            def stop(candidate, *args, **kwargs):
                if candidate == case['journal']:
                    record = core.read_json(candidate)
                    archive = core.read_json(case['path'] / 'native-operations' / record['id'] / 'record.json')
                    self.assertEqual(record['outcome'], 'complete')
                    self.assertEqual(record, archive)
                    self.assertEqual(record['phase'], 'final-verified')
                    raise OSError(errno.EIO, 'journal removal interrupted')
                return unlink(candidate, *args, **kwargs)
            with patch.object(Path, 'unlink', stop):
                with self.assertRaisesRegex(OSError, 'journal removal interrupted'): case['command']()
        record = core.read_json(case['journal'])
        self.assertEqual(record['phase'], phase)
        self.assertTrue(record['originally_mounted'])
        self.assertEqual(record['bridge_attempted'], phase != 'prepared')
        self.assertEqual(case['bridge'].call_count, 0 if phase == 'prepared' else 1)
        if phase == 'prepared':
            self.assertEqual(record['unmount_attempts'], [])
            self.assertNotIn('offline_admission', record)
        else:
            self.assertTrue(recovery._confirmed_bridge(record))
        return record

    def completed(self, case, record):
        self.assertEqual(record['outcome'], 'complete')
        self.assertEqual(case['bridge'].call_count, 1)
        self.assertFalse(case['journal'].exists())
        recovery.validate_compound(case['workspace'], record)

    def status(self, case, before):
        journal = case['journal'].read_bytes()
        archive_path = case['path'] / 'native-operations' / before['id'] / 'record.json'
        archive = archive_path.read_bytes()
        guards = case['guard'].call_count
        commands = copy.deepcopy(case['state']['commands'])
        result = self.store.snapshots(case['workspace'], operation_id=before['id'])
        self.assertEqual(journal, case['journal'].read_bytes())
        self.assertEqual(archive, archive_path.read_bytes())
        self.assertEqual(guards, case['guard'].call_count)
        self.assertEqual(commands, case['state']['commands'])
        return result

    def final_absent(self, case, *, complete=False):
        if complete:
            # Model process death after complete is durable, without the normal
            # exception handler rewriting outcome to incomplete.
            with patch.object(recovery, '_retain_compound_failure'):
                before = self.interrupt(case, 'final-verified')
            self.assertEqual(before['outcome'], 'complete')
        else:
            before = self.interrupt(case, 'final-verified')
        case['state']['rows'].clear()
        return before

    def assert_history(self, case, before, record, index=0):
        for key in ('id', 'target', 'recovery_name', 'committed_anchor', 'native_image_result', 'accepted_mount'):
            self.assertEqual(record.get(key), before.get(key), key)
        old = record['remount_attempts'][index]
        self.assertEqual(old['final_evidence'], before['final_evidence'])
        self.assertEqual({k: v for k, v in old.items() if k != 'final_evidence'},
                         {k: v for k, v in before['remount_attempts'][index].items() if k != 'final_evidence'})
        self.assertEqual(case['bridge'].call_count, 1)

    def test_same_mount_and_remount_attempted_baselines(self):
        for action in ('snapshot', 'rollback'):
            for phase in ('prepared', 'final-verified', 'remount-attempted'):
                with self.subTest(action=action, phase=phase), self.scenario(action) as case:
                    before = self.interrupt(case, phase)
                    if phase == 'remount-attempted': case['state']['rows'].clear()
                    record = case['command'](before['id'])['native_operation']
                    self.completed(case, record)
                    self.assertEqual(len(record['remount_attempts']), 2 if phase == 'remount-attempted' else 1)

    def test_prepared_absent_continuation_and_withdrawal(self):
        for action in ('snapshot', 'rollback'):
            for withdrawal in (False, True):
                with self.subTest(action=action, withdrawal=withdrawal), self.scenario(action) as case:
                    before = self.interrupt(case, 'prepared')
                    case['state']['rows'].clear()
                    status = self.status(case, before)
                    self.assertIsNotNone(status['next_action'])
                    self.assertIn('fresh exclusive', status['message'])
                    if withdrawal:
                        result = self.store.continue_unmount(case['workspace'], before['id'])
                        record = result['native_operation']
                        self.assertTrue(result['already_absent'])
                        self.assertFalse(result['mutation_started'])
                        self.assertEqual(record['phase'], 'offline')
                        self.assertEqual(case['bridge'].call_count, 0)
                    else:
                        record = case['command'](before['id'])['native_operation']
                        self.completed(case, record)
                    self.assertEqual(record['accepted_mount'], before['accepted_mount'])
                    self.assertEqual(record.get('recovery_name'), before.get('recovery_name'))
                    self.assertTrue(_native._consumed(record['offline_admission'], case['target']))
                    self.assertEqual(record['unmount_attempts'], [])
                    self.assertFalse(any(c[0] == '/sbin/umount' for c in case['state']['commands']))

    def test_prepared_terminal_qualification_only_allows_absence(self):
        for action in ('snapshot', 'rollback'):
            with self.subTest(action=action), self.scenario(action) as case:
                qualified = recovery._qualified
                def stop(operation, metadata, attempt):
                    qualified(operation, metadata, attempt)
                    raise OSError(errno.EIO, 'qualification interrupted')
                with patch.object(recovery, '_qualified', side_effect=stop):
                    with self.assertRaises(OSError): case['command']()
                before = core.read_json(case['journal'])
                self.assertEqual(before['phase'], 'prepared')
                self.assertFalse(before['unmount_attempts'][0]['launched'])
                case['state']['rows'].clear()
                record = case['command'](before['id'])['native_operation']
                self.completed(case, record)
                self.assertEqual(record['unmount_attempts'], before['unmount_attempts'])

    def test_prepared_absence_refuses_prior_work_and_ineligible_namespace(self):
        for action in ('snapshot', 'rollback'):
            for withdrawal in (False, True):
                for failure in ('result', 'launched', 'nested', 'incompatible', 'unknown', 'target', 'controller', 'name'):
                    with self.subTest(action=action, withdrawal=withdrawal, failure=failure), self.scenario(action) as case:
                        before = self.interrupt(case, 'prepared')
                        record = copy.deepcopy(before)
                        case['state']['rows'].clear()
                        if failure == 'result': record['native_image_result'] = {'ok': False}
                        if failure == 'launched': record['unmount_attempts'] = [{'launched': True, 'response': None}]
                        if failure == 'target': record['target']['file'][1] += 1
                        if failure == 'controller': record['host'] += '.other'
                        if failure == 'name': record['name'] = 'other'
                        if failure == 'nested':
                            case['state']['rows']['nested'] = dict(before['accepted_mount']['observation'], path=str(case['path'] / 'volume/nested'))
                        if failure == 'incompatible':
                            case['state']['rows'][str(case['path'] / 'volume')] = dict(before['accepted_mount']['observation'], filesystem='other')
                        _native._persist(case['journal'], record)
                        with patch('stallionfs._scan.mounts', side_effect=OSError(errno.EIO, 'unknown')) if failure == 'unknown' else nullcontext():
                            if failure != 'name': self.assertIsNone(self.status(case, record)['next_action'])
                            with self.assertRaises((OSError, core.StallionError)):
                                if withdrawal:
                                    # Withdrawal intentionally obtains the original name
                                    # from the journal; a name alone is not a mismatch.
                                    if failure == 'name':
                                        recovery.compound_locked(self.store, case['path'], case['metadata'],
                                            'snapshot' if action == 'snapshot' else 'restore', 'base',
                                            operation_id=before['id'], withdrawal=True)
                                    else: self.store.continue_unmount(case['workspace'], before['id'])
                                else: case['command'](before['id'])
                        case['guard'].assert_not_called()
                        self.assertEqual(case['bridge'].call_count, 0)
                        self.assertEqual(case['state']['commands'], [])
                        self.assertEqual(core.read_json(case['journal'])['phase'], 'prepared')

    def test_final_absence_remounts_with_history_even_pending_complete(self):
        for action in ('snapshot', 'rollback'):
            for complete in (False, True):
                with self.subTest(action=action, complete=complete), self.scenario(action) as case:
                    before = self.final_absent(case, complete=complete)
                    status = self.status(case, before)
                    self.assertFalse(status['current_mount_matches_completion'])
                    self.assertIsNotNone(status['next_action'])
                    self.assertIn('Previously verified; currently absent', status['message'])
                    record = case['command'](before['id'])['native_operation']
                    self.completed(case, record)
                    self.assert_history(case, before, record)
                    self.assertEqual(len(record['remount_attempts']), 2)
                    self.assertNotEqual(record['final_evidence'], before['final_evidence'])
                    self.assertEqual(case['guard'].call_args.kwargs['expected_anchor'], before['committed_anchor'])
                    mounts = [c for c in case['state']['commands'] if c[0] == '/sbin/mount']
                    self.assertEqual(len(mounts), 2)
                    self.assertTrue(all(c[1] == '-F' for c in mounts))

    def test_reset_checkpoint_interruptions_and_archive_failure(self):
        for action in ('snapshot', 'rollback'):
            for boundary in ('before-journal', 'after-journal', 'archive'):
                with self.subTest(action=action, boundary=boundary), self.scenario(action) as case:
                    before = self.final_absent(case, complete=True)
                    persist = _native._persist
                    fired = []
                    def stop(path, value):
                        reset = (value.get('phase') == 'committed' and value.get('outcome') == 'incomplete'
                                 and value['remount_attempts'][0].get('final_evidence'))
                        selected = path == case['journal'] if boundary != 'archive' else path.name == 'record.json'
                        if reset and selected and not fired:
                            fired.append(True)
                            # Keep retention from obscuring the exact crash state.
                            if boundary == 'after-journal': persist(path, value)
                            raise OSError(errno.EIO, 'reset checkpoint')
                        return persist(path, value)
                    with patch.object(_native, '_persist', side_effect=stop), patch.object(recovery, '_retain_compound_failure'):
                        with self.assertRaisesRegex(OSError, 'reset checkpoint'): case['command'](before['id'])
                    self.assertEqual(fired, [True])
                    retained = core.read_json(case['journal'])
                    self.assertEqual(len(retained['remount_attempts']), 1)
                    if boundary == 'before-journal':
                        self.assertEqual(retained, before)
                    else:
                        self.assertEqual(retained['phase'], 'committed')
                        self.assertEqual(retained['outcome'], 'incomplete')
                        self.assert_history(case, before, retained)
                    record = case['command'](before['id'])['native_operation']
                    self.completed(case, record)
                    self.assert_history(case, before, record)

    def test_restoration_interruptions_and_repeated_history(self):
        for action in ('snapshot', 'rollback'):
            for boundary in ('appended', 'qualified', 'mount-returned', 'final-verified', 'unlink'):
                with self.subTest(action=action, boundary=boundary), self.scenario(action) as case:
                    before = self.final_absent(case)
                    persist = _native.Operation.persist
                    fired = []
                    def stop(operation):
                        result = persist(operation)
                        r = operation.record
                        if len(r['remount_attempts']) != 2 or fired: return result
                        a = r['remount_attempts'][-1]
                        hit = ((boundary == 'appended' and not a['launched'] and 'qualified' not in a)
                               or (boundary == 'qualified' and 'qualified' in a and not a['launched'])
                               or (boundary == 'mount-returned' and a['response'] is not None)
                               or (boundary == 'final-verified' and r['phase'] == 'final-verified')
                               or (boundary == 'unlink' and r['outcome'] == 'complete'))
                        if hit:
                            fired.append(True)
                            raise OSError(errno.EIO, 'restoration interrupted')
                        return result
                    with patch.object(_native.Operation, 'persist', stop), patch.object(recovery, '_retain_compound_failure'):
                        with self.assertRaisesRegex(OSError, 'restoration interrupted'): case['command'](before['id'])
                    retained = core.read_json(case['journal'])
                    self.assert_history(case, before, retained)
                    if boundary in ('appended', 'qualified'):
                        self.assertFalse(recovery._terminal_attempt(retained, 'remount'))
                        self.assertTrue(recovery._terminal_attempt(retained, 'remount', 0))
                        # Copied observations cannot borrow an older terminal receipt.
                        forged = copy.deepcopy(retained)
                        forged['remount_attempts'][-1].update(copy.deepcopy(before['remount_attempts'][0]))
                        forged['remount_attempts'][-1]['launched'] = False
                        row = before['final_evidence']['observation']
                        self.assertFalse(recovery._mount_completion_evidence(forged, row))
                        self.assertTrue(recovery._mount_completion_evidence(forged, row, 0))
                    if boundary == 'mount-returned':
                        # No durable observation yet: present mount must refuse.
                        with self.assertRaises(core.StallionError): case['command'](before['id'])
                    case['state']['rows'].clear()
                    # Interrupt the next fully verified restoration as well.
                    with patch.object(Path, 'unlink', side_effect=OSError(errno.EIO, 'second unlink')):
                        with self.assertRaises(OSError): case['command'](before['id'])
                    second = core.read_json(case['journal'])
                    self.assertEqual(second['phase'], 'final-verified')
                    case['state']['rows'].clear()
                    record = case['command'](before['id'])['native_operation']
                    self.completed(case, record)
                    self.assert_history(case, before, record)
                    self.assert_history(case, second, record, len(second['remount_attempts']) - 1)

    def test_prelaunch_marker_without_terminal_receipt_refuses(self):
        for action in ('snapshot', 'rollback'):
            with self.subTest(action=action), self.scenario(action) as case:
                before = self.final_absent(case)
                command = _native.Operation.command
                def stop(operation, label, argv):
                    if label == 'mount': raise OSError(errno.EIO, 'before helper launch')
                    return command(operation, label, argv)
                with patch.object(_native.Operation, 'command', stop):
                    with self.assertRaises(OSError): case['command'](before['id'])
                with self.assertRaises(core.StallionError): case['command'](before['id'])
                self.assertEqual(case['bridge'].call_count, 1)

    def test_offline_guard_failure_and_post_guard_namespace_or_binding_change(self):
        for action in ('snapshot', 'rollback'):
            for withdrawal in (False, True):
                for failure in ('busy', 'unconsumed', 'close-error', 'nested-after', 'binding-after'):
                    with self.subTest(action=action, withdrawal=withdrawal, failure=failure), self.scenario(action) as case:
                        before = self.interrupt(case, 'prepared')
                        case['state']['rows'].clear()
                        receipt = copy.deepcopy(case['guard'].return_value)
                        def guard(*args, **kwargs):
                            if failure == 'busy': raise OSError(errno.EBUSY, 'held')
                            if failure == 'unconsumed': receipt['core_consumed'] = False
                            if failure == 'close-error': receipt['parent_close_errno'] = errno.EIO
                            if failure == 'nested-after':
                                case['state']['rows']['nested'] = dict(before['accepted_mount']['observation'], path=str(case['path'] / 'volume/nested'))
                            if failure == 'binding-after':
                                image = case['path'] / 'image.sfs'
                                image.rename(case['path'] / 'held.sfs')
                                image.write_bytes(b'replacement'); image.chmod(0o600)
                            return receipt
                        with patch.object(_native, 'guarded', side_effect=guard):
                            with self.assertRaises((OSError, core.StallionError)):
                                if withdrawal: self.store.continue_unmount(case['workspace'], before['id'])
                                else: case['command'](before['id'])
                        retained = core.read_json(case['journal'])
                        self.assertEqual(retained['phase'], 'prepared')
                        self.assertNotIn('offline_admission', retained)
                        self.assertEqual(case['bridge'].call_count, 0)
                        self.assertEqual(case['state']['commands'], [])

    def test_restoration_rechecks_absence_and_binding_after_anchor_guard(self):
        for action in ('snapshot', 'rollback'):
            for failure in ('nested', 'binding'):
                with self.subTest(action=action, failure=failure), self.scenario(action) as case:
                    before = self.final_absent(case)
                    commands = copy.deepcopy(case['state']['commands'])
                    receipt = copy.deepcopy(case['guard'].return_value)
                    def guard(target, **kwargs):
                        self.assertEqual(kwargs['expected_anchor'], before['committed_anchor'])
                        if failure == 'nested':
                            case['state']['rows']['nested'] = dict(before['accepted_mount']['observation'], path=str(case['path'] / 'volume/nested'))
                        else:
                            image = case['path'] / 'image.sfs'
                            image.rename(case['path'] / 'held.sfs')
                            image.write_bytes(b'replacement'); image.chmod(0o600)
                        return receipt
                    with patch.object(_native, 'guarded', side_effect=guard):
                        with self.assertRaises(core.StallionError): case['command'](before['id'])
                    record = core.read_json(case['journal'])
                    self.assertEqual(record['phase'], 'committed')
                    self.assertEqual(len(record['remount_attempts']), 2)
                    self.assertFalse(record['remount_attempts'][-1]['launched'])
                    self.assert_history(case, before, record)
                    self.assertEqual(case['state']['commands'], commands)

    def test_identity_namespace_and_historical_proof_refusals(self):
        failures = ('target', 'controller', 'name', 'action', 'nested', 'incompatible', 'unknown',
                    'child', 'missing-terminal', 'missing-qualification', 'missing-usability', 'missing-guard',
                    'missing-bridge', 'anchor', 'unconsumed', 'close-error', 'busy')
        for action in ('snapshot', 'rollback'):
            for failure in failures:
                with self.subTest(action=action, failure=failure), self.scenario(action) as case:
                    before = self.final_absent(case)
                    record = copy.deepcopy(before)
                    if failure == 'target': record['target']['file'][1] += 1
                    if failure == 'controller': record['host'] += '.other'
                    if failure == 'name': record['name'] = 'other'
                    if failure == 'action': record['operation'] = recovery.COMPOUND[1 if action == 'snapshot' else 0]; record['recovery_name'] = 'other'
                    if failure == 'nested':
                        case['state']['rows']['nested'] = dict(before['accepted_mount']['observation'], path=str(case['path'] / 'volume/nested'))
                    if failure == 'incompatible':
                        case['state']['rows'][str(case['path'] / 'volume')] = dict(before['accepted_mount']['observation'], filesystem='other')
                    if failure == 'child': record['helpers'][-1].update(child_pending=True, reaped=False, outcome='running'); record['child_pending'] = True
                    if failure == 'missing-terminal': record['helpers'].pop()
                    if failure.startswith('missing-'):
                        key = {'missing-qualification': 'qualified', 'missing-usability': 'evidence', 'missing-guard': 'guard'}.get(failure)
                        if key: record['remount_attempts'][-1].pop(key)
                    if failure == 'missing-bridge': record['bridge_returned'] = False
                    _native._persist(case['journal'], record)
                    commands = copy.deepcopy(case['state']['commands'])
                    guard = copy.deepcopy(case['guard'].return_value)
                    if failure == 'anchor': guard['generation'] += 1
                    if failure == 'unconsumed': guard['core_consumed'] = False
                    if failure == 'close-error': guard['parent_close_errno'] = errno.EIO
                    with patch.object(_native, 'guarded', return_value=guard) as guard_call:
                        if failure == 'busy': guard_call.side_effect = OSError(errno.EBUSY, 'held')
                        with patch('stallionfs._scan.mounts', side_effect=OSError(errno.EIO, 'unknown')) if failure == 'unknown' else nullcontext():
                            with self.assertRaises((OSError, core.StallionError)): case['command'](before['id'])
                            if failure == 'unknown':
                                self.assertIsNone(self.status(case, record)['next_action'])
                    self.assertEqual(case['bridge'].call_count, 1)
                    self.assertEqual(case['state']['commands'], commands)
                    if failure in ('nested', 'incompatible', 'child', 'missing-terminal', 'missing-qualification', 'missing-usability', 'missing-guard'):
                        self.assertIsNone(self.status(case, record)['next_action'])

    def test_completed_archives_never_restore_access(self):
        for action in ('snapshot', 'rollback'):
            with self.subTest(action=action), self.scenario(action) as case:
                record = case['command']()['native_operation']
                case['state']['rows'].clear()
                archive = case['path'] / 'native-operations' / record['id'] / 'record.json'
                data = archive.read_bytes()
                commands = copy.deepcopy(case['state']['commands'])
                guards = case['guard'].call_count
                result = case['command'](record['id'])
                self.assertFalse(result['current_status']['pending'])
                self.assertIsNone(result['current_status']['next_action'])
                self.assertEqual(case['state']['commands'], commands)
                self.assertEqual(case['guard'].call_count, guards)
                self.assertEqual(archive.read_bytes(), data)
                self.assertEqual(case['bridge'].call_count, 1)
