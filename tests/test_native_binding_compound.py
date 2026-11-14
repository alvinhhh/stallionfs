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

    def test_durable_publication_cuts_survive_repeated_terminal_remount_failures(self):
        seed = self.prepare()
        for action in ('snapshot', 'restore'):
            for cut in ('journal-evidence', 'archive-evidence', 'marker', 'final-evidence'):
                for failures in (1, 2):
                    with self.subTest(action=action, cut=cut, failures=failures), self.compound_controller_fixture() as state:
                        created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
                        path = Path(created['path']).parent.parent; metadata = core.read_json(path / 'meta.json')
                        if action == 'restore': self.store.snapshot(path.name, name='base', quiescent=True)
                        journal = self.store.root / 'journals' / (path.name + '.json')
                        def call(owner=None):
                            return recovery.compound_locked(self.store, path, metadata, action, 'base', operation_id=owner)
                        persist = _native._persist
                        def crash(destination, value):
                            result = persist(destination, value)
                            attempts = value.get('remount_attempts', [])
                            evidence = bool(attempts and 'evidence' in attempts[-1])
                            if ((cut == 'journal-evidence' and destination == journal and evidence)
                                    or (cut == 'archive-evidence' and destination.name == 'record.json' and evidence)
                                    or (cut == 'marker' and destination == path / 'native-mount.json' and value.get('state') == 'mounted')
                                    or (cut == 'final-evidence' and destination == journal and value.get('phase') == 'final-verified')):
                                raise SystemExit('after durable publication boundary')
                            return result
                        with patch.object(core, 'native_operation', wraps=core.native_operation) as bridge:
                            with patch.object(_native, '_persist', crash), patch.object(recovery, '_retain_compound_failure'):
                                with self.assertRaises(SystemExit): call()
                            first = core.read_json(journal)
                            marker = (path / 'native-mount.json').read_bytes()
                            self.assertTrue(first['remount_attempts'][0]['evidence']['usable'])
                            self.assertEqual(core.read_json(path / 'native-mount.json')['state'],
                                             'absent' if cut.endswith('-evidence') and cut != 'final-evidence' else 'mounted')
                            state['rows'].clear()
                            execute = _native.execute_owned
                            def fail(argv, record, save, directory, **kwargs):
                                if argv[0] == '/sbin/mount':
                                    record.update(argv=argv, child_pending=False, outcome='error', returncode=1,
                                                  pid=123, reaped=True, streams_eof=True, streams_durable=True, output_bytes=0,
                                                  stdout=str(directory / 'stdout'), stderr=str(directory / 'stderr'))
                                    save(); return record
                                return execute(argv, record, save, directory, **kwargs)
                            with patch.object(_native, 'execute_owned', side_effect=fail):
                                for _ in range(failures):
                                    with self.assertRaises(core.StallionError): call(first['id'])
                                    self.assertEqual(marker, (path / 'native-mount.json').read_bytes())
                                    _native.recover_install(self.store, path, metadata)
                            failed = core.read_json(journal)
                            self.assertEqual(len(failed['remount_attempts']), failures + 1)
                            final = call(first['id'])['native_operation']
                            self.assertEqual(bridge.call_count, 1)
                            self.assertEqual(final['outcome'], 'complete')
                            self.assertEqual(len(final['remount_attempts']), failures + 2)
                            self.assertEqual(final['remount_attempts'][:-1], failed['remount_attempts'])
                            self.assertEqual(final['helpers'][:len(failed['helpers'])], failed['helpers'])
                            for key, value in first['remount_attempts'][0].items():
                                self.assertEqual(final['remount_attempts'][0][key], value)
                            for key in ('id', 'workspace', 'operation', 'target', 'accepted_mount', 'native_image_result', 'committed_anchor'):
                                self.assertEqual(final[key], first[key])
                            self.assertFalse(journal.exists())
                            _native.recover_install(self.store, path, metadata)

    def test_historical_marker_and_unpublished_current_success_remain_distinct(self):
        seed = self.prepare()
        for action in ('snapshot', 'restore'):
            with self.subTest(action=action), self.compound_controller_fixture() as state:
                created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
                path = Path(created['path']).parent.parent; metadata = core.read_json(path / 'meta.json')
                if action == 'restore': self.store.snapshot(path.name, name='base', quiescent=True)
                journal = self.store.root / 'journals' / (path.name + '.json')
                marker_path = path / 'native-mount.json'; persist = _native._persist
                def call(owner=None):
                    return recovery.compound_locked(self.store, path, metadata, action, 'base', operation_id=owner)
                def first_cut(destination, value):
                    result = persist(destination, value)
                    if destination == marker_path and value.get('state') == 'mounted': raise SystemExit('published before final')
                    return result
                with patch.object(core, 'native_operation', wraps=core.native_operation) as bridge:
                    with patch.object(_native, '_persist', first_cut), patch.object(recovery, '_retain_compound_failure'):
                        with self.assertRaises(SystemExit): call()
                    first = core.read_json(journal); marker = marker_path.read_bytes(); state['rows'].clear()
                    execute = _native.execute_owned
                    def changed_mount(argv, *args, **kwargs):
                        result = execute(argv, *args, **kwargs)
                        if argv[0] == '/sbin/mount': state['rows'][str(path / 'volume')]['fsid'] = [73, 14]
                        return result
                    def second_cut(destination, value):
                        result = persist(destination, value)
                        if destination == journal and len(value.get('remount_attempts', [])) == 2 and 'evidence' in value['remount_attempts'][-1]:
                            raise SystemExit('durable new evidence before replacement marker')
                        return result
                    with patch.object(_native, 'execute_owned', side_effect=changed_mount), patch.object(_native, '_persist', second_cut), patch.object(recovery, '_retain_compound_failure'):
                        with self.assertRaises(SystemExit): call(first['id'])
                    current = core.read_json(journal)
                    self.assertEqual(marker_path.read_bytes(), marker)
                    self.assertNotEqual(current['remount_attempts'][0]['evidence']['observation'], current['remount_attempts'][1]['evidence']['observation'])
                    _native.recover_install(self.store, path, metadata)
                    for mutation in ('latest-helper', 'latest-guard', 'historical-helper', 'unrelated-marker'):
                        with self.subTest(mutation=mutation):
                            row = copy.deepcopy(current)
                            if mutation.endswith('-helper'):
                                index = 1 if mutation.startswith('latest') else 0
                                helper = next(h for h in row['helpers'] if h.get('stage') == 'remount' and h['attempt'] == index and h['label'] == 'mount')
                                helper.update(outcome='error', returncode=1)
                            elif mutation == 'latest-guard': row['remount_attempts'][1]['guard']['status'] = 0.0
                            else:
                                bad = core.read_json(marker_path); bad['observation']['fsid'] = [91, 22]
                                persist(marker_path, bad)
                            persist(journal, row)
                            before = {p: p.read_bytes() for p in self.store.root.rglob('*') if p.is_file()}
                            with patch.object(_native.Operation, 'command') as command:
                                with self.assertRaises(core.StallionError): _native.recover_install(self.store, path, metadata)
                                with self.assertRaises(core.StallionError): call(first['id'])
                                command.assert_not_called()
                            self.assertEqual(before, {p: p.read_bytes() for p in self.store.root.rglob('*') if p.is_file()})
                            marker_path.write_bytes(marker); persist(journal, current)
                    with patch.object(_native.Operation, 'command') as command:
                        final = call(first['id'])['native_operation']
                        command.assert_not_called()
                    self.assertEqual(bridge.call_count, 1)
                    self.assertEqual(final['remount_attempts'], current['remount_attempts'])
                    self.assertEqual(core.read_json(marker_path)['observation'], current['remount_attempts'][1]['evidence']['observation'])
                    self.assertFalse(journal.exists())
                    _native.recover_install(self.store, path, metadata)

    def test_historical_marker_survives_failed_remount_then_exact_retry(self):
        seed = self.prepare()
        for action in ('snapshot', 'restore'):
            with self.subTest(action=action), self.compound_controller_fixture() as state:
                created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
                path = Path(created['path']).parent.parent; metadata = core.read_json(path / 'meta.json')
                if action == 'restore': self.store.snapshot(path.name, name='base', quiescent=True)
                journal = self.store.root / 'journals' / (path.name + '.json')
                def call(owner=None):
                    return recovery.compound_locked(self.store, path, metadata, action, 'base', operation_id=owner)
                unlink = Path.unlink
                def stop(candidate, *args, **kwargs):
                    if candidate == journal: raise SystemExit('before journal removal')
                    return unlink(candidate, *args, **kwargs)
                with patch.object(core, 'native_operation', wraps=core.native_operation) as bridge:
                    with patch.object(Path, 'unlink', stop), patch.object(recovery, '_retain_compound_failure'):
                        with self.assertRaises(SystemExit): call()
                    first = core.read_json(journal); marker = (path / 'native-mount.json').read_bytes()
                    state['rows'].clear()
                    execute = _native.execute_owned
                    def fail(argv, record, persist, directory, **kwargs):
                        if argv[0] == '/sbin/mount':
                            record.update(argv=argv, child_pending=False, outcome='error', returncode=1,
                                          pid=123, reaped=True, streams_eof=True, streams_durable=True, output_bytes=0,
                                          stdout=str(directory / 'stdout'), stderr=str(directory / 'stderr'))
                            persist(); return record
                        return execute(argv, record, persist, directory, **kwargs)
                    with patch.object(_native, 'execute_owned', side_effect=fail):
                        with self.assertRaises(core.StallionError): call(first['id'])
                    failed = core.read_json(journal)
                    self.assertEqual(failed['remount_attempts'][0]['final_evidence'], first['final_evidence'])
                    self.assertEqual((path / 'native-mount.json').read_bytes(), marker)
                    # An earlier success without its actual reset lineage cannot
                    # substitute for the marker's historical producer.
                    for change in ('missing-lineage', 'malformed-historical-helper'):
                        with self.subTest(change=change):
                            bad = copy.deepcopy(failed)
                            if change == 'missing-lineage': bad['remount_attempts'][0].pop('final_evidence')
                            else:
                                helper = next(h for h in bad['helpers'] if h.get('stage') == 'remount' and h['attempt'] == 0 and h['label'] == 'mount')
                                helper.update(outcome='error', returncode=1)
                            _native._persist(journal, bad)
                            before = {p: p.read_bytes() for p in self.store.root.rglob('*') if p.is_file()}
                            with patch.object(_native.Operation, 'command') as command:
                                with self.assertRaises(core.StallionError): call(first['id'])
                                command.assert_not_called()
                            self.assertEqual(before, {p: p.read_bytes() for p in self.store.root.rglob('*') if p.is_file()})
                    _native._persist(journal, failed)
                    _native.recover_install(self.store, path, metadata)
                    final = call(first['id'])['native_operation']
                    self.assertEqual(bridge.call_count, 1)
                    self.assertEqual(final['outcome'], 'complete')
                    self.assertEqual(len(final['remount_attempts']), 3)
                    self.assertEqual(final['remount_attempts'][:2], failed['remount_attempts'])
                    self.assertEqual(final['native_image_result'], first['native_image_result'])
                    self.assertFalse(journal.exists())
                    _native.recover_install(self.store, path, metadata)

    def test_public_compound_publication_contradictions_preserve_owner(self):
        seed = self.prepare()
        mutations = ('mount', 'verify-package', 'discover', 'response-error', 'response-float',
                     'response-missing', 'guard-float', 'guard-bool', 'guard-consumed', 'observation-bool')
        for action in ('snapshot', 'restore'):
            for pending in (False, True):
                with self.subTest(action=action, pending=pending), self.compound_controller_fixture():
                    created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
                    path = Path(created['path']).parent.parent; metadata = core.read_json(path / 'meta.json')
                    if action == 'restore': self.store.snapshot(path.name, name='base', quiescent=True)
                    def call(owner=None):
                        return recovery.compound_locked(self.store, path, metadata, action, 'base', operation_id=owner)
                    journal = self.store.root / 'journals' / (path.name + '.json')
                    if pending:
                        with patch.object(_native.Operation, 'finish', side_effect=OSError('finish boundary')):
                            with self.assertRaises(OSError): call()
                        original = core.read_json(journal)
                    else: original = call()['native_operation']
                    archive = path / 'native-operations' / original['id'] / 'record.json'
                    destination = journal if pending else archive
                    _native.recover_install(self.store, path, metadata)
                    for mutation in mutations:
                        with self.subTest(mutation=mutation):
                            row = copy.deepcopy(original); attempt = row['remount_attempts'][-1]
                            if mutation in ('mount', 'verify-package', 'discover'):
                                helper = next(h for h in reversed(row['helpers']) if h.get('stage') == 'remount' and h['label'] == mutation)
                                helper.update(outcome='error', returncode=1)
                            elif mutation == 'response-error': attempt['response'] = {'returncode': 1, 'outcome': 'error'}
                            elif mutation == 'response-float': attempt['response']['returncode'] = 0.0
                            elif mutation == 'response-missing': attempt.pop('response')
                            elif mutation == 'guard-float': attempt['guard']['status'] = 0.0
                            elif mutation == 'guard-bool': attempt['guard']['status'] = False
                            elif mutation == 'guard-consumed': attempt['guard']['core_consumed'] = False
                            else: attempt['evidence']['observation']['owner'] = True
                            _native._persist(destination, row)
                            before = {p: p.read_bytes() for p in self.store.root.rglob('*') if p.is_file()}
                            with patch.object(core, 'native_operation') as bridge, patch.object(_native.Operation, 'command') as command:
                                with self.assertRaises(core.StallionError): _native.recover_install(self.store, path, metadata)
                                with self.assertRaises(core.StallionError): call(original['id'])
                                with self.assertRaises(core.StallionError): _native.mount_locked(self.store, path, metadata)
                                with self.assertRaises(core.StallionError): recovery.catalog_locked(self.store, path, metadata, 'restore', 'base')
                                bridge.assert_not_called(); command.assert_not_called()
                            self.assertEqual(before, {p: p.read_bytes() for p in self.store.root.rglob('*') if p.is_file()})
                            _native._persist(destination, original)
                            _native.recover_install(self.store, path, metadata)
                    with patch.object(core, 'native_operation') as bridge, patch.object(_native.Operation, 'command') as command:
                        self.assertEqual(call(original['id'])['native_operation']['outcome'], 'complete')
                        bridge.assert_not_called(); command.assert_not_called()
                    self.assertFalse(journal.exists())
                    _native.recover_install(self.store, path, metadata)

    def test_offline_catalog_keeps_actual_lifecycle_marker_owner(self):
        from stallionfs import _native_interval as interval
        seed = self.prepare()
        for kind in ('ordinary', 'legacy', 'compound'):
            with self.subTest(kind=kind), self.compound_controller_fixture():
                created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
                workspace = created['id']; path = Path(created['path']).parent.parent
                self.store.unmount(workspace)
                metadata = core.read_json(path / 'meta.json')
                shutil.rmtree(path / 'volume/repo')
                if kind == 'legacy':
                    for location in [path / 'native-mount.json', *path.glob('native-operations/*/record.json')]:
                        row = core.read_json(location)
                        for field in interval.FIELDS: row.pop(field, None)
                        _native._persist(location, row)
                elif kind == 'compound':
                    result = recovery.compound_locked(self.store, path, metadata, 'snapshot', 'offline')
                    self.assertFalse(result['native_operation']['originally_mounted'])
                marker = (path / 'native-mount.json').read_bytes()
                owner_id = core.read_json(path / 'native-mount.json')['operation']
                owner = path / 'native-operations' / owner_id / 'record.json'
                owner_bytes = owner.read_bytes()
                for action in ('snapshot', 'restore', 'snapshots'):
                    result = recovery.catalog_locked(self.store, path, metadata, action, 'catalog-base')
                    if action != 'snapshots':
                        record = result['native_operation']
                        binding.completed_operation(record, path, metadata, record['id'])
                        self.assertNotEqual(owner_id, record['id'])
                    self.assertEqual(marker, (path / 'native-mount.json').read_bytes())
                    self.assertEqual(owner_bytes, owner.read_bytes())
                    _native.recover_install(self.store, path, metadata)

    def test_public_compound_marker_requires_its_guard_and_remount_evidence(self):
        seed = self.prepare()
        for mounted in (False, True):
            with self.subTest(mounted=mounted), self.compound_controller_fixture():
                created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
                workspace = created['id']; path = Path(created['path']).parent.parent
                metadata = core.read_json(path / 'meta.json')
                if not mounted:
                    self.store.unmount(workspace); shutil.rmtree(path / 'volume/repo')
                result = recovery.compound_locked(self.store, path, metadata, 'snapshot', 'control')
                record = result['native_operation']
                location = path / 'native-mount.json'; original = core.read_json(location)
                archive = path / 'native-operations' / record['id'] / 'record.json'
                _native.recover_install(self.store, path, metadata)
                for change in ('marker', 'owner-action', 'owner-evidence', 'owner-child'):
                    with self.subTest(change=change):
                        marker = copy.deepcopy(original); row = copy.deepcopy(record)
                        if change == 'marker':
                            if mounted: marker['observation']['fsid'][0] += 1
                            else: marker['current_guard']['generation'] += 1
                        elif change == 'owner-action': row['operation'] = 'native-snapshot'
                        elif change == 'owner-child': row['child_pending'] = True
                        elif mounted: row['remount_attempts'][-1]['evidence']['usable'] = False
                        else: row['offline_admission']['generation'] += 1
                        _native._persist(location, marker); _native._persist(archive, row)
                        before = {p: p.read_bytes() for p in self.store.root.rglob('*') if p.is_file()}
                        with patch.object(core, 'native_operation') as bridge, patch.object(_native.Operation, 'command') as command:
                            with self.assertRaises(core.StallionError): _native.recover_install(self.store, path, metadata)
                            with self.assertRaises(core.StallionError): recovery.catalog_locked(self.store, path, metadata, 'restore', 'control')
                            bridge.assert_not_called(); command.assert_not_called()
                        self.assertEqual(before, {p: p.read_bytes() for p in self.store.root.rglob('*') if p.is_file()})
                _native._persist(location, original); _native._persist(archive, record)
                _native.recover_install(self.store, path, metadata)

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
                    _native.recover_install(self.store, path, metadata)
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

    def test_recovered_ordinary_interval_closes_at_compound_input(self):
        seed = self.prepare()
        with self.compound_controller_fixture() as state:
            created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = created['id']; path = Path(created['path']).parent.parent
            self.store.unmount(workspace)
            metadata = core.read_json(path / 'meta.json')
            execute = _native.execute_owned
            def fail(argv, record, persist, directory, **kwargs):
                if argv[0] == '/sbin/mount':
                    record.update(argv=argv, child_pending=False, outcome='error', returncode=1,
                                  pid=123, reaped=True, streams_eof=True, streams_durable=True, output_bytes=0,
                                  stdout=str(directory / 'stdout'), stderr=str(directory / 'stderr'))
                    persist(); return record
                return execute(argv, record, persist, directory, **kwargs)
            with patch.object(_native, 'execute_owned', side_effect=fail):
                with self.assertRaises(core.StallionError): _native.mount_locked(self.store, path, metadata)
            failed = {p:p.read_bytes() for p in path.glob('native-operations/*/record.json')}
            _native.mount_locked(self.store, path, metadata)
            incoming = core.read_json(path / 'native-mount.json')['ordinary_interval']
            result = self.store.snapshot(workspace, name='recovered', quiescent=True)['native_operation']
            closes = [a['input_interval_close'] for a in result['unmount_attempts'] if 'input_interval_close' in a]
            self.assertEqual(len(closes), 1)
            self.assertEqual(closes[0]['ordinary_interval'], incoming)
            self.assertNotIn('ordinary_interval', core.read_json(path / 'native-mount.json'))
            _native.recover_install(self.store, path, core.read_json(path / 'meta.json'))
            self.store.unmount(workspace)
            shutil.rmtree(path / 'volume/repo')
            (path / binding.NAME).unlink()
            _native.recover_install(self.store, path, core.read_json(path / 'meta.json'))
            self.assertEqual(failed, {p:p.read_bytes() for p in failed})


if __name__ == '__main__': unittest.main()
