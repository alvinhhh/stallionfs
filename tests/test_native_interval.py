"""Owned public controller interval and persistence boundary regressions."""
import contextlib
import copy
import unittest
from unittest.mock import patch
from stallionfs import core, _native, _native_binding as binding, _native_interval as interval
from test_native_binding_chains import OrdinaryChains


@contextlib.contextmanager
def owned():
    case = OrdinaryChains(); case.setUp()
    try:
        yield case
    finally:
        case.doCleanups()


def malformed_markers(original):
    """Literal wire mutations shared by public admission regressions."""
    for value in (True, False, 1.0, 0.0, 2, None, '1', {}, []):
        marker = copy.deepcopy(original)
        marker['lifecycle_version'] = value
        yield 'version-' + repr(value), marker
    marker = copy.deepcopy(original)
    marker.pop('lifecycle_version', None)
    yield 'missing-version', marker
    for value in ({}, None, False):
        marker = copy.deepcopy(original)
        marker['interval_seed'] = value
        yield 'seed-' + repr(value), marker
    for value in (None, {}, True, 1, []):
        marker = copy.deepcopy(original)
        marker['ordinary_interval'] = value
        yield 'token-' + repr(value), marker
    for fields in ({'interval_seed': None}, {'ordinary_interval': None},
                   {'lifecycle_version': None}, {'lifecycle_version': True},
                   {'lifecycle_version': 1.0}, {'lifecycle_version': 1, 'interval_seed': None}):
        marker = {k: copy.deepcopy(v) for k, v in original.items() if k not in interval.FIELDS}
        marker.update(fields)
        yield 'partial-' + repr(fields), marker


class Intervals(unittest.TestCase):
    def test_public_token_free_owner_classes_refuse_incompatible_bodies(self):
        from stallionfs import _native_recovery as recovery
        from test_native_reconcile import legacy, run
        for reconciled in (False, True):
            for translated in (False, True):
                for mounted in (False, True):
                    with self.subTest(reconciled=reconciled, translated=translated, mounted=mounted), owned() as t:
                        if reconciled:
                            legacy(t); self.assertEqual(run(t)['status'], 'current-image-reconciled')
                        with t.h.h.renumber() if translated else contextlib.nullcontext():
                            if mounted: t.mount()
                            else: t.mounted = True; t.unmount()
                            location = t.path / 'native-mount.json'; marker = t.f.read(location)
                            archive = t.path / 'native-operations' / marker['operation'] / 'record.json'
                            owner = t.f.read(archive)
                            for field in interval.FIELDS:
                                marker.pop(field, None); owner.pop(field, None)
                            t.f.save(location, marker); t.f.save(archive, owner)
                            _native.recover_install(t.store, t.path, t.meta)
                            actions = ('native-unknown', 'native-unmount' if mounted else 'native-mount') + recovery.ACTIONS + recovery.COMPOUND
                            for action in actions:
                                with self.subTest(action=action):
                                    t.f.save(archive, dict(owner, operation=action))
                                    before = {p: p.read_bytes() for p in t.store.root.rglob('*') if p.is_file()}
                                    with patch.object(_native.Operation, 'command') as command, patch.object(core, 'native_operation') as bridge:
                                        with self.assertRaises(core.StallionError): _native.recover_install(t.store, t.path, t.meta)
                                        with self.assertRaises(core.StallionError): t.mount()
                                        with self.assertRaises(core.StallionError): recovery.catalog_locked(t.store, t.path, t.meta, 'restore', 'control')
                                        command.assert_not_called(); bridge.assert_not_called()
                                    self.assertEqual(before, {p: p.read_bytes() for p in t.store.root.rglob('*') if p.is_file()})
                            t.f.save(archive, owner)
                            _native.recover_install(t.store, t.path, t.meta)
                            if not mounted:
                                with patch.object(core, 'native_operation', side_effect=RuntimeError('owned bridge sentinel')) as bridge:
                                    with self.assertRaisesRegex(RuntimeError, 'owned bridge sentinel'):
                                        recovery.catalog_locked(t.store, t.path, t.meta, 'restore', 'control')
                                    self.assertEqual(bridge.call_count, 1)

    def test_public_legacy_owner_requires_terminal_guard_and_typed_identity(self):
        from stallionfs import _native_recovery as recovery
        for mounted in (False, True):
            with self.subTest(mounted=mounted), owned() as t:
                if mounted: t.mount()
                else: t.mounted = True; t.unmount()
                location = t.path / 'native-mount.json'; marker = t.f.read(location)
                archive = t.path / 'native-operations' / marker['operation'] / 'record.json'
                owner = t.f.read(archive)
                for field in interval.FIELDS:
                    marker.pop(field, None); owner.pop(field, None)
                t.f.save(location, marker); t.f.save(archive, owner)
                _native.recover_install(t.store, t.path, t.meta)
                for change in ('child', 'outcome', 'guard', 'identity', 'helper'):
                    with self.subTest(change=change):
                        row = copy.deepcopy(owner)
                        if change == 'child': row['child_pending'] = 0
                        elif change == 'outcome': row['outcome'] = 'prepared'
                        elif change == 'guard': row['current_guard']['core_consumed'] = False
                        elif change == 'identity': row['target']['file'][1] = float(row['target']['file'][1])
                        else: row['helpers'][-1]['returncode'] = True
                        t.f.save(archive, row)
                        before = {p: p.read_bytes() for p in t.store.root.rglob('*') if p.is_file()}
                        with patch.object(core, 'native_operation') as bridge:
                            with self.assertRaises(core.StallionError): _native.recover_install(t.store, t.path, t.meta)
                            with self.assertRaises(core.StallionError): recovery.catalog_locked(t.store, t.path, t.meta, 'restore', 'control')
                            bridge.assert_not_called()
                        self.assertEqual(before, {p: p.read_bytes() for p in t.store.root.rglob('*') if p.is_file()})
                t.f.save(archive, owner)
                _native.recover_install(t.store, t.path, t.meta)

    def test_public_marker_owner_deletions_refuse_readback_and_dispatch(self):
        from test_native_reconcile import legacy, run
        for reconciled in (False, True):
            for translated in (False, True):
                for mounted in (False, True):
                    with self.subTest(reconciled=reconciled, translated=translated, mounted=mounted), owned() as t:
                        if reconciled:
                            legacy(t)
                            self.assertEqual(run(t)['status'], 'current-image-reconciled')
                        with t.h.h.renumber() if translated else contextlib.nullcontext():
                            t.mount(True); t.mount()
                            if not mounted: t.unmount()
                            location = t.path / 'native-mount.json'; original = t.f.read(location)
                            _native.recover_install(t.store, t.path, t.meta)
                            for fields in (('ordinary_interval',), ('ordinary_interval', 'lifecycle_version')):
                                with self.subTest(deleted=fields):
                                    marker = copy.deepcopy(original)
                                    for field in fields: marker.pop(field)
                                    t.f.save(location, marker)
                                    before = {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()}
                                    with self.assertRaises(core.StallionError): _native.recover_install(t.store, t.path, t.meta)
                                    with patch.object(_native.Operation, 'command', side_effect=AssertionError('unexpected dispatch')) as command:
                                        with self.assertRaises(core.StallionError): t.mount()
                                        command.assert_not_called()
                                    self.assertEqual(before, {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()})
                            t.f.save(location, original)
                            _native.recover_install(t.store, t.path, t.meta)
                            if mounted:
                                with patch.object(_native, '_usable', return_value=str(t.path / 'volume/repo')), \
                                        patch.object(_native.Operation, 'command') as command:
                                    t.mount()
                                    command.assert_not_called()
                                t.unmount()

    def test_public_marker_owner_missing_and_mismatched_records_refuse(self):
        for change in ('missing', 'id', 'workspace', 'target', 'guard', 'version', 'origin-seed', 'origin-token'):
            with self.subTest(change=change), owned() as t:
                t.mount(True); t.mount(); t.unmount()
                marker = t.f.read(t.path / 'native-mount.json')
                location = t.path / 'native-operations' / marker['operation'] / 'record.json'
                if change.startswith('origin-'):
                    location = t.path / 'native-operations' / marker['ordinary_interval']['mount_operation'] / 'record.json'
                if change == 'missing':
                    location.unlink(); location.parent.rmdir()
                else:
                    row = t.f.read(location)
                    if change == 'id': row['id'] = 'f' * 32
                    elif change == 'workspace': row['workspace'] = 'f' * 32
                    elif change == 'target': row['target']['file'][1] += 1
                    elif change == 'guard': row['current_guard']['generation'] += 1
                    elif change == 'version': row['lifecycle_version'] = True
                    elif change == 'origin-seed': row.pop('interval_seed')
                    elif change == 'origin-token': row.pop('ordinary_interval')
                    t.f.save(location, row)
                before = {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()}
                with self.assertRaises(core.StallionError): _native.recover_install(t.store, t.path, t.meta)
                with patch.object(_native.Operation, 'command') as command:
                    with self.assertRaises(core.StallionError): t.mount()
                    command.assert_not_called()
                self.assertEqual(before, {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()})

    def test_public_pending_marker_owners_keep_real_recovery(self):
        from test_native_reconcile import legacy, run
        for reconciled in (False, True):
            for translated in (False, True):
                for boundary in ('mount-before-marker', 'mount-finish', 'close-before-marker', 'close-finish'):
                    with self.subTest(reconciled=reconciled, translated=translated, boundary=boundary), owned() as t:
                        if reconciled:
                            legacy(t)
                            self.assertEqual(run(t)['status'], 'current-image-reconciled')
                        with t.h.h.renumber() if translated else contextlib.nullcontext():
                            if boundary == 'mount-before-marker':
                                t.fail_usable = True; t.mount(); t.fail_usable = False
                            elif boundary == 'mount-finish':
                                with patch.object(_native.Operation, 'finish', side_effect=OSError('owned finish boundary')):
                                    with self.assertRaises(OSError): t.mount()
                            else:
                                t.mount()
                                persist = _native._persist
                                def saved(path, row):
                                    if path == t.path / 'native-mount.json' and row.get('state') == 'absent':
                                        raise OSError('owned pre-marker boundary')
                                    return persist(path, row)
                                with patch.object(_native, '_persist', saved) if boundary == 'close-before-marker' else \
                                        patch.object(_native.Operation, 'finish', side_effect=OSError('owned finish boundary')):
                                    with self.assertRaises(OSError): t.unmount()
                            before = {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()}
                            _native.recover_install(t.store, t.path, t.meta)
                            self.assertEqual(before, {p: p.read_bytes() for p in before})
                            t.unmount()
                            _native.recover_install(t.store, t.path, t.meta)

    def test_public_legacy_and_token_free_owner_controls(self):
        from test_native_reconcile import legacy, run
        for reconciled in (False, True):
            for translated in (False, True):
                for kind in ('unmount-only', 'legacy-unmount', 'legacy-mounted'):
                    with self.subTest(reconciled=reconciled, translated=translated, kind=kind), owned() as t:
                        if reconciled:
                            legacy(t)
                            self.assertEqual(run(t)['status'], 'current-image-reconciled')
                        with t.h.h.renumber() if translated else contextlib.nullcontext():
                            if kind == 'legacy-mounted': t.mount()
                            else: t.mounted = True; t.unmount()
                            location = t.path / 'native-mount.json'; marker = t.f.read(location)
                            if kind.startswith('legacy'):
                                archive = t.path / 'native-operations' / marker['operation'] / 'record.json'
                                row = t.f.read(archive)
                                for field in interval.FIELDS:
                                    marker.pop(field, None); row.pop(field, None)
                                t.f.save(location, marker); t.f.save(archive, row)
                            before = {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()}
                            _native.recover_install(t.store, t.path, t.meta)
                            self.assertEqual(before, {p: p.read_bytes() for p in before})
                            if kind == 'legacy-mounted':
                                with patch.object(_native, '_usable', return_value=str(t.path / 'volume/repo')), \
                                        patch.object(_native.Operation, 'command') as command:
                                    t.mount(); command.assert_not_called()
                                t.unmount()
                            else:
                                t.mount(); t.unmount()
                            _native.recover_install(t.store, t.path, t.meta)

    def test_public_adoption_rejects_malformed_current_marker(self):
        with owned() as t:
            t.mount(True); t.mount(); t.unmount()
            location = t.path / 'native-mount.json'
            original = t.f.read(location)
            t.h.h.sidecar.unlink()
            variants = list(malformed_markers(original))
            for fields in (('ordinary_interval',), ('lifecycle_version', 'ordinary_interval')):
                marker = copy.deepcopy(original)
                for field in fields: marker.pop(field)
                variants.append(('deleted-' + repr(fields), marker))
            for name, marker in variants:
                with self.subTest(case=name):
                    t.f.save(location, marker)
                    before = {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()}
                    self.assertEqual(t.h.h.adopt()['status'], 'blocked')
                    self.assertFalse(t.h.h.sidecar.exists())
                    self.assertEqual(before, {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()})
            t.f.save(location, original)
            self.assertEqual(t.h.h.adopt()['status'], 'current-image-adopted')

    def test_public_binding_readback_rejects_malformed_current_marker(self):
        with owned() as t:
            t.mount(True); t.mount(); t.unmount()
            location = t.path / 'native-mount.json'; original = t.f.read(location)
            for name, marker in malformed_markers(original):
                for translated in (False, True):
                    with self.subTest(case=name, translated=translated):
                        t.f.save(location, marker)
                        before = {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()}
                        with t.h.h.renumber() if translated else contextlib.nullcontext():
                            with self.assertRaises(core.StallionError): _native.recover_install(t.store, t.path, t.meta)
                            with patch.object(_native.Operation, 'command') as command:
                                with self.assertRaises(core.StallionError): t.mount()
                                command.assert_not_called()
                        self.assertEqual(before, {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()})
            t.f.save(location, original)
            _native.recover_install(t.store, t.path, t.meta)

    def test_public_marker_schema_preserves_token_free_unmount(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy), owned() as t:
                t.mounted = True; t.unmount()
                location = t.path / 'native-mount.json'; marker = t.f.read(location)
                self.assertNotIn('ordinary_interval', marker)
                if legacy:
                    marker.pop('lifecycle_version')
                    t.f.save(location, marker)
                    archived = t.path / 'native-operations' / marker['operation'] / 'record.json'
                    row = t.f.read(archived)
                    row.pop('lifecycle_version')
                    t.f.save(archived, row)
                else:
                    self.assertIs(type(marker['lifecycle_version']), int)
                    self.assertEqual(marker['lifecycle_version'], 1)
                t.h.h.sidecar.unlink()
                before = {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()}
                self.assertEqual(t.h.h.adopt()['status'], 'current-image-adopted')
                _native.recover_install(t.store, t.path, t.meta)
                self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_two_recoveries_and_later_marker(self):
        with owned() as t:
            for _ in range(2):
                t.mount(True); t.mount(); t.unmount()
            t.mount(); t.unmount()
            rows = t.rows(); index = interval.Index(rows, t.path, t.meta)
            self.assertEqual(len(index.origins), 3)
            self.assertFalse(index.open)
            t.preserve_admit()
            t.public_result('current-image-adopted')

    def test_token_capture_precedes_helper_and_close_precedes_marker(self):
        with owned() as t:
            t.mount(True); t.mount()
            command = _native.Operation.command
            def checked(op, label, argv):
                if label == 'unmount':
                    self.assertEqual(t.f.read(op.journal), op.record)
                    self.assertEqual(t.f.read(op.directory / 'record.json'), op.record)
                    self.assertIn('ordinary_interval', op.record)
                return command(op, label, argv)
            persist = _native._persist
            def saved(path, row):
                if path == t.path / 'native-mount.json' and row['state'] == 'absent':
                    archived = t.f.read(t.path / 'native-operations' / row['operation'] / 'record.json')
                    self.assertEqual(archived['current_guard'], row['current_guard'])
                    self.assertIsNone(archived['observed_mount'])
                return persist(path, row)
            with patch.object(_native.Operation, 'command', checked), patch.object(_native, '_persist', saved):
                t.unmount()
            t.public_result('current-image-adopted')

    def test_stale_mounted_marker_cannot_capture_closed_origin(self):
        with owned() as t:
            t.mount(); stale = t.f.read(t.path / 'native-mount.json'); t.unmount()
            t.mount(); t.f.save(t.path / 'native-mount.json', stale)
            before = t.rows()
            with patch.object(_native.Operation, 'command') as command:
                with self.assertRaises(core.StallionError): t.unmount()
                command.assert_not_called()
            self.assertEqual(before, t.rows())

    def test_lifecycle_malformed_and_deleted_tokens_refuse(self):
        for field, value in [('lifecycle_version', True), ('lifecycle_version', 1.0),
                             ('lifecycle_version', 2), ('ordinary_interval', None),
                             ('ordinary_interval', {}), ('interval_seed', None)]:
            with self.subTest(field=field, value=value), owned() as t:
                t.mount(True); t.mount(); t.unmount()
                row = next(r for r in t.rows().values() if r['operation'] == 'native-mount' and r['outcome'] == 'complete')
                row[field] = value
                t.f.save(t.path / 'native-operations' / row['id'] / 'record.json', row)
                t.public_result('blocked')
        with owned() as t:
            t.mount(); t.unmount()
            row = next(r for r in t.rows().values() if r['operation'] == 'native-mount')
            del row['ordinary_interval']
            t.f.save(t.path / 'native-operations' / row['id'] / 'record.json', row)
            t.public_result('blocked')

    def test_close_marker_failure_retries_actual_pending_owner(self):
        for point in ('before-marker', 'after-marker', 'finish'):
            with self.subTest(point=point), owned() as t:
                t.mount(True); t.mount()
                original = _native._persist
                def fail(path, value):
                    if path == t.path / 'native-mount.json' and value['state'] == 'absent':
                        if point == 'after-marker': original(path, value)
                        if point != 'finish': raise OSError('owned marker fault')
                    return original(path, value)
                with patch.object(_native, '_persist', fail):
                    with patch.object(t.store, '_open', side_effect=OSError('owned finish boundary')) if point == 'finish' else contextlib.nullcontext():
                        with self.assertRaises(OSError): t.unmount()
                t.unmount()
                t.public_result('current-image-adopted')

    def test_duplicate_close_and_competing_origin_refuse(self):
        with owned() as t:
            t.mount(); t.unmount()
            close = next(r for r in t.rows().values() if r['operation'] == 'native-unmount')
            extra = copy.deepcopy(close); extra['id'] = 'f' * 32
            directory = t.path / 'native-operations' / extra['id']; directory.mkdir(mode=0o700)
            t.f.save(directory / 'record.json', extra)
            t.public_result('blocked')

    def test_seed_and_capture_persistence_faults_launch_no_helper(self):
        for action in ('mount', 'unmount'):
            for which in ('archive', 'journal'):
                with self.subTest(action=action, which=which), owned() as t:
                    if action == 'unmount': t.mount()
                    persist = _native._persist
                    def fault(path, record):
                        match = path.name == 'record.json' if which == 'archive' else path.parent.name == 'journals'
                        if match and record.get('operation') == 'native-' + action and record.get('outcome') == 'prepared':
                            raise OSError('owned initial durability fault')
                        return persist(path, record)
                    with patch.object(_native, '_persist', fault), patch.object(_native.Operation, 'command') as command:
                        with self.assertRaises(OSError): getattr(t, action)()
                        command.assert_not_called()

    def test_positive_observation_is_durable_before_readiness(self):
        with owned() as t:
            usable = t.usable
            def checked(store, path, metadata, **kwargs):
                operation = kwargs['operation']
                self.assertEqual(t.f.read(operation.directory / 'record.json'), operation.record)
                self.assertEqual(t.f.read(operation.journal), operation.record)
                self.assertIn('ordinary_interval', operation.record)
                self.assertIsNotNone(operation.record['observed_mount'])
                return usable(store, path, metadata, **kwargs)
            with patch.object(_native, '_usable', checked):
                t.fail_usable = True; t.mount()
            failed = copy.deepcopy(t.rows())
            t.unmount()
            self.assertEqual(failed, {n:r for n,r in t.rows().items() if n in failed})
            t.public_result('current-image-adopted')

    def test_torn_positive_owner_refuses_before_unmount(self):
        with owned() as t:
            t.fail_usable = True; t.mount()
            journal = t.store.root / 'journals' / (t.path.name + '.json')
            row = t.f.read(journal); row['ordinary_interval']['observation']['fsid'][0] += 1
            t.f.save(journal, row)
            with patch.object(_native.Operation, 'command') as command:
                with self.assertRaises(core.StallionError): t.unmount()
                command.assert_not_called()

    def test_linear_index_and_shuffled_history(self):
        with owned() as t:
            for _ in range(24): t.mount(True)
            t.mount(); t.unmount()
            rows = t.rows()
            member = binding._chain_member
            with patch.object(binding, '_chain_member', wraps=member) as calls:
                t.validate(dict(reversed(list(rows.items()))))
                self.assertLessEqual(calls.call_count, len(rows) * 3)

    def test_exact_token_schema_and_authority(self):
        mutations = [('version', True), ('version', 1.0), ('version', 2),
                     ('mount_operation', False), ('mount_operation', 'f' * 32),
                     ('workspace', 'f' * 32), ('target', {}), ('observation', {})]
        mutations += [('observation.' + key, value) for key, value in
                      [('flags', False), ('owner', 1.0), ('fsid', [True, 22]),
                       ('fsid', [11, 23]), ('path', '/inert'), ('filesystem', 'other')]]
        for field, value in mutations:
            with self.subTest(field=field, value=value), owned() as t:
                t.mount(); t.unmount()
                row = next(r for r in t.rows().values() if r['operation'] == 'native-mount')
                if '.' in field: row['ordinary_interval']['observation'][field.split('.')[1]] = value
                else: row['ordinary_interval'][field] = value
                t.f.save(t.path / 'native-operations' / row['id'] / 'record.json', row)
                t.public_result('blocked')

    def test_open_origin_prevents_another_mount_launch(self):
        with owned() as t:
            t.mount(); t.mounted = False
            with patch.object(_native.Operation, 'command') as command:
                with self.assertRaises(core.StallionError): t.mount()
                command.assert_not_called()

    def test_missing_guard_and_finish_sync_faults(self):
        for point in ('guard', 'journal-sync'):
            with self.subTest(point=point), owned() as t:
                t.mount(True); t.mount()
                original = core.sync_directory
                fired = []
                def sync(path):
                    journal = t.store.root / 'journals' / (t.path.name + '.json')
                    if point == 'journal-sync' and path == journal.parent and not journal.exists() and not fired:
                        fired.append(True); raise OSError('owned journal directory sync fault')
                    return original(path)
                with patch.object(core, 'sync_directory', sync):
                    with patch.object(_native, '_guard_current', side_effect=OSError('owned close fault')) if point == 'guard' else contextlib.nullcontext():
                        with self.assertRaises(OSError): t.unmount()
                if point == 'guard':
                    with self.assertRaises(core.StallionError): t.unmount()
                else:
                    self.assertTrue(fired)
                    t.unmount()
                    t.public_result('current-image-adopted')

    def test_competing_positive_origin_refuses_capture(self):
        with owned() as t:
            t.mount()
            row = copy.deepcopy(next(iter(t.rows().values())))
            row['id'] = 'f' * 32
            row['interval_seed']['mount_operation'] = row['id']
            row['ordinary_interval']['mount_operation'] = row['id']
            directory = t.path / 'native-operations' / row['id']; directory.mkdir(mode=0o700)
            t.f.save(directory / 'record.json', row)
            with patch.object(_native.Operation, 'command') as command:
                with self.assertRaises(core.StallionError): t.unmount()
                command.assert_not_called()

    def test_failed_mount_helper_with_positive_observation_has_owned_interval(self):
        with owned() as t:
            command = _native.Operation.command
            def mounted_error(op, label, argv):
                result = command(op, label, argv)
                if label == 'mount': t.mounted = True
                return result
            with patch.object(_native.Operation, 'command', mounted_error): t.mount(True)
            row = next(iter(t.rows().values()))
            self.assertEqual(row['outcome'], 'incomplete')
            self.assertEqual(row['ordinary_interval']['mount_operation'], row['id'])
            t.unmount()
            t.public_result('current-image-adopted')

    def test_positive_observation_archive_and_journal_fault_snapshots(self):
        for which in ('archive', 'journal'):
            with self.subTest(which=which), owned() as t:
                persist = _native._persist
                def fault(path, row):
                    match = path.name == 'record.json' if which == 'archive' else path.parent.name == 'journals'
                    if match and row.get('operation') == 'native-mount' and 'ordinary_interval' in row:
                        raise OSError('owned observation durability fault')
                    return persist(path, row)
                with patch.object(_native, '_persist', fault):
                    with self.assertRaises(OSError): t.mount()
                before = t.rows()
                if which == 'journal':
                    with patch.object(_native.Operation, 'command') as command:
                        with self.assertRaises(core.StallionError): t.unmount()
                        command.assert_not_called()
                else:
                    t.unmount()
                    self.assertNotIn('ordinary_interval', next(r for r in t.rows().values() if r['operation'] == 'native-unmount'))
                self.assertEqual(before, {n:r for n,r in t.rows().items() if n in before})
                t.public_result('blocked')

    def test_mounted_marker_before_finish_is_recovered_by_pending_owner(self):
        with owned() as t:
            with patch.object(_native.Operation, 'finish', side_effect=OSError('owned before mount finish')):
                with self.assertRaises(OSError): t.mount()
            row = next(iter(t.rows().values()))
            self.assertEqual(row['outcome'], 'incomplete')
            self.assertEqual(t.f.read(t.path / 'native-mount.json')['operation'], row['id'])
            t.unmount()
            t.public_result('current-image-adopted')

    def test_extra_target_fields_cannot_become_interval_authority(self):
        with owned() as t:
            t.mount(); t.unmount()
            row = next(r for r in t.rows().values() if r['operation'] == 'native-mount')
            for target in (row['target'], row['interval_seed']['target'], row['ordinary_interval']['target']):
                target['extra'] = 'not target authority'
            t.f.save(t.path / 'native-operations' / row['id'] / 'record.json', row)
            t.public_result('blocked')

    def test_consumed_close_archive_and_journal_fault_snapshots(self):
        for which in ('archive', 'journal'):
            with self.subTest(which=which), owned() as t:
                t.mount(True); t.mount()
                persist = _native._persist
                def fault(path, row):
                    match = path.name == 'record.json' if which == 'archive' else path.parent.name == 'journals'
                    if match and row.get('operation') == 'native-unmount' and 'current_guard' in row:
                        raise OSError('owned close durability fault')
                    return persist(path, row)
                with patch.object(_native, '_persist', fault):
                    with self.assertRaises(OSError): t.unmount()
                with patch.object(_native.Operation, 'command') as command:
                    with self.assertRaises(core.StallionError): t.unmount()
                    command.assert_not_called()
                t.public_result('blocked')

    def test_complete_archive_restart_snapshots(self):
        from pathlib import Path
        for boundary in ('journal-replace', 'journal-remove', 'directory-sync'):
            with self.subTest(boundary=boundary), owned() as t:
                t.mount(True); t.mount()
                journal = t.store.root / 'journals' / (t.path.name + '.json')
                persist, unlink, sync = _native._persist, Path.unlink, core.sync_directory
                def save(path, row):
                    if boundary == 'journal-replace' and path == journal and row.get('operation') == 'native-unmount' and row.get('outcome') == 'complete':
                        raise OSError('owned completion journal fault')
                    return persist(path, row)
                def remove(path, *args, **kwargs):
                    if boundary == 'journal-remove' and path == journal:
                        raise OSError('owned journal removal fault')
                    return unlink(path, *args, **kwargs)
                def syncing(path):
                    if boundary == 'directory-sync' and path == journal.parent and not journal.exists():
                        raise OSError('owned completion directory sync fault')
                    return sync(path)
                with patch.object(_native, '_persist', save), patch.object(Path, 'unlink', remove), \
                     patch.object(core, 'sync_directory', syncing), patch.object(_native, '_retain_failure'):
                    with self.assertRaises(OSError): t.unmount()
                if boundary == 'journal-replace':
                    with self.assertRaises(core.StallionError): t.unmount()
                    t.public_result('blocked')
                else:
                    if boundary == 'journal-remove': t.unmount()
                    t.public_result('current-image-adopted')

    def test_unused_completed_versioned_references_still_validate(self):
        for mode in ('malformed', 'cycle'):
            with self.subTest(mode=mode), owned() as t:
                t.mount(); t.unmount()
                rows = t.rows()
                mount = next(r for r in rows.values() if r['operation'] == 'native-mount')
                close = next(r for r in rows.values() if r['operation'] == 'native-unmount')
                mount['previous_unresolved'] = {'id': True} if mode == 'malformed' else dict(
                    id=close['id'], operation=close['operation'], outcome=close['outcome'],
                    record=str(t.path / 'native-operations' / close['id'] / 'record.json'))
                if mode == 'cycle':
                    close['previous_unresolved'] = dict(id=mount['id'], operation=mount['operation'], outcome=mount['outcome'],
                        record=str(t.path / 'native-operations' / mount['id'] / 'record.json'))
                for row in (mount, close): t.f.save(t.path / 'native-operations' / row['id'] / 'record.json', row)
                t.public_result('blocked')

    def test_durable_observation_restart_without_failure_handler(self):
        with owned() as t:
            proof = t.f.read(t.path / 'native-install.json'); proof['first_use'] = {'accepted': False}
            t.f.save(t.path / 'native-install.json', proof)
            with patch.object(_native, '_usable', side_effect=SystemExit('owned stop before readiness')), \
                 patch.object(_native, '_retain_failure'):
                with self.assertRaises(SystemExit): t.mount()
            row = next(iter(t.rows().values()))
            self.assertEqual(row['outcome'], 'incomplete')
            self.assertIn('ordinary_interval', row)
            self.assertEqual(t.f.read(t.path / 'native-install.json')['first_use'], {'accepted': False})
            t.unmount()
            self.assertEqual(row, t.rows()[row['id']])
            t.public_result('current-image-adopted')
            t.mount(); t.unmount()
            self.assertEqual(t.initial_calls, [True])

    def test_durable_close_restart_without_failure_handler(self):
        for boundary in ('before-marker', 'after-marker'):
            with self.subTest(boundary=boundary), owned() as t:
                t.mount(True); t.mount()
                persist = _native._persist
                def stop(path, row):
                    if path == t.path / 'native-mount.json' and row.get('state') == 'absent':
                        if boundary == 'after-marker': persist(path, row)
                        raise SystemExit('owned stop after durable close')
                    return persist(path, row)
                with patch.object(_native, '_persist', stop), patch.object(_native, '_retain_failure'):
                    with self.assertRaises(SystemExit): t.unmount()
                close = next(r for r in t.rows().values() if r['operation'] == 'native-unmount')
                self.assertEqual(close['outcome'], 'incomplete')
                self.assertIn('current_guard', close)
                t.unmount()
                self.assertEqual(close, t.rows()[close['id']])
                t.public_result('current-image-adopted')
