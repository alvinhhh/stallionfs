"""Explicit legacy eligibility on owned public-controller histories."""
import copy
import unittest
from unittest.mock import patch
from stallionfs import core, _native, _native_binding as binding, _native_reconcile as reconcile
from test_native_interval import owned, malformed_markers


def legacy(t):
    t.mount(True); t.mount(); t.unmount()
    for name, row in t.rows().items():
        for key in ('lifecycle_version', 'interval_seed', 'ordinary_interval'): row.pop(key, None)
        t.f.save(t.path / 'native-operations' / name / 'record.json', row)
    marker = t.f.read(t.path / 'native-mount.json')
    original = copy.deepcopy(marker)
    for key in ('lifecycle_version', 'ordinary_interval'): marker.pop(key, None)
    t.f.save(t.path / 'native-mount.json', marker)
    t.h.h.sidecar.unlink()
    return original


def run(t):
    return reconcile.reconcile_current(t.store.root, t.path.name, t.meta['transaction'])


class Reconciliation(unittest.TestCase):
    def test_public_reconciliation_rejects_malformed_current_marker(self):
        with owned() as t:
            template = legacy(t)
            location = t.path / 'native-mount.json'; original = t.f.read(location)
            for name, marker in malformed_markers(template):
                with self.subTest(case=name):
                    t.f.save(location, marker)
                    before = {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()}
                    self.assertEqual(run(t)['status'], 'blocked')
                    self.assertFalse(t.h.h.sidecar.exists())
                    self.assertFalse((t.path / 'native-reconciliations').exists())
                    self.assertEqual(before, {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()})
            t.f.save(location, original)
            self.assertEqual(run(t)['status'], 'current-image-reconciled')

    def test_reconciled_public_readback_rejects_malformed_current_marker(self):
        with owned() as t:
            legacy(t)
            self.assertEqual(run(t)['status'], 'current-image-reconciled')
            t.mount(); t.unmount()
            location = t.path / 'native-mount.json'; original = t.f.read(location)
            for name, marker in malformed_markers(original):
                with self.subTest(case=name):
                    t.f.save(location, marker)
                    before = {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()}
                    with self.assertRaises(core.StallionError): _native.recover_install(t.store, t.path, t.meta)
                    self.assertEqual(t.h.h.adopt()['status'], 'blocked')
                    self.assertEqual(before, {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()})
            t.f.save(location, original)
            _native.recover_install(t.store, t.path, t.meta)

    def test_explicit_legacy_scope_then_normal_cycle(self):
        with owned() as t:
            legacy(t)
            t.public_result('blocked')
            files = [t.path / n for n in ('meta.json', 'native-create.json', 'native-install.json')]
            files += list((t.path / 'native-operations').glob('*/record.json'))
            before = {p: p.read_bytes() for p in files}
            result = run(t)
            self.assertEqual(result['status'], 'current-image-reconciled', result)
            self.assertEqual(before, {p: p.read_bytes() for p in files})
            record = t.f.read(t.h.h.sidecar)
            self.assertEqual(record['schema'], 2)
            self.assertEqual(record['authority'], 'legacy-offline-reconciliation')
            _native.recover_install(t.store, t.path, t.meta)
            t.mount(); t.unmount()
            _native.recover_install(t.store, t.path, t.meta)
            self.assertEqual(before, {p: p.read_bytes() for p in files})

    def test_scope_changes_and_new_unknown_rows_refuse(self):
        with owned() as t:
            legacy(t)
            self.assertEqual(run(t)['status'], 'current-image-reconciled')
            row_path = next((t.path / 'native-operations').glob('*/record.json'))
            original = row_path.read_bytes()
            row = t.f.read(row_path); row['extra'] = 'changed'
            t.f.save(row_path, row)
            with self.assertRaises(core.StallionError): _native.recover_install(t.store, t.path, t.meta)
            row_path.write_bytes(original)
            _native.recover_install(t.store, t.path, t.meta)

    def test_receipt_before_binding_retry_and_guard_failure(self):
        with owned() as t:
            legacy(t)
            with patch.object(binding, 'publish', side_effect=OSError('owned binding fault')):
                result = run(t)
            self.assertEqual(result['status'], 'blocked')
            self.assertFalse(t.h.h.sidecar.exists())
            receipts = list((t.path / 'native-reconciliations').glob('*.json'))
            self.assertEqual(len(receipts), 1)
            self.assertEqual(run(t)['status'], 'current-image-reconciled')
            self.assertEqual(receipts, list((t.path / 'native-reconciliations').glob('*.json')))
        with owned() as t:
            legacy(t)
            with patch.object(_native, 'guarded', side_effect=OSError('owned guard fault')):
                self.assertEqual(run(t)['status'], 'blocked')
            self.assertFalse(t.h.h.sidecar.exists())
            self.assertFalse((t.path / 'native-reconciliations').exists())

    def test_public_reconciliation_budgets_and_authority(self):
        from stallionfs import _native_create_recovery as admission
        for key in ('MAX_DOCUMENT_BYTES', 'MAX_TOTAL_BYTES', 'MAX_ENTRIES'):
            with self.subTest(key=key), owned() as t:
                legacy(t)
                before = {p: p.read_bytes() for p in t.path.rglob('*') if p.is_file()}
                with patch.object(admission, key, 1): self.assertEqual(run(t)['status'], 'blocked')
                self.assertEqual(before, {p: p.read_bytes() for p in before})
                self.assertFalse(t.h.h.sidecar.exists())

    def test_cli_mutual_exclusion_and_explicit_dispatch(self):
        import contextlib
        import io
        from stallionfs.__main__ import main
        for extra in (['--adopt-current', '2' * 32], ['--continue', '2' * 32], ['--purge', '2' * 32], ['--confirm']):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit): main(['creations', '1' * 32, '--reconcile-current', '2' * 32, *extra])
        with owned() as t:
            legacy(t)
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code = main(['--root', str(t.store.root), '--json', 'creations', t.path.name,
                             '--reconcile-current', t.meta['transaction']])
            self.assertEqual(code, 0, output.getvalue())
            self.assertIn('current-image-reconciled', output.getvalue())

    def test_receipt_scope_and_guard_substitutions_refuse(self):
        for change in ('version', 'endpoint', 'hash', 'target', 'generation', 'duplicate'):
            with self.subTest(change=change), owned() as t:
                legacy(t)
                with patch.object(binding, 'publish', side_effect=OSError('owned stop before binding')):
                    self.assertEqual(run(t)['status'], 'blocked')
                location = next((t.path / 'native-reconciliations').glob('*.json'))
                receipt = t.f.read(location)
                if change == 'version': receipt['schema'] = True
                elif change == 'endpoint': receipt['scope']['endpoints'].append('f' * 32)
                elif change == 'hash': receipt['scope']['inventory'][0]['sha256'] = '0' * 64
                elif change == 'target': receipt['scope']['target']['file'][1] += 1
                elif change == 'generation': receipt['guard']['generation'] = 0
                else:
                    receipt['id'] = 'f' * 32
                    location = location.parent / (receipt['id'] + '.json')
                t.f.save(location, receipt)
                self.assertEqual(run(t)['status'], 'blocked')
                self.assertFalse(t.h.h.sidecar.exists())

    def test_new_unknown_operation_is_not_covered_by_old_scope(self):
        with owned() as t:
            legacy(t)
            self.assertEqual(run(t)['status'], 'current-image-reconciled')
            row = copy.deepcopy(next(iter(t.rows().values())))
            row.update(id='f' * 32, outcome='incomplete', previous_unresolved=None, helpers=[])
            directory = t.path / 'native-operations' / row['id']; directory.mkdir(mode=0o700)
            t.f.save(directory / 'record.json', row)
            with self.assertRaises(core.StallionError): _native.recover_install(t.store, t.path, t.meta)

    def test_bound_readback_rejects_duplicate_receipt_and_changed_basis(self):
        for change in ('duplicate', 'basis'):
            with self.subTest(change=change), owned() as t:
                legacy(t)
                self.assertEqual(run(t)['status'], 'current-image-reconciled')
                if change == 'duplicate':
                    location = next((t.path / 'native-reconciliations').glob('*.json'))
                    row = t.f.read(location); row['id'] = 'f' * 32
                    t.f.save(location.parent / (row['id'] + '.json'), row)
                else:
                    row = t.f.read(t.h.h.sidecar); row['basis']['scope_digest'] = '0' * 64
                    t.f.save(t.h.h.sidecar, row)
                with self.assertRaises(core.StallionError): _native.recover_install(t.store, t.path, t.meta)

    def test_receipt_publication_faults_and_interrupt_never_publish_binding(self):
        import os
        from stallionfs import _scan
        for boundary in ('rename', 'directory-sync', 'guard-interrupt'):
            with self.subTest(boundary=boundary), owned() as t:
                legacy(t)
                before = {p:p.read_bytes() for p in t.path.rglob('*') if p.is_file()}
                sync = os.fsync
                fired = []
                def fail_sync(fd):
                    directory = t.path / 'native-reconciliations'
                    if directory.exists() and os.fstat(fd).st_ino == directory.stat().st_ino and not fired:
                        fired.append(True); raise OSError('owned receipt directory sync fault')
                    return sync(fd)
                if boundary == 'rename':
                    with patch.object(_scan, '_publish_no_replace', side_effect=OSError('owned receipt publication fault')):
                        self.assertEqual(run(t)['status'], 'blocked')
                elif boundary == 'directory-sync':
                    with patch.object(os, 'fsync', fail_sync): self.assertEqual(run(t)['status'], 'blocked')
                    self.assertTrue(fired)
                else:
                    with patch.object(_native, 'guarded', side_effect=KeyboardInterrupt()):
                        with self.assertRaises(KeyboardInterrupt): run(t)
                self.assertFalse(t.h.h.sidecar.exists())
                self.assertEqual(before, {p:p.read_bytes() for p in before})
                self.assertEqual(run(t)['status'], 'current-image-reconciled')

    def test_public_legacy_refusals_do_not_waive_other_predicates(self):
        import contextlib
        for boundary in ('initial-probe', 'unknown-helper', 'pending', 'mounted', 'location',
                         'protection', 'transaction', 'target', 'installation-binding'):
            with self.subTest(boundary=boundary), owned() as t:
                old_binding = t.h.h.sidecar.read_bytes()
                if boundary == 'initial-probe':
                    proof = t.f.read(t.path / 'native-install.json'); proof['first_use'] = {'accepted': False}
                    t.f.save(t.path / 'native-install.json', proof)
                legacy(t)
                rows = t.rows()
                endpoint = next(r for r in rows.values() if r['operation'] == 'native-mount' and r['outcome'] == 'complete')
                if boundary == 'initial-probe':
                    del endpoint['write_probe']
                    t.f.save(t.path / 'native-operations' / endpoint['id'] / 'record.json', endpoint)
                elif boundary == 'unknown-helper':
                    endpoint['helpers'][-1].update(outcome='unknown', reaped=False)
                    t.f.save(t.path / 'native-operations' / endpoint['id'] / 'record.json', endpoint)
                elif boundary == 'pending': t.f.save(t.store.root / 'journals' / (t.path.name + '.json'), endpoint)
                elif boundary == 'location': t.f.save(t.path / 'native-location.json', {})
                elif boundary == 'protection': t.f.save(t.store.root / 'protected' / (t.path.name + '.json'), {})
                elif boundary == 'target':
                    meta = t.f.read(t.path / 'meta.json'); meta['native_image']['file'][1] += 1
                    t.f.save(t.path / 'meta.json', meta)
                elif boundary == 'installation-binding': t.h.h.sidecar.write_bytes(old_binding)
                before = {p:p.read_bytes() for p in t.store.root.rglob('*') if p.is_file()}
                with patch.object(core.Store, '_no_mounts', side_effect=core.StallionError('owned mounted exclusion')) if boundary == 'mounted' else contextlib.nullcontext():
                    result = (reconcile.reconcile_current(t.store.root, t.path.name, 'f' * 32)
                              if boundary == 'transaction' else run(t))
                self.assertEqual(result['status'], 'blocked', result)
                self.assertEqual(before, {p:p.read_bytes() for p in before})
                if boundary != 'installation-binding': self.assertFalse(t.h.h.sidecar.exists())

    def test_fresh_legacy_guard_advancement_and_conflicts(self):
        for mode in ('advance', 'lower', 'conflict'):
            with self.subTest(mode=mode), owned() as t:
                legacy(t)
                t.f.guard_anchor = dict(t.f.anchor, generation=3 if mode == 'advance' else 1 if mode == 'lower' else 2,
                                        root_digest='c' * 64)
                result = run(t)
                self.assertEqual(result['status'], 'current-image-reconciled' if mode == 'advance' else 'blocked', result)
                if mode == 'advance':
                    self.assertEqual(t.f.read(t.h.h.sidecar)['anchor']['generation'], 3)
                else:
                    self.assertFalse(t.h.h.sidecar.exists())
                    self.assertFalse((t.path / 'native-reconciliations').exists())
