"""Public ordinary controller histories on owned storage and helper doubles."""
import contextlib
import copy
import os
import unittest
from unittest.mock import patch
from stallionfs import core, _native, _native_binding as binding
import test_native_binding_history as history


class OrdinaryChains(unittest.TestCase):
    def setUp(self):
        self.real_usable = _native._usable
        self.h = history.BindingHistory()
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        self.path, self.meta, self.store, self.f = self.h.path, self.h.meta, self.h.store, self.h.f
        self.row = dict(path=str(self.path / 'volume'), filesystem='stallionfs', owner=os.getuid(),
                        flags=0, fsid=[11, 22], readonly=False, ignore_ownership=False, source='informational')
        self.mounted = False
        self.fail_mount = False
        self.fail_unmount = False
        self.fail_usable = False
        self.initial_calls = []
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(_native, 'observe', side_effect=lambda *a: copy.deepcopy(self.row) if self.mounted else None))
        stack.enter_context(patch.object(_native, 'qualify', side_effect=self.qualify))
        stack.enter_context(patch.object(_native.Operation, 'command', self.command))
        stack.enter_context(patch.object(_native, '_usable', side_effect=self.usable))
        stack.enter_context(patch.object(self.store, '_open', return_value=None))

    def qualify(self, operation, metadata):
        operation.command('verify-package', _native.package_argv(_native.HOST))
        operation.command('discover', [str(_native.HOST), '--discover-json'])
        return 'stallionfs'

    @property
    def command(self):
        fixture = self
        def run(operation, label, argv):
            failed = label == 'mount' and fixture.fail_mount or label == 'unmount' and fixture.fail_unmount
            if not failed and label in ('mount', 'unmount'):
                fixture.mounted = label == 'mount'
            result = dict(label=label, argv=argv, child_pending=False, pid=123, reaped=True,
                          returncode=1 if failed else 0, outcome='error' if failed else 'success',
                          stdout='/owned/stdout', stderr='/owned/stderr')
            operation.record['helpers'].append(result)
            operation.persist()
            return result
        return run

    def usable(self, store, path, metadata, *, initial, operation):
        self.initial_calls.append(initial)
        if initial:
            operation.record['write_probe'] = dict(path=str(path / 'volume/repo' / ('.stallionfs-write-' + 'a' * 32)), complete=not self.fail_usable)
            operation.persist()
        if self.fail_usable:
            raise core.StallionError('owned readiness/probe failure')
        return str(path / 'volume/repo')

    def mount(self, fail=False):
        self.fail_mount = fail
        if fail or self.fail_usable:
            with self.assertRaises(core.StallionError):
                _native.mount_locked(self.store, self.path, self.meta)
        else:
            _native.mount_locked(self.store, self.path, self.meta)

    def unmount(self, fail=False):
        self.fail_unmount = fail
        if fail:
            with self.assertRaises(core.StallionError):
                _native.unmount_locked(self.store, self.path, self.meta)
        else:
            _native.unmount_locked(self.store, self.path, self.meta)

    def rows(self):
        return {p.parent.name: self.f.read(p) for p in (self.path / 'native-operations').glob('*/record.json')}

    def validate(self, rows=None):
        return binding.archive_anchor(self.rows() if rows is None else rows, self.path, self.meta,
                                      self.f.read(self.path / 'native-mount.json'),
                                      self.f.read(self.path / 'native-install.json'))

    def preserve_admit(self):
        paths = [self.path / n for n in ('meta.json', 'native-create.json', 'native-install.json')]
        paths += list((self.path / 'native-operations').glob('*/record.json'))
        before = {p: p.read_bytes() for p in paths}
        self.validate()
        self.validate(dict(reversed(list(self.rows().items()))))
        self.h.h.sidecar.unlink()
        _native.recover_install(self.store, self.path, self.meta)
        with self.h.h.renumber():
            _native.recover_install(self.store, self.path, self.meta)
        self.assertEqual(before, {p: p.read_bytes() for p in paths})

    def test_repeated_absent_mount_failures(self):
        for _ in range(5):
            self.mount(True)
        self.unmount()
        self.preserve_admit()

    def test_unmount_only_interval_has_no_early_guard(self):
        self.mounted = True
        self.unmount(True)
        self.unmount(True)
        failed = self.rows()
        self.assertTrue(all('current_guard' not in r for r in failed.values()))
        self.assertTrue(all(r['operation'] == 'native-unmount' for r in failed.values()))
        self.f.guard_anchor = dict(self.f.anchor, generation=3, root_digest='c' * 64)
        self.unmount()
        self.preserve_admit()

    def test_failed_mount_interval_advances_close(self):
        self.fail_usable = True
        self.mount()
        self.unmount(True)
        self.f.guard_anchor = dict(self.f.anchor, generation=3, root_digest='c' * 64)
        self.unmount()
        self.preserve_admit()

    def test_complete_mount_retry_then_unlinked_close(self):
        self.mount(True)
        self.mount()
        self.unmount()
        close = next(r for r in self.rows().values() if r['operation'] == 'native-unmount')
        self.assertIsNone(close['previous_unresolved'])
        self.preserve_admit()

    def test_post_close_failure_then_absent_close(self):
        with patch.object(self.store, '_open', side_effect=core.StallionError('owned persistence boundary')):
            with self.assertRaises(core.StallionError):
                self.unmount()
        self.unmount()
        self.preserve_admit()

    def test_failed_probe_preserved_and_next_mount_requires_initial(self):
        proof = self.f.read(self.path / 'native-install.json')
        proof['first_use'] = {'accepted': False}
        self.f.save(self.path / 'native-install.json', proof)
        self.fail_usable = True
        self.mount()
        failed = self.rows()
        self.unmount()
        self.preserve_admit()
        self.assertEqual(self.f.read(self.path / 'native-install.json'), proof)
        self.assertFalse(next(iter(failed.values()))['write_probe']['complete'])
        self.fail_usable = False
        self.mount()
        self.assertEqual(self.initial_calls, [True, True])
        self.unmount()

    def test_observation_authority_and_informational_source(self):
        self.mounted = True
        self.unmount(True)
        self.unmount(True)
        self.unmount()
        rows = self.rows()
        first = next(r for r in rows.values() if r['previous_unresolved'] is None)
        first['observed_mount']['source'] = '/never/open/this'
        self.validate(rows)
        for key, value in [('owner', float(os.getuid())), ('flags', False), ('fsid', [True, 22]),
                           ('readonly', 0), ('ignore_ownership', 0), ('path', '/different'),
                           ('filesystem', 'other'), ('fsid', [11, 23])]:
            bad = copy.deepcopy(rows)
            bad[first['id']]['observed_mount'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(core.StallionError):
                self.validate(bad)

    def test_chain_edges_and_uncertainty(self):
        self.mount(True)
        self.mount(True)
        self.unmount()
        rows = self.rows()
        first = next(r for r in rows.values() if r['previous_unresolved'] is None)
        for field, value in [('outcome', 'prepared'), ('observation_error', {}), ('receipt_error', 'OSError'),
                             ('child_pending', True), ('protocol', True), ('protocol', 2.0),
                             ('previous_unresolved', {'id': 'f' * 32})]:
            bad = copy.deepcopy(rows)
            bad[first['id']][field] = value
            with self.subTest(field=field), self.assertRaises(core.StallionError):
                self.validate(bad)
        for name in rows:
            bad = copy.deepcopy(rows); del bad[name]
            with self.subTest(missing=name), self.assertRaises(core.StallionError):
                self.validate(bad)
        bad = copy.deepcopy(rows)
        extra = copy.deepcopy(first); extra['id'] = 'f' * 32
        extra['previous_unresolved'] = dict(id=first['id'], record='/wrong')
        bad[extra['id']] = extra
        with self.assertRaises(core.StallionError): self.validate(bad)

    def test_absent_generation_advance_refuses(self):
        self.mount(True)
        self.f.guard_anchor = dict(self.f.anchor, generation=3, root_digest='c' * 64)
        self.unmount()
        with self.assertRaises(core.StallionError): self.validate()

    def test_real_initial_readiness_and_probe_after_failed_write(self):
        from stallionfs import _native_create_git
        # Restore the real acceptance function under the fixture's boundary doubles.
        real_usable = self.real_usable
        repo = self.path / 'volume/repo'
        repo.mkdir()
        proof = self.f.read(self.path / 'native-install.json')
        proof['first_use'] = {'accepted': False}
        self.f.save(self.path / 'native-install.json', proof)
        write = os.write
        def short(fd, data):
            return 0 if data == b'stallionfs writable path\n' else write(fd, data)
        with patch.object(_native, '_usable', real_usable), \
             patch.object(_native_create_git, 'qualified_runtime', return_value=object()), \
             patch.object(self.store, '_standalone_git'), \
             patch.object(_native_create_git, 'readiness', return_value=(self.meta['commit'], self.meta['branch'])) as ready:
            with patch.object(os, 'write', side_effect=short), self.assertRaises(OSError):
                _native.mount_locked(self.store, self.path, self.meta)
            self.unmount()
            self.validate()
            self.assertEqual(self.f.read(self.path / 'native-install.json'), proof)
            failed = next(r for r in self.rows().values() if r['operation'] == 'native-mount')
            self.assertFalse(failed['write_probe']['complete'])
            _native.mount_locked(self.store, self.path, self.meta)
            self.assertEqual(ready.call_count, 2)
            self.assertTrue(self.f.read(self.path / 'native-install.json')['first_use']['accepted'])
            self.unmount()

    def test_close_generations_and_terminal_probe_refusals(self):
        self.fail_usable = True
        self.mount()
        self.unmount(True)
        self.unmount()
        rows = self.rows()
        closing = next(r for r in rows.values() if r['outcome'] == 'complete')
        for field, value in [('generation', 1), ('root_digest', 'e' * 64), ('committed_end', 1)]:
            bad = copy.deepcopy(rows)
            bad[closing['id']]['current_guard'][field] = value
            with self.subTest(field=field), self.assertRaises(core.StallionError): self.validate(bad)

    def test_chain_public_budget_and_fresh_close_no_write(self):
        from stallionfs import _native_create_recovery as admission
        self.mount(True); self.mount(True); self.unmount()
        self.h.h.sidecar.unlink()
        paths = [p for p in self.path.rglob('*') if p.is_file()]
        before = {p: p.read_bytes() for p in paths}
        for key in ('MAX_DOCUMENT_BYTES', 'MAX_TOTAL_BYTES', 'MAX_ENTRIES'):
            with self.subTest(budget=key), patch.object(admission, key, 1):
                result = self.h.h.adopt()
                self.assertEqual(result['status'], 'blocked')
            self.assertFalse(self.h.h.sidecar.exists())
            self.assertEqual(before, {p: p.read_bytes() for p in paths})
        for error in (core.StallionError('owned fresh guard failure'), KeyboardInterrupt()):
            with patch.object(_native, 'guarded', side_effect=error):
                if isinstance(error, KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt): self.h.h.adopt()
                else: self.assertEqual(self.h.h.adopt()['status'], 'blocked')
            self.assertFalse(self.h.h.sidecar.exists())
            self.assertEqual(before, {p: p.read_bytes() for p in paths})

    def test_terminal_mount_probe_and_missing_current_close(self):
        self.mount(True); self.mount(); self.unmount()
        rows = self.rows()
        endpoint = next(r for r in rows.values() if r['operation'] == 'native-mount' and r['outcome'] == 'complete')
        for probe in (None, {}, {'complete': False, 'path': str(self.path / 'volume/repo/.stallionfs-write-' ) + 'a' * 32},
                      {'complete': True, 'path': '/other/.stallionfs-write-' + 'a' * 32}):
            bad = copy.deepcopy(rows); bad[endpoint['id']]['write_probe'] = probe
            with self.subTest(probe=probe), self.assertRaises(core.StallionError): self.validate(bad)
        with self.assertRaises(core.StallionError):
            binding.archive_anchor(rows, self.path, self.meta, None,
                                   {'first_mount_attempted': False, 'guard': endpoint['current_guard']})

    def test_cycles_cross_targets_and_modern_unknown_ownership(self):
        self.mount(True); self.mount(True); self.unmount()
        rows = self.rows()
        first = next(r for r in rows.values() if r['previous_unresolved'] is None)
        last = next(r for r in rows.values() if r['outcome'] == 'complete')
        bad = copy.deepcopy(rows)
        bad[first['id']]['previous_unresolved'] = dict(operation=last['operation'], id=last['id'],
            outcome=last['outcome'], record=str(self.path / 'native-operations' / last['id'] / 'record.json'))
        with self.assertRaises(core.StallionError): self.validate(bad)
        for field, value in [('parent', [True, first['target']['parent'][1]]),
                             ('file', [float(first['target']['file'][0]), first['target']['file'][1]]),
                             ('component', 'other.sfs'), ('uuid', 'e' * 32)]:
            bad = copy.deepcopy(rows); bad[first['id']]['target'][field] = value
            with self.subTest(field=field), self.assertRaises(core.StallionError): self.validate(bad)
        for field, value in [('reaped', False), ('outcome', 'unknown'), ('streams_eof', False),
                             ('streams_durable', False), ('receipt_error', None), ('interrupted', False)]:
            bad = copy.deepcopy(rows)
            r = bad[first['id']]; r['protocol'] = 3
            for h in r['helpers']: h.update(streams_eof=True, streams_durable=True, output_bytes=0)
            r['helpers'][-1][field] = value
            with self.subTest(field=field), self.assertRaises(core.StallionError): self.validate(bad)

    def public_result(self, expected):
        self.h.h.sidecar.unlink(missing_ok=True)
        paths = [p for p in self.path.rglob('*') if p.is_file()]
        before = {p: p.read_bytes() for p in paths}
        result = self.h.h.adopt()
        self.assertEqual(result['status'], expected, result)
        self.assertEqual(before, {p: p.read_bytes() for p in paths})
        if expected == 'blocked':
            self.assertFalse(self.h.h.sidecar.exists())

    def test_public_initial_endpoint_requires_original_probe(self):
        proof = self.f.read(self.path / 'native-install.json')
        proof['first_use'] = {'accepted': False}
        self.f.save(self.path / 'native-install.json', proof)
        self.mount(True); self.mount(); self.unmount()
        endpoint = next(r for r in self.rows().values() if r['operation'] == 'native-mount' and r['outcome'] == 'complete')
        location = self.path / 'native-operations' / endpoint['id'] / 'record.json'
        self.public_result('current-image-adopted')
        for value in (None, {}, {'complete': False}, {'complete': True, 'path': '/wrong'}):
            bad = copy.deepcopy(endpoint)
            if value is None: del bad['write_probe']
            else: bad['write_probe'] = value
            self.f.save(location, bad)
            with self.subTest(probe=value): self.public_result('blocked')
        self.f.save(location, endpoint)
        proof = self.f.read(self.path / 'native-install.json')
        for key, value in [('accepted', 1), ('accepted', False), ('operation', True),
                           ('operation', 'f' * 32), ('write_probe', {})]:
            bad = copy.deepcopy(proof); bad['first_use'][key] = value
            self.f.save(self.path / 'native-install.json', bad)
            with self.subTest(field=key, value=value): self.public_result('blocked')
        self.f.save(self.path / 'native-install.json', proof)
        self.public_result('current-image-adopted')

    def test_public_noninitial_endpoint_and_independent_close(self):
        self.mount(True); self.mount()
        endpoint = next(r for r in self.rows().values() if r['outcome'] == 'complete')
        self.assertNotIn('write_probe', endpoint)
        self.f.guard_anchor = dict(self.f.anchor, generation=3, root_digest='c' * 64)
        self.unmount()
        close = next(r for r in self.rows().values() if r['operation'] == 'native-unmount')
        self.assertIsNone(close['previous_unresolved'])
        location = self.path / 'native-operations' / close['id'] / 'record.json'
        close['before_mount']['source'] = '/inert/informational'
        self.f.save(location, close)
        self.public_result('current-image-adopted')
        for field, value in [('before_mount', None), ('id', 'f' * 32), ('helpers', []),
                             ('current_guard', {}), ('observed_mount', self.row)]:
            bad = copy.deepcopy(close); bad[field] = value
            self.f.save(location, bad)
            with self.subTest(field=field): self.public_result('blocked')
        self.f.save(location, close)
        for field, value in [('flags', False), ('fsid', [11, 23]), ('owner', float(os.getuid()))]:
            bad = copy.deepcopy(close); bad['before_mount'][field] = value
            self.f.save(location, bad)
            with self.subTest(authority=field): self.public_result('blocked')
        self.f.save(location, close)
        self.public_result('current-image-adopted')

    def test_public_stale_absent_and_unarchived_install_guard(self):
        self.unmount()
        stale = self.f.read(self.path / 'native-mount.json')
        proof = self.f.read(self.path / 'native-install.json')
        self.mount(True); self.mount(); self.mounted = False
        self.f.save(self.path / 'native-mount.json', stale)
        self.public_result('blocked')
        stale.update(operation='f' * 32, current_guard=proof['guard'])
        self.f.save(self.path / 'native-mount.json', stale)
        self.public_result('blocked')

    def test_public_complete_mount_close_failure_then_absent_retry(self):
        self.mount(True); self.mount()
        self.f.guard_anchor = dict(self.f.anchor, generation=3, root_digest='c' * 64)
        with patch.object(self.store, '_open', side_effect=core.StallionError('owned close persistence failure')):
            with self.assertRaises(core.StallionError): self.unmount()
        self.unmount()
        self.public_result('current-image-adopted')

    def test_public_disconnected_mounted_close_does_not_prove_order(self):
        self.mounted = True
        self.unmount()
        stale = self.f.read(self.path / 'native-mount.json')
        self.mount(True); self.mount(); self.mounted = False
        self.f.save(self.path / 'native-mount.json', stale)
        self.public_result('blocked')

    def test_initial_identity_classification_independent_of_close(self):
        proof = self.f.read(self.path / 'native-install.json')
        proof['first_use'] = {'accepted': False}
        self.f.save(self.path / 'native-install.json', proof)
        self.mount(True); self.mount(); self.unmount()
        proof = self.f.read(self.path / 'native-install.json')
        endpoint = next(r for r in self.rows().values() if r['operation'] == 'native-mount' and r['outcome'] == 'complete')
        binding._mount_acceptance(endpoint, proof, self.path)
        for value in (None, {}, {'complete': False}, {'complete': True, 'path': '/wrong'}):
            bad = copy.deepcopy(endpoint)
            if value is None: del bad['write_probe']
            else: bad['write_probe'] = value
            with self.subTest(probe=value), self.assertRaises(core.StallionError):
                binding._mount_acceptance(bad, proof, self.path)
        for key, value in [('accepted', 1), ('accepted', False), ('operation', True),
                           ('operation', 'f' * 32), ('write_probe', {})]:
            bad = copy.deepcopy(proof); bad['first_use'][key] = value
            with self.subTest(field=key, value=value), self.assertRaises(core.StallionError):
                binding._mount_acceptance(endpoint, bad, self.path)
        later = copy.deepcopy(endpoint); later['id'] = 'f' * 32; del later['write_probe']
        binding._mount_acceptance(later, proof, self.path)
