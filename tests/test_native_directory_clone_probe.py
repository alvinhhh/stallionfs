"""Pure/mock safety checks. This module never executes a clone helper."""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

PERF = Path(__file__).parent / 'perf'
with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
    spec = importlib.util.spec_from_file_location('directory_probe_under_test', PERF / 'native_directory_clone_probe.py')
    probe = importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)
    import fileops, native_correctness, native_fixtures, native_suite
    import native_directory_restore as restoration_support


def native(calls=1, error=0):
    return {'schema': 1, 'marker': probe.MARKER, 'native_return': (-1 if error else 0) if calls else None,
            'native_errno': error if calls else None, 'admission_errno': error if not calls else 0,
            'clone_calls': calls, 'close_error': 0}


def detail_entry(kind='file', *, flags=0, mtime=100, acl=None):
    return {'kind': kind, 'flags': flags, 'mtime_ns': mtime,
            'acl': {'text_hex': acl, 'unavailable': None}, 'device_inode': [234567891, 987654321],
            'uid': 123456789, 'xattrs': {'PRIVATE-xattr': 'PRIVATE-value'}, 'sha256': 'deadbeef' * 8}


def detail_snapshot(entries=None, groups=None):
    return {'entries': entries if entries is not None else {'': detail_entry('directory'), 'PRIVATE-name': detail_entry()},
            'hardlink_groups': groups if groups is not None else [], 'unavailable_fields': []}


class FirstRecipeDetail(unittest.TestCase):
    def detail(self, source, destination, *, source_ok=True, outside_ok=True, independent=True):
        return probe.first_recipe_detail(source, destination,
            {'source_unchanged': source_ok, 'outside_sentinel_unchanged': outside_ok}, independent)

    def test_all_entries_flags_signed_deltas_acl_states_and_unchanged_entries_are_allowlisted(self):
        secret_acl = b'!#acl 1\ngroup:PRIVATE-user:PRIVATE-id:allow:read\n'.hex()
        source = detail_snapshot({'': detail_entry('directory'), 'PRIVATE-A': detail_entry(flags=64, mtime=100, acl=secret_acl),
                                  'PRIVATE-B': detail_entry('symlink', flags=2, mtime=200)})
        destination = deepcopy(source)
        destination['entries']['PRIVATE-A'] = detail_entry(flags=0, mtime=93)
        destination['entries']['PRIVATE-B']['mtime_ns'] = 205
        value = self.detail(source, destination)
        self.assertEqual(set(value), probe.DETAIL_FIELDS)
        self.assertEqual(value['status'], 'available'); self.assertEqual(value['entry_count'], 3)
        self.assertEqual([entry['entry_id'] for entry in value['entries']], ['e0001', 'e0002', 'e0003'])
        unchanged, a, b = value['entries']
        self.assertTrue(unchanged['mtime_equal']); self.assertEqual(unchanged['mtime_delta_ns'], 0)
        self.assertEqual((a['source_flags'], a['destination_flags'], a['mtime_delta_ns']), (64, 0, -7))
        self.assertEqual((a['source_acl'], a['destination_acl'], a['acl_equal']), ('nonempty', 'empty', False))
        self.assertEqual((b['source_kind'], b['mtime_delta_ns']), ('symlink', 5))
        self.assertTrue(all(set(entry) == probe.DETAIL_ENTRY_FIELDS for entry in value['entries']))
        encoded = json.dumps(value)
        for secret in ('PRIVATE', '234567891', '987654321', '123456789', 'deadbeef', secret_acl):
            self.assertNotIn(secret, encoded)
        self.assertLessEqual(len(encoded.encode()), probe.DETAIL_MAX_BYTES)

    def test_normalized_topology_preserves_split_merge_and_symlink_classes_without_inode_ids(self):
        entries = {'': detail_entry('directory'), **{f'PRIVATE-{name}': detail_entry() for name in 'ABCD'},
                   'PRIVATE-E': detail_entry('symlink'), 'PRIVATE-F': detail_entry('symlink')}
        source = detail_snapshot(entries, [['PRIVATE-A', 'PRIVATE-B'], ['PRIVATE-C', 'PRIVATE-D'], ['PRIVATE-E', 'PRIVATE-F']])
        destination = detail_snapshot(deepcopy(entries), [['PRIVATE-D', 'PRIVATE-B'], ['PRIVATE-C', 'PRIVATE-A']])
        value = self.detail(source, destination)
        self.assertEqual(value['entry_count'], 7)
        self.assertEqual(value['source_hardlink_groups'], [['e0002', 'e0003'], ['e0004', 'e0005'], ['e0006', 'e0007']])
        self.assertEqual(value['destination_hardlink_groups'], [['e0002', 'e0004'], ['e0003', 'e0005']])
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_missing_and_extra_entries_have_explicit_absence_without_partial_timestamp_claims(self):
        source = detail_snapshot()
        destination = detail_snapshot({'': detail_entry('directory'), 'PRIVATE-extra': detail_entry('symlink')})
        value = self.detail(source, destination)
        self.assertEqual(value['entry_count'], 3)
        absent = [entry for entry in value['entries'] if entry['source_kind'] is None or entry['destination_kind'] is None]
        self.assertEqual(len(absent), 2)
        self.assertTrue(all(entry['mtime_equal'] is None and entry['mtime_delta_ns'] is None and entry['acl_equal'] is None for entry in absent))

    def test_empty_acl_state_does_not_erase_serialization_difference(self):
        source = detail_snapshot(); destination = deepcopy(source)
        destination['entries']['PRIVATE-name']['acl']['text_hex'] = b'!#acl 1\n\x00'.hex()
        entry = self.detail(source, destination)['entries'][1]
        self.assertEqual((entry['source_acl'], entry['destination_acl']), ('empty', 'empty'))
        self.assertFalse(entry['acl_equal'])

    def test_unknown_identity_or_outside_closure_suppresses_all_detail(self):
        for options in ({'source_ok': False}, {'outside_ok': False}, {'independent': False}, {'independent': None}):
            with self.subTest(options=options):
                self.assertEqual(self.detail({}, {}, **options), {'schema': 1, 'status': 'unavailable', 'reason': 'identity_unverified'})

    def test_invalid_metadata_and_topology_fail_closed_without_private_values(self):
        bad = []
        for field, value in (('flags', True), ('flags', -1), ('flags', 1 << 32), ('mtime_ns', True), ('kind', 'PRIVATE-kind')):
            source = detail_snapshot(); source['entries']['PRIVATE-name'][field] = value; bad.append(source)
        source = detail_snapshot(); source['entries']['PRIVATE-name']['acl']['unavailable'] = 'PRIVATE exception /private/path'; bad.append(source)
        source = detail_snapshot(); source['entries']['PRIVATE-name']['acl']['text_hex'] = 'PRIVATE-invalid'; bad.append(source)
        source = detail_snapshot(); source['entries']['PRIVATE-name'] = None; bad.append(source)
        source = detail_snapshot(); source['unavailable_fields'] = None; bad.append(source)
        for groups in ([['PRIVATE-name', 'PRIVATE-name']], [['PRIVATE-name', 'missing']], [['', 'PRIVATE-name']], [['PRIVATE-name']]):
            bad.append(detail_snapshot(groups=groups))
        for source in bad:
            with self.subTest(source=source):
                value = self.detail(source, detail_snapshot())
                self.assertEqual(value, {'schema': 1, 'status': 'unavailable', 'reason': 'detail_schema_invalid'})

    def test_entry_and_serialized_bounds_never_export_truncated_detail(self):
        entries = {'': detail_entry('directory'), **{f'PRIVATE-{i:03}': detail_entry() for i in range(probe.DETAIL_MAX_ENTRIES - 1)}}
        source = detail_snapshot(entries)
        value = self.detail(source, deepcopy(source))
        self.assertEqual(value['entry_count'], probe.DETAIL_MAX_ENTRIES)
        self.assertLessEqual(len(json.dumps(value).encode()), probe.DETAIL_MAX_BYTES)
        source['entries']['PRIVATE-over-limit'] = detail_entry()
        self.assertEqual(self.detail(source, source), {'schema': 1, 'status': 'unavailable', 'reason': 'detail_bounds_exceeded'})
        with mock.patch.object(probe, 'DETAIL_MAX_BYTES', 1):
            self.assertEqual(self.detail(detail_snapshot(), detail_snapshot()),
                             {'schema': 1, 'status': 'unavailable', 'reason': 'detail_bounds_exceeded'})


class DirectoryProbe(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='directory-probe-mock-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.scratch = self.root / 'scratch'; self.scratch.mkdir()
        self.binary = self.root / 'stallionfs'; self.binary.write_bytes(b'mocked binary'); self.binary.chmod(0o700)
        self.helper = self.root / 'helper'; self.helper.write_bytes(b'NEVER EXECUTE'); self.helper.chmod(0o700)
        self.wheel = self.root / 'package.whl'; self.wheel.write_bytes(b'not installed')
        self.commands = []; self.docs = mock.Mock(); self.last_snapshot_count = None

    def run_probe(self, *, response=None, capture=None, missing_coverage=False, changed_pin=False,
                  source_changed=False, host=True, expected_error=None, sharing=True, pin_unavailable=False,
                  first_recipe_only=False, destination_preserved=True, restore_first_recipe=False,
                  restore_status='restored_pending_final_verifiers', restore_final_preserved=True, restore_close=True,
                  admission_error=None, setup_capture=False):
        cases = [(probe.FIRST_RECIPE if first_recipe_only and i == 0 else f'controlled-{i:02}',
                  expected_error if i == 0 else None) for i in range(probe.MAX_SMALL_CASES)]
        def prepare(base, name, *_):
            for entry in ('source', 'parent', 'outside'): (base / entry).mkdir()
            if first_recipe_only:
                for directory in ('a', 'b', 'c'): (base / 'source' / directory).mkdir()
                (base / 'source/a/file').write_bytes(b'original')
                for directory in ('b', 'c'): os.link(base / 'source/a/file', base / 'source' / directory / 'file')
            return (base / 'source', base / 'parent', base / 'outside', dict(cases)[name], [],
                    {field: not missing_coverage for field in probe.COVERAGE})
        def docs(base, name, specification):
            self.docs(name, specification)
            path = base / name; path.mkdir(); return path
        snapshot = detail_snapshot() if first_recipe_only else {'entries': {}, 'unavailable_fields': []}
        snapshots = mock.Mock(return_value=snapshot)
        checks = {'strict_equal': destination_preserved, 'sparse_preserved': True, 'independent_clone': True, 'candidate_losses': []}
        self.restorer = mock.Mock()
        self.restorer.summary = {'status': 'incomplete', 'error': 'restoration_close_failed'}
        self.restorer.close.return_value = restore_close
        def admission_report():
            closed = self.restorer.close.called
            return {'status': 'complete', 'phase': 'complete', 'refusal_code': None, 'errno': None,
                    'close': {'status': ('complete' if restore_close else 'incomplete') if closed else 'deferred',
                              'attempts': int(closed), 'failures': int(closed and not restore_close),
                              'errno': 5 if closed and not restore_close else None}}
        self.restorer.admission_report.side_effect = admission_report
        def reconstruct(_):
            checks['strict_equal'] = restore_final_preserved
            return {'status': restore_status}
        self.restorer.restore.side_effect = reconstruct
        restoration_module = types.ModuleType('native_directory_restore')
        restoration_module.Session = mock.Mock(return_value=self.restorer)
        restoration_module.Session.side_effect = admission_error
        restoration_module.AdmissionError = restoration_support.AdmissionError
        restoration_module.refusal_report = restoration_support.refusal_report
        product = types.ModuleType('stallionfs'); product.__file__ = '/private/tmp/installed/stallionfs/__init__.py'
        budget = types.ModuleType('stallionfs._benchmark_budget')
        pin_count = 0
        def pins(_):
            nonlocal pin_count
            pin_count += 1
            if pin_unavailable: raise FileNotFoundError('PRIVATE missing source /private/source-path')
            return {'source': ('b' if changed_pin and any(row[0][0] == str(self.helper) for row in self.commands) else 'a') * 64}
        def command(argv, **options):
            self.commands.append((argv, options))
            options['receipt'].update(pid=1234, exit_code=0, completion_uncertain=False)
            if argv[0] == str(self.helper):
                self.last_snapshot_count = snapshots.call_count
                if capture == 'exception': raise RuntimeError('PRIVATE raw capture diagnostic')
                if capture == 'uncertain': options['receipt']['completion_uncertain'] = True
                if capture == 'exit': options['receipt']['exit_code'] = 1
                value = response if response is not None else native()
                if expected_error and len([row for row in self.commands if row[0][0] == str(self.helper)]) == 1:
                    value = native(0, expected_error[0])
                if first_recipe_only:
                    target = Path(argv[1]) / argv[5] / argv[6]; target.mkdir()
                    for directory in ('a', 'b', 'c'): (target / directory).mkdir()
                    (target / 'a/file').write_bytes(b'original')
                    for directory in ('b', 'c'): os.link(target / 'a/file', target / directory / 'file')
                raw = value if isinstance(value, bytes) else json.dumps(value).encode()
                return subprocess.CompletedProcess(argv, 0, raw, b'')
            if argv[0] == '/usr/bin/sw_vers': return subprocess.CompletedProcess(argv, 0, b'26B118\n', b'')
            if setup_capture: options['receipt']['completion_uncertain'] = True
            return subprocess.CompletedProcess(argv, 0, b'[]', b'')
        budget.command = command
        source_verifications = 0
        def verify_source(*_):
            nonlocal source_verifications
            source_verifications += 1
            return {'unchanged': not (source_changed and source_verifications == 2)}
        output = self.root / 'status.json'
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(sys.modules, {'stallionfs': product, 'stallionfs._benchmark_budget': budget,
                                                              'native_directory_restore': restoration_module}))
            stack.enter_context(mock.patch.dict(os.environ, {'GITHUB_ACTIONS': 'true' if host else 'false',
                'STALLIONFS_DIRECTORY_FEASIBILITY_HOSTED': '1', 'RUNNER_TEMP': str(self.root)}))
            stack.enter_context(mock.patch.object(sys, 'platform', 'darwin'))
            stack.enter_context(mock.patch.object(probe, 'pins', side_effect=pins))
            stack.enter_context(mock.patch.object(probe, 'recipes', return_value=cases))
            stack.enter_context(mock.patch.object(probe, 'prepare', side_effect=prepare))
            stack.enter_context(mock.patch.object(fileops, 'scratch_volume', return_value={'ignore_ownership': False}))
            self.mounts = stack.enter_context(mock.patch.object(fileops, 'no_mounts_below'))
            stack.enter_context(mock.patch.object(fileops, 'large_fixture', side_effect=docs))
            stack.enter_context(mock.patch.object(native_fixtures, 'enrich_metadata'))
            stack.enter_context(mock.patch.object(native_fixtures, 'verify_metadata_coverage', return_value={'populated': True}))
            stack.enter_context(mock.patch.object(native_correctness, 'snapshot', snapshots))
            stack.enter_context(mock.patch.object(native_correctness, 'verify_clone', return_value=checks))
            stack.enter_context(mock.patch.object(native_correctness, 'verify_source', side_effect=verify_source))
            stack.enter_context(mock.patch.object(native_correctness, 'clone_sharing', return_value={'full_data_stream_sharing': sharing}))
            stack.enter_context(mock.patch.object(native_suite, 'cache_prepare', side_effect=AssertionError('No cache/timing work')))
            self.removals = stack.enter_context(mock.patch.object(probe.shutil, 'rmtree', wraps=shutil.rmtree))
            code = probe.probe(self.binary, self.wheel, self.helper, self.scratch, output, 'a' * 40,
                               first_recipe_only=first_recipe_only, restore_first_recipe=restore_first_recipe)
        return code, json.loads(output.read_text()), snapshots

    def test_restoration_keeps_raw_negative_and_runs_final_verifiers_with_exactly_one_helper_and_no_docs(self):
        code, value, _ = self.run_probe(first_recipe_only=True, restore_first_recipe=True, destination_preserved=False)
        self.assertEqual(code, 0); self.assertEqual(value['status'], 'first_recipe_restoration_complete')
        self.assertFalse(value['full_gate_qualified']); self.assertFalse(value['docs_attempted'])
        self.assertEqual(value['helper_invocations'], 1); self.assertEqual(value['clone_calls'], 1)
        self.assertFalse(value['cases'][0]['raw_clone']['passed']); self.assertTrue(value['cases'][0]['passed'])
        self.restorer.restore.assert_called_once(); self.restorer.close.assert_called_once()
        self.assertEqual((value['setup_completion'], value['target_completion'], value['helper_launch']),
                         ('complete', 'complete', 'observed'))
        self.assertEqual(value['restoration_completion'], 'restored_pending_final_verifiers')
        self.assertEqual((value['restoration_admission']['status'], value['restoration_admission']['phase']), ('complete', 'complete'))
        self.assertEqual(value['restoration_admission']['close']['status'], 'complete')
        self.docs.assert_not_called()

    def test_restoration_failure_or_unknown_completion_never_rescans_or_starts_later_work(self):
        _, value, snapshots = self.run_probe(first_recipe_only=True, restore_first_recipe=True, capture='uncertain')
        self.restorer.restore.assert_not_called()
        self.assertEqual(snapshots.call_count, self.last_snapshot_count)
        self.assertEqual(value['target_completion'], 'unknown'); self.assertEqual(value['cleanup'], 'retained_ephemeral')
        self.assertEqual(value['helper_launch'], 'observed'); self.assertEqual(value['restoration_completion'], 'not_started')
        self.setUp()
        _, value, snapshots = self.run_probe(first_recipe_only=True, restore_first_recipe=True, restore_status='incomplete')
        self.assertEqual(value['error'], 'restoration_incomplete'); self.assertEqual(value['cleanup'], 'retained_ephemeral')
        self.assertEqual(snapshots.call_count, self.last_snapshot_count + 3)
        self.docs.assert_not_called()

    def test_restoration_cannot_override_failed_final_verifier_or_close_failure(self):
        for options, error in (({'restore_final_preserved': False}, 'correctness_failed'),
                               ({'restore_close': False}, 'restoration_close_failed')):
            with self.subTest(options=options):
                self.setUp()
                code, value, _ = self.run_probe(first_recipe_only=True, restore_first_recipe=True, **options)
                self.assertEqual(code, 1); self.assertEqual(value['status'], 'incomplete')
                self.assertEqual(value['error'], error); self.assertEqual(value['cleanup'], 'retained_ephemeral')
                if not options.get('restore_close', True):
                    self.assertEqual(value['restoration_admission']['status'], 'complete')
                    self.assertEqual(value['restoration_admission']['close']['status'], 'incomplete')

    def test_restoration_flag_requires_first_recipe_scope_before_any_helper(self):
        code, value, _ = self.run_probe(restore_first_recipe=True)
        self.assertEqual(code, 1); self.assertEqual(value['error'], 'restoration_scope_invalid')
        self.assertEqual(value['helper_invocations'], 0); self.assertFalse(value['docs_attempted'])

    def test_constructor_refusal_preserves_report_close_failure_and_no_helper_or_method_start(self):
        report = {'status': 'refused', 'phase': 'acl', 'refusal_code': 'native_error', 'errno': 45,
                  'close': {'status': 'incomplete', 'attempts': 3, 'failures': 1, 'errno': 9}}
        error = restoration_support.AdmissionError(report)
        code, value, snapshots = self.run_probe(first_recipe_only=True, restore_first_recipe=True, admission_error=error)
        self.assertEqual(code, 1); self.assertEqual(value['stage'], 'restoration_admission')
        self.assertEqual(value['error'], 'restoration_admission_failed')
        self.assertEqual(value['restoration_admission'], report)
        self.assertEqual((value['setup_completion'], value['target_completion'], value['helper_launch'], value['restoration_completion']),
                         ('complete', 'not_started', 'not_started', 'not_started'))
        self.assertEqual(value['cases'], []); self.assertEqual(value['helper_invocations'], 0); self.assertEqual(value['clone_calls'], 0)
        self.assertFalse(value['docs_attempted']); self.assertEqual(value['cleanup'], 'retained_ephemeral')
        self.assertEqual(snapshots.call_count, 3); self.restorer.restore.assert_not_called()
        self.removals.assert_not_called(); self.docs.assert_not_called()
        self.assertLessEqual(len(json.dumps(value).encode()), 65536)

    def test_unclassified_constructor_exception_is_redacted_with_unproved_close(self):
        _, value, snapshots = self.run_probe(first_recipe_only=True, restore_first_recipe=True,
            admission_error=RuntimeError('PRIVATE /private/path ACL contents'))
        report = value['restoration_admission']
        self.assertEqual((report['phase'], report['refusal_code'], report['errno']), ('unknown', 'admission_error', None))
        self.assertEqual(report['close'], {'status': 'unknown', 'attempts': 0, 'failures': 0, 'errno': None})
        self.assertEqual(value['target_completion'], 'not_started'); self.assertEqual(snapshots.call_count, 3)
        self.assertNotIn('PRIVATE', json.dumps(value)); self.assertNotIn('/private/path', json.dumps(value))
        self.assertNotIn('ACL contents', json.dumps(value)); self.removals.assert_not_called()

    def test_uncertain_setup_capture_does_not_manufacture_helper_or_method_completion(self):
        code, value, snapshots = self.run_probe(first_recipe_only=True, restore_first_recipe=True, setup_capture=True)
        self.assertEqual(code, 1); self.assertEqual(value['setup_completion'], 'unknown')
        self.assertEqual(value['error'], 'setup_completion_unknown')
        self.assertEqual((value['target_completion'], value['helper_launch'], value['restoration_completion']),
                         ('not_started', 'not_started', 'not_started'))
        self.assertEqual(value['cases'], []); self.assertEqual(value['helper_invocations'], 0)
        self.assertEqual(snapshots.call_count, 0); self.assertEqual(value['cleanup'], 'retained_ephemeral')
        self.restorer.restore.assert_not_called(); self.removals.assert_not_called()

    def test_successful_first_recipe_only_stops_after_one_invocation_without_qualifying_full_gate(self):
        code, value, _ = self.run_probe(first_recipe_only=True)
        self.assertEqual(code, 0); self.assertEqual(value['status'], 'first_recipe_diagnostic_complete')
        self.assertTrue(value['first_recipe_only']); self.assertFalse(value['full_gate_qualified'])
        self.assertEqual((value['helper_invocations'], value['clone_calls'], len(value['cases'])), (1, 1, 1))
        self.assertEqual(value['cases'][0]['case'], probe.FIRST_RECIPE)
        self.assertTrue(value['cases'][0]['passed'])
        self.assertEqual(value['cases'][0]['first_recipe_detail']['status'], 'available')
        self.assertFalse(value['docs_attempted']); self.docs.assert_not_called()
        self.assertLessEqual(len(json.dumps(value).encode()), 65536)

    def test_first_recipe_failure_keeps_strict_stop_and_detail_without_later_work(self):
        code, value, _ = self.run_probe(first_recipe_only=True, destination_preserved=False)
        self.assertEqual(code, 1); self.assertEqual(value['error'], 'correctness_failed')
        self.assertEqual(value['status'], 'incomplete'); self.assertFalse(value['full_gate_qualified'])
        self.assertEqual((value['helper_invocations'], value['clone_calls'], len(value['cases'])), (1, 1, 1))
        self.assertEqual(value['cases'][0]['first_recipe_detail']['status'], 'available')
        self.assertFalse(value['docs_attempted']); self.docs.assert_not_called(); self.removals.assert_not_called()

    def test_first_recipe_unknown_capture_never_builds_detail_or_rescans(self):
        with mock.patch.object(probe, 'first_recipe_detail', wraps=probe.first_recipe_detail) as detail:
            _, value, snapshots = self.run_probe(first_recipe_only=True, capture='uncertain')
        detail.assert_not_called(); self.assertEqual(snapshots.call_count, self.last_snapshot_count)
        self.assertEqual(value['target_completion'], 'unknown'); self.assertIsNone(value['clone_calls'])
        self.assertEqual(value['helper_invocations'], 1); self.assertFalse(value['full_gate_qualified'])
        self.assertFalse(value['docs_attempted']); self.docs.assert_not_called(); self.removals.assert_not_called()

    def test_first_recipe_identity_failure_suppresses_detail_without_additional_snapshots(self):
        _, value, snapshots = self.run_probe(first_recipe_only=True, source_changed=True)
        self.assertEqual(value['error'], 'correctness_failed')
        self.assertEqual(value['cases'][0]['first_recipe_detail'],
                         {'schema': 1, 'status': 'unavailable', 'reason': 'identity_unverified'})
        self.assertEqual(snapshots.call_count, self.last_snapshot_count + 3)
        self.assertFalse(value['docs_attempted']); self.docs.assert_not_called(); self.removals.assert_not_called()

    def test_first_recipe_missing_detail_cannot_claim_diagnostic_completion(self):
        with mock.patch.object(probe, 'first_recipe_detail', return_value={'schema': 1, 'status': 'unavailable', 'reason': 'detail_bounds_exceeded'}):
            code, value, _ = self.run_probe(first_recipe_only=True)
        self.assertEqual(code, 1); self.assertEqual(value['status'], 'incomplete')
        self.assertEqual(value['error'], 'first_recipe_detail_unavailable')
        self.assertEqual(value['helper_invocations'], 1); self.assertFalse(value['full_gate_qualified'])
        self.assertFalse(value['docs_attempted']); self.docs.assert_not_called()

    def test_complete_gate_permits_exactly_one_unchanged_docs_fixture_and_only_sanitized_status(self):
        code, value, _ = self.run_probe()
        self.assertEqual(code, 0); self.assertEqual(value['clone_calls'], 20)
        self.assertEqual(value['status'], 'feasible_controlled_fixture_only')
        self.assertEqual(value['cleanup'], 'complete'); self.assertEqual(len(value['cases']), 20)
        self.docs.assert_called_once_with('docs_5k_100mb', {'files': 5000, 'bytes': 100000000})
        self.assertEqual(value['benchmark_verdict'], 'not_applicable')
        self.assertEqual(value['concurrency_and_cancellation'], 'unresolved')
        self.assertNotIn(str(self.root), json.dumps(value)); self.assertNotIn('PRIVATE', json.dumps(value))
        for argv, options in self.commands:
            self.assertLessEqual(len(argv), 11); self.assertLessEqual(options['timeout'], 60)
            self.assertEqual(options['output_limit'], 65536)

    def test_expected_admission_refusal_is_completed_and_has_no_manufactured_native_return(self):
        code, value, _ = self.run_probe(expected_error=(13,))
        self.assertEqual(code, 0); self.assertEqual(value['target_completion'], 'complete')
        first = value['cases'][0]
        self.assertTrue(first['passed']); self.assertIsNone(first['native_return'])
        self.assertIsNone(first['native_errno']); self.assertEqual(first['admission_errno'], 13)
        self.assertEqual(first['clone_calls'], 0); self.assertEqual(value['clone_calls'], 19)

    def test_unexpected_completed_native_error_stops_without_retry_or_post_observation(self):
        code, value, snapshots = self.run_probe(response=native(1, 5))
        self.assertEqual(code, 1); self.assertEqual(value['error'], 'clone_failed')
        self.assertEqual(value['target_completion'], 'complete')
        self.assertEqual(snapshots.call_count, self.last_snapshot_count)
        self.assertEqual(value['clone_calls'], 1); self.assertFalse(value['docs_attempted'])
        self.removals.assert_not_called(); self.docs.assert_not_called()

    def test_uncertain_capture_never_observes_or_cleans_or_retries(self):
        code, value, snapshots = self.run_probe(capture='uncertain')
        self.assertEqual(code, 1); self.assertEqual(value['target_completion'], 'unknown')
        self.assertEqual(snapshots.call_count, self.last_snapshot_count)
        self.removals.assert_not_called(); self.docs.assert_not_called()
        self.assertIsNone(value['clone_calls']); self.assertIsNone(value['cases'][0]['clone_calls'])
        self.assertEqual(len(self.commands), 3); self.assertEqual(self.mounts.call_count, 1)

    def test_capture_exception_remains_private_and_retained(self):
        _, value, snapshots = self.run_probe(capture='exception')
        self.assertEqual(value['target_completion'], 'unknown'); self.assertNotIn('PRIVATE', json.dumps(value))
        self.assertEqual(snapshots.call_count, self.last_snapshot_count); self.removals.assert_not_called()

    def test_protocol_failure_retains_root_without_post_observation(self):
        _, value, snapshots = self.run_probe(response=b'PRIVATE invalid JSON')
        self.assertEqual(value['target_completion'], 'unknown'); self.assertEqual(value['error'], 'protocol_invalid')
        self.assertEqual(snapshots.call_count, self.last_snapshot_count); self.removals.assert_not_called()

    def test_changed_source_pin_after_call_stops_before_verification_or_cleanup(self):
        _, value, snapshots = self.run_probe(changed_pin=True)
        self.assertEqual(value['error'], 'source_changed'); self.assertFalse(value['docs_attempted'])
        self.assertEqual(snapshots.call_count, self.last_snapshot_count); self.removals.assert_not_called()

    def test_missing_material_coverage_stops_before_document_fixture(self):
        _, value, _ = self.run_probe(missing_coverage=True)
        self.assertEqual(value['error'], 'coverage_incomplete'); self.assertFalse(value['docs_attempted'])
        self.docs.assert_not_called()

    def test_source_change_or_unproven_sharing_cannot_pass(self):
        _, value, _ = self.run_probe(source_changed=True)
        self.assertEqual(value['error'], 'correctness_failed'); self.assertFalse(value['docs_attempted'])
        self.removals.assert_not_called()

    def test_unproven_sharing_stops_before_docs_and_retains_fixture(self):
        _, value, _ = self.run_probe(sharing=False)
        self.assertEqual(value['error'], 'correctness_failed'); self.assertFalse(value['docs_attempted'])
        self.removals.assert_not_called(); self.docs.assert_not_called()

    def test_close_error_stops_before_post_observation_and_cleanup(self):
        _, value, snapshots = self.run_probe(response=dict(native(), close_error=5))
        self.assertEqual(value['error'], 'descriptor_close_failed'); self.assertEqual(value['target_completion'], 'complete')
        self.assertEqual(snapshots.call_count, self.last_snapshot_count); self.removals.assert_not_called()

    def test_host_refusal_precedes_all_commands_and_fixture_creation(self):
        _, value, _ = self.run_probe(host=False)
        self.assertEqual(value['error'], 'host_invalid'); self.assertEqual(self.commands, [])
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_real_source_pins_use_committed_inputs_without_generated_install_directory(self):
        checkout = Path(__file__).parents[1]
        observed = probe.pins(checkout)
        self.assertEqual(set(observed), set(probe.PIN_PATHS))
        self.assertIn('tests/test_native_directory_restore_fd_observer.py', observed)
        self.assertEqual(len(observed), 18)
        self.assertNotIn('stallionfs/_benchmark_runtime/native_metrics.py', observed)
        self.assertEqual(observed['tests/perf/native_metrics.py'],
                         hashlib.sha256((checkout / 'tests/perf/native_metrics.py').read_bytes()).hexdigest())
        self.assertTrue(all(len(value) == 64 for value in observed.values()))

    def test_missing_real_pin_uses_fixed_error_without_exporting_path(self):
        with self.assertRaises(probe.ProbeError) as caught: probe.pins(self.root)
        self.assertEqual(str(caught.exception), 'pin_unavailable')

    def test_source_pin_failure_records_stage_before_commands_or_fixture_creation(self):
        _, value, _ = self.run_probe(pin_unavailable=True)
        self.assertEqual((value['stage'], value['error']), ('source_pins', 'pin_unavailable'))
        self.assertEqual(value['target_completion'], 'not_started')
        self.assertEqual((value['helper_invocations'], value['clone_calls']), (0, 0))
        self.assertEqual(value['cases'], []); self.assertFalse(value['docs_attempted'])
        self.assertEqual(value['cleanup'], 'not_started'); self.assertEqual(self.commands, [])
        self.assertEqual(list(self.scratch.iterdir()), [])
        self.assertNotIn('PRIVATE', json.dumps(value)); self.assertNotIn('/private/source-path', json.dumps(value))

    def test_protocol_rejects_duplicate_unknown_boolean_and_contradictory_fields(self):
        self.assertEqual(probe.protocol(json.dumps(native()).encode()), native())
        self.assertEqual(probe.protocol(json.dumps(native(0, 1)).encode()), native(0, 1))
        invalid = [dict(native(), extra='PRIVATE'), dict(native(), clone_calls=True),
                   dict(native(), native_errno=1), dict(native(0, 1), native_return=-1),
                   dict(native(0, 1), admission_errno=0), dict(native(), native_return=True)]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(probe.ProbeError): probe.protocol(json.dumps(value).encode())
        with self.assertRaises(probe.ProbeError): probe.protocol(b'{"schema":1,"schema":1}')

    def test_workflow_routes_each_mode_and_artifact_explicitly(self):
        text = (Path(__file__).parents[1] / '.github/workflows/checks.yml').read_text()
        self.assertNotIn("inputs.mode != 'thread-cpu'", text)
        self.assertIn('options: [compare, thread-cpu, directory-feasibility, delete-thread-cpu]', text)
        for mode in ('compare', 'thread-cpu', 'directory-feasibility', 'delete-thread-cpu'):
            self.assertIn(f"if: inputs.mode == '{mode}'", text)
        directory_step = text.split('      - name: Collect hosted directory feasibility\n')[1].split('      - name: Show correctness')[0]
        self.assertNotIn('native_suite.py', directory_step); self.assertNotIn('thread-cpu', directory_step)
        self.assertIn("'--revision', os.environ['GITHUB_SHA'], '--first-recipe-only', '--restore-first-recipe']", directory_step)
        self.assertEqual(text.count("'--first-recipe-only'"), 1)
        self.assertEqual(text.count("'--restore-first-recipe'"), 1)
        self.assertIn('directory-feasibility-status.json', directory_step)
        fallback = directory_step.split('          if not output.exists():\n')[1]
        self.assertIn("'scope': 'hosted first-recipe selective restoration only'", fallback)
        self.assertIn("'first_recipe_only': True, 'restoration_only': True, 'full_gate_qualified': False", fallback)
        self.assertIn("'docs_attempted': None", fallback)
        self.assertIn("'helper_invocations': None", fallback)
        self.assertIn("'clone_calls': None", fallback)
        self.assertNotIn("'docs_attempted': False", fallback)

    def test_inherited_acl_preparation_uses_bounded_xattr_command_without_os_setxattr(self):
        base = self.scratch / 'preparation'; base.mkdir(mode=0o700)
        run = mock.Mock()
        with mock.patch.dict(probe.os.__dict__):
            probe.os.__dict__.pop('setxattr', None)
            prepared = probe.prepare(base, 'inherit-clean', native_fixtures, native_correctness, run)
        run.assert_called_once_with(['/usr/bin/xattr', '-w', 'com.apple.ResourceFork',
                                     'private resource fork', str(base / 'source/file')])
        self.assertIsNone(prepared[3])
        self.assertTrue(prepared[5]['inherited_acl'])
        self.assertEqual((base / 'source/file').read_bytes(), b'original')


if __name__ == '__main__': unittest.main()
