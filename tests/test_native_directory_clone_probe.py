"""Pure/mock safety checks. This module never executes a clone helper."""
from contextlib import ExitStack
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


def native(calls=1, error=0):
    return {'schema': 1, 'marker': probe.MARKER, 'native_return': (-1 if error else 0) if calls else None,
            'native_errno': error if calls else None, 'admission_errno': error if not calls else 0,
            'clone_calls': calls, 'close_error': 0}


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
                  source_changed=False, host=True, expected_error=None, sharing=True, pin_unavailable=False):
        cases = [(f'controlled-{i:02}', expected_error if i == 0 else None) for i in range(probe.MAX_SMALL_CASES)]
        def prepare(base, name, *_):
            for entry in ('source', 'parent', 'outside'): (base / entry).mkdir()
            return (base / 'source', base / 'parent', base / 'outside', dict(cases)[name], [],
                    {field: not missing_coverage for field in probe.COVERAGE})
        def docs(base, name, specification):
            self.docs(name, specification)
            path = base / name; path.mkdir(); return path
        snapshots = mock.Mock(return_value={'entries': {}, 'unavailable_fields': []})
        checks = {'strict_equal': True, 'sparse_preserved': True, 'independent_clone': True, 'candidate_losses': []}
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
                raw = value if isinstance(value, bytes) else json.dumps(value).encode()
                return subprocess.CompletedProcess(argv, 0, raw, b'')
            if argv[0] == '/usr/bin/sw_vers': return subprocess.CompletedProcess(argv, 0, b'26B118\n', b'')
            return subprocess.CompletedProcess(argv, 0, b'[]', b'')
        budget.command = command
        source_verifications = 0
        def verify_source(*_):
            nonlocal source_verifications
            source_verifications += 1
            return {'unchanged': not (source_changed and source_verifications == 2)}
        output = self.root / 'status.json'
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(sys.modules, {'stallionfs': product, 'stallionfs._benchmark_budget': budget}))
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
            code = probe.probe(self.binary, self.wheel, self.helper, self.scratch, output, 'a' * 40)
        return code, json.loads(output.read_text()), snapshots

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
        self.assertIn('options: [compare, thread-cpu, directory-feasibility]', text)
        self.assertIn("if: inputs.mode == 'directory-feasibility'", text)
        directory_step = text.split('      - name: Collect hosted directory feasibility\n')[1].split('      - name: Show correctness')[0]
        self.assertNotIn('native_suite.py', directory_step); self.assertNotIn('thread-cpu', directory_step)
        self.assertIn('directory-feasibility-status.json', directory_step)
        fallback = directory_step.split('          if not output.exists():\n')[1]
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
