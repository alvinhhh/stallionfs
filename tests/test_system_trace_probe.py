"""Privacy, completion and one-attempt boundaries; no profiler or clone executes."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

PERF = Path(__file__).parent / 'perf'
with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
    spec = importlib.util.spec_from_file_location('system_trace_probe_under_test', PERF / 'system_trace_probe.py')
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    import fileops
    import native_correctness
    import native_fixtures
    import native_suite

TOC = b'<trace-toc><run number="1"><data><table schema="syscall" target-pid="PRIVATE_PID"/></data></run></trace-toc>'
EXPORTED = b'''<trace-query-result><node xpath="PRIVATE_PATH">
<schema name="syscall"><col><mnemonic>start</mnemonic><name>PRIVATE_DISPLAY</name><type>timestamp</type></col></schema>
<row><schema name="PRIVATE_ROW_SCHEMA"/><value>PRIVATE_ROW_VALUE /Users/private/file</value></row>
</node></trace-query-result>'''


class TraceProbe(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='system-trace-probe-test-')
        self.root = Path(self.temp.name).resolve()
        self.binary = self.root / 'stallionfs'
        self.binary.write_bytes(b'not executed')
        self.binary.chmod(0o700)
        self.commands = []
        self.config = {'nonce': 'f' * 32, 'argv': [str(self.binary), 'clone', '--jobs', '2', 'source', 'destination'],
                       'cli_sha256': probe.digest(self.binary), 'receipt': str(self.root / 'completion.json'),
                       'deadline': time.monotonic() + 90}
        self.config['argv_sha256'] = probe.canonical_hash(self.config['argv'])
        self.exported = EXPORTED
        self.record_mode = 'complete'

    def tearDown(self):
        self.temp.cleanup()

    def target_receipt(self, config=None, config_hash='a' * 64):
        config = self.config if config is None else config
        return {'nonce': config['nonce'], 'argv_sha256': config['argv_sha256'],
                'config_sha256': config_hash, 'cli_sha256': config['cli_sha256'],
                'started': time.monotonic() - 0.001, 'ended': time.monotonic(), 'returned': True,
                'capture': {'argv': config['argv'], 'pid': 12345, 'exit_code': 0, 'completion_uncertain': False}}

    def fake_command(self, argv, **options):
        argv = list(argv)
        self.commands.append((argv, options))
        receipt = options.get('receipt')
        if receipt is not None:
            receipt.update(argv=argv, pid=1234, exit_code=0, completion_uncertain=False)
        stdout = b''
        if argv[1:4] == ['xctrace', 'help', 'record']:
            stdout = b'--template --time-limit --no-prompt --output --target-stdout --launch'
        elif argv[1:4] == ['xctrace', 'help', 'export']:
            stdout = b'--input --toc --xpath'
        elif argv[1:4] == ['xctrace', 'list', 'templates']:
            stdout = b'System Trace'
        elif argv[1:3] == ['--json', 'volumes']:
            stdout = b'[]'
        elif argv[1:3] == ['xctrace', 'record']:
            self.assertEqual(argv[argv.index('--time-limit') + 1], '3s')
            self.assertIn('--no-prompt', argv)
            self.assertEqual(options['timeout'], 60)
            self.assertEqual(argv[-2], '--target-launch')
            config_path = Path(argv[-1])
            config = probe.read_private(config_path)
            self.assertEqual(config['argv'][1:4], ['clone', '--jobs', '2'])
            self.assertEqual(config['argv'][0], str(self.binary))
            if self.record_mode != 'missing_completion':
                value = self.target_receipt(config, probe.digest(config_path))
                if self.record_mode == 'uncertain_completion':
                    value['capture']['completion_uncertain'] = True
                probe.write_private(Path(config['receipt']), value)
            Path(argv[argv.index('--output') + 1]).mkdir()
        elif argv[1:3] == ['xctrace', 'export']:
            stdout = TOC if '--toc' in argv else self.exported
        return subprocess.CompletedProcess(argv, 0, stdout, b'PRIVATE_TOOL_STDERR')

    def run_probe(self, *, metadata=True):
        budget = types.ModuleType('stallionfs._benchmark_budget')
        budget.command = self.fake_command
        product = types.ModuleType('stallionfs')
        product.__file__ = '/private/tmp/installed/stallionfs/__init__.py'
        snapshots = mock.Mock(return_value={'entries': {}})

        def small_fixture(base, name, specification):
            self.assertEqual(name, 'docs_5k_100mb')
            self.assertEqual(specification, {'files': 5000, 'bytes': 100000000})
            root = base / name
            root.mkdir()
            return root

        output = self.root / 'public/status.json'
        preserved = {'strict_equal': True, 'sparse_preserved': True, 'independent_clone': True}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(sys.modules, {'stallionfs': product, 'stallionfs._benchmark_budget': budget}))
            stack.enter_context(mock.patch.dict(os.environ, {}, clear=False))
            stack.enter_context(mock.patch.object(sys, 'platform', 'darwin'))
            stack.enter_context(mock.patch.object(probe.resource, 'setrlimit'))
            stack.enter_context(mock.patch.object(fileops, 'scratch_volume', return_value={'filesystem': 'apfs'}))
            stack.enter_context(mock.patch.object(fileops, 'no_mounts_below'))
            stack.enter_context(mock.patch.object(fileops, 'large_fixture', side_effect=small_fixture))
            stack.enter_context(mock.patch.object(fileops, 'fingerprint_sources', return_value={'stallionfs/cli.c': 'b' * 64}))
            stack.enter_context(mock.patch.object(native_fixtures, 'enrich_metadata'))
            stack.enter_context(mock.patch.object(native_fixtures, 'verify_metadata_coverage', return_value={'populated': metadata}))
            stack.enter_context(mock.patch.object(native_correctness, 'snapshot', snapshots))
            stack.enter_context(mock.patch.object(native_correctness, 'compare', return_value=preserved))
            stack.enter_context(mock.patch.object(native_correctness, 'verify_clone', return_value=preserved))
            stack.enter_context(mock.patch.object(native_correctness, 'verify_source', return_value={'unchanged': True}))
            stack.enter_context(mock.patch.object(native_correctness, 'clone_sharing', return_value={'full_data_stream_sharing': True}))
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = probe.probe(self.binary, self.root, output, 'c' * 40)
            self.assertEqual(stdout.getvalue() + stderr.getvalue(), '')
        return code, json.loads(output.read_text()), snapshots

    def test_schema_projection_excludes_rows_paths_display_and_toc_attributes(self):
        selected, exhaustive = probe.toc_selection(TOC)
        self.assertEqual((selected, exhaustive), (['syscall'], True))
        value = probe.schema_metadata(EXPORTED, 'syscall')
        self.assertEqual(value, {'identifier': 'syscall', 'columns': [{'identifier': 'start', 'type': 'timestamp'}]})
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_schema_rejects_unsafe_identifiers_and_unknown_metadata(self):
        bad = [EXPORTED.replace(b'>start<', b'>/Users/private<'),
               EXPORTED.replace(b'>start<', b'> start <'),
               EXPORTED.replace(b'>timestamp<', b'>timestamp secret<'),
               EXPORTED.replace(b'<col>', b'<col target="private">'),
               EXPORTED.replace(b'</col>', b'<unknown>private</unknown></col>'),
               EXPORTED.replace(b'<mnemonic>start</mnemonic>', b'<mnemonic><row>private</row></mnemonic>'),
               EXPORTED.replace(b'<schema name="syscall">', b'<schema name="syscall" target="private">')]
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(probe.ProbeError):
                probe.schema_metadata(raw, 'syscall')

    def test_schema_rejects_dtd_entities_encoding_depth_nodes_and_size(self):
        bad = [b'<!DOCTYPE x [<!ENTITY x "private">]><x>&x;</x>', b'<!ENTITY x "private"><x/>',
               b'<?xml version="1.0" encoding="UTF-16"?><x/>', b'<x>' * 33 + b'</x>' * 33,
               b'<x>' + b'<a/>' * 50000 + b'</x>', b'x' * (probe.MAX_XML + 1)]
        for raw in bad:
            with self.subTest(size=len(raw)), self.assertRaises((probe.ProbeError, ET_PARSE_ERRORS)):
                probe.parse_xml(raw)

    def test_schema_count_is_bounded_without_row_publication(self):
        toc = b'<trace-toc><run number="1"><data>' + b''.join(
            f'<table schema="table_{index}"/>'.encode() for index in range(probe.MAX_EXPORTS + 1)) + b'</data></run></trace-toc>'
        selected, exhaustive = probe.toc_selection(toc)
        self.assertEqual(len(selected), probe.MAX_EXPORTS)
        self.assertFalse(exhaustive)

    def test_completion_requires_bound_config_command_and_actual_clean_capture(self):
        good = self.target_receipt()
        probe.completion(self.config, good, 'a' * 64)
        changes = [({'nonce': 'wrong'}, None), ({'config_sha256': 'b' * 64}, None),
                   ({'cli_sha256': 'b' * 64}, None), ({'argv_sha256': 'b' * 64}, None),
                   ({'ended': float('nan')}, None), ({'returned': False}, None), ({}, {'completion_uncertain': True}),
                   ({}, {'exit_code': 1}), ({}, {'output_limit_exceeded': True}),
                   ({}, {'cleanup_error': 'PRIVATE'}), ({}, {'error': 'PRIVATE'}),
                   ({}, {'pid': True}), ({}, {'argv': ['wrong']})]
        for outer, capture in changes:
            value = copy.deepcopy(good)
            value.update(outer)
            if capture:
                value['capture'].update(capture)
            with self.subTest(change=(outer, capture)), self.assertRaises(probe.ProbeError):
                probe.completion(self.config, value, 'a' * 64)

    def test_launcher_uses_existing_capture_and_private_actual_pid_receipt(self):
        config_path = self.root / 'config.json'
        probe.write_private(config_path, self.config)
        budget = types.ModuleType('stallionfs._benchmark_budget')
        def command(argv, **kwargs):
            self.assertEqual(argv, self.config['argv'])
            self.assertEqual(kwargs['timeout'], 25)
            self.assertEqual(kwargs['output_limit'], 1048576)
            kwargs['receipt'].update(argv=argv, pid=9876, exit_code=0, completion_uncertain=False)
        budget.command = command
        with mock.patch.dict(sys.modules, {'stallionfs._benchmark_budget': budget}), mock.patch.dict(os.environ):
            self.assertEqual(probe.launcher(config_path), 0)
        value = probe.read_private(Path(self.config['receipt']))
        self.assertEqual(value['capture']['pid'], 9876)
        probe.completion(self.config, value, probe.digest(config_path))

    def test_launcher_capture_must_return_even_if_receipt_looks_clean(self):
        config_path = self.root / 'config.json'
        probe.write_private(config_path, self.config)
        budget = types.ModuleType('stallionfs._benchmark_budget')
        def failed_after_reap(argv, **kwargs):
            kwargs['receipt'].update(argv=argv, pid=9876, exit_code=0, completion_uncertain=False)
            raise OSError('PRIVATE receipt write failure')
        budget.command = failed_after_reap
        with mock.patch.dict(sys.modules, {'stallionfs._benchmark_budget': budget}), mock.patch.dict(os.environ):
            self.assertEqual(probe.launcher(config_path), 1)
        value = probe.read_private(Path(self.config['receipt']))
        self.assertFalse(value['returned'])
        with self.assertRaises(probe.ProbeError):
            probe.completion(self.config, value, probe.digest(config_path))

    def test_complete_mocked_probe_is_one_recording_with_no_cpu_or_raw_publication(self):
        code, result, snapshots = self.run_probe()
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['target_completion'], 'complete')
        self.assertTrue(result['correctness']['passed'])
        self.assertEqual(result['cpu_attribution'], 'unavailable')
        self.assertEqual(result['benchmark_verdict'], 'not_applicable')
        self.assertEqual(result['recording_attempts'], 1)
        self.assertEqual(result['cleanup'], 'complete')
        self.assertEqual(snapshots.call_count, 4)
        self.assertEqual(snapshots.call_args_list[-2].kwargs, {'observe_sharing': True})
        self.assertEqual(snapshots.call_args_list[-1].kwargs, {'observe_sharing': True})
        self.assertEqual(sum(argv[1:3] == ['xctrace', 'record'] for argv, _ in self.commands), 1)
        public = json.dumps(result)
        self.assertNotIn(str(self.root), public)
        self.assertNotIn('PRIVATE', public)
        self.assertNotIn('target_pid', public)
        self.assertFalse(list(self.root.glob('system-trace-private-*')))

    def test_missing_or_uncertain_target_completion_stops_before_post_snapshots_and_exports(self):
        for mode in ('missing_completion', 'uncertain_completion'):
            with self.subTest(mode=mode):
                self.commands.clear()
                self.record_mode = mode
                output = self.root / 'public/status.json'
                if output.exists():
                    output.unlink()
                code, result, snapshots = self.run_probe()
                self.assertEqual(code, 1)
                self.assertEqual(result['target_completion'], 'unknown')
                self.assertIsNone(result['correctness'])
                self.assertEqual(result['cleanup'], 'retained_ephemeral')
                self.assertEqual(snapshots.call_count, 2)
                self.assertFalse(any(argv[1:3] == ['xctrace', 'export'] for argv, _ in self.commands))

    def test_invalid_metadata_omits_whole_section_with_safe_incomplete_status(self):
        self.exported = EXPORTED.replace(b'>start<', b'>/Users/private<')
        code, result, _ = self.run_probe()
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(result['schema_metadata_status'], 'unavailable')
        self.assertNotIn('schema_metadata', result)
        self.assertNotIn('/Users/private', json.dumps(result))

    def test_metadata_fixture_failure_never_records(self):
        code, result, snapshots = self.run_probe(metadata=False)
        self.assertEqual(code, 1)
        self.assertEqual(result['recording_attempts'], 0)
        self.assertEqual(result['error'], 'metadata_incomplete')
        self.assertEqual(snapshots.call_count, 1)

    def test_preflight_failure_never_records_or_prepares_fixture(self):
        original = self.fake_command
        def no_template(argv, **kwargs):
            value = original(argv, **kwargs)
            if list(argv)[1:4] == ['xctrace', 'list', 'templates']:
                value.stdout = b'unsupported'
            return value
        with mock.patch.object(self, 'fake_command', side_effect=no_template):
            code, result, snapshots = self.run_probe()
        self.assertEqual(code, 1)
        self.assertEqual(result['recording_attempts'], 0)
        self.assertEqual(snapshots.call_count, 0)

    def test_recorder_failure_has_one_attempt_no_post_snapshots_or_raw_error(self):
        original = self.fake_command
        def failed_record(argv, **kwargs):
            if list(argv)[1:3] == ['xctrace', 'record']:
                self.commands.append((list(argv), kwargs))
                raise RuntimeError('PRIVATE /Users/private/trace')
            return original(argv, **kwargs)
        with mock.patch.object(self, 'fake_command', side_effect=failed_record):
            code, result, snapshots = self.run_probe()
        self.assertEqual(code, 1)
        self.assertEqual(result['recording_attempts'], 1)
        self.assertEqual(result['target_completion'], 'unknown')
        self.assertEqual(result['cleanup'], 'retained_ephemeral')
        self.assertEqual(snapshots.call_count, 2)
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertEqual(sum(argv[1:3] == ['xctrace', 'record'] for argv, _ in self.commands), 1)

    def test_uncertain_preflight_never_cleans_owned_private_storage(self):
        with mock.patch.object(self, 'fake_command', side_effect=RuntimeError('PRIVATE preflight failure')):
            code, result, snapshots = self.run_probe()
        self.assertEqual(code, 1)
        self.assertEqual(result['recording_attempts'], 0)
        self.assertEqual(result['cleanup'], 'retained_ephemeral')
        self.assertEqual(snapshots.call_count, 0)
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_correctness_requires_source_sharing_independence_and_sentinel(self):
        base = self.root / 'fixture'
        base.mkdir()
        sentinel = base / 'outside-sentinel'
        sentinel.write_bytes(b'keep outside linked trees\n')
        correct = mock.Mock()
        preserved = {'strict_equal': True, 'sparse_preserved': True, 'independent_clone': True}
        correct.verify_clone.return_value = preserved
        correct.verify_source.return_value = {'unchanged': True}
        correct.clone_sharing.return_value = {'full_data_stream_sharing': True}
        def validate():
            return probe.validate_copy(base / 'source', base / 'destination', {}, {}, base, correct, native_suite.preserved)
        self.assertTrue(validate()['passed'])
        correct.verify_source.return_value = {'unchanged': False}
        self.assertFalse(validate()['passed'])
        correct.verify_source.return_value = {'unchanged': True}
        correct.clone_sharing.return_value = {'full_data_stream_sharing': None}
        self.assertFalse(validate()['passed'])
        correct.clone_sharing.return_value = {'full_data_stream_sharing': True}
        correct.verify_clone.return_value = preserved | {'independent_clone': False}
        self.assertFalse(validate()['passed'])
        correct.verify_clone.return_value = preserved
        sentinel.write_bytes(b'changed')
        self.assertFalse(validate()['passed'])

    def test_publication_is_atomic_exclusive_and_size_bounded(self):
        output = self.root / 'public.json'
        probe.publish(output, {'status': 'incomplete'})
        self.assertEqual(json.loads(output.read_text()), {'status': 'incomplete'})
        with self.assertRaises(FileExistsError):
            probe.publish(output, {'status': 'complete'})
        self.assertFalse(list(self.root.glob('.trace-status-*')))
        with self.assertRaises(probe.ProbeError):
            probe.publish(self.root / 'oversize.json', {'bad': 'x' * 65536})
        self.assertFalse((self.root / 'oversize.json').exists())

    def test_owned_private_files_are_exclusive_mode_checked_and_size_bounded(self):
        path = self.root / 'private.json'
        probe.write_private(path, {'safe': True})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            probe.write_private(path, {})
        path.chmod(0o644)
        with self.assertRaises(probe.ProbeError):
            probe.read_private(path)
        path.chmod(0o600)
        with self.assertRaises(probe.ProbeError):
            probe.read_private(path, limit=1)


ET_PARSE_ERRORS = probe.ET.ParseError

if __name__ == '__main__':
    unittest.main()
