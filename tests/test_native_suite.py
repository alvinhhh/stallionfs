"""Native-suite orchestration on tiny fixtures with all command execution mocked."""
from contextlib import ExitStack, redirect_stdout
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PERF = Path(__file__).parent / 'perf'
with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
    spec = importlib.util.spec_from_file_location('native_suite_under_test', PERF / 'native_suite.py')
    suite = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(suite)

JOURNAL = suite.native_report.ReportJournal
SNAPSHOT = suite.native_correctness.snapshot
COMPARE = suite.native_correctness.compare
VERIFY_CLONE = suite.native_correctness.verify_clone
VERIFY_SOURCE = suite.native_correctness.verify_source
SCAN_FIXTURE = suite.native_fixtures.scan_fixture

# Native time -lp field labels; values are synthetic.
TIME_FOOTER = b'''real 0.25
user 0.04
sys 0.02
16384 maximum resident set size
0 average shared memory size
0 average unshared data size
0 average unshared stack size
1 page reclaims
0 page faults
0 swaps
0 block input operations
2 block output operations
0 messages sent
0 messages received
0 signals received
1 voluntary context switches
1 involuntary context switches
1 instructions retired
1 cycles elapsed
16384 peak memory footprint
'''


class NativeSuite(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='native-suite-test-')
        self.root = Path(self.temporary.name).resolve()
        self.binary = self.root / 'stallionfs'
        self.binary.write_bytes(b'not executed\n')
        self.binary.chmod(0o700)
        self.binary.with_name('stallionfs-python').write_bytes(b'not executed helper\n')
        self.output = self.root / 'result.json'
        self.commands = []
        self.measured = []
        self.fixture_calls = []
        self.cache_calls = []
        self.snapshot_calls = []
        self.snapshot_options = []
        self.snapshot_results = []
        self.scan_fixture_calls = []
        self.scan_expected = {}
        self.metadata_calls = []
        self.coverage_calls = []

    def tearDown(self):
        self.temporary.cleanup()

    def snapshot(self, path, **options):
        path = Path(path)
        self.snapshot_calls.append(path)
        self.snapshot_options.append(options)
        if path.is_dir():
            result = SNAPSHOT(path, **options)
        else:
            info = path.stat()
            result = {'payload': path.read_bytes().hex(), 'mode': info.st_mode,
                      'identity': (info.st_dev, info.st_ino)}
        self.snapshot_results.append(result)
        return result

    @staticmethod
    def compare(before, after, baseline=None):
        if 'entries' in before: return COMPARE(before, after, baseline)
        equal = (before['payload'], before['mode']) == (after['payload'], after['mode'])
        return {'strict_equal': equal, 'independent_clone': True,
                'sparse_preserved': True, 'differences': [] if equal else ['payload or mode']}

    @staticmethod
    def verify_clone(before, after):
        if 'entries' in before: return VERIFY_CLONE(before, after)
        return NativeSuite.compare(before, after) | {'independent_clone': before['identity'] != after['identity']}

    @staticmethod
    def verify_source(before, after):
        if 'entries' in before: return VERIFY_SOURCE(before, after)
        differences = [key for key in ('payload', 'mode', 'identity') if before[key] != after[key]]
        return {'unchanged': not differences, 'differences': differences}

    def fixtures(self, base, names):
        self.assertEqual(names, ['tiny_4kib'])
        self.fixture_calls.append(tuple(names))
        folder = base / 'fixtures'; folder.mkdir()
        source = folder / 'tiny'
        source.write_bytes(b'tiny fixture payload')
        return {'tiny_4kib': source}

    def scan_fixture(self, root, files, layout):
        self.scan_fixture_calls.append((root, files, layout))
        expected = SCAN_FIXTURE(root, 2, layout)  # Coordinator test; no 20k workload is executed.
        self.scan_expected[str(root)] = expected
        return expected

    def enrich_metadata(self, root, *, receipt, scan_layout=None):
        self.metadata_calls.append((root, scan_layout, len(self.snapshot_calls)))
        current = list(self.journal.iter_latest('metadata_preparation'))
        self.assertEqual(current[-1]['status'], 'preparing')
        self.assertFalse(self.output.exists())
        receipt.update(path='', test_receipt=len(self.metadata_calls))
        return receipt

    def verify_metadata_coverage(self, observed, receipt):
        self.assertIs(observed, self.snapshot_results[-1])
        self.assertEqual(receipt['test_receipt'], len(self.metadata_calls))
        self.assertEqual(len(self.snapshot_calls), self.metadata_calls[-1][2] + 1)
        self.coverage_calls.append(receipt)
        return {'populated': True, 'seeded_acl_text_bytes': 76, 'counts_include_root': True,
                'regular_files': 1, 'directories': 0, 'symlinks': 0, 'special_entries': 0,
                'logical_bytes': len(bytes.fromhex(observed['payload'])) if 'payload' in observed else 0}

    def command(self, argv, **kwargs):
        argv = [os.fspath(value) for value in argv]
        self.commands.append(argv)
        if argv[:1] == [str(self.binary)] and argv[1:] == ['--json', 'volumes']:
            return subprocess.CompletedProcess(argv, 0, b'{}', b'')
        if argv == [str(self.binary), '--version']:
            return subprocess.CompletedProcess(argv, 0, b'stallionfs test-version\n', b'')
        if argv[:3] == ['/usr/bin/sudo', '-n', '/usr/sbin/purge']:
            return subprocess.CompletedProcess(argv, 1, b'', b'purge unavailable')
        if argv[0] == '/usr/bin/ditto':
            shutil.copy2(argv[-2], argv[-1])
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        raise AssertionError(f'Unexpected setup command {argv}')

    def collect(self, argv, **kwargs):
        argv = [os.fspath(value) for value in argv]
        self.measured.append(argv)
        candidate = argv[0] == str(self.binary)
        operation = ('scan' if argv[0] == '/usr/bin/find' or (candidate and argv[1:3] == ['--json', 'scan']) else
                     argv[1] if candidate else 'move' if argv[0] == '/bin/mv' else 'delete' if argv[0] == '/bin/rm' else 'clone')
        stdout = b''
        if operation == 'clone': shutil.copy2(argv[-2], argv[-1])
        elif operation == 'move': Path(argv[-2]).rename(argv[-1])
        elif operation == 'delete': Path(argv[-1]).unlink()
        elif operation == 'scan':
            source = Path(argv[-1] if candidate else argv[3])
            if candidate: stdout = json.dumps(self.scan_expected[str(source)]).encode()
            else:
                records = []
                for path in source.rglob('*'):
                    info = path.lstat()
                    records.append(f'{info.st_mode:o}\t{info.st_size}\t{info.st_dev}\n')
                stdout = ''.join(records).encode('ascii')
        else: raise AssertionError(operation)
        return {'argv': argv, 'phase': kwargs['phase'], 'exit_code': 0, 'ok': True, 'completion_uncertain': False,
                'stdout_b64': base64.b64encode(stdout).decode('ascii'), 'stderr_b64': '',
                'wall_s': 1.0 if candidate else 2.0, 'user_s': 0.1, 'system_s': 0.1,
                'cpu_s': 0.2, 'rss_bytes': 16384, 'io_input_blocks': 0, 'io_output_blocks': 1,
                'precision_floor': {'wall_s': 1e-9, 'user_s': 0.01, 'system_s': 0.01, 'cpu_s': 0.02}}

    def run_suite(self, *, operations=('clone',), cache=('warm',), copy_tools=('cp-clone',), collector=None, command=None, fixture='tiny_4kib', extra=(), fixture_names=None, sharing=None, enrich=None, coverage=None):
        fixture_names = (fixture,) if fixture_names is None else fixture_names
        argv = ['native_suite.py', '--binary', str(self.binary), '--scratch', str(self.root),
                '--output', str(self.output), '--fixtures', *fixture_names, '--copy-tools', *copy_tools,
                '--operations', *operations, '--cache', *cache, '--runs', '3', '--samples', '10', *extra]
        def warm_manifest(path):
            self.cache_calls.append(str(path))
            return {'hash': Path(path).read_bytes().hex()}
        owner = self
        class CapturingJournal(JOURNAL):
            def __init__(self, output):
                super().__init__(output)
                owner.journal = self
        with ExitStack() as stack:
            patches = [
                mock.patch.object(suite.native_report, 'ReportJournal', CapturingJournal),
                mock.patch.object(sys, 'argv', argv),
                mock.patch.object(suite.platform, 'system', return_value='Darwin'),
                mock.patch.object(suite.fileops, 'command', side_effect=command or self.command),
                mock.patch.object(suite, 'restore_setup_symlink_times', return_value=[]),
                mock.patch.object(suite.fileops, 'scratch_volume', return_value={'fstype': 'apfs'}),
                mock.patch.object(suite.fileops, 'fingerprint_sources', return_value={'product': 'pinned'}),
                mock.patch.object(suite.fileops, 'digest', side_effect=lambda path: 'digest:' + str(path)),
                mock.patch.object(suite.fileops, 'fixtures', side_effect=self.fixtures),
                mock.patch.object(suite.native_fixtures, 'scan_fixture', side_effect=self.scan_fixture),
                mock.patch.object(suite.native_fixtures, 'enrich_metadata', side_effect=enrich or self.enrich_metadata),
                mock.patch.object(suite.native_fixtures, 'verify_metadata_coverage', side_effect=coverage or self.verify_metadata_coverage),
                mock.patch.object(suite.fileops, 'no_mounts_below'),
                mock.patch.object(suite.fileops, 'manifest', side_effect=warm_manifest),
                mock.patch.object(suite.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(2**60, 0, 2**60)),
                mock.patch.object(suite.native_metrics, 'collect', side_effect=collector or self.collect),
                mock.patch.object(suite.native_correctness, 'snapshot', side_effect=self.snapshot),
                mock.patch.object(suite.native_correctness, 'compare', side_effect=self.compare),
                mock.patch.object(suite.native_correctness, 'verify_clone', side_effect=self.verify_clone),
                mock.patch.object(suite.native_correctness, 'clone_sharing',
                                  side_effect=sharing or (lambda source_after, destination: {'full_data_stream_sharing': True})),
                mock.patch.object(suite.native_correctness, 'verify_move', side_effect=lambda before, after: self.compare(before, after) | {'move_identity': before['identity'] == after['identity']}),
                mock.patch.object(suite.native_correctness, 'verify_source', side_effect=self.verify_source),
            ]
            for patch in patches: stack.enter_context(patch)
            stack.enter_context(redirect_stdout(io.StringIO()))
            self.exit_code = suite.main()
        return json.loads(self.output.read_text())

    def test_duplicate_selectors_fail_before_creating_evidence(self):
        for options in ({'cache': ('warm', 'warm')}, {'copy_tools': ('cp', 'cp')},
                        {'operations': ('clone', 'clone')}, {'fixture_names': ('tiny_4kib', 'tiny_4kib')}):
            with self.subTest(options=options), self.assertRaisesRegex(RuntimeError, 'Duplicate benchmark selectors'):
                self.run_suite(**options)
            self.assertFalse(self.output.exists())
            self.assertFalse(self.output.with_name(self.output.name + '.journal').exists())
        self.assertEqual(self.measured, [])

    def test_scratch_creation_failure_closes_and_finalizes_failed_report(self):
        with mock.patch.object(suite.tempfile, 'mkdtemp', side_effect=OSError('scratch denied')):
            with self.assertRaisesRegex(OSError, 'scratch denied'):
                self.run_suite()
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['rows'], [])
        self.assertTrue(self.journal._stream.closed)

    def test_journal_failure_retains_fixture_without_retry_or_masking(self):
        append, close = JOURNAL.append, JOURNAL.close
        failed = []
        def fail(journal, kind, index, payload):
            self.assertFalse(failed, 'A failed journal was retried')
            if kind == 'rows':
                failed.append(True)
                raise OSError('injected report write')
            return append(journal, kind, index, payload)
        def close_failure(journal):
            close(journal)
            raise OSError('secondary close error')
        with mock.patch.object(JOURNAL, 'append', fail), mock.patch.object(JOURNAL, 'close', close_failure):
            with self.assertRaisesRegex(OSError, '^injected report write$'):
                self.run_suite()
        self.assertFalse(self.output.exists())
        self.assertEqual(len(self.measured), 1)
        self.assertTrue(self.journal._stream.closed)
        retained = list(self.root.glob('native-suite-*'))
        self.assertEqual(len(retained), 1)
        self.assertTrue((retained[0] / 'fixtures/tiny').exists())
        recovered = JOURNAL.open_existing(self.output)
        try:
            self.assertIn('active_operation', recovered.state)
            self.assertEqual(list(recovered.iter_latest('rows')), [])
        finally:
            recovered.close()

    def test_cache_conditioning_is_the_last_step_before_collection(self):
        timeline = []
        checkpoint = JOURNAL.checkpoint
        snapshot = self.snapshot
        def save(journal, state):
            timeline.append('checkpoint')
            return checkpoint(journal, state)
        def read(path, **options):
            result = snapshot(path, **options)
            timeline.append('snapshot')
            return result
        def cache(mode, timeout):
            self.assertEqual(timeline[-1], 'snapshot')
            timeline.append('cache')
            return {'mode': mode, 'policy': 'test'}
        def collect(argv, **kwargs):
            self.assertEqual(timeline[-1], 'cache')
            self.assertEqual(self.journal.state['active_operation']['argv'], argv)
            return self.collect(argv, **kwargs)
        with mock.patch.object(JOURNAL, 'checkpoint', save), mock.patch.object(suite, 'cache_prepare', cache), \
                mock.patch.object(self, 'snapshot', side_effect=read):
            self.run_suite(collector=collect)

    def test_single_run_is_partial_collection_with_ten_pairs(self):
        report = self.run_suite(extra=('--runs', '1'))
        self.assertEqual(report['selection']['runs'], 1)
        self.assertEqual(len(self.fixture_calls), 1)
        self.assertEqual(len(report['rows']), 40)
        self.assertTrue(report['passed'])
        self.assertFalse(report['all_metrics_won'])
        self.assertIn('three consecutive complete campaigns', report['limits'][0])
        self.assertTrue(report['cleanup_passed'])

    def test_three_runs_ten_pairs_keep_selection_and_source_validation(self):
        report = self.run_suite()
        self.assertEqual(self.exit_code, 0)
        self.assertTrue(report['passed'])
        self.assertTrue(report['cleanup_passed'])
        self.assertFalse(report['all_metrics_won'])
        self.assertEqual(len(self.fixture_calls), 3)
        self.assertEqual(len(self.metadata_calls), 3)
        self.assertEqual(len(self.coverage_calls), 3)
        self.assertEqual(len(report['metadata_preparation']), 3)
        self.assertTrue(all(row['status'] == 'prepared' and row['coverage']['populated'] is True
                            and row['coverage']['seeded_acl_text_bytes'] == 76
                            and row['coverage']['regular_files'] == 1
                            and row['coverage']['logical_bytes'] == len(b'tiny fixture payload')
                            for row in report['metadata_preparation']))
        self.assertEqual(len(report['rows']), 120)
        self.assertEqual(len(self.measured), 120)
        self.assertEqual(self.cache_calls, [])
        expected_snapshots = []
        for run in range(3):
            rows = [row for row in report['rows'] if row['run'] == run]
            self.assertEqual(len(rows), 40)
            self.assertEqual({row['operation'] for row in rows}, {'clone'})
            expected_snapshots.append(Path(rows[0]['argv'][-2]))  # Initial fixture snapshot.
            for row in rows:
                source, destination = map(Path, row['argv'][-2:])
                expected_snapshots.extend([source, destination, source])
            for phase in ('timing', 'resources'):
                for pair in range(10):
                    pair_rows = [row for row in rows if row['pair_id'] == pair and row['phase'] == phase]
                    self.assertEqual(len(pair_rows), 2)
                    self.assertEqual({row['method'] for row in pair_rows}, {'cp-clone', 'stallionfs'})
                    self.assertTrue(all(row['validated'] and row['source_unchanged'] for row in pair_rows))
        self.assertEqual(self.snapshot_calls, expected_snapshots)
        self.assertEqual(len(report['comparisons']), 6)
        self.assertEqual(report['comparisons'], suite.summarize_report(report['rows'], 10))
        for comparison in report['comparisons']:
            self.assertEqual('rss_bytes' in comparison['metrics'], comparison['phase'] == 'resources')
        self.assertTrue(all(row['metrics']['wall_s']['complete_pairs'] == 10 for row in report['comparisons']))
        self.assertFalse(list(self.root.glob('native-suite-*')))

    def test_enrichment_failure_retains_partial_fixture_before_measurement(self):
        def enrich(root, **options):
            self.enrich_metadata(root, **options)
            root.write_bytes(b'partially enriched')
            raise OSError('metadata unavailable')
        with self.assertRaisesRegex(OSError, 'metadata unavailable'):
            self.run_suite(enrich=enrich)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['metadata_preparation'][0]['status'], 'preparing')
        self.assertEqual(report['metadata_preparation'][0]['seed']['test_receipt'], 1)
        retained = Path(report['retained_fixture'])
        self.assertEqual((retained/'fixtures/tiny').read_bytes(), b'partially enriched')
        self.assertEqual(self.snapshot_calls, [])
        self.assertEqual(self.measured, [])

    def test_unpopulated_coverage_is_rejected_before_measurement(self):
        with self.assertRaisesRegex(RuntimeError, 'Metadata coverage incomplete'):
            self.run_suite(coverage=lambda *args: {'populated': False})
        report = json.loads(self.output.read_text())
        self.assertTrue(Path(report['retained_fixture']).is_dir())
        self.assertFalse(report['metadata_preparation'][0]['coverage']['populated'])
        self.assertEqual(self.measured, [])

    def test_coverage_exception_preserves_seed_receipt_and_fixture(self):
        def coverage(*args): raise RuntimeError('Seeded ACL entry missing')
        with self.assertRaisesRegex(RuntimeError, 'Seeded ACL entry missing'):
            self.run_suite(coverage=coverage)
        report = json.loads(self.output.read_text())
        self.assertTrue(Path(report['retained_fixture']).is_dir())
        self.assertEqual(report['metadata_preparation'][0]['seed']['test_receipt'], 1)
        self.assertEqual(len(self.snapshot_calls), 1)
        self.assertEqual(self.measured, [])

    def test_scan_reuses_pairs_and_full_before_after_source_snapshots(self):
        report = self.run_suite(operations=('scan',), fixture_names=('scan_flat_20k',))
        self.assertEqual(self.exit_code, 0)
        self.assertTrue(report['passed'])
        self.assertTrue(report['cleanup_passed'])
        self.assertEqual(len(report['rows']), 120)
        self.assertEqual(len(report['comparisons']), 6)
        self.assertEqual([(files, layout) for _, files, layout in self.scan_fixture_calls], [(20000, 'flat')] * 3)
        expected_snapshots = []
        for root, _, _ in self.scan_fixture_calls:
            expected_snapshots.extend([root] * (1 + 2 * 40))
        self.assertEqual(self.snapshot_calls, expected_snapshots)
        self.assertTrue(all(options in ({'allow_special': True}, {'allow_special': True, 'observe_sharing': False})
                            for options in self.snapshot_options))
        self.assertEqual(self.cache_calls, [])
        self.assertFalse(any(argv[0] == '/usr/bin/ditto' for argv in self.commands))
        self.assertTrue(all(row['validated'] and row['source_verification']['unchanged'] for row in report['rows']))
        self.assertEqual(set(report['executables']) & {'/usr/bin/find', '/usr/bin/stat'}, {'/usr/bin/find', '/usr/bin/stat'})

    def test_scan_source_mutation_stops_and_preserves_fixture(self):
        def collector(argv, **kwargs):
            result = self.collect(argv, **kwargs)
            source = Path(argv[3] if argv[0] == '/usr/bin/find' else argv[-1])
            (source / 'file-0').write_bytes(b'changed by command')
            return result
        with self.assertRaisesRegex(RuntimeError, 'changed.*source'):
            self.run_suite(operations=('scan',), fixture_names=('scan_flat_20k',), collector=collector)
        report = json.loads(self.output.read_text())
        self.assertTrue(Path(report['retained_fixture']).is_dir())
        self.assertFalse(report['rows'][0]['source_unchanged'])
        self.assertEqual(len(self.measured), 1)

    def test_scan_stdout_compression_is_lossless_small_and_precedes_checkpoint(self):
        raw = b'100644\t64\t16777234\n' * 20000 + b'10600\t0\t16777234\n'
        row = {'stdout': raw.decode('ascii'), 'stdout_b64': base64.b64encode(raw).decode('ascii')}
        self.assertEqual(suite.compress_scan_stdout(row), raw)
        encoded = row['stdout_gzip_b64']
        compressed = base64.b64decode(encoded, validate=True)
        self.assertEqual(gzip.decompress(compressed), raw)
        self.assertEqual(compressed[4:8], b'\0' * 4)  # Fixed gzip modification time.
        self.assertEqual(row['stdout_bytes'], len(raw))
        self.assertEqual(row['stdout_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertLess(len(encoded), len(raw) // 20)
        self.assertNotIn('stdout', row)
        self.assertNotIn('stdout_b64', row)
        append = JOURNAL.append
        def checkpoint(journal, kind, index, saved):
            if kind == 'rows':
                self.assertNotIn('stdout', saved)
                self.assertNotIn('stdout_b64', saved)
                output = gzip.decompress(base64.b64decode(saved['stdout_gzip_b64'], validate=True))
                self.assertEqual(saved['stdout_bytes'], len(output))
                self.assertEqual(saved['stdout_sha256'], hashlib.sha256(output).hexdigest())
            return append(journal, kind, index, saved)
        with mock.patch.object(JOURNAL, 'append', checkpoint):
            report = self.run_suite(operations=('scan',), fixture_names=('scan_flat_20k',))
        self.assertTrue(report['passed'])

    def test_scan_bad_output_still_verifies_source_after_each_row(self):
        def collector(argv, **kwargs):
            result = self.collect(argv, **kwargs)
            result['stdout_b64'] = base64.b64encode(b'bad output\n').decode('ascii')
            return result
        report = self.run_suite(operations=('scan',), fixture_names=('scan_flat_20k',), collector=collector)
        self.assertEqual(self.exit_code, 1)
        self.assertTrue(report['rows'])
        self.assertTrue(all(not row['validated'] and row['source_unchanged'] for row in report['rows']))
        self.assertEqual(len(self.snapshot_calls), 3 + 2 * len(report['rows']))

    def test_scan_selection_rejects_copy_operations_and_non_scan_fixtures(self):
        for operations, fixtures in [(('clone',), ('scan_flat_20k',)), (('scan',), ('tiny_4kib',)),
                                     (('scan', 'clone'), ('scan_flat_20k',))]:
            with self.subTest(operations=operations, fixtures=fixtures):
                with self.assertRaisesRegex(RuntimeError, 'Select --operations scan'):
                    self.run_suite(operations=operations, fixture_names=fixtures)
        self.assertEqual(self.measured, [])

    def test_scan_resource_footer_diagnostics_fail_and_preserve_source_check(self):
        self.assertEqual(suite.native_metrics.time_diagnostics(TIME_FOOTER), [])
        for warning in (b'find: unreadable entry', b'1 unsupported time counter',
                        b'NaN peak memory footprint', b'warning: invalid byte \xff'):
            with self.subTest(warning=warning):
                combined = TIME_FOOTER + warning + b'\n'
                self.assertTrue(suite.native_metrics.time_diagnostics(combined))
                # Existing resource parsing still accepts its numeric metrics.
                self.assertEqual(suite.native_metrics.parse_time(combined)['parse_errors'], [])
        def collector(argv, **kwargs):
            result = self.collect(argv, **kwargs)
            stderr = TIME_FOOTER + b'find: unreadable entry\n' if kwargs['phase'] == 'resources' else b''
            result['stderr_b64'] = base64.b64encode(stderr).decode('ascii')
            return result
        report = self.run_suite(operations=('scan',), fixture_names=('scan_flat_20k',), collector=collector)
        self.assertFalse(report['passed'])
        self.assertTrue(report['rows'])
        self.assertTrue(all(row['source_unchanged'] for row in report['rows']))
        self.assertTrue(any(row['correctness'].get('reason') == 'Scan command emitted diagnostics'
                            for row in report['rows']))

    def test_scan_numeric_protocol_counts_links_mounts_and_specials_without_names(self):
        raw = b'100640\t9\t7\n100640\t9\t7\n40750\t0\t7\n40750\t0\t8\n120777\t99\t7\n10600\t0\t7\n'
        expected = dict(files=2, directories=2, symlinks=1, other=1, logical_bytes=18, skipped_mounts=1)
        self.assertEqual(suite.parse_scan_output('find-stat', raw, 7), expected)
        self.assertEqual(suite.parse_scan_output('stallionfs', json.dumps(expected).encode(), 7), expected)
        path_bytes = os.fsencode(self.root) + b'/newline\ninvalid-\xff'
        root = Path(os.fsdecode(path_bytes))
        argv = suite.arguments('find-stat', 'scan', self.binary, root, self.root / 'unused')
        self.assertEqual(os.fsencode(argv[3]), path_bytes)
        self.assertEqual(argv[:3], ['/usr/bin/find', '-P', '-x'])
        self.assertEqual(argv[4:], ['-mindepth', '1', '-exec', '/usr/bin/stat', '-f', '%Op%t%Dz%t%Dd', '--', '{}', '+'])
        self.assertEqual(suite.arguments('stallionfs', 'scan', self.binary, root, None),
                         [str(self.binary), '--json', 'scan', str(root)])

    def test_scan_parser_rejects_malformed_numbers_types_and_missing_counters(self):
        for raw in (b'100644\t1\t7', b'100644\tx\t7\n', b'100644\t-1\t7\n', b'180644\t1\t7\n',
                    b'0\t1\t7\n', b'100644\t1\t2147483648\n', b'100644\t9223372036854775808\t7\n',
                    b'100644\t9223372036854775807\t7\n' * 3):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                suite.parse_scan_output('find-stat', raw, 7)
        good = dict.fromkeys(suite.SCAN_FIELDS, 0)
        bad = [[], {'files': 0}, good | {'extra': 0}, good | {'files': True}, good | {'files': -1},
               good | {'logical_bytes': 1 << 64}, good | {'other': 1.5}]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                suite.parse_scan_output('stallionfs', json.dumps(value).encode(), 7)
        duplicate = b'{"files": 0,' + json.dumps(good).encode()[1:]
        with self.assertRaisesRegex(ValueError, 'Duplicate scan counter'):
            suite.parse_scan_output('stallionfs', duplicate, 7)

    def test_exact_command_mappings_and_rsync_directory_slash(self):
        directory = self.root / 'source'; directory.mkdir()
        file = self.root / 'file'; file.write_bytes(b'x')
        destination = self.root / 'destination'
        prefixes = {'cp-clone': ['/bin/cp', '-cRp'], 'cp': ['/bin/cp', '-Rp'],
                    'ditto': ['/usr/bin/ditto', '--rsrc', '--extattr', '--acl'],
                    'rsync': ['/usr/bin/rsync', '-a', '--extended-attributes']}
        for method, prefix in prefixes.items():
            for source in (directory, file):
                expected_source = str(source) + ('/' if method == 'rsync' and source == directory else '')
                self.assertEqual(suite.arguments(method, 'clone', self.binary, source, destination),
                                 prefix + [expected_source, str(destination)])
        self.assertEqual(suite.arguments('move', 'move', self.binary, file, destination), ['/bin/mv', '-n', str(file), str(destination)])
        self.assertEqual(suite.arguments('delete', 'delete', self.binary, file, destination), ['/bin/rm', '-rf', str(file)])
        self.assertEqual(suite.arguments('stallionfs', 'delete', self.binary, file, destination), [str(self.binary), 'delete', '--recursive', str(file)])

    def test_cold_purge_failure_is_attempted_once_and_never_relabelled_warm(self):
        report = self.run_suite(cache=('cold', 'warm'))
        self.assertEqual(report['cold_cache_unavailable'], 'cache purge unavailable; no further purge retries')
        self.assertEqual(self.journal.state['cold_cache_unavailable'], report['cold_cache_unavailable'])
        purges = [args for args in self.commands if args[0] == '/usr/bin/sudo']
        self.assertEqual(len(purges), 1)
        self.assertEqual(len(self.measured), 120)
        self.assertTrue(all(row['cache'] == 'warm' for row in report['rows']))
        self.assertFalse(report['passed'])
        self.assertEqual(self.exit_code, 1)
        self.assertTrue(report['unavailable'])
        self.assertTrue(report['cleanup_passed'])

    def test_uncertain_timed_command_retains_owned_fixture(self):
        def uncertain(argv, **kwargs):
            return {'argv': list(argv), 'exit_code': None, 'ok': False, 'completion_uncertain': True}
        with self.assertRaises(suite.fileops.ChildCompletionUnknown): self.run_suite(collector=uncertain)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'failed')
        self.assertTrue(Path(report['retained_fixture']).is_dir())
        self.assertFalse(report.get('cleanup_passed', False))
        self.assertTrue(report['rows'][0]['completion_uncertain'])

    def test_interrupted_collector_receipt_and_fixture_are_retained(self):
        receipt = {'argv': ['interrupted'], 'exit_code': None, 'completion_uncertain': True, 'ok': False}
        def interrupted(*args, **kwargs): raise suite.native_metrics.ChildCompletionUnknown(receipt)
        with self.assertRaises(suite.native_metrics.ChildCompletionUnknown): self.run_suite(collector=interrupted)
        report = json.loads(self.output.read_text())
        self.assertTrue(Path(report['retained_fixture']).is_dir())
        self.assertEqual(report['rows'][0]['argv'], receipt['argv'])
        self.assertFalse(report['rows'][0]['validated'])

    def test_final_report_failure_does_not_mask_interrupted_command(self):
        receipt = {'argv': ['interrupted'], 'exit_code': None, 'completion_uncertain': True, 'ok': False}
        original = suite.native_metrics.ChildCompletionUnknown(receipt)
        def interrupted(*args, **kwargs): raise original
        with mock.patch.object(JOURNAL, 'finish', side_effect=OSError('final report disk full')):
            with self.assertRaises(suite.native_metrics.ChildCompletionUnknown) as caught:
                self.run_suite(collector=interrupted)
        self.assertIs(caught.exception, original)
        self.assertFalse(self.output.exists())
        self.assertTrue(self.journal._stream.closed)
        recovered = JOURNAL.open_existing(self.output)
        try:
            self.assertTrue(Path(recovered.state['retained_fixture']).is_dir())
            self.assertEqual(list(recovered.iter_latest('rows'))[0]['argv'], receipt['argv'])
        finally:
            recovered.close()

    def test_final_report_failure_cannot_return_success(self):
        with mock.patch.object(JOURNAL, 'finish', side_effect=OSError('final report disk full')):
            with self.assertRaisesRegex(OSError, 'final report disk full'):
                self.run_suite()
        self.assertFalse(self.output.exists())
        self.assertTrue(self.journal._stream.closed)

    def test_uncertain_setup_command_retains_owned_fixture(self):
        def setup(argv, **kwargs):
            if os.fspath(argv[0]) == '/usr/bin/ditto':
                raise suite.fileops.ChildCompletionUnknown('setup completion unknown')
            return self.command(argv, **kwargs)
        with self.assertRaises(suite.fileops.ChildCompletionUnknown):
            self.run_suite(operations=('delete',), command=setup)
        report = json.loads(self.output.read_text())
        self.assertTrue(Path(report['retained_fixture']).is_dir())
        self.assertFalse(report.get('cleanup_passed', False))
        self.assertEqual(self.measured, [])

    def test_setup_timeout_preserves_fixture_without_running_a_measurement(self):
        def setup(argv, **kwargs):
            if os.fspath(argv[0]) == '/usr/bin/ditto':
                raise subprocess.TimeoutExpired(argv, 1)
            return self.command(argv, **kwargs)
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_suite(operations=('move',), command=setup)
        report = json.loads(self.output.read_text())
        self.assertTrue(Path(report['retained_fixture']).is_dir())
        self.assertFalse(report.get('cleanup_passed', False))
        self.assertEqual(self.measured, [])

    def test_setup_timestamp_restoration_does_not_touch_symlink_referent(self):
        target = self.root/'target'; target.mkdir()
        outside = self.root/'outside'; outside.write_bytes(b'unchanged')
        link = target/'link'; link.symlink_to(outside)
        original = outside.stat()
        timestamp = 1700000000123456789
        expected = {'entries': {'link': {'kind': 'symlink', 'symlink_bytes': os.fsencode(outside).hex(),
                                        'mtime_ns': timestamp, 'device_inode': [original.st_dev, original.st_ino]}}}
        repairs = suite.restore_setup_symlink_times(target, expected)
        self.assertEqual(len(repairs), 1)
        self.assertEqual(link.lstat().st_mtime_ns, timestamp)
        self.assertEqual(outside.stat().st_mtime_ns, original.st_mtime_ns)
        self.assertEqual(outside.read_bytes(), b'unchanged')
        self.assertEqual(suite.restore_setup_symlink_times(target, expected), [])
        info = link.lstat()
        expected['entries']['link']['device_inode'] = [info.st_dev, info.st_ino]
        expected['entries']['link']['mtime_ns'] += 1
        with self.assertRaisesRegex(RuntimeError, 'aliases a source inode'):
            suite.restore_setup_symlink_times(target, expected)
        self.assertEqual(link.lstat().st_mtime_ns, timestamp)
        link.unlink(); link.write_bytes(b'replaced')
        with self.assertRaisesRegex(RuntimeError, 'symlink changed'):
            suite.restore_setup_symlink_times(target, expected)
        self.assertEqual(link.read_bytes(), b'replaced')

    def test_setup_copy_is_verified_before_move_and_delete(self):
        report = self.run_suite(operations=('move', 'delete'))
        self.assertTrue(report['passed'])
        self.assertEqual(len(report['preparation']), len(report['rows']))
        self.assertTrue(all(row['argv'][:4] == ['/usr/bin/ditto', '--rsrc', '--extattr', '--acl'] and row['validated']
                            and row['correctness']['independent_clone'] for row in report['preparation']))
        self.assertFalse(any(argv[:2] == [str(self.binary), 'clone'] for argv in self.commands))

    def test_setup_mismatch_retains_validation_and_fixture(self):
        def setup(argv, **kwargs):
            result = self.command(argv, **kwargs)
            if os.fspath(argv[0]) == '/usr/bin/ditto':
                Path(argv[-1]).write_bytes(b'changed during setup')
            return result
        with self.assertRaisesRegex(RuntimeError, 'Setup did not preserve'):
            self.run_suite(operations=('move',), command=setup)
        report = json.loads(self.output.read_text())
        self.assertTrue(Path(report['retained_fixture']).is_dir())
        self.assertEqual(len(report['preparation']), 1)
        self.assertFalse(report['preparation'][0]['validated'])
        self.assertEqual(report['preparation'][0]['correctness']['differences'], ['payload or mode'])
        self.assertEqual(self.measured, [])

    def test_setup_alias_is_rejected_before_measurement(self):
        def setup(argv, **kwargs):
            if os.fspath(argv[0]) == '/usr/bin/ditto':
                os.link(argv[-2], argv[-1])
                return subprocess.CompletedProcess(argv, 0, b'', b'')
            return self.command(argv, **kwargs)
        with self.assertRaisesRegex(RuntimeError, 'Setup did not preserve'):
            self.run_suite(operations=('delete',), command=setup)
        report = json.loads(self.output.read_text())
        self.assertFalse(report['preparation'][0]['correctness']['independent_clone'])
        self.assertTrue(Path(report['retained_fixture']).is_dir())
        self.assertEqual(self.measured, [])

    def test_setup_source_mutation_is_rejected_before_measurement(self):
        def setup(argv, **kwargs):
            result = self.command(argv, **kwargs)
            if os.fspath(argv[0]) == '/usr/bin/ditto':
                Path(argv[-2]).write_bytes(b'changed original during setup')
            return result
        with self.assertRaisesRegex(RuntimeError, 'Setup changed the source'):
            self.run_suite(operations=('delete',), command=setup)
        report = json.loads(self.output.read_text())
        self.assertFalse(report['preparation'][0]['source_verification']['unchanged'])
        self.assertTrue(Path(report['retained_fixture']).is_dir())
        self.assertEqual(self.measured, [])

    def test_setup_snapshot_exception_retains_fixture(self):
        snapshot = self.snapshot
        def fail_target(path, **kwargs):
            if Path(path).name == 'target': raise OSError('snapshot unavailable')
            return snapshot(path, **kwargs)
        with mock.patch.object(self, 'snapshot', side_effect=fail_target):
            with self.assertRaisesRegex(OSError, 'snapshot unavailable'):
                self.run_suite(operations=('move',))
        report = json.loads(self.output.read_text())
        self.assertTrue(Path(report['retained_fixture']).is_dir())
        self.assertEqual(report['preparation'][0]['exit_code'], 0)
        self.assertFalse(report['preparation'][0]['validated'])
        self.assertEqual(self.measured, [])

    def test_setup_failure_retains_stderr_and_fixture(self):
        def setup(argv, **kwargs):
            if os.fspath(argv[0]) == '/usr/bin/ditto':
                return subprocess.CompletedProcess(argv, 1, b'', b'setup error')
            return self.command(argv, **kwargs)
        with self.assertRaisesRegex(RuntimeError, 'Operand preparation failed'):
            self.run_suite(operations=('delete',), command=setup)
        report = json.loads(self.output.read_text())
        self.assertTrue(Path(report['retained_fixture']).is_dir())
        self.assertEqual(base64.b64decode(report['preparation'][0]['stderr_b64']), b'setup error')
        self.assertEqual(self.measured, [])

    def test_failed_method_is_not_retried_for_other_references_or_runs(self):
        failed = []
        def collector(argv, **kwargs):
            if os.fspath(argv[0]) == str(self.binary):
                failed.append(list(argv))
                return {'argv': list(argv), 'exit_code': 7, 'ok': False, 'completion_uncertain': False}
            return self.collect(argv, **kwargs)
        with mock.patch.object(suite.random.Random, 'shuffle', side_effect=lambda methods: methods.reverse()):
            report = self.run_suite(copy_tools=('cp-clone', 'cp'), collector=collector)
        self.assertEqual(len(failed), 1)
        self.assertFalse(report['passed'])
        self.assertEqual(self.exit_code, 1)
        self.assertTrue(report['cleanup_passed'])
        self.assertTrue(report['unavailable'])
        self.assertEqual(self.measured, [])
        self.assertEqual(len(report['rows']), 1)
        self.assertFalse(any(item['complete'] for item in report['comparisons']))

    def test_failed_reference_stops_both_sides_but_keeps_other_references(self):
        for candidate_first in (False, True):
            with self.subTest(candidate_first=candidate_first):
                self.output = self.root / f'failed-reference-{candidate_first}.json'
                self.measured.clear()
                failures = []
                def collector(argv, **kwargs):
                    if list(argv[:2]) == ['/bin/cp', '-cRp']:
                        failures.append(list(argv))
                        return {'argv': list(argv), 'phase': kwargs['phase'], 'exit_code': 7,
                                'ok': False, 'completion_uncertain': False}
                    return self.collect(argv, **kwargs)
                def order(methods):
                    if candidate_first: methods.reverse()
                with mock.patch.object(suite.random.Random, 'shuffle', side_effect=order):
                    report = self.run_suite(copy_tools=('cp-clone', 'cp'), collector=collector)
                failed_rows = [row for row in report['rows'] if row['reference'] == 'cp-clone']
                good_rows = [row for row in report['rows'] if row['reference'] == 'cp']
                self.assertEqual(len(failures), 1)
                self.assertEqual(len(failed_rows), 2 if candidate_first else 1)
                self.assertEqual(len(good_rows), 120)
                self.assertTrue(all(row['validated'] for row in good_rows))
                self.assertFalse(report['passed'])
                self.assertEqual(self.exit_code, 1)
                self.assertTrue(report['cleanup_passed'])
                self.assertTrue(any(item.get('failed_methods') == ['cp-clone'] for item in report['unavailable']))
                for item in report['comparisons']:
                    if item['reference'] == 'cp-clone':
                        metric = item['metrics']['wall_s']
                        self.assertEqual(metric['decision'], 'insufficient_samples')
                        self.assertEqual(metric['complete_pairs'], 0)
                        self.assertTrue(metric['excluded_pairs'])

    def test_source_mutation_stops_and_retains_evidence(self):
        def collector(argv, **kwargs):
            result = self.collect(argv, **kwargs)
            Path(argv[-2]).write_bytes(b'changed source')
            return result
        with self.assertRaisesRegex(RuntimeError, 'changed.*source'):
            self.run_suite(collector=collector)
        report = json.loads(self.output.read_text())
        self.assertTrue(Path(report['retained_fixture']).is_dir())
        self.assertFalse(report['rows'][0]['source_unchanged'])
        self.assertEqual(len(self.measured), 1)

    def test_post_command_snapshot_exception_retains_evidence(self):
        snapshot = self.snapshot
        cases = [('clone', 'tiny'), ('move', 'tiny'), ('delete', 'tiny'),
                 ('clone', 'destination'), ('move', 'destination')]
        for operation, failed_path in cases:
            for phase, metrics in suite.native_metrics.PHASE_METRICS.items():
                for error_type in (FileNotFoundError, OSError, RuntimeError):
                    with self.subTest(operation=operation, path=failed_path, phase=phase, error=error_type):
                        self.output = self.root / f'{operation}-{failed_path}-{phase}-{error_type.__name__}.json'
                        self.measured.clear()
                        original = error_type('post-command snapshot unavailable')
                        def fail_after_command(path, **options):
                            if self.measured and Path(path).name == failed_path:
                                raise original
                            return snapshot(path, **options)
                        with mock.patch.object(self, 'snapshot', side_effect=fail_after_command), \
                                mock.patch.object(suite.native_metrics, 'PHASE_METRICS', {phase: metrics}):
                            with self.assertRaises(error_type) as caught:
                                self.run_suite(operations=(operation,))
                        self.assertIs(caught.exception, original)
                        report = json.loads(self.output.read_text())
                        self.assertEqual(report['status'], 'failed')
                        self.assertEqual(report['error'], f'{error_type.__name__}: {original}')
                        self.assertFalse(report.get('cleanup_passed', False))
                        retained = Path(report['retained_fixture'])
                        self.assertEqual((retained / 'fixtures/tiny').read_bytes(), b'tiny fixture payload')
                        self.assertEqual((retained / 'outside-sentinel').read_bytes(), b'keep outside linked trees\n')
                        if operation != 'delete':
                            self.assertEqual((retained / 'destination').read_bytes(), b'tiny fixture payload')
                        self.assertFalse((retained / 'target').exists())
                        self.assertEqual(len(self.measured), 1)
                        self.assertEqual(len(report['rows']), 1)
                        row = report['rows'][0]
                        self.assertEqual(row['argv'], self.measured[0])
                        self.assertEqual(row['phase'], phase)
                        self.assertEqual(row['exit_code'], 0)
                        self.assertEqual(row['stdout_b64'], '')
                        self.assertEqual(row['stderr_b64'], '')
                        self.assertFalse(row['validated'])
                        self.assertNotIn('source_verification', row)

    def test_invalid_destination_with_unchanged_source_is_cleaned(self):
        def collector(argv, **kwargs):
            result = self.collect(argv, **kwargs)
            Path(argv[-1]).write_bytes(b'invalid destination')
            return result
        for operation in ('clone', 'move'):
            with self.subTest(operation=operation):
                self.output = self.root / f'invalid-destination-{operation}.json'
                self.measured.clear()
                report = self.run_suite(operations=(operation,), collector=collector)
                self.assertFalse(report['passed'])
                self.assertTrue(report['cleanup_passed'])
                self.assertNotIn('retained_fixture', report)
                self.assertEqual(len(self.measured), 1)
                self.assertEqual(len(report['rows']), 1)
                self.assertFalse(report['rows'][0]['validated'])
                self.assertTrue(report['rows'][0]['source_unchanged'])

    def test_clone_sharing_uses_post_copy_source_and_gates_only_clone_methods(self):
        for reference, outcome in ((reference, outcome) for reference in ('cp', 'cp-clone') for outcome in (False, None)):
            with self.subTest(reference=reference, outcome=outcome):
                self.output = self.root / f'sharing-{reference}-{outcome}.json'
                self.snapshot_calls.clear(); self.snapshot_options.clear()
                calls = []
                def sharing(source_after, destination):
                    calls.append((source_after, destination))
                    self.assertEqual(source_after['payload'], destination['payload'])
                    self.assertNotEqual(source_after['identity'], destination['identity'])
                    self.assertEqual(self.snapshot_options[-1], {'observe_sharing': True})
                    self.assertIs(source_after, self.snapshot_results[-1])
                    self.assertIs(destination, self.snapshot_results[-2])
                    return {'full_data_stream_sharing': outcome}
                # Reference first allows byte-copy rows to be observed before candidate failure.
                with mock.patch.object(suite.random.Random, 'shuffle', side_effect=lambda methods: None):
                    report = self.run_suite(copy_tools=(reference,), sharing=sharing)
                self.assertTrue(calls)
                self.assertFalse(report['passed'])
                byte_rows = [row for row in report['rows'] if row['method'] == 'cp']
                clone_rows = [row for row in report['rows'] if row['method'] in ('stallionfs', 'cp-clone')]
                self.assertEqual(bool(byte_rows), reference == 'cp')
                self.assertTrue(clone_rows)
                self.assertTrue(all(row['validated'] and not row['data_stream_sharing']['required'] for row in byte_rows))
                self.assertTrue(all(not row['validated'] and row['data_stream_sharing']['required'] for row in clone_rows))
                self.assertTrue(all(row['source_unchanged'] for row in report['rows']))

    def test_same_payload_source_replacement_stops_and_retains_evidence(self):
        def collector(argv, **kwargs):
            result = self.collect(argv, **kwargs)
            source = Path(argv[-2])
            before = self.snapshot(source)
            replacement = source.with_name(source.name + '-replacement')
            shutil.copy2(source, replacement)
            self.assertNotEqual(before['identity'], self.snapshot(replacement)['identity'])
            replacement.replace(source)
            self.assertTrue(self.compare(before, self.snapshot(source))['strict_equal'])
            return result
        with self.assertRaisesRegex(RuntimeError, 'changed.*source'):
            self.run_suite(collector=collector)
        report = json.loads(self.output.read_text())
        self.assertTrue(Path(report['retained_fixture']).is_dir())
        row = report['rows'][0]
        self.assertFalse(row['source_unchanged'])
        self.assertFalse(row['validated'])
        self.assertEqual(row['source_verification']['differences'], ['identity'])
        self.assertEqual(len(self.measured), 1)

    def test_uncertain_dependency_setup_preserves_partial_tree(self):
        def prepare(root, **kwargs):
            root.mkdir()
            (root/'partial-node-modules').write_bytes(b'partial installation')
            raise suite.fileops.ChildCompletionUnknown('npm completion unknown')
        with mock.patch.object(suite.native_fixtures, 'installed_dependencies', side_effect=prepare):
            with self.assertRaises(suite.fileops.ChildCompletionUnknown):
                self.run_suite(fixture='installed_dependencies', extra=(
                    '--node', str(self.root/'node'), '--npm', str(self.root/'npm-cli.js'), '--npm-cache', str(self.root)))
        report = json.loads(self.output.read_text())
        retained = Path(report['retained_fixture'])
        self.assertEqual((retained/'installed_dependencies/partial-node-modules').read_bytes(), b'partial installation')
        self.assertFalse(report.get('cleanup_passed', False))
        self.assertEqual(self.measured, [])
        self.assertEqual(report['preparation'][0]['fixture'], 'installed_dependencies')

    def test_failed_pair_cannot_become_a_statistical_win(self):
        rows = []
        for sample in range(11):
            for method in ('cp-clone', 'stallionfs'):
                row = {'run': 0, 'fixture': 'tiny_4kib', 'operation': 'clone', 'reference': 'cp-clone',
                       'cache': 'warm', 'phase': 'resources', 'method': method, 'pair_id': sample, 'ok': True, 'validated': True,
                       'completion_uncertain': False, 'wall_s': 10 if method == 'cp-clone' else 1,
                       'user_s': 1, 'system_s': 1, 'cpu_s': 2, 'rss_bytes': 16384,
                       'io_input_blocks': 0, 'io_output_blocks': 1}
                if sample == 10 and method == 'stallionfs': row['validated'] = False
                rows.append(row)
        result = suite.summarize_report(rows, 11)
        self.assertEqual(result[0]['metrics']['wall_s']['decision'], 'incomplete_pairs')
        self.assertEqual(result[0]['metrics']['wall_s']['complete_pairs'], 10)


if __name__ == '__main__': unittest.main()
