"""Scanner report orchestration with native work and resource collection mocked."""
from contextlib import ExitStack, redirect_stdout, redirect_stderr
import importlib.util
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


PERF = Path(__file__).parent / 'perf'
with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
    spec = importlib.util.spec_from_file_location('scan_statistics', PERF / 'scan.py')
    scan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scan)


class ScannerStatistics(unittest.TestCase):
    @staticmethod
    def fixture(path, *_):
        path.mkdir()
        (path / 'file').write_bytes(b'a')
        return {'files': 1}

    @staticmethod
    def snapshot(path, *, allow_special):
        assert allow_special is True
        data = path / 'file'
        info = data.stat()
        entry = dict(kind='file', size=info.st_size, sha256=hashlib.sha256(data.read_bytes()).hexdigest(),
                     mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid,
                     mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns,
                     birthtime_ns=getattr(info, 'st_birthtime_ns', None), flags=0,
                     device_inode=[info.st_dev, info.st_ino], link_count=info.st_nlink,
                     allocated_bytes=info.st_blocks * 512, holes={'ranges': []},
                     acl={'text_hex': b'group:uuid:everyone::allow:read\n'.hex(), 'unavailable': None},
                     xattrs={key.hex(): value.hex() for key, value in scan.native_fixtures.METADATA_XATTRS.items()})
        return {'entries': {'file': entry}, 'hardlink_groups': [], 'unavailable_fields': []}

    def configure(self, stack, root, *, memory=False):
        self.output = root / 'report.json'
        stack.enter_context(mock.patch.object(sys, 'argv', [
            'scan.py', '--scratch', str(root), '--output', str(self.output),
            '--samples', '10', '--files', '1', *(['--memory'] if memory else [])]))
        stack.enter_context(mock.patch.object(scan, 'fixture', side_effect=self.fixture))
        self.scanner = stack.enter_context(mock.patch.object(scan._scan, 'scan', return_value={'files': 1}))
        stack.enter_context(mock.patch.object(scan._scan, 'mounts', return_value=[]))
        stack.enter_context(mock.patch.object(scan.f, 'scratch_volume', return_value={'filesystem': 'apfs'}))
        stack.enter_context(mock.patch.object(scan.f, 'command', return_value=subprocess.CompletedProcess([], 0, b'24', b'')))
        self.cleanup = stack.enter_context(mock.patch.object(scan.f, 'remove_fixture', side_effect=shutil.rmtree))
        self.snapshots = stack.enter_context(mock.patch.object(scan.native_correctness, 'snapshot', side_effect=self.snapshot))
        self.enrich = stack.enter_context(mock.patch.object(scan.native_fixtures, 'enrich_metadata',
            side_effect=lambda path, *, receipt, scan_layout: receipt.update(
                path='file', data_size=1, hardlinks=None, sparse=None)))
        self.sampler = stack.enter_context(mock.patch.object(scan, 'memory_sample', side_effect=lambda path, method, *_: {
            'rss_bytes': 8192 if method == 'posix' else 4096,
            'footprint_bytes': 2048, 'exit_code': 0, 'counts': {'files': 1}}))
        stack.enter_context(redirect_stdout(io.StringIO()))

    def failed_report(self):
        report = json.loads(self.output.with_name(self.output.name + '.partial').read_text())
        self.assertFalse(report['passed'])
        self.assertFalse(report.get('cleanup_passed', False))
        self.assertTrue(Path(report['retained_fixture']).is_dir())
        self.assertFalse(self.output.exists())
        self.cleanup.assert_not_called()
        return report

    def test_scanner_exception_retains_pending_attempt(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory))
            self.scanner.side_effect = OSError('injected scanner failure')
            with self.assertRaisesRegex(OSError, 'injected scanner failure'):
                scan.main()
            report = self.failed_report()
            rows = report['workloads']['flat']['sample_rows']
            self.assertEqual(len(rows), 1)
            self.assertIn(rows[0]['method'], scan.METHODS)
            self.assertEqual((rows[0]['pair_id'], rows[0]['round']), (0, 0))
            self.assertFalse(rows[0]['ok'])
            self.assertFalse(rows[0]['validated'])
            self.assertNotIn('wall_s', rows[0])

    def test_failed_checkpoint_preserves_original_error_and_fixture(self):
        for failure in (OSError('injected scanner failure'), KeyboardInterrupt('interrupted')):
            with self.subTest(error=type(failure).__name__), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                self.scanner.side_effect = failure
                write_json = scan.f.write_json
                def checkpoint(path, report, previous):
                    if report['status'] == 'failed':
                        raise OSError('checkpoint write failed')
                    return write_json(path, report, previous)
                stack.enter_context(mock.patch.object(scan.f, 'write_json', side_effect=checkpoint))
                with self.assertRaises(type(failure)) as observed:
                    scan.main()
                self.assertIs(observed.exception, failure)
                self.assertIn('checkpoint write failed', failure.__notes__[0])
                self.assertIn(str(self.output) + '.partial', failure.__notes__[0])
                self.assertTrue(self.scanner.call_args.args[0].parent.is_dir())
                self.assertFalse(self.output.exists())
                self.cleanup.assert_not_called()
                report = json.loads(self.output.with_name(self.output.name + '.partial').read_text())
                self.assertEqual(report['status'], 'running')
                self.assertFalse(report['workloads']['flat']['sample_rows'][0]['validated'])

    def test_memory_rounds_and_comparisons_use_requested_samples(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory), memory=True)
            scan.main()
            report = json.loads(self.output.read_text())
            self.assertTrue(report['passed'])
            self.assertEqual(report['memory_samples_per_method'], 10)
            self.assertEqual(self.sampler.call_count, 90)
            self.assertIn('native_metrics.py', report['implementation_sha256'])
            self.assertIn('native_correctness.py', report['implementation_sha256'])
            for details in report['workloads'].values():
                metadata = details['metadata']
                self.assertEqual(metadata['status'], 'prepared')
                self.assertTrue(metadata['coverage']['populated'])
                baseline = Path(metadata['snapshot'])
                self.assertEqual(scan.f.digest(baseline), metadata['snapshot_sha256'])
                with gzip.open(baseline, 'rt') as stream:
                    self.assertIn('file', json.load(stream)['entries'])
                self.assertEqual(len(details['sample_rows']), 36)
                self.assertEqual(len(details['memory_rows']), 30)
                self.assertTrue(all(row['validated'] and row['source_precheck']['unchanged'] and
                                    row['source_verification']['unchanged']
                                    for row in details['sample_rows'] + details['memory_rows']))
                for method in ('bulk', 'bulk_serial'):
                    memory = details['memory_comparisons'][method]['rss_bytes']
                    self.assertEqual(memory['complete_pairs'], 10)
                    self.assertEqual(memory['decision'], 'candidate_lower')
                    self.assertEqual(memory['candidate']['p95'], 4096)
                    self.assertEqual(memory['candidate']['sample_variance'], 0)
                    for value in details['timing_comparisons'][method].values():
                        self.assertEqual(value['complete_pairs'], 10)
            self.assertFalse(self.output.with_name(self.output.name + '.partial').exists())

    def test_snapshots_are_private_under_permissive_umask(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory))
            previous_umask = os.umask(0)
            try:
                scan.main()
            finally:
                os.umask(previous_umask)
            report = json.loads(self.output.read_text())
            for details in report['workloads'].values():
                baseline = Path(details['metadata']['snapshot'])
                self.assertEqual(stat.S_IMODE(baseline.stat().st_mode), 0o600)
                with gzip.open(baseline, 'rt') as stream:
                    self.assertIn('file', json.load(stream)['entries'])

    def test_snapshot_symlink_collision_preserves_target_and_fixture(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory))
            target = Path(directory) / 'existing-data'
            target.write_bytes(b'preserve existing data')
            original = target.stat()
            baseline = self.output.with_name(self.output.name + '.flat.source.json.gz')
            baseline.symlink_to(target)
            with self.assertRaises(FileExistsError):
                scan.main()
            self.failed_report()
            self.scanner.assert_not_called()
            self.sampler.assert_not_called()
            self.assertTrue(baseline.is_symlink())
            self.assertEqual(target.stat(), original)
            self.assertEqual(target.read_bytes(), b'preserve existing data')

    def test_same_counts_do_not_hide_content_or_metadata_mutation(self):
        for field in ('sha256', 'mode'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                def mutate(path, **_):
                    if field == 'sha256':
                        (path / 'file').write_bytes(b'b')
                    else:
                        (path / 'file').chmod(0o600)
                    return {'files': 1}
                self.scanner.side_effect = mutate
                with self.assertRaisesRegex(RuntimeError, 'source changed during timing'):
                    scan.main()
                row = self.failed_report()['workloads']['flat']['sample_rows'][0]
                self.scanner.assert_called_once()
                self.assertTrue(row['ok'])
                self.assertTrue(row['counts_validated'])
                self.assertFalse(row['validated'])
                self.assertIn('wall_s', row)
                self.assertIn('cpu_s', row)
                self.assertIn(field, [loss['field'] for loss in row['source_verification']['candidate_losses']])

    def test_source_precheck_failure_prevents_scan(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory))
            def changed(path, **options):
                if self.snapshots.call_count == 2:
                    (path / 'file').write_bytes(b'b')
                return self.snapshot(path, **options)
            self.snapshots.side_effect = changed
            with self.assertRaisesRegex(RuntimeError, 'source changed before timing'):
                scan.main()
            row = self.failed_report()['workloads']['flat']['sample_rows'][0]
            self.scanner.assert_not_called()
            self.sampler.assert_not_called()
            self.assertFalse(row['source_precheck']['unchanged'])
            self.assertNotIn('wall_s', row)

    def test_unavailable_metadata_prevents_all_attempts(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory), memory=True)
            def unavailable(path, **options):
                observed = self.snapshot(path, **options)
                observed['unavailable_fields'] = ['acl']
                return observed
            self.snapshots.side_effect = unavailable
            with self.assertRaisesRegex(RuntimeError, 'Metadata observation unavailable'):
                scan.main()
            details = self.failed_report()['workloads']['flat']
            self.scanner.assert_not_called()
            self.sampler.assert_not_called()
            self.assertEqual(details['sample_rows'], [])
            self.assertEqual(details['memory_rows'], [])
            self.assertTrue(Path(details['metadata']['snapshot']).is_file())

    def test_metadata_setup_checkpoints_seed_before_failure(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory))
            def fail(path, *, receipt, scan_layout):
                checkpoint = json.loads(self.output.with_name(self.output.name + '.partial').read_text())
                self.assertEqual(checkpoint['workloads'][scan_layout]['metadata'], {'status': 'preparing', 'seed': {}})
                receipt['setup_started'] = True
                raise OSError('metadata setup failed')
            self.enrich.side_effect = fail
            with self.assertRaisesRegex(OSError, 'metadata setup failed'):
                scan.main()
            self.assertTrue(self.failed_report()['workloads']['flat']['metadata']['seed']['setup_started'])
            self.scanner.assert_not_called()

    def test_memory_mutation_retains_measurement_and_fixture(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory), memory=True)
            def mutate(path, *_):
                (path / 'file').write_bytes(b'b')
                return {'rss_bytes': 8192, 'footprint_bytes': 4096, 'exit_code': 0, 'counts': {'files': 1}}
            self.sampler.side_effect = mutate
            with self.assertRaisesRegex(RuntimeError, 'source changed during memory'):
                scan.main()
            details = self.failed_report()['workloads']['flat']
            self.assertEqual(len(details['sample_rows']), 36)
            self.sampler.assert_called_once()
            row = details['memory_rows'][0]
            self.assertTrue(row['ok'])
            self.assertFalse(row['validated'])
            self.assertEqual(row['rss_bytes'], 8192)
            self.assertFalse(row['source_verification']['unchanged'])

    def test_invalid_memory_child_preserves_raw_resource_measurement(self):
        row = {'validated': False}
        measured = {'exit_code': 0, 'rss_bytes': 4096, 'footprint_bytes': 2048}
        completed = subprocess.CompletedProcess([], 0, b'{"counts": {}, "native_binary_sha256": "hash"}', b'')
        with mock.patch.object(scan.f, 'measure_memory', return_value=(measured, completed)), \
                self.assertRaisesRegex(RuntimeError, 'Memory child counts'):
            scan.memory_sample('/unused', 'posix', {'files': 1}, 'hash', '/unused-metrics', row)
        self.assertEqual(row, {'validated': False, **measured})

    def test_warmups_missing_and_invalid_memory_cannot_create_win(self):
        rows = [dict(method=method, pair_id=index, phase='resources', warmup=index < 0,
                     ok=True, validated=True, rss_bytes=8192 if method == 'posix' else 4096)
                for method in scan.METHODS for index in range(-2, 11)]
        rows = [row for row in rows if not (row['method'] == 'bulk_serial' and row['pair_id'] == 5)]
        for row in rows:
            if row['method'] == 'bulk' and row['pair_id'] == 5:
                row['rss_bytes'] = 0
        for values in scan.comparisons(list(reversed(rows)), 'resources').values():
            result = values['rss_bytes']
            self.assertEqual(result['complete_pairs'], 10)
            self.assertEqual(result['decision'], 'incomplete_pairs')
            self.assertEqual(result['excluded_pairs'][0]['pair_id'], 5)

    def test_invalid_sample_count_stops_before_collection(self):
        with mock.patch.object(sys, 'argv', ['scan.py', '--scratch', '/unused',
                                            '--output', '/unused/result', '--samples', '9']), \
                mock.patch.object(scan.f, 'command') as command, \
                redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
            scan.main()
        self.assertEqual(failure.exception.code, 2)
        command.assert_not_called()
