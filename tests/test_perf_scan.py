"""Scanner report orchestration with native work and resource collection mocked."""
from contextlib import ExitStack, redirect_stdout, redirect_stderr
import copy
import errno
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
from types import SimpleNamespace
import unittest
from unittest import mock


PERF = Path(__file__).parent / 'perf'
with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
    spec = importlib.util.spec_from_file_location('scan_statistics', PERF / 'scan.py')
    scan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scan)


class ColdToolProvenance(unittest.TestCase):
    @staticmethod
    def info(**changes):
        values = dict(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o755, st_uid=0,
                      st_gid=0, st_size=16, st_mtime_ns=10, st_ctime_ns=20, st_flags=0)
        values.update(changes)
        return SimpleNamespace(**values)

    def observe(self, *, content=None, entry=None, target=None):
        fixture_hash = hashlib.sha256(b'controlled tool').hexdigest()
        with mock.patch.object(Path, 'lstat', side_effect=entry or (lambda path: self.info()), autospec=True), \
                mock.patch.object(Path, 'stat', side_effect=target or (lambda path: self.info()), autospec=True), \
                mock.patch.object(scan.f, 'digest', side_effect=content or (lambda path: fixture_hash)) as observed:
            self.hash_read = observed
            return scan.f.cold_tool_provenance()

    def test_fixed_tools_get_real_fixture_hashes_and_metadata(self):
        records = self.observe()
        self.assertEqual(list(records), ['/usr/bin/sudo', '/usr/sbin/purge'])
        self.assertEqual([str(call.args[0]) for call in self.hash_read.call_args_list], list(records))
        for row in records.values():
            self.assertEqual(row['sha256'], hashlib.sha256(b'controlled tool').hexdigest())
            self.assertEqual(row['content_hash_status'], 'available')
            self.assertIsNone(row['sha256_unavailable'])
            self.assertEqual(row['entry']['st_ino'], 2)
            self.assertEqual(row['target']['st_ctime_ns'], 20)

    def test_only_content_permission_denial_is_explicitly_unavailable(self):
        for code in (errno.EACCES, errno.EPERM):
            with self.subTest(errno=code):
                records = self.observe(content=PermissionError(code, 'controlled denied read'))
                self.assertEqual(len(records), 2)
                for row in records.values():
                    self.assertIsNone(row['sha256'])
                    self.assertEqual(row['content_hash_status'], 'unavailable')
                    self.assertEqual(row['sha256_unavailable']['errno'], code)

    def test_missing_or_inaccessible_metadata_remains_fatal(self):
        for field in ('entry', 'target'):
            for error in (FileNotFoundError(errno.ENOENT, 'missing'), PermissionError(errno.EACCES, 'metadata denied')):
                with self.subTest(field=field, error=type(error).__name__):
                    with self.assertRaises(type(error)):
                        self.observe(**{field: error})
                    self.hash_read.assert_not_called()

    def test_wrong_type_or_nonexecutable_target_is_fatal(self):
        for mode in (stat.S_IFDIR | 0o755, stat.S_IFREG | 0o644):
            with self.subTest(mode=mode), self.assertRaisesRegex(RuntimeError, 'regular executable'):
                self.observe(target=lambda path: self.info(st_mode=mode))
            self.hash_read.assert_not_called()

    def test_unexpected_content_io_error_is_fatal(self):
        for error in (OSError(errno.EIO, 'read failed'), PermissionError(errno.EIO, 'unexpected errno')):
            with self.subTest(error=type(error).__name__), self.assertRaises(type(error)):
                self.observe(content=error)

    def test_entry_or_target_replacement_is_fatal_even_if_content_unreadable(self):
        for changed in ('entry', 'target'):
            for unreadable in (False, True):
                with self.subTest(changed=changed, unreadable=unreadable):
                    calls = {'entry': 0, 'target': 0}
                    def metadata(field):
                        def observe(path):
                            calls[field] += 1
                            return self.info(st_ino=3 if field == changed and calls[field] > 1 else 2)
                        return observe
                    with self.assertRaisesRegex(RuntimeError, 'changed during provenance'):
                        self.observe(entry=metadata('entry'), target=metadata('target'),
                            content=PermissionError(errno.EACCES, 'denied') if unreadable else None)

    def test_symlink_entry_and_executable_target_are_pinned_separately(self):
        records = self.observe(entry=lambda path: self.info(st_mode=stat.S_IFLNK | 0o755, st_ino=9))
        for row in records.values():
            self.assertEqual(row['entry']['st_ino'], 9)
            self.assertEqual(row['target']['st_ino'], 2)


class ScannerStatistics(unittest.TestCase):
    @staticmethod
    def tool_records():
        # Controlled records for orchestration; no host executable is inspected.
        return {name: {'entry': {'st_ino': index}, 'target': {'st_ino': index},
                       'sha256': None, 'content_hash_status': 'unavailable',
                       'sha256_unavailable': {'errno': errno.EACCES, 'reason': 'Content read permission denied'}}
                for index, name in enumerate(('/usr/bin/sudo', '/usr/sbin/purge'), 1)}

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
        return {'entries': {'file': entry}, 'hardlink_groups': [], 'unavailable_fields': [],
                'metadata_capabilities': {'platform': 'darwin', 'flags': True, 'resource_fork': True,
                                          'acl': 'Darwin extended ACL'}}

    def configure(self, stack, root, *, memory=False, cache='warm'):
        self.output = root / 'report.json'
        stack.enter_context(mock.patch.object(sys, 'argv', [
            'scan.py', '--scratch', str(root), '--output', str(self.output),
            '--samples', '10', '--files', '1', *(['--memory'] if memory else []),
            *(['--cache', cache] if cache != 'warm' else [])]))
        stack.enter_context(mock.patch.object(scan, 'fixture', side_effect=self.fixture))
        self.scanner = stack.enter_context(mock.patch.object(scan._scan, 'scan', return_value={'files': 1}))
        stack.enter_context(mock.patch.object(scan._scan, 'mounts', return_value=[]))
        stack.enter_context(mock.patch.object(scan.f, 'scratch_volume', return_value={'filesystem': 'apfs'}))
        stack.enter_context(mock.patch.object(scan.f, 'command', return_value=subprocess.CompletedProcess([], 0, b'24', b'')))
        self.cleanup = stack.enter_context(mock.patch.object(scan.f, 'remove_fixture', side_effect=shutil.rmtree))
        self.snapshots = stack.enter_context(mock.patch.object(scan.native_correctness, 'snapshot', side_effect=self.snapshot))
        self.enrich = stack.enter_context(mock.patch.object(scan.native_fixtures, 'enrich_metadata',
            side_effect=lambda path, *, receipt, scan_layout: receipt.update(
                platform='darwin', path='file', data_size=1, hardlinks=None, sparse=None)))
        self.sampler = stack.enter_context(mock.patch.object(scan, 'memory_sample', side_effect=lambda path, method, *_: {
            'rss_bytes': 8192 if method == 'posix' else 4096,
            'footprint_bytes': 2048, 'exit_code': 0, 'counts': {'files': 1}}))
        self.conditioning = stack.enter_context(mock.patch.object(scan.native_suite, 'cache_prepare',
            return_value={'mode': cache, **({'exit_code': 0, 'stderr': ''} if cache == 'cold' else {})}))
        self.tools = stack.enter_context(mock.patch.object(scan.f, 'cold_tool_provenance',
                                                          side_effect=self.tool_records))
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
                def fixture(path, *args):
                    counts = self.fixture(path, *args)
                    (path / 'file').chmod(0o644)
                    self.assertEqual(stat.S_IMODE((path / 'file').stat().st_mode), 0o644)
                    return counts
                stack.enter_context(mock.patch.object(scan, 'fixture', side_effect=fixture))
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
            self.configure(stack, Path(directory), cache='cold')
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
            self.conditioning.assert_not_called()

    def test_memory_precheck_failure_prevents_next_purge_and_child(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory), memory=True, cache='cold')
            def changed(path, **options):
                if self.snapshots.call_count == 74:
                    (path / 'file').write_bytes(b'changed')
                return self.snapshot(path, **options)
            self.snapshots.side_effect = changed
            with self.assertRaisesRegex(RuntimeError, 'source changed before memory'):
                scan.main()
            row = self.failed_report()['workloads']['flat']['memory_rows'][0]
            self.assertFalse(row['source_precheck']['unchanged'])
            self.assertEqual(self.scanner.call_count, 36)
            self.assertEqual(self.conditioning.call_count, 36)
            self.sampler.assert_not_called()

    def test_cold_conditioning_follows_every_precheck_for_both_phases(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory), memory=True, cache='cold')
            events = []
            def snapshot(path, **options):
                events.append('snapshot')
                return self.snapshot(path, **options)
            def purge(*args):
                self.assertEqual(events[-1], 'snapshot')
                events.append('purge')
                return {'mode': 'cold', 'exit_code': 0, 'stderr': ''}
            def measure(path, **options):
                self.assertEqual(events[-2:], ['snapshot', 'purge'])
                events.append('timing')
                return {'files': 1}
            def memory(path, method, *_):
                self.assertEqual(events[-2:], ['snapshot', 'purge'])
                events.append('memory-launch')
                return {'rss_bytes': 8192 if method == 'posix' else 4096,
                        'footprint_bytes': None, 'exit_code': 0, 'counts': {'files': 1}}
            self.snapshots.side_effect = snapshot
            self.conditioning.side_effect = purge
            self.scanner.side_effect = measure
            self.sampler.side_effect = memory
            self.assertEqual(scan.main(), 0)
            report = json.loads(self.output.read_text())
            self.assertEqual(report['cache'], 'cold')
            self.assertEqual(self.conditioning.call_count, 198)
            self.assertEqual(self.scanner.call_count, 108)
            self.assertEqual(self.sampler.call_count, 90)
            self.assertIn('native_suite.py', report['implementation_sha256'])
            self.assertEqual(set(report['cold_tools']), {'/usr/bin/sudo', '/usr/sbin/purge'})
            self.assertTrue(report['cold_tool_identity_verified'])
            self.assertFalse(report['cold_tool_content_verified'])
            self.assertTrue(all(row['sha256'] is None for row in report['cold_tools'].values()))
            for details in report['workloads'].values():
                for row in details['sample_rows'] + details['memory_rows']:
                    self.assertEqual(row['cache'], 'cold')
                    self.assertEqual(row['cache_receipt']['exit_code'], 0)
                for method in ('bulk', 'bulk_serial'):
                    self.assertIsNone(details['memory_medians'][method]['footprint_bytes'])
                    self.assertEqual(set(details['memory_comparisons'][method]), {'rss_bytes'})
                    self.assertEqual(details['memory_comparisons'][method]['rss_bytes']['complete_pairs'], 10)
                    self.assertTrue(all(value['complete_pairs'] == 10
                                        for value in details['timing_comparisons'][method].values()))

    def test_warm_default_does_not_require_cold_tools(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory))
            original = scan.f.digest
            def digest(path):
                self.assertNotIn(str(path), ('/usr/bin/sudo', '/usr/sbin/purge'))
                return original(path)
            stack.enter_context(mock.patch.object(scan.f, 'digest', side_effect=digest))
            self.assertEqual(scan.main(), 0)
            report = json.loads(self.output.read_text())
            self.assertEqual(report['cache'], 'warm')
            self.assertNotIn('cold_tools', report)
            self.tools.assert_not_called()
            self.assertTrue(all(call.args == ('warm', 600) for call in self.conditioning.call_args_list))

    def test_denied_purge_never_launches_attempt_and_validates_before_cleanup(self):
        for memory in (False, True):
            with self.subTest(memory=memory), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory), memory=memory, cache='cold')
                failure_at = 37 if memory else 1
                def purge(*args):
                    return {'mode': 'cold', 'exit_code': int(self.conditioning.call_count == failure_at),
                            'stderr': 'denied' if self.conditioning.call_count == failure_at else ''}
                self.conditioning.side_effect = purge
                self.assertEqual(scan.main(), 1)
                report = json.loads(self.output.read_text())
                self.assertEqual(report['status'], 'complete')
                self.assertFalse(report['passed'])
                self.assertTrue(report['cleanup_passed'])
                self.assertTrue(report['denial_runtime_verified'])
                self.assertTrue(report['cold_tool_identity_verified'])
                self.assertFalse(report['cold_tool_content_verified'])
                self.assertTrue(report['denial_source_verification']['flat']['unchanged'])
                self.assertEqual(report['cold_cache_receipt']['exit_code'], 1)
                self.assertNotIn('retained_fixture', report)
                self.assertEqual(self.conditioning.call_count, failure_at)
                self.assertEqual(self.scanner.call_count, 36 if memory else 0)
                self.sampler.assert_not_called()
                details = report['workloads']['flat']
                row = (details['memory_rows'] if memory else details['sample_rows'])[-1]
                self.assertFalse(row['ok'])
                self.assertFalse(row['validated'])
                self.assertIn('unavailable', row)
                self.assertNotIn('wall_s', row)
                self.assertNotIn('rss_bytes', row)
                self.cleanup.assert_called_once()

    def test_denial_does_not_hide_mutation_runtime_drift_or_uncertain_purge(self):
        for failure in ('mutation', 'runtime', 'uncertain', 'signal', 'error'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory), cache='cold')
                if failure == 'runtime':
                    hashes, native, origin = scan.runtime_provenance()
                    stack.enter_context(mock.patch.object(scan, 'runtime_provenance',
                        side_effect=[(hashes, native, origin), ({'drift': 'changed'}, native, origin)]))
                def purge(*args):
                    if failure == 'mutation':
                        (self.snapshots.call_args.args[0] / 'file').write_bytes(b'changed')
                    if failure == 'uncertain':
                        raise scan.f.ChildCompletionUnknown('uncertain purge')
                    if failure == 'error':
                        raise OSError('purge failed')
                    return {'mode': 'cold', 'exit_code': -9 if failure == 'signal' else 1, 'stderr': 'denied'}
                self.conditioning.side_effect = purge
                with self.assertRaises((RuntimeError, OSError)):
                    scan.main()
                self.failed_report()
                self.scanner.assert_not_called()
                self.sampler.assert_not_called()
                self.conditioning.assert_called_once()

    def test_denied_purge_cleanup_failure_is_retained_failure(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory), cache='cold')
            self.conditioning.return_value = {'mode': 'cold', 'exit_code': 1, 'stderr': 'denied'}
            self.cleanup.side_effect = OSError('cleanup failed')
            with self.assertRaisesRegex(OSError, 'cleanup failed'):
                scan.main()
            report = json.loads(self.output.with_name(self.output.name + '.partial').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertFalse(report.get('cleanup_passed', False))
            self.assertFalse(report['cold_tool_identity_verified'])
            self.assertFalse(report['cold_tool_content_verified'])
            self.assertNotIn('denial_runtime_verified', report)
            self.assertTrue(Path(report['retained_fixture']).is_dir())
            self.assertFalse(self.output.exists())

    def test_uncertain_cold_memory_child_retains_fixture(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory), memory=True, cache='cold')
            self.sampler.side_effect = scan.f.ChildCompletionUnknown('memory child uncertain')
            with self.assertRaisesRegex(scan.f.ChildCompletionUnknown, 'memory child uncertain'):
                scan.main()
            report = self.failed_report()
            self.assertIsNone(report['cold_cache_unavailable'])
            self.assertEqual(self.conditioning.call_count, 37)
            self.sampler.assert_called_once()

    def test_tool_record_drift_cannot_close_denial_as_verified(self):
        for change in ('identity', 'readability', 'hash', 'missing'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory), cache='cold')
                before = self.tool_records()
                after = copy.deepcopy(before)
                if change == 'identity':
                    after['/usr/bin/sudo']['target']['st_ino'] += 1
                elif change == 'readability':
                    after['/usr/bin/sudo'].update(sha256=hashlib.sha256(b'controlled tool').hexdigest(),
                        content_hash_status='available', sha256_unavailable=None)
                elif change == 'hash':
                    for row in before.values():
                        row.update(sha256=hashlib.sha256(b'controlled tool').hexdigest(),
                                   content_hash_status='available', sha256_unavailable=None)
                    after = copy.deepcopy(before)
                    after['/usr/bin/sudo']['sha256'] = hashlib.sha256(b'changed tool').hexdigest()
                self.tools.side_effect = [before, FileNotFoundError('missing tool') if change == 'missing' else after]
                self.conditioning.return_value = {'mode': 'cold', 'exit_code': 1, 'stderr': 'denied'}
                with self.assertRaises((RuntimeError, FileNotFoundError)):
                    scan.main()
                report = self.failed_report()
                self.assertFalse(report['cold_tool_identity_verified'])
                self.assertFalse(report['cold_tool_content_verified'])
                self.assertNotIn('denial_runtime_verified', report)

    def test_real_fixture_hashes_allow_content_flag_only_after_cleanup(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory), cache='cold')
            records = self.tool_records()
            for row in records.values():
                row.update(sha256=hashlib.sha256(b'controlled tool').hexdigest(),
                           content_hash_status='available', sha256_unavailable=None)
            self.tools.side_effect = lambda: copy.deepcopy(records)
            def cleanup(path):
                partial = json.loads(self.output.with_name(self.output.name + '.partial').read_text())
                self.assertFalse(partial['cold_tool_identity_verified'])
                self.assertFalse(partial['cold_tool_content_verified'])
                shutil.rmtree(path)
            self.cleanup.side_effect = cleanup
            self.assertEqual(scan.main(), 0)
            report = json.loads(self.output.read_text())
            self.assertTrue(report['cold_tool_identity_verified'])
            self.assertTrue(report['cold_tool_content_verified'])

    def test_denial_cleanup_keeps_existing_root_and_mount_guards(self):
        for failure in ('identity', 'mount'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory), cache='cold')
                def purge(*args):
                    owned = self.snapshots.call_args.args[0].parent
                    if failure == 'identity':
                        owned.chmod(0o755)
                    else:
                        scan._scan.mounts.return_value = [{'path': str(owned / 'mounted')}]
                    return {'mode': 'cold', 'exit_code': 1, 'stderr': 'denied'}
                self.conditioning.side_effect = purge
                with self.assertRaisesRegex(RuntimeError, 'preserve it'):
                    scan.main()
                self.failed_report()

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

    def test_memory_requires_rss_and_footprint_remains_optional(self):
        completed = subprocess.CompletedProcess([], 0,
            b'{"counts": {"files": 1}, "native_binary_sha256": "hash"}', b'')
        for rss in (None, 0, -1, 4096):
            with self.subTest(rss=rss):
                row = {'validated': False}
                measured = {'exit_code': 0, 'rss_bytes': rss, 'footprint_bytes': None}
                with mock.patch.object(scan.f, 'measure_memory', return_value=(measured, completed)):
                    if rss == 4096:
                        result = scan.memory_sample('/unused', 'posix', {'files': 1}, 'hash', '/unused', row)
                        self.assertIsNone(result['footprint_bytes'])
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'peak RSS'):
                            scan.memory_sample('/unused', 'posix', {'files': 1}, 'hash', '/unused', row)
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
