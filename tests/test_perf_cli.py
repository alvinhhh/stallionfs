"""Existing tiny CLI deletion orchestration with all commands supervised and mocked."""
from contextlib import ExitStack, redirect_stderr
import base64
import copy
import importlib.util
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
    spec = importlib.util.spec_from_file_location('native_cli_cases', PERF / 'cli.py')
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)


class NativeDelete(unittest.TestCase):
    def configure(self, stack, root, *, cache=None, samples=10):
        self.root = root
        self.output = root / 'cli.json'
        binary = root / 'candidate'
        binary.write_bytes(b'controlled installed runtime')
        self.args = SimpleNamespace(scratch=root, output=self.output, candidate=binary,
                                    cache=cache or ['warm'], samples=samples)
        stack.enter_context(mock.patch.object(cli.platform, 'system', return_value='Darwin'))
        stack.enter_context(mock.patch.object(cli.native_metrics.sys, 'platform', 'darwin'))
        stack.enter_context(mock.patch.object(cli, 'installed', return_value={'binary': binary}))
        stack.enter_context(mock.patch.object(cli, 'scratch_volume', return_value={'filesystem': 'apfs'}))
        self.events = []
        self.mounts = stack.enter_context(mock.patch.object(
            cli, 'no_mounts_below', side_effect=lambda *_: self.events.append('mount')))
        self.pins_value = {'runtime': {'candidate': 'controlled fixture'}, 'cold_tools': {
            name: {'sha256': None, 'content_hash_status': 'unavailable'}
            for name in ('/usr/bin/sudo', '/usr/sbin/purge')}}
        self.pins = stack.enter_context(mock.patch.object(cli, 'native_delete_pins',
                                                        side_effect=lambda *_: copy.deepcopy(self.pins_value)))
        # Peripheral roots are mocked; the scored fixture retains exact 4 KiB/0640 contents.
        def fixtures(base):
            self.base = base
            tiny, empty, nested = base / 'tiny', base / 'empty', base / 'nested'
            tiny.write_bytes(bytes(range(256)) * 16)
            tiny.chmod(0o640)
            empty.mkdir()
            nested.mkdir()
            (nested / 'peripheral').write_bytes(b'preserve all created roots')
            (base / 'outside-sentinel').write_bytes(b'keep outside linked trees\n')
            return {'tiny_4kib': tiny, 'empty': empty, 'nested_1000': nested}, {}
        stack.enter_context(mock.patch.object(cli, 'make_fixtures', side_effect=fixtures))
        def command(argv, **kwargs):
            if argv[-1] == 'volumes':
                return subprocess.CompletedProcess(argv, 0, b'[]', b'')
            self.assertEqual(argv[:2], ['/bin/cp', '-cRp'])
            shutil.copy2(argv[-2], argv[-1])
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        self.setup = stack.enter_context(mock.patch.object(cli, 'command', side_effect=command))
        def condition(mode, timeout):
            self.assertEqual(self.events[-1], 'mount')
            self.events.append('condition')
            return {'mode': mode, **({'exit_code': 0, 'stderr': ''} if mode == 'cold' else {})}
        self.condition = stack.enter_context(mock.patch.object(cli.native_suite, 'cache_prepare', side_effect=condition))
        self.collect = stack.enter_context(mock.patch.object(cli.native_metrics, 'collect', side_effect=self.measure))

    def measure(self, argv, **kwargs):
        self.assertEqual(self.events[-1], 'condition')
        self.events.append('measure')
        self.assertIn('env', kwargs)
        self.assertEqual(kwargs['timeout_s'], 120)
        target = Path(argv[-1])
        info = target.lstat()
        self.assertTrue(target.is_absolute())
        self.assertEqual(target.parent, self.base)
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(info.st_nlink, 1)
        self.assertNotEqual(info.st_ino, (self.base / 'tiny').lstat().st_ino)
        native = argv[0] == '/bin/rm'
        if native:
            self.assertEqual(argv, ['/bin/rm', '-f', str(target)])
        else:
            self.assertEqual(argv[-2], 'delete')
        stdout = json.dumps({'path': str(target)}).encode() if '--json' in argv else b''
        target.unlink()
        stderr = b'real 0.01\nuser 0.01\nsys 0.00\n8192 maximum resident set size\n' if kwargs['phase'] == 'resources' else b''
        return {'phase': kwargs['phase'], 'exit_code': 0, 'ok': True, 'completion_uncertain': False,
                'wall_s': 0.004 if native else 0.002, 'cpu_s': 0.002 if native else 0.001,
                'rss_bytes': 8192 if native else 4096,
                'stdout_b64': base64.b64encode(stdout).decode(),
                'stderr_b64': base64.b64encode(stderr).decode()}

    def read(self):
        journal = cli.native_report.ReportJournal.open_existing(self.output)
        try:
            journal.verify()
            return journal.state, list(journal.iter_latest('rows')), list(journal.iter_latest('comparisons'))
        finally:
            journal.close()

    def retained(self):
        self.assertTrue(self.base.is_dir())
        state, rows, comparisons = self.read()
        self.assertEqual(state['status'], 'failed')
        self.assertFalse(state['passed'])
        self.assertFalse(state['cleanup_passed'])
        self.assertEqual(state['retained_fixture'], str(self.base))
        return state, rows, comparisons

    def test_exact_timing_resource_pairs_and_fresh_json_references(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory), samples=12)
            self.assertEqual(cli.native_delete(self.args), 0)
            state, rows, comparisons = self.read()
            self.assertTrue(state['cleanup_passed'])
            self.assertFalse(self.base.exists())
            self.assertFalse(state['qualified'])
            self.assertEqual((state['timing_pairs'], state['resource_pairs']), (31, 12))
            self.assertEqual(len(rows), 176)
            self.assertEqual(len(comparisons), 4)
            for form in ('plain', 'json'):
                for phase, count in (('timing', 31), ('resources', 12)):
                    for method in ('native', 'candidate'):
                        group = [row for row in rows if row['output'] == form and row['phase'] == phase and row['method'] == method]
                        measured = [row for row in group if not row['warmup']]
                        self.assertEqual({row['pair_id'] for row in measured}, set(range(1, count + 1)))
                        self.assertEqual(sum(row['warmup'] for row in group), int(phase == 'timing'))
                        self.assertTrue(all(row['validated'] for row in group))
                        if method == 'native':
                            self.assertTrue(all(base64.b64decode(row['stdout_b64']) == b'' for row in group))
            self.assertTrue(all(row['reference_output'] == 'plain' and row['paired'] for row in comparisons))
            self.assertTrue(all(set(row['metrics']) == {'rss_bytes'} and row['footprint'] == 'unavailable'
                                for row in comparisons if row['phase'] == 'resources'))

    def test_cold_rows_use_mocked_conditioning_and_keep_unreadable_content_limit(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory), cache=['cold'])
            self.assertEqual(cli.native_delete(self.args), 0)
            state, rows, _ = self.read()
            self.assertEqual(len(rows), 168)
            self.assertEqual(self.condition.call_count, 168)
            self.assertTrue(state['cold_tool_identity_verified'])
            self.assertFalse(state['cold_tool_content_verified'])
            self.assertTrue(all(row['cache_receipt']['mode'] == 'cold' for row in rows))

    def test_mount_observer_runs_before_conditioning_and_after_measurement_only(self):
        for cache in ('warm', 'cold'):
            with self.subTest(cache=cache), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory), cache=[cache])
                self.assertEqual(cli.native_delete(self.args), 0)
                self.assertEqual(self.events.count('condition'), 168)
                self.assertEqual(self.events.count('measure'), 168)
                for index, event in enumerate(self.events):
                    if event == 'condition':
                        self.assertEqual(self.events[index - 1:index + 3],
                                         ['mount', 'condition', 'measure', 'mount'])

    def test_conditioning_same_inode_metadata_changes_are_never_measured(self):
        for change in ('mode', 'size'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory), cache=['cold'])
                original = self.condition.side_effect
                def condition(mode, timeout):
                    result = original(mode, timeout)
                    target = self.base / 'target'
                    before = target.lstat()
                    if change == 'mode':
                        target.chmod(0o600)
                    else:
                        with target.open('r+b') as stream:
                            stream.truncate(2048)
                    self.assertEqual(target.lstat().st_ino, before.st_ino)
                    return result
                self.condition.side_effect = condition
                with self.assertRaisesRegex(RuntimeError, 'Delete operand metadata changed'):
                    cli.native_delete(self.args)
                self.collect.assert_not_called()
                self.assertTrue((self.base / 'target').exists())
                self.retained()

    def test_pair_closure_rejects_short_duplicate_invalid_and_extra_ids(self):
        for phase, count in (('timing', 31), ('resources', 10)):
            rows = [dict(method=method, pair_id=index, phase=phase, warmup=index == 0,
                         ok=True, validated=True, wall_s=0.01, cpu_s=0.01, rss_bytes=4096)
                    for method in ('native', 'candidate')
                    for index in (range(32) if phase == 'timing' else range(1, count + 1))]
            self.assertTrue(cli.native_delete_comparison(rows, phase, 10))
            for change in ('short', 'duplicate', 'extra', 'invalid', 'warmup'):
                altered = copy.deepcopy(rows)
                if change == 'short':
                    altered = [row for row in altered if row['pair_id'] <= 10] if phase == 'timing' else altered[:-1]
                elif change == 'duplicate':
                    altered[-1]['pair_id'] = altered[-2]['pair_id']
                elif change == 'extra':
                    altered.append({**altered[-1], 'pair_id': 99})
                elif change == 'invalid':
                    altered[-1]['validated'] = False
                else:
                    altered.append({**altered[-1], 'pair_id': 0, 'warmup': True})
                with self.subTest(phase=phase, change=change), self.assertRaises(RuntimeError):
                    cli.native_delete_comparison(altered, phase, 10)

    def test_bad_setup_operand_is_never_measured(self):
        for kind in ('symlink', 'directory', 'hardlink', 'replaced', 'condition-symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                original = self.setup.side_effect
                def setup(argv, **kwargs):
                    if argv[0] != '/bin/cp':
                        return original(argv, **kwargs)
                    target = Path(argv[-1])
                    if kind == 'symlink':
                        target.symlink_to(argv[-2])
                    elif kind == 'directory':
                        target.mkdir()
                    elif kind == 'hardlink':
                        os.link(argv[-2], target)
                    else:
                        result = original(argv, **kwargs)
                        return result
                    return subprocess.CompletedProcess(argv, 0, b'', b'')
                self.setup.side_effect = setup
                if kind == 'replaced':
                    original_checkpoint = cli.native_report.ReportJournal.checkpoint
                    swapped = []
                    def checkpoint(journal, state):
                        active = state.get('active_operation', {})
                        if not swapped and active.get('argv', ['/bin/cp'])[0] != '/bin/cp':
                            target = self.base / 'target'
                            replacement = self.base / 'replacement'
                            shutil.copy2(target, replacement)
                            os.replace(replacement, target)
                            swapped.append(True)
                        return original_checkpoint(journal, state)
                    stack.enter_context(mock.patch.object(cli.native_report.ReportJournal, 'checkpoint', new=checkpoint))
                elif kind == 'condition-symlink':
                    original_condition = self.condition.side_effect
                    def condition(mode, timeout):
                        result = original_condition(mode, timeout)
                        target = self.base / 'target'
                        target.unlink()
                        target.symlink_to(self.base / 'tiny')
                        return result
                    self.condition.side_effect = condition
                with self.assertRaises(RuntimeError):
                    cli.native_delete(self.args)
                self.assertTrue(self.base.exists())
                self.collect.assert_not_called()

    def test_source_sentinel_store_and_json_failures_retain_all_roots(self):
        for change in ('source', 'peripheral', 'sentinel', 'store', 'json'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                def measure(argv, **kwargs):
                    result = self.measure(argv, **kwargs)
                    if change == 'source':
                        (self.base / 'tiny').chmod(0o600)
                    elif change == 'peripheral':
                        (self.base / 'nested' / 'peripheral').write_bytes(b'changed')
                    elif change == 'sentinel':
                        (self.base / 'outside-sentinel').write_bytes(b'changed')
                    elif change == 'store':
                        (self.base / 'unused-store').mkdir()
                    elif '--json' in argv:
                        result['stdout_b64'] = base64.b64encode(b'{"path":"wrong"}').decode()
                    return result
                self.collect.side_effect = measure
                with self.assertRaises(RuntimeError):
                    cli.native_delete(self.args)
                self.retained()

    def test_resource_footer_is_allowed_but_diagnostics_and_missing_rss_fail(self):
        for change in ('diagnostic', 'rss'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                def measure(argv, **kwargs):
                    result = self.measure(argv, **kwargs)
                    if kwargs['phase'] == 'resources':
                        if change == 'diagnostic':
                            result['stderr_b64'] = base64.b64encode(base64.b64decode(result['stderr_b64']) + b'rm: warning\n').decode()
                        else:
                            result['rss_bytes'] = None
                    return result
                self.collect.side_effect = measure
                with self.assertRaises(RuntimeError):
                    cli.native_delete(self.args)
                self.retained()

    def test_uncertain_setup_or_measurement_preserves_receipt_and_operand(self):
        for phase in ('setup', 'measurement'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                receipt = {'completion_uncertain': True, 'stderr_b64': base64.b64encode(b'partial').decode()}
                if phase == 'setup':
                    original = self.setup.side_effect
                    def setup(argv, **kwargs):
                        result = original(argv, **kwargs)
                        if argv[0] == '/bin/cp':
                            error = cli.ChildCompletionUnknown('uncertain setup')
                            error.receipt = receipt
                            raise error
                        return result
                    self.setup.side_effect = setup
                else:
                    self.collect.side_effect = cli.native_metrics.ChildCompletionUnknown(receipt)
                with self.assertRaises(RuntimeError):
                    cli.native_delete(self.args)
                state, _, _ = self.retained()
                self.assertEqual(state['command_receipt'], receipt)
                self.assertTrue((self.base / 'target').exists())

    def test_denied_purge_is_failed_not_retried_and_warm_groups_continue(self):
        for cache, failure_at in ((['cold', 'warm'], 1), (['cold'], 65)):
            with self.subTest(cache=cache), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory), cache=cache)
                original = self.condition.side_effect
                def condition(mode, timeout):
                    result = original(mode, timeout)
                    if mode == 'cold' and self.condition.call_count == failure_at:
                        result['exit_code'] = 1
                        result['stderr'] = 'denied'
                    return result
                self.condition.side_effect = condition
                self.assertEqual(cli.native_delete(self.args), 1)
                state, rows, comparisons = self.read()
                self.assertFalse(state['passed'])
                self.assertTrue(state['cleanup_passed'])
                self.assertTrue(state['denial_runtime_verified'])
                self.assertTrue(state['cold_tool_identity_verified'])
                self.assertTrue(state['source_checks_passed'])
                self.assertFalse(self.base.exists())
                self.assertTrue(any('unavailable' in row and not row['ok'] for row in rows))
                self.assertEqual(sum(call.args[0] == 'cold' for call in self.condition.call_args_list), failure_at)
                if 'warm' in cache:
                    self.assertEqual(len(comparisons), 4)
                    self.assertTrue(all(row['cache'] == 'warm' for row in comparisons))
                    self.assertEqual(self.collect.call_count, 168)
                else:
                    self.assertEqual(self.collect.call_count, 64)

    def test_denial_cannot_hide_changed_source_runtime_or_abnormal_completion(self):
        for failure in ('source', 'runtime', 'signal'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory), cache=['cold'])
                def condition(mode, timeout):
                    if failure == 'source':
                        (self.base / 'nested' / 'peripheral').write_bytes(b'changed')
                    return {'mode': mode, 'exit_code': -9 if failure == 'signal' else 1, 'stderr': 'denied'}
                self.condition.side_effect = condition
                if failure == 'runtime':
                    self.pins.side_effect = [self.pins_value, {'runtime': 'changed'}]
                with self.assertRaises(RuntimeError):
                    cli.native_delete(self.args)
                self.retained()
                self.collect.assert_not_called()

    def test_journal_failure_before_cleanup_retains_fixture(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory))
            original = cli.native_report.ReportJournal.append
            def append(journal, kind, index, payload):
                if kind == 'rows':
                    raise OSError('journal append failed')
                return original(journal, kind, index, payload)
            stack.enter_context(mock.patch.object(cli.native_report.ReportJournal, 'append', new=append))
            with self.assertRaisesRegex(OSError, 'journal append failed'):
                cli.native_delete(self.args)
            self.assertTrue(self.base.exists())
            self.collect.assert_not_called()

    def test_late_report_failure_fails_after_cleanup_without_false_retention(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory))
            original = cli.native_report.ReportJournal.finish
            calls = []
            def finish(journal, state):
                calls.append(state['status'])
                if len(calls) == 1:
                    raise OSError('late final report failed')
                return original(journal, state)
            stack.enter_context(mock.patch.object(cli.native_report.ReportJournal, 'finish', new=finish))
            with self.assertRaisesRegex(OSError, 'late final report failed'):
                cli.native_delete(self.args)
            state, _, _ = self.read()
            self.assertEqual(state['status'], 'failed')
            self.assertFalse(state['passed'])
            self.assertTrue(state['cleanup_passed'])
            self.assertNotIn('retained_fixture', state)
            self.assertFalse(self.base.exists())

    def test_route_rejects_old_release_and_invalid_selections_without_target_calls(self):
        for extra in (['--baseline', '/old'], ['--samples', '9'], ['--cache', 'warm', 'warm']):
            with self.subTest(extra=extra), mock.patch.object(sys, 'argv', [
                    'cli.py', '--native-delete', '--candidate', '/candidate', '--scratch', '/unused',
                    '--output', '/unused/report', *extra]), mock.patch.object(cli, 'native_delete') as target, \
                    redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                cli.main()
            self.assertEqual(error.exception.code, 2)
            target.assert_not_called()

    def test_native_route_preserves_campaign_budget_and_separates_resource_count(self):
        deadline = 'STALLIONFS_BENCHMARK_DEADLINE'
        argv = ['cli.py', '--native-delete', '--candidate', '/candidate', '--scratch', '/unused',
                '--output', '/unused/report', '--samples', '12', '--cache', 'cold', 'warm']
        with mock.patch.object(sys, 'argv', argv), mock.patch.dict(os.environ, {deadline: '12345'}), \
                mock.patch.object(cli, 'native_delete', return_value=0) as target:
            self.assertEqual(cli.main(), 0)
            self.assertEqual(os.environ[deadline], '12345')
            args = target.call_args.args[0]
            self.assertEqual(args.samples, 12)
            self.assertEqual(args.cache, ['cold', 'warm'])
            self.assertIsNone(args.baseline)

    def test_ownership_mount_and_cleanup_errors_stop_without_success_claims(self):
        for failure in ('owner', 'mount', 'post-mount', 'cleanup'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                if failure == 'cleanup':
                    stack.enter_context(mock.patch.object(cli, 'remove_fixture', side_effect=OSError('cleanup failed')))
                elif failure == 'mount':
                    self.mounts.side_effect = RuntimeError('mounted fixture')
                else:
                    original = self.condition.side_effect
                    def condition(mode, timeout):
                        result = original(mode, timeout)
                        if failure == 'owner':
                            self.base.chmod(0o755)
                        else:
                            self.mounts.side_effect = RuntimeError('mounted fixture')
                        return result
                    self.condition.side_effect = condition
                with self.assertRaises((RuntimeError, OSError)):
                    cli.native_delete(self.args)
                self.retained()
                if failure == 'post-mount':
                    self.assertEqual(self.collect.call_count, 1)
                elif failure != 'cleanup':
                    self.collect.assert_not_called()
