"""Fixed CLI collection orchestration and explicit Darwin integration checks."""
from contextlib import ExitStack, redirect_stderr
import base64
import copy
import ctypes
import errno
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
        self.tracked_flags = {}
        original_lstat, original_fstat = Path.lstat, os.fstat
        def tracked_info(info):
            flags = self.tracked_flags.get((info.st_dev, info.st_ino))
            if flags is None:
                return info
            values = {name: getattr(info, name, None) for name in (
                'st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size',
                'st_mtime_ns', 'st_ctime_ns', 'st_flags')}
            return SimpleNamespace(**(values | {'st_flags': flags}))
        stack.enter_context(mock.patch.object(Path, 'lstat',
            new=lambda path, *a, **kw: tracked_info(original_lstat(path, *a, **kw))))
        stack.enter_context(mock.patch.object(cli.os, 'fstat',
            side_effect=lambda fd: tracked_info(original_fstat(fd))))
        def track(fd, flags):
            info = original_fstat(fd)
            self.assertEqual(flags, 64)
            self.tracked_flags[(info.st_dev, info.st_ino)] = flags
        self.track = stack.enter_context(mock.patch.object(cli, '_fchflags', side_effect=track))
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
            self.assertEqual(self.track.call_count, 176)
            self.assertEqual(state['fixture_policy'], cli.CLI_DELETE_FIXTURE_POLICY)
            self.assertTrue(all(row['fixture_policy'] == cli.CLI_DELETE_FIXTURE_POLICY
                                for row in rows + comparisons))
            journal = cli.native_report.ReportJournal.open_existing(self.output)
            try:
                preparations = list(journal.iter_latest('preparation'))
            finally:
                journal.close()
            for setup in preparations:
                initialization = setup['tracked_initialization']
                self.assertEqual(setup['fixture_policy'], cli.CLI_DELETE_FIXTURE_POLICY)
                self.assertEqual(initialization['policy'], cli.CLI_DELETE_FIXTURE_POLICY)
                self.assertEqual(initialization['status'], 'complete')
                self.assertTrue(initialization['descriptor_closed'])
                self.assertEqual(initialization['final_metadata'], setup['operand_metadata'])
                self.assertEqual(setup['operand_metadata']['st_flags'], 64)
            self.assertEqual(len(comparisons), 4)
            self.assertEqual({row['preparation_id'] for row in rows}, set(range(176)))
            self.assertEqual(json.loads(self.output.with_name(self.output.name + '.manifest').read_text())['event_count'], 1060)
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

    def test_tracked_initialization_errno_retains_preparation_before_conditioning(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory))
            self.track.side_effect = OSError('fchflags denied')
            with self.assertRaisesRegex(OSError, 'fchflags denied'):
                cli.native_delete(self.args)
            self.condition.assert_not_called()
            self.collect.assert_not_called()
            state, rows, comparisons = self.retained()
            self.assertEqual(rows, [])
            self.assertEqual(comparisons, [])
            self.assertTrue((self.base / 'target').exists())
            journal = cli.native_report.ReportJournal.open_existing(self.output)
            try:
                preparations = list(journal.iter_latest('preparation'))
            finally:
                journal.close()
            self.assertEqual(len(preparations), 1)
            initialization = preparations[0]['tracked_initialization']
            self.assertEqual(initialization['status'], 'failed')
            self.assertTrue(initialization['descriptor_closed'])
            self.assertIn('fchflags denied', initialization['error'])
            self.assertFalse(preparations[0]['validated'])
            self.assertNotIn('operand_metadata', preparations[0])

    def test_post_initialization_drift_cannot_rebase_the_prepared_snapshot(self):
        for field in ('st_flags', 'st_ctime_ns'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                original_init, original_lstat = cli.initialize_tracked_delete_operand, Path.lstat
                initialized = []
                def initialize(*args):
                    result = original_init(*args)
                    initialized.append(result)
                    return result
                def lstat(path, *args, **kwargs):
                    info = original_lstat(path, *args, **kwargs)
                    if initialized and path == self.base / 'target':
                        values = {name: getattr(info, name, None) for name in initialized[0]}
                        values[field] = 0 if field == 'st_flags' else values[field] + 1
                        return SimpleNamespace(**values)
                    return info
                stack.enter_context(mock.patch.object(cli, 'initialize_tracked_delete_operand', side_effect=initialize))
                stack.enter_context(mock.patch.object(Path, 'lstat', new=lstat))
                with self.assertRaisesRegex(RuntimeError, 'changed before prepared snapshot'):
                    cli.native_delete(self.args)
                self.condition.assert_not_called()
                self.collect.assert_not_called()
                self.retained()
                journal = cli.native_report.ReportJournal.open_existing(self.output)
                try:
                    setup = list(journal.iter_latest('preparation'))[0]
                finally:
                    journal.close()
                self.assertFalse(setup['validated'])
                self.assertEqual(setup['tracked_initialization']['final_metadata'], initialized[0])
                self.assertNotEqual(setup['operand_metadata'][field], initialized[0][field])
                self.assertEqual(setup['operand_metadata_stage'], 'before_content_validation')

    def test_prepared_diagnostic_snapshot_precedes_content_validation(self):
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_flags')
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory))
            original = cli.content_manifest
            snapshots = []
            target_reads = []
            def content(path):
                if path == self.base / 'target':
                    target_reads.append(True)
                    if len(target_reads) == 1:
                        info = path.lstat()
                        snapshots.append({name: getattr(info, name, None) for name in fields})
                        result = original(path)
                        path.chmod(0o600)
                        return result
                return original(path)
            stack.enter_context(mock.patch.object(cli, 'content_manifest', side_effect=content))
            with self.assertRaisesRegex(RuntimeError, 'at before_conditioning') as caught:
                cli.native_delete(self.args)
            state, rows, _ = self.retained()
            journal = cli.native_report.ReportJournal.open_existing(self.output)
            try:
                preparations = list(journal.iter_latest('preparation'))
            finally:
                journal.close()
            mismatch = caught.exception.operand_metadata_mismatch
            self.assertEqual(mismatch['expected'], snapshots[0])
            self.assertEqual(preparations[0]['operand_metadata'], snapshots[0])
            self.assertEqual(preparations[0]['operand_metadata_stage'], 'before_content_validation')
            self.assertTrue(preparations[0]['validated'])
            self.assertEqual(rows[0]['preparation_id'], mismatch['preparation_id'])
            self.assertEqual((mismatch['preparation_id'], mismatch['row_id']), (0, 0))
            self.assertEqual(mismatch['operation'], {key: rows[0][key] for key in
                             ('case_id', 'output', 'cache', 'phase', 'pair_id', 'method', 'warmup')})
            self.assertEqual(mismatch['path'], str(self.base / 'target'))
            self.assertEqual(mismatch['stage'], 'before_conditioning')
            self.assertEqual(state['operand_metadata_mismatch'], rows[0]['operand_metadata_mismatch'])
            self.assertEqual(mismatch['changed_fields'], sorted(name for name in fields
                             if mismatch['expected'][name] != mismatch['observed'][name]))
            self.assertIn('st_mode', mismatch['changed_fields'])
            self.condition.assert_not_called()
            self.collect.assert_not_called()
            self.assertTrue((self.base / 'target').exists())

    def test_every_prepared_metadata_field_drift_remains_fatal_without_diagnostic_restat(self):
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_flags')
        for field in fields:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                original_append = cli.native_report.ReportJournal.append
                original_lstat = Path.lstat
                prepared = []
                observed = []
                def append(journal, kind, index, payload):
                    if kind == 'preparation' and payload.get('validated'):
                        prepared.append(copy.deepcopy(payload['operand_metadata']))
                    return original_append(journal, kind, index, payload)
                def lstat(path, *args, **kwargs):
                    info = original_lstat(path, *args, **kwargs)
                    if prepared and path == self.base / 'target':
                        value = {name: getattr(info, name, None) for name in fields}
                        value[field] = (value[field] or 0) + (0o040 if field == 'st_mode' else 1)
                        if observed:
                            raise AssertionError('Diagnostic unexpectedly restatted operand')
                        observed.append(value)
                        return SimpleNamespace(**value)
                    return info
                stack.enter_context(mock.patch.object(cli.native_report.ReportJournal, 'append', new=append))
                stack.enter_context(mock.patch.object(Path, 'lstat', new=lstat))
                with self.assertRaises(RuntimeError) as caught:
                    cli.native_delete(self.args)
                self.condition.assert_not_called()
                self.collect.assert_not_called()
                self.assertTrue(self.base.is_dir())
                self.assertEqual(len(observed), 1)
                if field == 'st_nlink':
                    self.assertIn('independent regular file', str(caught.exception))
                else:
                    mismatch = caught.exception.operand_metadata_mismatch
                    self.assertEqual(mismatch['expected'], prepared[0])
                    self.assertEqual(prepared[0]['st_flags'], 64)
                    self.assertEqual(mismatch['observed'], observed[0])
                    self.assertEqual(mismatch['changed_fields'], [field])
                    self.assertEqual(mismatch['stage'], 'before_conditioning')
                    state, rows, _ = self.retained()
                    self.assertEqual(state['operand_metadata_mismatch'], mismatch)
                    self.assertEqual(rows[0]['operand_metadata_mismatch'], mismatch)

    def test_conditioning_and_denial_mismatches_record_the_actual_guard_stage(self):
        for denied in (False, True):
            with self.subTest(denied=denied), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory), cache=['cold'])
                original = self.condition.side_effect
                def condition(mode, timeout):
                    result = original(mode, timeout)
                    (self.base / 'target').chmod(0o600)
                    if denied:
                        result['exit_code'] = 1
                    return result
                self.condition.side_effect = condition
                with self.assertRaises(RuntimeError) as caught:
                    cli.native_delete(self.args)
                mismatch = caught.exception.operand_metadata_mismatch
                self.assertEqual(mismatch['stage'], 'denial_closeout' if denied else 'after_conditioning')
                self.assertIn('st_mode', mismatch['changed_fields'])
                self.assertEqual(self.condition.call_count, 1)
                self.collect.assert_not_called()
                state, rows, _ = self.retained()
                self.assertEqual(state['operand_metadata_mismatch'], mismatch)
                self.assertEqual(rows[0]['operand_metadata_mismatch'], mismatch)
                self.assertTrue((self.base / 'target').exists())

    def test_diagnostic_journal_failures_preserve_primary_comparison_and_secondary_error(self):
        for failure in ('append', 'checkpoint', 'finish'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                original_append = cli.native_report.ReportJournal.append
                original_checkpoint = cli.native_report.ReportJournal.checkpoint
                original_finish = cli.native_report.ReportJournal.finish
                prepared = []
                def append(journal, kind, index, payload):
                    if kind == 'preparation' and payload.get('validated'):
                        prepared.append(copy.deepcopy(payload['operand_metadata']))
                        (self.base / 'target').chmod(0o600)
                    if failure == 'append' and payload.get('operand_metadata_mismatch'):
                        raise OSError('diagnostic append failed')
                    return original_append(journal, kind, index, payload)
                def checkpoint(journal, state):
                    if failure == 'checkpoint' and state.get('operand_metadata_mismatch'):
                        raise OSError('diagnostic checkpoint failed')
                    return original_checkpoint(journal, state)
                def finish(journal, state):
                    if failure == 'finish' and state.get('operand_metadata_mismatch'):
                        raise OSError('diagnostic finish failed')
                    return original_finish(journal, state)
                stack.enter_context(mock.patch.object(cli.native_report.ReportJournal, 'append', new=append))
                stack.enter_context(mock.patch.object(cli.native_report.ReportJournal, 'checkpoint', new=checkpoint))
                stack.enter_context(mock.patch.object(cli.native_report.ReportJournal, 'finish', new=finish))
                with self.assertRaisesRegex(RuntimeError, 'at before_conditioning') as caught:
                    cli.native_delete(self.args)
                error = caught.exception
                mismatch = error.operand_metadata_mismatch
                self.assertEqual(mismatch['expected'], prepared[0])
                self.assertEqual(mismatch['stage'], 'before_conditioning')
                self.assertIn('st_mode', mismatch['changed_fields'])
                self.assertEqual(json.loads(error.__notes__[0].split(': ', 1)[1]), mismatch)
                self.assertTrue(any('diagnostic ' + failure + ' failed' in note for note in error.__notes__[1:]))
                self.condition.assert_not_called()
                self.collect.assert_not_called()
                self.assertTrue((self.base / 'target').exists())
                self.assertTrue(self.output.with_name(self.output.name + '.journal').exists())
                self.assertTrue(self.output.with_name(self.output.name + '.manifest').exists())
                self.assertFalse(self.output.exists())

    def test_pair_closure_rejects_short_duplicate_invalid_and_extra_ids(self):
        for phase, count in (('timing', 31), ('resources', 10)):
            rows = [dict(method=method, pair_id=index, phase=phase, warmup=index == 0,
                         ok=True, validated=True, fixture_policy=cli.CLI_DELETE_FIXTURE_POLICY,
                         wall_s=0.01, cpu_s=0.01, rss_bytes=4096)
                    for method in ('native', 'candidate')
                    for index in (range(32) if phase == 'timing' else range(1, count + 1))]
            self.assertTrue(cli.native_delete_comparison(rows, phase, 10))
            for change in ('short', 'duplicate', 'extra', 'invalid', 'warmup', 'historical', 'mixed-policy'):
                altered = copy.deepcopy(rows)
                if change == 'short':
                    altered = [row for row in altered if row['pair_id'] <= 10] if phase == 'timing' else altered[:-1]
                elif change == 'duplicate':
                    altered[-1]['pair_id'] = altered[-2]['pair_id']
                elif change == 'extra':
                    altered.append({**altered[-1], 'pair_id': 99})
                elif change == 'invalid':
                    altered[-1]['validated'] = False
                elif change == 'warmup':
                    altered.append({**altered[-1], 'pair_id': 0, 'warmup': True})
                elif change == 'historical':
                    altered[-1].pop('fixture_policy')
                else:
                    altered[-1]['fixture_policy'] = 'historical-untracked'
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


class TrackedOperandInitialization(unittest.TestCase):
    def boundary(self, stack, *, initial_flags=0, initial_change=None, final_change=None,
                 opened_change=None, path_final_change=None):
        self.target = Path('/owned/target')
        self.initial = dict(st_dev=10, st_ino=20, st_mode=stat.S_IFREG | 0o640,
                            st_nlink=1, st_uid=os.getuid(), st_gid=20, st_size=4096,
                            st_mtime_ns=100, st_ctime_ns=200, st_flags=initial_flags)
        self.initial.update(initial_change or {})
        self.final = self.initial | {'st_ctime_ns': 300, 'st_flags': 64}
        self.final.update(final_change or {})
        opened = self.initial | (opened_change or {})
        root = SimpleNamespace(st_dev=10, st_ino=5, st_mode=stat.S_IFDIR | 0o700,
                               st_uid=os.getuid())
        path_reads = iter((SimpleNamespace(**self.initial),
                           SimpleNamespace(**(self.final | (path_final_change or {})))))
        stack.enter_context(mock.patch.object(Path, 'lstat',
            new=lambda path: root if path == self.target.parent else next(path_reads)))
        self.open = stack.enter_context(mock.patch.object(cli.os, 'open', return_value=99))
        self.fstat = stack.enter_context(mock.patch.object(cli.os, 'fstat',
            side_effect=[SimpleNamespace(**opened), SimpleNamespace(**self.final)]))
        self.flags = stack.enter_context(mock.patch.object(cli, '_fchflags'))
        self.close = stack.enter_context(mock.patch.object(cli.os, 'close'))
        self.evidence = {}

    def initialize(self):
        return cli.initialize_tracked_delete_operand(self.target, (10, 5), (10, 7), self.evidence)

    def test_zero_or_tracked_flags_initialize_once_and_close_before_snapshot(self):
        for initial in (0, 64):
            with self.subTest(initial=initial), ExitStack() as stack:
                self.boundary(stack, initial_flags=initial)
                self.assertEqual(self.initialize(), self.final)
                self.open.assert_called_once_with(self.target,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                self.flags.assert_called_once_with(99, 64)
                self.close.assert_called_once_with(99)
                self.assertEqual(self.evidence, {'policy': cli.CLI_DELETE_FIXTURE_POLICY,
                    'status': 'complete', 'descriptor_closed': True,
                    'initial_metadata': self.initial, 'final_metadata': self.final})

    def test_other_initial_flags_and_unsafe_operands_are_rejected_before_mutation(self):
        changes = ({'st_flags': 1}, {'st_flags': 65}, {'st_uid': os.getuid() + 1},
                   {'st_mode': stat.S_IFLNK | 0o640}, {'st_nlink': 2},
                   {'st_dev': 11}, {'st_ino': 7})
        for change in changes:
            with self.subTest(change=change), ExitStack() as stack:
                self.boundary(stack, initial_change=change)
                with self.assertRaises(RuntimeError):
                    self.initialize()
                self.flags.assert_not_called()
                self.close.assert_not_called()
                self.assertEqual(self.evidence['status'], 'failed')

    def test_opened_identity_and_other_eight_fields_cannot_change(self):
        changes = {'st_dev': 11, 'st_ino': 21, 'st_mode': stat.S_IFREG | 0o600,
                   'st_nlink': 2, 'st_uid': os.getuid() + 1, 'st_gid': 21,
                   'st_size': 2048, 'st_mtime_ns': 101}
        for field, value in changes.items():
            with self.subTest(field=field), ExitStack() as stack:
                self.boundary(stack, opened_change={field: value})
                with self.assertRaises(RuntimeError):
                    self.initialize()
                self.flags.assert_not_called()
                self.close.assert_called_once_with(99)
                self.assertTrue(self.evidence['descriptor_closed'])

    def test_post_initialization_flags_and_other_eight_fields_are_checked(self):
        changes = {'st_dev': 11, 'st_ino': 21, 'st_mode': stat.S_IFREG | 0o600,
                   'st_nlink': 2, 'st_uid': os.getuid() + 1, 'st_gid': 21,
                   'st_size': 2048, 'st_mtime_ns': 101, 'st_flags': 0, 'path_identity': 21}
        for field, value in changes.items():
            with self.subTest(field=field), ExitStack() as stack:
                if field == 'path_identity':
                    self.boundary(stack, path_final_change={'st_ino': value})
                else:
                    self.boundary(stack, final_change={field: value})
                with self.assertRaises(RuntimeError):
                    self.initialize()
                self.flags.assert_called_once_with(99, 64)
                self.close.assert_called_once_with(99)
                self.assertEqual(self.evidence['status'], 'failed')

    def test_open_flag_and_close_errors_fail_without_retry_and_preserve_primary(self):
        for failure in ('open', 'fstat-before', 'flags', 'fstat-after', 'close', 'flags-and-close'):
            with self.subTest(failure=failure), ExitStack() as stack:
                self.boundary(stack)
                if failure == 'open':
                    self.open.side_effect = OSError('open denied')
                if failure == 'fstat-before':
                    self.fstat.side_effect = OSError('initial fstat failed')
                if failure == 'fstat-after':
                    self.fstat.side_effect = [SimpleNamespace(**self.initial), OSError('final fstat failed')]
                if failure in ('flags', 'flags-and-close'):
                    self.flags.side_effect = OSError('flags denied')
                if failure in ('close', 'flags-and-close'):
                    self.close.side_effect = OSError('close failed')
                with self.assertRaises(OSError) as caught:
                    self.initialize()
                self.assertEqual(self.evidence['status'], 'failed')
                self.assertEqual(self.open.call_count, 1)
                self.assertEqual(self.flags.call_count, int(failure not in ('open', 'fstat-before')))
                self.assertEqual(self.close.call_count, int(failure != 'open'))
                if failure == 'flags-and-close':
                    self.assertIn('flags denied', str(caught.exception))
                    self.assertIn('close failed', caught.exception.__notes__[0])
                    self.assertIn('close failed', self.evidence['close_error'])


class DarwinFlagBinding(unittest.TestCase):
    def test_missing_python_flag_export_fresh_load_and_initializer_still_use_literal_64(self):
        absent = object()
        previous = getattr(stat, 'UF_TRACKED', absent)
        with mock.patch.dict(stat.__dict__):
            stat.__dict__.pop('UF_TRACKED', None)
            self.assertFalse(hasattr(stat, 'UF_TRACKED'))
            with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
                spec = importlib.util.spec_from_file_location('native_cli_without_python_flag', PERF / 'cli.py')
                fresh = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(fresh)
            self.assertEqual(fresh.DARWIN_UF_TRACKED, 64)
            for initial in (0, 64):
                with self.subTest(initial=initial), ExitStack() as stack:
                    fixture = TrackedOperandInitialization()
                    fixture.boundary(stack, initial_flags=initial)
                    setter = stack.enter_context(mock.patch.object(fresh, '_fchflags'))
                    result = fresh.initialize_tracked_delete_operand(fixture.target, (10, 5), (10, 7), fixture.evidence)
                    setter.assert_called_once_with(99, 64)
                    fixture.flags.assert_not_called()
                    fixture.close.assert_called_once_with(99)
                    self.assertEqual(result, fixture.final)
                    self.assertEqual(result['st_flags'], 64)
                    self.assertEqual(fixture.evidence['final_metadata']['st_flags'], 64)
                    self.assertEqual(fixture.evidence['policy'], 'cli-delete-uf-tracked-v1')
                    self.assertEqual(fixture.evidence['status'], 'complete')
                    self.assertTrue(fixture.evidence['descriptor_closed'])
                    self.assertFalse(hasattr(stat, 'UF_TRACKED'))
        self.assertIs(getattr(stat, 'UF_TRACKED', absent), previous)

    def test_public_symbol_signature_is_cached_and_success_ignores_stale_errno(self):
        setter = mock.Mock(return_value=0)
        library = SimpleNamespace(fchflags=setter)
        with mock.patch.object(cli.sys, 'platform', 'darwin'), \
                mock.patch.object(cli, '_DARWIN_FCHFLAGS', None), \
                mock.patch.object(cli.ctypes, 'CDLL', return_value=library) as load, \
                mock.patch.object(cli.ctypes, 'get_errno', return_value=errno.EACCES) as error:
            cli._fchflags(7, 64)
            cli._fchflags(8, 64)
            load.assert_called_once_with('/usr/lib/libSystem.B.dylib', use_errno=True)
            self.assertEqual(setter.argtypes, [ctypes.c_int, ctypes.c_uint32])
            self.assertIs(setter.restype, ctypes.c_int)
            self.assertEqual((ctypes.sizeof(ctypes.c_int), ctypes.sizeof(ctypes.c_uint32)), (4, 4))
            self.assertEqual(setter.call_args_list, [mock.call(7, 64), mock.call(8, 64)])
            error.assert_not_called()

    def test_failed_symbol_resolution_is_not_cached_and_never_calls_a_setter(self):
        for failure in ('platform', 'library', 'symbol'):
            with self.subTest(failure=failure), \
                    mock.patch.object(cli.sys, 'platform', 'other' if failure == 'platform' else 'darwin'), \
                    mock.patch.object(cli, '_DARWIN_FCHFLAGS', None), \
                    mock.patch.object(cli.ctypes, 'CDLL') as load:
                if failure == 'library':
                    load.side_effect = OSError('library unavailable')
                else:
                    load.return_value = SimpleNamespace()
                with self.assertRaises((RuntimeError, OSError, AttributeError)):
                    cli._fchflags(7, 64)
                self.assertIsNone(cli._DARWIN_FCHFLAGS)
                self.assertEqual(load.call_count, int(failure != 'platform'))

    def test_minus_one_captures_exact_errno_and_other_nonzero_returns_fail(self):
        for result in (-1, 1):
            with self.subTest(result=result), \
                    mock.patch.object(cli.sys, 'platform', 'darwin'), \
                    mock.patch.object(cli, '_DARWIN_FCHFLAGS', mock.Mock(return_value=result)) as setter, \
                    mock.patch.object(cli.ctypes, 'get_errno', return_value=errno.EPERM) as error:
                with self.assertRaises(OSError if result == -1 else RuntimeError) as caught:
                    cli._fchflags(7, 64)
                setter.assert_called_once_with(7, 64)
                if result == -1:
                    self.assertEqual(caught.exception.errno, errno.EPERM)
                    error.assert_called_once_with()
                else:
                    error.assert_not_called()

    def test_real_darwin_binding_initializes_one_fresh_owned_file(self):
        self.assertEqual(sys.platform, 'darwin', 'This binding admission requires the target Mac')
        base = Path(tempfile.mkdtemp(prefix='stallionfs-cli-tracked-binding-'))
        base.chmod(0o700)
        target, source = base / 'target', base / 'tiny'
        content = bytes(range(256)) * 16
        held = None
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size',
                  'st_mtime_ns', 'st_ctime_ns', 'st_flags')
        def metadata(info):
            return {name: getattr(info, name, None) for name in fields}
        try:
            for path in (source, target):
                with path.open('xb') as stream:
                    stream.write(content)
                path.chmod(0o640)
            root, protected = base.lstat(), source.lstat()
            self.assertEqual(stat.S_IMODE(root.st_mode), 0o700)
            self.assertEqual(root.st_uid, os.getuid())
            held = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            self.assertEqual(os.read(held, len(content) + 1), content)
            self.assertEqual(os.read(held, 1), b'')
            before = metadata(os.fstat(held))
            self.assertEqual(metadata(target.lstat()), before)
            self.assertEqual(stat.S_IMODE(before['st_mode']), 0o640)
            self.assertEqual(before['st_size'], 4096)
            self.assertEqual(before['st_uid'], os.getuid())
            self.assertEqual(before['st_nlink'], 1)
            self.assertNotEqual((before['st_dev'], before['st_ino']), (protected.st_dev, protected.st_ino))
            evidence = {}
            with mock.patch.object(cli, '_DARWIN_FCHFLAGS', None), \
                    mock.patch.object(cli, '_fchflags', wraps=cli._fchflags) as call:
                final = cli.initialize_tracked_delete_operand(target,
                    (root.st_dev, root.st_ino), (protected.st_dev, protected.st_ino), evidence)
                self.assertEqual(call.call_count, 1)
                self.assertEqual(call.call_args.args[1], 64)
                self.assertNotEqual(call.call_args.args[0], held)
            self.assertEqual(final['st_flags'], 64)
            self.assertEqual({name: final[name] for name in fields[:8]},
                             {name: before[name] for name in fields[:8]})
            self.assertEqual(metadata(os.fstat(held)), final)
            self.assertEqual(metadata(target.lstat()), final)
            self.assertEqual(evidence['final_metadata'], final)
            self.assertEqual(evidence['status'], 'complete')
            self.assertTrue(evidence['descriptor_closed'])
            os.lseek(held, 0, os.SEEK_SET)
            self.assertEqual(os.read(held, len(content) + 1), content)
            self.assertEqual(os.read(held, 1), b'')
            self.assertEqual(metadata(os.fstat(held)), final)
            self.assertEqual(metadata(target.lstat()), final)
            closing, held = held, None
            os.close(closing)
            self.assertEqual((base.lstat().st_dev, base.lstat().st_ino), (root.st_dev, root.st_ino))
            self.assertEqual(set(base.iterdir()), {source, target})
            self.assertEqual(metadata(target.lstat()), final)
            self.assertEqual((source.lstat().st_dev, source.lstat().st_ino), (protected.st_dev, protected.st_ino))
            self.assertEqual(source.read_bytes(), content)
            target.unlink()
            source.unlink()
            base.rmdir()
        except BaseException as error:
            if held is not None:
                closing, held = held, None
                try:
                    os.close(closing)
                except BaseException as close_error:
                    error.add_note('Held descriptor close failed: ' + repr(close_error))
            error.add_note('Fresh tracked binding fixture retained if not already removed: ' + str(base))
            raise


class NativeClone(unittest.TestCase):
    """Real owned file transitions with modeled command measurement receipts."""
    read = NativeDelete.read
    retained = NativeDelete.retained

    def configure(self, stack, root, *, cache=None, samples=10):
        NativeDelete.configure(self, stack, root, cache=cache, samples=samples)
        self.pins_value['source'] = {}
        self.collect.side_effect = self.measure
        def inventory(argv, **kwargs):
            self.assertEqual(argv[-1], 'volumes')
            return subprocess.CompletedProcess(argv, 0, b'[]', b'')
        self.setup.side_effect = inventory
        def acl(path):
            self.events.append('acl')
            return {'text_hex': None, 'unavailable': None}
        self.acl = stack.enter_context(mock.patch.object(cli.native_correctness, '_acl', side_effect=acl))
        self.initializer = stack.enter_context(mock.patch.object(cli, 'initialize_tracked_delete_operand',
            side_effect=AssertionError('Clone must not initialize tracked flags')))

    def measure(self, argv, **kwargs):
        self.assertEqual(self.events[-1], 'condition')
        self.events.append('measure')
        source, destination = map(Path, argv[-2:])
        self.assertEqual(source, self.base / 'tiny')
        self.assertEqual(destination, self.base / 'destination')
        self.assertFalse(os.path.lexists(destination))
        self.assertEqual(source.read_bytes(), bytes(range(256)) * 16)
        self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o640)
        native = argv[0] == '/bin/cp'
        if native:
            self.assertEqual(argv, ['/bin/cp', '-cRp', str(source), str(destination)])
        else:
            self.assertEqual(argv[-3], 'clone')
        shutil.copy2(source, destination)
        stdout = json.dumps({'source': str(source), 'destination': str(destination)}).encode() if '--json' in argv else b''
        stderr = b'real 0.01\nuser 0.01\nsys 0.00\n8192 maximum resident set size\n' if kwargs['phase'] == 'resources' else b''
        return {'phase': kwargs['phase'], 'exit_code': 0, 'ok': True, 'completion_uncertain': False,
                'wall_s': 0.004 if native else 0.002, 'cpu_s': 0.002 if native else 0.001,
                'rss_bytes': 8192 if native else 4096, 'stdout_b64': base64.b64encode(stdout).decode(),
                'stderr_b64': base64.b64encode(stderr).decode()}

    def test_exact_pairs_json_references_read_only_preparation_and_derived_journal(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory), samples=12)
            self.assertEqual(cli.native_clone(self.args), 0)
            state, rows, comparisons = self.read()
            self.assertEqual(state['case_id'], 'cli/clone/tiny_4kib')
            self.assertEqual(state['fixture_policy'], cli.CLI_CLONE_FIXTURE_POLICY)
            self.assertTrue(state['cleanup_passed'])
            self.assertFalse(state['qualified'])
            self.assertFalse(self.base.exists())
            self.assertEqual(len(rows), 176)
            self.assertEqual(len(comparisons), 4)
            self.assertTrue(all(row['validated'] and row['output_verification']['mutation_isolated'] for row in rows))
            self.assertEqual(self.setup.call_count, 1)  # Inventory only; no preparation clone command.
            self.initializer.assert_not_called()
            self.track.assert_not_called()
            journal = cli.native_report.ReportJournal.open_existing(self.output)
            try:
                preparation = list(journal.iter_latest('preparation'))
            finally:
                journal.close()
            self.assertEqual(len(preparation), 176)
            self.assertTrue(all(row['kind'] == 'read_only_clone_admission' and 'argv' not in row
                                and row['validated'] for row in preparation))
            self.assertEqual({row['preparation_id'] for row in rows}, set(range(176)))
            # Two preparation versions, three measurement versions, four comparisons.
            self.assertEqual(json.loads(self.output.with_name(self.output.name + '.manifest').read_text())['event_count'],
                             176 * 5 + 4)
            for form in ('plain', 'json'):
                for phase, count in (('timing', 31), ('resources', 12)):
                    for method in ('native', 'candidate'):
                        group = [row for row in rows if (row['output'], row['phase'], row['method']) ==
                                 (form, phase, method)]
                        self.assertEqual({row['pair_id'] for row in group if not row['warmup']}, set(range(1, count + 1)))
                        self.assertEqual(sum(row['warmup'] for row in group), int(phase == 'timing'))
            self.assertTrue(all(row['reference'] == '/bin/cp -cRp' and row['paired']
                                and row['reference_output'] == 'plain' for row in comparisons))
            for i, event in enumerate(self.events):
                if event == 'condition':
                    self.assertEqual(self.events[i + 1], 'measure')

    def test_acl_text_unavailable_api_and_release_errors_fail_admission_without_measurement(self):
        for role in ('source', 'parent'):
            for value in ({'text_hex': '212361636c20310a', 'unavailable': None},
                          {'text_hex': None, 'unavailable': 'unsupported'}, OSError(errno.EIO, 'ACL release failed')):
                with self.subTest(role=role, value=value), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                    self.configure(stack, Path(directory))
                    def acl(path):
                        selected = self.base / 'tiny' if role == 'source' else self.base
                        if path == selected:
                            if isinstance(value, BaseException): raise value
                            return value
                        return {'text_hex': None, 'unavailable': None}
                    self.acl.side_effect = acl
                    with self.assertRaises((RuntimeError, OSError)):
                        cli.native_clone(self.args)
                    self.condition.assert_not_called()
                    self.collect.assert_not_called()
                    self.track.assert_not_called()
                    self.retained()

    def test_common_owner_and_parent_group_admission_does_not_normalize(self):
        for role, field in (('source', 'st_uid'), ('parent', 'st_uid'), ('source', 'st_gid')):
            with self.subTest(role=role, field=field), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                source = parent / 'tiny'
                source.write_bytes(bytes(range(256)) * 16)
                source.chmod(0o640)
                leaf, root = source.lstat(), parent.lstat()
                selected = (leaf.st_dev, leaf.st_ino) if role == 'source' else (root.st_dev, root.st_ino)
                metadata = cli._clone_metadata
                def altered(info):
                    value = metadata(info)
                    if (info.st_dev, info.st_ino) == selected:
                        value[field] += 1
                    return value
                with mock.patch.object(cli, '_clone_metadata', side_effect=altered), \
                        mock.patch.object(cli, '_fchflags') as setter, \
                        mock.patch.object(cli.native_correctness, '_acl') as acl:
                    with self.assertRaises(RuntimeError):
                        cli.clone_admission(source, parent, (leaf.st_dev, leaf.st_ino), (root.st_dev, root.st_ino))
                    setter.assert_not_called()
                    acl.assert_not_called()
                self.assertEqual(source.read_bytes(), bytes(range(256)) * 16)

    def test_acl_observation_identity_drift_is_not_rebased(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory))
            original = self.acl.side_effect
            def acl(path):
                result = original(path)
                if path.name == 'tiny':
                    path.chmod(0o600)
                return result
            self.acl.side_effect = acl
            with self.assertRaisesRegex(RuntimeError, 'changed during ACL observation'):
                cli.native_clone(self.args)
            self.collect.assert_not_called()
            self.retained()

    def test_each_source_metadata_field_changed_after_conditioning_is_rejected(self):
        for field in cli._CLONE_FIELDS:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                original_condition = self.condition.side_effect
                original_lstat = Path.lstat
                changed = False
                def condition(*args):
                    nonlocal changed
                    result = original_condition(*args)
                    changed = True
                    return result
                def lstat(path, *args, **kwargs):
                    info = original_lstat(path, *args, **kwargs)
                    if changed and path == self.base / 'tiny':
                        values = cli._clone_metadata(info)
                        values[field] = (values[field] or 0) + 1
                        return SimpleNamespace(**values)
                    return info
                self.condition.side_effect = condition
                stack.enter_context(mock.patch.object(Path, 'lstat', new=lstat))
                with self.assertRaisesRegex(RuntimeError, 'source metadata changed'):
                    cli.native_clone(self.args)
                self.collect.assert_not_called()
                self.retained()

    def test_parent_security_and_absent_destination_are_checked_after_conditioning(self):
        for change in ('parent-mode', 'destination'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                original = self.condition.side_effect
                def condition(*args):
                    result = original(*args)
                    if change == 'parent-mode':
                        self.base.chmod(0o755)
                    else:
                        (self.base / 'destination').write_bytes(b'unexpected')
                    return result
                self.condition.side_effect = condition
                with self.assertRaises(RuntimeError):
                    cli.native_clone(self.args)
                self.collect.assert_not_called()
                self.retained()

    def test_partial_output_uncertain_error_and_bad_json_remain_failed_and_retained(self):
        for failure in ('partial', 'uncertain', 'json'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                def measurement(argv, **kwargs):
                    row = self.measure(argv, **kwargs)
                    if failure == 'partial':
                        Path(argv[-1]).write_bytes(b'partial')
                        row.update(ok=False, exit_code=1)
                    elif failure == 'uncertain':
                        row.update(ok=False, completion_uncertain=True)
                    elif '--json' in argv:
                        row['stdout_b64'] = base64.b64encode(b'{}').decode()
                    return row
                self.collect.side_effect = measurement
                with self.assertRaises(RuntimeError):
                    cli.native_clone(self.args)
                self.assertTrue((self.base / 'destination').exists())
                self.retained()

    def test_postcopy_owner_mode_acl_and_independence_failures_do_not_become_valid_rows(self):
        for change in ('mode', 'owner', 'group', 'acl', 'alias', 'source', 'sentinel', 'store'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                def measurement(argv, **kwargs):
                    row = self.measure(argv, **kwargs)
                    source, destination = map(Path, argv[-2:])
                    if change == 'mode': destination.chmod(0o600)
                    elif change in ('owner', 'group'):
                        identity = (destination.stat().st_dev, destination.stat().st_ino)
                        metadata = cli._clone_metadata
                        def altered(info):
                            value = metadata(info)
                            if (info.st_dev, info.st_ino) == identity:
                                field = 'st_uid' if change == 'owner' else 'st_gid'
                                value[field] += 1
                            return value
                        stack.enter_context(mock.patch.object(cli, '_clone_metadata', side_effect=altered))
                    elif change == 'acl':
                        self.acl.side_effect = lambda p: {'text_hex': 'flagged', 'unavailable': None} if p == destination else {'text_hex': None, 'unavailable': None}
                    elif change == 'alias':
                        destination.unlink(); os.link(source, destination)
                    elif change == 'source': source.chmod(0o600)
                    elif change == 'sentinel': (self.base / 'outside-sentinel').write_bytes(b'changed')
                    else: (self.base / 'unused-store').mkdir()
                    return row
                self.collect.side_effect = measurement
                with self.assertRaises((RuntimeError, AssertionError)):
                    cli.native_clone(self.args)
                state, rows, comparisons = self.retained()
                self.assertFalse(rows[-1]['validated'])
                self.assertEqual(comparisons, [])

    def test_output_close_failure_is_not_retried_or_scored_as_success(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory))
            close = os.close
            verify = cli.verify_clone_output
            observed = []
            def fail(fd):
                close(fd)
                observed.append(fd)
                raise OSError(errno.EIO, 'observed close failure')
            def verification(*args, **kwargs):
                with mock.patch.object(cli.os, 'close', side_effect=fail):
                    return verify(*args, **kwargs)
            stack.enter_context(mock.patch.object(cli, 'verify_clone_output', side_effect=verification))
            with self.assertRaisesRegex(OSError, 'observed close failure'):
                cli.native_clone(self.args)
            self.assertEqual(len(observed), 1)
            self.retained()

    def test_positive_cold_denial_has_no_copy_or_retry_and_warm_groups_continue(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory), cache=['warm', 'cold'])
            original = self.condition.side_effect
            def condition(mode, timeout):
                result = original(mode, timeout)
                return result | {'exit_code': 1} if mode == 'cold' else result
            self.condition.side_effect = condition
            self.assertEqual(cli.native_clone(self.args), 1)
            state, rows, comparisons = self.read()
            self.assertEqual(self.collect.call_count, 168)
            self.assertEqual(sum(row['cache'] == 'cold' for row in rows), 1)
            self.assertEqual(sum(call.args[0] == 'cold' for call in self.condition.call_args_list), 1)
            self.assertTrue(state['cleanup_passed'])
            self.assertFalse(state['passed'])
            self.assertEqual(len(comparisons), 4)
            self.assertFalse(self.base.exists())
            self.assertEqual(json.loads(self.output.with_name(self.output.name + '.manifest').read_text())['event_count'],
                             168 * 5 + 4 + 8)

    def test_pair_policy_and_exact_measured_ids_are_required(self):
        good = [dict(fixture_policy=cli.CLI_CLONE_FIXTURE_POLICY, method=method, pair_id=i,
                     warmup=i == 0, phase='timing', ok=True, validated=True, wall_s=.01, cpu_s=.01)
                for method in ('native', 'candidate') for i in range(32)]
        for change in ('policy', 'missing', 'duplicate', 'invalid', 'extra'):
            rows = copy.deepcopy(good)
            if change == 'policy': rows[0]['fixture_policy'] = cli.CLI_DELETE_FIXTURE_POLICY
            elif change == 'missing': rows.pop()
            elif change == 'duplicate': rows[-1]['pair_id'] = rows[-2]['pair_id']
            elif change == 'invalid': rows[-1]['validated'] = False
            else: rows.append(dict(rows[-1], pair_id=32))
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                cli.native_clone_comparison(rows, 'timing', 10)


    def test_clone_route_rejects_baseline_mutual_routes_and_invalid_selections(self):
        fixed = ['cli.py', '--candidate', '/unused/candidate', '--scratch', '/unused', '--output', '/unused/report']
        for options in (['--native-clone', '--baseline', '/unused/old'],
                        ['--native-clone', '--native-delete'], ['--native-clone', '--samples', '9'],
                        ['--native-clone', '--samples', '101'], ['--native-clone', '--cache', 'warm', 'warm']):
            with self.subTest(options=options), mock.patch.object(sys, 'argv', fixed + options), \
                    mock.patch.object(cli, 'native_clone') as collect, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    cli.main()
                self.assertEqual(caught.exception.code, 2)
                collect.assert_not_called()

    def test_clone_route_preserves_existing_campaign_budget_and_resource_count(self):
        argv = ['cli.py', '--candidate', '/unused/candidate', '--scratch', '/unused', '--output', '/unused/report',
                '--native-clone', '--samples', '12', '--cache', 'warm', 'cold']
        def collect(args):
            self.assertEqual((args.samples, args.cache), (12, ['warm', 'cold']))
            self.assertEqual(os.environ['STALLIONFS_BENCHMARK_DEADLINE'], '12345')
            return 0
        with mock.patch.object(sys, 'argv', argv), \
                mock.patch.dict(os.environ, {'STALLIONFS_BENCHMARK_DEADLINE': '12345'}), \
                mock.patch.object(cli, 'native_clone', side_effect=collect):
            self.assertEqual(cli.main(), 0)
            self.assertEqual(os.environ['STALLIONFS_BENCHMARK_DEADLINE'], '12345')

    def test_journal_output_cleanup_and_late_finish_errors_cannot_report_collection_success(self):
        for failure in ('journal', 'output-cleanup', 'late-finish'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                append = cli.native_report.ReportJournal.append
                checkpoint = cli.native_report.ReportJournal.checkpoint
                finish = cli.native_report.ReportJournal.finish
                remove = cli.remove_fixture
                injected = OSError('clone row journal failed')
                committed = {}
                calls = {'append': 0, 'checkpoint': 0, 'finish': 0}
                def append_record(journal, kind, index, payload):
                    calls['append'] += 1
                    if failure == 'journal' and kind == 'rows' and payload.get('validated'):
                        self.assertFalse(committed, 'Validated-row append was retried')
                        committed.update(manifest=journal.manifest_path.read_bytes(),
                                         prefix=journal.journal_path.read_bytes(), calls=dict(calls),
                                         measurements=self.collect.call_count, commands=self.setup.call_count)
                        raise injected
                    return append(journal, kind, index, payload)
                def checkpoint_report(journal, state):
                    calls['checkpoint'] += 1
                    return checkpoint(journal, state)
                def finish_report(journal, state):
                    calls['finish'] += 1
                    if failure == 'late-finish' and state.get('cleanup_passed'):
                        raise OSError('clone final report failed')
                    return finish(journal, state)
                def cleanup(path):
                    if failure == 'output-cleanup' and path.name == 'destination':
                        raise OSError('clone output cleanup failed')
                    return remove(path)
                stack.enter_context(mock.patch.object(cli.native_report.ReportJournal, 'append', new=append_record))
                if failure == 'journal':
                    stack.enter_context(mock.patch.object(cli.native_report.ReportJournal, 'checkpoint', new=checkpoint_report))
                stack.enter_context(mock.patch.object(cli.native_report.ReportJournal, 'finish', new=finish_report))
                stack.enter_context(mock.patch.object(cli, 'remove_fixture', side_effect=cleanup))
                with self.assertRaises(OSError) as caught:
                    cli.native_clone(self.args)
                if failure == 'journal':
                    self.assertIs(caught.exception, injected)
                    self.assertTrue(self.base.is_dir())
                    self.assertFalse(self.output.exists())
                    self.assertFalse((self.base / 'destination').exists())
                    self.assertEqual({path.name for path in self.base.iterdir()},
                                     {'tiny', 'empty', 'nested', 'outside-sentinel'})
                    manifest = self.output.with_name(self.output.name + '.manifest')
                    journal = self.output.with_name(self.output.name + '.journal')
                    self.assertEqual(manifest.read_bytes(), committed['manifest'])
                    self.assertEqual(journal.read_bytes(), committed['prefix'])
                    self.assertEqual(len(committed['prefix']), json.loads(committed['manifest'])['committed_bytes'])
                    state, rows, comparisons = self.read()  # Verify the unchanged committed prefix read-only.
                    self.assertEqual(state['status'], 'running')
                    self.assertFalse(state['passed'])
                    self.assertFalse(state['cleanup_passed'])
                    self.assertEqual(state['fixture_root'], str(self.base))
                    self.assertEqual(len(rows), 1)
                    self.assertIs(rows[0]['validated'], False)
                    self.assertEqual(comparisons, [])
                    self.assertEqual(calls, committed['calls'])
                    self.assertEqual(self.collect.call_count, committed['measurements'])
                    self.assertEqual(self.setup.call_count, committed['commands'])
                    self.assertEqual((self.collect.call_count, self.setup.call_count), (1, 1))
                    self.assertFalse(self.output.exists())
                    self.assertTrue(self.base.is_dir())  # Collector retention precedes TemporaryDirectory teardown.
                elif failure == 'late-finish':
                    self.assertFalse(self.base.exists())
                    state, _, _ = self.read()
                    self.assertFalse(state['passed'])
                    self.assertNotIn('retained_fixture', state)
                else:
                    self.retained()


class NativeCloneParentDiagnostics(unittest.TestCase):
    """Parent namespace changes and strict precommand/security failure observations."""
    configure = NativeClone.configure
    measure = NativeClone.measure
    read = NativeClone.read
    retained = NativeClone.retained

    def test_compared_snapshots_are_frozen_before_reporting_without_a_stat(self):
        for fields in (cli._CLONE_FIELDS, cli._CLONE_PARENT_SECURITY):
            for field in fields:
                with self.subTest(fields=fields, field=field):
                    expected = dict.fromkeys(cli._CLONE_FIELDS, 100)
                    observed = dict(expected, **{field: 101})
                    with mock.patch.object(Path, 'lstat', side_effect=AssertionError('extra stat')), \
                            self.assertRaises(RuntimeError) as caught:
                        cli._clone_parent_compare(expected, observed, fields, stage='unit_comparison',
                            path=Path('/owned/parent'), diagnostic={'preparation_id': 7, 'row_id': 11},
                            message='parent mismatch')
                    error = caught.exception
                    frozen = error.clone_parent_metadata_mismatch_json
                    mismatch = json.loads(frozen)
                    self.assertEqual(mismatch['expected'], expected)
                    self.assertEqual(mismatch['observed'], observed)
                    self.assertEqual(mismatch['compared_fields'], list(fields))
                    self.assertEqual(mismatch['differing_fields'], [field])
                    self.assertEqual((mismatch['preparation_id'], mismatch['row_id']), (7, 11))
                    self.assertEqual((mismatch['stage'], mismatch['path']), ('unit_comparison', '/owned/parent'))
                    expected[field] = observed[field] = -1
                    self.assertEqual(error.clone_parent_metadata_mismatch_json, frozen)
                    self.assertEqual(json.loads(frozen)['observed'][field], 101)
                    self.assertEqual(error.__notes__, ['Clone parent metadata comparison: ' + frozen])

    def test_every_parent_precondition_field_still_rejects_with_the_compared_snapshot(self):
        for field in cli._CLONE_FIELDS:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                original_condition = self.condition.side_effect
                original_lstat = Path.lstat
                changed, observed = False, []
                def condition(*args):
                    nonlocal changed
                    result = original_condition(*args)
                    changed = True
                    return result
                def lstat(path, *args, **kwargs):
                    info = original_lstat(path, *args, **kwargs)
                    if changed and path == self.base:
                        value = cli._clone_metadata(info)
                        value[field] = (value[field] or 0) + 1
                        observed.append(value)
                        return SimpleNamespace(**value)
                    return info
                self.condition.side_effect = condition
                stack.enter_context(mock.patch.object(Path, 'lstat', new=lstat))
                with self.assertRaises(RuntimeError) as caught:
                    cli.native_clone(self.args)
                mismatch = json.loads(caught.exception.clone_parent_metadata_mismatch_json)
                security = field in cli._CLONE_PARENT_SECURITY
                self.assertEqual(mismatch['stage'], 'after_conditioning_security' if security else 'after_conditioning')
                self.assertEqual(mismatch['compared_fields'], list(cli._CLONE_PARENT_SECURITY if security else cli._CLONE_FIELDS))
                self.assertEqual(mismatch['differing_fields'], [field])
                self.assertEqual(mismatch['observed'], observed[-1])
                self.assertEqual(len(observed), 1 if security else 2)
                self.assertEqual((mismatch['preparation_id'], mismatch['row_id']), (0, 0))
                self.assertEqual(mismatch['path'], str(self.base))
                self.collect.assert_not_called()
                state, rows, _ = self.retained()
                self.assertEqual(state['clone_parent_metadata_mismatch'], mismatch)
                self.assertEqual(rows[0]['clone_parent_metadata_mismatch'], mismatch)

    def test_every_output_parent_security_field_still_rejects_before_acl_or_extra_reads(self):
        for field in cli._CLONE_PARENT_SECURITY:
            with self.subTest(field=field):
                parent, source, destination = Path('/owned'), Path('/owned/tiny'), Path('/owned/destination')
                source_metadata = dict.fromkeys(cli._CLONE_FIELDS, 100)
                parent_metadata = dict.fromkeys(cli._CLONE_FIELDS, 200)
                observed = dict(parent_metadata, **{field: 201})
                reads = []
                def lstat(path):
                    reads.append(path)
                    self.assertIn(path, (source, parent))
                    return SimpleNamespace(**(source_metadata if path == source else observed))
                with mock.patch.object(cli, 'verify_clone') as verify, \
                        mock.patch.object(Path, 'lstat', new=lstat), \
                        mock.patch.object(cli, '_clone_absent_acl') as acl, \
                        self.assertRaises(RuntimeError) as caught:
                    cli.verify_clone_output(source, destination, {},
                        {'source': source_metadata, 'parent': parent_metadata},
                        diagnostic={'preparation_id': 3, 'row_id': 5})
                mismatch = json.loads(caught.exception.clone_parent_metadata_mismatch_json)
                self.assertEqual(mismatch['stage'], 'output_before_acl')
                self.assertEqual(mismatch['expected'], parent_metadata)
                self.assertEqual(mismatch['observed'], observed)
                self.assertEqual(mismatch['compared_fields'], list(cli._CLONE_PARENT_SECURITY))
                self.assertEqual(mismatch['differing_fields'], [field])
                self.assertEqual((mismatch['preparation_id'], mismatch['row_id']), (3, 5))
                self.assertEqual(reads, [source, parent])
                verify.assert_called_once()
                acl.assert_not_called()

    def test_permitted_namespace_count_changes_complete_without_a_fixed_increment(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, Path(directory))
            original_lstat = Path.lstat
            transitions = []
            def lstat(path, *args, **kwargs):
                info = original_lstat(path, *args, **kwargs)
                if path == getattr(self, 'base', None):
                    value = cli._clone_metadata(info)
                    # Model differing namespace accounting, without assuming a universal delta.
                    value['st_nlink'] *= 17 if os.path.lexists(self.base / 'destination') else 3
                    return SimpleNamespace(**value)
                return info
            stack.enter_context(mock.patch.object(Path, 'lstat', new=lstat))
            def measurement(*args, **kwargs):
                before = self.base.lstat().st_nlink
                result = self.measure(*args, **kwargs)
                transitions.append((before, self.base.lstat().st_nlink))
                return result
            self.collect.side_effect = measurement
            self.assertEqual(cli.native_clone(self.args), 0)
            state, rows, comparisons = self.read()
            self.assertTrue(state['source_checks_passed'] and state['cleanup_passed'])
            self.assertTrue(all(row['validated'] for row in rows))
            self.assertEqual(len(rows), len(transitions))
            self.assertTrue(all(before != after for before, after in transitions))
            self.assertTrue(all(after - before != 1 for before, after in transitions))
            self.assertEqual(len(comparisons), 4)
            self.assertFalse(self.base.exists())
            self.track.assert_not_called()
            self.initializer.assert_not_called()

    def test_unexpected_entry_type_or_identity_still_rejects_after_namespace_creation(self):
        for change in ('entry', 'type', 'identity'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                def measurement(*args, **kwargs):
                    result = self.measure(*args, **kwargs)
                    if change == 'entry':
                        (self.base / 'unexpected').write_bytes(b'not a permitted output')
                    elif change == 'type':
                        (self.base / 'empty').rmdir()
                        (self.base / 'empty').write_bytes(b'not a directory')
                    else:
                        original = self.base / 'empty'
                        replacement = self.base / 'replacement'
                        replacement.mkdir()
                        self.assertNotEqual(original.stat().st_ino, replacement.stat().st_ino)
                        original.rmdir()
                        replacement.rename(original)
                    return result
                self.collect.side_effect = measurement
                with self.assertRaises(RuntimeError):
                    cli.native_clone(self.args)
                _, rows, comparisons = self.retained()
                self.assertFalse(rows[-1]['validated'])
                self.assertEqual(comparisons, [])

    def test_secondary_journal_failure_cannot_replace_the_frozen_parent_comparison(self):
        for failure in ('append', 'checkpoint', 'finish'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, Path(directory))
                original_lstat = Path.lstat
                original_condition = self.condition.side_effect
                changed = False
                def condition(*args):
                    nonlocal changed
                    result = original_condition(*args)
                    changed = True
                    return result
                def lstat(path, *args, **kwargs):
                    info = original_lstat(path, *args, **kwargs)
                    if changed and path == self.base:
                        value = cli._clone_metadata(info)
                        value['st_nlink'] += 1
                        return SimpleNamespace(**value)
                    return info
                self.condition.side_effect = condition
                stack.enter_context(mock.patch.object(Path, 'lstat', new=lstat))
                originals = {name: getattr(cli.native_report.ReportJournal, name)
                             for name in ('append', 'checkpoint', 'finish')}
                def append(journal, kind, index, payload):
                    if failure == 'append' and payload.get('clone_parent_metadata_mismatch'):
                        payload['clone_parent_metadata_mismatch']['observed']['st_nlink'] = -1
                        raise OSError('parent diagnostic append failed')
                    return originals['append'](journal, kind, index, payload)
                def checkpoint(journal, state):
                    if failure == 'checkpoint' and state.get('clone_parent_metadata_mismatch'):
                        state['clone_parent_metadata_mismatch']['observed']['st_nlink'] = -1
                        raise OSError('parent diagnostic checkpoint failed')
                    return originals['checkpoint'](journal, state)
                def finish(journal, state):
                    if failure == 'finish' and state.get('clone_parent_metadata_mismatch'):
                        state['clone_parent_metadata_mismatch']['observed']['st_nlink'] = -1
                        raise OSError('parent diagnostic finish failed')
                    return originals['finish'](journal, state)
                for name, replacement in (('append', append), ('checkpoint', checkpoint), ('finish', finish)):
                    stack.enter_context(mock.patch.object(cli.native_report.ReportJournal, name, new=replacement))
                with self.assertRaisesRegex(RuntimeError, 'CLI clone parent metadata changed') as caught:
                    cli.native_clone(self.args)
                error = caught.exception
                frozen = error.clone_parent_metadata_mismatch_json
                mismatch = json.loads(frozen)
                self.assertEqual(mismatch['differing_fields'], ['st_nlink'])
                self.assertEqual(mismatch['observed']['st_nlink'], mismatch['expected']['st_nlink'] + 1)
                self.assertEqual(mismatch['stage'], 'after_conditioning')
                self.assertEqual((mismatch['preparation_id'], mismatch['row_id']), (0, 0))
                self.assertEqual(error.__notes__[0], 'Clone parent metadata comparison: ' + frozen)
                self.assertTrue(any('parent diagnostic ' + failure + ' failed' in note for note in error.__notes__[1:]))
                self.collect.assert_not_called()
                self.assertTrue(self.output.with_name(self.output.name + '.journal').exists())
                self.assertTrue(self.output.with_name(self.output.name + '.manifest').exists())
                self.assertFalse(self.output.exists())


class NativeCloneReal(unittest.TestCase):
    """Two real CLI commands and real unsafe-output rejection; no timing samples."""
    def fixture(self):
        self.assertEqual(sys.platform, 'darwin', 'Real clone integration requires the target Darwin host')
        root = Path(tempfile.mkdtemp(prefix='stallionfs-cli-clone-unit-'))
        try:
            roots, _ = cli.make_fixtures(root)
            expected = {name: cli.content_manifest(path) for name, path in roots.items()}
            source = roots['tiny_4kib']
            before = root.lstat()
            prepared = cli.clone_admission(source, root, (source.stat().st_dev, source.stat().st_ino),
                                           (before.st_dev, before.st_ino))
            return root, roots, expected, prepared
        except BaseException:
            print('Real clone admission fixture retained: ' + str(root), file=sys.stderr)
            raise


    def cleanup_verified(self, root, roots, expected, prepared):
        self.assertTrue(all(cli.content_manifest(path) == expected[name] for name, path in roots.items()))
        self.assertEqual((root / 'outside-sentinel').read_bytes(), b'keep outside linked trees\n')
        self.assertEqual(cli._clone_metadata(roots['tiny_4kib'].lstat()), prepared['source'])
        self.assertEqual((root.stat().st_dev, root.stat().st_ino),
                         (prepared['parent']['st_dev'], prepared['parent']['st_ino']))
        cli.remove_fixture(root)
        self.assertFalse(root.exists())

    def test_real_native_and_installed_cli_clone_preserve_common_metadata_and_independence(self):
        root, roots, expected, prepared = self.fixture()
        try:
            binary = Path(sys.executable).with_name('sfs')
            self.assertTrue(binary.is_file(), 'Run under the accepted installed artifact Python')
            source, destination = roots['tiny_4kib'], root / 'destination'
            for argv in (['/bin/cp', '-cRp', str(source), str(destination)],
                         [str(binary), '--json', 'clone', str(source), str(destination)]):
                self.assertFalse(os.path.lexists(destination))
                result = cli.command(argv, check=False, timeout=30)
                self.assertEqual((result.returncode, result.stderr), (0, b''))
                if '--json' in argv:
                    self.assertEqual(json.loads(result.stdout), {'source': str(source), 'destination': str(destination)})
                else:
                    self.assertEqual(result.stdout, b'')
                observed = cli.verify_clone_output(source, destination, expected['tiny_4kib'], prepared)
                self.assertTrue(observed['descriptor_closed'] and observed['mutation_isolated'])
                cli.remove_fixture(destination)
            self.cleanup_verified(root, roots, expected, prepared)
        except BaseException:
            print('Real clone integration fixture retained: ' + str(root), file=sys.stderr)
            raise

    def test_real_hardlinked_output_is_rejected_without_payload_mutation(self):
        root, roots, expected, prepared = self.fixture()
        try:
            source, destination = roots['tiny_4kib'], root / 'destination'
            original = source.read_bytes()
            os.link(source, destination)
            with self.assertRaises((RuntimeError, AssertionError)):
                cli.verify_clone_output(source, destination, expected['tiny_4kib'], prepared)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(destination.read_bytes(), original)
            self.assertEqual(source.stat().st_nlink, 2)
            # This negative unit fixture never enters the collector or measured case.
            self.assertEqual((root.stat().st_dev, root.stat().st_ino),
                             (prepared['parent']['st_dev'], prepared['parent']['st_ino']))
            cli.remove_fixture(root)
            self.assertFalse(root.exists())
        except BaseException:
            print('Unsafe clone output fixture retained: ' + str(root), file=sys.stderr)
            raise
