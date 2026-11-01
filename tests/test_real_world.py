"""Checks that incorrect or incomplete work cannot become a benchmark win."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    'real_world_benchmark', Path(__file__).parent / 'perf' / 'real_world.py')
BENCHMARK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCHMARK)


class OwnedProcessSupervision(unittest.TestCase):
    """All PIDs, waits, clocks and signals in these lifecycle checks are mocked."""

    @contextlib.contextmanager
    def child(self, *, probe='absent', initially_exited=True, exits_on_signal=signal.SIGKILL,
              exits_on_observation=None, observe_errors=None, reap_error=None, signal_errors=None):
        child = SimpleNamespace(pid=424242, returncode=None)
        usage = SimpleNamespace(ru_utime=.1, ru_stime=.2, ru_maxrss=1024)
        events, signals = [], []
        state = {'reaped': False, 'observations': 0, 'exited': initially_exited, 'now': 0., 'sleeps': 0}

        def waitid(kind, pid, flags):
            self.assertEqual((kind, pid), (os.P_PID, child.pid))
            self.assertEqual(flags, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            self.assertFalse(state['reaped'], 'waitid must never inspect a reused PID')
            events.append('observe')
            state['observations'] += 1
            error = (observe_errors or {}).get(state['observations'])
            if error:
                raise error
            if state['observations'] == exits_on_observation:
                state['exited'] = True
            return SimpleNamespace(si_pid=child.pid) if state['exited'] else None

        def wait4(pid, flags):
            self.assertEqual((pid, flags), (child.pid, 0))
            self.assertTrue(state['exited'], 'a live child must never enter blocking wait4')
            events.append('reap')
            state['reaped'] = True
            if reap_error:
                raise reap_error
            return pid, 0, usage

        def killpg(pid, number):
            self.assertEqual(pid, child.pid)
            signals.append(number)
            events.append(f'signal:{number}')
            if number:
                self.assertFalse(state['reaped'], 'destructive signal targeted a reused PID')
                error = (signal_errors or {}).get(number)
                if error:
                    raise error
                if number == exits_on_signal:
                    state['exited'] = True
            else:
                self.assertTrue(state['reaped'])
                if probe == 'absent':
                    raise ProcessLookupError()
                if isinstance(probe, BaseException):
                    raise probe

        def sleep(duration):
            self.assertGreaterEqual(duration, 0)
            self.assertLessEqual(duration, .01)
            state['sleeps'] += 1
            self.assertLess(state['sleeps'], 1000, 'supervision exceeded its bounded observation window')
            state['now'] += duration

        with mock.patch.object(BENCHMARK.os, 'waitid', side_effect=waitid), \
                mock.patch.object(BENCHMARK.os, 'wait4', side_effect=wait4) as reaper, \
                mock.patch.object(BENCHMARK.os, 'killpg', side_effect=killpg), \
                mock.patch.object(BENCHMARK.time, 'monotonic', side_effect=lambda: state['now']), \
                mock.patch.object(BENCHMARK.time, 'sleep', side_effect=sleep):
            yield child, usage, events, signals, reaper, state

    def test_exit_observation_clock_precedes_reap(self):
        with self.child() as (child, expected_usage, events, signals, reaper, state):
            def exit_clock():
                events.append('exit_clock')
                return 123.5
            usage, ended, receipt = BENCHMARK.wait_owned_process(child, 5, exit_clock=exit_clock)
            self.assertIs(usage, expected_usage)
            self.assertEqual(ended, 123.5)
            self.assertEqual(events, ['observe', 'exit_clock', 'reap', 'signal:0'])
            self.assertEqual(signals, [0])
            self.assertEqual(receipt['post_reap_group_probe']['outcome'], 'absent_at_check')
            self.assertEqual(receipt['signals'], [])
            self.assertTrue(receipt['child_reaped'])
            self.assertEqual(child.returncode, 0)

    def test_reused_group_or_probe_error_never_causes_a_destructive_signal(self):
        for probe in ('present', PermissionError(1, 'probe denied')):
            with self.subTest(probe=probe), self.child(probe=probe) as data:
                child, _, events, signals, reaper, state = data
                with self.assertRaises(RuntimeError) as caught:
                    BENCHMARK.wait_owned_process(child, 5)
                self.assertTrue(caught.exception.process_group_uncertain)
                receipt = caught.exception.process_supervision
                self.assertEqual(signals, [0])
                self.assertEqual(receipt['post_reap_group_probe']['outcome'],
                                 'present' if probe == 'present' else 'error')
                self.assertEqual(receipt['signals'], [{'signal': int(signal.SIGKILL),
                    'reason': 'post_reap_group_uncertain', 'attempted': False,
                    'outcome': 'skipped_pid_reuse_possible'}])
                reaper.assert_called_once()

    def test_timeout_records_term_and_kill_before_reap(self):
        with self.child(initially_exited=False) as (child, _, events, signals, reaper, state):
            _, _, receipt = BENCHMARK.wait_owned_process(child, 0, graceful=True)
            self.assertEqual(signals, [signal.SIGTERM, signal.SIGKILL, 0])
            self.assertTrue(receipt['timed_out'])
            self.assertEqual([r['reason'] for r in receipt['signals']], ['timeout', 'timeout_grace_expired'])
            self.assertTrue(all(r['attempted'] and r['outcome'] == 'sent' for r in receipt['signals']))
            self.assertLess(events.index(f'signal:{signal.SIGKILL}'), events.index('reap'))
            self.assertLessEqual(state['now'], 2.02)

    def test_failed_sigkill_with_live_child_returns_uncertain_without_reap(self):
        with self.child(initially_exited=False,
                        signal_errors={signal.SIGKILL: PermissionError(1, 'signal denied')}) as data:
            child, _, events, signals, reaper, state = data
            with self.assertRaises(RuntimeError) as caught:
                BENCHMARK.wait_owned_process(child, 0)
            receipt = caught.exception.process_supervision
            self.assertTrue(caught.exception.process_group_uncertain)
            self.assertFalse(state['exited'])
            self.assertEqual(state['now'], 0)
            self.assertEqual(signals, [signal.SIGKILL])
            self.assertEqual(receipt['signals'][0]['outcome'], 'error')
            self.assertTrue(receipt['signals'][0]['attempted'])
            self.assertEqual(receipt['signals'][0]['errno'], 1)
            reaper.assert_not_called()

    def test_failed_timeout_ownership_check_returns_uncertain_without_signal_or_reap(self):
        with self.child(initially_exited=False, observe_errors={2: ChildProcessError(10, 'not our child')}) as data:
            child, _, events, signals, reaper, state = data
            with self.assertRaises(RuntimeError) as caught:
                BENCHMARK.wait_owned_process(child, 0)
            self.assertTrue(caught.exception.process_group_uncertain)
            self.assertFalse(state['exited'])
            self.assertEqual(state['now'], 0)
            self.assertEqual(signals, [])
            self.assertEqual(caught.exception.process_supervision['signals'][0]['outcome'],
                             'skipped_child_ownership_unverified')
            reaper.assert_not_called()

    def test_successful_sigkill_without_observed_exit_expires_without_reap(self):
        with self.child(initially_exited=False, exits_on_signal=None) as data:
            child, _, events, signals, reaper, state = data
            with self.assertRaisesRegex(RuntimeError, 'termination grace') as caught:
                BENCHMARK.wait_owned_process(child, .25)
            self.assertTrue(caught.exception.process_group_uncertain)
            self.assertFalse(state['exited'])
            self.assertGreaterEqual(state['now'], 2.25)
            self.assertLessEqual(state['now'], 2.26)
            self.assertEqual(signals, [signal.SIGKILL])
            reaper.assert_not_called()

    def test_failed_escalation_after_term_does_not_reap_live_child(self):
        with self.child(initially_exited=False,
                        signal_errors={signal.SIGKILL: PermissionError(1, 'signal denied')}) as data:
            child, _, events, signals, reaper, state = data
            with self.assertRaises(RuntimeError):
                BENCHMARK.wait_owned_process(child, 0, graceful=True)
            self.assertEqual(signals, [signal.SIGTERM, signal.SIGKILL])
            self.assertFalse(state['exited'])
            self.assertLessEqual(state['now'], 2.01)
            reaper.assert_not_called()

    def test_exit_at_signal_ownership_check_skips_destructive_signal(self):
        with self.child(initially_exited=False, exits_on_observation=2) as data:
            child, _, events, signals, reaper, state = data
            _, _, receipt = BENCHMARK.wait_owned_process(child, 0)
            self.assertEqual(signals, [0])
            self.assertEqual(receipt['signals'][0]['outcome'], 'skipped_child_exited')
            self.assertFalse(receipt['signals'][0]['attempted'])

    def test_observation_exception_kills_only_before_reap(self):
        for failure in (RuntimeError('observation failed'), KeyboardInterrupt('interrupted')):
            with self.subTest(failure=type(failure).__name__), \
                    self.child(initially_exited=False, observe_errors={1: failure}) as data:
                child, _, events, signals, reaper, state = data
                with self.assertRaises(type(failure)) as caught:
                    BENCHMARK.wait_owned_process(child, 5)
                self.assertIs(caught.exception, failure)
                self.assertTrue(failure.process_group_uncertain)
                self.assertEqual(signals, [signal.SIGKILL, 0])
                self.assertEqual(failure.process_supervision['signals'][0]['reason'], 'wait_exception')
                self.assertTrue(failure.process_supervision['child_reaped'])

    def test_exception_cleanup_with_live_child_has_bounded_grace_and_preserves_error(self):
        failure = KeyboardInterrupt('initial interruption')
        with self.child(initially_exited=False, exits_on_signal=None, observe_errors={1: failure}) as data:
            child, _, events, signals, reaper, state = data
            with self.assertRaises(KeyboardInterrupt) as caught:
                BENCHMARK.wait_owned_process(child, 5)
            self.assertIs(caught.exception, failure)
            self.assertEqual(signals, [signal.SIGKILL])
            self.assertLessEqual(state['now'], 2.01)
            self.assertEqual(failure.process_supervision['cleanup_errors'][0]['phase'], 'exit_observation')
            reaper.assert_not_called()

    def test_cleanup_wait_errors_do_not_replace_the_original_exception(self):
        for phase in ('observation', 'reap'):
            failure, secondary = KeyboardInterrupt('initial interruption'), OSError('cleanup wait failed')
            errors = {1: failure, **({3: secondary} if phase == 'observation' else {})}
            with self.subTest(phase=phase), self.child(initially_exited=False, observe_errors=errors,
                    reap_error=secondary if phase == 'reap' else None) as data:
                child, _, events, signals, reaper, state = data
                with self.assertRaises(KeyboardInterrupt) as caught:
                    BENCHMARK.wait_owned_process(child, 5)
                self.assertIs(caught.exception, failure)
                self.assertTrue(failure.process_group_uncertain)
                self.assertEqual(failure.process_supervision['cleanup_errors'][0]['error'], str(secondary))
                self.assertEqual(signals, [signal.SIGKILL])

    def test_wait4_exception_after_kernel_reap_never_signals_or_reaps_again(self):
        for failure in (ChildProcessError('already reaped'), KeyboardInterrupt('after kernel reap')):
            with self.subTest(failure=type(failure).__name__), self.child(reap_error=failure) as data:
                child, _, events, signals, reaper, state = data
                with self.assertRaises(type(failure)) as caught:
                    BENCHMARK.wait_owned_process(child, 5)
                self.assertIs(caught.exception, failure)
                self.assertTrue(failure.process_group_uncertain)
                self.assertTrue(failure.process_supervision['reap_started'])
                self.assertEqual(signals, [])
                reaper.assert_called_once()

    def test_lost_child_ownership_skips_exception_signal_and_reap(self):
        failure = ChildProcessError(10, 'child unavailable')
        with self.child(initially_exited=False, observe_errors={1: failure, 2: failure}) as data:
            child, _, events, signals, reaper, state = data
            with self.assertRaises(ChildProcessError) as caught:
                BENCHMARK.wait_owned_process(child, 5)
            self.assertIs(caught.exception, failure)
            self.assertEqual(signals, [])
            reaper.assert_not_called()
            self.assertEqual(failure.process_supervision['signals'][0]['outcome'],
                             'skipped_child_ownership_unverified')


class RealWorldValidity(unittest.TestCase):
    def test_manifest_detects_same_length_content_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / 'payload'
            payload.write_bytes(b'original bytes')
            original = BENCHMARK.manifest(root)
            payload.write_bytes(b'corrupt! bytes')
            self.assertEqual(payload.stat().st_size, len(b'original bytes'))
            self.assertNotEqual(BENCHMARK.manifest(root), original)

    def test_manifest_detects_split_hardlink_with_identical_bytes_and_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload, alias = root / 'payload', root / 'alias'
            payload.write_bytes(b'unchanged contents')
            payload.chmod(0o640)
            os.link(payload, alias)
            original = BENCHMARK.manifest(root)
            alias.unlink()
            alias.write_bytes(payload.read_bytes())
            alias.chmod(0o640)
            replaced = BENCHMARK.manifest(root)
            self.assertEqual(original['entries'], replaced['entries'])
            self.assertNotEqual(original['hardlinks'], replaced['hardlinks'])
            self.assertNotEqual(original, replaced)

    def test_failed_warmup_prevents_successful_measurement_becoming_a_win(self):
        def row(variant, warmup, status, wall):
            return {'case': 'scan', 'variant': variant, 'repetition': -1 if warmup else 0,
                    'warmup': warmup, 'status': status, 'wall_s': wall,
                    'cpu_s': wall / 2, 'peak_rss_bytes': 1024}

        samples = [row('native_posix', True, 'passed', 2),
                   row('native_posix', False, 'passed', 2),
                   row('sfs_jobs1', True, 'failed', .1),
                   row('sfs_jobs1', False, 'passed', .1),
                   row('sfs_jobs2', True, 'passed', 1),
                   row('sfs_jobs2', False, 'passed', 1)]
        summary = BENCHMARK.summarize(samples)['scan']
        self.assertNotIn('sfs_jobs1', summary['variants'])
        self.assertNotIn('sfs_jobs1', summary['comparisons'])
        self.assertEqual(summary['excluded_variants']['sfs_jobs1']['statuses'],
                         {'failed': 1, 'passed': 1})
        self.assertEqual(summary['comparisons']['sfs_jobs2']['wall_s']['wins'], 1)
        self.assertEqual(summary['variants']['sfs_jobs2']['n'], 1)

    def test_zero_rss_counter_cannot_become_a_memory_win(self):
        samples = [{'case': 'scan', 'variant': variant, 'repetition': 0,
                    'warmup': False, 'status': 'passed', 'wall_s': 1, 'cpu_s': .5,
                    'peak_rss_bytes': rss} for variant, rss in [('native_posix', 1024), ('sfs_jobs1', 0)]]
        summary = BENCHMARK.summarize(samples)['scan']
        self.assertFalse(summary['variants']['sfs_jobs1']['peak_rss_bytes']['available'])
        self.assertFalse(summary['comparisons']['sfs_jobs1']['peak_rss_bytes']['available'])
        self.assertIn('baseline_over_variant_median', summary['comparisons']['sfs_jobs1']['wall_s'])

    def test_copy_comparison_policy_preserves_logical_scope_and_numeric_results(self):
        policy = {'scope': 'logical_copy_commands', 'storage_mechanism': 'uncontrolled',
                  'materialized_copy_comparison': False}
        policies = {
            'native_ditto': dict(policy, reference_qualification='clone_capable',
                reason='ditto may enter clone-related paths; materialized-copy equivalence is not controlled.'),
            'sfs_jobs1': dict(policy,
                reason='Logical-copy validation does not establish storage-mechanism equivalence.'),
        }
        self.assertEqual(BENCHMARK.copy_comparison_policy('native_ditto', 'darwin'), policies['native_ditto'])
        self.assertEqual(BENCHMARK.copy_comparison_policy('native_cp', 'linux'),
                         dict(policies['sfs_jobs1'], clone_request='disabled_by_reflink_never'))
        self.assertEqual(BENCHMARK.clone_policy('native_cp', 'linux'), 'mandatory')
        values = {'native_ditto': [(9, 9, 999), (4, 2, 100), (6, 4, 120)],
                  'sfs_jobs1': [(9, 9, 999), (2, 3, 200), (3, 5, 240)]}
        samples = [{'case': 'copy', 'variant': variant, 'repetition': index - 1,
                    'warmup': index == 0, 'status': 'passed', 'wall_s': wall,
                    'cpu_s': cpu, 'peak_rss_bytes': rss}
                   for variant, rows in values.items() for index, (wall, cpu, rss) in enumerate(rows)]
        with mock.patch.object(BENCHMARK.sys, 'platform', 'darwin'):
            unlabelled = BENCHMARK.summarize(samples, expected_repetitions=2)['copy']
            labelled = [dict(s, copy_comparison_policy=dict(policies[s['variant']])) for s in samples]
            labelled += [dict(s, variant='native_cp', status='failed',
                              copy_comparison_policy=dict(policies['sfs_jobs1'])) for s in labelled[:3]]
            summary = BENCHMARK.summarize(labelled, expected_repetitions=2)['copy']
        self.assertEqual(summary['baseline'], 'native_ditto')
        self.assertEqual(summary['comparisons'], unlabelled['comparisons'])
        expected = {'native_ditto': {'wall_s': (5, 6, 1), 'cpu_s': (3, 4, 1),
                                      'peak_rss_bytes': (110, 120, 10)},
                    'sfs_jobs1': {'wall_s': (2.5, 3, .5), 'cpu_s': (4, 5, 1),
                                  'peak_rss_bytes': (220, 240, 20)}}
        for variant, metrics in expected.items():
            self.assertEqual(summary['variants'][variant]['copy_comparison_policy'], policies[variant])
            self.assertEqual(summary['variants'][variant]['n'], 2)
            for metric, (median, p95, deviation) in metrics.items():
                self.assertEqual(summary['variants'][variant][metric],
                                 {'median': median, 'p95': p95, 'population_stdev': deviation})
        for metric, ratio, wins, losses in [('wall_s', 2, 2, 0), ('cpu_s', .75, 0, 2),
                                          ('peak_rss_bytes', .5, 0, 2)]:
            self.assertEqual(summary['comparisons']['sfs_jobs1'][metric],
                             {'baseline_over_variant_median': ratio, 'wins': wins,
                              'losses': losses, 'ties': 0, 'paired_n': 2})
        self.assertEqual(summary['excluded_variants']['native_cp'],
                         {'copy_comparison_policy': policies['sfs_jobs1'], 'statuses': {'failed': 3}})
        self.assertNotIn('native_cp', summary['variants'])
        self.assertNotIn('copy_comparison_policy', samples[0])

    def test_copy_comparison_policy_does_not_infer_missing_or_inconsistent_labels(self):
        policy = {'scope': 'logical_copy_commands', 'storage_mechanism': 'uncontrolled',
                  'materialized_copy_comparison': False}
        samples = [{'case': 'copy', 'variant': variant, 'repetition': repetition,
                    'warmup': repetition == -1, 'status': 'passed', 'wall_s': 2,
                    'cpu_s': 1, 'peak_rss_bytes': 100,
                    'copy_comparison_policy': BENCHMARK.copy_comparison_policy(variant, 'darwin')}
                   for variant in ('native_ditto', 'sfs_jobs1') for repetition in (-1, 0)]
        for missing in (True, False):
            rows = [dict(s) for s in samples]
            if missing:
                rows[0].pop('copy_comparison_policy')
            else:
                rows[0]['copy_comparison_policy'] = dict(policy, storage_mechanism='materialized')
            with self.subTest(missing=missing), mock.patch.object(BENCHMARK.sys, 'platform', 'darwin'):
                summary = BENCHMARK.summarize(rows, expected_repetitions=1)['copy']
                observed = summary['variants']['native_ditto']['copy_comparison_policy']
                self.assertEqual(observed, dict(policy, scope='unrecorded_or_inconsistent',
                    reason='Copy-comparison policy was not consistently recorded for all attempts.'))
                self.assertEqual(summary['variants']['sfs_jobs1']['copy_comparison_policy'],
                    dict(policy, reason='Logical-copy validation does not establish storage-mechanism equivalence.'))
                self.assertEqual(summary['comparisons']['sfs_jobs1']['wall_s']['baseline_over_variant_median'], 1)

    def test_fallback_or_unknown_clone_policy_cannot_become_a_mandatory_clone_win(self):
        def row(variant, repetition, policy):
            sample = {'case': 'clone', 'variant': variant, 'repetition': repetition,
                      'warmup': repetition == -1, 'status': 'passed',
                      'wall_s': 2 if variant == 'native_cp' else 1,
                      'cpu_s': .5, 'peak_rss_bytes': 1024}
            if policy is not None:
                sample['clone_policy'] = policy
            return sample

        self.assertEqual(BENCHMARK.clone_policy('native_cp', 'darwin'), 'fallback_capable')
        self.assertEqual(BENCHMARK.clone_policy('native_cp', 'linux'), 'mandatory')
        for baseline_policy, candidate_policy in [('fallback_capable', 'mandatory'),
                                                  ('unknown', 'mandatory'), (None, 'mandatory'),
                                                  ('mandatory', None)]:
            with self.subTest(baseline=baseline_policy, candidate=candidate_policy):
                samples = [row(variant, i, policy) for i in (-1, 0, 1)
                           for variant, policy in [('native_cp', baseline_policy),
                                                   ('sfs_jobs1', candidate_policy)]]
                summary = BENCHMARK.summarize(samples, expected_repetitions=2)['clone']
                self.assertEqual(summary['variants']['native_cp']['wall_s']['median'], 2)
                self.assertEqual(summary['variants']['sfs_jobs1']['wall_s']['median'], 1)
                self.assertNotIn('sfs_jobs1', summary['comparisons'])
                self.assertIn('sfs_jobs1', summary['comparison_exclusions'])
        mandatory = [row(variant, i, 'mandatory') for i in (-1, 0, 1)
                     for variant in ('native_cp', 'sfs_jobs1')]
        self.assertEqual(BENCHMARK.summarize(mandatory, expected_repetitions=2)['clone']
                         ['comparisons']['sfs_jobs1']['wall_s']['wins'], 2)
        mandatory[0]['clone_policy'] = 'fallback_capable'
        inconsistent = BENCHMARK.summarize(mandatory, expected_repetitions=2)['clone']
        self.assertFalse(inconsistent['variants']['native_cp']['mandatory_clone_comparison_eligible'])
        self.assertNotIn('sfs_jobs1', inconsistent['comparisons'])

    def test_incomplete_or_duplicate_measurements_cannot_become_wins(self):
        def row(variant, repetition):
            return {'case': 'scan', 'variant': variant, 'repetition': repetition,
                    'warmup': repetition == -1, 'status': 'passed', 'wall_s': .1,
                    'cpu_s': .05, 'peak_rss_bytes': 1024}

        complete = [row('native_posix', i) for i in (-1, 0, 1)]
        for repetitions in [(-1, 0), (-1, 0, 0)]:
            with self.subTest(repetitions=repetitions):
                samples = complete + [row('sfs_jobs1', i) for i in repetitions]
                summary = BENCHMARK.summarize(samples, expected_repetitions=2)['scan']
                self.assertEqual(summary['variants']['native_posix']['n'], 2)
                self.assertNotIn('sfs_jobs1', summary['variants'])
                self.assertNotIn('sfs_jobs1', summary['comparisons'])
                self.assertEqual(summary['excluded_variants']['sfs_jobs1']['expected_repetitions'], 2)
                self.assertEqual(summary['excluded_variants']['sfs_jobs1']['observed_repetitions'], list(repetitions[1:]))

    def test_uncertain_exception_retains_fixture_before_inspection_or_deletion(self):
        self.check_uncertain_failure(RuntimeError('injected uncertain execution'))

    def test_uncertain_interrupt_retains_fixture_before_inspection_or_deletion(self):
        self.check_uncertain_failure(KeyboardInterrupt('injected uncertain interruption'))

    def test_uncertain_return_retains_fixture_before_inspection_or_deletion(self):
        self.check_uncertain_failure(None)

    def test_swapped_scratch_directory_or_symlink_cannot_be_deleted(self):
        for replacement_kind in ('directory', 'symlink'):
            with self.subTest(replacement=replacement_kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output = root / 'result.json'
                retained = {}

                def swap_scratch(argv, scratch, **kwargs):
                    scratch = Path(scratch)
                    (scratch / 'original-marker').write_bytes(b'original owned directory')
                    original = scratch.with_name(scratch.name + '-original')
                    scratch.rename(original)
                    if replacement_kind == 'directory':
                        scratch.mkdir()
                        replacement = scratch
                    else:
                        replacement = root / 'fresh-symlink-target'
                        replacement.mkdir()
                        scratch.symlink_to(replacement, target_is_directory=True)
                    (replacement / 'replacement-marker').write_bytes(b'replacement must remain')
                    retained.update(original=original, replacement=replacement, scratch=scratch)
                    raise RuntimeError('injected setup failure after scratch swap')

                argv = ['real_world.py', '--root', str(root), '--output', str(output),
                        '--files', '2', '--directories', '1', '--repetitions', '1']
                with mock.patch.object(sys, 'argv', argv), \
                        mock.patch.object(BENCHMARK, 'execute', side_effect=swap_scratch), \
                        mock.patch.object(BENCHMARK.shutil, 'which', return_value=sys.executable), \
                        mock.patch.object(BENCHMARK.shutil, 'rmtree') as removed, \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(BENCHMARK.main(), 1)
                    removed.assert_not_called()
                report = json.loads(output.read_text())
                self.assertTrue(report['retain_scratch'])
                self.assertIn('identity changed; cleanup refused', report['cleanup'])
                self.assertEqual((retained['original'] / 'original-marker').read_bytes(), b'original owned directory')
                self.assertEqual((retained['replacement'] / 'replacement-marker').read_bytes(), b'replacement must remain')
                self.assertEqual(retained['scratch'].is_symlink(), replacement_kind == 'symlink')

    def check_uncertain_failure(self, failure):
        if failure is not None:
            failure.process_group_uncertain = True
            failure.process_supervision = {'signals': [], 'post_reap_group_probe': {'outcome': 'present'}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'result.json'
            failed, inspected_after_failure = [False], []
            original_manifest, original_sha = BENCHMARK.manifest, BENCHMARK.sha

            def checked_manifest(path):
                if failed[0]: inspected_after_failure.append(('manifest', str(path)))
                return original_manifest(path)

            def checked_sha(path):
                if failed[0]: inspected_after_failure.append(('sha', str(path)))
                return original_sha(path)

            def fake_execute(argv, scratch, **kwargs):
                if kwargs.get('measurement_helper'):
                    failed[0] = True
                    if failure is not None:
                        raise failure
                    return {'returncode': 0, 'timed_out': False, 'output_truncated': False,
                            'process_group_quiescent': False, 'stdout': '', 'stderr': ''}
                if '-o' in argv:
                    Path(argv[-1]).write_bytes(b'placeholder helper; never executed')
                return {'returncode': 0, 'timed_out': False, 'output_truncated': False,
                        'process_group_quiescent': True, 'stdout': '', 'stderr': ''}

            argv = ['real_world.py', '--root', str(root), '--output', str(output),
                    '--files', '2', '--directories', '1', '--repetitions', '1']
            with mock.patch.object(sys, 'argv', argv), \
                    mock.patch.object(BENCHMARK, 'execute', side_effect=fake_execute), \
                    mock.patch.object(BENCHMARK, 'manifest', side_effect=checked_manifest), \
                    mock.patch.object(BENCHMARK, 'sha', side_effect=checked_sha), \
                    mock.patch.object(BENCHMARK.shutil, 'which', return_value=sys.executable), \
                    mock.patch.object(BENCHMARK.shutil, 'rmtree') as removed, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(BENCHMARK.main(), 1)
                removed.assert_not_called()
            report = json.loads(output.read_text())
            self.assertTrue(failed[0])
            self.assertEqual(inspected_after_failure, [])
            self.assertFalse(report['passed'])
            self.assertTrue(report['retain_scratch'])
            self.assertIn('retained', report['cleanup'])
            self.assertEqual(report['samples'][0]['status'], 'failed')
            if failure is not None:
                self.assertTrue(any(type(failure).__name__ in error for error in report['errors']))
                self.assertEqual(report['samples'][0]['supervision'], failure.process_supervision)
            self.assertTrue((Path(report['scratch']) / 'source/d000/f000000').is_file())
            self.assertTrue((Path(report['scratch']) / 'sentinel').is_file())

    def test_uncertain_setup_stops_before_launching_a_second_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root, output = Path(directory), Path(directory) / 'result.json'
            argv = ['real_world.py', '--root', str(root), '--output', str(output),
                    '--files', '2', '--directories', '1', '--repetitions', '1']
            with mock.patch.object(sys, 'argv', argv), \
                    mock.patch.object(BENCHMARK, 'execute', return_value={'process_group_quiescent': False}) as launched, \
                    mock.patch.object(BENCHMARK.shutil, 'which', return_value=sys.executable), \
                    mock.patch.object(BENCHMARK.shutil, 'rmtree') as removed, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(BENCHMARK.main(), 1)
                launched.assert_called_once()
                removed.assert_not_called()
            self.assertTrue(json.loads(output.read_text())['retain_scratch'])

    @unittest.skipUnless(sys.platform in ('darwin', 'linux'), 'Requires wait4 resource accounting')
    def test_timeout_terminates_and_reaps_owned_child(self):
        with tempfile.TemporaryDirectory() as directory:
            result = BENCHMARK.execute(
                [sys.executable, '-c',
                 'import os,time; print(os.getpid(), flush=True); time.sleep(10)'],
                directory, timeout=.5)
            self.assertTrue(result['timed_out'])
            self.assertEqual(result['returncode'], -signal.SIGKILL)
            pid = int(result['stdout'].strip())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)


class SfsFailureRetention(unittest.TestCase):
    """Main-level control flow with simulated commands and validation results."""

    @contextlib.contextmanager
    def scenario(self, failure_kind, *, stop=True, measured=False, exception_type=OSError,
                 uncertain=False, secondary_cleanup_failure=False):
        with tempfile.TemporaryDirectory() as directory:
            root, output = Path(directory), Path(directory) / 'result.json'
            expected = {'entries': {}, 'hardlinks': [['d000/f000000', 'hardlink-alias']]}
            different = {'entries': {}, 'hardlinks': []}
            receipt = {'returncode': 0, 'timed_out': False, 'output_truncated': False,
                       'process_group_quiescent': True, 'stdout': '', 'stderr': '',
                       'wall_s': .2, 'launcher_wall_s': .3, 'cpu_s': .1,
                       'peak_rss_bytes': 1024, 'measurement_method': 'mocked_receipt'}
            supervision = {'signals': [], 'post_reap_group_probe': {'outcome': 'present'}}
            state = {'scratch': None, 'current': None, 'failed': False, 'after_failure': [],
                     'executions': [], 'attempts': {}}
            original_rmtree = shutil.rmtree

            def fail(message):
                state['failed'] = True
                error = exception_type(message)
                if uncertain:
                    error.process_group_uncertain = True
                    error.process_supervision = supervision
                raise error

            def fixture_event(operation, path):
                if (state['failed'] and state['scratch'] is not None
                        and Path(path).is_relative_to(state['scratch'])):
                    state['after_failure'].append((operation, str(path)))

            def guarded(original):
                def check(path, *args, **kwargs):
                    fixture_event(original.__name__, path)
                    if (original.__name__ == 'write_text' and Path(path) == output and should_fail()
                            and failure_kind == 'report_exception' and not state['failed']):
                        fail('injected report write interruption')
                    return original(path, *args, **kwargs)
                return check

            def remove(path, *args, **kwargs):
                fixture_event('rmtree', path)
                if Path(path).name == 'target' and should_fail() and failure_kind == 'cleanup':
                    fail('injected target cleanup failure')
                if Path(path).name == 'target' and should_fail() and secondary_cleanup_failure:
                    raise OSError('injected target cleanup failure')
                if Path(path) == state['scratch'] and failure_kind == 'final_cleanup':
                    fail('injected scratch cleanup failure')
                return original_rmtree(path, *args, **kwargs)

            def make_target(source, target, **kwargs):
                target.mkdir()
                (target / 'd000').mkdir()
                (target / 'd000/f000000').write_bytes(b'simulated destination')
                (target / 'partial-marker').write_bytes(b'retain this target')

            def should_fail():
                current = state['current']
                wanted_variant = 'native_cp' if failure_kind == 'cp_contract' else 'sfs_jobs1'
                return (current and current['case'] == 'copy'
                        and current['variant'] == wanted_variant
                        and current['attempt'] == (1 if measured else 0))

            def manifest(path):
                fixture_event('manifest', path)
                if should_fail() and Path(path).name == 'source' and failure_kind == 'source_exception':
                    fail('injected source inspection failure')
                if should_fail() and Path(path).name == 'target' and failure_kind == 'target_exception':
                    fail('injected target inspection failure')
                if should_fail() and ((Path(path).name == 'target' and failure_kind in ('integrity', 'cp_contract'))
                                      or (Path(path).name == 'source' and failure_kind == 'source_check')):
                    state['failed'] = True
                    return different
                return expected

            def sha(path):
                fixture_event('sha', path)
                if should_fail() and Path(path).name == 'sentinel' and failure_kind == 'sentinel_exception':
                    fail('injected sentinel inspection failure')
                if should_fail() and Path(path).name == 'sentinel' and failure_kind == 'sentinel_check':
                    state['failed'] = True
                    return 'changed-sentinel-sha256'
                return 'simulated-sha256'

            def execute(argv, scratch, **kwargs):
                state['scratch'] = Path(scratch)
                if not kwargs.get('measurement_helper'):
                    if '-o' in argv:
                        Path(argv[-1]).write_bytes(b'simulated helper; never executed')
                    return dict(receipt)
                command = Path(argv[0]).name
                if command == 'sfs':
                    case, variant = argv[2], 'sfs_jobs1'
                elif command == 'scan-posix':
                    case, variant = 'scan', 'native_posix'
                elif command == 'rm':
                    case, variant = 'delete', 'native_rm'
                else:
                    case = 'clone' if '-cRp' in argv or '--reflink=always' in argv else 'copy'
                    variant = 'native_ditto' if command == 'ditto' else 'native_cp'
                key = case, variant
                attempt = state['attempts'].get(key, 0)
                state['attempts'][key] = attempt + 1
                state['current'] = {'case': case, 'variant': variant, 'attempt': attempt}
                state['executions'].append(dict(state['current']))
                target = Path(scratch) / 'target'
                if case in ('copy', 'clone'):
                    make_target(None, target)
                elif case == 'delete':
                    original_rmtree(target)
                result = dict(receipt)
                if case == 'scan':
                    result['stdout'] = json.dumps({'files': 3, 'directories': 1, 'symlinks': 2,
                                                  'other': 0, 'logical_bytes': 12288, 'skipped_mounts': 0})
                if should_fail() and failure_kind == 'command_exception':
                    fail('injected command interruption')
                if should_fail() and failure_kind in ('command', 'uncertain_return',
                                                     'uncertain_exception', 'uncertain_interrupt'):
                    state['failed'] = True
                    if failure_kind == 'command':
                        result.update(returncode=1, stderr='injected command failure')
                    elif failure_kind == 'uncertain_return':
                        result['process_group_quiescent'] = False
                    else:
                        error_type = KeyboardInterrupt if failure_kind == 'uncertain_interrupt' else RuntimeError
                        error = error_type('injected uncertain completion')
                        error.process_group_uncertain = True
                        error.process_supervision = supervision
                        raise error
                return result

            argv = ['real_world.py', '--root', str(root), '--output', str(output), '--sfs', 'sfs',
                    '--jobs', '1', '--files', '2', '--directories', '1', '--repetitions', '1']
            if stop:
                argv.append('--stop-on-sfs-failure')
            with contextlib.ExitStack() as stack:
                for name in ('stat', 'lstat', 'exists', 'is_symlink', 'unlink', 'open', 'read_bytes', 'write_text'):
                    stack.enter_context(mock.patch.object(Path, name, new=guarded(getattr(Path, name))))
                stack.enter_context(mock.patch.object(sys, 'argv', argv))
                stack.enter_context(mock.patch.object(BENCHMARK, 'execute', side_effect=execute))
                stack.enter_context(mock.patch.object(BENCHMARK, 'manifest', side_effect=manifest))
                stack.enter_context(mock.patch.object(BENCHMARK, 'sha', side_effect=sha))
                stack.enter_context(mock.patch.object(BENCHMARK.shutil, 'which',
                    side_effect=lambda name: None if name == 'df' else '/simulated/bin/' + name))
                stack.enter_context(mock.patch.object(BENCHMARK.shutil, 'rmtree', side_effect=remove))
                stack.enter_context(mock.patch.object(BENCHMARK.shutil, 'copytree', side_effect=make_target))
                stack.enter_context(mock.patch.object(BENCHMARK.random.Random, 'shuffle', return_value=None))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                self.assertEqual(BENCHMARK.main(), 1)
            report = json.loads(output.read_text())
            yield report, state, receipt, supervision

    def check_retained_failure(self, failure_kind, *, measured=False, exception_type=OSError):
        with self.scenario(failure_kind, measured=measured, exception_type=exception_type) as data:
            report, state, receipt, _ = data
            self.assertTrue(state['failed'])
            self.assertEqual(state['after_failure'], [], 'fixture inspected or deleted after failure detection')
            self.assertFalse(report['passed'])
            self.assertTrue(report['retain_scratch'])
            self.assertTrue(report['parameters']['stop_on_sfs_failure'])
            self.assertEqual(report['retention_reason'], 'sfs_sample_failure')
            self.assertEqual(report['cleanup'], 'retained_failure_evidence')
            self.assertEqual(report['stopped_on_sfs_failure'], len(report['samples']) - 1)
            self.assertEqual(len(state['executions']), len(report['samples']))
            failed = report['samples'][-1]
            self.assertEqual((failed['case'], failed['variant'], failed['repetition']),
                             ('copy', 'sfs_jobs1', 0 if measured else -1))
            self.assertEqual(failed['warmup'], not measured)
            self.assertEqual(failed['status'], 'failed')
            self.assertTrue(failed['error'])
            for metric in ('wall_s', 'launcher_wall_s', 'cpu_s', 'peak_rss_bytes', 'measurement_method'):
                if failure_kind == 'command_exception':
                    self.assertNotIn(metric, failed)
                else:
                    self.assertEqual(failed[metric], receipt[metric])
            if exception_type in (KeyboardInterrupt, SystemExit):
                self.assertIn(exception_type.__name__, failed['error'])
                self.assertTrue(any(error.startswith(exception_type.__name__ + ':')
                                    for error in report['errors']))
            self.assertTrue(any(failed['error'] in error for error in report['errors']))
            self.assertEqual((state['scratch'] / 'target/partial-marker').read_bytes(), b'retain this target')
            self.assertTrue((state['scratch'] / 'source/d000/f000000').is_file())
            self.assertTrue((state['scratch'] / 'sentinel').is_file())
            self.assertNotIn('sfs_jobs1', report['summary']['copy']['variants'])
            if failure_kind == 'integrity':
                self.assertEqual(failed['manifest_difference']['expected_hardlinks'],
                                 [['d000/f000000', 'hardlink-alias']])
                self.assertEqual(failed['manifest_difference']['actual_hardlinks'], [])

    def test_command_failure_retains_warmup_and_measured_sample_before_inspection(self):
        for measured in (False, True):
            with self.subTest(measured=measured):
                self.check_retained_failure('command', measured=measured)

    def test_integrity_failure_retains_target_before_source_inspection(self):
        self.check_retained_failure('integrity')

    def test_source_check_failure_retains_target_before_cleanup(self):
        for failure_kind in ('source_check', 'source_exception', 'sentinel_check'):
            with self.subTest(failure=failure_kind):
                self.check_retained_failure(failure_kind)

    def test_cleanup_failure_retains_remaining_target_without_further_inspection(self):
        self.check_retained_failure('cleanup')

    def test_interruptions_retain_failure_evidence_and_original_exception(self):
        for failure_kind in ('command_exception', 'target_exception', 'source_exception',
                             'sentinel_exception', 'cleanup'):
            for exception_type in (KeyboardInterrupt, SystemExit):
                for measured in (False, True):
                    with self.subTest(failure=failure_kind, exception=exception_type.__name__, measured=measured):
                        self.check_retained_failure(failure_kind, measured=measured, exception_type=exception_type)

    def test_default_interruptions_mark_sample_failed_and_stop_collection(self):
        for failure_kind in ('command_exception', 'target_exception', 'source_exception',
                             'sentinel_exception', 'cleanup'):
            with self.subTest(failure=failure_kind), \
                    self.scenario(failure_kind, stop=False, exception_type=KeyboardInterrupt) as data:
                report, state, _, _ = data
                self.assertEqual(report['samples'][-1]['status'], 'failed')
                self.assertIn('KeyboardInterrupt', report['samples'][-1]['error'])
                self.assertEqual(len(state['executions']), len(report['samples']))
                self.assertNotIn('retention_reason', report)
                self.assertNotIn('stopped_on_sfs_failure', report)
                self.assertEqual(report['cleanup'], 'passed')
                self.assertFalse(state['scratch'].exists())

    def test_later_cleanup_failure_does_not_replace_original_sample_error(self):
        with self.scenario('command', stop=False, secondary_cleanup_failure=True) as data:
            report, state, _, _ = data
            failed = report['samples'][-1]
            self.assertEqual(failed['error'], 'RuntimeError: Command failed: injected command failure')
            self.assertEqual(failed['secondary_errors'], ['Target cleanup failed: OSError: injected target cleanup failure'])
            self.assertTrue(any(failed['error'] in error for error in report['errors']))
            self.assertTrue(any(failed['secondary_errors'][0] in error for error in report['errors']))
            self.assertEqual(report['cleanup'], 'passed')
            self.assertFalse(state['scratch'].exists())

    def test_final_cleanup_interruption_still_saves_report(self):
        with self.scenario('final_cleanup', exception_type=KeyboardInterrupt) as data:
            report, state, _, _ = data
            self.assertEqual(state['after_failure'], [])
            self.assertFalse(report['passed'])
            self.assertTrue(report['retain_scratch'])
            self.assertNotIn('retention_reason', report)
            self.assertNotIn('stopped_on_sfs_failure', report)
            self.assertEqual(report['cleanup'], 'failed: KeyboardInterrupt: injected scratch cleanup failure')
            self.assertTrue(state['scratch'].exists())

    def test_interruption_while_saving_sample_retains_remaining_scratch(self):
        with self.scenario('report_exception', exception_type=KeyboardInterrupt) as data:
            report, state, receipt, _ = data
            self.assertEqual(state['after_failure'], [])
            self.assertFalse(report['passed'])
            self.assertEqual(report['retention_reason'], 'sfs_sample_failure')
            self.assertEqual(report['cleanup'], 'retained_failure_evidence')
            self.assertEqual(report['stopped_on_sfs_failure'], len(report['samples']) - 1)
            failed = report['samples'][-1]
            self.assertEqual(failed['status'], 'failed')
            self.assertIn('KeyboardInterrupt', failed['error'])
            self.assertEqual(failed['wall_s'], receipt['wall_s'])
            self.assertEqual(len(state['executions']), len(report['samples']))
            self.assertTrue((state['scratch'] / 'source').is_dir())

    def test_default_does_not_stop_or_retain_after_sfs_failure(self):
        with self.scenario('command', stop=False) as (report, state, _, _):
            self.assertFalse(report['parameters']['stop_on_sfs_failure'])
            self.assertNotIn('retention_reason', report)
            self.assertNotIn('stopped_on_sfs_failure', report)
            self.assertFalse(report.get('retain_scratch', False))
            self.assertEqual(report['cleanup'], 'passed')
            self.assertFalse(state['scratch'].exists())
            self.assertTrue(any(s['case'] == 'delete' and s['variant'] == 'sfs_jobs1'
                                and s['status'] == 'passed' for s in report['samples']))
            self.assertTrue(any(s['case'] == 'copy' and s['variant'] == 'sfs_jobs1'
                                and not s['warmup'] and s['status'] == 'passed' for s in report['samples']))

    def test_native_cp_hardlink_contract_failure_continues_with_flag_enabled(self):
        with self.scenario('cp_contract') as (report, state, _, _):
            failed = [s for s in report['samples'] if s['status'] == 'failed']
            self.assertEqual(len(failed), 1)
            self.assertEqual((failed[0]['case'], failed[0]['variant']), ('copy', 'native_cp'))
            self.assertEqual(failed[0]['manifest_difference']['actual_hardlinks'], [])
            self.assertNotIn('retention_reason', report)
            self.assertNotIn('stopped_on_sfs_failure', report)
            self.assertFalse(report.get('retain_scratch', False))
            self.assertEqual(report['cleanup'], 'passed')
            self.assertFalse(state['scratch'].exists())
            self.assertTrue(any(s['case'] == 'delete' and s['status'] == 'passed' for s in report['samples']))
            copy_summary = report['summary']['copy']
            self.assertNotIn('native_cp', copy_summary['variants'])
            self.assertEqual(copy_summary['excluded_variants']['native_cp']['statuses'],
                             {'failed': 1, 'passed': 1})
            self.assertIn('sfs_jobs1', copy_summary['variants'])
            if sys.platform == 'darwin':
                self.assertIn('native_ditto', copy_summary['variants'])
                self.assertEqual(copy_summary['baseline'], 'native_ditto')
            else:
                self.assertNotIn('sfs_jobs1', copy_summary['comparisons'])

    def test_uncertain_completion_keeps_its_separate_retention_path(self):
        for failure_kind in ('uncertain_return', 'uncertain_exception', 'uncertain_interrupt'):
            for stop in (False, True):
                with self.subTest(failure=failure_kind, stop=stop), \
                        self.scenario(failure_kind, stop=stop) as (report, state, receipt, supervision):
                    self.assertEqual(state['after_failure'], [])
                    self.assertTrue(report['retain_scratch'])
                    self.assertNotIn('retention_reason', report)
                    self.assertNotIn('stopped_on_sfs_failure', report)
                    self.assertIn('process completion is uncertain', report['cleanup'])
                    self.assertEqual(len(state['executions']), len(report['samples']))
                    self.assertEqual(report['samples'][-1]['status'], 'failed')
                    self.assertTrue((state['scratch'] / 'target/partial-marker').is_file())
                    if failure_kind == 'uncertain_return':
                        self.assertFalse(report['samples'][-1]['process_group_quiescent'])
                        self.assertEqual(report['samples'][-1]['wall_s'], receipt['wall_s'])
                    else:
                        self.assertEqual(report['samples'][-1]['supervision'], supervision)
                        self.assertEqual(report['supervision_failure'], supervision)

    def test_validation_and_cleanup_uncertainty_precedes_sfs_failure_retention(self):
        for failure_kind in ('source_exception', 'sentinel_exception', 'cleanup'):
            for exception_type in (RuntimeError, KeyboardInterrupt):
                for stop in (False, True):
                    with self.subTest(failure=failure_kind, exception=exception_type.__name__, stop=stop), \
                            self.scenario(failure_kind, stop=stop, exception_type=exception_type, uncertain=True) as data:
                        report, state, receipt, supervision = data
                        self.assertEqual(state['after_failure'], [])
                        self.assertTrue(report['retain_scratch'])
                        self.assertNotIn('retention_reason', report)
                        self.assertNotIn('stopped_on_sfs_failure', report)
                        self.assertIn('process completion is uncertain', report['cleanup'])
                        self.assertEqual(report['supervision_failure'], supervision)
                        failed = report['samples'][-1]
                        self.assertEqual(failed['status'], 'failed')
                        self.assertEqual(failed['supervision'], supervision)
                        self.assertEqual(failed['wall_s'], receipt['wall_s'])
                        self.assertEqual(len(state['executions']), len(report['samples']))
                        self.assertTrue((state['scratch'] / 'target/partial-marker').is_file())


class UncertainCompletionConsumers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for name in ('real_apps', 'real_batch'):
            spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / 'perf' / (name + '.py'))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            setattr(cls, name, module)

    def failure(self, kind):
        failure = kind('injected completion uncertainty')
        failure.process_group_uncertain = True
        failure.process_supervision = {'signals': [], 'post_reap_group_probe': {'outcome': 'present'}}
        return failure

    def test_application_wrapper_uses_observation_clock_and_returns_receipt(self):
        receipt = {'timed_out': False, 'post_reap_group_probe': {'outcome': 'absent_at_check'}}
        with mock.patch.dict(sys.modules, {'real_world': BENCHMARK}), \
                mock.patch.object(BENCHMARK, 'wait_owned_process', return_value=('usage', 123, receipt)) as waited:
            self.assertEqual(self.real_apps.bounded_wait('child', 5), ('usage', 123, False, True, receipt))
            waited.assert_called_once_with('child', 5, exit_clock=self.real_apps.time.perf_counter)

    def test_application_supervisor_initialization_failure_marks_completion_uncertain(self):
        failure = RuntimeError('watchdog initialization failed')
        with mock.patch.dict(sys.modules, {'real_world': BENCHMARK}), \
                mock.patch.object(BENCHMARK, 'wait_owned_process', side_effect=failure):
            with self.assertRaises(RuntimeError) as caught:
                self.real_apps.bounded_wait('child', 5)
            self.assertIs(caught.exception, failure)
            self.assertTrue(failure.process_group_uncertain)

    def test_execute_supervisor_initialization_failure_marks_completion_uncertain(self):
        failure = RuntimeError('watchdog initialization failed')
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(BENCHMARK.subprocess, 'Popen', return_value=SimpleNamespace(pid=424242)), \
                mock.patch.object(BENCHMARK, 'wait_owned_process', side_effect=failure), \
                mock.patch.object(BENCHMARK.os, 'killpg') as signaled:
            with self.assertRaises(RuntimeError) as caught:
                BENCHMARK.execute(['mock-command'], directory)
            self.assertIs(caught.exception, failure)
            self.assertTrue(failure.process_group_uncertain)
            signaled.assert_not_called()

    def test_batch_uncertainty_stops_before_verification_or_cleanup(self):
        for kind in (None, RuntimeError, KeyboardInterrupt):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root, output = Path(directory), Path(directory) / 'result.json'
                failure = self.failure(kind) if kind else None
                argv = ['real_batch.py', '--root', str(root), '--output', str(output),
                        '--sfs', sys.executable, '--count', '2', '--repetitions', '1']
                with mock.patch.object(sys, 'argv', argv), mock.patch.object(sys, 'platform', 'darwin'), \
                        mock.patch.dict(sys.modules, {'real_world': BENCHMARK}), \
                        mock.patch.object(BENCHMARK, 'execute', side_effect=failure,
                            return_value={'process_group_quiescent': False}) as launched, \
                        mock.patch.object(self.real_batch.shutil, 'which', return_value=sys.executable), \
                        mock.patch.object(self.real_batch, 'verify') as verified, \
                        mock.patch.object(self.real_batch.shutil, 'rmtree') as removed, \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(self.real_batch.main(), 1)
                    launched.assert_called_once()
                    verified.assert_not_called()
                    removed.assert_not_called()
                report = json.loads(output.read_text())
                self.assertTrue(report['retain_scratch'])
                self.assertFalse(report['cleanup_verified'])
                self.assertTrue(Path(report['retained_scratch']).is_dir())
                if failure:
                    self.assertEqual(report['supervision_failure'], failure.process_supervision)

    def test_application_uncertainty_stops_before_receipt_read_or_cleanup(self):
        for kind in (None, RuntimeError, KeyboardInterrupt):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root, output = Path(directory), Path(directory) / 'results'
                failure = self.failure(kind) if kind else None
                usage = SimpleNamespace(ru_utime=0, ru_stime=0, ru_maxrss=0)
                supervision = {'post_reap_group_probe': {'outcome': 'present'}}
                argv = ['real_apps.py', '--root', str(root), '--output', str(output), '--smoke']
                with mock.patch.object(sys, 'argv', argv), \
                        mock.patch.object(self.real_apps, 'bounded_wait', side_effect=failure,
                            return_value=(usage, 1, False, False, supervision)) as waited, \
                        mock.patch.object(self.real_apps.shutil, 'which', return_value=sys.executable), \
                        mock.patch.object(self.real_apps.subprocess, 'run',
                            return_value=SimpleNamespace(stdout='mock compiler', returncode=0)), \
                        mock.patch.object(self.real_apps.subprocess, 'Popen',
                            return_value=SimpleNamespace(pid=424242, returncode=0)), \
                        mock.patch.object(Path, 'read_text') as inspected, \
                        mock.patch.object(self.real_apps.shutil, 'rmtree') as removed, \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(self.real_apps.main(), 1)
                    waited.assert_called_once()
                    inspected.assert_not_called()
                    removed.assert_not_called()
                report = json.loads((output / 'result.json').read_text())
                self.assertTrue(report['retain_scratch'])
                self.assertFalse(report['cleanup_verified'])
                self.assertTrue(Path(report['retained_scratch']).is_dir())
                if failure:
                    self.assertEqual(report['supervision_failure'], failure.process_supervision)
                else:
                    self.assertEqual(report['runs'][0]['supervision'], supervision)


@unittest.skipUnless(sys.platform in ('darwin', 'linux') and shutil.which('cc'),
                     'Requires a native compiler and wait4')
class NativeMeasurementValidity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.storage = tempfile.TemporaryDirectory()
        cls.root = Path(cls.storage.name)
        cls.helper = cls.root / 'measure'
        source = Path(__file__).parent / 'perf' / 'real_world_measure.c'
        subprocess.run([shutil.which('cc'), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(source), '-o', str(cls.helper)], check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.storage.cleanup()

    def execute(self, argv, **kwargs):
        return BENCHMARK.execute(argv, self.root, measurement_helper=self.helper, **kwargs)

    def test_small_command_does_not_inherit_large_python_parent_rss(self):
        retained = bytearray(b'x' * (64 * 1024 * 1024))
        self.assertEqual(retained[-1], ord('x'))
        parent_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        parent_rss *= 1 if sys.platform == 'darwin' else 1024
        result = self.execute([shutil.which('true')])
        self.assertNotIn('measurement_error', result)
        self.assertEqual(result['returncode'], 0)
        self.assertEqual(result['measurement_method'], 'native_supervisor_wait4')
        self.assertLess(result['peak_rss_bytes'], min(parent_rss / 2, 32 * 1024 * 1024))
        self.assertGreaterEqual(result['wall_s'], 0)
        self.assertGreaterEqual(result['cpu_s'], 0)
        self.assertGreaterEqual(result['launcher_wall_s'], result['wall_s'])

    def test_command_status_signal_and_output_remain_separate_from_metrics(self):
        result = self.execute(['/bin/sh', '-c', 'printf out; printf err >&2; exit 7'])
        self.assertEqual(result['returncode'], 7)
        self.assertEqual(result['launcher_returncode'], 0)
        self.assertEqual((result['stdout'], result['stderr']), ('out', 'err'))
        signaled = self.execute(['/bin/sh', '-c', 'kill -TERM $$'])
        self.assertEqual(signaled['returncode'], -signal.SIGTERM)
        self.assertEqual(signaled['launcher_returncode'], 0)

    def test_native_timeout_drains_the_owned_process_group(self):
        result = self.execute([sys.executable, '-c',
                               'import os,time; print(os.getpid(),flush=True); time.sleep(10)'], timeout=.5)
        self.assertTrue(result['timed_out'])
        self.assertTrue(result['process_group_quiescent'])
        self.assertEqual(result['returncode'], -signal.SIGTERM)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(result['stdout'].strip()), 0)


if __name__ == '__main__':
    unittest.main()
