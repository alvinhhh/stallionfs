"""Collector failure receipts and paired-statistics checks, without performance runs."""
import base64
from contextlib import contextmanager, ExitStack
import importlib.util
from pathlib import Path
import signal
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('native_metrics', Path(__file__).parent / 'perf/native_metrics.py')
metrics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metrics)

REPORT = b'''command diagnostic\nreal 0.25\nuser 0.04\nsys 0.02\n 16384  maximum resident set size\n 0 block input operations\n 2 block output operations\n'''
GNU_REPORT = b'''native-time-v1 wall_s=0.25
native-time-v1 user_s=0.04
native-time-v1 system_s=0.02
native-time-v1 rss_kib=16
native-time-v1 io_input_blocks=0
native-time-v1 io_output_blocks=2
'''


def process(*, code=0, effects=None):
    child = mock.Mock(pid=54321, returncode=code)
    child.communicate.side_effect = effects or [(b'bytes\xff', REPORT)]
    return child


def rows(values, metric='wall_s'):
    return [{'pair_id': index, metric: value, 'ok': True, 'validated': True,
             'completion_uncertain': False, 'precision_floor': {metric: 0}}
            for index, value in enumerate(values)]


@contextmanager
def alarm_environment(**overrides):
    """Model signal ownership without installing handlers or starting real timers."""
    state = dict(handler=signal.SIG_DFL, timer=(0, 0), mask=set(), pending=set(), consumed=[])
    state.update(overrides)
    def handler_set(_sig, handler):
        previous, state['handler'] = state['handler'], handler
        return previous
    def timer_set(_kind, seconds, interval=0):
        previous, state['timer'] = state['timer'], (seconds, interval)
        return previous
    def mask_set(how, values):
        previous = state['mask'].copy()
        state['mask'] = previous | values if how == signal.SIG_BLOCK else set(values)
        return previous
    def consume(values):
        self_signal = next(iter(state['pending'] & values))
        state['pending'].remove(self_signal)
        state['consumed'].append(self_signal)
        return self_signal
    with ExitStack() as stack:
        for name, value in {'getsignal': lambda _sig: state['handler'], 'signal': handler_set,
                            'getitimer': lambda _kind: state['timer'], 'setitimer': timer_set,
                            'pthread_sigmask': mask_set, 'sigpending': lambda: state['pending'].copy(),
                            'sigwait': consume}.items():
            stack.enter_context(mock.patch.object(metrics.signal, name, side_effect=value))
        stack.enter_context(mock.patch.object(metrics.threading, 'active_count', return_value=1))
        yield state


def usage(user, system):
    return SimpleNamespace(ru_utime=user, ru_stime=system)


class NativeCollector(unittest.TestCase):
    def test_gnu_parser_units_missing_malformed_duplicate_and_nonfinite(self):
        parsed = metrics.parse_gnu_time(GNU_REPORT)
        self.assertEqual(parsed['rss_bytes'], 16384)
        self.assertEqual((parsed['io_input_blocks'], parsed['io_output_blocks']), (0, 2))
        self.assertEqual(parsed['parse_errors'], [])
        for invalid in (b'', b'-1', b'0', b'NaN', b'inf', b'16 KiB', b'16.0', b'1e9'):
            with self.subTest(invalid=invalid):
                result = metrics.parse_gnu_time(GNU_REPORT.replace(b'rss_kib=16', b'rss_kib=' + invalid))
                self.assertIsNone(result['rss_bytes'])
                self.assertIn('rss_bytes', result['parse_errors'])
        for invalid in (b'-1', b'NaN', b'inf', b'0.04s', b'1e9', b'9' * 400):
            with self.subTest(invalid=invalid):
                result = metrics.parse_gnu_time(GNU_REPORT.replace(b'user_s=0.04', b'user_s=' + invalid))
                self.assertIsNone(result['user_s'])
                self.assertIsNone(result['cpu_s'])
        for suffix in (b'native-time-v1 user_s=0.05\n', b'native-time-v1 user_s=NaN\n'):
            self.assertIsNone(metrics.parse_gnu_time(GNU_REPORT + suffix)['user_s'])
        self.assertIsNone(metrics.parse_gnu_time(GNU_REPORT.replace(b'native-time-v1 rss_kib=16\n', b''))['rss_bytes'])

    def test_linux_resource_wrapper_and_raw_failure_receipts(self):
        for report, valid in ((GNU_REPORT, True), (GNU_REPORT + b'native-time-v1 rss_kib=bad\n', False)):
            with self.subTest(valid=valid), mock.patch.object(metrics.sys, 'platform', 'linux'), \
                 mock.patch.object(metrics.subprocess, 'Popen', return_value=process(effects=[(b'out\xff', report)])) as popen:
                row = metrics.collect(['/bin/cp', '-a', '--reflink=never', '--', 'source', 'dest'], timeout_s=2)
                self.assertEqual(metrics.time_diagnostics(GNU_REPORT + b'cp diagnostic\n'), ['cp diagnostic'])
            self.assertEqual(row['ok'], valid)
            self.assertEqual(popen.call_args.args[0], ['/usr/bin/time', '--format=' + metrics.GNU_TIME_FORMAT,
                                                     '--', *row['argv']])
            self.assertEqual(base64.b64decode(row['stderr_b64']), report)
            self.assertEqual(base64.b64decode(row['stdout_b64']), b'out\xff')
            self.assertIn('excludes ZFS ARC', row['rss_scope'])

    def test_parse_preserves_observed_zero_and_missing_is_none(self):
        parsed = metrics.parse_time(REPORT)
        self.assertEqual(parsed['rss_bytes'], 16384)
        self.assertEqual(parsed['io_input_blocks'], 0)
        self.assertEqual(parsed['io_output_blocks'], 2)
        self.assertAlmostEqual(parsed['cpu_s'], 0.06)
        self.assertEqual(parsed['parse_errors'], [])
        malformed = metrics.parse_time(b'real nonsense\nuser NaN\nsys -1\n')
        for key in ('time_wall_s', 'user_s', 'system_s', 'cpu_s', 'rss_bytes', 'io_input_blocks', 'io_output_blocks'):
            self.assertIsNone(malformed[key])
        duplicate = metrics.parse_time(REPORT + b'user 0.03\n')
        self.assertIsNone(duplicate['user_s'])
        self.assertIsNone(duplicate['cpu_s'])

    def test_receipt_uses_exact_argv_lossless_output_and_separate_wall(self):
        child = process()
        with mock.patch.object(metrics.subprocess, 'Popen', return_value=child) as popen, \
             mock.patch.object(metrics.time, 'perf_counter', side_effect=[10, 10.5]):
            row = metrics.collect(['/bin/cp', 'name with spaces', 'dest'], timeout_s=2, env={'PATH': '/bin'})
        self.assertTrue(row['ok'])
        self.assertEqual(row['wall_s'], 0.5)
        self.assertEqual(row['time_wall_s'], 0.25)
        self.assertEqual(row['argv'], ['/bin/cp', 'name with spaces', 'dest'])
        self.assertEqual(base64.b64decode(row['stdout_b64']), b'bytes\xff')
        self.assertEqual(base64.b64decode(row['stderr_b64']), REPORT)
        self.assertEqual(row['precision_floor']['cpu_s'], 0.02)
        self.assertEqual(popen.call_args.args[0], ['/usr/bin/time', '-lp', '/bin/cp', 'name with spaces', 'dest'])
        self.assertTrue(popen.call_args.kwargs['start_new_session'])
        self.assertEqual(popen.call_args.kwargs['env'], {'PATH': '/bin', 'LC_ALL': 'C'})

    def test_nonzero_and_incomplete_reports_fail_without_discarding_receipt(self):
        for code, stderr in [(7, REPORT), (0, b'real 0.00\nuser 0.00\nsys 0.00\ntime: sysctl: denied\n')]:
            with self.subTest(code=code), mock.patch.object(metrics.subprocess, 'Popen', return_value=process(code=code, effects=[(b'', stderr)])):
                row = metrics.collect(['/usr/bin/true'], timeout_s=1)
            self.assertFalse(row['ok'])
            self.assertEqual(row['exit_code'], code)
            self.assertEqual(base64.b64decode(row['stderr_b64']), stderr)
            if code == 0: self.assertIsNone(row['rss_bytes'])

    def test_zero_rss_is_unavailable_and_keeps_raw_receipt(self):
        stderr = REPORT.replace(b'16384  maximum resident', b'0  maximum resident')
        parsed = metrics.parse_time(stderr)
        self.assertIsNone(parsed['rss_bytes'])
        self.assertEqual(parsed['parse_errors'], ['rss_bytes'])
        self.assertEqual(parsed['io_input_blocks'], 0)
        with mock.patch.object(metrics.subprocess, 'Popen', return_value=process(effects=[(b'', stderr)])):
            row = metrics.collect(['/usr/bin/true'], timeout_s=1)
        self.assertEqual(row['exit_code'], 0)
        self.assertFalse(row['ok'])
        self.assertIsNone(row['rss_bytes'])
        self.assertEqual(base64.b64decode(row['stderr_b64']), stderr)

    def test_timeout_terminates_original_group_and_keeps_uncertainty(self):
        child = process(code=-signal.SIGKILL, effects=[
            subprocess.TimeoutExpired('command', 1, output=b'partial', stderr=b'pending'),
            subprocess.TimeoutExpired('command', 1, output=b'partial', stderr=b'pending'),
            (b'partial', b'pending')])
        with mock.patch.object(metrics.subprocess, 'Popen', return_value=child), \
             mock.patch.object(metrics.os, 'killpg', side_effect=[None, None, ProcessLookupError()]) as kill:
            row = metrics.collect(['/bin/sleep', '60'], timeout_s=0.1, termination_grace_s=0.1)
        self.assertTrue(row['timed_out'])
        self.assertTrue(row['completion_uncertain'])
        self.assertFalse(row['ok'])
        self.assertEqual(kill.call_args_list, [mock.call(54321, signal.SIGTERM), mock.call(54321, signal.SIGKILL), mock.call(54321, 0)])
        self.assertEqual(base64.b64decode(row['stdout_b64']), b'partial')

    def test_reaped_leader_does_not_leave_original_group_unterminated(self):
        child = process(code=0, effects=[subprocess.TimeoutExpired('command', 1), (b'', REPORT), (b'', REPORT)])
        with mock.patch.object(metrics.subprocess, 'Popen', return_value=child), \
             mock.patch.object(metrics.os, 'killpg', side_effect=[None, None, None, ProcessLookupError()]) as kill:
            row = metrics.collect(['/usr/bin/true'], timeout_s=0.1)
        self.assertEqual(kill.call_args_list, [mock.call(54321, signal.SIGTERM), mock.call(54321, 0),
                                               mock.call(54321, signal.SIGKILL), mock.call(54321, 0)])
        self.assertTrue(row['completion_uncertain'])

    def test_unreapable_child_is_bounded_and_partial_bytes_retained(self):
        timeout = subprocess.TimeoutExpired('command', 1, output=b'x', stderr=b'y')
        child = process(code=None, effects=[timeout, timeout, timeout])
        child.wait.side_effect = subprocess.TimeoutExpired('command', 1)
        with mock.patch.object(metrics.subprocess, 'Popen', return_value=child), mock.patch.object(metrics.os, 'killpg'):
            row = metrics.collect(['/bin/sleep', '60'], timeout_s=0.1, termination_grace_s=0.1)
        self.assertTrue(row['leader_reap_timed_out'])
        self.assertTrue(row['completion_uncertain'])
        self.assertEqual(base64.b64decode(row['stdout_b64']), b'x')
        child.stdout.close.assert_called_once()
        child.stderr.close.assert_called_once()
        self.assertEqual(child.wait.call_args, mock.call(timeout=0.1))

    def test_interrupt_raises_with_uncertain_receipt(self):
        child = process(code=-signal.SIGTERM, effects=[KeyboardInterrupt(), (b'x', b'y')])
        with mock.patch.object(metrics.subprocess, 'Popen', return_value=child), \
             mock.patch.object(metrics.os, 'killpg', side_effect=[None, ProcessLookupError()]), \
             self.assertRaises(metrics.ChildCompletionUnknown) as caught:
            metrics.collect(['/bin/sleep', '60'], timeout_s=1)
        self.assertTrue(caught.exception.receipt['completion_uncertain'])
        self.assertEqual(caught.exception.receipt['interruption'], 'KeyboardInterrupt')

    def test_spawn_failure_and_bad_inputs(self):
        with mock.patch.object(metrics.subprocess, 'Popen', side_effect=OSError('missing time')):
            row = metrics.collect(['/usr/bin/true'], timeout_s=1)
        self.assertFalse(row['ok'])
        self.assertIsNone(row['wall_s'])
        self.assertIsNone(row['exit_code'])
        for arguments, timeout in [([], 1), (['bad\0name'], 1), (['ok'], 0), (['ok'], float('inf'))]:
            with self.assertRaises(ValueError): metrics.collect(arguments, timeout_s=timeout)


class DirectTiming(unittest.TestCase):
    def test_direct_blocking_communication_and_precise_cpu_exclude_harness(self):
        child = process(effects=[(b'output', b'command diagnostic')])
        with alarm_environment() as alarm, \
             mock.patch.object(metrics.subprocess, 'Popen', return_value=child) as popen, \
             mock.patch.object(metrics.resource, 'getrusage', side_effect=[usage(10, 2), usage(10.001, 2.002)]) as counters, \
             mock.patch.object(metrics.time, 'perf_counter', side_effect=[20, 20.001, 20.004]):
            row = metrics.collect(['/bin/cp', 'source', 'dest'], timeout_s=2, phase='timing')
        self.assertTrue(row['ok'])
        self.assertEqual(row['phase'], 'timing')
        self.assertIsNone(row['wrapped_argv'])
        self.assertEqual(popen.call_args.args[0], ['/bin/cp', 'source', 'dest'])
        child.communicate.assert_called_once_with()
        self.assertEqual(counters.call_args_list, [mock.call(metrics.resource.RUSAGE_CHILDREN)] * 2)
        self.assertAlmostEqual(row['wall_s'], 0.004)
        self.assertAlmostEqual(row['cpu_s'], 0.003)
        self.assertEqual(row['child_cpu_before'], {'user_s': 10, 'system_s': 2})
        self.assertEqual(row['precision_floor']['cpu_s'], 0.000004)
        self.assertEqual(row['stderr'], 'command diagnostic')
        self.assertEqual(row['parse_errors'], [])
        for key in ('rss_bytes', 'io_input_blocks', 'io_output_blocks'):
            self.assertIsNone(row[key])
        self.assertEqual((alarm['handler'], alarm['timer'], alarm['mask']), (signal.SIG_DFL, (0, 0), set()))

    def test_alarm_timeout_disarms_before_bounded_cleanup(self):
        with alarm_environment() as alarm:
            calls = []
            def communicate(**kwargs):
                calls.append(kwargs)
                if not kwargs:
                    alarm['handler'](signal.SIGALRM, None)
                self.assertEqual(alarm['timer'], (0, 0))
                return b'partial', b'diagnostic'
            child = process(code=-signal.SIGTERM)
            child.communicate.side_effect = communicate
            with mock.patch.object(metrics.subprocess, 'Popen', return_value=child), \
                 mock.patch.object(metrics.resource, 'getrusage', side_effect=[usage(1, 1), usage(1.01, 1.02)]), \
                 mock.patch.object(metrics.os, 'killpg', side_effect=[None, ProcessLookupError()]):
                row = metrics.collect(['/bin/sleep', '60'], timeout_s=1, phase='timing')
        self.assertEqual(calls, [{}, {'timeout': 1.0}])
        self.assertTrue(row['timed_out'])
        self.assertTrue(row['completion_uncertain'])
        self.assertFalse(row['ok'])
        self.assertEqual(base64.b64decode(row['stdout_b64']), b'partial')
        self.assertEqual(alarm['handler'], signal.SIG_DFL)

    def test_interrupt_keeps_receipt_and_restores_alarm(self):
        child = process(code=-signal.SIGTERM, effects=[KeyboardInterrupt(), (b'x', b'y')])
        with alarm_environment() as alarm, \
             mock.patch.object(metrics.subprocess, 'Popen', return_value=child), \
             mock.patch.object(metrics.resource, 'getrusage', return_value=usage(1, 1)), \
             mock.patch.object(metrics.os, 'killpg', side_effect=[None, ProcessLookupError()]), \
             self.assertRaises(metrics.ChildCompletionUnknown) as caught:
            metrics.collect(['/bin/sleep', '60'], timeout_s=1, phase='timing')
        self.assertTrue(caught.exception.receipt['completion_uncertain'])
        self.assertEqual(caught.exception.receipt['interruption'], 'KeyboardInterrupt')
        self.assertEqual(alarm['handler'], signal.SIG_DFL)
        self.assertEqual(alarm['timer'], (0, 0))

    def test_pending_owned_alarm_is_consumed_before_restoration(self):
        with alarm_environment() as alarm:
            child = process()
            def completed():
                alarm['pending'].add(signal.SIGALRM)
                return b'', b''
            child.communicate.side_effect = lambda **kwargs: (b'', b'') if kwargs else completed()
            with mock.patch.object(metrics.subprocess, 'Popen', return_value=child), \
                 mock.patch.object(metrics.resource, 'getrusage', return_value=usage(1, 1)), \
                 mock.patch.object(metrics.os, 'killpg', side_effect=[None, ProcessLookupError()]):
                row = metrics.collect(['/bin/true'], timeout_s=1, phase='timing')
        self.assertFalse(row['ok'])
        self.assertTrue(row['timed_out'])
        self.assertTrue(row['completion_uncertain'])
        self.assertEqual(alarm['pending'], set())
        self.assertEqual(alarm['consumed'], [signal.SIGALRM])
        self.assertEqual(alarm['handler'], signal.SIG_DFL)

    def test_foreign_signal_ownership_is_rejected_before_spawn(self):
        for overrides in ({'handler': lambda *_: None}, {'timer': (1, 0)}, {'timer': (0, 1)},
                          {'mask': {signal.SIGALRM}}, {'pending': {signal.SIGALRM}}):
            with self.subTest(overrides=overrides), alarm_environment(**overrides), \
                 mock.patch.object(metrics.subprocess, 'Popen') as popen, self.assertRaises(RuntimeError):
                metrics.collect(['/bin/true'], timeout_s=1, phase='timing')
            popen.assert_not_called()
        for name, value in [('active_count', 2), ('current_thread', object())]:
            with alarm_environment(), mock.patch.object(metrics.threading, name, return_value=value), \
                 mock.patch.object(metrics.subprocess, 'Popen') as popen, self.assertRaises(RuntimeError):
                metrics.collect(['/bin/true'], timeout_s=1, phase='timing')
            popen.assert_not_called()

    def test_spawn_failure_or_interruption_never_arms_timer(self):
        for error in (OSError('spawn failed'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), alarm_environment() as alarm, \
                 mock.patch.object(metrics.subprocess, 'Popen', side_effect=error), \
                 mock.patch.object(metrics.resource, 'getrusage', return_value=usage(1, 1)), \
                 mock.patch.object(metrics.signal, 'setitimer', wraps=metrics.signal.setitimer) as timer:
                if isinstance(error, KeyboardInterrupt):
                    with self.assertRaises(metrics.ChildCompletionUnknown) as caught:
                        metrics.collect(['/bin/true'], timeout_s=1, phase='timing')
                    row = caught.exception.receipt
                    self.assertTrue(row['completion_uncertain'])
                else:
                    row = metrics.collect(['/bin/true'], timeout_s=1, phase='timing')
            self.assertFalse(row['ok'])
            self.assertIsNone(row['wall_s'])
            self.assertEqual(timer.call_args_list, [mock.call(signal.ITIMER_REAL, 0)])
            self.assertEqual(alarm['handler'], signal.SIG_DFL)

    def test_startup_past_deadline_enters_cleanup_without_blocking_communicate(self):
        child = process(code=-signal.SIGTERM, effects=[(b'', b'')])
        with alarm_environment(), mock.patch.object(metrics.subprocess, 'Popen', return_value=child), \
             mock.patch.object(metrics.resource, 'getrusage', return_value=usage(1, 1)), \
             mock.patch.object(metrics.time, 'perf_counter', side_effect=[0, 2, 2.01]), \
             mock.patch.object(metrics.os, 'killpg', side_effect=[None, ProcessLookupError()]):
            row = metrics.collect(['/bin/true'], timeout_s=1, phase='timing')
        self.assertTrue(row['timed_out'])
        child.communicate.assert_called_once_with(timeout=1.0)

    def test_cpu_unavailable_invalid_counter_and_negative_delta_fail_closed(self):
        for values in ([usage(2, 1), usage(1, 1)], [usage(1, 1), usage(float('nan'), 1)],
                       [OSError('counter unavailable'), usage(1, 1)]):
            with self.subTest(values=values), alarm_environment(), \
                 mock.patch.object(metrics.subprocess, 'Popen', return_value=process()), \
                 mock.patch.object(metrics.resource, 'getrusage', side_effect=values):
                row = metrics.collect(['/bin/true'], timeout_s=1, phase='timing')
            self.assertFalse(row['ok'])
            self.assertTrue(row['cpu_error'])
            self.assertIsNone(row['cpu_s'])
            self.assertFalse(row['completion_uncertain'])

    def test_alarm_restore_failure_retains_receipt_and_bounds_termination(self):
        child = process(effects=[(b'x', b'y'), (b'x', b'y')])
        with alarm_environment() as alarm:
            original = metrics.signal.signal
            def failing_restore(sig, handler):
                if handler == signal.SIG_DFL:
                    raise RuntimeError('restore failed')
                return original(sig, handler)
            with mock.patch.object(metrics.signal, 'signal', side_effect=failing_restore), \
                 mock.patch.object(metrics.subprocess, 'Popen', return_value=child), \
                 mock.patch.object(metrics.resource, 'getrusage', return_value=usage(1, 1)), \
                 mock.patch.object(metrics.os, 'killpg', side_effect=[None, ProcessLookupError()]), \
                 self.assertRaises(metrics.ChildCompletionUnknown) as caught:
                metrics.collect(['/bin/true'], timeout_s=1, phase='timing')
        row = caught.exception.receipt
        self.assertTrue(row['completion_uncertain'])
        self.assertFalse(row['ok'])
        self.assertIn('restore failed', row['alarm_cleanup_error'])
        self.assertEqual(base64.b64decode(row['stdout_b64']), b'x')
        self.assertEqual(alarm['timer'], (0, 0))
        self.assertEqual(alarm['mask'], set())

    def test_unexpected_communication_failure_always_preserves_live_fixture(self):
        child = process(effects=[RuntimeError('collector failed'), (b'partial', b'error')])
        with alarm_environment(), mock.patch.object(metrics.subprocess, 'Popen', return_value=child), \
             mock.patch.object(metrics.resource, 'getrusage', return_value=usage(1, 1)), \
             mock.patch.object(metrics.os, 'killpg', side_effect=[None, ProcessLookupError()]), \
             self.assertRaises(metrics.ChildCompletionUnknown) as caught:
            metrics.collect(['/bin/true'], timeout_s=1, phase='timing')
        self.assertTrue(caught.exception.receipt['completion_uncertain'])
        self.assertEqual(base64.b64decode(caught.exception.receipt['stdout_b64']), b'partial')

    def test_signal_mask_restoration_failure_cannot_release_fixture(self):
        child = process(effects=[(b'x', b'y'), (b'x', b'y')])
        with alarm_environment():
            original = metrics.signal.pthread_sigmask
            def failing_restore(how, values):
                if how == signal.SIG_SETMASK:
                    raise RuntimeError('mask restore failed')
                return original(how, values)
            with mock.patch.object(metrics.signal, 'pthread_sigmask', side_effect=failing_restore), \
                 mock.patch.object(metrics.subprocess, 'Popen', return_value=child), \
                 mock.patch.object(metrics.resource, 'getrusage', return_value=usage(1, 1)), \
                 mock.patch.object(metrics.os, 'killpg', side_effect=[None, ProcessLookupError()]), \
                 self.assertRaises(metrics.ChildCompletionUnknown) as caught:
                metrics.collect(['/bin/true'], timeout_s=1, phase='timing')
        self.assertTrue(caught.exception.receipt['completion_uncertain'])
        self.assertIn('mask restore failed', caught.exception.receipt['error'])
        self.assertFalse(caught.exception.receipt['ok'])


class NativeStatistics(unittest.TestCase):
    def test_summary_definitions_and_fail_closed_inputs(self):
        result = metrics.summarize(range(1, 11))
        self.assertEqual(result['median'], 5.5)
        self.assertEqual(result['p95'], 10)
        self.assertAlmostEqual(result['sample_variance'], 55/6)
        for values in [range(9), [1]*9+[None], [1]*9+[float('nan')], [1]*9+[-1], [1]*9+[True]]:
            with self.assertRaises(ValueError): metrics.summarize(values)

    def test_pair_ids_match_independently_of_input_order(self):
        a = rows(range(20, 30)); b = rows(range(10, 20))
        result = metrics.compare_paired(a, list(reversed(b)), 'wall_s')
        self.assertEqual(result['decision'], 'candidate_faster')
        self.assertEqual(result['paired_sample_variance'], 0)
        self.assertEqual(result['paired_mean_savings'], 10)
        reverse = metrics.compare_paired(b, a, 'wall_s')
        self.assertEqual(reverse['decision'], 'candidate_slower')

    def test_variance_threshold_prevents_small_noisy_gap_claim(self):
        result = metrics.compare_paired(rows([10]*10), rows([0]*5+[19]*5), 'wall_s')
        self.assertEqual(result['decision'], 'inconclusive')
        self.assertGreater(result['required_gap'], result['paired_mean_savings'])
        result = metrics.compare_paired(rows([10]*10), rows([9]*10), 'wall_s', minimum_gain=1)
        self.assertEqual(result['decision'], 'inconclusive')

    def test_gain_inside_run_variability_cannot_pass_with_more_samples(self):
        native = [10, 20] * 50
        candidate = [9, 19] * 50
        result = metrics.compare_paired(rows(native), rows(candidate), 'wall_s')
        self.assertEqual(result['paired_standard_error'], 0)
        self.assertGreater(result['native_stddev'], result['paired_mean_savings'])
        self.assertEqual(result['decision'], 'inconclusive')

    def test_missing_failed_unvalidated_or_unavailable_pair_prevents_win(self):
        for change in [{'ok': False}, {'validated': False}, {'wall_s': None}, {'completion_uncertain': True}]:
            with self.subTest(change=change):
                a, b = rows([10]*11), rows([1]*11); b[-1].update(change)
                result = metrics.compare_paired(a, b, 'wall_s')
                self.assertEqual(result['complete_pairs'], 10)
                self.assertEqual(result['decision'], 'incomplete_pairs')
        self.assertEqual(metrics.compare_paired(rows([10]*10), rows([1]*9), 'wall_s')['decision'], 'insufficient_samples')
        with self.assertRaises(ValueError): metrics.compare_paired(rows([1]*10)+[rows([1])[0]], rows([1]*10), 'wall_s')

    def test_rounded_cpu_zero_and_quantization_floor_prevent_claim(self):
        a, b = rows([0.01]*10, 'cpu_s'), rows([0]*10, 'cpu_s')
        for row in a+b: row['precision_floor']['cpu_s'] = 0.02
        self.assertEqual(metrics.compare_paired(a, b, 'cpu_s')['decision'], 'below_resolution')
        a, b = rows([0.04]*10, 'cpu_s'), rows([0.03]*10, 'cpu_s')
        for row in a+b: row['precision_floor']['cpu_s'] = 0.02
        self.assertEqual(metrics.compare_paired(a, b, 'cpu_s')['decision'], 'inconclusive')

    def test_nonpositive_rss_on_either_side_prevents_claim(self):
        for side in (0, 1):
            for value in (0, -1):
                with self.subTest(side=side, value=value):
                    pair = (rows([32768]*11, 'rss_bytes'), rows([16384]*11, 'rss_bytes'))
                    pair[side][-1]['rss_bytes'] = value
                    result = metrics.compare_paired(*pair, 'rss_bytes')
                    self.assertEqual(result['complete_pairs'], 10)
                    self.assertEqual(result['decision'], 'incomplete_pairs')
                    self.assertEqual(result['excluded_pairs'], [
                        {'pair_id': 10, 'reason': 'unavailable or invalid metric'}])

    def test_timing_cpu_uses_its_own_floor_and_mixed_phases_are_rejected(self):
        a, b = rows([0.004] * 10, 'cpu_s'), rows([0.002] * 10, 'cpu_s')
        for row in a + b: row['phase'] = 'timing'
        result = metrics.compare_paired(a, b, 'cpu_s')
        self.assertEqual(result['decision'], 'candidate_lower')
        self.assertEqual(result['required_gap'], metrics.TIMING_PRECISION['cpu_s'])
        with self.assertRaises(ValueError): metrics.compare_paired(a, b, 'rss_bytes')
        b[0]['phase'] = 'resources'
        with self.assertRaises(ValueError): metrics.compare_paired(a, b, 'cpu_s')
        b[0]['phase'] = 'unknown'
        with self.assertRaises(ValueError): metrics.compare_paired(a, b, 'cpu_s')
        with self.assertRaises(ValueError): metrics.collect(['/bin/true'], timeout_s=1, phase='unknown')


if __name__ == '__main__': unittest.main()
