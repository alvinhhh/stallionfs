"""Owned synthetic processes only; no product or host storage operations."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parents[1] / 'tools/ci_test_entry.py'
spec = importlib.util.spec_from_file_location('ci_test_entry_test', SOURCE)
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)
NS = 10**9

CHILD = '''
import importlib.util, os, sys, threading, time, unittest
spec = importlib.util.spec_from_file_location('entry', sys.argv[1])
e = importlib.util.module_from_spec(spec); spec.loader.exec_module(e)
events = e.Events(sys.argv[2])
mode = sys.argv[3]
observer_done = threading.Event()
exit_done = threading.Event()
stack_count = 0
original_emit = events.emit
def observed_emit(value):
    global stack_count
    original_emit(value)
    if value.get('kind') == 'stack':
        stack_count += 1
        if stack_count == 3: observer_done.set()
    if value.get('phase') == 'exit' and value.get('state') == 'end': exit_done.set()
events.emit = observed_emit
original_snapshots = events.snapshots
def snapshots(delays):
    if mode == 'finalization' and not exit_done.wait(2):
        raise RuntimeError('exit observer did not progress')
    original_snapshots(delays)
events.snapshots = snapshots
def wait_for_observer():
    if not observer_done.wait(2): raise RuntimeError('snapshot observer did not progress')
secret = 'SECRET_SENTINEL_4821'
os.environ['PRIVATE_TEST_VALUE'] = secret
class Case(unittest.TestCase):
    def runTest(self):
        self.assertTrue(mode != 'fail', 'controlled assertion failure')
def boundary(name):
    if mode == name + '-error': raise ValueError(secret)
    if mode == name + '-delay':
        exec(compile('import time; time.sleep(.3)', '/private/' + secret + '/fake.py', 'exec'))
        wait_for_observer()
    if mode == name + '-stall': time.sleep(10)
def factory():
    def suite(): return unittest.TestSuite([Case()])
    def account(result):
        boundary('accounting')
        if mode in ('finalization', 'finalization-stall'):
            def finalize():
                time.sleep(10 if mode.endswith('stall') else .3)
                if mode == 'finalization': wait_for_observer()
            threading.Thread(target=finalize).start()
        return not result.wasSuccessful()
    return suite, lambda: boundary('close'), lambda: boundary('admission'), account, unittest.TextTestResult
code = e.lifecycle(factory, events, snapshot_delays=(.04, .04, .04))
if mode == 'cap': print('x' * 100000, flush=True)
if mode == 'pipe':
    # A deliberately inherited pipe owned by this fixture, self-terminating.
    import subprocess
    subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(2.4)'])
if mode == 'invalid': events.stream.write('{}\\n'); events.stream.flush()
sys.exit(code)
'''


WATCHDOG_CHILD = '''
import faulthandler, importlib.util, inspect, os, sys, threading, time, unittest
spec = importlib.util.spec_from_file_location('entry', sys.argv[1])
e = importlib.util.module_from_spec(spec); spec.loader.exec_module(e)
os.environ.update(CI_INVOCATION='watchdog-test', CI_MODE='suite', CI_JOB_BINDING='watchdog-test')
events = e.Events(sys.argv[2])
observer_done = threading.Event()
snapshots = events.snapshots
def observed_snapshots(delays):
    time.sleep(.1)
    snapshots(delays)
    observer_done.set()
events.snapshots = observed_snapshots
if sys.argv[3] == 'blocked':
    read, write = os.pipe()
    os.set_blocking(write, False)
    try:
        while True: os.write(write, b'x' * 4096)
    except BlockingIOError:
        pass
    os.set_blocking(write, True)
    os.dup2(write, 2)
runner = unittest.TextTestRunner
e.unittest.TextTestRunner = lambda **kwargs: runner(stream=sys.stdout, **kwargs)
class Case(unittest.TestCase):
    def runTest(self): time.sleep(.2)
def close():
    if not observer_done.wait(2):
        raise RuntimeError('snapshot observer did not progress')
def factory():
    return (lambda: unittest.TestSuite([Case()]), close, lambda: None,
            lambda result: not result.wasSuccessful(), unittest.TextTestResult)
kwargs = dict(snapshot_delays=(.01, .01, .01))
# Keep the same blocked-output reproduction runnable against the native watchdog.
if 'watchdog_interval' in inspect.signature(e.lifecycle).parameters:
    kwargs['watchdog_interval'] = .03
else:
    dump = faulthandler.dump_traceback_later
    faulthandler.dump_traceback_later = lambda *args, **kwargs: dump(.03, **kwargs)
print('main-thread=' + hex(threading.get_ident()), flush=True)
sys.exit(e.lifecycle(factory, events, **kwargs))
'''


class EntryTests(unittest.TestCase):
    def run_watchdog_child(self, mode):
        with tempfile.TemporaryDirectory(prefix='ci-watchdog-owned-') as directory:
            events = Path(directory) / 'events.jsonl'
            child = subprocess.run([sys.executable, '-I', '-B', '-c', WATCHDOG_CHILD,
                                    str(SOURCE), str(events), mode],
                                   capture_output=True, timeout=3, check=False)
            self.assertEqual(child.returncode, 0, child.stderr)
            return child, [json.loads(line) for line in events.read_text().splitlines()]

    def test_blocked_watchdog_output_does_not_block_closure(self):
        _, events = self.run_watchdog_child('blocked')
        phases = [(row['phase'], row['state']) for row in events if row['kind'] == 'phase']
        self.assertEqual(phases, [(phase, state) for phase in entry.PHASES for state in ('start', 'end')])
        self.assertEqual(len([row for row in events if row['kind'] == 'stack']), 3)

    def test_watchdog_output_contains_main_thread_file_and_line(self):
        child, _ = self.run_watchdog_child('visible')
        main_thread = child.stdout.decode().splitlines()[0].split('=')[1]
        output = child.stderr.decode()
        self.assertIn('Timeout (0:00:00.030000)!\n', output)
        main_stack = output.split('Thread ' + main_thread + ' (most recent call first):\n')[1]
        self.assertRegex(main_stack.split('\n\n')[0], r'  File "<string>", line \d+ in runTest')

    def test_watchdog_empty_frames_and_short_writes(self):
        stop = Mock()
        stop.wait.side_effect = (False, True)
        stop.is_set.return_value = False
        output = []
        def write(fd, data):
            self.assertEqual(fd, 2)
            output.append(data[:7])
            return len(data[:7])
        with patch.object(entry.sys, '_current_frames', return_value={}), \
                patch.object(entry.os, 'write', side_effect=write):
            entry.suite_watchdog(stop, 300)
        self.assertEqual(b''.join(output), b'Timeout (0:05:00)!\n')

    def test_watchdog_stopped_or_closed_output_returns(self):
        stop = entry.threading.Event()
        stop.set()
        with patch.object(entry.os, 'write') as write:
            entry.suite_watchdog(stop, 300)
            write.assert_not_called()
        for outcome in (BrokenPipeError(), 0):
            stop = Mock()
            stop.wait.return_value = False
            stop.is_set.return_value = False
            with patch.object(entry.sys, '_current_frames', return_value={}), \
                    patch.object(entry.os, 'write', side_effect=[outcome]) as write:
                entry.suite_watchdog(stop, .03)
                write.assert_called_once()

    def test_watchdog_bounds_threads_and_frame_depth(self):
        stop = Mock()
        stop.wait.side_effect = (False, True)
        stop.is_set.return_value = False
        frame = SimpleNamespace(f_code=SimpleNamespace(co_filename='watchdog.py', co_name='run'), f_lineno=12)
        frame.f_back = frame
        output = []
        def write(fd, data):
            output.append(data)
            return len(data)
        with patch.object(entry.sys, '_current_frames', return_value=dict.fromkeys(range(65), frame)), \
                patch.object(entry.os, 'write', side_effect=write):
            entry.suite_watchdog(stop, .03)
        data = b''.join(output)
        self.assertEqual(data.count(b'Thread 0x'), 64)
        self.assertEqual(data.count(b'  File '), 64 * 64)
        self.assertEqual(data.count(b'  ...\n'), 64)

    def run_child(self, mode, timeout=4, **kwargs):
        with tempfile.TemporaryDirectory(prefix='ci-entry-owned-') as directory:
            root = Path(directory)
            child = root / 'child.py'; child.write_text(CHILD)
            events = root / 'events.jsonl'
            start = time.monotonic()
            receipt = entry.supervise([sys.executable, '-I', '-B', str(child), str(SOURCE), str(events), mode],
                                      events, timeout, echo=False, **kwargs)
            elapsed = time.monotonic() - start
            self.assertGreaterEqual(receipt['collected'], receipt['launched'])
            entry.validate_receipt(json.dumps(receipt))
            raw = events.read_text() if events.exists() else ''
            self.assertNotIn('SECRET_SENTINEL_4821', raw + json.dumps(receipt))
            if mode == 'pipe':
                # Let only the short-lived owned fixture descendant finish.
                time.sleep(max(0, 2.6 - elapsed))
            return receipt, elapsed

    def test_passing_and_assertion_failure_same_lifecycle(self):
        for mode, code in (('pass', 0), ('fail', 1)):
            with self.subTest(mode=mode):
                r, _ = self.run_child(mode)
                self.assertEqual(r['returncode'], code)
                self.assertTrue(r['valid'] and r['complete'] and r['reaped'])
                self.assertEqual(r['eof'], {'stdout': True, 'stderr': True})
                self.assertFalse(r['cleanup_uncertainty'])
                self.assertEqual(r['success'], code == 0)
                phases = [x for x in r['events'] if x['kind'] == 'phase']
                self.assertEqual([(x['phase'], x['state']) for x in phases],
                                 [(p, s) for p in entry.PHASES for s in ('start', 'end')])
                self.assertEqual(phases[-2]['failures'], code)
                self.assertEqual(r['escaped_descendants'], 'unavailable')

    def test_delayed_boundaries_and_non_daemon_finalization(self):
        for mode in ('close-delay', 'admission-delay', 'accounting-delay', 'finalization'):
            with self.subTest(mode=mode):
                r, elapsed = self.run_child(mode)
                self.assertTrue(r['success'], r)
                self.assertGreater(elapsed, .29)
                stacks = [x for x in r['events'] if x['kind'] == 'stack']
                self.assertEqual(len(stacks), 3)
                self.assertTrue(any(not t['daemon'] for t in stacks[-1]['threads']))
                if mode == 'finalization':
                    self.assertGreater(r['events'][-1]['time'], next(x['time'] for x in r['events'] if x.get('phase') == 'exit'))

    def test_errors_preserve_admission_and_non_success(self):
        for mode in ('close-error', 'admission-error', 'accounting-error'):
            r, _ = self.run_child(mode)
            self.assertFalse(r['success'])
            self.assertEqual(r['returncode'], 1)
            self.assertTrue(r['complete'])
            self.assertTrue(any(x.get('phase') == 'admission' for x in r['events']))
            self.assertEqual([x['error'] for x in r['events'] if x.get('state') == 'error'], ['ValueError'])

    def test_deadlines_distinguish_post_suite_stalls(self):
        for boundary in ('close', 'admission', 'accounting'):
            r, elapsed = self.run_child(boundary + '-stall', timeout=.6)
            self.assertEqual(r['reason'], 'deadline')
            self.assertEqual(r['last_phase']['phase'], boundary)
            self.assertFalse(r['success'])
            self.assertTrue(r['reaped'])
            completed = [x for x in r['events'] if x.get('phase') == 'suite' and x['state'] == 'end']
            self.assertEqual(completed[0]['tests'], 1)
            self.assertEqual(completed[0]['failures'], 0)
            self.assertLess(elapsed, 3)

    def test_finalization_stall_has_exit_request_without_success(self):
        r, elapsed = self.run_child('finalization-stall', timeout=.6)
        self.assertEqual(r['reason'], 'deadline')
        self.assertEqual(r['last_phase']['phase'], 'exit')
        self.assertTrue(r['complete'] and r['reaped'])
        self.assertFalse(r['success'])
        self.assertLess(elapsed, 3)

    def test_cap_no_eof_invalid_and_cancellation_fail_closed(self):
        for mode, kwargs, reason in (('cap', {'output_cap': 4096}, 'output_cap'),
                                     ('pipe', {}, 'no_eof'), ('invalid', {}, None)):
            r, _ = self.run_child(mode, **kwargs)
            self.assertFalse(r['success'])
            self.assertEqual(r['reason'], reason)
            if mode == 'pipe': self.assertTrue(r['cleanup_uncertainty'])
            if mode == 'invalid': self.assertFalse(r['valid'])
        started = time.monotonic()
        r, _ = self.run_child('close-stall', cancelled=lambda: time.monotonic() - started > .3)
        self.assertEqual(r['reason'], 'cancelled')
        self.assertTrue(r['reaped'])
        self.assertFalse(r['success'])

    def test_marker_validation_and_caps(self):
        r, _ = self.run_child('pass')
        rows = r['events']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events'
            for data in (b'', b'{}', b'x' * (entry.DIAGNOSTIC_CAP + 1),
                         ('\n'.join(json.dumps(x) for x in rows[::-1]) + '\n').encode(),
                         ('\n'.join(json.dumps(x) for x in rows * 4) + '\n').encode()):
                path.write_bytes(data)
                with self.assertRaises(ValueError): entry.validate(path)
            path.write_text(json.dumps(rows[0]) + '\n')
            self.assertFalse(entry.validate(path)[1])
            rows[-2]['secret'] = 'SECRET_SENTINEL_4821'
            path.write_text('\n'.join(json.dumps(x) for x in rows) + '\n')
            with self.assertRaises(ValueError): entry.validate(path)

    def test_job_remainder_is_anchored_and_reserves_upload(self):
        self.assertEqual(entry.remainder(100*NS, 20, 125*NS), 1045)
        self.assertEqual(entry.remainder(100*NS, 20, 5000*NS), 0)
        self.assertEqual(entry.remainder(100*NS, 15, 900*NS, tail=True), 90)
        self.assertEqual(entry.remainder(100*NS, 15, 870*NS), 0)
        self.assertEqual(entry.remainder(100*NS, 15, 990*NS, tail=True), 0)
        self.assertEqual(entry.remainder(100*NS, 15, 125*NS+1), 744.999999999)
        for start, minutes in ((float('nan'), 20), (501*NS, 20), (0, 46),
                               (True, 20), (-1, 20), (100.0, 20), (0, True)):
            with self.assertRaises(ValueError): entry.remainder(start, minutes, 500*NS)
        for now in (True, float('inf'), float('nan'), -1, 100.0):
            with self.assertRaises(ValueError): entry.remainder(0, 20, now)
        with self.assertRaises(ValueError): entry.remainder(0, 20, NS, tail=1)

    def test_intel_worker_allocation_boundaries(self):
        self.assertEqual(entry.remainder(100*NS, 45, 125*NS), 2545)
        self.assertEqual(entry.remainder(100*NS, 60, 100*NS), 3470)
        self.assertEqual(entry.remainder(100*NS, 60, 125*NS), 3445)
        self.assertEqual(entry.remainder(100*NS, 60, 125*NS, tail=True), 3565)
        self.assertEqual(entry.remainder(100*NS, 60, 3570*NS), 0)
        for minutes in range(121):
            if minutes not in (15, 20, 30, 45, 60):
                with self.subTest(minutes=minutes), self.assertRaises(ValueError):
                    entry.remainder(100*NS, minutes, 125*NS)

    def test_suite_and_receipt_timeout_boundaries(self):
        for minutes in (45, 60):
            with self.subTest(minutes=minutes):
                receipt, _ = self.run_child('pass', timeout=minutes*60-entry.RESERVE)
                self.assertTrue(receipt['success'])
                self.assertEqual(receipt['timeout'], minutes*60-entry.RESERVE)
        for timeout in (60*60-entry.RESERVE+.001, 61*60-entry.RESERVE,
                        0, -1, True, None, '', float('inf'), float('nan')):
            with self.subTest(timeout=timeout):
                with self.assertRaisesRegex(ValueError, 'Suite deadline'):
                    self.run_child('pass', timeout=timeout)
                with self.assertRaises(ValueError):
                    entry.validate_receipt(json.dumps(dict(receipt, timeout=timeout)))

    def test_allocation_uses_explicit_clock_without_generic_origin_or_fallback(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        with patch.object(entry.time, 'clock_gettime_ns', return_value=10025*NS) as clock, \
                patch.object(entry.time, 'monotonic', side_effect=AssertionError('wrong origin')), \
                patch.object(entry.time, 'perf_counter', side_effect=AssertionError('wrong origin')):
            self.assertEqual(entry.remainder(10000*NS,20),1045)
            clock.assert_called_once_with(entry.time.CLOCK_MONOTONIC_RAW)
        for clock_value in (True, -1, 1.5, float('inf'), float('nan')):
            with self.subTest(clock_value=clock_value), \
                    patch.object(entry.time, 'clock_gettime_ns', return_value=clock_value):
                with self.assertRaises(ValueError): entry.allocation_clock_ns()
        with patch.object(entry, 'time', SimpleNamespace()):
            with self.assertRaisesRegex(ValueError, 'clock unavailable'): entry.allocation_clock_ns()
        with patch.object(entry.time, 'clock_gettime_ns', side_effect=OSError('unavailable')):
            with self.assertRaisesRegex(ValueError, 'clock unavailable'): entry.allocation_clock_ns()


    def test_required_skip_and_contextual_accounting(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        def result(skips=(), contextual=0, activation=1, success=True):
            return SimpleNamespace(skipped=list(skips), contextual_successes=contextual, activation_successes=activation,
                                   wasSuccessful=lambda: success, testsRun=1)
        capability = (SimpleNamespace(id=lambda: 'setUpClass (test_fskit.FSKitInterfaces)'),
                      'FSKit capability unavailable: synthetic')
        ordinary = (SimpleNamespace(id=lambda: 'required.test'), 'missing')
        with patch.dict(os.environ, STALLIONFS_TEST_IMAGES='1'):
            self.assertFalse(entry.account_result(result([capability]), None, False, 'context'))
            self.assertTrue(entry.account_result(result([ordinary]), None, False, 'context'))
            self.assertTrue(entry.account_result(result(), None, True, 'context'))
            self.assertFalse(entry.account_result(result(contextual=1), None, True, 'context'))
            self.assertTrue(entry.account_result(result(contextual=2), None, True, 'context'))
            self.assertTrue(entry.account_result(result(success=False), None, False, 'context'))
            self.assertTrue(entry.account_result(result([capability]), 'pass', False, 'context'))

    def test_ownership_capability_skips_do_not_exempt_unrelated_skips_or_failures(self):
        names = (
            'test_privileged_copy_clone_move_preserve_foreign_ownership',
            'test_unprivileged_copy_refuses_loss_clone_uses_darwin_ownership_move_preserves',
            'test_move_round_trip_preserves_acl_xattrs_resource_fork_and_aliases',
            'test_image_import_preserves_foreign_ownership_and_aliases',
        )
        reason = 'Ownership fixtures require root or passwordless sudo: sudo: a password is required'
        def refused(skips, success=True, probe=None):
            result = SimpleNamespace(skipped=skips, contextual_successes=0, activation_successes=0,
                                     wasSuccessful=lambda: success, testsRun=4)
            return entry.account_result(result, probe, False, entry.CONTEXTUAL_TEST)
        skips = [(SimpleNamespace(id=lambda name=name: 'test_ownership.Ownership.' + name), reason)
                 for name in names]
        with patch.dict(os.environ, STALLIONFS_TEST_IMAGES='1'):
            self.assertFalse(refused([]))
            self.assertFalse(refused(skips))
            self.assertTrue(refused(skips, success=False))
            self.assertTrue(refused(skips, probe='pass'))
            self.assertTrue(refused([(skips[0][0], 'different reason')]))
            unrelated = (SimpleNamespace(id=lambda: 'test_ownership.Ownership.test_other'), reason)
            self.assertTrue(refused([unrelated]))
            self.assertTrue(refused(skips + [unrelated]))

    def test_sigkill_capability_skips_require_exact_test_ids_and_reason(self):
        names = (
            'test_killed_copy_clone_preserve_source_and_allow_partial_destination',
            'test_killed_move_has_exactly_one_complete_inode_tree',
            'test_killed_preparation_is_unpublished_reported_and_not_cached',
            'test_killed_rollback_reconciles_both_sides_of_exchange_without_replay',
        )
        reason = 'SIGKILL pause hook unavailable: compile: unsupported SDK'
        skips = [(SimpleNamespace(id=lambda name=name: 'test_sigkill.ProcessDeath.' + name), reason)
                 for name in names]
        def refused(entries, success=True, probe=None):
            result = SimpleNamespace(skipped=entries, contextual_successes=0, activation_successes=0,
                                     wasSuccessful=lambda: success, testsRun=4)
            return entry.account_result(result, probe, False, entry.CONTEXTUAL_TEST)
        with patch.dict(os.environ, STALLIONFS_TEST_IMAGES='1'):
            self.assertFalse(refused([]))
            for skip in skips:
                self.assertFalse(refused([skip]))
            self.assertFalse(refused(skips))
            self.assertTrue(refused(skips, success=False))
            self.assertTrue(refused(skips, probe='pass'))
            for invalid_reason in ('different reason', 'SIGKILL pause hook unavailable', ''):
                self.assertTrue(refused([(skips[0][0], invalid_reason)]))
            for invalid_id in ('test_sigkill.ProcessDeath.test_other',
                               'setUpClass (test_sigkill.ProcessDeath)',
                               'test_sigkill.PauseHookCapabilities.test_unavailable_probe_skips_individual_tests'):
                unrelated = (SimpleNamespace(id=lambda: invalid_id), reason)
                self.assertTrue(refused([unrelated]))
                self.assertTrue(refused(skips + [unrelated]))

    def test_root_git_sigkill_skips_are_narrow(self):
        reason = 'SIGKILL Git fixtures require a non-root test process'
        names = ['test_sigkill.ProcessDeath.' + name for name in (
            'test_killed_preparation_is_unpublished_reported_and_not_cached',
            'test_killed_rollback_reconciles_both_sides_of_exchange_without_replay')]
        def refused(name, message=reason, success=True, probe=None):
            result = SimpleNamespace(skipped=[(SimpleNamespace(id=lambda: name), message)],
                                     contextual_successes=0, activation_successes=0,
                                     wasSuccessful=lambda: success, testsRun=1)
            return entry.account_result(result, probe, False, entry.CONTEXTUAL_TEST)
        with patch.dict(os.environ, STALLIONFS_TEST_IMAGES='1'):
            for name in names:
                self.assertFalse(refused(name))
                self.assertTrue(refused(name, success=False))
                self.assertTrue(refused(name, probe='pass'))
                self.assertTrue(refused(name, message=reason + ': other'))
            for name in ('test_sigkill.ProcessDeath.test_killed_move_has_exactly_one_complete_inode_tree',
                         'test_sigkill.ProcessDeath.test_killed_copy_clone_preserve_source_and_allow_partial_destination',
                         'setUpClass (test_sigkill.ProcessDeath)', 'unrelated.test'):
                self.assertTrue(refused(name))

    def test_workspace_sigkill_capability_skips_require_exact_ids_and_reasons(self):
        folder_names = (
            'test_killed_create_publishes_only_complete_workspace',
            'test_killed_snapshot_publishes_only_complete_capture',
            'test_killed_remove_preserves_payload_in_workspaces_or_trash',
            'test_killed_purge_and_gc_retain_reported_remainder',
            'test_killed_native_delete_is_confined_and_survivors_intact',
        )
        image_names = (
            'test_killed_image_create_keeps_closed_complete_candidate',
            'test_killed_image_snapshot_keeps_closed_complete_candidate',
            'test_killed_mount_and_detach_reconcile_existing_attachment',
        )
        folders = ['test_sigkill_workspace.WorkspaceDeath.' + name for name in folder_names]
        images = ['test_sigkill_workspace.MountedImageDeath.' + name for name in image_names]
        root_reason = 'SIGKILL Git fixtures require a non-root test process'
        hook = 'SIGKILL pause hook unavailable: workspace rename: DYLD stripped'
        image = 'SIGKILL image fixtures unavailable: missing /usr/bin/hdiutil'
        def skipped(name, reason):
            return SimpleNamespace(id=lambda: name), reason
        def refused(skips, success=True, probe=None):
            result = SimpleNamespace(skipped=skips, contextual_successes=0, activation_successes=0,
                                     wasSuccessful=lambda: success, testsRun=8)
            return entry.account_result(result, probe, False, entry.CONTEXTUAL_TEST)
        with patch.dict(os.environ, STALLIONFS_TEST_IMAGES='1'):
            valid = [skipped(name, hook) for name in folders + images] + [skipped(name, image) for name in images]
            for skip in valid:
                self.assertFalse(refused([skip]))
            self.assertFalse(refused(valid))
            self.assertTrue(refused(valid, success=False))
            self.assertTrue(refused(valid, probe='pass'))
            root_skips = [skipped(name, root_reason) for name in folders[:-1] + images]
            for skip in root_skips:
                self.assertFalse(refused([skip]))
            self.assertFalse(refused(root_skips))
            self.assertTrue(refused(root_skips, success=False))
            self.assertTrue(refused(root_skips, probe='pass'))
            native_delete = skipped(folders[-1], root_reason)
            self.assertTrue(refused([native_delete]))
            self.assertTrue(refused(root_skips + [native_delete]))
            for name in folders + images:
                self.assertTrue(refused([skipped(name, root_reason + ': other')]))
            for name in folders:
                self.assertTrue(refused([skipped(name, image)]))
            for reason in ('', 'SIGKILL pause hook unavailable', 'SIGKILL image fixtures unavailable', 'other'):
                for name in folders + images:
                    self.assertTrue(refused([skipped(name, reason)]))
            for name in ('test_sigkill_workspace.WorkspaceDeath.test_other',
                         'test_sigkill_workspace.MountedImageDeath.test_other',
                         'setUpClass (test_sigkill_workspace.WorkspaceDeath)',
                         'setUpClass (test_sigkill_workspace.MountedImageDeath)',
                         'test_sigkill_workspace.WorkspaceHookCapabilities.test_probe_failure_names_boundary'):
                for reason in (hook, image, root_reason):
                    invalid = skipped(name, reason)
                    self.assertTrue(refused([invalid]))
                    self.assertTrue(refused(valid + [invalid]))

    def test_adapter_skip_requires_nested_pass_or_unsupported_host(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        import contextlib, io
        capability = (SimpleNamespace(id=lambda: 'setUpClass (test_fskit.FSKitInterfaces)'),
                      'FSKit capability unavailable: synthetic unsupported host')
        adapter = (SimpleNamespace(id=lambda: entry.ADAPTER_TEST), 'requires compiled offline activation driver')
        def refused(skips, successes=0, required=False, successful=True, contextual=1):
            result = SimpleNamespace(skipped=skips, activation_successes=successes,
                                     contextual_successes=contextual, wasSuccessful=lambda: successful)
            return entry.account_result(result, None, required, entry.CONTEXTUAL_TEST)
        with patch.dict(os.environ, STALLIONFS_TEST_IMAGES='1'), contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(refused([adapter], 1, required=True))
            self.assertFalse(refused([adapter, capability]))
            for count in (0, 2, -1, True, None):
                with self.subTest(count=count):
                    self.assertTrue(refused([adapter], count, required=True))
            self.assertTrue(refused([adapter, capability], required=True))
            self.assertTrue(refused([adapter], 1, successful=False))
            self.assertTrue(refused([], 0, required=True))
            self.assertTrue(refused([adapter], 1, required=True, contextual=0))
            self.assertTrue(refused([(adapter[0], 'different skip')], 1))
            self.assertTrue(refused([(SimpleNamespace(id=lambda: 'other.test'), adapter[1])], 1))
            self.assertTrue(refused([adapter]))

    def test_result_counts_only_actual_successful_required_selectors(self):
        import io
        class Synthetic(unittest.TestCase):
            def __init__(self, identity, outcome='pass'):
                super().__init__('runTest'); self.identity=identity; self.outcome=outcome
            def id(self): return self.identity
            def runTest(self):
                if self.outcome == 'fail': self.fail('controlled required-selector failure')
                if self.outcome == 'skip': self.skipTest('controlled required-selector skip')
        for outcome in ('pass', 'fail', 'skip'):
            suite=unittest.TestSuite([Synthetic(entry.CONTEXTUAL_TEST), Synthetic(entry.ACTIVATION_TEST, outcome)])
            result=unittest.TextTestRunner(stream=io.StringIO(), resultclass=entry.ContextualResult).run(suite)
            self.assertEqual(result.contextual_successes, 1)
            self.assertEqual(result.activation_successes, int(outcome == 'pass'))
            self.assertEqual(result.wasSuccessful(), outcome != 'fail')

    def test_workflow_entry_allocation_and_fixed_discovery(self):
        import ast
        root = SOURCE.parents[1]
        text = (root / '.github/workflows/checks.yml').read_text()
        worker = text.split('  test-execution:', 1)[1].split('\n  test:', 1)[0]
        self.assertLess(worker.index('Anchor worker allocation'), worker.index('uses: actions/checkout'))
        self.assertIn("time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)", worker)
        self.assertIn("clock='darwin-CLOCK_MONOTONIC_RAW-ns-v1'", worker)
        self.assertLess(worker.index('Create owned CI interpreter'), worker.index('Check shared allocation clock'))
        self.assertLess(worker.index('Check shared allocation clock'), worker.index('Install pinned wheel backend'))
        self.assertIn("record['start_ns'] <= before_ns <= sample['sample_ns'] <= after_ns", worker)
        expressions = [line.split('${{ ', 1)[1] for line in worker.splitlines()
                       if 'timeout-minutes: ${{' in line or 'CI_JOB_MINUTES: ${{' in line]
        self.assertEqual(len(expressions), 2)
        self.assertEqual(expressions[0], expressions[1])
        self.assertIn("matrix.os == 'macos-26' && matrix.phase == 'installed' && 30", expressions[0])
        self.assertIn("matrix.os == 'macos-26-intel' && matrix.phase == 'installed' && 60", expressions[0])
        # Keep the original anchor and shared tail reserve; the slow installed
        # workers receive room for the observed suite rather than a fresh clock.
        self.assertEqual(entry.remainder(100*NS, 30, 344*NS), 1426)
        self.assertIn("'tools/ci_test_entry.py'", worker)
        self.assertIn('raise SystemExit(entry.main())', worker)
        tree = ast.parse(SOURCE.read_text())
        discoveries = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                       and isinstance(node.func, ast.Attribute) and node.func.attr == 'discover']
        self.assertEqual(len(discoveries), 1)
        self.assertEqual(ast.unparse(discoveries[0]), "unittest.defaultTestLoader.discover(str(checkout / 'tests'))")
        self.assertEqual(entry.remainder(100*NS, 45, 125*NS), 2545)
        self.assertGreater(entry.remainder(100*NS, 45, 125*NS), 1792)




ACCOUNTING_CHILD = '''
import importlib.util,sys,types,unittest
spec=importlib.util.spec_from_file_location('entry',sys.argv[1])
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
mode=sys.argv[3]
class Case(unittest.TestCase):
    def runTest(self):
        for i in range(2):
            with self.subTest(i=i):
                if mode in ('failure','mixed'): self.fail('controlled')
            with self.subTest(error=i):
                if mode in ('error','mixed'): raise ValueError('controlled')
            with self.subTest(skip=i):
                if mode in ('skip','mixed'): self.skipTest('controlled')
    @classmethod
    def setUpClass(cls):
        if mode=='class-error': raise ValueError('controlled')
        if mode=='class-skip': raise unittest.SkipTest('controlled')
    @classmethod
    def tearDownClass(cls):
        if mode=='teardown-error': raise ValueError('controlled')
module=types.ModuleType('owned_fixture');sys.modules[module.__name__]=module
Case.__module__=module.__name__
def setUpModule():
    if mode=='module-error': raise ValueError('controlled')
    if mode=='module-skip': raise unittest.SkipTest('controlled')
module.setUpModule=setUpModule

def factory():
    return (lambda:unittest.TestSuite([Case()]),lambda:None,lambda:None,
            lambda r:not r.wasSuccessful(),unittest.TextTestResult)
sys.exit(e.lifecycle(factory,e.Events(sys.argv[2])))
'''


class AccountingTests(unittest.TestCase):
    def check_outcomes(self, cases):
        for mode, counts, code in cases:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                path=Path(d)/'events.jsonl'
                r=entry.supervise([sys.executable,'-I','-B','-c',ACCOUNTING_CHILD,
                                   str(SOURCE),str(path),mode],path,4,echo=False,mode='suite')
                saved=entry.validate_receipt(path.with_suffix('.jsonl.receipt.json').read_bytes())
                self.assertEqual(r,saved)
                self.assertEqual(r['returncode'],code)
                self.assertTrue(r['valid'] and r['complete'] and r['reaped'],r)
                self.assertTrue(all(r['eof'].values()))
                self.assertFalse(r['cleanup_uncertainty'])
                self.assertEqual(r['success'],code==0)
                phases=[x for x in r['events'] if x['kind']=='phase']
                self.assertEqual([(x['phase'],x['state']) for x in phases],
                                 [(p,s) for p in entry.PHASES for s in ('start','end')])
                for record in (phases[3],phases[-2]):
                    self.assertEqual(tuple(record[k] for k in entry.COUNTS),counts)

    def test_real_multiple_subtest_failures_errors_and_skips(self):
        self.check_outcomes([('failure',(1,2,0,0),1),('error',(1,0,2,0),1),
                             ('skip',(1,0,0,2),0),('mixed',(1,2,2,2),1)])

    def test_real_class_and_module_fixture_errors_without_methods(self):
        self.check_outcomes([('class-error',(0,0,1,0),1),('module-error',(0,0,1,0),1),
                             ('teardown-error',(1,0,1,0),1)])

    def test_real_class_and_module_fixture_skips_without_methods(self):
        self.check_outcomes([('class-skip',(0,0,0,1),0),('module-skip',(0,0,0,1),0)])


class CaptureResultTests(unittest.TestCase):
    def test_prelaunch_refusal_leaves_capture_null(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'events';path.write_text('keep')
            result=entry.CaptureResult()
            with patch.object(entry.subprocess,'Popen',side_effect=AssertionError('must not launch')) as spawn:
                r=entry.supervise([sys.executable,'-I','-B','-c','pass'],path,2,
                                  echo=False,result=result)
            spawn.assert_not_called()
            self.assertIsNone(result.capture)
            self.assertEqual(r['reason'],'setup_error')
            self.assertEqual(path.read_text(),'keep')
            self.assertEqual(entry.validate_receipt(path.with_suffix('.receipt.json').read_bytes()),r)

    def test_invalid_collected_payload_still_raises_with_capture(self):
        from unittest.mock import patch
        original=entry._supervise
        def malformed(*args,**kwargs):
            r=original(*args,**kwargs)
            r['bytes']=True
            return r
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'events';result=entry.CaptureResult()
            with patch.object(entry,'_supervise',side_effect=malformed), self.assertRaises(ValueError):
                entry.supervise([sys.executable,'-I','-B','-c','pass'],path,2,
                                echo=False,result=result)
            self.assertTrue(result.capture['reaped'])
            self.assertTrue(all(result.capture['eof'].values()))
            self.assertEqual(path.with_suffix('.receipt.json').read_bytes(),b'')
            with self.assertRaises(ValueError):entry.validate_receipt(json.dumps(result.capture))

    def test_unavailable_capture_has_exact_failure_schema(self):
        r=dict(success=False,reason='capture_unavailable',job='a'*64,cleanup_uncertainty=True)
        self.assertEqual(entry.validate_receipt(json.dumps(r)),r)
        for field,value in (('success',True),('cleanup_uncertainty',False),('job',None),
                            ('job','x'*64),('job',[]),('pid',None),('eof',{}),('reaped',True)):
            with self.subTest(field=field,value=value), self.assertRaises(ValueError):
                entry.validate_receipt(json.dumps(dict(r,**{field:value})))
        for field in r:
            invalid=dict(r);del invalid[field]
            with self.assertRaises(ValueError):entry.validate_receipt(json.dumps(invalid))


# This fixture runs public allocation/claim/collection with a harmless lifecycle.
PUBLIC_ENTRY_CHILD = r'''
import sys,os,unittest,importlib.util
from pathlib import Path
spec=importlib.util.spec_from_file_location('entry',sys.argv[1]);e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
root=Path(sys.argv[3]);mode=os.environ['CI_MODE']
with (root/'launches').open('a') as stream:stream.write(sys.argv[5]+mode+'\n')
if sys.argv[4]=='bare':raise SystemExit(1 if mode=='fail' else 0)
class Case(unittest.TestCase):
 def runTest(self):
  fail=mode=='fail'
  if sys.argv[4]=='unexpected':fail=not fail
  self.assertFalse(fail)
def factory():return lambda:unittest.TestSuite([Case()]),lambda:None,lambda:None,lambda r:not r.wasSuccessful(),unittest.TextTestResult
sys.exit(e.lifecycle(factory,e.Events(sys.argv[2])))
'''

PUBLIC_ENTRY_WRAPPER = r'''
import sys,os,json,importlib.util
from pathlib import Path
source=Path(sys.argv[1]);root=Path(sys.argv[2]);case=json.loads(sys.argv[3])
spec=importlib.util.spec_from_file_location('entry',source/'tools/ci_test_entry.py');e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
collect=e._supervise;opened=Path.open;fsync=e.os.fsync;dumps=e.json.dumps;validate=e.validate_receipt
mode=case['mode'];stage=case.get('stage');sink=case.get('sink','capture');behavior=case.get('behavior')
failed=False;target_fd=None;prior=None

def argv(path,which,prefix=''):
 return [sys.executable,'-I','-B',str(root/'child.py'),str(source/'tools/ci_test_entry.py'),str(path),str(root),which,prefix]
def save(name,value):
 with opened(root/name,'x') as stream:stream.write(dumps(value))
if behavior=='stale':
 prior=e.supervise(argv(root/'prior.jsonl','normal','prior:'),root/'prior.jsonl',3,echo=False,mode=mode,job=os.environ['CI_ALLOCATION_SHA256'])
 save('prior-capture.json',prior)
def collected(args,path,timeout,**kwargs):
 current=kwargs['mode']
 which='unexpected' if behavior=='unexpected' and current==mode else 'normal'
 if current==mode and case.get('bare'):which='bare'
 actual=collect(argv(path,which),path,min(timeout,3),**kwargs)
 save('actual-'+current+'.json',actual)
 if current==mode:
  if behavior=='null':return None
  if behavior=='scalar':return 0
  if behavior=='stale':return prior
  if behavior=='malformed':return dict(actual,bytes=True)
  if behavior in ('reversed','missing-collected'):
   returned=dict(actual)
   if behavior=='reversed':returned['collected']=actual['launched']-1
   else:returned.pop('collected')
   save('returned-'+current+'.json',returned)
   return returned
 return actual
e._supervise=collected

def fault():
 global failed
 failed=True
 if stage=='serialize':raise ValueError('SECRET_SENTINEL_4821')
 raise OSError('SECRET_SENTINEL_4821')
def target(path,args):
 if mode is None:return False
 if sink=='capture':return path.name==mode+'.jsonl.receipt.json'
 if sink=='result':return path.parent.name=='suite-closure' and path.name==mode+'.json'
 return path.name=='ci-phase-'+mode+'.json' and args and args[0]=='w'
class Sink:
 def __init__(self,stream):self.stream=stream
 def __enter__(self):return self
 def __getattr__(self,key):return getattr(self.stream,key)
 def __exit__(self,*args):
  result=self.stream.__exit__(*args)
  if stage=='close' and not failed:fault()
  return result
 def write(self,data):
  if sink=='capture':
   with opened(root/'attempted-capture.json','x') as stream:stream.write(data)
  if stage=='write' and not failed:fault()
  return self.stream.write(data)
 def flush(self):
  if stage=='flush' and not failed:fault()
  return self.stream.flush()
def open_path(path,*args,**kwargs):
 global target_fd
 if path.name.startswith('suite-closure-refusal-') and case.get('block_refusal'):
  raise PermissionError('secondary sink failure')
 if target(path,args) and stage=='open' and not failed:fault()
 stream=opened(path,*args,**kwargs)
 if behavior=='setup' and path.name==mode+'.jsonl.receipt.json':
  with opened(path.with_name(mode+'.jsonl'),'x') as events:events.write('keep')
 if target(path,args) and stage:
  target_fd=stream.fileno();return Sink(stream)
 return stream
def sync(fd):
 if fd==target_fd and stage=='fsync' and not failed:fault()
 return fsync(fd)
def serialize(value,*args,**kwargs):
 if stage=='serialize' and not failed and type(value) is dict and value.get('mode')==mode and 'qualification' in value:fault()
 return dumps(value,*args,**kwargs)
Path.open=open_path;e.os.fsync=sync;e.json.dumps=serialize
if case.get('collisions'):
 original=e.write_refusal
 def refusal(receipt,label,category,**kwargs):return original(receipt,label,category,token='f'*32)
 e.write_refusal=refusal
sys.argv=[str(source/'tools/ci_test_entry.py')]
sys.exit(e.main())
'''


def run_public_entry(root, case):
    import subprocess,hashlib
    env=dict(os.environ,RUNNER_TEMP=str(root),GITHUB_RUN_ID='entry',GITHUB_RUN_ATTEMPT='1',
             GITHUB_JOB='test',CI_WORKER='owned',CI_SPARSE_REQUIRED='0')
    data=json.dumps(dict(schema=1,clock='darwin-CLOCK_MONOTONIC_RAW-ns-v1',
         start_ns=entry.allocation_clock_ns(),minutes=15,
         identity={k:env[k] for k in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB','CI_WORKER')},token='a'*32)).encode()
    (root/'ci-allocation.json').write_bytes(data)
    env['CI_ALLOCATION_SHA256']=hashlib.sha256(data).hexdigest()
    (root/'child.py').write_text(PUBLIC_ENTRY_CHILD)
    for i in range(case.get('collisions',0)):
        (root/('suite-closure-refusal-'+('f'*32)+'-'+str(i)+'.json')).write_bytes(b'keep')
    args=[sys.executable,'-I','-B','-c',PUBLIC_ENTRY_WRAPPER,str(SOURCE.parents[1]),str(root),json.dumps(case)]
    p=subprocess.run(args,env=env,text=True,capture_output=True,timeout=10)
    (root/'public.log').write_text(p.stdout+p.stderr)
    return p,env


class PublicEntryTests(unittest.TestCase):
    def check_fault(self, root, case):
        p,env=run_public_entry(root,case)
        self.assertEqual(p.returncode,1,p.stderr)
        mode=case['mode']
        paths=[path for path in root.glob('*-refusal-*') if path.read_bytes()!=b'keep']
        if case.get('block_refusal') or case.get('collisions')==4 or case.get('behavior')=='malformed':
            self.assertIn('receipt unavailable',p.stderr)
            self.assertIn('ValueError' if case.get('stage')=='serialize' or case.get('behavior')=='malformed' else 'OSError',p.stderr)
            self.assertTrue(all(path.stat().st_size==0 for path in paths))
        else:
            self.assertEqual(len(paths),1)
            refusal=entry.validate_receipt(paths[0].read_bytes())
            self.assertEqual((refusal['mode'],refusal['job']),(mode,env['CI_ALLOCATION_SHA256']))
            self.assertFalse(refusal['success'] or refusal['qualification'])
            if case.get('stage')=='open':
                self.assertIsNone(refusal['capture'])
                self.assertFalse((root/('actual-'+mode+'.json')).exists())
            elif case.get('behavior') in ('null','scalar','stale'):
                self.assertEqual(refusal['capture'],dict(success=False,reason='capture_unavailable',
                                                       job=refusal['job'],cleanup_uncertainty=True))
            else:
                actual=entry.validate_receipt((root/('actual-'+mode+'.json')).read_bytes())
                self.assertEqual(refusal['capture'],actual)
                self.assertNotIn('qualification',actual)
            self.assertEqual(refusal['error'],'ValueError' if case.get('behavior') or case.get('stage')=='serialize' else 'OSError')
        for path in root.glob('actual-*.json'):
            actual=entry.validate_receipt(path.read_bytes())
            self.assertTrue(actual['valid'] and actual['complete'] and actual['reaped'])
            self.assertTrue(all(actual['eof'].values()))
            self.assertFalse(actual['cleanup_uncertainty'])
            self.assertEqual(actual['returncode'],1 if actual['mode']=='fail' else 0)
        if (root/'attempted-capture.json').exists():
            self.assertEqual(entry.strict_json((root/'attempted-capture.json').read_bytes()),
                             entry.strict_json((root/('actual-'+mode+'.json')).read_bytes()))
        modes=('pass','fail','suite');index=modes.index(mode)
        expected=list(modes[:index if case.get('stage')=='open' else index+1])
        if case.get('behavior')=='stale':expected.insert(0,'prior:'+mode)
        self.assertEqual((root/'launches').read_text().splitlines() if (root/'launches').exists() else [],expected)
        ledger=entry.strict_json((root/('ci-phase-'+mode+'.json')).read_bytes()) if (root/('ci-phase-'+mode+'.json')).stat().st_size else None
        self.assertTrue(ledger is None or not ledger['complete'])
        old={path:path.read_bytes() for path in root.rglob('*') if path.is_file()}
        # Replay uses the real public entry without the fault fixture.
        import subprocess
        replay=subprocess.run([sys.executable,'-I','-B',str(SOURCE)],env=env,capture_output=True,text=True,timeout=5)
        self.assertEqual(replay.returncode,1)
        for path,data in old.items():self.assertEqual(path.read_bytes(),data)
        for i in range(case.get('collisions',0)):
            self.assertEqual((root/('suite-closure-refusal-'+('f'*32)+'-'+str(i)+'.json')).read_bytes(),b'keep')
        self.assertNotIn('SECRET_SENTINEL',p.stderr)

    def test_public_capture_sink_faults_for_each_mode(self):
        for mode in ('pass','fail','suite'):
            for stage in ('write','flush','fsync','close'):
                with self.subTest(mode=mode,stage=stage),tempfile.TemporaryDirectory() as d:
                    self.check_fault(Path(d),dict(mode=mode,stage=stage))

    def test_public_result_and_finish_persistence_faults(self):
        for mode,stage in (('pass','write'),('fail','flush'),('suite','fsync'),('suite','close'),('pass','serialize')):
            with self.subTest(mode=mode,stage=stage),tempfile.TemporaryDirectory() as d:
                self.check_fault(Path(d),dict(mode=mode,stage=stage,sink='result'))
        with tempfile.TemporaryDirectory() as d:
            self.check_fault(Path(d),dict(mode='fail',stage='write',sink='ledger'))

    def test_public_untrustworthy_returns_for_each_mode(self):
        for mode in ('pass','fail','suite'):
            for behavior in ('null','stale'):
                with self.subTest(mode=mode,behavior=behavior),tempfile.TemporaryDirectory() as d:
                    self.check_fault(Path(d),dict(mode=mode,behavior=behavior))
        for behavior in ('scalar','malformed'):
            with self.subTest(behavior=behavior),tempfile.TemporaryDirectory() as d:
                self.check_fault(Path(d),dict(mode='suite',behavior=behavior))

    def test_public_next_mode_prelaunch_capture_is_reset(self):
        for mode in ('fail','suite'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as d:
                self.check_fault(Path(d),dict(mode=mode,stage='open'))

        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p,_=run_public_entry(root,dict(mode='fail',behavior='setup'))
            self.assertEqual(p.returncode,1,p.stderr)
            self.assertEqual((root/'launches').read_text(),'pass\n')
            self.assertFalse((root/'actual-fail.json').exists())
            outcome=entry.strict_json((root/'suite-closure/fail.json').read_bytes())
            self.assertEqual(outcome['reason'],'setup_error')
            self.assertFalse(outcome['success'] or outcome['qualification'])
            self.assertIsNone(outcome['pid'])
            self.assertEqual((root/'suite-closure/fail.jsonl').read_text(),'keep')
            self.assertFalse(list(root.glob('*-refusal-*')))

    def test_public_refusal_collisions_and_unavailable_root_keep_primary(self):
        for collisions in (1,4):
            with self.subTest(collisions=collisions),tempfile.TemporaryDirectory() as d:
                self.check_fault(Path(d),dict(mode='suite',stage='write',collisions=collisions))
        with tempfile.TemporaryDirectory() as d:
            self.check_fault(Path(d),dict(mode='fail',stage='serialize',sink='result',block_refusal=True))

    def test_public_fresh_outcomes_and_exact_negative_probe(self):
        for mode in (None,'pass','fail','suite'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as d:
                root=Path(d);p,_=run_public_entry(root,dict(mode=mode,behavior='unexpected' if mode else None))
                self.assertEqual(p.returncode,0 if mode is None else 1,p.stderr)
                expected=('pass','fail','suite') if mode is None else ('pass','fail','suite')[:('pass','fail','suite').index(mode)+1]
                self.assertEqual((root/'launches').read_text().splitlines(),list(expected))
                self.assertFalse(list(root.glob('*-refusal-*')))
                for current in expected:
                    actual=entry.validate_receipt((root/('actual-'+current+'.json')).read_bytes())
                    self.assertTrue(actual['reaped'] and all(actual['eof'].values()))
                    outcome=entry.strict_json((root/'suite-closure'/(current+'.json')).read_bytes())
                    self.assertEqual(outcome['qualification'],current=='suite' and mode is None)
                    ledger=entry.strict_json((root/('ci-phase-'+current+'.json')).read_bytes())
                    self.assertEqual(ledger['complete'],current!=mode)

    def test_public_modes_reject_malformed_parent_time_with_or_without_events(self):
        for mode in ('pass','fail','suite'):
            for bare in (False,True):
                for behavior in ('reversed','missing-collected'):
                    with self.subTest(mode=mode,bare=bare,behavior=behavior),tempfile.TemporaryDirectory() as d:
                        root=Path(d);p,_=run_public_entry(root,dict(mode=mode,bare=bare,behavior=behavior))
                        self.assertEqual(p.returncode,1,p.stderr)
                        actual=entry.validate_receipt((root/('actual-'+mode+'.json')).read_bytes())
                        returned=entry.strict_json((root/('returned-'+mode+'.json')).read_bytes())
                        self.assertEqual(actual['valid'],not bare)
                        self.assertGreaterEqual(actual['collected'],actual['launched'])
                        self.assertTrue(actual['reaped'] and all(actual['eof'].values()))
                        self.assertFalse(actual['cleanup_uncertainty'])
                        self.assertEqual(actual['returncode'],1 if mode=='fail' else 0)
                        self.assertEqual({k:v for k,v in actual.items() if k!='collected'},
                                         {k:v for k,v in returned.items() if k!='collected'})
                        with self.assertRaises(ValueError):entry.validate_receipt(json.dumps(returned))
                        self.assertFalse(entry.strict_json((root/('ci-phase-'+mode+'.json')).read_bytes())['complete'])
                        self.assertEqual((root/'suite-closure'/(mode+'.jsonl.receipt.json')).read_bytes(),b'')
                        self.assertFalse((root/'suite-closure'/(mode+'.json')).exists())
                        self.assertIn('ValueError; receipt unavailable',p.stderr)
                        modes=('pass','fail','suite')
                        self.assertEqual((root/'launches').read_text().splitlines(),list(modes[:modes.index(mode)+1]))

    def test_entry_refusal_schema_rejects_binding_and_flag_mutations(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);run_public_entry(root,dict(mode='suite',stage='write'))
            r=entry.validate_receipt(next(root.glob('*-refusal-*')).read_bytes())
            import copy
            for field,value in (('mode','pass'),('job','b'*64),('success',True),('qualification',True),('error','KeyError'),('capture',[])):
                invalid=copy.deepcopy(r);invalid[field]=value
                with self.subTest(field=field),self.assertRaises(ValueError):entry.validate_receipt(json.dumps(invalid))
            invalid=copy.deepcopy(r);invalid['capture']['qualification']=True
            with self.assertRaises(ValueError):entry.validate_receipt(json.dumps(invalid))

def collect_parent_shapes(root):
    from unittest.mock import patch
    import subprocess
    rows={}
    def collect(name,argv,**kwargs):
        path=root/(name+'.jsonl')
        receipt=entry.supervise(argv,path,kwargs.pop('timeout',2),echo=False,**kwargs)
        rows[name]=receipt
        assert entry.validate_receipt(path.with_suffix('.jsonl.receipt.json').read_bytes())==receipt
        return receipt
    (root/'setup.jsonl').write_text('keep')
    collect('setup',[sys.executable,'-I','-B','-c','raise AssertionError("must not launch")'])
    collect('spawn-error',[str(root/'absent-executable')])
    collect('no-events',[sys.executable,'-I','-B','-c','pass'])
    collect('timeout',[sys.executable,'-I','-B','-c','import time;time.sleep(.4)'],timeout=.05)
    collect('cap',[sys.executable,'-I','-B','-c',"print('x'*8192,flush=True)"],output_cap=1024)
    began=time.monotonic()
    collect('no-eof',[sys.executable,'-I','-B','-c',
        'import subprocess,sys;subprocess.Popen([sys.executable,"-I","-B","-c","import time;time.sleep(2.4)"])'],timeout=4)
    time.sleep(max(0,2.6-(time.monotonic()-began)))
    owned=[];popen=entry.subprocess.Popen
    def spawn(*args,**kwargs):
        child=popen(*args,**kwargs);owned.append(child)
        def unavailable():raise OSError('owned cleanup fault')
        child.terminate=unavailable
        return child
    release=root/'release'
    script='import time\nfrom pathlib import Path\np=Path(%r)\nend=time.monotonic()+2\nwhile not p.exists() and time.monotonic()<end:time.sleep(.01)\n' % str(release)
    try:
        with patch.object(entry.subprocess,'Popen',side_effect=spawn):
            collect('cleanup-unavailable',[sys.executable,'-I','-B','-c',script],cancelled=lambda:True)
    finally:
        release.touch()
        for child in owned:
            try:child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill();child.wait(timeout=2)
        (root/'post-wait.json').write_text(json.dumps([dict(pid=p.pid,returncode=p.returncode) for p in owned]))
    return rows


class ParentShapeTests(unittest.TestCase):
    def test_real_producer_shapes_keep_interval_and_cleanup_distinct(self):
        with tempfile.TemporaryDirectory() as d:
            rows=collect_parent_shapes(Path(d))
            for name,r in rows.items():
                self.assertEqual(entry.validate_receipt(json.dumps(r)),r)
                self.assertFalse(r['success'])
                if r['pid'] is None:
                    self.assertNotIn('launched',r)
                    self.assertNotIn('collected',r)
                    for key in ('launched','collected'):
                        with self.subTest(name=name,key=key),self.assertRaises(ValueError):
                            entry.validate_receipt(json.dumps(dict(r,**{key:0})))
                else:
                    self.assertGreaterEqual(r['collected'],r['launched'])
                    self.assertEqual(r['reaped'],r['returncode'] is not None)
                    if not r['reaped'] or not all(r['eof'].values()):
                        self.assertTrue(r['cleanup_uncertainty'])
                        with self.assertRaises(ValueError):
                            entry.validate_receipt(json.dumps(dict(r,cleanup_uncertainty=False)))
            self.assertEqual(rows['setup']['reason'],'setup_error')
            self.assertEqual(rows['spawn-error']['reason'],'spawn_error')
            self.assertTrue(rows['no-events']['reaped'] and all(rows['no-events']['eof'].values()))
            for name,reason in (('timeout','deadline'),('cap','output_cap'),('no-eof','no_eof'),('cleanup-unavailable','cancelled')):
                self.assertEqual(rows[name]['reason'],reason)
            unknown=rows['cleanup-unavailable']
            self.assertFalse(unknown['reaped'])
            self.assertIsNone(unknown['returncode'])
            self.assertTrue(unknown['cleanup_uncertainty'])
            self.assertEqual(unknown['cleanup_error'],'owned_child_cleanup_incomplete')
            self.assertEqual(json.loads((Path(d)/'post-wait.json').read_text()),[dict(pid=unknown['pid'],returncode=0)])
            with self.assertRaises(ValueError):
                entry.validate_receipt(json.dumps(dict(rows['no-events'],reason='spawn_error')))
            with self.assertRaises(ValueError):
                entry.validate_receipt(json.dumps(dict(rows['spawn-error'],reason=None)))

if __name__ == '__main__': unittest.main()
