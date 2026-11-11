"""Bounded bootstrap capture checks using private Python children."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch


_spec = importlib.util.spec_from_file_location(
    '_git_build_capture_tests', Path(__file__).resolve().parents[1] / 'tools/_git_capture.py')
capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture)


class GitBuildCaptureTests(unittest.TestCase):
    def setUp(self):
        receipts = os.environ.get('STALLIONFS_CAPTURE_TEST_RECEIPTS')
        if receipts:
            self.root = Path(tempfile.mkdtemp(prefix='capture-', dir=receipts))
        else:
            temporary = tempfile.TemporaryDirectory(prefix='sfs-build-capture-')
            self.addCleanup(temporary.cleanup)
            self.root = Path(temporary.name)
        self.children = []
        self.pipe_names = {}
        self.eof = set()
        self.group_operations = []
        self.patch('_command_state', {'failure': None, 'active': None,
                                     'first_signal': None, 'signal_count': 0})
        self.patch('_COMMAND_ENV', {'PATH': os.defpath, 'HOME': str(self.root), 'LC_ALL': 'C'})
        popen, read, killpg = subprocess.Popen, os.read, os.killpg

        def spawn(*args, **kwargs):
            self.assertEqual(args[0][0], sys.executable)
            self.assertTrue(kwargs['start_new_session'])
            self.assertEqual(kwargs['env'], capture._COMMAND_ENV)
            child = popen(*args, **kwargs)
            self.children.append(child)
            for name in ('stdout', 'stderr'):
                self.pipe_names[getattr(child, name).fileno()] = (child.pid, name)
            return child

        def observed_read(descriptor, size):
            data = read(descriptor, size)
            if not data and descriptor in self.pipe_names:
                self.eof.add(self.pipe_names[descriptor])
            return data

        def owned_group_operation(group, number):
            owned = [child for child in self.children if child.pid == group]
            self.assertEqual(len(owned), 1, 'Group operation requires a retained child handle')
            reaped = owned[0].returncode is not None
            self.group_operations.append({'pid': group, 'signal': number, 'leader_reaped': reaped})
            if reaped:
                self.assertEqual(number, 0, 'No mutating group signal after leader reaping')
                # A single-child fixture has no group members after its leader exits.
                raise ProcessLookupError
            return killpg(group, number)

        self.patch_object(capture.subprocess, 'Popen', Mock(side_effect=spawn))
        self.patch_object(capture.os, 'read', observed_read)
        self.patch_object(capture.os, 'killpg', owned_group_operation)
        self.addCleanup(self.finish_children)

    def patch(self, name, value):
        return self.patch_object(capture, name, value)

    def patch_object(self, target, name, value):
        context = patch.object(target, name, value)
        result = context.start()
        self.addCleanup(context.stop)
        return result

    def reset_state(self):
        capture._command_state.update(failure=None, active=None, first_signal=None, signal_count=0)

    def finish_children(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
            child.stdout.close()
            child.stderr.close()
        (self.root / 'owned-children.json').write_text(json.dumps({
            'children': [{'pid': child.pid, 'returncode': child.returncode} for child in self.children],
            'eof_streams': sorted(self.eof), 'group_operations': self.group_operations,
        }, indent=2) + '\n')

    def command(self, source, label, timeout=3):
        return capture._owned_command([sys.executable, '-I', '-S', '-B', '-c', source],
                                      cwd=self.root, timeout=timeout, stem=self.root / label)

    def receipt(self, label):
        return json.loads((self.root / (label + '.command.json')).read_text())

    def assert_reaped_and_eof(self, child):
        self.assertIsNotNone(child.returncode)
        self.assertEqual(child.wait(timeout=0), child.returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(child.pid, os.WNOHANG)
        self.assertIn((child.pid, 'stdout'), self.eof)
        self.assertIn((child.pid, 'stderr'), self.eof)

    def test_success_retains_both_streams_through_eof_and_reaps_child(self):
        stdout, stderr = b'o' * 100000, b'e' * 80000
        result = self.command('import os; os.write(1, b"o" * 100000); os.write(2, b"e" * 80000)', 'success')
        self.assertEqual((result.returncode, result.stdout.encode(), result.stderr.encode()),
                         (0, stdout, stderr))
        record = self.receipt('success')
        self.assertEqual(record['phase'], 'done')
        self.assertIsNone(record['first_failure'])
        self.assertFalse(record['cleanup_uncertain'])
        self.assertEqual(record['kill_attempts'], 0)
        for name, data in (('stdout', stdout), ('stderr', stderr)):
            self.assertEqual(Path(record[name + '_path']).read_bytes(), data)
            self.assertEqual(record[name + '_retained_bytes'], len(data))
            self.assertEqual(record[name + '_discarded_bytes'], 0)
        self.assertEqual(capture._command_state['active'], None)
        self.assert_reaped_and_eof(self.children[0])

    def test_nonzero_exit_retains_receipts_and_refuses_later_commands(self):
        result = self.command('import os; os.write(1,b"out\\n"); os.write(2,b"err\\n"); raise SystemExit(7)', 'nonzero')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (7, 'out\n', 'err\n'))
        record = self.receipt('nonzero')
        self.assertEqual(record['first_failure'], {'kind': 'exit', 'detail': 'nonzero: 7'})
        self.assertEqual(record['returncode'], 7)
        self.assertTrue(record['cleanup_uncertain'])
        self.assertEqual(record['group_signal_skipped_reason'], 'leader_already_reaped')
        self.assertIsNone(record['group_alive_after_cleanup'])
        self.assert_reaped_and_eof(self.children[0])
        before = len(self.children)
        with self.assertRaisesRegex(RuntimeError, 'Further build commands refused'):
            self.command('raise SystemExit(0)', 'refused')
        self.assertEqual(len(self.children), before)
        self.assertFalse((self.root / 'refused.started.json').exists())
        self.assertEqual(capture._command_state['failure'], record['first_failure'])

    def test_each_stream_cap_retains_prefix_drains_and_reaps(self):
        self.patch('_COMMAND_STREAM_CAP', 4096)
        for descriptor, name in ((1, 'stdout'), (2, 'stderr')):
            with self.subTest(stream=name):
                self.reset_state()
                with self.assertRaisesRegex(RuntimeError, 'capture limit'):
                    self.command(f'import os; os.write({descriptor}, b"x" * 65536)', name + '-cap')
                record = self.receipt(name + '-cap')
                self.assertEqual(record['cap_reached'], [name])
                self.assertEqual(record[name + '_retained_bytes'], 4096)
                self.assertEqual(Path(record[name + '_path']).read_bytes(), b'x' * 4096)
                self.assertGreater(record[name + '_discarded_bytes'], 0)
                self.assertEqual(record['first_failure']['kind'], 'capture_limit')
                self.assertFalse(record['timeout'])
                self.assert_reaped_and_eof(self.children[-1])
                self.assertIsNone(capture._command_state['active'])

    def test_timeout_retains_partial_streams_kills_and_reaps_direct_child(self):
        source = 'import os,time; os.write(1,b"begin out\\n"); os.write(2,b"begin err\\n"); time.sleep(10)'
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            self.command(source, 'timeout', timeout=0.5)
        self.assertEqual(caught.exception.output, b'begin out\n')
        self.assertEqual(caught.exception.stderr, b'begin err\n')
        record = self.receipt('timeout')
        self.assertTrue(record['timeout'])
        self.assertEqual(record['first_failure'], {'kind': 'timeout', 'detail': 'timeout'})
        self.assertEqual(record['kill_attempts'], 1)
        self.assertEqual(record['returncode'], -signal.SIGKILL)
        self.assertEqual(record['stdout_discarded_bytes'], 0)
        self.assertEqual(record['stderr_discarded_bytes'], 0)
        self.assert_reaped_and_eof(self.children[0])

    def test_first_error_latch_survives_cancellation_and_refuses_launch(self):
        capture._latch_command('capture_limit', 'first')
        capture._latch_command('timeout', 'later')
        capture._cancel_command(signal.SIGTERM, None, state=capture._command_state)
        self.assertEqual(capture._command_state['failure'], {'kind': 'capture_limit', 'detail': 'first'})
        self.assertEqual(capture._command_state['first_signal'], signal.SIGTERM)
        with self.assertRaisesRegex(RuntimeError, 'Further build commands refused'):
            self.command('raise SystemExit(0)', 'latched')
        capture.subprocess.Popen.assert_not_called()
        self.assertFalse((self.root / 'latched.started.json').exists())

    def test_reaped_leader_skips_mutating_group_signals_and_marks_uncertainty(self):
        for returncode, group_alive in ((7, False), (0, True)):
            with self.subTest(returncode=returncode, group_alive=group_alive):
                self.reset_state()
                pipes = []
                for _ in range(2):
                    descriptor, writer = os.pipe()
                    os.close(writer)
                    pipes.append(os.fdopen(descriptor, 'rb', buffering=0))
                process = SimpleNamespace(pid=424242, returncode=returncode,
                    stdout=pipes[0], stderr=pipes[1], poll=Mock(return_value=returncode),
                    wait=Mock(return_value=returncode))
                label = 'reaped-' + str(returncode)
                observation = Mock(return_value=None) if group_alive else Mock(side_effect=ProcessLookupError)
                with patch.object(capture.subprocess, 'Popen', return_value=process), \
                        patch.object(capture.os, 'killpg', observation):
                    if group_alive:
                        with self.assertRaisesRegex(RuntimeError, 'process group alive'):
                            self.command('raise SystemExit(0)', label)
                    else:
                        self.assertEqual(self.command('raise SystemExit(7)', label).returncode, 7)
                observation.assert_called_once_with(process.pid, 0)
                record = self.receipt(label)
                self.assertEqual(record['kill_attempts'], 0)
                self.assertEqual(record['group_signal_skipped_reason'], 'leader_already_reaped')
                self.assertEqual(record['group_ownership_after_cleanup'], 'unknown_after_reap')
                self.assertIsNone(record['group_alive_after_cleanup'])
                self.assertTrue(record['cleanup_uncertain'])
                self.assertIsNone(capture._command_state['active'])

    def test_handler_install_restore_and_closed_cancellation_state(self):
        previous = {number: object() for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
        with patch.object(capture.signal, 'signal', side_effect=lambda number, handler: previous[number]) as install:
            restored = capture._install_command_handlers()
            self.assertEqual(restored, previous)
            handler = install.call_args_list[0].args[1]
            handler(signal.SIGTERM, None)
            handler(signal.SIGINT, None)
            self.assertEqual(capture._command_state['first_signal'], signal.SIGTERM)
            self.assertEqual(capture._command_state['signal_count'], 2)
            self.assertEqual(capture._command_state['failure']['kind'], 'cancelled')
            capture._command_state['cancellation_closed'] = True
            handler(signal.SIGHUP, None)
            self.assertEqual(capture._command_state['signal_count'], 2)
            capture._restore_command_handlers(restored)
            self.assertEqual(install.call_args_list[-3:],
                             [call(number, previous[number]) for number in previous])
        capture.subprocess.Popen.assert_not_called()


if __name__ == '__main__':
    unittest.main()
