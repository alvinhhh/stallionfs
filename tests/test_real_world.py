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
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    'real_world_benchmark', Path(__file__).parent / 'perf' / 'real_world.py')
BENCHMARK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCHMARK)


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

    def check_uncertain_failure(self, failure):
        failure.process_group_uncertain = True
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
                    raise failure
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
            self.assertTrue(any(type(failure).__name__ in error for error in report['errors']))
            self.assertTrue((Path(report['scratch']) / 'source/d000/f000000').is_file())
            self.assertTrue((Path(report['scratch']) / 'sentinel').is_file())

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
