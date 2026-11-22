"""Verify that failed scan samples retain evidence without exporting their output."""
import base64
import hashlib
import importlib.util
from pathlib import Path
import unittest


class HostedScanProjection(unittest.TestCase):
    def test_failed_stdout_is_hashed_without_transfer_limit(self):
        tools = Path(__file__).resolve().parents[1] / 'tools'
        spec = importlib.util.spec_from_file_location('ci_native_scan', tools / 'ci_native_scan.py')
        lane = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lane)
        binary = Path('/installed/bin/sfs')
        fixture = Path('/fixture')
        row = {
            'fixture': 'empty', 'output': 'plain', 'phase': 'timing',
            'case_id': 'cli/scan/empty', 'operation': 'scan', 'reference': 'find-stat',
            'cache': 'warm', 'fixture_policy': 'cli-scan-original-counts-v1',
            'method': 'candidate', 'pair_id': 1, 'warmup': False,
            'argv': [str(binary), 'scan', str(fixture / 'empty')],
            'correctness': {'passed': False},
        }
        for size in (65536, 65537):
            with self.subTest(size=size):
                stdout = b'x' * size
                row['stdout_b64'] = base64.b64encode(stdout).decode('ascii')
                result = lane.sample(row, None, binary, fixture, 'apfs', {})
                self.assertFalse(result['correctness_passed'])
                self.assertNotIn('stdout_b64', result)
                self.assertEqual(result['stdout_sha256'], hashlib.sha256(stdout).hexdigest())

        row['correctness'] = {'passed': True}
        with self.assertRaisesRegex(ValueError, 'Scan output exceeds transfer limit'):
            lane.sample(row, None, binary, fixture, 'apfs', {})
