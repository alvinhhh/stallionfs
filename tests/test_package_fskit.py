"""Package profile refusal cases; actual compiler matrix is in test_fskit."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('package_fskit', Path(__file__).resolve().parents[1] / 'tools/package_fskit.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackageProfileTests(unittest.TestCase):
    def test_complete_uniform_architecture_profiles_and_requested_policy(self):
        data = b'exact executable bytes for tool-boundary fixture'
        for policy, marker in (('read-only', '_stallionfs_factory_read_only_v1'),
                               ('contextual-writes', '_stallionfs_factory_contextual_writes_v1')):
            def inspect(argv, directory):
                self.assertEqual(Path(argv[-1]).read_bytes(), data)
                if argv[0] == '/usr/bin/lipo': return 'arm64 x86_64\n'
                self.assertIn(argv[2], ('arm64', 'x86_64'))
                return '_other_defined_symbol\n' + marker + '\n'
            with patch.object(package, '_tool_output', side_effect=inspect):
                result = package.compiled_factory_profile(data, policy)
                self.assertEqual(result, {'schema': 1, 'policy': policy,
                    'architectures': ['arm64', 'x86_64'], 'pre_sign_sha256': hashlib.sha256(data).hexdigest()})
                with self.assertRaises(ValueError):
                    package.compiled_factory_profile(data, 'contextual-writes' if policy == 'read-only' else 'read-only')

    def test_missing_contradictory_mixed_and_incomplete_profiles_are_refused(self):
        readonly, writable = '_stallionfs_factory_read_only_v1\n', '_stallionfs_factory_contextual_writes_v1\n'
        for responses in ([''], ['arm64 arm64'], ['unknown'], ['arm64', ''],
                          ['arm64', readonly + writable], ['arm64', writable + writable],
                          ['arm64 x86_64', readonly, writable]):
            with self.subTest(responses=responses), patch.object(package, '_tool_output', side_effect=responses):
                with self.assertRaises(ValueError): package.compiled_factory_profile(b'fixture')

    def test_tools_require_success_complete_output_and_deadline(self):
        for mode in ('status', 'oversize', 'encoding', 'timeout'):
            def run(argv, **kwargs):
                self.assertEqual(kwargs['timeout'], 30)
                self.assertIs(kwargs['stdout'], kwargs['stderr'])
                if mode == 'timeout': raise subprocess.TimeoutExpired(argv, 30)
                kwargs['stdout'].write(b'x' * (package.PROFILE_OUTPUT_LIMIT + 1) if mode == 'oversize'
                                       else b'\xff' if mode == 'encoding' else b'failed')
                return subprocess.CompletedProcess(argv, 1 if mode == 'status' else 0)
            with self.subTest(mode=mode), patch.object(package.subprocess, 'run', side_effect=run):
                with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                    package._tool_output(['/usr/bin/nm', 'fixture'], None)

    def test_inspected_executable_cannot_change_before_copy(self):
        def inspect(argv, directory):
            if argv[0] == '/usr/bin/lipo': return 'arm64'
            Path(argv[-1]).write_bytes(b'substituted')
            return '_stallionfs_factory_contextual_writes_v1\n'
        with patch.object(package, '_tool_output', side_effect=inspect):
            with self.assertRaises(ValueError): package.compiled_factory_profile(b'original')
