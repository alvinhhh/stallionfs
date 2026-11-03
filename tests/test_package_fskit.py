"""Package profile refusal cases; actual compiler matrix is in test_fskit."""
import hashlib
import importlib.util
from contextlib import redirect_stdout
import io
import json
import os
import plistlib
import sys
from types import SimpleNamespace
import tempfile
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
        for tool, mode in ((tool, mode) for tool in ('nm', 'otool')
                           for mode in ('status', 'oversize', 'encoding', 'timeout')):
            def run(argv, **kwargs):
                self.assertEqual(kwargs['timeout'], 30)
                self.assertIs(kwargs['stdout'], kwargs['stderr'])
                if mode == 'timeout': raise subprocess.TimeoutExpired(argv, 30)
                kwargs['stdout'].write(b'x' * (package.PROFILE_OUTPUT_LIMIT + 1) if mode == 'oversize'
                                       else b'\xff' if mode == 'encoding' else b'failed')
                return subprocess.CompletedProcess(argv, 1 if mode == 'status' else 0)
            with self.subTest(mode=mode), patch.object(package.subprocess, 'run', side_effect=run):
                with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                    package._tool_output(['/usr/bin/' + tool, 'fixture'], None)

    def test_inspected_executable_cannot_change_before_copy(self):
        def inspect(argv, directory):
            if argv[0] == '/usr/bin/lipo': return 'arm64'
            Path(argv[-1]).write_bytes(b'substituted')
            return '_stallionfs_factory_contextual_writes_v1\n'
        with patch.object(package, '_tool_output', side_effect=inspect):
            with self.assertRaises(ValueError): package.compiled_factory_profile(b'original')


# Exact deployment-command form retained from ordinary Apple arm64 tool output.
APPLE_BUILD_VERSION = """Load command 11
      cmd LC_BUILD_VERSION
  cmdsize 32
 platform 1
    minos 27.0
      sdk 27.0
   ntools 1
     tool 3
  version 27037.1
Load command 12
      cmd LC_SOURCE_VERSION
  cmdsize 16
  version 0.0
"""


class PackageCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.host = self.base / 'host'
        self.extension = self.base / 'module'
        self.host.write_bytes(b'host executable fixture')
        self.extension.write_bytes(b'module executable fixture')
        self.host.chmod(0o700)
        self.extension.chmod(0o700)
        self.app = self.base / 'Candidate.app'
        self.manifest = self.base / 'candidate.json'
        self.inventories = {'host': 'arm64', 'extension': 'arm64'}
        self.targets = {}
        self.templates = package._load_templates()
        old_mask = os.umask(0o077)
        self.addCleanup(os.umask, old_mask)

    def inspect(self, argv, directory):
        name = Path(argv[-1]).name
        expected = self.host.read_bytes() if name == 'host' else self.extension.read_bytes()
        self.assertEqual(Path(argv[-1]).read_bytes(), expected)
        if argv[0] == '/usr/bin/lipo':
            return self.inventories[name]
        if argv[0] == '/usr/bin/nm':
            return '_stallionfs_factory_contextual_writes_v1\n'
        self.assertEqual(argv[:2], ['/usr/bin/otool', '-arch'])
        self.assertEqual(argv[3], '-l')
        return self.targets.get((name, argv[2]), APPLE_BUILD_VERSION)

    def admission(self, host_floor='27.0', module_floor='27.0'):
        with patch.object(package, '_tool_output', side_effect=self.inspect):
            return package.inspect_package_artifacts(self.host.read_bytes(), self.extension.read_bytes(),
                                                     host_floor, module_floor, 'contextual-writes')

    def assemble(self, manifest=True):
        argv = ['package_fskit.py', '--host', str(self.host), '--extension', str(self.extension),
                '--out', str(self.app), '--bundle-version', '9', '--access-policy', 'contextual-writes']
        if manifest:
            argv += ['--manifest-out', str(self.manifest)]
        self.stdout = io.StringIO()
        with patch.object(sys, 'argv', argv), redirect_stdout(self.stdout), \
                patch.object(package, '_load_templates', return_value=[
                    plistlib.loads(plistlib.dumps(value)) for value in self.templates]), \
                patch.object(package, '_tool_output', side_effect=self.inspect):
            package.main()

    def test_matching_known_universal_sets_and_independent_targets(self):
        # Synthetic inventories cover admission, not installed architecture support.
        self.inventories = {'host': 'x86_64 arm64e arm64', 'extension': 'arm64 x86_64 arm64e'}
        for name, architecture, minimum, sdk in (
                ('host', 'arm64', '26', '28.1'), ('host', 'arm64e', '25.3.1', '27'),
                ('extension', 'x86_64', '26.2', '26.3')):
            self.targets[name, architecture] = APPLE_BUILD_VERSION.replace('minos 27.0', 'minos ' + minimum).replace('sdk 27.0', 'sdk ' + sdk)
        factory, targets = self.admission('28', '27.0.0')
        self.assertEqual(factory['architectures'], ['arm64', 'x86_64', 'arm64e'])
        self.assertEqual([item['architecture'] for item in targets[0]], ['arm64', 'arm64e', 'x86_64'])
        self.assertEqual(targets[0][0]['minimum_os'], '26')
        self.assertEqual(targets[1][2]['sdk'], '26.3')
        for version in ('27', '27.0', '27.0.0'):
            self.admission(version, version)

    def test_invalid_architecture_inventories_refuse(self):
        for inventory in ('', 'arm64 arm64', 'unknown', 'arm64 x86_64'):
            for name in ('host', 'extension'):
                with self.subTest(name=name, inventory=inventory):
                    self.inventories = {'host': 'arm64', 'extension': 'arm64'}
                    self.inventories[name] = inventory
                    with self.assertRaises(ValueError): self.admission()

    def test_deployment_command_ambiguity_and_versions_refuse(self):
        invalid = [
            '', APPLE_BUILD_VERSION.replace('LC_BUILD_VERSION', 'LC_VERSION_MIN_MACOSX'),
            APPLE_BUILD_VERSION + APPLE_BUILD_VERSION,
            APPLE_BUILD_VERSION + 'Load command 13\n cmd LC_VERSION_MIN_MACOSX\n version 27.0\n sdk 27.0\n',
            APPLE_BUILD_VERSION.replace('      sdk 27.0\n', ''),
            APPLE_BUILD_VERSION.replace('platform 1', 'platform 2'),
            APPLE_BUILD_VERSION.replace('platform 1', 'platform macos'),
            APPLE_BUILD_VERSION.replace('    minos 27.0\n', ''),
            APPLE_BUILD_VERSION.replace('platform 1', 'platform 1\n platform 1'),
            APPLE_BUILD_VERSION.replace('minos 27.0', 'minos 27.0\n minos 26.0'),
            APPLE_BUILD_VERSION.replace('sdk 27.0', 'sdk 27.0\n sdk'),
            APPLE_BUILD_VERSION.replace('cmd LC_BUILD_VERSION', 'cmd LC_BUILD_VERSION\n cmd LC_BUILD_VERSION extra'),
            APPLE_BUILD_VERSION.replace('sdk 27.0', 'sdk 26.0'),
        ]
        for version in ('-1', '27.beta', '27.0.0.1', '27..0', ''):
            invalid.append(APPLE_BUILD_VERSION.replace('minos 27.0', 'minos ' + version))
            invalid.append(APPLE_BUILD_VERSION.replace('sdk 27.0', 'sdk ' + version))
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(ValueError):
                package._deployment_target(text, 'arm64')
        for host_floor, module_floor in (('26', '26'), ('27', '28'), ('invalid', '27'), ('27', None)):
            with self.subTest(floors=(host_floor, module_floor)), self.assertRaises(ValueError):
                self.admission(host_floor, module_floor)
        self.targets['extension', 'arm64'] = APPLE_BUILD_VERSION.replace('minos 27.0', 'minos 28').replace('sdk 27.0', 'sdk 28')
        with self.assertRaises(ValueError): self.admission('28', '27')

    def test_target_tool_failure_and_private_copy_substitution_refuse(self):
        original = self.inspect
        for mode in ('failure', 'substitution'):
            def inspect(argv, directory):
                result = original(argv, directory)
                if argv[0] == '/usr/bin/otool':
                    if mode == 'failure': raise ValueError('tool failure')
                    if Path(argv[-1]).name == 'extension':
                        Path(argv[-1]).write_bytes(b'substituted')
                return result
            with self.subTest(mode=mode), patch.object(package, '_tool_output', side_effect=inspect):
                with self.assertRaises(ValueError):
                    package.inspect_package_artifacts(self.host.read_bytes(), self.extension.read_bytes(), '27', '27')

    def test_default_output_and_complete_deterministic_manifest(self):
        self.assemble(False)
        self.assertEqual(self.stdout.getvalue(), 'Unsigned package: ' + str(self.app) + '\n')
        self.assertFalse(self.manifest.exists())
        self.app = self.base / 'WithManifest.app'
        self.assemble()
        first = self.manifest.read_bytes()
        value = json.loads(first)
        self.assertEqual(value['kind'], 'fskit-unsigned-assembly-candidate')
        self.assertEqual(value['assembly'], 'no-signing-performed')
        self.assertEqual(value['architectures'], ['arm64'])
        self.assertEqual(value['factory_policy'], 'contextual-writes')
        self.assertEqual(self.manifest.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(value['pre_sign_package_files']), 4)
        for row in value['pre_sign_package_files']:
            self.assertEqual(row['sha256'], hashlib.sha256((self.app / row['path']).read_bytes()).hexdigest())
        for name, binary in (('host', self.host), ('module', self.extension)):
            self.assertEqual(value[name]['declared_minimum_os'], '27.0')
            self.assertEqual(value[name]['slices'], [{'architecture': 'arm64', 'platform': 'macos', 'minimum_os': '27.0', 'sdk': '27.0'}])
            self.assertEqual(value[name]['pre_sign_input_sha256'], hashlib.sha256(binary.read_bytes()).hexdigest())
        for directory in [self.app] + [path for path in self.app.rglob('*') if path.is_dir()]:
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.app = self.base / 'Another.app'
        self.manifest = self.base / 'another.json'
        self.assemble()
        self.assertEqual(self.manifest.read_bytes(), first)

    def test_existing_paths_symlinks_and_invalid_locations_refuse(self):
        original = self.manifest
        existing = self.base / 'existing.json'
        existing.write_bytes(b'preserve')
        dangling = self.base / 'dangling.json'
        dangling.symlink_to(self.base / 'missing')
        link = self.base / 'link.json'
        link.symlink_to(existing)
        other = self.base / 'other'
        other.mkdir()
        for location in (existing, dangling, link, self.app / 'inside.json', other / 'sibling.json',
                         self.base / 'missing-parent' / 'receipt.json', self.base / 'receipt.txt'):
            self.manifest = location
            with self.subTest(location=location), self.assertRaises((ValueError, OSError)):
                self.assemble()
            self.assertFalse(self.app.exists())
        self.assertEqual(existing.read_bytes(), b'preserve')
        self.assertTrue(dangling.is_symlink())
        self.manifest = original
        self.assemble()
        previous = self.manifest.read_bytes()
        with self.assertRaises(SystemExit): self.assemble()
        self.assertEqual(self.manifest.read_bytes(), previous)

    def test_exclusive_reservation_race_and_inspection_failure_leave_no_app(self):
        real_open = package.os.open
        def race(path, flags, *args, **kwargs):
            if flags & os.O_EXCL:
                self.manifest.write_bytes(b'race winner')
            return real_open(path, flags, *args, **kwargs)
        with patch.object(package.os, 'open', side_effect=race), self.assertRaises(FileExistsError):
            self.assemble()
        self.assertEqual(self.manifest.read_bytes(), b'race winner')
        self.assertFalse(self.app.exists())
        self.manifest = self.base / 'inspection.json'
        self.targets['host', 'arm64'] = ''
        with self.assertRaises(ValueError): self.assemble()
        self.assertFalse(self.manifest.exists())
        self.assertFalse(self.app.exists())

    def test_assembly_and_manifest_failures_retain_partial_outputs_without_success(self):
        real_write = package.write_new
        def fail_assembly(path, data, mode):
            if path.is_relative_to(self.app): raise OSError('assembly failed')
            return real_write(path, data, mode)
        for failure in ('assembly', 'short', 'write'):
            self.app = self.base / (failure + '.app')
            self.manifest = self.base / (failure + '.json')
            if failure == 'assembly':
                context = patch.object(package, 'write_new', side_effect=fail_assembly)
            elif failure == 'short':
                context = patch.object(package.os, 'write', return_value=1)
            else:
                context = patch.object(package.os, 'write', side_effect=OSError('manifest failed'))
            with context, self.assertRaises(OSError): self.assemble()
            self.assertTrue(self.app.is_dir())
            self.assertTrue(self.manifest.is_file())
            self.assertEqual(self.stdout.getvalue(), '')
            with self.assertRaises(SystemExit): self.assemble()

    def test_reserved_descriptor_identity_and_content_are_checked(self):
        for mode in ('replacement', 'unlink', 'hardlink', 'readback'):
            location = self.base / (mode + '.json')
            parent, descriptor = package._reserve_manifest(location)
            try:
                if mode in ('replacement', 'unlink'):
                    location.unlink()
                    if mode == 'replacement': location.write_bytes(b'replacement')
                elif mode == 'hardlink':
                    os.link(location, self.base / 'second-link')
                context = patch.object(package.os, 'read', return_value=b'wrong') if mode == 'readback' else patch.object(package.os, 'fsync', wraps=os.fsync)
                with context, self.assertRaises(OSError):
                    package._write_manifest(parent, descriptor, location, {'schema': 1})
                if mode == 'replacement': self.assertEqual(location.read_bytes(), b'replacement')
            finally:
                os.close(descriptor)
                os.close(parent)


    def test_template_and_staged_copy_failures_are_truthful(self):
        self.templates[0].pop('CFBundleIdentifier')
        with self.assertRaises(ValueError): self.assemble()
        self.assertFalse(self.app.exists())
        self.assertFalse(self.manifest.exists())
        path = self.base / 'staged'
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(OSError, 'Package copy mismatch'):
            package._candidate_manifest(SimpleNamespace(), [], [], {}, [(path, b'original', 0o755)], self.base)

    def test_reserved_parent_descriptor_anchors_the_manifest_write(self):
        directory = self.base / 'parent'
        directory.mkdir()
        location = directory / 'receipt.json'
        parent, descriptor = package._reserve_manifest(location)
        moved = self.base / 'moved-parent'
        try:
            directory.rename(moved)
            directory.mkdir()
            replacement = directory / 'receipt.json'
            replacement.write_bytes(b'preserve different parent')
            package._write_manifest(parent, descriptor, location, {'schema': 1})
            self.assertEqual(json.loads((moved / 'receipt.json').read_bytes()), {'schema': 1})
            self.assertEqual(replacement.read_bytes(), b'preserve different parent')
        finally:
            os.close(descriptor)
            os.close(parent)
