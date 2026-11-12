"""Package profile refusal cases; actual compiler matrix is in test_fskit."""
import ast
import hashlib
import base64
import zipfile
import importlib.util
from contextlib import redirect_stdout
import io
import json
import os
import plistlib
import stat
import sys
from types import SimpleNamespace
import tempfile
from pathlib import Path
import subprocess
import tarfile
import tomllib
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('package_fskit', Path(__file__).resolve().parents[1] / 'tools/package_fskit.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class ProductVersions(unittest.TestCase):
    def test_product_declarations_and_package_templates_agree(self):
        source = Path(__file__).resolve().parents[1]
        project = tomllib.loads((source / 'pyproject.toml').read_text())
        module = ast.parse((source / 'stallionfs/__init__.py').read_text())
        version = next(ast.literal_eval(node.value) for node in module.body
                       if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == '__version__' for target in node.targets))
        self.assertEqual(package.PACKAGE_VERSION, '0.7.0')
        self.assertEqual(project['project']['version'], package.PACKAGE_VERSION)
        self.assertEqual(version, package.PACKAGE_VERSION)
        for template in package._load_templates():
            self.assertEqual(template['CFBundleShortVersionString'], package.PACKAGE_VERSION)
            self.assertEqual(template['CFBundleVersion'], '__BUNDLE_VERSION__')


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

    def test_runtime_inputs_require_an_external_manifest_before_inspection(self):
        argv = ['package_fskit.py', '--host', str(self.host), '--extension', str(self.extension),
                '--out', str(self.app), '--bundle-version', '9', '--runtime-inputs', str(self.base / 'inputs.json')]
        with patch.object(sys, 'argv', argv), patch.object(package, 'inspect_package_artifacts') as inspect, \
                patch.object(sys, 'stderr', io.StringIO()), self.assertRaises(SystemExit):
            package.main()
        inspect.assert_not_called()
        self.assertFalse(self.app.exists())

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


SOURCE = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def put(path, data=b'fixture', mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


def pinned(path):
    return {'path': str(path), 'sha256': digest(path.read_bytes())}


def json_file(path, value):
    return put(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


class RuntimeAssembly(unittest.TestCase):
    def setUp(self):
        old = os.umask(0o077)
        self.addCleanup(os.umask, old)
        self.temporary = tempfile.TemporaryDirectory(prefix='package-runtime-', dir=SOURCE.parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.bundle = package._runtime_bundle()
        bundle_patch = patch.object(package, '_runtime_bundle', return_value=self.bundle)
        bundle_patch.start()
        self.addCleanup(bundle_patch.stop)

    def inputs(self):
        python = self.root / 'python'
        put(python / 'bin/python3.13', b'inert interpreter', 0o755)
        put(python / 'lib/python3.13/encodings/__init__.py', b'# inert stdlib\n')
        (python / 'lib/python3.13/lib-dynload').mkdir()
        metadata = {'python_version': '3.13.18', 'python_tag': 'cp313', 'target_triple': 'aarch64-apple-darwin',
                    'python_config_vars': {'SOABI': 'cpython-313-darwin', 'EXT_SUFFIX': '.cpython-313-darwin.so',
                                           'Py_GIL_DISABLED': '0', 'Py_DEBUG': '0'}}
        license_path = put(self.root / 'metadata/licenses/LICENSE', b'Python license fixture')
        records = {'licenses': [{'path': 'licenses/LICENSE', 'sha256': digest(license_path.read_bytes()),
                                  'size': license_path.stat().st_size}]}
        descriptor = {'python_exe': 'bin/python3.13', 'python_root': str(python),
                      'license_root': str(license_path.parent)}
        for name, data in {'python_archive': b'archive fixture', 'full_archive': b'full fixture',
                           'python_inventory': json.dumps(package._runtime_inventory(python)).encode(),
                           'metadata': json.dumps(metadata).encode(), 'static_receipt': b'{}',
                           'license_records': json.dumps(records).encode()}.items():
            path = put(self.root / (name + '.input'), data)
            descriptor['metadata_file' if name == 'metadata' else name] = str(path)
            descriptor[name + '_sha256'] = digest(data)
        python_descriptor = json_file(self.root / 'python.json', descriptor)
        git = self.root / 'git'
        put(git / 'bin/git', b'inert git', 0o700)
        (git / 'libexec/git-core').mkdir(parents=True)
        (git / 'share/git-core/templates').mkdir(parents=True)
        put(git / 'share/git-core/templates/template', b'inert template', 0o600)
        (git / 'libexec/git-core/git').symlink_to('../../bin/git')
        inventory = json_file(self.root / 'git-tree.json', package._runtime_inventory(git))
        qualification = json_file(self.root / 'git-qualification.json', {
            'schema': 1, 'inventory_sha256': digest(inventory.read_bytes()),
            'static_closure_accepted': True, 'local_correctness_passed': True, 'synthetic_fixture': True})
        sources = {path.relative_to(SOURCE).as_posix(): path.read_bytes()
                   for path in (SOURCE / 'stallionfs').iterdir() if path.is_file() and path.suffix in ('.py', '.c', '.h')}
        sources.update({name: (SOURCE / name).read_bytes() for name in ('setup.py', 'pyproject.toml',
            'tools/build_git_runtime.py', 'tools/_git_capture.py',
            *('tools/git-inputs/' + name for name in ('combined.patch', 'notices.patch', 'config.mak', 'header-manifest.json', 'alias.c')))})
        build_sources = {name: digest(data) for name, data in sources.items()}
        files = {name: data for name, data in sources.items() if name.startswith('stallionfs/') and name.endswith('.py')}
        resources = {}
        for name in ('fileops.py', 'native_suite.py', 'native_metrics.py', 'native_correctness.py',
                     'native_fixtures.py', 'native_report.py', 'campaign.py', 'scan.py', 'run.py', 'cli.py',
                     'fixture/package.json', 'fixture/package-lock.json', 'fixture/check.cjs'):
            data = (SOURCE / 'tests/perf' / name).read_bytes()
            files['stallionfs/_benchmark_runtime/' + name] = data
            resources[name] = digest(data)
        files.update({'stallionfs/_benchmark_runtime/manifest.json': json.dumps({
            'kind': 'build-source provenance', 'build_source_sha256': build_sources, 'resources': resources}).encode(),
            'stallionfs/_scan.cpython-313-darwin.so': b'inert scan',
            'stallionfs/_image.cpython-313-darwin.so': b'inert image',
            'stallionfs-0.7.0.data/scripts/sfs': b'inert native launcher',
            'stallionfs-0.7.0.data/scripts/stallionfs': b'inert native launcher',
            'stallionfs-0.7.0.dist-info/METADATA': b'Name: stallionfs\nVersion: 0.7.0\n',
            'stallionfs-0.7.0.dist-info/WHEEL': b'Tag: cp313-cp313-macosx_15_0_arm64\n',
            'stallionfs-0.7.0.dist-info/entry_points.txt': b'stallionfs-python = stallionfs.__main__:main\n'})
        record = 'stallionfs-0.7.0.dist-info/RECORD'
        files[record] = (''.join(name + ',sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
                                  + ',' + str(len(data)) + '\n' for name, data in files.items()) + record + ',,\n').encode()
        wheel = self.root / 'fixture.whl'
        with zipfile.ZipFile(wheel, 'w') as archive:
            for name, data in files.items(): archive.writestr(name, data)
        wheel.chmod(0o644)
        license = put(self.root / 'COPYING', b'Git license fixture')
        source = put(self.root / 'git-source.tar.xz', b'Git corresponding source fixture')
        config = put(self.root / 'config.mak', b'Git build recipe fixture')
        hook_patch = put(self.root / 'hook.patch', b'Git hook patch fixture')
        notices = put(self.root / 'notices.patch', b'Git change notices fixture')
        alias = put(self.root / 'alias.c', b'Git alias source fixture')
        header_rows = []
        header_inputs = {}
        for row in json.loads((SOURCE / 'tools/git-inputs/header-manifest.json').read_bytes()):
            data = ('inert header ' + row['file']).encode()
            header_rows.append(dict(row, bytes=len(data), sha256=digest(data)))
            header_inputs['Git/sources/' + row['file']] = put(self.root / row['file'], data)
        curl_headers = json_file(self.root / 'curl-headers.json', header_rows)
        # Substitute only the recognized pins for these inert owned fixtures.
        self.bundle.GIT_CONTRACT = dict(self.bundle.GIT_CONTRACT, source_distribution_sha256=pinned(source)['sha256'],
            build_config_sha256=pinned(config)['sha256'], input_inventory_sha256=pinned(inventory)['sha256'],
            combined_patch_sha256=pinned(hook_patch)['sha256'], notice_patch_sha256=pinned(notices)['sha256'],
            alias_source_sha256=pinned(alias)['sha256'], curl_header_manifest_sha256=pinned(curl_headers)['sha256'])
        self.bundle.QUALIFIED_GIT_INPUTS = frozenset({pinned(inventory)['sha256']})
        self.bundle.QUALIFIED_GIT_ARCHITECTURES = {pinned(inventory)['sha256']: 'arm64'}
        qualification_value = json.loads(qualification.read_bytes())
        qualification_value['native_create'] = dict(self.bundle.GIT_CONTRACT)
        json_file(qualification, qualification_value)
        source_inputs = {'Git/sources/git-source.tar.xz': source, 'Git/sources/config.mak': config,
            'Git/sources/combined.patch': hook_patch, 'Git/sources/header-manifest.json': curl_headers,
            'Git/sources/notices.patch': notices, 'Git/sources/alias.c': alias, **header_inputs}
        script_bytes = io.BytesIO()
        with tarfile.open(fileobj=script_bytes, mode='w:xz') as archive:
            for name in ('tools/build_git_runtime.py', 'tools/_git_capture.py', 'stallionfs/_git_sources.py',
                         'stallionfs/_bundle.py', *('tools/git-inputs/' + name for name in
                         ('combined.patch', 'notices.patch', 'config.mak', 'header-manifest.json', 'alias.c'))):
                data = (source_inputs['Git/sources/' + Path(name).name].read_bytes()
                        if name.startswith('tools/git-inputs/') else (SOURCE / name).read_bytes())
                member = tarfile.TarInfo(name); member.size = len(data); archive.addfile(member, io.BytesIO(data))
        curl_license = put(self.root / 'CURL-COPYING', b'Curl license fixture')
        source_inputs.update({'Git/COPYING': license, 'Git/CURL-COPYING': curl_license,
            'Git/SOURCES.txt': put(self.root / 'SOURCES.txt', b'Offline rebuild fixture'),
            'Git/sources/build-scripts.tar.xz': put(self.root / 'build-scripts.tar.xz', script_bytes.getvalue())})
        value = {'schema': 1, 'python_descriptor': pinned(python_descriptor),
                 'git': {'root': str(git), 'inventory': pinned(inventory), 'qualification': pinned(qualification)},
                 'wheel': pinned(wheel), 'licenses': [dict(pinned(license), destination='Git/COPYING'),
                                                     dict(pinned(curl_license), destination='Git/CURL-COPYING')],
                 'sources': [dict(pinned(path), destination=name) for name, path in source_inputs.items()]}
        self.descriptor = json_file(self.root / 'runtime-inputs.json', value)
        self.value = value
        self.app = self.root / 'Assembled With Spaces.app'
        self.manifest = self.root / 'candidate.json'
        self.host = put(self.root / 'host', mode=0o755)
        self.extension = put(self.root / 'extension', mode=0o755)

    def test_regular_wheel_git_is_verified_then_omitted_from_app_members(self):
        self.inputs()
        with zipfile.ZipFile(self.value['wheel']['path']) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        prefix = 'stallionfs/_git/'
        payload = {'bin/git': b'inert Git', 'libexec/git-core/git': b'inert native alias',
                   'share/git-core/templates/description': b'inert template', 'COPYING': b'Git license fixture'}
        payload.update({row['destination'][len('Git/'):]: Path(row['path']).read_bytes() for row in self.value['sources']})
        source = {key: self.bundle.GIT_CONTRACT[key] for key in self.bundle.GIT_SOURCE_KEYS}
        manifest = {'schema': 1, 'kind': 'package-git-runtime', 'source': source, 'build': {},
            'files': [{'path': name, 'mode': '0o755' if name.startswith(('bin/', 'libexec/')) else '0o644',
                       'size': len(data), 'sha256': digest(data)} for name, data in payload.items()]}
        files.update({prefix + name: data for name, data in payload.items()})
        files[prefix + 'manifest.json'] = json.dumps(manifest).encode()
        record = 'stallionfs-0.7.0.dist-info/RECORD'; files.pop(record)
        files[record] = (''.join(name + ',sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
            + ',' + str(len(data)) + '\n' for name, data in files.items()) + record + ',,\n').encode()
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            for name, data in files.items(): archive.writestr(name, data)
        python = json.loads(Path(self.value['python_descriptor']['path']).read_bytes())
        metadata = json.loads(Path(python['metadata_file']).read_bytes())
        admitted, *_, source_assets = package._runtime_source_wheel(stream.getvalue(), metadata, {})
        self.assertFalse(any(name.startswith(prefix) for name in admitted))
        self.assertIn('stallionfs/_bundle.py', admitted)
        self.assertEqual(len(source_assets), 21)
        for change in ('extra', 'bytes', 'manifest', 'source'):
            changed = dict(files)
            if change == 'extra': changed[prefix + 'unlisted'] = b'not admitted'
            elif change == 'bytes': changed[prefix + 'bin/git'] = b'substituted'
            elif change == 'manifest': changed.pop(prefix + 'manifest.json')
            else:
                value = json.loads(changed[prefix + 'manifest.json']); value['source']['combined_patch_sha256'] = '0' * 64
                changed[prefix + 'manifest.json'] = json.dumps(value).encode()
            with self.subTest(change=change), self.assertRaises(ValueError): package._runtime_package_git(changed)

    def test_prior_product_wheel_is_not_relabelled_as_current(self):
        self.inputs()
        with zipfile.ZipFile(self.value['wheel']['path']) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        metadata_name = 'stallionfs-0.7.0.dist-info/METADATA'
        files[metadata_name] = files[metadata_name].replace(b'Version: 0.7.0\n', b'Version: 0.6.3\n')
        record = 'stallionfs-0.7.0.dist-info/RECORD'
        files.pop(record)
        files[record] = (''.join(name + ',sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
                                + ',' + str(len(data)) + '\n' for name, data in files.items()) + record + ',,\n').encode()
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        python = json.loads(Path(self.value['python_descriptor']['path']).read_bytes())
        metadata = json.loads(Path(python['metadata_file']).read_bytes())
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            package._runtime_source_wheel(stream.getvalue(), metadata, {})


    def inspect(self, argv, directory):
        if argv[0] == '/usr/bin/lipo': return 'arm64'
        if argv[0] == '/usr/bin/nm':
            return {'wheel-2': '_PyInit__scan', 'wheel-3': '_PyInit__image'}.get(Path(argv[-1]).name,
                    '_stallionfs_factory_contextual_writes_v1') + '\n'
        self.assertEqual(argv[0], '/usr/bin/otool')
        return APPLE_BUILD_VERSION

    def assemble(self):
        argv = ['package_fskit.py', '--host', str(self.host), '--extension', str(self.extension),
                '--out', str(self.app), '--bundle-version', '9', '--manifest-out', str(self.manifest),
                '--runtime-inputs', str(self.descriptor)]
        self.stdout = io.StringIO()
        with patch.object(sys, 'argv', argv), patch.object(package, '_tool_output', side_effect=self.inspect), redirect_stdout(self.stdout):
            package.main()

    def test_complete_synthetic_mapping_modes_and_source_sidecar_under_both_umasks(self):
        self.inputs()
        for mask in (0o022, 0o077):
            self.app = self.root / (str(mask) + '.app')
            self.manifest = self.root / (str(mask) + '.json')
            previous = os.umask(mask)
            try: self.assemble()
            finally: os.umask(previous)
            value = json.loads(self.manifest.read_bytes())['runtime']
            self.assertFalse(value['complete_candidate'])
            self.assertFalse(value['distribution_signing_performed'])
            self.assertEqual(value['inventory'], package._runtime_inventory(self.app))
            self.assertEqual(self.app.stat().st_mode & 0o777, 0o755)
            self.assertEqual(self.manifest.stat().st_mode & 0o777, 0o600)
            self.assertTrue((self.app / 'Contents/Resources/Runtime/CLI/bin/stallionfs-python').stat().st_mode & 0o111)
            sidecar = self.root / value['source_sidecar']['path']
            self.assertEqual(value['source_sidecar']['inventory'], package._runtime_inventory(sidecar))
            self.assertTrue((self.app / 'Contents/Resources/Licenses/Git/COPYING').is_file())
            descriptor = json.loads((self.app / self.bundle.DESCRIPTOR).read_bytes())
            payload = self.bundle.git_payload(self.app / 'Contents/Resources/Runtime/Git')
            self.assertEqual(descriptor['schema'], 2)
            self.assertEqual(descriptor['git'], dict(self.bundle.GIT_CONTRACT,
                payload_entries=payload['entries'], payload_sha256=payload['sha256']))
            self.assertEqual(value['git'], descriptor['git'])
            self.assertEqual(value['descriptor_sha256'], digest((self.app / self.bundle.DESCRIPTOR).read_bytes()))
            self.assertEqual((self.app / 'Contents/Resources/Runtime/Git/bin/git').stat().st_mode & 0o777, 0o755)
            self.assertEqual((self.app / 'Contents/Resources/Runtime/Git/share/git-core/templates/template').stat().st_mode & 0o777, 0o644)

    def test_complete_offline_source_set_is_required_before_app_output(self):
        self.inputs()
        original = json.loads(self.descriptor.read_bytes())
        self.assertEqual(len(original['sources']), 21)
        for change in ('header', 'scripts', 'instructions', 'curl-license', 'raw-archive', 'changed-header'):
            value = json.loads(json.dumps(original))
            if change in ('header', 'scripts', 'instructions'):
                suffix = {'header': '/typecheck-gcc.h', 'scripts': '/build-scripts.tar.xz',
                          'instructions': '/SOURCES.txt'}[change]
                value['sources'] = [row for row in value['sources'] if not row['destination'].endswith(suffix)]
            elif change == 'curl-license':
                value['licenses'] = [row for row in value['licenses'] if row['destination'] != 'Git/CURL-COPYING']
            elif change == 'raw-archive':
                extra = put(self.root / 'unexpected-archive', b'not part of the delivered source set')
                value['sources'].append(dict(pinned(extra), destination='Git/git-2.56.0.tar.xz'))
            else:
                changed = put(self.root / 'changed-header', b'changed public header')
                next(row for row in value['sources'] if row['destination'].endswith('/typecheck-gcc.h')).update(pinned(changed))
            json_file(self.descriptor, value)
            with self.subTest(change=change), self.assertRaises(ValueError): self.assemble()
            self.assertFalse(self.app.exists())
            self.assertFalse(self.manifest.exists())

    def test_native_contract_and_actual_source_build_inventory_pins_are_required(self):
        self.inputs()
        original = json.loads(self.descriptor.read_bytes())
        qualification_path = Path(original['git']['qualification']['path'])
        qualification = json.loads(qualification_path.read_bytes())
        for change in ('missing', 'unknown', 'extra', 'boolean-schema', 'source', 'build', 'inventory'):
            value = json.loads(json.dumps(original))
            declaration = json.loads(json.dumps(qualification))
            if change == 'missing': declaration.pop('native_create')
            elif change == 'unknown': declaration['native_create']['contract'] = 'unknown-contract'
            elif change == 'extra': declaration['native_create']['trusted'] = True
            elif change == 'boolean-schema': declaration['native_create']['schema'] = True
            elif change in ('source', 'build'):
                index = 0 if change == 'source' else 1
                replacement = put(self.root / (change + '-replacement'), b'different pinned input')
                value['sources'][index].update(pinned(replacement))
            else:
                inventory = put(self.root / 'different-inventory.json',
                    Path(value['git']['inventory']['path']).read_bytes() + b'\n')
                value['git']['inventory'] = pinned(inventory)
                declaration['inventory_sha256'] = pinned(inventory)['sha256']
            json_file(qualification_path, declaration)
            value['git']['qualification'] = pinned(qualification_path)
            json_file(self.descriptor, value)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'contract|provenance'):
                self.assemble()
            self.assertFalse(self.app.exists())
            self.assertFalse(self.manifest.exists())

    def test_missing_substituted_qualification_license_and_wheel_inputs_refuse_before_output(self):
        self.inputs()
        original = self.descriptor.read_bytes()
        for mutation in ('schema', 'qualification', 'license', 'source', 'wheel-pin'):
            value = json.loads(original)
            if mutation == 'schema': value['schema'] = 2
            elif mutation == 'qualification':
                value['git']['qualification'] = pinned(json_file(self.root / 'unqualified.json', {'schema': 1}))
            elif mutation == 'license': value['licenses'] = []
            elif mutation == 'source': value['sources'] = []
            else: value['wheel']['sha256'] = '0' * 64
            json_file(self.descriptor, value)
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, KeyError)):
                self.assemble()
            self.assertFalse(self.app.exists())
            self.assertFalse(self.manifest.exists())

    def test_source_mutation_and_unlisted_output_are_detected_and_retained(self):
        self.inputs()
        original = package._runtime_write_at
        def substitute(root, name, data, mode=0o644):
            result = original(root, name, data, mode)
            if name == 'Contents/Resources/Runtime/runtime.json':
                original(root, 'unexpected', b'unlisted')
            return result
        with patch.object(package, '_runtime_write_at', side_effect=substitute), self.assertRaisesRegex(ValueError, 'mapping changed'):
            self.assemble()
        self.assertTrue((self.app / 'unexpected').is_file())
        self.assertEqual(self.stdout.getvalue(), '')
        self.assertEqual(self.manifest.read_bytes(), b'')
        with self.assertRaises(SystemExit): self.assemble()

    def test_runtime_input_change_during_copy_is_refused(self):
        self.inputs()
        original = package._runtime_write_at
        def change_input(root, name, data, mode=0o644):
            result = original(root, name, data, mode)
            if name == 'Contents/Resources/Runtime/CPython/bin/python3.13':
                (self.root / 'python/bin/python3.13').write_bytes(b'changed input')
            return result
        with patch.object(package, '_runtime_write_at', side_effect=change_input), self.assertRaisesRegex(ValueError, 'changed after copy'):
            self.assemble()
        self.assertTrue(self.app.is_dir())
        self.assertEqual(self.manifest.read_bytes(), b'')
        self.assertEqual(self.stdout.getvalue(), '')

    def test_wheel_traversal_collision_symlink_and_record_corruption_refuse(self):
        self.inputs()
        metadata = json.loads((self.root / 'metadata.input').read_bytes())
        for names in (('../outside',), ('same', 'SAME'), ('link',)):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, 'w') as archive:
                for name in names:
                    item = zipfile.ZipInfo(name)
                    if name == 'link': item.external_attr = (stat.S_IFLNK | 0o777) << 16
                    archive.writestr(item, b'fixture')
            with self.subTest(names=names), self.assertRaises(ValueError):
                package._runtime_wheel_members(stream.getvalue(), metadata)
        stream = io.BytesIO()
        with zipfile.ZipFile(self.root / 'fixture.whl') as original, zipfile.ZipFile(stream, 'w') as changed:
            for item in original.infolist():
                data = original.read(item)
                changed.writestr(item, data + b'changed' if item.filename == 'stallionfs/core.py' else data)
        with self.assertRaisesRegex(ValueError, 'RECORD'):
            package._runtime_wheel_members(stream.getvalue(), metadata)

    def test_required_python_members_and_exact_current_benchmark_resources_are_mandatory(self):
        self.inputs()
        with zipfile.ZipFile(self.root / 'fixture.whl') as archive:
            original = {item.filename: archive.read(item) for item in archive.infolist()}
        for mutation in ('bootstrap', 'main', 'resource-map', 'resource-file', 'stale-resource', 'foreign-package'):
            files = dict(original)
            if mutation == 'bootstrap': files.pop('stallionfs/_bundle.py')
            elif mutation == 'main': files.pop('stallionfs/__main__.py')
            elif mutation == 'resource-file': files.pop('stallionfs/_benchmark_runtime/cli.py')
            elif mutation == 'foreign-package': files['stallionfs/injected.py'] = b'raise AssertionError("unlisted")'
            else:
                name = 'stallionfs/_benchmark_runtime/manifest.json'
                manifest = json.loads(files[name])
                if mutation == 'resource-map': manifest['resources'].pop('cli.py')
                else:
                    files['stallionfs/_benchmark_runtime/cli.py'] = b'stale resource with valid self-hash'
                    manifest['resources']['cli.py'] = digest(files['stallionfs/_benchmark_runtime/cli.py'])
                files[name] = json.dumps(manifest).encode()
            record = 'stallionfs-0.7.0.dist-info/RECORD'
            files.pop(record)
            files[record] = (''.join(name + ',sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
                                      + ',' + str(len(data)) + '\n' for name, data in files.items()) + record + ',,\n').encode()
            wheel = self.root / (mutation + '.whl')
            with zipfile.ZipFile(wheel, 'w') as archive:
                for name, data in files.items(): archive.writestr(name, data)
            value = dict(self.value, wheel=pinned(wheel))
            json_file(self.descriptor, value)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.assemble()
            self.assertFalse(self.app.exists())
            self.assertFalse(self.manifest.exists())
