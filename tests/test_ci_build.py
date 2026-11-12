"""Pure routing, archive, backend and current-build receipt boundaries."""
import hashlib
import ast
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name):
    path = Path(__file__).resolve().parents[1] / 'tools' / (name + '.py')
    spec = importlib.util.spec_from_file_location('test_' + name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class Routing(unittest.TestCase):
    def test_only_exact_first_manual_intel_request_admits(self):
        module = load('ci_native_qualify')
        value = {'EXPECTED_SOURCE_SHA': 'a' * 40, 'GITHUB_SHA': 'a' * 40,
                 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                 'QUALIFICATION_MODE': 'native-git-qualification', 'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'X64'}
        module.gate(value)
        changes = {'EXPECTED_SOURCE_SHA': ('', 'a' * 39, 'A' * 40, '$(command)'),
                   'GITHUB_SHA': ('b' * 40,), 'GITHUB_RUN_ATTEMPT': ('2',),
                   'GITHUB_EVENT_NAME': ('push', 'pull_request'),
                   'QUALIFICATION_MODE': ('compare', 'unsigned-app-artifact'), 'RUNNER_ARCH': ('ARM64',)}
        for key, alternatives in changes.items():
            for other in alternatives:
                with self.subTest(key=key, value=other), self.assertRaises(ValueError):
                    module.gate({**value, key: other})

    def test_workflow_manual_modes_remain_disjoint_and_matrix_gate_stays_required(self):
        text = (Path(__file__).resolve().parents[1] / '.github/workflows/checks.yml').read_text()
        self.assertIn("if: github.event_name != 'workflow_dispatch'", text)
        docs = text.split('  hosted-docs-screen:', 1)[1].split('    runs-on:', 1)[0]
        self.assertIn('contains(fromJSON', docs)
        for mode in ('compare', 'thread-cpu', 'directory-feasibility', 'directory-docs-feasibility', 'delete-thread-cpu'):
            self.assertIn('"' + mode + '"', docs)
        self.assertNotIn('native-git-qualification', docs)
        self.assertNotIn('unsigned-app-artifact', docs)
        intel = text.split('  native-git-qualification:', 1)[1]
        self.assertIn("if: github.event_name == 'workflow_dispatch' && inputs.mode == 'native-git-qualification'", intel)
        self.assertIn('runs-on: macos-26-intel', intel)
        self.assertNotIn('strategy:', intel)
        self.assertIn('cancel-in-progress: false', intel)
        self.assertIn('persist-credentials: false', intel)
        self.assertIn("required_skips = os.environ.get('STALLIONFS_TEST_IMAGES') == '1'", text)
        self.assertIn('not result.wasSuccessful() or bool(required_skips) or missing_contextual', text)
        test = text.split('      - name: Test installed wheel', 1)[1].split('      - name: Check large', 1)[0]
        self.assertLess(test.index('controller.initialize_installed'), test.index("sys.path.insert(0, str(checkout / 'tests'))"))
        self.assertLess(test.index('controller.initialize_installed'), test.index('defaultTestLoader.discover'))


class ComponentArchive(unittest.TestCase):
    def test_private_metadata_mode_is_preserved(self):
        module = load('ci_build'); data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:xz') as opened:
            info = tarfile.TarInfo('input-inventory.json'); info.size = 2; info.mode = 0o600
            opened.addfile(info, io.BytesIO(b'{}'))
        with tempfile.TemporaryDirectory() as temporary:
            module.extract_component(data.getvalue(), Path(temporary))
            path = Path(temporary) / 'input-inventory.json'
            self.assertEqual(path.read_bytes(), b'{}')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_aggregate_metadata_refuses_without_body_read(self):
        module = load('ci_build')
        members = []
        for index in range(3):
            member = tarfile.TarInfo(str(index)); member.size = 64 * 1024 ** 2; member.mode = 0o644
            members.append(member)
        class Archive:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def __iter__(self): return iter(members)
            def extractfile(self, member): raise AssertionError('No body may be read')
        with tempfile.TemporaryDirectory() as temporary, patch.object(module.tarfile, 'open', return_value=Archive()):
            with self.assertRaisesRegex(ValueError, 'expanded byte limit'):
                module.extract_component(b'inert', Path(temporary))
            self.assertFalse(list(Path(temporary).iterdir()))

    def test_unsafe_paths_and_link_members_refuse(self):
        module = load('ci_build')
        for name in ('../outside', '/absolute', 'a/../outside', './member', ''):
            with self.subTest(name=name), self.assertRaises(ValueError): module.relative(name)
        member = tarfile.TarInfo('link'); member.type = tarfile.SYMTYPE; member.linkname = 'outside'
        class Archive:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def __iter__(self): return iter([member])
        with tempfile.TemporaryDirectory() as temporary, patch.object(module.tarfile, 'open', return_value=Archive()):
            with self.assertRaisesRegex(ValueError, 'ordinary'): module.extract_component(b'inert', Path(temporary))

    def test_missing_architecture_fails_before_network_or_creation(self):
        module = load('ci_build')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); lock = root / 'lock.json'
            lock.write_text(json.dumps({'schema': 1, 'components': {}}))
            with patch.object(module.urllib.request, 'urlopen', side_effect=AssertionError('No network')):
                with self.assertRaisesRegex(ValueError, 'No reviewed qualified component'):
                    module.fetch(lock, root / 'output', 'x86_64')
            self.assertFalse((root / 'output').exists())

    def test_standalone_symlink_parent_and_escape_refuse(self):
        module = load('ci_native_python')
        member = tarfile.TarInfo('python/bin/python'); member.type = tarfile.SYMTYPE; member.linkname = '../../outside'
        with self.assertRaises(ValueError): module.inventory([member])
        directory_link = tarfile.TarInfo('python/bin'); directory_link.type = tarfile.SYMTYPE; directory_link.linkname = 'lib'
        file = tarfile.TarInfo('python/bin/python3.13')
        with self.assertRaises(ValueError): module.inventory([directory_link, file])


class CacheAndReceipt(unittest.TestCase):
    def test_owned_destination_uses_physical_parent(self):
        module = load('ci_build')
        with tempfile.TemporaryDirectory(dir='/var/tmp') as temporary:
            parent = Path(temporary)
            actual = module.owned_destination(parent / 'owned-output')
            self.assertEqual(actual, parent.resolve() / 'owned-output')
            self.assertFalse(actual.exists())
            if sys.platform == 'darwin': self.assertNotEqual(actual, parent / 'owned-output')

    def test_owned_lexical_and_physical_paths_normalize_to_same_coordinate(self):
        module = load('ci_native_qualify')
        with tempfile.TemporaryDirectory(dir='/var/tmp') as temporary:
            lexical = Path(temporary); physical = lexical.resolve()
            data = (str(lexical / 'receipt') + '\n' + str(physical / 'receipt')).encode()
            actual = module.normalized_text(data, [(str(lexical), '${QUALIFICATION}'), (str(physical), '${QUALIFICATION}')])
            self.assertEqual(actual, b'${QUALIFICATION}/receipt\n${QUALIFICATION}/receipt')

    def test_cache_guard_blocks_git_effect_during_actual_builder_call(self):
        module = load('_ci_cache')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); cache = root / 'cache'; cache.mkdir()
            data = b'{"schema": 1}'; (cache / 'manifest.json').write_bytes(data)
            checks = []; guard = module.CacheOnlyGuard(cache, hashlib.sha256(data).hexdigest(), root / 'build', lambda: checks.append(True))
            def forbidden(*args): guard.audit('subprocess.Popen', ('git',))
            builder = SimpleNamespace(build=forbidden); guard.wrap(builder)
            with self.assertRaisesRegex(RuntimeError, 'cache-only boundary refused'): builder.build(cache, root / 'build')
            self.assertEqual(guard.effects, ['subprocess.Popen']); self.assertFalse(guard.active)
            self.assertEqual(len(checks), 1)

    def test_cache_guard_accepts_one_manifest_return_and_refuses_repeat(self):
        module = load('_ci_cache')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); cache = root / 'cache'; cache.mkdir()
            data = b'{"schema": 1}'; (cache / 'manifest.json').write_bytes(data)
            guard = module.CacheOnlyGuard(cache, hashlib.sha256(data).hexdigest(), root / 'build', lambda: None)
            builder = SimpleNamespace(build=lambda *args: {'schema': 1}); guard.wrap(builder)
            self.assertEqual(builder.build(cache, root / 'build'), {'schema': 1}); guard.require_complete()
            with self.assertRaisesRegex(RuntimeError, 'One cache consumption'): builder.build(cache, root / 'build')

    def test_destination_is_derived_from_actual_backend(self):
        module = load('ci_build')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            build_py = SimpleNamespace(build_lib=str(root / 'backend-selected-library'), ensure_finalized=lambda: None)
            build = SimpleNamespace(build_temp=str(root / 'backend-selected-objects'), ensure_finalized=lambda: None)
            dist = SimpleNamespace(get_command_obj=lambda name: {'build_py': build_py, 'build': build}[name])
            setuptools = SimpleNamespace(setup=lambda **kwargs: dist)
            def setup_script(*args, **kwargs): setuptools.setup()
            with patch.dict(sys.modules, setuptools=setuptools), patch.object(module.importlib.metadata, 'version', return_value=module.SETUPTOOLS), patch.object(module.runpy, 'run_path', side_effect=setup_script):
                self.assertEqual(module.metadata(root), {'build_lib': build_py.build_lib, 'build_temp': build.build_temp})

    def test_current_build_receipt_supplies_exact_wheel_descriptor_and_source_pins(self):
        module = load('ci_build')
        with tempfile.TemporaryDirectory() as temporary, patch.dict(sys.modules):
            sys.modules.pop('ci_git_input', None)
            root = Path(temporary).resolve(); wheel = root / 'current.whl'; wheel.write_bytes(b'wheel')
            receipt = {'schema': 1, 'cache_return': [{'cache_return': True, 'calls': 1}], 'guard_effects': [],
                'interpreter_sha256': module.digest(Path(sys.executable).read_bytes()), 'interpreter_version': sys.version,
                'architecture': module.platform.machine(), 'wheel': wheel.name, 'wheel_sha256': '1' * 64,
                'descriptor_sha256': '2' * 64, 'source_pins_sha256': '3' * 64}
            (root / 'build-result.json').write_text(json.dumps(receipt)); calls = []
            fake = SimpleNamespace(initialize=lambda *args, **kwargs: calls.append((args, kwargs)) or 'admitted')
            with patch.object(module, 'load', return_value=fake): self.assertEqual(module.initialize_installed(root / 'source', root), 'admitted')
            args, keywords = calls[0]
            self.assertEqual(args[1:5], (wheel, '1' * 64, root / 'native-input.json', '2' * 64))
            self.assertEqual(keywords, {'source_pins': root / 'source-pins.json', 'source_pins_sha256': '3' * 64})
            self.assertIs(sys.modules['ci_git_input'], fake)


class MetadataObservations(unittest.TestCase):
    observations = []

    def test_single_bounded_observations_preserve_failure_and_global_reserve(self):
        for case in ('success', 'timeout', 'nonzero', 'capture-failure', 'budget-refusal'):
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix='ci-inert-metadata-') as temporary:
                module = load('ci_native_qualify'); base = Path(temporary).resolve(); root = base / 'packet'
                interpreter = base / 'dependency/python/bin/python3.13'; interpreter.parent.mkdir(parents=True)
                interpreter.write_bytes(b'inert dependency marker; never executed')
                (base / 'dependency/origin.json').write_text(json.dumps({'executable_sha256': hashlib.sha256(interpreter.read_bytes()).hexdigest(), 'version': '3.13.18'}))
                state = {'failure': None, 'active': None, 'first_signal': None, 'signal_count': 0}
                commands = []
                def command(argv, *, cwd, timeout, stem):
                    commands.append((stem.name, timeout))
                    if stem.name == 'stage-sdk-version':
                        if case == 'timeout':
                            state['failure'] = {'kind': 'timeout', 'detail': stem.name}
                            raise subprocess.TimeoutExpired(argv, timeout)
                        if case == 'nonzero':
                            state['failure'] = {'kind': 'exit', 'detail': stem.name}
                            return subprocess.CompletedProcess(argv, 7, '', '')
                        if case == 'capture-failure': state['failure'] = {'kind': 'cleanup_uncertain'}
                    if stem.name == 'stage-build':
                        wheels = root / 'wheels'; wheels.mkdir(); wheel = wheels / 'inert.whl'; wheel.write_bytes(b'inert wheel')
                        (root / 'build-result.json').write_text(json.dumps({'wheel': wheel.name, 'wheel_sha256': hashlib.sha256(wheel.read_bytes()).hexdigest()}))
                    if stem.name == 'stage-campaign':
                        campaign = root / 'campaign'; campaign.mkdir()
                        (campaign / 'result.json').write_text(json.dumps({'passed': True, 'input_unchanged': True, 'input_unregistered': True,
                            'owned_commands': 581, 'successes': list(range(10)), 'strict_native_environment_commands': list(range(92)), 'structural_refusals': list(range(27))}))
                    return subprocess.CompletedProcess(argv, 0, '', '')
                capture = SimpleNamespace(_COMMAND_ENV=None, _command_state=state, _install_command_handlers=lambda: {},
                    _restore_command_handlers=lambda previous: None, _owned_command=command)
                def package(checkout, packet, *, failed=False):
                    archive = root / ('native-git-qualification.failure.tar.xz' if failed else 'native-git-qualification.tar.xz')
                    archive.write_bytes(b'inert completed archive marker')
                    receipt = root / ('failure-transfer-result.json' if failed else 'transfer-result.json')
                    receipt.write_text(json.dumps({'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'bytes': archive.stat().st_size}))
                ticks = iter((0, 1590 if case == 'budget-refusal' else 0))
                now = lambda: next(ticks, 1590 if case == 'budget-refusal' else 0)
                environment = {'EXPECTED_SOURCE_SHA': 'a' * 40, 'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
                    'GITHUB_EVENT_NAME': 'workflow_dispatch', 'QUALIFICATION_MODE': 'native-git-qualification', 'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'X64'}
                source = Path(__file__).resolve().parents[1]
                with patch.object(module, 'load', return_value=capture), patch.object(module, 'package', side_effect=package), patch.object(module.time, 'monotonic', side_effect=now), patch.object(module.platform, 'machine', return_value='x86_64'), patch.object(sys, 'platform', 'darwin'), patch.object(sys, 'executable', str(interpreter)), patch.dict(os.environ, environment, clear=True):
                    if case == 'success': self.assertIsNone(module.execute(source, root))
                    else:
                        with self.assertRaises(ValueError): module.execute(source, root)
                result = json.loads((root / 'execution-result.json').read_bytes())
                self.assertEqual(result['passed'], case == 'success')
                self.assertEqual(len(commands), len(set(label for label, timeout in commands)))
                if case == 'success':
                    self.assertEqual(commands, [('stage-os-build', 30), ('stage-xcode', 30), ('stage-sdk-version', 30),
                        ('stage-sdk-path', 30), ('stage-build', 600), ('stage-install', 45), ('stage-campaign', 900)])
                elif case == 'budget-refusal':
                    self.assertEqual(commands, [])
                    self.assertIn('Combined qualification deadline reserve', result['failure']['message'])
                else:
                    self.assertEqual(commands, [('stage-os-build', 30), ('stage-xcode', 30), ('stage-sdk-version', 30)])
                    self.assertEqual(result['failure']['type'], {'timeout': 'TimeoutExpired', 'nonzero': 'CalledProcessError', 'capture-failure': 'ValueError'}[case])
                    self.assertIsNotNone(result['capture_state']['failure'])
                with patch.dict(os.environ, GITHUB_SHA='a' * 40, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', GITHUB_OUTPUT=str(base / 'github-output'),
                        QUALIFICATION_STEP_OUTCOME='success' if case == 'success' else 'failure'):
                    completion = json.loads((root / 'transfer-completion.json').read_bytes())
                    self.assertEqual(completion['failed'], case != 'success')
                    module.transfer_ready(root)
                    selected = root / ('native-git-qualification.tar.xz' if case == 'success' else 'native-git-qualification.failure.tar.xz')
                    self.assertEqual((base / 'github-output').read_text(), 'available=true\narchive=' + str(selected) + '\n')
                self.observations.append({'case': case, 'commands': commands, 'passed': result['passed'], 'actual_child_commands': 0})


class ProcessOutcomes(unittest.TestCase):
    observations = []

    def test_ordinary_wrapper_requires_zero_exit_and_clean_final_capture(self):
        for case in ('nonzero', 'cleanup', 'active', 'restore-cancel', 'clean'):
            with self.subTest(case=case):
                module = load('ci_execute')
                state = {'failure': None, 'active': None, 'first_signal': None, 'signal_count': 0}
                def command(*args, **kwargs):
                    if case in ('nonzero', 'cleanup'): state['failure'] = {'kind': case}
                    if case == 'active': state['active'] = {'phase': 'incomplete'}
                    return subprocess.CompletedProcess(args[0], 7 if case == 'nonzero' else 0, '', '')
                def restore(previous):
                    if case == 'restore-cancel': state.update(failure={'kind': 'cancelled'}, first_signal=15, signal_count=1)
                capture = SimpleNamespace(_COMMAND_ENV=None, _command_state=state,
                    _install_command_handlers=lambda: {}, _restore_command_handlers=restore, _owned_command=command)
                spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda value: None))
                with patch.object(module.importlib.util, 'spec_from_file_location', return_value=spec), patch.object(module.importlib.util, 'module_from_spec', return_value=capture), patch.object(sys, 'argv', ['ci_execute.py', '--timeout', '600', '--stem', '/inert/stem', '/inert/tool']):
                    if case == 'clean': self.assertIsNone(module.main())
                    elif case == 'nonzero':
                        with self.assertRaises(subprocess.CalledProcessError) as caught: module.main()
                        self.assertEqual(caught.exception.returncode, 7)
                    else:
                        with self.assertRaises(RuntimeError): module.main()
                self.observations.append({'wrapper': 'ordinary', 'case': case, 'clean_success': case == 'clean', 'actual_child_commands': 0})

    def test_intel_wrapper_refuses_process_and_finalization_failure(self):
        for case in ('nonzero-after-passed-json', 'restore-cancel', 'result-write-latch', 'package-latch', 'package-error', 'failed-package-error', 'failed-package-latch', 'failed-package-exit-zero', 'clean'):
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix='ci-inert-outcome-') as temporary:
                module = load('ci_native_qualify'); base = Path(temporary).resolve(); root = base / 'packet'
                interpreter = base / 'dependency/python/bin/python3.13'; interpreter.parent.mkdir(parents=True)
                interpreter.write_bytes(b'owned inert interpreter marker; never executed')
                (base / 'dependency/origin.json').write_text(json.dumps({'executable_sha256': hashlib.sha256(interpreter.read_bytes()).hexdigest(), 'version': '3.13.18'}))
                state = {'failure': None, 'active': None, 'first_signal': None, 'signal_count': 0}
                packages = []; labels = []
                def command(argv, *, cwd, timeout, stem):
                    labels.append(stem.name)
                    if stem.name == 'stage-build':
                        wheels = root / 'wheels'; wheels.mkdir(); wheel = wheels / 'inert.whl'; wheel.write_bytes(b'inert wheel')
                        (root / 'build-result.json').write_text(json.dumps({'wheel': wheel.name, 'wheel_sha256': hashlib.sha256(wheel.read_bytes()).hexdigest()}))
                    if stem.name == 'stage-campaign':
                        campaign = root / 'campaign'; campaign.mkdir()
                        (campaign / 'result.json').write_text(json.dumps({'passed': True, 'input_unchanged': True, 'input_unregistered': True,
                            'owned_commands': 581, 'successes': list(range(10)), 'strict_native_environment_commands': list(range(92)), 'structural_refusals': list(range(27))}))
                        if case in ('nonzero-after-passed-json', 'failed-package-error', 'failed-package-latch', 'failed-package-exit-zero'):
                            state['failure'] = {'kind': 'exit', 'detail': 'stage-campaign: 7'}
                            return subprocess.CompletedProcess(argv, 7, '', '')
                    return subprocess.CompletedProcess(argv, 0, '', '')
                def restore(previous):
                    if case == 'restore-cancel': state.update(failure={'kind': 'cancelled'}, first_signal=15, signal_count=1)
                capture = SimpleNamespace(_COMMAND_ENV=None, _command_state=state,
                    _install_command_handlers=lambda: {}, _restore_command_handlers=restore, _owned_command=command)
                def package(checkout, packet, *, failed=False):
                    packages.append(failed)
                    archive = root / ('native-git-qualification.failure.tar.xz' if failed else 'native-git-qualification.tar.xz')
                    archive.write_bytes(b'owned inert completed archive marker')
                    receipt = root / ('failure-transfer-result.json' if failed else 'transfer-result.json')
                    receipt.write_text(json.dumps({'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'bytes': archive.stat().st_size}))
                    if not failed and case == 'package-latch': state['failure'] = {'kind': 'cleanup_uncertain'}
                    if not failed and case == 'package-error': raise ValueError('Inert transfer finalization failure')
                    if failed and case == 'failed-package-error': raise ValueError('Inert failed evidence transfer failure')
                    if failed and case == 'failed-package-exit-zero': raise SystemExit(0)
                    if failed and case == 'failed-package-latch': state.update(failure={'kind': 'cancelled'}, first_signal=15, signal_count=1)
                original_write = module.write; writes = []
                def write(path, value):
                    original_write(path, value)
                    if path.name == 'execution-result.json':
                        writes.append(value['passed'])
                        if case == 'result-write-latch' and len(writes) == 1: state['failure'] = {'kind': 'receipt_error'}
                environment = {'EXPECTED_SOURCE_SHA': 'a' * 40, 'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
                    'GITHUB_EVENT_NAME': 'workflow_dispatch', 'QUALIFICATION_MODE': 'native-git-qualification', 'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'X64'}
                source = Path(__file__).resolve().parents[1]
                with patch.object(module, 'load', return_value=capture), patch.object(module, 'package', side_effect=package), patch.object(module, 'write', side_effect=write), patch.object(module.platform, 'machine', return_value='x86_64'), patch.object(sys, 'platform', 'darwin'), patch.object(sys, 'executable', str(interpreter)), patch.dict(os.environ, environment, clear=True):
                    if case == 'clean': self.assertIsNone(module.execute(source, root))
                    else:
                        with self.assertRaises((ValueError, RuntimeError)): module.execute(source, root)
                result = json.loads((root / 'execution-result.json').read_bytes())
                self.assertEqual(result['passed'], case == 'clean')
                self.assertEqual(result['failure'] is None, case == 'clean')
                self.assertTrue(json.loads((root / 'campaign/result.json').read_bytes())['passed'])
                if case != 'clean': self.assertTrue((root / 'transfer-invalidated.json').exists())
                if case in ('result-write-latch', 'package-latch', 'package-error'):
                    self.assertEqual(writes, [True, False])
                    previous = root / 'execution-before-transfer.json'
                    self.assertTrue(json.loads(previous.read_bytes())['passed'])
                    self.assertEqual(result['previous_observation_sha256'], hashlib.sha256(previous.read_bytes()).hexdigest())
                if case == 'nonzero-after-passed-json':
                    self.assertEqual(result['failure']['type'], 'CalledProcessError')
                    self.assertEqual(result['stages'][-1]['returncode'], 7)
                if case in ('failed-package-error', 'failed-package-latch'):
                    self.assertTrue((root / 'failure-transfer-invalidated.json').is_file())
                    self.assertTrue((root / 'execution-before-failure-transfer.json').is_file())
                    self.assertEqual(result['failure']['type'], 'CalledProcessError')
                    self.assertTrue(any(error['type'] == 'ValueError' for error in result['failure']['finalization_errors']))
                if case == 'failed-package-exit-zero':
                    self.assertTrue((root / 'failure-transfer-invalidated.json').is_file())
                    self.assertTrue(any(error['type'] == 'SystemExit' for error in result['failure']['finalization_errors']))
                self.observations.append({'wrapper': 'Intel', 'case': case, 'passed': result['passed'], 'failure': result['failure'],
                    'packaging_modes_failed': packages, 'result_observations': writes, 'stub_command_labels': labels, 'actual_child_commands': 0})

    def test_standalone_complete_verdict_controls_exit_even_when_optimized(self):
        source = Path(__file__).resolve().parents[1] / 'tools/ci_native_campaign.py'
        tree = ast.parse(source.read_bytes()); position = max(i for i, node in enumerate(tree.body) if isinstance(node, ast.Try))
        fragment = ast.Module(body=tree.body[position].finalbody + tree.body[position + 1:], type_ignores=[])
        for case in ('changed-input', 'counts', 'registration', 'raw-clean', 'registered-clean'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve(); data = b'[]'; expected = hashlib.sha256(data).hexdigest()
                (root / 'input-inventory.json').write_bytes(data + (b' ' if case == 'changed-input' else b''))
                registered = case == 'registered-clean'; values = {expected} if case in ('registration', 'registered-clean') else set()
                saved = {}; namespace = {'package': SimpleNamespace(_runtime_inventory=lambda path: []),
                    '_bundle': SimpleNamespace(git_payload=lambda path: {}, QUALIFIED_GIT_INPUTS=frozenset(values)),
                    'GIT': root / 'inert-Git', 'PACKET': root, 'CAMPAIGN': root, 'bound': {},
                    'sha': lambda value: hashlib.sha256(value).hexdigest(), 'Path': Path, 'inventory': [], 'inventory_sha': expected,
                    'payload': {}, 'durable': lambda path, value, *args: saved.update({path.name: value}),
                    'command_rows': list(range(580 if case == 'counts' else 581)), 'failure': None, 'successes': list(range(10)),
                    'refusals': list(range(27)), 'strict_env': list(range(92)), 'guards': [], 'checks': [1], 'contract': {},
                    'args': SimpleNamespace(registered_input=registered), 'json': json, 'print': lambda *args: None}
                compiled = compile(fragment, str(source), 'exec', optimize=2)
                clean = case in ('raw-clean', 'registered-clean')
                if clean: exec(compiled, namespace)
                else:
                    with self.assertRaisesRegex(RuntimeError, 'complete retained result'): exec(compiled, namespace)
                self.assertEqual(saved['result.json']['passed'], clean)
                self.observations.append({'wrapper': 'standalone-finalizer-AST', 'case': case, 'passed': saved['result.json']['passed'],
                    'actor_body_executed': False, 'compile_optimization': 2})

    def test_invalidated_success_archive_is_never_selected_for_transfer(self):
        module = load('ci_native_qualify')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = root / 'output'
            normal = root / 'native-git-qualification.tar.xz'; normal.write_bytes(b'earlier observation')
            (root / 'transfer-result.json').write_text(json.dumps({'archive_sha256': hashlib.sha256(normal.read_bytes()).hexdigest(), 'bytes': normal.stat().st_size}))
            (root / 'transfer-invalidated.json').write_text('{}')
            with patch.dict(os.environ, GITHUB_OUTPUT=str(output), GITHUB_SHA='a' * 40, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', QUALIFICATION_STEP_OUTCOME='failure'):
                with self.assertRaises(ValueError): module.transfer_ready(root)
                self.assertFalse(output.exists())
                failed = root / 'native-git-qualification.failure.tar.xz'; failed.write_bytes(b'actual final failure')
                (root / 'failure-transfer-result.json').write_text(json.dumps({'archive_sha256': hashlib.sha256(failed.read_bytes()).hexdigest(), 'bytes': failed.stat().st_size}))
                (root / 'execution-result.json').write_text(json.dumps({'schema': 1, 'passed': False, 'failure': {'type': 'OwnedFailure'}}))
                module.complete_transfer(root, failed=True)
                module.transfer_ready(root)
            self.assertEqual(output.read_text(), 'available=true\narchive=' + str(failed) + '\n')
            self.assertEqual(normal.read_bytes(), b'earlier observation')
            (root / 'failure-transfer-invalidated.json').write_text('{}')
            with patch.dict(os.environ, GITHUB_OUTPUT=str(output)):
                with self.assertRaisesRegex(ValueError, 'finalization is incomplete'): module.transfer_ready(root)
            self.assertEqual(output.read_text(), 'available=true\narchive=' + str(failed) + '\n')

    def test_failed_transfer_contains_evidence_and_excludes_runtime_binaries(self):
        module = load('ci_native_qualify')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); native = root / 'Git/bin/git'; native.parent.mkdir(parents=True)
            native.write_bytes(b'owned inert binary marker; never executed')
            for name in ('origin-package-manifest.json', 'build-result.json'):
                (root / name).write_text('{}')
            failed = {'passed': False, 'failure': {'type': 'CalledProcessError', 'message': 'Owned inert rc7'}}
            (root / 'execution-result.json').write_text(json.dumps(failed))
            (root / 'stage-campaign.command.json').write_text(json.dumps({'returncode': 7, 'cleanup_uncertain': True}))
            (root / 'stage-campaign.stdout.bin').write_text(str(root / 'owned-output'))
            source = Path(__file__).resolve().parents[1]
            with patch.dict(os.environ, GITHUB_SHA='a' * 40): module.package(source, root, failed=True)
            receipt = json.loads((root / 'failure-transfer-result.json').read_bytes())
            archive = root / 'native-git-qualification.failure.tar.xz'
            self.assertEqual(receipt['archive_sha256'], hashlib.sha256(archive.read_bytes()).hexdigest())
            with tarfile.open(archive) as opened:
                names = opened.getnames(); self.assertTrue(all(not name.startswith(('Git/', 'Sources/Git/')) for name in names))
                manifest = json.load(opened.extractfile('transfer-manifest.json'))
                self.assertFalse(manifest['qualification_passed']); self.assertFalse(manifest['runtime_binaries_included'])
                self.assertEqual(json.load(opened.extractfile('evidence/execution-result.json')), failed)
                self.assertEqual(opened.extractfile('evidence/capture/stage-campaign.stdout.bin').read(), b'${QUALIFICATION}/owned-output')
            self.assertEqual(native.read_bytes(), b'owned inert binary marker; never executed')


class TransferCompletion(unittest.TestCase):
    observations = []

    def test_interrupted_finalization_never_selects_preexisting_archives(self):
        cases = ('normal-result-write-error', 'failure-result-write-error', 'normal-result-rename-error',
                 'failure-result-rename-error', 'normal-invalidation-error', 'failure-invalidation-error',
                 'pending-completion-error', 'completion-link-error')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix='ci-transfer-fault-') as temporary:
                module = load('ci_native_qualify'); base = Path(temporary).resolve(); root = base / 'packet'
                interpreter = base / 'dependency/python/bin/python3.13'; interpreter.parent.mkdir(parents=True)
                interpreter.write_bytes(b'inert dependency marker; never executed')
                (base / 'dependency/origin.json').write_text(json.dumps({'executable_sha256': hashlib.sha256(interpreter.read_bytes()).hexdigest(), 'version': '3.13.18'}))
                state = {'failure': None, 'active': None, 'first_signal': None, 'signal_count': 0}
                def command(argv, *, cwd, timeout, stem):
                    if stem.name == 'stage-build':
                        wheels = root / 'wheels'; wheels.mkdir(); wheel = wheels / 'inert.whl'; wheel.write_bytes(b'inert wheel')
                        (root / 'build-result.json').write_text(json.dumps({'wheel': wheel.name, 'wheel_sha256': hashlib.sha256(wheel.read_bytes()).hexdigest()}))
                    if stem.name == 'stage-campaign':
                        campaign = root / 'campaign'; campaign.mkdir()
                        (campaign / 'result.json').write_text(json.dumps({'passed': True, 'input_unchanged': True, 'input_unregistered': True,
                            'owned_commands': 581, 'successes': list(range(10)), 'strict_native_environment_commands': list(range(92)), 'structural_refusals': list(range(27))}))
                        if case.startswith('failure-'):
                            state['failure'] = {'kind': 'exit', 'detail': 'stage-campaign: 7'}
                            return subprocess.CompletedProcess(argv, 7, '', '')
                    return subprocess.CompletedProcess(argv, 0, '', '')
                capture = SimpleNamespace(_COMMAND_ENV=None, _command_state=state, _install_command_handlers=lambda: {},
                    _restore_command_handlers=lambda previous: None, _owned_command=command)
                def package(checkout, packet, *, failed=False):
                    archive = root / ('native-git-qualification.failure.tar.xz' if failed else 'native-git-qualification.tar.xz')
                    archive.write_bytes(b'inert completed archive marker')
                    receipt = root / ('failure-transfer-result.json' if failed else 'transfer-result.json')
                    receipt.write_text(json.dumps({'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'bytes': archive.stat().st_size}))
                    if case.startswith('failure-') and failed or case.startswith('normal-') and not failed:
                        raise OSError('Inert finalization error after archive receipt')
                original_write = module.write; writes = []
                def write(path, value):
                    if path.name == 'execution-result.json':
                        writes.append(value['passed'])
                        if case.endswith('result-write-error') and len(writes) == 2: raise OSError('Inert failed-result rewrite error')
                    if case == 'normal-invalidation-error' and path.name == 'transfer-invalidated.json': raise OSError('Inert invalidation write error')
                    if case == 'failure-invalidation-error' and path.name == 'failure-transfer-invalidated.json': raise OSError('Inert failure invalidation write error')
                    if case == 'pending-completion-error' and path.name == 'transfer-completion.pending.json': raise OSError('Inert completion write error')
                    original_write(path, value)
                original_rename = Path.rename; original_link = module.os.link
                def rename(path, destination):
                    if case.endswith('result-rename-error') and path == root / 'execution-result.json': raise OSError('Inert failed-result rename error')
                    return original_rename(path, destination)
                def link(source, destination, *args, **kwargs):
                    if case == 'completion-link-error': raise OSError('Inert completion commit error')
                    return original_link(source, destination, *args, **kwargs)
                environment = {'EXPECTED_SOURCE_SHA': 'a' * 40, 'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
                    'GITHUB_EVENT_NAME': 'workflow_dispatch', 'QUALIFICATION_MODE': 'native-git-qualification', 'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'X64'}
                source = Path(__file__).resolve().parents[1]
                with patch.object(module, 'load', return_value=capture), patch.object(module, 'package', side_effect=package), patch.object(module, 'write', side_effect=write), patch.object(Path, 'rename', rename), patch.object(module.os, 'link', side_effect=link), patch.object(module.platform, 'machine', return_value='x86_64'), patch.object(sys, 'platform', 'darwin'), patch.object(sys, 'executable', str(interpreter)), patch.dict(os.environ, environment, clear=True):
                    with self.assertRaises((OSError, RuntimeError, ValueError)): module.execute(source, root)
                self.assertFalse((root / 'transfer-completion.json').exists())
                self.assertTrue(list(root.glob('native-git-qualification*.tar.xz')))
                output = base / 'github-output'
                with patch.dict(os.environ, GITHUB_OUTPUT=str(output), GITHUB_SHA='a' * 40, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', QUALIFICATION_STEP_OUTCOME='failure'):
                    with self.assertRaisesRegex(ValueError, 'completion missing'): module.transfer_ready(root)
                self.assertFalse(output.exists())
                self.observations.append({'case': case, 'archive_preserved': True, 'completion_committed': False,
                    'selected': False, 'result_present': (root / 'execution-result.json').exists(), 'result_writes': writes,
                    'actual_child_commands': 0})

    def test_completion_binds_result_receipt_archive_source_and_workflow_outcome(self):
        for case in ('normal-clean', 'failure-clean', 'result-changed', 'receipt-changed', 'archive-changed',
                     'source-changed', 'run-changed', 'attempt-changed', 'normal-step-failed', 'failed-step-succeeded'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                module = load('ci_native_qualify'); root = Path(temporary).resolve()
                failed = case in ('failure-clean', 'failed-step-succeeded')
                result = {'schema': 1, 'passed': not failed, 'failure': {'type': 'OwnedFailure'} if failed else None,
                    'capture_state': {'failure': None, 'active': None, 'first_signal': None, 'signal_count': 0}}
                (root / 'execution-result.json').write_text(json.dumps(result))
                archive = root / ('native-git-qualification.failure.tar.xz' if failed else 'native-git-qualification.tar.xz')
                archive.write_bytes(b'owned inert archive')
                receipt = root / ('failure-transfer-result.json' if failed else 'transfer-result.json')
                receipt.write_text(json.dumps({'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'bytes': archive.stat().st_size}))
                with patch.dict(os.environ, GITHUB_SHA='a' * 40, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1'): module.complete_transfer(root, failed=failed)
                self.assertTrue((root / 'transfer-completion.json').exists())
                if case == 'result-changed': (root / 'execution-result.json').write_bytes((root / 'execution-result.json').read_bytes() + b' ')
                if case == 'receipt-changed': receipt.write_bytes(receipt.read_bytes() + b' ')
                if case == 'archive-changed': archive.write_bytes(b'changed inert archive')
                outcome = 'failure' if failed else 'success'
                if case == 'normal-step-failed': outcome = 'failure'
                if case == 'failed-step-succeeded': outcome = 'success'
                output = root / 'github-output'; clean = case in ('normal-clean', 'failure-clean')
                with patch.dict(os.environ, GITHUB_OUTPUT=str(output), GITHUB_SHA=('b' if case == 'source-changed' else 'a') * 40,
                        GITHUB_RUN_ID='124' if case == 'run-changed' else '123', GITHUB_RUN_ATTEMPT='2' if case == 'attempt-changed' else '1',
                        QUALIFICATION_STEP_OUTCOME=outcome):
                    if clean: module.transfer_ready(root)
                    else:
                        with self.assertRaises(ValueError): module.transfer_ready(root)
                self.assertEqual(output.exists(), clean)
                if clean: self.assertEqual(output.read_text(), 'available=true\narchive=' + str(archive) + '\n')
                self.observations.append({'case': case, 'completion_committed': True, 'selected': clean, 'actual_child_commands': 0})


def owned_ci_bootstrap():
    """Load the code that the workflow actually writes and executes."""
    text = (Path(__file__).resolve().parents[1] / '.github/workflows/checks.yml').read_text()
    step = text.split('      - name: Create owned CI interpreter\n', 1)[1].split('      - name:', 1)[0]
    body = step.split("          python -I -B - <<'PY'\n", 1)[1].rsplit('          PY', 1)[0]
    body = '\n'.join(line[10:] for line in body.splitlines())
    tree = ast.parse(body)
    assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == 'BOOTSTRAP_SOURCE' for target in node.targets))
    source = ast.literal_eval(assignment.value)
    module = SimpleNamespace(__name__='ci_inert', BOOTSTRAP_SOURCE=source)
    exec(compile(source, '<workflow-owned-ci-interpreter>', 'exec'), module.__dict__)
    return module


class OwnedCIInterpreter(unittest.TestCase):
    def exercise(self, root, case='success', temporary=None):
        module = owned_ci_bootstrap()
        base = root / 'trusted-base'; base.mkdir()
        executable = base / 'python3.13'; executable.write_bytes(b'inert interpreter; never executed'); executable.chmod(0o755)
        github_env = root / 'github-env'
        github_path = root / 'github-path'
        calls = {'create': 0, 'capture': 0, 'probe': 0}
        state = SimpleNamespace(executable=str(executable), _base_executable=str(executable),
                                base_prefix=str(base), prefix=str(base), version='inert 3.13', argv=['outer'])
        module.sys = state
        module.platform = SimpleNamespace(machine=lambda: 'arm64')
        paths = {}
        module.sysconfig = SimpleNamespace(get_path=lambda name: paths[name])

        class Builder:
            def __init__(self, **kwargs):
                self.kwargs = kwargs
            def create(self, destination):
                calls['create'] += 1
                self_test.assertEqual(self.kwargs, dict(with_pip=True, symlinks=False, upgrade=False, upgrade_deps=False))
                if case == 'creation-nonzero': raise subprocess.CalledProcessError(7, ['inert-ensurepip'])
                environment = Path(destination)
                scripts = environment / 'bin'; scripts.mkdir()
                library = environment / 'lib'; library.mkdir()
                selected = scripts / 'python3.13'
                if case == 'missing-executable': pass
                elif case == 'symlink-executable': selected.symlink_to(executable)
                else:
                    selected.write_bytes(b'wrong copy' if case == 'wrong-copy' else executable.read_bytes())
                    selected.chmod(0o644 if case == 'nonexecutable' else 0o755)
                paths.update(scripts=str(scripts), purelib=str(library), platlib=str(library), data=str(environment),
                             stdlib=str(base), include=str(base))
                if case == 'scheme-escape': paths['purelib'] = str(base)
                if case == 'nul-scripts': paths['scripts'] += '\x00'
                if case == 'mode-changed': scripts.chmod(0o777)
                self.post_setup(SimpleNamespace(env_exe=str(selected)))

        self_test = self
        module.venv = SimpleNamespace(EnvBuilder=Builder)
        def child(argv, **kwargs):
            calls['probe'] += 1
            self.assertEqual(kwargs, {'check': True})
            self.assertEqual(argv[1:3], ['-I', '-B'])
            if case == 'probe-timeout': raise subprocess.TimeoutExpired(argv, 90)
            before = state.executable, state.prefix, state.base_prefix, state.version, module.platform
            state.executable = argv[0]; state.prefix = argv[6]
            if case == 'base-prefix-reuse': state.base_prefix = argv[6]
            if case == 'version-differs': state.version = 'other interpreter'
            if case == 'architecture-differs': module.platform = SimpleNamespace(machine=lambda: 'x86_64')
            try: module.probe(*map(Path, argv[5:8]), json.loads(argv[8]), json.loads(argv[9]))
            finally: state.executable, state.prefix, state.base_prefix, state.version, module.platform = before
            return subprocess.CompletedProcess(argv, 0)
        module.subprocess = SimpleNamespace(run=child)
        def captured():
            calls['capture'] += 1
            argv = state.argv
            self.assertEqual(argv[1:3], ['--timeout', '90'])
            self.assertEqual(argv[6], 'create')
            self.assertTrue(Path(argv[5]).is_absolute())
            module.create(*map(Path, argv[7:11]), json.loads(argv[11]), json.loads(argv[12]))
            if case in ('output-cap', 'capture-failure', 'finalization-failure'):
                raise RuntimeError(case)
            if case == 'zero-early-exit': raise SystemExit(0)
            if case == 'driver-replaced':
                driver = Path(argv[5]); data = driver.read_bytes(); driver.unlink(); driver.write_bytes(data)
            if case == 'environment-replaced':
                environment = Path(argv[9]); environment.rename(environment.with_name('previous')); environment.mkdir(mode=0o700)
        runner = SimpleNamespace(main=captured)
        module.importlib = SimpleNamespace(util=SimpleNamespace(
            spec_from_file_location=lambda *args: SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None)),
            module_from_spec=lambda spec: runner))
        if case == 'wrong-owner':
            actual = module.identity
            def refuse_owner(path, directory=False):
                if Path(path).name == 'venv':
                    with patch.object(module.os, 'getuid', return_value=os.getuid() + 1):
                        return actual(path, directory)
                return actual(path, directory)
            module.identity = refuse_owner
        if case.startswith('existing-'):
            container = root / 'ci-python'
            if case == 'existing-directory': container.mkdir()
            elif case == 'existing-file': container.write_bytes(b'preserved')
            else: container.symlink_to(base, target_is_directory=True)
        if temporary is None: temporary = root
        if case == 'success': module.bootstrap(temporary, root, github_env, github_path)
        else:
            with self.assertRaises((ValueError, OSError, RuntimeError, subprocess.SubprocessError)):
                module.bootstrap(temporary, root, github_env, github_path)
            self.assertFalse(github_env.exists(), 'Failed bootstrap must not publish an interpreter')
            self.assertFalse(github_path.exists(), 'Failed bootstrap must not publish a PATH prefix')
        self.assertLessEqual(calls['create'], 1)
        self.assertLessEqual(calls['capture'], 1)
        self.assertEqual(state.argv, ['outer'])
        return module, state, calls, github_env

    def test_fresh_copy_and_base_stdlib_are_accepted_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            module, state, calls, output = self.exercise(root)
            value = json.loads((root / 'ci-python/origin.json').read_text())
            self.assertEqual(calls, {'create': 1, 'capture': 1, 'probe': 1})
            self.assertEqual(output.read_text(), 'CI_PYTHON=' + value['executable'] + '\nCI_CONTAINER=' + str(root / 'ci-python') + '\n')
            self.assertEqual((root / 'github-path').read_text(), value['paths']['scripts'] + '\n')
            self.assertNotEqual(value['prefix'], value['base_prefix'])
            self.assertEqual(set(value['paths']), {'scripts', 'purelib', 'platlib', 'data'})
            # Directory timestamps and optional interpreter aliases are not copy identities.
            alias = root / 'ci-python/venv/bin/python'; alias.symlink_to('python3.13')
            module.validate(value, root / 'ci-python', root / 'ci-python/venv', value['base'])

    def test_creation_identity_scheme_and_collector_failures_never_publish(self):
        cases = ('existing-directory', 'existing-file', 'existing-symlink', 'wrong-owner',
                 'mode-changed', 'driver-replaced', 'environment-replaced', 'missing-executable',
                 'symlink-executable', 'nonexecutable', 'wrong-copy', 'version-differs', 'architecture-differs',
                 'scheme-escape', 'nul-scripts', 'base-prefix-reuse', 'creation-nonzero',
                 'probe-timeout', 'output-cap', 'capture-failure', 'finalization-failure', 'zero-early-exit')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                with patch('builtins.print'):
                    _, _, calls, _ = self.exercise(root, case)
                self.assertEqual(calls['capture'], 0 if case.startswith('existing-') or case == 'wrong-owner' else 1)
                self.assertEqual(calls['create'], calls['capture'])

    def test_control_characters_cannot_publish_environment_or_path(self):
        for character in ('\n', '\r', '\t', '\x7f', '\x85'):
            with self.subTest(character=repr(character)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve() / ('owned-' + character); root.mkdir(mode=0o700)
                with patch('builtins.print'):
                    self.exercise(root, 'control-in-path')

    def test_existing_phase_consumers_find_owned_cli_before_stale_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            _, _, _, output = self.exercise(root)
            exports = dict(line.split('=', 1) for line in output.read_text().splitlines())
            scripts = Path((root / 'github-path').read_text().rstrip('\n'))
            installed = scripts / 'stallionfs'; installed.write_bytes(b'inert owned native marker'); installed.chmod(0o755)
            stale = root / 'stale-bin'; stale.mkdir()
            previous = stale / 'stallionfs'; previous.write_bytes(b'stale unrelated marker'); previous.chmod(0o755)
            self.assertEqual(shutil.which('stallionfs', path=str(stale)), str(previous))
            path = os.pathsep.join((str(scripts), str(stale)))
            with patch.dict(os.environ, dict(exports, PATH=path, GITHUB_ACTIONS='true')):
                for filename, class_name in (('test_native_phase_probe.py', 'NativePhaseCounters'),
                                              ('test_native_delete_phase_probe.py', 'NativeDeleteCounters')):
                    tree = ast.parse((Path(__file__).resolve().parent / filename).read_text())
                    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
                    method = next(node for node in owner.body if isinstance(node, ast.FunctionDef))
                    guard = next(node for node in method.body if isinstance(node, ast.If)
                                 and 'GITHUB_ACTIONS' in ast.unparse(node.test))
                    # Execute only the existing installed-CLI lookup/read assertions, never its harness body.
                    scope = {'shutil': shutil, 'Path': Path, 'self': self, 'probe': SimpleNamespace(MARKER='inert diagnostic marker')}
                    exec(compile(ast.Module(body=guard.body, type_ignores=[]), filename, 'exec'), scope)
                    self.assertEqual(scope['installed'], str(installed))

    def test_alias_bootstrap_routes_physical_seal_and_refuses_container_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve(); root = parent / 'physical'; root.mkdir(mode=0o700)
            alias = parent / 'alias'; alias.symlink_to(root, target_is_directory=True)
            module, state, _, output = self.exercise(root, temporary=alias)
            exports = dict(line.split('=', 1) for line in output.read_text().splitlines())
            container = Path(exports['CI_CONTAINER'])
            self.assertEqual(container, root / 'ci-python')
            self.assertNotEqual(container, alias / 'ci-python')
            state.executable = exports['CI_PYTHON']
            scripts = Path(state.executable).parent
            for name in ('sfs', 'stallionfs', 'stallionfs-python'):
                path = scripts / name
                path.write_text('#!' + state.executable + '\nfrom stallionfs.__main__ import main\n')
                path.chmod(0o755)
            module.check_install(container, True); module.check_install(container, False)
            # Changing an unused lexical alias cannot redirect the exported physical coordinate.
            other = parent / 'other'; other.mkdir(); alias.unlink(); alias.symlink_to(other, target_is_directory=True)
            module.check_install(container, False)
            original = container.with_name('original'); container.rename(original)
            shutil.copytree(original, container)
            with self.assertRaisesRegex(ValueError, 'CI environment replaced'):
                module.check_install(container, False)

    def test_console_helper_is_bound_to_selected_copy_and_retained(self):
        for shell, spaces in ((False, False), (True, False), (True, True)):
            with self.subTest(shell=shell, spaces=spaces), tempfile.TemporaryDirectory(prefix='ci with space-' if spaces else 'ci-inert-') as temporary:
                root = Path(temporary).resolve()
                module, state, _, _ = self.exercise(root)
                container = root / 'ci-python'
                value = json.loads((container / 'origin.json').read_text())
                state.executable = value['executable']
                scripts = Path(value['paths']['scripts'])
                selected = value['executable']
                quoted = '"' + selected + '"' if spaces else selected
                header = ("#!/bin/sh\n'''exec' " + quoted + " \"$0\" \"$@\"\n' '''\n") if shell else '#!' + selected + '\n'
                helper = scripts / 'stallionfs-python'
                helper.write_text(header + 'from stallionfs.__main__ import main\n'); helper.chmod(0o755)
                for name in ('sfs', 'stallionfs'):
                    path = scripts / name; path.write_bytes(b'inert native launcher'); path.chmod(0o755)
                module.check_install(container, True); module.check_install(container, False)
                helper.write_text('#!/different/python\nfrom stallionfs.__main__ import main\n')
                with self.assertRaisesRegex(ValueError, 'console helper route'): module.check_install(container, False)
                helper.write_text(header + 'from stallionfs.__main__ import main\n')
                (scripts / 'stallionfs').write_bytes(b'changed native launcher')
                with self.assertRaisesRegex(ValueError, 'launcher changed'): module.check_install(container, False)

    def test_all_ordinary_consumers_and_diagnostics_use_the_owned_interpreter(self):
        text = (Path(__file__).resolve().parents[1] / '.github/workflows/checks.yml').read_text()
        ordinary = text.split('  test:', 1)[1].split('  hosted-docs-screen:', 1)[0]
        self.assertEqual(ordinary.count('          python -I -B'), 1)
        self.assertEqual(ordinary.count('"${CI_PYTHON:?}" -I -B'), 10)
        self.assertLess(ordinary.index('name: Create owned CI interpreter'), ordinary.index('name: Install pinned wheel backend'))
        self.assertIn("if: failure() && steps.ci-python.outcome == 'success'", ordinary)
        self.assertIn('"${CI_STALLIONFS:?}" --root "$RUNNER_TEMP/stallionfs-smoke" doctor', ordinary)
        self.assertIn('"${CI_CONTAINER:?}/bootstrap.py" check "${CI_CONTAINER:?}"', ordinary)
        self.assertIn('"${CI_CONTAINER:?}/bootstrap.py" seal "${CI_CONTAINER:?}"', ordinary)
        self.assertNotIn('$RUNNER_TEMP/ci-python', ordinary)
        self.assertIn("Path(os.environ['GITHUB_PATH'])", ordinary)
        self.assertIn('fail-fast: false', ordinary)
        self.assertIn("(matrix.os == 'macos-26-intel' || matrix.os == 'xcode-27') && 30 || 15", ordinary)
        for os_name, python in (('macos-15', '3.12'), ('macos-26', '3.11'), ('macos-26', '3.13'),
                                ('macos-26', '3.14'), ('macos-26-intel', '3.13'), ('xcode-27', '3.13')):
            self.assertIn('{os: ' + os_name + ", python: '" + python + "', images: '", ordinary)
        self.assertEqual(ordinary.count('          - {os:'), 6)
        self.assertIn('actions/checkout@11d5960a326750d5838078e36cf38b85af677262', ordinary)
        self.assertIn('actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065', ordinary)
        self.assertNotIn('cancel-in-progress', ordinary)
        self.assertIn('--timeout 600', ordinary)
        self.assertIn('timeout-minutes: 9', ordinary)

    def test_build_tool_directory_owner_guard_is_unchanged(self):
        module = load('package_fskit')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve()
            module.os.close(module._runtime_directory(path))
            actual = module.os.fstat
            def mismatched(fd):
                info = actual(fd)
                return SimpleNamespace(st_uid=info.st_uid + 1)
            with patch.object(module.os, 'fstat', side_effect=mismatched):
                with self.assertRaisesRegex(ValueError, 'Directory ownership changed'):
                    module._runtime_directory(path)


if __name__ == '__main__': unittest.main()
