"""Transfer coverage with a closed test child and inert build inputs."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile


TOOLS = Path(__file__).resolve().parents[1] / 'tools'
SOURCE = 'a' * 40
WHEEL = 'stallionfs-0.7.0-cp313-cp313-macosx_13_0_x86_64.whl'
CHILD = """
from pathlib import Path
from types import SimpleNamespace
import runpy, sys, unittest
from unittest.mock import patch

class Case(unittest.TestCase):
    def __init__(self, identity):
        super().__init__()
        self.identity = identity

    def id(self):
        return self.identity

    def runTest(self):
        pass

sys.modules.update(
    stallionfs=SimpleNamespace(__file__='/installed/stallionfs/__init__.py',
                               images=object(), _scan=SimpleNamespace(__file__='/installed/_scan.so')),
    image_failure_diagnostics=SimpleNamespace(install=lambda *args: SimpleNamespace(close=lambda: None)),
)
tool, events = sys.argv[1:]
sys.argv = [tool, '--child', events, 'suite']
with patch('platform.machine', return_value='x86_64'), patch('subprocess.run'), \
        patch('sysconfig.get_path', return_value=str(Path(sys.prefix).resolve() / 'bin')):
    entry = runpy.run_path(tool)
    # This child tests receipt binding with synthetic successes. The crash
    # fixtures and their exact accounting are tested separately.
    identities = sorted(entry.get('SIGKILL_TESTS', ())) or ['wheel_retention.synthetic']
    suite = unittest.TestSuite(Case(identity) for identity in identities)
    with patch.object(unittest.defaultTestLoader, 'discover', return_value=suite):
        raise SystemExit(entry['main']())
"""
ADMISSION = """
import hashlib, json

def initialize(checkout, wheel, wheel_sha, descriptor, descriptor_sha, *, source_pins, source_pins_sha256):
    for path, sha in ((wheel, wheel_sha), (descriptor, descriptor_sha), (source_pins, source_pins_sha256)):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == sha
    return {'check': lambda: None, 'contract': {
        'descriptor_sha256': descriptor_sha,
        'input_inventory_sha256': json.loads(descriptor.read_bytes())['inventory']['sha256']}}
"""


def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WheelRetention(unittest.TestCase):
    def test_closed_child_to_stager(self):
        build, entry, budget = (load(name) for name in ('ci_build', 'ci_test_entry', 'ci_job_budget'))
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            root = Path(temporary).resolve()
            checkout = root / 'source'
            tools = checkout / 'tools'
            tools.mkdir(parents=True)
            for name in ('ci_build.py', 'package_fskit.py'):
                shutil.copyfile(TOOLS / name, tools / name)
            (tools / 'ci_git_input.py').write_text(ADMISSION)
            output = root / 'qualified-wheel'
            output.mkdir()
            native = root / 'qualified-git-component'
            native.mkdir()
            closure = root / 'suite-closure'
            closure.mkdir()
            stage = root / 'installed-intel-wheel'
            suite_path = closure / 'suite.json'
            candidate_path = root / 'installed-wheel-candidate.json'
            wheel = output / WHEEL
            pins_path = output / 'source-pins.json'

            def write_json(path, value):
                path.write_text(json.dumps(value))
                return build.digest(path.read_bytes())

            component = {'sha256': 'b' * 64, 'bytes': 100, 'url': 'https://example.test/component'}
            for name, key in (('component-manifest.json', 'manifest_sha256'),
                              ('input-inventory.json', 'inventory_sha256'),
                              ('qualification.json', 'qualification_sha256')):
                component[key] = write_json(native / name, {'inert': name})
            write_json(root / 'component-download.json', {'architecture': 'x86_64', **component})
            descriptor_sha = write_json(output / 'native-input.json', {
                'root': str(native / 'Git'),
                'inventory': {'path': str(native / 'input-inventory.json'), 'sha256': component['inventory_sha256']},
                'qualification': {'path': str(native / 'qualification.json'), 'sha256': component['qualification_sha256']}})

            inputs = dict.fromkeys([*build.producer_source_names(()), 'stallionfs/module.py'], b'fixture')
            inputs['pyproject.toml'] = b'[project]\nname = "stallionfs"\nversion = "0.7.0"\n'
            pins = [dict(path=name, mode='0o644', bytes=len(data), sha256=build.digest(data))
                    for name, data in inputs.items()]
            inputs['tools/ci-git-components.json'] = json.dumps(
                {'schema': 1, 'components': {'x86_64': component}}).encode()

            def git_output(_checkout, *args, limit, stdin=None):
                if args == ('rev-parse', '--verify', 'HEAD'):
                    return (SOURCE + '\n').encode()
                if args[0] == 'diff':
                    return b''
                blobs = {f'{index:040x}'.encode(): data for index, data in enumerate(inputs.values(), 1)}
                if args[0] == 'ls-tree':
                    self.assertIn(SOURCE, args)
                    return b''.join(b'100644 blob %s %d\t%s\0' % (oid, len(data), name.encode())
                                    for oid, (name, data) in zip(blobs, inputs.items()))
                self.assertEqual(args, ('cat-file', '--batch'))
                return b''.join(b'%s blob %d\n%s\n' % (oid, len(blobs[oid]), blobs[oid])
                                for oid in stdin.read().splitlines())

            environment = dict(GITHUB_REPOSITORY='alvinhhh/stallionfs', GITHUB_EVENT_NAME='push',
                               GITHUB_REF='refs/heads/main', GITHUB_JOB='test-execution', GITHUB_SHA=SOURCE,
                               GITHUB_RUN_ID='42', GITHUB_RUN_ATTEMPT='1', GITHUB_WORKSPACE=str(checkout),
                               CI_WORKER='macos-26-intel-3.13-1-installed', CI_CONTAINER=str(root / 'container'),
                               CI_RETAIN_INTEL_WHEEL='1', STALLIONFS_TEST_IMAGES='1', STALLIONFS_QUALIFICATION='1',
                               STALLIONFS_REQUIRE_CONTEXTUAL_FSKIT='0', RUNNER_OS='macOS', RUNNER_ARCH='X64',
                               RUNNER_TEMP=str(root), GITHUB_ENV=str(root / 'env'), GITHUB_OUTPUT=str(root / 'outputs'))
            stack.enter_context(patch.dict(os.environ, environment))
            stack.enter_context(patch.object(build, 'git_output', side_effect=git_output))
            stack.enter_context(patch.object(build.platform, 'machine', return_value='x86_64'))
            stack.enter_context(patch.object(build.platform, 'mac_ver', return_value=('26.4.1', (), 'x86_64')))
            stack.enter_context(patch.object(build.platform, 'python_version', return_value='3.13.1'))
            stack.enter_context(patch.object(build, 'sys', SimpleNamespace(
                executable=sys.executable, platform='darwin', version=sys.version,
                version_info=(3, 13), implementation=SimpleNamespace(name='cpython'))))
            stack.enter_context(patch.object(budget, 'entry_module', entry, create=True))
            now = 10000 * budget.NS
            stack.enter_context(patch.object(entry, 'allocation_clock_ns', return_value=now))

            def allocate(remainder):
                allocation = dict(schema=1, clock=budget.ALLOCATION_CLOCK, minutes=60, token='c' * 32,
                                  start_ns=now - (3590 - remainder) * budget.NS,
                                  identity={key: os.environ[key] for key in budget.IDENTITY})
                job = write_json(root / 'ci-allocation.json', allocation)
                os.environ['CI_ALLOCATION_SHA256'] = job
                return job

            def run_child(producer_pins, metadata_version='0.7.0', filename_version='0.7.0'):
                for previous in output.glob('*.whl'):
                    previous.unlink()
                selected = wheel.with_name(WHEEL.replace('0.7.0', filename_version))
                with zipfile.ZipFile(selected, 'w') as archive:
                    archive.writestr(f'stallionfs-{filename_version}.dist-info/METADATA',
                                     f'Name: stallionfs\nVersion: {metadata_version}\n\n')
                write_json(output / 'build-result.json', {
                    'schema': 1, 'cache_return': [{'cache_return': True, 'calls': 1}], 'guard_effects': [],
                    'architecture': 'x86_64', 'interpreter_version': sys.version,
                    'interpreter_sha256': build.digest(Path(sys.executable).read_bytes()),
                    'git_compilation': 'reused exact qualified component', 'wheel': selected.name,
                    'wheel_sha256': build.digest(selected.read_bytes()), 'descriptor_sha256': descriptor_sha,
                    'source_pins_sha256': write_json(pins_path, producer_pins)})
                candidate_path.unlink(missing_ok=True)
                events = closure / f'child-{len(list(closure.glob("*.jsonl")))}.jsonl'
                receipt = entry.supervise([sys.executable, '-I', '-B', '-c', CHILD,
                                           str(TOOLS / 'ci_test_entry.py'), str(events)],
                                          events, 10, mode='suite', job=job, echo=False)
                self.assertTrue(receipt['success'], (receipt, events.read_text()))
                write_json(suite_path, dict(receipt, qualification=True))
                budget.finish('suite', job)
                return receipt

            job = allocate(400)
            run_child(pins)
            candidate = json.loads(candidate_path.read_bytes())
            write_json(candidate_path, dict(candidate, invocation='f' * 32))
            with self.assertRaisesRegex(ValueError, 'different suite or source'):
                build.stage_intel_wheel(checkout, root, entry, job)
            write_json(candidate_path, candidate)
            wheel.write_bytes(b'mutated')
            with self.assertRaisesRegex(ValueError, 'Input digest mismatch'):
                build.stage_intel_wheel(checkout, root, entry, job)

            changed_pyproject = inputs['pyproject.toml'].replace(b'0.7.0', b'0.7.1')
            drift = [dict(row, sha256=build.digest(changed_pyproject)) if row['path'] == 'pyproject.toml'
                     else row for row in pins]
            run_child(drift, metadata_version='0.7.1', filename_version='0.7.1')
            with self.assertRaisesRegex(ValueError, 'Producer source bytes differ'):
                build.stage_intel_wheel(checkout, root, entry, job)

            for bad_pins, message in ((pins[:-1], 'receipt shape differs'),
                                      ([*pins[:-1], dict(pins[-1], path='unrelated.py')], 'set differs'),
                                      ([*pins[:-1], dict(pins[-1], mode='0o755')], 'mode differs')):
                with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                    build.committed_wheel_inputs(checkout, root, SOURCE, bad_pins)
            inputs['stallionfs/new_source.c'] = b'committed source absent from producer pins'
            with self.assertRaisesRegex(ValueError, 'receipt shape differs'):
                build.committed_wheel_inputs(checkout, root, SOURCE, pins)
            del inputs['stallionfs/new_source.c']

            run_child(pins, metadata_version='0.7.1')
            with self.assertRaisesRegex(ValueError, 'Wheel metadata differs'):
                build.stage_intel_wheel(checkout, root, entry, job)
            run_child(pins, metadata_version='0.7.1', filename_version='0.7.1')
            with self.assertRaisesRegex(ValueError, 'Wheel filename version differs'):
                build.stage_intel_wheel(checkout, root, entry, job)
            self.assertFalse(stage.exists())

            job = allocate(124)
            self.assertEqual(budget.tail('wheel-upload'), 1)
            self.assertEqual((root / 'outputs').read_text(), 'admitted=false\n')
            self.assertFalse(stage.exists())

            job = allocate(400)
            receipt = run_child(pins)
            original = wheel.read_bytes()
            self.assertEqual(build.stage_intel_wheel(checkout, root, entry, job), WHEEL)
            self.assertEqual({path.name for path in stage.iterdir()}, {WHEEL, 'proof.json'})
            self.assertEqual((stage / WHEEL).read_bytes(), original)
            proof_data = (stage / 'proof.json').read_bytes()
            proof = json.loads(proof_data)
            self.assertNotIn(str(root).encode(), proof_data)
            self.assertEqual(proof['source_sha'], SOURCE)
            self.assertEqual(proof['wheel']['sha256'], build.digest(original))
            self.assertEqual(proof['suite']['invocation'], receipt['invocation'])
