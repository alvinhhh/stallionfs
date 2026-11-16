"""Bounded installed-wheel ImageSpace diagnostics; never a full qualification."""
import argparse
import base64
from contextlib import contextmanager, nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import unittest
from unittest.mock import patch

SELECTOR = 'test_images_space.ImageSpace.test_volume_full_preserves_existing_data_and_other_images'
OBSERVATION = 'enospc-sibling-detach'
MODE = 'image-space-repeat'
INTEL_MODE = 'image-space-repeat-intel'
SNAPSHOT = 'test_image_store.ImageStoreTests.test_snapshot_rollback_and_protected_retirement'
CHILD_SECONDS = 180
MAX_CHILDREN = 512


def require(value, message):
    if not value:
        raise ValueError(message)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def count(value):
    require(isinstance(value, str) and re.fullmatch(r'(?:[1-9]|1[0-9]|20)', value),
            'Repeat count must be an integer from 1 through 20')
    return int(value)


def gate(env):
    require(env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and env.get('IMAGE_REPEAT_MODE') in (MODE, INTEL_MODE), 'Manual diagnostic mode required')
    expected = env.get('EXPECTED_SOURCE_SHA', '')
    require(re.fullmatch('[0-9a-f]{40}', expected) and expected == env.get('GITHUB_SHA'),
            'Exact reviewed source SHA required')
    require(env.get('STALLIONFS_TEST_IMAGES') == '1'
            and env.get('STALLIONFS_TEST_SNAPSHOT_OBSERVATION') == OBSERVATION,
            'Exact image observation selector required')
    require(env.get('RUNNER_OS') == 'macOS' and env.get('RUNNER_ARCH') == ('X64' if env.get('IMAGE_REPEAT_MODE') == INTEL_MODE else 'ARM64'),
            'Profile macOS runner architecture required')
    repetitions = count(env.get('IMAGE_REPEAT_COUNT', ''))
    if env.get('IMAGE_REPEAT_MODE') == INTEL_MODE:
        require(repetitions <= 10, 'Intel campaigns are bounded to 10 pairs')
        require(all(re.fullmatch(r'[1-9][0-9]*', env.get(key, '')) for key in
                    ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')) and bool(env.get('GITHUB_JOB')),
                'Hosted run and job binding required')
    return repetitions


def selectors_for(env):
    return (SELECTOR, SNAPSHOT) if env.get('IMAGE_REPEAT_MODE') == INTEL_MODE else (SELECTOR,)


def binding(env):
    """Bind each Intel child to this source, hosted attempt and interpreter."""
    return {**{key: env.get(key) for key in ('GITHUB_SHA', 'GITHUB_RUN_ID',
            'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB', 'IMAGE_REPEAT_MODE')},
            'executable': sys.executable, 'python': sys.version,
            'interpreter_sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()}


def recovery_complete(diagnostics, events):
    """Pair every raw command failure with a complete, admitted public recovery."""
    failures = [row for row in events if row['kind'] == 'failure']
    require(type(diagnostics.attempts) is int and len(failures) == diagnostics.attempts,
            'Raw failure accounting differs')
    ids = [row['operation_id'] for row in failures]
    require(len(set(ids)) == len(ids) and all(type(i) is int and i > 0 for i in ids),
            'Failure operation identity differs')
    require(all(row['kind'] in ('failure', 'mapping', 'lsof', 'unavailable', 'eject_log',
                                      'eject_command', 'validation', 'eject_outcome')
                and row['phase'] == 'after' and row['operation_id'] in ids for row in events),
            'Unpaired recovery evidence')
    for failure in failures:
        rows = [row for row in events if row['operation_id'] == failure['operation_id']]
        proof = [row for row in rows if row['kind'] in ('failure', 'eject_command', 'validation', 'eject_outcome')]
        require([row['kind'] for row in proof] ==
                ['failure', 'eject_command', 'validation', 'validation', 'eject_outcome'],
                'Recovery evidence incomplete')
        _, command, current, confirmed, outcome = proof
        device = failure['failed_device']
        require(isinstance(device, str) and re.fullmatch(r'/dev/disk[0-9]+', device),
                'Recovery device invalid')
        require(failure['operation'] == 'eject' and failure['error'] == '_CommandFailure'
                and failure['expected_busy'] is False and failure['expected_mountpoint'] is not None,
                'Unqualified raw failure')
        require(command['attempt'] == 1 and command['executable'] == '/usr/sbin/diskutil'
                and command['verb'] == 'eject' and command['device'] == device
                and command['returncode'] == 1 and command['complete'] is True,
                'First failed command incomplete')
        stdout = base64.b64decode(command['stdout_base64'], validate=True).strip()
        stderr = base64.b64decode(command['stderr_base64'], validate=True).strip()
        require(stdout in (b'', f'Eject failed for {device.removeprefix("/dev/")}'.encode())
                and stderr == b'Volume failed to eject', 'First failure not admitted for recovery')
        for sample, read in ((current, 'current'), (confirmed, 'confirmed')):
            require(sample['read'] == read and sample['sample_status'] == 'validated'
                    and sample['reason'] is None and sample['selected_device'] == device
                    and sample['mountpoint_state'] == 'expected' and bool(sample['entities'])
                    and device in [entry['device'] for entry in sample['entities']],
                    'Recovery normal validation incomplete')
        require(all(current[key] == confirmed[key] for key in
                    ('selected_device', 'volume_device', 'mountpoint_state', 'entities')),
                'Recovery validation mapping differs')
        require(type(outcome['commands']) is int and outcome['commands'] == 2
                and type(outcome['first_status']) is int and outcome['first_status'] == 1
                and type(outcome['continuation_status']) is int and outcome['continuation_status'] == 0
                and outcome['outcome'] == 'recovered', 'Public recovery incomplete')


def diagnostic_events(diagnostics, directory):
    require(directory is not None and 'image_failure_diagnostics' in sys.modules, 'Diagnostic artifact missing')
    module = sys.modules['image_failure_diagnostics']
    require(not diagnostics.capture_disabled and diagnostics.attempts < module.ATTEMPTS
            and module.artifact_available(directory),
            'Diagnostic artifact incomplete')
    return [json.loads(line) for line in (directory / module.REPORT).read_bytes().splitlines()]


def snapshot_complete(diagnostics, directory):
    require(not diagnostics.capture_disabled and diagnostics.before_attempts == 0,
            'Snapshot diagnostics incomplete or unexpected observation')
    if diagnostics.attempts == 0:
        require(directory is None or not (directory / 'image-failures.jsonl').exists(),
                'Unaccounted snapshot evidence')
        return
    recovery_complete(diagnostics, diagnostic_events(diagnostics, directory))


def bind_test_sources(checkout):
    """Bind the test and its cleanup hook to the reviewed commit before import."""
    names = ('tools/ci_image_repeat.py', 'tests/test_images_space.py',
             'tests/test_image_store.py', 'tests/image_failure_diagnostics.py')
    expected = {}
    for name in names:
        result = subprocess.run(['git', 'show', os.environ['GITHUB_SHA'] + ':' + name],
                                cwd=checkout, capture_output=True, check=True, timeout=10)
        expected[name] = result.stdout
    def check():
        require(all((checkout / name).read_bytes() == data for name, data in expected.items()),
                'Reviewed test or cleanup source differs')
    check()
    return check


@contextmanager
def owned_children():
    """Account only for direct Popen children; never signal observed helper PIDs."""
    children = []
    original = subprocess.Popen.__init__

    def initialize(child, *args, **kwargs):
        require(len(children) < MAX_CHILDREN, 'Direct child count exceeds bound')
        original(child, *args, **kwargs)
        children.append(child)

    with patch.object(subprocess.Popen, '__init__', initialize):
        yield children


def child_status(children, *, complete=True):
    records = []
    for child in children:
        row = {'pid': child.pid, 'returncode': None}
        try:
            row['returncode'] = child.poll()
        except BaseException as error:
            row['error'] = type(error).__name__
        records.append(row)
    if complete:
        require(all(type(row['returncode']) is int for row in records),
                'Direct command child completion uncertain')
    return records


def observation_complete(diagnostics, directory):
    """Require the selected mapped sibling and both complete holder queries."""
    intel = os.environ.get('IMAGE_REPEAT_MODE') == INTEL_MODE
    require(not diagnostics.capture_disabled and diagnostics.before_attempts == 1
            and (intel or diagnostics.attempts == 0), 'Observation budget or unexpected failure')
    module = sys.modules['image_failure_diagnostics']
    require(module.artifact_available(directory), 'Observation artifact incomplete')
    events = [json.loads(line) for line in (directory / module.REPORT).read_bytes().splitlines()]
    if intel:
        recovery_complete(diagnostics, [row for row in events if row['phase'] != 'before'])
        events = [row for row in events if row['phase'] == 'before']
    require([row['kind'] for row in events] == ['observation', 'mapping', 'lsof', 'lsof'],
            'Exact observation events incomplete')
    first, mapping, *holders = events
    require(all(row['phase'] == 'before' and row['operation_id'] == first['operation_id'] for row in events),
            'Observation operation differs')
    require(first['operation'] == 'eject' and first['stage'] == 'sibling-detach'
            and first['expected_busy'] is False and first['error'] is None
            and first['observation'] == 'before detach validation'
            and first.get('pre_observation') == 'attempted', 'Selected sibling detach unavailable')
    require(Path(mapping['image']).name == 'sibling.sparseimage'
            and mapping['mountpoint_matches'] is True
            and mapping['mountpoint'] == mapping['expected_mountpoint']
            and mapping['mountpoint'] == first['expected_mountpoint']
            and mapping['mountpoint'] is not None and mapping['volume_device'] in mapping['devices']
            and mapping['backing_identity_matches_first'] is True,
            'Sibling mapping incomplete')
    if intel:
        for failure in [row for row in diagnostic_events(diagnostics, directory) if row['kind'] == 'failure']:
            if failure['operation_id'] == first['operation_id']:
                require(failure['expected_mountpoint'] == first['expected_mountpoint']
                        and failure['failed_device'] in mapping['devices'],
                        'Selected recovery operation differs')
    for index, row in enumerate(holders):
        require(type(row['returncode']) is int and row['returncode'] in (0, 1)
                and row['stderr'] == '' and isinstance(row['stdout'], str)
                and row['reaped'] is True and row['timeout'] is False and row['truncated'] is False
                and row['display_truncated'] is False and row['capture_error'] is None
                and row['cleanup_error'] is None
                and (row['backing_device_after'], row['backing_inode_after']) ==
                    (mapping['backing_device'], mapping['backing_inode']), 'Holder observation incomplete')
        require(row['backing_identity_status'] == ('matched' if index == 0 else 'not_queried'),
                'Backing holder identity incomplete')
        # Exit 1 can mean one of the requested selections had no match. Validate
        # the structured records independently of the exit status, using the
        # same parser that established the collector's backing identity.
        require(module.Diagnostics._holder_identity(row['stdout'].splitlines(),
                    mapping['image'] if index == 0 else None,
                    (mapping['backing_device'], mapping['backing_inode'])) == row['backing_identity_status'],
                'Holder records incomplete')


def run_suite(suite, fixture_class, diagnostics, directory, children, *, snapshot_module=None, acceptance=None):
    if fixture_class is None:
        def checked_remove(base):
            # image_fixture reaches this slot only after successful owned cleanup.
            snapshot_complete(diagnostics, directory)
            diagnostics.close()
            child_status(children)
            if acceptance is not None:
                acceptance()
            return original_remove(base)
        if snapshot_module is not None:
            original_remove = snapshot_module.remove_tree
            require(snapshot_module.image_fixture.__wrapped__.__globals__ is vars(snapshot_module)
                    and Path(snapshot_module.image_fixture.__wrapped__.__code__.co_filename).resolve() ==
                        Path(snapshot_module.__file__).resolve(),
                    'Snapshot cleanup hook differs')
        with patch.object(snapshot_module, 'remove_tree', checked_remove) if snapshot_module is not None else nullcontext():
            result = unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)
        require(result.testsRun == 1 and result.wasSuccessful() and not result.skipped
                and not result.expectedFailures and not result.unexpectedSuccesses,
                'Exact test failed, skipped or incomplete')
        snapshot_complete(diagnostics, directory)
        return
    original_clean = fixture_class.clean

    def checked_clean(test):
        # Check before the fixture deletes itself, so incomplete evidence is kept.
        if not getattr(test, 'retain', False):
            try:
                observation_complete(diagnostics, directory)
                child_status(children)
                if acceptance is not None:
                    acceptance()
            except BaseException:
                test.retain = True
                raise
        return original_clean(test)

    with patch.object(fixture_class, 'clean', checked_clean):
        result = unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)
    require(result.testsRun == 1 and result.wasSuccessful() and not result.skipped
            and not result.expectedFailures and not result.unexpectedSuccesses,
            'Exact test failed, skipped or incomplete')


def invoke(checkout, root, selector):
    require(selector in selectors_for(os.environ), 'Exact test selector required')
    require(sys.platform == 'darwin' and platform.mac_ver()[0].split('.')[0] == '26'
            and (platform.machine(), sys.version_info[:2]) ==
                (('x86_64', (3, 13)) if os.environ.get('IMAGE_REPEAT_MODE') == INTEL_MODE else ('arm64', (3, 11))),
            'Diagnostic requires actual macOS 26 and profile architecture/Python')
    gate(os.environ)
    import stallionfs
    from stallionfs import images, _scan
    for module in (stallionfs, images, _scan):
        require(not Path(module.__file__).resolve().is_relative_to(checkout), 'Installed wheel required')
    require(Path.cwd() == root and Path(os.environ['TMPDIR']).resolve() == root / 'tmp',
            'Fresh invocation directory required')
    controller = load('image_repeat_ci_build', checkout / 'tools/ci_build.py')
    admitted = controller.initialize_installed(checkout, Path(os.environ['RUNNER_TEMP']).resolve() / 'qualified-wheel')
    admitted['check']()
    source_check = bind_test_sources(checkout) if os.environ.get('IMAGE_REPEAT_MODE') == INTEL_MODE else lambda: None
    sys.path.insert(0, str(checkout / 'tests'))
    import image_failure_diagnostics as diagnostic_module
    test_module_name = selector.split('.')[0]
    test_module = __import__(test_module_name)
    require(Path(test_module.__file__).resolve() == checkout / 'tests' / (test_module_name + '.py'),
            'Test source differs')
    suite = unittest.defaultTestLoader.loadTestsFromName(selector)
    require(suite.countTestCases() == 1 and [test.id() for test in suite] == [selector],
            'Exact loaded test required')
    directory = root / 'diagnostics'
    diagnostics = diagnostic_module.install(images, directory)
    status = {'scope': 'diagnostic-only', 'full_qualification': False, 'passed': False,
              'selector': selector, 'observation': OBSERVATION if selector == SELECTOR else None, 'owned_children': [],
              'host': {'macos': platform.mac_ver()[0], 'python': platform.python_version(),
                       'architecture': platform.machine()}}
    if os.environ.get('IMAGE_REPEAT_MODE') == INTEL_MODE:
        status['binding'] = binding(os.environ)
    completion = observation_complete if selector == SELECTOR else snapshot_complete
    try:
        with owned_children() as children:
            try:
                run_suite(suite, test_module.ImageSpace if selector == SELECTOR else None, diagnostics, directory, children,
                          snapshot_module=test_module if selector == SNAPSHOT else None,
                          acceptance=lambda: (source_check(), admitted['check']()))
                completion(diagnostics, directory)
            finally:
                try:
                    diagnostics.close()
                finally:
                    status['owned_children'] = child_status(children, complete=False)
                    require(all(type(row['returncode']) is int for row in status['owned_children']),
                            'Direct command child completion uncertain')
        admitted['check']()
        require(not list((root / 'tmp').iterdir()), 'Owned fixture cleanup incomplete; retained')
        status['qualified_recoveries'] = diagnostics.attempts
        status['passed'] = True
    except BaseException as error:
        status['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        status['raw_diagnostic_attempts'] = diagnostics.attempts
        write(root / 'result.json', status)


def repeat(checkout, root, repetitions, capture):
    maximum = 10 if os.environ.get('IMAGE_REPEAT_MODE') == INTEL_MODE else 20
    require(type(repetitions) is int and 1 <= repetitions <= maximum, 'Invalid repetition count')
    require(root.is_absolute() and root.parent.resolve(strict=True) == root.parent,
            'Physical evidence parent required')
    root.mkdir(mode=0o700)
    status = {'scope': 'diagnostic-only', 'full_qualification': False, 'passed': False,
              'requested': repetitions, 'completed': 0, 'selector': SELECTOR, 'observation': OBSERVATION}
    selectors = selectors_for(os.environ)
    status.update(selectors=list(selectors), completed_tests=0, attempted_tests=0)
    if os.environ.get('IMAGE_REPEAT_MODE') == INTEL_MODE:
        status['binding'] = binding(os.environ)
    try:
        for trial in range(repetitions * len(selectors)):
            index = trial // len(selectors) + 1
            selector = selectors[trial % len(selectors)]
            status['attempted_tests'] += 1
            suffix = ('-space' if selector == SELECTOR else '-snapshot') if len(selectors) > 1 else ''
            invocation = root / f'iteration-{index:02d}{suffix}'
            invocation.mkdir(mode=0o700)
            temporary = invocation / 'tmp'
            temporary.mkdir(mode=0o700)
            capture._COMMAND_ENV = dict(os.environ, TMPDIR=str(temporary))
            result = capture._owned_command([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                'invoke', '--checkout', str(checkout), '--root', str(invocation), '--selector', selector],
                cwd=invocation, timeout=CHILD_SECONDS, stem=invocation / 'child')
            result.check_returncode()
            load('image_repeat_ci_execute', Path(__file__).with_name('ci_execute.py')).require_capture(capture)
            observed = json.loads((invocation / 'result.json').read_bytes())
            require(observed.get('scope') == 'diagnostic-only' and observed.get('full_qualification') is False
                    and observed.get('passed') is True and observed.get('selector') == selector
                    and observed.get('observation') == (OBSERVATION if selector == SELECTOR else None)
                    and not list(temporary.iterdir()), 'Child test, observation or cleanup incomplete')
            if 'binding' in status:
                require(observed.get('binding') == status['binding'], 'Child source, run or interpreter differs')
            status['completed_tests'] += 1
            status['completed'] = status['completed_tests'] // len(selectors)
        status['passed'] = True
    except BaseException as error:
        status['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        write(root / 'summary.json', status)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('repeat', 'invoke'))
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--selector', default=SELECTOR, choices=(SELECTOR, SNAPSHOT))
    args = parser.parse_args()
    repetitions = gate(os.environ)
    checkout = args.checkout.resolve(strict=True)
    root = args.root.absolute()
    os.umask(0o077)
    if args.action == 'invoke':
        invoke(checkout, root, args.selector)
    else:
        capture = load('image_repeat_capture', Path(__file__).with_name('_git_capture.py'))
        previous = capture._install_command_handlers()
        try:
            repeat(checkout, root, repetitions, capture)
        finally:
            capture._restore_command_handlers(previous)


if __name__ == '__main__':
    main()
