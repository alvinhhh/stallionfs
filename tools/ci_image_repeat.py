"""Bounded installed-wheel ImageSpace diagnostics; never a full qualification."""
import argparse
from contextlib import contextmanager
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
            and env.get('IMAGE_REPEAT_MODE') == MODE, 'Manual diagnostic mode required')
    expected = env.get('EXPECTED_SOURCE_SHA', '')
    require(re.fullmatch('[0-9a-f]{40}', expected) and expected == env.get('GITHUB_SHA'),
            'Exact reviewed source SHA required')
    require(env.get('STALLIONFS_TEST_IMAGES') == '1'
            and env.get('STALLIONFS_TEST_SNAPSHOT_OBSERVATION') == OBSERVATION,
            'Exact image observation selector required')
    require(env.get('RUNNER_OS') == 'macOS' and env.get('RUNNER_ARCH') == 'ARM64',
            'macOS ARM64 runner required')
    return count(env.get('IMAGE_REPEAT_COUNT', ''))


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
    require(not diagnostics.capture_disabled and diagnostics.before_attempts == 1
            and diagnostics.attempts == 0, 'Observation budget or unexpected failure')
    module = sys.modules['image_failure_diagnostics']
    require(module.artifact_available(directory), 'Observation artifact incomplete')
    events = [json.loads(line) for line in (directory / module.REPORT).read_bytes().splitlines()]
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
    for index, row in enumerate(holders):
        require(type(row['returncode']) is int and row['returncode'] in (0, 1)
                and row['stderr'] == '' and (row['returncode'] == 0 or row['stdout'] == '')
                and row['reaped'] is True and row['timeout'] is False and row['truncated'] is False
                and row['display_truncated'] is False and row['capture_error'] is None
                and row['cleanup_error'] is None
                and (row['backing_device_after'], row['backing_inode_after']) ==
                    (mapping['backing_device'], mapping['backing_inode']), 'Holder observation incomplete')
        require(row['backing_identity_status'] == ('matched' if index == 0 else 'not_queried'),
                'Backing holder identity incomplete')


def run_suite(suite, fixture_class, diagnostics, directory, children):
    original_clean = fixture_class.clean

    def checked_clean(test):
        # Check before the fixture deletes itself, so incomplete evidence is kept.
        if not getattr(test, 'retain', False):
            try:
                observation_complete(diagnostics, directory)
                child_status(children)
            except BaseException:
                test.retain = True
                raise
        return original_clean(test)

    with patch.object(fixture_class, 'clean', checked_clean):
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    require(result.testsRun == 1 and result.wasSuccessful() and not result.skipped
            and not result.expectedFailures and not result.unexpectedSuccesses,
            'Exact test failed, skipped or incomplete')


def invoke(checkout, root, selector):
    require(selector == SELECTOR, 'Exact test selector required')
    require(sys.platform == 'darwin' and platform.mac_ver()[0].split('.')[0] == '26'
            and platform.machine() == 'arm64' and sys.version_info[:2] == (3, 11),
            'Diagnostic requires actual macOS 26 ARM64 and Python 3.11')
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
    sys.path.insert(0, str(checkout / 'tests'))
    import image_failure_diagnostics as diagnostic_module
    import test_images_space
    require(Path(test_images_space.__file__).resolve() == checkout / 'tests/test_images_space.py',
            'Test source differs')
    suite = unittest.defaultTestLoader.loadTestsFromName(selector)
    require(suite.countTestCases() == 1 and [test.id() for test in suite] == [SELECTOR],
            'Exact loaded test required')
    directory = root / 'diagnostics'
    diagnostics = diagnostic_module.install(images, directory)
    status = {'scope': 'diagnostic-only', 'full_qualification': False, 'passed': False,
              'selector': selector, 'observation': OBSERVATION, 'owned_children': [],
              'host': {'macos': platform.mac_ver()[0], 'python': platform.python_version(),
                       'architecture': platform.machine()}}
    try:
        with owned_children() as children:
            try:
                run_suite(suite, test_images_space.ImageSpace, diagnostics, directory, children)
                observation_complete(diagnostics, directory)
            finally:
                try:
                    diagnostics.close()
                finally:
                    status['owned_children'] = child_status(children, complete=False)
                    require(all(type(row['returncode']) is int for row in status['owned_children']),
                            'Direct command child completion uncertain')
        admitted['check']()
        require(not list((root / 'tmp').iterdir()), 'Owned fixture cleanup incomplete; retained')
        status['passed'] = True
    except BaseException as error:
        status['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        write(root / 'result.json', status)


def repeat(checkout, root, repetitions, capture):
    require(type(repetitions) is int and 1 <= repetitions <= 20, 'Invalid repetition count')
    require(root.is_absolute() and root.parent.resolve(strict=True) == root.parent,
            'Physical evidence parent required')
    root.mkdir(mode=0o700)
    status = {'scope': 'diagnostic-only', 'full_qualification': False, 'passed': False,
              'requested': repetitions, 'completed': 0, 'selector': SELECTOR, 'observation': OBSERVATION}
    try:
        for index in range(1, repetitions + 1):
            invocation = root / f'iteration-{index:02d}'
            invocation.mkdir(mode=0o700)
            temporary = invocation / 'tmp'
            temporary.mkdir(mode=0o700)
            capture._COMMAND_ENV = dict(os.environ, TMPDIR=str(temporary))
            result = capture._owned_command([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                'invoke', '--checkout', str(checkout), '--root', str(invocation), '--selector', SELECTOR],
                cwd=invocation, timeout=CHILD_SECONDS, stem=invocation / 'child')
            result.check_returncode()
            load('image_repeat_ci_execute', Path(__file__).with_name('ci_execute.py')).require_capture(capture)
            observed = json.loads((invocation / 'result.json').read_bytes())
            require(observed.get('scope') == 'diagnostic-only' and observed.get('full_qualification') is False
                    and observed.get('passed') is True and observed.get('selector') == SELECTOR
                    and observed.get('observation') == OBSERVATION
                    and not list(temporary.iterdir()), 'Child test, observation or cleanup incomplete')
            status['completed'] = index
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
    parser.add_argument('--selector', default=SELECTOR, choices=(SELECTOR,))
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
