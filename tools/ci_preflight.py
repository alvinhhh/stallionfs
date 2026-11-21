"""Conservative change classification and portable CI contract checks."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEST_INPUTS = frozenset(('README.md', 'docs/fskit-maintenance.md'))
PORTABLE_TESTS = (
    'test_ci_preflight',
    'test_ci_build',
    'test_ci_git_input',
    'test_ci_image_repeat',
    'test_ci_test_entry.EntryTests.test_workflow_entry_allocation_and_fixed_discovery',
    'test_ci_test_entry.AccountingTests',
    'test_ci_test_entry.CaptureResultTests',
    'test_ci_test_entry.ParentShapeTests',
    'test_ci_evidence.EvidenceTests.test_workflow_all_required_work_precedes_suite',
    'test_native_delete_phase_probe',
    'test_native_directory_clone_probe',
)


def non_code(path):
    parts = PurePosixPath(path).parts
    if (not parts or path.startswith('/') or '..' in parts
            or path in TEST_INPUTS or parts[-1].startswith('LICENSE')):
        return False
    return (path.startswith(('docs/', '.github/ISSUE_TEMPLATE/'))
            or path.endswith('.md'))


def requires_macos(paths):
    return paths is None or not paths or not all(non_code(path) for path in paths)


def changed_paths(event_name, event, checkout):
    try:
        if event_name == 'pull_request':
            before = event['pull_request']['base']['sha']
            after = event['pull_request']['head']['sha']
        elif event_name == 'push':
            before, after = event['before'], event['after']
        else:
            return None
        if any(not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{40}', sha)
               or sha == '0' * 40 for sha in (before, after)):
            return None
        result = subprocess.run(
            ['git', 'diff', '--no-ext-diff', '--no-renames', '--name-only', '-z', before, after, '--'],
            cwd=checkout, check=True, capture_output=True, timeout=30)
        return [os.fsdecode(path) for path in result.stdout.split(b'\0') if path]
    except (KeyError, TypeError, OSError, subprocess.SubprocessError):
        return None


def portable_tests(checkout):
    sys.path[:0] = [str(checkout / 'tests'), str(checkout)]
    suite = unittest.defaultTestLoader.loadTestsFromNames(PORTABLE_TESTS)
    result = unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)
    return 0 if result.wasSuccessful() else 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('classify', 'test'))
    args = parser.parse_args(argv)
    if args.mode == 'test':
        return portable_tests(ROOT)
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    paths = changed_paths(os.environ['GITHUB_EVENT_NAME'], event, ROOT)
    value = str(requires_macos(paths)).lower()
    print('macos=' + value)
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('macos=' + value + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
