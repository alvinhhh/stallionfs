"""Change ranges and fail-closed aggregate checks, without macOS dependencies."""
import importlib.util
import itertools
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ci_preflight', ROOT / 'tools/ci_preflight.py')
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class Classification(unittest.TestCase):
    def test_documentation_only_and_mixed_changes(self):
        paths = ['docs/usage.md', 'docs/new.txt', 'CONTRIBUTING.md', 'SECURITY.md',
                 'tests/perf/README.md', '.github/ISSUE_TEMPLATE/bug.yml', 'nested/notes.md']
        self.assertFalse(preflight.requires_macos(paths))
        for path in ('stallionfs/core.py', 'tests/test_cli.py', 'tools/ci_build.py',
                     '.github/workflows/checks.yml', 'README.md', 'LICENSE', 'LICENSE.txt',
                     'nested/LICENSE.md', 'docs/fskit-maintenance.md', 'docs/LICENSE-notice',
                     '/docs/usage.md', 'docs/../stallionfs/core.py'):
            with self.subTest(path=path):
                self.assertTrue(preflight.requires_macos([path]))
                self.assertTrue(preflight.requires_macos([*paths, path]))

    def test_empty_or_unknown_change_is_code(self):
        for paths in (None, [], ['']):
            with self.subTest(paths=paths):
                self.assertTrue(preflight.requires_macos(paths))

    def test_exact_git_ranges_include_deletions_and_both_sides_of_renames(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root).decode().strip()

            def commit():
                git('add', '--all')
                git('-c', 'user.name=CI test', '-c', 'user.email=ci@example.invalid',
                    'commit', '-qm', 'fixture')
                return git('rev-parse', 'HEAD')

            git('init', '-q')
            (root / 'code.py').write_text('source\n')
            before = commit()
            (root / 'code.py').rename(root / 'renamed.md')
            after = commit()
            for event_name, event in (
                    ('pull_request', {'pull_request': {'base': {'sha': before}, 'head': {'sha': after}}}),
                    ('push', {'before': before, 'after': after})):
                with self.subTest(event=event_name):
                    paths = preflight.changed_paths(event_name, event, root)
                    self.assertCountEqual(paths, ['code.py', 'renamed.md'])
                    self.assertTrue(preflight.requires_macos(paths))
            (root / 'renamed.md').unlink()
            (root / 'notes\nwith space.md').write_text('docs\n')
            final = commit()
            paths = preflight.changed_paths('push', {'before': after, 'after': final}, root)
            self.assertCountEqual(paths, ['renamed.md', 'notes\nwith space.md'])
            self.assertFalse(preflight.requires_macos(paths))
            self.assertEqual(preflight.changed_paths('push', {'before': final, 'after': final}, root), [])
            self.assertIsNone(preflight.changed_paths('push', {'before': 'a' * 40, 'after': final}, root))

    def test_missing_zero_or_invalid_ranges_never_skip_macos(self):
        with patch.object(preflight.subprocess, 'run') as run:
            for event_name, event in (
                    ('push', {}), ('push', {'before': '0' * 40, 'after': 'a' * 40}),
                    ('push', {'before': '--help', 'after': 'a' * 40}),
                    ('push', {'before': None, 'after': 'a' * 40}),
                    ('pull_request', {'pull_request': {}}), ('workflow_dispatch', {})):
                with self.subTest(event=event):
                    self.assertIsNone(preflight.changed_paths(event_name, event, ROOT))
            run.assert_not_called()
        for error in (OSError(), subprocess.TimeoutExpired('git', 30),
                      subprocess.CalledProcessError(128, 'git')):
            with self.subTest(error=type(error)), patch.object(preflight.subprocess, 'run', side_effect=error):
                self.assertIsNone(preflight.changed_paths('push', {'before': 'a' * 40, 'after': 'b' * 40}, ROOT))

    def test_classify_output_and_malformed_event(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event = root / 'event.json'
            output = root / 'output'
            event.write_text('{}')
            with patch.dict(os.environ, GITHUB_EVENT_PATH=str(event), GITHUB_OUTPUT=str(output),
                            GITHUB_EVENT_NAME='push'):
                for paths, value in ((['docs/usage.md'], 'false'), (None, 'true'), ([], 'true')):
                    with patch.object(preflight, 'changed_paths', return_value=paths):
                        self.assertEqual(preflight.main(['classify']), 0)
                    self.assertEqual(output.read_text().splitlines()[-1], 'macos=' + value)
                event.write_text('{')
                before = output.read_bytes()
                with self.assertRaises(json.JSONDecodeError):
                    preflight.main(['classify'])
                self.assertEqual(output.read_bytes(), before)

    def test_portable_runner_propagates_failure(self):
        for successful in (True, False):
            with self.subTest(successful=successful), patch.object(preflight.sys, 'path', list(preflight.sys.path)), \
                    patch.object(preflight.unittest.defaultTestLoader, 'loadTestsFromNames') as load, \
                    patch.object(preflight.unittest, 'TextTestRunner') as runner:
                runner.return_value.run.return_value.wasSuccessful.return_value = successful
                self.assertEqual(preflight.main(['test']), 0 if successful else 1)
                load.assert_called_once_with(preflight.PORTABLE_TESTS)
                runner.assert_called_once_with(verbosity=2, failfast=True)
                runner.return_value.run.assert_called_once_with(load.return_value)


class Workflow(unittest.TestCase):
    def test_preflight_and_execution_dependencies(self):
        text = (ROOT / '.github/workflows/checks.yml').read_text()
        job = text.split('  preflight:\n', 1)[1].split('\n  test-execution:', 1)[0]
        self.assertIn("if: github.event_name != 'workflow_dispatch'", job)
        self.assertIn('runs-on: ubuntu-latest', job)
        self.assertIn('timeout-minutes: 5', job)
        self.assertIn('fetch-depth: 0', job)
        self.assertIn("python-version: '3.13'", job)
        self.assertIn('macos: ${{ steps.changes.outputs.macos }}', job)
        self.assertIn('python -B tools/ci_preflight.py classify', job)
        self.assertIn("if: steps.changes.outputs.macos == 'true'", job)
        self.assertIn('python -B tools/ci_preflight.py test', job)
        execution = text.split('  test-execution:\n', 1)[1].split('\n  test:', 1)[0]
        self.assertIn('    needs: preflight\n', execution)
        self.assertIn("if: github.event_name != 'workflow_dispatch' && needs.preflight.result == 'success' && needs.preflight.outputs.macos == 'true'", execution)

    def test_gate_truth_table_executes_actual_shell(self):
        text = (ROOT / '.github/workflows/checks.yml').read_text()
        gate = text.split('\n  test:\n', 1)[1].split('\n  image-space-repeat:', 1)[0]
        self.assertIn('    needs: [preflight, test-execution]\n', gate)
        for name, expression in (('PREFLIGHT_RESULT', 'needs.preflight.result'),
                                 ('EXECUTION_RESULT', 'needs.test-execution.result'),
                                 ('MACOS', 'needs.preflight.outputs.macos')):
            self.assertIn(name + ': ${{ ' + expression + ' }}', gate)
        script = re.search(r'^        run: (.+)$', gate, re.MULTILINE)[1]
        for preflight_result, execution, macos in itertools.product(
                ('success', 'failure', 'cancelled', 'skipped', ''),
                ('success', 'failure', 'cancelled', 'skipped', ''), ('true', 'false', '')):
            with self.subTest(preflight=preflight_result, execution=execution, macos=macos):
                result = subprocess.run(['/bin/sh', '-e', '-c', script], capture_output=True, timeout=2,
                                        env={**os.environ, 'PREFLIGHT_RESULT': preflight_result,
                                             'EXECUTION_RESULT': execution, 'MACOS': macos})
                expected = preflight_result == 'success' and (
                    execution == 'success' or (macos == 'false' and execution == 'skipped'))
                self.assertEqual(result.returncode == 0, expected)

    def test_concurrency_keeps_event_groups_disjoint(self):
        text = (ROOT / '.github/workflows/checks.yml').read_text().split('\njobs:', 1)[0]
        self.assertIn("group: ${{ github.workflow }}-${{ github.event_name }}-${{ github.event_name == 'pull_request' && github.event.pull_request.number || github.event_name == 'push' && github.ref || github.run_id }}", text)
        self.assertIn("cancel-in-progress: ${{ github.event_name == 'pull_request' }}", text)


if __name__ == '__main__':
    unittest.main()
