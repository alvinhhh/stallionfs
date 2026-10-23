"""Workspace statistics and argument checks without creating workspaces."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock


PERF = Path(__file__).parent / 'perf'
with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
    spec = importlib.util.spec_from_file_location('workspace_statistics', PERF / 'run.py')
    workspace = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(workspace)


def rows(wall=1.0, cpu=0.005, count=10):
    return [dict(pair_id=i + 1, phase='timing', ok=True, validated=True,
                 total_s=wall, total_cpu_s=cpu,
                 precision_floor={'wall_s': 1e-9, 'cpu_s': 0.000012006})
            for i in range(count)]


class WorkspaceStatistics(unittest.TestCase):
    def test_completion_requires_finished_cleanup(self):
        for cleanup in (True, False):
            with self.subTest(cleanup=cleanup), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                root = Path(directory).resolve()
                output = root / 'report.json'
                arguments = ['run.py', '--scratch', str(root), '--npm-cache', str(root),
                             '--output', str(output), '--source-files', '1', '--concurrency', '1',
                             '--methods', 'stallionfs_folder']
                store = mock.Mock(root=root / 'store')
                store.prepare.return_value = {'id': 'seed'}
                store.create.return_value = {'id': 'workspace', 'path': str(root / 'workspace')}
                store.gc.return_value = ['workspace']
                stack.enter_context(mock.patch.object(sys, 'argv', arguments))
                stack.enter_context(mock.patch.object(workspace, 'Store', return_value=store))
                stack.enter_context(mock.patch.object(workspace, 'git'))
                stack.enter_context(mock.patch.object(workspace, 'digest', return_value='same-content'))
                stack.enter_context(mock.patch.object(workspace, 'run', side_effect=lambda argv, *args:
                    'v24.19.0' if argv == ['node', '--version'] else '24'))
                pool = stack.enter_context(mock.patch.object(workspace, 'ThreadPoolExecutor'))
                pool.return_value.__enter__.return_value.map.side_effect = map
                stack.enter_context(mock.patch.object(workspace, 'remove_tree',
                                                       side_effect=shutil.rmtree if cleanup else lambda _: None))
                stack.enter_context(redirect_stdout(io.StringIO()))
                stack.enter_context(redirect_stderr(io.StringIO()))
                if cleanup:
                    workspace.main()
                    report = json.loads(output.read_text())
                    self.assertTrue(report['passed'])
                    self.assertTrue(report['cleanup_passed'])
                    self.assertEqual(report['status'], 'complete')
                    self.assertEqual(len(report['raw']['1']['stallionfs_folder']), 10)
                else:
                    with self.assertRaisesRegex(RuntimeError, 'cleanup did not complete'):
                        workspace.main()
                    report = json.loads(output.with_suffix('.partial.json').read_text())
                    self.assertFalse(report['passed'])
                    self.assertFalse(report.get('cleanup_passed', False))
                    self.assertFalse(output.exists())

    def test_explicit_node_and_npm_reach_preparation_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            node, npm = root / 'node', root / 'npm-cli.js'
            node.write_text('not executed')
            npm.write_text('not executed')
            output = root / 'report.json'
            arguments = ['run.py', '--scratch', str(root), '--npm-cache', str(root),
                         '--output', str(output), '--node', str(node), '--npm', str(npm),
                         '--source-files', '1']
            store = mock.Mock()
            store.prepare.side_effect = RuntimeError('stop at preparation')
            def command(argv, *args):
                return 'v24.19.0' if argv == [str(node), '--version'] else '24'
            with mock.patch.object(sys, 'argv', arguments), redirect_stderr(io.StringIO()), \
                    mock.patch.object(workspace, 'run', side_effect=command) as run, \
                    mock.patch.object(workspace, 'git'), mock.patch.object(workspace, 'Store', return_value=store), \
                    self.assertRaisesRegex(RuntimeError, 'stop at preparation'):
                workspace.main()
            self.assertIn(mock.call([str(node), str(npm), '--version']), run.call_args_list)
            setup = store.prepare.call_args.kwargs['command']
            self.assertEqual(setup[:3], [str(node), str(npm), 'ci'])
            self.assertIn('--offline', setup)
            report = json.loads(output.with_suffix('.partial.json').read_text())
            self.assertEqual(report['node_command'], [str(node)])
            self.assertEqual(report['npm_command'], [str(node), str(npm)])
            self.assertFalse(output.exists())

    def test_runtime_options_require_both_paths_before_commands(self):
        with mock.patch.object(sys, 'argv', ['run.py', '--scratch', '/unused', '--npm-cache', '/unused',
                                            '--output', '/unused/report', '--node', '/unused/node']), \
                mock.patch.object(workspace, 'run') as command, redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit) as failure:
            workspace.main()
        self.assertEqual(failure.exception.code, 2)
        command.assert_not_called()

    def test_summary_keeps_existing_keys_and_adds_distribution(self):
        keys = ('ready_s', 'remove_s', 'reclaim_s', 'total_s',
                'ready_cpu_s', 'remove_cpu_s', 'reclaim_cpu_s', 'total_cpu_s')
        result = workspace.summary([dict.fromkeys(keys, i) for i in range(1, 11)])
        self.assertEqual(set(result), set(keys))
        for value in result.values():
            self.assertEqual(value['median'], 5.5)
            self.assertEqual(value['mean'], 5.5)
            self.assertEqual((value['n'], value['min'], value['max'], value['p95']), (10, 1, 10, 10))
            self.assertAlmostEqual(value['sample_variance'], 55 / 6)

    def test_pairs_use_sample_identity_and_timing_precision(self):
        baseline, candidate = rows(wall=2.0, cpu=0.01), rows()
        for index, (left, right) in enumerate(zip(baseline, candidate)):
            left['total_s'] += index / 128
            right['total_s'] += index / 128
        result = workspace.paired_totals({'worktree_install': baseline,
                                           'stallionfs_folder': list(reversed(candidate))})
        self.assertIsNone(result['unavailable'])
        values = result['methods']['stallionfs_folder']
        self.assertEqual(values['total_s']['decision'], 'candidate_faster')
        self.assertEqual(values['total_s']['paired_sample_variance'], 0)
        self.assertEqual(values['total_cpu_s']['decision'], 'candidate_lower')
        self.assertAlmostEqual(values['total_cpu_s']['required_gap'], 0.000012006)
        self.assertEqual(values['total_cpu_s']['phase'], 'timing')

    def test_unequal_sample_counts_cannot_win(self):
        result = workspace.paired_totals({'worktree_install': rows(wall=2, count=11),
                                           'stallionfs_folder': rows()})
        for value in result['methods']['stallionfs_folder'].values():
            self.assertEqual(value['complete_pairs'], 10)
            self.assertEqual(value['decision'], 'incomplete_pairs')
            self.assertEqual(value['excluded_pairs'], [{'pair_id': 11, 'reason': 'missing pair'}])

    def test_invalid_batches_are_excluded_without_shifting_pairs(self):
        for change in ({'validated': False}, {'ok': False}, {'completion_uncertain': True},
                       {'total_s': float('nan'), 'total_cpu_s': None}):
            with self.subTest(change=change):
                candidate = rows(count=11)
                candidate[4].update(change)
                result = workspace.paired_totals({'worktree_install': rows(wall=2, count=11),
                                                   'stallionfs_folder': candidate})
                for value in result['methods']['stallionfs_folder'].values():
                    self.assertEqual(value['decision'], 'incomplete_pairs')
                    self.assertEqual(value['complete_pairs'], 10)
                    self.assertEqual(value['excluded_pairs'][0]['pair_id'], 5)

    def test_missing_baseline_is_unavailable(self):
        result = workspace.paired_totals({'stallionfs_folder': rows()})
        self.assertEqual(result['methods'], {})
        self.assertEqual(result['unavailable'], 'worktree_install was not selected')

    def test_duplicate_identity_is_rejected(self):
        candidate = rows()
        candidate[1]['pair_id'] = candidate[0]['pair_id']
        with self.assertRaisesRegex(ValueError, 'duplicate pair_id'):
            workspace.paired_totals({'worktree_install': rows(), 'stallionfs_folder': candidate})

    def test_too_few_samples_fail_before_running_commands(self):
        arguments = ['run.py', '--scratch', '/unused', '--npm-cache', '/unused',
                     '--output', '/unused/result.json']
        for samples in ('1', '9'):
            with self.subTest(samples=samples), redirect_stderr(io.StringIO()), \
                    mock.patch.object(sys, 'argv', [*arguments, '--samples', samples]), \
                    mock.patch.object(workspace, 'run') as command, \
                    mock.patch.object(workspace.tempfile, 'mkdtemp') as fixture, \
                    self.assertRaises(SystemExit) as error:
                workspace.main()
            self.assertEqual(error.exception.code, 2)
            command.assert_not_called()
            fixture.assert_not_called()
