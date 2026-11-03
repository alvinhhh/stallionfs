"""Installed benchmark selection, ownership, evidence and exit boundaries."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from stallionfs import __main__ as cli, benchmark


def arguments(**changes):
    values = dict(list=False, full=False, fixtures=None, operations=None, samples=10,
                  scratch=None, jobs=4, output=None, json=True, node=None, npm=None,
                  npm_cache=None, cache=['warm'])
    values.update(changes)
    return SimpleNamespace(**values)


class BenchmarkCLI(unittest.TestCase):
    def test_list_is_static_and_bypasses_store_paths_and_resources(self):
        with mock.patch.object(benchmark, '_preflight', side_effect=AssertionError('probe')), \
                mock.patch.object(Path, 'resolve', side_effect=AssertionError('resolve')), \
                mock.patch.object(tempfile, 'mkdtemp', side_effect=AssertionError('write')), \
                mock.patch.dict(sys.modules, {'stallionfs.core': None}), redirect_stdout(io.StringIO()) as stream:
            self.assertEqual(cli.main(['benchmark', '--list', '--json']), 0)
        data = json.loads(stream.getvalue())
        self.assertEqual(len(data['cases']), 37)
        self.assertFalse(data['qualified'])

    def test_json_option_works_before_or_after_command(self):
        for argv in (['--json', 'benchmark', '--list'], ['benchmark', '--json', '--list']):
            with redirect_stdout(io.StringIO()) as stream:
                self.assertEqual(cli.main(argv), 0)
            self.assertEqual(len(json.loads(stream.getvalue())['cases']), 37)

    def test_help_does_not_import_core_or_run_a_probe(self):
        with mock.patch.dict(sys.modules, {'stallionfs.core': None}), \
                mock.patch.object(benchmark, '_preflight', side_effect=AssertionError('probe')), \
                redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as stopped:
            cli.main(['benchmark', '--help'])
        self.assertEqual(stopped.exception.code, 0)

    def test_too_few_samples_are_rejected(self):
        with redirect_stdout(io.StringIO()), mock.patch.object(sys, 'stderr', io.StringIO()), \
                self.assertRaises(SystemExit) as stopped:
            cli.main(['benchmark', '--samples', '9'])
        self.assertEqual(stopped.exception.code, 2)

    def test_full_never_silently_narrows_the_campaign(self):
        for change in ({'fixtures': ['tiny_4kib']}, {'operations': ['delete']}, {'jobs': 1}):
            with mock.patch.object(sys, 'platform', 'darwin'), self.assertRaisesRegex(ValueError, 'do not narrow'):
                benchmark._preflight(arguments(full=True, **change))

    def test_all_fixed_cases_and_both_api_methods_stay_visible(self):
        coverage = benchmark._coverage(['warm'])
        self.assertEqual(len(coverage), 37)
        self.assertEqual(len({row['id'] for row in coverage}), 37)
        row = next(row for row in coverage if row['id'] == 'api-scan/flat')
        self.assertEqual({cell['reference'] for cell in row['required_cells']},
                         {'bulk_serial-vs-posix', 'bulk-vs-posix'})
        cli_row = next(row for row in coverage if row['id'] == 'cli/scan/empty')
        self.assertTrue(all(cell['status'] == 'unavailable' for cell in cli_row['required_cells']))
        self.assertTrue(all(not cell['win'] for row in coverage for cell in row['required_cells']))
        workspaces = [row for row in coverage if row['required_set'] == 'WORKSPACE']
        self.assertEqual(len(workspaces), 2)
        self.assertTrue(all(row['collector'] == 'workspaces' for row in workspaces))

    def test_fallback_clone_reference_is_not_mandatory_clone_evidence(self):
        row = next(row for row in benchmark._coverage(['warm', 'cold'])
                   if row['id'] == 'fileops/clone/docs_5k_100mb')
        self.assertEqual({cell['reference'] for cell in row['required_cells']},
                         {'cp-clone', 'cp', 'ditto', 'rsync'})
        self.assertTrue(any(cell['status'] == 'inadmissible' for cell in row['required_cells']))
        self.assertFalse(any(cell['win'] for cell in row['required_cells']))

    def test_ordinary_copy_coverage_is_selected_but_never_qualified(self):
        for cache, collected in ((['warm'], True), (['warm', 'cold'], True),
                                 (['cold'], True), (['cold'], False)):
            with self.subTest(cache=cache, collected=collected):
                row = next(row for row in benchmark._coverage(cache, collected=collected)
                           if row['id'] == 'native/copy/tiny_4kib')
                self.assertEqual(row['collector'], 'native-copy')
                self.assertFalse(row['catalog_only'])
                self.assertFalse(row['qualified'])
                self.assertEqual(len(row['required_cells']), 4)
                for cell in row['required_cells']:
                    self.assertEqual(cell['output'], 'plain')
                    self.assertEqual(cell['status'], 'collected_unverified'
                                     if collected and cell['cache'] in cache else 'unavailable')
                    self.assertFalse(cell['win'])

    def test_existing_output_and_sidecars_are_never_overwritten(self):
        for suffix in ('', '.journal', '.manifest'):
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'result.json'
                existing = output.with_name(output.name + suffix)
                existing.write_bytes(b'keep')
                with self.assertRaisesRegex(ValueError, 'already exists'):
                    benchmark._new_output(output)
                self.assertEqual(existing.read_bytes(), b'keep')

    def test_missing_full_prerequisites_do_not_create_a_run(self):
        with mock.patch.object(sys, 'platform', 'darwin'), \
                mock.patch.object(benchmark, '_resources', return_value=Path('/installed/runtime')), \
                mock.patch.object(tempfile, 'mkdtemp', side_effect=AssertionError('created')), \
                redirect_stdout(io.StringIO()) as stream:
            code = benchmark.run(arguments(full=True))
        data = json.loads(stream.getvalue())
        self.assertEqual(code, 1)
        self.assertIn('--node', data['error'])
        self.assertIn('--npm-cache', data['error'])
        self.assertIsNone(data['run_directory'])

    def test_native_executable_is_the_installed_helper_sibling(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('stallionfs', 'stallionfs-python'):
                path = root / name
                path.write_text('')
                path.chmod(0o700)
            with mock.patch.object(sys, 'platform', 'darwin'), \
                    mock.patch.object(sys, 'argv', [str(root / 'stallionfs-python')]), \
                    mock.patch.object(benchmark, 'TOOLS', ()), \
                    mock.patch.object(benchmark, '_resources', return_value=root), \
                    mock.patch.object(benchmark.sysconfig, 'get_path', return_value='/wrong'), \
                    mock.patch.object(benchmark.shutil, 'disk_usage', return_value=SimpleNamespace(free=10**15)):
                _, binary, _, _, _ = benchmark._preflight(arguments(scratch=root))
            self.assertEqual(binary, root / 'stallionfs')

    def test_scratch_symlink_is_not_used_as_an_operand_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            link = root / 'link'
            link.symlink_to(root, target_is_directory=True)
            for name in ('stallionfs', 'stallionfs-python'):
                file = root / name
                file.write_text('')
                file.chmod(0o700)
            with mock.patch.object(sys, 'platform', 'darwin'), \
                    mock.patch.object(sys, 'argv', [str(root / 'stallionfs-python')]), \
                    mock.patch.object(benchmark, 'TOOLS', ()), \
                    mock.patch.object(benchmark, '_resources', return_value=root), \
                    self.assertRaisesRegex(ValueError, 'not a symlink'):
                benchmark._preflight(arguments(scratch=link))
            self.assertTrue(link.is_symlink())

    def test_failed_collection_retains_owned_directory(self):
        with tempfile.TemporaryDirectory() as parent:
            with mock.patch.object(benchmark, '_preflight', return_value=(Path(parent), Path('/installed/sfs'), Path(parent), ['tiny_4kib'], ['copy'])), \
                    mock.patch.object(benchmark, '_collect', side_effect=RuntimeError('uncertain child')), \
                    redirect_stdout(io.StringIO()) as stream:
                code = benchmark.run(arguments())
            data = json.loads(stream.getvalue())
            run = Path(data['run_directory'])
            self.assertEqual(code, 1)
            self.assertTrue(run.is_dir())
            self.assertEqual(run.parent, Path(parent))
            self.assertEqual(run.stat().st_mode & 0o777, 0o700)
            self.assertEqual(json.loads((run / 'summary.json').read_text())['status'], 'failed')

    def test_comparative_losses_do_not_fail_a_completed_quick_collection(self):
        with tempfile.TemporaryDirectory() as parent:
            result = {'status': 'complete', 'exit_code': 0, 'collection_complete': True,
                      'required_coverage_complete': False, 'qualified': False,
                      'comparisons': [{'metrics': {'cpu_s': {'decision': 'candidate_higher'}}}]}
            with mock.patch.object(benchmark, '_preflight', return_value=(Path(parent), Path('/installed/sfs'), Path(parent), ['tiny_4kib'], ['copy'])), \
                    mock.patch.object(benchmark, '_collect', return_value=result), redirect_stdout(io.StringIO()) as stream:
                self.assertEqual(benchmark.run(arguments()), 0)
            data = json.loads(stream.getvalue())
            self.assertFalse(data['qualified'])
            self.assertEqual(data['comparisons'][0]['metrics']['cpu_s']['decision'], 'candidate_higher')

    def test_incomplete_full_collection_has_explicit_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as parent:
            result = {'status': 'incomplete', 'exit_code': 2, 'collection_complete': True,
                      'required_coverage_complete': False, 'qualified': False, 'cases': benchmark._coverage(['warm'])}
            with mock.patch.object(benchmark, '_preflight', return_value=(Path(parent), Path('/installed/sfs'), Path(parent), ['tiny_4kib'], ['copy'])), \
                    mock.patch.object(benchmark, '_collect', return_value=result), redirect_stdout(io.StringIO()) as stream:
                self.assertEqual(benchmark.run(arguments(full=True)), 2)
            data = json.loads(stream.getvalue())
            self.assertEqual(data['status'], 'incomplete')
            self.assertTrue(data['collection_complete'])
            self.assertFalse(data['required_coverage_complete'])
            self.assertEqual(len(data['cases']), 37)

    def test_full_collection_requires_exact_cache_specific_stages(self):
        from stallionfs import _benchmark_budget as budget
        changes = ('none', 'missing', 'duplicate', 'reordered', 'failed', 'cleanup-failed')
        for cache, target, change in ((cache, target, change)
                                     for cache in (['warm'], ['cold'], ['warm', 'cold'])
                                     for target in ('native-copy', 'native-cli-delete', 'native-cli-clone', 'scan-api-cold' if 'cold' in cache else 'scan-api')
                                     for change in changes):
            with self.subTest(cache=cache, target=target, change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                planned = ['native-files', 'native-copy', 'native-cli-delete', 'native-cli-clone', 'native-scan', 'scan-api',
                           *(['scan-api-cold'] if 'cold' in cache else []), 'workspaces']
                stages = [{'cycle': cycle, 'stage': stage,
                           'outcome': {'passed': True, 'cleanup_passed': True}}
                          for cycle in range(1, 4) for stage in planned]
                self.assertEqual(len(stages), 24 if 'cold' in cache else 21)
                index = next(index for index, row in enumerate(stages)
                             if row['cycle'] == 2 and row['stage'] == target)
                if change == 'missing':
                    del stages[index]
                elif change == 'duplicate':
                    stages.insert(index + 1, stages[index])
                elif change == 'reordered':
                    stages[index], stages[index + 1] = stages[index + 1], stages[index]
                elif change == 'failed':
                    stages[index]['outcome']['passed'] = False
                elif change == 'cleanup-failed':
                    stages[index]['outcome']['cleanup_passed'] = False
                def command(argv, **kwargs):
                    kwargs['receipt']['exit_code'] = 0
                    output = root / 'campaign'
                    output.mkdir()
                    (output / 'campaign.json').write_text(json.dumps({'status': 'complete', 'stages': stages}))
                args = arguments(full=True, cache=cache, node=root/'node', npm=root/'npm-cli.js', npm_cache=root)
                with mock.patch.object(budget, 'command', side_effect=command):
                    if change != 'none':
                        with self.assertRaisesRegex(RuntimeError, 'correctness and cleanup'):
                            benchmark._collect(args, root, root/'sfs', root, [], [])
                    else:
                        result = benchmark._collect(args, root, root/'sfs', root, [], [])
                        self.assertEqual(result['status'], 'incomplete')
                        self.assertEqual(result['exit_code'], 2)
                        self.assertTrue(result['collection_complete'])
                        self.assertFalse(result['required_coverage_complete'])
                        self.assertFalse(result['qualified'])
                        self.assertEqual(result['always_warm_collectors'], ['workspaces'])
                        row = next(row for row in result['cases'] if row['id'] == 'native/copy/tiny_4kib')
                        for cell in row['required_cells']:
                            self.assertEqual(cell['status'], 'collected_unverified'
                                             if cell['cache'] in cache else 'unavailable')

    def test_output_race_keeps_the_other_file(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            output = parent / 'summary.json'
            def collect(*unused):
                output.write_bytes(b'other writer')
                return {'status': 'complete', 'exit_code': 0, 'collection_complete': True}
            with mock.patch.object(benchmark, '_preflight', return_value=(parent, Path('/installed/sfs'), parent, ['tiny_4kib'], ['copy'])), \
                    mock.patch.object(benchmark, '_collect', side_effect=collect), redirect_stdout(io.StringIO()):
                self.assertEqual(benchmark.run(arguments(output=output)), 1)
            self.assertEqual(output.read_bytes(), b'other writer')

    def test_installed_resource_manifest_has_only_the_runtime_allowlist(self):
        resources = benchmark._resources()
        manifest = json.loads((resources / 'manifest.json').read_text())
        expected = {'fileops.py', 'native_suite.py', 'native_metrics.py', 'native_correctness.py',
                    'native_fixtures.py', 'native_report.py', 'campaign.py', 'scan.py', 'run.py', 'cli.py',
                    'fixture/package.json', 'fixture/package-lock.json', 'fixture/check.cjs'}
        self.assertEqual(set(manifest['resources']), expected)
        self.assertFalse(any('test_' in name or 'results/' in name for name in expected))


class BenchmarkDeadline(unittest.TestCase):
    def test_expired_budget_does_not_spawn_even_a_setup_command(self):
        from stallionfs import _benchmark_budget as budget
        with mock.patch.object(budget, 'remaining', side_effect=TimeoutError('expired')), \
                mock.patch.object(budget.subprocess, 'Popen') as popen, \
                mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(TimeoutError):
            budget.command(['/bin/true'])
        popen.assert_not_called()


    def test_setup_preserves_umask_and_skips_success_receipt_inside_workspace_timing(self):
        from stallionfs import _benchmark_budget as budget
        process = mock.Mock(returncode=0, pid=42)
        with mock.patch.object(budget, 'remaining', return_value=10), \
                mock.patch.object(budget.subprocess, 'Popen', return_value=process) as popen, \
                mock.patch.object(budget, '_drain', return_value=(b'out', b'err')), \
                mock.patch.object(budget, '_receipt') as receipt:
            result = budget.command(['/bin/true'], umask=0o077, persist_success=False)
        self.assertEqual(result.stdout, b'out')
        self.assertEqual(popen.call_args.kwargs['umask'], 0o077)
        receipt.assert_not_called()

    def test_post_spawn_uncertainty_preserves_primary_and_secondary_errors(self):
        from stallionfs import _benchmark_budget as budget
        from stallionfs._benchmark_runtime import native_metrics
        primary = TimeoutError('shared deadline')
        process = mock.Mock(returncode=None, pid=42)
        with mock.patch.object(budget, 'remaining', return_value=10), \
                mock.patch.object(budget.subprocess, 'Popen', return_value=process), \
                mock.patch.object(budget, '_drain', side_effect=primary), \
                mock.patch.object(native_metrics, '_stop_group', side_effect=OSError('cleanup')), \
                mock.patch.object(budget, '_receipt', side_effect=OSError('receipt')), \
                self.assertRaises(budget.ChildCompletionUnknown) as caught:
            budget.command(['/bin/true'])
        self.assertIs(caught.exception.__cause__, primary)
        self.assertTrue(caught.exception.receipt['completion_uncertain'])
        self.assertIn('cleanup', caught.exception.receipt['cleanup_error'])
        self.assertTrue(any('receipt' in note for note in primary.__notes__))
        self.assertIsNone(process.stdout)
        self.assertIsNone(process.stderr)

    def test_fileops_bridge_reaches_its_existing_retention_exception(self):
        from stallionfs import _benchmark_budget as budget
        from stallionfs._benchmark_runtime import fileops
        original = budget.ChildCompletionUnknown({'completion_uncertain': True})
        with mock.patch.dict(os.environ, {budget.DEADLINE: '1'}), \
                mock.patch.object(budget, 'command', side_effect=original) as command, \
                self.assertRaises(fileops.ChildCompletionUnknown) as caught:
            fileops.command(['/bin/true'])
        self.assertIs(caught.exception.__cause__, original)
        self.assertIs(caught.exception.receipt, original.receipt)
        self.assertEqual(command.call_args.kwargs['umask'], 0o077)

    def test_core_budget_does_not_write_success_receipts(self):
        from stallionfs import _benchmark_budget as budget, core
        with mock.patch.dict(os.environ, {budget.DEADLINE: '1'}), \
                mock.patch.object(budget, 'command', return_value=SimpleNamespace(returncode=0, stdout=b'ok', stderr=b'')) as command:
            self.assertEqual(core.run(['/bin/true']), 'ok')
        self.assertFalse(command.call_args.kwargs['persist_success'])
        self.assertNotIn('umask', command.call_args.kwargs)

    def test_streamed_output_is_capped_without_buffering_the_campaign(self):
        from stallionfs import _benchmark_budget as budget
        process = mock.Mock(stdout=mock.Mock(), stderr=mock.Mock())
        selector = mock.MagicMock()
        selector.get_map.side_effect = [True, True, False]
        keys = [SimpleNamespace(fd=3, data=0, fileobj=process.stdout),
                SimpleNamespace(fd=4, data=1, fileobj=process.stderr)]
        selector.select.side_effect = [[(keys[0], None), (keys[1], None)],
                                       [(keys[0], None), (keys[1], None)]]
        with mock.patch.object(budget.selectors, 'DefaultSelector') as factory, \
                mock.patch.object(budget.os, 'set_blocking'), \
                mock.patch.object(budget.os, 'read', side_effect=[b'abc', b'de', b'', b'']), \
                mock.patch.object(budget, 'remaining', return_value=10):
            factory.return_value.__enter__.return_value = selector
            output = io.BytesIO()
            receipt = {'argv': ['collector']}
            self.assertEqual(budget._drain(process, 100, receipt, output), (b'', b''))
        self.assertEqual(output.getvalue(), b'abcde')
        self.assertEqual(receipt['output_bytes'], 5)
        process.wait.assert_called_once()

    def test_output_limit_stops_at_the_real_drain_decision(self):
        from stallionfs import _benchmark_budget as budget
        process = mock.Mock(stdout=mock.Mock(), stderr=mock.Mock())
        selector = mock.MagicMock()
        selector.get_map.return_value = True
        key = SimpleNamespace(fd=3, data=0, fileobj=process.stdout)
        selector.select.return_value = [(key, None)]
        output, receipt = io.BytesIO(), {'argv': ['collector']}
        with mock.patch.object(budget.selectors, 'DefaultSelector') as factory, \
                mock.patch.object(budget.os, 'set_blocking'), \
                mock.patch.object(budget.os, 'read', return_value=b'abcd'), \
                mock.patch.object(budget, 'remaining', return_value=10), \
                mock.patch.object(budget, 'OUTPUT_LIMIT', 3):
            factory.return_value.__enter__.return_value = selector
            with self.assertRaisesRegex(RuntimeError, 'output limit'):
                budget._drain(process, 100, receipt, output)
        self.assertEqual(output.getvalue(), b'abc')
        self.assertEqual(receipt['output_bytes'], 3)
        self.assertEqual(receipt['discarded_output_bytes'], 1)
        self.assertTrue(receipt['output_limit_exceeded'])
        process.wait.assert_not_called()


    def test_required_output_modes_follow_the_fixed_case_families(self):
        modes = {'TREE-CLONE': {'plain'}, 'TREE-MOVE': {'plain'}, 'TREE-DELETE': {'plain'},
                 'ORDINARY-COPY': {'plain'}, 'COMMAND-SCAN': {'json'}, 'API-SCAN': {'api'},
                 'WORKSPACE': {'api'}, 'CLI-SCAN': {'plain', 'json'},
                 'CLI-VOLUMES': {'plain', 'json'}, 'CLI-TINY': {'plain', 'json'}}
        for case in benchmark._coverage(['warm', 'cold']):
            self.assertEqual({cell['output'] for cell in case['required_cells']}, modes[case['required_set']])

    def test_api_cache_cells_name_the_selected_stage_and_workspaces_stay_warm(self):
        for cache, collected in ((['warm'], True), (['cold'], True),
                                 (['warm', 'cold'], True), (['warm', 'cold'], False)):
            for case in benchmark._coverage(cache, collected=collected):
                if case['required_set'] == 'API-SCAN':
                    self.assertEqual(len(case['required_cells']), 8)
                    for cell in case['required_cells']:
                        mode = cell['cache']
                        self.assertEqual(cell['collector'], 'scan-api-cold' if mode == 'cold' else 'scan-api')
                        self.assertEqual(cell['status'], 'collected_unverified'
                                         if collected and (mode == 'warm' or mode in cache) else 'unavailable')
                        self.assertFalse(cell['win'])
                    self.assertFalse(case['qualified'])
                elif case['required_set'] == 'WORKSPACE':
                    self.assertTrue(all(cell['status'] == 'unavailable' for cell in case['required_cells']
                                        if cell['cache'] == 'cold' or cell['phase'] == 'resources'))

    def test_list_marks_catalog_only_entries_without_starting_collectors(self):
        catalog = benchmark._catalog()
        collected_cli = {'cli/delete/tiny_4kib', 'cli/clone/tiny_4kib'}
        self.assertTrue(all(case['catalog_only'] for case in catalog['cases'] if case['id'].startswith('cli/') and case['id'] not in collected_cli))
        self.assertFalse(any(case['catalog_only'] for case in catalog['cases'] if case['id'].startswith('fileops/')))
        self.assertFalse(next(case['catalog_only'] for case in catalog['cases'] if case['id'] == 'cli/delete/tiny_4kib'))
        self.assertFalse(next(case['catalog_only'] for case in catalog['cases'] if case['id'] == 'cli/clone/tiny_4kib'))

    def test_only_existing_cli_delete_and_clone_get_native_coverage(self):
        selected = {'cli/delete/tiny_4kib': ('native-cli-delete', '/bin/rm -f'),
                    'cli/clone/tiny_4kib': ('native-cli-clone', '/bin/cp -cRp')}
        for cache, collected in ((['warm'], True), (['cold'], True), (['warm', 'cold'], True), (['warm', 'cold'], False)):
            coverage = benchmark._coverage(cache, collected=collected)
            self.assertEqual(len(coverage), 37)
            for case, (collector, reference) in selected.items():
                row = next(row for row in coverage if row['id'] == case)
                self.assertEqual(row['collector'], collector)
                self.assertFalse(row['catalog_only'])
                self.assertFalse(row['qualified'])
                self.assertEqual(len(row['required_cells']), 8)
                for cell in row['required_cells']:
                    self.assertEqual(cell['reference'], reference)
                    self.assertEqual(cell['status'], 'collected_unverified'
                                     if collected and cell['cache'] in cache else 'unavailable')
                    self.assertFalse(cell['win'])
            for other in coverage:
                if other['id'].startswith('cli/') and other['id'] not in selected:
                    self.assertIsNone(other['collector'])
                    self.assertTrue(all(cell['status'] == 'unavailable' for cell in other['required_cells']))

    def test_text_comparisons_name_reference_and_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            result = {'status': 'complete', 'exit_code': 0, 'comparisons': [
                {'operation': 'copy', 'fixture': 'tiny_4kib', 'reference': 'cp', 'phase': 'resources',
                 'metrics': {'rss_bytes': {'native': {'median': 1}, 'candidate': {'median': 2}, 'decision': 'candidate_higher'}}}]}
            with mock.patch.object(benchmark, '_preflight', return_value=(parent, Path('/installed/sfs'), parent, [], [])), \
                    mock.patch.object(benchmark, '_collect', return_value=result), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(benchmark.run(arguments(json=False)), 0)
            self.assertIn('reference=cp phase=resources rss_bytes', output.getvalue())

    def test_outer_control_capture_streams_log_and_keeps_its_receipt(self):
        from stallionfs import _benchmark_budget as budget
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def command(argv, **kwargs):
                self.assertNotIn('phase', kwargs)
                kwargs['output'].write(b'progress')
                kwargs['receipt'].update(exit_code=0, output_bytes=8)
            with mock.patch.object(budget, 'command', side_effect=command), \
                    mock.patch.object(benchmark, '_read_native', return_value=({'status': 'complete', 'passed': True, 'cleanup_passed': True}, [])):
                result = benchmark._collect(arguments(), root, root/'sfs', root, ['tiny_4kib'], ['copy'])
            self.assertEqual(result['exit_code'], 0)
            self.assertEqual((root/'collector.log').read_bytes(), b'progress')
            self.assertEqual(json.loads((root/'collector-receipt.json').read_text())['output_bytes'], 8)

    def test_full_preflight_node_and_sudo_probes_use_bounded_capture(self):
        from stallionfs import _benchmark_budget as budget
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('stallionfs', 'stallionfs-python', 'node'):
                file = root/name; file.write_text(''); file.chmod(0o700)
            npm = root/'npm/bin/npm-cli.js'; npm.parent.mkdir(parents=True); npm.write_text('')
            (npm.parent.parent/'package.json').write_text('{"name":"npm"}')
            with mock.patch.object(sys, 'platform', 'darwin'), \
                    mock.patch.object(sys, 'argv', [str(root/'stallionfs-python')]), \
                    mock.patch.object(benchmark, 'TOOLS', ()), \
                    mock.patch.object(benchmark, '_resources', return_value=root), \
                    mock.patch.object(benchmark.shutil, 'disk_usage', return_value=SimpleNamespace(free=10**15)), \
                    mock.patch.object(benchmark.shutil, 'which', return_value='/usr/bin/git'), \
                    mock.patch.object(Path, 'is_file', return_value=True), \
                    mock.patch.object(budget, 'command', return_value=SimpleNamespace(returncode=0, stdout=b'v24.0.0')) as command:
                benchmark._preflight(arguments(full=True, node=root/'node', npm=npm, npm_cache=root, scratch=root, cache=['cold']))
            self.assertEqual(command.call_count, 2)
            self.assertTrue(all(call.kwargs['output_limit'] == 65536 for call in command.call_args_list))
            self.assertEqual(command.call_args.kwargs['output_limit'], 65536)
            self.assertEqual(command.call_args.kwargs['timeout'], 5)

    def test_installed_scan_provenance_needs_no_repository_c_files(self):
        import importlib.util
        from stallionfs import _scan
        resources = benchmark._resources()
        spec = importlib.util.spec_from_file_location('installed_scan_check', resources/'scan.py')
        scan = importlib.util.module_from_spec(spec)
        with mock.patch.object(sys, 'path', [str(resources), *sys.path]):
            spec.loader.exec_module(scan)
        from stallionfs._benchmark_runtime import fileops
        with mock.patch.object(scan, 'f', fileops):
            hashes, binary, origin = scan.runtime_provenance()
        self.assertEqual(binary, Path(_scan.__file__).resolve())
        self.assertIn('installed-package/_benchmark_budget.py', hashes)
        self.assertIn('Installed package', origin)
        with mock.patch.object(scan, 'f', fileops), \
                mock.patch.object(scan._scan, '__file__', '/different/package/_scan.so'), \
                self.assertRaisesRegex(RuntimeError, 'extension from this installed package'):
            scan.runtime_provenance()

    def test_capped_failure_retains_the_actual_partial_bytes(self):
        import base64
        from stallionfs import _benchmark_budget as budget
        process = mock.Mock(stdout=mock.Mock(), stderr=mock.Mock())
        selector = mock.MagicMock(); selector.get_map.return_value = True
        key = SimpleNamespace(fd=3, data=0, fileobj=process.stdout)
        selector.select.return_value = [(key, None)]
        primary = OSError('read failed after prefix'); receipt = {'argv': ['collector']}
        with mock.patch.object(budget.selectors, 'DefaultSelector') as factory, \
                mock.patch.object(budget.os, 'set_blocking'), \
                mock.patch.object(budget.os, 'read', side_effect=[b'prefix', primary]), \
                mock.patch.object(budget, 'remaining', return_value=10):
            factory.return_value.__enter__.return_value = selector
            with self.assertRaises(OSError) as caught:
                budget._drain(process, 100, receipt, None)
        self.assertIs(caught.exception, primary)
        self.assertEqual(base64.b64decode(receipt['stdout_partial_b64']), b'prefix')
        self.assertEqual(receipt['stdout_retained_bytes'], 6)
        self.assertEqual(receipt['output_bytes'], 6)


    def test_wrapped_sigint_keeps_exit_130_and_the_uncertainty_receipt(self):
        from stallionfs import _benchmark_budget as budget
        failure = budget.ChildCompletionUnknown({'completion_uncertain': True})
        failure.__cause__ = KeyboardInterrupt()
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            with mock.patch.object(benchmark, '_preflight', return_value=(parent, Path('/installed/sfs'), parent, [], [])), \
                    mock.patch.object(benchmark, '_collect', side_effect=failure), redirect_stdout(io.StringIO()) as stream:
                self.assertEqual(benchmark.run(arguments()), 130)
            value = json.loads(stream.getvalue())
            self.assertEqual(value['status'], 'interrupted')
            self.assertTrue(value['command_receipt']['completion_uncertain'])


if __name__ == '__main__':
    unittest.main()
