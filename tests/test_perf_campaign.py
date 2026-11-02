"""Campaign ordering and stop rules with subprocesses replaced by report fixtures."""
from contextlib import redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


PERF = Path(__file__).parent / 'perf'
with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
    spec = importlib.util.spec_from_file_location('campaign_under_test', PERF / 'campaign.py')
    campaign = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(campaign)


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.output = self.root / 'reports'
        self.calls = []
        self.args = []
        for name in ('binary', 'scratch', 'node', 'npm', 'npm-cache'):
            path = self.root / name
            if name in ('scratch', 'npm-cache'):
                path.mkdir()
            else:
                path.write_text('fixture')
            self.args += ['--' + name, str(path)]
        self.args += ['--output-dir', str(self.output)]

    def child(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        output = Path(argv[argv.index('--output') + 1])
        state = {'status': 'complete', 'passed': True, 'cleanup_passed': True}
        if Path(argv[2]).name == 'native_suite.py':
            writer = campaign.native_report.ReportJournal(output)
            try:
                writer.finish(state)
            finally:
                writer.close()
        else:
            campaign.f.write_new_json(output, state)
        kwargs['stdout'].write(b'stage log\n')
        return subprocess.CompletedProcess(argv, 0)

    def run_mocked(self, child=None, pins=None):
        with mock.patch.object(campaign, 'fingerprints', **(pins or {'return_value': {'fixed': 'hash'}})), \
                mock.patch.object(campaign.subprocess, 'run', side_effect=child or self.child):
            return campaign.main(self.args)

    def report(self):
        return json.loads((self.output / 'campaign.json').read_text())

    def test_three_sequential_cycles_cover_existing_workloads_once(self):
        self.assertEqual(self.run_mocked(), 0)
        result = self.report()
        self.assertEqual(result['status'], 'complete')
        self.assertTrue(result['collection_passed'])
        self.assertFalse(result['all_metrics_won'])
        expected = ['native-files', 'native-copy', 'native-scan', 'scan-api', 'workspaces']
        self.assertEqual([row['stage'] for row in result['stages']], expected * 3)
        self.assertEqual([row['cycle'] for row in result['stages']], [1] * 5 + [2] * 5 + [3] * 5)
        self.assertEqual(len(self.calls), 15)
        for argv, options in self.calls:
            self.assertEqual(argv[:2], [sys.executable, '-B'])
            self.assertEqual(argv[argv.index('--samples') + 1], '10')
            self.assertEqual(options['cwd'], self.output)
            self.assertFalse(options['check'])
            self.assertNotIn('shell', options)
        files, copy, scan, api, workspace = [argv for argv, _ in self.calls[:5]]
        self.assertEqual(files[files.index('--fixtures') + 1:files.index('--node')], list(campaign.FILES))
        self.assertEqual(files[files.index('--operations') + 1:files.index('--copy-tools')],
                         ['clone', 'move', 'delete'])
        self.assertEqual(len(campaign.FILES), 13)
        self.assertEqual(len(set(campaign.FILES)), 13)
        for argv, _ in self.calls[1::5]:
            self.assertEqual(Path(argv[2]).name, 'native_suite.py')
            self.assertEqual(argv[argv.index('--operations') + 1:],
                             ['copy', '--copy-tools', 'cp', '--fixtures', 'tiny_4kib'])
            self.assertEqual(argv[argv.index('--binary') + 1], files[files.index('--binary') + 1])
        self.assertEqual(scan[scan.index('--fixtures') + 1:], list(campaign.SCANS))
        for argv in (files, copy, scan):
            self.assertEqual(argv[argv.index('--runs') + 1], '1')
            self.assertEqual(argv[argv.index('--cache') + 1:argv.index('--operations')], ['warm', 'cold'])
        self.assertIn('--memory', api)
        self.assertEqual(api[api.index('--files') + 1], '20000')
        self.assertEqual(workspace[workspace.index('--methods') + 1:workspace.index('--concurrency')],
                         ['worktree_install', 'stallionfs_folder'])
        self.assertEqual(workspace[workspace.index('--concurrency') + 1], '4')
        self.assertEqual(workspace[workspace.index('--source-files') + 1], '1000')
        for flag in ('--node', '--npm', '--npm-cache'):
            self.assertEqual(files[files.index(flag) + 1], workspace[workspace.index(flag) + 1])
        self.assertTrue(all(Path(row['log']).read_bytes() == b'stage log\n' for row in result['stages']))

    def test_native_correctness_failure_continues_but_campaign_returns_failure(self):
        def failed_first(argv, **kwargs):
            if self.calls:
                return self.child(argv, **kwargs)
            self.calls.append((argv, kwargs))
            output = Path(argv[argv.index('--output') + 1])
            writer = campaign.native_report.ReportJournal(output)
            try:
                writer.append('unavailable', 0, {'reason': 'purge denied'})
                writer.finish({'status': 'complete', 'passed': False, 'cleanup_passed': True})
            finally:
                writer.close()
            return subprocess.CompletedProcess(argv, 1)
        self.assertEqual(self.run_mocked(failed_first), 1)
        report = self.report()
        self.assertEqual(len(self.calls), 15)
        self.assertEqual(report['status'], 'complete')
        self.assertFalse(report['collection_passed'])
        self.assertEqual(report['stages'][0]['status'], 'complete_with_failures')
        self.assertFalse(report['all_metrics_won'])

    def test_native_control_reads_manifest_without_loading_final_json(self):
        output = self.root / 'native.json'
        writer = campaign.native_report.ReportJournal(output)
        try:
            writer.finish({'status': 'complete', 'passed': True, 'cleanup_passed': True})
        finally:
            writer.close()
        original = campaign.read_small
        def read(path):
            self.assertEqual(path, output.with_name(output.name + '.manifest'))
            return original(path)
        with mock.patch.object(campaign, 'read_small', side_effect=read):
            for name in ('native-files', 'native-copy'):
                state, evidence = campaign.outcome(name, output)
                self.assertTrue(state['passed'])
                self.assertIn('not independently verified', evidence['verification'])
        with output.with_name(output.name + '.journal').open('ab') as stream:
            stream.write(b'uncommitted')
        for name in ('native-files', 'native-copy'):
            with self.assertRaisesRegex(RuntimeError, 'uncommitted tail'):
                campaign.outcome(name, output)

    def test_denied_purge_is_not_retried_in_later_native_stages(self):
        for cache, denied_stage, expected_calls, expected_skips in (
                (['warm', 'cold'], 'native-files', 15, 0),
                (['cold'], 'native-files', 7, 8),
                (['warm', 'cold'], 'native-copy', 15, 0),
                (['cold'], 'native-copy', 8, 7)):
            with self.subTest(cache=cache, denied_stage=denied_stage):
                self.calls = []
                self.output = self.root / ('reports-' + '-'.join(cache) + '-' + denied_stage)
                self.args[self.args.index('--output-dir') + 1] = str(self.output)
                def denied(argv, **kwargs):
                    output = Path(argv[argv.index('--output') + 1])
                    if output.name != 'cycle-1-' + denied_stage + '.json':
                        return self.child(argv, **kwargs)
                    self.calls.append((argv, kwargs))
                    writer = campaign.native_report.ReportJournal(output)
                    try:
                        writer.finish({'status': 'complete', 'passed': False, 'cleanup_passed': True,
                                       'cold_cache_unavailable': 'purge denied'})
                    finally:
                        writer.close()
                    return subprocess.CompletedProcess(argv, 1)
                with mock.patch.object(campaign, 'fingerprints', return_value={'fixed': 'hash'}), \
                        mock.patch.object(campaign.subprocess, 'run', side_effect=denied):
                    self.assertEqual(campaign.main([*self.args, '--cache', *cache]), 1)
                report = self.report()
                self.assertEqual(len(self.calls), expected_calls)
                self.assertEqual(len(report['stages']), 15)
                self.assertEqual(report['cold_cache_unavailable'], 'purge denied')
                self.assertFalse(report['collection_passed'])
                denied_index = next(index for index, (argv, _) in enumerate(self.calls)
                                    if Path(argv[argv.index('--output') + 1]).name ==
                                    'cycle-1-' + denied_stage + '.json')
                for argv, _ in self.calls[denied_index + 1:]:
                    if Path(argv[2]).name == 'native_suite.py':
                        self.assertEqual(argv[argv.index('--cache') + 1:argv.index('--operations')], ['warm'])
                skipped = [row for row in report['stages'] if row['status'] == 'unavailable']
                self.assertEqual(len(skipped), expected_skips)
                self.assertTrue(all(row['argv'] is None and row['planned_argv'] for row in skipped))

    def test_incomplete_uncertain_and_non_native_failures_cannot_continue(self):
        evidence = {'final_report_exists': True}
        healthy = {'status': 'complete', 'passed': True, 'cleanup_passed': True}
        for change in ({'status': 'failed'}, {'status': 'running'}, {'cleanup_passed': False},
                       {'retained_fixture': '/retained'}, {'completion_uncertain': True},
                       {'error': 'failed'}, {'cleanup_error': 'busy'}, {'passed': False}):
            with self.subTest(change=change):
                self.assertFalse(campaign.safe_to_continue('native-files', 0, {**healthy, **change}, evidence))
        self.assertFalse(campaign.safe_to_continue('native-files', -9, healthy, evidence))
        self.assertFalse(campaign.safe_to_continue('native-files', 0, healthy, {'final_report_exists': False}))
        self.assertFalse(campaign.safe_to_continue('workspaces', 1, {**healthy, 'passed': False}, evidence))

    def test_failed_native_stage_retains_references_and_stops_next_launch(self):
        def failed(argv, **kwargs):
            self.calls.append((argv, kwargs))
            output = Path(argv[argv.index('--output') + 1])
            writer = campaign.native_report.ReportJournal(output)
            try:
                writer.finish({'status': 'failed', 'passed': False, 'retained_fixture': '/owned/fixture'})
            finally:
                writer.close()
            return subprocess.CompletedProcess(argv, 1)
        with self.assertRaisesRegex(RuntimeError, 'confirmed cleanup'):
            self.run_mocked(failed)
        report = self.report()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(report['status'], 'stopped')
        row = report['stages'][0]
        self.assertEqual(row['outcome']['retained_fixture'], '/owned/fixture')
        self.assertTrue(Path(row['output']).is_file())
        self.assertTrue(Path(row['log']).is_file())

    def test_changed_runtime_stops_before_next_stage(self):
        with self.assertRaisesRegex(RuntimeError, 'changed during stage'):
            self.run_mocked(pins={'side_effect': [{'hash': 'before'}, {'hash': 'before'}, {'hash': 'after'}]})
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(self.report()['stages'][0]['fingerprints_unchanged'])

    def test_copy_stage_requires_native_journal_and_confirmed_cleanup(self):
        for failure in ('missing-journal', 'uncommitted-tail', 'cleanup-failed'):
            with self.subTest(failure=failure):
                self.calls = []
                self.output = self.root / ('reports-' + failure)
                self.args[self.args.index('--output-dir') + 1] = str(self.output)
                def failed_copy(argv, **kwargs):
                    completed = self.child(argv, **kwargs)
                    output = Path(argv[argv.index('--output') + 1])
                    if output.name == 'cycle-1-native-copy.json':
                        journal = output.with_name(output.name + '.journal')
                        if failure == 'missing-journal':
                            journal.unlink()
                        elif failure == 'uncommitted-tail':
                            with journal.open('ab') as stream:
                                stream.write(b'uncommitted')
                        else:
                            manifest = output.with_name(output.name + '.manifest')
                            state = json.loads(manifest.read_text())
                            state['state']['cleanup_passed'] = False
                            manifest.write_text(json.dumps(state))
                    return completed
                with self.assertRaises((OSError, RuntimeError)):
                    self.run_mocked(failed_copy)
                report = self.report()
                self.assertEqual(len(self.calls), 2)
                self.assertEqual(report['status'], 'stopped')
                self.assertEqual(report['stages'][-1]['stage'], 'native-copy')
                self.assertTrue(Path(report['stages'][-1]['output']).is_file())
                self.assertTrue(Path(report['stages'][-1]['log']).is_file())

    def test_interruption_preserves_pending_identity_and_original_error(self):
        failure = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_mocked(mock.Mock(side_effect=failure))
        self.assertIs(caught.exception, failure)
        report = self.report()
        self.assertEqual(report['status'], 'stopped')
        self.assertEqual(len(report['stages']), 1)
        self.assertTrue(report['stages'][0]['completion_uncertain'])
        self.assertEqual(report['stages'][0]['stage'], 'native-files')

    def test_failed_partial_report_is_retained_and_not_treated_as_final(self):
        output = self.root / 'api.json'
        partial = output.with_name(output.name + '.partial')
        campaign.f.write_new_json(partial, {'status': 'failed', 'passed': False,
                                          'retained_fixture': '/owned/scan'})
        state, evidence = campaign.outcome('scan-api', output)
        self.assertEqual(state['retained_fixture'], '/owned/scan')
        self.assertFalse(evidence['final_report_exists'])
        self.assertEqual(evidence['summary'], str(partial))
        self.assertFalse(campaign.safe_to_continue('scan-api', 1, state, evidence))

    def test_existing_output_and_small_sample_count_do_not_launch(self):
        self.output.mkdir()
        sentinel = self.output / 'preserve'
        sentinel.write_text('existing')
        with mock.patch.object(campaign.subprocess, 'run') as child:
            with self.assertRaisesRegex(RuntimeError, 'new campaign output'):
                campaign.main(self.args)
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                campaign.main([*self.args, '--samples', '9'])
        child.assert_not_called()
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(sentinel.read_text(), 'existing')

    def test_child_environment_pins_node_and_removes_runtime_overrides(self):
        supplied = {'PATH': '/usr/bin', 'NODE_OPTIONS': '--require=unrelated', 'NODE_PATH': '/unrelated',
                    'npm_config_prefix': '/unrelated', 'NPM_CONFIG_CACHE': '/unrelated',
                    'PYTHONPATH': '/unrelated', 'PYTHONHOME': '/unrelated', 'KEEP': 'value'}
        with mock.patch.dict(os.environ, supplied, clear=True):
            result = campaign.environment(self.root / 'node')
        self.assertEqual(result, {'PATH': str(self.root) + os.pathsep + '/usr/bin',
                                  'KEEP': 'value', 'PYTHONDONTWRITEBYTECODE': '1'})

    def test_checkout_runtime_origins_are_rejected_before_reading_inputs(self):
        for target in ('binary', 'python', 'package'):
            with self.subTest(target=target):
                args = mock.Mock(binary=(campaign.f.REPO / 'bin/stallionfs'
                                         if target == 'binary' else self.root / 'stallionfs'))
                python = str(campaign.f.REPO / 'bin/python' if target == 'python' else self.root / 'python')
                package = campaign.f.REPO / 'stallionfs' if target == 'package' else self.root / 'site-packages/stallionfs'
                with mock.patch.dict(sys.modules, {'stallionfs': mock.Mock(__file__=str(package / '__init__.py'))}), \
                        mock.patch.object(sys, 'executable', python), \
                        mock.patch.object(campaign.f, 'digest') as digest, \
                        self.assertRaisesRegex(RuntimeError, 'outside the checkout'):
                    campaign.fingerprints(args)
                digest.assert_not_called()

    def test_warm_fingerprints_do_not_require_cold_cache_tools(self):
        args = mock.Mock(binary=self.root / 'bin/stallionfs', node=self.root / 'node',
                         npm=self.root / 'npm/bin/npm-cli.js')
        package = self.root / 'site-packages/stallionfs'
        cold_tools = {'/usr/bin/sudo', '/usr/sbin/purge'}
        for cache in (['warm'], ['warm', 'cold']):
            args.cache = cache
            # This fixture models checkout tools, not an installed resource manifest.
            files = {args.binary, args.binary.with_name('stallionfs-python'),
                     self.root / 'bin/python', args.node, args.npm,
                     args.npm.parent.parent / 'package.json', Path('/usr/bin/git'),
                     *(Path(name) for name in ('/bin/cp', '/bin/mv', '/bin/rm',
                       '/usr/bin/ditto', '/usr/bin/rsync', '/usr/bin/find',
                       '/usr/bin/stat', '/usr/bin/time', '/bin/chmod'))}
            if 'cold' in cache:
                files.update(map(Path, cold_tools))
            with self.subTest(cache=cache), \
                    mock.patch.dict(sys.modules, {'stallionfs': mock.Mock(__file__=str(package / '__init__.py'))}), \
                    mock.patch.object(sys, 'executable', str(self.root / 'bin/python')), \
                    mock.patch.object(sys, 'prefix', str(self.root)), \
                    mock.patch.object(Path, 'is_file', autospec=True, side_effect=lambda path: path in files), \
                    mock.patch.object(campaign.os, 'access', return_value=True), \
                    mock.patch.object(campaign.shutil, 'which', return_value='/usr/bin/git'), \
                    mock.patch.object(campaign.f, 'fingerprint_sources', return_value={}), \
                    mock.patch.object(campaign.f, 'digest', return_value='hash'):
                result = campaign.fingerprints(args)['runtime_sha256']
                self.assertEqual(cold_tools.intersection(result), cold_tools if 'cold' in cache else set())
