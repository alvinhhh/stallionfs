"""Release-gate acceptance and report adapters without executing benchmarks."""
from contextlib import redirect_stdout, redirect_stderr
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4


SPEC = importlib.util.spec_from_file_location('release_gate',
                                            Path(__file__).parent / 'perf' / 'release_gate.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def metric(name, native=1.0, candidate=0.5):
    return {'complete_pairs': 10, 'excluded_pairs': [],
            'native': {'n': 10, 'median': native}, 'candidate': {'n': 10, 'median': candidate},
            'paired_median_savings': native - candidate,
            'decision': 'candidate_faster' if name == 'wall_s' else 'candidate_lower'}


def rows(phase, methods=('native', 'candidate')):
    return [{'phase': phase, 'method': method, 'pair_id': i, 'ok': True,
             'validated': True, 'correctness': {'passed': True}}
            for method in methods for i in range(10)]


def report(case='fileops/move/large_64mib'):
    return {'case_id': case, 'status': 'complete', 'passed': True, 'cleanup_passed': True,
            'comparisons': [dict(phase=phase, reference='cp', cache='warm',
                                 metrics={name: metric(name) for name in metrics})
                            for phase, metrics in (('timing', ('wall_s', 'cpu_s')),
                                                    ('resources', ('rss_bytes',)))],
            'rows': [dict(row, reference='cp', cache='warm')
                     for phase in ('timing', 'resources') for row in rows(phase)],
            'unavailable': []}


def evaluate(document):
    return gate.evaluate_documents([document], (document['case_id'],))


def scanner_report(layout):
    methods = ('posix', 'bulk_serial', 'bulk')
    workload = {'sample_rows': rows('timing', methods),
                'memory_rows': rows('resources', methods),
                'timing_comparisons': {method: {name: metric(name) for name in ('wall_s', 'cpu_s')}
                                       for method in methods[1:]},
                'memory_comparisons': {method: {'rss_bytes': metric('rss_bytes')}
                                       for method in methods[1:]}}
    return {'status': 'complete', 'cleanup_passed': True, 'workloads': {layout: workload}}


def workspace_report(count):
    methods = ('worktree_install', 'stallionfs_folder')
    return {'status': 'complete', 'cleanup_passed': True,
            'raw': {count: {method: rows('timing', (method,)) for method in methods}},
            'comparisons': {count: {'methods': {'stallionfs_folder': {
                'total_s': metric('wall_s'), 'total_cpu_s': metric('cpu_s')}}}}}


def identified_report(case):
    if case.startswith('api-scan/'):
        layout = case.split('/')[-1]
        document = scanner_report(layout)
        workload = document['workloads'][layout]
        samples = workload['sample_rows'] + workload['memory_rows']
        for row in workload['memory_rows']:
            row['started_utc'] = '2026-01-01T00:00:00.000001+00:00'
            row['time_output'] = 'synthetic time diagnostics'
    elif case.startswith('workspace/'):
        count = case.rsplit('concurrency', 1)[1]
        document = workspace_report(count)
        samples = [row for method in document['raw'][count].values() for row in method]
    else:
        document = report(case)
        samples = document['rows']
        for row in samples:
            row['started_utc'] = '2026-01-01T00:00:00.000001+00:00'
            row['cwd'] = '/synthetic/collector'
        if not case.startswith('cli/'):
            del document['case_id']
            _, operation, fixture = case.split('/')
            for row in samples + document['comparisons']:
                row.update(operation=operation, fixture=fixture)
    for row in samples:
        row['sample_id'] = uuid4().hex
        value = 1.0 if row['method'] in ('native', 'posix', 'worktree_install') else 0.5
        if case.startswith('workspace/'):
            row.update(total_s=value, total_cpu_s=value)
        elif row['phase'] == 'timing':
            row.update(wall_s=value, cpu_s=value)
        else:
            row['rss_bytes'] = int(2 * value)
    return document


class ReleaseGate(unittest.TestCase):
    def test_universe_counts_every_catalog_case(self):
        self.assertEqual(len(gate.UNIVERSE), 37)
        self.assertEqual(set(gate.UNIVERSE), {case['id'] for case in gate.CATALOG})

    def test_uncollected_cases_fail_in_denominator(self):
        missing = {'cli/scan/empty', 'cli/volumes/volumes'}
        result = gate.evaluate_documents([report(case) for case in gate.UNIVERSE if case not in missing])
        self.assertEqual((result['passing_cases'], result['total_cases']), (35, 37))
        self.assertFalse(result['passed'])
        case = next(case for case in result['cases'] if case['case'] == 'cli/volumes/volumes')
        self.assertEqual(case['reasons'], ['not collected'])

    def test_all_pass(self):
        runs = [gate.evaluate_documents([identified_report(case) for case in gate.UNIVERSE])
                for _ in range(3)]
        self.assertEqual([run['passing_cases'] for run in runs], [37, 37, 37])
        self.assertTrue(gate.qualify(runs)['qualified'])

    def test_qualify_itself_rejects_repeated_evaluated_evidence(self):
        run = gate.evaluate_documents([identified_report(case) for case in gate.UNIVERSE])
        decision = gate.qualify([run, copy.deepcopy(run), copy.deepcopy(run)])
        self.assertFalse(decision['qualified'])
        self.assertIn('raw benchmark samples were reused', decision['input_error'])

    def test_89_versus_90_percent(self):
        universe = tuple('fileops/move/case' + str(i) for i in range(100))
        documents = [report(case) for case in universe]
        for count, passed in ((89, False), (90, True)):
            with self.subTest(count=count):
                selected = copy.deepcopy(documents)
                for document in selected[count:]:
                    document['comparisons'][0]['metrics']['cpu_s']['decision'] = 'inconclusive'
                    document['comparisons'][1]['metrics']['rss_bytes']['decision'] = 'inconclusive'
                result = gate.evaluate_documents(selected, universe)
                self.assertEqual(result['passing_cases'], count)
                self.assertEqual(result['passed'], passed)

    def test_missing_case_stays_in_denominator(self):
        result = gate.evaluate_documents([], ('native/copy/tiny_4kib',))
        self.assertEqual(result['total_cases'], 1)
        self.assertFalse(result['passed'])
        self.assertEqual(result['cases'][0]['reasons'], ['not collected'])

    def test_correctness_failure(self):
        for change in ({'validated': False}, {'ok': False}, {'correctness': {'passed': False}},
                       {'source_verification': {'unchanged': False}}, {'completion_uncertain': True}):
            with self.subTest(change=change):
                document = report()
                document['rows'][0].update(change)
                self.assertFalse(evaluate(document)['passed'])

    def test_reference_losses_are_shown_without_failing_valid_comparisons(self):
        document = report()
        document['passed'] = False
        reference = document['rows'][0]
        reference.update(validated=False, correctness={'strict_equal': False,
                         'candidate_losses': [{'path': '', 'field': 'acl'}],
                         'sparse_preserved': False})
        result = evaluate(document)
        self.assertTrue(result['passed'])
        warnings = result['cases'][0]['references'][0]['reference_losses']
        self.assertEqual(warnings[0]['method'], 'native')
        self.assertEqual(warnings[0]['correctness'], reference['correctness'])
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'native.json').write_text(json.dumps(document))
            with redirect_stdout(io.StringIO()) as output:
                gate.main([str(root)])
            self.assertIn('reference losses (not candidate failures): native: acl,sparse_preserved',
                          output.getvalue())
        candidate = next(row for row in document['rows'] if row['method'] == 'candidate')
        candidate.update(validated=False, correctness=copy.deepcopy(reference['correctness']))
        self.assertFalse(evaluate(document)['passed'])

    def test_candidate_correctness_flags_are_never_waived(self):
        for key in ('sparse_preserved', 'independent_clone', 'move_identity', 'move_source_absent'):
            with self.subTest(key=key):
                document = report()
                candidate = next(row for row in document['rows'] if row['method'] == 'candidate')
                candidate['correctness'][key] = False
                self.assertFalse(evaluate(document)['passed'])

    def test_reference_losses_do_not_invent_comparisons(self):
        document = report()
        document['rows'][0].update(validated=False, correctness={'strict_equal': False,
                                 'candidate_losses': [{'field': 'acl'}]})
        for comparison in document['comparisons']:
            for value in comparison['metrics'].values():
                value.update(complete_pairs=0, excluded_pairs=[{'pair_id': 0}],
                             decision='insufficient_samples', native=None, candidate=None)
        result = evaluate(document)
        self.assertFalse(result['passed'])
        self.assertIn('no comparable reference', result['cases'][0]['reasons'])
        self.assertTrue(result['cases'][0]['references'][0]['excluded'])

    def test_loss_only_reference_excluded_but_other_failures_are_not(self):
        document = report()
        lost = report()
        for row in lost['rows']:
            row['reference'] = 'lossy'
            if row['method'] == 'native':
                row.update(validated=False, correctness={'strict_equal': False,
                           'candidate_losses': [{'field': 'acl'}]})
        for comparison in lost['comparisons']:
            comparison['reference'] = 'lossy'
            for value in comparison['metrics'].values():
                value.update(complete_pairs=0, excluded_pairs=[{'pair_id': 0}],
                             decision='insufficient_samples', native=None, candidate=None)
        for key in ('rows', 'comparisons'):
            document[key].extend(lost[key])
        document['unavailable'] = [dict(reference='lossy', cache='warm', method='native',
            reason='method failed; remaining identical attempts skipped')]
        self.assertTrue(evaluate(document)['passed'])
        for change in ({'reason': 'timeout'}, {'reason': 'setup failure'},
                       {'failed_methods': ['candidate']}):
            with self.subTest(change=change):
                invalid = copy.deepcopy(document)
                invalid['unavailable'][0].update(change)
                self.assertFalse(evaluate(invalid)['passed'])
        for change in ({'completion_uncertain': True}, {'source_unchanged': False},
                       {'ok': False}, {'validated': False}):
            with self.subTest(candidate=change):
                invalid = copy.deepcopy(document)
                next(row for row in invalid['rows'] if row['reference'] == 'lossy' and
                     row['method'] == 'candidate').update(change)
                self.assertFalse(evaluate(invalid)['passed'])
        missing = copy.deepcopy(document)
        missing['rows'] = [row for row in missing['rows'] if row['reference'] != 'lossy']
        self.assertFalse(evaluate(missing)['passed'])

    def test_reference_execution_and_source_failures_still_fail(self):
        for change in ({'ok': False}, {'exit_code': 1}, {'completion_uncertain': True},
                       {'source_unchanged': False}):
            with self.subTest(change=change):
                document = report()
                document['rows'][0].update(validated=False, correctness={'strict_equal': False,
                                         'candidate_losses': [{'field': 'acl'}]}, **change)
                self.assertFalse(evaluate(document)['passed'])

    def test_single_file_floor_uses_paired_median_not_difference_of_medians(self):
        for saving, passed in ((0.000009, False), (gate.SINGLE_FILE_SAVING_S, True)):
            with self.subTest(saving=saving):
                document = report('native/copy/tiny_4kib')
                document['comparisons'][0]['metrics']['wall_s']['paired_median_savings'] = saving
                self.assertEqual(evaluate(document)['passed'], passed)

    def test_single_file_floor_mandatory_even_above_90_percent(self):
        documents = [report(case) for case in gate.UNIVERSE]
        document = next(d for d in documents if d['case_id'] == 'native/copy/tiny_4kib')
        document['comparisons'][0]['metrics']['wall_s']['paired_median_savings'] = 0
        result = gate.evaluate_documents(documents)
        self.assertEqual(result['passing_cases'], 36)
        self.assertFalse(result['passed'])

    def test_bulk_floor(self):
        for candidate, passed in ((90.01, False), (90, True)):
            with self.subTest(candidate=candidate):
                document = report('fileops/clone/flat_2000')
                document['comparisons'][0]['metrics']['wall_s'] = metric('wall_s', 100, candidate)
                self.assertEqual(evaluate(document)['passed'], passed)
        document['comparisons'][0]['metrics']['wall_s'] = metric('wall_s', 1, 0.9)
        self.assertTrue(evaluate(document)['passed'])

    def test_bulk_floor_is_mandatory(self):
        documents = [report(case) for case in gate.UNIVERSE]
        document = next(d for d in documents if d['case_id'] == 'fileops/clone/flat_2000')
        document['comparisons'][0]['metrics']['wall_s'] = metric('wall_s', 100, 99)
        result = gate.evaluate_documents(documents)
        self.assertEqual(result['passing_cases'], 36)
        self.assertFalse(result['passed'])

    def test_elapsed_must_win_not_just_cpu_and_rss(self):
        document = report()
        document['comparisons'][0]['metrics']['wall_s']['decision'] = 'inconclusive'
        self.assertFalse(evaluate(document)['passed'])

    def test_either_cpu_or_rss_suffices(self):
        for name, index in (('cpu_s', 0), ('rss_bytes', 1)):
            with self.subTest(name=name):
                document = report()
                document['comparisons'][index]['metrics'][name]['decision'] = 'candidate_higher'
                self.assertTrue(evaluate(document)['passed'])

    def test_every_reference_required(self):
        document = report()
        extra = copy.deepcopy(document)
        for row in extra['rows'] + extra['comparisons']:
            row['reference'] = 'ditto'
        extra['comparisons'][0]['metrics']['wall_s']['decision'] = 'inconclusive'
        document['rows'].extend(extra['rows'])
        document['comparisons'].extend(extra['comparisons'])
        self.assertFalse(evaluate(document)['passed'])

    def test_short_excluded_or_mismatched_pairs_fail(self):
        for mode in ('short', 'excluded', 'duplicate', 'missing', 'mismatched_count'):
            with self.subTest(mode=mode):
                document = report()
                value = document['comparisons'][0]['metrics']['wall_s']
                if mode == 'short':
                    value['complete_pairs'] = 9
                elif mode == 'excluded':
                    value['excluded_pairs'] = [{'pair_id': 11}]
                elif mode == 'duplicate':
                    document['rows'][1]['pair_id'] = 0
                elif mode == 'missing':
                    document['rows'] = []
                else:
                    value['complete_pairs'] = 11
                    value['native']['n'] = value['candidate']['n'] = 11
                self.assertFalse(evaluate(document)['passed'])

    def test_incomplete_unavailable_and_cleanup_fail(self):
        for change in ({'status': 'failed'}, {'cleanup_passed': False}, {'error': 'timeout'},
                       {'unavailable': [{'reference': 'other', 'phase': 'timing'}]}):
            with self.subTest(change=change):
                document = report()
                document.update(change)
                self.assertFalse(evaluate(document)['passed'])

    def test_fewer_than_three_runs_and_empty(self):
        run = evaluate(report())
        self.assertFalse(gate.qualify([])['qualified'])
        self.assertFalse(gate.qualify([run, run])['qualified'])

    def test_verdict_flip(self):
        passing = evaluate(report())
        document = report()
        document['rows'][0]['validated'] = False
        failing = evaluate(document)
        result = gate.qualify([passing, failing, passing])
        self.assertFalse(result['qualified'])
        self.assertEqual(result['verdict_flips'], [document['case_id']])

    def test_native_case_mapping(self):
        for operation, fixture, expected in (
                ('clone', 'flat_2000', 'fileops/clone/flat_2000'),
                ('copy', 'tiny_4kib', 'native/copy/tiny_4kib'),
                ('scan', 'scan_flat_20k', 'native/scan/scan_flat_20k')):
            with self.subTest(operation=operation):
                document = report()
                del document['case_id']
                for row in document['rows'] + document['comparisons']:
                    row.update(operation=operation, fixture=fixture)
                self.assertTrue(gate.evaluate_documents([document], (expected,))['passed'])

    def test_api_adapter(self):
        result = gate.evaluate_documents([scanner_report('flat')], ('api-scan/flat',))
        self.assertTrue(result['passed'])
        self.assertEqual(len(result['cases'][0]['references']), 2)

    def test_workspace_adapter_without_rss(self):
        result = gate.evaluate_documents([workspace_report('1')],
                                        ('workspace/total/folder-vs-worktree_install/concurrency1',))
        self.assertTrue(result['passed'])

    def test_cli_plain_and_json_are_separate_references(self):
        document = report('cli/clone/tiny_4kib')
        other = copy.deepcopy(document)
        for output, data in (('plain', document), ('json', other)):
            for row in data['rows'] + data['comparisons']:
                row['output'] = output
        document['rows'].extend(other['rows'])
        document['comparisons'].extend(other['comparisons'])
        self.assertEqual(len(evaluate(document)['cases'][0]['references']), 2)
        document['comparisons'][-1]['metrics']['rss_bytes']['complete_pairs'] = 0
        self.assertFalse(evaluate(document)['passed'])

    def test_load_summary_directory_and_campaign_deduplicates(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'native.json').write_text(json.dumps(report()))
            (root / 'summary.json').write_text(json.dumps({'report': 'native.json'}))
            (root / 'campaign.json').write_text(json.dumps({'stages': [{'output': 'summary.json'}]}))
            result = gate.load_run(root)
            case = next(case for case in result['cases'] if case['case'] == 'fileops/move/large_64mib')
            self.assertTrue(case['passed'])
            self.assertEqual(len(case['references']), 1)

    def test_stopped_or_invalidated_campaign_fails_its_reports(self):
        for stage in ({'output': 'summary.json', 'fingerprints_unchanged': False},
                      {'output': 'summary.json', 'status': 'stopped', 'completion_uncertain': True}):
            with tempfile.TemporaryDirectory() as name:
                root = Path(name)
                (root / 'native.json').write_text(json.dumps(report()))
                (root / 'summary.json').write_text(json.dumps({'report': 'native.json'}))
                (root / 'campaign.json').write_text(json.dumps({'stages': [stage]}))
                result = gate.load_run(root)
                self.assertTrue(result['input_errors'])
                self.assertFalse(result['passed'])

    def test_reference_loss_summary_defers_to_its_completed_report(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'native.json').write_text(json.dumps(report()))
            (root / 'summary.json').write_text(json.dumps({
                'status': 'failed', 'report': 'native.json', 'reference_failures': [{'tool': 'rsync'}],
                'error': 'Native comparison failed correctness checks; see reference_failures'}))
            result = gate.load_run(root / 'summary.json')
            self.assertFalse(result['input_errors'])
            case = next(case for case in result['cases'] if case['case'] == 'fileops/move/large_64mib')
            self.assertTrue(case['passed'])

    def test_malformed_campaign_stages_are_input_errors(self):
        with tempfile.TemporaryDirectory() as name:
            file = Path(name) / 'campaign.json'
            for stages in ([None], 'x', [1]):
                file.write_text(json.dumps({'stages': stages}))
                self.assertIn('malformed campaign stages', ' '.join(gate.load_run(file)['input_errors']))

    def test_summary_directory_still_reads_sibling_reports(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'native.json').write_text(json.dumps(report()))
            (root / 'summary.json').write_text(json.dumps({'report': 'native.json'}))
            (root / 'cli').mkdir()
            (root / 'cli' / 'native.json').write_text(json.dumps(report('cli/clone/tiny_4kib')))
            result = gate.load_run(root)
            passed = {case['case'] for case in result['cases'] if case['passed']}
            self.assertEqual(passed, {'fileops/move/large_64mib', 'cli/clone/tiny_4kib'})

    def test_invalid_empty_and_missing_inputs_fail_closed(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for content in ('{', '[]', '{}'):
                file = root / 'bad.json'
                file.write_text(content)
                self.assertTrue(gate.load_run(file)['input_errors'])
            self.assertFalse(gate.load_run(root / 'absent.json')['passed'])

    def test_cli_json_and_nonzero_exit_for_real_universe_missing(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'native.json').write_text(json.dumps(report()))
            with redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()):
                code = gate.main([str(root), '--json', str(root / 'decision.json')])
            self.assertEqual(code, 1)
            self.assertIn('RELEASE GATE: NOT QUALIFIED', output.getvalue())
            self.assertIn('not collected', output.getvalue())
            self.assertFalse(json.loads((root / 'decision.json').read_text())['qualified'])

    def test_failed_summary_follows_run_directory(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            document = report()
            document['status'] = 'failed'
            (root / 'native.json').write_text(json.dumps(document))
            summary = root / 'summary.json'
            summary.write_text(json.dumps({'run_directory': str(root), 'status': 'failed'}))
            result = gate.load_run(summary)
            case = next(case for case in result['cases'] if case['case'] == document['case_id'])
            self.assertFalse(case['passed'])
            self.assertIn('collection incomplete', case['reasons'])
            self.assertNotIn('not collected', case['reasons'])


class ReleaseIndependence(unittest.TestCase):
    ROW_SOURCES = (
        ('native/scan/scan_flat_20k', ('rows',)),
        ('cli/clone/tiny_4kib', ('rows',)),
        ('api-scan/flat', ('workloads', 'flat', 'sample_rows')),
        ('api-scan/flat', ('workloads', 'flat', 'memory_rows')),
        ('workspace/total/folder-vs-worktree_install/concurrency1', ('raw', '1', 'worktree_install')),
    )

    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.decision = root / 'decision.json'
        self.paths = [root / str(i) for i in range(3)]
        for i, directory in enumerate(self.paths):
            directory.mkdir()
            for case in gate.UNIVERSE:
                document = identified_report(case)
                document['timestamp'] = f'2026-01-01T00:00:0{i}+00:00'
                document['collection_metadata'] = {'run': i}
                self.report_path(i, case).write_text(json.dumps(document))
            (directory / 'summary.json').write_text(json.dumps({'report': '0.json'}))

    def report_path(self, run, case):
        return self.paths[run] / f'{gate.UNIVERSE.index(case)}.json'

    def check_decision(self, paths, qualified, error=None):
        with redirect_stdout(io.StringIO()):
            code = gate.main([*map(str, paths), '--json', str(self.decision)])
        decision = json.loads(self.decision.read_text())
        self.assertEqual([run['passing_cases'] for run in decision['runs']], [37, 37, 37])
        self.assertEqual(code, 0 if qualified else 1)
        self.assertEqual(decision['qualified'], qualified)
        if error:
            self.assertIn(error, decision['input_error'])

    def test_independent_complete_runs_with_identical_results_qualify(self):
        self.check_decision(self.paths, True)

    def test_same_resolved_report_paths_cannot_qualify(self):
        self.check_decision([self.paths[0]] * 3, False, 'Runs overlap')

    def test_copies_at_distinct_paths_cannot_qualify(self):
        case = 'native/scan/scan_flat_20k'
        recorded = self.report_path(1, case).read_text()
        for copied in (recorded, json.dumps(json.loads(recorded), sort_keys=True, indent=2)):
            with self.subTest(reformatted=copied != recorded):
                self.report_path(2, case).write_text(copied)
                self.check_decision(self.paths, False, 'Runs overlap')

    def test_row_transplants_cannot_qualify_with_rewritten_or_pruned_metadata(self):
        for case, location in self.ROW_SOURCES:
            with self.subTest(case=case, rows=location):
                target = self.report_path(2, case)
                original = target.read_text()
                source_document = json.loads(self.report_path(1, case).read_text())
                target_document = json.loads(original)
                self.assertNotEqual(target_document['timestamp'], source_document['timestamp'])
                del target_document['collection_metadata']
                source, destination = source_document, target_document
                for key in location:
                    source, destination = source[key], destination[key]
                destination[0] = source[0].copy()
                # Metadata pruning can also change the serialized raw row.
                destination[0].pop('cwd', None)
                destination[0].pop('time_output', None)
                target.write_text(json.dumps(target_document, sort_keys=True, indent=2))
                try:
                    self.check_decision(self.paths, False, 'Runs overlap')
                finally:
                    target.write_text(original)

    def test_missing_or_malformed_sample_id_blocks_qualification(self):
        for case, location in self.ROW_SOURCES:
            target = self.report_path(2, case)
            original = target.read_text()
            for identity in (None, 'not-a-uuid'):
                with self.subTest(case=case, rows=location, identity=identity):
                    document = json.loads(original)
                    samples = document
                    for key in location:
                        samples = samples[key]
                    if identity is None:
                        del samples[0]['sample_id']
                    else:
                        samples[0]['sample_id'] = identity
                    target.write_text(json.dumps(document))
                    self.check_decision(self.paths, False, 'missing or invalid raw sample_id')
            target.write_text(original)

    def test_row_transplants_from_unscored_samples_cannot_qualify(self):
        diagnostic = self.paths[0] / 'diagnostic.json'
        for case, location in self.ROW_SOURCES:
            with self.subTest(case=case, rows=location):
                target = self.report_path(2, case)
                original = target.read_text()
                source = identified_report(case)
                document = json.loads(original)
                source_rows, target_rows = source, document
                for key in location:
                    source_rows, target_rows = source_rows[key], target_rows[key]
                if 'workloads' in source:
                    source['workloads']['diagnostic'] = source['workloads'].pop('flat')
                elif 'raw' in source:
                    source['raw']['2'] = source['raw'].pop('1')
                    source['comparisons']['2'] = source['comparisons'].pop('1')
                else:
                    source['case_id'] = 'native/scan/diagnostic'
                diagnostic.write_text(json.dumps(source))
                try:
                    self.check_decision(self.paths, True)
                    target_rows[0] = source_rows[0]
                    target.write_text(json.dumps(document))
                    self.check_decision(self.paths, False, 'raw benchmark samples were reused')
                finally:
                    target.write_text(original)
                    diagnostic.unlink()

    def test_legacy_report_can_be_inspected_but_blocks_qualification(self):
        case = 'cli/clone/tiny_4kib'
        target = self.report_path(2, case)
        target.write_text(json.dumps(report(case)))
        self.assertEqual(gate.load_run(self.paths[2])['passing_cases'], 37)
        self.check_decision(self.paths, False, 'missing or invalid raw sample_id')

    def test_a_sample_cannot_stand_in_for_two_pairs_in_one_comparison(self):
        target = self.report_path(2, 'native/scan/scan_flat_20k')
        document = json.loads(target.read_text())
        document['rows'][1]['sample_id'] = document['rows'][0]['sample_id']
        target.write_text(json.dumps(document))
        self.check_decision(self.paths, False, 'raw sample_id repeated within a comparison')


if __name__ == '__main__':
    unittest.main()
