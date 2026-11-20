"""Release-gate acceptance and report adapters without executing benchmarks."""
from contextlib import redirect_stdout, redirect_stderr
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


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


class ReleaseGate(unittest.TestCase):
    def test_universe_counts_every_catalog_case(self):
        self.assertEqual(len(gate.UNIVERSE), 37)
        self.assertEqual(set(gate.UNIVERSE), {case['id'] for case in gate.CATALOG})

    def test_uncollectable_catalog_only_cases_fail_in_denominator(self):
        result = gate.evaluate_documents([report(case) for case in gate.UNIVERSE
                                          if case not in gate.CATALOG_ONLY])
        self.assertEqual((result['passing_cases'], result['total_cases']), (33, 37))
        self.assertFalse(result['passed'])
        case = next(case for case in result['cases'] if case['case'] == 'cli/volumes/volumes')
        self.assertEqual(case['reasons'], ['catalog only: no native reference or collector'])

    def test_all_pass(self):
        result = gate.evaluate_documents([report(case) for case in gate.UNIVERSE])
        self.assertEqual(result['passing_cases'], 37)
        self.assertTrue(gate.qualify([result, copy.deepcopy(result), copy.deepcopy(result)])['qualified'])

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
        workload = {'sample_rows': rows('timing', ('posix', 'bulk_serial')) +
                    [r for r in rows('timing', ('bulk',))],
                    'memory_rows': rows('resources', ('posix', 'bulk_serial')) +
                    [r for r in rows('resources', ('bulk',))],
                    'timing_comparisons': {method: {name: metric(name) for name in ('wall_s', 'cpu_s')}
                                           for method in ('bulk', 'bulk_serial')},
                    'memory_comparisons': {method: {'rss_bytes': metric('rss_bytes')}
                                           for method in ('bulk', 'bulk_serial')}}
        document = {'status': 'complete', 'cleanup_passed': True, 'workloads': {'flat': workload}}
        result = gate.evaluate_documents([document], ('api-scan/flat',))
        self.assertTrue(result['passed'])
        self.assertEqual(len(result['cases'][0]['references']), 2)

    def test_workspace_adapter_without_rss(self):
        document = {'status': 'complete', 'cleanup_passed': True,
                    'raw': {'1': {method: rows('timing', (method,)) for method in
                                   ('worktree_install', 'stallionfs_folder')}},
                    'comparisons': {'1': {'methods': {'stallionfs_folder': {
                        'total_s': metric('wall_s'), 'total_cpu_s': metric('cpu_s')}}}}}
        result = gate.evaluate_documents([document],
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

    def test_three_distinct_complete_directories_qualify_but_reuse_does_not(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            paths = []
            for i in range(3):
                directory = root / str(i)
                directory.mkdir()
                paths.append(str(directory))
                for j, case in enumerate(gate.UNIVERSE):
                    (directory / f'{j}.json').write_text(json.dumps(report(case)))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(gate.main(paths), 0)
            self.assertIn('RELEASE GATE: QUALIFIED', output.getvalue())
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(gate.main([paths[0]] * 3), 1)
            self.assertIn('Runs overlap', output.getvalue())


if __name__ == '__main__':
    unittest.main()
