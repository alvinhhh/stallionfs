"""Release acceptance over recorded paired comparisons, not collection success."""
import argparse
import json
import math
from pathlib import Path
import runpy
import sys


PASS_FRACTION = 0.90
SINGLE_FILE_SAVING_S = 0.00001
BULK_IMPROVEMENT = 0.10
MINIMUM_PAIRS = 10
MINIMUM_RUNS = 3
CANDIDATE_METHODS = {'stallionfs', 'candidate', 'bulk', 'bulk_serial', 'stallionfs_folder'}
CATALOG_ONLY = {'cli/scan/empty', 'cli/scan/nested_1000',
                'cli/volumes/volumes', 'cli/move/tiny_4kib'}
CATALOG = runpy.run_path(str(Path(__file__).resolve().parents[2] /
                            'stallionfs' / '_benchmark_cases.py'))['CASES']
UNIVERSE = tuple(case['id'] for case in CATALOG)


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def bulk_case(case):
    return ('scan/' in case or case.startswith('api-scan/') or
            any(name in case for name in ('flat_2000', 'nested_10000', 'docs_',
                                         'git_', 'dependencies_', 'cache_', 'dataset_')))


def case_id(record, document):
    if document.get('case_id'):
        return document['case_id']
    fixture, operation = record.get('fixture'), record.get('operation')
    if not fixture or not operation:
        return None
    family = 'native' if operation in ('copy', 'scan') else 'fileops'
    return f'{family}/{operation}/{fixture}'


def document_errors(document):
    errors = []
    if document.get('status') != 'complete':
        errors.append('collection incomplete')
    if document.get('cleanup_passed') is not True:
        errors.append('cleanup not verified')
    if any(document.get(key) for key in ('error', 'retained_fixture', 'completion_uncertain',
                                         'cold_cache_unavailable')):
        errors.append('collection error or unavailable evidence')
    return errors


def native_groups(document):
    groups = {}
    for kind in ('comparisons', 'rows', 'unavailable'):
        for record in document.get(kind, []):
            case = case_id(record, document)
            if case is None:
                continue
            context = tuple(record.get(key) for key in ('run', 'cache', 'output', 'reference'))
            key = (case, context)
            group = groups.setdefault(key, {'case': case, 'reference': str(context),
                                            'metrics': {}, 'rows': {}, 'unavailable': [],
                                            'errors': document_errors(document)})
            if kind == 'unavailable':
                group['errors'].append('unavailable')
                group['unavailable'].append(record)
                continue
            phase = record.get('phase')
            if kind == 'rows':
                group['rows'].setdefault(phase, []).append(record)
            else:
                for metric, value in record.get('metrics', {}).items():
                    if (phase == 'timing' and metric in ('wall_s', 'cpu_s') or
                            phase == 'resources' and metric == 'rss_bytes'):
                        if metric in group['metrics']:
                            group['errors'].append('duplicate metric evidence')
                        group['metrics'][metric] = value
    return list(groups.values())


def api_groups(document):
    groups = []
    for layout, workload in document['workloads'].items():
        for method in ('bulk_serial', 'bulk'):
            metrics = dict(workload.get('timing_comparisons', {}).get(method, {}))
            metrics.update(workload.get('memory_comparisons', {}).get(method, {}))
            groups.append({'case': 'api-scan/' + layout, 'reference': method + '-vs-posix',
                           'metrics': metrics, 'errors': document_errors(document),
                           'rows': {phase: [row for row in workload.get(source, [])
                                            if row.get('method') in ('posix', method)]
                                    for phase, source in (('timing', 'sample_rows'),
                                                          ('resources', 'memory_rows'))
                                    if workload.get(source)}})
    return groups


def workspace_groups(document):
    groups = []
    for count, comparison in document['comparisons'].items():
        metrics = comparison.get('methods', {}).get('stallionfs_folder', {})
        rows = document.get('raw', {}).get(count, {})
        errors = document_errors(document)
        if comparison.get('unavailable') or comparison.get('diagnostic_only'):
            errors.append('workspace reference unavailable or diagnostic only')
        groups.append({'case': 'workspace/total/folder-vs-worktree_install/concurrency' + count,
                       'reference': 'worktree_install', 'errors': errors,
                       'metrics': {key: metrics[source] for key, source in
                                   (('wall_s', 'total_s'), ('cpu_s', 'total_cpu_s'))
                                   if source in metrics},
                       'rows': {'timing': [dict(row, method=method)
                                           for method in ('worktree_install', 'stallionfs_folder')
                                           for row in rows.get(method, [])]}})
    return groups


def valid_metric(metric):
    return (isinstance(metric, dict) and type(metric.get('complete_pairs')) is int and
            metric['complete_pairs'] >= MINIMUM_PAIRS and metric.get('excluded_pairs') == [] and
            all(isinstance(metric.get(side), dict) and
                type(metric[side].get('n')) is int and
                metric[side]['n'] == metric['complete_pairs'] and
                number(metric[side].get('median')) and metric[side]['median'] >= 0
                for side in ('native', 'candidate')))


def reference_losses(row):
    correctness = row.get('correctness', {})
    if (row.get('method') not in CANDIDATE_METHODS and
            (correctness.get('candidate_losses') or correctness.get('sparse_preserved') is False)):
        return {'method': row.get('method'), 'phase': row.get('phase'),
                'pair_id': row.get('pair_id'), 'correctness': correctness}
    return None


def operation_failed(row):
    correctness = row.get('correctness', {})
    return (row.get('ok') is not True or row.get('exit_code', 0) != 0 or
            row.get('completion_uncertain') or row.get('source_unchanged') is False or
            row.get('source_verification', {}).get('unchanged') is False or
            row.get('source_precheck', {}).get('unchanged') is False or
            row.get('counts_validated') is False or
            not reference_losses(row) and
            (row.get('validated') is not True or correctness.get('passed') is False or
             correctness.get('strict_equal') is False or
             any(correctness.get(key) is False for key in
                 ('sparse_preserved', 'independent_clone', 'move_identity', 'move_source_absent'))))


def row_errors(phases):
    errors = []
    if not phases.get('timing'):
        errors.append('raw validated timing pairs missing')
    for phase, rows in phases.items():
        methods = {}
        for row in rows:
            if operation_failed(row):
                errors.append('row correctness/validation failed')
            if row.get('warmup'):
                continue
            methods.setdefault(row.get('method'), []).append(row.get('pair_id'))
        pairs = list(methods.values())
        if (len(pairs) != 2 or any(None in ids or len(ids) != len(set(ids)) or
                                   len(ids) < MINIMUM_PAIRS for ids in pairs) or
                len(pairs) == 2 and set(pairs[0]) != set(pairs[1])):
            errors.append(str(phase) + ': fewer than ten complete unique validated pairs')
    return errors


def evaluate_group(group):
    metrics, case = group['metrics'], group['case']
    errors = list(group['errors']) + row_errors(group['rows'])
    for name, metric in metrics.items():
        phase = 'resources' if name == 'rss_bytes' else 'timing'
        counts = {}
        for row in group['rows'].get(phase, []):
            if not row.get('warmup'):
                method = row.get('method')
                counts[method] = counts.get(method, 0) + 1
        if (not valid_metric(metric) or any(count != metric['complete_pairs']
                                           for count in counts.values()) or len(counts) != 2):
            errors.append(name + ': incomplete or inconsistent paired evidence')
    wall = metrics.get('wall_s')
    if not valid_metric(wall):
        errors.append('not comparable: no valid elapsed paired comparison')
    if not any(valid_metric(metrics.get(metric)) for metric in ('cpu_s', 'rss_bytes')):
        errors.append('not comparable: no valid CPU or peak RSS paired comparison')
    faster = valid_metric(wall) and wall.get('decision') in ('candidate_faster', 'faster')
    if not faster:
        errors.append('elapsed not lower beyond noise with >=10 valid pairs')
    resource_win = any(valid_metric(metrics.get(metric)) and
                       metrics[metric].get('decision') in ('candidate_lower', 'lower')
                       for metric in ('cpu_s', 'rss_bytes'))
    if not resource_win:
        errors.append('neither CPU nor peak RSS lower beyond noise')
    floor_errors = []
    if 'tiny_4kib' in case:
        if not (faster and number(wall.get('paired_median_savings')) and
                wall['paired_median_savings'] >= SINGLE_FILE_SAVING_S):
            floor_errors.append('single-file paired elapsed saving below 0.01 ms or unverified')
    if bulk_case(case):
        if not (valid_metric(wall) and wall['native']['median'] > 0 and
                wall['candidate']['median'] <= wall['native']['median'] * (1 - BULK_IMPROVEMENT)):
            floor_errors.append('bulk median elapsed improvement below 10% or unverified')
    errors.extend(floor_errors)
    warnings = [reference_losses(row) for rows in group['rows'].values() for row in rows
                if reference_losses(row)]
    excluded = (bool(warnings) and
                not (valid_metric(wall) and any(valid_metric(metrics.get(metric))
                                               for metric in ('cpu_s', 'rss_bytes'))) and
                not any(operation_failed(row) for rows in group['rows'].values() for row in rows) and
                all(error == 'unavailable' for error in group['errors']) and
                all(record.get('reason') in ('method failed; remaining identical attempts skipped',
                                            'pair unavailable after a method failed; neither side repeated')
                    and set(record.get('failed_methods', [record.get('method')])) <=
                    {warning['method'] for warning in warnings}
                    for record in group.get('unavailable', [])))
    return {**group, 'passed': not errors, 'floor_passed': not floor_errors,
            'reference_losses': warnings, 'excluded': excluded,
            'reasons': sorted(set(errors))}


def evaluate_documents(documents, universe=UNIVERSE, input_errors=()):
    collected = {case: [] for case in universe}
    for document in documents:
        if 'workloads' in document:
            groups = api_groups(document)
        elif isinstance(document.get('comparisons'), dict) and 'raw' in document:
            groups = workspace_groups(document)
        else:
            groups = native_groups(document)
        for group in groups:
            if group['case'] in collected:
                collected[group['case']].append(evaluate_group(group))
    cases = []
    for case, groups in collected.items():
        required = [group for group in groups if not group['excluded']]
        reasons = sorted({reason for group in required for reason in group['reasons']})
        if not groups:
            reasons = (['catalog only: no native reference or collector'] if case in CATALOG_ONLY
                       else ['not collected'])
        elif not required:
            reasons.append('no comparable reference')
        cases.append({'case': case, 'passed': bool(groups) and not reasons,
                      'floor_passed': (all(group['floor_passed'] for group in required) if required else
                                       'tiny_4kib' not in case and not bulk_case(case)),
                      'reasons': reasons, 'references': groups})
    passing = sum(case['passed'] for case in cases)
    required = math.ceil(len(cases) * PASS_FRACTION)
    return {'passed': passing >= required and all(case['floor_passed'] for case in cases)
            and not input_errors, 'passing_cases': passing, 'total_cases': len(cases),
            'required_passing_cases': required, 'cases': cases, 'input_errors': list(input_errors)}


def qualify(runs):
    flips = [case['case'] for case in runs[0]['cases']
             if len({next(item['passed'] for item in run['cases'] if item['case'] == case['case'])
                     for run in runs}) > 1] if runs else []
    return {'kind': 'release gate', 'qualified': len(runs) >= MINIMUM_RUNS and
            all(run['passed'] for run in runs) and not flips,
            'minimum_runs': MINIMUM_RUNS, 'constants': {'pass_fraction': PASS_FRACTION,
            'single_file_saving_s': SINGLE_FILE_SAVING_S, 'bulk_improvement': BULK_IMPROVEMENT},
            'verdict_flips': flips, 'runs': runs}


def load_run(path):
    documents, errors, seen = [], [], set()

    def read(file, explicit=False):
        file = file.resolve()
        if file in seen:
            return
        seen.add(file)
        try:
            document = json.loads(file.read_text(), parse_constant=lambda value: None)
            if not isinstance(document, dict):
                raise ValueError('expected a JSON object')
            stages = document.get('stages', [])
            if not isinstance(stages, list) or not all(isinstance(row, dict) for row in stages):
                raise ValueError('malformed campaign stages')
            for row in [document] + stages:
                if (row.get('error') or row.get('completion_uncertain') or
                        row.get('status') == 'stopped' or row.get('fingerprints_unchanged') is False):
                    errors.append(f'{file}: collection wrapper stopped or invalidated'
                                  + (f": {row['error']}" if row.get('error') else ''))
            if 'report' in document:
                target = Path(document['report'])
                read(target if target.is_absolute() else file.parent / target, True)
            elif 'campaign' in document:
                target = Path(document['campaign'])
                read(target if target.is_absolute() else file.parent / target, True)
            elif 'stages' in document:
                for stage in document['stages']:
                    target = Path(stage['output'])
                    read(target if target.is_absolute() else file.parent / target, True)
            elif ('workloads' in document or 'comparisons' in document and
                  ('rows' in document or 'raw' in document)):
                documents.append(document)
            elif 'run_directory' in document:
                target = Path(document['run_directory'])
                read((target if target.is_absolute() else file.parent / target) / 'native.json', True)
            elif explicit:
                raise ValueError('not a completed benchmark report or summary')
        except (OSError, ValueError, TypeError, KeyError) as error:
            errors.append(str(file) + ': ' + str(error))

    if path.is_dir():
        entry = next((path / name for name in ('summary.json', 'campaign.json')
                      if (path / name).is_file()), None)
        if entry:
            read(entry, True)
        for file in sorted(path.rglob('*.json')):
            if not file.name.endswith('.partial.json'):
                read(file)
    else:
        read(path, True)
    if not documents:
        errors.append('no benchmark reports found')
    result = evaluate_documents(documents, input_errors=errors)
    result['input'] = str(path)
    result['report_files'] = sorted(map(str, seen))
    return result


def medians(group):
    parts = []
    for key in ('wall_s', 'cpu_s', 'rss_bytes'):
        value = group['metrics'].get(key)
        if valid_metric(value):
            parts.append(f"{key}={value['native']['median']:.6g}→{value['candidate']['median']:.6g}")
        else:
            parts.append(key + '=unavailable')
    return ', '.join(parts)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', type=Path, nargs='+', metavar='RUN')
    parser.add_argument('--json', type=Path, help='Write the full release-gate decision')
    args = parser.parse_args(argv)
    try:
        result = qualify([load_run(path) for path in args.runs])
        files = [set(run['report_files']) for run in result['runs']]
        if any(left & right for index, left in enumerate(files) for right in files[index + 1:]):
            result['qualified'] = False
            result['input_error'] = 'Runs overlap; independent qualification runs are required'
        print('RELEASE GATE (not collection passing); elapsed/CPU seconds, RSS bytes')
        print('Case | ' + ' | '.join(f'Run {i + 1}' for i in range(len(args.runs))) + ' | Reasons / medians native→sfs')
        for index, case in enumerate(UNIVERSE):
            values = [run['cases'][index] for run in result['runs']]
            details = []
            for i, value in enumerate(values):
                detail = '; '.join(value['reasons']) or 'pass'
                measured = '; '.join(group['reference'] + ': ' + medians(group)
                                     for group in value['references'])
                losses = sorted({warning['method'] + ': ' + ','.join(sorted(
                    {loss['field'] for loss in warning['correctness'].get('candidate_losses', [])} |
                    ({'sparse_preserved'} if warning['correctness'].get('sparse_preserved') is False else set())))
                    for group in value['references'] for warning in group['reference_losses']})
                if losses:
                    detail += '; reference not comparable: ' + '; '.join(losses) if any(
                        group['excluded'] for group in value['references']) else (
                        '; reference losses (not candidate failures): ' + '; '.join(losses))
                details.append(f'R{i + 1}: {detail}' + ('; ' + measured if measured else ''))
            print(case + ' | ' + ' | '.join('PASS' if value['passed'] else 'FAIL' for value in values)
                  + ' | ' + ' / '.join(details))
        for i, run in enumerate(result['runs']):
            print(f"Run {i + 1}: {run['passing_cases']}/{run['total_cases']} cases pass; "
                  f"need {run['required_passing_cases']} plus all single-file/bulk floors; "
                  + ('PASS' if run['passed'] else 'FAIL'))
            for error in run['input_errors']:
                print('Input error: ' + error)
        print('Verdict flips: ' + (', '.join(result['verdict_flips']) or 'none'))
        if result.get('input_error'):
            print(result['input_error'])
        print(f"RELEASE GATE: {'QUALIFIED' if result['qualified'] else 'NOT QUALIFIED'} "
              f"({len(args.runs)} runs; at least {MINIMUM_RUNS} required)")
        if args.json:
            args.json.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
        return 0 if result['qualified'] else 1
    except (OSError, ValueError, TypeError, KeyError) as error:
        print('RELEASE GATE: NOT QUALIFIED: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
