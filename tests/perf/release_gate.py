"""Release acceptance over recorded paired comparisons, not collection success."""
import argparse
from contextlib import closing
from datetime import datetime
import hashlib
from itertools import takewhile, zip_longest
import json
import math
from pathlib import Path
import re
import runpy
import sys


PASS_FRACTION = 0.90
SINGLE_FILE_SAVING_S = 0.00001
BULK_IMPROVEMENT = 0.10
MINIMUM_PAIRS = 10
MINIMUM_RUNS = 3
CANDIDATE_METHODS = {'stallionfs', 'candidate', 'bulk', 'bulk_serial', 'stallionfs_folder'}
SAMPLE_ID = re.compile(r'[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}')
CATALOG = runpy.run_path(str(Path(__file__).resolve().parents[2] /
                            'stallionfs' / '_benchmark_cases.py'))['CASES']
UNIVERSE = tuple(case['id'] for case in CATALOG)

CAMPAIGN_STAGES = {
    'native-files': 'fileops/',
    'native-copy': 'native/copy/',
    'native-cli-delete': 'cli/delete/',
    'native-cli-clone': 'cli/clone/',
    'native-cli-move': 'cli/move/',
    'native-cli-scan': 'cli/scan/',
    'native-cli-volumes': 'cli/volumes/',
    'native-scan': 'native/scan/',
    'scan-api': 'api-scan/',
    'scan-api-cold': 'api-scan/',
    'workspaces': 'workspace/',
}
SHA256 = re.compile(r'[0-9a-f]{64}')


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


def raw_report_rows(document):
    if 'workloads' in document:
        for workload in document['workloads'].values():
            yield from workload.get('sample_rows', [])
            yield from workload.get('memory_rows', [])
    elif isinstance(document.get('comparisons'), dict) and 'raw' in document:
        raw = document['raw']
        if not isinstance(raw, dict):
            raise ValueError('expected a raw workspace sample object')
        for concurrency in raw.values():
            if not isinstance(concurrency, dict):
                raise ValueError('expected raw workspace methods for each concurrency')
            for rows in concurrency.values():
                yield from rows
    else:
        yield from document.get('rows', [])


def evaluate_documents(documents, universe=UNIVERSE, input_errors=()):
    collected = {case: [] for case in universe}
    raw_sample_ids = set()
    candidate_failure_cases = set()
    for document in documents:
        # Unscored reports and methods can still reveal reuse by a scored comparison.
        for row in raw_report_rows(document):
            if not isinstance(row, dict):
                raise ValueError('expected a raw benchmark sample object')
            identity = row.get('sample_id')
            if isinstance(identity, str) and SAMPLE_ID.fullmatch(identity):
                raw_sample_ids.add(identity)
        if 'workloads' in document:
            groups = api_groups(document)
        elif isinstance(document.get('comparisons'), dict) and 'raw' in document:
            groups = workspace_groups(document)
        else:
            groups = native_groups(document)
        for group in groups:
            if group['case'] in collected:
                collected[group['case']].append(evaluate_group(group))
                if any(row.get('method') in CANDIDATE_METHODS and operation_failed(row)
                       for rows in group['rows'].values() for row in rows):
                    candidate_failure_cases.add(group['case'])
    cases = []
    for case, groups in collected.items():
        required = [group for group in groups if not group['excluded']]
        reasons = sorted({reason for group in required for reason in group['reasons']})
        if not groups:
            reasons = ['not collected']
        elif not required:
            reasons.append('no comparable reference')
        cases.append({'case': case, 'passed': bool(groups) and not reasons,
                      'floor_passed': (all(group['floor_passed'] for group in required) if required else
                                       'tiny_4kib' not in case and not bulk_case(case)),
                      'reasons': reasons, 'references': groups})
    passing = sum(case['passed'] for case in cases)
    required = math.ceil(len(cases) * PASS_FRACTION)
    return {'passed': passing >= required and all(case['floor_passed'] for case in cases)
            and not candidate_failure_cases and not input_errors,
            'passing_cases': passing, 'total_cases': len(cases),
            'required_passing_cases': required, 'cases': cases, 'input_errors': list(input_errors),
            'candidate_failure_cases': sorted(candidate_failure_cases),
            'raw_sample_ids': sorted(raw_sample_ids)}


def runs_overlap(identities):
    return any(not left.isdisjoint(right) for index, left in enumerate(identities)
               for right in identities[index + 1:])


def independence_error(runs):
    if runs_overlap([set(run.get('report_files', [])) for run in runs]):
        return 'Runs overlap; independent qualification runs are required'
    evidence = []
    for index, run in enumerate(runs, 1):
        sample_ids = set(run.get('raw_sample_ids', []))
        for case in run['cases']:
            for group in case['references']:
                group_ids = set()
                for rows in group['rows'].values():
                    for row in rows:
                        identity = row.get('sample_id')
                        if not isinstance(identity, str) or not SAMPLE_ID.fullmatch(identity):
                            return f"Run {index}, {case['case']}: missing or invalid raw sample_id"
                        if identity in group_ids:
                            return f"Run {index}, {case['case']}: raw sample_id repeated within a comparison"
                        group_ids.add(identity)
                # The two API bulk comparisons share the same POSIX samples.
                sample_ids.update(group_ids)
        evidence.append(sample_ids)
    if runs_overlap(evidence):
        return 'Runs overlap; raw benchmark samples were reused'
    return None


def qualify(runs):
    flips = [case['case'] for case in runs[0]['cases']
             if len({next(item['passed'] for item in run['cases'] if item['case'] == case['case'])
                     for run in runs}) > 1] if runs else []
    error = independence_error(runs)
    result = {'kind': 'release gate', 'qualified': len(runs) >= MINIMUM_RUNS and
              all(run['passed'] for run in runs) and not flips and error is None,
              'minimum_runs': MINIMUM_RUNS, 'constants': {'pass_fraction': PASS_FRACTION,
              'single_file_saving_s': SINGLE_FILE_SAVING_S, 'bulk_improvement': BULK_IMPROVEMENT},
              'verdict_flips': flips, 'runs': runs}
    if error:
        result['input_error'] = error
    return result


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
                completed_failure_report = 'reference_failures' in row and 'report' in row
                if ((row.get('error') and not completed_failure_report) or row.get('completion_uncertain') or
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


def campaign_file(expected, recorded):
    if (expected.parent / recorded != expected or expected.resolve() != expected or
            not expected.is_file()):
        raise ValueError(f'missing or misassigned campaign file: {expected.name}')
    return expected


def json_object(raw):
    document = json.loads(raw, parse_constant=lambda value: None)
    if not isinstance(document, dict):
        raise ValueError('expected a JSON object')
    return document


def clean_campaign_report(document):
    return (not document_errors(document) and not document.get('cleanup_error') and
            type(document.get('passed')) is bool)


def verified_native_report(output, raw, evidence=None):
    from native_report import ENCODER, KINDS, ReportJournal

    if evidence is not None:
        campaign_file(output.with_suffix('.json.manifest'), evidence['manifest'])
        campaign_file(output.with_suffix('.json.journal'), evidence['journal'])
    try:
        with closing(ReportJournal.open_existing(output)) as reader:
            if evidence is not None:
                provenance = reader.provenance
                if (provenance['original_manifest_sha256'] != evidence['manifest_sha256'] or
                        provenance['committed_bytes'] != evidence['committed_bytes'] or
                        provenance['committed_prefix_sha256'] != evidence['claimed_prefix_sha256']):
                    raise ValueError('native journal does not match its recorded control evidence')
            document = json.loads(raw)
            state = reader.state
            if (not isinstance(document, dict) or set(document) != set(state).union(KINDS) or
                    ENCODER.encode({key: document[key] for key in state}) != ENCODER.encode(state)):
                raise ValueError('final native report state differs from committed journal')
            for kind in KINDS:
                records = document[kind]
                if not isinstance(records, list) or any(
                        not isinstance(final, dict) or committed is None or
                        ENCODER.encode(final) != ENCODER.encode(committed)
                        for final, committed in zip_longest(records, reader.iter_latest(kind))):
                    raise ValueError(f'final native report {kind} differ from committed journal')
            return document
    except ValueError as error:
        raise ValueError(f'{output.name}: {error}') from error


def campaign_reports(output, stage, cache):
    name = stage['stage']
    raw = output.read_bytes()
    outcome, evidence = stage['outcome'], stage['evidence']
    native = name.startswith('native-')
    cli = name.startswith('native-cli-')
    document = verified_native_report(output, raw, evidence) if native else json_object(raw)
    passed = document.get('passed')
    if (not clean_campaign_report(document) or not clean_campaign_report(outcome) or
            any(document.get(key) != value for key, value in outcome.items()) or
            evidence.get('final_report_exists') is not True or
            stage.get('status') != ('complete' if passed else 'complete_with_failures') or
            type(stage.get('exit_code')) is not int or stage['exit_code'] != (0 if passed else 1) or
            (not passed and (not native or cli))):
        raise ValueError('stage did not finish with confirmed cleanup and final report')

    if not native:
        campaign_file(output, evidence['summary'])
        if hashlib.sha256(raw).hexdigest() != evidence['summary_sha256']:
            raise ValueError('report does not match its recorded summary evidence')

    cases = [case for case in UNIVERSE if case.startswith(CAMPAIGN_STAGES[name])]
    reports = {output: document}
    if cli:
        if (document.get('case_ids', [document.get('case_id')]) != cases or
                document.get('case_id') not in (None, *cases) or
                document.get('source_checks_passed') is not True or document.get('cache') != cache):
            raise ValueError('CLI case IDs, source checks or cache do not match the stage')
        if name == 'native-cli-scan':
            reports = {}
            links = document['stages']
            if not isinstance(links, list) or len(links) != len(cases):
                raise ValueError('missing CLI scan case reports')
            if any(row.get('case_id') not in cases for kind in ('rows', 'comparisons', 'unavailable')
                   for row in document[kind]):
                raise ValueError('unexpected evidence in the CLI scan aggregate')
            for case, link in zip(cases, links):
                child = campaign_file(output.with_stem(output.stem + '-' + case.rsplit('/', 1)[-1]),
                                      link['output'])
                report = verified_native_report(child, child.read_bytes())
                if (not clean_campaign_report(report) or report['passed'] is not True or
                        report.get('case_id') != case or report.get('source_checks_passed') is not True or
                        report.get('cache') != cache or any(
                            report[kind] != [row for row in document[kind] if row.get('case_id') == case]
                            for kind in ('rows', 'comparisons', 'unavailable'))):
                    raise ValueError(f'{child.name}: CLI scan case report does not match its aggregate')
                reports[child] = report
    if native:
        contexts = {(case_id(row, report), row.get('cache'), row.get('output') if cli else None)
                    for report in reports.values() for kind in ('rows', 'comparisons', 'unavailable')
                    for row in report[kind]}
        if not {(case, mode, form) for case in cases for mode in cache
                for form in (('plain', 'json') if cli else (None,))} <= contexts:
            raise ValueError('missing case, cache or output-form evidence for the stage')
    elif name == 'workspaces':
        if (document.get('format') != 4 or document.get('workspace_invocation') != 'cli' or
                not {'1', '4'} <= document['comparisons'].keys()):
            raise ValueError('missing CLI folder-workspace comparisons')
    elif (document.get('cache') != cache[0] or
          not {case.split('/')[-1] for case in cases} <= document['workloads'].keys()):
        raise ValueError('missing API scan workload or wrong cache')

    return list(reports.values()), {output, *reports}


def campaign_time(record, key):
    stamp = datetime.fromisoformat(record[key])
    if stamp.utcoffset() is None:
        raise ValueError('campaign timestamp is missing its time zone')
    return stamp


def load_campaign(path):
    """Use one closed campaign as one qualification input per sequential cycle."""
    path = path.resolve()
    try:
        campaign = json_object(path.read_bytes())
        cache, samples = campaign['cache'], campaign['samples']
        if (type(campaign.get('schema')) is not int or campaign['schema'] != 1 or
                type(campaign.get('cycles')) is not int or campaign['cycles'] != MINIMUM_RUNS or
                campaign.get('status') != 'complete' or any(campaign.get(key) for key in
                    ('error', 'completion_uncertain', 'cold_cache_unavailable')) or
                not isinstance(cache, list) or not cache or not set(cache) <= {'warm', 'cold'} or
                len(cache) != len(set(cache)) or type(samples) is not int or not 10 <= samples <= 100):
            raise ValueError('expected a complete three-cycle campaign with valid cache and sample settings')
        pins = campaign['fingerprints']
        for kind in ('source_sha256', 'runtime_sha256'):
            if not isinstance(pins[kind], dict) or not pins[kind] or not all(
                    isinstance(value, str) and SHA256.fullmatch(value) for value in pins[kind].values()):
                raise ValueError(f'missing or invalid campaign {kind} fingerprints')
        if 'cold' in cache and (not isinstance(pins.get('cold_tools'), dict) or not pins['cold_tools']):
            raise ValueError('missing cold-tool fingerprints')
        stages = [name for name in CAMPAIGN_STAGES if name != 'scan-api-cold' or 'cold' in cache]
        expected = [(cycle, name) for cycle in range(1, MINIMUM_RUNS + 1) for name in stages]
        if [(row['cycle'], row['stage']) for row in campaign['stages']] != expected:
            raise ValueError('missing, repeated or nonsequential campaign stages')
        previous = campaign_time(campaign, 'started_utc')
        for row in campaign['stages']:
            started, ended = campaign_time(row, 'started_utc'), campaign_time(row, 'ended_utc')
            if type(row['cycle']) is not int or not previous <= started <= ended:
                raise ValueError('nonsequential campaign stage timestamps')
            previous = ended
        if (previous > campaign_time(campaign, 'ended_utc') or
                campaign.get('collection_passed') is not
                all(row.get('status') == 'complete' for row in campaign['stages'])):
            raise ValueError('inconsistent campaign completion status')
    except (OSError, ValueError, TypeError, KeyError) as error:
        return [dict(evaluate_documents([], input_errors=[f'{path}: {error}']), input=str(path))]

    configurations, runs = {}, []
    rows = iter(campaign['stages'])
    for cycle in range(1, MINIMUM_RUNS + 1):
        documents, files, errors = [], [], []
        for name in stages:
            stage = next(rows)
            label = f'cycle-{cycle}-{name}'
            try:
                mode = cache if name.startswith('native-') else ['cold' if name == 'scan-api-cold' else 'warm']
                if (stage.get('fingerprints_unchanged') is not True or stage.get('cache') != mode or
                        any(stage.get(key) for key in ('error', 'completion_uncertain', 'omitted_cold_cache'))):
                    raise ValueError('invalidated or incomplete stage, or mismatched cache')
                output = campaign_file(path.parent / (label + '.json'), stage['output'])
                campaign_file(output.with_suffix('.log'), stage['log'])
                argv = stage['argv']
                if not isinstance(argv, list) or not all(isinstance(arg, str) for arg in argv):
                    raise ValueError('invalid stage command')
                output_index = argv.index('--output') + 1
                campaign_file(output, argv[output_index])
                command = argv[:output_index] + argv[output_index + 1:]
                actual_cache = (list(takewhile(lambda arg: not arg.startswith('--'),
                                               argv[argv.index('--cache') + 1:]))
                                if name != 'workspaces' else mode)
                if (command != configurations.setdefault(name, command) or actual_cache != mode or
                        argv[argv.index('--samples') + 1] != str(samples) or
                        (name in ('native-files', 'native-copy', 'native-scan') and
                         argv[argv.index('--runs') + 1] != '1')):
                    raise ValueError('stage command does not match the campaign configuration')
                reports, report_files = campaign_reports(output, stage, mode)
                documents.extend(reports)
                files.extend(report_files)
            except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError) as error:
                errors.append(f'{label}: {error}')
        try:
            run = evaluate_documents(documents, input_errors=errors)
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            run = evaluate_documents([], input_errors=[*errors, f'Cycle {cycle}: {error}'])
        runs.append(dict(run, input=str(path), cycle=cycle, report_files=sorted(map(str, files))))
    return runs


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
    parser.add_argument('runs', type=Path, nargs='*', metavar='RUN')
    parser.add_argument('--campaign', type=Path, metavar='CAMPAIGN.JSON',
                        help='Evaluate each of the three cycles in one completed campaign')
    parser.add_argument('--json', type=Path, help='Write the full release-gate decision')
    args = parser.parse_args(argv)
    if bool(args.campaign) == bool(args.runs):
        parser.error('Provide positional runs or one --campaign manifest')
    try:
        runs = load_campaign(args.campaign) if args.campaign else [load_run(path) for path in args.runs]
        result = qualify(runs)
        print('RELEASE GATE (not collection passing); elapsed/CPU seconds, RSS bytes')
        print('Case | ' + ' | '.join(f'Run {i + 1}' for i in range(len(runs))) + ' | Reasons / medians native→sfs')
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
            if run['candidate_failure_cases']:
                print('Candidate operation or correctness failures: ' + ', '.join(run['candidate_failure_cases']))
            for error in run['input_errors']:
                print('Input error: ' + error)
        print('Verdict flips: ' + (', '.join(result['verdict_flips']) or 'none'))
        if result.get('input_error'):
            print(result['input_error'])
        print(f"RELEASE GATE: {'QUALIFIED' if result['qualified'] else 'NOT QUALIFIED'} "
              f"({len(runs)} runs; at least {MINIMUM_RUNS} required)")
        if args.json:
            args.json.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
        return 0 if result['qualified'] else 1
    except (OSError, ValueError, TypeError, KeyError) as error:
        print('RELEASE GATE: NOT QUALIFIED: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
