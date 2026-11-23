"""Run the frozen warm CLI scan collector and project its public evidence."""
import base64
from collections import defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import sys
import time


FIXTURES = {'empty': 'empty', 'nested_1000': 'nested'}
CASES = ['cli/scan/' + name for name in FIXTURES]
PAIRS = {'timing': range(32), 'resources': range(1, 11)}
TIMING_MEASUREMENTS = ('wall_s', 'user_s', 'system_s', 'cpu_s')
MEASUREMENTS = (*TIMING_MEASUREMENTS, 'time_wall_s', 'rss_bytes', 'io_input_blocks', 'io_output_blocks')
FIXTURE_COUNTS = {
    'empty': dict(files=0, directories=0, symlinks=0, other=0, logical_bytes=0, skipped_mounts=0),
    'nested_1000': dict(files=1003, directories=11, symlinks=3, other=1,
                        logical_bytes=512000 + 5 + (2 << 20), skipped_mounts=0),
}
VERDICTS = ('candidate_faster', 'candidate_slower', 'candidate_lower', 'candidate_higher',
            'inconclusive', 'below_resolution', 'insufficient_samples', 'incomplete_pairs')
TOOLS = ('/usr/bin/find', '/usr/bin/stat', '/usr/bin/time')
SCOPE = 'Installed source wheel on one GitHub-hosted macOS VM'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write(path, value):
    # Serialize before touching an uploadable file.
    data = json.dumps(value, allow_nan=False, separators=(',', ':')) + '\n'
    with path.open('x') as stream:
        stream.write(data)


def numbers(record, keys):
    return {name: record[name] for name in keys
            if type(record.get(name)) in (int, float) and math.isfinite(record[name])}


def group(row):
    key = tuple(row[name] for name in ('fixture', 'output', 'phase'))
    fixture, form, phase = key
    require(fixture in FIXTURES and form in ('plain', 'json') and phase in PAIRS
            and row['case_id'] == 'cli/scan/' + fixture and row['operation'] == 'scan'
            and row['reference'] == 'find-stat' and row['cache'] == 'warm'
            and row['fixture_policy'] == 'cli-scan-original-counts-v1', 'Unexpected scan group')
    return key


def sample(row, cli, binary, base, device, counts):
    fixture, form, phase = group(row)
    method, pair = row['method'], row['pair_id']
    require(method in ('native', 'candidate') and type(pair) is int and pair in PAIRS[phase]
            and row['warmup'] is (pair == 0), 'Unexpected scan sample')
    source = base / FIXTURES[fixture]
    if method == 'native':
        argv = cli.native_suite.arguments('find-stat', 'scan', binary, source, None)
    else:
        argv = [str(binary), *(['--json'] if form == 'json' else []), 'scan', str(source)]
    wrapper = ['/usr/bin/time', '-lp'] if phase == 'resources' else []
    require(row['argv'] == argv and ('executed_argv' not in row or row['executed_argv'] == wrapper + argv),
            'Scan command differs from the fixed recipe')

    aliases = {str(binary): '$CANDIDATE', str(source): '$FIXTURE/' + source.name}
    result = dict(case_id='cli/scan/' + fixture, fixture=fixture, output=form, phase=phase,
                  method=method, pair_id=pair, warmup=pair == 0,
                  argv=[aliases.get(arg, arg) for arg in argv],
                  precision_floor=numbers(row.get('precision_floor', {}), MEASUREMENTS))
    result.update(numbers(row, (*MEASUREMENTS, 'exit_code', 'timeout_s')))
    for flag in ('ok', 'validated', 'source_unchanged', 'timed_out', 'completion_uncertain'):
        result[flag] = row.get(flag) if type(row.get(flag)) is bool else None
    result['correctness_passed'] = row.get('correctness', {}).get('passed') is True
    result['parse_errors'] = [name for name in MEASUREMENTS if name in row.get('parse_errors', ())]
    sample_id = row.get('sample_id')
    if sample_id is not None:
        require(type(sample_id) is str and re.fullmatch('[0-9a-f]{32}', sample_id), 'Invalid sample ID')
        result['sample_id'] = sample_id
    started = row.get('started_utc', '')
    if re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{6})?\+00:00', started):
        result['started_utc'] = started
    if 'stderr_b64' in row:
        result['stderr_sha256'] = hashlib.sha256(base64.b64decode(row['stderr_b64'], validate=True)).hexdigest()
    if 'stdout_b64' in row:
        raw = base64.b64decode(row['stdout_b64'], validate=True)
        result['stdout_sha256'] = hashlib.sha256(raw).hexdigest()
        if result['correctness_passed']:
            require(len(raw) <= 65536, 'Scan output exceeds transfer limit')
            # Recheck the synthetic output before allowing its bytes across the boundary.
            if method == 'native' or form == 'json':
                observed = cli.native_suite.parse_scan_output(
                    'find-stat' if method == 'native' else 'stallionfs', raw, device)
                require(observed == counts, 'Projected scan counters differ')
            else:
                require(raw == cli.scan_text(counts), 'Projected scan text differs')
            result['stdout_b64'] = base64.b64encode(raw).decode('ascii')
    return result


def comparison(row):
    fixture, form, phase = group(row)
    metrics = {}
    expected = ('wall_s', 'cpu_s') if phase == 'timing' else ('rss_bytes',)
    require(set(row['metrics']) == set(expected), 'Unexpected comparison metrics')
    for name in expected:
        metric = row['metrics'][name]
        decision = metric['decision']
        require(decision in VERDICTS, 'Unexpected scan verdict')
        metrics[name] = {'decision': decision,
                         **numbers(metric, ('complete_pairs', 'paired_mean_savings',
                            'paired_median_savings', 'paired_sample_variance', 'required_gap',
                            'native_stddev', 'candidate_stddev', 'paired_stddev',
                            'paired_standard_error', 'variance_threshold')),
                         'excluded_pair_ids': [item['pair_id'] for item in metric['excluded_pairs']
                                               if type(item['pair_id']) is int and item['pair_id'] in PAIRS[phase]]}
        for method in ('native', 'candidate'):
            summary = metric[method]
            metrics[name][method] = None if summary is None else numbers(
                summary, ('n', 'median', 'p95', 'mean', 'sample_variance', 'minimum', 'maximum'))
    return dict(fixture=fixture, output=form, phase=phase, metrics=metrics)


def valid_measurements(row):
    if row['phase'] == 'resources':
        return all(row.get(name, -1) >= 0 for name in MEASUREMENTS) and row['rss_bytes'] > 0
    return all(row.get(name, -1) >= 0 for name in TIMING_MEASUREMENTS)


def project(cli, output, binary, scratch, bindings):
    journal = cli.native_report.ReportJournal.open_existing(
        output, max_manifest_bytes=256 * 1024, max_journal_bytes=64 * 1024**2,
        max_event_bytes=256 * 1024, max_events=1500)
    try:
        state = journal.state
        pins = state['pins']
        volume = state['volume']
        require(state['case_ids'] == CASES and state['schema'] == 1
                and state['cache'] == ['warm'] and state['timing_pairs'] == 31
                and state['resource_pairs'] == 10 and state['timing_warmup_id'] == 0
                and volume['filesystem'] == 'apfs' and volume['readonly'] is False
                and pins['source']['tests/perf/cli.py'] == bindings['collector_sha256']
                and pins['python'] == bindings['python_sha256']
                and pins['runtime']['bin/stallionfs'] == bindings['launcher_sha256']
                and pins['runtime']['bin/stallionfs-python'] == bindings['helper_sha256']
                and all(pins['tools'][name] == bindings['tool_sha256'][name] for name in TOOLS),
                'Scan configuration or provenance differs')
        base = Path(state['fixture_root']) if 'fixture_root' in state else None
        fixtures = {}
        for name in FIXTURES.keys() & state.get('fixtures', {}).keys():
            fixture = state['fixtures'][name]
            counts, digest = fixture['counts'], fixture['manifest_sha256']
            require(counts == FIXTURE_COUNTS[name]
                    and all(type(value) is int for value in counts.values())
                    and re.fullmatch('[0-9a-f]{64}', digest), 'Invalid synthetic fixture metadata')
            fixtures[name] = dict(counts=counts, manifest_sha256=digest)
        rows = []
        paired_rows = defaultdict(list)
        device = scratch.stat().st_dev
        for row in journal.iter_latest('rows'):
            require(base is not None and base.parent == scratch
                    and base.name.startswith('stallionfs-cli-scan-'), 'Unexpected fixture root')
            rows.append(sample(row, cli, binary, base, device, fixtures[row['fixture']]['counts']))
            paired_rows[group(row)].append(row)
        comparisons = []
        for row in journal.iter_latest('comparisons'):
            key = group(row)
            expected = cli.catalog_comparison(paired_rows[key], row['phase'], 10, row['fixture_policy'])
            require(row['metrics'] == expected, 'Scan comparison differs from its committed samples')
            comparisons.append(comparison(row))
        row_keys = {(r['fixture'], r['output'], r['phase'], r['method'], r['pair_id']) for r in rows}
        sample_ids = {r['sample_id'] for r in rows if 'sample_id' in r}
        command_uncertain = (state.get('command_receipt', {}).get('completion_uncertain') is True
                             or any(r['completion_uncertain'] is True for r in rows))
        closed = (state['status'] == 'complete' and state['passed'] is True and not command_uncertain
                  and state['cleanup_passed'] is True and state['source_checks_passed'] is True
                  and fixtures.keys() == FIXTURES.keys()
                  and len(rows) == len(row_keys) == len(sample_ids) == 336
                  and len({(c['fixture'], c['output'], c['phase']) for c in comparisons}) == len(comparisons) == 8
                  and all(r['ok'] is True and r['validated'] is True and r['correctness_passed']
                          and r['source_unchanged'] is True and r['completion_uncertain'] is False
                          and r['timed_out'] is False and r.get('exit_code') == 0 and not r['parse_errors']
                          and 'stdout_b64' in r and valid_measurements(r) for r in rows))
        return dict(report_complete=closed, cleanup_passed=state['cleanup_passed'] is True,
                    command_completion_uncertain=command_uncertain,
                    source_checks_passed=state['source_checks_passed'] is True, fixtures=fixtures,
                    journal=journal.provenance, rows=rows, comparisons=comparisons)
    finally:
        journal.close()


def collect(cli, command, checkout, binary, root, bindings):
    root.mkdir(mode=0o700)
    scratch, temporary = root / 'scratch', root / 'tmp'
    for path in (scratch, temporary):
        path.mkdir(mode=0o700)
    output = root / 'scan.json'
    env = dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL='C', HOME=str(root),
               TMPDIR=str(temporary), STALLIONFS_HOME=str(root / 'unused-store'),
               STALLIONFS_BENCHMARK_DEADLINE=str(time.monotonic() + 600))
    # The checked-out script imports its sibling collectors. Keep its script
    # directory on sys.path while ignoring Python environment and user site.
    argv = [sys.executable, '-E', '-s', '-B', str(checkout / 'tests/perf/cli.py'),
            '--native-scan', '--cache', 'warm', '--samples', '10', '--candidate', str(binary),
            '--scratch', str(scratch), '--output', str(output)]
    receipt = {}
    status = {'collector_status': 'interrupted_or_timed_out'}
    try:
        child = command(argv, cwd=root, environment=env, timeout=630, umask=0o077,
                        receipt=receipt, output_limit=65536)
        status.update(collector_status='exited', exit_code=child.returncode)
    except Exception:
        if receipt.get('output_limit_exceeded') is True:
            status['collector_status'] = 'output_limit'
    status['collector_completion_uncertain'] = (receipt.get('completion_uncertain') is not False
                                                  or status.get('exit_code', 0) < 0)
    try:
        status.update(project(cli, output, binary, scratch, bindings), evidence_status='projected')
    except FileNotFoundError:
        status['evidence_status'] = 'no_checkpoint'
    except (OSError, ValueError, RuntimeError, TypeError, KeyError):
        status['evidence_status'] = 'checkpoint_rejected'
    status['complete'] = (status.get('exit_code') == 0 and not status['collector_completion_uncertain']
                          and status.get('report_complete') is True)
    return status


def main():
    checkout = Path(__file__).resolve().parents[1]
    temporary = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    revision = os.environ['GITHUB_SHA']
    require(sys.platform == 'darwin' and platform.machine() == 'arm64'
            and re.fullmatch('[0-9a-f]{40}', revision), 'Unexpected hosted environment')
    sys.path.insert(0, str(checkout / 'tools'))
    from ci_build import initialize_installed
    from stallionfs._benchmark_budget import command

    wheel = temporary / 'qualified-wheel'
    initialize_installed(checkout, wheel)
    receipt = json.loads((wheel / 'build-result.json').read_bytes())
    binary = Path(sys.executable).with_name('stallionfs')
    sys.path.insert(0, str(checkout / 'tests/perf'))
    import cli

    def runner_field(name, pattern):
        value = os.environ.get(name, '')
        return value if re.fullmatch(pattern, value) else None

    bindings = dict(collector_sha256=cli.digest(checkout / 'tests/perf/cli.py'),
                    python_sha256=cli.digest(Path(sys.executable).resolve()),
                    launcher_sha256=cli.digest(binary),
                    helper_sha256=cli.digest(binary.with_name('stallionfs-python')),
                    tool_sha256={name: cli.digest(Path(name)) for name in TOOLS})
    evidence = temporary / 'hosted-native-scan-evidence'
    evidence.mkdir(mode=0o700)
    write(evidence / 'provenance.json', dict(
        schema=1, scope=SCOPE, release_qualification=False, revision=revision,
        runner_label='macos-15', arch='arm64',
        os_version=platform.mac_ver()[0], image_os=runner_field('ImageOS', r'macos[0-9]{2}'),
        image_version=runner_field('ImageVersion', r'[0-9.]{1,32}'), python=platform.python_version(),
        run_id=runner_field('GITHUB_RUN_ID', r'[0-9]{1,20}'),
        run_attempt=runner_field('GITHUB_RUN_ATTEMPT', r'[0-9]{1,6}'),
        wheel_sha256=receipt['wheel_sha256'], build_source_pins_sha256=receipt['source_pins_sha256'],
        build_input_sha256=receipt['descriptor_sha256'], command=['--native-scan', '--cache', 'warm', '--samples', '10'],
        timing_pairs=31, timing_warmup_id=0, resource_pairs=10,
        resources_wrapper=['/usr/bin/time', '-lp'], io_scope='OS block operations',
        timing_cpu_scope='Waited-for child CPU delta', rss_scope='Reported individual-process peak',
        cache='Warm synthetic fixture with validated reads before measurement',
        **bindings))
    complete = True
    seen_samples = set()
    for cycle in (1, 2, 3):
        status = (collect(cli, command, checkout, binary, temporary / f'hosted-native-scan-{cycle}', bindings)
                  if complete else {'complete': False, 'collector_status': 'skipped_after_incomplete_cycle'})
        if status['complete']:
            sample_ids = {row['sample_id'] for row in status['rows']}
            if seen_samples & sample_ids:
                status.update(complete=False, cross_cycle_sample_reuse=True)
            seen_samples.update(sample_ids)
        write(evidence / f'cycle-{cycle}.json', {'cycle': cycle, **status})
        print(f"Cycle {cycle}: {status['collector_status']}; "
              f"evidence {status.get('evidence_status', 'unavailable')}; "
              f"{len(status.get('rows', []))} sample rows.", flush=True)
        complete = status['complete']
    return 0 if complete else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(f'Hosted scan setup or evidence write failed ({type(error).__name__}).', file=sys.stderr)
        sys.exit(1)
