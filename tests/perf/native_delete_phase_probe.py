"""One hosted fixed-cache delete CPU diagnostic; no performance verdict."""
import argparse
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_phase_probe import ProbeError, STATUSES, UINT64_MAX, clean_capture, digest, publish, read_report, require

MARKER = 'stallionfs-delete-thread-cpu-v1'
PHASES = ('entry_unlinkat', 'directory_unlinkat')
DEADLINE = 'STALLIONFS_BENCHMARK_DEADLINE'
RESERVE = 30
PIN_PATHS = ('setup.py', 'pyproject.toml', 'stallionfs/_main.c', 'stallionfs/_tree.c',
             'stallionfs/_tree.h', 'stallionfs/_walk.c', 'stallionfs/_benchmark_budget.py',
             'tests/perf/fileops.py', 'tests/perf/native_metrics.py', 'tests/perf/native_fixtures.py',
             'tests/perf/native_correctness.py', 'tests/perf/native_suite.py', 'tests/perf/native_phase_probe.py',
             'tests/perf/native_delete_phase_probe.py', 'tests/test_native_delete_phase_probe.py',
             '.github/workflows/checks.yml')


class Deadline:
    def __init__(self, value):
        require(isinstance(value, str), 'deadline_invalid')
        self.inherited = value
        try:
            self.end = float(value)
        except (TypeError, ValueError):
            raise ProbeError('deadline_invalid') from None
        require(math.isfinite(self.end) and 0 < self.end - time.monotonic() <= 900, 'deadline_invalid')
        self.expired = False
        self.previous = None

    def check(self):
        require(os.environ.get(DEADLINE) == self.inherited, 'deadline_changed')
        remaining = self.end - RESERVE - time.monotonic()
        if remaining <= 0:
            self.expired = True
            raise TimeoutError('usable deadline exhausted')
        return remaining

    def timeout(self, requested=600):
        require(math.isfinite(requested) and requested > 0, 'timeout_invalid')
        return min(600, requested, self.check())

    def alarm(self, *_):
        self.expired = True
        raise TimeoutError('usable deadline exhausted')

    def start(self):
        remaining = self.check()
        require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'deadline_handler_busy')
        self.previous = signal.signal(signal.SIGALRM, self.alarm)
        signal.setitimer(signal.ITIMER_REAL, remaining)

    def close(self):
        if self.previous is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self.previous)


def pins(checkout):
    return {name: digest(checkout / name) for name in PIN_PATHS}


def expected_calls(snapshot):
    require(snapshot.get('entries', {}).get('', {}).get('kind') == 'directory', 'fixture_invalid')
    counts = dict.fromkeys(PHASES, 0)
    for entry in snapshot['entries'].values():
        kind = entry.get('kind')
        require(kind in ('directory', 'file', 'symlink'), 'unsupported_fixture_type')
        counts['directory_unlinkat' if kind == 'directory' else 'entry_unlinkat'] += 1
    return counts


def validate_report(value, expected):
    require(isinstance(value, dict) and set(value) == {'schema', 'marker', 'status', 'workers_requested',
            'workers_started', 'main_fallback', 'scope', 'counters', 'slots'}, 'counter_report_invalid')
    require(type(value['schema']) is int and value['schema'] == 1 and value['marker'] == MARKER
            and value['scope'] == 'instrumented run_tree main and worker spans'
            and value['status'] in STATUSES and type(value['workers_requested']) is int
            and value['workers_requested'] == 4 and type(value['workers_started']) is int
            and 0 <= value['workers_started'] <= 4 and type(value['main_fallback']) is bool
            and value['main_fallback'] == (value['workers_started'] == 0), 'counter_report_invalid')
    execution = {key: value[key] for key in ('workers_requested', 'workers_started', 'main_fallback')}
    if value['status'] != 'available':
        require(value['counters'] is None and value['slots'] == [], 'counter_report_invalid')
        return execution, None

    def row(item, slot=None):
        require(isinstance(item, dict) and set(item) == {'total_cpu_ns', *PHASES} | ({'slot'} if slot is not None else set()),
                'counter_report_invalid')
        if slot is not None:
            require(type(item['slot']) is int and item['slot'] == slot, 'counter_report_invalid')
        require(type(item['total_cpu_ns']) is int and 0 <= item['total_cpu_ns'] <= UINT64_MAX, 'counter_report_invalid')
        for phase in PHASES:
            counter = item[phase]
            require(isinstance(counter, dict) and set(counter) == {'calls', 'failures', 'cpu_ns'}, 'counter_report_invalid')
            require(all(type(number) is int and 0 <= number <= UINT64_MAX for number in counter.values()), 'counter_report_invalid')
            require(counter['failures'] == 0, 'counter_report_invalid')
        require(sum(item[phase]['cpu_ns'] for phase in PHASES) <= item['total_cpu_ns'], 'counter_report_invalid')

    slots, total = value['slots'], value['counters']
    require(isinstance(slots, list) and len(slots) == value['workers_started'] + 1, 'counter_report_invalid')
    for index, item in enumerate(slots): row(item, index)
    row(total)
    require(total['total_cpu_ns'] > 0 and total['total_cpu_ns'] == sum(item['total_cpu_ns'] for item in slots), 'counter_report_invalid')
    for phase in PHASES:
        require(total[phase]['calls'] == expected[phase], 'counter_report_invalid')
        for field in ('calls', 'failures', 'cpu_ns'):
            require(total[phase][field] == sum(item[phase][field] for item in slots), 'counter_report_invalid')
    return execution, {'scope': value['scope'], 'clock': 'CLOCK_THREAD_CPUTIME_ID', 'counters': total, 'slots': slots,
                       'limits': ['Instrumented CPU composition only; includes clock and bookkeeping overhead.',
                                  'Unclassified CPU does not separate traversal, allocation, locks or scheduling.',
                                  'No kernel-only, wall-time, historical-excess or performance-gain claim.']}


def probe(binary, wheel, scratch, output, revision):
    result = {'schema': 1, 'scope': 'hosted fixed-cache delete CPU only', 'status': 'incomplete',
              'stage': 'host_checks', 'target_completion': 'not_started', 'delete_attempts': 0,
              'counter_status': 'unavailable', 'cleanup': 'not_started', 'correctness': None,
              'selection': {'fixture': 'cache_200k_10gb', 'operation': 'delete', 'cache': 'warm', 'workers': 'default four'},
              'budget': {'aggregate_seconds': 900, 'outer_reserve_seconds': 30, 'inner_command_cap_seconds': 600},
              'benchmark_verdict': 'not_applicable'}
    private = identity = budget = old_setup_command = None
    safe_to_clean = uncertain = False
    try:
        require(sys.platform == 'darwin' and os.environ.get('GITHUB_ACTIONS') == 'true'
                and os.environ.get('STALLIONFS_DELETE_CPU_HOSTED') == '1'
                and re.fullmatch('[0-9a-f]{40}', revision) is not None, 'host_invalid')
        budget = Deadline(os.environ.get(DEADLINE)); budget.start()
        from stallionfs._benchmark_budget import command
        import stallionfs
        import fileops
        import native_correctness as correct
        import native_fixtures
        import native_suite

        def guard():
            budget.check()
            require(not uncertain, 'target_completion_unknown')

        old_setup_command = fileops.command
        def setup_command(argv, *, check=True, timeout=120, environment=None):
            nonlocal safe_to_clean, uncertain
            guard(); allowed = budget.timeout(timeout); prior = safe_to_clean; safe_to_clean = False
            try:
                child = old_setup_command(argv, check=check, timeout=allowed, environment=environment)
            except BaseException:
                uncertain = True
                raise
            safe_to_clean = prior
            return child
        fileops.command = setup_command

        def run(argv, *, deleting=False):
            nonlocal safe_to_clean, uncertain
            guard(); allowed = budget.timeout(); prior = safe_to_clean; safe_to_clean = False
            receipt = {}
            try:
                child = command(argv, timeout=allowed, umask=0o077, receipt=receipt, output_limit=65536)
            except BaseException:
                uncertain = True
                if deleting: result['target_completion'] = 'unknown'
                raise ProbeError('target_completion_unknown') from None
            if not clean_capture(receipt):
                uncertain = True
                if deleting: result['target_completion'] = 'unknown'
                raise ProbeError('target_completion_unknown')
            if deleting: result['target_completion'] = 'complete'
            safe_to_clean = prior
            guard()
            return child

        result['stage'] = 'inputs'; guard()
        binary, wheel, scratch = [path.resolve(strict=True) for path in (binary, wheel, scratch)]
        runner = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        checkout = Path(__file__).resolve().parents[2]
        require(scratch != runner and scratch.is_relative_to(runner) and binary.is_file() and os.access(binary, os.X_OK)
                and wheel.is_file() and not os.path.lexists(output), 'input_invalid')
        require(not Path(stallionfs.__file__).resolve().is_relative_to(checkout), 'wheel_invalid')
        require(MARKER.encode() in binary.read_bytes(), 'profile_not_compiled')
        pinned = pins(checkout)
        binary_pins = {'cli_sha256': digest(binary), 'wheel_sha256': digest(wheel)}
        result.update(revision=revision, source_sha256=pinned, diagnostic_build_marker=MARKER, **binary_pins)
        def check_pins():
            guard()
            require(pins(checkout) == pinned and digest(binary) == binary_pins['cli_sha256']
                    and digest(wheel) == binary_pins['wheel_sha256'], 'source_changed')
            guard()

        private = Path(tempfile.mkdtemp(prefix='delete-cpu-private-', dir=scratch)); identity = private.stat()
        receipts = private / 'receipts'; receipts.mkdir(mode=0o700)
        os.environ['STALLIONFS_BENCHMARK_RECEIPTS'] = str(receipts)
        result['stage'] = 'volume'; inventory = json.loads(run([str(binary), '--json', 'volumes']).stdout)
        volume = fileops.scratch_volume(inventory, scratch)
        require(volume.get('ignore_ownership') is False, 'scratch_invalid')
        result['volume'] = {'filesystem': 'apfs', 'readonly': False, 'ignore_ownership': False}
        fileops.no_mounts_below(binary, private); guard()
        base = private / 'fixture'; base.mkdir(mode=0o700)
        (base / 'outside-sentinel').write_bytes(b'keep outside deleted tree\n')
        sentinel = base / 'outside-sentinel'; sentinel_before = correct.snapshot(sentinel)
        result['stage'] = 'fixture'; spec = fileops.LARGE_PROFILES['cache_200k_10gb']
        reserve = 2 * spec['bytes'] + spec['files'] * 8192 + fileops.HEADROOM
        require(shutil.disk_usage(scratch).free >= reserve, 'scratch_capacity_unavailable')
        guard(); source = fileops.large_fixture(base, 'cache_200k_10gb', spec); guard()
        seed = {}; native_fixtures.enrich_metadata(source, receipt=seed); guard()
        expected = correct.snapshot(source); guard()
        coverage = native_fixtures.verify_metadata_coverage(expected, seed)
        require(coverage['populated'] is True, 'metadata_incomplete')
        require(coverage['regular_files'] == 200002 and coverage['directories'] == 204
                and coverage['logical_bytes'] == 10016777216, 'fixed_fixture_changed')
        result['fixture'] = {'name': 'cache_200k_10gb', 'coverage': coverage}
        target = base / 'target'
        result['stage'] = 'operand'; require(not os.path.lexists(target), 'target_exists')
        run(['/usr/bin/ditto', '--rsrc', '--extattr', '--acl', str(source), str(target)])
        native_suite.restore_setup_symlink_times(target, expected); guard()
        before = correct.snapshot(target); guard()
        require(native_suite.preserved(correct.verify_clone(expected, before)), 'operand_invalid')
        require(correct.verify_source(expected, correct.snapshot(source))['unchanged'] is True, 'source_changed'); guard()
        counts = expected_calls(before)
        require(counts == {'entry_unlinkat': 200002, 'directory_unlinkat': 204}, 'fixed_fixture_changed')
        result['expected_calls'] = counts
        result['stage'] = 'warm'; native_suite.cache_prepare('warm', budget.timeout()); guard(); check_pins()
        report = private / 'thread-cpu.json'
        os.environ['STALLIONFS_DIAGNOSTIC_THREAD_CPU_REPORT'] = str(report)
        argv = native_suite.arguments('stallionfs', 'delete', binary, target, base / 'unused', jobs=None)
        result['stage'] = 'delete'; guard()
        result['delete_attempts'] = 1
        run(argv, deleting=True)
        result['stage'] = 'validation'; guard()
        absent = not os.path.lexists(target)
        unchanged = correct.verify_source(expected, correct.snapshot(source))['unchanged'] is True; guard()
        sentinel_ok = correct.verify_source(sentinel_before, correct.snapshot(sentinel))['unchanged'] is True; guard()
        result['correctness'] = {'target_absent': absent, 'source_unchanged': unchanged,
                                 'outside_sentinel_unchanged': sentinel_ok, 'passed': absent and unchanged and sentinel_ok}
        require(result['correctness']['passed'], 'correctness_failed'); check_pins()
        safe_to_clean = True
        native = read_report(report)
        result['execution'], composition = validate_report(native, counts)
        result['counter_status'] = native['status']
        if composition is not None:
            result['cpu_composition'] = composition
            result['status'] = 'complete'
    except BaseException as error:
        if isinstance(error, TimeoutError):
            safe_to_clean = False
            if budget is not None: budget.expired = True
        result['error'] = str(error) if isinstance(error, ProbeError) else ('deadline_exhausted' if isinstance(error, TimeoutError) else 'diagnostic_incomplete')
    finally:
        os.environ.pop('STALLIONFS_DIAGNOSTIC_THREAD_CPU_REPORT', None)
        if private is not None:
            result['cleanup'] = 'retained_ephemeral'
            if safe_to_clean and not uncertain and budget is not None and not budget.expired:
                try:
                    budget.check()
                    current = private.lstat()
                    require(stat.S_ISDIR(current.st_mode) and current.st_uid == os.getuid() and stat.S_IMODE(current.st_mode) == 0o700
                            and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino), 'cleanup_failed')
                    fileops.no_mounts_below(binary, private); budget.check()
                    shutil.rmtree(private); budget.check()
                    require(not private.exists(), 'cleanup_failed')
                    result['cleanup'] = 'complete'
                except BaseException:
                    result['status'] = 'incomplete'; result['error'] = 'cleanup_incomplete'
        if old_setup_command is not None: fileops.command = old_setup_command
        if budget is not None:
            if budget.expired: result['status'] = 'incomplete'
            budget.close()
        publish(output, result)
    return 0 if result['status'] == 'complete' and result['cleanup'] == 'complete' else 1


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'wheel', 'scratch', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--revision', required=True)
    args = parser.parse_args()
    return probe(args.binary, args.wheel, args.scratch, args.output, args.revision)


if __name__ == '__main__': raise SystemExit(main())
