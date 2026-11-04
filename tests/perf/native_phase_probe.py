"""One correctness-qualified, instrumented document clone; no performance verdict."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time

MARKER = 'stallionfs-thread-cpu-v1'
SCOPE = 'instrumented run_tree main and worker spans'
UINT64_MAX = (1 << 64) - 1
PHASES = ('clone_leaf', 'directory_metadata')
STATUSES = ('available', 'clock_read_invalid', 'clock_range_invalid', 'nested_phase',
            'counter_overflow', 'worker_bound', 'join_failed', 'operation_failed')


class ProbeError(Exception):
    """Fixed public status code, never raw tool diagnostics."""


def require(condition, code):
    if not condition:
        raise ProbeError(code)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, 'counter_report_invalid')
        result[key] = value
    return result


def read_report(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 65536, 'counter_report_invalid')
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def validate_report(value):
    require(isinstance(value, dict) and set(value) == {'schema', 'marker', 'status', 'workers_requested',
            'workers_started', 'main_fallback', 'scope', 'counters', 'slots'}, 'counter_report_invalid')
    require(type(value['schema']) is int and value['schema'] == 1 and value['marker'] == MARKER and value['scope'] == SCOPE
            and value['status'] in STATUSES and type(value['workers_requested']) is int
            and value['workers_requested'] == 2 and type(value['workers_started']) is int
            and 0 <= value['workers_started'] <= 2 and type(value['main_fallback']) is bool
            and value['main_fallback'] == (value['workers_started'] == 0), 'counter_report_invalid')
    if value['status'] != 'available':
        require(value['counters'] is None and value['slots'] == [], 'counter_report_invalid')
        return None
    require(value['workers_started'] == 2 and not value['main_fallback'], 'counter_report_invalid')

    def integer(number):
        require(type(number) is int and 0 <= number <= UINT64_MAX, 'counter_report_invalid')
        return number

    def counters(row, slot=None):
        require(isinstance(row, dict) and set(row) == {'total_cpu_ns', *PHASES} | ({'slot'} if slot is not None else set()),
                'counter_report_invalid')
        if slot is not None:
            require(type(row['slot']) is int and row['slot'] == slot, 'counter_report_invalid')
        total = integer(row['total_cpu_ns'])
        used = 0
        for phase in PHASES:
            counter = row[phase]
            require(isinstance(counter, dict) and set(counter) == {'calls', 'failures', 'cpu_ns'}, 'counter_report_invalid')
            for number in counter.values():
                integer(number)
            require(counter['failures'] == 0, 'counter_report_invalid')
            if slot is None:
                require(counter['calls'] > 0, 'counter_report_invalid')
            used += counter['cpu_ns']
        require(used <= total, 'counter_report_invalid')
        return total

    slots = value['slots']
    require(isinstance(slots, list) and len(slots) == 3, 'counter_report_invalid')
    for index, row in enumerate(slots):
        counters(row, index)
    aggregate = value['counters']
    require(counters(aggregate) > 0 and aggregate['total_cpu_ns'] == sum(row['total_cpu_ns'] for row in slots),
            'counter_report_invalid')
    for phase in PHASES:
        for field in ('calls', 'failures', 'cpu_ns'):
            require(aggregate[phase][field] == sum(row[phase][field] for row in slots), 'counter_report_invalid')
    return {'scope': SCOPE, 'clock': 'CLOCK_THREAD_CPUTIME_ID', 'counters': aggregate, 'slots': slots,
            'limits': ['Includes counter overhead; no subtraction or speedup claim.',
                       'Excludes CLI startup, run_tree setup and worker exit announcement/teardown.',
                       'Function phases are subsets of the thread totals; other work is unclassified.']}


def publish(path, value):
    require(len(json.dumps(value).encode()) <= 65536, 'publication_limit')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.phase-status-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def clean_capture(receipt):
    return (receipt.get('completion_uncertain') is False and type(receipt.get('exit_code')) is int and receipt['exit_code'] == 0
            and type(receipt.get('pid')) is int and receipt['pid'] > 1
            and not any(receipt.get(key) for key in ('error', 'cleanup_error', 'output_limit_exceeded',
                                                    'timed_out', 'discarded_output_bytes')))


def probe(binary, wheel, scratch, output, revision):
    from stallionfs._benchmark_budget import command
    import stallionfs
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import fileops
    import native_correctness as correct
    import native_fixtures
    import native_suite
    result = {'schema': 1, 'scope': 'hosted diagnostic source build', 'status': 'incomplete',
              'target_completion': 'unknown', 'correctness': None, 'counter_status': 'unavailable',
              'clone_attempts': 0, 'cleanup': 'not_started', 'benchmark_verdict': 'not_applicable'}
    private = identity = None
    safe_to_clean = True
    os.environ['STALLIONFS_BENCHMARK_DEADLINE'] = str(time.monotonic() + 120)
    try:
        require(sys.platform == 'darwin' and re.fullmatch('[0-9a-f]{40}', revision) is not None, 'host_invalid')
        binary, wheel, scratch = binary.resolve(strict=True), wheel.resolve(strict=True), scratch.resolve(strict=True)
        require(binary.is_file() and os.access(binary, os.X_OK) and not output.exists(), 'input_invalid')
        checkout = Path(__file__).resolve().parents[2]
        require(not Path(stallionfs.__file__).resolve().is_relative_to(checkout), 'wheel_invalid')
        require(MARKER.encode() in binary.read_bytes(), 'profile_not_compiled')
        private = Path(tempfile.mkdtemp(prefix='native-phase-private-', dir=scratch))
        identity = private.stat()
        receipts = private / 'receipts'; receipts.mkdir(mode=0o700)
        os.environ['STALLIONFS_BENCHMARK_RECEIPTS'] = str(receipts)

        def run(argv, timeout=15):
            nonlocal safe_to_clean
            receipt = {}
            try:
                child = command(argv, timeout=timeout, umask=0o077, receipt=receipt, output_limit=1048576)
            except BaseException:
                safe_to_clean = False
                raise
            if not clean_capture(receipt):
                safe_to_clean = False
                raise ProbeError('target_completion_unknown')
            return child

        fileops.scratch_volume(json.loads(run([str(binary), '--json', 'volumes']).stdout), scratch)
        require(shutil.disk_usage(scratch).free >= fileops.HEADROOM, 'scratch_invalid')
        def sources():
            hashes = fileops.fingerprint_sources()
            hashes.update({path.name: fileops.digest(path) for path in Path(__file__).parent.glob('native_*.py')})
            return hashes
        result.update(revision=revision, source_sha256=sources(), cli_sha256=digest(binary), wheel_sha256=digest(wheel),
                      diagnostic_build_marker=MARKER)
        base = private / 'fixture'; base.mkdir(mode=0o700)
        fileops.no_mounts_below(binary, base)
        (base / 'outside-sentinel').write_bytes(b'keep outside linked trees\n')
        source = fileops.large_fixture(base, 'docs_5k_100mb', fileops.LARGE_PROFILES['docs_5k_100mb'])
        seed = {}; native_fixtures.enrich_metadata(source, receipt=seed)
        expected = correct.snapshot(source)
        require(native_fixtures.verify_metadata_coverage(expected, seed)['populated'] is True, 'metadata_incomplete')
        destination = base / 'destination'
        require(not os.path.lexists(destination), 'destination_exists')
        before = correct.snapshot(source)
        require(native_suite.preserved(correct.compare(expected, before)), 'source_precheck_failed')
        native_suite.cache_prepare('warm', 15)
        report = private / 'thread-cpu.json'
        os.environ['STALLIONFS_DIAGNOSTIC_THREAD_CPU_REPORT'] = str(report)
        argv = native_suite.arguments('stallionfs', 'clone', binary, source, destination, jobs=2)
        result['clone_attempts'] = 1
        safe_to_clean = False
        run(argv, timeout=60)
        result['target_completion'] = 'complete'
        after = correct.snapshot(destination, observe_sharing=True)
        destination_ok = native_suite.preserved(correct.verify_clone(before, after))
        source_after = correct.snapshot(source, observe_sharing=True)
        unchanged = correct.verify_source(expected, source_after)['unchanged'] is True
        sharing = correct.clone_sharing(source_after, after)['full_data_stream_sharing'] is True
        sentinel = (base / 'outside-sentinel').read_bytes() == b'keep outside linked trees\n'
        result['correctness'] = {'destination_preserved': destination_ok, 'source_unchanged': unchanged,
                                'full_data_stream_sharing': sharing, 'outside_sentinel_unchanged': sentinel,
                                'passed': destination_ok and unchanged and sharing and sentinel}
        require(result['correctness']['passed'], 'correctness_failed')
        require(sources() == result['source_sha256'] and digest(binary) == result['cli_sha256']
                and digest(wheel) == result['wheel_sha256'], 'source_changed')
        safe_to_clean = True
        native = read_report(report)
        composition = validate_report(native)
        result['counter_status'] = native['status']
        if composition is not None:
            result['cpu_composition'] = composition
            result['status'] = 'complete'
    except BaseException as error:
        result['error'] = str(error) if isinstance(error, ProbeError) else 'diagnostic_incomplete'
    finally:
        os.environ.pop('STALLIONFS_DIAGNOSTIC_THREAD_CPU_REPORT', None)
        if private is not None:
            result['cleanup'] = 'retained_ephemeral'
            if safe_to_clean:
                try:
                    current = private.lstat()
                    require(stat.S_ISDIR(current.st_mode) and current.st_uid == os.getuid()
                            and stat.S_IMODE(current.st_mode) == 0o700
                            and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino), 'cleanup_failed')
                    fileops.no_mounts_below(binary, private)
                    shutil.rmtree(private)
                    require(not private.exists(), 'cleanup_failed')
                    result['cleanup'] = 'complete'
                except BaseException:
                    result['status'] = 'incomplete'; result['error'] = 'cleanup_failed'
        publish(output, result)
    return 0 if result['status'] == 'complete' and result['cleanup'] == 'complete' else 1


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'wheel', 'scratch', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--revision', required=True)
    args = parser.parse_args()
    try:
        return probe(args.binary, args.wheel, args.scratch, args.output, args.revision)
    except BaseException:
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
