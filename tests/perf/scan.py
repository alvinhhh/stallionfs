"""Compare the shipped bulk scanner with an equivalent native POSIX traversal."""
import argparse
from datetime import datetime, timezone
import gzip
import json
import os
from pathlib import Path
import platform
import random
import stat
import statistics
import sys
import tempfile
import time

import fileops as f
import native_correctness
import native_fixtures
import native_metrics
from native_fixtures import scan_fixture as fixture
from stallionfs import __version__, _scan


METHODS = {'posix': 1, 'bulk_serial': 1, 'bulk': 4}
CHILD = '''
import hashlib, json, pathlib, sys
from stallionfs import _scan
native = hashlib.sha256(pathlib.Path(_scan.__file__).read_bytes()).hexdigest()
assert native == sys.argv[4], 'Child native extension differs'
method = sys.argv[2]
counts = _scan.scan(sys.argv[1], bulk=method != 'posix', jobs=4 if method == 'bulk' else 1)
assert counts == json.loads(sys.argv[3]), 'Child scan counts differ'
print(json.dumps({'counts': counts, 'native_binary_sha256': native}))
'''


def memory_sample(path, method, expected, native_hash, metrics, record=None):
    row, completed = f.measure_memory([sys.executable, '-I', '-B', '-c', CHILD, path, method,
                                       json.dumps(expected), native_hash], metrics)
    if record is not None:
        record.update(row)
    if row.get('completion_uncertain') or row['exit_code'] != 0:
        raise f.ChildCompletionUnknown('Memory child completion uncertain; preserve fixture')
    f.require(completed is not None and not completed.stderr, 'Memory child output unavailable or invalid')
    observed = json.loads(completed.stdout)
    f.require(observed == {'counts': expected, 'native_binary_sha256': native_hash},
              'Memory child counts or native extension differ')
    return {**row, **observed}


def comparisons(rows, phase):
    methods = {method: [row for row in rows if row['method'] == method and not row['warmup']]
               for method in METHODS}
    metrics = ('wall_s', 'cpu_s') if phase == 'timing' else ('rss_bytes',)
    return {method: {metric: native_metrics.compare_paired(methods['posix'], values, metric)
                     for metric in metrics}
            for method, values in methods.items() if method != 'posix'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--files', type=int, default=20000)
    parser.add_argument('--samples', type=int, default=11)
    parser.add_argument('--memory', action='store_true', help='Separate Python-process peak-memory samples per method/layout; uses --samples')
    args = parser.parse_args()
    if not 1 <= args.files <= 1000000 or not 10 <= args.samples <= 100:
        parser.error('Use 1–1,000,000 files and 10–100 samples')
    rng = random.Random(20261006)
    package = Path(__file__).resolve().parents[2] / 'stallionfs'
    sources = [package / name for name in ('__init__.py', '_scan.c', '_walk.c', '_tree.h')]
    sources += [Path(__file__), Path(f.__file__), Path(native_fixtures.__file__),
                Path(native_metrics.__file__), Path(native_correctness.__file__)]
    hashes = {path.name: f.digest(path) for path in sources}
    native_binary = Path(_scan.__file__)
    f.require(native_binary.resolve().parent != package.resolve(),
              'Use an installed runtime outside the source checkout')
    scratch = args.scratch.resolve(strict=True)
    f.require(scratch.is_dir(), '--scratch must be an existing directory')
    volume = f.scratch_volume(_scan.mounts(), scratch)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output = args.output.absolute()
    partial = output.with_name(output.name + '.partial')
    f.require(not os.path.lexists(output) and not os.path.lexists(partial), 'Preserve existing output or checkpoint')
    result = {'version': __version__, 'timestamp': datetime.now(timezone.utc).isoformat(), 'system': platform.platform(),
              'cpu': f.command(['/usr/sbin/sysctl', '-n', 'machdep.cpu.brand_string']).stdout.decode().strip(),
              'memory_bytes': int(f.command(['/usr/sbin/sysctl', '-n', 'hw.memsize']).stdout),
              'implementation_sha256': hashes,
              'native_binary_sha256': f.digest(native_binary),
              'native_module': native_binary.name,
              'native_origin': 'Installed runtime outside source checkout; memory children verify the same binary hash',
              'python_binary_sha256': f.digest(Path(sys.executable)),
              'python': platform.python_version(), 'samples': args.samples, 'warmup_rounds': 2,
              'timing': 'Python API wall and process CPU time; native implementations; warm OS cache; no process startup',
              'source_validation': 'Populated ACL, xattr/resource fork, sparse and hardlink coverage; full source snapshots before and after each attempt, outside API timing and child memory. Read-induced access times are excluded. Prechecks read all file contents; cache residency is not guaranteed.',
              'jobs': METHODS, 'status': 'running', 'passed': False,
              'layouts': 'Flat and 100-files-per-folder nested layouts; deep40 distributes files evenly along a 40-directory single-child chain, with special entries and empty directory at its deepest leaf',
              'volume': {key: volume.get(key) for key in ('filesystem', 'readonly', 'ignore_ownership')},
              'memory_samples_per_method': args.samples if args.memory else 0,
              'memory_method': 'Separate fresh Python-process peak RSS/physical footprint from time -lp. Includes interpreter, import and child count/hash checks; excludes parent runner. Same startup for every method. Wrapper times are diagnostics, not API timing results or standalone C-engine memory.',
              'workloads': {}}
    if args.memory:
        result['time_sha256'] = f.digest(Path('/usr/bin/time'))
    root = Path(tempfile.mkdtemp(prefix='stallionfs-scan-', dir=scratch))
    identity = root.lstat()
    cleanup_safe, checkpoint_identity = False, None

    def checkpoint():
        nonlocal checkpoint_identity
        checkpoint_identity = f.write_json(partial, result, checkpoint_identity)

    try:
        try:
            checkpoint()
            for layout in ('flat', 'nested', 'deep40'):
                path = root / layout
                rows = {method: [] for method in METHODS}
                cpu_rows = {method: [] for method in METHODS}
                details = {'raw_seconds': rows, 'raw_cpu_seconds': cpu_rows,
                           'sample_rows': [], 'memory_rows': [],
                           'metadata': {'status': 'preparing', 'seed': {}}}
                result['workloads'][layout] = details
                checkpoint()
                expected = fixture(path, args.files, layout)
                details['expected'] = expected
                metadata = details['metadata']
                native_fixtures.enrich_metadata(path, receipt=metadata['seed'], scan_layout=layout)
                checkpoint()
                expected_source = native_correctness.snapshot(path, allow_special=True)
                baseline = output.with_name(output.name + f'.{layout}.source.json.gz')
                metadata['snapshot'] = str(baseline)
                with open(baseline, 'xb', opener=lambda name, flags: os.open(name, flags, 0o600)) as raw:
                    with gzip.open(raw, 'wt', encoding='utf-8') as stream:
                        json.dump(expected_source, stream, sort_keys=True)
                        stream.write('\n')
                metadata['snapshot_sha256'] = f.digest(baseline)
                metadata['coverage'] = native_fixtures.verify_metadata_coverage(expected_source, metadata['seed'])
                f.require(metadata['coverage']['populated'] is True, 'Metadata coverage incomplete')
                metadata['status'] = 'prepared'
                checkpoint()
                for index in range(args.samples + 2):
                    order = list(METHODS)
                    rng.shuffle(order)
                    for method in order:
                        row = dict(method=method, round=index, pair_id=index, order=order,
                                   phase='timing', warmup=index < 2, ok=False, validated=False)
                        details['sample_rows'].append(row)
                        checkpoint()
                        before = native_correctness.snapshot(path, allow_special=True)
                        row['source_precheck'] = native_correctness.verify_source(expected_source, before)
                        f.require(row['source_precheck']['unchanged'], 'Scan source changed before timing attempt')
                        cpu_start = time.process_time()
                        start = time.perf_counter()
                        observed = _scan.scan(path, bulk=method != 'posix', jobs=METHODS[method])
                        elapsed = time.perf_counter() - start
                        cpu_elapsed = time.process_time() - cpu_start
                        row.update(wall_s=elapsed, cpu_s=cpu_elapsed, ok=True,
                                   counts_validated=observed == expected, observed=observed,
                                   precision_floor={'wall_s': 2 * time.get_clock_info('perf_counter').resolution,
                                                    'cpu_s': 2 * time.get_clock_info('process_time').resolution})
                        row['source_verification'] = native_correctness.verify_source(
                            before, native_correctness.snapshot(path, allow_special=True))
                        f.require(row['source_verification']['unchanged'], 'Scan source changed during timing attempt')
                        row['validated'] = row['counts_validated']
                        f.require(row['validated'], f'{method}: expected {expected}, got {observed}')
                        if index >= 2:
                            rows[method].append(elapsed)
                            cpu_rows[method].append(cpu_elapsed)
                    checkpoint()
                medians = {method: statistics.median(samples) for method, samples in rows.items()}
                details.update(median_seconds=medians, speedup=medians['posix'] / medians['bulk'],
                               median_cpu_seconds={method: statistics.median(samples) for method, samples in cpu_rows.items()},
                               timing_comparisons=comparisons(details['sample_rows'], 'timing'))
                if args.memory:
                    for index in range(args.samples):
                        order = list(METHODS)
                        rng.shuffle(order)
                        for method in order:
                            row = dict(method=method, round=index, pair_id=index, order=order, warmup=False,
                                       phase='resources', ok=False, validated=False)
                            details['memory_rows'].append(row)
                            checkpoint()
                            before = native_correctness.snapshot(path, allow_special=True)
                            row['source_precheck'] = native_correctness.verify_source(expected_source, before)
                            f.require(row['source_precheck']['unchanged'], 'Scan source changed before memory attempt')
                            row.update(memory_sample(path, method, expected, result['native_binary_sha256'], root / 'memory.txt', row))
                            row['ok'] = True
                            row['source_verification'] = native_correctness.verify_source(
                                before, native_correctness.snapshot(path, allow_special=True))
                            f.require(row['source_verification']['unchanged'], 'Scan source changed during memory attempt')
                            row['validated'] = True
                            checkpoint()
                    details['memory_medians'] = {
                        method: {key: statistics.median(row[key] for row in details['memory_rows'] if row['method'] == method)
                                 if all(row[key] is not None for row in details['memory_rows'] if row['method'] == method) else None
                                 for key in ('rss_bytes', 'footprint_bytes')} for method in METHODS}
                    details['memory_comparisons'] = comparisons(details['memory_rows'], 'resources')
                print(layout, json.dumps(medians), flush=True)
            f.require({path.name: f.digest(path) for path in sources} == hashes and
                      f.digest(native_binary) == result['native_binary_sha256'] and
                      f.digest(Path(sys.executable)) == result['python_binary_sha256'] and
                      (not args.memory or f.digest(Path('/usr/bin/time')) == result['time_sha256']),
                      'Source, interpreter or native binary changed during measurement')
            cleanup_safe = True
        finally:
            if cleanup_safe:
                current = root.lstat()
                f.require(stat.S_ISDIR(current.st_mode) and stat.S_IMODE(current.st_mode) == 0o700 and
                          (current.st_dev, current.st_ino, current.st_uid) == (identity.st_dev, identity.st_ino, os.getuid()),
                          'Fixture identity changed; preserve it')
                f.require(not any(Path(row['path']) == root or root in Path(row['path']).parents for row in _scan.mounts()),
                          'Fixture contains a mounted filesystem; preserve it')
                f.remove_fixture(root)
                result['cleanup_passed'] = True
            else:
                result['retained_fixture'] = str(root)
        result.update(status='complete', passed=True)
        f.write_new_json(output, result)
    except BaseException as exc:
        result.update(status='failed', passed=False, error=f'{type(exc).__name__}: {exc}')
        if root.exists():
            result['retained_fixture'] = str(root)
        try:
            checkpoint()
        except BaseException as checkpoint_error:
            exc.add_note(f'Failed to write checkpoint {partial}: '
                         f'{type(checkpoint_error).__name__}: {checkpoint_error}')
        raise
    current = partial.lstat()
    if (current.st_dev, current.st_ino) == checkpoint_identity:
        partial.unlink()


if __name__ == '__main__':
    main()
