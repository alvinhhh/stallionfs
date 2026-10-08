"""Compare the shipped bulk scanner with an equivalent native POSIX traversal."""
import argparse
from datetime import datetime, timezone
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


def fixture(path, files, layout):
    path.mkdir()
    chain, parent = [], path
    if layout == 'deep40':
        for _ in range(40):
            parent = parent / 'd'
            parent.mkdir()
            chain.append(parent)
    for i in range(files):
        parent = (chain[i * 40 // files] if chain else
                  path / str(i // 100) if layout == 'nested' else path)
        if layout == 'nested' and i % 100 == 0:
            parent.mkdir()
        (parent / f'file-{i}').write_bytes(bytes([i % 256]) * (i % 1024))
    extras = chain[-1] if chain else path
    (extras / 'empty').mkdir()
    (extras / 'space and \n café 🐎').write_bytes(b'hello')
    (extras / 'directory-link').symlink_to('empty', target_is_directory=True)
    (extras / 'dangling-link').symlink_to('absent')
    (extras / 'outside-link').symlink_to('/')
    os.mkfifo(extras / 'pipe')
    with (extras / 'sparse').open('wb') as stream:
        stream.truncate(1 << 20)
    os.link(extras / 'sparse', extras / 'hard-link')
    return dict(files=files + 3,
                directories=1 + (40 if chain else (files + 99) // 100 if layout == 'nested' else 0),
                symlinks=3, other=1, logical_bytes=sum(i % 1024 for i in range(files)) + 5 + (2 << 20),
                skipped_mounts=0)


def memory_sample(path, method, expected, native_hash, metrics):
    row, completed = f.measure_memory([sys.executable, '-I', '-B', '-c', CHILD, path, method,
                                       json.dumps(expected), native_hash], metrics)
    if row.get('completion_uncertain') or row['exit_code'] != 0:
        raise f.ChildCompletionUnknown('Memory child completion uncertain; preserve fixture')
    f.require(completed is not None and not completed.stderr, 'Memory child output unavailable or invalid')
    observed = json.loads(completed.stdout)
    f.require(observed == {'counts': expected, 'native_binary_sha256': native_hash},
              'Memory child counts or native extension differ')
    return {**row, **observed}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--files', type=int, default=20000)
    parser.add_argument('--samples', type=int, default=11)
    parser.add_argument('--memory', action='store_true', help='Three separate Python-process peak-memory samples per method/layout')
    args = parser.parse_args()
    if not 1 <= args.files <= 1000000 or not 1 <= args.samples <= 100:
        parser.error('Use 1–1,000,000 files and 1–100 samples')
    rng = random.Random(20261006)
    package = Path(__file__).resolve().parents[2] / 'stallionfs'
    sources = [package / name for name in ('__init__.py', '_scan.c', '_walk.c', '_tree.h')]
    sources += [Path(__file__), Path(f.__file__)]
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
              'jobs': METHODS, 'status': 'running', 'passed': False,
              'layouts': 'Flat and 100-files-per-folder nested layouts; deep40 distributes files evenly along a 40-directory single-child chain, with special entries and empty directory at its deepest leaf',
              'volume': {key: volume.get(key) for key in ('filesystem', 'readonly', 'ignore_ownership')},
              'memory_samples_per_method': 3 if args.memory else 0,
              'memory_method': 'Separate fresh Python-process peak RSS/physical footprint from time -lp. Includes interpreter, import and child count/hash checks; excludes parent runner. Same startup for every method. Wrapper times are diagnostics, not API timing results or standalone C-engine memory.',
              'workloads': {}}
    if args.memory:
        result['time_sha256'] = f.digest(Path('/usr/bin/time'))
    root = Path(tempfile.mkdtemp(prefix='stallionfs-scan-', dir=scratch))
    identity = root.lstat()
    cleanup_safe, checkpoint_identity = True, None

    def checkpoint():
        nonlocal checkpoint_identity
        checkpoint_identity = f.write_json(partial, result, checkpoint_identity)

    try:
        try:
            checkpoint()
            for layout in ('flat', 'nested', 'deep40'):
                path = root / layout
                expected = fixture(path, args.files, layout)
                rows = {method: [] for method in METHODS}
                cpu_rows = {method: [] for method in METHODS}
                details = {'expected': expected, 'raw_seconds': rows, 'raw_cpu_seconds': cpu_rows,
                           'sample_rows': [], 'memory_rows': []}
                result['workloads'][layout] = details
                for index in range(args.samples + 2):
                    order = list(METHODS)
                    rng.shuffle(order)
                    for method in order:
                        cpu_start = time.process_time()
                        start = time.perf_counter()
                        observed = _scan.scan(path, bulk=method != 'posix', jobs=METHODS[method])
                        elapsed = time.perf_counter() - start
                        cpu_elapsed = time.process_time() - cpu_start
                        f.require(observed == expected, f'{method}: expected {expected}, got {observed}')
                        details['sample_rows'].append({'method': method, 'round': index, 'order': order,
                                                       'warmup': index < 2, 'wall_s': elapsed, 'cpu_s': cpu_elapsed})
                        if index >= 2:
                            rows[method].append(elapsed)
                            cpu_rows[method].append(cpu_elapsed)
                    checkpoint()
                medians = {method: statistics.median(samples) for method, samples in rows.items()}
                details.update(median_seconds=medians, speedup=medians['posix'] / medians['bulk'],
                               median_cpu_seconds={method: statistics.median(samples) for method, samples in cpu_rows.items()})
                if args.memory:
                    for index in range(3):
                        order = list(METHODS)
                        rng.shuffle(order)
                        for method in order:
                            cleanup_safe = False
                            row = memory_sample(path, method, expected, result['native_binary_sha256'], root / 'memory.txt')
                            row.update(method=method, round=index, order=order, warmup=False)
                            details['memory_rows'].append(row)
                            cleanup_safe = True
                            checkpoint()
                    details['memory_medians'] = {
                        method: {key: statistics.median(row[key] for row in details['memory_rows'] if row['method'] == method)
                                 if all(row[key] is not None for row in details['memory_rows'] if row['method'] == method) else None
                                 for key in ('rss_bytes', 'footprint_bytes')} for method in METHODS}
                print(layout, json.dumps(medians), flush=True)
        except (f.ChildCompletionUnknown, KeyboardInterrupt):
            cleanup_safe = False
            raise
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
        f.require({path.name: f.digest(path) for path in sources} == hashes and
                  f.digest(native_binary) == result['native_binary_sha256'] and
                  f.digest(Path(sys.executable)) == result['python_binary_sha256'] and
                  (not args.memory or f.digest(Path('/usr/bin/time')) == result['time_sha256']),
                  'Source, interpreter or native binary changed during measurement')
        result.update(status='complete', passed=True)
        f.write_new_json(output, result)
    except BaseException as exc:
        result.update(status='failed', passed=False, error=f'{type(exc).__name__}: {exc}')
        if root.exists():
            result['retained_fixture'] = str(root)
        checkpoint()
        raise
    current = partial.lstat()
    if (current.st_dev, current.st_ino) == checkpoint_identity:
        partial.unlink()


if __name__ == '__main__':
    main()
