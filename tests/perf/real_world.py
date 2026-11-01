#!/usr/bin/env python3
"""Bounded warm-cache file operations on an explicitly selected filesystem."""
import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import shutil
import signal
import stat
import statistics
import subprocess
import sys
import tempfile
import threading
import time


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def manifest(root):
    """Independent contents, modes, symlink targets and regular hardlink groups."""
    rows, groups = {}, {}
    pending = [Path(root)]
    while pending:
        path = pending.pop()
        info = path.lstat()
        name = str(path.relative_to(root))
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            rows[name] = ['directory', mode]
            pending.extend(sorted(path.iterdir()))
        elif stat.S_ISLNK(info.st_mode):
            rows[name] = ['symlink', mode, os.readlink(path)]
        elif stat.S_ISREG(info.st_mode):
            rows[name] = ['file', mode, info.st_size, sha(path)]
            groups.setdefault((info.st_dev, info.st_ino), []).append(name)
        else:
            raise RuntimeError('Unexpected fixture object: ' + str(path))
    links = sorted(sorted(names) for names in groups.values() if len(names) > 1)
    return {'entries': rows, 'hardlinks': links}


def execute(argv, scratch, timeout=180, measurement_helper=None):
    """Measure native commands below a small exec'd supervisor, not Python's fork RSS."""
    with tempfile.TemporaryFile(dir=scratch) as out, tempfile.TemporaryFile(dir=scratch) as err, tempfile.TemporaryFile(dir=scratch) as metrics:
        start = time.monotonic()
        command = [str(x) for x in argv]
        launched = [str(measurement_helper), str(metrics.fileno()), '--', *command] if measurement_helper else command
        proc = subprocess.Popen(launched, stdout=out, stderr=err,
                                pass_fds=(metrics.fileno(),) if measurement_helper else (),
                                env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'}, start_new_session=True)
        canceled, deadline = threading.Event(), {'expired': False}

        def kill_group(number=signal.SIGKILL):
            try:
                os.killpg(proc.pid, number)
            except ProcessLookupError:
                pass

        def watchdog():
            if not canceled.wait(max(0, timeout - (time.monotonic() - start))):
                deadline['expired'] = True
                kill_group(signal.SIGTERM if measurement_helper else signal.SIGKILL)
                if measurement_helper and not canceled.wait(2):
                    kill_group()

        timer = threading.Thread(target=watchdog, daemon=True)
        timer.start()
        try:
            _, status, usage = os.wait4(proc.pid, 0)
        except BaseException as exc:
            kill_group()
            _, status, _ = os.wait4(proc.pid, 0)
            proc.returncode = os.waitstatus_to_exitcode(status)
            exc.process_group_uncertain = True
            raise
        finally:
            canceled.set()
            timer.join()
        launcher_wall = time.monotonic() - start
        proc.returncode = os.waitstatus_to_exitcode(status)
        # A reaped supervisor alone does not certify that its process group drained.
        group_quiet, group_was_busy = False, False
        for _ in range(101):
            try:
                os.killpg(proc.pid, 0)
            except ProcessLookupError:
                group_quiet = True
                break
            group_was_busy = True
            kill_group()
            time.sleep(.01)
        out.seek(0); err.seek(0)
        stdout, stderr = out.read(65537), err.read(65537)
        result = {'argv': command, 'returncode': proc.returncode,
            'wall_s': launcher_wall, 'cpu_s': usage.ru_utime + usage.ru_stime,
            'peak_rss_bytes': usage.ru_maxrss * (1 if sys.platform == 'darwin' else 1024),
            'stdout': stdout[:65536].decode(errors='replace'),
            'stderr': stderr[:65536].decode(errors='replace'),
            'output_truncated': len(stdout) > 65536 or len(stderr) > 65536,
            'timed_out': deadline['expired'], 'process_group_quiescent': group_quiet,
            'unexpected_descendants': group_was_busy,
            'measurement_method': 'native_supervisor_wait4' if measurement_helper else 'python_wait4',
            'launcher_wall_s': launcher_wall, 'launcher_returncode': proc.returncode}
        if measurement_helper:
            metrics.seek(0)
            try:
                measured = json.loads(metrics.read(4097))
                if proc.returncode or set(measured) != {'returncode', 'wall_s', 'cpu_s', 'peak_rss_bytes'}:
                    raise ValueError('Supervisor failed or returned malformed metrics')
                if (type(measured['returncode']) is not int or measured['returncode'] > 255
                        or measured['returncode'] < -127 or type(measured['peak_rss_bytes']) is not int
                        or measured['peak_rss_bytes'] < 0
                        or any(type(measured[k]) not in (int, float) or not math.isfinite(measured[k])
                               or measured[k] < 0 for k in ('wall_s', 'cpu_s'))):
                    raise ValueError('Invalid native metrics')
                result.update(measured)
                if group_was_busy:
                    result['measurement_error'] = 'Command left descendants after measured exit'
            except (ValueError, TypeError) as exc:
                result.update(wall_s=None, cpu_s=None, peak_rss_bytes=None, measurement_error=str(exc))
    return result


def summarize(samples, expected_repetitions=None):
    if expected_repetitions is not None and (type(expected_repetitions) is not int or expected_repetitions < 1):
        raise ValueError('Expected repetitions must be a positive integer')
    result = {}
    for case in ('scan', 'copy', 'clone', 'delete'):
        variants, excluded = {}, {}
        for variant in sorted({s['variant'] for s in samples if s['case'] == case}):
            attempts = [s for s in samples if s['case'] == case and s['variant'] == variant]
            if any(s['status'] != 'passed' for s in attempts):
                excluded[variant] = {'statuses': {status: sum(s['status'] == status for s in attempts)
                                                 for status in sorted({s['status'] for s in attempts})}}
                continue
            rows = [s for s in samples if s['case'] == case and s['variant'] == variant
                    and not s['warmup'] and s['status'] == 'passed']
            if expected_repetitions is not None and (len(rows) != expected_repetitions or
                    sorted(s['repetition'] for s in rows) != list(range(expected_repetitions))):
                excluded[variant] = {'reason': 'Incomplete or duplicate measured repetitions',
                                     'expected_repetitions': expected_repetitions,
                                     'measured_samples': len(rows),
                                     'observed_repetitions': sorted(s['repetition'] for s in rows)}
                continue
            if not rows:
                continue
            variants[variant] = {'n': len(rows)}
            for key in ('wall_s', 'cpu_s', 'peak_rss_bytes'):
                values = sorted(s[key] for s in rows)
                if key == 'peak_rss_bytes' and values[0] <= 0:
                    variants[variant][key] = {'available': False, 'reason': 'Zero RSS counter is not a memory observation'}
                    continue
                variants[variant][key] = {'median': statistics.median(values),
                    'p95': values[math.ceil(.95 * len(values)) - 1],
                    'population_stdev': statistics.pstdev(values)}
        baseline = {'scan': 'native_posix', 'copy': 'native_ditto' if sys.platform == 'darwin' else 'native_cp',
                    'clone': 'native_cp', 'delete': 'native_rm'}[case]
        comparisons = {}
        for variant in list(variants):
            if baseline not in variants or variant == baseline:
                continue
            ratios = {}
            for metric in ('wall_s', 'cpu_s', 'peak_rss_bytes'):
                if any('median' not in variants[v][metric] for v in (baseline, variant)):
                    ratios[metric] = {'available': False}
                    continue
                native = {s['repetition']: s[metric] for s in samples if s['case'] == case
                          and s['variant'] == baseline and not s['warmup'] and s['status'] == 'passed'}
                pairs = [(native[s['repetition']], s[metric]) for s in samples if s['case'] == case
                         and s['variant'] == variant and not s['warmup'] and s['status'] == 'passed'
                         and s['repetition'] in native]
                a, b = variants[baseline][metric]['median'], variants[variant][metric]['median']
                ratios[metric] = {'baseline_over_variant_median': a / b if b else None,
                                 'wins': sum(y < x for x, y in pairs),
                                 'losses': sum(y > x for x, y in pairs),
                                 'ties': sum(y == x for x, y in pairs), 'paired_n': len(pairs)}
            comparisons[variant] = ratios
        result[case] = {'variants': variants, 'excluded_variants': excluded,
                        'baseline': baseline, 'comparisons': comparisons}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True, help='Existing writable filesystem directory')
    parser.add_argument('--output', type=Path, required=True, help='New JSON path; sibling CSV must also be absent')
    parser.add_argument('--sfs', help='Optional installed sfs executable')
    parser.add_argument('--repetitions', type=int, default=10)
    parser.add_argument('--files', type=int, default=10000)
    parser.add_argument('--directories', type=int, default=100, help='Use 1 for a flat file layout')
    jobs = parser.add_mutually_exclusive_group()
    jobs.add_argument('--jobs', type=int, choices=range(1, 5), help='Single sfs worker count')
    jobs.add_argument('--sfs-jobs', help='Comma-separated sfs worker counts; default 1,2,4')
    args = parser.parse_args()
    if sys.platform not in ('darwin', 'linux'):
        parser.error('Only macOS and Linux have qualified resource units')
    if args.repetitions < 1 or args.files < 2 or args.files > 100000:
        parser.error('Require repetitions >= 1 and 2 <= files <= 100000')
    if not 1 <= args.directories <= 10000:
        parser.error('Require 1 <= directories <= 10000')
    try:
        worker_counts = [int(x) for x in args.sfs_jobs.split(',')] if args.sfs_jobs else ([args.jobs] if args.jobs else [1, 2, 4])
        if not worker_counts or len(set(worker_counts)) != len(worker_counts) or any(x not in range(1, 5) for x in worker_counts):
            raise ValueError()
    except ValueError:
        parser.error('--sfs-jobs requires distinct counts in 1,2,3,4')
    root, output = args.root.resolve(strict=True), args.output.absolute()
    if not root.is_dir() or not output.parent.is_dir():
        parser.error('Root and output parent must be existing directories')
    csv_path = output.with_suffix('.csv')
    if csv_path == output or output.exists() or csv_path.exists():
        parser.error('JSON and CSV output paths must be distinct and new')
    tools = {name: shutil.which(name) for name in ('cp', 'rm', 'cc')}
    if sys.platform == 'darwin':
        tools['ditto'] = shutil.which('ditto')
    if args.sfs:
        tools['sfs'] = shutil.which(args.sfs)
    if any(value is None for value in tools.values()):
        parser.error('Missing executable: ' + str(tools))
    # Exclusive creation refuses existing files and dangling symlinks.
    with open(output, 'x'):
        pass
    with open(csv_path, 'x'):
        pass
    scratch = Path(tempfile.mkdtemp(prefix='sfs-real-world-', dir=root))
    report = {'schema': 2, 'passed': False, 'samples': [], 'errors': [], 'setup': [],
              'parameters': vars(args) | {'root': str(root), 'output': str(output)},
              'scratch': str(scratch), 'system': {'platform': platform.platform(),
              'uname': list(os.uname()), 'python': sys.version, 'device': root.stat().st_dev},
              'notes': ['Warm-cache workloads; no cache purge or filesystem administration.',
              'Setup, SHA256/mode/link/topology validation, mutation and cleanup are outside timing.',
              'Native supervisor wait4 measures command CPU and per-child RSS, not Python fork high-water or simultaneous group RAM.',
              'Command wall covers supervisor fork/exec through wait4; launcher_wall_s separately includes Python/supervisor startup and watchdog.',
              'Setup receipts use Python wait4; their RSS may inherit the Python parent and is not a workload comparison.',
              'A zero native RSS counter is retained raw but unavailable for memory summaries or wins.',
              'Supervision covers the owned process group; these known commands do not detach into new sessions.',
              'No durability flush, power-loss test, ACL/xattr/owner/time comparison or physical-space inference.',
              'Clone commands request mandatory CoW; independent physical-sharing attributes are not inspected.',
              'Each case has one warmup followed by deterministically shuffled variants each measured repetition.']}
    report['parameters']['sfs'] = args.sfs
    report['parameters']['worker_counts'] = worker_counts
    for key in ('root', 'output'):
        report['parameters'][key] = str(report['parameters'][key])

    def save():
        report['summary'] = summarize(report['samples'], expected_repetitions=args.repetitions)
        output.write_text(json.dumps(report, indent=2) + '\n')
        fields = ('case', 'variant', 'repetition', 'warmup', 'status', 'wall_s', 'launcher_wall_s', 'measurement_method', 'cpu_s',
                  'peak_rss_bytes', 'returncode', 'validation', 'error')
        with open(csv_path, 'w', newline='') as stream:
            writer = csv.DictWriter(stream, fields, extrasaction='ignore')
            writer.writeheader(); writer.writerows(report['samples'])

    try:
        report['tools'] = {k: {'path': v, 'sha256': sha(v)} for k, v in tools.items()}
        report['setup'].append(execute([tools['cc'], '--version'], scratch))
        if shutil.which('df'):
            report['filesystem'] = execute([shutil.which('df'), '-T' if sys.platform == 'linux' else '-P', root], scratch)
        if any(not item['process_group_quiescent'] for item in report['setup'] + ([report['filesystem']] if 'filesystem' in report else [])):
            report['retain_scratch'] = True
            raise RuntimeError('Setup process group did not drain')
        source = Path(__file__).with_name('real_world_scan.c')
        measurement_source = Path(__file__).with_name('real_world_measure.c')
        report['sources'] = {str(p): sha(p) for p in (Path(__file__), source, measurement_source)}
        helper, measurement = scratch / 'scan-posix', scratch / 'measure-command'
        for code, binary in ((source, helper), (measurement_source, measurement)):
            compiled = execute([tools['cc'], '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', code, '-o', binary], scratch)
            report['setup'].append(compiled)
            if not compiled['process_group_quiescent']:
                report['retain_scratch'] = True
            if compiled['returncode'] or compiled['timed_out'] or compiled['output_truncated'] or report.get('retain_scratch'):
                raise RuntimeError('Native helper compilation failed: ' + code.name)
        report['helpers'] = {str(p): sha(p) for p in (helper, measurement)}
        dataset = scratch / 'source'; dataset.mkdir(mode=0o700)
        for i in range(args.directories):
            (dataset / f'd{i:03d}').mkdir(mode=0o750)
        for i in range(args.files):
            path = dataset / f'd{i % args.directories:03d}' / f'f{i:06d}'
            path.write_bytes(hashlib.sha256(str(i).encode()).digest() * 128)
            path.chmod(0o640)
        os.link(dataset / 'd000/f000000', dataset / 'hardlink-alias')
        (dataset / 'relative-link-a').symlink_to('d000/f000000')
        (dataset / 'relative-link-b').symlink_to(f'd{1 % args.directories:03d}/f000001')
        expected = manifest(dataset)
        report['fixture'] = {'files': args.files, 'file_bytes': 4096, 'directories': args.directories,
                             'manifest_sha256': hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest()}
        counts = {'files': args.files + 1, 'directories': args.directories, 'symlinks': 2, 'other': 0,
                  'logical_bytes': (args.files + 1) * 4096, 'skipped_mounts': 0}
        sentinel = scratch / 'sentinel'; sentinel.write_bytes(b'untouched\x00sentinel')
        sentinel_hash = sha(sentinel)
        rng, unavailable = random.Random(20261101), set()
        for case in ('scan', 'copy', 'clone', 'delete'):
            for repetition in range(-1, args.repetitions):
                variants = [{'scan': 'native_posix', 'copy': 'native_cp',
                             'clone': 'native_cp', 'delete': 'native_rm'}[case]]
                if case == 'copy' and sys.platform == 'darwin': variants.append('native_ditto')
                if args.sfs: variants.extend('sfs_jobs' + str(n) for n in worker_counts)
                rng.shuffle(variants)
                for variant in variants:
                    sample = {'case': case, 'variant': variant, 'repetition': repetition,
                              'warmup': repetition == -1, 'status': 'pending'}
                    report['samples'].append(sample)
                    if (case, variant) in unavailable:
                        sample['status'] = 'skipped_unsupported'; save(); continue
                    target = scratch / 'target'
                    stop = False
                    try:
                        if target.exists() or target.is_symlink():
                            raise RuntimeError('Unexpected existing target')
                        if case == 'delete':
                            shutil.copytree(dataset, target, symlinks=True)
                        path = dataset if case == 'scan' else target
                        if variant.startswith('sfs_jobs'):
                            sample['jobs'] = int(variant.removeprefix('sfs_jobs'))
                            argv = [tools['sfs'], '--json', case, path, '--jobs', str(sample['jobs'])]
                            if case in ('copy', 'clone'):
                                argv.insert(3, dataset)
                            if case == 'delete':
                                argv.append('--recursive')
                        elif case == 'scan':
                            argv = [helper, dataset]
                        elif case == 'delete':
                            argv = [tools['rm'], '-rf', target]
                        elif variant == 'native_ditto':
                            argv = [tools['ditto'], '--rsrc', '--extattr', '--acl', dataset, target]
                        else:
                            flags = ['-cRp'] if case == 'clone' else ['-Rp']
                            if sys.platform == 'linux':
                                flags = ['-a', '--reflink=' + ('always' if case == 'clone' else 'never')]
                            argv = [tools['cp'], *flags, dataset, target]
                        sample.update(execute(argv, scratch, measurement_helper=measurement))
                        if not sample['process_group_quiescent']:
                            report['retain_scratch'] = True
                            raise RuntimeError('Command process group did not drain')
                        if sample.get('measurement_error'):
                            raise RuntimeError('Native measurement failed: ' + sample['measurement_error'])
                        if sample['returncode']:
                            text = sample['stderr'].lower()
                            unsupported = (case == 'clone' and variant == 'native_cp' and sys.platform == 'linux'
                                           and 'failed to clone' in text
                                           and ('operation not supported' in text or 'eopnotsupp' in text))
                            if unsupported:
                                sample['status'] = 'unsupported'; unavailable.add((case, variant))
                            else:
                                raise RuntimeError('Command failed: ' + sample['stderr'])
                        elif sample['timed_out'] or sample['output_truncated']:
                            raise RuntimeError('Timed out or exceeded output limit')
                        elif case == 'scan':
                            if json.loads(sample['stdout']) != counts:
                                raise RuntimeError('Scan counters differ')
                        elif case == 'delete':
                            if target.exists() or target.is_symlink():
                                raise RuntimeError('Deletion incomplete')
                        else:
                            observed = manifest(target)
                            if observed != expected:
                                sample['manifest_difference'] = {
                                    'entries': [k for k in sorted(set(observed['entries']) | set(expected['entries']))
                                                if observed['entries'].get(k) != expected['entries'].get(k)][:20],
                                    'expected_hardlinks': expected['hardlinks'], 'actual_hardlinks': observed['hardlinks']}
                                raise RuntimeError('Copy contents/modes/links/topology differ')
                            for name, entry in expected['entries'].items():
                                if entry[0] == 'file':
                                    a, b = (target / name).stat(), (dataset / name).stat()
                                    if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino):
                                        raise RuntimeError('Destination aliases source inode: ' + name)
                            if case == 'clone' and repetition == 0:
                                with open(target / 'd000/f000000', 'r+b') as stream:
                                    stream.write(b'edit')
                                sample['mutation_isolation_checked'] = True
                        sample['validation'] = 'not_applicable_unsupported' if sample['status'] == 'unsupported' else 'passed'
                        if sample['status'] == 'pending':
                            sample['status'] = 'passed'
                    except BaseException as exc:
                        if getattr(exc, 'process_group_uncertain', False):
                            report['retain_scratch'] = True
                        sample.update(status='failed', error=f'{type(exc).__name__}: {exc}')
                        report['errors'].append(f'{case}/{variant}/{repetition}: {type(exc).__name__}: {exc}')
                        if not isinstance(exc, Exception):
                            raise
                    finally:
                        if report.get('retain_scratch'):
                            raise RuntimeError('Uncertain process completion; scratch retained without further inspection')
                        try:
                            if manifest(dataset) != expected or sha(sentinel) != sentinel_hash:
                                raise RuntimeError('Source or sentinel changed')
                            sample['source_unchanged'] = True
                        except Exception as exc:
                            sample.update(status='failed', error=str(exc))
                            report['errors'].append(str(exc)); stop = True
                        try:
                            if target.is_symlink(): target.unlink()
                            elif target.exists(): shutil.rmtree(target)
                        except Exception as exc:
                            sample.update(status='failed', error='Target cleanup failed: ' + str(exc))
                            report['errors'].append(sample['error']); stop = True
                        save()
                    if stop:
                        raise RuntimeError('Stopped after unsafe source state or failed cleanup')
        report['passed'] = not report['errors']
    except BaseException as exc:
        report['passed'] = False
        report['errors'].append(f'{type(exc).__name__}: {exc}')
        if getattr(exc, 'process_group_uncertain', False):
            report['retain_scratch'] = True
    finally:
        try:
            if report.get('retain_scratch'):
                raise RuntimeError('Scratch retained because process completion is uncertain')
            if scratch.parent != root or not scratch.name.startswith('sfs-real-world-'):
                raise RuntimeError('Scratch identity guard failed')
            shutil.rmtree(scratch)
            report['cleanup'] = 'passed'
        except Exception as exc:
            report['passed'] = False
            report['cleanup'] = 'failed: ' + str(exc)
        save()
    print(json.dumps({'passed': report['passed'], 'output': str(output), 'cleanup': report['cleanup']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
