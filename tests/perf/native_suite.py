"""Run matched native command comparisons; preserve losses and failed validation."""
import argparse
import base64
import gzip
from datetime import datetime, timezone
import json
import hashlib
from itertools import product
import os
from pathlib import Path
import platform
import random
import re
import shutil
import stat
import subprocess
import sys
import time
import tempfile

import fileops
import native_metrics
import native_correctness
import native_fixtures
import native_report

PROFILES = {**fileops.LARGE_PROFILES, 'huge_2x10gib': {'files': 2, 'bytes': 20 * 1024**3}}

COPY_TOOLS = {
    'cp-clone': ['/bin/cp', '-cRp'],
    'cp': ['/bin/cp', '-Rp'],
    'ditto': ['/usr/bin/ditto', '--rsrc', '--extattr', '--acl'],
    'rsync': ['/usr/bin/rsync', '-a', '--extended-attributes'],
}
SCAN_FIELDS = ('files', 'directories', 'symlinks', 'other', 'logical_bytes', 'skipped_mounts')


def compress_scan_stdout(row):
    """Retain exact stdout compactly before checkpointing; return bytes for parsing."""
    raw = base64.b64decode(row.pop('stdout_b64'), validate=True)
    row.pop('stdout', None)
    row.update(stdout_gzip_b64=base64.b64encode(gzip.compress(raw, mtime=0)).decode('ascii'),
               stdout_sha256=hashlib.sha256(raw).hexdigest(), stdout_bytes=len(raw))
    return raw


def parse_scan_output(method, output, root_device):
    """Validate raw numeric output after timing; names never enter the stat protocol."""
    if method == 'stallionfs':
        def unique_fields(pairs):
            result = dict(pairs)
            if len(result) != len(pairs):
                raise ValueError('Duplicate scan counter')
            return result
        counts = json.loads(output, object_pairs_hook=unique_fields)
    elif method == 'find-stat':
        counts = dict.fromkeys(SCAN_FIELDS, 0)
        if output and not output.endswith(b'\n'):
            raise ValueError('Incomplete stat record')
        for line in output.split(b'\n')[:-1]:
            if not re.fullmatch(rb'[0-7]+\t-?[0-9]+\t-?[0-9]+', line):
                raise ValueError('Invalid stat record')
            mode, size, device = line.split(b'\t')
            mode, size, device = int(mode, 8), int(size), int(device)
            kind = stat.S_IFMT(mode)
            if (not 0 <= mode <= 0xffff or not -(1 << 63) <= size < 1 << 63
                    or not -(1 << 31) <= device < 1 << 31
                    or kind not in {stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK,
                                    stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK}):
                raise ValueError('Invalid stat type or numeric range')
            if kind == stat.S_IFREG:
                if size < 0: raise ValueError('Negative regular-file size')
                counts['files'] += 1
                counts['logical_bytes'] += size
            elif kind == stat.S_IFDIR:
                counts['directories'] += 1
                counts['skipped_mounts'] += (device & 0xffffffff) != (root_device & 0xffffffff)
            elif kind == stat.S_IFLNK:
                counts['symlinks'] += 1
            else:
                counts['other'] += 1
    else:
        raise ValueError('Unknown scan method')
    if (type(counts) is not dict or set(counts) != set(SCAN_FIELDS)
            or any(type(value) is not int or not 0 <= value < 1 << 64 for value in counts.values())):
        raise ValueError('Expected exactly six unsigned 64-bit scan counters')
    return counts


def arguments(method, operation, binary, source, destination):
    if operation == 'scan':
        if method == 'stallionfs':
            return [str(binary), '--json', 'scan', str(source)]
        if method != 'find-stat': raise ValueError('Unknown scan reference')
        return ['/usr/bin/find', '-P', '-x', str(source), '-mindepth', '1',
                '-exec', '/usr/bin/stat', '-f', '%Op%t%Dz%t%Dd', '--', '{}', '+']
    if method == 'stallionfs':
        return ([str(binary), 'clone', str(source), str(destination)] if operation == 'clone' else
                [str(binary), 'move', str(source), str(destination)] if operation == 'move' else
                [str(binary), 'delete', '--recursive', str(source)])
    if operation == 'clone':
        args = COPY_TOOLS[method] + [str(source), str(destination)]
        if method == 'rsync' and source.is_dir():
            args[-2] += '/'
        return args
    return (['/bin/mv', '-n', str(source), str(destination)] if operation == 'move' else
            ['/bin/rm', '-rf', str(source)])


def cache_prepare(mode, timeout):
    if mode == 'warm':
        # The immediately preceding validated snapshot already read every byte.
        return {'mode': mode, 'policy': 'full read during validated before snapshot; residency not guaranteed for trees larger than RAM'}
    result = fileops.command(['/usr/bin/sudo', '-n', '/usr/sbin/purge'], check=False, timeout=timeout)
    return {'mode': mode, 'exit_code': result.returncode,
            'stderr': result.stderr.decode(errors='replace'),
            'policy': 'purge requested; device caches and complete eviction are not observable'}


def restore_setup_symlink_times(target, expected):
    """Restore symlink modification times on disposable ditto operands only."""
    repairs = []
    source_inodes = {tuple(entry['device_inode']) for entry in expected['entries'].values()}
    for name, entry in expected['entries'].items():
        if entry['kind'] != 'symlink': continue
        path = target / name
        before = path.lstat()
        fileops.require(stat.S_ISLNK(before.st_mode) and os.readlink(os.fsencode(path)).hex() == entry['symlink_bytes'],
                        'Setup symlink changed before timestamp restoration')
        fileops.require((before.st_dev, before.st_ino) not in source_inodes, 'Setup symlink aliases a source inode')
        if before.st_mtime_ns == entry['mtime_ns']: continue
        os.utime(path, ns=(before.st_atime_ns, entry['mtime_ns']), follow_symlinks=False)
        after = path.lstat()
        fileops.require((after.st_dev, after.st_ino, after.st_mode) == (before.st_dev, before.st_ino, before.st_mode)
                        and os.readlink(os.fsencode(path)).hex() == entry['symlink_bytes']
                        and after.st_mtime_ns == entry['mtime_ns'], 'Setup symlink timestamp restoration failed')
        repairs.append({'path': name, 'before_mtime_ns': before.st_mtime_ns, 'after_mtime_ns': after.st_mtime_ns})
    return repairs


def preserved(result):
    if 'passed' in result:
        return result['passed'] is True
    return (result.get('strict_equal') is True and result.get('sparse_preserved') is True
            and result.get('independent_clone', True) is True
            and result.get('move_identity', True) is True
            and result.get('move_source_absent', True) is True)


def summarize_report(rows, required_samples):
    groups = {}
    for row in rows:
        key = tuple(row[field] for field in ('run', 'fixture', 'operation', 'reference', 'cache', 'phase'))
        groups.setdefault(key, []).append(row)
    result = []
    for key, values in groups.items():
        native = [row for row in values if row['method'] != 'stallionfs']
        candidate = [row for row in values if row['method'] == 'stallionfs']
        comparisons = {metric: native_metrics.compare_paired(native, candidate, metric)
                       for metric in native_metrics.PHASE_METRICS[key[-1]]}
        result.append(dict(zip(('run', 'fixture', 'operation', 'reference', 'cache', 'phase'), key)) | {
            'expected_pairs': required_samples, 'complete': len(native) == len(candidate) == required_samples,
            'metrics': comparisons})
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--scratch', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--samples', type=int, default=10)
    p.add_argument('--runs', type=int, default=3, help='Collection repetitions; fewer than three is a partial campaign')
    p.add_argument('--cache', nargs='+', choices=['warm', 'cold'], default=['warm', 'cold'])
    p.add_argument('--fixtures', nargs='+', choices=[*fileops.SAMPLES, *PROFILES, *native_fixtures.PROFILES, *native_fixtures.SCAN_PROFILES, 'installed_dependencies'],
                   default=list(fileops.SAMPLES) + list(PROFILES) + list(native_fixtures.PROFILES))
    p.add_argument('--copy-tools', nargs='+', choices=list(COPY_TOOLS), default=list(COPY_TOOLS))
    p.add_argument('--operations', nargs='+', choices=['clone', 'move', 'delete', 'scan'], default=['clone', 'move', 'delete'])
    p.add_argument('--node', type=Path, help='Node executable for installed_dependencies')
    p.add_argument('--npm', type=Path, help='npm CLI JavaScript entrypoint for installed_dependencies')
    p.add_argument('--npm-cache', type=Path, help='Existing isolated offline npm cache')
    p.add_argument('--timeout', type=float, default=600)
    a = p.parse_args()
    for selection in (a.fixtures, a.operations, a.cache, a.copy_tools):
        fileops.require(len(selection) == len(set(selection)), 'Duplicate benchmark selectors are not allowed')
    fileops.require(platform.system() == 'Darwin', 'macOS is required')
    fileops.require(a.samples >= 10 and a.runs >= 1, 'At least 10 samples and 1 collection run are required')
    fileops.require(0 < a.timeout < float('inf'), 'Timeout must be finite and positive')
    scan_mode = 'scan' in a.operations
    scan_fixtures = [name in native_fixtures.SCAN_PROFILES for name in a.fixtures]
    fileops.require((scan_mode and a.operations == ['scan'] and all(scan_fixtures)) or
                    (not scan_mode and not any(scan_fixtures)),
                    'Select --operations scan only with scan_flat_20k, scan_nested_20k or scan_deep40_20k')
    binary, scratch = a.binary.resolve(strict=True), a.scratch.resolve(strict=True)
    fileops.require(binary.is_file() and os.access(binary, os.X_OK), 'An installed executable is required')
    if 'installed_dependencies' in a.fixtures:
        fileops.require(all((a.node, a.npm, a.npm_cache)), 'installed_dependencies requires --node, --npm and --npm-cache')
    output = a.output.absolute()
    fileops.require(output.parent.is_dir() and not os.path.lexists(output), 'Use a new output file')
    inventory = json.loads(fileops.command([binary, '--json', 'volumes']).stdout)
    volume = fileops.scratch_volume(inventory, scratch)
    sources = fileops.fingerprint_sources()
    sources.update({x.name: fileops.digest(x) for x in Path(__file__).parent.glob('native_*.py')})
    if 'installed_dependencies' in a.fixtures:
        sources.update({'tests/perf/fixture/'+name: fileops.digest(Path(__file__).parent/'fixture'/name) for name in native_fixtures.LOCKED_FILES})
    helper = binary.with_name('stallionfs-python')
    fileops.require(helper.is_file(), 'Installed Python helper is missing')
    executables = {str(binary): fileops.digest(binary), str(helper): fileops.digest(helper)}
    for tool in [*COPY_TOOLS.values(), ['/bin/mv'], ['/bin/rm'], ['/usr/bin/time'], ['/bin/chmod']]:
        executables[tool[0]] = fileops.digest(Path(tool[0]))
    if scan_mode:
        executables.update({path: fileops.digest(Path(path)) for path in ('/usr/bin/find', '/usr/bin/stat')})
    report = {'schema': 1, 'version': fileops.command([binary, '--version']).stdout.decode().strip(), 'status': 'running', 'passed': False, 'all_metrics_won': False,
              'cold_cache_unavailable': None,
              'timestamp': datetime.now(timezone.utc).isoformat(), 'system': platform.platform(),
              'source_sha256': sources, 'executables': executables, 'volume': volume,
              'selection': {key: str(value) if isinstance(value, Path) else value for key, value in vars(a).items() if value is not None} | {'binary': str(binary), 'scratch': str(scratch), 'output': str(output)},
              'limits': [
                  'A collection run is not full-suite acceptance; three consecutive complete campaigns are required.',
                  'Direct timing and wrapped resource samples are separate phases; read-only scans reuse a verified source.',
                  'Move/delete operands use ditto with no-follow symlink timestamp restoration, then strict independence and source checks before timing.',
                  'Direct CPU covers reaped children, not unrelated filesystem services.',
                  'Resource-pass CPU counters may round short commands to zero; this cannot establish a CPU win.',
                  'Block I/O counters are not physical device byte counts or APFS sharing measurements.',
                  'Source hashing may change access times, which are excluded; source identity and change times remain checked.',
                  'This runner covers copy, move, delete and opt-in scans, not the whole native-tool matrix.']}
    if scan_mode:
        report['limits'].extend([
            'Scan fixtures reuse scan.py\'s flat, nested and deep40 layouts with 20,000 generated files and unchanged special entries.',
            'find/stat includes batched stat startup, extra lookups and per-entry numeric output; count parsing is outside timing. StallionFS aggregates inside its command.',
            'Scan stdout is retained as gzip (mtime=0) then base64, with uncompressed SHA-256 and byte length; compression is outside timing.',
            'Scan CPU includes waited stat descendants; RSS is the largest individual process peak, not combined process-tree memory or capture-buffer memory.',
            'Scan equivalence covers stable owned trees; it does not establish equal behavior during concurrent path replacement.'])
    journal = native_report.ReportJournal(output)
    counts = dict.fromkeys(('rows', 'preparation', 'metadata_preparation', 'comparisons', 'unavailable'), 0)
    pending = {}
    all_rows_valid = True
    journal_failed = False
    def append(kind, index, value):
        nonlocal journal_failed
        try:
            journal.append(kind, index, value)
        except BaseException:
            journal_failed = True
            raise
    def record(kind, value, *, active=False):
        index = counts[kind]
        counts[kind] += 1
        if active:
            if kind in pending: raise RuntimeError('Previous report record is still active')
            pending[kind] = (index, value)
        else:
            append(kind, index, value)
    def checkpoint():
        nonlocal journal_failed
        try:
            for kind, (index, value) in pending.items():
                append(kind, index, value)
            journal.checkpoint(report)
        except BaseException:
            journal_failed = True
            raise
    def release(kind):
        # Call only after the current mutation has been checkpointed.
        pending.pop(kind, None)
    base = identity = None
    uncertain = False
    rng = random.Random(20261010)
    blocked_methods = set()
    cold_unavailable = None
    try:
        checkpoint()
        base = Path(tempfile.mkdtemp(prefix='native-suite-', dir=scratch))
        identity = base.stat()
        report['fixture_root'] = str(base)
        checkpoint()
        (base / 'outside-sentinel').write_bytes(b'keep outside linked trees\n')
        for run in range(a.runs):
            for name in a.fixtures:
                fileops.no_mounts_below(binary, base)
                if name in native_fixtures.SCAN_PROFILES:
                    fileops.require(shutil.disk_usage(scratch).free >= fileops.HEADROOM, 'Insufficient scan fixture space')
                    source = base / name
                    expected_scan = native_fixtures.scan_fixture(source, 20000, native_fixtures.SCAN_PROFILES[name])
                elif name == 'installed_dependencies':
                    fileops.require(shutil.disk_usage(scratch).free >= fileops.HEADROOM, 'Insufficient dependency preparation headroom')
                    preparation = {'run': run, 'fixture': name, 'status': 'preparing'}
                    record('preparation', preparation, active=True); checkpoint()
                    source = native_fixtures.installed_dependencies(base/name, node=a.node, npm=a.npm, cache=a.npm_cache,
                        receipt=preparation, checkpoint=checkpoint, timeout=a.timeout)
                elif name in native_fixtures.PROFILES:
                    spec = native_fixtures.PROFILES[name]
                    reserve = (2 * spec['files'] * spec['width'] * spec['height'] * 3 + fileops.HEADROOM
                               if name == 'photo_library' else fileops.HEADROOM)
                    fileops.require(shutil.disk_usage(scratch).free >= reserve, f'Insufficient space for {name}')
                    source = (native_fixtures.photo_library(base / name, **spec) if name == 'photo_library'
                              else native_fixtures.deep_tree(base / name, **spec))
                elif name in fileops.SAMPLES:
                    fileops.require(shutil.disk_usage(scratch).free >= fileops.HEADROOM, 'Insufficient free space')
                    source = fileops.fixtures(base, [name])[name]
                else:
                    spec = PROFILES[name]
                    reserve = (4 if name.startswith('git_') else 2) * spec['bytes'] + spec['files'] * 8192 + fileops.HEADROOM
                    fileops.require(shutil.disk_usage(scratch).free >= reserve, f'Insufficient space for {name}')
                    source = fileops.large_fixture(base, name, spec)
                metadata = {'run': run, 'fixture': name, 'kind': 'metadata-enrichment', 'status': 'preparing', 'seed': {}}
                record('metadata_preparation', metadata, active=True)
                uncertain = True
                checkpoint()
                native_fixtures.enrich_metadata(
                    source, receipt=metadata['seed'], scan_layout=native_fixtures.SCAN_PROFILES.get(name))
                checkpoint()
                snapshot_options = {'allow_special': True} if scan_mode else {}
                expected = native_correctness.snapshot(source, **snapshot_options)
                metadata['coverage'] = native_fixtures.verify_metadata_coverage(expected, metadata['seed'])
                fileops.require(metadata['coverage']['populated'] is True, 'Metadata coverage incomplete')
                metadata['status'] = 'prepared'
                checkpoint()
                release('metadata_preparation')
                uncertain = False
                if name == 'installed_dependencies':
                    preparation['manifest_sha256'] = hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                    regular = [entry for entry in expected['entries'].values() if entry['kind'] == 'file']
                    preparation.update(regular_files=len(regular), logical_bytes=sum(entry['size'] for entry in regular))
                    checkpoint()
                    release('preparation')
                for operation in a.operations:
                    references = ['find-stat'] if operation == 'scan' else a.copy_tools if operation == 'clone' else [operation]
                    for reference in references:
                        for cache, phase in product(a.cache, native_metrics.PHASE_METRICS):
                            failed = [method for method in (reference, 'stallionfs')
                                      if (name, operation, method) in blocked_methods]
                            if failed:
                                record('unavailable', dict(run=run, fixture=name, operation=operation,
                                    reference=reference, cache=cache, phase=phase, failed_methods=failed,
                                    reason='pair unavailable after a method failed; neither side repeated'))
                                continue
                            if cache == 'cold' and cold_unavailable is not None:
                                record('unavailable', dict(run=run, fixture=name, operation=operation, reference=reference, cache=cache, phase=phase, reason=cold_unavailable))
                                continue
                            group_rows = []
                            for sample in range(a.samples):
                                methods = [reference, 'stallionfs']; rng.shuffle(methods)
                                for method in methods:
                                    case = (name, operation, method)
                                    if any((name, operation, member) in blocked_methods for member in methods):
                                        break
                                    target, dest = base / 'target', base / 'destination'
                                    fileops.require(not os.path.lexists(target) and not os.path.lexists(dest), 'Stale operation paths')
                                    operand, setup = source, None
                                    key = dict(run=run, fixture=name, operation=operation, reference=reference,
                                               cache=cache, phase=phase, sample=sample, method=method)
                                    if operation not in ('clone', 'scan'):
                                        # Setup stays outside timing and does not prelaunch the measured candidate.
                                        setup = key | {'argv': ['/usr/bin/ditto', '--rsrc', '--extattr', '--acl', str(source), str(target)],
                                                       'exit_code': None, 'validated': False}
                                        uncertain = True
                                        record('preparation', setup, active=True); checkpoint()
                                        prepared = fileops.command(setup['argv'], check=False, timeout=a.timeout)
                                        setup.update(exit_code=prepared.returncode,
                                                     stdout_b64=base64.b64encode(prepared.stdout).decode('ascii'),
                                                     stderr_b64=base64.b64encode(prepared.stderr).decode('ascii'))
                                        if prepared.returncode:
                                            uncertain = True
                                            raise RuntimeError('Operand preparation failed; receipt and fixture retained')
                                        setup['symlink_timestamp_repairs'] = restore_setup_symlink_times(target, expected)
                                        operand = target
                                    argv = arguments(method, operation, binary, operand, dest)
                                    report['active_operation'] = key | {'argv': argv, 'state': 'source validation, cache preparation or command pending'}
                                    checkpoint()
                                    before = native_correctness.snapshot(operand, **snapshot_options)
                                    setup_correctness = (native_correctness.verify_source(expected, before) if scan_mode else
                                                         native_correctness.verify_clone(expected, before) if setup else
                                                         native_correctness.compare(expected, before))
                                    if setup is not None:
                                        setup.update(correctness=setup_correctness, validated=preserved(setup_correctness))
                                        if not setup['validated']:
                                            raise RuntimeError('Setup did not preserve the source fixture; evidence retained')
                                        setup['source_verification'] = native_correctness.verify_source(
                                            expected, native_correctness.snapshot(source))
                                        setup['validated'] &= setup['source_verification']['unchanged']
                                        if not setup['validated']:
                                            raise RuntimeError('Setup changed the source fixture; evidence retained')
                                        uncertain = False
                                    if scan_mode and not setup_correctness['unchanged']:
                                        report['source_precheck_failure'] = setup_correctness
                                        raise RuntimeError('Scan source changed before measurement; preserved for inspection')
                                    fileops.require(scan_mode or preserved(setup_correctness), 'Setup did not preserve the source fixture')
                                    conditioning = cache_prepare(cache, a.timeout)
                                    if cache == 'cold' and conditioning['exit_code']:
                                        cold_unavailable = 'cache purge unavailable; no further purge retries'
                                        report['cold_cache_unavailable'] = cold_unavailable
                                        record('unavailable', key | {'reason': cold_unavailable, 'cache_receipt': conditioning})
                                        if target.exists(): fileops.remove_fixture(target)
                                        report.pop('active_operation', None)
                                        checkpoint()
                                        release('preparation')
                                        break
                                    try:
                                        receipt = native_metrics.collect(argv, timeout_s=a.timeout, phase=phase)
                                    except native_metrics.ChildCompletionUnknown as error:
                                        uncertain = True
                                        record('rows', key | error.receipt | {'validated': False}, active=True)
                                        raise
                                    row = key | receipt
                                    del receipt
                                    row['pair_id'] = sample
                                    row.update(validated=False, cache_receipt=conditioning)
                                    scan_stdout = (compress_scan_stdout(row) if operation == 'scan'
                                                   and not row.get('completion_uncertain') else None)
                                    record('rows', row, active=True)
                                    report.pop('active_operation', None)
                                    checkpoint()
                                    release('preparation')
                                    if row.get('completion_uncertain'):
                                        uncertain = True
                                        raise fileops.ChildCompletionUnknown('Command completion uncertain; fixture retained')
                                    if row['exit_code'] == 0:
                                        if operation == 'scan':
                                            try:
                                                stderr = base64.b64decode(row['stderr_b64'], validate=True)
                                                if (stderr if phase == 'timing' else native_metrics.time_diagnostics(stderr)):
                                                    raise ValueError('Scan command emitted diagnostics')
                                                observed = parse_scan_output(method, scan_stdout,
                                                                             before['entries']['']['device_inode'][0])
                                                row['correctness'] = {'passed': observed == expected_scan,
                                                                      'expected': expected_scan, 'observed': observed}
                                            except (ValueError, KeyError, TypeError) as error:
                                                row['correctness'] = {'passed': False, 'reason': str(error)}
                                        elif operation == 'delete':
                                            row['correctness'] = {'passed': not os.path.lexists(operand), 'differences': []}
                                        else:
                                            after = native_correctness.snapshot(dest, observe_sharing=True) if operation == 'clone' else native_correctness.snapshot(dest)
                                            row['correctness'] = (native_correctness.verify_clone(before, after) if operation == 'clone' else native_correctness.verify_move(before, after))
                                            if operation == 'move':
                                                row['move_identity'] = row['correctness']['move_identity']
                                            if operation == 'move' and os.path.lexists(operand):
                                                row['correctness']['move_source_absent'] = False
                                        row['validated'] = preserved(row['correctness'])
                                    else:
                                        row['correctness'] = {'passed': False, 'reason': 'command failed'}
                                    source_after = native_correctness.snapshot(source, observe_sharing=operation == 'clone', **snapshot_options)
                                    row['source_verification'] = native_correctness.verify_source(
                                        before if scan_mode else expected, source_after)
                                    row['source_unchanged'] = row['source_verification']['unchanged']
                                    del scan_stdout
                                    row['validated'] &= row['source_unchanged']
                                    if operation == 'clone' and row['exit_code'] == 0:
                                        row['data_stream_sharing'] = native_correctness.clone_sharing(source_after, after)
                                        required = method in ('stallionfs', 'cp-clone')
                                        row['data_stream_sharing']['required'] = required
                                        if required:
                                            row['validated'] &= row['data_stream_sharing']['full_data_stream_sharing'] is True
                                    if not row['validated'] or not row.get('ok'):
                                        blocked_methods.add(case)
                                        record('unavailable', key | {'reason': 'method failed; remaining identical attempts skipped'})
                                    fileops.require((base / 'outside-sentinel').read_bytes() == b'keep outside linked trees\n', 'Operation followed a fixture symlink')
                                    if not row['source_unchanged']:
                                        uncertain = True
                                        raise RuntimeError('Operation changed the retained source fixture; preserved for inspection')
                                    fileops.no_mounts_below(binary, base)
                                    for path in (target, dest): fileops.remove_fixture(path)
                                    checkpoint()
                                    all_rows_valid &= row['validated'] and bool(row.get('ok'))
                                    projection_fields = (*key, 'pair_id', 'ok', 'validated', 'completion_uncertain',
                                                         'precision_floor', *native_metrics.METRICS)
                                    group_rows.append({field: row[field] for field in projection_fields if field in row})
                                    release('rows')
                                    del row
                                if ((cold_unavailable is not None and cache == 'cold') or
                                        any((name, operation, member) in blocked_methods for member in methods)):
                                    break
                            for comparison in summarize_report(group_rows, a.samples):
                                record('comparisons', comparison)
                            checkpoint()
                            print(json.dumps({'run': run, 'fixture': name, 'operation': operation,
                                              'reference': reference, 'cache': cache, 'phase': phase}), flush=True)
                fileops.remove_fixture(base / 'fixtures' if name in fileops.SAMPLES else base/name if name == 'installed_dependencies' else source)
        fileops.require(all(fileops.digest(Path(path)) == value for path, value in executables.items()), 'Executable changed')
        current_sources = fileops.fingerprint_sources()
        current_sources.update({x.name: fileops.digest(x) for x in Path(__file__).parent.glob('native_*.py')})
        if 'installed_dependencies' in a.fixtures:
            current_sources.update({'tests/perf/fixture/'+name: fileops.digest(Path(__file__).parent/'fixture'/name) for name in native_fixtures.LOCKED_FILES})
        fileops.require(current_sources == sources, 'Harness or product source changed')
        report['status'] = 'complete'
        report['passed'] = bool(counts['rows']) and not counts['unavailable'] and all_rows_valid
    except BaseException as error:
        if scan_mode or isinstance(error, (fileops.ChildCompletionUnknown, native_metrics.ChildCompletionUnknown, subprocess.TimeoutExpired, KeyboardInterrupt, SystemExit)):
            uncertain = True
        report.update(status='failed', error=f'{type(error).__name__}: {error}')
        raise
    finally:
        try:
            if journal_failed:
                uncertain = True
            else:
                checkpoint()
            if base is None:
                pass
            elif uncertain or identity is None:
                report['retained_fixture'] = str(base)
            else:
                current = base.lstat()
                fileops.require(stat.S_ISDIR(current.st_mode) and current.st_uid == os.getuid() and
                                stat.S_IMODE(current.st_mode) == 0o700 and
                                (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino), 'Fixture identity changed')
                fileops.no_mounts_below(binary, base)
                shutil.rmtree(base)
                report['cleanup_passed'] = not base.exists()
        except BaseException as cleanup_error:
            report.update(passed=False, status='failed', retained_fixture=str(base),
                          cleanup_error=f'{type(cleanup_error).__name__}: {cleanup_error}')
            if 'error' not in report:
                raise
        finally:
            primary_error = sys.exc_info()[1]
            try:
                if not journal_failed:
                    checkpoint()
                    journal.finish(report)
                elif base is not None:
                    print(f'Report write failed; fixture retained at {base}', file=sys.stderr)
            except BaseException as report_error:
                if primary_error is None: raise
                print(f'Final report also failed: {report_error}', file=sys.stderr)
            finally:
                primary_error = sys.exc_info()[1]
                try:
                    journal.close()
                except BaseException as close_error:
                    if primary_error is None: raise
                    print(f'Journal close also failed: {close_error}', file=sys.stderr)
    return 0 if report['passed'] else 1



if __name__ == '__main__':
    raise SystemExit(main())
