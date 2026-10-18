"""Collect three sequential cycles of the existing benchmark workloads.

Completion is a collection result, never an all-metrics acceptance result.
Each stage owns its fixtures and evidence; this driver never removes them.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import fileops as f
import native_fixtures
import native_report


HERE = Path(__file__).resolve().parent
FILES = (*f.SAMPLES, *f.LARGE_PROFILES, 'huge_2x10gib',
         *native_fixtures.PROFILES, 'installed_dependencies')
SCANS = tuple(native_fixtures.SCAN_PROFILES)


def environment(node):
    result = {key: value for key, value in os.environ.items()
              if key not in ('PYTHONPATH', 'PYTHONHOME', 'NODE_OPTIONS', 'NODE_PATH')
              and not key.lower().startswith('npm_config_')}
    result.update(PATH=str(node.parent) + os.pathsep + result.get('PATH', ''),
                  PYTHONDONTWRITEBYTECODE='1')
    return result


def fingerprints(args):
    import stallionfs
    package = Path(stallionfs.__file__).resolve().parent
    python = Path(sys.executable).absolute()
    for path in (args.binary, python, python.resolve(), package):
        f.require(not path.is_relative_to(f.REPO), 'Use an installed runtime outside the checkout')
    f.require(package.is_relative_to(Path(sys.prefix).resolve()) and
              args.binary.parent == python.parent.resolve(),
              'Use the Python and CLI from the same installed environment')
    helper = args.binary.with_name('stallionfs-python')
    npm_manifest = args.npm.parent.parent / 'package.json'
    git = shutil.which('git', path=environment(args.node)['PATH'])
    f.require(git is not None, 'Git is required')
    paths = {Path(path) for path in (args.binary, helper, python, args.node, args.npm,
             npm_manifest, git, '/bin/cp', '/bin/mv', '/bin/rm', '/usr/bin/ditto',
             '/usr/bin/rsync', '/usr/bin/find', '/usr/bin/stat', '/usr/bin/time',
             '/bin/chmod')}
    if 'cold' in args.cache:
        paths.update((Path('/usr/bin/sudo'), Path('/usr/sbin/purge')))
    paths.update(path for path in package.rglob('*') if path.suffix in ('.py', '.so') and path.is_file())
    f.require(all(path.is_file() for path in paths) and
              all(os.access(path, os.X_OK) for path in (args.binary, python, args.node)),
              'Installed runtime or reference tool is missing')
    source = f.fingerprint_sources()
    source.update({path.relative_to(f.REPO).as_posix(): f.digest(path)
                   for path in (*HERE.glob('*.py'), *(HERE / 'fixture' / name for name in native_fixtures.LOCKED_FILES))})
    return {'source_sha256': source,
            'runtime_sha256': {str(path): f.digest(path) for path in sorted(paths)}}


def stages(args, cycle):
    common = ['--scratch', str(args.scratch), '--samples', str(args.samples)]
    runtime = ['--node', str(args.node), '--npm', str(args.npm), '--npm-cache', str(args.npm_cache)]
    native = ['--binary', str(args.binary), '--runs', '1', '--cache', *args.cache]
    selections = (
        ('native-files', 'native_suite.py', [*native, '--operations', 'clone', 'move', 'delete',
         '--copy-tools', 'cp-clone', 'cp', 'ditto', 'rsync', '--fixtures', *FILES, *runtime]),
        ('native-scan', 'native_suite.py', [*native, '--operations', 'scan', '--fixtures', *SCANS]),
        ('scan-api', 'scan.py', ['--files', '20000', '--memory']),
        ('workspaces', 'run.py', ['--methods', 'worktree_install', 'stallionfs_folder',
         '--concurrency', '4', '--source-files', '1000', *runtime]),
    )
    for name, script, options in selections:
        output = args.output_dir / f'cycle-{cycle}-{name}.json'
        yield name, output, [sys.executable, '-B', str(HERE / script), *common,
                             '--output', str(output), *options]


def read_small(path):
    with path.open('rb') as stream:
        raw = stream.read(native_report.MAX_MANIFEST_BYTES + 1)
    f.require(len(raw) <= native_report.MAX_MANIFEST_BYTES, 'Oversized stage summary')
    value = json.loads(raw)
    f.require(isinstance(value, dict), 'Stage summary must be an object')
    return value


def outcome(name, output):
    """Read control state, not the potentially large native result payload."""
    if name.startswith('native-'):
        manifest_path = output.with_name(output.name + '.manifest')
        manifest = read_small(manifest_path)
        journal = output.with_name(output.name + '.journal')
        f.require(manifest.get('storage_schema') == 1 and manifest.get('journal') == journal.name
                  and type(manifest.get('committed_bytes')) is int and manifest['committed_bytes'] >= 0
                  and journal.stat().st_size == manifest['committed_bytes'],
                  'Native journal is missing, truncated or has an uncommitted tail')
        state = manifest.get('state')
        f.require(isinstance(state, dict), 'Native manifest state is missing')
        evidence = {'manifest': str(manifest_path), 'manifest_sha256': f.digest(manifest_path),
                    'journal': str(journal), 'committed_bytes': manifest['committed_bytes'],
                    'claimed_prefix_sha256': manifest.get('prefix_sha256'),
                    'verification': 'Manifest control state and journal length only; journal contents and final JSON are not independently verified'}
    else:
        partial = (output.with_suffix('.partial.json') if name == 'workspaces'
                   else output.with_name(output.name + '.partial'))
        path = output if output.is_file() else partial
        state = read_small(path)
        evidence = {'summary': str(path), 'summary_sha256': f.digest(path)}
    evidence['final_report_exists'] = output.is_file()
    fields = ('status', 'passed', 'cleanup_passed', 'retained_fixture',
              'completion_uncertain', 'error', 'cleanup_error', 'cold_cache_unavailable')
    return {key: state[key] for key in fields if key in state}, evidence


def safe_to_continue(name, code, state, evidence):
    terminal = (state.get('status') == 'complete' and state.get('cleanup_passed') is True
                and type(state.get('passed')) is bool and evidence['final_report_exists']
                and not any(state.get(key) for key in
                            ('retained_fixture', 'completion_uncertain', 'error', 'cleanup_error')))
    return terminal and ((code == 0 and state['passed']) or
                         (name.startswith('native-') and code == 1 and not state['passed']))


def collect(args):
    pins = fingerprints(args)
    args.output_dir.mkdir(mode=0o700)
    summary = args.output_dir / 'campaign.json'
    report = {'schema': 1, 'status': 'running', 'all_metrics_won': False,
              'started_utc': datetime.now(timezone.utc).isoformat(), 'cycles': 3,
              'samples': args.samples, 'cache': args.cache, 'fingerprints': pins, 'stages': [],
              'cold_cache_unavailable': None,
              'scope': 'Sequential collection of existing workloads; exit success does not establish performance acceptance',
              'unavailable_coverage': [
                  'Finder completion and resource comparisons',
                  'Workspace lifecycle peak memory and full metadata equivalence',
                  'Replacement/exchange moves, mount-record listing and image/recovery workflows',
                  'Cold-cache API scanner and workspace measurements; those stages remain warm',
                  'Representative photo workload; the current PNG corpus is synthetic',
                  'Mounted FSKit serving-process resources and deferred writes',
                  'External-drive repeat coverage; only the supplied scratch location is used',
                  'CLI JSON/startup-only cases and mounted-image steady-state I/O are outside this campaign'],
              'cold_cache': ('Purge-conditioned native stages requested; denied purges remain failures in child reports. Device-cache eviction is not established'
                             if 'cold' in args.cache else 'Unavailable: cold-cache stages were not selected'),
              'limits': ['Node executable, npm entrypoint and package manifest are pinned; the entire npm tree is not pinned',
                         'Native command CPU excludes shared services; native RSS is not simultaneous descendant memory',
                         'Scanner memory includes Python startup, imports and validation',
                         'Reports and logs contain local paths; review or export before publication']}
    identity = None

    def save():
        nonlocal identity
        identity = f.write_json(summary, report, identity)

    try:
        save()
        for cycle in range(1, 4):
            for name, output, argv in stages(args, cycle):
                f.require(fingerprints(args) == pins, 'Source or runtime changed before stage')
                log = output.with_suffix('.log')
                omitted = report['cold_cache_unavailable'] if name.startswith('native-') and 'cold' in args.cache else None
                planned = argv
                if omitted:
                    start, end = argv.index('--cache') + 1, argv.index('--operations')
                    remaining = [cache for cache in argv[start:end] if cache != 'cold']
                    argv = [*argv[:start], *remaining, *argv[end:]] if remaining else None
                row = {'cycle': cycle, 'stage': name, 'argv': argv, 'output': str(output),
                       'log': str(log), 'status': 'pending', 'started_utc': datetime.now(timezone.utc).isoformat()}
                if omitted:
                    row.update(planned_argv=planned, omitted_cold_cache=omitted)
                report['stages'].append(row)
                if argv is None:
                    row.update(status='unavailable', reason='Requested cold cache is unavailable; no stage launched')
                    save()
                    continue
                save()
                try:
                    with log.open('xb') as stream:
                        row['status'] = 'running'
                        save()
                        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=stream,
                                                   stderr=subprocess.STDOUT, cwd=args.output_dir,
                                                   env=environment(args.node), check=False)
                    row.update(exit_code=completed.returncode, ended_utc=datetime.now(timezone.utc).isoformat())
                    row['outcome'], row['evidence'] = outcome(name, output)
                    row['fingerprints_unchanged'] = fingerprints(args) == pins
                    f.require(row['fingerprints_unchanged'], 'Source or runtime changed during stage')
                    f.require(safe_to_continue(name, completed.returncode, row['outcome'], row['evidence']),
                              'Stage did not finish with confirmed cleanup; stop and retain all evidence')
                    if row['outcome'].get('cold_cache_unavailable'):
                        report['cold_cache_unavailable'] = row['outcome']['cold_cache_unavailable']
                    row['status'] = 'complete' if row['outcome']['passed'] else 'complete_with_failures'
                    save()
                except BaseException as error:
                    row.update(status='stopped', error=f'{type(error).__name__}: {error}')
                    if 'exit_code' not in row:
                        row['completion_uncertain'] = True
                    raise
        report.update(status='complete', collection_passed=not report['cold_cache_unavailable'] and
                      all(row.get('outcome', {}).get('passed') is True for row in report['stages']),
                      ended_utc=datetime.now(timezone.utc).isoformat())
        save()
    except BaseException as error:
        report.update(status='stopped', collection_passed=False, error=f'{type(error).__name__}: {error}')
        try:
            save()
        except BaseException as secondary:
            print(f'Campaign checkpoint also failed: {secondary}', file=sys.stderr)
        raise
    return 0 if report['collection_passed'] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'scratch', 'output-dir', 'node', 'npm', 'npm-cache'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--samples', type=int, default=10)
    parser.add_argument('--cache', nargs='+', choices=('warm', 'cold'), default=['warm', 'cold'])
    args = parser.parse_args(argv)
    if not 10 <= args.samples <= 100 or len(args.cache) != len(set(args.cache)):
        parser.error('Use 10–100 samples and distinct cache selections')
    for name in ('binary', 'scratch', 'node', 'npm', 'npm_cache'):
        setattr(args, name, getattr(args, name).expanduser().resolve(strict=True))
    f.require(args.scratch.is_dir() and args.npm_cache.is_dir(), 'Scratch and offline npm cache must exist')
    output = args.output_dir.expanduser().absolute()
    args.output_dir = output.parent.resolve(strict=True) / output.name
    f.require(not os.path.lexists(args.output_dir), 'Choose a new campaign output directory')
    return collect(args)


if __name__ == '__main__':
    raise SystemExit(main())
