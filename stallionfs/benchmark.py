"""Installed entry point for disposable native comparisons."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
import time

from ._benchmark_cases import CASES

FIXTURES = ('tiny_4kib', 'large_64mib', 'flat_2000', 'nested_10000',
            'dependencies_100k', 'git_50k_2gb', 'cache_200k_10gb',
            'docs_5k_100mb', 'dataset_2k_50gb', 'scan_flat_20k',
            'scan_nested_20k', 'scan_deep40_20k')
TOOLS = ('/bin/cp', '/bin/mv', '/bin/rm', '/bin/chmod', '/usr/bin/ditto',
         '/usr/bin/rsync', '/usr/bin/time', '/usr/bin/find', '/usr/bin/stat')
GIB = 1024 ** 3
RUNTIME_FILES = frozenset(('fileops.py', 'native_suite.py', 'native_metrics.py',
    'native_correctness.py', 'native_fixtures.py', 'native_report.py', 'campaign.py',
    'scan.py', 'run.py', 'cli.py', 'fixture/package.json', 'fixture/package-lock.json',
    'fixture/check.cjs'))


def parser(commands):
    p = commands.add_parser('benchmark', help='Compare existing cases in disposable storage')
    p.add_argument('--list', action='store_true', help='List cases without running commands or writing files')
    p.add_argument('--full', action='store_true', help='Collect the full existing campaign; report required coverage gaps')
    p.add_argument('--fixtures', nargs='+', choices=FIXTURES, help='Select existing native fixtures')
    p.add_argument('--operations', nargs='+', choices=('copy', 'clone', 'move', 'delete', 'scan'))
    p.add_argument('--samples', type=int, choices=range(10, 101), default=10, metavar='N', help='Configurable phase pairs, 10–100; CLI delete timing uses 31 (default: 10)')
    p.add_argument('--scratch', type=Path, help='Existing parent for new disposable storage')
    p.add_argument('--jobs', type=int, choices=range(1, 5), default=4, help='Native workers, 1–4 (default: 4)')
    p.add_argument('--output', type=Path, help='New JSON summary file; default is inside the run directory')
    p.add_argument('--json', action='store_true', default=argparse.SUPPRESS, help='Print the JSON summary')
    p.add_argument('--node', type=Path, help='Full collection: Node 24+ executable')
    p.add_argument('--npm', type=Path, help='Full collection: npm bin/npm-cli.js')
    p.add_argument('--npm-cache', type=Path, help='Full collection: isolated offline npm cache')
    p.add_argument('--cache', nargs='+', choices=('warm', 'cold'), default=['warm'], help='Full collection cache modes; cold requests sudo purge')
    return p


def _catalog():
    return {'cases': [{'id': case['id'], 'required_set': case['required_set'],
                       'catalog_only': case['required_set'] in ('CLI-SCAN', 'CLI-VOLUMES', 'CLI-TINY')
                                       and case['id'] not in ('cli/delete/tiny_4kib', 'cli/clone/tiny_4kib')}
                      for case in CASES], 'quick': ['native/copy/tiny_4kib',
            'fileops/move/tiny_4kib', 'fileops/delete/tiny_4kib'],
            'full': 'Existing three-cycle collection, with required coverage gaps retained',
            'qualified': False}


def _resources():
    root = Path(__file__).with_name('_benchmark_runtime')
    path = root / 'manifest.json'
    if not path.is_file():
        raise RuntimeError('Installed benchmark resources are missing; reinstall the package')
    with path.open('rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise RuntimeError('Oversized installed benchmark manifest')
    manifest = json.loads(raw)
    if manifest.get('schema') != 1 or manifest.get('kind') != 'build-source provenance':
        raise RuntimeError('Invalid installed benchmark resources')
    if set(manifest.get('resources', {})) != RUNTIME_FILES:
        raise RuntimeError('Installed benchmark resource set changed')
    for name, expected in manifest['resources'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise RuntimeError('Invalid benchmark resource name')
        file = root / relative
        if not file.is_file() or file.is_symlink() or hashlib.sha256(file.read_bytes()).hexdigest() != expected:
            raise RuntimeError('Installed benchmark resource changed: ' + name)
    return root


def _new_output(path):
    if path.name in ('', '.', '..') or not path.parent.is_dir():
        raise ValueError('Output needs an existing parent and a new file name')
    for target in (path, path.with_name(path.name + '.journal'),
                   path.with_name(path.name + '.manifest'), path.with_suffix('.log'),
                   path.with_suffix('.partial.json'), path.with_name(path.name + '.partial')):
        if os.path.lexists(target):
            raise ValueError('Output already exists: ' + str(target))


def _environment():
    return {key: value for key, value in os.environ.items()
            if key not in ('PYTHONPATH', 'PYTHONHOME', 'NODE_OPTIONS', 'NODE_PATH')
            and not key.startswith('STALLIONFS_BENCHMARK_') and not key.lower().startswith('npm_config_')}


def _preflight(args):
    if sys.platform != 'darwin':
        raise RuntimeError('Installed comparisons currently require macOS/APFS')
    if args.full and (args.fixtures or args.operations or args.jobs != 4):
        raise ValueError('--full keeps the campaign selection and default workers; do not narrow it')
    if not args.full and any((args.node, args.npm, args.npm_cache)):
        raise ValueError('Node/npm inputs apply only to --full')
    if len(args.cache) != len(set(args.cache)) or (not args.full and args.cache != ['warm']):
        raise ValueError('Use distinct cache modes; quick comparisons use warm fixtures')
    fixtures, operations = args.fixtures or ['tiny_4kib'], args.operations or ['copy', 'move', 'delete']
    if len(fixtures) != len(set(fixtures)) or len(operations) != len(set(operations)):
        raise ValueError('Do not repeat fixtures or operations')
    scans = [name.startswith('scan_') for name in fixtures]
    if any(scans) and (not all(scans) or operations != ['scan']):
        raise ValueError('Scan fixtures require --operations scan without file operations')
    if 'scan' in operations and not all(scans):
        raise ValueError('Select existing scan fixtures for --operations scan')
    if 'copy' in operations and fixtures != ['tiny_4kib']:
        raise ValueError('Ordinary copy uses the existing tiny_4kib case')
    resources = _resources()
    entry = Path(sys.argv[0]).absolute()
    binary = ((entry.parent if entry.name == 'stallionfs-python'
               else Path(sysconfig.get_path('scripts'))) / 'stallionfs')
    helper = binary.with_name('stallionfs-python')
    missing = [str(path) for path in (binary, helper, *map(Path, TOOLS))
               if not path.is_file() or not os.access(path, os.X_OK)]
    if args.full:
        missing += ['--' + name.replace('_', '-') for name in ('node', 'npm', 'npm_cache')
                    if getattr(args, name) is None]
        if args.node and (not args.node.is_file() or not os.access(args.node, os.X_OK)):
            missing.append('executable --node')
        if args.npm and not args.npm.is_file():
            missing.append('npm --npm entrypoint')
        if args.npm_cache and (not args.npm_cache.is_dir() or args.npm_cache.is_symlink()):
            missing.append('isolated --npm-cache directory')
    if missing:
        raise RuntimeError('Missing prerequisites: ' + ', '.join(missing))
    if args.full:
        manifest = args.npm.parent.parent / 'package.json'
        if not manifest.is_file() or json.loads(manifest.read_text()).get('name') != 'npm':
            raise RuntimeError('Missing prerequisite: npm bin/npm-cli.js and package manifest')
        try:
            from ._benchmark_budget import command
            child = command([str(args.node), '--version'], timeout=5,
                            persist_success=False, output_limit=65536, environment=_environment())
            if child.returncode or int(child.stdout.decode().strip().removeprefix('v').split('.')[0]) < 24:
                raise RuntimeError('Missing prerequisite: Node 24 or newer')
            if 'cold' in args.cache:
                if not Path('/usr/sbin/purge').is_file():
                    raise RuntimeError('Missing prerequisite: /usr/sbin/purge')
                privilege = command(['/usr/bin/sudo', '-n', 'true'], timeout=5,
                                    persist_success=False, output_limit=65536, environment=_environment())
                if privilege.returncode:
                    raise RuntimeError('Cold collection requires existing noninteractive sudo purge access')
        except (subprocess.SubprocessError, ValueError) as error:
            raise RuntimeError('Cannot validate full collection prerequisites: ' + str(error)) from error
    parent = args.scratch or Path(tempfile.gettempdir())
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError('Scratch must be an existing directory, not a symlink')
    parent = parent.resolve(strict=True)
    if args.full and shutil.which('git') is None:
        raise RuntimeError('Missing prerequisite: Git')
    if args.output:
        _new_output(args.output.absolute())
    sizes = {'large_64mib': 64 * 1024**2, 'dependencies_100k': 102400000,
             'git_50k_2gb': 2000000000, 'cache_200k_10gb': 10000000000,
             'docs_5k_100mb': 100000000, 'dataset_2k_50gb': 50000000000}
    required = (220 * GIB if args.full else 4 * max((sizes.get(x, 0) for x in fixtures), default=0) + 2 * GIB)
    if shutil.disk_usage(parent).free < required:
        raise RuntimeError(f'Insufficient scratch space: need at least {required} free bytes')
    return resources, binary, parent, fixtures, operations


def _coverage(cache, *, collected=True):
    result = []
    for case in CASES:
        family = case['required_set']
        native = family.startswith('TREE-') or family == 'COMMAND-SCAN'
        collector = ('native-cli-clone' if case['id'] == 'cli/clone/tiny_4kib'
                     else 'native-cli-delete' if case['id'] == 'cli/delete/tiny_4kib'
                     else 'native-scan' if family == 'COMMAND-SCAN' else 'native-files' if native
                     else 'native-copy' if family == 'ORDINARY-COPY'
                     else 'scan-api' if family == 'API-SCAN' else 'workspaces' if family == 'WORKSPACE' else None)
        required = []
        outputs = (('api',) if family in ('API-SCAN', 'WORKSPACE') else
                   ('json',) if family == 'COMMAND-SCAN' else
                   ('plain',) if native or family == 'ORDINARY-COPY' else ('plain', 'json'))
        references = (('/bin/cp -cRp',) if case['id'] == 'cli/clone/tiny_4kib'
                      else ('/bin/rm -f',) if case['id'] == 'cli/delete/tiny_4kib'
                      else ('cp-clone', 'cp', 'ditto', 'rsync') if family == 'TREE-CLONE'
                      else ('bulk_serial-vs-posix', 'bulk-vs-posix') if family == 'API-SCAN'
                      else ('recorded-native-reference',))
        for mode in ('warm', 'cold'):
            for output in outputs:
                for reference in references:
                    for phase in ('timing', 'resources'):
                        selected_mode = mode in cache
                        if family == 'API-SCAN':
                            selected_mode |= mode == 'warm'
                        elif family == 'WORKSPACE':
                            selected_mode = mode == 'warm'
                        available = collected and collector is not None and selected_mode
                        available &= not (family == 'WORKSPACE' and mode == 'cold')
                        available &= not (family == 'WORKSPACE' and phase == 'resources')
                        policy = not (family == 'TREE-CLONE' and reference in ('cp-clone', 'cp', 'ditto', 'rsync'))
                        status = 'collected_unverified' if available else 'unavailable'
                        reason = 'Required cells are not independently accepted by collection completion'
                        if not available:
                            reason = 'No selected collector for this required cell'
                        elif not policy:
                            status, reason = 'inadmissible', 'Reference does not establish a mandatory-clone command contract'
                        required.append({'cache': mode, 'output': output, 'reference': reference,
                                         'phase': phase, 'status': status, 'reason': reason, 'win': False})
                        if family == 'API-SCAN':
                            required[-1]['collector'] = 'scan-api-cold' if mode == 'cold' else 'scan-api'
        result.append({'id': case['id'], 'required_set': family, 'collector': collector,
                       'catalog_only': collector is None,
                       'required_cells': required, 'qualified': False})
    return result


def _read_native(output):
    from ._benchmark_runtime.native_report import ReportJournal
    journal = ReportJournal.open_existing(output)
    try:
        journal.verify()
        state = journal.state
        comparisons = list(journal.iter_latest('comparisons'))
        return state, comparisons
    finally:
        journal.close()


def _collect(args, resources, binary, root, fixtures, operations):
    from ._benchmark_budget import command
    environment = _environment()
    receipts = root / 'receipts'
    receipts.mkdir(mode=0o700)
    environment.update(STALLIONFS_BENCHMARK_DEADLINE=str(time.monotonic() + (86400 if args.full else 600)),
                       STALLIONFS_BENCHMARK_RECEIPTS=str(receipts),
                       STALLIONFS_BENCHMARK_BINARY=str(binary.resolve()),
                       STALLIONFS_BENCHMARK_PACKAGE=str(Path(__file__).parent.resolve()),
                       PYTHONDONTWRITEBYTECODE='1')
    if args.full:
        argv = [sys.executable, '-B', str(resources / 'campaign.py'), '--binary', str(binary),
                '--scratch', str(root), '--output-dir', str(root / 'campaign'),
                '--samples', str(args.samples), '--cache', *args.cache,
                '--node', str(args.node.resolve()), '--npm', str(args.npm.resolve()),
                '--npm-cache', str(args.npm_cache.resolve())]
    else:
        argv = [sys.executable, '-B', str(resources / 'native_suite.py'), '--binary', str(binary),
                '--scratch', str(root), '--output', str(root / 'native.json'), '--samples', str(args.samples),
                '--runs', '1', '--cache', 'warm', '--jobs', str(args.jobs),
                '--fixtures', *fixtures, '--operations', *operations, '--copy-tools',
                *(['cp-clone', 'cp', 'ditto', 'rsync'] if 'clone' in operations else ['cp'])]
    receipt = {'log': str(root / 'collector.log')}
    log = (root / 'collector.log').open('xb')
    primary = None
    try:
        command(argv, timeout=(86410 if args.full else 610), environment=environment,
                cwd=root, output=log, persist_success=False, receipt=receipt)
    except BaseException as error:
        primary = error
        raise
    finally:
        for closeout in (log.close, lambda: (root / 'collector-receipt.json').write_text(
                json.dumps(receipt, indent=2) + '\n')):
            try:
                closeout()
            except BaseException as secondary:
                if primary is None:
                    primary = secondary
                else:
                    primary.add_note('Collector evidence closeout also failed: ' + str(secondary))
        if primary is not None and sys.exc_info()[1] is None:
            raise primary
    if receipt.get('completion_uncertain'):
        raise RuntimeError('Collector completion uncertain; all run files retained')
    if receipt.get('exit_code') != 0:
        raise RuntimeError('Collector failed; see its retained receipt and partial reports')
    if args.full:
        path = root / 'campaign/campaign.json'
        state = json.loads(path.read_text()) if path.is_file() else {}
        stages = state.get('stages', [])
        planned = ('native-files', 'native-copy', 'native-cli-delete', 'native-cli-clone', 'native-scan', 'scan-api',
                   *(('scan-api-cold',) if 'cold' in args.cache else ()), 'workspaces')
        expected = [(cycle, stage) for cycle in range(1, 4) for stage in planned]
        complete = (state.get('status') == 'complete'
                    and [(row.get('cycle'), row.get('stage')) for row in stages] == expected
                    and all(row.get('outcome', {}).get('passed') is True
                            and row.get('outcome', {}).get('cleanup_passed') is True for row in stages))
        if not complete:
            raise RuntimeError('Full collector did not complete correctness and cleanup; see retained campaign')
        return {'status': 'incomplete', 'collection_complete': True, 'required_coverage_complete': False,
                'qualified': False, 'cases': _coverage(args.cache), 'comparisons': [],
                'campaign': str(path), 'always_warm_collectors': ['workspaces'], 'exit_code': 2}
    state, comparisons = _read_native(root / 'native.json')
    if not (state.get('status') == 'complete' and state.get('passed') is True
            and state.get('cleanup_passed') is True and not state.get('retained_fixture')):
        raise RuntimeError('Comparison failed correctness or cleanup; see retained report')
    return {'status': 'complete', 'collection_complete': True, 'required_coverage_complete': False,
            'qualified': False, 'comparisons': comparisons, 'report': str(root / 'native.json'), 'exit_code': 0}


def run(args):
    # This branch must remain ahead of path resolution, Store and native imports.
    if args.list:
        value = _catalog()
        print(json.dumps(value) if args.json else '\n'.join(
            case['id'] + (' (catalog only)' if case['catalog_only'] else '') for case in value['cases']))
        return 0
    root = None
    try:
        resources, binary, parent, fixtures, operations = _preflight(args)
        root = Path(tempfile.mkdtemp(prefix='sfs-benchmark-', dir=parent))
        os.chmod(root, 0o700)
        result = _collect(args, resources, binary, root, fixtures, operations)
    except KeyboardInterrupt:
        result = {'status': 'interrupted', 'collection_complete': False, 'qualified': False, 'exit_code': 130}
    except (OSError, ValueError, RuntimeError) as error:
        result = {'status': 'failed', 'error': str(error), 'collection_complete': False,
                  'qualified': False, 'exit_code': 1}
        cause = error
        for _ in range(8):
            if isinstance(cause, KeyboardInterrupt):
                result.update(status='interrupted', exit_code=130)
                break
            cause = getattr(cause, '__cause__', None)
            if cause is None:
                break
        if hasattr(error, 'receipt'):
            result['command_receipt'] = error.receipt
    if args.full and 'cases' not in result:
        result['cases'] = _coverage(args.cache, collected=False)
        result['required_coverage_complete'] = False
    result['run_directory'] = str(root) if root else None
    result['scope'] = 'Full collection with required gaps' if args.full else 'Selected warm comparisons'
    result['limits'] = ['Not release qualification', 'RSS is the maximum individual child peak, not whole-system memory',
                        'cp -c permits fallback; sharing observations do not change that contract',
                        'Completion uncertainty retains storage; descendant containment is not established']
    if root is not None:
        # The owned copy survives an explicit-output collision or write failure.
        targets = ([args.output.absolute()] if args.output else []) + [root / 'summary.json']
        for output in targets:
            try:
                fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'w') as stream:
                    json.dump(result, stream, indent=2)
                    stream.write('\n')
            except OSError as error:
                result.update(status='failed', error='Cannot write summary: ' + str(error), exit_code=1)
    if args.json:
        print(json.dumps(result))
    else:
        print('Benchmark ' + result['status'] + (': ' + result['error'] if result.get('error') else ''))
        if root:
            print('Results: ' + str(root))
        for item in result.get('comparisons', []):
            for metric in ('wall_s', 'cpu_s', 'rss_bytes'):
                value = item.get('metrics', {}).get(metric)
                if value and value.get('native') and value.get('candidate'):
                    print(f"{item['operation']} {item['fixture']} reference={item.get('reference', 'unrecorded')} "
                          f"phase={item.get('phase', 'unrecorded')} {metric}: "
                          f"native {value['native']['median']:.6g}, sfs {value['candidate']['median']:.6g} "
                          f"({value['decision']})")
    return result['exit_code']
