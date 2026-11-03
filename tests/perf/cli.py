"""Compare installed CLI cases, including startup, on private fixtures."""
import argparse
import base64
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from math import comb
import os
from pathlib import Path
import platform
import random
import shutil
import stat
import statistics
import subprocess
import sys
import tempfile
import time

import fileops as f
import native_correctness
import native_metrics
import native_report
import native_suite

from fileops import (REPO, ChildCompletionUnknown, command, cpu_usage, digest, fingerprint_sources, manifest,
                     no_mounts_below, remove_fixture, require, scratch_volume,
                     verify_clone, write_new_json)


SEED = 20261007
APPLE = {"clone": ["/bin/cp", "-cRp"], "move": ["/bin/mv", "-n"], "delete": ["/bin/rm", "-f"]}
MACHO = {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe",
         b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}


def installed(binary):
    """Locate an installed venv runtime without importing it into this process."""
    require(binary.is_file() and os.access(binary, os.X_OK), "CLI must be executable")
    with binary.open("rb") as stream:
        require(stream.read(4) in MACHO, "CLI must be an installed native executable")
    helper, python = binary.with_name("stallionfs-python"), binary.with_name("python")
    require(helper.is_file() and python.is_file() and (binary.parent.parent / "pyvenv.cfg").is_file(),
            "Install each CLI into a separate virtual environment with its Python helper")
    info = json.loads(command([python, "-I", "-B", "-c",
        "import json,sys,stallionfs; print(json.dumps({'package':stallionfs.__file__,"
        "'version':stallionfs.__version__,'python':'.'.join(map(str,sys.version_info[:3]))}))"]).stdout)
    package = Path(info["package"]).resolve().parent
    require(package.is_relative_to(binary.parent.parent), "Package resolved outside its virtual environment")
    return {"binary": binary, "helper": helper, "python": python, "package": package,
            "version": info["version"], "python_version": info["python"]}


def runtime_hashes(runtime):
    paths = {"bin/stallionfs": runtime["binary"], "bin/stallionfs-python": runtime["helper"],
             "bin/python": runtime["python"]}
    paths.update({"package/" + path.relative_to(runtime["package"]).as_posix(): path
                  for path in runtime["package"].rglob("*")
                  if path.is_file() and path.suffix in {".py", ".so"}})
    return {name: digest(path) for name, path in sorted(paths.items())}


def source_hashes():
    return {**fingerprint_sources(), "tests/perf/cli.py": digest(Path(__file__))}


def measure(arguments, environment):
    # Same process options and CPU accounting as fileops.py; retain output for validation.
    before, before_error = cpu_usage()
    started_utc = datetime.now(timezone.utc).isoformat()
    start = time.perf_counter()
    result = subprocess.run([str(arg) for arg in arguments], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=120, umask=0o077, env=environment)
    wall = time.perf_counter() - start
    after, after_error = cpu_usage()
    row = {"started_utc": started_utc, "wall_s": wall, "exit_code": result.returncode}
    if before is None or after is None:
        row.update(cpu_s=None, cpu_self_s=None, cpu_children_s=None,
                   cpu_unavailable=before_error or after_error)
    else:
        row.update({key: after[key] - before[key] for key in before})
        row["cpu_self_s"] = row["self_user_s"] + row["self_system_s"]
        row["cpu_children_s"] = row["children_user_s"] + row["children_system_s"]
        row["cpu_s"] = row["cpu_self_s"] + row["cpu_children_s"]
    return row, result


def scan_text(values):
    return (f"{values['files']} files, {values['directories']} directories, "
            f"{values['symlinks']} symlinks, {values['other']} other entries\n"
            f"{values['logical_bytes']} logical bytes; {values['skipped_mounts']} nested volumes skipped\n").encode()


def volumes_text(values):
    return "".join(f"{row['filesystem']}\t{'read-only' if row['readonly'] else 'writable'}\t{row['path']}\n"
                   for row in values).encode()


def make_fixtures(base):
    tiny, empty, nested = base / "tiny", base / "empty", base / "nested"
    tiny.write_bytes(bytes(range(256)) * 16)
    tiny.chmod(0o640)
    empty.mkdir()
    nested.mkdir()
    for index in range(1000):
        parent = nested / f"group-{index // 100:02}"
        parent.mkdir(exist_ok=True)
        (parent / f"file-{index:04}").write_bytes(index.to_bytes(4, "little") + b"x" * 508)
    (nested / "empty").mkdir()
    (nested / "space \n café 🐎").write_bytes(b"hello")
    (nested / "directory-link").symlink_to("empty", target_is_directory=True)
    (nested / "dangling-link").symlink_to("absent")
    (nested / "outside-link").symlink_to("../outside-sentinel")
    os.mkfifo(nested / "pipe")
    with (nested / "sparse").open("wb") as stream:
        stream.truncate(1 << 20)
    os.link(nested / "sparse", nested / "hard-link")
    (base / "outside-sentinel").write_bytes(b"keep outside linked trees\n")
    expected = {
        "empty": dict(files=0, directories=0, symlinks=0, other=0, logical_bytes=0, skipped_mounts=0),
        "nested_1000": dict(files=1003, directories=11, symlinks=3, other=1,
                            logical_bytes=512000 + 5 + (2 << 20), skipped_mounts=0)}
    return {"tiny_4kib": tiny, "empty": empty, "nested_1000": nested}, expected


def content_manifest(path):
    """Use the shared manifest while recording FIFO metadata without opening it."""
    if not path.is_dir():
        return manifest(path)
    result = {}
    for item in [path, *path.rglob("*")]:
        relative = item.relative_to(path).as_posix()
        info = item.lstat()
        if stat.S_ISFIFO(info.st_mode):
            row = {"kind": "fifo", "mode": stat.S_IMODE(info.st_mode)}
        elif stat.S_ISDIR(info.st_mode):
            row = {"kind": "directory", "mode": stat.S_IMODE(info.st_mode)}
        else:
            row = manifest(item)[""]
        result[relative] = row
    return result


def summarize(rows):
    result = {}
    for case in sorted({row["case"] for row in rows}):
        result[case] = {}
        for method in sorted({row["method"] for row in rows if row["case"] == case}):
            selected = [row for row in rows if row["case"] == case and row["method"] == method and not row["warmup"]]
            result[case][method] = {key: statistics.median(row[key] for row in selected)
                                   if all(row[key] is not None for row in selected) else None
                                   for key in ("wall_s", "cpu_s", "cpu_self_s", "cpu_children_s")}
    return result


def native_comparisons(medians):
    """Name the measured plain Apple reference, including for JSON candidate output."""
    result = {}
    for operation, arguments in APPLE.items():
        reference_case = f"{operation}/tiny_4kib/plain"
        reference = medians[reference_case]["apple"]
        for output in ("plain", "json"):
            case = f"{operation}/tiny_4kib/{output}"
            candidate = medians[case]["candidate"]
            result[case] = {
                "reference_command": " ".join(arguments) + (" PATH" if operation == "delete" else " SOURCE DESTINATION"),
                "reference_case": reference_case, "reference_output": "plain", "candidate_output": output,
                "paired": output == "plain",
                "wall_speedup": reference["wall_s"] / candidate["wall_s"],
                "cpu_speedup": reference["cpu_s"] / candidate["cpu_s"]
                    if reference["cpu_s"] is not None and candidate["cpu_s"] else None,
                "cpu_speedup_metric": "cpu_s: benchmark runner plus reaped command CPU",
                "command_cpu_speedup": reference["cpu_children_s"] / candidate["cpu_children_s"]
                    if reference["cpu_children_s"] is not None and candidate["cpu_children_s"] else None,
            }
    return result


def paired_plain_effects(rows):
    """Compare the fixed 31 paired plain file-command rounds; never pair JSON output."""
    result = {}
    count, lower, target = 31, 10, 0.00001
    coverage = 1 - 2 * sum(comb(count, rank) for rank in range(lower)) / 2**count
    for operation in APPLE:
        case = f"{operation}/tiny_4kib/plain"
        pairs = {method: {} for method in ("apple", "candidate")}
        for row in rows:
            if row["case"] != case or row["warmup"] or row["method"] not in pairs:
                continue
            rounds = pairs[row["method"]]
            require(row["round"] not in rounds, f"{case}: duplicate measured pair")
            rounds[row["round"]] = row
        require(all(set(rounds) == set(range(1, count + 1)) for rounds in pairs.values()),
                f"{case}: missing measured pair; expected rounds 1 through 31")
        effect = result[case] = {"pairs": count, "lower_order_statistic": lower,
                                "interval_coverage": coverage, "required_wall_saving_s": target}
        for metric in ("wall_s", "cpu_children_s"):
            if any(row[metric] is None for rounds in pairs.values() for row in rounds.values()):
                effect[metric] = None
                continue
            savings = sorted(pairs["apple"][number][metric] - pairs["candidate"][number][metric]
                             for number in range(1, count + 1))
            effect[metric] = {"median_saving_s": statistics.median(savings),
                              "median_saving_interval_s": [savings[lower - 1], savings[-lower]],
                              "pairs_with_lower_candidate_value": sum(value > 0 for value in savings)}
            if metric == "wall_s":
                effect["pairs_meeting_wall_target"] = sum(value >= target for value in savings)
                effect["wall_target_demonstrated"] = savings[lower - 1] >= target
    return result, {
        "cpu": "cpu_children_s is completed-command user plus system CPU, excluding benchmark-runner CPU.",
        "difference": "Apple minus StallionFS within the same measured round; positive values favor StallionFS.",
        "interval": "Distribution-free two-sided order-statistic confidence interval for the median paired difference, assuming independent rounds. Coverage is at least 95%; repeated host conditions can correlate rounds.",
        "memory": "Memory is measured separately; these effects do not establish a memory advantage.",
        "scope": "Plain single-file cases only. JSON commands use an unpaired plain Apple reference and are excluded from this paired analysis."
    }



CLI_DELETE_FIXTURE_POLICY = 'cli-delete-uf-tracked-v1'
# Darwin sys/stat.h defines this flag even when Python's stat module omits it.
DARWIN_UF_TRACKED = 0x00000040
_DARWIN_FCHFLAGS = None


def _fchflags(descriptor, flags):
    """Call Darwin's descriptor flag setter with its public C signature."""
    global _DARWIN_FCHFLAGS
    require(sys.platform == 'darwin', 'Tracked CLI fixtures require Darwin fchflags')
    if _DARWIN_FCHFLAGS is None:
        library = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        setter = library.fchflags
        setter.argtypes = [ctypes.c_int, ctypes.c_uint32]
        setter.restype = ctypes.c_int
        _DARWIN_FCHFLAGS = setter
    result = _DARWIN_FCHFLAGS(descriptor, flags)
    if result == -1:
        code = ctypes.get_errno()
        raise OSError(code, 'fchflags failed: ' + os.strerror(code))
    require(result == 0, 'Unexpected fchflags return value')


def initialize_tracked_delete_operand(target, root_identity, source_identity, evidence):
    """Initialize only a fresh owned independent operand before its prepared snapshot."""
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size',
              'st_mtime_ns', 'st_ctime_ns', 'st_flags')
    stable = fields[:8]
    def metadata(info):
        return {name: getattr(info, name, None) for name in fields}
    descriptor = None
    evidence.update(policy=CLI_DELETE_FIXTURE_POLICY, status='running', descriptor_closed=False)
    try:
        require(target.is_absolute() and target.name == 'target', 'Invalid tracked delete operand')
        root = target.parent.lstat()
        require(stat.S_ISDIR(root.st_mode) and stat.S_IMODE(root.st_mode) == 0o700
                and root.st_uid == os.getuid() and (root.st_dev, root.st_ino) == root_identity,
                'Tracked operand root changed')
        initial = metadata(target.lstat())
        evidence['initial_metadata'] = dict(initial)

        def valid(value):
            require(stat.S_ISREG(value['st_mode']) and stat.S_IMODE(value['st_mode']) == 0o640
                    and value['st_size'] == 4096 and value['st_nlink'] == 1
                    and value['st_uid'] == os.getuid() and value['st_dev'] == root_identity[0]
                    and (value['st_dev'], value['st_ino']) != source_identity,
                    'Tracked operand must be an owned independent regular file')
            require(value['st_flags'] in (0, DARWIN_UF_TRACKED), 'Unexpected initial tracked operand flags')

        valid(initial)
        descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        opened = metadata(os.fstat(descriptor))
        valid(opened)
        require(all(opened[name] == initial[name] for name in stable),
                'Tracked operand identity or metadata changed while opening')
        _fchflags(descriptor, DARWIN_UF_TRACKED)
        final = metadata(os.fstat(descriptor))
        evidence['final_metadata'] = dict(final)
        require(final['st_flags'] == DARWIN_UF_TRACKED
                and all(final[name] == initial[name] for name in stable),
                'Tracked operand initialization changed protected metadata or flags')
        require(metadata(target.lstat()) == final, 'Tracked operand path changed during initialization')
    except BaseException as error:
        evidence.update(status='failed', error=f'{type(error).__name__}: {error}')
        if descriptor is not None:
            try:
                os.close(descriptor)
                evidence['descriptor_closed'] = True
            except BaseException as close_error:
                evidence['close_error'] = f'{type(close_error).__name__}: {close_error}'
                error.add_note('Tracked operand close failed: ' + evidence['close_error'])
        raise
    try:
        os.close(descriptor)
    except BaseException as error:
        evidence.update(status='failed', close_error=f'{type(error).__name__}: {error}')
        raise
    evidence.update(status='complete', descriptor_closed=True)
    return final


def native_delete_pins(runtime, cache):
    sources = source_hashes()
    sources.update({Path(module.__file__).name: digest(Path(module.__file__))
                    for module in (f, native_metrics, native_report, native_suite)})
    result = {'runtime': runtime_hashes(runtime), 'source': sources,
              'python': digest(Path(sys.executable).resolve()),
              'tools': {name: digest(Path(name)) for name in ('/bin/rm', '/bin/cp', '/usr/bin/time')}}
    if 'cold' in cache:
        result['cold_tools'] = f.cold_tool_provenance()
    return result


def native_delete_comparison(rows, phase, samples):
    require(all(row.get('fixture_policy') == CLI_DELETE_FIXTURE_POLICY for row in rows),
            'CLI delete fixture policies differ or are untagged')
    require(all(row['method'] in ('native', 'candidate') for row in rows), 'Unexpected CLI delete method')
    expected = set(range(1, 32 if phase == 'timing' else samples + 1))
    methods = {}
    for method in ('native', 'candidate'):
        warmups = [row for row in rows if row['method'] == method and row['warmup']]
        require((len(warmups) == 1 and warmups[0]['pair_id'] == 0) if phase == 'timing' else not warmups,
                'Incorrect planned CLI delete warmup')
        selected = [row for row in rows if row['method'] == method and not row['warmup']]
        ids = [row['pair_id'] for row in selected]
        require(all(type(value) is int for value in ids) and len(ids) == len(expected)
                and set(ids) == expected, 'Incomplete or duplicate planned CLI delete pairs')
        require(all(row['phase'] == phase and row.get('ok') is True and row.get('validated') is True
                    and not row.get('completion_uncertain') for row in selected + warmups),
                'Invalid planned CLI delete measurement')
        methods[method] = selected
    return {metric: native_metrics.compare_paired(methods['native'], methods['candidate'], metric)
            for metric in (('wall_s', 'cpu_s') if phase == 'timing' else ('rss_bytes',))}


def native_delete(args):
    """Collect only the existing CLI tiny-delete case against fresh rm calls."""
    require(platform.system() == 'Darwin', 'This comparison requires macOS')
    scratch = args.scratch.expanduser().resolve(strict=True)
    output = args.output.expanduser().absolute()
    require(scratch.is_dir() and output.parent.is_dir(), 'Scratch and output parent must exist')
    require(shutil.disk_usage(scratch).free >= 256 * 1024**2, 'At least 256 MiB free is required')
    runtime = installed(args.candidate.expanduser().resolve(strict=True))
    binary = runtime['binary']
    pins = native_delete_pins(runtime, args.cache)
    inventory = json.loads(command([binary, '--json', 'volumes']).stdout)
    volume = scratch_volume(inventory, scratch)
    report = {'schema': 1, 'case_id': 'cli/delete/tiny_4kib', 'fixture_policy': CLI_DELETE_FIXTURE_POLICY,
              'status': 'running', 'passed': False,
              'qualified': False, 'all_metrics_won': False, 'cleanup_passed': False,
              'timing_pairs': 31, 'timing_warmup_id': 0, 'resource_pairs': args.samples,
              'cache': args.cache, 'pins': pins, 'volume': volume, 'cold_cache_unavailable': None,
              'cache_condition': 'Full source and candidate-based mount checks precede conditioning. After conditioning, identical root/operand metadata checks precede both methods without candidate execution or fixture file-content reads. Fully cold metadata residency is not established.',
              'limits': ['Only the original 4 KiB/0640 CLI fixture is scored; this is not the enriched native-delete case.',
                         'Each fresh owned operand is initialized once to UF_TRACKED=64 before its prepared snapshot and outside measurement; deletion cost is not equivalent to historical untracked or untagged fixtures.',
                         'Timing includes command startup; CPU is completed-command/reaped-child CPU from native_metrics, not legacy harness-plus-child cpu_s.',
                         'RSS is the measured individual-process peak, not simultaneous process-tree or whole-system memory. Footprint is unavailable.',
                         'JSON candidate calls are independently paired with fresh plain-output rm calls.',
                         'Purge conditioning does not establish complete OS/device-cache eviction.',
                         'After conditioning only root/operand metadata is checked; mount checks use the candidate before conditioning and after measurement. Stable owned trees are required; cache residency is not guaranteed.',
                         'Unreadable cold-tool contents remain unverified; matching metadata establishes observed identity stability only.',
                         'Stable owned fixtures only; concurrent hostile path replacement is not contained.',
                         'No release qualification or tiny-command saving target is established by collection.']}
    journal = native_report.ReportJournal(output)
    journal_failed = False
    counters = dict.fromkeys(('rows', 'preparation', 'comparisons', 'unavailable'), 0)
    base = None
    cleaned = False

    def checkpoint():
        nonlocal journal_failed
        try:
            journal.checkpoint(report)
        except BaseException:
            journal_failed = True
            raise

    def record(kind, value, index=None):
        nonlocal journal_failed
        if index is None:
            index = counters[kind]
            counters[kind] += 1
        try:
            journal.append(kind, index, value)
        except BaseException:
            journal_failed = True
            raise
        return index

    try:
        checkpoint()
        base = Path(tempfile.mkdtemp(prefix='stallionfs-cli-delete-', dir=scratch))
        base.chmod(0o700)
        identity = base.lstat()
        report['fixture_root'] = str(base)
        checkpoint()
        roots, _ = make_fixtures(base)
        require(roots == {'tiny_4kib': base / 'tiny', 'empty': base / 'empty', 'nested_1000': base / 'nested'},
                'CLI fixture roots differ from the existing case')
        tiny = roots['tiny_4kib'].lstat()
        require(stat.S_ISREG(tiny.st_mode) and stat.S_IMODE(tiny.st_mode) == 0o640
                and roots['tiny_4kib'].read_bytes() == bytes(range(256)) * 16,
                'CLI tiny fixture bytes or mode differ')
        expected = {name: content_manifest(path) for name, path in roots.items()}
        identities = {name: (path.lstat().st_dev, path.lstat().st_ino) for name, path in roots.items()}
        report['fixtures'] = {name: {'manifest_sha256': hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
                                     'root_identity': identities[name]} for name, value in expected.items()}
        source = roots['tiny_4kib']
        target = base / 'target'
        unused_store = base / 'unused-store'
        environment = dict(os.environ, STALLIONFS_HOME=str(unused_store), PYTHONDONTWRITEBYTECODE='1')
        environment.pop('PYTHONPATH', None)
        environment.pop('PYTHONHOME', None)

        def owned(*, mounts=True):
            current = base.lstat()
            require(stat.S_ISDIR(current.st_mode) and stat.S_IMODE(current.st_mode) == 0o700
                    and current.st_uid == os.getuid()
                    and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino),
                    'Private fixture root changed; preserve it')
            if mounts:
                no_mounts_below(binary, base)

        def sources():
            owned()
            require(not os.path.lexists(unused_store), 'Command created an unnecessary store')
            require((base / 'outside-sentinel').read_bytes() == b'keep outside linked trees\n', 'Sentinel changed')
            for name, path in roots.items():
                info = path.lstat()
                require((info.st_dev, info.st_ino) == identities[name]
                        and content_manifest(path) == expected[name], 'CLI source fixture changed: ' + name)

        def operand(prepared=None, *, contents=True, mounts=True, stage=None):
            owned(mounts=mounts)
            require(target.is_absolute() and target.parent == base and target.name == 'target', 'Invalid delete operand')
            info = target.lstat()
            require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_nlink == 1,
                    'Delete operand must be an independent regular file')
            require((info.st_dev, info.st_ino) != identities['tiny_4kib'], 'Delete operand aliases protected source')
            metadata = {name: getattr(info, name, None) for name in (
                'st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size',
                'st_mtime_ns', 'st_ctime_ns', 'st_flags')}
            if prepared is not None and metadata != prepared:
                mismatch = {'stage': stage, 'path': str(target), 'preparation_id': setup_id,
                            'row_id': row_id, 'operation': {name: row[name] for name in
                                ('case_id', 'output', 'cache', 'phase', 'pair_id', 'method', 'warmup')},
                            'expected': dict(prepared), 'observed': dict(metadata),
                            'changed_fields': sorted(name for name in metadata if metadata[name] != prepared[name])}
                error = RuntimeError('Delete operand metadata changed at ' + stage)
                error.operand_metadata_mismatch = mismatch
                error.add_note('Operand metadata comparison: ' + json.dumps(mismatch, sort_keys=True))
                raise error
            if contents:
                require(content_manifest(target) == expected['tiny_4kib'], 'Delete operand differs from CLI fixture')
            return metadata

        rng = random.Random(SEED)
        for form in ('plain', 'json'):
            for cache in args.cache:
                for phase in ('timing', 'resources'):
                    key = {'case_id': report['case_id'], 'fixture_policy': CLI_DELETE_FIXTURE_POLICY,
                           'output': form, 'cache': cache, 'phase': phase,
                           'reference': '/bin/rm -f', 'reference_output': 'plain', 'paired': True}
                    if cache == 'cold' and report['cold_cache_unavailable']:
                        record('unavailable', key | {'reason': report['cold_cache_unavailable']})
                        checkpoint()
                        continue
                    rows = []
                    denied = False
                    rounds = range(32) if phase == 'timing' else range(1, args.samples + 1)
                    for pair_id in rounds:
                        order = ['native', 'candidate']
                        rng.shuffle(order)
                        for method in order:
                            sources()
                            require(not os.path.lexists(target), 'Stale delete operand')
                            setup = key | {'pair_id': pair_id, 'method': method,
                                           'argv': ['/bin/cp', '-cRp', str(source), str(target)], 'validated': False}
                            setup_id = record('preparation', setup)
                            report['active_operation'] = setup
                            checkpoint()
                            completed = command(setup['argv'], check=False, timeout=120, environment=environment)
                            setup.update(exit_code=completed.returncode,
                                stdout_b64=base64.b64encode(completed.stdout).decode(),
                                stderr_b64=base64.b64encode(completed.stderr).decode())
                            record('preparation', setup, setup_id)
                            require(completed.returncode == 0, 'CLI operand setup failed; preserve fixture')
                            verify_clone(source, target, expected['tiny_4kib'])
                            sources()
                            setup['tracked_initialization'] = {}
                            try:
                                initialized = initialize_tracked_delete_operand(target,
                                    (identity.st_dev, identity.st_ino), identities['tiny_4kib'],
                                    setup['tracked_initialization'])
                                prepared = operand()
                                setup['operand_metadata'] = dict(prepared)
                                setup['operand_metadata_stage'] = 'before_content_validation'
                                require(prepared == initialized,
                                        'Tracked operand changed before prepared snapshot')
                            except BaseException as error:
                                try:
                                    record('preparation', setup, setup_id)
                                except BaseException as journal_error:
                                    error.add_note('Tracked preparation reporting failed: ' + repr(journal_error))
                                raise
                            setup['validated'] = True
                            record('preparation', setup, setup_id)
                            argv = ['/bin/rm', '-f', str(target)] if method == 'native' else [
                                str(binary), *(['--json'] if form == 'json' else []), 'delete', str(target)]
                            row = key | {'pair_id': pair_id, 'preparation_id': setup_id,
                                         'warmup': phase == 'timing' and pair_id == 0,
                                         'method': method, 'argv': argv, 'ok': False, 'validated': False}
                            row_id = record('rows', row)
                            report['active_operation'] = row
                            checkpoint()
                            sources()
                            operand(prepared, stage='before_conditioning')
                            conditioning = native_suite.cache_prepare(cache, 120)
                            row['cache_receipt'] = conditioning
                            if cache == 'cold':
                                code = conditioning.get('exit_code')
                                require(type(code) is int and code >= 0, 'Purge did not establish normal completion')
                                if code:
                                    report['cold_cache_unavailable'] = 'cache purge unavailable; no further purge retries'
                                    report['cold_cache_receipt'] = conditioning
                                    row['unavailable'] = report['cold_cache_unavailable']
                                    record('rows', row, row_id)
                                    sources()
                                    operand(prepared, stage='denial_closeout')
                                    require(native_delete_pins(runtime, args.cache) == pins, 'CLI runtime or tool provenance changed')
                                    remove_fixture(target)
                                    record('unavailable', key | {'reason': report['cold_cache_unavailable']})
                                    report.pop('active_operation', None)
                                    checkpoint()
                                    denied = True
                                    break
                            operand(prepared, contents=False, mounts=False, stage='after_conditioning')
                            receipt = native_metrics.collect(argv, timeout_s=120, env=environment, phase=phase)
                            row.update(receipt)
                            record('rows', row, row_id)
                            checkpoint()
                            require(not row.get('completion_uncertain') and row.get('ok') is True
                                    and row.get('exit_code') == 0, 'CLI measurement failed or uncertain')
                            stderr = base64.b64decode(row['stderr_b64'], validate=True)
                            require(not (native_metrics.time_diagnostics(stderr) if phase == 'resources' else stderr),
                                    'Delete command emitted diagnostics')
                            stdout = base64.b64decode(row['stdout_b64'], validate=True)
                            if method == 'candidate' and form == 'json':
                                require(json.loads(stdout) == {'path': str(target)}, 'CLI delete JSON contract differs')
                            else:
                                require(stdout == b'', 'Delete command output differs')
                            require(not os.path.lexists(target), 'Delete did not complete before returning')
                            sources()
                            if phase == 'resources':
                                require(type(row.get('rss_bytes')) is int and row['rss_bytes'] > 0, 'Peak RSS unavailable')
                            row['validated'] = True
                            record('rows', row, row_id)
                            rows.append(row)
                            report.pop('active_operation', None)
                            checkpoint()
                        if denied:
                            break
                    if not denied:
                        record('comparisons', key | {'metrics': native_delete_comparison(rows, phase, args.samples),
                                                     'footprint': 'unavailable'})
                        checkpoint()
        sources()
        report['source_checks_passed'] = True
        require(not os.path.lexists(target), 'Unconsumed delete operand remains')
        require(native_delete_pins(runtime, args.cache) == pins, 'CLI runtime or tool provenance changed')
        checkpoint()
        try:
            journal.verify()
        except BaseException:
            journal_failed = True
            raise
        owned()
        remove_fixture(base)
        cleaned = True
        report.update(status='complete', passed=report['cold_cache_unavailable'] is None, cleanup_passed=True)
        if 'cold' in args.cache:
            report['cold_tool_identity_verified'] = True
            report['cold_tool_content_verified'] = all(row['content_hash_status'] == 'available'
                and row['sha256'] is not None for row in pins['cold_tools'].values())
        if report['cold_cache_unavailable']:
            report['denial_runtime_verified'] = True
        checkpoint()
        journal.finish(report)
    except BaseException as error:
        report.update(status='failed', passed=False, error=f'{type(error).__name__}: {error}')
        if hasattr(error, 'receipt'):
            report['command_receipt'] = error.receipt
        if base is not None and not cleaned:
            report['retained_fixture'] = str(base)
        mismatch = getattr(error, 'operand_metadata_mismatch', None)
        if mismatch is not None:
            report['operand_metadata_mismatch'] = mismatch
            row['operand_metadata_mismatch'] = mismatch
        if not journal_failed:
            try:
                if mismatch is not None:
                    record('rows', row, row_id)
                checkpoint()
                journal.finish(report)
            except BaseException as secondary:
                error.add_note('Report closeout also failed: ' + str(secondary))
        raise
    finally:
        primary = sys.exc_info()[1]
        try:
            journal.close()
        except BaseException as secondary:
            if primary is None:
                raise
            primary.add_note('Journal close also failed: ' + str(secondary))
    return 0 if report['passed'] else 1


CLI_CLONE_FIXTURE_POLICY = 'cli-clone-acl-absent-v1'
_CLONE_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size',
                 'st_mtime_ns', 'st_ctime_ns', 'st_flags')
# Parent link accounting can change with child entries; full precommand snapshots still include it.
_CLONE_PARENT_SECURITY = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_flags')


def _clone_metadata(info):
    return {name: getattr(info, name, None) for name in _CLONE_FIELDS}


def _clone_parent_compare(expected, observed, fields, *, stage, path, diagnostic=None, message, error=None):
    if all(observed[name] == expected[name] for name in fields):
        return
    mismatch = {'expected': dict(expected), 'observed': dict(observed),
                'compared_fields': list(fields),
                'differing_fields': [name for name in fields if observed[name] != expected[name]],
                'stage': stage, 'path': str(path),
                'preparation_id': None, 'row_id': None, **(diagnostic or {})}
    # Freeze the compared values before any failure-report I/O can fail or mutate a payload.
    snapshot = json.dumps(mismatch, sort_keys=True)
    if error is None:
        error = RuntimeError(message)
    error.clone_parent_metadata_mismatch_json = snapshot
    error.add_note('Clone parent metadata comparison: ' + snapshot)
    raise error


def _clone_absent_acl(path):
    observed = native_correctness._acl(path)
    require(observed == {'text_hex': None, 'unavailable': None},
            'CLI clone requires an observed absent extended ACL: ' + str(path))
    return observed


def clone_admission(source, parent, source_identity, parent_identity, *, diagnostic=None):
    """Observe the generated fixture; never initialize flags, ownership or ACLs."""
    before = {'source': _clone_metadata(source.lstat()), 'parent': _clone_metadata(parent.lstat())}
    leaf, directory = before['source'], before['parent']
    require(stat.S_ISREG(leaf['st_mode']) and stat.S_IMODE(leaf['st_mode']) == 0o640
            and leaf['st_size'] == 4096 and leaf['st_nlink'] == 1
            and leaf['st_uid'] == os.geteuid()
            and (leaf['st_dev'], leaf['st_ino']) == source_identity,
            'CLI clone source admission differs')
    require(stat.S_ISDIR(directory['st_mode']) and stat.S_IMODE(directory['st_mode']) == 0o700
            and directory['st_uid'] == os.geteuid()
            and (directory['st_dev'], directory['st_ino']) == parent_identity
            and leaf['st_dev'] == directory['st_dev'] and leaf['st_gid'] == directory['st_gid'],
            'CLI clone parent ownership or group admission differs')
    before['acl'] = {'source': _clone_absent_acl(source), 'parent': _clone_absent_acl(parent)}
    require(_clone_metadata(source.lstat()) == leaf,
            'CLI clone admission changed during ACL observation')
    _clone_parent_compare(directory, _clone_metadata(parent.lstat()), _CLONE_FIELDS,
                          stage='admission_after_acl', path=parent, diagnostic=diagnostic,
                          message='CLI clone admission changed during ACL observation')
    return before


def verify_clone_output(source, destination, expected, prepared, *, diagnostic=None):
    """Validate the real output, then mutate only its checked independent descriptor."""
    parent = destination.parent
    def closure(stage):
        require(_clone_metadata(source.lstat()) == prepared['source'], 'CLI clone source metadata changed')
        current = _clone_metadata(parent.lstat())
        _clone_parent_compare(prepared['parent'], current, _CLONE_PARENT_SECURITY,
                              stage=stage + '_before_acl', path=parent, diagnostic=diagnostic,
                              message='CLI clone parent identity or security metadata changed')
        _clone_absent_acl(source)
        _clone_absent_acl(parent)
        after_parent = _clone_metadata(parent.lstat())
        require(_clone_metadata(source.lstat()) == prepared['source'],
                'CLI clone metadata changed during output observation')
        _clone_parent_compare(prepared['parent'], after_parent, _CLONE_PARENT_SECURITY,
                              stage=stage + '_after_acl', path=parent, diagnostic=diagnostic,
                              message='CLI clone metadata changed during output observation')

    verify_clone(source, destination, expected)
    closure('output')
    info = _clone_metadata(destination.lstat())
    original = prepared['source']
    require(stat.S_ISREG(info['st_mode']) and info['st_nlink'] == 1
            and (info['st_dev'], info['st_ino']) != (original['st_dev'], original['st_ino'])
            and info['st_dev'] == original['st_dev']
            and all(info[name] == original[name] for name in
                    ('st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_flags')),
            'CLI clone output metadata or independence differs')
    _clone_absent_acl(destination)
    require(_clone_metadata(destination.lstat()) == info, 'CLI clone output changed during ACL observation')
    payload = bytes(range(256)) * 16
    descriptor = os.open(destination, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        require(_clone_metadata(os.fstat(descriptor)) == info and _clone_metadata(destination.lstat()) == info,
                'CLI clone output descriptor differs from public path')
        require(os.pread(descriptor, 4097, 0) == payload and os.pread(descriptor, 1, 4096) == b'',
                'CLI clone output bytes or EOF differ')
        require(os.pwrite(descriptor, b'changed', 0) == 7, 'CLI clone independence mutation was short')
        require(os.pread(descriptor, 4097, 0) == b'changed' + payload[7:] and
                os.pread(descriptor, 1, 4096) == b'', 'CLI clone independence mutation differs')
        changed = _clone_metadata(os.fstat(descriptor))
        require(all(changed[name] == info[name] for name in
                    ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size', 'st_flags'))
                and _clone_metadata(destination.lstat()) == changed, 'CLI clone mutated output identity changed')
    except BaseException as error:
        try:
            os.close(descriptor)
        except BaseException as secondary:
            error.add_note('Clone output close also failed: ' + repr(secondary))
        raise
    os.close(descriptor)
    require(_clone_metadata(destination.lstat()) == changed, 'CLI clone output changed after close')
    _clone_absent_acl(destination)
    require(_clone_metadata(destination.lstat()) == changed, 'CLI clone output changed during final ACL observation')
    require(source.read_bytes() == payload, 'CLI clone mutation changed protected source bytes or EOF')
    closure('mutation')
    return {'output_metadata': info, 'mutation_metadata': changed, 'bytes_and_eof': True,
            'independent_descriptor': True, 'mutation_isolated': True, 'descriptor_closed': True,
            'acl_absence': True}


def native_clone_pins(runtime, cache):
    pins = native_delete_pins(runtime, cache)
    pins['source'][Path(native_correctness.__file__).name] = digest(Path(native_correctness.__file__))
    return pins


def native_clone_comparison(rows, phase, samples):
    require(all(row.get('fixture_policy') == CLI_CLONE_FIXTURE_POLICY for row in rows),
            'CLI clone fixture policies differ or are untagged')
    require(all(row['method'] in ('native', 'candidate') for row in rows), 'Unexpected CLI clone method')
    expected = set(range(1, 32 if phase == 'timing' else samples + 1))
    methods = {}
    for method in ('native', 'candidate'):
        warmups = [row for row in rows if row['method'] == method and row['warmup']]
        require((len(warmups) == 1 and warmups[0]['pair_id'] == 0) if phase == 'timing' else not warmups,
                'Incorrect planned CLI clone warmup')
        selected = [row for row in rows if row['method'] == method and not row['warmup']]
        ids = [row['pair_id'] for row in selected]
        require(all(type(value) is int for value in ids) and len(ids) == len(expected)
                and set(ids) == expected, 'Incomplete or duplicate planned CLI clone pairs')
        require(all(row['phase'] == phase and row.get('ok') is True and row.get('validated') is True
                    and not row.get('completion_uncertain') for row in selected + warmups),
                'Invalid planned CLI clone measurement')
        methods[method] = selected
    return {metric: native_metrics.compare_paired(methods['native'], methods['candidate'], metric)
            for metric in (('wall_s', 'cpu_s') if phase == 'timing' else ('rss_bytes',))}

def native_clone(args):
    """Collect only the existing CLI tiny-clone case against fresh cp calls."""
    require(platform.system() == 'Darwin', 'This comparison requires macOS')
    scratch = args.scratch.expanduser().resolve(strict=True)
    output = args.output.expanduser().absolute()
    require(scratch.is_dir() and output.parent.is_dir(), 'Scratch and output parent must exist')
    require(shutil.disk_usage(scratch).free >= 256 * 1024**2, 'At least 256 MiB free is required')
    runtime = installed(args.candidate.expanduser().resolve(strict=True))
    binary = runtime['binary']
    pins = native_clone_pins(runtime, args.cache)
    inventory = json.loads(command([binary, '--json', 'volumes']).stdout)
    volume = scratch_volume(inventory, scratch)
    report = {'schema': 1, 'case_id': 'cli/clone/tiny_4kib', 'fixture_policy': CLI_CLONE_FIXTURE_POLICY,
              'status': 'running', 'passed': False,
              'qualified': False, 'all_metrics_won': False, 'cleanup_passed': False,
              'timing_pairs': 31, 'timing_warmup_id': 0, 'resource_pairs': args.samples,
              'cache': args.cache, 'pins': pins, 'volume': volume, 'cold_cache_unavailable': None,
              'cache_condition': 'Full source and candidate-based mount checks precede conditioning. After conditioning, identical root/operand metadata checks precede both methods without candidate execution or fixture file-content reads. Fully cold metadata residency is not established.',
              'limits': ['Only the original 4 KiB/0640 CLI clone fixture is scored; no enriched native-files alias.',
                         'Source flags/ownership/ACLs are observed without modification; destination is absent until the measured command. Source and parent ACL absence is admitted before conditioning.',
                         'Timing includes command startup; CPU is completed-command/reaped-child CPU from native_metrics, not legacy harness-plus-child cpu_s.',
                         'RSS is the measured individual-process peak, not simultaneous process-tree or whole-system memory. Footprint is unavailable.',
                         'JSON candidate calls are independently paired with fresh plain-output cp -cRp calls. cp may fall back; command success and independence do not prove clone syscalls or physical block sharing.',
                         'Purge conditioning does not establish complete OS/device-cache eviction.',
                         'After conditioning only root/operand metadata is checked; mount checks use the candidate before conditioning and after measurement. Stable owned trees are required; cache residency is not guaranteed.',
                         'Unreadable cold-tool contents remain unverified; matching metadata establishes observed identity stability only.',
                         'Stable owned fixtures only; concurrent hostile path replacement is not contained.',
                         'No release qualification or tiny-command saving target is established by collection.']}
    journal = native_report.ReportJournal(output)
    journal_failed = False
    counters = dict.fromkeys(('rows', 'preparation', 'comparisons', 'unavailable'), 0)
    base = None
    cleaned = False

    def checkpoint():
        nonlocal journal_failed
        try:
            journal.checkpoint(report)
        except BaseException:
            journal_failed = True
            raise

    def record(kind, value, index=None):
        nonlocal journal_failed
        if index is None:
            index = counters[kind]
            counters[kind] += 1
        try:
            journal.append(kind, index, value)
        except BaseException:
            journal_failed = True
            raise
        return index

    try:
        checkpoint()
        base = Path(tempfile.mkdtemp(prefix='stallionfs-cli-clone-', dir=scratch))
        base.chmod(0o700)
        identity = base.lstat()
        report['fixture_root'] = str(base)
        checkpoint()
        roots, _ = make_fixtures(base)
        require(roots == {'tiny_4kib': base / 'tiny', 'empty': base / 'empty', 'nested_1000': base / 'nested'},
                'CLI fixture roots differ from the existing case')
        tiny = roots['tiny_4kib'].lstat()
        require(stat.S_ISREG(tiny.st_mode) and stat.S_IMODE(tiny.st_mode) == 0o640
                and roots['tiny_4kib'].read_bytes() == bytes(range(256)) * 16,
                'CLI tiny fixture bytes or mode differ')
        expected = {name: content_manifest(path) for name, path in roots.items()}
        identities = {name: (path.lstat().st_dev, path.lstat().st_ino) for name, path in roots.items()}
        report['fixtures'] = {name: {'manifest_sha256': hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
                                     'root_identity': identities[name]} for name, value in expected.items()}
        source = roots['tiny_4kib']
        source_baseline = _clone_metadata(source.lstat())
        parent_metadata = _clone_metadata(base.lstat())
        target = base / 'destination'
        unused_store = base / 'unused-store'
        environment = dict(os.environ, STALLIONFS_HOME=str(unused_store), PYTHONDONTWRITEBYTECODE='1')
        environment.pop('PYTHONPATH', None)
        environment.pop('PYTHONHOME', None)

        setup_id = row_id = None
        row = None

        def diagnostic():
            return {'preparation_id': setup_id, 'row_id': row_id}

        def owned(*, mounts=True, stage='source_closure'):
            current = base.lstat()
            try:
                require(stat.S_ISDIR(current.st_mode) and stat.S_IMODE(current.st_mode) == 0o700
                        and current.st_uid == os.getuid()
                        and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino),
                        'Private fixture root changed; preserve it')
            except RuntimeError as error:
                _clone_parent_compare(parent_metadata, _clone_metadata(current), _CLONE_PARENT_SECURITY,
                                      stage=stage + '_security', path=base, diagnostic=diagnostic(),
                                      message=str(error), error=error)
                raise
            current_metadata = _clone_metadata(current)
            _clone_parent_compare(parent_metadata, current_metadata, _CLONE_PARENT_SECURITY,
                                  stage=stage + '_security', path=base, diagnostic=diagnostic(),
                                  message='CLI clone parent security metadata changed')
            if mounts:
                no_mounts_below(binary, base)

        def sources():
            owned()
            require(not os.path.lexists(unused_store), 'Command created an unnecessary store')
            require((base / 'outside-sentinel').read_bytes() == b'keep outside linked trees\n', 'Sentinel changed')
            for name, path in roots.items():
                info = path.lstat()
                require((info.st_dev, info.st_ino) == identities[name]
                        and content_manifest(path) == expected[name], 'CLI source fixture changed: ' + name)

            require(_clone_metadata(source.lstat()) == source_baseline, 'CLI clone protected source metadata changed')
            allowed = {'tiny', 'empty', 'nested', 'outside-sentinel'}
            if os.path.lexists(target):
                allowed.add(target.name)
            require({path.name for path in base.iterdir()} == allowed, 'Unexpected CLI clone fixture entry')

        def guard(prepared, *, mounts=True, stage):
            owned(mounts=mounts, stage=stage)
            require(not os.path.lexists(target), 'CLI clone destination must remain absent')
            require(_clone_metadata(source.lstat()) == prepared['source'], 'CLI clone source metadata changed')
            _clone_parent_compare(prepared['parent'], _clone_metadata(base.lstat()), _CLONE_FIELDS,
                                  stage=stage, path=base, diagnostic=diagnostic(),
                                  message='CLI clone parent metadata changed')

        rng = random.Random(SEED)
        for form in ('plain', 'json'):
            for cache in args.cache:
                for phase in ('timing', 'resources'):
                    key = {'case_id': report['case_id'], 'fixture_policy': CLI_CLONE_FIXTURE_POLICY,
                           'output': form, 'cache': cache, 'phase': phase,
                           'reference': '/bin/cp -cRp', 'reference_output': 'plain', 'paired': True}
                    if cache == 'cold' and report['cold_cache_unavailable']:
                        record('unavailable', key | {'reason': report['cold_cache_unavailable']})
                        checkpoint()
                        continue
                    rows = []
                    denied = False
                    rounds = range(32) if phase == 'timing' else range(1, args.samples + 1)
                    for pair_id in rounds:
                        order = ['native', 'candidate']
                        rng.shuffle(order)
                        for method in order:
                            setup_id = row_id = None
                            row = None
                            sources()
                            require(not os.path.lexists(target), 'Stale CLI clone destination')
                            setup = key | {'pair_id': pair_id, 'method': method,
                                           'kind': 'read_only_clone_admission', 'validated': False}
                            setup_id = record('preparation', setup)
                            report['active_operation'] = setup
                            checkpoint()
                            prepared = clone_admission(source, base, identities['tiny_4kib'],
                                                       (identity.st_dev, identity.st_ino), diagnostic=diagnostic())
                            require(prepared['source'] == source_baseline, 'CLI clone source snapshot cannot be rebased')
                            setup['operand_metadata'] = prepared
                            setup['operand_metadata_stage'] = 'before_conditioning'
                            setup['validated'] = True
                            record('preparation', setup, setup_id)
                            argv = ['/bin/cp', '-cRp', str(source), str(target)] if method == 'native' else [
                                str(binary), *(['--json'] if form == 'json' else []), 'clone', str(source), str(target)]
                            row = key | {'pair_id': pair_id, 'preparation_id': setup_id,
                                         'warmup': phase == 'timing' and pair_id == 0,
                                         'method': method, 'argv': argv, 'ok': False, 'validated': False}
                            row_id = record('rows', row)
                            report['active_operation'] = row
                            checkpoint()
                            sources()
                            guard(prepared, stage='before_conditioning')
                            conditioning = native_suite.cache_prepare(cache, 120)
                            row['cache_receipt'] = conditioning
                            if cache == 'cold':
                                code = conditioning.get('exit_code')
                                require(type(code) is int and code >= 0, 'Purge did not establish normal completion')
                                if code:
                                    report['cold_cache_unavailable'] = 'cache purge unavailable; no further purge retries'
                                    report['cold_cache_receipt'] = conditioning
                                    row['unavailable'] = report['cold_cache_unavailable']
                                    record('rows', row, row_id)
                                    sources()
                                    guard(prepared, stage='denial_closeout')
                                    require(native_clone_pins(runtime, args.cache) == pins, 'CLI runtime or tool provenance changed')
                                    require(not os.path.lexists(target), 'Denied clone destination must stay absent')
                                    record('unavailable', key | {'reason': report['cold_cache_unavailable']})
                                    report.pop('active_operation', None)
                                    checkpoint()
                                    denied = True
                                    break
                            guard(prepared, mounts=False, stage='after_conditioning')
                            receipt = native_metrics.collect(argv, timeout_s=120, env=environment, phase=phase)
                            row.update(receipt)
                            record('rows', row, row_id)
                            checkpoint()
                            require(not row.get('completion_uncertain') and row.get('ok') is True
                                    and row.get('exit_code') == 0, 'CLI measurement failed or uncertain')
                            stderr = base64.b64decode(row['stderr_b64'], validate=True)
                            require(not (native_metrics.time_diagnostics(stderr) if phase == 'resources' else stderr),
                                    'Clone command emitted diagnostics')
                            stdout = base64.b64decode(row['stdout_b64'], validate=True)
                            if method == 'candidate' and form == 'json':
                                require(json.loads(stdout) == {'source': str(source), 'destination': str(target)}, 'CLI clone JSON contract differs')
                            else:
                                require(stdout == b'', 'Clone command output differs')
                            row['output_verification'] = verify_clone_output(
                                source, target, expected['tiny_4kib'], prepared, diagnostic=diagnostic())
                            sources()
                            remove_fixture(target)
                            require(not os.path.lexists(target), 'CLI clone output cleanup did not finish')
                            if phase == 'resources':
                                require(type(row.get('rss_bytes')) is int and row['rss_bytes'] > 0, 'Peak RSS unavailable')
                            row['validated'] = True
                            record('rows', row, row_id)
                            rows.append(row)
                            report.pop('active_operation', None)
                            checkpoint()
                        if denied:
                            break
                    if not denied:
                        record('comparisons', key | {'metrics': native_clone_comparison(rows, phase, args.samples),
                                                     'footprint': 'unavailable'})
                        checkpoint()
        sources()
        report['source_checks_passed'] = True
        require(not os.path.lexists(target), 'Unconsumed CLI clone output remains')
        require(native_clone_pins(runtime, args.cache) == pins, 'CLI runtime or tool provenance changed')
        checkpoint()
        try:
            journal.verify()
        except BaseException:
            journal_failed = True
            raise
        owned()
        remove_fixture(base)
        cleaned = True
        report.update(status='complete', passed=report['cold_cache_unavailable'] is None, cleanup_passed=True)
        if 'cold' in args.cache:
            report['cold_tool_identity_verified'] = True
            report['cold_tool_content_verified'] = all(row['content_hash_status'] == 'available'
                and row['sha256'] is not None for row in pins['cold_tools'].values())
        if report['cold_cache_unavailable']:
            report['denial_runtime_verified'] = True
        checkpoint()
        journal.finish(report)
    except BaseException as error:
        report.update(status='failed', passed=False, error=f'{type(error).__name__}: {error}')
        if hasattr(error, 'receipt'):
            report['command_receipt'] = error.receipt
        if base is not None and not cleaned:
            report['retained_fixture'] = str(base)
        mismatch_json = getattr(error, 'clone_parent_metadata_mismatch_json', None)
        if mismatch_json is not None:
            report['clone_parent_metadata_mismatch'] = json.loads(mismatch_json)
            if row is not None:
                row['clone_parent_metadata_mismatch'] = json.loads(mismatch_json)
        if not journal_failed:
            try:
                if mismatch_json is not None and row is not None:
                    record('rows', row, row_id)
                checkpoint()
                journal.finish(report)
            except BaseException as secondary:
                error.add_note('Report closeout also failed: ' + str(secondary))
        raise
    finally:
        primary = sys.exc_info()[1]
        try:
            journal.close()
        except BaseException as secondary:
            if primary is None:
                raise
            primary.add_note('Journal close also failed: ' + str(secondary))
    return 0 if report['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, help="Older installed CLI for legacy two-release comparisons")
    parser.add_argument("--candidate", type=Path, required=True, help="Installed candidate CLI")
    parser.add_argument("--scratch", type=Path, required=True, help="Existing writable APFS directory")
    parser.add_argument("--output", type=Path, required=True, help="New report path")
    native_route = parser.add_mutually_exclusive_group()
    native_route.add_argument('--native-delete', action='store_true', help='Collect the existing tiny-delete case against rm')
    native_route.add_argument('--native-clone', action='store_true', help='Collect the existing tiny-clone case against cp -cRp')
    parser.add_argument('--samples', type=int, help='Native CLI resource pairs, 10–100; timing always uses 31 pairs')
    parser.add_argument('--cache', nargs='+', choices=('warm', 'cold'), help='Native CLI cache modes')
    args = parser.parse_args()
    if args.native_delete or args.native_clone:
        if args.baseline is not None:
            parser.error('Native CLI comparisons use the candidate and native command; do not supply --baseline')
        args.samples = args.samples if args.samples is not None else 10
        args.cache = args.cache if args.cache is not None else ['warm']
        if not 10 <= args.samples <= 100 or len(args.cache) != len(set(args.cache)):
            parser.error('Use 10–100 resource pairs and distinct cache modes')
        deadline = 'STALLIONFS_BENCHMARK_DEADLINE'
        supplied_deadline = deadline in os.environ
        if not supplied_deadline:
            os.environ[deadline] = str(time.monotonic() + 600)
        try:
            return native_clone(args) if args.native_clone else native_delete(args)
        finally:
            if not supplied_deadline:
                os.environ.pop(deadline, None)
    if args.baseline is None or args.samples is not None or args.cache is not None:
        parser.error('Legacy comparisons require --baseline; --samples and --cache apply only to --native-delete or --native-clone')
    require(platform.system() == "Darwin", "This comparison requires macOS")
    scratch = args.scratch.expanduser().resolve(strict=True)
    output_arg = args.output.expanduser().absolute()
    output = output_arg.parent.resolve(strict=True) / output_arg.name
    require(scratch.is_dir() and not os.path.lexists(output), "Scratch must exist and output must be new")
    require(shutil.disk_usage(scratch).free >= 256 * 1024**2, "At least 256 MiB free space is required")
    runtimes = {name: installed(getattr(args, name).expanduser().resolve(strict=True))
                for name in ("baseline", "candidate")}
    require(runtimes["baseline"]["binary"] != runtimes["candidate"]["binary"], "Use separate installed CLIs")
    fingerprints = {name: runtime_hashes(runtime) for name, runtime in runtimes.items()}
    sources = source_hashes()
    apple_hashes = {name: digest(Path(args[0])) for name, args in APPLE.items()}
    inventory = json.loads(command([runtimes["baseline"]["binary"], "--json", "volumes"]).stdout)
    require(isinstance(inventory, list) and inventory, "Mount inventory is unavailable")
    require(json.loads(command([runtimes["candidate"]["binary"], "--json", "volumes"]).stdout) == inventory,
            "Installed versions disagree about mounted filesystems")
    volume = scratch_volume(inventory, scratch)
    hardware = {}
    for name in ("hw.model", "machdep.cpu.brand_string", "hw.memsize", "hw.logicalcpu"):
        result = command(["/usr/sbin/sysctl", "-n", name], check=False)
        hardware[name] = result.stdout.decode().strip() if result.returncode == 0 else {"unavailable": True}
    _, cpu_error = cpu_usage()
    report = {
        "format": 1, "timestamp": datetime.now(timezone.utc).isoformat(), "system": platform.platform(),
        "python": platform.python_version(), "hardware": hardware, "source_sha256": sources,
        "installed": {name: {"version": runtime["version"], "python": runtime["python_version"],
                             "runtime_sha256": fingerprints[name]} for name, runtime in runtimes.items()},
        "apple_sha256": apple_hashes, "cpu_unavailable_at_start": cpu_error,
        "volume": {key: volume.get(key) for key in ("filesystem", "readonly", "ignore_ownership")},
        "samples": {"tiny_4kib": 31, "empty": 31, "nested_1000": 7, "volumes": 31},
        "warmups": 1, "random_seed": SEED, "rows": [], "fixtures": {},
        "native_reference_unavailable": {
            "scan": "No equivalent macOS command measured; scan.py separately compares native POSIX and bulk APIs without process startup.",
            "volumes": "No equivalent macOS command measured; diskutil disk inventory has different semantics from cached mounted filesystems."},
        "notes": [
            "Baseline and candidate are two installed StallionFS releases; Apple commands are separate plain-output references.",
            "Fresh subprocess wall time includes startup and completed operation; CPU includes harness and reaped child time.",
            "Each case uses deterministically shuffled paired rounds, retaining every sample and warmup.",
            "Setup, output validation, checksums, mode/inode checks and cleanup are outside timing.",
            "Warm caches; no durability flush, large fixture, new volume, or asynchronous cleanup.",
            "Apple references are cp -cRp, mv -n and rm -f on an absent exact destination or existing regular file.",
            "JSON file-command comparisons reuse the measured Apple plain-output case: they are unpaired across output cases and do not include JSON formatting in the reference.",
            "Those controlled cases do not establish equivalent overwrite, cross-volume or general command semantics.",
            "The requested store path must remain absent throughout; no workspace is prepared.",
            "Runtime/source paths, mount paths, owners and command output are validated locally and omitted from this report."]}
    base = Path(tempfile.mkdtemp(prefix="stallionfs-cli-", dir=scratch))
    base.chmod(0o700)
    identity = base.lstat()
    unused_store = base / "unused-store"
    environment = dict(os.environ, STALLIONFS_HOME=str(unused_store), PYTHONDONTWRITEBYTECODE="1")
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    cleanup_safe = True
    try:
        roots, counts = make_fixtures(base)
        expected = {name: content_manifest(path) for name, path in roots.items()}
        source_info = roots["tiny_4kib"].lstat()
        source_identity = (source_info.st_dev, source_info.st_ino)
        for name, snapshot in expected.items():
            report["fixtures"][name] = {"manifest_sha256": hashlib.sha256(
                json.dumps(snapshot, sort_keys=True).encode()).hexdigest(), "counts": counts.get(name)}
        no_mounts_below(runtimes["baseline"]["binary"], base)
        cases = [(op, "tiny_4kib", form) for op in APPLE for form in ("plain", "json")]
        cases += [("scan", fixture, form) for fixture in counts for form in ("plain", "json")]
        cases += [("volumes", "volumes", form) for form in ("plain", "json")]
        rng = random.Random(SEED)
        for operation, fixture, form in cases:
            case = "/".join((operation, fixture, form))
            for round_number in range(report["samples"][fixture] + 1):
                methods = ["baseline", "candidate"]
                if operation in APPLE and form == "plain":
                    methods.append("apple")
                rng.shuffle(methods)
                for method in methods:
                    target, destination = base / "target", base / "destination"
                    require(not os.path.lexists(target) and not os.path.lexists(destination), "Stale fixture path")
                    arguments = APPLE[operation][:] if method == "apple" else [
                        runtimes[method]["binary"], *(["--json"] if form == "json" else []), operation]
                    wanted, text = None, b""
                    if operation in APPLE:
                        source = roots["tiny_4kib"]
                        if operation != "clone":
                            command(["/bin/cp", "-cRp", source, target])
                            verify_clone(source, target, expected["tiny_4kib"])
                            before = target.lstat()
                        if operation == "delete":
                            arguments += [target]
                            wanted = {"path": str(target)}
                        else:
                            origin = source if operation == "clone" else target
                            arguments += [origin, destination]
                            wanted = {"source": str(origin), "destination": str(destination)}
                    elif operation == "scan":
                        arguments += [roots[fixture]]
                        wanted, text = counts[fixture], scan_text(counts[fixture])
                    else:
                        wanted, text = inventory, volumes_text(inventory)
                    row, result = measure(arguments, environment)
                    row.update(case=case, operation=operation, fixture=fixture, output=form,
                               method=method, round=round_number, warmup=round_number == 0)
                    report["rows"].append(row)
                    require(result.returncode == 0 and not result.stderr,
                            f"{case}/{method}: command failed ({result.returncode}): {result.stderr.decode(errors='replace')}")
                    require(json.dumps(json.loads(result.stdout), sort_keys=True) == json.dumps(wanted, sort_keys=True)
                            if form == "json" else result.stdout == text,
                            f"{case}/{method}: output contract differs")
                    require(not os.path.lexists(unused_store), "Command created an unnecessary workspace store")
                    if operation == "delete":
                        require(not os.path.lexists(target), "Deletion did not finish before returning")
                    elif operation in {"clone", "move"}:
                        if operation == "clone":
                            verify_clone(source, destination, expected["tiny_4kib"])
                            with destination.open("r+b") as stream:
                                stream.write(b"changed")
                        else:
                            require(manifest(destination) == expected["tiny_4kib"] and not os.path.lexists(target),
                                    "Move contents, metadata or source removal differ")
                            after = destination.lstat()
                            require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), "Move copied the file")
                        remove_fixture(destination)
                    require(manifest(roots["tiny_4kib"]) == expected["tiny_4kib"], "Original source changed")
                    source_info = roots["tiny_4kib"].lstat()
                    require((source_info.st_dev, source_info.st_ino) == source_identity, "Original source inode changed")
                    require((base / "outside-sentinel").read_bytes() == b"keep outside linked trees\n", "Symlink target changed")
                print(json.dumps({"case": case, "round": round_number, "warmup": round_number == 0,
                                  "order": methods}), flush=True)
        require(all(content_manifest(path) == expected[name] for name, path in roots.items()), "Fixture changed")
    except (ChildCompletionUnknown, KeyboardInterrupt):
        cleanup_safe = False
        raise
    finally:
        if cleanup_safe:
            current = base.lstat()
            require(stat.S_ISDIR(current.st_mode) and stat.S_IMODE(current.st_mode) == 0o700 and current.st_uid == os.getuid()
                    and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino), "Private fixture root changed; preserve it")
            no_mounts_below(runtimes["baseline"]["binary"], base)
            shutil.rmtree(base)
            require(not os.path.lexists(base), "Fixture cleanup did not complete")
    require(source_hashes() == sources, "Source changed during measurement; results rejected")
    require({name: runtime_hashes(runtime) for name, runtime in runtimes.items()} == fingerprints,
            "Installed runtime changed during measurement; results rejected")
    require({name: digest(Path(args[0])) for name, args in APPLE.items()} == apple_hashes,
            "Apple reference changed during measurement; results rejected")
    report["medians"] = summarize(report["rows"])
    report["candidate_vs_release_wall_speedup"] = {
        case: methods["baseline"]["wall_s"] / methods["candidate"]["wall_s"] for case, methods in report["medians"].items()}
    report["candidate_vs_apple_wall_speedup"] = {
        case: methods["apple"]["wall_s"] / methods["candidate"]["wall_s"]
        for case, methods in report["medians"].items() if "apple" in methods}
    report["candidate_vs_native_plain_reference"] = native_comparisons(report["medians"])
    report["paired_plain_effects"], report["paired_plain_effects_method"] = paired_plain_effects(report["rows"])
    report.update(passed=True, output_contracts_passed=True, no_store_created=True,
                  completed_utc=datetime.now(timezone.utc).isoformat())
    serialized = json.dumps(report)
    require(all(value not in serialized for value in (str(base), str(scratch), str(REPO), str(Path.home()),
                                                       "/Users/", "/private/var/folders/")), "Report contains a local path")
    write_new_json(output, report)
    print("Complete sanitized CLI comparison written.", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
