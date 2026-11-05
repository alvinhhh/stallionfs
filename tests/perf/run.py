"""Internal performance check. Uses disposable fixtures; never cleans a user checkout."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import resource
import shutil
import stat
import sys
import tempfile
import threading
import time
import uuid

import fileops as f
import native_metrics
import stallionfs
from stallionfs import core, images
from stallionfs.core import Store, git, remove_tree, run
from stallionfs import __version__, _scan

METHODS = ("worktree_install", "prepared_byte_copy", "stallionfs_folder", "stallionfs_image")


def candidate_fingerprints(binary):
    checkout = Path(__file__).resolve().parents[2]
    f.require(binary.is_file() and os.access(binary, os.X_OK)
              and not binary.is_relative_to(checkout), 'Use an installed executable outside the checkout')
    with binary.open('rb') as stream:
        f.require(stream.read(4) in {b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe',
                                   b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'},
                  '--binary must be the installed native executable')
    if Path(f.__file__).with_name('manifest.json').is_file():
        f.require(str(binary) == os.environ.get('STALLIONFS_BENCHMARK_BINARY')
                  and str(Path(stallionfs.__file__).resolve().parent) == os.environ.get('STALLIONFS_BENCHMARK_PACKAGE'),
                  'Use this installed package and its native executable')
    else:
        f.require(binary.parent == Path(sys.executable).absolute().parent.resolve()
                  and Path(stallionfs.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()),
                  'Use the Python and CLI from the same installed environment')
    helper = binary.with_name('stallionfs-python')
    f.require(helper.is_file() and os.access(helper, os.X_OK), 'Installed Python helper is missing')
    package = Path(stallionfs.__file__).resolve().parent
    return {str(path): f.digest(path) for path in
            (binary, helper, package / '__main__.py', package / 'lifecycle.py')}


class FolderCLI:
    """Validate the three workspace CLI results before using their identifiers."""
    def __init__(self, binary, root, seed):
        self.binary, self.root, self.seed = binary, Path(root).resolve(strict=True), seed
        self.identity = self.root.lstat()
        f.require(bool(re.fullmatch('[0-9a-f]{64}', seed)), 'Invalid prepared seed ID')

    def command(self, *arguments):
        raw = run([str(self.binary), '--root', str(self.root), '--json', *arguments])
        f.require(isinstance(raw, str) and len(raw) <= 65536, 'Invalid workspace CLI response')
        value = json.loads(raw)
        f.require(isinstance(value, dict), 'Workspace CLI response must be an object')
        return value

    def path(self, value, collection, ident=None):
        actual = value.get('id')
        f.require(isinstance(actual, str) and bool(re.fullmatch('[0-9a-f]{32}', actual))
                  and (ident is None or actual == ident) and value.get('seed') == self.seed,
                  'Workspace CLI returned an unexpected identity')
        expected = self.root / collection / actual / 'repo'
        f.require(value.get('path') == str(expected), 'Workspace CLI returned an unexpected path')
        return expected, actual

    def verify_store(self):
        current = self.root.lstat()
        f.require((current.st_dev, current.st_ino) == (self.identity.st_dev, self.identity.st_ino),
                  'Workspace store identity changed')

    def verify_path(self, expected):
        self.verify_store()
        for path in (self.root, expected.parent.parent, expected.parent, expected):
            info = path.lstat()
            f.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                      and info.st_dev == self.identity.st_dev, 'Workspace CLI path is not an owned directory')

    def create(self):
        return self.path(self.command('create', self.seed), 'workspaces')

    def verify_created(self, created):
        f.require(len({ident for _, ident in created}) == len(created),
                  'Workspace CLI reused an identity within the batch')
        for path, _ in created: self.verify_path(path)

    def remove(self, ident):
        return self.path(self.command('remove', ident), 'trash', ident)

    def reclaim(self):
        return self.command('gc', '--older-than', '0', '--yes').get('deleted')

    def verify_reclamation(self, deleted, expected):
        self.verify_store()
        f.require(isinstance(deleted, list) and all(isinstance(ident, str)
                  and re.fullmatch('[0-9a-f]{32}', ident) for ident in deleted)
                  and len(deleted) == len(set(deleted)) and set(deleted) == set(expected),
                  'Incomplete workspace reclamation')
        f.require(all(not os.path.lexists(self.root / collection / ident)
                      for ident in expected for collection in ('workspaces', 'trash')),
                  'Workspace reclamation left retained storage')
        staging = self.root / 'staging'
        info = staging.lstat()
        f.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                  and info.st_dev == self.identity.st_dev, 'Workspace staging is not an owned directory')
        f.require(next(staging.iterdir(), None) is None, 'Workspace reclamation left retained staging')


def invocation_mode(rows):
    modes = {row.get('invocation_mode') for row in rows}
    f.require(len(modes) == 1 and modes <= {'cli', 'git_npm_cli', 'api_diagnostic'},
              'Missing or mixed workspace invocation modes')
    return modes.pop()


def runtime_fingerprints():
    checkout = Path(__file__).resolve().parents[2]
    paths = {name: Path(module.__file__).resolve() for name, module in
             (("__init__.py", stallionfs), ("core.py", core), ("images.py", images))}
    if Path(f.__file__).with_name('manifest.json').is_file():
        paths['_benchmark_budget.py'] = Path(core.__file__).with_name('_benchmark_budget.py').resolve()
    f.require(Path(f.__file__).with_name("manifest.json").is_file() or
              all(not path.is_relative_to(checkout) for path in paths.values()),
              "Use an installed runtime outside the source checkout")
    return {name: f.digest(path) for name, path in paths.items()}


def cpu_seconds():
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return time.process_time() + children.ru_utime + children.ru_stime


def digest(root):
    rows = []
    for parent, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in files + [d for d in dirs if Path(parent, d).is_symlink()]:
            if name == ".git":
                continue
            path = Path(parent, name)
            data = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
            rows.append((str(path.relative_to(root)), hashlib.sha256(data).hexdigest(), path.stat().st_mode & 0o111))
    return hashlib.sha256(json.dumps(sorted(rows)).encode()).hexdigest()


def summary(rows):
    invocation_mode(rows)
    result = {}
    for key in ("ready_s", "remove_s", "reclaim_s", "total_s",
                "ready_cpu_s", "remove_cpu_s", "reclaim_cpu_s", "total_cpu_s"):
        values = native_metrics.summarize(row[key] for row in rows)
        values["min"] = values.pop("minimum")
        values["max"] = values.pop("maximum")
        result[key] = values
    return result


def paired_totals(methods):
    baseline = "worktree_install"
    modes = {method: invocation_mode(rows) for method, rows in methods.items()}
    for method, mode in modes.items():
        allowed = ({'git_npm_cli'} if method == baseline else
                   {'cli', 'api_diagnostic'} if method == 'stallionfs_folder' else {'api_diagnostic'})
        f.require(mode in allowed, 'Unexpected workspace invocation mode')
    result = {"baseline": baseline, "methods": {}, "unavailable": None,
              "invocation_modes": modes, "diagnostic_only": 'api_diagnostic' in modes.values()}
    if baseline not in methods:
        result["unavailable"] = "worktree_install was not selected"
        return result
    projected = {method: [{**row, "wall_s": row.get("total_s"),
                          "cpu_s": row.get("total_cpu_s")} for row in rows]
                 for method, rows in methods.items()}
    result["methods"] = {
        method: {key: native_metrics.compare_paired(projected[baseline], rows, metric)
                 for key, metric in (("total_s", "wall_s"), ("total_cpu_s", "cpu_s"))}
        for method, rows in projected.items() if method != baseline}
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True, help="Existing writable APFS directory")
    parser.add_argument("--npm-cache", type=Path, required=True)
    parser.add_argument("--node", type=Path, help="Node executable; defaults to node on PATH")
    parser.add_argument("--npm", type=Path, help="npm CLI JavaScript entrypoint; defaults to npm on PATH")
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--source-files", type=int, default=1000)
    parser.add_argument("--image-size", type=int, default=8, metavar="GIB")
    parser.add_argument("--methods", nargs="+", choices=METHODS, default=list(METHODS))
    parser.add_argument("--source-only", action="store_true")
    invocation = parser.add_mutually_exclusive_group(required=True)
    invocation.add_argument('--binary', type=Path, help='Installed native stallionfs executable for the folder lifecycle')
    invocation.add_argument('--api-diagnostic', action='store_true', help='Diagnostic API timing, excluding CLI startup')
    args = parser.parse_args()
    methods = list(dict.fromkeys(args.methods))
    if (not 10 <= args.samples <= 100 or not 1 <= args.concurrency <= 32
            or args.source_files < 1 or not 1 <= args.image_size <= 65536):
        parser.error("Use 10–100 samples, 1–32 workers, a positive file count and a 1–65536 GiB image")
    if bool(args.node) != bool(args.npm):
        parser.error("Pass --node and --npm together")
    binary = args.binary.expanduser().resolve(strict=True) if args.binary else None
    candidate_pins = candidate_fingerprints(binary) if binary else None
    modes = {method: ('git_npm_cli' if method == 'worktree_install' else
                     'cli' if method == 'stallionfs_folder' and binary else 'api_diagnostic') for method in methods}
    node = str(args.node.resolve(strict=True)) if args.node else "node"
    npm = [node, str(args.npm.resolve(strict=True))] if args.npm else ["npm"]
    node_version = run([node, "--version"])
    if not args.source_only and int(node_version.removeprefix("v").split(".")[0]) < 24:
        parser.error("The locked npm fixture requires Node 24 or newer; select the supported runtime before benchmarking")
    output_arg = args.output.expanduser().absolute()
    output_arg.parent.mkdir(parents=True, exist_ok=True)
    args.output = output_arg.parent.resolve() / output_arg.name
    partial_output = args.output.with_suffix('.partial.json')
    if os.path.lexists(args.output) or os.path.lexists(partial_output):
        parser.error("Choose a new output path or archive existing results before another run")
    npm_cache = args.npm_cache.resolve()
    setup = [] if args.source_only else [*npm, "ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", str(npm_cache)]
    code = Path(__file__).resolve().parents[2] / "stallionfs"
    fingerprint_paths = {name: code / name
                         for name in ("core.py", "_scan.c", "_tree.c", "_walk.c", "_tree.h", "images.py", "__init__.py")}
    fingerprint_paths["tests/perf/run.py"] = Path(__file__).resolve()
    fingerprint_paths["tests/perf/fileops.py"] = Path(f.__file__).resolve()
    fingerprint_paths["tests/perf/native_metrics.py"] = Path(native_metrics.__file__).resolve()
    if Path(f.__file__).with_name('manifest.json').is_file():
        package = Path(stallionfs.__file__).resolve().parent
        fingerprint_paths = {name: package / name for name in ('core.py', 'images.py', '__init__.py', '_benchmark_budget.py')}
        fingerprint_paths.update({'tests/perf/' + name: Path(__file__).with_name(name)
                                  for name in ('run.py', 'fileops.py', 'native_metrics.py')})
        fingerprint_paths['installed-build-manifest'] = Path(f.__file__).with_name('manifest.json')
    fingerprints = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for name, path in fingerprint_paths.items()}
    native_binary = Path(_scan.__file__)
    native_fingerprint = hashlib.sha256(native_binary.read_bytes()).hexdigest()
    installed_fingerprints = runtime_fingerprints()
    result = {"format": 4, "version": __version__, "status": "incomplete", "passed": False, "timestamp": datetime.now(timezone.utc).isoformat(),
              "implementation_sha256": hashlib.sha256(json.dumps(fingerprints, sort_keys=True).encode()).hexdigest(),
              "source_sha256": fingerprints,
              "installed_python_sha256": installed_fingerprints,
              "native_binary_sha256": native_fingerprint,
              "harness_sha256": fingerprints["tests/perf/run.py"],
              "system": platform.platform(), "machine": platform.machine(),
              "cpu": run(["sysctl", "-n", "machdep.cpu.brand_string"]),
              "memory_bytes": int(run(["sysctl", "-n", "hw.memsize"])),
              "python": platform.python_version(), "node": node_version,
              "npm": run([*npm, "--version"]), "git": run(["git", "--version"]),
              "node_command": [node], "npm_command": npm,
              "samples": args.samples, "concurrency": args.concurrency,
              "methods_selected": methods,
              "workspace_invocation": 'cli' if binary else 'api_diagnostic',
              "invocation_modes": modes, "candidate_runtime_sha256": candidate_pins,
              "setup": setup[:-1] + ["<isolated warm npm cache>"] if setup else [],
              "warmup_batches_per_method": 1, "source_files_generated": args.source_files,
              "timing": "Warm filesystem cache, no cache flushing; prepared seed setup excluded. Per-method invocation modes distinguish CLI startup from diagnostic API calls.",
              "cpu_timing": "Process CPU including worker threads plus waited child-process CPU, summed over the same ready/remove/reclaim phases as wall time. Validation is excluded.",
              "comparison_scope": "Paired lifecycle wall and CPU totals against Git worktree plus setup. Memory and full metadata equivalence are not measured.",
              "worktree_coordination": "Only Git registration is serialized; installation and filesystem deletion run in parallel. One final Git prune is included in removal timing.",
              "methods": {}, "raw": {}, "preparation": {}, "comparisons": {}}

    checkpoint_identity = None

    def save():
        nonlocal checkpoint_identity
        checkpoint_identity = f.write_json(partial_output, result, checkpoint_identity)

    base = Path(tempfile.mkdtemp(prefix="stallionfs-perf-", dir=args.scratch.resolve()))
    try:
        source = base / "source"
        shutil.copytree(Path(__file__).parent / "fixture", source, ignore=shutil.ignore_patterns("node_modules"))
        for index in range(args.source_files):
            path = source / "src" / str(index // 100) / f"module-{index}.ts"
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_text(f"export const value{index}: number = {index};\n" * 20)
        git(source, "init", "-b", "main")
        git(source, "add", ".")
        git(source, "-c", "user.name=Benchmark", "-c", "user.email=benchmark@example.invalid", "commit", "-m", "Locked fixture")
        result["lockfile_sha256"] = hashlib.sha256((source / "package-lock.json").read_bytes()).hexdigest()
        result["fixture_dependencies"] = json.loads((source / "package.json").read_text())["dependencies"]
        store = Store(base / "store")
        store.doctor()
        start = time.perf_counter()
        seed = store.prepare(source, key="locked-npm-fixture", command=setup)
        folder_prepare = time.perf_counter() - start
        seed_repo = store.root / "seeds" / seed["id"] / "repo"
        expected = digest(seed_repo)
        result["fixture_digest"] = expected
        sizes = [p.stat().st_size for p in seed_repo.rglob("*") if p.is_file() and not p.is_symlink()]
        result["seed_regular_files"] = len(sizes)
        result["seed_logical_bytes"] = sum(sizes)
        result["preparation"]["stallionfs_folder"] = {
            "cold_prepare_s": folder_prepare, "seed_regular_files": len(sizes),
            "seed_logical_bytes": sum(sizes)}
        seeds = {"stallionfs_folder": seed}
        folder_cli = FolderCLI(binary, store.root, seed['id']) if binary and 'stallionfs_folder' in methods else None
        result["storage_note"] = "Seed content bytes include Git; shared APFS clone blocks are not inferred from logical file sizes."
        if "stallionfs_image" in methods:
            start = time.perf_counter()
            image_seed = store.prepare(source, key="locked-npm-fixture", command=setup, image_size=args.image_size)
            image_prepare = time.perf_counter() - start
            image_info = (store.root / "seeds" / image_seed["id"] / "workspace.sparseimage").stat()
            result["preparation"]["stallionfs_image"] = {
                "cold_prepare_s": image_prepare, "capacity_gib": args.image_size,
                "seed_content_logical_bytes": sum(sizes),
                "backing_file_logical_bytes": image_info.st_size,
                "backing_file_allocated_bytes": image_info.st_blocks * 512}
            result["storage_note"] += " Image allocation is reported st_blocks, not unique physical usage."
            result["image_timing"] = "Ready includes mount and branch creation; remove includes normal detach; reclaim includes backing-file deletion. Validation is outside timing."
            seeds["stallionfs_image"] = image_seed
        registration = threading.Lock()

        def create(method):
            if method == 'stallionfs_folder' and folder_cli:
                return folder_cli.create()
            if method in seeds:
                value = store.create(seeds[method]["id"])
                return Path(value["path"]), value["id"]
            destination = base / f"{method}-{uuid.uuid4().hex}"
            if method == "worktree_install":
                # Another Git process must not observe a partially registered worktree.
                with registration:
                    git(source, "worktree", "add", "--detach", str(destination), "HEAD")
                if setup:
                    run(setup, destination)
            elif method == "prepared_byte_copy":
                # copyfile on macOS uses fcopyfile for bytes; no COPYFILE_CLONE flag.
                shutil.copytree(seed_repo, destination, symlinks=True, copy_function=shutil.copy2)
                git(destination, "checkout", "-b", f"perf/{uuid.uuid4().hex}")
            return destination, None

        def remove(method, item):
            path, ident = item
            if method == 'stallionfs_folder' and folder_cli:
                return folder_cli.remove(ident)
            elif method in seeds:
                store.move(ident)
            else:
                shutil.rmtree(path)

        def batch(method, count):
            cpu_start = cpu_seconds()
            start = time.perf_counter()
            with ThreadPoolExecutor(max_workers=count) as pool:
                created = list(pool.map(lambda _: create(method), range(count)))
            ready = time.perf_counter() - start
            ready_cpu = cpu_seconds() - cpu_start
            # Validation is outside timing and identical for all methods.
            if method == 'stallionfs_folder' and folder_cli:
                folder_cli.verify_created(created)
            for path, _ in created:
                if digest(path) != expected:
                    raise RuntimeError(f"Fixture mismatch: {method}")
                if setup:
                    run([node, "check.cjs"], path)
            cpu_start = cpu_seconds()
            start = time.perf_counter()
            with ThreadPoolExecutor(max_workers=count) as pool:
                retired = list(pool.map(lambda item: remove(method, item), created))
            if method == "worktree_install":
                git(source, "worktree", "prune", "--expire", "now")
            removed = time.perf_counter() - start
            removed_cpu = cpu_seconds() - cpu_start
            if method == 'stallionfs_folder' and folder_cli:
                for path, ident in retired:
                    folder_cli.verify_path(path)
                    f.require(not os.path.lexists(store.root / 'workspaces' / ident),
                              'Workspace retirement did not complete')
            cpu_start = cpu_seconds()
            start = time.perf_counter()
            deleted = (folder_cli.reclaim()
                       if method == 'stallionfs_folder' and folder_cli else
                       store.gc(older_than=0, yes=True) if method in seeds else [])
            reclaimed = time.perf_counter() - start
            reclaimed_cpu = cpu_seconds() - cpu_start
            if method == 'stallionfs_folder' and folder_cli:
                folder_cli.verify_reclamation(deleted, [ident for _, ident in created])
            if method in seeds and set(deleted) != {ident for _, ident in created}:
                raise RuntimeError(f"Incomplete workspace reclamation: {method}")
            if method == "worktree_install":
                registered = [line.removeprefix('worktree ') for line in git(source, "worktree", "list", "--porcelain").splitlines()
                              if line.startswith('worktree ')]
                if registered != [str(source)]:
                    raise RuntimeError("Baseline cleanup left registered worktrees")
            return {"ready_s": ready, "remove_s": removed, "reclaim_s": reclaimed,
                    "total_s": ready + removed + reclaimed,
                    "ready_cpu_s": ready_cpu, "remove_cpu_s": removed_cpu,
                    "reclaim_cpu_s": reclaimed_cpu,
                    "total_cpu_s": ready_cpu + removed_cpu + reclaimed_cpu}

        randomizer = random.Random(20261006)
        for count in sorted({1, args.concurrency}):
            label = str(count)
            result["raw"][label] = {method: [] for method in methods}
            for method in methods:
                result['current'] = dict(workers=count, phase='warmup', method=method)
                batch(method, count)
            for sample in range(args.samples):
                order = methods.copy()
                randomizer.shuffle(order)
                for method in order:
                    result['current'] = dict(workers=count, phase='measurement', sample=sample + 1, method=method)
                    row = batch(method, count)
                    row.update(pair_id=sample + 1, phase="timing", ok=True, validated=True,
                               invocation_mode=modes[method],
                               precision_floor={
                                   "wall_s": 6 * time.get_clock_info("perf_counter").resolution,
                                   # Three phase deltas, each with parent and two child CPU counters.
                                   "cpu_s": 3 * (2 * time.get_clock_info("process_time").resolution + 0.000004)})
                    result["raw"][label][method].append(row)
                    save()
                    print(f"workers={count} sample={sample + 1} {method}: ready={row['ready_s']:.3f}s total={row['total_s']:.3f}s", file=sys.stderr, flush=True)
            result["methods"][label] = {method: summary(rows) for method, rows in result["raw"][label].items()}
            result["comparisons"][label] = paired_totals(result["raw"][label])
        sequential = result["methods"]["1"]
        for method in seeds:
            if "worktree_install" not in sequential or method not in sequential:
                continue
            saving = sequential["worktree_install"]["total_s"]["median"] - sequential[method]["total_s"]["median"]
            preparation = result["preparation"][method]
            preparation["amortization_workspaces"] = math.ceil(preparation["cold_prepare_s"] / saving) if saving > 0 else None
        if any(hashlib.sha256(fingerprint_paths[name].read_bytes()).hexdigest() != value
               for name, value in fingerprints.items()):
            raise RuntimeError("Runtime source changed during the benchmark; results are invalid")
        if hashlib.sha256(native_binary.read_bytes()).hexdigest() != native_fingerprint:
            raise RuntimeError("Native binary changed during the benchmark; results are invalid")
        if runtime_fingerprints() != installed_fingerprints:
            raise RuntimeError("Installed Python modules changed during the benchmark; results are invalid")
        if binary and candidate_fingerprints(binary) != candidate_pins:
            raise RuntimeError('Workspace CLI runtime changed during the benchmark; results are invalid')
        result["correctness"] = "Every measured and warmup workspace matched full content/executable-mode digest (excluding Git metadata)" + (" and passed fixture smoke test" if setup else "")
        remove_tree(base)
        f.require(not os.path.lexists(base), "Workspace benchmark cleanup did not complete")
        result['cleanup_passed'] = True
    except BaseException as exc:
        result['error'] = {'type': type(exc).__name__, 'message': str(exc).replace(str(base), '<benchmark>').replace(str(npm_cache), '<npm-cache>')}
        save()
        # A failed attach can leave a live mount. Preserve the fixture for safe recovery.
        print(f"Benchmark failed; retained disposable storage for recovery: {base}", file=sys.stderr)
        raise
    result.pop('current', None)
    result.update(status='complete', passed=True)
    f.write_new_json(args.output, result)
    if checkpoint_identity is not None:
        try:
            info = partial_output.lstat()
            if (info.st_dev, info.st_ino) == checkpoint_identity:
                partial_output.unlink()
        except FileNotFoundError:
            pass
    print(args.output)


if __name__ == "__main__":
    main()
