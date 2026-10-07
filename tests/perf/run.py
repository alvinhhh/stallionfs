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
import resource
import shutil
import statistics
import sys
import tempfile
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from stallionfs.core import Store, git, remove_tree, run
from stallionfs import _scan

METHODS = ("worktree_install", "prepared_byte_copy", "stallionfs_folder", "stallionfs_image")


def cpu_seconds():
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return time.process_time() + children.ru_utime + children.ru_stime


def digest(root):
    rows = []
    for parent, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in sorted(dirs) if d != ".git"]
        for name in sorted(files + [d for d in dirs if Path(parent, d).is_symlink()]):
            if name == ".git":
                continue
            path = Path(parent, name)
            data = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
            rows.append((str(path.relative_to(root)), hashlib.sha256(data).hexdigest(), path.stat().st_mode & 0o111))
    return hashlib.sha256(json.dumps(sorted(rows)).encode()).hexdigest()


def summary(rows):
    return {key: {"median": statistics.median(row[key] for row in rows),
                  "min": min(row[key] for row in rows),
                  "max": max(row[key] for row in rows)}
            for key in ("ready_s", "remove_s", "reclaim_s", "total_s",
                        "ready_cpu_s", "remove_cpu_s", "reclaim_cpu_s", "total_cpu_s")}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True, help="Existing writable APFS directory")
    parser.add_argument("--npm-cache", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--source-files", type=int, default=1000)
    parser.add_argument("--image-size", type=int, default=8, metavar="GIB")
    parser.add_argument("--methods", nargs="+", choices=METHODS, default=list(METHODS))
    parser.add_argument("--source-only", action="store_true")
    args = parser.parse_args()
    methods = list(dict.fromkeys(args.methods))
    if (not 1 <= args.samples <= 100 or not 1 <= args.concurrency <= 32
            or args.source_files < 1 or not 1 <= args.image_size <= 65536):
        parser.error("Use 1–100 samples, 1–32 workers, a positive file count and a 1–65536 GiB image")
    node_version = run(["node", "--version"])
    if not args.source_only and int(node_version.removeprefix("v").split(".")[0]) < 24:
        parser.error("The locked npm fixture requires Node 24 or newer; select the supported runtime before benchmarking")
    args.output = args.output.resolve()
    partial_output = args.output.with_suffix('.partial.json')
    if args.output.exists() or partial_output.exists():
        parser.error("Choose a new output path or archive existing results before another run")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    npm_cache = args.npm_cache.resolve()
    setup = [] if args.source_only else ["npm", "ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", str(npm_cache)]
    code = Path(__file__).resolve().parents[2] / "stallionfs"
    fingerprint_paths = {name: code / name
                         for name in ("core.py", "_scan.c", "_tree.c", "_tree.h", "images.py", "__init__.py")}
    fingerprint_paths["tests/perf/run.py"] = Path(__file__).resolve()
    fingerprints = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for name, path in fingerprint_paths.items()}
    native_binary = Path(_scan.__file__)
    native_fingerprint = hashlib.sha256(native_binary.read_bytes()).hexdigest()
    result = {"format": 3, "status": "incomplete", "timestamp": datetime.now(timezone.utc).isoformat(),
              "implementation_sha256": hashlib.sha256(json.dumps(fingerprints, sort_keys=True).encode()).hexdigest(),
              "source_sha256": fingerprints,
              "native_binary_sha256": native_fingerprint,
              "harness_sha256": fingerprints["tests/perf/run.py"],
              "system": platform.platform(), "machine": platform.machine(),
              "cpu": run(["sysctl", "-n", "machdep.cpu.brand_string"]),
              "memory_bytes": int(run(["sysctl", "-n", "hw.memsize"])),
              "python": platform.python_version(), "node": node_version,
              "npm": run(["npm", "--version"]), "git": run(["git", "--version"]),
              "samples": args.samples, "concurrency": args.concurrency,
              "methods_selected": methods,
              "setup": setup[:-1] + ["<isolated warm npm cache>"] if setup else [],
              "warmup_batches_per_method": 1, "source_files_generated": args.source_files,
              "timing": "API wall time, warm filesystem cache, no cache flushing; setup downloads excluded",
              "cpu_timing": "Process CPU including worker threads plus waited child-process CPU, summed over the same ready/remove/reclaim phases as wall time. Validation is excluded.",
              "worktree_coordination": "Only Git registration is serialized; installation and filesystem deletion run in parallel. One final Git prune is included in removal timing.",
              "methods": {}, "raw": {}, "preparation": {}}

    def save(path):
        temporary = path.with_name(path.name + '.tmp')
        temporary.write_text(json.dumps(result, indent=2) + '\n')
        temporary.replace(path)

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
            if method in seeds:
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
            for path, _ in created:
                if digest(path) != expected:
                    raise RuntimeError(f"Fixture mismatch: {method}")
                if setup:
                    run(["node", "check.cjs"], path)
            cpu_start = cpu_seconds()
            start = time.perf_counter()
            with ThreadPoolExecutor(max_workers=count) as pool:
                list(pool.map(lambda item: remove(method, item), created))
            if method == "worktree_install":
                git(source, "worktree", "prune", "--expire", "now")
            removed = time.perf_counter() - start
            removed_cpu = cpu_seconds() - cpu_start
            cpu_start = cpu_seconds()
            start = time.perf_counter()
            deleted = store.gc(older_than=0, yes=True) if method in seeds else []
            reclaimed = time.perf_counter() - start
            reclaimed_cpu = cpu_seconds() - cpu_start
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
                    result["raw"][label][method].append(row)
                    save(partial_output)
                    print(f"workers={count} sample={sample + 1} {method}: ready={row['ready_s']:.3f}s total={row['total_s']:.3f}s", file=sys.stderr, flush=True)
            result["methods"][label] = {method: summary(rows) for method, rows in result["raw"][label].items()}
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
        result["correctness"] = "Every measured and warmup workspace matched full content/executable-mode digest (excluding Git metadata)" + (" and passed fixture smoke test" if setup else "")
        remove_tree(base)
    except BaseException as exc:
        result['error'] = {'type': type(exc).__name__, 'message': str(exc).replace(str(base), '<benchmark>').replace(str(npm_cache), '<npm-cache>')}
        save(partial_output)
        # A failed attach can leave a live mount. Preserve the fixture for safe recovery.
        print(f"Benchmark failed; retained disposable storage for recovery: {base}", file=sys.stderr)
        raise
    result.pop('current', None)
    result['status'] = 'complete'
    save(args.output)
    partial_output.unlink(missing_ok=True)
    print(args.output)


if __name__ == "__main__":
    main()
