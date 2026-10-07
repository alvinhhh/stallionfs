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
import shutil
import statistics
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from stallionfs.core import Store, git, run


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
            for key in ("ready_s", "remove_s", "reclaim_s", "total_s")}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True, help="Existing writable APFS directory")
    parser.add_argument("--npm-cache", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--source-files", type=int, default=1000)
    parser.add_argument("--source-only", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.samples <= 100 or not 1 <= args.concurrency <= 32 or args.source_files < 1:
        parser.error("Use 1–100 samples, 1–32 workers and a positive file count")
    args.output = args.output.resolve()
    npm_cache = args.npm_cache.resolve()
    setup = [] if args.source_only else ["npm", "ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", str(npm_cache)]
    result = {"format": 1, "timestamp": datetime.now(timezone.utc).isoformat(),
              "implementation_sha256": hashlib.sha256((Path(__file__).resolve().parents[2] / "stallionfs/core.py").read_bytes()).hexdigest(),
              "system": platform.platform(), "machine": platform.machine(),
              "cpu": run(["sysctl", "-n", "machdep.cpu.brand_string"]),
              "memory_bytes": int(run(["sysctl", "-n", "hw.memsize"])),
              "python": platform.python_version(), "node": run(["node", "--version"]),
              "npm": run(["npm", "--version"]), "git": run(["git", "--version"]),
              "samples": args.samples, "concurrency": args.concurrency,
              "setup": setup[:-1] + ["<isolated warm npm cache>"] if setup else [],
              "warmup_batches_per_method": 1, "source_files_generated": args.source_files,
              "timing": "API wall time, warm filesystem cache, no cache flushing; setup downloads excluded",
              "methods": {}, "raw": {}}
    with tempfile.TemporaryDirectory(prefix="stallionfs-perf-", dir=args.scratch.resolve()) as directory:
        base = Path(directory)
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
        result["cold_prepare_s"] = time.perf_counter() - start
        seed_repo = store.root / "seeds" / seed["id"] / "repo"
        expected = digest(seed_repo)
        result["fixture_digest"] = expected
        sizes = [p.stat().st_size for p in seed_repo.rglob("*") if p.is_file() and not p.is_symlink()]
        result["seed_regular_files"] = len(sizes)
        result["seed_logical_bytes"] = sum(sizes)
        result["storage_note"] = "Logical bytes include Git; APFS shared physical bytes are not inferred from du or st_blocks."

        def create(method):
            if method == "stallionfs":
                value = store.create(seed["id"])
                return Path(value["path"]), value["id"]
            destination = base / f"{method}-{uuid.uuid4().hex}"
            if method == "worktree_install":
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
            if method == "stallionfs":
                store.move(ident)
            elif method == "worktree_install":
                git(source, "worktree", "remove", "--force", str(path))
            else:
                shutil.rmtree(path)

        def batch(method, count):
            start = time.perf_counter()
            with ThreadPoolExecutor(max_workers=count) as pool:
                created = list(pool.map(lambda _: create(method), range(count)))
            ready = time.perf_counter() - start
            # Validation is outside timing and identical for all methods.
            for path, _ in created:
                if digest(path) != expected:
                    raise RuntimeError(f"Fixture mismatch: {method}")
                if setup:
                    run(["node", "check.cjs"], path)
            start = time.perf_counter()
            with ThreadPoolExecutor(max_workers=count) as pool:
                list(pool.map(lambda item: remove(method, item), created))
            removed = time.perf_counter() - start
            start = time.perf_counter()
            if method == "stallionfs":
                store.gc(older_than=0, yes=True)
            reclaimed = time.perf_counter() - start
            return {"ready_s": ready, "remove_s": removed, "reclaim_s": reclaimed,
                    "total_s": ready + removed + reclaimed}

        methods = ["worktree_install", "prepared_byte_copy", "stallionfs"]
        randomizer = random.Random(20261006)
        for count in sorted({1, args.concurrency}):
            label = str(count)
            result["raw"][label] = {method: [] for method in methods}
            for method in methods:
                batch(method, count)
            for sample in range(args.samples):
                order = methods.copy()
                randomizer.shuffle(order)
                for method in order:
                    row = batch(method, count)
                    result["raw"][label][method].append(row)
                    print(f"workers={count} sample={sample + 1} {method}: ready={row['ready_s']:.3f}s total={row['total_s']:.3f}s", file=sys.stderr, flush=True)
            result["methods"][label] = {method: summary(rows) for method, rows in result["raw"][label].items()}
        sequential = result["methods"]["1"]
        saving = sequential["worktree_install"]["total_s"]["median"] - sequential["stallionfs"]["total_s"]["median"]
        result["seed_amortization_workspaces"] = math.ceil(result["cold_prepare_s"] / saving) if saving > 0 else None
        result["correctness"] = "Every measured and warmup workspace matched full content/executable-mode digest (excluding Git metadata)" + (" and passed fixture smoke test" if setup else "")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
