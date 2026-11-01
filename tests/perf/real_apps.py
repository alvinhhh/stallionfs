#!/usr/bin/env python3
"""Portable application/I/O measurements on an existing filesystem root."""
import argparse
import concurrent.futures
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import resource
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time

SCRIPT = Path(__file__).resolve()
SEED = 818730


def rss_bytes(usage):
    return int(usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024))


def wait_child(child):
    _, status, usage = os.wait4(child.pid, 0)
    child.returncode = os.waitstatus_to_exitcode(status)
    if child.returncode:
        raise RuntimeError(f"child exited {child.returncode}; see stderr log")
    return usage


def run_child(argv, cwd):
    return wait_child(subprocess.Popen(argv, cwd=cwd, stdout=subprocess.DEVNULL))


def child_metric(start, usages):
    return dict(wall_seconds=time.perf_counter() - start,
                user_seconds=sum(u.ru_utime for u in usages),
                system_seconds=sum(u.ru_stime for u in usages),
                cpu_seconds=sum(u.ru_utime + u.ru_stime for u in usages),
                peak_rss_bytes=max(rss_bytes(u) for u in usages),
                rss_scope="maximum single child process high-water; not concurrent summed RSS")


def self_start():
    return time.perf_counter(), resource.getrusage(resource.RUSAGE_SELF)


def self_metric(before):
    now = resource.getrusage(resource.RUSAGE_SELF)
    return dict(wall_seconds=time.perf_counter() - before[0],
                user_seconds=now.ru_utime - before[1].ru_utime,
                system_seconds=now.ru_stime - before[1].ru_stime,
                cpu_seconds=now.ru_utime + now.ru_stime - before[1].ru_utime - before[1].ru_stime,
                peak_rss_bytes=rss_bytes(now),
                rss_scope="worker process lifetime high-water, including setup and prior stages")


def build_case(root, cc, jobs, smoke):
    count = 2 if smoke else 32
    (root / "values.h").write_text("#define BASE 170\n")
    for i in range(count):
        (root / f"part{i}.c").write_text(
            f'#include "values.h"\nint part{i}(void) {{ return BASE + {i}; }}\n')
    declarations = "".join(f"int part{i}(void);\n" for i in range(count))
    expression = "+".join(f"part{i}()" for i in range(count))
    (root / "main.c").write_text('#include <stdio.h>\n' + declarations +
                                f'int main(void) {{ printf("%d\\n", {expression}); return 0; }}\n')
    sources = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sorted(root.iterdir()) if p.suffix in (".c", ".h")}
    (root / "sources.json").write_text(json.dumps(sources, sort_keys=True))

    def compile_one(name):
        return run_child([cc, "-O2", "-c", name + ".c", "-o", name + ".o"], root)

    names = [f"part{i}" for i in range(count)] + ["main"]
    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        usages = list(pool.map(compile_one, names))
    usages.append(run_child([cc, *[n + ".o" for n in names], "-o", "program"], root))
    full = child_metric(start, usages)
    expected = sum(170 + i for i in range(count))
    if subprocess.check_output([str(root / "program")], text=True).strip() != str(expected):
        raise RuntimeError("compiled program returned wrong sum")
    # Rebuild one changed translation unit and relink, retaining the other objects.
    (root / "part0.c").write_text('#include "values.h"\nint part0(void) { return BASE + 1; }\n')
    start = time.perf_counter()
    usages = [compile_one("part0"), run_child([cc, *[n + ".o" for n in names], "-o", "program"], root)]
    incremental = child_metric(start, usages)
    if subprocess.check_output([str(root / "program")], text=True).strip() != str(expected + 1):
        raise RuntimeError("incremental build returned wrong sum")
    return dict(full_build=full, incremental_build=incremental)


def payload(writer, row):
    return hashlib.sha256(f"{writer}:{row}:payload".encode()).hexdigest()


def sqlite_writer(db, writer, rows, batch):
    with contextlib.closing(sqlite3.connect(db, timeout=60, isolation_level=None)) as conn:
        conn.execute("PRAGMA synchronous=FULL")
        for begin in range(0, rows, batch):
            conn.execute("BEGIN IMMEDIATE")
            conn.executemany("INSERT INTO records VALUES (?,?)",
                             [(writer * rows + i, payload(writer, i))
                              for i in range(begin, min(rows, begin + batch))])
            conn.execute("COMMIT")


def sqlite_case(root, smoke):
    rows, batch = (8, 4) if smoke else (500, 25)
    db = root / "records.sqlite"
    with contextlib.closing(sqlite3.connect(db)) as conn:
        if conn.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
            raise RuntimeError("WAL was not enabled")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
    start = time.perf_counter()
    children = [subprocess.Popen([sys.executable, str(SCRIPT), "--writer", str(db), str(i), str(rows), str(batch)])
                for i in range(2)]
    usages, errors = [], []
    for child in children:
        try:
            usages.append(wait_child(child))
        except RuntimeError as error:
            errors.append(str(error))
    metric = child_metric(start, usages) if usages else None
    if errors:
        raise RuntimeError("; ".join(errors))
    with contextlib.closing(sqlite3.connect(db)) as conn:
        actual = conn.execute("SELECT id,payload FROM records ORDER BY id").fetchall()
        expected = [(w * rows + i, payload(w, i)) for w in range(2) for i in range(rows)]
        if actual != expected or conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("SQLite row or integrity validation failed")
    return dict(sqlite_two_writers=metric)


def write_all(fd, data, offset=None):
    view = memoryview(data)
    while view:
        written = os.write(fd, view) if offset is None else os.pwrite(fd, view, offset)
        if written <= 0:
            raise OSError("zero-length write")
        view = view[written:]
        if offset is not None:
            offset += written


def io_case(root, smoke):
    size = (1 if smoke else 64) * 1024 * 1024
    writes = 8 if smoke else 1000
    block = bytes(range(256)) * 4096
    expected = hashlib.sha256()
    for _ in range(size // len(block)):
        expected.update(block)
    expected_digest = expected.hexdigest()
    path = root / "sequential.bin"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        start = self_start()
        for _ in range(size // len(block)):
            write_all(fd, block)
        os.fsync(fd)
        sequential_write = self_metric(start)
        with path.open("rb", buffering=0) as stream:
            observed = hashlib.file_digest(stream, "sha256").hexdigest()
        if path.stat().st_size != size or observed != expected_digest:
            raise RuntimeError("sequential write validation failed")
        start = self_start()
        digest = hashlib.sha256()
        with path.open("rb", buffering=0) as stream:
            while data := stream.read(1024 * 1024):
                digest.update(data)
        sequential_read = self_metric(start)
        if digest.hexdigest() != expected_digest:
            raise RuntimeError("sequential read validation failed")
        rng, expected_pages = random.Random(SEED), {}
        operations = []
        for index in range(writes):
            page = rng.randrange(size // 4096)
            value = hashlib.sha256(f"overwrite:{index}".encode()).digest() * 128
            operations.append((page * 4096, value))
            expected_pages[page] = value
        start = self_start()
        for offset, value in operations:
            write_all(fd, value, offset)
        os.fsync(fd)
        overwrite = self_metric(start)
        with path.open("rb", buffering=0) as stream:
            for page in range(size // 4096):
                if stream.read(4096) != expected_pages.get(page, block[:4096]):
                    raise RuntimeError(f"random overwrite validation failed at page {page}")
            if stream.read(1):
                raise RuntimeError("random overwrite changed file size")
    finally:
        os.close(fd)
    return dict(sequential_write_fsync=sequential_write, sequential_read_sha256=sequential_read,
                random_overwrite_fsync=overwrite)


def worker(args):
    root, case, cc, jobs, smoke, receipt = args
    result = dict(case=case, correct=False)
    Path(receipt).write_text(json.dumps(result) + "\n")
    try:
        root = Path(root)
        result["metrics"] = (build_case(root, cc, int(jobs), smoke == "1") if case == "build"
                             else sqlite_case(root, smoke == "1") if case == "sqlite"
                             else io_case(root, smoke == "1"))
        if case == "build":
            result["generated_initial_source_sha256"] = json.loads((root / "sources.json").read_text())
            result["generated_incremental_source_sha256"] = hashlib.sha256((root / "part0.c").read_bytes()).hexdigest()
        result["correct"] = True
    except BaseException as error:
        result["error"] = f"{type(error).__name__}: {error}"
    Path(receipt).write_text(json.dumps(result, indent=2) + "\n")
    return 0 if result["correct"] else 1


def summarize(samples):
    return dict(n=len(samples), median=statistics.median(samples),
                p95=sorted(samples)[math.ceil(0.95 * len(samples)) - 1],
                population_stdev=statistics.pstdev(samples))


def bounded_wait(child, timeout):
    try:
        from real_world import wait_owned_process
        usage, elapsed_done, supervision = wait_owned_process(child, timeout, exit_clock=time.perf_counter)
    except BaseException as error:
        error.process_group_uncertain = True
        raise
    exited = supervision['post_reap_group_probe']['outcome'] == 'absent_at_check'
    return usage, elapsed_done, supervision['timed_out'], exited, supervision


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="existing filesystem directory")
    parser.add_argument("--output", type=Path, required=True, help="new result directory")
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=180, help="seconds per case, including setup/checks")
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--smoke", action="store_true", help="tiny validation only; not benchmark evidence")
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if not root.is_dir() or not 1 <= args.jobs <= 32 or not 1 <= args.repetitions <= 1000 or not 0 < args.timeout < float("inf"):
        parser.error("root must be a directory; jobs 1..32; repetitions 1..1000; positive finite timeout")
    cc = shutil.which(args.cc)
    if not cc:
        parser.error("C compiler was not found")
    cc = str(Path(cc).resolve())
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    compiler = subprocess.run([cc, "--version"], capture_output=True, text=True, timeout=15)
    result = dict(schema_version=1, passed=False, smoke=args.smoke, root=str(root), jobs=args.jobs,
                  repetitions=1 if args.smoke else args.repetitions, warmups=0 if args.smoke else 1,
                  seed=SEED, timeout_seconds=args.timeout, provenance=dict(platform=platform.platform(), kernel=platform.release(),
                  python=sys.version, executable=sys.executable, sqlite=sqlite3.sqlite_version,
                  compiler=cc, compiler_version=compiler.stdout.strip(), compiler_version_exit=compiler.returncode,
                  source_sha256=hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
                  supervisor_source_sha256=hashlib.sha256(SCRIPT.with_name('real_world.py').read_bytes()).hexdigest()),
                  runs=[], summary={},
                  workload=dict(generated_part_units=2 if args.smoke else 32,
                                translation_units=3 if args.smoke else 33, writers=2,
                  rows_per_writer=8 if args.smoke else 500, rows_per_transaction=4 if args.smoke else 25,
                  io_bytes=(1 if args.smoke else 64)*1024*1024, random_writes=8 if args.smoke else 1000,
                  random_write_bytes=4096, root_device=root.stat().st_dev),
                  interpretation=["No cache purge: read stages are warm-cache; all filesystem roots use the same procedure.",
                  "Uses os.fsync on every OS; macOS F_FULLFSYNC is not requested. Not a power-loss durability test.",
                  "Child process startup/runtime costs are included in application measurements.",
                  "Parent worker-envelope wall includes exit observation at a 10 ms polling interval and scheduling delay; worker-stage timings are unchanged.",
                  "CPU is summed child usage for application stages; RSS is maximum single-process high-water, not tree sum.",
                  "I/O stage CPU is worker self usage; RSS includes setup/prior-stage high-water.",
                  "Correctness checks and data generation are outside timed stages; worker envelope includes both."])
    scratch = Path(tempfile.mkdtemp(prefix=".stallionfs-real-apps-", dir=root))
    identity = (scratch.stat().st_dev, scratch.stat().st_ino)
    def save():
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    try:
        rng = random.Random(SEED)
        for iteration in range(-result["warmups"], result["repetitions"]):
            order = ["build", "sqlite", "io"]
            rng.shuffle(order)
            for case in order:
                label = f"{'warmup' if iteration < 0 else 'round'}-{abs(iteration):03}-{case}"
                directory = scratch / label
                directory.mkdir(mode=0o700)
                receipt = output / (label + ".json")
                started = time.perf_counter()
                with (output / (label + ".stderr.log")).open("wb") as log:
                    child = subprocess.Popen([sys.executable, str(SCRIPT), "--worker", str(directory), case,
                                              cc, str(args.jobs), str(int(args.smoke)), str(receipt)],
                                             stdout=subprocess.DEVNULL, stderr=log, start_new_session=True)
                    usage, ended, timed_out, exited, supervision = bounded_wait(child, args.timeout)
                    if not exited:
                        result['retain_scratch'] = True
                if not exited:
                    row = dict(case=case, correct=False)
                else:
                    try:
                        row = json.loads(receipt.read_text())
                    except (OSError, json.JSONDecodeError) as error:
                        row = dict(case=case, correct=False, receipt_error=str(error))
                if timed_out or not exited:
                    row.update(correct=False, error="case deadline exceeded" if timed_out else "worker group exit unverified")
                row.update(iteration=iteration, warmup=iteration < 0, exit_code=child.returncode, timed_out=timed_out,
                           process_group_exit_verified=exited, supervision=supervision,
                           worker_envelope=dict(wall_seconds=ended-started,
                           user_seconds=usage.ru_utime, system_seconds=usage.ru_stime,
                           cpu_seconds=usage.ru_utime+usage.ru_stime, peak_rss_bytes=rss_bytes(usage)))
                result["runs"].append(row)
                save()
                if child.returncode or not row["correct"]:
                    raise RuntimeError(f"{label} failed; partial receipts retained")
                shutil.rmtree(directory)
        for row in result["runs"]:
            if not row["warmup"]:
                for stage, metric in row["metrics"].items():
                    values = result["summary"].setdefault(stage, {})
                    for key in ("wall_seconds", "user_seconds", "system_seconds", "cpu_seconds", "peak_rss_bytes"):
                        values.setdefault(key, []).append(metric[key])
        for values in result["summary"].values():
            for key, samples in values.items():
                values[key] = summarize(samples)
        result["passed"] = True
    except BaseException as error:
        result["error"] = f"{type(error).__name__}: {error}"
        if getattr(error, 'process_group_uncertain', False):
            result['retain_scratch'] = True
            result['supervision_failure'] = getattr(error, 'process_supervision', {})
    finally:
        try:
            if result.get('retain_scratch'):
                result["retained_scratch"] = str(scratch)
                raise RuntimeError("owned worker group exit uncertain; scratch retained")
            if scratch.is_symlink() or (scratch.stat().st_dev, scratch.stat().st_ino) != identity:
                raise RuntimeError("scratch identity changed; cleanup refused")
            shutil.rmtree(scratch)
            result["cleanup_verified"] = not os.path.lexists(scratch)
        except BaseException as error:
            result["cleanup_verified"] = False
            result["cleanup_error"] = str(error)
            result["passed"] = False
        save()
    print(json.dumps(dict(passed=result["passed"], output=str(output), cleanup_verified=result["cleanup_verified"])))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--writer":
        sqlite_writer(sys.argv[2], *map(int, sys.argv[3:6]))
    else:
        sys.exit(worker(sys.argv[2:]) if len(sys.argv) > 1 and sys.argv[1] == "--worker" else main())
