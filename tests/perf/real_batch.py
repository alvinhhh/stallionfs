#!/usr/bin/env python3
"""Measure launch amortization for existing installed clone operations on macOS."""
import argparse
import hashlib
import json
import math
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

SCRIPT = Path(__file__).resolve()
DATA = hashlib.sha256(b"owned-real-batch-source").digest() * 128


def worker(variant, directory, sfs, count):
    directory = Path(directory)
    source = directory / "source"
    detail = {}
    if variant == "installed_api":
        import stallionfs
        module = Path(stallionfs.__file__).resolve()
        if module.is_relative_to(SCRIPT.parents[2]):
            raise RuntimeError("installed API resolved to source checkout")
        detail = dict(module=str(module), version=stallionfs.__version__,
                      module_sha256=hashlib.sha256(module.read_bytes()).hexdigest())
        # Resolve/import the native extension once inside the timed worker.
        operation = stallionfs.clone
        detail["extension"] = str(Path(stallionfs._scan.__file__).resolve())
        detail["extension_sha256"] = hashlib.sha256(Path(detail["extension"]).read_bytes()).hexdigest()
    for index in range(int(count)):
        destination = directory / f"clone-{index:05}"
        if variant == "installed_api":
            operation(str(source), str(destination), jobs=1)
        else:
            argv = ([sfs, "clone", str(source), str(destination), "--jobs", "1"]
                    if variant == "installed_cli" else ["/bin/cp", "-c", str(source), str(destination)])
            subprocess.run(argv, check=True, stdout=subprocess.DEVNULL)
    print(json.dumps(detail))


def verify(directory, count):
    paths = [directory / "source"] + [directory / f"clone-{i:05}" for i in range(count)]
    identities = set()
    for path in paths:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o640 or path.read_bytes() != DATA:
            raise RuntimeError("bytes/mode/type mismatch: " + path.name)
        identity = (info.st_dev, info.st_ino)
        if identity in identities:
            raise RuntimeError("source/clone inode alias")
        identities.add(identity)
    mutation = b"owned mutation" * 17
    paths[1].write_bytes(mutation)
    for index, path in enumerate(paths):
        if path.read_bytes() != (mutation if index == 1 else DATA):
            raise RuntimeError("clone mutation escaped target")
    return dict(bytes_modes_types=True, distinct_inodes=len(identities), mutation_isolated=True,
                source_unchanged=True, sibling_clones_unchanged=True)


def main():
    from real_world import execute, sha
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new JSON file")
    parser.add_argument("--sfs", required=True, help="installed sfs executable")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    root, output = args.root.resolve(strict=True), args.output.absolute()
    if sys.platform != "darwin" or not root.is_dir() or not 1 <= args.count <= 10000 or not 1 <= args.repetitions <= 1000:
        parser.error("macOS existing root, count 1..10000 and repetitions 1..1000 required")
    if not 0 < args.timeout < float("inf"):
        parser.error("positive finite timeout required")
    sfs, python = shutil.which(args.sfs), shutil.which(args.python)
    if not sfs or not python or not Path("/bin/cp").is_file():
        parser.error("installed sfs, Python and /bin/cp are required")
    sfs, python = str(Path(sfs).absolute()), str(Path(python).absolute())
    with output.open("x"):
        pass
    scratch = Path(tempfile.mkdtemp(prefix="sfs-real-batch-", dir=root))
    identity = (scratch.stat().st_dev, scratch.stat().st_ino)
    prior_cwd = Path.cwd()
    report = dict(schema=1, passed=False, samples=[], summary={}, root=str(root), count=args.count,
                  repetitions=args.repetitions, warmups=1, seed=20261101, timeout_seconds=args.timeout,
                  tools=dict(sfs=sfs, python=python, cp="/bin/cp"),
                  clone_policies={"installed_cli":"mandatory", "installed_api":"mandatory", "native_cp":"fallback_capable"},
                  source_hashes={p.name: sha(p) for p in (SCRIPT, SCRIPT.with_name("real_world.py"))},
                  system=dict(platform=platform.platform(), kernel=platform.release(), python=sys.version),
                  notes=["Existing API launch amortization hypothesis; no new clone algorithm or universal speed claim.",
                         "Each batch times the selected worker interpreter startup, imports and all requested operations.",
                         "Parent wall includes exit observation at a 10 ms polling interval and scheduling delay.",
                         "wait4 CPU includes waited descendants; RSS is the largest process high-water, not concurrent tree RAM.",
                         "Warm-cache; no purge. Setup, full verification, mutation checks and cleanup are outside timing.",
                         "Native cp -c permits copy fallback; its timing is not a mandatory-clone comparison.",
                         "Independent bytes/mode/type/inode checks do not establish physical extent sharing."])
    def save():
        output.write_text(json.dumps(report, indent=2) + "\n")
    try:
        os.chdir(scratch)
        report["tool_hashes"] = {name: sha(path) for name, path in report["tools"].items()}
        rng = random.Random(report["seed"])
        for repetition in range(-1, args.repetitions):
            variants = ["installed_cli", "installed_api", "native_cp"]
            rng.shuffle(variants)
            for variant in variants:
                directory = scratch / f"{repetition}-{variant}"
                directory.mkdir(mode=0o700)
                source = directory / "source"
                source.write_bytes(DATA)
                source.chmod(0o640)
                sample = dict(variant=variant, clone_policy=report["clone_policies"][variant],
                              repetition=repetition, warmup=repetition < 0, status="failed")
                report["samples"].append(sample)
                sample.update(execute([python, "-I", SCRIPT, "--worker", variant, directory, sfs, args.count], scratch, args.timeout))
                if not sample['process_group_quiescent']:
                    report['retain_scratch'] = True
                    raise RuntimeError('Worker process group completion is uncertain; scratch retained')
                save()
                if sample["returncode"] or sample["timed_out"] or sample["output_truncated"]:
                    raise RuntimeError(f"{variant} worker failed; partial receipts retained")
                sample["installed_module"] = json.loads(sample["stdout"])
                sample["validation"] = verify(directory, args.count)
                sample["status"] = "passed"
                save()
                shutil.rmtree(directory)
        for variant in ("installed_cli", "installed_api", "native_cp"):
            rows = [r for r in report["samples"] if r["variant"] == variant and not r["warmup"]]
            metrics = report["summary"].setdefault(variant, {})
            for key in ("wall_s", "cpu_s", "peak_rss_bytes"):
                values = sorted(row[key] for row in rows)
                metrics[key] = dict(n=len(values), median=statistics.median(values),
                                    p95=values[math.ceil(.95 * len(values))-1], population_stdev=statistics.pstdev(values))
        report["passed"] = True
    except BaseException as error:
        report["error"] = f"{type(error).__name__}: {error}"
        if getattr(error, 'process_group_uncertain', False):
            report['retain_scratch'] = True
            report['supervision_failure'] = getattr(error, 'process_supervision', {})
    finally:
        os.chdir(prior_cwd)
        try:
            if report.get('retain_scratch'):
                raise RuntimeError('Scratch retained because process completion is uncertain')
            if scratch.is_symlink() or (scratch.stat().st_dev, scratch.stat().st_ino) != identity:
                raise RuntimeError("scratch identity changed; cleanup refused")
            shutil.rmtree(scratch)
            report["cleanup_verified"] = not os.path.lexists(scratch)
        except BaseException as error:
            report.update(passed=False, cleanup_verified=False, cleanup_error=str(error), retained_scratch=str(scratch))
        save()
    print(json.dumps(dict(passed=report["passed"], cleanup_verified=report["cleanup_verified"], output=str(output))))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        worker(*sys.argv[2:])
    else:
        sys.exit(main())
