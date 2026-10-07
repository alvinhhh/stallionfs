"""Compare installed file commands with native macOS commands on private fixtures.

All commands include process startup. Content checks and fixture setup are outside
timing. Large synthetic fixtures are opt-in. An atomic partial report preserves
samples on failure; only a fully validated and cleaned run produces the result.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import resource
import shutil
import stat
import statistics
import subprocess
import tempfile
import time


REPO = Path(__file__).resolve().parents[2]
BASELINES = {"clone": "/bin/cp", "delete": "/bin/rm", "move": "/bin/mv"}
RNG_SEED = 20261007
SAMPLES = {"tiny_4kib": 31, "large_64mib": 7, "flat_2000": 7, "nested_10000": 7}
LARGE_PROFILES = {
    "dependencies_100k": {"files": 100_000, "bytes": 102_400_000},
    "git_50k_2gb": {"files": 50_000, "bytes": 2_000_000_000},
    "cache_200k_10gb": {"files": 200_000, "bytes": 10_000_000_000},
    "docs_5k_100mb": {"files": 5_000, "bytes": 100_000_000},
    "dataset_2k_50gb": {"files": 2_000, "bytes": 50_000_000_000},
}
HEADROOM = 2 * 1024**3


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(arguments, *, check=True, timeout=120, environment=None):
    try:
        result = subprocess.run([str(arg) for arg in arguments], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, umask=0o077, env=environment)
    except KeyboardInterrupt as exc:
        raise ChildCompletionUnknown("Command interrupted; child completion is unknown; preserve its fixture") from exc
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {arguments[0]}: "
                           + result.stderr.decode(errors="replace").strip())
    return result


def cpu_usage():
    try:
        own = resource.getrusage(resource.RUSAGE_SELF)
        children = resource.getrusage(resource.RUSAGE_CHILDREN)
        return {"self_user_s": own.ru_utime, "self_system_s": own.ru_stime,
                "children_user_s": children.ru_utime, "children_system_s": children.ru_stime}, None
    except (OSError, ValueError) as exc:
        return None, str(exc)


def measure(arguments, *, timeout=120):
    before, before_error = cpu_usage()
    started_utc = datetime.now(timezone.utc).isoformat()
    start = time.perf_counter()
    try:
        completed = command(arguments, check=False, timeout=timeout)
        outcome = {"exit_code": completed.returncode}
        if completed.returncode:
            outcome["error"] = completed.stderr.decode(errors="replace").strip()
    except ChildCompletionUnknown:
        raise
    except Exception as exc:
        outcome = {"exit_code": None, "error": f"{type(exc).__name__}: {exc}"}
    wall = time.perf_counter() - start
    after, after_error = cpu_usage()
    result = {"started_utc": started_utc, "wall_s": wall, **outcome}
    if before is None or after is None:
        result.update(cpu_s=None, cpu_self_s=None, cpu_children_s=None,
                      cpu_unavailable=before_error or after_error)
    else:
        result.update({key: after[key] - before[key] for key in before})
        result["cpu_self_s"] = result["self_user_s"] + result["self_system_s"]
        result["cpu_children_s"] = result["children_user_s"] + result["children_system_s"]
        result["cpu_s"] = result["cpu_self_s"] + result["cpu_children_s"]
    return result


def manifest(root):
    """Hash every regular file and record every mode and symlink without following it."""
    result = {}

    def visit(path, relative):
        info = path.lstat()
        row = {"mode": stat.S_IMODE(info.st_mode)}
        if stat.S_ISREG(info.st_mode):
            row.update(kind="file", size=info.st_size, sha256=digest(path))
        elif stat.S_ISLNK(info.st_mode):
            row.update(kind="symlink", target=os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            row["kind"] = "directory"
        else:
            raise RuntimeError(f"Unexpected fixture entry: {relative}")
        result[relative] = row
        if row["kind"] == "directory":
            for child in sorted(path.iterdir()):
                visit(child, f"{relative}/{child.name}" if relative else child.name)

    visit(root, "")
    return result


def verify_clone(source, destination, expected):
    require(manifest(destination) == expected, "Cloned contents, modes or links differ")
    for relative, row in expected.items():
        if row["kind"] == "file":
            original = (source / relative if relative else source).lstat()
            copied = (destination / relative if relative else destination).lstat()
            require((original.st_dev, original.st_ino) != (copied.st_dev, copied.st_ino),
                    "Clone used mutable hard links to the source")


def fixtures(base):
    source = base / "fixtures"
    source.mkdir(mode=0o700)
    block = random.Random(42).randbytes(1024 * 1024)
    tiny, large = source / "tiny", source / "large"
    tiny.write_bytes(block[:4096])
    with large.open("xb", buffering=0) as stream:
        for _ in range(64):
            require(stream.write(block) == len(block), "Short fixture write")
    tiny.chmod(0o640)
    large.chmod(0o640)
    roots = {"tiny_4kib": tiny, "large_64mib": large}
    for name, count in (("flat_2000", 2000), ("nested_10000", 10000)):
        root = source / name
        root.mkdir(mode=0o750)
        for index in range(count):
            parent = root if count == 2000 else root / f"group-{index // 500:02}" / f"part-{index // 50 % 10:02}"
            parent.mkdir(mode=0o750, parents=True, exist_ok=True)
            path = parent / f"file-{index:05}"
            payload = index.to_bytes(8, "little") + block[:504]
            path.write_bytes(payload)
            path.chmod(0o750 if index % 97 == 0 else 0o640)
        first = next(root.rglob("file-00000"))
        (root / "relative-link").symlink_to(first.relative_to(root))
        (root / "dangling-link").symlink_to("absent-target")
        (root / "outside-link").symlink_to(base / "outside-sentinel")
        roots[name] = root
    return roots


def git_command(root, *arguments):
    # Ignore the user's Git hooks, filters and signing configuration in synthetic repositories.
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
                       GIT_AUTHOR_DATE="2026-01-01T00:00:00+00:00", GIT_COMMITTER_DATE="2026-01-01T00:00:00+00:00")
    try:
        return command(["/usr/bin/git", "-C", root, "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                        "-c", "core.hooksPath=/dev/null", "-c", "gc.auto=0", *arguments],
                       timeout=None, environment=environment)
    except BaseException as exc:
        raise ChildCompletionUnknown("Git command did not finish cleanly; preserve its fixture") from exc


def large_fixture(base, name, specification):
    """Materialize synthetic source bytes; a Git profile also has a real committed object store."""
    root = base / name
    root.mkdir(mode=0o750)
    count, total = specification["files"], specification["bytes"]
    require(count > 0 and total >= count * 128, "Fixture sizes must allow complete file contents")
    block = random.Random(42).randbytes(1024 * 1024)
    text_block = bytes(97 + byte % 26 for byte in block)
    for index in range(count):
        size = total // count + (index < total % count)
        if name.startswith("dependencies_"):
            parent, filename = root / "node_modules" / f"package-{index // 100:04}" / "lib", f"module-{index:06}.js"
        elif name.startswith("git_"):
            parent, filename = root / "src" / f"module-{index // 500:04}", f"source-{index:06}.bin"
        elif name.startswith("cache_"):
            parent, filename = root / "cache" / f"shard-{index // 1000:04}", f"entry-{index:06}.bin"
        elif name.startswith("docs_"):
            parent = root / ("pages" if index % 5 == 0 else "assets") / f"section-{index // 100:04}"
            filename = f"page-{index:06}.html" if index % 5 == 0 else f"asset-{index:06}.bin"
        else:
            parent, filename = root / f"shard-{index // 100:04}", f"record-{index:06}.bin"
        parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        prefix, suffix, payload = index.to_bytes(8, "little"), b"", block
        if filename.endswith(".html"):
            prefix = f"<!doctype html><html><title>Page {index}</title><body><pre>".encode()
            suffix, payload = b"</pre></body></html>\n", text_block
        elif filename.endswith(".js"):
            prefix, suffix, payload = f"export const module{index} = '".encode(), b"';\n", text_block
        require(size >= len(prefix) + len(suffix), "Fixture file is too small for its format")
        with (parent / filename).open("xb", buffering=0) as stream:
            require(stream.write(prefix) == len(prefix), "Short fixture write")
            remaining = size - len(prefix) - len(suffix)
            while remaining:
                part = payload[:min(remaining, len(payload))]
                require(stream.write(part) == len(part), "Short fixture write")
                remaining -= len(part)
            require(stream.write(suffix) == len(suffix), "Short fixture write")
        (parent / filename).chmod(0o640)
    if name.startswith("git_"):
        git_command(root, "init", "--quiet", "--template=", "--initial-branch=main")
        git_command(root, "add", "--all")
        git_command(root, "commit", "--quiet", "-m", "Synthetic source fixture")
        git_command(root, "gc", "--quiet", "--prune=now")
        git_command(root, "fsck", "--full", "--strict")
        require(not git_command(root, "status", "--porcelain=v1", "--untracked-files=all").stdout,
                "Generated Git fixture is not a clean committed repository")
    return root


def fixture_totals(root, snapshot):
    result = {"regular_files": 0, "directories": 0, "symlinks": 0, "logical_bytes": 0,
              "allocated_bytes": 0, "git_files": 0, "git_logical_bytes": 0,
              "git_allocated_bytes": 0}
    for relative, row in snapshot.items():
        path = root / relative if relative else root
        info = path.lstat()
        allocated = info.st_blocks * 512
        if row["kind"] == "file":
            require(allocated >= info.st_size and not (info.st_flags & stat.UF_COMPRESSED),
                    "Synthetic fixture contains sparse or filesystem-compressed data")
        result["allocated_bytes"] += allocated
        result[{"file": "regular_files", "directory": "directories", "symlink": "symlinks"}[row["kind"]]] += 1
        result["logical_bytes"] += row.get("size", 0)
        if relative == ".git" or relative.startswith(".git/"):
            result["git_files"] += row["kind"] == "file"
            result["git_logical_bytes"] += row.get("size", 0)
            result["git_allocated_bytes"] += allocated
    result["source_regular_files"] = result["regular_files"] - result["git_files"]
    result["source_logical_bytes"] = result["logical_bytes"] - result["git_logical_bytes"]
    return result


def no_mounts_below(binary, base):
    # Use the installed package's native mount inventory, not a disk-device inventory.
    records = json.loads(command([binary, "--json", "volumes"]).stdout)
    require(isinstance(records, list) and records, "Mounted-filesystem inventory is unavailable")
    for row in records:
        require(isinstance(row, dict) and isinstance(row.get("path"), str), "Invalid mount inventory")
        point = Path(row["path"])
        require(point.is_absolute(), "Invalid mountpoint")
        require(point != base and base not in point.parents, "Fixture contains a mounted filesystem; preserve it")


def scratch_volume(inventory, scratch):
    # Firmlinks such as /Users resolve to the Data volume without a lexical mount prefix.
    device = scratch.stat().st_dev
    matching = []
    for row in inventory:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str) or not isinstance(row.get("device"), str):
            continue
        point, backing = Path(row["path"]), Path(row["device"])
        if not point.is_absolute() or not backing.is_absolute():
            continue
        try:
            mount_info, backing_info = point.stat(), backing.stat()
        except OSError:
            continue
        if (mount_info.st_dev == device and stat.S_ISBLK(backing_info.st_mode)
                and backing_info.st_rdev == device):
            matching.append(row)
    require(len(matching) == 1, "Scratch filesystem could not be uniquely identified by device")
    volume = matching[0]
    require(volume.get("filesystem") == "apfs" and volume.get("readonly") is False,
            "Scratch must be writable APFS")
    return volume


def remove_fixture(path):
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)
    require(not os.path.lexists(path), "Fixture cleanup did not complete")


def fingerprint_sources():
    paths = [REPO / "pyproject.toml", REPO / "setup.py", Path(__file__)]
    paths.extend(path for path in (REPO / "stallionfs").iterdir()
                 if path.is_file() and path.suffix in {".c", ".h", ".py"})
    return {path.relative_to(REPO).as_posix(): digest(path) for path in sorted(paths)}


def write_json(path, value, previous=None):
    """Publish exclusively, or replace only this run's previous atomic checkpoint."""
    fd, temporary = tempfile.mkstemp(prefix=".fileops-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if previous is None:
            os.link(temporary, path)
        else:
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == previous,
                    "Checkpoint path changed; preserve it")
            os.replace(temporary, path)
        info = path.lstat()
        return info.st_dev, info.st_ino
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def write_new_json(path, value):
    write_json(path, value)


class ChildCompletionUnknown(RuntimeError):
    """A measurement wrapper may have left a command using the fixture."""


def measure_memory(arguments, metrics):
    """Measure one child's peak bytes; wrapper wall time is separate from timing samples."""
    started_utc = datetime.now(timezone.utc).isoformat()
    start = time.perf_counter()
    try:
        completed = command(["/usr/bin/time", "-lp", "-o", metrics, *arguments], check=False, timeout=None)
        row = {"started_utc": started_utc, "wrapper_wall_s": time.perf_counter() - start,
               "exit_code": completed.returncode, "time_output": metrics.read_text() if metrics.exists() else ""}
        if completed.returncode:
            row.update(completion_uncertain=True, error=completed.stderr.decode(errors="replace").strip())
            return row
        for key, label in (("rss_bytes", "maximum resident set size"), ("footprint_bytes", "peak memory footprint")):
            match = re.search(r"^\s*(\d+)\s+" + label + r"\s*$", row["time_output"], re.MULTILINE)
            row[key] = int(match.group(1)) if match else None
        require(row["rss_bytes"] is not None, "time did not report the child's peak RSS")
        return row
    except ChildCompletionUnknown:
        raise
    except BaseException as exc:
        raise ChildCompletionUnknown("Memory wrapper or report completion is unknown; preserve its fixture") from exc


def compare_fixture(binary, base, fixture, source, expected, operations, samples, rng, report, checkpoint,
                    *, timeout=120, memory=False):
    for operation in operations:
        for round_number in range(samples if memory else samples + 1):
            methods = ["stallionfs", "baseline"]
            rng.shuffle(methods)
            pair = {}
            for method in methods:
                target, destination = base / "target", base / "destination"
                require(not os.path.lexists(target) and not os.path.lexists(destination), "Stale fixture path")
                if operation == "clone":
                    arguments = ([binary, "clone", "--jobs", "4", source, destination] if method == "stallionfs" else
                                 ["/bin/cp", "-cRp", source, destination])
                else:
                    command(["/bin/cp", "-cRp", source, target], timeout=timeout)
                    verify_clone(source, target, expected)
                    before_move = target.lstat()
                    if operation == "delete":
                        arguments = ([binary, "delete", "--recursive", "--jobs", "4", target] if method == "stallionfs" else
                                     ["/bin/rm", "-rf", target])
                    else:
                        arguments = ([binary, "move", target, destination] if method == "stallionfs" else
                                     ["/bin/mv", "-n", target, destination])
                report["phase"] = {"fixture": fixture, "operation": operation, "method": method,
                                   "round": round_number, "measurement": "memory" if memory else "timing"}
                checkpoint()
                row = measure_memory(arguments, base / "memory.txt") if memory else measure(arguments, timeout=timeout)
                row.update(operation=operation, fixture=fixture, method=method,
                           round=round_number, warmup=not memory and round_number == 0, validated=False)
                report["memory_rows" if memory else "rows"].append(row)
                if row.get("completion_uncertain"):
                    raise ChildCompletionUnknown("Memory wrapper failed; preserve its fixture")
                checkpoint()
                require(row["exit_code"] == 0, f"Timed command failed: {row.get('error', row['exit_code'])}")
                if operation == "delete":
                    require(not os.path.lexists(target), "Deletion returned before removing its tree")
                else:
                    if operation == "clone":
                        verify_clone(source, destination, expected)
                    else:
                        require(manifest(destination) == expected, "Moved contents or metadata differ")
                        require(not os.path.lexists(target), "Move left the source behind")
                        after_move = destination.lstat()
                        require((before_move.st_dev, before_move.st_ino) ==
                                (after_move.st_dev, after_move.st_ino), "Move copied instead of renaming")
                    no_mounts_below(binary, base)
                    remove_fixture(destination)
                require((base / "outside-sentinel").read_bytes() == b"keep outside linked trees\n", "Operation followed a symlink")
                row["validated"] = True
                checkpoint()
                pair[method] = row["wrapper_wall_s" if memory else "wall_s"]
            print(json.dumps({"operation": operation, "fixture": fixture, "round": round_number,
                              "warmup": not memory and round_number == 0, "order": methods,
                              "wrapper_wall_s" if memory else "wall_s": pair}), flush=True)
        require(manifest(source) == expected, "Original source fixture changed")


def summarize(rows, keys=("wall_s", "cpu_s", "cpu_self_s", "cpu_children_s")):
    medians = {}
    for operation in BASELINES:
        selected = [row for row in rows if row["operation"] == operation]
        if not selected:
            continue
        medians[operation] = {}
        for fixture in sorted({row["fixture"] for row in selected}):
            medians[operation][fixture] = {}
            for method in ("stallionfs", "baseline"):
                samples = [row for row in selected if row["fixture"] == fixture and row["method"] == method
                           and not row["warmup"]]
                require(samples and all(row["validated"] and row["exit_code"] == 0 for row in samples),
                        "Cannot summarize incomplete or invalid samples")
                medians[operation][fixture][method] = {
                    key: statistics.median(row[key] for row in samples) if all(row[key] is not None for row in samples) else None
                    for key in keys}
    return medians


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="Installed native stallionfs executable")
    parser.add_argument("--scratch", type=Path, required=True, help="Existing APFS directory for disposable fixtures")
    parser.add_argument("--output", type=Path, required=True, help="New JSON result path")
    parser.add_argument("--suite", choices=("standard", "large", "all"), default="standard",
                        help="Large adds five synthetic clone/delete workloads; generation is sequential")
    parser.add_argument("--memory", action="store_true", help="Separate three-sample child peak-memory pass")
    parser.add_argument("--timeout", type=float, default=600, help="Timed operation/setup-copy timeout in seconds")
    args = parser.parse_args()
    require(platform.system() == "Darwin", "This comparison requires macOS")
    binary = args.binary.expanduser().resolve(strict=True)
    scratch = args.scratch.expanduser().resolve(strict=True)
    output_arg = args.output.expanduser().absolute()
    output = output_arg.parent.resolve(strict=True) / output_arg.name
    partial = output.with_name(output.name + ".partial")
    require(binary.is_file() and os.access(binary, os.X_OK), "--binary must be an executable file")
    with binary.open("rb") as stream:
        require(stream.read(4) in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe",
                                   b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"},
                "--binary must be the installed native executable, not a Python script")
    require(scratch.is_dir(), "--scratch must be an existing directory")
    require(not os.path.lexists(output) and not os.path.lexists(partial), "Output or checkpoint exists; preserve earlier results")
    require(0 < args.timeout < float("inf"), "--timeout must be finite and positive")
    require(shutil.disk_usage(scratch).free >= HEADROOM, "At least two GiB host headroom is required")
    helper = binary.with_name("stallionfs-python")
    require(helper.is_file(), "Installed Python helper is missing beside the native executable")
    version = command([binary, "--version"]).stdout.decode().strip()
    inventory = json.loads(command([binary, "--json", "volumes"]).stdout)
    require(isinstance(inventory, list) and inventory, "Mounted-filesystem inventory is unavailable")
    volume = scratch_volume(inventory, scratch)
    sources = fingerprint_sources()
    executables = {"stallionfs": binary, "stallionfs-python": helper,
                   **{name: Path(value) for name, value in BASELINES.items()}}
    if args.suite != "standard":
        executables["git"] = Path("/usr/bin/git")
    if args.memory:
        executables["time"] = Path("/usr/bin/time")
    executable_hashes = {name: digest(path) for name, path in executables.items()}
    hardware = {}
    for name in ("hw.model", "machdep.cpu.brand_string", "hw.memsize", "hw.logicalcpu"):
        result = command(["/usr/sbin/sysctl", "-n", name], check=False)
        hardware[name] = (result.stdout.decode().strip() if result.returncode == 0 else
                          {"unavailable": result.stderr.decode(errors="replace").strip()})
    _, cpu_error = cpu_usage()
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(), "system": platform.platform(),
        "python": platform.python_version(), "version": version, "hardware": hardware,
        "source_sha256": sources, "executable_sha256": executable_hashes,
        "volume": {key: volume.get(key) for key in ("filesystem", "readonly", "ignore_ownership")},
        "suite": args.suite, "samples_by_fixture": {}, "warmups": 1, "random_seed": RNG_SEED, "native_jobs": 4,
        "timeout_s": args.timeout, "status": "running", "passed": False,
        "cpu_unavailable_at_start": cpu_error, "fixtures": {}, "rows": [],
        "memory_samples_per_method": 3 if args.memory else 0, "memory_rows": [],
        "output_formats": {"stallionfs": "plain", "baseline": "plain"},
        "reference_platform": "macOS",
        "commands": {"clone": {"stallionfs": "stallionfs clone --jobs 4 SOURCE DESTINATION",
                                "baseline": "/bin/cp -cRp SOURCE DESTINATION"},
                     "delete": {"stallionfs": "stallionfs delete --recursive --jobs 4 PATH",
                                 "baseline": "/bin/rm -rf PATH"},
                     "move": {"stallionfs": "stallionfs move SOURCE DESTINATION",
                               "baseline": "/bin/mv -n SOURCE DESTINATION"}},
        "notes": [
            "Every timed command is a fresh process; wall time includes startup and completed operation.",
            "CPU is the harness self plus reaped child CPU during each timed command, not wall time or machine utilization.",
            "Fixed paired rounds use deterministic shuffled method order; all samples and warmups are retained.",
            "Tiny-file commands have 31 measured pairs; the other fixtures have seven. One warmup pair is excluded from each median.",
            "No caches are purged. Full source/setup verification reads precede timing; larger fixtures can exceed RAM, so content is not assumed resident.",
            "Setup, full content/mode/link verification and cleanup are outside timed commands and identical between methods.",
            "Clone baseline uses cp -cRp to request native cloning and preserve metadata; no weaker byte-copy baseline is substituted.",
            "Every move uses an absent exact destination on the same filesystem. Existing-destination exit-status differences are not timed.",
            "Deletion timing ends only after process exit, and absence is checked immediately; no rename-to-trash or deferred deletion.",
            "These commands do not promise fsync durability; this benchmark makes no durable-write or power-loss claim.",
            "Volumes is used only for filesystem validation and cleanup protection; diskutil device inventory is not a comparison baseline.",
            "Speedup is baseline median divided by stallionfs median; values below one retain regressions.",
            "All workloads are generated synthetic fixtures; node_modules-shaped files are not installed third-party dependencies.",
            "Large profile sizes use decimal GB (1,000,000,000 bytes) and MB (1,000,000 bytes); dependency files are 1,024 bytes each.",
            "Git profile targets refer to its committed source files; .git files/bytes and actual combined totals are reported separately.",
            "Every source byte is written. Repeated deterministic blocks are allowed; sparse files and filesystem compression are rejected.",
            "Allocated bytes sum st_blocks * 512, including directory metadata; they are not exclusive physical usage of shared APFS extents.",
            "Each large fixture is removed before generating the next; headroom covers source, a complete copy, metadata and two GiB reserve.",
            "Checkpoints and full verification are outside timed commands. Partial reports remain invalid until cleanup and frozen-hash checks pass.",
            "Optional memory rows are separate three-sample /usr/bin/time -lp child measurements; RSS and footprint are bytes, not cumulative child peaks.",
            "Memory wrapper wall time includes extra process startup and must not be compared with unwrapped timing rows; memory rows are excluded from speedups.",
        ],
    }
    base = Path(tempfile.mkdtemp(prefix="fileops-", dir=scratch))
    identity = base.stat()
    checkpoint_identity = None

    def checkpoint():
        nonlocal checkpoint_identity
        checkpoint_identity = write_json(partial, report, checkpoint_identity)

    try:
        checkpoint()
        cleanup_safe = True
        try:
            (base / "outside-sentinel").write_bytes(b"keep outside linked trees\n")
            no_mounts_below(binary, base)
            rng = random.Random(RNG_SEED)
            if args.suite != "large":
                roots = fixtures(base)
                for name, source in roots.items():
                    expected = manifest(source)
                    report["fixtures"][name] = fixture_totals(source, expected)
                    report["samples_by_fixture"][name] = SAMPLES[name]
                    compare_fixture(binary, base, name, source, expected, tuple(BASELINES), SAMPLES[name], rng,
                                    report, checkpoint, timeout=args.timeout)
                    if args.memory:
                        compare_fixture(binary, base, name, source, expected, tuple(BASELINES), 3, rng,
                                        report, checkpoint, timeout=args.timeout, memory=True)
                no_mounts_below(binary, base)
                remove_fixture(base / "fixtures")
            if args.suite != "standard":
                for name, specification in LARGE_PROFILES.items():
                    reserve = (4 if name.startswith("git_") else 2) * specification["bytes"]
                    reserve += 2 * specification["files"] * 4096 + HEADROOM
                    free = shutil.disk_usage(scratch).free
                    report["phase"] = {"fixture": name, "operation": "generate"}
                    checkpoint()
                    require(free >= reserve, f"Insufficient space for {name}: {free} free, {reserve} required")
                    source = large_fixture(base, name, specification)
                    expected = manifest(source)
                    totals = fixture_totals(source, expected)
                    require(totals["source_regular_files"] == specification["files"] and
                            totals["source_logical_bytes"] == specification["bytes"], "Generated source totals differ")
                    require(shutil.disk_usage(scratch).free >= totals["allocated_bytes"] + HEADROOM,
                            "Insufficient headroom for a complete independent fixture copy")
                    report["fixtures"][name] = {**totals, "requested_source_regular_files": specification["files"],
                                                "requested_source_logical_bytes": specification["bytes"],
                                                "free_bytes_before_generation": free, "required_free_bytes": reserve}
                    report["samples_by_fixture"][name] = 7
                    compare_fixture(binary, base, name, source, expected, ("clone", "delete"), 7, rng,
                                    report, checkpoint, timeout=args.timeout)
                    if args.memory:
                        compare_fixture(binary, base, name, source, expected, ("clone", "delete"), 3, rng,
                                        report, checkpoint, timeout=args.timeout, memory=True)
                    no_mounts_below(binary, base)
                    remove_fixture(source)
                    del expected
        except ChildCompletionUnknown:
            cleanup_safe = False
            raise
        finally:
            if not cleanup_safe:
                report["retained_fixture"] = str(base)
            else:
                try:
                    current = base.lstat()
                    require(stat.S_ISDIR(current.st_mode) and current.st_uid == os.getuid() and
                            stat.S_IMODE(current.st_mode) == 0o700 and
                            (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino),
                            "Private fixture root changed; preserve it")
                    no_mounts_below(binary, base)
                    shutil.rmtree(base)
                    require(not os.path.lexists(base), "Final fixture cleanup did not complete")
                    report["cleanup_passed"] = True
                except BaseException as exc:
                    report["retained_fixture"] = str(base)
                    raise RuntimeError(f"Cleanup uncertain; preserve fixtures at {base}: {exc}") from exc
        require(fingerprint_sources() == sources, "Source changed during benchmark; results rejected")
        require({name: digest(path) for name, path in executables.items()} == executable_hashes,
                "An executable changed during benchmark; results rejected")
        medians = summarize(report["rows"])
        report["medians"] = medians
        report["memory_medians"] = summarize(report["memory_rows"], ("rss_bytes", "footprint_bytes"))
        report["wall_speedup"] = {operation: {fixture: values["baseline"]["wall_s"] / values["stallionfs"]["wall_s"]
                                               for fixture, values in comparisons.items()}
                                    for operation, comparisons in medians.items()}
        current = partial.lstat()
        require((current.st_dev, current.st_ino) == checkpoint_identity, "Checkpoint path changed; preserve it")
        report.update(passed=True, status="complete", completed_utc=datetime.now(timezone.utc).isoformat())
        write_new_json(output, report)
    except BaseException as exc:
        report.update(passed=False, status="failed", error=f"{type(exc).__name__}: {exc}",
                      failed_utc=datetime.now(timezone.utc).isoformat())
        checkpoint()
        raise
    # The result is now published; failure to remove its checkpoint does not invalidate measurements.
    try:
        current = partial.lstat()
        if (current.st_dev, current.st_ino) == checkpoint_identity:
            partial.unlink()
    except OSError:
        print(f"Checkpoint retained: {partial}", flush=True)
    print(f"Complete paired result: {output}", flush=True)


if __name__ == "__main__":
    main()
