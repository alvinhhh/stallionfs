"""Compare installed file commands with native macOS commands on private fixtures.

All commands include process startup. Content checks and fixture setup are outside
timing. Results appear only after every correctness check and cleanup succeeds.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import random
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


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(arguments, *, check=True):
    result = subprocess.run([str(arg) for arg in arguments], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=120, umask=0o077)
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


def measure(arguments):
    before, before_error = cpu_usage()
    started_utc = datetime.now(timezone.utc).isoformat()
    start = time.perf_counter()
    command(arguments)
    wall = time.perf_counter() - start
    after, after_error = cpu_usage()
    result = {"started_utc": started_utc, "wall_s": wall}
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


def write_new_json(path, value):
    # Publish a fully written report without replacing a report created by another run.
    fd, temporary = tempfile.mkstemp(prefix=".fileops-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="Installed native stallionfs executable")
    parser.add_argument("--scratch", type=Path, required=True, help="Existing APFS directory for disposable fixtures")
    parser.add_argument("--output", type=Path, required=True, help="New JSON result path")
    args = parser.parse_args()
    require(platform.system() == "Darwin", "This comparison requires macOS")
    binary = args.binary.expanduser().resolve(strict=True)
    scratch = args.scratch.expanduser().resolve(strict=True)
    output_arg = args.output.expanduser().absolute()
    output = output_arg.parent.resolve(strict=True) / output_arg.name
    require(binary.is_file() and os.access(binary, os.X_OK), "--binary must be an executable file")
    with binary.open("rb") as stream:
        require(stream.read(4) in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe",
                                   b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"},
                "--binary must be the installed native executable, not a Python script")
    require(scratch.is_dir(), "--scratch must be an existing directory")
    require(not os.path.lexists(output), "Output already exists; preserve earlier results")
    require(shutil.disk_usage(scratch).free >= 2 * 1024**3, "At least two GiB host headroom is required")
    helper = binary.with_name("stallionfs-python")
    require(helper.is_file(), "Installed Python helper is missing beside the native executable")
    version = command([binary, "--version"]).stdout.decode().strip()
    inventory = json.loads(command([binary, "--json", "volumes"]).stdout)
    require(isinstance(inventory, list) and inventory, "Mounted-filesystem inventory is unavailable")
    volume = scratch_volume(inventory, scratch)
    sources = fingerprint_sources()
    executables = {"stallionfs": binary, "stallionfs-python": helper,
                   **{name: Path(value) for name, value in BASELINES.items()}}
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
        "samples_by_fixture": SAMPLES, "warmups": 1, "random_seed": RNG_SEED, "native_jobs": 4,
        "cpu_unavailable_at_start": cpu_error, "fixtures": {}, "rows": [],
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
            "Sources and setup copies are read before timing; these are warm-cache measurements without cache purges.",
            "Setup, full content/mode/link verification and cleanup are outside timed commands and identical between methods.",
            "Clone baseline uses cp -cRp to request native cloning and preserve metadata; no weaker byte-copy baseline is substituted.",
            "Every move uses an absent exact destination on the same filesystem. Existing-destination exit-status differences are not timed.",
            "Deletion timing ends only after process exit, and absence is checked immediately; no rename-to-trash or deferred deletion.",
            "These commands do not promise fsync durability; this benchmark makes no durable-write or power-loss claim.",
            "Volumes is used only for filesystem validation and cleanup protection; diskutil device inventory is not a comparison baseline.",
            "Speedup is baseline median divided by stallionfs median; values below one retain regressions.",
        ],
    }
    base = Path(tempfile.mkdtemp(prefix="fileops-", dir=scratch))
    identity = base.stat()
    try:
        (base / "outside-sentinel").write_bytes(b"keep outside linked trees\n")
        roots = fixtures(base)
        expected = {name: manifest(path) for name, path in roots.items()}
        for name, snapshot in expected.items():
            report["fixtures"][name] = {
                "regular_files": sum(row["kind"] == "file" for row in snapshot.values()),
                "directories": sum(row["kind"] == "directory" for row in snapshot.values()),
                "symlinks": sum(row["kind"] == "symlink" for row in snapshot.values()),
                "logical_bytes": sum(row.get("size", 0) for row in snapshot.values()),
            }
        no_mounts_below(binary, base)
        rng = random.Random(RNG_SEED)
        for operation in ("clone", "delete", "move"):
            for fixture, source in roots.items():
                for round_number in range(SAMPLES[fixture] + 1):
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
                            command(["/bin/cp", "-cRp", source, target])
                            verify_clone(source, target, expected[fixture])
                            before_move = target.lstat()
                            if operation == "delete":
                                arguments = ([binary, "delete", "--recursive", "--jobs", "4", target] if method == "stallionfs" else
                                             ["/bin/rm", "-rf", target])
                            else:
                                arguments = ([binary, "move", target, destination] if method == "stallionfs" else
                                             ["/bin/mv", "-n", target, destination])
                        row = measure(arguments)
                        row.update(operation=operation, fixture=fixture, method=method,
                                   round=round_number, warmup=round_number == 0)
                        report["rows"].append(row)
                        if operation == "delete":
                            require(not os.path.lexists(target), "Deletion returned before removing its tree")
                        else:
                            if operation == "clone":
                                verify_clone(source, destination, expected[fixture])
                            else:
                                require(manifest(destination) == expected[fixture], "Moved contents or metadata differ")
                                require(not os.path.lexists(target), "Move left the source behind")
                                after_move = destination.lstat()
                                require((before_move.st_dev, before_move.st_ino) ==
                                        (after_move.st_dev, after_move.st_ino), "Move copied instead of renaming")
                            remove_fixture(destination)
                        require((base / "outside-sentinel").read_bytes() == b"keep outside linked trees\n", "Operation followed a symlink")
                        pair[method] = row["wall_s"]
                    print(json.dumps({"operation": operation, "fixture": fixture, "round": round_number,
                                      "warmup": round_number == 0, "order": methods, "wall_s": pair}), flush=True)
                require(manifest(source) == expected[fixture], "Original source fixture changed")
    finally:
        try:
            current = base.lstat()
            require(stat.S_ISDIR(current.st_mode) and current.st_uid == os.getuid() and
                    stat.S_IMODE(current.st_mode) == 0o700 and
                    (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino),
                    "Private fixture root changed; preserve it")
            no_mounts_below(binary, base)
            shutil.rmtree(base)
            require(not os.path.lexists(base), "Final fixture cleanup did not complete")
        except BaseException as exc:
            raise RuntimeError(f"Cleanup uncertain; preserve fixtures at {base}: {exc}") from exc
    require(fingerprint_sources() == sources, "Source changed during benchmark; results rejected")
    require({name: digest(path) for name, path in executables.items()} == executable_hashes,
            "An executable changed during benchmark; results rejected")
    medians = {}
    for operation in BASELINES:
        medians[operation] = {}
        for fixture in SAMPLES:
            medians[operation][fixture] = {}
            for method in ("stallionfs", "baseline"):
                rows = [r for r in report["rows"] if r["operation"] == operation and r["fixture"] == fixture
                        and r["method"] == method and not r["warmup"]]
                medians[operation][fixture][method] = {
                    key: statistics.median(r[key] for r in rows) if all(r[key] is not None for r in rows) else None
                    for key in ("wall_s", "cpu_s", "cpu_self_s", "cpu_children_s")}
    report["medians"] = medians
    report["wall_speedup"] = {operation: {fixture: values["baseline"]["wall_s"] / values["stallionfs"]["wall_s"]
                                           for fixture, values in comparisons.items()}
                                for operation, comparisons in medians.items()}
    report["passed"] = True
    report["completed_utc"] = datetime.now(timezone.utc).isoformat()
    write_new_json(output, report)
    print(f"Complete paired result: {output}", flush=True)


if __name__ == "__main__":
    main()
