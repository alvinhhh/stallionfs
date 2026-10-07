"""Compare two installed CLIs, including startup, on small private fixtures."""
import argparse
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
import tempfile
import time

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
    for item in [path, *sorted(path.rglob("*"))]:
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True, help="Older installed CLI in a virtual environment")
    parser.add_argument("--candidate", type=Path, required=True, help="New installed CLI in a separate virtual environment")
    parser.add_argument("--scratch", type=Path, required=True, help="Existing writable APFS directory")
    parser.add_argument("--output", type=Path, required=True, help="New sanitized JSON result path")
    args = parser.parse_args()
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
    main()
