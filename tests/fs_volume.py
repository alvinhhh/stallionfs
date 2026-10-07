"""Check an existing volume with ordinary file APIs; never mount or format it.

Run: python3 tests/fs_volume.py ROOT --output results.json
Run unchanged on each candidate volume. Timings include Python overhead and
warm-cache reads. F_FULLFSYNC is mandatory for the durable write measurements.
Successful flush calls do not prove survival of a power loss or device failure.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import ctypes
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import stat
import statistics
import sys
import tempfile
import threading
import time
import unicodedata


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def fullsync(stream):
    stream.flush()
    os.fsync(stream.fileno())
    # A fast result must never come from silently weakening durability.
    fcntl.fcntl(stream.fileno(), fcntl.F_FULLFSYNC)


def check_xattr(path):
    # Python does not expose os.setxattr on macOS; use the native API directly.
    libc = ctypes.CDLL(None, use_errno=True)
    file, name, value = os.fsencode(path), b"com.stallionfs.check", b"attribute\0value"
    common = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t,
              ctypes.c_uint32, ctypes.c_int]
    libc.setxattr.argtypes = libc.getxattr.argtypes = common
    libc.getxattr.restype = ctypes.c_ssize_t
    libc.removexattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    buffer = ctypes.create_string_buffer(256)
    for operation in (lambda: libc.setxattr(file, name, value, len(value), 0, 0),
                      lambda: libc.getxattr(file, name, buffer, len(buffer), 0, 0)):
        if operation() < 0:
            raise OSError(ctypes.get_errno(), "Native extended attribute operation failed")
    require(buffer.raw[:len(value)] == value, "Extended attribute mismatch")
    if libc.removexattr(file, name, 0) < 0:
        raise OSError(ctypes.get_errno(), "Extended attribute removal failed")
    require(libc.getxattr(file, name, buffer, len(buffer), 0, 0) == -1
            and ctypes.get_errno() == errno.ENOATTR, "Extended attribute was not removed")


def compatibility(root):
    path = root / "file"
    path.write_bytes(b"original")
    with path.open("r+b", buffering=0) as stream:
        stream.seek(2)
        require(stream.write(b"XX") == 2, "Short overwrite")
        stream.truncate(5)
        require(path.read_bytes() == b"orXXi", "Overwrite/truncate changed wrong bytes")
        stream.truncate(12)
        require(path.read_bytes() == b"orXXi" + b"\0" * 7, "Extension was not zero-filled")
        os.fsync(stream.fileno())
        fullsync(stream)
    result = {"file_fsync": True, "file_fullfsync": True}
    directory_fd = os.open(root, os.O_RDONLY)
    try:
        try:
            os.fsync(directory_fd)
            result["directory_fsync"] = True
        except OSError as exc:
            if exc.errno not in (errno.EINVAL, errno.ENOTSUP):
                raise
            result["directory_fsync"] = {"supported": False, "errno": exc.errno}
    finally:
        os.close(directory_fd)

    path.chmod(0o750)
    require(stat.S_IMODE(path.stat().st_mode) == 0o750, "Mode bits did not persist")
    check_xattr(path)

    link = root / "hardlink"
    os.link(path, link)
    require(path.stat().st_ino == link.stat().st_ino, "Hardlink has a different inode")
    with link.open("r+b", buffering=0) as stream:
        require(stream.write(b"changed") == 7, "Short hardlink write")
        require(path.read_bytes().startswith(b"changed"), "Hardlink did not share writes")
        path.unlink()
        require(link.stat().st_nlink == 1, "Unlink did not reduce link count")
        link.unlink()
        require(not link.exists(), "Unlinked path remains visible")
        stream.seek(0)
        require(stream.read().startswith(b"changed"), "Unlink invalidated an open file")
        fullsync(stream)

    source = root / "directory"
    source.mkdir()
    (source / "child").write_bytes(b"nested")
    moved = root / "renamed-directory"
    source.rename(moved)
    require(not source.exists() and (moved / "child").read_bytes() == b"nested",
            "Directory rename lost content")

    # The target lies outside the directory being removed but inside our sandbox.
    sentinel = root / "outside-sentinel"
    sentinel.write_bytes(b"keep")
    links = root / "symlinks"
    links.mkdir()
    (links / "relative").symlink_to("../outside-sentinel")
    (links / "absolute").symlink_to(sentinel)
    (links / "dangling").symlink_to("missing")
    require((links / "relative").read_bytes() == b"keep", "Relative symlink failed")
    require((links / "absolute").read_bytes() == b"keep", "Absolute symlink failed")
    require((links / "dangling").is_symlink() and not (links / "dangling").exists(),
            "Dangling symlink semantics changed")
    shutil.rmtree(links)
    require(sentinel.read_bytes() == b"keep", "Cleanup followed a symlink")

    (root / "CaseProbe").write_bytes(b"case")
    result["case_sensitive"] = not (root / "caseprobe").exists()
    composed = "caf\u00e9"
    (root / composed).write_bytes(b"unicode")
    result["unicode_normalization_equivalent"] = (root / unicodedata.normalize("NFD", composed)).exists()
    require((root / composed).read_bytes() == b"unicode", "Unicode filename round trip failed")

    target = root / "atomic"
    old, new = b"a" * 65536, b"b" * 65536
    target.write_bytes(old)
    started, stop = threading.Event(), threading.Event()

    def reader():
        count = 0
        while not stop.is_set():
            require(target.read_bytes() in (old, new), "Atomic replace exposed partial content")
            count += 1
            started.set()
        return count

    with target.open("rb") as held, ThreadPoolExecutor(max_workers=1) as pool:
        reading = pool.submit(reader)
        try:
            require(started.wait(10), "Atomic replace reader failed to start")
            for i in range(100):
                replacement = root / "replacement"
                replacement.write_bytes(new if i % 2 == 0 else old)
                os.replace(replacement, target)
            require(held.read() == old, "Replace changed an already-open old inode")
        finally:
            stop.set()
        result["atomic_replace_reads"] = reading.result()
    return result


def performance(root):
    result = {}
    block = random.Random(42).randbytes(1024 * 1024)

    def measure(name, action):
        start = time.perf_counter()
        action()
        result[name] = time.perf_counter() - start

    small = root / "small"
    small.mkdir()
    paths = [small / str(i) for i in range(2000)]

    def create():
        for path in paths:
            with path.open("xb") as stream:
                require(stream.write(block[:512]) == 512, "Short small-file write")

    measure("create_2000_buffered_s", create)

    def metadata():
        for path in paths:
            info = path.stat(follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and info.st_size == 512,
                    "Small-file metadata mismatch")

    measure("stat_2000_warm_s", metadata)

    def read():
        for path in paths:
            require(path.read_bytes() == block[:512], "Small-file content mismatch")

    measure("read_2000_warm_s", read)

    def rename():
        for path in paths:
            path.rename(path.with_name(path.name + "-renamed"))

    measure("rename_2000_s", rename)
    measure("delete_2000_s", lambda: shutil.rmtree(small))
    durable = root / "durable"
    durable.write_bytes(block[:4096])

    def overwrite():
        with durable.open("r+b", buffering=0) as stream:
            for i in range(20):
                stream.seek(0)
                require(stream.write(bytes([i]) * 4096) == 4096, "Short durable write")
                fullsync(stream)
        require(durable.read_bytes() == bytes([19]) * 4096, "Durable overwrite mismatch")

    measure("overwrite_20_fullfsync_s", overwrite)
    large = root / "large"
    expected = hashlib.sha256()
    for _ in range(64):
        expected.update(block)

    def write_large():
        with large.open("xb", buffering=0) as stream:
            for _ in range(64):
                require(stream.write(block) == len(block), "Short large-file write")
            fullsync(stream)

    measure("write_64mib_fullfsync_s", write_large)

    def read_large():
        actual = hashlib.sha256()
        with large.open("rb") as stream:
            while data := stream.read(len(block)):
                actual.update(data)
        require(actual.digest() == expected.digest(), "Large-file hash mismatch")

    measure("read_64mib_warm_hash_s", read_large)

    def worker(number):
        folder = root / f"worker-{number}"
        folder.mkdir()
        for i in range(500):
            path = folder / str(i)
            value = f"{number}:{i}".encode()
            path.write_bytes(value)
            require(path.read_bytes() == value, "Concurrent file content mismatch")
        shutil.rmtree(folder)

    def parallel():
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(worker, range(4)))

    measure("parallel_4x500_create_read_delete_s", parallel)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Existing directory on the volume to check")
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.root.is_dir() or not 1 <= args.samples <= 100:
        parser.error("root must be an existing directory; samples must be between 1 and 100")
    root = Path(tempfile.mkdtemp(prefix="stallionfs-check-", dir=args.root.resolve()))
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": platform.platform(), "python": platform.python_version(),
        "samples": args.samples, "warmups": 1,
        "notes": ["Ordinary OS file APIs; Python overhead included; reads use warm caches.",
                  "Only fullfsync-labeled writes request durable completion.",
                  "Flush success does not establish power-loss, crash or device-failure recovery.",
                  "No mounts, formatting, cache purges, global settings or existing-file edits."],
    }
    try:
        checks = root / "compatibility"
        checks.mkdir()
        report["compatibility"] = compatibility(checks)
        shutil.rmtree(checks)
        rows = []
        for sample in range(args.samples + 1):
            scratch = root / f"sample-{sample}"
            scratch.mkdir()
            row = performance(scratch)
            shutil.rmtree(scratch)
            if sample:
                rows.append(row)
            print(f"Completed {'warmup' if not sample else f'sample {sample}'}", file=sys.stderr)
        report["rows"] = rows
        report["medians"] = {key: statistics.median(row[key] for row in rows) for key in rows[0]}
        report["passed"] = True
    except Exception as exc:
        report["passed"] = False
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            shutil.rmtree(root)
        except OSError as exc:
            report["passed"] = False
            report["cleanup_error"] = f"{type(exc).__name__}: {exc}"
    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(output)
    else:
        print(output, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
