"""Compare the shipped bulk scanner with an equivalent native POSIX traversal."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from stallionfs._scan import scan


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--files', type=int, default=20000)
    parser.add_argument('--samples', type=int, default=11)
    args = parser.parse_args()
    if not 1 <= args.files <= 1000000 or not 1 <= args.samples <= 100:
        parser.error('Use 1–1,000,000 files and 1–100 samples')
    rng = random.Random(20261006)
    source = Path(__file__).resolve().parents[2] / 'stallionfs/_scan.c'
    result = {'timestamp': datetime.now(timezone.utc).isoformat(), 'system': platform.platform(),
              'cpu': subprocess.check_output(['sysctl', '-n', 'machdep.cpu.brand_string'], text=True).strip(),
              'memory_bytes': int(subprocess.check_output(['sysctl', '-n', 'hw.memsize'])),
              'implementation_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
              'python': platform.python_version(), 'samples': args.samples, 'warmup_rounds': 2,
              'timing': 'Python API wall time; native implementations; warm OS cache; no process startup',
              'workloads': {}}
    with tempfile.TemporaryDirectory(prefix='stallionfs-scan-', dir=args.scratch.resolve()) as directory:
        root = Path(directory)
        for layout in ('flat', 'nested'):
            path = root / layout
            path.mkdir()
            for i in range(args.files):
                parent = path if layout == 'flat' else path / str(i // 100)
                parent.mkdir(exist_ok=True)
                (parent / f'file-{i}').write_bytes(bytes([i % 256]) * (i % 1024))
            (path / 'empty').mkdir()
            (path / 'space and \n café 🐎').write_bytes(b'hello')
            (path / 'directory-link').symlink_to('empty', target_is_directory=True)
            (path / 'dangling-link').symlink_to('absent')
            (path / 'outside-link').symlink_to('/')
            os.mkfifo(path / 'pipe')
            with (path / 'sparse').open('wb') as stream:
                stream.truncate(1 << 20)
            os.link(path / 'sparse', path / 'hard-link')
            expected = dict(files=args.files + 3, directories=1 + ((args.files + 99) // 100 if layout == 'nested' else 0),
                            symlinks=3, other=1, logical_bytes=sum(i % 1024 for i in range(args.files)) + 5 + (2 << 20),
                            skipped_mounts=0)
            rows = {'posix': [], 'bulk': []}
            for index in range(args.samples + 2):
                order = list(rows)
                rng.shuffle(order)
                for method in order:
                    start = time.perf_counter()
                    observed = scan(path, bulk=method == 'bulk')
                    elapsed = time.perf_counter() - start
                    if observed != expected:
                        raise RuntimeError(f'{method}: expected {expected}, got {observed}')
                    if index >= 2:
                        rows[method].append(elapsed)
            medians = {method: statistics.median(samples) for method, samples in rows.items()}
            result['workloads'][layout] = {'expected': expected, 'raw_seconds': rows, 'median_seconds': medians,
                                          'speedup': medians['posix'] / medians['bulk']}
            print(layout, json.dumps(medians), flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
