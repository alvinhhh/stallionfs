# Internal performance checks

## Metadata scanning

Build the installed extension first, then compare its bulk scanner with the private native POSIX reference path:

```sh
python3 -m pip install -e .
mkdir -p /tmp/stallionfs-perf
python3 tests/perf/scan.py --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/scan.json
```

Both paths are C implementations that retrieve the same counts and logical lengths. The baseline uses `readdir` and `fstatat`; the optimized path uses `getattrlistbulk`. The test creates flat and nested 20,000-file layouts, plus symlinks, a FIFO, Unicode names, a sparse file and a hard link. Every result must equal independently calculated fixture totals. Two warmups are discarded, then 11 samples run in shuffled order. API timings include the same Python call overhead and exclude fixture creation and process startup. This does not measure reads of file contents or acceleration inside other applications.

Recorded results: [M2 metadata scans](results/scan-m2.json).

## Prepared workspaces

The fixture is a locked JavaScript dependency tree with 1,000 generated source files. Tests compare:

- `git worktree add` followed by an offline `npm ci` from a warm package cache.
- A full byte copy of an already prepared standalone repository.
- A stallionfs workspace from the same prepared repository.

Install the fixture's packages once to populate a dedicated cache, then run on APFS:

```sh
mkdir -p /tmp/stallionfs-perf
npm ci --prefix tests/perf/fixture --ignore-scripts --no-audit --no-fund --cache /tmp/stallionfs-perf/npm-cache
python3 tests/perf/run.py --scratch /tmp/stallionfs-perf --npm-cache /tmp/stallionfs-perf/npm-cache --output /tmp/stallionfs-perf/results.json
```

Use a supported Node version for the fixture (Node 24+). Package lifecycle scripts are disabled in this fixture. stallionfs itself does not need Node or npm.

One warmup batch per method is discarded. Seven measured samples run in a deterministic shuffled order, at one and four concurrent workspaces. Every generated workspace must match the prepared tree's content and executable-mode digest and render a small React component successfully. Git bookkeeping differs between standalone clones and linked worktrees and is excluded from the digest. Validation time is excluded from all methods' timing.

`ready_s` measures creation plus required installation. `remove_s` measures immediate removal. `reclaim_s` includes full trash deletion for stallionfs. `total_s` is their sum. Worktree and byte-copy removal already reclaim their directories. The one-time seed cost is reported separately, with the number of workspaces needed to amortize it using median total times. Parallel batches are wall time for the entire batch, not per-workspace latencies.

`--source-only` measures the same source checkout without dependency preparation. `--samples`, `--concurrency` and `--source-files` change the load. The package cache and filesystem cache are warm; the test does not flush OS caches, download packages during measurement, or measure unique APFS physical storage. Raw samples include hardware and software versions. Keep failed validation as a failure; never report its partial timings as a result.

This uses the Python API. CLI process startup is excluded for stallionfs; Git/npm subprocess startup is included in their operations. These are local workspace timings, not agent inference or general filesystem benchmarks. Results depend on file count, dependency layout, hardware, system load and cache state.

Recorded results: [M2 workspaces](results/workspaces-m2.json). The median complete lifecycle was roughly tied with worktree/install; it was faster than copying a prepared tree byte-for-byte. Host load varied substantially: all raw samples, including the slower ones, are retained. The calculated seed break-even is arithmetic on medians and does not establish a reliable benefit when those medians are this close.
