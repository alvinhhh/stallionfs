# Internal performance checks

## Metadata scanning

Build the installed extension first, then compare its bulk scanner with the private native POSIX reference path:

```sh
python3 -m pip install -e .
mkdir -p /tmp/stallionfs-perf
python3 tests/perf/scan.py --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/scan.json
```

Both paths are C implementations that retrieve the same counts and logical lengths. The baseline uses `readdir` and `fstatat`; the optimized path uses `getattrlistbulk`. The test creates flat and nested 20,000-file layouts, plus symlinks, a FIFO, Unicode names, a sparse file and a hard link. Every result must equal independently calculated fixture totals. Two warmups are discarded, then 11 samples run in shuffled order. API timings include the same Python call overhead and exclude fixture creation and process startup. This does not measure reads of file contents or acceleration inside other applications.

Recorded results: [M2 metadata scans, 0.3.0](results/scan-v0.3-m2.json). Bulk scanning took 20.90 ms versus 41.67 ms for the flat layout (1.99×), and 25.93 ms versus 47.86 ms for nested folders (1.85×). Neither result reaches a strict 2× threshold. [Earlier 0.2.0 results](results/scan-m2.json) remain available.

## Prepared workspaces

The fixture is a locked JavaScript dependency tree with 1,000 generated source files. Tests compare:

- `git worktree add` followed by an offline `npm ci` from a warm package cache.
- A full byte copy of an already prepared standalone repository.
- A stallionfs folder clone from the same prepared repository.
- A stallionfs APFS image clone, including mounting and unmounting its volume.

Install the fixture's packages once to populate a dedicated cache, then run on APFS:

```sh
mkdir -p /tmp/stallionfs-perf
npm ci --prefix tests/perf/fixture --ignore-scripts --no-audit --no-fund --cache /tmp/stallionfs-perf/npm-cache
python3 tests/perf/run.py --scratch /tmp/stallionfs-perf --npm-cache /tmp/stallionfs-perf/npm-cache --output /tmp/stallionfs-perf/results.json
```

Use macOS 26+ and Node 24+ for this comparison. Package lifecycle scripts are disabled in the fixture. stallionfs itself does not need Node or npm. Images have an 8 GiB capacity by default; `--image-size` changes it.

Image volumes use the product defaults: Spotlight indexing disabled, file ownership enabled. The host's indexing configuration is unchanged.

Git worktree registration runs one call at a time because concurrent `git worktree add` calls can race on shared repository metadata. Dependency installation and directory deletion run in parallel. A final `git worktree prune` is included in removal time, and the test verifies that no worktrees remain registered.

One warmup batch per method is discarded. Seven measured samples run in a deterministic shuffled order, at one and four concurrent workspaces. Every generated workspace must match the prepared tree's content and executable-mode digest and render a small React component successfully. Git bookkeeping differs between standalone clones and linked worktrees and is excluded from the digest. Validation time is excluded from all methods' timing.

`ready_s` measures creation plus required installation or image attachment. `remove_s` includes image detachment where applicable. `reclaim_s` includes full trash deletion for stallionfs. `total_s` is their sum. Worktree and byte-copy removal already reclaim their directories. The one-time seed cost is reported separately for each backend, with the number of workspaces needed to amortize it using median total times. Parallel batches are wall time for the entire batch, not per-workspace latencies.

`--source-only` measures the same source checkout without dependency preparation. `--samples`, `--concurrency` and `--source-files` change the load. The package cache and filesystem cache are warm; the test does not flush OS caches, download packages during measurement, or measure unique APFS physical storage. Raw samples include hardware and software versions. Keep failed validation as a failure; never report its partial timings as a result.

This uses the Python API. CLI process startup is excluded for stallionfs; Git/npm subprocess startup is included in their operations. These are local workspace timings, not agent inference or general filesystem benchmarks. Results depend on file count, dependency layout, hardware, system load and cache state.

Results include every measured sample, source-file hashes and the loaded native binary's hash. The runner rejects results if runtime source or the loaded native binary changes during measurement. Image allocation reports `st_blocks`, which does not distinguish shared APFS blocks from unique physical storage. Seed break-even is calculated from medians, not a guarantee for another workload.

Recorded results: [M2 workspaces, 0.3.0](results/workspaces-v0.3-m2.json). Image workspace creation and full cleanup took median 1.55 seconds for one workspace and 3.42 seconds for four, versus 6.14 and 23.10 seconds for worktree/install. The one-time image preparation took 12.28 seconds, recovered after three workspaces at these medians.

This run had substantial timing variation. Full-cycle ranges were 5.13–24.85 seconds for one worktree/install versus 1.38–2.75 seconds for one image, and 11.28–42.82 seconds versus 2.44–4.18 seconds for four. All seven samples are retained. Folder cloning was slower than worktree/install for one workspace in this run.

Earlier results: [M2 workspaces, 0.2.0](results/workspaces-m2.json), where folder clones were roughly tied with worktree/install.

## File I/O inside a workspace

Compare ordinary APFS folders with an already-mounted image workspace:

```sh
python3 tests/perf/io.py --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/io.json
```

Use macOS 26+ and allow at least 4 GiB of free space. The test creates its own source repository and 2 GiB image through the production workspace API, then compares the same operations on both volumes. One warmup pair is discarded and seven measured pairs run in shuffled order. Image creation and mounting are excluded here; the workspace comparison above includes those costs.

Operations cover 2,000 small-file creates, reads, metadata lookups, renames and deletes; four concurrent create/read/delete workers; 64 MiB writes and reads; and 20 durable 4 KiB overwrites. Durable writes require `F_FULLFSYNC` on both volumes. Other creates are buffered; read and metadata caches are warm. Timings include equal Python overhead and inline validation.

Compatibility checks cover permissions, extended attributes, hard links, symlinks, open-file unlinking, atomic replacement, case handling and Unicode names. Successful flush calls do not prove recovery from power loss or hardware failure. The runner records volume flags, code hashes, raw samples and all regressions, and only writes a final result after validation and safe cleanup.

Recorded results: [M2 file I/O, 0.3.0](results/io-v0.3-m2.json). Medians over seven pairs, in milliseconds:

| Operation | APFS folder | APFS image |
| --- | ---: | ---: |
| Create 2,000 small files (buffered) | 250.08 | 347.40 |
| Look up metadata for 2,000 files | 6.30 | 6.33 |
| Read 2,000 small files (warm) | 52.91 | 47.66 |
| Rename 2,000 files | 184.63 | 189.75 |
| Delete 2,000 files | 92.50 | 116.20 |
| 20 durable 4 KiB overwrites | 116.38 | 249.18 |
| Write 64 MiB durably | 33.74 | 126.26 |
| Read and hash 64 MiB (warm) | 35.45 | 35.28 |
| Four workers: create, read and delete 500 files each | 181.68 | 462.52 |

The image backend does not accelerate general file I/O. Durable overwrite latency was 2.14× higher, durable 64 MiB writes took 3.74× as long, and concurrent file operations took 2.55× as long. Metadata lookups and large warm reads were roughly tied. Compatibility checks matched on both volumes, and cleanup completed. The published result removes the OS mount-owner account annotation; timings and functional mount flags are unchanged.
