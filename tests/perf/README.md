# Internal performance checks

## CLI startup and structured output

Compare two releases installed into separate virtual environments:

```sh
python3 tests/perf/cli.py --baseline .venv-old/bin/stallionfs --candidate .venv-new/bin/stallionfs --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/cli.json
```

The existing scratch directory must be on writable APFS with 256 MiB free. This measures plain and JSON clone, move and delete on a 4 KiB file; scans of an empty folder and a nested 1,000-file fixture; and mounted-filesystem output. Every invocation starts a new process. There are 31 measured pairs per case, seven for the nested scan, and one retained warmup. Method order is shuffled with a fixed seed. Small plain file operations also include separate `/bin/cp -cRp`, `/bin/mv -n` and `/bin/rm -f` references; these are not interchangeable commands outside the controlled fixture.

Output contracts, counts, checksums, modes, inode behavior, source independence and the absence of an unnecessary workspace store are checked outside timing. No volume is mounted and no large fixture is created. Results retain every sample, wall and CPU time, and source plus installed-runtime hashes. A final report is written only after validation and cleanup; it omits personal paths and raw command output. Release-to-release speedups and Apple-command comparisons are reported separately. Keep both installations and the runtime source unchanged during the run.

Recorded results: [M2 command startup, 0.6.0](results/cli-v0.6-m2.json). This current-release view retains all 432 current-release and macOS samples, including warmups. Internal prior-release controls are omitted; the report records its source digest and row counts. Every retained sample passed validation and cleanup.

| Command | Plain output | JSON output | macOS plain-output reference |
| --- | ---: | ---: | ---: |
| Copy one 4 KiB file | 3.18 ms | 3.08 ms | 2.46 ms |
| Move one 4 KiB file | 3.09 ms | 3.17 ms | 2.29 ms |
| Delete one 4 KiB file | 3.07 ms | 3.43 ms | 2.49 ms |
| Scan an empty folder | 3.01 ms | 3.00 ms | — |
| Scan 1,000 files | 3.64 ms | 3.28 ms | — |
| List mounted volumes | 2.90 ms | 3.05 ms | — |

JSON file commands use the separately measured macOS plain-output reference; those comparisons are unpaired and the reference does not format JSON. No equivalent system command was measured for scans or mounted-volume output. The scanner API comparison below supplies its POSIX baseline. Small-file commands remain slower than the macOS references.

## File commands

Compare the installed native executable with `/bin/cp -cRp`, `/bin/rm -rf` and `/bin/mv -n`:

```sh
python3 tests/perf/fileops.py --binary .venv/bin/stallionfs --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/fileops.json
```

The scratch directory must exist on writable APFS with at least 2 GiB free. The fixtures are a 4 KiB file, a 64 MiB file, 2,000 files in one folder and 10,000 files across nested folders. Each timed command starts a new process. There are 31 measured pairs for the small file and seven for each larger fixture, plus one excluded warmup pair. Pair order is shuffled with a fixed seed.

Copying uses native copy-on-write on both sides. Every copy and move must preserve the fixture's contents, modes and symlink targets; clones must have independent inodes. Moves use an absent exact destination and must preserve the inode. Deletion must finish before returning. Fixture setup, validation and cleanup are outside timing. Results include wall time, process and child CPU, source and executable hashes, and every sample. These are warm-cache operations without a durability flush.

Recorded results: [M2 file commands, 0.6.0](results/fileops-v0.6-m2.json). All 336 samples, including warmups, passed validation and cleanup. CPU is total process time across threads and children; it can exceed wall time.

| Operation | Fixture | macOS wall | stallionfs wall | Speedup | macOS CPU | stallionfs CPU |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Clone | 4 KiB file | 2.40 ms | 3.17 ms | 0.76× | 2.26 ms | 2.86 ms |
| Clone | 64 MiB file | 3.49 ms | 3.81 ms | 0.91× | 3.13 ms | 3.43 ms |
| Clone | 2,000 flat files | 200.84 ms | 194.40 ms | 1.03× | 198.85 ms | 192.37 ms |
| Clone | 10,000 nested files | 1203.80 ms | 439.49 ms | 2.74× | 1185.63 ms | 1571.50 ms |
| Delete | 4 KiB file | 2.80 ms | 3.60 ms | 0.78× | 2.72 ms | 3.09 ms |
| Delete | 64 MiB file | 5.27 ms | 5.54 ms | 0.95× | 4.97 ms | 4.85 ms |
| Delete | 2,000 flat files | 54.82 ms | 58.55 ms | 0.94× | 54.64 ms | 54.60 ms |
| Delete | 10,000 nested files | 408.05 ms | 197.70 ms | 2.06× | 385.20 ms | 530.82 ms |
| Move | 4 KiB file | 2.41 ms | 3.13 ms | 0.77× | 2.20 ms | 2.77 ms |
| Move | 64 MiB file | 3.41 ms | 4.26 ms | 0.80× | 3.40 ms | 3.76 ms |
| Move | 2,000 flat files | 3.94 ms | 4.87 ms | 0.81× | 3.91 ms | 4.49 ms |
| Move | 10,000 nested files | 3.80 ms | 5.25 ms | 0.72× | 3.69 ms | 4.82 ms |

Nested copying reached about 22,750 files/s, versus 8,300 files/s for `cp`. The larger gains use more CPU: nested copying used 33% more, deletion 38% more. Flat deletion, single-file commands and every move case were slower. `--jobs 1` provides a lower-CPU option; these command results use the default four workers.

## Metadata scanning

Build the installed extension first, then compare its bulk scanner with the private native POSIX reference path:

```sh
python3 -m pip install -e .
mkdir -p /tmp/stallionfs-perf
python3 tests/perf/scan.py --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/scan.json
```

All three paths are C implementations that retrieve the same counts and logical lengths. The baseline uses `readdir` and `fstatat`; the optimized paths use `getattrlistbulk`, with one worker or the default four. Folders with fewer than two immediate subdirectories stay sequential. The test creates flat and nested 20,000-file layouts, plus symlinks, a FIFO, Unicode names, a sparse file and a hard link. Every result must equal independently calculated fixture totals. Two warmups are discarded, then 11 samples run in shuffled order. Wall and process CPU timings include the same Python call overhead and exclude fixture creation and process startup. This does not measure reads of file contents or acceleration inside other applications.

Recorded results: [M2 metadata scans, 0.6.0](results/scan-v0.6-m2.json). Every measured scan returned the same totals.

| Layout | Method | Wall | CPU |
| --- | --- | ---: | ---: |
| 20,000 flat files | Native POSIX | 38.20 ms | 38.08 ms |
| 20,000 flat files | Bulk, one worker | 21.39 ms | 21.32 ms |
| 20,000 flat files | Bulk, default | 20.30 ms | 20.27 ms |
| 20,000 files across 200 folders | Native POSIX | 46.64 ms | 43.72 ms |
| 20,000 files across 200 folders | Bulk, one worker | 24.82 ms | 24.16 ms |
| 20,000 files across 200 folders | Bulk, default | 10.10 ms | 41.34 ms |

Default scanning was 1.88× faster than POSIX for flat folders and 4.62× faster for nested folders. Nested parallel scanning was 2.46× faster than serial bulk scanning and used 71% more CPU. Flat folders do not start worker threads.

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

`--source-only` measures the same source checkout without dependency preparation. `--samples`, `--concurrency` and `--source-files` change the load. Use `--methods worktree_install stallionfs_folder` for a folder-only comparison; unselected image workspaces are not prepared. The package cache and filesystem cache are warm; the test does not flush OS caches, download packages during measurement, or measure unique APFS physical storage. Raw samples include hardware and software versions. Keep failed validation as a failure; never report its partial timings as a result.

Format 3 also records process CPU, including worker threads and waited child processes, over the same phases as wall time. Validation is excluded from both.

This uses the Python API. CLI process startup is excluded for stallionfs; Git/npm subprocess startup is included in their operations. These are local workspace timings, not agent inference or general filesystem benchmarks. Results depend on file count, dependency layout, hardware, system load and cache state.

Results include every measured sample, source-file hashes and the loaded native binary's hash. The runner rejects results if runtime source or the loaded native binary changes during measurement. Image allocation reports `st_blocks`, which does not distinguish shared APFS blocks from unique physical storage. Seed break-even is calculated from medians, not a guarantee for another workload.

Recorded results: [M2 prepared folder workspaces, 0.6.0](results/workspaces-v0.6-node24-m2.json). The 28 measured batches and their warmups passed content, executable-mode, fixture smoke and cleanup checks. This run selected `worktree_install` and `stallionfs_folder`; images and byte copies were not measured.

| Workspaces | Method | Ready | Reclaim | Full lifecycle | Total CPU | Lifecycle range |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Git worktree + npm ci | 6.785 s | Included in removal | 9.134 s | 10.706 s | 7.575–24.092 s |
| 1 | Prepared folder | 3.601 s | 1.130 s | 4.983 s | 9.070 s | 4.106–9.289 s |
| 4 | Git worktree + npm ci | 22.134 s | Included in removal | 27.824 s | 49.335 s | 20.583–45.339 s |
| 4 | Prepared folder | 9.376 s | 3.996 s | 13.596 s | 39.114 s | 12.326–41.594 s |

The seed contained 12,581 regular files, including Git metadata. Preparation took 2.907 s with the warm npm cache, amortized after one workspace using this run's median lifecycle savings.

Single-workspace lifecycle was 1.83× faster with 15% less CPU; four-workspace lifecycle was 2.05× faster with 21% less CPU. Every paired lifecycle comparison favored prepared folders, but the ranges show substantial variation. The 41.594 s folder batch, including 32.375 s of reclamation, is retained. These are measurements of this release, not a claim of improvement over a previous release.

## File I/O inside a workspace

Compare ordinary APFS folders with an already-mounted image workspace:

```sh
python3 tests/perf/io.py --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/io.json
```

Use macOS 26+ and allow at least 4 GiB of free space. The test creates its own source repository and 2 GiB image through the production workspace API, then compares the same operations on both volumes. One warmup pair is discarded and seven measured pairs run in shuffled order. Image creation and mounting are excluded here; the workspace comparison above includes those costs.

Operations cover 2,000 small-file creates, reads, metadata lookups, renames and deletes; four concurrent create/read/delete workers; 64 MiB writes and reads; and 20 durable 4 KiB overwrites. Durable writes require `F_FULLFSYNC` on both volumes. Other creates are buffered; read and metadata caches are warm. Timings include equal Python overhead and inline validation.

Compatibility checks cover permissions, extended attributes, hard links, symlinks, open-file unlinking, atomic replacement, case handling and Unicode names. Successful flush calls do not prove recovery from power loss or hardware failure. The runner records volume flags, code hashes, raw samples and all regressions, and only writes a final result after validation and safe cleanup.

No image I/O figures are shown until this comparison has been run on the current release. Image workspaces are intended for repeated workspace creation; they do not establish faster general file I/O.
