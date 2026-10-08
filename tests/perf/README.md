# Internal performance checks

Measured with stallionfs 0.6.2 on an Apple M2, 24 GiB RAM, macOS 27 and Python 3.13.3. JSON results retain samples, validation outcomes and source/runtime hashes.

Run from the repository with an installation outside the checkout and writable APFS scratch space. Use new output filenames:

```sh
python3 -m venv /tmp/stallionfs-perf-env
/tmp/stallionfs-perf-env/bin/python -m pip install .
mkdir -p /tmp/stallionfs-perf
```

No caches are flushed. Setup, validation and cleanup are outside timing unless stated otherwise. Uncertain child completion retains the fixture. KiB/MiB/GiB use powers of 1,024; MB/GB are decimal. Speedup is baseline/stallionfs time; signed changes are stallionfs minus baseline. CLI paired savings use Apple minus stallionfs.

CPU seconds measure total work. Average CPU cores is the median of per-sample CPU-seconds/wall-seconds ratios: command CPU for file operations, matching lifecycle CPU/wall phases for workspaces. Less CPU work does not imply lower average or instantaneous load. Peak utilization is unmeasured.

## CLI startup and structured output

The baseline path must contain a separately installed release:

```sh
/tmp/stallionfs-perf-env/bin/python tests/perf/cli.py --baseline /tmp/stallionfs-baseline/bin/stallionfs --candidate /tmp/stallionfs-perf-env/bin/stallionfs --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/cli.json
```

Requires 256 MiB free. Timings include startup and completed operations: 31 measured rounds per case, seven for the nested scan, plus one warmup, with shuffled order. Checks cover output, contents, modes, inodes and absence of a workspace store.

[CLI results](results/cli-v0.6.2-m2.json) retain 432 current-release/Apple rows; 336 prior-release rows and summaries are omitted. Tables show medians. Command CPU is user plus system time including threads (`cpu_children_s`); runner CPU is separate.

| Command | Wall ms, Apple → plain → JSON | Command CPU ms, Apple → plain → JSON |
| --- | ---: | ---: |
| Clone 4 KiB | 2.426 → 3.064 → 3.100 | 1.366 → 1.823 → 1.780 |
| Move 4 KiB | 2.536 → 3.307 → 3.465 | 1.521 → 1.932 → 2.255 |
| Delete 4 KiB | 4.403 → 4.937 → 3.247 | 2.488 → 2.994 → 1.950 |
| Scan empty folder | — → 3.111 → 4.041 | — → 1.802 → 2.456 |
| Scan 1,000 nested files | — → 3.658 → 4.063 | — → 3.695 → 3.837 |
| List mounted volumes | — → 2.927 → 2.955 | — → 1.681 → 1.710 |

Apple references are plain `cp -cRp`, `mv -n` and `rm -f`; JSON comparisons are unpaired against these plain-output measurements. No system-command reference was measured for scan or volume output. Raw paired intervals assume independent rounds. Host variation can affect the unpaired plain/JSON comparison; timestamps and sample order are retained. Memory is measured separately.

## File commands

```sh
/tmp/stallionfs-perf-env/bin/python tests/perf/fileops.py --memory --binary /tmp/stallionfs-perf-env/bin/stallionfs --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/fileops.json
```

Requires 2 GiB free. Clone, delete and move each cover a 4 KiB file, a 64 MiB file, 2,000 flat files and 10,000 nested files. References are `cp -cRp`, `rm -rf` and `mv -n`. Both copies use copy-on-write; moves use an absent exact destination. Overwrite and cross-volume behavior are outside this comparison.

Limit a run with `--fixtures flat_2000 nested_10000 --operations clone`. Unselected fixtures are never generated; JSON records selected cases and setup, validation and cleanup durations separately from command timing.

Fresh-process timings use 31 measured pairs for 4 KiB, seven otherwise, plus one warmup, with shuffled order. CPU uses `cpu_children_s`; `cpu_self_s` and aggregate `cpu_s` remain diagnostics. `--memory` adds three separate pairs using `time -lp`: child peak RSS and physical footprint, excluding the runner. Wrapped times are separate; memory counters do not measure unique filesystem-cache or APFS storage use.

Validation checks content, modes, symlinks, independent clone inodes, preserved move inodes and completed deletion. Deletion operates on a copy-on-write copy of the retained fixture. Verification reads precede timing; fixtures may exceed RAM. No durability flush is requested. `--timeout` adjusts the 600-second operation/setup-copy limit.

[File-command results](results/fileops-v0.6.2-m2.json)

| Operation | Fixture | Wall ms, Apple → stallionfs | Command CPU ms, Apple → stallionfs | Average CPU cores, Apple → stallionfs | Peak RSS KiB, Apple → stallionfs | Footprint KiB, Apple → stallionfs |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Clone | 4 KiB file | 2.573 → 3.250 | 1.467 → 1.927 | 0.581 → 0.598 | 1280.000 → 1600.000 | 1056.234 → 1152.375 |
| Clone | 64 MiB file | 3.252 → 3.842 | 1.901 → 2.285 | 0.578 → 0.596 | 1280.000 → 1600.000 | 1056.234 → 1152.375 |
| Clone | 2,000 flat files | 448.148 → 405.474 | 405.306 → 385.643 | 0.908 → 0.958 | 1952.000 → 1728.000 | 1712.234 → 1248.375 |
| Clone | 10,000 nested files | 2435.076 → 1259.987 | 2181.169 → 3687.348 | 0.886 → 2.926 | 1440.000 → 1984.000 | 1200.234 → 1520.375 |
| Delete | 4 KiB file | 2.748 → 3.271 | 1.630 → 1.922 | 0.599 → 0.582 | 1424.000 → 1600.000 | 1152.234 → 1152.375 |
| Delete | 64 MiB file | 4.905 → 5.266 | 3.428 → 3.471 | 0.699 → 0.665 | 1424.000 → 1600.000 | 1152.234 → 1152.375 |
| Delete | 2,000 flat files | 140.347 → 125.274 | 129.887 → 120.085 | 0.925 → 0.910 | 1664.000 → 1792.000 | 1440.234 → 1328.375 |
| Delete | 10,000 nested files | 995.116 → 721.404 | 853.139 → 1459.493 | 0.884 → 2.152 | 1424.000 → 1872.000 | 1184.234 → 1408.375 |
| Move | 4 KiB file | 2.772 → 3.504 | 1.538 → 2.040 | 0.568 → 0.586 | 1264.000 → 1600.000 | 1040.234 → 1152.375 |
| Move | 64 MiB file | 3.576 → 4.278 | 1.927 → 2.671 | 0.595 → 0.595 | 1264.000 → 1600.000 | 1040.234 → 1152.375 |
| Move | 2,000 flat files | 11.895 → 17.584 | 7.274 → 7.778 | 0.634 → 0.485 | 1264.000 → 1600.000 | 1040.234 → 1152.375 |
| Move | 10,000 nested files | 13.032 → 9.911 | 6.071 → 5.751 | 0.478 → 0.566 | 1264.000 → 1600.000 | 1040.234 → 1152.375 |

## Large file trees

```sh
/tmp/stallionfs-perf-env/bin/python tests/perf/fileops.py --suite large --memory --binary /tmp/stallionfs-perf-env/bin/stallionfs --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/large.json
```

Each profile measures clone and delete using the same protocol:

| Synthetic input | Source files | Source bytes |
| --- | ---: | ---: |
| Dependency-shaped JavaScript tree | 100,000 | 102.4 MB |
| Committed Git repository | 50,000 | 2 GB, plus `.git` |
| Build cache | 200,000 | 10 GB |
| HTML and assets | 5,000 | 100 MB |
| Sharded dataset | 2,000 | 50 GB |

Data is fully written; dependency files are generated, not installed packages. Git metadata is additional. Profiles run sequentially; the largest requires roughly 103 GB free. Each operation has seven timing pairs, one warmup and three memory pairs. `--suite all` includes the standard cases and moves.

Results distinguish logical/allocated bytes and file counts. APFS blocks may be shared; copy-on-write files/s is not data-transfer throughput.

Git metadata adds 13 regular files and 9,328,259 logical bytes; combined totals are 50,013 regular files and 2,009,328,259 logical bytes.

| Operation | Fixture | Wall s, Apple → stallionfs | Command CPU s, Apple → stallionfs | Average CPU cores, Apple → stallionfs | Peak RSS KiB, Apple → stallionfs | Footprint KiB, Apple → stallionfs |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Clone | Dependencies | 19.232 → 10.942 | 17.424 → 32.968 | 0.928 → 3.057 | 1776.000 → 1936.000 | 1568.258 → 1504.375 |
| Clone | Git repository | 8.050 → 4.243 | 7.461 → 13.218 | 0.937 → 3.119 | 1632.000 → 1952.000 | 1408.258 → 1488.375 |
| Clone | Build cache | 30.430 → 12.456 | 28.188 → 41.789 | 0.926 → 3.355 | 1776.000 → 1904.000 | 1616.258 → 1536.375 |
| Clone | HTML/assets | 1.244 → 0.484 | 1.138 → 1.442 | 0.915 → 2.880 | 1456.000 → 1952.000 | 1216.234 → 1488.375 |
| Clone | Dataset | 0.305 → 0.134 | 0.290 → 0.389 | 0.953 → 3.095 | 1424.000 → 1904.000 | 1184.234 → 1424.375 |
| Delete | Dependencies | 5.096 → 3.870 | 4.709 → 9.571 | 0.924 → 2.473 | 1552.000 → 1872.000 | 1328.234 → 1408.375 |
| Delete | Git repository | 3.356 → 2.776 | 2.980 → 5.716 | 0.883 → 2.016 | 1520.000 → 1920.000 | 1296.234 → 1456.375 |
| Delete | Build cache | 20.404 → 13.895 | 15.929 → 25.918 | 0.861 → 1.806 | 1568.000 → 1856.000 | 1344.234 → 1392.375 |
| Delete | HTML/assets | 0.365 → 0.176 | 0.342 → 0.512 | 0.912 → 2.784 | 1424.000 → 1872.000 | 1184.234 → 1408.375 |
| Delete | Dataset | 0.190 → 0.148 | 0.186 → 0.253 | 0.955 → 1.723 | 1440.000 → 1856.000 | 1216.234 → 1392.375 |

## Metadata scanning

```sh
/tmp/stallionfs-perf-env/bin/python tests/perf/scan.py --memory --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/scan.json
```

[Scanner results](results/scan-v0.6.2-m2.json) compare native POSIX `readdir`/`fstatat`, serial `getattrlistbulk`, and bulk with a four-worker limit. Each layout has 20,000 files plus Unicode, symlink, FIFO, sparse-file, hard-link and empty-directory checks. Nested uses 200 folders; deep40 uses a 40-directory chain. Flat and deep40 stay sequential.

The 117 timing rows include two warmups and 11 measured rounds per method/layout. Wall/process CPU include Python API overhead, excluding startup. The 27 memory rows use three fresh Python children per method/layout, including interpreter, imports and count/hash checks; they are not standalone C-engine memory measurements.

| Layout | Method | Wall ms | Process CPU ms | Average CPU cores | Python peak RSS KiB | Python footprint KiB |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Flat | POSIX | 38.37 | 38.05 | 0.992 | 18000 | 8720.49 |
| Flat | Bulk, one | 19.21 | 19.10 | 0.997 | 18000 | 8736.49 |
| Flat | Bulk, default | 20.87 | 20.43 | 0.996 | 18016 | 8736.49 |
| Nested | POSIX | 36.75 | 36.67 | 0.998 | 18048 | 8768.47 |
| Nested | Bulk, one | 20.35 | 20.21 | 0.996 | 18032 | 8768.49 |
| Nested | Bulk, default | 7.25 | 31.10 | 4.355 | 18176 | 8896.49 |
| Deep40 | POSIX | 37.39 | 37.13 | 0.993 | 18336 | 9056.49 |
| Deep40 | Bulk, one | 18.83 | 18.75 | 0.993 | 18016 | 8736.49 |
| Deep40 | Bulk, default | 20.03 | 19.86 | 0.991 | 18000 | 8736.49 |

Three memory samples provide observed ranges, not confidence intervals. Small differences within overlapping ranges do not establish a memory advantage. JSON includes the ranges and signed comparisons. This measures metadata counts and logical lengths, not content reads or other applications.

## Prepared workspaces

Use Node 24+ to fill a dedicated package cache, then compare folders:

```sh
npm ci --prefix tests/perf/fixture --ignore-scripts --no-audit --no-fund --cache /tmp/stallionfs-perf/npm-cache
/tmp/stallionfs-perf-env/bin/python tests/perf/run.py --methods worktree_install stallionfs_folder --scratch /tmp/stallionfs-perf --npm-cache /tmp/stallionfs-perf/npm-cache --output /tmp/stallionfs-perf/workspaces.json
```

[Folder results](results/workspaces-v0.6.2-node24-m2.json) use locked dependencies, 1,000 generated source files and offline installation without lifecycle scripts. Validation checks content/executable modes and React rendering, excluding Git bookkeeping. The current run retains 32 default/control batches, including four warmups, plus eight batches for an explicit two-worker experiment. Each configuration has seven measured rounds; shuffled order and timestamps are retained.

`ready_s` includes creation/setup; lifecycle adds removal and completed reclamation. CPU includes coordinator/worker threads and waited children, excluding validation. Stallionfs API timing excludes CLI startup; Git/npm startup is included. Only Git registration is serialized. Installs and deletion run concurrently; removal includes a final Git prune. Values are whole-batch medians:

| Workspaces | Method | Ready s | Ready CPU s | Lifecycle s | Lifecycle CPU s | Average CPU cores | Lifecycle range s |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Git worktree + npm ci | 2.393 | 4.890 | 3.514 | 5.811 | 1.617 | 2.784–7.519 |
| 1 | Prepared folder, jobs=4 | 1.680 | 3.924 | 2.169 | 5.237 | 2.372 | 1.154–5.297 |
| 4 | Git worktree + npm ci | 14.360 | 30.153 | 17.584 | 38.343 | 2.417 | 7.360–26.883 |
| 4 | Prepared folder, jobs=4 | 7.208 | 22.844 | 10.376 | 29.998 | 2.955 | 4.611–14.634 |

The seed held 12,581 files including Git. Cold preparation took 4.278 s and is excluded from the lifecycle figures. The baseline includes dependency installation, not just an Apple file command.

Elapsed times varied substantially across rounds, including the Git/npm control; all samples are retained. Paired intervals assume independent rounds, which host drift can violate.

With four concurrent workspaces, `jobs=2` was slower than the default in 6 of 7 paired rounds. All rows remain in JSON; the default remains four workers.

Omit `--methods` to include `prepared_byte_copy` and `stallionfs_image`, unmeasured here. Images require macOS 26+, include attach/detach, preserve ownership enforcement, disable Spotlight and default to 8 GiB (`--image-size`). Image CPU accounting excludes shared macOS helpers. Workload options: `--source-only`, `--samples`, `--concurrency`, `--source-files`.

### Workspace memory

[Workspace memory](results/workspace-memory-v0.6.2-m2.json) retains 16 batches/48 complete phases. Lifecycle peak medians use three paired rounds plus one excluded warmup per method/concurrency:

| Concurrent workspaces | Sampled lifecycle RSS MiB, Git/npm → folder | Sampled lifecycle footprint MiB, Git/npm → folder |
| ---: | ---: | ---: |
| 1 | 379.969 → 59.531 | 386.438 → 50.923 |
| 4 | 1062.922 → 58.641 | 1234.089 → 48.282 |

The sampler sums current counters for the post-setup coordinator and observed descendants, including threads; preparation/validation are excluded. Sequential queries target 5 ms intervals; actual sweeps/gaps are recorded. These are sampled group sums, not exact atomic peaks or sums of lifetime maxima. Short processes/spikes may be missed; RSS may double-count shared pages; charged footprint is not unique RAM. This run does not measure CPU/wall speedups.

Timing and memory use the same content, symlink-target and executable-mode digest, lockfile and dependencies. Fresh seed commits and Git metadata byte counts differ and are retained per batch. JSON preserves all measurements and sampling gaps, replaces personal paths with labels and omits per-PID logs.

## File I/O inside a workspace

This harness loads the checkout, so use a separate editable build:

```sh
python3 -m venv /tmp/stallionfs-io-env
/tmp/stallionfs-io-env/bin/python -m pip install -e .
/tmp/stallionfs-io-env/bin/python tests/perf/io.py --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/io.json
```

Requires macOS 26+ and 4 GiB free. A 2 GiB image is compared with ordinary APFS: 2,000 small-file creates/reads/lookups/renames/deletes, four concurrent create/read/delete workers, 64 MiB writes/reads and 20 durable 4 KiB overwrites. Seven shuffled pairs follow a warmup. Timing excludes mounting and includes Python overhead/inline validation.

Compatibility covers permissions, xattrs, hard links, symlinks, open-file unlinking, atomic replacement, Unicode and case behavior. Durable writes require `F_FULLFSYNC`; other creates are buffered and read/metadata caches are warm. Flush success does not prove power-loss recovery. Image I/O is unmeasured in this release.
