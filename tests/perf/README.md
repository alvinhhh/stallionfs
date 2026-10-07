# Internal performance checks

Measured with stallionfs 0.6.1 on an Apple M2, 24 GiB RAM, macOS 27 and Python 3.13.3. JSON results retain samples, validation outcomes and source/runtime hashes.

The final package adds a Python interruption diagnostic fix after measurement. Native binaries and the workspace API are byte-identical; the changed dispatcher is outside every measured path. Each JSON records both package hashes and the change under `release_applicability`.

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

[CLI results](results/cli-v0.6.1-m2.json) retain 432 current-release/Apple rows; 336 prior-release rows and summaries are omitted. Tables show medians. Command CPU is user plus system time including threads (`cpu_children_s`); runner CPU is separate.

| Command | Wall ms, Apple → plain → JSON | Command CPU ms, Apple → plain → JSON |
| --- | ---: | ---: |
| Clone 4 KiB | 2.191 → 2.791 → 2.735 | 1.214 → 1.639 → 1.602 |
| Move 4 KiB | 2.121 → 2.837 → 2.814 | 1.144 → 1.604 → 1.611 |
| Delete 4 KiB | 2.209 → 2.656 → 2.712 | 1.233 → 1.533 → 1.538 |
| Scan empty folder | — → 2.651 → 2.537 | — → 1.493 → 1.441 |
| Scan 1,000 nested files | — → 2.951 → 3.011 | — → 2.680 → 2.835 |
| List mounted volumes | — → 2.617 → 2.676 | — → 1.476 → 1.524 |

Apple references are plain `cp -cRp`, `mv -n` and `rm -f`; JSON comparisons are unpaired against these plain-output measurements. No system-command reference was measured for scan or volume output. Raw paired intervals assume independent rounds. Memory is measured separately.

## File commands

```sh
/tmp/stallionfs-perf-env/bin/python tests/perf/fileops.py --memory --binary /tmp/stallionfs-perf-env/bin/stallionfs --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/fileops.json
```

Requires 2 GiB free. Clone, delete and move each cover a 4 KiB file, a 64 MiB file, 2,000 flat files and 10,000 nested files. References are `cp -cRp`, `rm -rf` and `mv -n`. Both copies use copy-on-write; moves use an absent exact destination. Overwrite and cross-volume behavior are outside this comparison.

Limit a run with `--fixtures flat_2000 nested_10000 --operations clone`. Unselected fixtures are never generated; JSON records selected cases and setup, validation and cleanup durations separately from command timing.

Fresh-process timings use 31 measured pairs for 4 KiB, seven otherwise, plus one warmup, with shuffled order. CPU uses `cpu_children_s`; `cpu_self_s` and aggregate `cpu_s` remain diagnostics. `--memory` adds three separate pairs using `time -lp`: child peak RSS and physical footprint, excluding the runner. Wrapped times are separate; memory counters do not measure unique filesystem-cache or APFS storage use.

Validation checks content, modes, symlinks, independent clone inodes, preserved move inodes and completed deletion. Deletion operates on a copy-on-write copy of the retained fixture. Verification reads precede timing; fixtures may exceed RAM. No durability flush is requested. `--timeout` adjusts the 600-second operation/setup-copy limit.

[File-command results](results/fileops-v0.6.1-m2.json). The combined standard/large run retains 496 timing rows (44 warmups) and 132 memory rows. JSON also includes user/system CPU, observed memory ranges and signed comparisons.

| Operation | Fixture | Wall ms, Apple → stallionfs | Command CPU ms, Apple → stallionfs | Average CPU cores, Apple → stallionfs | Peak RSS KiB, Apple → stallionfs | Footprint KiB, Apple → stallionfs |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Clone | 4 KiB file | 2.317 → 2.856 | 1.311 → 1.650 | 0.567 → 0.585 | 1280.000 → 1600.000 | 1056.234 → 1152.375 |
| Clone | 64 MiB file | 2.787 → 3.289 | 1.633 → 1.877 | 0.575 → 0.588 | 1280.000 → 1600.000 | 1056.234 → 1152.375 |
| Clone | 2,000 flat files | 196.945 → 186.781 | 192.384 → 185.085 | 0.980 → 0.991 | 1952.000 → 1728.000 | 1712.234 → 1264.375 |
| Clone | 10,000 nested files | 1136.211 → 422.773 | 1114.945 → 1530.642 | 0.982 → 3.620 | 1440.000 → 1936.000 | 1200.234 → 1472.375 |
| Delete | 4 KiB file | 2.343 → 2.964 | 1.319 → 1.690 | 0.575 → 0.573 | 1424.000 → 1600.000 | 1152.234 → 1152.375 |
| Delete | 64 MiB file | 3.913 → 4.514 | 2.449 → 2.884 | 0.683 → 0.635 | 1424.000 → 1600.000 | 1152.234 → 1152.375 |
| Delete | 2,000 flat files | 54.525 → 47.731 | 51.097 → 46.250 | 0.964 → 0.968 | 1664.000 → 1808.000 | 1440.234 → 1344.375 |
| Delete | 10,000 nested files | 390.566 → 178.170 | 375.642 → 533.704 | 0.955 → 3.052 | 1424.000 → 1888.000 | 1184.234 → 1424.375 |
| Move | 4 KiB file | 2.288 → 2.937 | 1.241 → 1.684 | 0.548 → 0.574 | 1264.000 → 1600.000 | 1040.234 → 1152.375 |
| Move | 64 MiB file | 2.933 → 3.747 | 1.601 → 2.172 | 0.551 → 0.571 | 1264.000 → 1600.000 | 1040.234 → 1152.375 |
| Move | 2,000 flat files | 3.452 → 4.111 | 2.141 → 2.564 | 0.642 → 0.615 | 1264.000 → 1600.000 | 1040.234 → 1152.375 |
| Move | 10,000 nested files | 3.527 → 4.378 | 1.871 → 2.273 | 0.546 → 0.534 | 1264.000 → 1600.000 | 1040.234 → 1152.375 |

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

Git metadata adds 13 regular files and 9,248,301 logical bytes; combined totals are 50,013 regular files and 2,009,248,301 logical bytes.

| Operation | Fixture | Wall s, Apple → stallionfs | Command CPU s, Apple → stallionfs | Average CPU cores, Apple → stallionfs | Peak RSS KiB, Apple → stallionfs | Footprint KiB, Apple → stallionfs |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Clone | Dependencies | 12.411 → 4.373 | 12.048 → 15.828 | 0.967 → 3.621 | 1792.000 → 1968.000 | 1568.258 → 1504.375 |
| Clone | Git repository | 6.069 → 2.188 | 5.842 → 7.535 | 0.967 → 3.446 | 1632.000 → 1968.000 | 1408.258 → 1504.375 |
| Clone | Build cache | 24.995 → 8.754 | 24.101 → 30.262 | 0.959 → 3.463 | 1824.000 → 1968.000 | 1600.258 → 1504.375 |
| Clone | HTML/assets | 0.604 → 0.235 | 0.587 → 0.805 | 0.971 → 3.433 | 1456.000 → 1936.000 | 1216.234 → 1472.375 |
| Clone | Dataset | 0.241 → 0.091 | 0.234 → 0.303 | 0.968 → 3.383 | 1424.000 → 1872.000 | 1184.234 → 1408.375 |
| Delete | Dependencies | 4.042 → 1.800 | 3.806 → 5.815 | 0.939 → 3.249 | 1552.000 → 1904.000 | 1328.234 → 1440.375 |
| Delete | Git repository | 2.089 → 0.948 | 1.927 → 2.970 | 0.931 → 3.129 | 1520.000 → 1888.000 | 1296.234 → 1440.398 |
| Delete | Build cache | 8.210 → 4.146 | 7.688 → 11.899 | 0.936 → 2.894 | 1568.000 → 1920.000 | 1344.234 → 1456.375 |
| Delete | HTML/assets | 0.199 → 0.100 | 0.192 → 0.324 | 0.957 → 3.259 | 1424.000 → 1872.000 | 1184.234 → 1408.375 |
| Delete | Dataset | 0.196 → 0.140 | 0.184 → 0.242 | 0.954 → 1.699 | 1440.000 → 1888.000 | 1216.234 → 1424.375 |

## Metadata scanning

```sh
/tmp/stallionfs-perf-env/bin/python tests/perf/scan.py --memory --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/scan.json
```

[Scanner results](results/scan-v0.6.1-m2.json) compare native POSIX `readdir`/`fstatat`, serial `getattrlistbulk`, and bulk with a four-worker limit. Each layout has 20,000 files plus Unicode, symlink, FIFO, sparse-file, hard-link and empty-directory checks. Nested uses 200 folders; deep40 uses a 40-directory chain. Flat and deep40 stay sequential.

The 117 timing rows include two warmups and 11 measured rounds per method/layout. Wall/process CPU include Python API overhead, excluding startup. The 27 memory rows use three fresh Python children per method/layout, including interpreter, imports and count/hash checks; they are not standalone C-engine memory measurements.

| Layout | Method | Wall ms | Process CPU ms | Python peak RSS KiB | Python footprint KiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Flat | POSIX | 32.56 | 32.54 | 18032 | 8752.47 |
| Flat | Bulk, one | 16.30 | 16.28 | 18032 | 8752.47 |
| Flat | Bulk, default | 16.18 | 16.18 | 18016 | 8752.49 |
| Nested | POSIX | 35.42 | 35.17 | 18000 | 8736.49 |
| Nested | Bulk, one | 17.01 | 17.00 | 18016 | 8752.49 |
| Nested | Bulk, default | 7.51 | 32.41 | 18160 | 8864.49 |
| Deep40 | POSIX | 29.62 | 29.59 | 18272 | 8992.49 |
| Deep40 | Bulk, one | 13.34 | 13.34 | 18016 | 8752.49 |
| Deep40 | Bulk, default | 12.97 | 12.97 | 18048 | 8768.47 |

The flat RSS difference is one 16 KiB page within overlapping observed ranges; three samples do not establish a gain beyond variation. JSON includes ranges and signed comparisons. This measures metadata counts and logical lengths, not content reads or other applications.

## Prepared workspaces

Use Node 24+ to fill a dedicated package cache, then compare folders:

```sh
npm ci --prefix tests/perf/fixture --ignore-scripts --no-audit --no-fund --cache /tmp/stallionfs-perf/npm-cache
/tmp/stallionfs-perf-env/bin/python tests/perf/run.py --methods worktree_install stallionfs_folder --scratch /tmp/stallionfs-perf --npm-cache /tmp/stallionfs-perf/npm-cache --output /tmp/stallionfs-perf/workspaces.json
```

[Folder results](results/workspaces-v0.6.1-node24-m2.json) use locked dependencies, 1,000 generated source files and offline installation without lifecycle scripts. Validation checks content/executable modes and React rendering, excluding Git bookkeeping. The 28 rows retain seven batches per method/concurrency; warmup rows and method order were not recorded.

`ready_s` includes creation/setup; lifecycle adds removal and completed reclamation. CPU includes coordinator/worker threads and waited children, excluding validation. Stallionfs API timing excludes CLI startup; Git/npm startup is included. Only Git registration is serialized. Installs and deletion run concurrently; removal includes a final Git prune. Values are whole-batch medians:

| Workspaces | Method | Ready s | Ready CPU s | Lifecycle s | Lifecycle CPU s | Average CPU cores | Lifecycle range s |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Git worktree + npm ci | 1.296 | 2.868 | 2.014 | 3.496 | 1.751 | 1.919–2.112 |
| 1 | Prepared folder | 0.683 | 2.206 | 0.963 | 2.931 | 3.030 | 0.927–1.001 |
| 4 | Git worktree + npm ci | 3.892 | 13.833 | 5.527 | 17.848 | 3.269 | 5.240–5.758 |
| 4 | Prepared folder | 2.612 | 10.564 | 3.642 | 13.611 | 3.682 | 3.595–4.504 |

The seed held 12,581 files including Git. Preparation took 1.906 s, amortized after two workspaces using median lifecycle savings. The baseline includes dependency installation, not just an Apple file command.

Omit `--methods` to include `prepared_byte_copy` and `stallionfs_image`, unmeasured here. Images require macOS 26+, include attach/detach, preserve ownership enforcement, disable Spotlight and default to 8 GiB (`--image-size`). Image CPU accounting excludes shared macOS helpers. Workload options: `--source-only`, `--samples`, `--concurrency`, `--source-files`.

### Workspace memory

[Workspace memory](results/workspace-memory-v0.6.1-m2.json) retains 16 batches/48 complete phases. Lifecycle peak medians use three paired rounds plus one excluded warmup per method/concurrency:

| Workspaces | Sampled RSS MiB, Git/npm → folder | Charged footprint MiB, Git/npm → folder |
| ---: | ---: | ---: |
| 1 | 422.45 → 65.08 | 385.20 → 49.44 |
| 4 | 1287.16 → 74.30 | 1314.69 → 53.88 |

The sampler sums current counters for the post-setup coordinator and observed descendants, including threads; preparation/validation are excluded. Sequential queries target 5 ms intervals; actual sweeps/gaps are recorded. These are sampled group sums, not exact atomic peaks or sums of lifetime maxima. Short processes/spikes may be missed; RSS may double-count shared pages; charged footprint is not unique RAM. This run does not measure CPU/wall speedups.

Timing and memory fixture digests differ; cross-protocol identity is not established. JSON retains measurement hashes, replaces personal paths with labels and omits per-PID logs.

## File I/O inside a workspace

This harness loads the checkout, so use a separate editable build:

```sh
python3 -m venv /tmp/stallionfs-io-env
/tmp/stallionfs-io-env/bin/python -m pip install -e .
/tmp/stallionfs-io-env/bin/python tests/perf/io.py --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/io.json
```

Requires macOS 26+ and 4 GiB free. A 2 GiB image is compared with ordinary APFS: 2,000 small-file creates/reads/lookups/renames/deletes, four concurrent create/read/delete workers, 64 MiB writes/reads and 20 durable 4 KiB overwrites. Seven shuffled pairs follow a warmup. Timing excludes mounting and includes Python overhead/inline validation.

Compatibility covers permissions, xattrs, hard links, symlinks, open-file unlinking, atomic replacement, Unicode and case behavior. Durable writes require `F_FULLFSYNC`; other creates are buffered and read/metadata caches are warm. Flush success does not prove power-loss recovery. Image I/O is unmeasured in this release.
