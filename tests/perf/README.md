# Internal performance checks

[Expanded native comparisons and current status](../../work/BENCHMARKS.md).

JSON results retain samples, validation outcomes and source/runtime hashes.

## Latest native comparisons — 2026-10-24

All five reports use the same packaged native binary on macOS 27 arm64. Each has
ten valid pairs for direct timing and ten separate resource pairs. Values below
are native / StallionFS medians; raw samples, hashes and uncertainty are linked.
Compressed downloads are JSON (XZ); decompress before using plain-JSON readers.

| Warm fixture and reference | Direct wall | Direct CPU | Peak RSS | Paired screen |
| --- | ---: | ---: | ---: | --- |
| [4 KiB ordinary copy, `cp -Rp`](results/ordinary-copy-tiny-v0.6.3-arm64.json) | 4.857479 / 5.860917 ms | 2.5900 / 3.3275 ms | 1,032,192 / 1,671,168 B | StallionFS slower; CPU/RSS higher |
| [4 KiB move, `mv -n` — JSON (XZ)](results/native-move-tiny-20261024-arm64.json.xz) | 3.758250 / 4.704146 ms | 1.801 / 2.417 ms | 1,032,192 / 1,654,784 B | StallionFS slower; CPU/RSS higher |
| [Flat 20k scan, find/stat — JSON (XZ)](results/native-scan-flat-20261024-arm64.json.xz) | 14.145645 / 0.033494 s | 13.1820985 / 0.0298065 s | 5,079,040 / 1,769,472 B | StallionFS wall/CPU/RSS lower |
| [Nested 20k scan, find/stat — JSON (XZ)](results/native-scan-nested-20261024-arm64.json.xz) | 12.784476 / 0.017051 s | 12.3910670 / 0.0505270 s | 2,703,360 / 1,933,312 B | StallionFS wall/CPU/RSS lower |
| [Deep40 20k scan, find/stat — JSON (XZ)](results/native-scan-deep40-20261024-arm64.json.xz) | 13.018228 / 0.032026 s | 12.7617735 / 0.0286840 s | 4,063,232 / 1,769,472 B | StallionFS wall/CPU/RSS lower |

Copy and move each cover one enriched 4 KiB regular file. Move uses an absent
exact destination on the same volume and checks preserved inode identity. Its
wrapped-wall result is inconclusive; StallionFS wrapped-wall p95 is 27.401166 ms,
with no excluded samples. Scans cover `scan_flat_20k`, `scan_nested_20k` and
`scan_deep40_20k` using the existing scanner implementation. Direct wall includes
command startup; CPU includes waited children. Peak RSS is the largest individual
process peak. These warm partial runs do not complete the acceptance matrix.

Run from the repository with an installation outside the checkout and writable APFS scratch space. Use new output filenames:

```sh
python3 -m venv /tmp/stallionfs-perf-env
/tmp/stallionfs-perf-env/bin/python -m pip install .
mkdir -p /tmp/stallionfs-perf
```

Caches are flushed only for native cold-cache phases. Setup, validation and cleanup are outside timing unless stated otherwise. Uncertain child completion retains the fixture. KiB/MiB/GiB use powers of 1,024; MB/GB are decimal. Speedup is baseline/stallionfs time; signed changes are stallionfs minus baseline. CLI paired savings use Apple minus stallionfs.

CPU seconds measure total work. Average CPU cores is the median of per-sample CPU-seconds/wall-seconds ratios: command CPU for file operations, matching lifecycle CPU/wall phases for workspaces. Less CPU work does not imply lower average or instantaneous load. Peak utilization is unmeasured.

## Sequential campaign

With the isolated installation above, Node 24 or newer and an existing offline
npm cache containing the locked fixture dependencies:

```sh
/tmp/stallionfs-perf-env/bin/python tests/perf/campaign.py \
  --binary /tmp/stallionfs-perf-env/bin/stallionfs \
  --scratch /tmp/stallionfs-perf --output-dir /tmp/stallionfs-campaign \
  --node /path/to/node --npm /path/to/npm/bin/npm-cli.js \
  --npm-cache /path/to/isolated-npm-cache
```

The output directory must be new. Three outer cycles each collect all 13 existing
native file-operation fixtures (including installed dependencies), the three
native command scan layouts, the 20,000-file scanner API comparison with memory,
and folder-workspace lifecycle comparisons at concurrency one and four. Each
stage uses ten measured rounds by default (`--samples`, minimum ten). Native
stages use one internal repetition per outer cycle; the older fileops campaigns
are not run again. This includes the existing 50 GB dataset and its copies.

`--cache warm cold` is the default for native command stages. The API scanner and
workspace stages remain warm. A denied purge is retained and never retried by
later stages: warm work continues, or subsequent native stages are recorded as
unavailable when only cold was requested. Nothing is installed or downloaded.

`campaign.json` checkpoints stage arguments, exit status, log/report references
and source/runtime fingerprints. Native status is read from the small manifest,
with journal length checked; the driver does not independently verify its full
journal or final JSON. Completed native correctness/cache failures remain in the
campaign and allow later stages only after confirmed cleanup. Failed, incomplete
or uncertain completion stops the driver. Existing evidence is never resumed or
replaced.

Exit zero means the selected collection completed its checks, not that every
metric won; `all_metrics_won` remains false. Finder, mounted FSKit resources,
workspace peak memory/full metadata equivalence, external-drive repeats,
replacement/exchange moves, mount listing, image/recovery workflows and
CLI JSON/startup-only cases remain outside this campaign, as does mounted-image
steady-state I/O. Child reports retain their
measurement limits and failures. Review local paths before publishing reports.

API scanner attempts check source contents and metadata before and after each
call. A small three-layout collection with separate memory children passed these
checks; the complete campaign remains unqualified. Use `native_suite.py --runs 1`
for a single native diagnostic run. It omits the campaign's API and workspace
stages and does not establish a complete acceptance suite.

## CLI startup and structured output

The baseline path must contain a separately installed release:

```sh
/tmp/stallionfs-perf-env/bin/python tests/perf/cli.py --baseline /tmp/stallionfs-baseline/bin/stallionfs --candidate /tmp/stallionfs-perf-env/bin/stallionfs --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/cli.json
```

Requires 256 MiB free. Timings include startup and completed operations: 31 measured rounds per case, seven for the nested scan, plus one warmup, with shuffled order. Checks cover output, contents, modes, inodes and absence of a workspace store.

Apple references are plain `cp -cRp`, `mv -n` and `rm -f`; JSON comparisons are unpaired against these plain-output measurements. No system-command reference was measured for scan or volume output. Raw paired intervals assume independent rounds. Host variation can affect the unpaired plain/JSON comparison; timestamps and sample order are retained. Memory is measured separately.

## File commands

```sh
/tmp/stallionfs-perf-env/bin/python tests/perf/fileops.py --memory --binary /tmp/stallionfs-perf-env/bin/stallionfs --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/fileops.json
```

Requires 2 GiB free. Clone, delete and move each cover a 4 KiB file, a 64 MiB file, 2,000 flat files and 10,000 nested files. References are `cp -cRp`, `rm -rf` and `mv -n`. Both copies use copy-on-write; moves use an absent exact destination. Overwrite and cross-volume behavior are outside this comparison.

Limit a run with `--fixtures flat_2000 nested_10000 --operations clone`. Unselected fixtures are never generated; JSON records selected cases and setup, validation and cleanup durations separately from command timing.

Fresh-process timings use 31 measured pairs for 4 KiB, seven otherwise, plus one warmup, with shuffled order. CPU uses `cpu_children_s`; `cpu_self_s` and aggregate `cpu_s` remain diagnostics. `--memory` adds three separate pairs using `time -lp`: child peak RSS and physical footprint, excluding the runner. Wrapped times are separate; memory counters do not measure unique filesystem-cache or APFS storage use.

Validation checks content, modes, symlinks, independent clone inodes, preserved move inodes and completed deletion. Deletion operates on a copy-on-write copy of the retained fixture. Verification reads precede timing; fixtures may exceed RAM. No durability flush is requested. `--timeout` adjusts the 600-second operation/setup-copy limit.

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

## Metadata scanning

```sh
/tmp/stallionfs-perf-env/bin/python tests/perf/scan.py --memory --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/scan.json
```

New runs require at least ten measured rounds. `--memory` uses the same sample
count in separate processes. Reports include paired wall, CPU and RSS
comparisons with p95 and sample variance; warmups are excluded.

Each run checks source contents and metadata before and after scanning. Fixtures
include populated ACLs, xattrs and resource forks. Validation runs outside the
timed call and memory child; a failure stops collection and retains the fixture.

The scanner compares native POSIX `readdir`/`fstatat`, serial `getattrlistbulk`, and bulk with a four-worker limit. Each layout has 20,000 files plus Unicode, symlink, FIFO, sparse-file, hard-link and empty-directory checks. Nested uses 200 folders; deep40 uses a 40-directory chain. Flat and deep40 stay sequential.

Wall/process CPU include Python API overhead, excluding startup. Memory measurements use fresh Python children per method/layout, including interpreter, imports and count/hash checks; they are not standalone C-engine memory measurements.

Observed memory ranges are not confidence intervals. Small differences within overlapping ranges do not establish a memory advantage. JSON includes the ranges and signed comparisons. This measures metadata counts and logical lengths, not content reads or other applications.

### Native scan commands

The opt-in command comparison reuses the exact 20,000-file flat, nested and
deep40 fixtures above, including sparse files, hardlinks, symlinks and a FIFO:

```sh
/tmp/stallionfs-perf-env/bin/python tests/perf/native_suite.py --binary /tmp/stallionfs-perf-env/bin/stallionfs --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/native-scan.json --operations scan --fixtures scan_flat_20k scan_nested_20k scan_deep40_20k --cache warm
```

It compares `stallionfs --json scan ROOT` with this native recipe:

```sh
/usr/bin/find -P -x ROOT -mindepth 1 -exec /usr/bin/stat -f '%Op%t%Dz%t%Dd' -- '{}' +
```

Both commands must match all six counters and leave source contents and metadata
unchanged. Symlinks are not followed; hardlinked names count separately. The
numeric protocol contains no filenames. Malformed output and diagnostics fail
validation.

The runner collects three runs of ten pairs per phase. Find/stat includes helper
startup and per-entry output; its counters are aggregated after timing.
StallionFS aggregates inside its command. CPU includes waited children; peak RSS
is the largest individual process peak, not their simultaneous memory use.
These are comparisons on stable trees, not concurrent mutation tests.

Raw stdout is retained losslessly in `stdout_gzip_b64`, with its original hash
and length in `stdout_sha256` and `stdout_bytes`. Compression and validation run
after timing. Incomplete collector receipts can retain the original raw fields.

## Prepared workspaces

Use Node 24+ to fill a dedicated package cache, then compare folders:

```sh
npm ci --prefix tests/perf/fixture --ignore-scripts --no-audit --no-fund --cache /tmp/stallionfs-perf/npm-cache
/tmp/stallionfs-perf-env/bin/python tests/perf/run.py --methods worktree_install stallionfs_folder --scratch /tmp/stallionfs-perf --npm-cache /tmp/stallionfs-perf/npm-cache --output /tmp/stallionfs-perf/workspaces.json
```

New runs require at least ten measured rounds (the default). Reports include
p95, sample variance and paired lifecycle wall/CPU comparisons against
`worktree_install`; a lower median alone does not establish a win. These
comparisons exclude memory and full metadata equivalence.

The baseline includes dependency installation, not just an Apple file command. Paired intervals assume independent rounds, which host drift can violate.
Folder comparisons use locked dependencies, generated source files and offline installation without lifecycle scripts. Validation checks content/executable modes and React rendering, excluding Git bookkeeping.

`ready_s` includes creation/setup; lifecycle adds removal and completed reclamation. CPU includes coordinator/worker threads and waited children, excluding validation. Stallionfs API timing excludes CLI startup; Git/npm startup is included. Only Git registration is serialized. Installs and deletion run concurrently; removal includes a final Git prune.

Omit `--methods` to include `prepared_byte_copy` and `stallionfs_image`, unmeasured here. Images require macOS 26+, include attach/detach, preserve ownership enforcement, disable Spotlight and default to 8 GiB (`--image-size`). Image CPU accounting excludes shared macOS helpers. Workload options: `--source-only`, `--samples`, `--concurrency`, `--source-files`.

### Workspace memory

The sampler sums current counters for the post-setup coordinator and observed descendants, including threads; preparation/validation are excluded. Sequential queries target 5 ms intervals; actual sweeps/gaps are recorded. These are sampled group sums, not exact atomic peaks or sums of lifetime maxima. Short processes/spikes may be missed; RSS may double-count shared pages; charged footprint is not unique RAM. Memory sampling does not measure CPU/wall speedups.

## File I/O inside a workspace

This harness loads the checkout, so use a separate editable build:

```sh
python3 -m venv /tmp/stallionfs-io-env
/tmp/stallionfs-io-env/bin/python -m pip install -e .
/tmp/stallionfs-io-env/bin/python tests/perf/io.py --scratch /tmp/stallionfs-perf --output /tmp/stallionfs-perf/io.json
```

Requires macOS 26+ and 4 GiB free. A 2 GiB image is compared with ordinary APFS: 2,000 small-file creates/reads/lookups/renames/deletes, four concurrent create/read/delete workers, 64 MiB writes/reads and 20 durable 4 KiB overwrites. Seven shuffled pairs follow a warmup. Timing excludes mounting and includes Python overhead/inline validation.

Compatibility covers permissions, xattrs, hard links, symlinks, open-file unlinking, atomic replacement, Unicode and case behavior. Durable writes require `F_FULLFSYNC`; other creates are buffered and read/metadata caches are warm. Flush success does not prove power-loss recovery. Image I/O is unmeasured in this release.

## Installed dependencies

`installed_dependencies` uses the checked-in package lock to install a real `node_modules` tree. It requires Node 24 or newer, the npm JavaScript entrypoint, and an existing isolated npm cache containing the locked packages. Missing cache entries fail preparation; the suite does not download packages or run package lifecycle scripts.

```sh
python tests/perf/native_suite.py \
  --binary /path/to/installed/stallionfs \
  --scratch /path/to/apfs/scratch \
  --output /path/to/new-result.json \
  --fixtures installed_dependencies \
  --node /path/to/node \
  --npm /path/to/npm/bin/npm-cli.js \
  --npm-cache /path/to/isolated-npm-cache
```

Installation, the fixture's `check.cjs`, and a TypeScript CLI version check run before measurement. The matching locked TypeScript platform package must be installed; a successful npm exit alone is insufficient. Results record the actual file count, bytes, canonical source-manifest hash, dependency versions, lock hashes, Node/npm versions, commands, and cache path. Runtime hashes cover the Node executable and npm entrypoint/package manifest; the entire npm package tree is not pinned. The cache is retained. The separate `dependencies_100k` fixture remains synthetic and does not represent installed packages.

The npm cache may receive npm metadata and logs. Keep it outside personal projects. Setup failures retain their command receipts; uncertain child completion also retains the disposable fixture for inspection.

Both npm version inspection and installation use the disposable project prefix and empty user/global configuration files. The manifest hash is SHA-256 of UTF-8 JSON with sorted keys and compact separators; it identifies the observed snapshot, not a saved copy of its contents.

## Native clone sharing

The native suite observes regular-file data-stream clone attributes through the
already-open validation descriptors. Destination attributes are compared with
the post-copy source. StallionFS and `cp -cRp` require positive sharing evidence
for every data-bearing regular-file stream; ordinary `cp`, `ditto` and `rsync`
record sharing separately from copy correctness. Unsupported attributes and
zero identifiers remain unknown. Empty and observed holes-only streams are not
positive evidence; a tree with no qualifying streams remains unknown.

Matching nonzero clone IDs and full-sharing flags do not establish resource-fork
sharing or disk-space savings. Observations are sequential, not atomic. Every
pair's raw attributes and returned masks are retained as gzip/base64 JSON Lines
with an uncompressed SHA-256 and byte length. Encoding occurs outside timing
and streams directly into compressed storage. The exporter validates these
records before replacing explicitly selected path prefixes. Numeric scan output
is also validated and preserved byte for byte.

## Native report storage

During a run, `--output result.json` writes `result.json.journal` and
`result.json.manifest`. The journal appends raw measurements and subsequent
validation results; the manifest records the last committed prefix and its
SHA-256. Previous measurements are not rewritten at every checkpoint. The runner
keeps the current comparison in memory and writes the usual schema 1
`result.json` once at completion, including handled failures.

Keep the journal and manifest together. Interrupted or failed writes retain
their evidence; readers reject a truncated, changed or uncommitted tail. Runs
cannot resume from a journal. These checks do not establish power-loss recovery.

To export a large report without loading it all into memory, pass its manifest:

```sh
python tests/perf/export_native.py /path/to/result.json.manifest \
  /path/to/new-export.json --alias /path/to/private/root SCRATCH
```

The export uses the same schema and measurements, with explicit path
substitutions and provenance hashes. Review the content before publishing;
unrecognized strings are not automatically scrubbed. Regular JSON input remains
supported. Output paths must be new.
