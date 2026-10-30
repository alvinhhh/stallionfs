# Internal performance checks

[Expanded native comparisons and current status](../../work/BENCHMARKS.md).

JSON results retain samples, validation outcomes and source/runtime hashes.

## Current native comparisons — October 29–30, 2026 (UTC)

macOS 27 arm64, warm fixtures, ten direct timing pairs and ten separate resource pairs per row. Values are native / StallionFS medians. Linked JSON (XZ) retains all samples, actual commands, CPU, reported RSS, p95, sample variance, precision floors, correctness and paired decisions; decompress before using a plain-JSON reader.

| Fixture and reference | Direct wall | Direct CPU | Reported RSS | Paired screen |
| --- | ---: | ---: | ---: | --- |
| [4 KiB ordinary copy, `cp -Rp`](results/ordinary-copy-tiny-20261030-arm64.json.xz) | 7.156500 / 9.539208 ms | 4.207000 / 5.710000 ms | 1,081,344 / 1,671,168 B | Wall gap inconclusive; CPU/RSS higher |
| [4 KiB move, `mv -n`](results/native-move-tiny-direct-controls-20261030-arm64.json.xz) | 3.730521 / 4.360750 ms | 1.854000 / 2.422000 ms | 1,032,192 / 1,654,784 B | Slower; CPU inconclusive; RSS higher |
| [Flat 20k scan, recorded find/stat](results/native-scans-20k-20261030-arm64.json.xz) | 11.416478 / 0.033169 s | 11.182524 / 0.029916 s | 5,111,808 / 1,769,472 B | Wall/CPU/RSS lower |
| [Nested 20k scan, recorded find/stat](results/native-scans-20k-20261030-arm64.json.xz) | 12.136531 / 0.017766 s | 11.955517 / 0.054096 s | 2,588,672 / 1,933,312 B | Wall/CPU/RSS lower |
| [Deep40 20k scan, recorded find/stat](results/native-scans-20k-20261030-arm64.json.xz) | 12.614668 / 0.034431 s | 12.410770 / 0.031100 s | 3,997,696 / 1,769,472 B | Wall/CPU/RSS lower |
| [Document clone, explicit `--jobs 2`, ditto](results/native-clone-docs-jobs2-20261029-arm64.json.xz) | 0.763839 / 0.356793 s | 0.741951 / 0.661337 s | 1,818,624 / 1,916,928 B | Wall/CPU lower; RSS higher |
| [Document clone, default 4 workers (`--jobs 4`), ditto](results/native-clone-docs-default4-20261029-arm64.json.xz) | 0.738710 / 0.219446 s | 0.709180 / 0.778186 s | 1,818,624 / 1,998,848 B | Wall lower; CPU/RSS higher |

RSS means `/usr/bin/time -lp reported maximum RSS`: a reported process peak, not whole-system or aggregate descendant memory. Earlier exec-image coverage is unproven. Direct CPU uses serialized reaped-child accounting; rounded-zero resource CPU does not establish a CPU win. Copy's higher elapsed median has an inconclusive wall gap under the paired noise screen and the 0.01 ms single-file floor.

The measured executable is `fb743b75ea6053a0f3060e97e54ca95ab15f21d9fc6186c644eb56b8c960c7d1`, built from commit `0a1c708f5461f92bf085d5a9a8a072b7b8ce86ee` (tree `0364901cbbbab92b8a9741cba41f7c60bd0bb8f3`). Its five native C/header hashes match current source. This is native-content equivalence, not a new build of the newer main or managed Python lifecycle. The move file is an explicitly derived direct-control subset of an interleaved collection; it is not a canonical-harness rerun.

### Measured commands and inputs

Recorded native command templates use the exact flags below; the data files retain each actual path and resource wrapper after explicit path redaction:

```sh
/bin/cp -Rp SOURCE DESTINATION
/bin/mv -n SOURCE DESTINATION
/usr/bin/ditto --rsrc --extattr --acl SOURCE DESTINATION
stallionfs copy SOURCE DESTINATION
stallionfs move SOURCE DESTINATION
stallionfs clone --jobs 2 SOURCE DESTINATION
stallionfs clone --jobs 4 SOURCE DESTINATION
/usr/bin/find -P -x ROOT -mindepth 1 -exec /usr/bin/stat -f '%Op%t%Dz%t%Dd' -- '{}' +
stallionfs --json scan ROOT
```

Scan comparisons apply only to that find/stat numeric-output recipe, not native scanners generally. Both sides count six stable-tree fields; content-read throughput is not measured. The enriched scan fixtures contain 20,003 regular-file names and 12,196,597 logical bytes, plus three symlinks and one special entry. Directory counts including root are 2 flat, 202 nested and 42 deep40. Copy and move each use one enriched 4,096-byte file. The document tree contains 5,002 regular files, 105 directories including root and 116,777,216 logical bytes. Generated ACL/xattr, hardlink, sparse, source-stability and command-specific correctness observations remain in the data.

The clone configurations are the same workload. Two workers are explicit; the four-worker row records `--jobs 4`, matching the default setting. Both preserve the observed RSS increase. No worker default was changed. Older raw result files remain available.

### Linux/OpenZFS descriptive references

Separate warm document-tree cells, ten direct and ten GNU Time resource samples each; these are unpaired native references, with no StallionFS comparison.

| Method | Direct wall median | Direct CPU median | Reported RSS median |
| --- | ---: | ---: | ---: |
| [GNU cp `--reflink=never`](results/linux-openzfs-docs-ordinary-20261030.json.xz) | 1.340353690 s | 0.864389000 s | 1,728,512 B |
| [GNU cp `--reflink=always`](results/linux-openzfs-docs-required-reflink-20261030.json.xz) | 0.714952497 s | 0.713276500 s | 1,728,512 B |

Linux VM on a macOS APFS-backed disk file. GNU Time reports per-process maximum RSS, converted from KiB to bytes once, excluding ARC, kernel and guest/host caches. Required-reflink API acceptance and the first validated destination's aggregate pool-counter corroboration are distinct; full per-file physical sharing and exclusive storage savings remain unknown. These descriptive cells establish no causal filesystem/product win.

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

Exit zero means the selected collection completed its correctness checks.
Release acceptance requires three consecutive complete suites with every required
comparison correct and lower wall time plus lower CPU or lower peak RSS, beyond
precision and observed variation. `all_metrics_won` remains a placeholder, not
an implemented release decision. Finder, mounted FSKit resources,
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

On macOS, the native suite observes regular-file data-stream clone attributes through the
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

## Linux/OpenZFS native references

Linux admits one existing workload, `docs_5k_100mb`, with warm cache, ten direct
and ten resource samples, one run, and no StallionFS binary or worker-count
option. Select one method per new report:

```sh
python tests/perf/native_suite.py --scratch /path/on/zfs \
  --output /path/to/new-copy.json --fixtures docs_5k_100mb \
  --operations copy --copy-tools cp --cache warm --samples 10 --runs 1 --timeout 120

python tests/perf/native_suite.py --scratch /path/on/zfs \
  --output /path/to/new-clone.json --fixtures docs_5k_100mb \
  --operations clone --copy-tools cp-clone --cache warm --samples 10 --runs 1 --timeout 120
```

`gnu-cp` executes `/bin/cp -a --reflink=never -- SOURCE DESTINATION`.
`gnu-cp-reflink` executes `/bin/cp -a --reflink=always -- SOURCE DESTINATION`;
an unsupported clone fails rather than falling back to byte copy. Both retain
the same content, metadata, POSIX ACL/xattr, hardlink, sparse, independent-inode,
unchanged-source and sentinel checks. A clone command, raw measurement or
semantic failure stops the cell and retains the owned fixture and journal.
Changed source or executable pins also retain the clone fixture. Do not resume
or rerun a failed cell.

Clone evidence has separate outcomes:

- Each row records required-reflink API acceptance from the exact command's exit
  status. Exit zero remains API evidence even if resource parsing or subsequent
  semantic validation fails; it does not make that measurement valid.
- Read-only `zpool get` observations bracket the first command and its strict
  validation, outside timing and before removing the first destination. The
  `zpool` executable is pinned before and after collection. Positive changes in
  both `bcloneused` and `bclonesaved`, on the same pool GUID with the feature
  active, corroborate that pool interval. A changed GUID stops the cell and
  retains the destination. Missing, stale, malformed or decreasing counters
  remain inconclusive; feature state or ratio alone is insufficient. There is
  no polling, forced transaction sync, property change or fallback.
- Per-file full physical sharing remains unknown. Aggregate pool counters do
  not identify every shared extent or establish exclusive storage savings.
  Linux does not use Darwin clone attributes, and unavailable FIEMAP/FIBMAP
  observations are not required. The macOS sharing gates above are unchanged.

Report `passed` describes collection and semantic validity, independently of
pool corroboration. Stale aggregate counters do not negate API acceptance; any
physical-optimization claim remains inconclusive without corroboration. GNU
documents required-reflink behavior in its [coreutils source](https://github.com/coreutils/coreutils/blob/v9.7/src/copy.c);
OpenZFS documents the aggregate [pool counters](https://openzfs.github.io/openzfs-docs/man/v2.4/7/zpoolprops.7.html).

The two methods produce separate descriptive summaries, with no paired verdict
or product comparison. Keep an existing ordinary-copy reference intact when
adding clone evidence; do not pool statistics or recollect ordinary copy merely
because other source changed. No clone results are implied by these instructions.
Any published reference needs its measured source identity, raw evidence hashes,
host/guest context and independent verification, with private paths removed.

GNU Time resource samples retain raw output and convert RSS KiB to bytes exactly
once. Process RSS excludes ARC, kernel and guest/host caches; ARC/meminfo are
context rather than whole-system peak memory. Warm validation reads do not
guarantee residency. A Linux VM backed by a macOS APFS disk file is a VM reference,
not bare-metal or causal filesystem performance evidence. Linux ACLs and user
xattrs do not establish Darwin ACL/resource-fork equality. The macOS
`/usr/bin/time -lp` host-access readiness issue does not change the Linux GNU Time
wrapper or authorize broader permissions.

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
