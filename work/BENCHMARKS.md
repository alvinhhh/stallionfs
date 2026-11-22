# Native comparisons

The full target remains unmet. The latest warm tiny-copy and tiny-move comparisons lose wall, CPU and RSS; the warm flat, nested and deep40 scans pass those paired screens. The expanded matrix remains incomplete.

## Command coverage

Collected copy and ordinary move comparisons use absent exact destinations on
the same APFS volume. Inputs stay unchanged; setup and verification are outside
timing. Other released operation classes remain listed with their missing
comparisons.

| Native operation | StallionFS operation | Status |
| --- | --- | --- |
| `cp -cRp SRC DST` | `stallionfs clone SRC DST` | Copy-on-write comparison |
| `cp -Rp SRC DST` | `stallionfs copy SRC DST` | [Warm 4 KiB: slower wall, higher CPU/RSS](../tests/perf/results/ordinary-copy-tiny-v0.6.3-arm64.json) |
| `ditto --rsrc --extattr --acl SRC DST` | `stallionfs clone SRC DST` | Copy result; metadata losses are checked |
| `rsync -a --extended-attributes SRC/ DST/` | `stallionfs clone SRC DST` | Fresh directory copy only; no incremental/remote counterpart |
| `mv -n SRC DST` | `stallionfs move SRC DST` | [Warm 4 KiB JSON (XZ)](../tests/perf/results/native-move-tiny-20261024-arm64.json.xz): slower direct wall, higher CPU/RSS; same filesystem, absent destination |
| Exact-path replacement move | move with replacement | Required; exact native cases and collection pending |
| Atomic exchange | move with exchange | Required; native API comparison pending; a sequence of ordinary moves is not atomic exchange |
| `rm -rf PATH` | `stallionfs delete --recursive PATH` | Permanent completed deletion |
| Finder copy/move/delete | clone/move/delete | Scripted copy/move correctness checked below; shared-service resources and deletion unmeasured. Trash is not permanent deletion |
| `find -P -x ROOT -mindepth 1 -exec stat -f '%Op%t%Dz%t%Dd' -- {} +` | `stallionfs --json scan ROOT` | Warm [flat20k JSON (XZ)](../tests/perf/results/native-scan-flat-20261024-arm64.json.xz), [nested20k JSON (XZ)](../tests/perf/results/native-scan-nested-20261024-arm64.json.xz) and [deep40 JSON (XZ)](../tests/perf/results/native-scan-deep40-20261024-arm64.json.xz): wall/CPU/RSS screens passed |
| Cached mount-record listing | `volumes` / `mounts` | Required; exact native fields and resource boundary unqualified |
| `du -skx ROOT` | none | Allocated blocks differ from scan's logical file bytes |
| `ls -la ROOT` | none | No directory-entry listing command; `stallionfs list` lists workspaces |
| `mdfind -onlyin ROOT QUERY` | none | No indexed search implementation |
| `tar`, `zip` | none | No archive/compression implementation |
| `fs_usage` | none | Profiling tool, not a file operation |
| Git worktree plus locked offline setup | folder prepare/create/remove/gc | Existing create/cleanup comparison; peak simultaneous memory and full metadata equivalence unmeasured |
| Image creation/clone/attach/detach/deletion workflow | image prepare/create/mount/unmount/remove/gc | Released capability; complete equivalent workflow and resource coverage pending |
| Equivalent recovery and store-management workflow | restore/forget/list/diagnostics | Exact workflow/disposition pending; no single native filesystem command |

Compressed report downloads are JSON (XZ); decompress before using plain-JSON readers. Tiny move wrapped wall is inconclusive; StallionFS p95 is 27.401166 ms, with no excluded samples.

The FSKit prototype is separate from the released CLI. Timing native tools on that volume must also account for its serving process and deferred writes; CLI results cannot stand in for that measurement.

Finder and StallionFS passed the 4 KiB copy and move correctness checks with
populated metadata. Finder's 2,000-file copy returned a destination reply,
but split an internal hardlink, changed 1,994 timestamps by −59 to +60 ns, and
added `.DS_Store` to the destination container. Completion remained uncertain and
the check stopped there. No Finder timing, CPU or memory result is claimed.

### Hosted CLI scan, November 22, 2026 (UTC)

Three sequential cycles on one GitHub-hosted `macos-15` arm64 VM (macOS 15.8.2,
image `20261118.0550.1`) used an installed source wheel from
`ae38698bc08d67777c9960056311651ace3352fc`. Each warm fixture and output form
(plain or JSON) had one warmup pair, 31 measured timing pairs and 10 separate
resource pairs per cycle. All 1,008 command outputs matched the six expected
counters, including 24 warmup outputs. No pairs were excluded.

The timed native find/stat recipe in the table above emits numeric records for
each entry on the same device, excluding the root and without following
symlinks. Its counts are aggregated after timing. StallionFS aggregates and
formats the counts inside its timed command. The ratios apply to this recipe.

| Fixture | Metric | Native / StallionFS medians across six cycle/form cells | Paired result |
| --- | --- | --- | --- |
| `nested_1000` | Direct elapsed | 568.741–604.927 / 5.024–5.608 ms | Faster in all six. Native took 105.78–115.86× as long. |
| `nested_1000` | Direct child CPU | 566.899–603.043 / 4.659–5.263 ms | Lower in all six. Native used 113.60–124.60× as much. |
| `nested_1000` | Peak process RSS | 2.0625 / 2.7031 MiB | Higher in all six (+31.1%). |
| `empty` | Direct elapsed | 3.351–3.686 / 3.994–4.576 ms | Slower in one, inconclusive in five. |
| `empty` | Direct child CPU | 2.418–2.609 / 3.089–3.428 ms | Higher in four, inconclusive in two. |
| `empty` | Peak process RSS | 1.9531 / 2.5313 MiB | Higher in all six (+29.6%). |

All 120 resource pairs recorded zero OS input and output block operations for
both methods. RSS is the peak of an individual process reported by
`/usr/bin/time -lp`. The results cover two synthetic warm scan fixtures on this
VM. Physical hardware, the final installed release and the full 37-case matrix
remain unqualified by this run.

[Raw results (JSON XZ)](../tests/perf/results/hosted-native-scan-20261122-arm64-run44995704979-attempt1.json.xz)
retain `provenance.json` and `cycle-1.json` through `cycle-3.json` byte for byte,
including measurements and stdout for every projected row, plus stdout, stderr
and journal hashes.
GitHub Actions artifact `14743828581` came from run `44995704979`, attempt 1,
[job 137126156331](https://github.com/alvinhhh/stallionfs/actions/runs/44995704979/job/137126156331).
Original ZIP SHA-256 `28bb596ac58197489f657e826cd2564e37a0a385bc476fcf1dc1f3a9b39e3b4b`.
JSON XZ SHA-256 `c7455e58af3714348e05177c67710791f094522d0b5fcf54aaeeada6e090889c`.

## Reproduce

Install an isolated build, then run the suite on disposable APFS scratch space:

```sh
python3 -m venv /tmp/stallionfs-bench-env
/tmp/stallionfs-bench-env/bin/python -m pip install .
mkdir -p /tmp/stallionfs-bench
/tmp/stallionfs-bench-env/bin/python tests/perf/native_suite.py \
  --binary /tmp/stallionfs-bench-env/bin/stallionfs \
  --scratch /tmp/stallionfs-bench --output /tmp/stallionfs-native.json
```

Each method runs ten times per measurement phase, across three repetitions. Inputs include 100,000 tiny files, a committed Git repository, a 200,000-file build cache, a 50 GB dataset, two 10 GiB files, a 40-level tree and synthetic PNG images with JSON sidecars. The image fixture contains 2,000 distinct 1024×768 RGB noise images, about 4.72 GB, and 2,000 sidecars. It is not a Photos.app database or a sample of JPEG/HEIC compression ratios. Output paths must be new. Failed commands and validation failures remain in the report and produce a nonzero exit status.

Add `--runs 1` for one native diagnostic run. The command above omits the opt-in
dependency and native scan fixtures, scanner API and workspace lifecycle stages.
The [sequential campaign](../tests/perf/README.md#sequential-campaign) includes
those existing stages, but still omits required classes and resources listed
here. Neither command currently proves the complete acceptance matrix.

The opt-in [installed-dependency fixture](../tests/perf/README.md#installed-dependencies) passed offline preparation and integrity checks on arm64 with Node 24.19.0: 11,564 regular files, 85,568,073 logical bytes and five symlinks. Timed comparisons are pending.

While running, results are saved in an append-only journal and a small manifest
beside the requested output. The final JSON is written once. See
[report storage](../tests/perf/README.md#native-report-storage) for inspection and
export. Reporting does not run between the pre-command source read, cache
conditioning and command launch.

Warm runs read the input before each method; inputs larger than RAM are not assumed resident. Cold runs request `sudo -n purge` immediately before the command, after validation. A denied purge is recorded as unavailable. Purge does not establish eviction of device caches. No interactive password prompt or security-setting change is attempted.

Timing and resource measurements use separate, freshly prepared operands:

- Direct timing measures command startup through completion. Child CPU comes from the difference in `RUSAGE_CHILDREN` counters, excluding harness CPU. The runner permits one command at a time and uses blocking completion with an alarm deadline, avoiding Python's timed-wait polling sleeps. The deadline starts before launch but can only interrupt after process creation returns.
- `/usr/bin/time -lp` collects peak RSS and block I/O counters. Its wrapped wall and rounded CPU measurements are retained separately. CPU output rounds to hundredths of a second; these values are not substituted for direct CPU measurements.

Comparisons report median, nearest-rank p95 and sample variance. A screened win requires both mean and median paired savings to exceed native, candidate and paired standard deviations, three paired standard errors, and measurement precision. Missing or invalid pairs prevent a win. Direct CPU uses a conservative 4 µs representation floor; that is not a guarantee of accounting accuracy. This is a screening rule, not a confidence interval. Shared filesystem-service CPU and simultaneous descendant memory are not measured.

Block I/O counts are not device-byte measurements. Clone sharing is not logical data-transfer throughput.

## Required coverage still pending

- Complete run results and raw data for the expanded matrix.
- Replacement/exchange moves, mount-record listing and image/recovery workflow comparisons.
- Finder comparisons, mounted FSKit resource accounting, lifecycle peak simultaneous memory and full metadata equivalence.
- Cold scanner API and workspace lifecycle coverage; those stages currently remain warm.
- A reproducible representative photo workload; the existing noise PNG fixture is synthetic.
- Complete suites using the populated metadata fixtures. Each fixture now includes a nonempty ACL, extended attribute and resource fork; directory fixtures also include sparse data and internal hardlinks. Setup verifies their presence before timing. Clone rows check independent destination inodes and APFS data-stream sharing. Native preservation failures remain in the report.
- External-drive runs when a suitable drive is connected. None was present in the latest inventory.
- Three consecutive complete suites with every required comparison passing correctness and recovery across the full workload scope, and gains in any two of direct elapsed time, direct total CPU (user plus system), and peak RSS from resource passes beyond measurement precision and observed variation. Keep the third metric visible.

[Current bounded results](../tests/perf/README.md) retain the native comparisons and losses. A filtered run is not full-suite completion. Unsupported semantics, unavailable measurements and losses must not be removed from an acceptance report.

Workspace commands run as the same user and are not isolated from the account.
Separate directories and copy-on-write files do not meet isolated code-execution
requirements. See the current [execution boundary](../docs/storage.md).
