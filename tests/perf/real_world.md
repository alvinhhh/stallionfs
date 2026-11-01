# Exploratory filesystem comparisons

These runners compare file operations and applications on an existing filesystem. They create private disposable directories and remove only their own fixtures. They do not create pools, change filesystem properties, mount volumes, purge caches or alter system settings.

## File operations

```sh
python3 tests/perf/real_world.py --root /path/to/scratch \
  --output /path/to/new-results.json --sfs /path/to/sfs \
  --repetitions 10 --files 10000 --directories 100 --sfs-jobs 1,2,4
```

Omit `--sfs` on Linux. A C compiler named `cc` is required. The matching `real_world_scan.c` and `real_world_measure.c` must be beside the script. Use `--directories 1` for a single populated directory beneath the fixture root.

Each case has one warmup and ten measured repetitions by default. Candidate order is shuffled deterministically within each repetition. The fixture contains 4 KiB files, relative symlinks and a hardlink alias. Scanning uses the same six counters as `sfs scan`; the native reference is a compiled POSIX directory walker, not one subprocess per file.

Copy and clone validation checks every file hash, mode, symlink target, directory mode and hardlink group. Source/destination regular inodes must differ. One measured clone is edited to check source isolation. Every operation rechecks the original fixture and an independent sentinel outside timing. ACLs, xattrs, ownership, timestamps, physical extent sharing and power-loss survival are not established by this runner.

The references are macOS `cp -Rp`, `cp -cRp`, `ditto --rsrc --extattr --acl`, and `rm -rf`; Linux uses GNU `cp -a --reflink=never`, mandatory `--reflink=always`, and `rm -rf`. An unsupported mandatory clone remains unsupported. An incorrect copy remains failed, even if its command exits successfully. Any failed sample excludes that entire candidate from successful statistics. Raw failures are retained, the overall run returns failure, and unaffected candidates continue. Incompatible candidates remain non-wins when considering the complete comparison set. `ditto` is reported separately and does not retroactively replace a failed `cp` result.

JSON and CSV contain raw elapsed time, child CPU and maximum RSS. JSON also contains median, nearest-rank p95, population standard deviation, and paired wins/losses where a valid reference exists. Resource units are normalized to bytes. RSS is a per-process high-water value; it is not total concurrent memory or filesystem kernel-cache usage. The application runner’s child readings can include inherited pre-exec state, so they must not be interpreted as isolated compiler or filesystem memory. Schema 2 measures command fork/exec through a small native supervisor, avoiding Python pre-exec RSS inheritance. Native child wall time and the separate Python launcher wall time are both retained. A zero RSS counter is unavailable, never a memory win. Validation and fixture setup are outside timing.

## Application workloads

```sh
python3 tests/perf/real_apps.py --root /path/to/scratch \
  --output /path/to/new-result-directory --repetitions 10 --jobs 2
```

The runner builds and executes a C project with 32 generated units plus `main`, changes one unit and relinks, runs two SQLite WAL writers with synchronous FULL transactions, and measures 64 MiB sequential writes and hashed reads plus 1,000 random 4 KiB overwrites. Writes use `fsync`; macOS `F_FULLFSYNC` is not requested. All generated rows, compiled output and file bytes are checked.

Application stages include process startup. Their CPU is summed child usage and RSS is the largest individual child high-water mark, not simultaneous summed memory. I/O-stage RSS includes setup and prior stages in that worker. Correctness checks are outside stage timing. Per-case deadlines terminate only owned process groups; uncertain exit retains scratch data. `--smoke` uses tiny cases for validating the runner and must not be reported as benchmark evidence.

## Interpretation

All reads are warm-cache; no cold-cache claim is made. Run filesystem roots sequentially during an otherwise quiet interval. Record actual mount types, hardware, VM resources, compiler/runtime versions and filesystem settings. A Linux VM versus its macOS host changes the OS, compiler, runtime, available CPU/RAM and I/O path; those timings are practical observations, not an isolated proof that one filesystem is intrinsically faster. Guest process CPU excludes host virtualization work, and process RSS excludes ZFS ARC and other kernel caches. APFS workspace images are Apple APFS, not the custom StallionFS filesystem.

This exploratory suite is separate from the fixed release qualification matrix. Keep every loss, unsupported case and correctness failure. Do not infer production reliability, universal superiority or physical power-loss recovery from finite passing checks.

## Launch amortization

```sh
python3 tests/perf/real_batch.py --root /path/to/scratch \
  --output /path/to/new-batch-results.json --sfs /path/to/installed/sfs \
  --python /path/to/installed/environment/bin/python --count 100 --repetitions 10
```

This macOS-only probe performs the same 100 independent 4 KiB clones through the installed `sfs` CLI, the installed Python API in one worker, and repeated native `cp -c` commands. It measures interpreter startup/imports and all operations in each batch, then checks bytes, modes, distinct inodes and write isolation outside timing. It investigates process-launch overhead using existing functionality; it does not introduce a new clone algorithm.
