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

Ordinary-copy results compare logical-copy commands, with the physical storage mechanism uncontrolled. In particular, `native_ditto` is not a materialized-copy reference: its invocation may enter clone-related paths. The JSON report records `copy_comparison_policies`; every copy sample and its variant summary retain `copy_comparison_policy` with `scope=logical_copy_commands`, `storage_mechanism=uncontrolled` and `materialized_copy_comparison=false`. The `native_ditto` policy also states `reference_qualification=clone_capable` and explains why materialized-copy equivalence is uncontrolled. Linux ordinary `cp` separately records its explicit `clone_request=disabled_by_reflink_never`; that request does not establish physical extent behavior. Timings, statuses, baseline selection and arithmetic retain their existing meaning as command comparisons. Missing or inconsistent sample policy metadata produces summary scope `unrecorded_or_inconsistent`; the summarizer does not infer a mechanism from the current host. This policy is separate from mandatory-clone eligibility below.

Content equality, independent inodes and an observed clone-related call stack do not establish successful cloning, physical sharing or materialized I/O. A later call-stack observation does not establish the mechanisms used by earlier benchmark samples or supply a CPU attribution or timing correction. Prior reports and their source hashes remain unchanged.

Add `--stop-on-sfs-failure` to stop at the first failed SFS sample, including a warmup. Once the failure is detected, the runner saves the sample error and available execution receipt, retains scratch and any remaining partial target, and performs no further fixture inspection or deletion. Exceptions and interruptions during command execution, validation, or per-sample cleanup count as failures. An interrupted cleanup can retain only what has not already been removed. The report records `retention_reason=sfs_sample_failure`, the stopped sample index, and `cleanup=retained_failure_evidence`.

Process-completion uncertainty takes precedence over intentional failure-evidence retention and keeps its separate retention path and supervision receipt. The original sample error remains available if later validation or cleanup also fails; additional failures appear in `secondary_errors`. Native-reference failures, including a `cp` hardlink-contract failure, do not trigger this flag. The option defaults to false and changes only future collection behavior; prior reports and their classifications are unchanged.

Clone semantics are recorded explicitly in `clone_policies` and every clone sample's `clone_policy`. SFS clone and GNU `cp --reflink=always` are `mandatory`. Apple `cp -c` is `fallback_capable`: the installed `cp(1)` manual permits a fallback to `copyfile` across filesystems or where cloning is unsupported. Content equality, independent inodes and write isolation do not distinguish a clone from a byte copy. A fallback-capable reference retains its raw timing and correctness result, but cannot support a mandatory-clone comparison. Summary comparisons require `mandatory` on every reference and candidate attempt, including warmup; missing, unknown or inconsistent policies fail that eligibility check. Existing reports without policy metadata must not acquire mandatory semantics from the machine running an analysis. Excluded comparisons state their policy reason, and a failed native `cp` remains failed rather than being replaced by another reference.

JSON and CSV contain raw elapsed time, child CPU and maximum RSS. JSON also contains median, nearest-rank p95, population standard deviation, and paired wins/losses where a valid reference exists. Resource units are normalized to bytes. RSS is a per-process high-water value; it is not total concurrent memory or filesystem kernel-cache usage. The application runner’s child readings can include inherited pre-exec state, so they must not be interpreted as isolated compiler or filesystem memory. Schema 2 measures command fork/exec through a small native supervisor, avoiding Python pre-exec RSS inheritance. Native child wall time and the separate Python launcher wall time are both retained. A zero RSS counter is unavailable, never a memory win. Validation and fixture setup are outside timing.

The Python supervisor observes child exit without reaping, closes every destructive signal path, then reaps once. It records signal attempts and one read-only group-presence check after reap. An existing group or probe error makes completion uncertain and prevents fixture inspection or removal. Absence is established only at that check; independently detached processes are outside this supervision. A changed scratch-directory identity also prevents final removal.

Exit observation uses a 10 ms polling interval. Python launcher, application worker-envelope and batch elapsed times include observation and scheduling delay. Native C command metrics and worker-reported application stage timers do not include that polling delay. Termination waits have bounded grace periods; underlying OS calls can still block.

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

This macOS-only probe creates 100 independent 4 KiB destinations through the installed `sfs` clone CLI, the installed clone API in one worker, and repeated native `cp -c` requests. It measures interpreter startup/imports and all operations in each batch, then checks bytes, modes, distinct inodes and write isolation outside timing. It investigates process-launch overhead using existing functionality; it does not introduce a new clone algorithm.

The native `cp -c` route can fall back to byte copying. Its retained batch timing describes those command invocations; these checks do not establish mandatory clone semantics or physical sharing for that reference.
