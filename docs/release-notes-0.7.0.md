# StallionFS 0.7.0 release notes — draft

These notes cover the 0.7.0 source candidate. The signed release is pending.

- **Workspaces:** Take snapshots and roll back while retaining the prior
  state. Opt-in cleanup can retire eligible workspaces to protected trash
  without permanently deleting them. See the [0.7.0 user guide](user-guide-0.7.0.md).
- **Installation:** The source CLI is available. The signed installer and a
  qualified FSKit app upgrade/removal procedure are not available on `main`.
  Use `sfs doctor` for the APFS clone and isolation probe.
  Use `sfs doctor --installation` for read-only installation checks and an
  ordered removal plan. The packaged FSKit app requires Apple silicon and
  macOS 27 or later to pass the installation check.
- **Performance:** In [three recorded warm document-clone comparisons on APFS](performance-cli167-ditto-20261115.md),
  the unsigned private CLI had 56.76–57.19% lower median elapsed time and
  7.27% higher median peak process RSS than the recorded `ditto` reference.
  This is one workload, not installed-release performance.
  The [0.7.0 release gate](../tests/perf/release_gate.py) requires at least
  34/37 cases to pass in each of at least three independent runs, with all
  performance floors met and identical per-case verdicts. A failed candidate
  operation or incorrect result disqualifies the run. [PR #71](https://github.com/alvinhhh/stallionfs/pull/71)
  reports three independent runs on the then-current `main` plus the sparse fix
  from [PR #72](https://github.com/alvinhhh/stallionfs/pull/72):
  macOS 26.6.2 arm64, 12 cores, 16 GiB, `--samples 10`, warm cache.
  The runs passed 8/37, 7/37, and 8/37 cases: **RELEASE GATE: NOT QUALIFIED**.
  Cases for the 2 GB, 10 GB, and 50 GB fixtures were not collected and
  counted as failures.
