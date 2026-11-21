# StallionFS 0.7.0 release notes — draft

This draft describes what is available on `main`, not a signed release.

- **Workspaces:** Take snapshots and roll back while retaining the prior
  state. Opt-in cleanup can retire eligible workspaces to protected trash
  without permanently deleting them. See the [0.7.0 user guide](user-guide-0.7.0.md).
- **Installation:** The source CLI is available. The signed installer and a
  qualified FSKit app upgrade/removal procedure are not available on `main`.
  Use `sfs doctor` for the APFS clone and isolation probe; there is no
  `sfs doctor --installation` check yet.
- **Performance:** In [three recorded warm document-clone comparisons on APFS](performance-cli167-ditto-20261115.md),
  the unsigned private CLI had 56.76–57.19% lower median elapsed time and
  7.27% higher median peak process RSS than the recorded `ditto` reference.
  This is one workload, not installed-release performance or evidence that
  the [full performance gate](../tests/perf/README.md#performance-release-gate)
  has been met.
