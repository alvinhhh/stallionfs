# Private CLI document clone versus ditto — November 15, 2026

Three fresh collections compared the unsigned private CLI167 with
`ditto --rsrc --extattr --acl` on host APFS. Each collected ten timing pairs
and ten separate resource pairs: 120 measured rows in total, all validated,
with no exclusions, retries or unavailable rows. Correctness and cleanup passed
in every collection.

This is one warm document-clone case with two workers and an explicitly selected
reference. It does not qualify an installed release, mounted FSKit throughput,
the full benchmark matrix or performance against every native tool.

[All 120 sanitized measurement rows](../tests/perf/results/private-cli167-ditto-20261115-arm64.json)
retain pair IDs, original order, elapsed time, user/system/total CPU, resource
measurements, precision fields and correctness flags. Values below are medians;
full precision, p95 and sample variance remain in the data.

| Collection | Wall: StallionFS / ditto | CPU: StallionFS / ditto | Peak RSS: StallionFS / ditto |
| --- | ---: | ---: | ---: |
| 1 | 365.156 / 848.477 ms | 703.425 / 834.592 ms | 1,888 / 1,760 KiB |
| 2 | 360.191 / 833.008 ms | 694.768 / 822.708 ms | 1,888 / 1,760 KiB |
| 3 | 362.588 / 846.936 ms | 695.544 / 830.978 ms | 1,888 / 1,760 KiB |

Median peak process RSS was 128 KiB (7.27%) higher in every collection. All 30
resource pairs also had higher RSS. The measured RSS is the individual command's peak, not total
system, filesystem-service, kernel or cache memory. Recorded RSS precision floors
were 0 B; constant observations in collection 1 do not establish exact physical
memory use.

## Conditional confidence results

Each collection met the predeclared selected-case gate through wall time and
CPU. Wall medians were 56.76–57.19% lower and CPU medians 15.55–16.30% lower
than ditto; RSS was 7.27% higher. These ratios of marginal medians are descriptive
effect sizes. The confidence intervals below concern the **median paired
fractional savings**, a different estimand. Positive savings mean lower/faster;
negative savings are losses.

| Collection | Metric | Ratio-of-medians savings % | Median paired savings % | Pointwise paired-median CI % | Adjusted one-sided lower % |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Wall | 56.9633 | 55.4640 | [52.5596, 58.5801] | 47.7137 |
| 1 | CPU | 15.7164 | 14.3509 | [10.9361, 16.2496] | 3.6836 |
| 1 | RSS | -7.2727 | -7.2727 | [-7.2727, -7.2727] | -7.2727 |
| 2 | Wall | 56.7601 | 56.9562 | [55.1649, 58.4357] | 54.1346 |
| 2 | CPU | 15.5511 | 15.8145 | [13.2588, 18.5265] | 11.1171 |
| 2 | RSS | -7.2727 | -7.2727 | [-7.2727, -7.2727] | -8.2569 |
| 3 | Wall | 57.1882 | 57.3916 | [50.1214, 58.7810] | 49.7371 |
| 3 | CPU | 16.2981 | 16.8251 | [11.3110, 17.6254] | 6.0259 |
| 3 | RSS | -7.2727 | -7.2727 | [-7.2727, -7.2727] | -8.1818 |

The unrounded gate required a wall ratio-of-medians reduction of at least 10%,
an adjusted wall lower bound of at least 10%, and an adjusted CPU or RSS lower bound
above zero in **each** collection. All three met it through CPU; the RSS loss
remains. This is the selected-case gate, not the harness's weaker any-two-metric
variation screen and not release qualification.

For each matched pair, fractional savings are `(native - candidate) / native`.
The pointwise intervals use the second through ninth ordered effects at ten
pairs, with coverage at least 97.8515625% (nominal 95%). The simultaneous
one-sided bounds retain the predeclared 36-endpoint Bonferroni budget for this
nine-endpoint selection: nominal family coverage is 95%, and the discrete
coverage is at least 96.484375% under the sampling assumptions. Upper endpoints
of these one-sided intervals are unbounded. RSS pointwise intervals are not
separately adjusted simultaneous upper bounds on memory loss.

The adjusted effects subtract the sum of both rows' representation floors
before division by the native value, using a minimum floor of 4 microseconds
per CPU observation. At this sample size the simultaneous lower bound is the
smallest adjusted paired effect. Representation floors are margins from the
measurement format, not guaranteed bounds on measurement error.

These inferences are conditional on independent pair effects from a
common-median distribution within each collection and phase. Independence was
not established. The repeated method schedules described below can coexist
with serial, order, cache or system effects. Three serial collections were
analyzed separately; they were not pooled into 30 pairs and do not establish
long-term reliability or host-wide repeatability.

The unchanged analysis script's SHA-256 is
`c95ce1c717a62906d0cd4f92538de83ae5ed6f32d8f436a522f12d74f88b049a`;
its result SHA-256 is
`4a32776cf4793f08d1576f00837d05c1a8083c7c384b13a6c5fb3740d5cf1eba`.
Full-precision statistical scalars and the original measurement rows are in the
linked JSON; rounding in these tables did not enter acceptance.

## Workload and measurement

The generated, enriched `docs_5k_100mb` fixture contained 5,002 regular-file
names, 105 directories including the root, and 116,777,216 logical bytes.
There were no symlinks or special entries, so this result provides no symlink
coverage. Counts and logical lengths include hardlink aliases.

Recorded allocation was 106,602,496 B: the sum of `st_blocks * 512`, including
hardlink aliases. It is neither the logical workload size nor exclusive physical
storage. The sparse file had 8,388,608 logical bytes and 2,101,248 allocated bytes.
Observed sharing of data-bearing regular-file streams does not establish
resource-fork sharing or disk-space savings.

Both commands include process startup. Direct timing rows provide wall and
child CPU time. Separate resource rows use `/usr/bin/time -lp`; per-component
rounding and all original precision floors are retained. All recorded input and
output block counters in the 60 resource rows were zero; this is not evidence
of zero physical I/O.

Warm conditioning reads the complete fixture during the validated before
snapshot. It does not guarantee residency. Both commands passed strict
correctness, sparse preservation, clone independence, source stability and
sharing checks; the harness's outside-sentinel and final cleanup checks passed.
No failed rows were repaired or removed.

The same first-method order patterns occurred in all three collections:
ditto ran first in seven of ten resource pairs and six of ten timing pairs.
Repeated order patterns and three serial collections do not establish
independent samples or eliminate cache, drift, scheduling or order effects.

## Host and measured source

The reports identify macOS 27.0 arm64, writable APFS with ownership enabled.
After collection, hardware identification recorded Mac14,2, Apple M2, eight
physical and eight logical cores, 24 GiB RAM, and macOS build 26A428. This later
identification does not establish the power mode, temperature, throttling or
background workload during collection; those conditions were not recorded.

The measured product version was `0.7.0`, private artifact CLI167, built from
commit `ac259a42049b21897f814b5cb978da581e876ed9`, tree
`156ecc63c8dd2f40f3be73e00c00d88d45c1dded`. It used bundled CPython 3.13 and
native extensions. The private bundle was not installed, registered or signed
for distribution. Its Mach-O components had ad hoc linker signatures.
The packaged benchmark and report unit modules passed 81 tests before collection;
this is separate from the 120 measured rows.

| Artifact | SHA-256 / build ID |
| --- | --- |
| Wheel | `c379b8e3cd92afb98cc1cd7d9f5379c009c60cfca49b8c75f40d5babd621ffa3` |
| Runtime descriptor | `330ef502d0fd9e7d8912dbe524ff9d4083c2b249a267513093ed8b8b7f485f27` |
| Source build ID | `3301a09338f5c7492d3fc5e8b641c3993a033f283968418b0e58e9a11ae46f11` |
| Measured CLI | `78badb67a50b47444768468a52bd0cd75d67f37209fe2e9fb01d18e28dc5c9ab` |
| `ditto` | `88933d7c96cc2c02219d61f5523b61a902dca8fdeed3b8384f24066ff48541bb` |
| `/usr/bin/time` | `6fe69a2da5af0a6e965785f8fbb03901c5bb8eef7f308f70620d4458ed28cce7` |

The JSON includes all 90 recorded source and installed-resource hashes. Original
input report hashes are retained below; paths, owner/device identifiers, PIDs,
command output and compressed per-file metadata observations are omitted from
the public export. The sanitized export is not a byte-identical original report.

| Collection | Original `native.json` SHA-256 |
| --- | --- |
| 1 | `1208e6e70c208576ebd971060ce6dc4cdab449029d4e5745504c53c449d51f98` |
| 2 | `37069dab48f5603413581cc95fce3f056f2ef2dcf434116f245ce16e52817808` |
| 3 | `413174caaa3f4fd5c30ad19ab307e9cfb8560449da9a4f6616b01a8826184c29` |

## Release readiness

The measured source's [Checks run 43695767751](https://github.com/alvinhhh/stallionfs/actions/runs/43695767751)
failed all six installed-wheel test jobs; three sanitizer jobs passed. The local
81-test module result does not establish full CI success. Release readiness
remains blocked and the release work remains draft. These selected performance
results do not override that failure. A recorded offline FSKit adapter assertion,
`canonical duplicate root`, and separate harness/admission failures remain
under diagnosis; no common root cause is established here.

## Reference selection and reproduction

An earlier four-reference collection failed strict correctness for `cp -cRp`,
`cp -Rp` and `rsync`. That collection remains failed. These are three new,
explicit ditto-only collections on the unchanged enriched fixture; they do not
repair or qualify the failed four-reference selection. The default public
benchmark still selects all four references. No reference was silently dropped.

Use macOS on writable APFS with ownership enabled, the pinned source above,
matching built CLI/native extensions, and available `ditto` and `/usr/bin/time`.
See [source installation](../README.md#installation) for build prerequisites.
A different build or host requires its own provenance and correctness checks;
these measurements identify the exact private bundle above.

For each collection, choose a fresh empty scratch directory and a new output
path outside it. Replace every placeholder below with your own paths:

```sh
/path/to/matching/CLI/bin/sfs benchmark \
  --fixtures docs_5k_100mb --operations clone \
  --samples 10 --jobs 2 --cache warm --copy-tools ditto \
  --scratch /path/on/apfs/fresh-empty-scratch \
  --output /path/to/new-summary.json --json
```

The measured commands are `stallionfs clone --jobs 2 SOURCE DESTINATION` and
`/usr/bin/ditto --rsrc --extattr --acl SOURCE DESTINATION`. Ditto's copying
policy is distinct from a command that requires cloning; observed data sharing
does not make those policies equivalent.

Inspect exit status and terminal JSON before admitting a collection. Require
complete collection, correctness, cleanup, all 40 validated rows and no
unavailable rows; a summary file alone is provisional. Preserve the native
report and its journal/manifest. Repeat only after inspection, using two more
fresh scratch/output pairs. `qualified: false` remains appropriate for this
selected comparison: it is not full release qualification.
