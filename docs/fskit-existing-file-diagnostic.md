# Existing-file write diagnostic

This is a private direct-callback diagnostic, not writable product support.
The default FSKit build remains read-only. The additional
`STALLION_WRITE_DIAGNOSTIC` condition permits a harness to bind one disposable
image UUID before loading a writable path resource. Without that binding it
also remains read-only. It does not provide an installed writable launch path.

Only existing regular files can be written or resized. All namespace changes,
xattr changes and other supported metadata setters remain refused. Files must
belong to the image owner and permit owner writes; setuid/setgid files and files
with a native security-descriptor xattr are refused. This is not complete
POSIX/ACL authorization. The legacy write callback has no caller context;
installed access routing is unqualified.

A delivered write streams borrowed bytes in at most64KiB core calls within one
transaction. One successful commit executes both existing full-storage fences
before returning the full callback count. A failed callback reports zero and
its error, even if provisional chunks appended bytes. Outcome-unknown errors
retain the host errno and terminal status; zero acknowledged bytes does not
mean the disk definitely stayed unchanged. No uncommitted callback data is
acknowledged by the module. Default kernel caching remains unknown.

Resize supports size only. Computed fields fail EINVAL; mode, owner/group,
flags and supported time setters fail ENOTSUP before mutation. Added/backup
time are unrepresented and remain unconsumed. Directory/symlink size is ignored.
Size is consumed after a successful commit or validated same-size no-op.
A later attribute-fetch failure reports an error without undoing that commit.
Shrink changes logical EOF but does not reclaim append capacity. No logical
free-space or host-space figure is invented.

The first data-delivery failure is retained, including rejection before queueing;
later mutations stop and every subsequent synchronization reports that failure.
Wait/dWait check the preceding delivered callbacks and committed receipt.
NoWait is an asynchronous ordered check, not proof that the kernel has delivered
all dirty data. Unmount retains its void completion and existing ordered drain;
deactivate does no I/O. Installed fsync/F_FULLFSYNC/O_SYNC/O_DSYNC routing,
delayed syscall errors, coherency and failed cleanup-sync behavior are unqualified.

Ordinary and maintenance callbacks share the existing256-request/8MiB admission
budget, charging whole retained payloads plus4KiB per callback. The diagnostic
adds at most4096 fixed trace records and fixed saturating counters. Overflow
makes a complete routing claim unavailable. Records contain operation/inode,
offset/length, timing, commit receipts and errors, never contents or paths.
Fence attempted/succeeded bits record the actual two core calls. Writes and
sync/close/reclaim/unmount/unload events share one sequence and monotonic time
basis. Sync arrivals, flags and error completions are observed even when they
are rejected before queueing. Lifecycle
completions remain separately O(pending framework unmounts); no whole-process
memory bound or arbitrary lifecycle-flood qualification is claimed.

`sfs_result.limit_reason` distinguishes append-capacity ENOSPC, file-size EFBIG
and structural/counter EOVERFLOW on begin/write/resize/commit. Internal arena,
token and allocation failures that already returned NOMEM continue to map to
ENOMEM. The receipt also exposes transaction/poison state; it changes no disk
format. Test-only counter/reservation injections are excluded from normal builds.

## Focused source validation

The SDK27 arm64 local builds, focused C receipts, private write helper and existing
read-only helper pass. These are direct-callback results, not installed routing
evidence. Use the compiler settings from [the read-only recipe](fskit-readonly.md). Build the ordinary
extension first, without either diagnostic define, and verify its symbol table
excludes `sfs_diag_`, `sfs_image_diagnostic_`, `enableWriteDiagnostic`,
`diagnosticWrite`, and test hooks.

For the separate helper, compile image.c with the substitutions declared in
`tests/fskit_write_hooks.h`: pread, pwrite, fcntl, clock_gettime, malloc and calloc
map to their `sfs_diag_` counterparts. Compile `tests/fskit_write_hooks.c`
separately without substitutions. Link the current Extension.swift and
Volume.swift with `tests/fskit_write_driver.swift`, defining both
`STALLION_ADAPTER_CHECK` and `STALLION_WRITE_DIAGNOSTIC`. The helper accepts an
owned empty0700 parent directory and creates fresh images beneath it. It does
not sign, install or mount a filesystem. Preserve its fixtures and output on
failure; run it with an external bounded process-group supervisor.

The focused C test is
`ImageCore.test_existing_file_diagnostic_receipts_and_transaction_failures` in
`tests/test_image.py`. Its private compile condition enables only boundary
injection, including a reservation ceiling that does not alter the selected
on-disk anchor. Run the existing selected-information/read-only tests for the
shared receipt change. Run the existing read-only adapter helper to check that
the ordinary build remains unchanged. These are correctness tests, not new
performance cases or installed qualification.

The SDK27 `SetAttributesRequest` setters for `supportsLimitedXAttrs` and
`inhibitKernelOffloadedIO` did not make those fields valid in the direct helper.
The helper reports this explicitly: all18 field policies are checked directly,
while callback tests exercise the16 constructible fields and the actual
empty/size-only requests produced by those two setters. This does not establish
how the kernel constructs capability-field requests.
