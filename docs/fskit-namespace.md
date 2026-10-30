# General read-only FSKit namespace

The adapter accepts format 0.6 images through the existing private-parent,
private single-link image, local APFS, no-follow and exclusive-handle admission
checks. The container and volume use the image UUID. File identifiers map the
core inode to inode + 1; every hardlink alias shares one active FSItem.
Directory names are case-sensitive opaque bytes, at most 255 bytes, with no
normalization. Lookup and streaming enumeration preserve the exact alias.
Enumeration verifiers bind the image UUID, committed generation/root digest,
directory, attribute mode and mount nonce. Stale cookies are rejected.

`sfs_image_get_information` returns the already selected checked state after a
constant-work file identity check. It allocates no traversal state and performs
no namespace walk. UUID/device/inode identify the open image; generation,
committed end and root digest identify its committed state. Pending edits do
not change that committed receipt. The read-only adapter never refreshes its
receipt to conceal an unexpected state change.

Append headroom is the capacity after the aligned physical image tail. It
includes the cost of abandoned appends and excludes no reservation for future
metadata. It is not logical free space, host free space or reclaimable storage.
Volume free-space statistics remain unsupported. Item allocation reports only
referenced data cells, excluding metadata and xattrs; shared cells can appear
in multiple items' accounting.

## Resource limits and errors

| Resource | Limit | Failure |
| --- | --- | --- |
| Individual xattr value | 1 MiB | E2BIG before value allocation |
| Xattr list | 64 KiB including name terminators, 1,024 names | E2BIG before appending the excess name; no partial list |
| Canonical active items | 4,096 including root | ENFILE before item creation/publication |
| Accepted ordinary and maintenance callbacks | 256 queued or running, shared budget | EAGAIN before queue submission |
| Callback retained payload budget | 8 MiB, including 4 KiB charge per callback | EAGAIN before queue submission |
| Mount options | 64 strings, 1,024 UTF-8 bytes each | E2BIG before queue submission |
| Resource URL | 4,096 UTF-8 bytes | ENAMETOOLONG before queue submission |

Read callback charges include the entire FSKit buffer length, not merely the
requested range. Names are bounded before scheduling. Mutations reply EROFS
immediately without retaining data or entering the queue. Completed callbacks
release their charges even on failure. Item capacity is released only inside a
successful `tryReclaim` block; root is retained until unload. The unary resource
owner separately limits its callbacks to 256 with an 8 KiB charge per callback.

Unmount closes ordinary admission atomically with submission of its cleanup
callback. Cleanup and its reply always run asynchronously after earlier accepted
work, including when requested from a packing or reply callback. New ordinary
requests return EAGAIN while unmounts are pending and ENXIO after they finish.
Only a successful explicit mount reopens admission; an older queued mount
returns EBUSY if a newer unmount is pending. Activation, mount, deactivation,
synchronization, close and reclaim use the same bounded maintenance budget and
remain available after unmount. Deactivation performs no I/O; read-only unmount
only clears cached state.

The SDK's unmount reply has no error argument. Framework unmount requests are
therefore separate control work, tracked as a pending count with one dispatch
work item and completion per request: O(pending unmounts) storage, with no fixed
cap or flood-resistance guarantee. There is no waiter array, synchronous wait,
dropped reply or overload success. Replies run outside the submission lock.

Unload returns nonconsuming EBUSY while an unmount or bounded callback remains
pending. The resource owner retains its volume, resource and security scope so
unload can be retried. A consuming unload closes once, including when close
returns an error. Later unmount calls still receive a deferred reply without
touching the consumed handle.

These budgets cover adapter-admitted work, not opaque FSKit/kernel object
storage, caller-retained replies or a whole-process RSS guarantee. The core's
existing bounded caches remain separate. Pending framework control requests are
also outside the ordinary request budget. Enumeration retains one row at a time.
ENAMETOOLONG, EINVAL, ENOENT, ENOATTR and EEXIST retain their distinct meanings.
An unclassified core SFS_LIMIT becomes EOVERFLOW; bounded xattr operations use
E2BIG/ERANGE. No writable ENOSPC/EFBIG inference is made from SFS_LIMIT. A writer
must distinguish capacity, object-size and structural limits before admission.

## Access and qualification boundary

Custom access checks support only the image owner's effective UID on an item
with that same stored owner UID. Stored owner read/search bits constrain grants;
file execution, writes and unsupported access-mask bits are denied. A present
`com.apple.system.Security` xattr causes ENOTSUP, rather than interpreting its
opaque bytes as an ACL. This is a conservative owner-only policy, not complete
POSIX group/supplementary-group, root-override or ACL authorization. Metadata and
xattr storage do not establish those semantics.

The SDK access-check contract returns an allow/deny result. Its FSContext
provides effective user/group IDs but no supplementary-group list; the adapter
does not assume an undocumented kernel fallback performs missing checks.
Actual access-check dispatch, ancestor search enforcement, application resource
fork behavior, kernel buffer/packer delivery, acquired security scope, signing
and installed lifecycle require separate qualification. General read-only
source does not qualify a writable mount or replace an earlier compiled trial.

The source tests extend `tests/fskit_adapter_driver.swift` with two independently
created images, 81 root names, one-row pagination, exact aliases, oversized
xattr preallocation refusal, aggregate-list refusal, queued-callback saturation,
byte-budget accounting, item saturation/reclaim, unsupported format and damaged
root refusal. Lifecycle schedules cover 257 reentrant unmount requests, accepted
work and saturated admission, concurrent admission/cutoff races, mount/unload
crossings, nonconsuming busy unload, post-unmount cleanup and terminal replies.
Reclaim tests preserve the actual SDK result on a direct item and separately
exercise successful cleanup through a test-only SDK boundary; they do not prove
successful kernel-directed reclamation.
Their direct producer temporarily enables writes in the test-only
syscall hooks; that gate is disabled before any adapter callback. The core
`metadata-information` case checks allocation/read counts, pending-versus-
committed receipts, immutable identity and stale committed-position rejection.
Compilation and execution are separate evidence; these test sources alone
establish no passing result. [Current build and helper instructions](fskit-readonly.md)
exclude FixtureIdentity from production compilation and identify the historical
fixture-restricted source separately.
