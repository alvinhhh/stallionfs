# Experimental image format 0.2

This internal C core stores an offline filesystem image. The public `sfs` and
`stallionfs` commands do not use it. This is an incompatible replacement for
format 0.1, not a mounted filesystem or a stable compatibility promise. Unknown
versions and feature bits are refused. There is no migration or automatic repair.

The backing object must be a current-user-owned, single-link regular file with
private permission bits on local writable APFS. The containing directory must be
owned by that user with mode 0700 permission bits. The final pathname component
is opened without following symlinks; creation is exclusive, requests mode 0600,
and never removes a failed image. Each handle, including ordinary read-only open
and recovery inspection,
keeps a nonblocking exclusive advisory lock on one pinned image descriptor until
checked close. Identity, filesystem, permissions and actual EOF are checked.
Locks coordinate cooperating callers; hashes do not authenticate an image against
an attacker rewriting the file and all its hashes. Callers serialize operations
on a handle, including avoiding reentry from a cancellation callback.

## Limits and ordering

| Quantity | Format or API limit |
| --- | --- |
| Physical capacity, including abandoned tails | Explicit at creation; 4096-byte multiple, 16384 through 9223372036854771712 bytes |
| Logical file size | Through 9223372036854775807 bytes, subject to compiled lower caps |
| Metadata or raw data cell | Exactly 4096 bytes |
| Ordered index height | At most 16, with leaf level 0 |
| Named snapshots | At most 32; catalog height at most 2 |
| Name | 1–255 bytes |
| One write call | At most 65536 bytes; at most 17 affected raw cells |
| One active write batch | One inode, inclusive touched-block span at most 256 |

Integers are unsigned little-endian unless explicitly described as keys. Reserved
bytes are zero, structures and pointers are never serialized, and hashing uses
CommonCrypto SHA-256. Names are case-sensitive raw bytes without normalization;
NUL, slash, `.` and `..` are invalid. Root inode 1 is implicit. Other inode IDs
start at 2, increase monotonically and are never reused. Directories and regular
files are the only inode kinds. Holes below logical EOF read as zero.

The current namespace counter cannot be below a snapshot namespace counter.
Ordinary admission and writable publication also check the predecessor namespace counter.
These are consistency checks, not authentication against a rewritten history.

## References, envelopes and raw cells

A reference is 56 bytes: type u32 at 0, reserved u32 at 4, absolute offset u64 at
8, length u64 at 16, expected digest[32] at 24. A zero reference has all 56 bytes
zero. Types are namespace 2, commit root 4, index 5 and raw data 6; old payload and
catalog types are unsupported. Every nonzero length is 4096. Cells start at offset
8192 or later on 4096-byte boundaries. A child cell must end at or before its
parent's offset and fit within physical EOF, the candidate committed end and
capacity. Equal typed references may share immutable storage. Conflicting types
or digests at one offset fail full verification.

Metadata cells have this 64-byte envelope:

| Offset | Bytes | Value |
| --- | --- | --- |
| 0 | 8 | `SFSREC02` |
| 8 | 4 | Type |
| 12 | 4 | Zero |
| 16 | 8 | 4032, the body length |
| 24 | 16 | Image UUID |
| 40 | 24 | Zero |

Their digest covers all 4096 bytes. Raw cells contain exactly 4096 logical data
bytes, with no envelope. Their parent extent row carries the digest of a 36-byte
domain followed by the raw cell: `SFSDAT02` at 0, UUID at 8, u32 type 6 at 24,
u64 length 4096 at 28. Raw hash input is therefore 4132 bytes. Bytes after an
extent row's visible length must be zero. Missing extents and the zero suffix of
a short visible extent do not expose retained contents when a file grows.

A namespace cell contains inode-index reference at 64, name-index reference at
120, next inode u64 at 176, entry count u64 at 184, and zero bytes from 192.
Zero entry count requires both indexes to be zero; otherwise both exist. The
implicit root is excluded from the count. The count is also bounded by nine times
the candidate's physical cell count before it bounds parent walks.

A commit-root cell contains current namespace reference at 64, optional snapshot
catalog index reference at 120, and zero bytes from 176. Snapshots reference whole
immutable namespaces; they never own mutable pages.

## Ordered index cells

Map kinds are inode 1, name 2, extent 3 and snapshot 4. Every index uses this header:

| Offset | Bytes | Field |
| --- | --- | --- |
| 64 | 4 | Map kind |
| 68 | 2 | Level, 0 for leaf |
| 70 | 2 | Row count |
| 72 | 8 | Birth generation, positive and no later than the candidate |
| 80 | 8 | Zero |
| 88, 90 | 2 each | Actual minimum and maximum key lengths |
| 92 | 20 | Zero |
| 112 | 263 | Minimum key, zero-padded |
| 375 | 263 | Maximum key, zero-padded |
| 638 | 2 | Zero |
| 640 | Remaining | Fixed-stride rows, then zero padding |

Inode, extent and snapshot keys are unsigned numbers encoded as big-endian eight
bytes in fences and internal rows. A name key is big-endian parent inode followed
by the raw name, compared lexicographically as unsigned bytes, with a shorter
prefix first. Rows are strictly ordered. Each internal row names its child's
actual minimum; the next minimum is an exclusive upper fence, and the final
child's actual maximum equals its parent's maximum. Expected map, level, fences,
root/nonroot occupancy, birth generation, counter and EOF context are checked on
cache hits as well as misses. All leaves have equal depth.

| Map | Leaf stride | Nonroot leaf rows | Internal stride | Nonroot children |
| --- | --- | --- | --- | --- |
| Inode | 352 | 3–9 | 72 | 16–48 |
| Name | 280 | 4–12 | 328 | 3–9 |
| Extent | 72 | 16–48 | 72 | 16–48 |
| Snapshot | 328 | 3–9 | 72 | 16–48 |

An empty tree is a zero reference. A root leaf has 1 through the stated maximum
rows; an internal root has 2 through the maximum children. There are no sibling
or parent pointers.

Leaf row layouts, relative to each row:

- Inode: inode u64 at 0, parent u64 at 8, kind u32 at 16, name length u32 at 20,
  logical size u64 at 24, extent-index reference at 32, name[255] at 88, nine
  trailing zero bytes. Directories have size zero and no extent root; a zero-size
  file also has no extent root. Positive-size files may be entirely sparse.
- Name: parent u64 at 0, name length u32 at 8, name[255] at 12, inode u64 at 267,
  five trailing zero bytes. Each row must agree with its canonical inode row.
- Extent: block number u64 at 0, raw reference at 8, visible length u16 at 64,
  six trailing zero bytes. Visible length is 1–4096, and block plus visible length
  must fit the referencing file's EOF.
- Snapshot: view u32 at 0, zero u32 at 4, namespace reference at 8, name length
  u32 at 64, name[255] at 68, five trailing zero bytes. IDs and names are unique;
  the next ID follows the largest retained ID.

Internal rows contain key length u32 at 0, zero u32 at 4, key at 8, and child
reference at 16 for numeric maps or 271 for names. The name key area is 263 bytes
and its internal row has one final zero byte. Unused name/key bytes are zero.

Insertion splits a full child at floor(3b/2), where b is its minimum occupancy,
before descent. A full root gains a level. Deletion borrows from a left sibling
above minimum, otherwise a right sibling above minimum, otherwise merges with the
right sibling when present or the left sibling. A one-child root collapses.
Changed extrema and ancestor minima are recomputed from checked child headers.
Growth beyond height 16 is refused before image writes, including any required
batch seal.

## Slots and publication

Slots occupy bytes 0–4095 and 4096–8191. Their layout is:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | `SFSIMG01` |
| 8, 12 | 4 each | Major 0, minor 2 |
| 16 | 8 | Feature bits, zero |
| 24 | 16 | Nonzero UUID |
| 40 | 8 | Positive generation |
| 48 | 56 | Commit-root reference |
| 104 | 8 | Committed end, exactly root offset plus 4096 |
| 112 | 32 | SHA-256 of this slot with these 32 bytes zeroed |
| 144 | 8 | Physical capacity |
| 152 | Remaining | Zero |

Creation writes the empty namespace and root, finalizes the slot bytes, performs
`F_FULLFSYNC`, writes both generation-1 slots, performs `F_FULLFSYNC`, syncs the
parent directory, then performs a final image `F_FULLFSYNC`. It checks the pinned
parent and named image identities before acknowledging. Initial EOF is 16384.

A normal open, writable or read-only, requires two coherent slots with equal UUID and capacity.
Equal generations are allowed only for identical generation-1 slots. Otherwise
the generations are consecutive, ends increase, and the newest generation's
parity equals its slot index. A slot failure or incoherent pair requires explicit
read-only recovery inspection; opening never initializes or repairs an image.

On an existing ordinary handle, verify (and writable commit) preserves a slot-read failure as
`SFS_IO` in the read phase, with the first slot's saved errno when both fail.
Unsupported-format status retains precedence. These failures poison the handle
and discard its transaction. A later budget or cancellation stop cannot hide an
already observed fatal slot failure. Without such a failure, a controlled stop
returns `SFS_INCOMPLETE` and preserves the otherwise unchanged transaction.
Initial-open and read-only recovery policies remain as described above.

`sfs_image_open_readonly` uses `O_RDONLY` with the same no-follow, close-on-exec,
nonblocking descriptor and exclusive lifetime lock as normal writable open. It
selects the newest coherent anchor and returns `ROOT_ONLY`; it performs no full
scan, auxiliary work, image write/truncate/barrier, repair or recovery fallback.
The existing owned/private/single-link and local writable APFS admission rules
still apply. With nonnull `out`, every failure leaves `*out` NULL. Initial slot
I/O or pair failure remains `RECOVERY_REQUIRED` with saved slot errno; unsupported
format takes precedence. Load, identity and cleanup failures retain normal-open
status/phase/errno rules. A failed close still consumes its handle exactly once.

Healthy ordinary read-only handles reject all transactions and mutations with
`STATE`, phase NONE and errno 0. Select accepts only recovery handles and returns
`INVALID` for either ordinary policy, including poisoned handles. Other
ready-guarded calls return `POISONED` before argument/transaction errors once an
ordinary handle has suffered a fatal I/O, integrity, unsupported-format or
reconciliation failure. Explicit verify freshly requires the valid pair and same
latest anchor; it does not fall back to an older still-present slot. Recovery
inspection/selection retains its separate nonpoisoning policy. Ordinary reads
use existing touched-path and stable-descriptor checks, not a fresh slot scan
per call. Explicit full verification may write only its bounded auxiliary state.

Commit freshly reconciles slots and the current root, refusing an unexpected
anchor rather than rebasing. It seals pending children, indexes and namespace,
appends the final commit root, and finalizes the new slot bytes. It then performs
`F_FULLFSYNC`, writes slot `generation % 2`, and performs `F_FULLFSYNC` again before
acknowledging. No reachable allocation, reference fixup or hashing occurs after
the first fence. An error before attempting the slot write returns I/O failure;
a failed slot attempt or later fence returns outcome unknown. Both poison the
handle. A lost acknowledgement cannot establish whether the new root persisted.

Aborted and failed appends remain immutable and consume capacity. They are never
truncated or reused. A later append aligns past a partial tail with explicit zero
padding. Initial reserved-slot space is left as a zero hole until publication.

## Transactions, batching and admission

Readers always observe committed state, including while a transaction is active.
Snapshot creation captures the last committed current namespace. There is no
read-your-writes API. Zero-length writes are no-ops.

Writable pages are bounded RAM overlays identified by transaction/batch epoch,
map, logical inode or global-map owner, namespace lineage and traversal token.
Writable reuse is never keyed only by an old physical reference. Separate inodes
sharing an immutable extent tree receive separate overlays. Splits and merges
create fresh tokens. Appended cells, even uncommitted ones, are never modified.

One file-write batch retains its inode row and extent overlay across caller
chunks while its touched numeric block span remains at most 256. Changing inode,
exceeding that span, another mutating operation, or commit seals the batch.
Sealing writes only reachable changed extent pages in child-before-parent order,
the one existing inode path, and one namespace. It does not publish a slot.

Two arenas are allocated lazily, each bounded by 5 MiB including at most 1024
page bodies and bounded merge/path bookkeeping. A same-batch call clones only
allocated live pages, prepares at most 17 zero-initialized raw merges, applies
changes tentatively, and counts exact dirty pages. Clean pages are detached before
retaining the next batch. The 10 MiB ceiling is not a default resident footprint.
Metadata and auxiliary read caches are separately bounded by 4 MiB each.

Let E be actual EOF including tails, K the tentative batch's exact changed extent
pages and Hi the checked inode height. A same-batch write of c raw cells reserves
`c + K + Hi + 1 namespace + 1 final root` cells beyond aligned E. Existing pending
liability is replaced, not added twice. On a batch transition, add the old batch's
exact seal cost and reserve the new call using `c*(3Hplus+3)` extent pages, where
`Hplus=min(16,max(1,checked extent height+1))`. The actual new shape/count must fit
that allowance. Metadata edits use their checked heights and known key edits;
input and height checks occur before a required old-batch seal. Publication space
is reserved once and cannot be consumed by earlier appends.

Admission/cap `SFS_LIMIT` returns admission phase with errno 0, discards the whole
staged transaction, and appends nothing for the rejected call, including no old
batch seal. Earlier tails remain charged. Invalid arguments and early allocation
failure can retain unchanged prior staging; late failure after append/sealing
starts discards the whole transaction. After non-I/O discard, commit returns
`SFS_STATE`. I/O or integrity failure poisons the handle, and readiness returns
`SFS_POISONED` before transaction-state errors. Close/reopen is required.

Growth allocates no holes. Before extending a file, a lower-bound check against
its old EOF rejects an extent at or beyond the first invalid block, including an
overlong visible boundary. Partial writes verify old raw data and its zero tail,
start with zero buffers, retain only old visible bytes, then overlay caller data.
This does not prove the absence of corruption in an unvisited malformed subtree.

Nonzero shrink counts the retained extent prefix in one checked pass and rebuilds
that prefix in a second pass, without retaining a row list. An existing partial
boundary gets a newly verified raw copy with a zero tail. For R retained rows,
page counts are `n0=ceil(R/48)`, then `ni=ceil(n(i-1)/48)` through 1. Each level's
known input is divided into nearly equal groups, first remainder groups larger.
One page buffer per level streams finalized child references upward. Reservation
is exactly the sum of those pages, Hi, namespace, final root and the optional
boundary raw cell, plus an old batch's seal liability. Zero truncate and growth
need only Hi, namespace and final root, plus that old liability. No shrink returns
physical capacity. A tiny shrink of a large file still scans and copies its
retained metadata; this is an explicit cost of the bounded rebuild algorithm.

## Verification, coverage and iteration

`ROOT_ONLY` open/commit checks slots, the selected root, namespace and root index
headers, bounded snapshot catalog and counter floors. It does not establish global
bijection, acyclicity or payload health. `TOUCHED` operations additionally check
their actual inode/name/extent paths, changed neighbors, canonical relationships,
parent chains and requested raw cells. Parent walks use checked links, a declared
count bound and cycle detection. An unrelated mutation may succeed before full
verification later discovers unrelated damage.

`FULL_REACHABLE` requires all selected current/snapshot namespace counts,
inode/name bijection, parent directory relationships and cycles, all index
structure, EOF relationships, raw hashes and zero tails. `verify`, `inspect` and
`select` require explicit positive budgets for unique raw cells, metadata read
bytes, metadata hash-input bytes, reference/semantic checks, auxiliary length and
auxiliary I/O bytes, plus an optional cancellation callback. Inspect shares totals
across both candidate passes; completed candidates retain their individual full
result if a later candidate stops. Select starts a fresh pass. Inspection never
selects implicitly. Fresh passes discard the clean metadata cache. A successfully
decoded slot anchor is retained independently of full-verification status. An
interrupted first observation leaves no anchor to compare; the first successful
decode during selection captures it before full verification starts. That anchor
remains pinned even if verification stops, and later selection rejects a changed
known anchor. Capturing an anchor alone never selects or verifies the candidate.

A fresh pass uses a new owned mode-0600 auxiliary `memo` file in an owned
mode-0700 temporary directory below the retained image parent. It has one 128-byte
entry per physical cell at actual EOF, including tails: state u32, type u32,
digest[32], subtree count u64, maximum inode u64, maximum file end or raw last
nonzero position u64, and 64 zero bytes. It stores no payload or namespace rows.
Intrinsic completion and exact-namespace semantic completion are distinct.
Recurrence and conflicting identities fail. The file is private temporary work,
not persistent trust or an image sidecar; length budget and actual free-space
headroom are checked before creating it. Cache-miss reads and dirty eviction
writes consume the auxiliary I/O budget. Cleanup errors prevent full coverage.

Full verification may reuse a completed raw digest/last-nonzero summary and
intrinsic subtree counts. Every metadata reference still obtains the whole
checked cell and revalidates its current context. Distinct namespace semantics
read actual inode/name rows again. Cache eviction therefore permits and charges
full metadata rereads and rehashes. There is no metadata-once bound. Successfully
completed unique raw cells contribute 4096 bytes read and 4132 SHA input bytes
each; each metadata load or reload contributes 4096 of each, with slot/control
reads charged separately. Failed attempts are additional work. Read counters
alone are not evidence of actual hash inputs.

Charges and cancellation checks precede the work they permit. A controlled stop
returns `SFS_INCOMPLETE`, its reason, errno 0 and no full coverage. Allocation
failure remains `SFS_NOMEM`. Actual auxiliary ENOSPC is `SFS_IO`, real errno
`ENOSPC`, and `SFS_PHASE_VERIFY_AUX`; it is neither corruption nor a budget stop.
The first failure survives auxiliary cleanup. A controlled explicit verification
stop retains an otherwise unchanged active transaction; ordinary-handle
I/O/integrity failure discards any transaction and poisons the handle.

Directory iteration returns one entry at a time through a zero-initialized opaque
1088-byte cookie. It binds namespace digest[32], parent u64 at 32, depth u32 at
40, flags u32 at 44, and at most 16 frames of 64 bytes beginning at 48. A frame
contains reference[56], index u16, level u16 and four zero bytes. Flag 1 means
started and flag 2 means finished; unused frames and final padding are zero.
Each path is checked again from the bound name root. Changed namespace returns
state failure; malformed or wrong-parent cookies are invalid. Cookies contain no
process pointers. Reads report only a verified prefix in `read_count` if a later
cell fails, and do not copy unverified bytes.

`sfs_image_resume_after(image, view, expected_generation, expected_root_digest,
parent, previous, out, result)` reconstructs that same cookie after a canonical
child. It checks readiness first, then requires nonnull output/digest, nonzero
generation and a previous inode greater than root. Invalid arguments return
`INVALID`; generation or commit-root digest mismatch returns `STATE` before I/O.
Use the generation and root digest from the successful open or select receipt,
not a namespace digest. The digest distinguishes independently valid recovery
roots with the same generation. These are consistency checks, not authentication.

Resume resolves the explicit committed view, validates the parent directory and
canonical previous inode, seeks the raw `(parent, name)` key and consumes exactly
the matching name row. Missing view or previous inode is `NOT_FOUND`; invalid,
missing or nondirectory parent, or a child belonging to another directory, is
`INVALID`. A missing or inconsistent canonical name mapping is `CORRUPT`. It
uses a fixed number of indexed paths bounded by height 16 and page fanout, no
directory-prefix scan or raw data reads. It does not consume the successor.
Resuming after the last child succeeds; subsequent `next` reports found=0.

On every failure a nonnull output cookie remains byte-for-byte unchanged. Success
publishes a locally completed cookie with canonical padding and `TOUCHED`
coverage/errno 0, never FULL. Late failures retain existing phase/errno and
ordinary-versus-recovery poison rules. No budget or cancellation interface is
added. The output remains bound to the namespace and parent for `next`; no cookie
format changes. Active transactions expose only committed membership. Any new
committed generation invalidates the old resume receipt even for an unchanged
snapshot; reopening an unchanged image permits reconstruction with its fresh
receipt. Callers retain image/volume identity and original view/verifier binding
and serialize access. Passing another explicit view requests that view; this
helper proves membership, not that the caller previously emitted the inode.

This representation removes the earlier fixed small-file/namespace design caps.
It does not establish target-scale performance, CPU/RSS wins, recovery under real
power loss, or production reliability. Reclamation, snapshot deletion, complete
Mac attributes, ordinary FSKit installation and mounting remain later work.
