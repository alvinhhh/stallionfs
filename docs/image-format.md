# Experimental image formats 0.2, 0.3, 0.4 and 0.5

This internal C core stores an offline filesystem image. The public `sfs` and
`stallionfs` commands do not use it. This is an incompatible replacement for
format 0.1, not a mounted filesystem or a stable compatibility promise.
Exactly minors 2, 3, 4 and 5 remain supported; unknown versions and feature bits are refused.
Legacy create produces 0.2. `sfs_image_create_metadata` explicitly creates 0.3.
`sfs_image_create_metadata_version` accepts an explicit minor 3, 4 or 5.
There is no migration, conversion-on-open or automatic repair.

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
| Symlink target, formats 0.4/0.5 | 1–4096 non-NUL bytes; independent of the regular-file cap |
| One write call | At most 65536 bytes; at most 17 affected raw cells |
| One active write batch | One inode, inclusive touched-block span at most 256 |

Integers are unsigned little-endian unless described as keys or signed times. Reserved
bytes are zero, structures and pointers are never serialized, and hashing uses
CommonCrypto SHA-256. Names are case-sensitive raw bytes without normalization;
NUL, slash, `.` and `..` are invalid. Root inode 1 is implicit. Other inode IDs
start at 2, increase monotonically and are never reused. Kinds are directory 1 and regular file 2; formats 0.4/0.5 also admit symlink 3.
Holes below regular-file logical EOF read as zero. Link targets are never followed.

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
| 0 | 8 | `SFSREC02` / `SFSREC03` / `SFSREC04` / `SFSREC05` for the exact minor |
| 8 | 4 | Type |
| 12 | 4 | Zero |
| 16 | 8 | 4032, the body length |
| 24 | 16 | Image UUID |
| 40 | 24 | Zero |

Their digest covers all 4096 bytes. Raw cells contain exactly 4096 logical data
bytes, with no envelope. Their parent extent row carries the digest of a 36-byte
domain followed by the raw cell: `SFSDAT02`, `SFSDAT03`, `SFSDAT04` or `SFSDAT05` at 0 for the candidate
version, UUID at 8, u32 type 6 at 24,
u64 length 4096 at 28. Raw hash input is therefore 4132 bytes. Bytes after an
extent row's visible length must be zero. Missing extents and the zero suffix of
a short visible extent do not expose retained contents when a file grows.

A namespace cell contains inode-index reference at 64, name-index reference at
120, next inode u64 at 176 and entry count u64 at 184. Format 0.2 has zero bytes
from 192. Formats 0.3/0.4/0.5 store the root metadata tuple at 192.
Formats 0.3/0.4 have zero bytes from 280. Format 0.5 stores an xattr-index
reference at 280..335 and zero bytes from 336; this root is independent of the
inode/name count, and root-owned attributes are legal when that count is zero.
Zero entry count requires both indexes to be zero; otherwise both exist. The
implicit root is excluded from the count. The count is also bounded by the inode
leaf maximum (nine for 0.2, six for 0.3/0.4/0.5) times the candidate's physical cell count
before it bounds parent walks.

A commit-root cell contains current namespace reference at 64, optional snapshot
catalog index reference at 120, and zero bytes from 176. Snapshots reference whole
immutable namespaces; they never own mutable pages.

## Ordered index cells

Map kinds are inode 1, name 2, extent 3, snapshot 4 and xattr 5.
Map 5 is admitted only in minor 5. Every index uses this header:

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
| Inode, 0.2 | 352 | 3–9 | 72 | 16–48 |
| Inode, 0.3/0.4/0.5 | 440 | 2–6 | 72 | 16–48 |
| Name | 280 | 4–12 | 328 | 3–9 |
| Extent | 72 | 16–48 | 72 | 16–48 |
| Snapshot | 328 | 3–9 | 72 | 16–48 |
| Xattr, 0.5 | 352 | 3–9 | 328 | 3–9 |

An empty tree is a zero reference. A root leaf has 1 through the stated maximum
rows; an internal root has 2 through the maximum children. There are no sibling
or parent pointers.

Leaf row layouts, relative to each row:

- Inode: inode u64 at 0, parent u64 at 8, kind u32 at 16, name length u32 at 20,
  logical size u64 at 24, extent-index reference at 32, name[255] at 88, nine
  trailing zero bytes through offset 351. Formats 0.3, 0.4 and 0.5 add the metadata tuple at
  offset 352. Directories have size zero and no extent root; a zero-size
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

## Format 0.3/0.4/0.5 metadata

The root namespace and every inode row carry this 88-byte tuple. Offsets are
relative to namespace byte 192 or inode-row byte 352:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0, 16, 32, 48 | 16 each | Birth, access, modification, change time |
| 64, 68, 72, 76 | 4 each | Mode, UID, GID, BSD flags |
| 80 | 8 | Logical extent-row count |

Each time stores signed 64-bit seconds as little-endian two's-complement bits,
u32 nanoseconds, then u32 zero. Nanoseconds range from 0 through 999999999.
Negative seconds and times in any relative order are valid. Wall-clock rollback
and restored values are not clamped, rounded or made monotonic. Public C structs
are encoded field by field; their padding is not persisted or validated as input.

Mode includes matching regular-file `0100000`, directory `0040000`, or
format-0.4/0.5 symlink `0120000` type bits
plus permission/special bits `07777`; other type or high bits are invalid. UID/GID
are literal u32 values. The supported flag mask is `0x8001` (`UF_NODUMP|UF_HIDDEN`),
both caller-controlled advisory attributes. Other caller flags return early,
nonpoisoning `UNSUPPORTED`; unrecognized stored bits are corruption. Immutable,
append-only, restricted, compressed, dataless, firmlink and other behavioral flags
are not implemented. Stored mode/ownership is metadata, not new per-inode access
control enforcement, ACL inheritance or a complete native metadata promise.

Files count present logical extent mappings, including repeated physical
references. Counts must agree with empty/nonempty extent roots and be at most
ceil(size/4096) and the physical extent-row bound. Directories/root have count 0. Symlinks have exactly one mapping.
FULL verification compares each file count with its actual intrinsic extent-row
summary. Bounded stat checks representations and paths rather than rescanning
the file. `referenced_data_bytes` is count times 4096: holes charge zero,
allocated zeros and partial cells charge a full cell, and each file/view and each
repeated mapping is charged independently. It excludes indexes, image tails,
host allocation and global uniqueness/reclaimability. It is primary-data mapping
accounting, not an established FSKit all-fork allocation mapping.

`link_count` is the explicit SFS convention 1 for files, symlinks, directories and root.
There are no hardlinks or stored child-directory link counters. Snapshot sharing
does not add a canonical name. This convention does not equate all Darwin stat,
getattrlist and FSKit representations. A future hardlink feature would also need
to revise canonical-name and resume-after-inode assumptions.

### Producers, setters and time rules

Legacy create still makes 0.2 and all legacy operations keep their 0.2 behavior,
without sampling a metadata clock or inventing old history. Explicit
`create_metadata` makes 0.3, with required root attributes. `add_metadata` accepts
required mode/UID/GID/flags and optional exact birth/access/modification
restorations. Legacy add also works on 0.3/0.4/0.5: fresh files use type+0600, directories
type+0700, actual effective process UID/GID and flags 0. These defaults are not
preserved source attributes or native permission-inheritance policy.

One validated `CLOCK_REALTIME` sample supplies each effectful 0.3/0.4/0.5 operation before
any required pending-batch seal or image append. Explicit create samples before
exclusive image creation. All four fresh times default to that sample; selected
restorations replace only birth/access/modification. Source ctime is not
restorable. A real clock failure returns `TIME_UNAVAILABLE`, phase NONE and its
saved errno. A malformed clock sample has the same status and errno 0. Both are
early, nonpoisoning and preserve prior staging and physical bytes; failed create
has no new image. Invalid caller timestamps return `INVALID` instead.

| Operation | Automatic timestamp updates |
| --- | --- |
| Accepted positive write, including equal bytes | File modification/change |
| Size-changing resize | File modification/change |
| Add/remove | Parent modification/change, including root |
| Real rename | Moved inode change; distinct parents modification/change |
| Nonempty setter, including equal values | Change time; selected explicit/NOW fields |
| Read/stat/iteration/resume, snapshot, commit, abort | No new sample or automatic time update |

`set_metadata` uses `fields` to select mode/UID/GID/flags/birth/access/modification.
Its `now` mask may select only a subset of selected time fields; those use the
same operation sample. Unselected fields are OMIT and are not read. Explicit
times are restored exactly, without Darwin setattrlist's earlier-mtime/birth
coupling. No ctime, size, kind, allocation or link setter exists. Wrong kind bits,
unknown masks, invalid NOW subsets and out-of-range nanoseconds are `INVALID`.
Root is a supported setter target. Mutations require the ordinary writable
transaction policy; snapshot views are immutable.

Zero-length writes preserve existing validation and then do not sample or seal.
Identical parent/name rename preserves its validations and has no new effect.
Empty/OMIT-only setters validate target existence and capability, then do not
sample or seal. Equal-size resize retains its existing pending-batch admission
and seal behavior but does not sample or change times. Commit/flush preserves
the staged operation values, never substitutes commit time. Reads never update
atime. Snapshots capture exactly the committed namespace, including its metadata,
even when a transaction has newer staged values.

### Bounded reads and complete transactions

`stat_metadata` returns the existing entry plus stored times/attributes,
referenced data bytes and link count through checked indexed paths. It performs
no extent/directory scan, raw read or auxiliary verifier pass. It returns
`TOUCHED`, not FULL, and leaves its output unchanged on failure. A healthy 0.2
handle's new metadata API returns direct nonpoisoning `UNSUPPORTED`, phase NONE,
errno 0, without changing outputs or prior staging. This capability refusal is
distinct from fatal on-disk unsupported-format handling. Readiness, poisoned
handle and read-only/recovery mutation guards still take precedence. Create
retains the existing out-handle-NULL failure contract; add publishes its inode
output only on success.

Metadata mutations deduplicate target and up to two nonroot parents; root changes
share the namespace cell. Same-parent rename updates that parent once. Complete
parent/target changes and the timestamp are validated/probed before an old batch
can seal. A pending target's effective data/count/times come from its batch.
After sealing, the final edit preserves the newly materialized extent reference
and reuses the captured changes once. It never restores stale pre-seal data.

With pending work, let `B(H)=3H+3`, `H+=min(16,H+1)` after the real height check,
and `Lold=Kold+Hi_old+1`. Add `Lold` once to these new-cell upper reservations,
which include namespace and one eventual commit root:

| New edit | Cells |
| --- | --- |
| Add with nonroot parent | `B(Hi+)+Hi+B(Hn+)+2` |
| Remove with nonroot parent | `B(Hi)+Hi+B(Hn)+2` |
| Cross-parent rename, both nonroot | `3Hi+2B(Hn+)+2` |
| Same-parent rename, nonroot | `2Hi+2B(Hn+)+2` |
| Nonroot/root setter | `Hi+2` / `2` |

Root parent roles omit their inode path. Without a pending batch, the complete
tentative edit reserves its actual dirty pages plus namespace/root. Probes are
released before old-batch sealing/final construction to retain the two-arena
bound. Only actual dirty cells are appended. LIMIT discards the whole transaction
before any rejected-call append or old seal; prior tails remain charged. Early
input/capability/clock/allocation failures retain untouched prior staging. Late
failures discard all staging; I/O/integrity still poison. Existing uncertainty,
identity, lock, counter, recovery and publication rules remain in force.

The inode leaf maximum falls from 9 to 6, increasing inode-page storage at similar
occupancy. The cache and arena caps do not grow. This is not a measured speed or
memory improvement. Complete native attributes, behavioral flags, native fork import/export, hardlinks,
clone import and mounted permission/SDK mapping remain separate unfinished work.

## Formats 0.4/0.5 symlinks

A symlink inode has size L in 1–4096, mode type `0120000`, the same 88-byte
metadata tuple as format 0.3, extent count 1, and a nonzero extent root. Its root
is a level-0 leaf with exactly one row: block 0, visible length L, and one raw
reference. The raw prefix contains no NUL; bytes after L are zero. Raw precedes
extent leaf, which precedes its inode page. There is no inline target, resolver,
follow option, target mutator or additional index. Names retain their usual
component rules; targets are opaque bytes and may contain slash, dot components,
non-UTF8, absolute/relative/dangling/cyclic text. No referent is checked.

The target bound and refusal of empty targets are SFS core policies. They do not
establish native import/export fidelity: the Darwin/XNU symlink interface has its
own path-length constraints. No 4096-byte OS export or mounted behavior is claimed.

`create_metadata_version(directory, name, capacity, minor, root, out, result)`
accepts only 3, 4 or 5. After validating the output, capacity, directory/component
and required root pointer, an unsupported requested minor returns direct
`UNSUPPORTED/NONE/errno0`, before clock, allocation or image creation. Every
failure with a valid output pointer sets it NULL. Supported versions then validate
root metadata and use the existing creation protocol. Existing create wrappers
still produce exactly 2 and 3 with their previous argument precedence. A mixed
version slot pair or tree is not accepted; unknown stored versions remain fatal
admission failures, distinct from nonpoisoning API capability refusal.

`symlink_metadata` requires an active writable transaction, explicit initial
metadata and inode output. It first applies existing readiness/identity rules,
then validates target, name, parent, canonical absence and metadata. Empty,
NUL-containing or over-4096 target input is `INVALID` before clock/sealing and
preserves prior staging/output. Overlong names retain existing admission LIMIT
behavior. Minors 2/3 return direct nonpoisoning `UNSUPPORTED` for the capability.
The target is copied into one zeroed heap cell and one operation clock is sampled
before any old seal or append. Link and parent updates share that sample. Early
allocation/clock failure preserves staging; no times are fabricated.

Creation reuses the complete metadata-add edit. With pending work reserve
`Lold + B(Hi+) + P*Hi + B(Hn+) + 4`, where P is 0 for root parent and 1 otherwise:
the ordinary metadata-add bound plus exactly one raw cell and one extent leaf.
The old liability and final commit root occur once. The full probe includes the
one-row extent plus inode/name/parent changes using nonpublishable provisional
references. Free it before sealing the old batch, reconcile logical parent/root
state, and rebuild with the same timestamp in one fresh arena. At most two arenas
are live. The conservative new edit needs at most 263 resident overlay pages,
within the unchanged 1024-page arena; the target uses one of the existing
17-cell heap allowance. No additional cell-sized automatic buffer is added.

Before the new raw append, prepare its reference at aligned EOF and the exact
leaf reference at EOF+4096, with the leaf's staged generation already set.
References are encoded only in unsealed overlays, never read as physical cells.
The complete final edit reserves actual dirty inode/name pages plus four cells
(raw, extent, namespace, eventual commit root). Append raw, then the single
extent leaf with no intervening append; require the sealed leaf to equal its
prepared reference before any inode serialization. Append inode/name indexes and
namespace through the existing writer. Only complete success updates staged
namespace and inode output. The operation appends dirty inode/name pages plus
three cells, leaving one commit-root cell reserved. Late errors discard staging
and retain charged tails; fatal errors poison under the existing rules. No
half-link is staged or published.

`readlink` exposes only the committed selected view. Readiness and output-pointer
checks precede `*read_count=0`; early failures leave both outputs untouched.
After valid pointers, format absence returns nonpoisoning `UNSUPPORTED/NONE/0`.
The existing stable-descriptor guard precedes checked namespace/canonical inode
lookup, even on cache hits. Missing view/inode is `NOT_FOUND`; wrong kind is
`INVALID`. A buffer smaller than L (including NULL/zero capacity) returns direct
nonpoisoning `LIMIT/NONE/0` without extent/raw traversal or transaction discard;
it does not claim target integrity. With enough space, validate the complete
shape and bytes into a heap cell, then copy exactly L bytes without a terminator.
Any failure leaves target bytes unchanged and count zero. Success is `TOUCHED`;
checked-path failures retain their phase/errno and ordinary-versus-recovery poison
policy. There is no read clock or atime mutation.

Every FULL link visit validates the one-row shape and no-NUL semantics, even when
a regular inode already completed an intrinsic extent summary. A separate shape
check is charged before loading, and a semantic check before raw/memo examination.
Every checked minor-4/5 raw fetch, including a regular file's, computes first-zero
and last-nonzero together. A completed raw memo may satisfy no-output link checks
only when first-zero>=L and last-nonzero<=L. It never supplies output payload.
Thus shared raw or whole-extent references are safe in either regular/link order;
a regular file's interior NUL cannot become a valid link via a cache hit. Metadata
cache misses re-read/re-hash; auxiliary eviction persists the same checked
128-byte summary. Fresh passes inherit no memo. Real fetches consume raw budget;
valid summary reuse does not, and observed malformed shape/summary/bytes fail
before later controlled stops.

Generic add remains file/directory only. Generic regular read/write/resize reject
links even for zero-length/equal-size calls. Rename/remove and metadata setters
operate on the link itself; snapshots preserve its target and attributes. Links
cannot be directory parents. Canonical-name, resume and cookie contracts remain
unchanged; there are no hardlinked symlinks or new scan APIs.

## Format 0.5 xattrs

An attribute key is big-endian owner inode followed by its exact name bytes.
Names are 1..255 non-NUL bytes; slash, dot, dot-dot, case and non-UTF8 bytes are
retained. This differs from directory component validation and is a storage
policy, not a universal native name limit. Owners may be root, directories,
regular files or symlinks and are never followed. `com.apple.ResourceFork` is an
ordinary opaque value; it has no special allocation or access policy here.

Map 5 leaf stride is 352, with 3..9 rows in nonroot leaves and 1..9 in a root.
Its variable-key internal stride is 328, with 3..9 nonroot children and 2..9
root children, the child reference at 271 and zero byte 327, as for name indexes.
Leaf fields are:

| Offset | Bytes | Value |
| --- | --- | --- |
| 0 | 8 | Owner inode, 1 through next_inode-1 |
| 8 | 4 | Name length |
| 12 | 255 | Exact name, zero suffix |
| 267 | 5 | Zero |
| 272 | 8 | Logical value length L |
| 280 | 56 | Extent-index reference |
| 336 | 8 | Mapping count N |
| 344 | 8 | Zero |

Values are dense binary strings through `SFS_FILE_MAX`, subject to the setter's
`size_t` representation and physical capacity. There is no 65536-byte setter cap.
N is `L/4096 + (L%4096 != 0)`; L=0 requires N=0 and null extent root but retains
an attribute row. Otherwise blocks are exactly 0..N-1, each visible length is
4096 except the final remainder, and the final raw suffix is zero. NUL bytes are
legal throughout values. References retain the ordinary type, bounds, digest and
child-before-parent requirements. No global xattr count is stored.

The five APIs are whole-value upsert, single-name remove, exact-name size, range
read and ordered next. Set requires caller-owned stable input for the whole call,
without output overlap; NULL is allowed for an empty value. Missing owner, value
or view returns NOT_FOUND. Remove of an absent name does not sample a clock or
seal work. Successful set, including identical bytes, and remove sample one clock
and update only owner ctime. Primary data, size, mtime, other metadata and parent
times are preserved, including pending primary data writes to the same owner.
Reads use committed explicit views without atime writes. Primary
`referenced_data_bytes` continues to exclude attribute mappings.

Ready, argument/name/range validation, format capability, descriptor identity
and checked lookup precede work. Invalid input returns INVALID/NONE/0 without
staging changes. Minors 2/3/4 return nonpoisoning UNSUPPORTED/NONE/0. Valid but
unrepresentable lengths and insufficient complete capacity use admission LIMIT
and discard staging. Size output remains unchanged on failure. Range read
initializes a valid read count after argument checks and returns only a checked
prefix if a later cell fails. Offset+capacity is checked; EOF/zero capacity still
checks owner and attribute existence. Missing or short requested mappings are
corruption, never holes. No byte terminator is returned.

Next binds the successful open/select generation and commit-root digest; a
mismatch is STATE with unchanged outputs. NULL/zero after-name starts; otherwise
seek strictly after that opaque name even if it is absent. Stop at the owner
boundary. Success returns one complete entry/found=1, or found=0 with entry
unchanged at end. Failure preserves both outputs. No allocated list or new cookie
exists. Every new commit invalidates prior generation binding; xattr-only changes
also change the namespace digest used by ordinary directory cookies.

Whole-value construction uses one zeroed raw cell and the existing heap extent
prefix builder with 16 cell buffers. Page counts Pe(N) use safe quotient/remainder
ceilings by 48 through one root, with the existing balanced occupancy. Every raw
precedes its extent leaf, every child precedes its parent, and the completed value
root precedes its attribute row. Producer counters and empty buffers are checked
before installation. No intermediate chunk publishes a namespace.

Let Hi and Ha be checked inode and attribute heights, Lold the old pending batch
seal cost without the final commit root, and I=Hi for nonroot owners or 0 for
root. Set reserves once, before any old seal or append:
`Lold + N + Pe(N) + Ba + I + 2`, where Ba=Ha for replacement or
`3*min(Ha+1,16)+3` for insertion. A private structural probe rejects real height
failure before sealing. Remove reserves `Lold + (3*Ha+3) + I + 2`.
The final two cells are one namespace and one eventual commit root. These are
conservative admission bounds, not minimum space requirements. All arithmetic is
checked, and actual dirty pages/appended totals must fit. Probe arenas are freed
before old batch flush; reconciliation retains primary data and mtime before
changing ctime. Attribute and owner roots remain private until one final namespace
contains both. At most one pending-primary arena and one work arena coexist;
the prefix builder is separately bounded. Existing arena caps are unchanged.

Removing an inode first counts K owned attributes without a list, probes the
ordinary metadata removal, and reserves `Lold + K*(3*Ha+3) + R`, where R is the
existing metadata-removal bound including namespace and commit root. Each
attribute deletion seeks afresh, uses and frees one arena, seals only a private
root, and refreshes reader EOF before the next traversal. Deletion never raises
height. After exactly K deletions a final seek must find no owned row; then one
namespace publishes attribute, inode, name and parent changes together. Memory
is independent of K and there is no artificial attribute-count cap.

Before the first seal/append, clock and allocation failure retain staging; LIMIT
and fatal failures retain their existing discard rules. Any failure after that
boundary discards the transaction and retains charged tails. Fatal I/O/integrity
failures keep their existing poison policy. Abort does not reclaim storage.
Snapshots keep their old attribute roots and values unchanged.

ROOT_ONLY binds/checks the attribute root without certifying complete values.
FULL walks all attribute rows, rechecks owner existence, and checks each specific
L/N dense stream, independently of intrinsic extent memo success. Each owner/length
and dense mapping semantic check consumes CHECKS. RAW verification uses binary
semantics while preserving minor-4/5 first-zero summaries for later symlink use.
Shared raw memo may skip repeated no-output hashing, never per-value density
checks or output-byte fetching. Namespace semantic completion is memoized only
after these checks succeed, for current state, snapshots and recovery candidates.

Decoded namespace size is 328 bytes (56 more than minors 2/3/4 implementation
state); the live/staged pair grows 112 bytes. Node 440, anchor 104 and context
568 byte layouts, CELL4096, PAGE_HEAD640, MAX_ROW440, MAX_HEIGHT16 and arena caps
are unchanged. These are structural sizes, not measured process memory.

## Slots and publication

Slots occupy bytes 0–4095 and 4096–8191. Their layout is:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | `SFSIMG01` |
| 8, 12 | 4 each | Major 0, minor 2, 3, 4 or 5 |
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

A normal open, writable or read-only, requires two coherent slots with equal version, UUID and capacity.
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
nonzero position u64, and 64 zero bytes. Completed RAW entries in minors 4/5 use
the count slot at byte 40 for first-zero index (4096 if absent), byte 48 is zero,
and byte 56 is last-nonzero-plus-one. Both positions are at most 4096 and
first-zero is at most last-nonzero. RAW state is exactly 2 with matching type and
digest; bytes 64–127 are zero. RAW bytes 40–55 stay zero in minors 2/3. It stores no payload or namespace rows.
Intrinsic completion and exact-namespace semantic completion are distinct.
Recurrence and conflicting identities fail. The file is private temporary work,
not persistent trust or an image sidecar; length budget and actual free-space
headroom are checked before creating it. Cache-miss reads and dirty eviction
writes consume the auxiliary I/O budget. Cleanup errors prevent full coverage.

Full verification may reuse a completed raw digest/last-nonzero summary (plus first-zero for minors 4/5) and
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
