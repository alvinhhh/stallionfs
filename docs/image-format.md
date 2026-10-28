# Experimental image format 0.1

The internal C image core qualifies a small offline storage representation. It is
not mounted, installed, packaged with the CLI, or a stable on-disk format. Unknown
versions and feature bits are refused. Existing `sfs` and `stallionfs` operations
do not use this core.

The only supported backing store is a current-user-owned, single-link regular
file with private permission bits on local writable APFS. Its containing directory
must be owned by the current user with mode 0700 permission bits. The final image
component is opened without following symlinks. Creation uses exclusive creation
with mode 0600 and never replaces an existing file. Every handle, including a
read-only inspection handle, retains a nonblocking exclusive advisory lock on its
one pinned descriptor until close. A conflicting opener returns busy. Locks
coordinate cooperating callers; this format does not defend against an attacker
rewriting the backing file and its hashes or replacing its pathname.

## Limits and encoding

All integers are canonical unsigned little-endian. Structures and pointers are
never serialized. Reserved bytes must be zero. SHA-256 uses CommonCrypto.

| Limit | Value |
| --- | --- |
| Physical image size, including abandoned tails | 64 MiB |
| Logical file size | 4 MiB |
| Each metadata record, including its envelope | 1 MiB |
| Namespace entries below the separate root inode | 1024 |
| Named snapshots | 32 |
| Component or snapshot name | 255 bytes |

Names are nonempty byte strings; NUL, slash, `.` and `..` are refused. Names are
case-sensitive, with no Unicode normalization. The root inode is 1. Inode IDs are
monotonic, never reused, and retained by snapshots. Entries are directories or
regular files. Duplicate names in one parent, invalid parents, duplicate IDs and
directory cycles are refused. The current next-inode counter cannot be below any
reachable snapshot namespace's counter. Writable admission also requires it to
be at least the predecessor namespace's verified counter. Deletion and unchanged
counters remain valid. These checks enforce retained-record consistency; they do
not authenticate an image against an attacker who rewrites all relevant hashes.

The implementation rewrites whole bounded files and the complete namespace per
transaction. It never reuses or truncates abandoned storage. These representations
must be replaced with indexed metadata, independently checksummed ranged payloads
and separately qualified space management before mounted or large-workload
qualification. The caps cannot represent 100k–200k files, a 50 GB dataset or 10 GB
files. The encoding and caps are not a production compatibility promise.

## References and records

A reference is 56 bytes:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | Type: payload 1, namespace 2, catalog 3, root 4 |
| 4 | 4 | Reserved zero |
| 8 | 8 | Absolute record offset |
| 16 | 8 | Record length including the 64-byte envelope, excluding alignment padding |
| 24 | 32 | Expected SHA-256 of envelope and body |

Records begin at offset 8192 or later, aligned to 4096 bytes. Every writer pads
each record to the next alignment boundary with zero bytes. A reference must fit
inside its candidate's committed end and physical EOF. Child records must end
before their parent's record begins. Identical immutable records may be shared;
different overlapping referenced records are refused. All bounds, types and
counts are checked before allocation or data reads. Images are never memory-mapped.

Each 64-byte envelope contains:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | ASCII `SFSREC01` |
| 8 | 4 | Type |
| 12 | 4 | Reserved zero |
| 16 | 8 | Body length |
| 24 | 16 | Image UUID |
| 40 | 24 | Reserved zero |

Payload bodies contain exactly the logical file bytes. Empty files still have a
payload record with an empty body. Directory payload references and sizes are zero.

A namespace body starts with a 16-byte header: entry count at offset 0 (4 bytes),
reserved zero at 4 (4 bytes), and next inode ID at 8 (8 bytes). Entries are ordered
by increasing inode ID. Each has an 88-byte prefix followed by its name bytes:

| Entry offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | Inode ID |
| 8 | 8 | Parent inode ID |
| 16 | 4 | Kind: directory 1, file 2 |
| 20 | 4 | Name byte length |
| 24 | 8 | Logical file size |
| 32 | 56 | Payload reference, or zero for directories |
| 88 | variable | Name |

A catalog body begins with count (4 bytes) and reserved zero (4 bytes). Each
snapshot has a 64-byte prefix: name length at 0 (4 bytes), reserved zero at 4
(4 bytes), namespace reference at 8 (56 bytes), then name bytes at 64. Snapshot
entries reference namespaces, never catalogs or commit roots. Their array position
plus one is the stable view ID; view 0 means the current committed namespace.
There is no snapshot deletion in this milestone.

A commit-root body is exactly 112 bytes: the active namespace reference followed
by the catalog reference. No record body has trailing unparsed bytes.

## Commit slots

Two distinct 4096-byte slots occupy offsets 0 and 4096. A slot contains:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | ASCII `SFSIMG01` |
| 8 | 4 | Major version 0 |
| 12 | 4 | Minor version 1 |
| 16 | 8 | Known feature bits, currently zero |
| 24 | 16 | Nonzero image UUID |
| 40 | 8 | Nonzero generation |
| 48 | 56 | Commit-root reference |
| 104 | 8 | Committed end: aligned end of the commit-root record |
| 112 | 32 | SHA-256 over all 4096 bytes with this field zero |
| 144 | 3952 | Reserved zero |

Alignment does not make a slot write atomic. Both slots must be individually
valid and agree on UUID, version and feature bits. Equal generations are accepted
only for the identical initial generation-1 pair, with identical complete root
references and committed ends. Otherwise generations must be adjacent and
nonwrapping, ends must strictly increase, and the newest slot index must equal
generation modulo 2. Generation 2 replaces slot 0; generation 3 replaces slot 1.
A valid checksum does not override a violated pair invariant.

The empty initial namespace is at 8192 (80 bytes), catalog at 12288 (72 bytes),
and root at 16384 (176 bytes). The initial committed end is 20480.

## Creation and publication

Creation pins and validates the parent descriptor before exclusive creation, then
immediately takes the image lock before initialization. It validates the held
image and parent backing identity. A failed lock retains the empty created file.
The creation protocol is:

1. Admit and append the complete empty namespace, catalog and root.
2. Require a successful image `F_FULLFSYNC`.
3. Write slot 0, then the matching generation-1 slot 1.
4. Require a second successful image `F_FULLFSYNC`.
5. Require parent-directory `fsync`, then a final image `F_FULLFSYNC`.
6. Recheck the pinned parent and its final entry against the held image identity.
7. Check parent descriptor close, then acknowledge creation and retain the image lock.

Failure before slot publication reports an initialization error with the retained
phase and errno. Once slot publication begins, any error reports outcome unknown.
There is no acknowledged predecessor during creation. Zero or one valid slot is
never an implicitly usable new image. A failed attempt never unlinks, truncates,
repairs, retries or reinitializes the file. A failed parent close also prevents a
creation acknowledgment.

One transaction may be staged per writable handle. Namespace mutations and
ranged input are kept private until commit. Each mutating operation checks the
exact padded payload, manifest, catalog and root costs against the actual EOF
recorded for the pinned image. A limit failure discards the entire transaction
without appending; `commit` then returns state error. The handle remains usable
for a fresh transaction. A generation overflow is also refused before append.
Commit rechecks descriptor identity, physical EOF and the committed reachable
state before writing. A freshly verified slot pair whose newest anchor differs
from the handle's committed anchor poisons the handle before any append. Host
interference observed by these checks is an error.

Ordinary commit appends complete immutable records after aligned physical EOF,
requires image `F_FULLFSYNC`, writes the older slot with generation N+1, and
requires a second image `F_FULLFSYNC` before acknowledgment. Exact read/write loops
retry EINTR and complete short transfers. A zero-byte write fails. No weaker
barrier is substituted. An I/O or detected integrity failure on a writable handle
invalidates further use until close/reopen; a failure from slot publication onward
is outcome unknown.
The old committed root is never rewritten as a rollback. Failed append tails
consume image capacity on reopen.

`F_FULLFSYNC` availability and process interruption tests do not establish physical
power-loss behavior on every device. Recovery atomicity assumes a crash-only
model with correctly honored durability barriers. A lost reply after the second
barrier may leave a complete committed generation without an acknowledgment.
Reconcile UUID, generation and root digest after reopening.

## Recovery, verification and API coverage

Normal open requires two valid slots with valid pair invariants and fully verifies
the newest candidate's root, namespace, catalog, current payloads and every
snapshot's payloads. Damaged slots require explicit recovery inspection. Damaged
newest reachable content fails; an older generation is never silently substituted.
Writable open and fresh writable verification additionally verify the predecessor
root and namespace metadata to establish the inode-counter floor. Unreadable or
corrupt predecessor metadata fails closed with I/O error and its errno, or
corruption respectively. This check validates predecessor payload references
structurally without reading their bodies or the predecessor catalog/snapshot
bodies. It does not expand full verification to unrelated predecessor-only data.
Within one verification pass, identical payload references are hashed once after
all reference bounds, types and overlaps are checked. Independent verification
calls always start fresh.

Inspection opens read-only and reports each independently fully verified candidate
and whether the slot pair is valid. It does not select a candidate. The caller
must explicitly select a slot before reading. Its report always states that the
latest generation may be unknown: accepting an older candidate can omit
acknowledged data. Inspection neither repairs slots nor restores write service.
Its candidates do not require the predecessor metadata used for writable
admission. A fully verified newest candidate can therefore remain readable when
that predecessor metadata is damaged. Read-only inspection handles remain open
after errors; callers may explicitly retry verification or select a candidate.
Selection rereads the chosen slot and verifies that exact candidate again.
If no candidate verifies, it fails closed. `physical_end > committed_end` reports
an uncommitted tail; recognizable tail bytes never establish a commit.

Each inspection candidate retains its own read errno. When normal open refuses a
slot pair, its single result reports the first slot read error in index order
(slot 0 before slot 1), or zero when no read syscall failed. Unknown-version or
feature refusal retains unsupported status; other invalid pairs require recovery.
An inspection with no usable candidate uses the same index precedence for its
summary error. Checked cleanup failures are reported separately as close errors.

The opaque-handle C ABI in `filesystem/image.h` exposes stable inode IDs, checked
64-bit ranged reads/writes, separate size changes, one-entry directory iteration,
named snapshots and explicit verification. Inputs never require an entire file
or namespace serialization. A zeroed iterator cookie binds to one namespace
digest; changing that namespace invalidates the cookie. Callers must serialize
access to one handle and use a fresh cookie when changing parent directories.
Reads and namespace queries observe committed state, including during staging.
Snapshot creation in a transaction retains its last committed namespace.

Full verification returns the verified generation/root digest and
`SFS_COVERAGE_FULL_REACHABLE`. Successful ordinary reads do not claim full coverage.
The capped full-open behavior is an experimental restriction. Before mounted
integration, open must use bounded anchor/root verification, traversal must verify
touched metadata, ranged reads must verify touched checksum units, and full
reachable verification must remain an explicit scrub operation. That later
coverage change requires separate review; it is not implemented here.

Permissions, ownership, timestamps, links, sparse partial writes, xattrs, ACLs,
application/Finder behavior, open-file lifetimes, concurrent mounted access,
pooling, redundancy/repair, compression, encryption, replication and reclamation
are outside this core. Checksums detect damage and cannot reconstruct lost data.
There is no mount, public image command, writable recovery or production claim.
