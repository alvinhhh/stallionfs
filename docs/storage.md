# Storage and recovery

The private storage directory has mode `0700`. ACLs granting access to other users are rejected. It contains:

| Directory | Contents |
| --- | --- |
| `seeds/<id>/repo` | Prepared Git repositories; do not edit these directly |
| `workspaces/<id>/repo` | Working copies for agents |
| `trash/<id>/repo` | Removed workspaces, available to restore |
| `<collection>/<id>/workspace.sparseimage` | APFS image for a seed or image workspace |
| `workspaces/<id>/volume/repo` | Repository inside a mounted image workspace |
| `staging` | Unpublished work and interrupted permanent deletion |
| `locks` | Advisory object locks and managed-use leases outside movable payloads |
| `snapshots/<id>` | Captured repository or closed image and its record |
| `recovery/<id>` | Permanent rollback candidate or actual previous workspace |
| `lifecycle` | Mutable enrollment and explicit open/closed state |
| `journals` | Pending rollback identities |
| `protected` | Retirement protection published before moving a workspace to trash |

Preparation and seed deletion take an exclusive lock on that seed. Creates take a shared lock, so independent clones can run concurrently. Managed workspace mutations take the nonblocking exclusive use lease, then the workspace lock, then the retention lock when needed. Creation takes its seed lock before this sequence. `run` keeps the use lease while its command runs. Opted-in folder sessions also pass the same open descriptor to their command; closing the wrapper descriptor does not unlock surviving inherited copies. The lease files stay outside moved directories. There is no background process.

Preparation and folder creation publish by renaming a completed staging directory. Image creation publishes the closed image and metadata before mounting at its final path. If mounting or branch creation fails, the workspace is retained; `stallionfs mount ID` retries initialization. A `ready.json` marker records completed initialization, so remounting never resets the branch.

Failed or interrupted preparation and creation retain unfinished directories in `staging`, since setup commands may still have running descendants. Errors report the retained path, and `doctor` lists these entries. Stop setup commands and other stallionfs processes, then inspect the directory before removing it. A failed image preparation can leave an attached volume: detach that image normally first. Recursive cleanup refuses directories containing mounted volumes. Staging entries never become cache hits.

Garbage collection skips every protected trash ID, including uncertain protection records. Permanent deletion moves an eligible unprotected trash object into staging first. If deletion fails, its remaining files stay there and the error reports their location. Other trash objects can still be listed, restored or collected.

This protects against ordinary process interruption. It is not a backup or a filesystem-wide crash transaction: a power loss can leave newly written file data incomplete. Keep source code in Git and back up work you need. If a seed is damaged, delete it with `forget` and prepare it again. A damaged workspace should be copied aside and recovered with ordinary Git tools before cleanup.

Folder cloning pins files with open descriptors and uses `fclonefileat`, preserving file metadata and copying directory metadata after populating children. Image cloning uses `clonefile` on a closed sparse image. A failed clone fails the operation; there is no silent full-copy fallback. Symlinks are copied as links and must stay inside the prepared workspace. Writes can still run out of disk space when APFS allocates new blocks.

The prepared image is detached and fully flushed before publication. Each copy mounts with file ownership enabled. Attachment checks use the backing image path, current device and mountpoint; copied volume UUIDs are never used as identity. Managed workspace cleanup retains busy or uncertain attachments and never force-detaches a volume or deletes an attached image.

Folder clones still create metadata for each file. Image clones share the backing file's blocks, including the filesystem metadata, until changed. Each workspace has its own Git repository. `du` and file block counts do not reliably identify unique physical space shared by APFS clones, so performance results do not infer a physical-space percentage from them.

The store assumes one trusted operating-system user. Do not edit internal metadata, replace store directories with links, or modify prepared seeds while creating workspaces. Agents run as that same user and are not isolated from the rest of the account.

Rollback recovery never uses staging. The selected snapshot is cloned into a permanent recovery slot before an intent record stores the current and candidate device/inode pairs. One exchange places the replacement at the working path and the actual old payload in the recovery slot. After any reported exchange failure, including interruption after native success, reconciliation compares both identities. A known before/after pair finalizes the record without swapping again; missing or unexpected identities block further managed mutations. Remount failure leaves both replacement and recovery intact.

Mutable lifecycle and journal finalization use atomic replacement of a complete JSON file. Existing create-only markers still refuse overwriting. These operations provide process-interruption recovery, not a power-loss durability guarantee. Snapshots are immutable through the managed commands; the operating-system user can still modify store files directly.

Cooperative folder sessions persist their opt-in against the current lifecycle generation before command launch. Cleanup apply and the post-run observer can record the first free-lease observation only under the use lease and workspace lock, after checking generation, enrollment, identity, folder backend, and the absence of a pending rollback journal. They never infer closure from PID disappearance. Ordinary reopen replaces the generation and clears the opt-in. A seven-day idle grace reuses the protected retirement path; it adds no permanent deletion path.

Cleanup and idle observation take a shared store lock before each workspace's use lease, reread the policy, and retain the store lock through that item's checks and changes. Disabling cleanup waits for an active item to finish and prevents later items from starting. Opportunistic passes attempt eight valid workspace ID names in lexical order, starting after the saved cursor and wrapping safely when names disappear. Cursor updates take the exclusive store lock after workspace locks are released, preserve the current settings, and apply only if the observed cursor still matches. Explicit preview and apply scan the full collection. Preview neither observes idle state nor advances the cursor; cleanup and idle observation leave pending rollback journals unchanged.
## Native image registrations

Native registrations contain metadata referencing an external backing file.
They are not folder workspaces or APFS sparse-image copies. Their snapshots and
recovery roots remain in the native image's authoritative catalog; no host
snapshot index or whole-file exchange is used. Existing protected cleanup for
folder/APFS workspaces remains separate. Native registrations are ineligible for
cleanup and cannot authorize deletion of external backing data.

Native snapshot, listing and restore hold their managed-use lease, workspace lock, canonical
parent guard and one core backing-inode lock through commit/abort and consumed
close. They recheck registered parent/file device-inode identity and image UUID.
Registration inspects the external image under the core lock before creating its
managed ID and writes only the external-reference metadata.
The current known FSKit loader opens through that same core lock; actual mounted
drain, kernel writeback, cache invalidation and reactivation remain unqualified.
This cooperative storage model does not contain adversarial same-user path
changes or programs writing without the core lock. The immediate parent's ACL
is checked; there is no claim that every ancestor is symlink-free.

Restore uses ordinary ROOT_ONLY integrity checks, preserves retained snapshots
and inode high-water, and adds the prior current as a recovery root in one
unchanged two-fence transaction. It does not certify unread payloads or reclaim
append capacity. Full reachable verification remains a separate operation.
`committed_end` is the selected committed extent; `physical_end` can also include
staged or aborted append data. A successful close is not a commit certificate.

Production restore budgets allow 512 MiB each of metadata reads and hashes and
50 million checks. RAW/auxiliary dimensions are positive but unused. Exhaustion
reports the actual INCOMPLETE reason without automatic enlargement/retry. The
bridge holds the GIL and checks Python signals and a 30-second cooperative
deadline before commit; blocking I/O and the commit itself may outlast it.
Cancellation before publication aborts only the owned transaction. Signals or
response-allocation failure after commit preserve the actual operation and
cleanup receipts and recovery name when a response can be delivered. A pending
signal never replaces known commit state or triggers an automatic rollback.

An unknown final-fence outcome belongs to that invocation. No separate global
uncertainty ledger is created. A later explicit call freshly validates both
slots/current ROOT_ONLY state; healthy reopen is an observation, not retroactive
proof that an earlier fence completed. Malformed pairs refuse normal admission.
Physical power-loss recovery, native lifecycle cleanup, installed mounting and
performance acceptance require separate qualification.


## Installed owned native workspaces

Native creation keeps the prepared folder input and verified image candidate
under the existing typed creation intent. Installation holds the same creation
locks and backing guard while moving only the owned resource directory to
`workspaces/<id>`. It verifies the moved destination with the same guard token.
After consumption, exact inode, UUID and initial committed anchor must match the
FULL-verified import before `native-install.json` records completed ownership.
`native-create.json` remains immutable origin evidence; current installed
location and later anchors are separate. The resource directory must retain its
original inode through the rename; recovery also binds the saved intent object
and installation metadata to that immutable origin.

A rename followed by a proof/close error retains `installed-unconfirmed` plus
the intent. Before any first mount, explicit recovery may use a fresh guard with
the original anchor and lineage to complete installation without repeating import
or rename. It preserves the previous result. Once mounting has been attempted,
that first-install recovery route is closed. Installed ownership blocks external
registration of the backing inode independently of the creation journal.

Mount/unmount intents and helper output remain in each workspace's
`native-operations` directory; the active typed record is also in the existing
journal directory. The lease spans helper launch, stop/reap and observation.
Interruption while a directly owned helper is being launched is recorded until
its handle is retained, then handled under the same lease. A helper that cannot
be reaped leaves a pending hold and stays supervised; no later managed mutator
is admitted. Persisted helper dispositions must contain typed terminal/reaped
evidence; missing or inconsistent fields retain the hold. Prior attempts are
referenced by retained receipt path, and repeated supervision failures keep
counts plus first/last detail rather than an unbounded nested history.
These records describe observed operations, not a live-session
registry or authenticated history of adapter writeback.

The resource-directory descriptor is outside the mount. It checks host/backing
identity while a new mounted-root descriptor supplies `fstatfs` evidence after
mounting. The descriptor observation and native mount table must agree on exact
root, type, owner, flags and filesystem ID. Informational source text is not
interpreted as backing identity. Mounted observation descriptors close before
ordinary unmount. Namespace absence followed by a fresh guard/consumed close
permits a normal later mount, but grants neither prior-close success nor deletion
authority. Owned workspaces stay unenrolled and without `closed_at`; native
snapshot/rollback/retirement/purge support is a later step.

First-mount attempt and successful first-use acceptance are separate durable
facts. Until the initial Git branch/commit and write/fsync/remove probe succeed,
a mount after recovery must repeat those acceptance checks. Successful acceptance
is persisted before a usable repository path is returned. Later ordinary branch
and content changes do not reapply original import expectations.
