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
