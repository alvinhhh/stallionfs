# Storage and recovery

The private storage directory has mode `0700` and contains:

| Directory | Contents |
| --- | --- |
| `seeds/<id>/repo` | Prepared Git repositories; do not edit these directly |
| `workspaces/<id>/repo` | Working copies for agents |
| `trash/<id>/repo` | Removed workspaces, available to restore |
| `<collection>/<id>/workspace.sparseimage` | APFS image for a seed or image workspace |
| `workspaces/<id>/volume/repo` | Repository inside a mounted image workspace |
| `staging` | Unpublished work during preparation or creation |
| `locks` | Advisory per-object locks |

Preparation and seed deletion take an exclusive lock on that seed. Creates take a shared lock, so independent clones can run concurrently. Workspace moves and deletion take a per-workspace lock. There is no background process.

Preparation and folder creation publish by renaming a completed staging directory. Image creation publishes the closed image and metadata before mounting at its final path. If mounting or branch creation fails, the workspace is retained; `stallionfs mount ID` retries initialization. A `ready.json` marker records completed initialization, so remounting never resets the branch.

A process killed without cleanup may leave a directory in `staging`; `doctor` lists these entries. Stop other stallionfs processes and inspect the directory before removing it. A failed image preparation can leave an attached volume: detach that image normally first. Recursive cleanup refuses directories containing mounted volumes. Staging entries never become cache hits.

This protects against ordinary process interruption. It is not a backup or a filesystem-wide crash transaction: a power loss can leave newly written file data incomplete. Keep source code in Git and back up work you need. If a seed is damaged, delete it with `forget` and prepare it again. A damaged workspace should be copied aside and recovered with ordinary Git tools before cleanup.

Folder cloning uses descriptor-relative `clonefileat` calls, preserving file metadata and copying directory metadata after populating children. Image cloning uses `clonefile` on a closed sparse image. A failed clone fails the operation; there is no silent full-copy fallback. Symlinks are copied as links and must stay inside the prepared workspace. Writes can still run out of disk space when APFS allocates new blocks.

The prepared image is detached and fully flushed before publication. Each copy mounts with file ownership enabled. Attachment checks use the backing image path, current device and mountpoint; copied volume UUIDs are never used as identity. A busy or uncertain attachment is retained. No operation force-detaches a volume or deletes an attached image.

Folder clones still create metadata for each file. Image clones share the backing file's blocks, including the filesystem metadata, until changed. Each workspace has its own Git repository. `du` and file block counts do not reliably identify unique physical space shared by APFS clones, so performance results do not infer a physical-space percentage from them.

The store assumes one trusted operating-system user. Do not edit internal metadata, replace store directories with links, or modify prepared seeds while creating workspaces. Agents run as that same user and are not isolated from the rest of the account.
