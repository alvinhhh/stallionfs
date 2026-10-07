# Storage and recovery

The private storage directory has mode `0700` and contains:

| Directory | Contents |
| --- | --- |
| `seeds/<id>/repo` | Prepared Git repositories; do not edit these directly |
| `workspaces/<id>/repo` | Working copies for agents |
| `trash/<id>/repo` | Removed workspaces, available to restore |
| `staging` | Unpublished work during preparation or creation |
| `locks` | Advisory per-object locks |

Preparation and seed deletion take an exclusive lock on that seed. Creates take a shared lock, so independent clones can run concurrently. Workspace moves and deletion take a per-workspace lock. There is no background process.

Preparation and creation publish by renaming a completed staging directory. A failed operation cannot appear as a completed workspace. A process killed without cleanup may leave a directory in `staging`; `doctor` lists these entries. Once all stallionfs processes have stopped, inspect those directories and remove the abandoned ones. They never become cache hits.

This protects against ordinary process interruption. It is not a backup or a filesystem-wide crash transaction: a power loss can leave newly written file data incomplete. Keep source code in Git and back up work you need. If a seed is damaged, delete it with `forget` and prepare it again. A damaged workspace should be copied aside and recovered with ordinary Git tools before cleanup.

Cloning uses `clonefile` for every regular file. A failed clone fails the operation; there is no silent full-copy fallback. Symlinks are copied as links and must stay inside the workspace. Writes to a clone can still run out of disk space when APFS allocates new blocks.

Copy-on-write shares file data, not all metadata. Time and metadata use still grow with the number of files. Each seed keeps an independent Git object database, and each workspace has its own cloned Git directory. `du` and file block counts do not reliably identify unique physical space shared by APFS clones, so performance results report logical size without claiming a physical-space percentage.

The store assumes one trusted operating-system user. Do not edit internal metadata, replace store directories with links, or modify prepared seeds while creating workspaces. Agents run as that same user and are not isolated from the rest of the account.
