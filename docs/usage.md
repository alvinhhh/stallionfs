# Usage

## File operations

```sh
sfs copy source destination
sfs copy source destination --strategy auto
sfs clone source destination
sfs clone source destination --jobs 1
sfs move source destination
sfs move source destination --replace
sfs move first second --exchange
sfs delete file
sfs delete --recursive folder
sfs delete --missing-ok file
sfs volumes
```

`copy` copies file data and metadata to an exact new path. The default, `--strategy materialized`, copies file data without requesting APFS cloning. It requires macOS 13 or later. Regular files, directories and symlinks are supported; symlink targets are not followed. Internal regular-file and symlink hardlinks share new destination inodes, independent of the source. Existing destinations, special files, nested source volumes and destinations inside the source are rejected.

`--strategy auto` attempts data-fork cloning for eligible regular files inside the new private destination tree, then verifies ordinary-copy metadata. When only the group differs, it verifies every other field before applying metadata and checking the complete result again. Eligible files must belong to the current user, have owner read/write permission, no setuid/setgid bits, zero file flags and an empty extended ACL. Single-file operands, symlinks and other regular files use materialized copying. Only unsupported-clone and cross-volume errors permit fallback, and only when the destination entry is still absent. Other errors, including failures after a successful clone, retain any partial output and fail. Both strategies use the same copy preservation requirements. Cloned data may share physical blocks; resource forks are always verified and are copied again only when metadata application is required.

Copying can cross volumes when the destination supports the required mode, ownership, modification time, flags, ACLs, extended attributes (including resource forks) and sparse hole ranges. Unsupported or unpreserved properties fail explicitly. Access, change and birth times and allocated-block counts are not equality requirements. The operation checks source stability but does not provide an atomic snapshot; keep both trees stable during copying.

On failure, any partial output remains at the exact destination you requested, even if the error identifies a child path. Inspect that destination before retrying. Workers are joined and descriptors released before returning; cancellation may wait for an in-progress platform operation.

`clone` creates an independent copy at an exact new path on the same APFS volume. It accepts regular files, directories and symlinks, preserves permissions, ACLs, extended attributes and timestamps, and never falls back to copying file data. Hardlink relationships between regular files or symlinks inside a copied tree are preserved. Destination aliases share one new inode with each other, never with the source or its external aliases. Changing one destination alias changes its other destination aliases without changing the source. macOS applies its normal clone ownership rules, clears setuid/setgid bits on regular files, and adds inherited destination ACL entries to cloned files. A destination inside the source is rejected.

Directory copying uses up to four workers. Files are pinned before cloning, links are copied without following their targets, and nested volumes and special files are rejected. Keep the source and destination trees stable during the operation; a recursive copy is not an atomic snapshot of concurrent changes. An error may leave a partial new destination. All workers stop before the command returns.

Copies and directory clones require a destination parent owned by the current user or root. Non-sticky parents writable by other users, and ACLs granting other users permission to change directory entries or permissions, are rejected. The new directory stays private while its children are copied; its final metadata is applied last. Destination name and descriptor checks rely on both trees remaining stable; they cannot prove which inode was cloned if the same user replaces a leaf before its first post-clone lookup.

Ordinary copies of a single file or symlink also reject destination parents that grant inheritable file access to other users, before creating any output.

`move` uses the filesystem's atomic rename operation. It treats the destination as an exact path, including when that path names a directory. The default refuses an existing destination. `--replace` replaces it; `--exchange` swaps two existing paths. Cross-volume moves fail without copying or deleting the source.

`delete` removes files and symlinks. Directories require `--recursive`; mounted volumes and directories containing mounts are refused. Deletion is permanent and finishes before the command returns. It can stop after partial deletion if an entry cannot be removed. `--missing-ok` accepts an absent final entry, while other errors still fail.

`--jobs` accepts 1–4 for `copy`, `clone`, `delete` and `scan`. Four prioritizes elapsed time; one reduces CPU use. Folder workspace `create` and trash `gc` accept the same option. Garbage collection shares the worker limit across directories.

File operations, scans and volume listings run in the native executable, including with `--json`. `volumes` lists cached mount records; it does not inspect partition maps, repair disks or change volume settings.

Successful `copy --strategy auto` JSON includes `"strategy": "auto"` alongside `source` and `destination`. Default and explicit materialized-copy JSON contain only `source` and `destination`. `--strategy=auto` and `--strategy=materialized` are also accepted; `clone` does not accept a strategy option.

The same operations are available to Python applications:

```python
from stallionfs import clone, copy, delete, mounts, move, scan

copy("source", "destination", jobs=4)
copy("another-source", "another-destination", jobs=4, strategy="auto")
move("destination", "renamed")
delete("renamed", recursive=True, jobs=1)
print(mounts())
```

## Scan a folder

```sh
sfs scan /path/to/folder
sfs --json scan /path/to/folder
sfs scan --jobs 1 /path/to/folder
```

`scan` uses `getattrlistbulk` to count regular files, subdirectories, symlinks, other entries, and regular-file logical bytes. It reads metadata, leaves files unchanged, and does not create a workspace store. Symlinks inside the tree are not followed. Nested volumes are skipped and counted in `skipped_mounts`.

Nested directories can be scanned concurrently. Flat folders use a sequential path; `--jobs 1` keeps all scanning sequential for lower CPU use.

Logical bytes describe file lengths, not allocated disk space. Hard links count once per directory entry; sparse files count their full logical length. Permission errors, disappearing directories, unsupported metadata operations, and traversal deeper than 511 subdirectories stop the scan with an error instead of printing incomplete totals. A live scan is not an atomic snapshot of a changing tree.

This accelerates the scan command. Other applications continue using their own filesystem APIs.

## Prepare a seed

```sh
sfs prepare /path/to/project --key node22-npm10-v1 -- npm ci
sfs prepare /path/to/project --ref release-branch --key node22-pnpm10-v1 -- pnpm install --frozen-lockfile
sfs prepare /path/to/project --key source-only-v1
```

The source must be a clean Git checkout. Ignored local files such as `.env` and `node_modules` are not copied from it. Preparation clones the selected commit, runs the command after `--`, and saves the result. That command runs with your permissions and environment; use it only on code you trust.

The seed ID includes the source path, exact commit, origin, command arguments, cache key, macOS release and CPU architecture. Change `--key` when changing Node, npm, Python, compiler versions, relevant environment variables, registry configuration, or other external inputs. Environment variables are not inspected or hashed. A lockfile change is a source change and needs a commit.

Setup must leave tracked files and HEAD unchanged and must exit after its child processes finish. Dependencies must use relocatable paths. Python virtual environments and build outputs with embedded absolute paths usually need a fresh setup per workspace. Absolute or escaping symlinks, submodules, nested repositories, special files and shared Git object stores are rejected.

Git hooks from the source are not copied. Global Git filters and explicitly requested package lifecycle scripts can still execute as part of preparation. Configure authentication with your usual Git credential helper rather than a token embedded in the origin URL.

### Disk-image workspaces

For large dependency trees, prepare an APFS image:

```sh
seed=$(sfs prepare /path/to/project --key node22-npm10-v1 --image-size 8 -- npm ci)
workspace=$(sfs create "$seed")
cd "$workspace"
```

`--image-size` sets each workspace's capacity in GiB. The image grows as blocks are used, up to that limit. Creation clones the closed image and mounts a separate APFS volume for the workspace. Editors, shells and Git use the returned path normally.

These volumes have Spotlight indexing disabled. File permissions and ownership remain enabled.

Images require macOS 26 or later. After restarting the Mac, run `sfs mount WORKSPACE_ID` to mount a workspace again. `sfs unmount WORKSPACE_ID` releases its mount without moving it to trash. Stop processes using the volume before unmounting; stallionfs never forces an unmount.

Image creation and file I/O are separate workloads. Use the [I/O comparison](../tests/perf/README.md#file-io-inside-a-workspace) to measure your workload before choosing images over folders.

Preparing the image takes longer than preparing an ordinary folder. Small source-only repositories may be better served by folder workspaces or Git worktrees. Each mounted image also consumes a disk device; unmount workspaces when they are idle.

## Start an agent

```sh
workspace=$(sfs create "$seed" --name parser)
cd "$workspace"
codex
# or run claude, opencode, your editor, or a shell here
```

Use `--json` before the command for automation:

```sh
sfs --json create "$seed" --name parser
```

The result contains `id`, `path`, `branch`, `seed`, `commit` and `created`. The branch is `stallionfs/<name>-<unique-id>`. Stdout contains the result; preparation output and errors go to stderr. Normal errors exit 1, argument errors 2, and interrupted operations 130.

Each workspace is a standalone repository, so it is not listed by `git worktree list` in the source. Push its branch, or import a local commit with `git fetch /path/to/workspace branch-name` and cherry-pick it in your main checkout. Workspaces share no Git index or writable Git object files.

stallionfs is most useful when many agents start at the same commit with expensive dependency or build preparation. Other applications continue to use their own filesystem APIs.

## Remove and restore

Stop processes using a workspace before moving or deleting it. `remove` moves the entire workspace to trash, including uncommitted and ignored files. It unmounts image workspaces first. `restore` moves the workspace back and remounts it if needed. Neither checks whether changes were pushed because removal is reversible.

`gc` previews trash older than 24 hours. `gc --yes` permanently deletes eligible trash; `--older-than 0` includes all trash. Save or push any work you need first.

`forget SEED_ID` previews removal of a seed. Add `--yes` to delete it. Existing workspaces remain usable. Prepare again to rebuild the cache.

## Snapshots and rollback

```sh
sfs snapshot WORKSPACE_ID --quiescent --name before-change
sfs snapshots WORKSPACE_ID
sfs rollback WORKSPACE_ID SNAPSHOT_ID --quiescent
sfs retained
```

Stop all writers before using `--quiescent`. Folder snapshots capture the complete repository, including HEAD, branch, index, staged and unstaged changes, untracked and ignored files, supported metadata, and internal hardlinks. They use the same clone rules described above. Capture is not atomic while external programs are writing. The managed-use lease coordinates stallionfs commands; it cannot detect or stop unrelated writers. Linked worktrees, shared/external Git storage, Git configuration includes, and active Git locks are rejected; external Git files are not captured.

Image snapshots check standalone Git metadata, normally detach and flush the owned image, clone it while closed, publish the snapshot, then remount if it was attached. An initially closed image is briefly mounted for the Git check and left closed afterward. Busy or uncertain attachments fail without force-detaching. Image snapshot and rollback do not require `--quiescent`, but all volume users must release it for normal detachment to succeed. A failure after detachment can leave the workspace unmounted; use `sfs mount WORKSPACE_ID` after resolving the error.

Rollback clones the selected snapshot into a permanent recovery directory and atomically exchanges it with the current repository or backing image. The actual previous workspace remains in `recovery/RECOVERY_ID`; the selected snapshot stays unchanged. The command returns the recovery ID. An interrupted exchange is reconciled from recorded file identities before another managed mutation. Uncertain identities block mutation and retain both paths for inspection.

## Managed use and cleanup

```sh
sfs run WORKSPACE_ID -- codex
sfs enroll WORKSPACE_ID
# After all commands, descendants, editors, and shells have stopped using it:
sfs close WORKSPACE_ID --quiescent
sfs cleanup --enable
sfs cleanup
sfs cleanup --apply
sfs cleanup --disable
```

Cleanup is off by default. Both global enablement and workspace enrollment are required. `enroll --disable WORKSPACE_ID` removes enrollment. `run` holds an exclusive managed-use lease and records the workspace as open before starting the command. For ordinary `run`, command exit, a dead process, or a released lease never means closed. Only explicit `close --quiescent` records closure. It also normally detaches and flushes image workspaces. Running commands does not contain their descendants or restrict filesystem access.

Enabled cleanup retires eligible workspaces seven days after explicit closure or the first reliable idle observation of an opted-in cooperative session. It skips ordinary open, legacy, unknown, busy, mounted, corrupt, or identity-changed workspaces and invalid or future timestamps. Explicit preview and apply inspect the full workspace collection. Managed CLI mutations also attempt a nonblocking pass over at most eight workspace IDs after completing the requested operation. A saved lexical cursor advances over busy and ineligible IDs too, so later workspaces are visited on subsequent passes. Ordinary file operations never run cleanup. This is opportunistic maintenance; there is no scheduled service. Preview does not record idle observations, reconcile pending rollbacks, or advance the cursor. Apply also skips pending rollback journals until an explicit workspace operation resolves them.

### Cooperative session retirement

```sh
sfs cleanup --enable
sfs enroll WORKSPACE_ID
sfs run --auto-retire WORKSPACE_ID -- COMMAND ARGUMENTS
```

`--auto-retire` must appear before the workspace ID. It supports folder workspaces only and requires enabled cleanup and valid enrollment before launch. Images continue to require explicit `close --quiescent`.

Use this option only with cooperating commands. The command receives `STALLIONFS_LEASE_FD`, an inherited open descriptor holding the workspace lease, and `STALLIONFS_LEASE_GENERATION`, the session generation. Every process that may continue writing independently must keep that descriptor open and pass it to its own writers until they finish. For Python subprocesses, explicitly include it in `pass_fds`. A waiting ancestor holding the descriptor does not protect a child after that ancestor dies. Never call `flock(..., LOCK_UN)` on the shared descriptor; close it when finished. This option does not contain processes or detect unmanaged writers.

The wrapper closes its own descriptor without unlocking descendants' copies. After the wrapper exits, a targeted check records `idle_since` only if the exact enrolled generation's lease is free and its identity still matches. A surviving holder keeps it busy. If the wrapper crashes, a later cleanup apply can make that first observation. The seven-day grace starts at this observation, not process death, creation, or command exit. Later checks preserve a valid idle timestamp. Preview never starts the grace period.

An ordinary reopen, restore, or new session clears the old session's opt-in. Disabled cleanup, a changed generation, malformed state, future timestamps, or pending rollback keeps the workspace ineligible. This allows forgotten cooperative sessions to be retired while preserving the explicit-close rule for other workspaces.

Retirement moves the whole workspace into protected trash. It does not permanently delete data or free the retained blocks. `gc --yes`, including `--older-than 0`, skips protected trash. Restore with `sfs restore WORKSPACE_ID`; restoration marks it open so it cannot immediately be retired again. An interrupted retirement before the move leaves the workspace in place with protection; explicitly reopening it with `run`, `mount`, or `enroll` cancels a verified source-only retirement intent.

Snapshots, rollback recovery, and protected retirement share a limit of 32 retained objects, including incomplete objects. The limit stops new retention; it never evicts existing data. There is no logical-size quota. APFS clones can still run out of disk space as files change.

```sh
sfs purge snapshots SNAPSHOT_ID
sfs purge recovery RECOVERY_ID
sfs purge trash WORKSPACE_ID
# Add --yes to permanently delete the listed retained data.
```

`purge` is deliberate permanent deletion. Inspect the data first. Interrupted deletion retains its remainder in staging and reports that path, keeping usable snapshot listings clear of partial entries. Pending rollback journals and mounted images prevent purging. Keep any previous rollback repository you need by copying `recovery/RECOVERY_ID/repo` to a new path before purging its slot; image recovery remains a closed `workspace.sparseimage` backing file.
## Owned native workspaces

Native workspaces require a qualified, signed StallionFS package enabled in
File System Extensions settings. The production filesystem type is `stallionfs`.
The current controller requires macOS 27 and a writable package; packaging,
discovery and offline tests alone do not qualify an installed release. See
[FSKit packaging](fskit-package.md) for the remaining distribution and mounted
validation requirements.

Prepare an ordinary folder seed, then create an independent native image:

```sh
seed=$(sfs prepare /path/to/project --key dependencies-v1 -- npm ci)
sfs --json create "$seed" --backend native-image --capacity-gib 8 --name parser
sfs run WORKSPACE_ID -- python3 -c 'from pathlib import Path; Path("result").write_text("saved")'
sfs unmount WORKSPACE_ID
sfs mount WORKSPACE_ID
```

Successful creation prints the mounted `volume/repo` path, containing the
prepared commit, dependencies and a new workspace branch. Each image has a fresh
UUID. Creation verifies the imported image, installs only its owned resource
directory, completes its ownership proof, then mounts and checks the writable
repository path. Capacity is required in GiB; APFS-image seeds are not accepted.
Ordinary folder creation remains the default.

`run` holds the managed-use lease while the command executes. Stop shells,
editors and other users before `unmount`; unmount never forces a busy volume.
After successful ordinary unmount, the controller requires namespace absence
and a fresh exact-image guard with successful consumed close. Later mounts allow
legitimate content and Git changes; they do not reset the original branch or
require the creation anchor to remain current.

On failure, use `--json` and retain the reported workspace, journal and operation
files. A completed install survives mount failure. If the target is absent,
`mount ID` can try a new operation after the previous helper is reaped. If a
matching mount exists but completion is unresolved, explicitly `unmount ID`
before mounting again. An unresolved executing helper blocks new managed
mutators; keep its controller supervising it. Timeout/interruption never means
that the OS rolled the operation back. Installation recovery before first mount
uses a new guard of the retained image; it does not repeat import or rename.

The controller uses ordinary macOS type dispatch and current mount observations.
These do not authenticate an exact live adapter session or prove a previous
adapter close succeeded. A fresh guard validates only its own current admission
and consumed close. Owned snapshots, rollback, cleanup enrollment, retirement,
removal and purge remain unsupported. An unmounted owned image stays protected
and receives no cleanup closure credit.

`--native-host PATH` selects the containing app's `Contents/MacOS/StallionFS`
discovery executable. `--native-profile private-sfsro27` is reserved for explicit
private qualification with that short type; it is not the production default.
Neither option installs, registers, enables or signs an extension.

## Closed native images

Register an existing native image without moving or copying its backing file:

```sh
workspace=$(sfs register-native-image /private/owned/image.sfs --name work)
sfs snapshot "$workspace" --name before-edit
sfs snapshots "$workspace"
sfs rollback "$workspace" before-edit
```

Native snapshot IDs are their names. Rollback retains the previous current
namespace under the returned recovery name, in the same durable commit. Listing
shows both ordinary and recovery snapshots. Names use filesystem bytes without
normalization and must be one component of 1–255 bytes. The catalog holds at
most 32 snapshots; full catalogs fail without evicting an existing root.

These commands operate on closed images. The managed lease and ordinary core
exclusive inode lock reject cooperating active users, including the current
FSKit loader while it retains its core handle. They do not detect arbitrary
noncooperating writers or qualify mounted kernel caching. Mount/run for external registrations, cleanup enrollment, retirement and
removal are unsupported by these commands.
Registering an external file grants no authority to delete it.

The immediate parent must be private, owned and local writable APFS. Registration
resolves parent aliases once and records the actual parent/file identities and
image UUID; the final image must not be a symlink. Replacing or moving a recorded
parent/backing inode requires explicit re-registration. Intermediate ancestors
are not claimed to be locked or symlink-free.

Use `--json` for operation, staging, abort and consumed-close receipts. A failed
command can report a committed change or unknown publication; it does not imply
rollback. Preserve its recovery name and inspect the image before repeating the
operation. Later explicitly requested calls use fresh ordinary validation;
malformed slot pairs require explicit recovery rather than automatic repair.

