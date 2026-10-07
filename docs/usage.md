# Usage

## Scan a folder

```sh
stallionfs scan /path/to/folder
stallionfs --json scan /path/to/folder
```

`scan` uses `getattrlistbulk` to count regular files, subdirectories, symlinks, other entries, and regular-file logical bytes. It reads metadata, leaves files unchanged, and does not create a workspace store. Symlinks inside the tree are not followed. Nested volumes are skipped and counted in `skipped_mounts`.

Logical bytes describe file lengths, not allocated disk space. Hard links count once per directory entry; sparse files count their full logical length. Permission errors, disappearing directories, unsupported metadata operations, and traversal deeper than 511 subdirectories stop the scan with an error instead of printing incomplete totals. A live scan is not an atomic snapshot of a changing tree.

This accelerates the scan command. Other applications continue using their own filesystem APIs.

## Prepare a seed

```sh
stallionfs prepare /path/to/project --key node22-npm10-v1 -- npm ci
stallionfs prepare /path/to/project --ref release-branch --key node22-pnpm10-v1 -- pnpm install --frozen-lockfile
stallionfs prepare /path/to/project --key source-only-v1
```

The source must be a clean Git checkout. Ignored local files such as `.env` and `node_modules` are not copied from it. Preparation clones the selected commit, runs the command after `--`, and saves the result. That command runs with your permissions and environment; use it only on code you trust.

The seed ID includes the source path, exact commit, origin, command arguments, cache key, macOS release and CPU architecture. Change `--key` when changing Node, npm, Python, compiler versions, relevant environment variables, registry configuration, or other external inputs. Environment variables are not inspected or hashed. A lockfile change is a source change and needs a commit.

Setup must leave tracked files and HEAD unchanged and must exit after its child processes finish. Dependencies must use relocatable paths. Python virtual environments and build outputs with embedded absolute paths usually need a fresh setup per workspace. Absolute or escaping symlinks, submodules, nested repositories, special files and shared Git object stores are rejected.

Git hooks from the source are not copied. Global Git filters and explicitly requested package lifecycle scripts can still execute as part of preparation. Configure authentication with your usual Git credential helper rather than a token embedded in the origin URL.

### Disk-image workspaces

For large dependency trees, prepare an APFS image:

```sh
seed=$(stallionfs prepare /path/to/project --key node22-npm10-v1 --image-size 8 -- npm ci)
workspace=$(stallionfs create "$seed")
cd "$workspace"
```

`--image-size` sets each workspace's capacity in GiB. The image grows as blocks are used, up to that limit. Creation clones the closed image and mounts a separate APFS volume for the workspace. Editors, shells and Git use the returned path normally.

These volumes have Spotlight indexing disabled. File permissions and ownership remain enabled.

Images require macOS 26 or later. After restarting the Mac, run `stallionfs mount WORKSPACE_ID` to mount a workspace again. `stallionfs unmount WORKSPACE_ID` releases its mount without moving it to trash. Stop processes using the volume before unmounting; stallionfs never forces an unmount.

Images speed up repeated workspace creation, but add overhead to file writes. The [I/O comparison](../tests/perf/README.md#file-io-inside-a-workspace) measured slower durable writes and concurrent file operations inside images. Prefer folder workspaces for work that writes heavily.

Preparing the image takes longer than preparing an ordinary folder. Small source-only repositories may be better served by folder workspaces or Git worktrees. Each mounted image also consumes a disk device; unmount workspaces when they are idle.

## Start an agent

```sh
workspace=$(stallionfs create "$seed" --name parser)
cd "$workspace"
codex
# or run claude, opencode, your editor, or a shell here
```

Use `--json` before the command for automation:

```sh
stallionfs --json create "$seed" --name parser
```

The result contains `id`, `path`, `branch`, `seed`, `commit` and `created`. The branch is `stallionfs/<name>-<unique-id>`. Stdout contains the result; preparation output and errors go to stderr. Normal errors exit 1, argument errors 2, and interrupted operations 130.

Each workspace is a standalone repository, so it is not listed by `git worktree list` in the source. Push its branch, or import a local commit with `git fetch /path/to/workspace branch-name` and cherry-pick it in your main checkout. Workspaces share no Git index or writable Git object files.

stallionfs is most useful when many agents start at the same commit with expensive dependency or build preparation. It does not change APFS's general file-write, search or deletion speed.

## Remove and restore

Stop processes using a workspace before moving or deleting it. `remove` moves the entire workspace to trash, including uncommitted and ignored files. It unmounts image workspaces first. `restore` moves the workspace back and remounts it if needed. Neither checks whether changes were pushed because removal is reversible.

`gc` previews trash older than 24 hours. `gc --yes` permanently deletes eligible trash; `--older-than 0` includes all trash. Save or push any work you need first.

`forget SEED_ID` previews removal of a seed. Add `--yes` to delete it. Existing workspaces remain usable. Prepare again to rebuild the cache.
