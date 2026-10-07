# Usage

## Prepare a seed

```sh
stallionfs prepare /path/to/project --key node22-npm10-v1 -- npm ci
stallionfs prepare /path/to/project --ref release-branch --key node22-pnpm10-v1 -- pnpm install --frozen-lockfile
stallionfs prepare /path/to/project --key source-only-v1
```

The source must be a clean Git checkout. Ignored local files such as `.env` and `node_modules` are not copied from it. Preparation clones the selected commit, runs the command after `--`, and saves the result. That command runs with your permissions and environment; use it only on code you trust. No repository-defined stallionfs hooks are run automatically.

The seed ID includes the source path, exact commit, origin, command arguments, cache key, macOS release and CPU architecture. Change `--key` when changing Node, npm, Python, compiler versions, relevant environment variables, registry configuration, or other external inputs. Environment variables are not inspected or hashed. A lockfile change is a source change and needs a commit.

Setup must leave tracked files and HEAD unchanged and must exit after its child processes finish. Use relocatable dependencies: ordinary npm and pnpm layouts work; Python virtual environments and build outputs with embedded absolute paths usually need a fresh setup per workspace. Absolute or escaping symlinks, submodules, nested repositories, special files and shared Git object stores are rejected.

Git hooks from the source are not copied. Global Git filters and explicitly requested package lifecycle scripts can still execute as part of preparation. Configure authentication with your usual Git credential helper rather than a token embedded in the origin URL.

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

For source-only repositories, ordinary Git worktrees may be faster and smaller. stallionfs is most useful when many agents start at the same commit with expensive dependency or build preparation. It does not change APFS's general file-write, search or deletion speed.

## Remove and restore

Stop processes using a workspace before moving or deleting it. `remove` moves the entire workspace to trash, including uncommitted and ignored files. `restore` moves it back. Neither checks whether changes were pushed because removal is reversible.

`gc` previews trash older than 24 hours. `gc --yes` permanently deletes eligible trash; `--older-than 0` includes all trash. Save or push any work you need first. Cleanup does the actual recursive deletion and can take time.

`forget SEED_ID` previews removal of a seed. Add `--yes` to delete it. Existing workspaces remain usable. Prepare again to rebuild the cache.
