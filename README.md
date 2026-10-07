# stallionfs

stallionfs (Stallion File System) provides filesystem tools for macOS: bulk directory scans and ready-to-use workspaces for coding agents.

Scan an ordinary folder without reading every file's contents. For agent workspaces, prepare a repository once, including dependencies, then create independent copies using APFS copy-on-write. Each workspace has its own Git history and branch; unchanged file data shares space on disk.

## Features

- Count files and logical bytes with native bulk metadata reads.
- Reuse installed dependencies across new agent workspaces.
- Create multiple workspaces at once.
- Start from a specific commit, branch or tag.
- Use ordinary Git commands to commit and push changes.
- Remove workspaces to trash and restore them when needed.
- Use the CLI from scripts with JSON output.

## Quick start

You'll need macOS, Python 3.11+, and Xcode Command Line Tools to build from source. Workspaces also require APFS and Git.

```sh
git clone https://github.com/alvinhhh/stallionfs.git
cd stallionfs
python3 -m venv .venv
.venv/bin/pip install .
export PATH="$PWD/.venv/bin:$PATH"

stallionfs scan /path/to/folder
stallionfs --json scan /path/to/folder
```

To create a prepared workspace:

```sh
stallionfs doctor
seed=$(stallionfs prepare /path/to/project --key node22-npm10-v1 -- npm ci)
workspace=$(stallionfs create "$seed" --name fix-parser)
cd "$workspace"
```

Run your agent in the new directory. Commit and push changes as usual:

```sh
git add src/parser.ts
git commit -m "Fix parser"
git push -u origin HEAD
```

Prepare from a clean checkout. The cache key names your toolchain and environment; change it when those change. A new source commit gets a new seed automatically.

## Manage workspaces

```sh
stallionfs list
stallionfs remove WORKSPACE_ID
stallionfs restore WORKSPACE_ID
stallionfs gc                 # Preview trash older than 24 hours
stallionfs gc --yes           # Delete that trash
stallionfs forget SEED_ID --yes
```

Storage defaults to `~/Library/Application Support/stallionfs`. Set `STALLIONFS_HOME` or use `--root` to put it elsewhere on APFS. Deleting a seed leaves existing workspaces intact.

## Performance

Measured on an Apple M2 with 24 GB RAM and macOS 27, using warm caches. Times are medians.

| Operation | Baseline | stallionfs |
| --- | ---: | ---: |
| Scan 20,000 files in one folder | 40.83 ms | 20.57 ms |
| Scan 20,000 files across 200 folders | 42.16 ms | 22.03 ms |
| Create and fully clean up one prepared workspace | 5.28 s | 5.22 s |
| Create and fully clean up four concurrent workspaces | 11.16 s | 11.34 s |

Scan comparisons use equivalent native POSIX traversal, with 11 samples per layout. Workspace comparisons use Git worktrees plus an offline npm install, with seven samples and 12,581 prepared files. One-time seed preparation took 1.97 seconds. Workspace results were roughly tied with the warm-cache baseline. [Measurements and test setup](tests/perf/README.md).

## Development

```sh
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
python3 -m compileall -q stallionfs
python3 -m pip wheel --no-deps --wheel-dir dist .
```

The runtime uses Python's standard library, a small C extension, and native macOS filesystem APIs.

## Documentation

- [Usage and agent integration](docs/usage.md)
- [Storage and recovery](docs/storage.md)
- [Security](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## License

[MIT](LICENSE).
