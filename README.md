# stallionfs

stallionfs (Stallion File System) creates ready-to-use workspaces for coding agents on macOS. Prepare a repository once, including its dependencies, then create independent copies using APFS copy-on-write.

Each workspace has its own files, Git history and branch. Edits stay in that workspace, and unchanged file data shares space on disk.

## Features

- Reuse installed dependencies across new agent workspaces.
- Create multiple workspaces at once.
- Start from a specific commit, branch or tag.
- Use ordinary Git commands to commit and push changes.
- Remove workspaces to trash and restore them when needed.
- Use the CLI from scripts with JSON output.

## Quick start

You'll need macOS on APFS, Python 3.11+ and Git.

```sh
git clone https://github.com/alvinhhh/stallionfs.git
cd stallionfs
python3 -m venv .venv
.venv/bin/pip install .
export PATH="$PWD/.venv/bin:$PATH"

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

## Development

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q stallionfs
python3 -m pip wheel --no-deps --wheel-dir dist .
```

The runtime uses Python's standard library and the native macOS file-cloning API.

## Documentation

- [Usage and agent integration](docs/usage.md)
- [Storage and recovery](docs/storage.md)
- [Security](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## License

[MIT](LICENSE).
