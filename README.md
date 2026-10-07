# stallionfs
**because stallions eat Apples**

stallionfs provides native file operations and prepared Git workspaces on macOS.

[Usage](docs/usage.md) · [Storage and recovery](docs/storage.md) · [Issues](https://github.com/alvinhhh/stallionfs/issues)

## Highlights

- Clone files and folders with APFS copy-on-write.
- Move, swap and delete paths, or list mounted volumes.
- Install dependencies once and reuse them across workspaces.
- Clone a whole APFS workspace volume without copying every file.
- Count files and sizes with native bulk metadata reads.

APFS copy-on-write shares unchanged data on disk. Each workspace has its own Git repository and branch; edits in one don't affect the others.

## Usage

```sh
stallionfs clone project project-copy
stallionfs move project-copy old-project
stallionfs delete --recursive old-project
stallionfs volumes
```

Destinations are exact paths. Clones and moves refuse to overwrite existing files; `move --replace` and `move --exchange` are explicit alternatives. Use `--jobs 1` with cloning, deletion or scanning for lower CPU use. See [file operations](docs/usage.md#file-operations) for options and supported filesystems.

Prepare a clean checkout, then start working in a copy:

```sh
seed=$(stallionfs prepare /path/to/project --key node22-npm10-v1 --image-size 8 -- npm ci)
workspace=$(stallionfs create "$seed" --name fix-parser)
cd "$workspace"
```

The command after `--` runs once during preparation. Change `--key` when you change the toolchain or setup environment. A new source commit gets a new seed automatically.

`--image-size 8` creates workspaces as separate 8 GiB APFS volumes and requires macOS 26+. Omit it to use ordinary folders. See [disk-image workspaces](docs/usage.md#disk-image-workspaces) for capacity and mounting details.

To count files and their total logical size:

```sh
stallionfs scan /path/to/folder
stallionfs --json scan /path/to/folder
```

The scanner counts symlinks without following them and skips nested volumes.

Leave the workspace and stop processes using it before removal. To remove, restore, or clear old trash:

```sh
stallionfs list
stallionfs remove WORKSPACE_ID
stallionfs restore WORKSPACE_ID
stallionfs gc                 # Preview trash older than 24 hours
stallionfs gc --yes           # Delete that trash
```

Files are stored in `~/Library/Application Support/stallionfs`. Set `STALLIONFS_HOME` or pass `--root` to use another location. Use `--json` before the command name for structured output.

## Installation

Requires macOS, Python 3.11+ and Xcode Command Line Tools. Workspace storage must be on APFS. Install from source:

```sh
git clone https://github.com/alvinhhh/stallionfs.git
cd stallionfs
python3 -m venv .venv
.venv/bin/pip install .
source .venv/bin/activate
```

## Performance

0.6.1 · Apple M2 · 24 GiB RAM · macOS 27. Median elapsed times.

| Operation | Baseline | stallionfs | Speedup |
| --- | ---: | ---: | ---: |
| Scan 20,000 files across 200 folders | 35.42 ms | 7.51 ms | 4.72× |
| Scan 20,000 files in one folder | 32.56 ms | 16.18 ms | 2.01× |
| Clone 10,000 files in nested folders | 1.136 s | 0.423 s | 2.69× |
| Delete those 10,000 files | 0.391 s | 0.178 s | 2.19× |
| Create and reclaim one folder workspace | 2.014 s | 0.963 s | 2.09× |
| Create and reclaim four concurrent workspaces | 5.527 s | 3.642 s | 1.52× |
| Clone 100,000 JavaScript files | 12.411 s | 4.373 s | 2.84× |
| Delete 100,000 JavaScript files | 4.042 s | 1.800 s | 2.25× |
| Clone a Git repository (50,013 files) | 6.069 s | 2.188 s | 2.77× |
| Delete a Git repository (50,013 files) | 2.089 s | 0.948 s | 2.20× |
| Clone a build cache (200,000 files, 10 GB) | 24.995 s | 8.754 s | 2.86× |
| Delete a build cache (200,000 files, 10 GB) | 8.210 s | 4.146 s | 1.98× |
| Clone 5,000 HTML and asset files | 0.604 s | 0.235 s | 2.57× |
| Delete 5,000 HTML and asset files | 0.199 s | 0.100 s | 1.99× |
| Clone a dataset (2,000 files, 50 GB) | 0.241 s | 0.091 s | 2.64× |
| Delete a dataset (2,000 files, 50 GB) | 0.196 s | 0.140 s | 1.39× |
| Scan 20,000 files along a 40-folder chain | 29.62 ms | 12.97 ms | 2.28× |

Baselines: native POSIX scanning, `cp -cRp`, `rm -rf`, and Git worktrees + offline `npm ci`. File trees are generated; workspace times include cleanup and exclude seed preparation. [Full results, CPU and memory](tests/perf/README.md).

## Contributing

[Open an issue](https://github.com/alvinhhh/stallionfs/issues) for bugs or feature requests. See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions and tests, or [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE). Maintained by [@alvinhhh](https://github.com/alvinhhh).
