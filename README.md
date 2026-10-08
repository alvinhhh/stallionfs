# stallionfs
**because stallions eat Apples**

**STILL IN DEVELOPMENT! DO NOT USE IN A PRODUCTION ENVIRONMENT!**
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

0.6.3 · Apple M2 · 24 GiB RAM · macOS 27. Median elapsed times.

| Operation | Baseline | stallionfs | Speedup |
| --- | ---: | ---: | ---: |
| Clone a 4 KiB file | 2.333 ms | 3.323 ms | 0.70× |
| Move a 4 KiB file | 2.580 ms | 3.160 ms | 0.82× |
| Delete a 4 KiB file | 2.848 ms | 3.179 ms | 0.90× |
| Scan 20,000 files across 200 folders | 35.64 ms | 6.79 ms | 5.25× |
| Scan 20,000 files in one folder | 34.84 ms | 18.06 ms | 1.93× |
| Clone 10,000 files in nested folders | 1.229 s | 0.495 s | 2.48× |
| Delete those 10,000 files | 0.398 s | 0.220 s | 1.81× |
| Create and reclaim one folder workspace | 9.211 s | 5.340 s | 1.72× |
| Create and reclaim four concurrent workspaces | 25.342 s | 10.566 s | 2.40× |
| Clone 100,000 JavaScript files | 15.875 s | 5.481 s | 2.90× |
| Delete 100,000 JavaScript files | 6.709 s | 6.408 s | 1.05× |
| Clone a Git repository (50,013 files) | 7.752 s | 4.784 s | 1.62× |
| Delete a Git repository (50,013 files) | 2.593 s | 1.627 s | 1.59× |
| Clone a build cache (200,000 files, 10 GB) | 31.856 s | 16.308 s | 1.95× |
| Delete a build cache (200,000 files, 10 GB) | 14.250 s | 12.982 s | 1.10× |
| Clone 5,000 HTML and asset files | 0.597 s | 0.217 s | 2.75× |
| Delete 5,000 HTML and asset files | 0.211 s | 0.110 s | 1.92× |
| Clone a dataset (2,000 files, 50 GB) | 0.262 s | 0.095 s | 2.76× |
| Delete a dataset (2,000 files, 50 GB) | 0.235 s | 0.191 s | 1.23× |
| Scan 20,000 files along a 40-folder chain | 35.66 ms | 17.21 ms | 2.07× |

As for single file operations, I can only say I still recommend native unix commands. But for everything else, use stallion.

Baselines: native POSIX scanning, `cp -cRp`, `mv -n`, `rm -rf`, and Git worktrees + offline `npm ci`. File trees are generated; workspace times include cleanup and exclude seed preparation. [Full results, CPU and memory](tests/perf/README.md).

## Contributing

[Open an issue](https://github.com/alvinhhh/stallionfs/issues) for bugs or feature requests. See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions and tests, or [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE). Maintained by [@alvinhhh](https://github.com/alvinhhh).
