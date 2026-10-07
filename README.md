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

stallionfs 0.6.0 on an Apple M2 with 24 GB RAM, macOS 27. Median times with warm caches:

| Operation | Baseline | stallionfs | Speedup |
| --- | ---: | ---: | ---: |
| Scan 20,000 files across 200 folders | 46.64 ms | 10.10 ms | 4.62× |
| Scan 20,000 files in one folder | 38.20 ms | 20.30 ms | 1.88× |
| Clone 10,000 files in nested folders | 1.204 s | 0.439 s | 2.74× |
| Delete those 10,000 files | 0.408 s | 0.198 s | 2.06× |
| Create and reclaim one folder workspace | 9.134 s | 4.983 s | 1.83× |
| Create and reclaim four concurrent workspaces | 27.824 s | 13.596 s | 2.05× |

Scans compare against native `readdir`/`fstatat` traversal through the same Python API. Copies compare against `cp -cRp`, using copy-on-write on both sides; deletion compares against `rm -rf`. Command timings include process startup; deletion finishes before the command returns.

Workspace results compare prepared folder clones with `git worktree add` and an offline `npm ci` from a warm cache. They include complete cleanup, exclude one-time seed preparation, and varied substantially between samples. Four concurrent workspaces used 21% less CPU.

Parallel file operations trade CPU for elapsed time. Nested cloning used 33% more CPU than `cp`; deletion used 38% more than `rm`. Sequential scanning is available with `--jobs 1`.

Single-file commands and moves remain slower than Apple's commands. [Full results](tests/perf/README.md) include every measured workload, CPU time, JSON output and native comparisons.

## Contributing

[Open an issue](https://github.com/alvinhhh/stallionfs/issues) for bugs or feature requests. See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions and tests, or [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE). Maintained by [@alvinhhh](https://github.com/alvinhhh).
