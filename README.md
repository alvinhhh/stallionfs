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

0.6.2 · Apple M2 · 24 GiB RAM · macOS 27. Median elapsed times.

| Operation | Baseline | stallionfs | Speedup |
| --- | ---: | ---: | ---: |
| Clone a 4 KiB file | 2.573 ms | 3.250 ms | 0.79× |
| Move a 4 KiB file | 2.772 ms | 3.504 ms | 0.79× |
| Delete a 4 KiB file | 2.748 ms | 3.271 ms | 0.84× |
| Scan 20,000 files across 200 folders | 36.75 ms | 7.25 ms | 5.07× |
| Scan 20,000 files in one folder | 38.37 ms | 20.87 ms | 1.84× |
| Clone 10,000 files in nested folders | 2.435 s | 1.260 s | 1.93× |
| Delete those 10,000 files | 0.995 s | 0.721 s | 1.38× |
| Create and reclaim one folder workspace | 3.514 s | 2.169 s | 1.62× |
| Create and reclaim four concurrent workspaces | 17.584 s | 10.376 s | 1.69× |
| Clone 100,000 JavaScript files | 19.232 s | 10.942 s | 1.76× |
| Delete 100,000 JavaScript files | 5.096 s | 3.870 s | 1.32× |
| Clone a Git repository (50,013 files) | 8.050 s | 4.243 s | 1.90× |
| Delete a Git repository (50,013 files) | 3.356 s | 2.776 s | 1.21× |
| Clone a build cache (200,000 files, 10 GB) | 30.430 s | 12.456 s | 2.44× |
| Delete a build cache (200,000 files, 10 GB) | 20.404 s | 13.895 s | 1.47× |
| Clone 5,000 HTML and asset files | 1.244 s | 0.484 s | 2.57× |
| Delete 5,000 HTML and asset files | 0.365 s | 0.176 s | 2.08× |
| Clone a dataset (2,000 files, 50 GB) | 0.305 s | 0.134 s | 2.27× |
| Delete a dataset (2,000 files, 50 GB) | 0.190 s | 0.148 s | 1.29× |
| Scan 20,000 files along a 40-folder chain | 37.39 ms | 20.03 ms | 1.87× |

As for single file operations, I can only say I still recommend native unix commands. But for everything else, use stallion.

Baselines: native POSIX scanning, `cp -cRp`, `mv -n`, `rm -rf`, and Git worktrees + offline `npm ci`. File trees are generated; workspace times include cleanup and exclude seed preparation. [Full results, CPU and memory](tests/perf/README.md).

## Contributing

[Open an issue](https://github.com/alvinhhh/stallionfs/issues) for bugs or feature requests. See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions and tests, or [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE). Maintained by [@alvinhhh](https://github.com/alvinhhh).
