# stallionfs

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

Destinations are exact paths. Clones and moves refuse to overwrite existing files; `move --replace` and `move --exchange` are explicit alternatives. Use `--jobs 1` with cloning or deletion for lower CPU use. See [file operations](docs/usage.md#file-operations) for options and supported filesystems.

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

stallionfs 0.5.0 on an Apple M2 with 24 GB RAM, macOS 27. Median times with warm caches:

| File command | macOS command | stallionfs |
| --- | ---: | ---: |
| Copy one 4 KiB file | 2.31 ms | 2.83 ms |
| Move one 4 KiB file | 2.24 ms | 2.83 ms |
| Delete one 4 KiB file | 2.35 ms | 2.83 ms |

These include process startup and compare against `cp -cRp`, `mv -n` and `rm -f`. Apple's commands are faster on these small files. The measured commands and their JSON output run in C.

| Command | Time |
| --- | ---: |
| Copy one 4 KiB file, JSON output | 3.51 ms |
| Move one 4 KiB file, JSON output | 3.00 ms |
| Delete one 4 KiB file, JSON output | 2.97 ms |
| Scan 1,000 files | 4.22 ms |

| Scan | Native POSIX baseline | stallionfs |
| --- | ---: | ---: |
| 20,000 files in one folder | 37.38 ms | 18.06 ms |
| 20,000 files across 200 folders | 41.36 ms | 22.07 ms |

The 20,000-file scans use the Python API and exclude command startup. Both implementations retrieve the same counts and logical sizes. Flat scanning was 2.07× faster; nested scanning was 1.87× faster.

[Results and test setup](tests/perf/README.md). Workspace lifecycle and image I/O figures will be added when measured on the current release.

## Contributing

[Open an issue](https://github.com/alvinhhh/stallionfs/issues) for bugs or feature requests. See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions and tests, or [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE). Maintained by [@alvinhhh](https://github.com/alvinhhh).
