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

Apple M2, 24 GB RAM, macOS 27. Median times with warm caches:

| File command, 0.4.0 | macOS command | stallionfs |
| --- | ---: | ---: |
| Copy 10,000 files in nested folders | 1.93 s | 0.67 s |
| Delete those folders | 0.46 s | 0.29 s |
| Copy one 4 KiB file | 2.27 ms | 2.94 ms |
| Move one 4 KiB file | 2.91 ms | 3.77 ms |

These include command startup and compare against `cp -cRp`, `rm -rf` and `mv -n`. Small commands remain slower. Nested copying used 27% more CPU and deletion 51% more; `--jobs 1` is available for lower CPU use. See the [complete file-command results](tests/perf/README.md#file-commands).

| Scan | Native POSIX baseline | stallionfs |
| --- | ---: | ---: |
| 20,000 files in one folder | 41.67 ms | 20.90 ms |
| 20,000 files across 200 folders | 47.86 ms | 25.93 ms |

Folder workspace times in 0.4.0 include creation, setup and full cleanup:

| Workspaces | Worktree + install | stallionfs folder |
| --- | ---: | ---: |
| One | 2.87 s | 1.61 s |
| Four concurrent | 11.20 s | 7.47 s |

<sub><sup>Scans were measured in 0.3.0 over 11 runs. The 0.4.0 folder comparison uses seven runs with 12,581 prepared files and an offline `npm ci` baseline. Folder preparation took 2.79 s, recovered after three workspaces at these medians. CPU use was about equal for one workspace and 21% lower for four. Concurrent timings varied substantially, and one pair was slower with stallionfs; [all samples and test setup](tests/perf/README.md) are included.</sup></sub>

The earlier [0.3.0 image comparison](tests/perf/README.md#prepared-workspaces) measured 3.97× faster creation and cleanup for one workspace and 6.76× for four. Image volumes also have a cost: durable writes took 2.14–3.74× as long as ordinary APFS folders, and concurrent file I/O took 2.55× as long in a separate [I/O comparison](tests/perf/README.md#file-io-inside-a-workspace). Use the image option for repeated workspace creation, and folders for work that writes heavily.

## Contributing

[Open an issue](https://github.com/alvinhhh/stallionfs/issues) for bugs or feature requests. See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions and tests, or [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE). Maintained by [@alvinhhh](https://github.com/alvinhhh).
