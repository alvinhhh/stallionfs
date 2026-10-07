# stallionfs

stallionfs is a macOS CLI for prepared Git workspaces and directory scans.

[Usage](docs/usage.md) · [Storage and recovery](docs/storage.md) · [Issues](https://github.com/alvinhhh/stallionfs/issues)

## Highlights

- Install dependencies once and reuse them across workspaces.
- Clone a whole APFS workspace volume without copying every file.
- Count files and sizes with native bulk metadata reads.

APFS copy-on-write shares unchanged data on disk. Each workspace has its own Git repository and branch; edits in one don't affect the others.

## Usage

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

Files are stored in `~/Library/Application Support/stallionfs`. Set `STALLIONFS_HOME` or pass `--root` to use another location. All commands accept `--json` before the command name.

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

| Scan | Native POSIX baseline | stallionfs |
| --- | ---: | ---: |
| 20,000 files in one folder | 41.67 ms | 20.90 ms |
| 20,000 files across 200 folders | 47.86 ms | 25.93 ms |

Workspace times include creation, setup or mounting, and full cleanup:

| Workspaces | Worktree + install | stallionfs folder | stallionfs image |
| --- | ---: | ---: | ---: |
| One | 6.14 s | 6.86 s | 1.55 s |
| Four concurrent | 23.10 s | 13.65 s | 3.42 s |

<sub><sup>Scans compare C implementations of `readdir`/`fstatat` and `getattrlistbulk` over 11 runs. Workspaces use seven runs with 12,581 prepared files and an offline `npm ci` baseline. Seed preparation took 2.38 s for folders and 12.28 s for images; image preparation broke even after three workspaces at these medians. Timings varied substantially; [all samples and test setup](tests/perf/README.md) are included.</sup></sub>

Image volumes also have a cost: durable writes took 2.14–3.74× as long as ordinary APFS folders, and concurrent file I/O took 2.55× as long in a separate [I/O comparison](tests/perf/README.md#file-io-inside-a-workspace). Use the image option for repeated workspace creation, and folders for work that writes heavily.

## Contributing

[Open an issue](https://github.com/alvinhhh/stallionfs/issues) for bugs or feature requests. See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions and tests, or [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE). Maintained by [@alvinhhh](https://github.com/alvinhhh).
