# stallionfs
**because stallions eat Apples**

**STILL IN DEVELOPMENT! DO NOT USE IN A PRODUCTION ENVIRONMENT!**
stallionfs provides native file operations and prepared Git workspaces on macOS.

[Usage](docs/usage.md) · [Storage and recovery](docs/storage.md) · [Issues](https://github.com/alvinhhh/stallionfs/issues)

## Highlights

- Clone files and folders with APFS copy-on-write.
- Copy file data and metadata, including between compatible volumes.
- Move, swap and delete paths, or list mounted volumes.
- Install dependencies once and reuse them across workspaces.
- Clone a whole APFS workspace volume without copying every file.
- Count files and sizes with native bulk metadata reads.

APFS copy-on-write shares unchanged data on disk. Each workspace has its own Git repository and branch; edits in one don't affect the others.

## Usage

Use `sfs`; `stallionfs` remains available.

```sh
sfs copy source destination
sfs clone project project-copy
sfs move project-copy old-project
sfs delete --recursive old-project
sfs volumes
```

Destinations are exact paths. Copies, clones and moves refuse to overwrite existing files; `move --replace` and `move --exchange` are explicit alternatives. Use `--jobs 1` with copying, cloning, deletion or scanning for lower CPU use. See [file operations](docs/usage.md#file-operations) for options and supported filesystems.

Prepare a clean checkout, then start working in a copy:

```sh
seed=$(sfs prepare /path/to/project --key node22-npm10-v1 --image-size 8 -- npm ci)
workspace=$(sfs create "$seed" --name fix-parser)
cd "$workspace"
```

The command after `--` runs once during preparation. Change `--key` when you change the toolchain or setup environment. A new source commit gets a new seed automatically.

`--image-size 8` creates workspaces as separate 8 GiB APFS volumes and requires macOS 26+. Omit it to use ordinary folders. See [disk-image workspaces](docs/usage.md#disk-image-workspaces) for capacity and mounting details.

To count files and their total logical size:

```sh
sfs scan /path/to/folder
sfs --json scan /path/to/folder
```

The scanner counts symlinks without following them and skips nested volumes.

Leave the workspace and stop processes using it before removal. To remove, restore, or clear old trash:

```sh
sfs list
sfs remove WORKSPACE_ID
sfs restore WORKSPACE_ID
sfs gc                 # Preview trash older than 24 hours
sfs gc --yes           # Delete that trash
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

0.6.3 · macOS 27 arm64 · warm generated fixtures · October 24–29, 2026. Median elapsed times, including command startup, from ten timing pairs per comparison.

| Operation | Native reference | Native | stallionfs |
| --- | --- | ---: | ---: |
| [Copy a 4 KiB file](tests/perf/results/ordinary-copy-tiny-v0.6.3-arm64.json) | `cp -Rp` | 4.857 ms | 5.861 ms |
| [Move a 4 KiB file](tests/perf/results/native-move-tiny-20261024-arm64.json.xz) | `mv -n` | 3.758 ms | 4.704 ms |
| [Scan 20,000 files in one folder](tests/perf/results/native-scan-flat-20261024-arm64.json.xz) | `find` + batched `stat` | 14.146 s | 33.494 ms |
| [Scan 20,000 files across nested folders](tests/perf/results/native-scan-nested-20261024-arm64.json.xz) | `find` + batched `stat` | 12.784 s | 17.051 ms |
| [Scan 20,000 files along a 40-folder chain](tests/perf/results/native-scan-deep40-20261024-arm64.json.xz) | `find` + batched `stat` | 13.018 s | 32.026 ms |
| [Clone a document tree, 5,002 files, `--jobs 1`](tests/perf/results/native-clone-docs-jobs1-20261029-arm64.json.xz) | `ditto --rsrc --extattr --acl` | 754.396 ms | 572.289 ms |

[CPU, memory and full results](tests/perf/README.md).

## Contributing

[Open an issue](https://github.com/alvinhhh/stallionfs/issues) for bugs or feature requests. See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions and tests, or [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE). Maintained by [@alvinhhh](https://github.com/alvinhhh).
