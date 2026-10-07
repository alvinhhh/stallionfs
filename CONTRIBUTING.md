# Contributing

Open an issue with the macOS version, filesystem, Python version, command and smallest example that reproduces the problem. Remove tokens, private paths and repository contents before sharing logs.

For code changes, use a Mac with APFS and run:

```sh
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
python3 -m compileall -q stallionfs
```

Reinstall after changing native C code; both the extension and CLI need rebuilding.

On macOS 26+, include the disk-image tests:

```sh
STALLIONFS_TEST_IMAGES=1 python3 -m unittest discover -s tests -v
```

They create disposable APFS images, exercise mount recovery and fill a 1 GiB test volume. Allow at least 3 GiB of free space.

Keep changes focused. Add a regression check for behavior that can lose or share user data. Keep implementation, tests and related documentation together.

Performance checks live in `tests/perf`. Keep locked fixtures and raw samples when changing published performance numbers. Count seed preparation and complete deletion separately from workspace startup. Report regressions as well as improvements.

Contributions are licensed under the project's MIT license.
