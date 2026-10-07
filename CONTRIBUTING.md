# Contributing

Open an issue with the macOS version, filesystem, Python version, command and smallest example that reproduces the problem. Remove tokens, private paths and repository contents before sharing logs.

For code changes, use a Mac with APFS and run:

```sh
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
python3 -m compileall -q stallionfs
```

Keep changes focused. Add a regression check for behavior that can lose or share user data. Group implementation, tests and related documentation into a complete commit; do not send a chain of fixups.

Performance checks live in `tests/perf`. Keep locked fixtures and raw samples when changing published performance numbers. Count seed preparation and complete deletion separately from workspace startup. Report regressions as well as improvements.

Contributions are licensed under the project's MIT license.
