# stallionfs

Local macOS filesystem tools: native bulk metadata scanning and prepared copy-on-write Git workspaces. Use Python's standard library and native platform APIs. Prefer measured gains and small changes. Broad filesystem acceleration is the direction; do not claim it is already implemented or infer system-wide benefits from one operation.

Trace filesystem and Git effects before edits. Preserve source checkouts, publish completed objects atomically, validate IDs, never share mutable files via hard links, and never silently fall back to byte copying. Every destructive path needs a focused regression check.

Build the native extension with `python3 -m pip install -e .`. Run `python3 -m unittest discover -s tests -v` and `python3 -m compileall -q stallionfs` before publishing substantive changes. Measure scanner changes with `tests/perf/scan.py` and workspace changes with the locked fixture in `tests/perf/run.py`; keep cold preparation, ready time, and full cleanup distinct. Never claim general filesystem acceleration from workspace timings. Preserve failed approaches and comparisons as evidence internally; don't ship a new storage layer unless its measured gains justify it.

Write the README for users: what it does, features, setup, development, links and license. Keep operational details in docs. Use measured performance as stats, not benchmark-related marketing copy. Do not add slogans, compliance prose or speculative warnings.

Batch related implementation, tests and docs into substantial commits, roughly five or six small edits per commit. No status-only commits, scaffold-only commits or repetitive fixups. Use the existing alvinhhh/stallionfs repository; preserve its visibility. Keep caches, credentials, private source, runtime workspaces and raw personal paths out of Git.
