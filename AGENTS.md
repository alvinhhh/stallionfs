# stallionfs

Local macOS CLI for prepared copy-on-write Git workspaces. Python standard library only at runtime; APFS clonefile is the native backend. Prefer native capabilities and small changes.

Trace filesystem and Git effects before edits. Preserve source checkouts, publish completed objects atomically, validate IDs, never share mutable files via hard links, and never silently fall back to byte copying. Every destructive path needs a focused regression check.

Run `python3 -m unittest discover -s tests -v` and `python3 -m compileall -q stallionfs` before publishing substantive changes. Benchmark changes with the locked fixture in `tests/perf`; keep cold preparation, ready time, and full cleanup distinct. Never claim general filesystem acceleration from workspace timings.

Write the README for users: what it does, features, setup, development, links and license. Keep operational details in docs. Use measured performance as stats, not benchmark-related marketing copy. Do not add slogans, compliance prose or speculative warnings.

Batch related implementation, tests and docs into substantial commits, roughly five or six small edits per commit. No status-only commits, scaffold-only commits or repetitive fixups. Use the existing alvinhhh/stallionfs repository; preserve its visibility. Keep caches, credentials, private source, runtime workspaces and raw personal paths out of Git.
