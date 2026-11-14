# Contributing

Open an issue with the macOS version, filesystem, Python version, command and smallest example that reproduces the problem. Remove tokens, private paths and repository contents before sharing logs.

For code changes, use a Mac with APFS and run:

```sh
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
python3 -m compileall -q stallionfs
```

Reinstall after changing native C code; both the extension and CLI need rebuilding.

## Git dependency

Source, sdist and editable builds compile the pinned Git dependency for the current arm64 or x86_64 host. The recipe targets macOS 13 and uses the macOS system curl library with pinned public headers. The complete wheel may require a newer macOS version because of the Python toolchain used for its extensions; its platform tag is computed from the actual binaries.

The first build downloads the two archives pinned in `stallionfs/_git_sources.py`. For an offline source build, put those exact archives in an owned directory and set `STALLIONFS_BUILD_INPUTS` to it. The remaining patches, headers manifest, configuration and alias source are included in the sdist. No global package or system Git installation is changed.

Each built runtime contains `SOURCES.txt`, both component licenses, a sanitized Git source archive, the complete patches, eleven curl headers, and an archive of the exact build scripts with their original paths. `SOURCES.txt` describes rebuilding entirely from those delivered files through `--delivered-sources`; that mode has no download fallback. The sanitized source omits optional non-build contributor instructions and retains dated notices for modified files. The manifest records the original archive, sanitized source, patches, recipe, final modified source and payload as separate identities.

The Python package's regular-file runtime is separate from a signed native companion. An app uses its own private Git and corresponding source, and does not copy the wheel's `_git` tree. Keep the complete adjacent `.sources` directory with the app in the same distributed ZIP or disk image. Generic Git inspection does not grant native creation or recovery authority. Native compatibility and installed-runtime qualification remain separate checks.

### CI component publication

CI consumes an exact qualified component for its architecture before building the current wheel. Publish source and component updates in this order:

1. Prepare the source commit with a new immutable component URL and its final archive, manifest and qualification digests. Use a new component tag; preserve existing tags and assets.
2. Push only that tag, pointing to the prepared commit. The Checks workflow runs ordinary tests on pull requests and pushes to `main` or `stable`; a component tag push does not start that matrix.
3. Publish the component prerelease at that tag. Verify the public download's bytes, archive digest, finite manifest and corresponding source against the prepared commit.
4. Fast-forward the pull request branch to that same commit. Its newly triggered tests can now fetch the published component.

Intel qualification requires a separate explicit first-attempt dispatch pinned to the reviewed source SHA. Its metadata queries have a single bounded invocation, and timeout or capture failure stops the job. A failed diagnostic artifact does not qualify a native input. Register an Intel component only after its actual build, campaign and complete evidence pass review; ordinary Intel CI continues to refuse a missing qualified component.

On macOS 26+, include the disk-image tests:

```sh
STALLIONFS_TEST_IMAGES=1 python3 -m unittest discover -s tests -v
```

They create disposable APFS images, exercise mount recovery and fill a 1 GiB test volume. Allow at least 3 GiB of free space.

### Hosted ImageSpace diagnostic

The Checks `image-space-repeat` manual mode builds and admits the current installed wheel with the ordinary CI setup on macOS 26 ARM64 and Python 3.11. After pushing the reviewed commit to a branch, dispatch it with its full SHA:

```sh
gh workflow run checks.yml --repo alvinhhh/stallionfs --ref BRANCH \
  -f mode=image-space-repeat -f expected-source-sha=FULL_COMMIT_SHA -f repeat-count=20
```

This repeats only `test_images_space.ImageSpace.test_volume_full_preserves_existing_data_and_other_images`, selecting `STALLIONFS_TEST_SNAPSHOT_OBSERVATION=enospc-sibling-detach`. The count accepts integers 1–20. Each invocation has a fresh Python child, temporary directory and existing diagnostic collector. Each child has a 180-second outer limit; the job has 90 minutes for at most 20 children, existing setup limits and evidence transfer. Existing test commands and collector limits (four failure attempts, 12 seconds, existing byte caps) remain unchanged.

The run stops on the first test failure, skip, incomplete mapping/holder observation, unaccounted direct child, or uncertain fixture cleanup. Incomplete observations retain the fixture before normal test cleanup; the runner never retries, forces an eject, signals an observed helper, or assumes a shared helper belongs exclusively to the test. Failed fixtures remain on the ephemeral worker until it is reclaimed. The artifact contains raw command streams/receipts, bounded observations and result summaries, not disk images. Download it before the one-day retention expires.

A passing diagnostic reports only the requested exact-case invocations. It cannot replace the six installed jobs, three sanitizer jobs, or their six required aggregate checks. Ordinary pull request and push discovery, assertions and per-command limits are unchanged. Intel installed qualification has a 45-minute whole-job budget: run 43531158583 reached its previous 30-minute limit while tests were still completing after about 41 seconds of setup. The additional 15 minutes provides bounded suite and transfer headroom; it is not evidence of a performance improvement or a guaranteed pass. Other job budgets are unchanged.

On macOS 27+ ARM64 with a selected macOS SDK 27+, discovery also compiles and runs the direct FSKit callback suite with and without `STALLION_CONTEXT_HANDLERS`, then checks both ordinary read-only extension builds. Select the required Xcode through `DEVELOPER_DIR` or `xcode-select` before invoking tests. To run only this suite:

```sh
python3 -m unittest discover -s tests -p test_fskit.py -v
```

Unsupported runtimes and SDKs report a capability skip. Compiler failures, unexpected warnings and callback assertion failures fail the test. Failed fixtures and command receipts remain at the path printed by the test; CI uploads only the captured command diagnostics. These checks do not establish installed client-context delivery or kernel routing. Hosted FSKit coverage requires a job whose actual runtime and selected SDK pass the capability gate; a runner label alone is insufficient.

Keep changes focused. Add a regression check for behavior that can lose or share user data. Keep implementation, tests and related documentation together.

Performance checks live in `tests/perf`. Keep locked fixtures and raw samples when changing published performance numbers. Count seed preparation and complete deletion separately from workspace startup. Report regressions as well as improvements.

Contributions are licensed under the project's MIT license.
