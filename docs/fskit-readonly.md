# Read-only FSKit build and helper

The current adapter reads format 0.6 images using their checked UUID and
committed namespace. It reads file data, symbolic links and bounded opaque
xattrs; mutations return EROFS. See [namespace semantics and limits](fskit-namespace.md).
This recipe validates source and helper behavior; it does not qualify installation.

The recipe below builds current production source and a separate offline helper.
It does not install, register, launch or mount an extension. It is separate from
the CLI and Python wheel. Existing macOS15/26 CI covers the CLI and C tests;
it does not build or run this SDK27 adapter.

The earlier fixture-restricted source and recipe are at commit
`31f7e57cea323cfc0fb41370280731b3f189fcb3`. That historical source accepted only
its generated fixture identity. Existing compiled and signed trial evidence
belongs to its original source; this recipe does not reproduce or replace it.

## Prerequisites

Use an arm64 Mac running macOS27 with Xcode and MacOSX27.0.sdk at the explicit
paths below. The recipe uses Bash and standard macOS command-line tools, Swift6
complete concurrency checking, and C11. It requires no profile, signing identity,
account setup or downloaded fixture. Linker-generated ad-hoc signatures are not
identity signing or installation authority.

Run from the repository root in Bash. Setup and hash/output checks surround
11 substantive commands: two compiler versions, six compile/link steps, one
fixture producer, one symbol inspection and one helper execution. Stop at the
first failure and retain the output directory. The producer creates its own
absent fixture directory; do not create or reuse that directory beforehand.

```bash
set -euo pipefail
experiment_root="$(pwd -P)"
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
export SDKROOT="$DEVELOPER_DIR/Platforms/MacOSX.platform/Developer/SDKs/MacOSX27.0.sdk"
experiment_bin="$DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin"
export PATH="$experiment_bin:/usr/bin:/bin" LANG=C LC_ALL=C
test -d "$SDKROOT"
test -f "$experiment_root/filesystem/image.c"
test -f "$experiment_root/tests/fskit_adapter_driver.swift"
experiment_out="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/sfs-fskit.XXXXXXXX")"
experiment_out="$(cd "$experiment_out" && pwd -P)"
printf 'Output: %s\n' "$experiment_out"
mkdir "$experiment_out/tmp"
export TMPDIR="$experiment_out/tmp/"
c=("$experiment_bin/clang" -std=c11 -Wall -Wextra -Werror -O1 -g
   -target arm64-apple-macos27.0 -isysroot "$SDKROOT" -I "$experiment_root/filesystem")
swift=("$experiment_bin/swiftc" -swift-version 6 -strict-concurrency=complete
       -target arm64-apple-macos27.0 -sdk "$SDKROOT"
       -module-cache-path "$experiment_out/module-cache"
       -I "$experiment_root/filesystem/fskit" -g -Onone)
adapter=("$experiment_root/filesystem/fskit/Extension.swift"
         "$experiment_root/filesystem/fskit/Volume.swift")
inputs=(filesystem/image.c filesystem/image.h docs/image-format.md
        filesystem/fskit/Extension.swift filesystem/fskit/Volume.swift
        filesystem/fskit/SFSImageBridge.h filesystem/fskit/module.modulemap
        tests/fskit_fixture.c tests/fskit_image_hooks.c
        tests/fskit_adapter_driver.swift docs/fskit-readonly.md docs/fskit-namespace.md)
/usr/bin/shasum -a 256 -- "${inputs[@]}" > "$experiment_out/sources.before.sha256"
check_warnings() {
    while IFS= read -r line || test -n "$line"; do
        case "$line" in *warning:*)
            case "${line#*warning: }" in
                "'Operations' was deprecated in macOS 27.0 [#DeprecatedDeclaration]"|"'ReadWriteOperations' was deprecated in macOS 27.0 [#DeprecatedDeclaration]"|"'XattrOperations' was deprecated in macOS 27.0 [#DeprecatedDeclaration]") ;;
                *) printf '%s\n' "$line" >&2; return 1 ;;
            esac ;;
        esac
    done < "$1"
}

# 01–02: matching compiler versions
"$experiment_bin/clang" --version
"$experiment_bin/swiftc" --version
# 03: production core
"${c[@]}" -c filesystem/image.c -o "$experiment_out/image.o"
# 04: fixture producer
"${c[@]}" tests/fskit_fixture.c "$experiment_out/image.o" -o "$experiment_out/fixture-producer"
# 05: create and fully verify one fresh image and its generated Swift identity
"$experiment_out/fixture-producer" "$experiment_out/fixture"
identity="$experiment_out/fixture/FixtureIdentity.swift"
/usr/bin/shasum -a 256 -- "$experiment_out/fixture/image.sfs" \
    "$experiment_out/fixture/manifest.json" "$identity" > "$experiment_out/fixture.before.sha256"
# 06: production extension; compiled only
"${swift[@]}" -parse-as-library -application-extension \
    -Xlinker -e -Xlinker _NSExtensionMain "${adapter[@]}" \
    "$experiment_out/image.o" -o "$experiment_out/readonly-extension" \
    2> "$experiment_out/extension.stderr"
check_warnings "$experiment_out/extension.stderr"
# 07–08: separately hooked core and test hooks
"${c[@]}" -Dpread=sfs_hooks_pread -Dpwrite=sfs_hooks_pwrite \
    -Dclose=sfs_hooks_close -Dfsync=sfs_hooks_fsync -Dftruncate=sfs_hooks_ftruncate \
    -c filesystem/image.c -o "$experiment_out/image-hooked.o"
"${c[@]}" -c tests/fskit_image_hooks.c -o "$experiment_out/hooks.o"
# 09: offline helper; the define removes the production extension entrypoint
"${swift[@]}" -parse-as-library -D STALLION_ADAPTER_CHECK \
    "${adapter[@]}" "$identity" tests/fskit_adapter_driver.swift \
    "$experiment_out/image-hooked.o" "$experiment_out/hooks.o" \
    -o "$experiment_out/adapter-check" 2> "$experiment_out/helper-build.stderr"
check_warnings "$experiment_out/helper-build.stderr"
# 10: production symbols must retain the extension entrypoint and exclude hooks
"$experiment_bin/nm" "$experiment_out/readonly-extension" > "$experiment_out/production.symbols"
/usr/bin/grep -Eq '[[:space:]]U[[:space:]]+_NSExtensionMain$' "$experiment_out/production.symbols"
symbol_status=0
/usr/bin/grep -Eiq '(sfs_hooks|sfs_test_|adapter_check|FixtureIdentity|reclaimForTesting|sqlite)' "$experiment_out/production.symbols" || symbol_status=$?
case "$symbol_status" in
    0) printf '%s\n' 'Unexpected production test symbol' >&2; exit 1 ;;
    1) ;;
    *) printf 'Production symbol inspection failed: status %s\n' "$symbol_status" >&2; exit "$symbol_status" ;;
esac
# 11: one actual offline integration test, without a filesystem mount
"$experiment_out/adapter-check" "$experiment_out/fixture" \
    > "$experiment_out/helper.stdout" 2> "$experiment_out/helper.stderr"
printf '%s\n' \
    'PASS: real-core namespace, aliases, pagination, resource limits, reclaim, lifecycle ordering, read-only refusal and consumed close' \
    'UNTESTED: kernel access routing, packer/buffer delivery, kernel reclaim counts, acquired security scope and signed lifecycle' \
    > "$experiment_out/helper.expected"
/usr/bin/cmp "$experiment_out/helper.expected" "$experiment_out/helper.stdout"
test ! -s "$experiment_out/helper.stderr"
/usr/bin/shasum -a 256 -- "$experiment_out/fixture/image.sfs" \
    "$experiment_out/fixture/manifest.json" "$identity" > "$experiment_out/fixture.after.sha256"
/usr/bin/cmp "$experiment_out/fixture.before.sha256" "$experiment_out/fixture.after.sha256"
/usr/bin/shasum -a 256 -- "${inputs[@]}" > "$experiment_out/sources.after.sha256"
/usr/bin/cmp "$experiment_out/sources.before.sha256" "$experiment_out/sources.after.sha256"
```

The helper must exit successfully with exactly the two expected lines and no
stderr. Its individual callback waits are ten seconds; the manual
shell recipe does not impose an overall process deadline or output-size cap.
Keep generated files outside the checkout. They contain the fresh image identity
and local uid/gid and are not source files to commit.

## Helper coverage

The producer creates ten inodes with eleven names in an image configured for
8MiB capacity, supplies 49,226 payload bytes, performs full image verification
and consumes its handle before writing the manifest and identity. The backing
file can be smaller than capacity. One inode has three names, including a
cross-parent alias. Its generated identity is compiled only into the helper's
historical fixture assertions, never the production extension.

The helper directly calls the adapter with the real image core. It checks
metadata, reads, symlinks, xattrs, canonical alias items, directory pagination and
refused packing, continuation/session validation, read-only refusal, injected
read failures, cache release, remount helper state, retained errors and consuming
close/lock release. It also creates two independent images with arbitrary UUIDs
and 81 root names, tests value/list/item/callback limits and reclaim capacity,
checks unsupported-format and corrupt-root refusal, and tests unmount ordering
from packing/reply callbacks with accepted work and a full request queue. Methods named
mount/unmount change helper state without an OS filesystem mount. The test
packing closure is separate from the kernel's
FSDirectoryEntryPacker. Finite assertions are not independent syscall counts.

Parent projection for aliases and primary-only `referenced_data_bytes` allocation
remain experimental hypotheses. Kernel/caller dispatch, cold/warm foreign-user
denial, real directory buffer delivery, acquired security scope, reclaim return
counts, signed lifecycle and mounted fidelity remain separate qualification.
Test source alone is not a passing result or a performance measurement.
