# Unsigned FSKit development package

This recipe assembles a containing app and nested FSKit extension for the
adapter described in [fskit-readonly.md](fskit-readonly.md).
It uses host ID `com.alvinhhh.stallionfs` and module ID
`com.alvinhhh.stallionfs.module`. The default package profile uses filesystem
short name `stallionfs`; `--profile private-sfsro27` explicitly selects the private
test type. Packaging is preparation for controlled qualification, not an installer.
The read-only recipe below does not qualify writable workspace creation.

First complete the offline recipe in that document in a Bash session. Keep its
successful output directory, three fixture files, source hashes and compiler
logs. Current production extensions accept supported validated format-0.6 images.
Generated `FixtureIdentity.swift` belongs to the offline helper and historical
fixture-restricted builds; it is not a restriction on the current public factory.
Keep fixture images and identity files outside the app bundle, and do not
substitute an older extension binary for the current reviewed source.

From the same repository root and Bash session, choose an explicit development
bundle version. The value below is an example for a disposable package, not a
claim about an installed version or permission to replace an app.

```bash
package_version=2
test ! -e "$experiment_out/package-host"
test ! -e "$experiment_out/StallionFS.app"
"${swift[@]}" -warnings-as-errors -parse-as-library \
    filesystem/fskit/Host.swift -o "$experiment_out/package-host"
python3 -I -B tools/package_fskit.py \
    --host "$experiment_out/package-host" \
    --extension "$experiment_out/readonly-extension" \
    --out "$experiment_out/StallionFS.app" \
    --bundle-version "$package_version" \
    --profile private-sfsro27 --access-policy read-only
```

This adds one host compilation and one packaging invocation. Packaging performs no compilation or extension execution. It uses bounded
`lipo`, `nm` and `otool` inspection of private copies of the exact executable bytes. It creates only a fresh output app, copies
the two executable byte streams, and fills the bundle-version fields in the two
Info.plist templates. It refuses an existing destination, never replaces an app,
and retains partial output on failure. Do not retry into that partial output.
The manual recipe does not impose an overall deadline or output cap.

Both executables must have matching, nonempty architecture inventories drawn
from `arm64`, `arm64e` and `x86_64`. Inventory order does not matter. Every slice
must have exactly one modern `LC_BUILD_VERSION` command for macOS (numeric
platform `1`), a numeric minimum OS and SDK, and an SDK at least as new as that
slice's minimum. Legacy-only, missing, duplicate or conflicting deployment
metadata is refused. Versions accept one to three numeric components;
`27`, `27.0` and `27.0.0` compare equally. Different compatible slice minima and
SDKs are allowed.

Each executable minimum must be no greater than its own generated plist's
`LSMinimumSystemVersion`; the containing app's declared minimum must be at least
the module's declared minimum. The current templates remain `27.0`. An executable
requiring `26.0` is compatible with that declaration; one requiring `28.0` is
refused. These structural checks run even without a manifest. Actual ordinary
Host/module test evidence is arm64/macOS 27 only. Synthetic universal test cases
cover parsing and admission; they do not qualify installed Intel, universal or
arm64e FSKit behavior or change the Intel CLI contract.

Each inspection tool has a 30-second deadline. A nonzero exit, invalid UTF-8 or
complete output larger than 1 MiB is an error. This accepted-output limit does
not cap temporary-file growth while the tool runs. Input substitution, a
host/module inventory mismatch, an unsupported platform or an incompatible
minimum is an error before output creation. Packaging never launches either
executable.

## Optional candidate manifest

Add `--manifest-out "$experiment_out/candidate.json"` to either packaging command
to write an external unsigned assembly receipt. The path must be a fresh `.json`
sibling of the output app with the same existing resolved parent. No receipt is
created by default. Missing/different parents, paths inside the app, existing
entries and dangling or final symlinks are refused. The packager never creates
manifest parent directories or overwrites an entry.

The schema-1 JSON has kind `fskit-unsigned-assembly-candidate` and assembly
`no-signing-performed`. It records the package profile/version, filesystem short
name, controller protocol, derived factory policy, sorted architecture inventory,
and each artifact's bundle ID, declared minimum, per-slice platform/minimum/SDK
and `pre_sign_input_sha256`. `pre_sign_package_files` lists all four package paths
and SHA-256 hashes of their verified staged bytes. Executable hashes equal the
corresponding input hashes. Serialization sorts keys and ends with a newline;
there are no timestamps, absolute paths, source-tree claims, account identifiers
or credentials. The existing module factory declaration is unchanged.

The parent directory is held open and the manifest leaf is exclusively reserved
without following a final symlink, at mode `0600`, after input/template inspection
and before app assembly. JSON is written only after all four app files are
written and verified. The retained descriptor must remain a regular single-link
file, match its named entry, and pass complete-write/readback checks. A short
write, replaced/unlinked entry or manifest failure fails the whole invocation;
`Unsigned package: PATH` is printed only after optional manifest completion.
A later assembly or manifest failure can leave a partial app and an empty or
incomplete reserved manifest, or a complete app without a valid receipt. Only an
exit-zero invocation yields a completed candidate receipt. Keep failed outputs
for diagnosis and choose fresh paths for retries; the packager does not remove
or rewrite replaced entries. Directory anchoring protects this manifest write
from subsequent parent-path substitution; it does not establish protection
against arbitrary hostile replacement of the app's directory ancestors.

App staging directories intentionally remain private `0700`; this command does
not normalize shared-installation permissions. “Pre-sign” identifies the
build/package input boundary: the packager performs no identity signing, while
the linker may already have added ad-hoc executable signatures. The receipt
neither validates those signatures nor proves they are absent. External JSON
can be edited and supplies no authenticated authority, trusted signing,
notarization, installed module identity or ordinary-install qualification.
Signing can change executable bytes; retain separate final hashes for a later
signed/notarized artifact. The runtime controller does not trust this receipt.

Normal host launch retains the AppKit run loop. `--discover-json` instead uses
public FSClient inventory discovery before initializing NSApplication. Its
completion and deadline share a single gate; package/signature inspection runs
on a background queue. Nil inventory, fetch failure, malformed metadata and
timeout are errors. Package metadata and the complete JSON result each have a
1 MiB transport limit; exceeding it fails the inventory without omitting modules.
The controller owns this helper, captures output and reaps it after completion
or interruption. Building the host does not launch or activate an extension. The module keeps path-resource
support, `FSRequiresSecurityScopedPathURLResources=true`, and no block-resource
support. Its existing security-scope handling and read-only image open are
unchanged. The required flag preserves the installed module's scoped-resource
policy. Actual scope delivery, acquisition, lifetime and mounted access remain
unverified; packaging does not exercise them. Experimental bundle version 2
distinguishes this test bundle from version 1, not a product release.

`Module.entitlements` declares only the existing sandbox and FSKit capability.
`Host.entitlements` is empty. These are templates for later reviewed signing,
not applied permissions. Any provisioning profile, certificate selector and
profile-derived team/application identifiers must remain external inputs.
No profile, private key, team/device identifier or signing credential is bundled
by this recipe. “Unsigned” means no identity-signing action or bundle seal is
performed; the compiler/linker may already have produced ad-hoc executable
signatures. Those do not establish FSKit entitlement authority.

Before an existing-ID update, establish the exact installed bundle/version,
registration and enablement state; retain a verified backup; choose the intended
new version, filesystem short-name behavior, activation-option compatibility
and minimum-system requirements; validate the existing profile
and signing eligibility against the final package; and qualify the signed
artifact and restoration procedure. The same module ID can collide with the
existing installation, so do not register this second copy or replace the
installed app merely because packaging succeeded. No new identifier or account
registration is presumed necessary. The package has not established mounted
correctness, writable operation, ordinary installation or distribution readiness.

## Writable controller packages

A writable production extension must be compiled with both
`-D STALLION_CONTEXT_HANDLERS` and `-D STALLION_CONTEXT_WRITES`. Neither or just
one flag leaves the public factory read-only. Caller context, admitted resource
write access and retained item-open mode remain independent runtime checks.
Do not use diagnostic write flags or fixture identity hooks in the product.

Using the same selected SDK/tool arrays and ordinary `image.o` from the offline
recipe, build the current public writable factory and normal Host explicitly:

```bash
"${swift[@]}" -warnings-as-errors -D STALLION_CONTEXT_HANDLERS \
    -D STALLION_CONTEXT_WRITES -parse-as-library -application-extension \
    -Xlinker -e -Xlinker _NSExtensionMain \
    filesystem/fskit/Extension.swift filesystem/fskit/Volume.swift \
    "$experiment_out/image.o" -o "$experiment_out/writable-extension"
"${swift[@]}" -warnings-as-errors -parse-as-library \
    filesystem/fskit/Host.swift -o "$experiment_out/writable-host"
python3 -I -B tools/package_fskit.py \
    --host "$experiment_out/writable-host" \
    --extension "$experiment_out/writable-extension" \
    --out "$experiment_out/WritableStallionFS.app" \
    --bundle-version "$package_version" --profile production \
    --access-policy contextual-writes
```

These outputs must be fresh private preparation paths. This builds and assembles
an unsigned candidate only. Shared-release directory permissions, distribution
signing, installer/CLI delivery and installed qualification remain separate.

For a qualified writable build, package with `--profile production
--access-policy contextual-writes`. The optional access-policy argument is a
consistency assertion: packaging derives policy from the exported factory marker
selected by the actual compiled both-flags branch. Every architecture must expose
exactly one matching defined marker. Missing or stripped markers, contradictory
markers, mixed architecture policies and a falsely requested policy are rejected.
The plist records the derived policy, architectures and explicitly pre-sign input
digest. Signing can change executable bytes; that digest is build traceability,
not a post-sign identity assertion. The final signature seals executable and
derived declaration together. Final artifact qualification can repeat the same
compiled-profile inspection on the signed executable. This does not grant write
authority. The controller requires the derived declaration and protocol 1, checks the package
signature, OS minimum, exact discovered bundle URL/ID/version/signing identity,
enabled state and absence of enabled short-type collisions. Discovery alone
does not establish writable behavior or attest an exact live adapter session.
First managed use also verifies the prepared Git branch/commit and performs a
real write/fsync/remove probe through the mounted repository path. Acceptance is
durable and required even when the first mount follows installation recovery;
failed checks retain the installed image and unresolved probe record. Later
accepted writable sessions may legitimately change branch and content.

Contextual creation access accepts `addFile` and `addSubdirectory`, separately or
together, on linked owner directories with write/search mode bits, no special
mode bits, flags or opaque ACL. This includes the linked root without a namespace
parent ID. Creation access requires a mounted writable resource; every combined
right still passes its original permission checks. On regular files the SDK's
`addSubdirectory` bit remains `appendData` under the existing file policy.
Directory construction checks `addSubdirectory` and search through that same
policy. Installed mkdir routing and persistence require separate qualification;
direct callback tests do not establish them.

File, directory and symbolic-link creation accept optional access, modification
and birth times in the initial creation transaction. Each concrete signed second
and nanosecond value is preserved exactly, including zero and negative seconds.
Omitted times and the child's ctime use the core creation sample; the parent's
mtime/ctime use that sample independently of restored child times. Invalid
nanoseconds and mixed unsupported fields reject the entire request. Fields are
acknowledged only after both complete SDK result roles and the commit validate.

Creation still requires explicit owner mode/UID/GID and the original parent's
write/search authority. Restrictive initial child modes do not prevent applying
supplied times. Flags must be absent or zero; file/directory size must be absent
or zero, and every explicit symlink size is refused. Computed fields, changeTime,
backupTime, addedTime and capability hints remain unsupported. These callback
semantics do not establish which attributes Finder or copying utilities supply,
or qualify installed copy metadata fidelity and close/remount behavior.

Contextual extended-attribute mutation accepts owned regular files, directories
(including root) and symbolic links. It requires a mounted writable resource,
owner-write mode, zero flags, no special mode bits and no opaque ACL. Every
combined access right must independently pass against the original metadata.
Directory search is required only for a separate search or creation right.
Symlink attributes belong to the link's exact held inode and pin, never its
target; a dangling or changed target does not redirect an attribute operation.

Get/list retain owner-read and ACL checks, including on read-only resources and
readable flagged or special-mode objects. Values are opaque whole values bounded
at 1 MiB; create-only, replace-only and delete policies use current committed
existence. Ordinary FinderInfo, quarantine and vendor names are supported; ACL,
security, compression and provenance namespaces remain refused. ResourceFork
mutation, including deletion, is regular-file-only; inherited nonregular values
remain readable. This does not implement named-fork streaming or FinderInfo
field transformations.

Mutation prepares the SDK free-space result before commit and acknowledges only
a verified commit. Get/list results carry values and names, not item-attribute
snapshots. Xattrs change only their stored values and ctime. Held unlinked
items retain their original pin and last-parent witness without gaining namespace
authority; detached values are not promised to survive close or crash. Linked
and root values are checked by closed read-only readback in callback tests.
Installed Finder/copy behavior, no-follow syscall routing, caching and mounted
durability require separate qualification.

Contextual removal accepts regular files, symbolic links and empty directories.
A known nonempty directory returns `ENOTEMPTY` before a transaction begins; the
core also rechecks the exact name/inode and directory emptiness during unlink.
After final-name removal, core metadata remains detached: link count zero and
no live parent/name. The retained item separately keeps its verified last-known
parent relationship, bound to that item and pin. Removal and later held-item
results use that informational parent ID with current post-transaction metadata
and the full SDK-required attributes. The relationship is published only after
a verified commit and discarded when the pin is reclaimed. It grants no
permission to use a detached directory as a namespace parent or relink an item.
Direct core edits without that verified callback relationship do not acquire it.
Contextual rename also accepts atomic replacement of an owned destination item.
The adapter verifies both name-to-inode bindings and each item's removal policy
before one core transaction. Files and symlinks can replace either nondirectory
kind; directories can replace only empty directories. All four result roles use
current post-transaction metadata and the full SDK-required attributes. A victim
losing its last name uses the same commit-bound informational parent relationship
as removal. Its held pin remains independent of the moved source until reclaim.
Renaming a path onto itself or another name of the same inode is a validated
no-op: it overwrites nothing, returns no overwritten-item snapshot and does not
start a transaction. Failures preserve the existing rollback or uncertain-outcome
rules. Direct callback tests do not qualify installed syscall or cache behavior.
Mounted snapshots and generic stale cleanup remain unsupported.

Contextual attribute setting accepts ordinary owner permission bits and explicit
access, modification and birth times, including a request combined with regular
file resize. The original item and caller must pass the owner, ACL, flags and
special-mode policy. Metadata and security access checks use that same policy;
security authorization does not implement ACL or ownership changes. Every other
requested access right still requires its original permission. Mode cannot grant
the data permission needed by a resize in the same request.

Resize and metadata changes share one transaction. Explicit times are applied
after resize, even when equal to the original times. Nanoseconds are preserved
exactly; unsupported date coercions are refused. Full SDK result attributes are
prepared before commit, and supported fields are acknowledged only after verified
success. An all-value no-op does not commit. Held detached items retain their
own token and informational parent relationship; their metadata still does not
survive the core handle closing. UID/GID, flags and special permission bits remain
unsupported setters; backup and added times have no on-disk representation and
remain unconsumed. Installed chmod/fchmod, time-setting and cache behavior require
separate qualification; direct callback tests do not establish their routing.

Release qualification must bind the final signed artifact to the reviewed
both-flags build and exercise two complete create/run/write/fsync/unmount/remount
read cycles through the installed module. Retain package identity, public
inventory and command/current-image observations. Source, fake-controller and
direct callback tests do not establish mounted persistence or distribution
eligibility. The production signing/profile, installation, enablement and mounted
qualification gates remain open until that intended artifact passes them.

The contextual writable profile authorizes regular-file execution only for the
volume owner, with owner read and execute bits (`0500`), no special permission
bits, zero flags and no opaque ACL descriptor. Both contextual build flags,
contextual-write admission, enabled writes, mounted readiness and current writable
resource access are required. Read-only, legacy and diagnostic fixture profiles
retain their execution refusal. Every combined access right still needs its own
original permission; directory search and unrelated reads are unchanged.

Retained detached files use their exact owned pin and current inode permissions
and ACL. Their last-known parent grants no namespace or execution authority, and
a replacement path cannot supply the held victim's permissions. Access checks
grant no open modes and cannot restore an unlinked pathname. This policy is not
an execution sandbox: an external interpreter can consume readable script data.

Direct callback tests qualify these decisions and SDK result construction only.
Installed direct script/native launch, loader mappings, new-launch permission
revocation, executable replacement, retained descriptor/mapping lifetime and
remount persistence remain required qualification gates. Actual mount flags and
platform code-signature/quarantine restrictions remain independent constraints.

The SDK27 contextual interface implements sparse data/hole seek for regular
files, on both read-only and writable volumes. Mapped 4096-byte blocks count as
data through EOF, including allocated zeros and zero-filled growth tails;
unmapped blocks are holes. Queries use committed state and exact retained pins,
including detached replacement victims. They do not change atime or open modes.
Current owner/read-attributes and opaque-ACL policy applies; the callback has no
per-descriptor mode identity. This does not prove mounted write-only-descriptor
or permission-change behavior.

Negative offsets, unknown regions and nonregular items return `EINVAL`;
at/beyond EOF or exhausted data returns `ENXIO`. A hole search starting below EOF
can return EOF. The at-EOF hole policy follows Darwin's syscall description;
FSKit's callback wording does not explicitly document that exception or the
beyond-EOF errno. Installed forwarding remains a qualification gate.

One query budget covers the complete mapping traversal: 4 GiB each for metadata
read/hash work and 128 Mi checks, with cancellation and finite memory. Dense
next-hole work is linear in visited mapping metadata, not file bytes; sparse
gaps are skipped. Exhaustion returns nonpoisoning `EAGAIN`, never invented EOF.
These limits are not a guarantee that arbitrary valid large files complete.
The opt-in 10 GiB mapping-shape test encodes 2,621,440 mappings with shared raw
payload and minimum leaf occupancy; it qualifies metadata traversal only.
Actual dense 10 GiB payload/copy completion, installed seek routing and existing
sparse copy/import round trips remain separate gates. Clone support remains
pending. SDK26.2/legacy builds do not reference the new seek handler API.

## Optional self-contained CLI runtime

`--runtime-inputs /absolute/runtime-inputs.json` extends this same packager with
the CLI and its private Python/Git dependencies. It requires `--manifest-out`
and an existing owned `0700` output parent. The default host/module-only recipe
below is unchanged. This option assembles an unsigned candidate; it does not
install, register, sign or notarize an app.

The schema-1 input object has exactly `schema`, `python_descriptor`, `git`,
`wheel`, `licenses` and `sources`. A pinned file is an object with absolute
`path` and lowercase SHA-256 `sha256` fields:

```json
{
  "schema": 1,
  "python_descriptor": {"path": "/inputs/python.json", "sha256": "..."},
  "git": {
    "root": "/inputs/private-git",
    "inventory": {"path": "/inputs/git-tree.json", "sha256": "..."},
    "qualification": {"path": "/inputs/git-qualification.json", "sha256": "..."}
  },
  "wheel": {"path": "/inputs/stallionfs.whl", "sha256": "..."},
  "licenses": [{"path": "/inputs/COPYING", "sha256": "...", "destination": "Git/COPYING"}],
  "sources": [
    {"path": "/inputs/git-source.tar.xz", "sha256": "...", "destination": "Git/source.tar.xz"},
    {"path": "/inputs/git-build-recipe", "sha256": "...", "destination": "Git/build-recipe"}
  ]
}
```

The abbreviated hashes above are placeholders, not usable inputs. The Python
descriptor pins the preserved runtime root/inventory, install-only and matching
full archives, upstream build metadata, static receipt and complete license
records. Supported metadata is currently traditional-GIL CPython 3.13.18,
`cpython-313-darwin`, arm64; no runtime is fetched or selected automatically.
The wheel must have the exact cp313 arm64 tag, complete RECORD, the native
launchers/extensions and current source/resource provenance, including
`_bundle.py`. Build a fresh source-matched wheel after changing Python source.
The old wheel is not a substitute. Native wheel members undergo the same
bounded existing Apple-tool inspection contract; this option adds no compiler
or tool-selection fallback.

Tree inventories are sorted arrays of normalized relative `path`, `type`,
`mode` (octal string), and `size`, with `sha256` for files or `link` for symlinks.
Only ordinary owned files/directories and present confined relative symlinks
are admitted. The Git qualification object has integer `schema:1`, the pinned
`inventory_sha256`, `static_closure_accepted:true` and
`local_correctness_passed:true`. These are explicit caller assertions backed by
the retained artifact reviews/receipts; JSON supplies no signature or independent
approval authority. The packager cannot determine license/source completeness
from a count of files. Supply the independently reviewed complete Git source,
build/config/patch material and any required dependency material, with exact
notices. Missing required maps, changed pins, unsupported members and unsafe
links or modes refuse assembly.

The app preserves `Contents/Resources/Runtime/{CPython,Git,CLI}`. Native `sfs`
and `stallionfs` stay in `CLI/bin` and keep their existing C fast paths. Their
sibling `stallionfs-python` is a fixed `/bin/sh` helper using only quoted
relative bundle paths, `-I -B -S` and the explicit wheel bootstrap. It preserves
cwd, arguments and the helper identity needed by existing benchmark dispatch;
it does not use PATH to find Python, process `.pth` files or inherit shell
startup instructions. Unsupported direct relative/symlink helper invocations
refuse. Source/wheel installations retain their existing entry points.

Internal Git operations, including the diagnostic version call and budgeted
path, remove inherited `GIT_*` routing before setting the private executable,
helper/template directories and child-only private Git PATH prefix. Generic
preparation and user workspace commands retain their existing PATH behavior.
Caller-selected external tools/configuration remain outside the private Git
closure; no network, credential or keychain qualification is implied.

The schema-2 runtime descriptor adds a compact native-creation Git contract:
source, build-config and input-inventory hashes plus the assembled payload's
canonical tree hash and entry count. Native creation selects it from the same
companion Host used for package verification, including source/wheel callers.
Schema-1 descriptors remain usable by generic/bootstrap paths but do not grant
native branch-mutation authority. Package verification must accept that same
app under the expected publisher requirement before the first creation effect.

Signing changes Mach-O bytes. The signing controller must finalize the Git
payload descriptor after nested Git signing and before the outer app seal.
The internal finalizer requires the assembled descriptor hash, original payload
rows and exact resulting hashes of independently verified signature transforms;
it refuses other byte, namespace, link or mode changes. It does not sign or
verify signatures itself. Controlled verifier fixtures do not qualify a signed
companion, installed package or mounted filesystem.

With this option only, app directories become `0755`, executable inputs/helper
`0755` and ordinary resources `0644`; the receipt remains `0600`. Licenses are
inside `Contents/Resources/Licenses`; a fresh sibling `APP.app.sources`
directory holds the pinned corresponding-source/build files. Existing sidecars
are never overwritten. The external receipt adds the exact runtime inventory,
input hashes, source build ID and license/source mappings. Complete input and
output checks finish before a success message. A failure retains partial
output and may leave an empty reserved receipt; use fresh paths after review.

The runtime validator checks physical same-bundle paths, ownership, modes and
required dependencies. It does not authenticate the interpreter already loaded.
Group-writable installation anchors, ACL policy, signed app/CLI pairing including
mounted reuse, final nested-code layout/hardened runtime, notarized distribution,
owned user links and installed FSKit lifecycle remain separate qualification
gates. Do not treat a private assembly or CLI test as an installation/update
permission or a stable mounted-filesystem result.

## User command link

The Control Panel offers `Install Command`, `Remove Command` and `Refresh` for
one per-user `~/.local/bin/sfs` link. The target must be the admitted physical
`/Applications/StallionFS.app` and its bundled native CLI. Workspace, relocated,
translocated, symlinked and mounted-volume candidates are refused. These actions
manage a command link; they do not install, replace or remove the app or prepare
an FSKit module for an update.

`Extension Settings` opens the macOS File System Extensions pane for manual
module enablement and any macOS authorization. `Quit StallionFS` (Command-Q)
uses normal app termination. Command setup must finish before the app can quit
or its panel can close.

The corresponding bundled CLI actions are `sfs command status`, `sfs command
install` and `sfs command remove`; place `--json` before `command` for structured
output. They run before workspace Store initialization. Status creates no
directories, lock or workspace store. Install creates missing user-owned command
directories but never changes existing permissions. Ownership, mode and ACL
checks must admit the held parents. A regular file, dangling foreign link or link
to a previous/other target is a conflict, not an entry to overwrite or adopt.

The panel displays an exact zsh/bash PATH line; CLI output includes it when its
process PATH lacks the command folder. They never edit a shell profile or change
PATH. Terminal configuration can differ from the app's environment; use the
displayed command path or PATH line in that terminal.

The Host requests helper termination after 30 seconds or oversized output. It
keeps mutation controls disabled until the owned helper actually exits and both
streams finish. This is not a hard stop guarantee for uninterruptible OS work.

Mutation is serialized by an owned local lock and rechecks the target, parents
and exact owned link. It does not provide atomic compare/unlink protection
against arbitrary same-user replacement. Interrupted or uncertain operations
retain the observed entry; refresh status before an explicit install/remove.
Removal deletes only the exact current-user link to the admitted target. Empty
directories and the small lock file remain. If app admission is unavailable,
restore the app to its supported location before managing its link. No workspace
data, mount, signing state or system registration is changed. Ordinary app
installation, upgrade/removal and signed installed qualification remain separate.

## Hosted unsigned components

The manual **Checks** workflow mode `unsigned-app-artifact` builds from the
selected commit on a verified macOS 27 ARM64 host with selected Xcode 27.1 and
SDK 27.0. It compiles the ordinary host, the production extension with
`STALLION_CONTEXT_HANDLERS` and `STALLION_CONTEXT_WRITES`, a matching CPython 3.13
ARM64 wheel, and `tools/mount_witness.c`. The mount witness is compiled without
being run. This finite job does not sign for distribution, install, register,
or mount anything. Linker-added ad-hoc signatures may be present.

The artifact contains only the four unsigned app files, wheel, mount witness,
repository `LICENSE`, and public `provenance.json` in `StallionFS-unsigned-arm64.tar.gz`. The manifest
records the source commit/tree, source and component hashes, actual tools and
SDK, command results, production symbol checks, existing packager candidate
receipt, and wheel RECORD/source/native-member validation. The archive is
reopened and its exact inventory and file hashes verified before upload.
Failed builds do not upload a component archive. Retention is three days;
download and verify the archive into durable storage before expiry.

These are assembly inputs, not a self-contained release: the shell app lacks
the private Python and Git runtimes required by the bundled-runtime recipe.
No private runtime descriptors, licenses/source sidecars, installation receipts,
fixture identities, keys, profiles, or account identifiers are workflow inputs.
Bundle version 146 identifies this component build; the product version is
unchanged. A later private assembly must use the matching wheel and preserve
its source and build provenance.
