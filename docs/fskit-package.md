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

Release qualification must bind the final signed artifact to the reviewed
both-flags build and exercise two complete create/run/write/fsync/unmount/remount
read cycles through the installed module. Retain package identity, public
inventory and command/current-image observations. Source, fake-controller and
direct callback tests do not establish mounted persistence or distribution
eligibility. The production signing/profile, installation, enablement and mounted
qualification gates remain open until that intended artifact passes them.
