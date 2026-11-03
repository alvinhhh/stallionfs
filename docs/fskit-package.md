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
logs. The production `readonly-extension` binary is compiled against that
fixture's generated `FixtureIdentity.swift`: its UUID, generation, digest and
topology remain mandatory. Do not substitute another fixture or an older
extension binary. The image and its identity stay outside the app bundle.

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
`lipo` and `nm` inspection of a private copy of the exact executable bytes. It creates only a fresh output app, copies
the two executable byte streams, and fills the bundle-version fields in the two
Info.plist templates. It refuses an existing destination, never replaces an app,
and retains partial output on failure. Do not retry into that partial output.
The manual recipe does not impose an overall deadline or output cap.

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
