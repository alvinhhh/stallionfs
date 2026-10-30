# Unsigned FSKit development package

This recipe assembles a containing app and nested FSKit extension for the
fixed-fixture adapter described in [fskit-readonly.md](fskit-readonly.md).
It uses host ID `com.alvinhhh.stallionfs` and module ID
`com.alvinhhh.stallionfs.module`. The filesystem short name remains `sfsro27`.
It is preparation for controlled mounted qualification, not an installer or a
general image mounter. Mutation operations remain read-only refusals.

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
    --bundle-version "$package_version"
```

This adds one host compilation and one packaging invocation. Packaging performs
no compilation or subprocess calls. It creates only a fresh output app, copies
the two executable byte streams, and fills the bundle-version fields in the two
Info.plist templates. It refuses an existing destination, never replaces an app,
and retains partial output on failure. Do not retry into that partial output.
The manual recipe does not impose an overall deadline or output cap.

The host is an ordinary minimal AppKit run loop. Building it does not launch it,
activate an extension or create filesystem access. The module keeps path-resource
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
