# StallionFS 0.7.0 user guide

## Install, upgrade, and remove

The signed installer is not available on `main`. For the command line and
ordinary APFS workspaces, use the [source install](../README.md#installation)
on macOS with Python 3.11+, Xcode Command Line Tools, and APFS workspace
storage. These source instructions do not install or enable the FSKit app.

To replace a source install, stop commands using the old environment. Use the
same source-install steps from the desired checkout in a fresh virtual
environment, then activate it instead of the old one. This replaces the CLI
you run; it does not migrate workspace data or qualify an FSKit app upgrade.
To remove a source install, deactivate and remove the dedicated virtual
environment. The workspace store is separate by default
(`~/Library/Application Support/stallionfs`); preserve it and any custom
`STALLIONFS_HOME` or `--root` location if you want to keep your workspaces.

There is no qualified end-user FSKit app upgrade or uninstall procedure on
`main`. The repository has [exact-artifact maintenance tooling](fskit-maintenance.md),
but its signed installed qualification is still pending. The bundled
`sfs command install` and `sfs command remove` only manage the owned
per-user `~/.local/bin/sfs` link, not the app, extension, or workspace data.

## Check your workspace store

`sfs doctor --installation` is not implemented. Run `sfs doctor` to test APFS
cloning and copy-on-write isolation in your selected store. It reports the
store path, Git and Python versions, and any remaining staging entries.
It does not verify signatures, the installed app, or extension enablement.

## Take a snapshot and roll back

For a folder workspace, stop all writers (including editors and background
processes) before using `--quiescent`. StallionFS cannot stop unrelated writers.

```sh
sfs snapshot WORKSPACE_ID --name before-change --quiescent
sfs snapshots WORKSPACE_ID
sfs rollback WORKSPACE_ID SNAPSHOT_ID --quiescent
sfs retained
```

Use the ID from `sfs snapshots`, not the display name. A folder snapshot
includes the repository and its local state, including untracked and ignored
files. Rollback restores the selected snapshot without changing it and
returns the recovery ID for the previous workspace contents, stored in
`recovery/RECOVERY_ID` under the store. Keep separate backups of work you need.

[APFS disk images](usage.md#snapshots-and-rollback) must be able to detach
normally; release all volume users first. See the separate instructions for
[owned native workspaces](usage.md#owned-native-workspaces) and
[externally registered native images](usage.md#closed-native-images).
If a native operation fails, keep the reported IDs and diagnostics and check
its outcome before retrying; a failure does not necessarily mean nothing changed.

## Clean up workspaces

For folder and APFS disk-image workspaces, stop their users and run
`sfs remove WORKSPACE_ID` to move a workspace to trash. Use
`sfs restore WORKSPACE_ID` to bring it back. Explicit removal of an owned
native workspace also requires enrollment and seven days of confirmed
inactivity. Restoring an owned native workspace leaves it unmounted.
`sfs gc` previews eligible ordinary trash older than 24 hours by default;
`sfs gc --yes` permanently deletes eligible entries.

Opt-in cleanup is off by default. Enroll a workspace and record closure only
after all workspace users have stopped:

```sh
sfs enroll WORKSPACE_ID
sfs close WORKSPACE_ID --quiescent
sfs cleanup --enable
sfs cleanup
sfs cleanup --apply
```

After seven days closed, an eligible workspace can be moved to **protected
trash**, either by `cleanup --apply` or opportunistically after another
managed command. `sfs cleanup` without flags previews retirement.
`sfs cleanup --disable` stops future cleanup passes. Ordinary `sfs run`
exit does not record closure; see [cooperative session retirement](usage.md#cooperative-session-retirement)
for the folder-only opt-in alternative.

Ordinary GC skips protected trash. Use `sfs restore WORKSPACE_ID` to recover
it and `sfs retained` to inspect retained data. `sfs purge trash WORKSPACE_ID`
previews permanent removal of protected trash; add `--yes` only after
reviewing it. Purging an owned native image deletes its internal snapshots
and rollback recovery data too. Cleanup cannot retire externally registered
native images.
