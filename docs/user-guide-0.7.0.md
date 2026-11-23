# StallionFS 0.7.0 user guide

## Install, upgrade, and remove

The signed installer is not available on `main`. For the command line and
ordinary APFS workspaces, use the [source install](../README.md#installation)
on macOS with Python 3.11+, Xcode Command Line Tools, and APFS workspace
storage. These source instructions do not install or enable the FSKit app.

To replace a source install, stop commands using the old environment. Use the
same source-install steps from the desired checkout in a fresh virtual
environment. If you reuse the same checkout, use a different path such as
`.venv-replacement` in the environment creation, install, and activation
commands. Keep the old environment until `command -v sfs` points to the new
environment's `bin/sfs` and `sfs --help` runs successfully.

To remove a source install, stop editors, shells, and other processes using
its workspaces. With the old CLI, run `sfs unmount WORKSPACE_ID` for each
mounted [APFS disk-image workspace](usage.md#disk-image-workspaces) you own.
For a custom store, use the same `STALLIONFS_HOME` setting or run
`sfs --root STORE_PATH unmount WORKSPACE_ID`. If a volume is busy or you cannot
confirm it unmounted, keep the old CLI available until you resolve the mount state.

Before deactivating and removing the old environment, confirm that your stores
are outside it, including the default `~/Library/Application Support/stallionfs`
and any stores selected with `STALLIONFS_HOME` or `--root`. Preserve those stores.

There is no qualified end-user FSKit app upgrade or uninstall procedure on
`main`. For controlled work on an already installed app, follow the
[exact-artifact removal and restoration procedure](fskit-maintenance.md#finite-removal-and-restoration-procedure).
Keep the authenticated recovery archive and every store. Stop all writers
across users and normally unmount each identified owned workspace through the
admitted app while it is intact. Stop if a workspace is busy or its mount state
is uncertain. Quit normally and check the exact extension's selection and
enablement in File System Extensions settings as directed by the procedure.

If the app copy is incomplete or the app and extension have different product
versions or build numbers, preserve the copies and stores until you can verify
the exact installed artifact. The bundled
`sfs command install` and `sfs command remove` only manage the owned
per-user `~/.local/bin/sfs` link, not the app, extension, or workspace data.

## Check your workspace store

Run `sfs doctor` to test APFS cloning and copy-on-write isolation in your
selected store. It reports the store path, Git and Python versions, and any
remaining staging entries.
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
