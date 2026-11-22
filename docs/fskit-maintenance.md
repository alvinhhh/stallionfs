# Exact-artifact maintenance

The same-artifact procedure covers removal, reinstall, interrupted reinstall and restoration
of the exact last independently authorized app at `/Applications/StallionFS.app`.
It preserves stores. It does not authorize an upgrade, downgrade, pending-request
recovery, forced unmount, process termination, registration reset or automatic
replacement. Default packages retain empty `public_upgrade_support`. The separate
cross-version controller below requires an explicit signed exact-pair declaration
and release qualification for the final artifacts.

The implementation supplies a standalone native collector and an external
observer. Same-artifact observation uses only the standard library; populated
cross-version observation additionally uses the independently admitted installed
package's bounded schema validators and read-only hosting identity primitive.
Its parser reports and policy functions are diagnostics, not
a maintenance reservation or execution capability. `maintenance_clearance` and
`store_access_eligible` remain false. Follow this procedure only after the exact
installed qualification rows below pass for the final signed artifact.

## Delivery and independent admission

The fixed resources are `Contents/Resources/Maintenance/observer.py`,
`stallionfs-maintenance`, and `compatibility.json`. The native executable is a
separately signed C leaf, not an extracted app main. No Python, daemon, developer
tool or system scripting runtime is required for its retained collection.

Build the leaf from `filesystem/fskit/maintenance_native.c` with the producer's
selected SDK/architecture and `-std=c11 -Wall -Wextra -Werror -O1`. Production
builds pass no test/fault/cap macros. Hosted unsigned component production now
includes this executable and its source hash. Pass that matching input as
`--maintenance-native` to `tools/package_fskit.py`; runtime assembly requires it.
The assembly receipt pins both C source and input executable and requires exact
inventory mode/readback for the role. A digest does not prove compiler/source
correspondence: retain the matching producer provenance and reviewed inputs.
Existing unsigned components and app candidates without the new role cannot be
relabelled as this build. A changed producer, leaf, observer or packager requires
new matching source/component and assembled-artifact membership evidence.

Sign the standalone role with identifier
`com.alvinhhh.stallionfs.maintenance` before the outer seal. The packager's
`sign_maintenance_leaf` accepts an explicit signer and unsigned input digest,
refuses an already sealed app, and verifies the independent expected publisher.
Sign all other nested code, finalize Git and its generated `runtime.json`, then
seal the outer app.

For direct distribution, submit a separate ZIP for notarization and staple the
accepted ticket to the sealed app. Create a fresh final ZIP after stapling.
Set `FINAL_APP` to the source-matched, admitted physical `StallionFS.app`,
`RELEASE_PARENT` to a caller-exclusive 0700 output directory outside the app,
and `PUBLISHER_TEAM` to the independently selected publisher. Run the command
from the reviewed checkout with a trusted Xcode selected. Keep the input and
working directories local, outside file sync and exclusive to this staging
operation.

```sh
python3 -I -B tools/build_fskit_distribution.py \
  --app "$FINAL_APP" --release-parent "$RELEASE_PARENT" --publisher "$PUBLISHER_TEAM"
```

On success, the printed private directory holds `StallionFS.zip` and
`final-maintenance-bindings.json`. The command checks the exact archive before
extraction and checks the physical extraction against the same binding. It
requires Developer ID Application and validates the stapled ticket on that
extracted app. The ZIP excludes quarantine and provenance transfer metadata.
Other extended attributes, ACLs, and filesystem flags changed by the archive
round trip stop staging. A failed attempt can leave a private ZIP and
verification scratch at the path reported with the error. Use only the
directory reported on success, and retain its archive and bindings together.
Keep corresponding sources and
licenses beside the archive. Installation and qualification of that exact ZIP
remain separate release steps.

`final_maintenance_bindings` verifies the outer app,
extension, leaf and every Mach-O member against the independently expected
publisher, compares the exact app-only ZIP against the final app inventory, and
returns final artifact, descriptor, observer, compatibility and signed-leaf
hashes for external retention. Source/license sidecars stay separate. It does
not establish installation history or STORE authority. Preserve that final
record through a separately authenticated release channel; a candidate's own
resource, a locally calculated hash, or a self-reported publisher is insufficient.
The compatibility resource deliberately contains no final/self hash.

Before launching any installed Python, use trusted system static verification
and the independently retained final record to admit the physical fixed-path
app, its complete inventory, descriptor, interpreter and expected publisher.
Do not run a candidate interpreter or Host to authenticate that candidate. For
`codesign -R`, literal requirements start with `=`; for example the leaf requires
`=anchor apple generic and identifier "com.alvinhhh.stallionfs.maintenance" and certificate leaf[subject.OU] = "4CQS5J4848"`.
Independently check nested publishers; an outer deep signature check alone is
not an assertion that every nested role has the expected publisher.

Retain the admitted observer, leaf, exact app ZIP and release mapping outside
the app in accessible owner-controlled storage before withdrawal. Copy controls
exclusively without following links. The controller requires an existing private
0700 output directory; files are exclusive 0600, copied executable 0700, with
owner/mode/no-ACL checks, immediate readback and held/path identity checks.
It refuses aliases, hardlinks, unsafe ownership/modes and unsupported ACLs.
Do not use an app-local retention directory. Loss of the leaf permits recovery
only from the separately statically admitted exact archive, followed by the same
publisher/byte/ownership checks. Missing trustworthy artifact or publisher
identity stops restoration. Do not extract an arbitrary replacement helper.

## Observation while the app is intact

Prepare the external session authorization from the authenticated final mapping
and independently retained installation history. The schema-1 authorization has
exact `artifact`, `archive`, `inventory`, `roles`, `runtime`, `publisher`, `home`,
`last_installed`, `executable_history`, `store_history`, `store_runtime`, and
`cooperation` fields. `runtime` describes interpreter routing; `store_runtime`
is the separate final Git/descriptor/executable identity used by retained requests.
The independently supplied authorization digest and expected publisher must
match. `cooperation` names the current boot UUID, confirmation time, all covered
UIDs and either `single-user-controlled` or
`all-possible-users-cooperative`. A shared `/Applications` app requires every
possible user's continuous cooperation, or a controlled single-user window;
current-UID inspection cannot stand in for that agreement. Unknown/uncovered
sessions block. An authorization file is not proof that someone actually
stopped their writers; the operator must establish and maintain that condition.

Run the external observer using only the already statically admitted installed
runtime, at the fixed path, with `-I -B -S`:

```text
/Applications/StallionFS.app/Contents/Resources/Runtime/CPython/bin/python3.13 -I -B -S /external/observer.py remove --authorization /external/session.json --authorization-sha256 EXPECTED --publisher 4CQS5J4848 --retain /external/new-observation --root /explicit/store
```

Use `reinstall` or `restore` for those operations. The external directory must
exist and be empty. No product module is imported, no site initialization or
`.pth` processing occurs, and package-resource execution under
`__name__='maintenance_observer_resource'` stays inert.

The observer acquires the account database home/default root, actual literal
`STALLIONFS_HOME`, and every explicit root. It durably publishes `request.json`
before STORE control enumeration, content reads, locks or recovery, and never
replaces its denominator after a failure. Output admission first reads only
path/ancestor metadata to exclude physical app/STORE overlap; unsafe,
unresolvable or overlapping output refuses before any publication, including
`failure.json`.
Relative/hostile or empty environment roots remain visible and refuse rather
than silently falling back. It checks actual interpreter version, ABI,
architecture, GIL build, executable, isolation flags and initial search paths
against independent expectations. It separately verifies static app/nested
role signatures and hashes before collecting stores, and rechecks the full
installed inventory afterward. The original request and separately retained
activity have distinct hashes; native evidence cannot rewrite requested roots.

The leaf's typed `sysctl(KERN_PROC_ALL)` spine includes rows missed by
libproc-only enumeration. `proc_pidpath` supplements those rows, with repeated
PID/start/UID/parent/path checks and a second process snapshot. ENOENT for a
stable live PID is uncertainty, not absence. Only typed PID0/P_SYSTEM evidence
classifies the kernel. Typed mount snapshots and login-session records retain
unknowns, caps, denial, truncation, churn and PID reuse. Relevant helpers,
managed descendants, unknown live paths, unknown FSKit mounts and uncovered
sessions block. An exited collector and complete transport receipt cannot
convert an incomplete native observation into clearance.

The admitted bundled command actions, when their individual step is qualified,
are concrete fixed-path invocations:

```text
/Applications/StallionFS.app/Contents/Resources/Runtime/CLI/bin/sfs --json command status
/Applications/StallionFS.app/Contents/Resources/Runtime/CLI/bin/sfs --json command remove
/Applications/StallionFS.app/Contents/Resources/Runtime/CLI/bin/sfs --json command install
/Applications/StallionFS.app/Contents/Resources/Runtime/CLI/bin/sfs --root /exact/store unmount EXACT_ID
/Applications/StallionFS.app/Contents/MacOS/StallionFS --discover-json
```

Command-link actions precede Store initialization. Unmount is a STORE operation
and belongs before the final baseline. After reinstall, a qualified persistence
trial uses the same explicit root/ID with `mount`, actual read/write/fsync/close,
then ordinary `unmount` and `mount` followed by independent content comparison.
These commands do not bypass pending/history/enablement or installed
qualification gates. Finder app copying/removal and Settings choices remain
manual, with actual outcomes recorded at each step.

Known pending requests stay pending even when their exact original runtime
matches. Exact runtime restoration does not make them terminal. Use only their
separate qualified same-runtime recovery route; keep unknown/mixed mutation
history as a STORE blocker. The observer never initializes, reconciles, purges,
mounts, unmounts, creates locks or reserves a store. Its existing finite
per-root entry/document/control-byte limits and global request/output limits
still apply. Complete enumeration can contain blockers; omitted scope,
revalidation/close errors and serialization limits refuse explicitly.

## Fresh observation without Python

After removal, an interrupted copy or a reboot, use the already admitted
external standalone leaf directly in a **new empty private child of the
previously admitted external retention location**:

```text
/external/stallionfs-maintenance retain /external/new-native-observation
```

The admitted parent must still be physically bound and disjoint from the
original retained root denominator. A missing/changed parent requires separate
metadata-only disjointness admission before collection. The standalone leaf
enforces private transport and fixed-app ancestry exclusion; without the root
history it cannot independently attest STORE disjointness or grant maintenance
authority. Do not substitute an arbitrary private directory.

`retain` forks exactly one owned observer worker. It closes inherited worker
FDs, uses a five-second monotonic deadline and a 16 MiB output cap, drains the
owned pipe, reaps only its own child, and retains `native.json` plus
`native-completion.json`. The worker has an independent alarm if its controller
dies. Timeout/output/I/O/close/binding uncertainty preserves partial output and
refuses. It never signals a saved or unrelated process. Completion is usable
only if the leaf exit is zero, both files read back at the expected private
bindings, the raw output byte count/SHA256 match the retained stream receipt,
completion is true with reaped/EOF/durable/bound/cleanup fields true
and error fields false, the worker outcome is success with returncode zero,
**and** native JSON is complete with no uncertainty.
The collector hashes its bounded stream and performs exact FD byte/hash/size/
mtime/ctime readback before claiming transport completion. An empty/truncated
receipt after interruption is unresolved, not success. The Python controller's
terminal exit/JSON also must confirm its final descriptor closes; a pre-close
observation file alone cannot prove controller cleanup.

Observe a fresh boot UUID and reconfirm cooperation after restart. Previous
mount/process/session/enablement/discovery/link observations are stale. Reacquire
all required observations; a restart does not prove unmount/writeback success.
Any unknown relevant live identity still blocks executable withdrawal/restoration.
The native result and independently retained exact artifact/history allow the
manual software-only route below without asking the missing Python to approve
its own restoration. After restoring software, run the normal observer against
the unchanged original requested roots before any STORE use. If that request is
lost, retain the scope uncertainty and reconstruct it independently; never
silently replace it with the current default alone.

## Finite removal and restoration procedure

1. Retain exact independently authenticated recovery bytes, final mapping,
   original request and current history outside the app. Check complete archive
   extraction, static signatures, fixed path and available copy space. An
   estimate is not a space reservation; disk-full remains an interruption case.
2. Establish the controlled/cooperative all-user window. Finish known helpers
   and managed descendants normally. Resolve only separately supported pending
   work under its exact runtime. Normally unmount each exactly identified owned
   workspace through the admitted app before the final read-only baseline.
   Busy/unknown unmount, unresolved child, pending work, unknown activity or a
   failed root stops removal. Do not purge to make observations green.
3. While static app admission works, inspect/remove only this user's exact owned
   command link through the existing app command action. No link, owned link,
   owned dangling link and foreign file/link are separate states. Preserve
   foreign entries; app-first deletion requires same-artifact restoration before
   the normal owned-link action. Other users manage their own links.
4. Quit normally, use ordinary File System Extensions settings when required,
   and inspect actual selection/enablement separately from app bytes. Repeat
   fresh native/store observation after intended unmount/link/Settings changes.
   Keep all writers stopped. Use Finder Move to Trash only for the exact admitted
   app. Do not empty Trash or remove stores, sidecars or registration globally.
5. For reinstall/restoration, inspect actual target state using the table below.
   Copy only the independently admitted **same exact last artifact** to the
   physical fixed path using Finder. Cancellation, denied authorization,
   disk-full or interruption leaves the result unverified. Preserve all data,
   archives, original scope and observed uncertainty.
6. Before store access, verify the installed full inventory/static signature,
   descriptor and expected nested publishers again. Open only that fixed-path
   app; use ordinary Settings enablement and admitted installed Host discovery.
   Require exact URL/build/team, enabled state and unique supported type.
   Wrong/stale/duplicate/unselected identity stops; no election reset or staging
   copy launch. Reinspect each owned/foreign link separately.
7. Repeat observation over the original denominator. Restore executable
   availability separately from STORE readiness. Keep dormant pending requests
   bound to their exact runtime for qualified recovery. Record the first
   potentially mutating store dispatch externally; unknown dispatch counts as
   potentially mutating. Then perform only the exact artifact's separately
   qualified mount/read/write/persistence procedure.

| Actual state | Required action |
| --- | --- |
| Intact exact app | Keep it; verify bytes and fresh downtime. Finish only supported remaining steps. |
| Absent or partial app | Restore exact same artifact only with independent artifact/publisher authority, known exact last-installed history, no possible newer executable, and fresh complete native downtime. Missing Python is not itself a STORE or software authorization. |
| Intact wrong app | Preserve evidence. Unknown or possibly newer history blocks the same-artifact route; do not select an older archive opportunistically. With independently proven exact history, correct only the known interrupted same-artifact operation. |
| Exact artifact authority survives, root request lost | Software-only restoration may proceed after fresh downtime; STORE scope remains blocked. Do not reduce the original denominator. |
| Leaf lost, exact admitted archive survives | Recover only that archive's statically admitted leaf, then reacquire native evidence. No arbitrary helper fallback. |
| Artifact/publisher identity lost, last version unknown or possible newer execution | Stop; retain app, archives and stores. No restoration/downgrade. |
| Any live/unknown mount, helper, descendant, session or changed binding | Stop and reestablish the cooperative window normally. No force detach, saved-PID signal or assumption that counts imply clearance. |
| Known dormant exact-runtime request | Preserve pending status and original runtime; software restoration does not authorize continuation. |
| Mixed/unknown STORE mutation history | Software-only same-artifact restoration may restore availability; all STORE operations remain blocked pending separately qualified resolution. |
| Removal/reinstall interrupted or rebooted | Record app/link/enablement independently, reacquire every required observation, then resume only the exact supported unfinished step. |

These observations are cooperative snapshots. They cannot exclude arbitrary
future writers or atomically prevent a same-user replacement between checks and
Finder actions. New work, another session, reboot or any relevant binding change
invalidates the gate. Maintain cooperation throughout; repeat observation after
reaching a known state. No boolean or caller-supplied empty activity list grants
clearance.

## Remaining installed qualification

| Required final-artifact case | Proof still required |
| --- | --- |
| Native producer/platform | SDK27 production build, final Developer ID nested+outer signatures, copied-leaf publisher verification, ARM64 and Intel paths independently. Current SDK26.2/ad-hoc owned fixtures are not this proof. |
| Installed bootstrap | Exact fixed-path installed CPython flags/ABI/search path; hostile environment, wrong publisher, stale descriptor, external tamper and import-side-effect refusal. Copied-runtime evidence does not cover removal/reinstall. |
| Normal removal/reinstall | Actual fixed-path Finder withdrawal and same-artifact reinstall; owned/no/dangling/foreign links and ordinary Settings/discovery results; preserve every requested store and external reference. |
| Interruption/control loss | Cancel/denied authorization/disk full/partial copy, missing interpreter/leaf/request, controller death and reboot; fresh native evidence and same-artifact software-only recovery without reducing STORE scope. |
| Real filesystem behavior | Normal unmount/remount and actual read/write/fsync/close/rename persistence with final signed artifact, including admitted namespace/metadata policy and lifecycle checks. |
| Read-only metadata | Existing Documents ctime drift remains unresolved, including snapshot-only drift. Nonempty control ACLs remain unsupported. No fixture substitution or waiver closes these cases. |
| Upgrade | A separately tested actual predecessor/candidate pair and its interruption/recovery paths. Public support remains empty until that proof exists. |

Current host observation includes persistent live process paths that remain
unavailable. The implemented refusal stays in place; neither native counts nor
synthetic tests establish normal-host maintenance clearance.

## Cross-version upgrade controller

`observer.py upgrade` retains a cross-version transaction and issues one manual
step at a time. It never copies, deletes or launches an app, changes Settings,
manages registrations, or mutates a store. Its output is a next step under the
continuing cooperative window; `maintenance_clearance` and
`store_access_eligible` remain false. Installation, selection and actual mounted
persistence are separately checked outcomes.

A schema-2 compatibility resource declares the exact predecessor's complete
final inventory ID and descriptor SHA256, plus the candidate build/source ID,
observer SHA256, runtime and parser contracts. Schema-1 resources remain readable
but do not authorize this route. Version ranges, descriptor equality alone, and
same-publisher equality do not admit another predecessor. Declare the pair before
signing, then qualify that exact finished signed artifact. Publish its unchanged
authenticated release mapping only after qualification; there is no runtime
`qualified` flag or separate test-result authentication mechanism.

Before running the external controller, independently admit both release mappings
and statically verify the candidate observer and the selected **installed**
runtime. The controller is the candidate's signed observer retained externally;
it need not equal the predecessor observer. Prepare/publication use the admitted
predecessor at the fixed path. After publication, verification uses the admitted
candidate at that same path. Never execute a staged candidate to authenticate it.
The current runtime artifact identity is supplied independently in each session
and must match the complete installed inventory before runtime and store checks.
Runtime routing checks cannot authenticate an interpreter already loaded before
the required static checks.

Populated stores are inspected through held, no-follow descriptors. Recognized
folder and sparseimage seeds/workspaces retain their payloads without traversal
or image interpretation. Native workspaces require matching creation and install
lineage, binding, hosting volume UUID/file identities, lifecycle, terminal operation
archive and absent-mount evidence. Schema-2 bindings also require their exact
reconciliation receipt and scope. A lifecycle status of `open` alone does not
mean an active mount. Unknown entries, pending operations, orphan lifecycle
records, moved/device-translated identities and unrecognized layouts block the
handoff. Cooperative downtime and the fresh native activity snapshot remain
mandatory; schema recognition is not a reservation against other writers.
Open or closed native lifecycle records may retain a `native_idle` baseline.
Its generation, held target, timestamp, anchor and consumed guard must agree;
the baseline may be historically stale and never replaces the independent
terminal archive, absent-mount evidence or fresh downtime checks.

Sparseimage admission additionally captures `/usr/bin/hdiutil info -plist` with
the existing bounded inspection collector (30 seconds, 2 MiB, EOF, reaped child,
durable output/readback and a fresh request/boot binding). **Every attached disk
image blocks sparseimage admission**, including unrelated images and attachments
without a mounted volume. Reported image paths are never followed to guess alias
equivalence. Use an extracted ZIP candidate; a mounted installer DMG also blocks
this check. The controller never detaches an image. Failed, stale, malformed or
incomplete inspection remains a blocker.

The controller imports a fixed module closure only from the fully inventoried,
publisher-verified installed package. It checks every source/extension hash,
compiles source bytes without accepting cached bytecode, rejects ambient product
imports and does not add site/user/staged-candidate search paths. Store constructors,
resolution/recovery routines and native backing operations are not called. The
only package-native primitive used is `hosting_identity` on already held directory
and image descriptors; it reads host metadata and is rechecked before descriptor
release. The old installed package supplies these validators before publication;
the candidate installed package supplies them afterward. A missing API blocks
the operation and never selects an alternate package or interpreter.

The independently SHA256-pinned schema-2 session object has exactly:

| Field | Value |
| --- | --- |
| `schema`, `kind` | `2`, `upgrade-session` |
| `old`, `candidate` | Exact `final_maintenance_bindings` mappings with complete inventory/signing roles and archive digest; candidate requires `build`. A legacy predecessor mapping may omit `build` as described below. Resolve archive locations to admitted absolute external paths. |
| `controller` | Candidate `artifact_id` and `observer_sha256`. |
| `runtime_artifact_id` | Exact independently admitted installed predecessor or candidate artifact ID for this invocation. |
| `home`, `cooperation` | Account database home and the existing explicit all-user/cooperative window contract. |
| `history` | `request_sha256`, `previous_step_sha256`, `last_installed`, `candidate_access` (`none`, `possible`, `unknown`), `continuous_downtime` (boolean). |

For preparation, both history digests are null, last installed is the exact
predecessor, access is `none`, and downtime is continuously established. These
are independently established history assertions, not facts inferred from an
empty journal. For continuation, use the returned request and step digests in a
fresh independently admitted session with current history/cooperation. The app
bindings, original root denominator and baseline stay unchanged. Test reports
are retained release evidence, not fields added to this session.

Older schema-1 final mappings did not contain `build`. Preserve that exact old
mapping and signed app. After its full historical inventory, nested publishers
and descriptor/resource hashes pass, derive the predecessor build from its own
Info.plist and runtime descriptor. Require their versions, fixed bundle ID,
source ID in the independently admitted store runtime, and signed compatibility
resource to agree. Retain the derived build in that attempt without enriching
or changing the original mapping. Missing or conflicting old metadata refuses;
candidate build metadata cannot substitute for it. The candidate mapping still
requires an explicit independently admitted build.

Use the existing trusted static admission before each command. The argument
paths below are placeholders for independently admitted absolute paths:

```text
/Applications/StallionFS.app/Contents/Resources/Runtime/CPython/bin/python3.13 -I -B -S /external/observer.py upgrade --phase prepare --candidate-app /external/candidate/StallionFS.app --authorization /external/session.json --authorization-sha256 EXPECTED --publisher 4CQS5J4848 --retain /external/upgrade --root /exact/store
```

`prepare` requires an empty private external `0700` transaction directory and an
intact exact predecessor. It retains the original literal roots/reasons,
environment/default contract, both artifacts/archives, controller and history
before reading store controls. Candidate/archive locations must be outside
stores; archives must also be outside the installed and staged apps. The
baseline records every requested root's physical identity or admitted absent
default. Duplicate aliases remain separate requested rows. Pending work,
unknown activity, incomplete roots, unsafe paths or cleanup uncertainty stop.

Repeat the command with the same transaction directory, explicit roots and an
updated admitted session, selecting one phase:

| Phase | Result |
| --- | --- |
| `publish` | Recheck both admitted artifacts, full original root coverage, continuous original cooperation and fresh native downtime. Durably record possible candidate exposure **before** returning the Finder instruction to preserve the predecessor and install the exact candidate. |
| `verify` | Require the actual fixed-path candidate, its full inventory/signatures, declared pair and candidate runtime. Reobserve the original roots before the ordinary Settings/discovery/link verification handoff. This does not assert those manual steps succeeded. |
| `resume` | Inspect actual installed bytes and the bound journal/history. An intact predecessor after possible/unknown exposure yields exact-candidate repair. An intact candidate with unknown last-installed/access history or an unclosed attempt yields software-only verification, without the Settings/discovery handoff. Foreign or unresolved artifacts stop. |
| `rollback` | Before any exposure handoff, require positive complete baseline/current root evidence and unchanged uninterrupted cooperation/history. Keep the intact exact predecessor. This bounded route does not restore an older app after publication. |

Each invocation retains its own signature/activity/observation attempt. Steps
are exclusive, fsynced and read back, with the original request, baseline and
previous-step digests. These digests hash the exact canonical retained JSON bytes
including their final newline, so native `openssl dgst -sha256` can compare them
without Python. Partial/torn records are preserved and block continuation;
no step is silently discarded. A lost response after the exposure record was
written still counts as possible exposure. A stale external continuation digest
stops; inspect and independently reconcile retained history before supplying a
new digest. Record absence alone never proves that candidate code did not run.
Changed default/environment roots, dropped/added explicit roots, changed physical
identities and newly appearing absent-default roots stop instead of rebasing.

Every durably created attempt directory must be accounted for. Only its committed
step closes an attempt. An unreferenced attempt, including controller death before
the exposure record, is preserved and makes access unknown; it cannot silently
inherit the earlier prepared step's continuity. Such a transaction cannot issue
initial publication or predecessor rollback. Fresh complete admission may still
permit exact-candidate software repair. Unknown last-installed history likewise
cannot issue first publication or normal candidate verification; a claimed prior
candidate installation cannot be interpreted as an unexposed predecessor merely
because the actual current app is the predecessor.

Publication, enablement or a possible launch makes this transaction candidate-only
for software repair. An unknown launch/history interval or broken cooperative
window cannot regain predecessor rollback. Restoring an old app after candidate
STORE access needs a separately qualified reverse transition; it is not provided
by this forward controller. Preserve the old app/archive, candidate, partial
copies, records, every store and foreign command links throughout.

If installed Python is absent or partial, this Python controller cannot run.
Use the native/static no-Python procedure below with the exact independently
authorized **candidate** and fresh complete downtime to restore software
availability only. The original scope and all STORE restrictions remain. Do not
substitute predecessor restoration, a relocated Python or a source interpreter.
If exact candidate history/authority, static verification or native downtime is
unavailable, stop and preserve everything. After candidate restoration, verify
the full fixed-path inventory and nested signatures before launching its Python
and this externally admitted controller. Foreign/uncertain installed contents
need independently resolved history; do not overwrite them opportunistically.

Release qualification must exercise the real predecessor-to-candidate path,
normal unmount/remount, cross-version content and admitted metadata persistence,
cancelled/partial publication, controller death and reboot recovery. Source
tests exercise inert app/store bytes and retained transaction I/O with controlled
signature/runtime/activity adapters; they do not qualify installed replacement,
FSKit selection, or user-data persistence. No historical private metadata trial
is converted into a compatibility waiver or a universal writer-proof requirement.

## No-Python admission and decision commands

Use this branch only to restore executable availability. It is an intermediate
software-only checkpoint for the manual procedure above; it never opens a store.
Native activity checks do not decide artifact history or human cooperation.

Before executing the retained leaf, verify the external release record's bytes
against its independently authenticated expected SHA256, then the exact archive
against that record. Use native `/usr/bin/openssl`, not interpreter scripts such
as `shasum`. The following paths are examples to substitute from the retained
record. Every parent must be physically admitted first: inspect each component
with `/bin/ls -lde` and `/usr/bin/stat -f '%d:%i %u:%Lp %HT'`; require no symlink,
expected owner (root or this UID), no group/other writes, no unsupported ACL, and
match the retained external parent's device/inode. The external root itself is
private 0700. A missing/changed parent requires fresh metadata-only disjointness
admission against the original roots, not an arbitrary new private directory.

```sh
set -eu
RELEASE=/external/final-release.json
ARCHIVE=/external/exact-app.zip
EXPECTED_RELEASE_SHA=INDEPENDENTLY_AUTHENTICATED_64_HEX_DIGEST
line=$(/usr/bin/openssl dgst -sha256 -r "$RELEASE")
[ "${line%% *}" = "$EXPECTED_RELEASE_SHA" ]
line=$(/usr/bin/openssl dgst -sha256 -r "$ARCHIVE")
[ "${line%% *}" = "$(/usr/bin/plutil -extract archive.sha256 raw -expect string "$RELEASE")" ]
/bin/mkdir -m 700 /external/new-extraction
/usr/bin/ditto -x -k "$ARCHIVE" /external/new-extraction
STAGED=/external/new-extraction/StallionFS.app
[ ! -L "$STAGED" ]
[ "$(/usr/bin/stat -f '%Lp' "$STAGED")" = 755 ]
count=$(/usr/bin/plutil -extract signing_roles raw -expect array "$RELEASE")
[ "$count" -gt 2 ]
i=0
while [ "$i" -lt "$count" ]; do
  code=$(/usr/bin/plutil -extract "signing_roles.$i.path" raw -expect string "$RELEASE")
  requirement=$(/usr/bin/plutil -extract "signing_roles.$i.requirement" raw -expect string "$RELEASE")
  /usr/bin/codesign --verify --deep --strict -R "$requirement" "$STAGED/$code"
  i=$((i+1))
done
```

The authenticated mapping's `signing_roles` is generated by final packaging:
outer app, extension, standalone leaf and every Mach-O role, each verified
against the independent expected publisher. A candidate does not supply this
trusted mapping. The archive check binds the exact complete signed app inventory,
including empty directories, file/link types and modes; extraction is from those
already admitted bytes into a fresh private location. Repeat static checks on the
installed fixed path before launching its Python or Host. For a broken installed
app, never run that broken runtime to make these decisions.

Recover a missing external leaf only from the above admitted archive. Copy that
one fixed role exclusively into the already admitted external location, then
check its expected bytes and standalone signature before launch:

```sh
set -eu
LEAF=/external/stallionfs-maintenance
(umask 077; set -C; /bin/cat "$STAGED/Contents/Resources/Maintenance/stallionfs-maintenance" > "$LEAF")
/bin/chmod 700 "$LEAF"
[ ! -L "$LEAF" ]
[ "$(/usr/bin/stat -f '%u:%Lp:%l' "$LEAF")" = "$(/usr/bin/id -u):700:1" ]
/bin/ls -le "$LEAF"
line=$(/usr/bin/openssl dgst -sha256 -r "$LEAF")
[ "${line%% *}" = "$(/usr/bin/plutil -extract artifact.native_sha256 raw -expect string "$RELEASE")" ]
/usr/bin/codesign --verify --strict -R '=anchor apple generic and identifier "com.alvinhhh.stallionfs.maintenance" and certificate leaf[subject.OU] = "4CQS5J4848"' "$LEAF"
```

Require no ACL entries in that small `ls` output. If an external leaf already
exists, do not overwrite it: inspect its existing owner/mode/link/ACL/hash and
signature using the same checks, or use a fresh exclusively created control
name. Only the independently admitted exact leaf may execute.

The following is the actual finite native activity decision command block.
Set `LEAF`, `RETAIN_PARENT`, `OBSERVATION`, and `EXPECTED_PARENT_ID` to the admitted
external leaf, its admitted parent, a **new** child directory, and that parent's
retained `device:inode`. It creates no app/store file. Run it immediately after
all possible users establish/reconfirm the current maintenance window. It has
no hundreds-row manual classification step: the native summary is derived from
the same acquired typed rows, excludes only its stable exact own worker/controller
identities and paths, computes recursive helper descendants, and blocks other
UID sessions or account-lookup uncertainty. No login rows do not prove human
cooperation. All possible users must continue to cooperate, including users
without an active login record.

<!-- native-activity-decision -->
```sh
set -eu
: "${LEAF:?}" "${RETAIN_PARENT:?}" "${OBSERVATION:?}" "${EXPECTED_PARENT_ID:?}"
[ "$(/usr/bin/stat -f '%d:%i' "$RETAIN_PARENT")" = "$EXPECTED_PARENT_ID" ]
[ "$(/usr/bin/stat -f '%u:%Lp' "$RETAIN_PARENT")" = "$(/usr/bin/id -u):700" ]
[ "$(/usr/bin/dirname "$OBSERVATION")" = "$RETAIN_PARENT" ]
/bin/mkdir -m 700 "$OBSERVATION"
if "$LEAF" retain "$OBSERVATION"; then leaf_exit=0; else leaf_exit=$?; fi
[ "$leaf_exit" = 0 ]
C="$OBSERVATION/native-completion.json"
R="$OBSERVATION/native.json"
value() { /usr/bin/plutil -extract "$1" raw -expect "$2" "$3"; }
for file in "$C" "$R"; do
  [ ! -L "$file" ]
  [ "$(/usr/bin/stat -f '%u:%Lp:%l' "$file")" = "$(/usr/bin/id -u):600:1" ]
done
[ "$(value schema integer "$C")" = 1 ]
for flag in complete reaped streams_eof output_readback output_durable directory_bound output_bound cleanup_complete; do
  [ "$(value "$flag" bool "$C")" = true ]
done
for flag in io_error close_errors; do [ "$(value "$flag" bool "$C")" = false ]; done
[ "$(value returncode integer "$C")" = 0 ]
[ "$(value outcome string "$C")" = success ]
[ "$(/usr/bin/stat -f '%z' "$R")" = "$(value output_bytes integer "$C")" ]
line=$(/usr/bin/openssl dgst -sha256 -r "$R")
[ "${line%% *}" = "$(value output_sha256 string "$C")" ]
[ "$(value schema integer "$R")" = 1 ]
[ "$(value scope string "$R")" = global-kernel-snapshot ]
[ "$(value complete bool "$R")" = true ]
[ "$(value uncertainties array "$R")" = 0 ]
[ "$(value processes array "$R")" -gt 0 ]
[ "$(value activity.scope string "$R")" = global-cooperative-snapshot ]
[ "$(value activity.clear_at_observation bool "$R")" = true ]
for count in helpers descendants mounts other_user_sessions; do
  [ "$(value "activity.$count" integer "$R")" = 0 ]
done
[ "$(/usr/sbin/sysctl -n kern.bootsessionuuid)" = "$(value boot_id string "$R")" ]
[ "$(/usr/bin/stat -f '%d:%i' "$RETAIN_PARENT")" = "$EXPECTED_PARENT_ID" ]
printf '%s\n' 'Native activity checks passed'
```

A nonzero command status, lookup/denial/timeout, changed binding, missing output,
current-boot mismatch, known helper/descendant/mount or another UID session means
**stop before Finder replacement**. Keep both files and partial receipts. The
same native snapshot can be complete with an active helper or mount: the summary
must independently pass. Native `clear_at_observation` is a diagnostic snapshot,
not authorization. The current host's unknown live paths still prevent passage.

After this command passes, inspect only the small independent history/cooperation
packet: (1) authenticated artifact/publisher identity survives; (2) last installed
artifact is exactly that record's artifact ID; (3) there is no possible newer or
unknown executable history; (4) all possible users have reconfirmed the current
window/boot and remain stopped; (5) original root request and STORE uncertainties
are preserved, even if unavailable. If any of1-4 is missing, stop; do not choose
an older archive. A lost request in5 can permit **software-only** restoration,
but never STORE access or silent scope reduction. Unknown/mixed STORE mutation
history similarly stays blocked while exact software availability can be restored.

For an interrupted declared upgrade, replace the same-artifact history conditions
2 and 3 with the independently admitted upgrade session and its exact candidate
release mapping: verify the original request and latest step byte digests against
the retained independent pins; preserve the candidate-only exposure/history
classification; exclude any executable outside the admitted predecessor/candidate
pair. Admit the schema-2 pair and current candidate runtime selection from the
retained authenticated release/session packet before the native procedure. This
manual software-only branch may repair only that candidate, never the predecessor.
A missing/torn transaction, unavailable pins, foreign/unknown executable identity,
or inability to establish this limited history stops; no current Python policy
result is invented. Unknown STORE mutations within the admitted pair still block
STORE access. All native/static checks, fresh cooperation and original-scope
preservation remain mandatory.

Only after every applicable check passes may Finder copy the statically admitted
`STAGED` app to `/Applications/StallionFS.app` for the exact absent/partial/known
interrupted same-artifact case or the admitted candidate-only upgrade repair
above. Record cancellation/denial/space/copy failure as
an interruption and reacquire before retry. An intact-wrong target with unknown
or possibly newer history stops. Once installed bytes/static roles and ordinary
Settings/discovery pass, run the restored admitted observer over the original
roots; keep exact dormant requests pending for separately qualified recovery.
Reboot or resumed work at any point invalidates the snapshot and requires the
whole fresh activity/boot/cooperation check again.

The owned native fixture tests compile the same retained collector with test-only
fixed typed snapshots, then execute the exact command block above: a positive
snapshot passes; active helper plus descendant, active mount, unknown path,
and other-account session snapshots fail. Additional native tests exercise
truncation, wrong bytes/receipt, deadline, controller loss and close uncertainty.
These are executable no-Python decision tests, not final publisher/installed proof.

## Exact installed layout before any runtime launch

Publisher equality alone is insufficient: another intact same-publisher artifact
must not run in place of the admitted exact artifact. Generate a physical native
`mtree` specification from `STAGED` **after** its archive hash and all static role
checks above. `mtree` on the qualification host supports `sha256digest`; an OS
without that keyword must stop, never substitute a weaker digest. Use a fresh
specification path under the admitted external control parent. Set
`APP_TO_CHECK=/Applications/StallionFS.app` for the actual installed comparison.
Admit all physical parent components first as described above; the target must
be an ordinary directory at that exact fixed path, never an alias/translocation.

<!-- exact-layout-decision -->
```sh
set -eu
: "${STAGED:?}" "${APP_TO_CHECK:?}" "${LAYOUT_SPEC:?}"
[ ! -L "$STAGED" ]
[ ! -L "$APP_TO_CHECK" ]
[ -d "$APP_TO_CHECK" ]
[ "$(/usr/bin/stat -f '%Lp' "$STAGED")" = 755 ]
[ "$(/usr/bin/stat -f '%Lp' "$APP_TO_CHECK")" = 755 ]
(umask 077; set -C; /usr/sbin/mtree -c -P -k type,mode,link,sha256digest,acldigest -p "$STAGED" > "$LAYOUT_SPEC")
comparison=$(/usr/sbin/mtree -P -p "$APP_TO_CHECK" -f "$LAYOUT_SPEC")
[ -z "$comparison" ]
bad=$(/usr/bin/find -P "$APP_TO_CHECK" \( ! -uid 0 -a ! -uid "$(/usr/bin/id -u)" \) -print -quit)
[ -z "$bad" ]
bad=$(/usr/bin/find -P "$APP_TO_CHECK" -type f -links +1 -print -quit)
[ -z "$bad" ]
printf '%s\n' 'Exact app layout checks passed'
```

These are physical, read-only checks of every file/type/mode/link/SHA256/ACL and
all entries, including empty directories. Missing/extra entry reporting stays enabled. Require both a zero command
status and empty comparison output: this native mtree can report an extra entry
while returning zero, so its exit status alone is insufficient. Never add update/remove/ignore flags (`-u`, `-U`, `-r`, `-e`, `-w`)
or follow-link `-L`. A mismatch, inaccessible member, wrong owner, hardlink,
missing/extra member or changed descriptor/interpreter stops before executing
any installed code. Independently repeat the trusted release record's static
publisher-role loop with `STAGED` replaced by the admitted fixed installed path.
Only after **both** exact layout and static role checks pass may the installed
interpreter or Host run. They authenticate no part of their own bootstrap.

For missing/broken-app restoration, the admitted staged artifact can be copied
without executing its Python. Apply the exact-layout and static-role checks to
the installed result before any restored runtime launches. This step precedes
the fresh native activity snapshot, so thousands of file hashes do not consume
that snapshot's freshness window. Later binding changes invalidate both steps;
maintain the cooperative window and repeat after an interruption or restart.
The owned fixture tests execute this exact native `mtree`/`find` block for the
positive layout and changed bytes/mode/link/type, missing empty directory,
extra entry and hardlink refusals. No Documents metadata waiver is implied.
