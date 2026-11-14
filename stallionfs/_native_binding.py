"""Persistent hosting identity; historical receipts keep their original targets."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from . import core, _native, _scan, _bundle, _native_interval, _native_reconcile, _native_recovery
from ._native_create_recovery import Admission, require, pair, safe, semantic

NAME = 'native-binding.json'
KEYS = {'schema', 'epoch', 'authority', 'workspace', 'transaction', 'historical',
        'origin_target', 'stable', 'admitted_target', 'anchor', 'guard', 'complete', 'publication_file_id'}


def historical_target(path, metadata):
    old = metadata['native_image']
    return {'directory': str(path), 'component': 'image.sfs', 'parent': old['object'],
            'file': old['file'], 'uuid': old['uuid']}


def evidence(a, path, metadata):
    """Only immutable installation fields enter this digest; first use is mutable."""
    from ._native_create_recovery import origin_metadata, installed_metadata, install_proof
    created = a.read(path / 'native-create.json')
    origin = metadata.get('origin')
    require(type(origin) is dict, 'missing-origin')
    origin_metadata(origin, created)
    expected = dict(installed_metadata(origin, metadata['native_image']['parent'],
                                      metadata.get('controller_profile'), metadata.get('native_host')), state='installed')
    require(semantic(metadata) == expected, 'installed-metadata-mismatch')
    proof = a.read(path / 'native-install.json')
    install_proof(proof, expected, historical_target(path, metadata))
    return fingerprint(origin, created, proof), proof


def fingerprint(origin, created, proof):
    value = {'origin': origin, 'creation': created,
             'installation': {k: proof[k] for k in ('operation', 'id', 'transaction', 'target',
                                                  'complete', 'guard', 'previous_installation')}}
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


@contextlib.contextmanager
def descriptors(a, path, metadata):
    require(path.resolve() == path and path.name == metadata['id']
            and path.parent in (a.root / 'workspaces', a.root / 'trash'), 'binding-location')
    collection = a.directory(a.root / 'workspaces')
    a.directory(path.parent)
    directory = a.directory(path)
    fd = os.open('image.sfs', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        initial = os.fstat(fd)
        def stamp(info):
            return (pair(info), info.st_uid, info.st_gid, info.st_mode, info.st_nlink,
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        def observe():
            a.check()
            infos = [os.fstat(n) for n in (collection, directory, fd)]
            named = os.stat('image.sfs', dir_fd=directory, follow_symlinks=False)
            require(safe(infos[2]) and stat.S_ISREG(infos[2].st_mode)
                    and stamp(infos[2]) == stamp(initial) and stamp(infos[2]) == stamp(named) and infos[2].st_dev == infos[0].st_dev == infos[1].st_dev,
                    'backing-substitution')
            identities = [_scan.hosting_identity(n) for n in (collection, directory, fd)]
            for identity, info in zip(identities, infos):
                require(type(identity) is dict and set(identity) == {'volume_uuid', 'file_id'}
                        and type(identity['volume_uuid']) is str
                        and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', identity['volume_uuid'])
                        and uuid.UUID(identity['volume_uuid']).int != 0
                        and type(identity['file_id']) is int and 0 < identity['file_id'] < 1 << 64
                        and identity['file_id'] == info.st_ino, 'invalid-hosting-identity')
            require(len({i['volume_uuid'] for i in identities}) == 1, 'hosting-volume-mismatch')
            old = metadata['native_image']
            require([i['file_id'] for i in identities] == [old[k][1] for k in ('parent', 'object', 'file')],
                    'hosting-file-id-mismatch')
            stable = {'volume_uuid': identities[0]['volume_uuid'],
                      'collection': identities[0]['file_id'], 'object': identities[1]['file_id'],
                      'file': identities[2]['file_id']}
            target = {'directory': str(path), 'component': 'image.sfs', 'parent': pair(infos[1]),
                      'file': pair(infos[2]), 'uuid': old['uuid']}
            return stable, target
        stable, target = observe()
        yield stable, target, observe
        require(observe() == (stable, target), 'hosting-binding-changed')
    finally:
        os.close(fd)


def completed_operation(record, path, metadata, name):
    """Admit archived terminal evidence against its own historical target."""
    from . import _native_recovery as recovery
    require(record.get('workspace') == path.name and record.get('id') == name
            and record.get('outcome') == 'complete' and record.get('child_pending') is False,
            'binding-unresolved-resources')
    target = core.native_target({'ownership': 'external-reference', 'native_image': record.get('target')})
    old = metadata['native_image']
    require(target['directory'] == str(path) and target['component'] == 'image.sfs'
            and target['uuid'] == old['uuid'] and target['parent'][1] == old['object'][1]
            and target['file'][1] == old['file'][1] and target['parent'][0] == target['file'][0],
            'binding-operation-target')
    action = record.get('operation')
    if action in recovery.CATALOG:
        recovery.validate_intent(path.name, record)
        result = record.get('native_image_result')
        mutation = action != 'native-catalog-observe'
        require(record.get('bridge_attempted') is True and type(result) is dict,
                'binding-operation-incomplete')
        require(result.get('ok') is True and result.get('operation') == {
                    'native-catalog-observe': 'snapshots', 'native-snapshot': 'snapshot',
                    'native-restore': 'restore'}[action]
                and result.get('committed') is mutation and result.get('commit_attempted') is mutation
                and result.get('outcome') == ('committed' if mutation else 'not_committed')
                and result.get('close_attempted') is True and result.get('abort_attempted') is False
                and all(type(result.get(k)) is int and result[k] == 0
                        for k in ('error_code', 'guard_close_errno', 'path_errno'))
                and result.get('interrupted') is False and result.get('deadline_expired') is False
                and result.get('response_complete', True) is True
                and result.get('snapshot') == record.get('name')
                and result.get('recovery') == record.get('recovery_name'), 'binding-operation-incomplete')
        receipt, closed = result.get('receipt'), result.get('close_receipt')
        require(type(receipt) is dict and type(closed) is dict, 'binding-operation-incomplete')
        anchor = {k: receipt.get(k) for k in ('generation', 'committed_end', 'root_digest')}
        require(recovery._valid_anchor(anchor) and all(
            type(row.get('status')) is int and row['status'] == 0
            and row.get('poisoned') is False and row.get('transaction_active') is False
            and [row.get('device'), row.get('inode')] == target['file'] and row.get('uuid') == target['uuid']
            and all(row.get(k) == v for k, v in anchor.items()) for row in (receipt, closed)),
            'binding-operation-incomplete')
    elif action in recovery.COMPOUND:
        recovery.validate_compound(path.name, record)
        _native.check_helpers(record, {'verify-package', 'discover', 'unmount', 'mount'})
        require(all(h.get('outcome') in ('success', 'error', 'not-launched') for h in record['helpers']),
                'binding-operation-incomplete')
        # Its catalog transaction has the same bridge receipt contract as an
        # offline operation. Validate those bytes without changing the archive.
        completed_operation(dict(record, operation='native-snapshot' if action == recovery.COMPOUND[0]
                                 else 'native-restore', helpers=[]), path, metadata, name)
        require(recovery._confirmed_bridge(record) and record['phase'] == 'final-verified',
                'binding-operation-incomplete')
        row = record['final_evidence']['observation']
        if record['originally_mounted']:
            require(recovery._mount_completion_evidence(record, row), 'binding-operation-incomplete')
            last = len(record['remount_attempts']) - 1
            require(any(h.get('stage') == 'remount' and h.get('attempt') == last and h.get('label') == 'mount'
                        and h.get('outcome') == 'success' and h.get('returncode') == 0 for h in record['helpers']),
                    'binding-operation-incomplete')
        else:
            require(row is None, 'binding-operation-incomplete')
    elif action in ('native-mount', 'native-unmount'):
        _native.check_pending(path.name, record)
        require(_native._consumed(record.get('current_guard'), target)
                and 'observed_mount' in record, 'binding-operation-incomplete')
        helpers = record['helpers']
        require(all(h.get('outcome') == 'success' and h.get('returncode') == 0 for h in helpers),
                'binding-operation-incomplete')
        if action == 'native-mount':
            require(record.get('mount_attempted') is True and type(record['observed_mount']) is dict
                    and [h['label'] for h in helpers] == ['verify-package', 'discover', 'mount'],
                    'binding-operation-incomplete')
        else:
            require(record['observed_mount'] is None and (
                record.get('already_absent') is True and record.get('before_mount') is None and helpers == []
                or type(record.get('before_mount')) is dict and [h['label'] for h in helpers] == ['unmount']),
                'binding-operation-incomplete')
    else:
        require(False, 'binding-unresolved-resources')


def exclusions(store, a, path, metadata, *, reconciliation=None):
    """No stale ownership or mount evidence can authorize a new epoch/translation."""
    require(path.parent == a.root / 'workspaces', 'binding-moved')
    require(not a.exists(a.root / 'journals' / (path.name + '.json')), 'binding-pending-operation')
    require(not a.exists(path / 'native-location.json'), 'binding-moved')
    for parent in ('protected', 'trash'):
        require(not os.path.lexists(a.root / parent / (path.name + ('.json' if parent == 'protected' else ''))),
                'binding-retirement')
    store._no_mounts(path)
    require(not a.names(path / 'volume'), 'occupied-volume')
    from ._native_interval import load
    if reconciliation is not None and reconciliation.get('complete') is True:
        from ._native_reconcile import validate_scope
        validate_scope(a, path, metadata, reconciliation)
    records = load(a, path)
    mounted = a.read(path / 'native-mount.json') if a.exists(path / 'native-mount.json') else None
    proof = a.read(path / 'native-install.json')
    return archive_anchor(records, path, metadata, mounted, proof, reconciliation=reconciliation)


def _same_evidence(left, right):
    """Compare full JSON evidence without Python's numeric type coercion."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(_same_evidence(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(_same_evidence(a, b) for a, b in zip(left, right))
    return left == right


def _pair_guard(receipt, target):
    """Validate each exceptional close independently before comparing witnesses."""
    from ._native_recovery import _valid_anchor
    require(type(receipt) is dict, 'binding-resolution-guard')
    anchor = {k: receipt.get(k) for k in ('generation', 'committed_end', 'root_digest')}
    require(_valid_anchor(anchor) and type(receipt.get('uuid')) is str
            and all(type(receipt.get(k)) is int and receipt[k] == 0
                    for k in ('status', 'parent_close_errno'))
            and all(type(receipt.get(k)) is int and 0 <= receipt[k] < 1 << 64
                    for k in ('device', 'inode'))
            and ('physical_end' not in receipt or type(receipt['physical_end']) is int
                 and receipt['committed_end'] <= receipt['physical_end'] < 1 << 64)
            and _native._consumed(receipt, target), 'binding-resolution-guard')



def _chain_observation(row, path, metadata):
    """Return only independently typed mount authority, never source text."""
    if row is None:
        return None
    profile = metadata.get('controller_profile')
    require(type(profile) is str and profile in _native.PROFILES, 'binding-operation-profile')
    require(type(row) is dict and type(row.get('path')) is str
            and row['path'] == str(path / 'volume')
            and type(row.get('filesystem')) is str
            and row['filesystem'] == _native.PROFILES[profile]['type']
            and type(row.get('owner')) is int and row['owner'] == os.getuid()
            and type(row.get('flags')) is int
            and type(row.get('fsid')) is list and len(row['fsid']) == 2
            and all(type(n) is int for n in row['fsid'])
            and row.get('readonly') is False and row.get('ignore_ownership') is False,
            'binding-resolution-observation')
    return {key: row[key] for key in ('path', 'filesystem', 'owner', 'flags', 'fsid')}


def _chain_member(record, path, metadata, name):
    """Validate an ordinary exceptional member without changing its outcome."""
    require(record.get('id') == name and record.get('workspace') == path.name
            and record.get('outcome') in ('incomplete', 'complete')
            and record.get('operation') in ('native-mount', 'native-unmount')
            and not any(k in record for k in ('observation_error', 'receipt_error'))
            and ('protocol' not in record or type(record['protocol']) is int
                 and record['protocol'] in (2, 3)), 'binding-unresolved-resources')
    _native.check_pending(path.name, record)
    target = core.native_target({'ownership': 'external-reference', 'native_image': record.get('target')})
    old = metadata['native_image']
    require(target['directory'] == str(path) and target['component'] == 'image.sfs'
            and target['uuid'] == old['uuid'] and target['parent'][1] == old['object'][1]
            and target['file'][1] == old['file'][1] and target['parent'][0] == target['file'][0],
            'binding-operation-target')
    require('observed_mount' in record, 'binding-resolution-observation')
    after = _chain_observation(record['observed_mount'], path, metadata)
    guard = record.get('current_guard')
    if 'current_guard' in record:
        _pair_guard(guard, target)
    if 'failed_current_guard' in record:
        _pair_guard(record['failed_current_guard'], target)
        require(guard is not None and _same_evidence(guard, record['failed_current_guard']),
                'binding-resolution-guard')
    helpers = record['helpers']
    require(all(k not in record or type(record[k]) is bool for k in
                ('mount_attempted', 'already_absent')), 'binding-operation-incomplete')
    if 'protocol' not in record and any(any(k in h for k in
            ('streams_eof', 'streams_durable', 'output_bytes')) for h in helpers):
        _native.check_helpers(dict(record, protocol=2), {'verify-package', 'discover', 'mount', 'unmount'})
    require(all(not any(k in h for k in ('receipt_error', 'collector_error', 'stream_close_errors',
                'interrupted', 'stop_errors')) for h in helpers), 'binding-operation-incomplete')
    require(all(h['outcome'] in ('success', 'error', 'not-launched') for h in helpers)
            and all(h['outcome'] == 'success' for h in helpers[:-1]), 'binding-operation-incomplete')
    profile = metadata.get('controller_profile')
    require(type(profile) is str and profile in _native.PROFILES, 'binding-operation-profile')
    if record['operation'] == 'native-mount':
        labels = ['verify-package', 'discover', 'mount']
        require(guard is not None and len(helpers) <= 3
                and [h['label'] for h in helpers] == labels[:len(helpers)], 'binding-operation-incomplete')
        for h in helpers:
            if h['label'] == 'mount':
                argv = ['/sbin/mount', '-t', _native.PROFILES[profile]['type'], str(path), str(path / 'volume')]
                require(record.get('mount_attempted') is True
                        and h['argv'] in (argv, argv[:1] + ['-F'] + argv[1:]), 'binding-mount-argv')
            elif h['label'] == 'discover':
                require(len(h['argv']) == 2 and h['argv'][1] == '--discover-json'
                        and Path(h['argv'][0]).is_absolute()
                        and Path(h['argv'][0]).name == 'StallionFS'
                        and Path(h['argv'][0]).parent.name == 'MacOS', 'binding-mount-argv')
            else:
                # Package argv contains the historical signed app location.
                require(len(h['argv']) == 7
                        and h['argv'] == _native.package_argv(Path(h['argv'][-1]) / 'Contents/MacOS/StallionFS'),
                        'binding-mount-argv')
        if helpers:
            host = str(Path(helpers[0]['argv'][-1]) / 'Contents/MacOS/StallionFS')
            require('native_host' not in metadata or metadata['native_host'] == host, 'binding-mount-argv')
            if len(helpers) >= 2:
                require(helpers[1]['argv'] == [host, '--discover-json'], 'binding-mount-argv')
        if after is not None:
            require(len(helpers) == 3, 'binding-operation-incomplete')
        if record['outcome'] == 'complete' and 'write_probe' in record:
            probe = record['write_probe']
            require(type(probe) is dict and probe.get('complete') is True
                    and type(probe.get('path')) is str
                    and Path(probe['path']).parent == path / 'volume/repo'
                    and re.fullmatch(r'\.stallionfs-write-[0-9a-f]{32}', Path(probe['path']).name),
                    'binding-operation-incomplete')
        return None, after, guard, False
    require('before_mount' in record, 'binding-resolution-observation')
    before = _chain_observation(record['before_mount'], path, metadata)
    if before is None:
        require(record.get('already_absent') is True and helpers == []
                and after is None and guard is not None, 'binding-operation-incomplete')
    else:
        require(len(helpers) == 1 and helpers[0]['label'] == 'unmount'
                and helpers[0]['argv'] == ['/sbin/umount', str(path / 'volume')], 'binding-operation-incomplete')
        if helpers[0]['outcome'] == 'success':
            require(after is None and guard is not None, 'binding-operation-incomplete')
        else:
            require(record['outcome'] == 'incomplete' and guard is None
                    and _same_evidence(before, after), 'binding-operation-incomplete')
    return before, after, guard, after is None


def _mount_acceptance(record, proof, path):
    """The producer persists initial acceptance before completing its mount."""
    require(type(proof) is dict and proof.get('first_mount_attempted') is True,
            'binding-initial-acceptance')
    first = proof.get('first_use')
    require(type(first) is dict and first.get('accepted') is True
            and type(first.get('operation')) is str
            and re.fullmatch('[0-9a-f]{32}', first['operation']), 'binding-initial-acceptance')
    probe = first.get('write_probe')
    require(type(probe) is dict and probe.get('complete') is True
            and type(probe.get('path')) is str
            and Path(probe['path']).parent == path / 'volume/repo'
            and re.fullmatch(r'\.stallionfs-write-[0-9a-f]{32}', Path(probe['path']).name),
            'binding-initial-acceptance')
    if first['operation'] == record['id']:
        require(_same_evidence(record.get('write_probe'), probe), 'binding-initial-acceptance')
    else:
        # _usable(initial=False) never emits a probe. A different initial
        # identity cannot explain a probe on this completed operation.
        require('write_probe' not in record, 'binding-initial-acceptance')


def archive_anchor(records, path, metadata, mounted, proof=None, *, reconciliation=None, collect_legacy=False):
    """Validate an Admission-bounded archive map without following any stored paths."""
    from ._native_interval import correlate_marker
    if mounted is not None:
        correlate_marker(records, mounted, path, metadata)
    closed = []
    incoming = {}
    paths = {str(path / 'native-operations' / name / 'record.json'): name for name in records}
    for name, record in records.items():
        require(type(name) is str and re.fullmatch('[0-9a-f]{32}', name)
                and type(record) is dict, 'binding-operation-schema')
        reference = record.get('previous_unresolved')
        if type(reference) is dict:
            # Count malformed incoming edges too, before judging their authority.
            targets = set()
            if type(reference.get('id')) is str and reference['id'] in records:
                targets.add(reference['id'])
            if type(reference.get('record')) is str and reference['record'] in paths:
                targets.add(paths[reference['record']])
            for target in targets:
                incoming.setdefault(target, []).append(name)
    exceptional = set()
    successor = {}
    for name, record in records.items():
        if record.get('outcome') == 'complete':
            completed_operation(record, path, metadata, name)
            if record['operation'] in ('native-snapshot', 'native-restore', 'native-catalog-observe',
                                       'native-mounted-snapshot', 'native-mounted-restore'):
                closed.append(record['native_image_result']['close_receipt'])
        else:
            exceptional.add(name)
            candidates = incoming.get(name, [])
            require(len(candidates) == 1 and candidates[0] != name, 'binding-resolution-edge')
            successor[name] = candidates[0]
    # Walk each suffix once; no recursion or ordering/timestamp assumptions.
    resolved = set()
    used = set()
    for start in exceptional:
        trail, visiting = [], set()
        current = start
        while current not in resolved:
            require(current not in visiting, 'binding-resolution-edge')
            visiting.add(current)
            trail.append(current)
            used.add(current)
            if current not in exceptional:
                require(records[current].get('outcome') == 'complete'
                        and records[current].get('operation') in ('native-mount', 'native-unmount'),
                        'binding-resolution-edge')
                break
            current = successor[current]
        resolved.update(trail)
    # Check every used incoming reference, including completed boundaries.
    pending = list(used)
    predecessors = {}
    while pending:
        name = pending.pop()
        record = records[name]
        require('previous_unresolved' in record, 'binding-resolution-edge')
        reference = record['previous_unresolved']
        if reference is None:
            continue
        require(type(reference) is dict and type(reference.get('id')) is str
                and re.fullmatch('[0-9a-f]{32}', reference['id'])
                and reference['id'] in records and reference['id'] != name, 'binding-resolution-edge')
        previous = reference['id']
        prior = records[previous]
        expected = dict(operation=prior.get('operation'), id=previous, outcome=prior.get('outcome'),
                        record=str(path / 'native-operations' / previous / 'record.json'))
        require(_same_evidence(reference, expected) and incoming.get(previous) == [name]
                and _same_evidence(record.get('target'), prior.get('target')), 'binding-resolution-edge')
        predecessors[name] = previous
        if previous not in used:
            require(prior.get('outcome') == 'complete', 'binding-resolution-edge')
            used.add(previous)
            pending.append(previous)
    members = {name: _chain_member(records[name], path, metadata, name) for name in used}
    require(mounted is not None or not any(records[n]['outcome'] == 'complete'
            and records[n]['operation'] == 'native-mount' for n in used), 'binding-missing-closed-anchor')
    completed_mounts = [n for n in used if records[n]['outcome'] == 'complete'
                        and records[n]['operation'] == 'native-mount']
    for name in completed_mounts:
        _mount_acceptance(records[name], proof, path)
    from ._native_interval import Index
    intervals = Index(records, path, metadata)
    require(not intervals.open, 'binding-open-interval')
    for name in intervals.origins:
        if records[name]['outcome'] == 'complete':
            _mount_acceptance(records[name], proof, path)
    closed.extend(intervals.closed_guards)
    legacy = set(completed_mounts) - intervals.origins.keys()
    if legacy:
        from ._native_reconcile import legacy_closes
        closed.extend(legacy_closes(records, path, metadata, legacy))
        require(type(reconciliation) is dict and legacy <= set(reconciliation['scope']['endpoints']),
                'binding-close-continuity-unproven')
        closed.append(reconciliation['guard'])
    for name in set(completed_mounts) - legacy:
        require(name in intervals.closes, 'binding-close-continuity-unproven')
    if intervals.origins or mounted is not None and 'lifecycle_version' in mounted:
        require(type(mounted) is dict and type(mounted.get('operation')) is str
                and mounted['operation'] in records, 'binding-resolution-marker')
        current = records[mounted['operation']]
        completed_operation(current, path, metadata, current['id'])
        require(_same_evidence(current.get('target'), mounted.get('target'))
                and _same_evidence(current.get('current_guard'), mounted.get('current_guard'))
                and _same_evidence(current.get('ordinary_interval'), mounted.get('ordinary_interval')),
                'binding-resolution-marker')
    # Propagate only witnessed guards along each explicit linear sequence.
    following = {previous: name for name, previous in predecessors.items()}
    seen = set()
    for root in used - predecessors.keys():
        current, previous_after, last_guard = root, None, None
        first = True
        while current is not None:
            require(current not in seen, 'binding-resolution-edge')
            seen.add(current)
            before, after, guard, is_close = members[current]
            if not first:
                require(_same_evidence(previous_after, before), 'binding-resolution-observation')
            if guard is not None and last_guard is not None:
                if before is None:
                    require(_same_evidence(guard, last_guard), 'binding-resolution-guard')
                else:
                    require(guard['generation'] >= last_guard['generation'], 'binding-resolution-guard')
                    if guard['generation'] == last_guard['generation']:
                        require(all(_same_evidence(guard[k], last_guard[k]) for k in
                                    ('generation', 'committed_end', 'root_digest')), 'binding-conflicting-anchors')
            if guard is not None:
                last_guard = guard
            if is_close:
                closed.append(guard)
            if mounted is not None and mounted.get('operation') == current:
                target = core.native_target({'ownership': 'external-reference', 'native_image': mounted.get('target')})
                _pair_guard(mounted.get('current_guard'), target)
                require(is_close and _same_evidence(mounted['target'], records[current]['target'])
                        and _same_evidence(mounted['current_guard'], guard), 'binding-resolution-marker')
            previous_after, first = after, False
            current = following.get(current)
    require(seen == used, 'binding-resolution-edge')
    if mounted is not None:
        require(mounted.get('state') == 'absent' and type(mounted.get('target')) is dict
                and mounted['target']['uuid'] == metadata['native_image']['uuid']
                and mounted['target']['file'][1] == metadata['native_image']['file'][1]
                and _native._consumed(mounted.get('current_guard'), mounted['target']), 'binding-mount-uncertain')
        closed.append(mounted['current_guard'])
    else:
        require(type(proof) is dict and proof.get('first_mount_attempted') is False,
                'binding-missing-closed-anchor')
        closed.append(proof['guard'])
    # Catalog commits advance the generation after an ordinary unmount. Use
    # affirmative close evidence for the newest generation without rewriting
    # that unmount or granting it a fresh cleanup timestamp.
    from ._native_recovery import _valid_anchor
    anchors = {}
    for receipt in closed:
        anchor = {k: receipt.get(k) for k in ('generation', 'committed_end', 'root_digest')}
        require(_valid_anchor(anchor), 'binding-missing-closed-anchor')
        generation = anchor['generation']
        require(generation not in anchors or anchors[generation] == anchor, 'binding-conflicting-anchors')
        anchors[generation] = anchor
    result = max(closed, key=lambda receipt: receipt['generation'])
    return (result, legacy) if collect_legacy else result


def validate(record, metadata, digest):
    require(type(record) is dict and type(record.get('schema')) is int
            and (record['schema'] == 1 and set(record) == KEYS
                 and record.get('authority') in ('installation', 'current-image-adoption')
                 or record['schema'] == 2 and set(record) == KEYS | {'basis'}
                 and record.get('authority') == 'legacy-offline-reconciliation') and record['complete'] is True
            and type(record['publication_file_id']) is int and 0 < record['publication_file_id'] < 1 << 64
            and record['authority'] in ('installation', 'current-image-adoption', 'legacy-offline-reconciliation')
            and isinstance(record['epoch'], str) and re.fullmatch('[0-9a-f]{32}', record['epoch'])
            and record['workspace'] == metadata['id'] and record['transaction'] == metadata['transaction']
            and record['origin_target'] == metadata['native_image'] and record['historical'] == digest,
            'invalid-native-binding')
    stable = record['stable']
    require(type(stable) is dict and set(stable) == {'volume_uuid', 'collection', 'object', 'file'}
            and type(stable['volume_uuid']) is str
            and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', stable['volume_uuid'])
            and uuid.UUID(stable['volume_uuid']).int != 0
            and all(type(stable[k]) is int and 0 < stable[k] < 1 << 64 for k in ('collection', 'object', 'file'))
            and [stable[k] for k in ('collection', 'object', 'file')]
                == [metadata['native_image'][k][1] for k in ('parent', 'object', 'file')],
            'invalid-native-binding')
    core.native_target({'ownership': 'external-reference', 'native_image': record['admitted_target']})
    admitted = record['admitted_target']
    require(admitted['parent'][1] == stable['object'] and admitted['file'][1] == stable['file']
            and admitted['uuid'] == metadata['native_image']['uuid'] and admitted['component'] == 'image.sfs'
            and Path(admitted['directory']).name == metadata['id']
            and Path(admitted['directory']).parent.name == 'workspaces', 'invalid-native-binding')
    from ._native_recovery import _valid_anchor
    require(_valid_anchor(record['anchor']) and _native._consumed(record['guard'], record['admitted_target'], record['anchor']),
            'incomplete-native-binding')


def resolve(store, path, metadata, *, admission=None):
    """Return a live target. No binding is written by read-only resolution."""
    a = admission or Admission(store.root)
    try:
        binding = path / NAME
        if not a.exists(binding):
            return None
        digest, _ = evidence(a, path, metadata)
        record = a.read(binding)
        validate(record, metadata, digest)
        reconciliation = None
        if record['schema'] == 2:
            from ._native_reconcile import read_basis
            reconciliation = read_basis(a, path, metadata, record['basis'])
            if not a.exists(a.root / 'journals' / (path.name + '.json')) and _native.observe(path / 'volume', metadata['controller_profile']) is None:
                exclusions(store, a, path, metadata, reconciliation=reconciliation)
        require(a.files[binding][0][1] == record['publication_file_id'], 'binding-publication-substitution')
        require(record['admitted_target']['directory'] == str(a.root / 'workspaces' / path.name),
                'binding-store-location-changed')
        with descriptors(a, path, metadata) as (stable, target, observe):
            expected = record['stable']
            require(stable == expected, 'hosting-identity-changed')
            mounted_path = path / 'native-mount.json'
            mounted = a.read(mounted_path) if a.exists(mounted_path) else {}
            from ._native_interval import correlate_marker, load, pending_ordinary
            journal = a.root / 'journals' / (path.name + '.json')
            pending = a.read(journal) if a.exists(journal) else None
            records = load(a, path)
            # Retained receipts keep their original workspace paths after a
            # managed move. Validate that historical identity without changing
            # it into current relocation or destructive authority.
            history_path = a.root / 'workspaces' / path.name
            correlate_marker(records, mounted, history_path, metadata, pending)
            translated = target['file'][0] != record['admitted_target']['file'][0]
            if translated:
                require(pending is None or _same_evidence(pending.get('target'), target), 'binding-pending-operation')
                location_path = path / 'native-location.json'
                location = a.read(location_path) if a.exists(location_path) else {}
                located = (location.get('complete') is True and location.get('object') == target['parent']
                           and location.get('file') == target['file'] and location.get('uuid') == target['uuid']
                           and _native._consumed(location.get('guard'), target))
                if mounted.get('target') != target and not located:
                    if pending is None:
                        exclusions(store, a, path, metadata, reconciliation=reconciliation)
                    else:
                        pending_ordinary(records, pending, path, metadata)
                elif mounted.get('state') != 'mounted' and not located:
                    require(mounted.get('state') == 'absent' and _native._consumed(mounted.get('current_guard'), target),
                            'binding-mount-uncertain')
            # A mounted image cannot acquire an offline guard. Its exact live
            # target still needs the ordinary mount observation checks at use.
            if translated and admission is None and pending is None and (mounted.get('state') != 'mounted' or mounted.get('target') != target):
                _native.guarded(target, lambda token: require(observe() == (stable, target), 'hosting-binding-changed'))
            require(a.read(binding) == record and evidence(a, path, metadata)[0] == digest, 'binding-evidence-changed')
            return target
    finally:
        if admission is None:
            a.close()


def enroll(store, a, path, metadata, *, adopt=False, reconciliation=None):
    """Caller holds store/use/workspace locks. Publish only after consumed close."""
    if a.exists(path / NAME):
        existing = a.read(path / NAME)
        if existing.get('schema') == 2:
            from ._native_reconcile import read_basis
            reconciliation = read_basis(a, path, metadata, existing.get('basis'))
        if adopt:
            exclusions(store, a, path, metadata, reconciliation=reconciliation)
            require(a.read(path / NAME).get('authority') in ('current-image-adoption', 'legacy-offline-reconciliation'),
                    'image-already-has-installation-binding')
        resolve(store, path, metadata, admission=a)
        return {'status': 'current-image-adopted' if adopt else 'bound', 'already_adopted': True,
                'workspace': path.name, 'transaction': metadata['transaction']}
    digest, _ = evidence(a, path, metadata)
    closed = exclusions(store, a, path, metadata, reconciliation=reconciliation)
    require(closed.get('physical_end') == closed.get('committed_end'), 'binding-uncertain-physical-end')
    anchor = {k: closed[k] for k in ('generation', 'committed_end', 'root_digest')}
    with descriptors(a, path, metadata) as (stable, target, observe):
        if reconciliation is not None:
            require(_same_evidence(stable, reconciliation['scope']['stable']), 'reconciliation-host-changed')
        if not adopt:
            require(target == historical_target(path, metadata)
                    and pair(os.fstat(a.directory(path.parent))) == metadata['native_image']['parent'],
                    'legacy-device-changed-use-adopt-current')
        def held(token):
            exclusions(store, a, path, metadata, reconciliation=reconciliation)
            require(observe() == (stable, target) and evidence(a, path, metadata)[0] == digest,
                    'binding-evidence-changed')
        receipt = _native.guarded(target, held, anchor=anchor, expected_anchor=anchor)
        require(receipt.get('physical_end') == anchor['committed_end'], 'binding-uncertain-physical-end')
        require(observe() == (stable, target) and evidence(a, path, metadata)[0] == digest,
                'binding-evidence-changed')
        exclusions(store, a, path, metadata, reconciliation=reconciliation)
        record = dict(schema=1, epoch=uuid.uuid4().hex,
                      authority='current-image-adoption' if adopt else 'installation', workspace=path.name,
                      transaction=metadata['transaction'], historical=digest, origin_target=metadata['native_image'],
                      stable=stable, admitted_target=target, anchor=anchor, guard=receipt, complete=True)
        if reconciliation is not None:
            from ._native_reconcile import binding_basis
            record.update(schema=2, authority='legacy-offline-reconciliation',
                          basis=binding_basis(a, path, reconciliation))
        publish(a, path / NAME, record)
        require(a.read(path / NAME) == record and observe() == (stable, target), 'binding-publication-changed')
    return {'status': 'current-image-adopted' if adopt else 'bound', 'workspace': path.name,
            'transaction': metadata['transaction'], 'authority': record['authority'], 'epoch': record['epoch']}


def publish(a, path, record):
    """Retain the publication descriptor through name-relative identity checks."""
    parent = a.directory(path.parent)
    require(not a.exists(path), 'binding-already-exists')
    temporary = '.' + NAME + '.' + uuid.uuid4().hex
    fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent)
    try:
        record['publication_file_id'] = os.fstat(fd).st_ino
        data = json.dumps({'format': 1, **record}, sort_keys=True, allow_nan=False).encode() + b'\n'
        pending = memoryview(data)
        while pending:
            count = os.write(fd, pending)
            require(count > 0, 'binding-short-write')
            pending = pending[count:]
        os.fsync(fd)
        before = os.fstat(fd)
        a.check()
        require(not a.exists(path), 'binding-already-exists')
        _scan._publish_no_replace(parent, temporary, path.name)
        after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        require(pair(before) == pair(after) == pair(os.fstat(fd)) and safe(after)
                and before.st_size == after.st_size, 'binding-publication-substitution')
        os.lseek(fd, 0, os.SEEK_SET)
        require(os.read(fd, len(data) + 1) == data, 'binding-publication-content')
        os.fsync(parent)
        a.check()
    finally:
        os.close(fd)


def adopt_current(root, workspace, transaction):
    from ._native_create_recovery import diagnostic
    response = {'workspace': workspace, 'transaction': transaction, 'status': 'blocked'}
    try:
        core.identifier(workspace, 32); core.identifier(transaction, 32)
        with core.Store.existing(root, shared=False) as (store, a):
            a.lock(a.root / 'locks' / ('use-' + workspace))
            a.lock(a.root / 'locks' / ('workspace-' + workspace))
            path = a.root / 'workspaces' / workspace
            metadata = a.read(path / 'meta.json')
            require(metadata.get('id') == workspace and metadata.get('transaction') == transaction, 'transaction-mismatch')
            from ._native_create_authority import installed
            installed(path, metadata)
            from ._native_create_recovery import discover, conflicts
            _, owners, affected = discover(a)
            require(not affected, 'inventory-incomplete')
            conflicts(a, {'status': 'already-installed', 'origin': metadata['origin']}, owners)
            response.update(enroll(store, a, path, metadata, adopt=True))
    except (OSError, ValueError, TypeError, KeyError, core.StallionError) as error:
        response.update(diagnostic(error))
        if isinstance(error, BlockingIOError): response['status'] = 'busy'
    return response
