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

from . import core, _native, _scan
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


def exclusions(store, a, path, metadata):
    """No stale ownership or mount evidence can authorize a new epoch/translation."""
    require(path.parent == a.root / 'workspaces', 'binding-moved')
    require(not a.exists(a.root / 'journals' / (path.name + '.json')), 'binding-pending-operation')
    require(not a.exists(path / 'native-location.json'), 'binding-moved')
    for parent in ('protected', 'trash'):
        require(not os.path.lexists(a.root / parent / (path.name + ('.json' if parent == 'protected' else ''))),
                'binding-retirement')
    store._no_mounts(path)
    require(not a.names(path / 'volume'), 'occupied-volume')
    closed = []
    if a.exists(path / 'native-operations'):
        for name in a.names(path / 'native-operations'):
            require(re.fullmatch('[0-9a-f]{32}', name), 'binding-operation-schema')
            record = a.read(path / 'native-operations' / name / 'record.json')
            completed_operation(record, path, metadata, name)
            if record['operation'] in ('native-snapshot', 'native-restore', 'native-catalog-observe',
                                       'native-mounted-snapshot', 'native-mounted-restore'):
                closed.append(record['native_image_result']['close_receipt'])
    if a.exists(path / 'native-mount.json'):
        mounted = a.read(path / 'native-mount.json')
        require(mounted.get('state') == 'absent' and type(mounted.get('target')) is dict
                and mounted['target']['uuid'] == metadata['native_image']['uuid']
                and mounted['target']['file'][1] == metadata['native_image']['file'][1]
                and _native._consumed(mounted.get('current_guard'), mounted['target']), 'binding-mount-uncertain')
        closed.append(mounted['current_guard'])
    else:
        proof = a.read(path / 'native-install.json')
        require(proof.get('first_mount_attempted') is False, 'binding-missing-closed-anchor')
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
    return max(closed, key=lambda receipt: receipt['generation'])


def validate(record, metadata, digest):
    require(type(record) is dict and set(record) == KEYS and type(record['schema']) is int
            and record['schema'] == 1 and record['complete'] is True
            and type(record['publication_file_id']) is int and 0 < record['publication_file_id'] < 1 << 64
            and record['authority'] in ('installation', 'current-image-adoption')
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
        require(a.files[binding][0][1] == record['publication_file_id'], 'binding-publication-substitution')
        require(record['admitted_target']['directory'] == str(a.root / 'workspaces' / path.name),
                'binding-store-location-changed')
        with descriptors(a, path, metadata) as (stable, target, observe):
            expected = record['stable']
            require(stable == expected, 'hosting-identity-changed')
            mounted_path = path / 'native-mount.json'
            mounted = a.read(mounted_path) if a.exists(mounted_path) else {}
            translated = target['file'][0] != record['admitted_target']['file'][0]
            if translated:
                journal = a.root / 'journals' / (path.name + '.json')
                pending = a.read(journal) if a.exists(journal) else None
                require(pending is None or pending.get('target') == target, 'binding-pending-operation')
                location_path = path / 'native-location.json'
                location = a.read(location_path) if a.exists(location_path) else {}
                located = (location.get('complete') is True and location.get('object') == target['parent']
                           and location.get('file') == target['file'] and location.get('uuid') == target['uuid']
                           and _native._consumed(location.get('guard'), target))
                if mounted.get('target') != target and not located:
                    exclusions(store, a, path, metadata)
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


def enroll(store, a, path, metadata, *, adopt=False):
    """Caller holds store/use/workspace locks. Publish only after consumed close."""
    if a.exists(path / NAME):
        if adopt:
            exclusions(store, a, path, metadata)
            require(a.read(path / NAME).get('authority') == 'current-image-adoption',
                    'image-already-has-installation-binding')
        resolve(store, path, metadata, admission=a)
        return {'status': 'current-image-adopted' if adopt else 'bound', 'already_adopted': True,
                'workspace': path.name, 'transaction': metadata['transaction']}
    digest, _ = evidence(a, path, metadata)
    closed = exclusions(store, a, path, metadata)
    require(closed.get('physical_end') == closed.get('committed_end'), 'binding-uncertain-physical-end')
    anchor = {k: closed[k] for k in ('generation', 'committed_end', 'root_digest')}
    with descriptors(a, path, metadata) as (stable, target, observe):
        if not adopt:
            require(target == historical_target(path, metadata)
                    and pair(os.fstat(a.directory(path.parent))) == metadata['native_image']['parent'],
                    'legacy-device-changed-use-adopt-current')
        def held(token):
            exclusions(store, a, path, metadata)
            require(observe() == (stable, target) and evidence(a, path, metadata)[0] == digest,
                    'binding-evidence-changed')
        receipt = _native.guarded(target, held, anchor=anchor, expected_anchor=anchor)
        require(receipt.get('physical_end') == anchor['committed_end'], 'binding-uncertain-physical-end')
        require(observe() == (stable, target) and evidence(a, path, metadata)[0] == digest,
                'binding-evidence-changed')
        exclusions(store, a, path, metadata)
        record = dict(schema=1, epoch=uuid.uuid4().hex,
                      authority='current-image-adoption' if adopt else 'installation', workspace=path.name,
                      transaction=metadata['transaction'], historical=digest, origin_target=metadata['native_image'],
                      stable=stable, admitted_target=target, anchor=anchor, guard=receipt, complete=True)
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
