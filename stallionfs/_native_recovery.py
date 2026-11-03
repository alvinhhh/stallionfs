"""Owned catalog operations and recoverable, protected native directory moves."""
from __future__ import annotations

import os
from pathlib import Path
import re
import time

from . import _native, core
from .lifecycle import identity, finite_time, STALE_SECONDS

CATALOG = ('native-snapshot', 'native-restore', 'native-catalog-observe')
MOVES = ('native-retire', 'native-return')
ACTIONS = CATALOG + MOVES


def anchor(receipt):
    return {key: receipt[key] for key in ('generation', 'root_digest', 'committed_end')}


def _valid_anchor(value):
    return (isinstance(value, dict) and set(value) == {'generation', 'root_digest', 'committed_end'}
            and all(type(value[key]) is int and 0 <= value[key] < (1 << 64)
                    for key in ('generation', 'committed_end'))
            and isinstance(value['root_digest'], str)
            and re.fullmatch('[0-9a-f]{64}', value['root_digest']) is not None)


def validate_intent(workspace, record, *, moving=False):
    if (record.get('workspace') != workspace or record.get('operation') not in ACTIONS
            or not isinstance(record.get('id'), str) or not re.fullmatch('[0-9a-f]{32}', record['id'])
            or record.get('outcome') not in ('prepared', 'incomplete', 'complete')
            or record.get('child_pending') is not False or record.get('helpers') != []):
        raise core.StallionError('Malformed native recovery intent; retained unchanged')
    core.native_target({'ownership': 'external-reference', 'native_image': record.get('target')})
    if record['operation'] in MOVES:
        if not moving:
            raise core.StallionError('Native move needs explicit restore to resolve its retained location')
        source = 'workspaces' if record['operation'] == 'native-retire' else 'trash'
        destination = 'trash' if source == 'workspaces' else 'workspaces'
        if (type(record.get('rename_attempted')) is not bool
                or not isinstance(record.get('source_location'), dict)
                or not isinstance(record.get('destination_location'), dict)
                or record['source_location'].get('collection') != source
                or record['destination_location'].get('collection') != destination
                or record['destination_location'].get('operation') != record['id']):
            raise core.StallionError('Malformed native move intent; retained unchanged')
    if record['operation'] in CATALOG and type(record.get('bridge_attempted')) is not bool:
        raise core.StallionError('Malformed native catalog disposition; retained unchanged')
    if record['operation'] == 'native-snapshot':
        core.Store._native_name(record.get('name'))
    if record['operation'] == 'native-restore':
        core.Store._native_name(record.get('name'))
        core.Store._native_name(record.get('recovery_name'))


def location(store, path, metadata, *, override=None):
    """Validate current location separately from immutable installation evidence."""
    original = metadata['native_image']
    record_path = path / 'native-location.json'
    record = override if override is not None else core.read_json(record_path) if record_path.exists() else None
    if record is None:
        if path.parent != store.root / 'workspaces' or original['parent'] != identity(path.parent):
            raise core.StallionError('Native object has no confirmed current location')
        proof = core.read_json(path / 'native-install.json') if (path / 'native-install.json').exists() else {}
        return {'schema': 1, 'workspace': path.name, 'transaction': metadata['transaction'],
                'origin_target': original, 'collection': 'workspaces', 'parent': original['parent'],
                'object': original['object'], 'file': original['file'], 'uuid': original['uuid'],
                'operation': metadata['transaction'], 'complete': True, 'guard': proof.get('guard')}
    if (not isinstance(record, dict) or type(record.get('schema')) is not int or record['schema'] != 1 or record.get('workspace') != path.name
            or record.get('transaction') != metadata['transaction'] or record.get('origin_target') != original
            or record.get('collection') not in ('workspaces', 'trash')
            or path != store.root / record['collection'] / metadata['id']
            or record.get('parent') != identity(path.parent)
            or any(record.get(key) != original[key] for key in ('object', 'file', 'uuid'))
            or not isinstance(record.get('operation'), str) or not re.fullmatch('[0-9a-f]{32}', record['operation'])):
        raise core.StallionError('Native current-location provenance changed')
    resolved = {'directory': str(path), 'component': 'image.sfs', 'parent': original['object'],
                'file': original['file'], 'uuid': original['uuid']}
    if override is None and (record.get('complete') is not True or not _native._consumed(record.get('guard'), resolved)):
        raise core.StallionError('Native current location needs explicit restore recovery')
    return record


def ready(store, path, metadata):
    target = _native.installed_target(store, path, metadata)
    proof = core.read_json(path / 'native-install.json')
    first = proof.get('first_use')
    if (not isinstance(first, dict) or first.get('accepted') is not True
            or not isinstance(first.get('operation'), str) or not re.fullmatch('[0-9a-f]{32}', first['operation'])
            or proof.get('first_mount_attempted') is not True
            or not isinstance(first.get('write_probe'), dict) or first['write_probe'].get('complete') is not True
            or not isinstance(first['write_probe'].get('path'), str)
            or Path(first['write_probe']['path']).parent != store.root / 'workspaces' / path.name / 'volume/repo'
            or not re.fullmatch(r'\.stallionfs-write-[0-9a-f]{32}', Path(first['write_probe']['path']).name)):
        raise core.StallionError('Native recovery requires successful first managed use')
    return target


def absent(store, path):
    try:
        store._no_mounts(path)
    except core.StallionError as error:
        raise core.StallionError('Unmount the native workspace explicitly before catalog or retirement operations') from error


def _failure(error, operation):
    # Receipt work is best effort; never replace the operation's primary error.
    try:
        details = core.native_failure_details(error)
        if details is not None and details is not operation.record:
            operation.record['native_image_result'] = details
        receipt = getattr(error, 'native_current_guard', None)
        if receipt is not None:
            operation.record['failed_current_guard'] = receipt
        operation.record.update(outcome='incomplete', error={'type': type(error).__name__, 'message': str(error)})
        try:
            operation.persist()
        except BaseException as saving:
            operation.record['receipt_error'] = type(saving).__name__
        error.native_candidate_result = operation.record
    except BaseException:
        pass


def catalog_locked(store, path, metadata, action, name=None):
    target = ready(store, path, metadata)
    absent(store, path)
    journal = store.root / 'journals' / (path.name + '.json')
    if journal.exists():
        prior = core.read_json(journal)
        _native.check_pending(path.name, prior)
        if prior['operation'] in CATALOG and action != 'snapshots':
            # Observe the current catalog under its own fresh admission. Never
            # replay the prior mutation or relabel its lost result as successful.
            catalog_locked(store, path, metadata, 'snapshots')
    details = {'bridge_attempted': False}
    if action != 'snapshots':
        details['name'] = store._native_name(name)
        if action == 'restore':
            import uuid
            details['recovery_name'] = 'recovery-' + uuid.uuid4().hex
    operation = _native.Operation(store, path, {'snapshot': 'native-snapshot',
        'restore': 'native-restore', 'snapshots': 'native-catalog-observe'}[action], target, details=details)
    try:
        if action != 'snapshots':
            store._open(path.name, path, metadata)
        operation.record['bridge_attempted'] = True
        operation.persist()
        names = () if action == 'snapshots' else (operation.record['name'],)
        if action == 'restore': names += (operation.record['recovery_name'],)
        result = core.native_operation(target, action, *names)
        operation.record['native_image_result'] = result
        operation.persist()
        operation.finish()
        if action == 'snapshots': return result['snapshots']
        response = {'workspace': path.name, 'backend': 'native-image', 'native_image_result': result,
                    'native_operation': operation.record}
        if action == 'snapshot': response.update(id=name, name=name)
        else: response.update(snapshot=name, recovery=operation.record['recovery_name'])
        return response
    except BaseException as error:
        _failure(error, operation)
        raise


def closed_baseline(store, path, metadata):
    _native.unmount_locked(store, path, metadata)
    metadata = core.read_json(path / 'meta.json')
    target = ready(store, path, metadata)
    absent(store, path)
    receipt = _native.guarded(target)
    state = store._open(path.name, path, metadata)
    state.update(status='closed', closed_at=time.time(), native_idle={
        'generation': state['generation'], 'target': target, 'anchor': anchor(receipt),
        'observed_at': time.time(), 'guard': receipt})
    _native._persist(store._state(path.name), state)
    return state


def eligible(store, path, metadata, state, now, *, observe=False):
    if not store._valid_state(path.name, path, metadata, state, now): return None
    target = ready(store, path, metadata)
    absent(store, path)
    baseline = state.get('native_idle')
    if baseline is not None and (not isinstance(baseline, dict)
            or baseline.get('generation') != state['generation'] or baseline.get('target') != target
            or not finite_time(baseline.get('observed_at')) or baseline['observed_at'] > now
            or not _valid_anchor(baseline.get('anchor'))
            or not _native._consumed(baseline.get('guard'), target, baseline['anchor'])):
        if observe: store._open(path.name, path, metadata)
        return None
    if baseline is None and not observe: return None
    receipt = _native.guarded(target)
    if baseline is None or baseline['anchor'] != anchor(receipt):
        if observe:
            state = store._open(path.name, path, metadata)
            state['native_idle'] = {'generation': state['generation'], 'target': target,
                'anchor': anchor(receipt), 'observed_at': now, 'guard': receipt}
            _native._persist(store._state(path.name), state)
        return None
    since = state.get('closed_at') if state['status'] == 'closed' else baseline['observed_at']
    if not finite_time(since) or since > now or now - since < STALE_SECONDS: return None
    return path, metadata, state


def _no_external_references(store, target):
    for entry in (store.root / 'workspaces').iterdir():
        metadata = core.read_json(entry / 'meta.json')
        if metadata.get('backend') == 'native-image' and metadata.get('ownership') != 'store-created':
            other = core.native_target(metadata)
            if other['file'] == target['file']:
                raise core.StallionError('External registration conflicts with owned native movement')


def _protection(store, workspace, metadata):
    path = store.root / 'protected' / (workspace + '.json')
    record = core.read_json(path)
    if (record.get('id') != workspace or record.get('kind') != 'native-owned'
            or record.get('transaction') != metadata['transaction']
            or record.get('target') != metadata['native_image']):
        raise core.StallionError('Native protection does not match immutable ownership')
    return path


def _save_move(operation, path):
    operation.path = path
    operation.directory = path / 'native-operations' / operation.record['id']
    operation.persist()


def recover_move(store, workspace):
    """Resolve one actual location with a fresh guard; never repeat its rename."""
    journal = store.root / 'journals' / (workspace + '.json')
    record = core.read_json(journal)
    validate_intent(workspace, record, moving=True)
    if record['operation'] not in MOVES: raise core.StallionError('Expected retained native move')
    metadata = record.get('metadata')
    if not isinstance(metadata, dict) or metadata.get('id') != workspace:
        raise core.StallionError('Native move metadata is malformed')
    candidates = []
    for key in ('source_location', 'destination_location'):
        saved = record.get(key)
        if not isinstance(saved, dict) or saved.get('collection') not in ('workspaces', 'trash'):
            raise core.StallionError('Native move location is malformed')
        path = store.root / saved['collection'] / workspace
        if os.path.lexists(path): candidates.append((path, saved))
    if len(candidates) != 1 or record['source_location']['collection'] == record['destination_location']['collection']:
        raise core.StallionError('Native move has ambiguous actual locations; retained unchanged')
    path, saved = candidates[0]
    if core.read_json(path / 'meta.json') != metadata:
        raise core.StallionError('Native moved metadata changed')
    target = _native.installed_target(store, path, metadata, _location=saved)
    intended_source = store.root / record['source_location']['collection'] / workspace
    if record['target'] != dict(target, directory=str(intended_source)):
        raise core.StallionError('Native move intent target changed')
    recorded_location = path / 'native-location.json'
    if recorded_location.exists():
        observed = core.read_json(recorded_location)
        observed.pop('format', None)
        prior = dict(record['source_location']); prior.pop('format', None)
        if observed != prior:
            # A destination record may have become durable before the failure.
            location(store, path, metadata)
            if (observed.get('operation') != record['id']
                    or observed.get('collection') != saved['collection']):
                raise core.StallionError('Unexpected native move location proof; retained unchanged')
    protection_path = store.root / 'protected' / (workspace + '.json')
    completed_location = record.get('current_location') or record.get('resolution', {}).get('current_location')
    restored_complete = (isinstance(completed_location, dict)
        and completed_location.get('collection') == 'workspaces'
        and completed_location.get('complete') is True
        and _native._consumed(completed_location.get('guard'), target))
    if os.path.lexists(protection_path):
        protection = _protection(store, workspace, metadata)
    elif (path.parent == store.root / 'workspaces'
          and (record.get('rename_attempted') is False
               or restored_complete)):
        # Either no move was admitted, or restored-location completion was
        # durable before the existing protection was removed.
        protection = None
    else:
        raise core.StallionError('Native move protection is missing; retained unchanged')
    absent(store, path)
    _no_external_references(store, target)
    try:
        receipt = _native.guarded(target)
        # Fence both sides of an uncertain rename before releasing its journal.
        for key in ('source_location', 'destination_location'):
            core.sync_directory(store.root / record[key]['collection'])
        current = dict(saved, operation=record['id'], complete=True, guard=receipt)
        _native._persist(path / 'native-location.json', current)
        store._open(workspace, path, metadata)
        record['resolution'] = {'current_location': current, 'prior_outcome': record['outcome']}
        _native._persist(path / 'native-operations' / record['id'] / 'record.json', record)
        _native._persist(journal, record)
        if path.parent == store.root / 'workspaces' and protection is not None:
            protection.unlink(); core.sync_directory(protection.parent)
        journal.unlink(); core.sync_directory(journal.parent)
    except BaseException as error:
        try:
            record['recovery_failures'] = record.get('recovery_failures', 0) + 1
            record['last_recovery_error'] = {'type': type(error).__name__, 'message': str(error),
                'guard': getattr(error, 'native_current_guard', None)}
            _native._persist(path / 'native-operations' / record['id'] / 'record.json', record)
            _native._persist(journal, record)
            error.native_candidate_result = record
        except BaseException:
            pass
        raise
    return path, metadata, record


def move_locked(store, workspace, *, restore=False, selected=None):
    journal = store.root / 'journals' / (workspace + '.json')
    if journal.exists():
        record = core.read_json(journal)
        if record.get('operation') in MOVES:
            if not restore: raise core.StallionError('Resolve the retained native move with explicit restore')
            # Existing protection recovery has no new-slot admission check.
            resolved = None
            try:
                with core.lock(store.root / 'locks/retention', blocking=False):
                    path, metadata, resolved = recover_move(store, workspace)
            except BaseException as error:
                if resolved is not None:
                    try:
                        error.native_candidate_result = resolved
                    except BaseException:
                        pass
                raise
            if path.parent == store.root / 'workspaces':
                return {'restored': workspace, 'mounted': False, 'next': 'sfs mount ' + workspace,
                        'native_operation': resolved}
        else: _native.check_pending(workspace, record)
    source = 'trash' if restore else 'workspaces'
    destination = 'workspaces' if restore else 'trash'
    path, metadata = store.object(source, workspace)
    target = ready(store, path, metadata)
    absent(store, path)
    if restore:
        admission = core.lock(store.root / 'locks/retention', blocking=False)
    else:
        state = core.read_json(store._state(workspace)) if selected is None else selected[2]
        if selected is None:
            selected = eligible(store, path, metadata, state, time.time())
        if selected is None: raise core.StallionError('Native retirement requires an enrolled workspace stale for seven days')
        admission = store._retention()
    final = store.root / destination / workspace
    if os.path.lexists(final): raise core.StallionError('Native move destination already exists')
    completed = None
    try:
        with admission:
            if restore: _protection(store, workspace, metadata)
            import uuid
            operation_id = uuid.uuid4().hex
            old_location = location(store, path, metadata)
            new_location = dict(old_location, collection=destination, parent=identity(final.parent),
                                operation=operation_id, complete=False, guard=None)
            operation = _native.Operation(store, path, 'native-return' if restore else 'native-retire', target,
                operation_id=operation_id, details={'metadata': metadata, 'source_location': old_location,
                    'destination_location': new_location, 'rename_attempted': False})
            protection = store.root / 'protected' / (workspace + '.json')
            try:
                operation.persist()
                if not restore:
                    if os.path.lexists(protection): raise core.StallionError('Existing protection requires explicit restore')
                    core.write_json(protection, {'id': workspace, 'kind': 'native-owned',
                        'transaction': metadata['transaction'], 'target': metadata['native_image'],
                        'generation': state['generation'], 'retired_at': time.time()})
                    core.sync_directory(protection.parent)
                expected = None if restore else state['native_idle']['anchor']
                def held(token):
                    if not restore and core.read_json(store._state(workspace)) != state:
                        error = core.StallionError('Native lifecycle changed before retirement')
                        error.native_lifecycle_mismatch = True
                        raise error
                    absent(store, path)
                    _no_external_references(store, target)
                    token.verify(target)
                    operation.record['rename_attempted'] = True
                    operation.persist()
                    from ._scan import move
                    move(path, final)
                    token.verify(dict(target, directory=str(final)))
                    core.sync_directory(path.parent); core.sync_directory(final.parent)
                receipt = _native.guarded(target, held, expected_anchor=expected)
                current = dict(new_location, complete=True, guard=receipt)
                _native._persist(final / 'native-location.json', current)
                operation.record['current_location'] = current
                _save_move(operation, final)
                store._open(workspace, final, metadata)
                if restore:
                    operation.record['outcome'] = 'complete'
                    operation.persist()
                    protection.unlink(); core.sync_directory(protection.parent)
                operation.finish()
                completed = {'restored' if restore else 'retired': workspace, 'mounted': False,
                        'next': 'sfs mount ' + workspace if restore else 'sfs restore ' + workspace,
                        'native_operation': operation.record}
                return completed
            except BaseException as error:
                # Rename may complete before its caller sees an error. Locate the
                # archive by the immutable object; the top-level journal stays fixed.
                actual = final if os.path.lexists(final) and not os.path.lexists(path) else path
                operation.path = actual
                operation.directory = actual / 'native-operations' / operation.record['id']
                receipt = getattr(error, 'native_current_guard', None)
                if (not restore and (getattr(error, 'native_anchor_mismatch', False)
                                         or getattr(error, 'native_lifecycle_mismatch', False))
                        and actual == path and _native._consumed(receipt, target)):
                    try:
                        store._open(workspace, path, metadata)
                        operation.record.update(stale_reset=True, current_guard=receipt)
                        protection.unlink(); core.sync_directory(protection.parent)
                        operation.finish()
                        return None
                    except BaseException as reset_error:
                        operation.record['reset_error'] = type(reset_error).__name__
                _failure(error, operation)
                raise
    except BaseException as error:
        if completed is not None:
            try:
                error.native_image_result = completed
            except BaseException:
                pass
        raise
