"""Owned catalog operations and recoverable, protected native directory moves."""
from __future__ import annotations

import copy
import errno
import os
from pathlib import Path
import re
import shlex
import time

from . import _native, core
from .lifecycle import identity, finite_time, STALE_SECONDS

CATALOG = ('native-snapshot', 'native-restore', 'native-catalog-observe')
MOVES = ('native-retire', 'native-return')
ACTIONS = CATALOG + MOVES


# One owner spans normal withdrawal, one catalog transaction, and remount.
COMPOUND = ('native-mounted-snapshot', 'native-mounted-restore')
PHASES = ('prepared', 'unmount-attempted', 'offline', 'bridge-attempted',
          'committed', 'remount-attempted', 'final-verified')
MOUNT_KEYS = ('path', 'filesystem', 'owner', 'flags', 'fsid')


def _operation_command(record, action, *arguments):
    # Installed targets are canonical <root>/workspaces/<workspace> paths.
    directory = Path(record['target']['directory'])
    if not directory.is_absolute() or directory.name != record['workspace'] or directory.parent.name != 'workspaces':
        raise core.StallionError('Operation workspace binding is malformed')
    return shlex.join(['sfs', '--root', str(directory.parent.parent), action, record['workspace'], *arguments])


def pending_message(record):
    try:
        command = _operation_command(record, 'snapshots', '--operation', record['id'])
    except (KeyError, TypeError, ValueError, core.StallionError):
        return 'Native operation is retained; its workspace binding is malformed.'
    return f"Operation {record['id']} is retained. Inspect it with {command}; use its matching --continue command."


def validate_compound(workspace, record):
    """Validate intent/phase structure separately from terminal child evidence."""
    def bad():
        raise core.StallionError('Malformed mounted recovery intent; retained unchanged')
    if (not isinstance(record, dict) or record.get('workspace') != workspace
            or record.get('operation') not in COMPOUND
            or not isinstance(record.get('id'), str) or not re.fullmatch('[0-9a-f]{32}', record['id'])
            or record.get('phase') not in PHASES
            or record.get('outcome') not in ('prepared', 'incomplete', 'complete')
            or type(record.get('originally_mounted')) is not bool
            or type(record.get('bridge_attempted')) is not bool
            or type(record.get('bridge_returned')) is not bool
            or type(record.get('child_pending')) is not bool
            or not isinstance(record.get('helpers'), list)
            or record.get('profile') not in _native.PROFILES
            or not isinstance(record.get('host'), str)):
        bad()
    core.native_target({'ownership': 'external-reference', 'native_image': record.get('target')})
    core.Store._native_name(record.get('name'))
    if record['operation'] == 'native-mounted-restore':
        core.Store._native_name(record.get('recovery_name'))
    if record['originally_mounted'] and not isinstance(record.get('accepted_mount'), dict):
        bad()
    if (record['phase'] in ('prepared', 'unmount-attempted', 'offline')) == record['bridge_attempted']:
        bad()
    if record['bridge_returned'] and not record['bridge_attempted']:
        bad()
    if record['phase'] in ('committed', 'remount-attempted', 'final-verified'):
        if not _confirmed_bridge(record) or record.get('committed_anchor') != anchor(record['native_image_result']['receipt']):
            bad()
    # Helpers are flat, owned by this operation, and belong to one ordered
    # qualification + lifecycle attempt. No nested owners can finish the journal.
    groups = []
    for kind in ('unmount', 'remount'):
        attempts = record.get(kind + '_attempts')
        if not isinstance(attempts, list): bad()
        for index, attempt in enumerate(attempts):
            if not isinstance(attempt, dict) or type(attempt.get('launched')) is not bool: bad()
            groups.append((kind, index))
    previous = -1
    labels = {}
    for helper in record['helpers']:
        if not isinstance(helper, dict): bad()
        group = (helper.get('stage'), helper.get('attempt'))
        if group not in groups or type(group[1]) is not int: bad()
        position = groups.index(group)
        if position < previous: bad()
        previous = position
        sequence = labels.setdefault(group, [])
        sequence.append(helper.get('label'))
        expected = ['verify-package', 'discover', 'unmount' if group[0] == 'unmount' else 'mount']
        if sequence != expected[:len(sequence)]: bad()
        if sequence[-1] == expected[-1] and not record[group[0] + '_attempts'][group[1]]['launched']: bad()
    if record['unmount_attempts'] and not record['originally_mounted']: bad()
    if record['remount_attempts'] and (not record['originally_mounted'] or not _confirmed_bridge(record)): bad()
    if record['phase'] == 'unmount-attempted' and not any(item['launched'] for item in record['unmount_attempts']): bad()
    if record['phase'] == 'remount-attempted' and (not record['remount_attempts'] or not record['remount_attempts'][-1]['launched']): bad()
    if record['phase'] == 'offline' and not _native._consumed(record.get('offline_admission'), record['target']): bad()
    if record['phase'] == 'final-verified' and (not isinstance(record.get('final_evidence'), dict)
            or 'observation' not in record['final_evidence']): bad()
    host = Path(record['host'])
    command_paths = {
        'verify-package': ['/usr/bin/codesign', '--verify', '--deep', '--strict', str(host.parent.parent.parent)],
        'discover': [str(host), '--discover-json'],
        'unmount': ['/sbin/umount', str(Path(record['target']['directory']) / 'volume')],
        'mount': ['/sbin/mount', '-t', _native.PROFILES[record['profile']]['type'],
                  record['target']['directory'], str(Path(record['target']['directory']) / 'volume')]}
    for helper in record['helpers']:
        if 'argv' in helper and helper['argv'] != command_paths[helper['label']]:
            if helper['label'] != 'verify-package' or helper['argv'] != _native.package_argv(host): bad()
    if record['outcome'] == 'complete' and record['phase'] != 'final-verified': bad()


def _confirmed_bridge(record):
    result = record.get('native_image_result')
    target = record['target']
    if (record.get('bridge_returned') is not True or not isinstance(result, dict)
            or result.get('ok') is not True or result.get('committed') is not True
            or result.get('commit_attempted') is not True or result.get('outcome') != 'committed'
            or result.get('close_attempted') is not True or result.get('guard_close_errno') != 0
            or result.get('path_errno') != 0 or result.get('interrupted') is not False
            or result.get('deadline_expired') is not False
            or result.get('operation') != ('snapshot' if record['operation'] == COMPOUND[0] else 'restore')
            or result.get('snapshot') != record['name']):
        return False
    if record['operation'] == COMPOUND[1] and result.get('recovery') != record['recovery_name']: return False
    receipt, closed = result.get('receipt'), result.get('close_receipt')
    if not isinstance(receipt, dict) or not isinstance(closed, dict): return False
    if not _valid_anchor({key: receipt.get(key) for key in ('generation', 'root_digest', 'committed_end')}): return False
    # The bridge consumes its handle whenever close_attempted is true. Normal
    # bridge receipts have no guard-only core_consumed/parent_close_errno fields.
    return all(value.get('status') == 0 and value.get('poisoned') is False
               and value.get('transaction_active') is False
               and [value.get('device'), value.get('inode')] == target['file']
               and value.get('uuid') == target['uuid']
               and all(value.get(key) == receipt[key] for key in ('generation', 'root_digest', 'committed_end'))
               for value in (receipt, closed))


def _mounts_only_at(store, path):
    from . import _scan
    allowed = str(path / 'volume')
    if any(Path(row['path']).is_relative_to(path) and row['path'] != allowed for row in _scan.mounts()):
        raise core.StallionError('Workspace has another mounted path; no lifecycle command was started')


def _matching_mount(store, path, metadata, target, *, expected=None):
    _mounts_only_at(store, path)
    profile = metadata['controller_profile']
    row = _native.observe(path / 'volume', profile)
    state_path = path / 'native-mount.json'
    state = core.read_json(state_path) if state_path.exists() else {}
    accepted = state if expected is None else expected
    if (row is None or state != accepted or accepted.get('state') != 'mounted'
            or accepted.get('target') != target
            or accepted.get('profile', profile) != profile
            or not isinstance(accepted.get('observation'), dict)
            or accepted['observation'].get('filesystem') != _native.PROFILES[profile]['type']
            or any(accepted['observation'].get(key) != row[key] for key in MOUNT_KEYS)):
        raise core.StallionError('Accepted native mount does not match the current target, profile or observation; no unmount was started')
    return state, row


def _load_compound(store, path, operation_id):
    core.identifier(operation_id, 32)
    journal = store.root / 'journals' / (path.name + '.json')
    if journal.exists():
        record = core.read_json(journal)
        if record.get('id') != operation_id:
            raise core.StallionError('A different operation owns this workspace; retained unchanged')
    else:
        record = core.read_json(path / 'native-operations' / operation_id / 'record.json')
        if record.get('outcome') != 'complete':
            raise core.StallionError('Incomplete operation has no matching journal; retained unchanged')
    validate_compound(path.name, record)
    if (record['id'] != operation_id or record['target']['directory'] != str(path)
            or record['target']['component'] != 'image.sfs'):
        raise core.StallionError('Operation identity or workspace path changed; retained unchanged')
    return record, journal.exists()


def _terminal(record):
    _native.check_helpers(record, {'verify-package', 'discover', 'mount', 'unmount'})


def compound_summary(record):
    """Summarize historical dispositions without promoting attached receipts."""
    try:
        committed = _confirmed_bridge(record)
    except (KeyError, TypeError, ValueError):
        committed = False
    mutation = 'committed' if committed else 'incomplete' if record.get('bridge_attempted') else 'not-started'
    if committed:
        message = 'Snapshot committed.' if record['operation'] == COMPOUND[0] else (
            'Rollback committed. Recovery snapshot: ' + record['recovery_name'] + '.')
    elif mutation == 'incomplete':
        message = 'Snapshot/rollback outcome is incomplete. Do not repeat it.'
    else:
        message = 'Snapshot/rollback has not started.'
    mount = 'not-requested'
    if record.get('originally_mounted'):
        mount = 'not-attempted'
        attempts = record.get('remount_attempts', [])
        if attempts and attempts[-1].get('launched'):
            attempt = attempts[-1]
            helpers = [item for item in record.get('helpers', [])
                       if item.get('stage') == 'remount' and item.get('attempt') == len(attempts) - 1
                       and item.get('label') == 'mount']
            terminal = _terminal_attempt(record, 'remount')
            response = attempt.get('response')
            if terminal and helpers[0]['outcome'] == 'not-launched':
                mount = 'not-launched'
            elif (terminal and isinstance(response, dict) and type(response.get('returncode')) is int
                    and response['returncode'] != 0):
                mount = 'failed'
            elif (record.get('phase') == 'final-verified' and isinstance(record.get('final_evidence'), dict)
                  and _mount_completion_evidence(record, record['final_evidence'].get('observation'))):
                mount = 'verified'
            else:
                mount = 'unknown'
        if committed:
            messages = {'not-attempted': 'Remount was not attempted.',
                        'not-launched': 'Remount was not launched.',
                        'failed': 'Remount command failed; current mount state is separate.',
                        'unknown': 'Mount completion is unknown. Do not repeat snapshot/rollback.',
                        'verified': 'Remount was verified.'}
            message += ' ' + messages[mount]
            if mount == 'verified' and attempts[-1].get('response') is None:
                message += ' Its command response remains unknown.'
    elif committed:
        message += ' No remount was requested.'
    return {'mutation': mutation, 'mount': mount, 'message': message}


def format_compound_status(status):
    lines = [status['message']]
    if status.get('current_mount_matches_completion') is False:
        lines.append('Historical completion is unchanged; the current mount differs from the recorded final state.')
    if status.get('current_observation_error'):
        lines.append('Current mount observation failed: ' + status['current_observation_error'])
    if status.get('next_action'):
        lines.append(status['next_action'])
    if status.get('recovery'):
        lines.append(status['recovery'] + ' Path: ' + status['path'])
    return '\n'.join(lines)


def compound_status(store, path, metadata, operation_id):
    record, pending = _load_compound(store, path, operation_id)
    status = {'workspace': path.name, 'operation': operation_id, 'phase': record['phase'],
              'pending': pending, 'path': str(path / 'volume'), 'native_operation': record, 'next_action': None}
    try:
        _terminal(record)
    except core.StallionError:
        status['message'] = (f'Operation {operation_id} still has unresolved process ownership. '
                             'Keep its controller running; no continuation was started.')
        return status
    phase = record['phase']
    messages = {
        'prepared': 'Snapshot/rollback has not started.',
        'unmount-attempted': 'Unmount result is unknown; no snapshot/rollback was started.',
        'offline': 'Current backing admission succeeded; snapshot/rollback has not started.',
        'bridge-attempted': 'Snapshot/rollback outcome is incomplete. Do not repeat it.',
        'committed': 'Snapshot/rollback committed. Remount is separate.',
        'remount-attempted': 'Mount completion is unknown. Do not repeat snapshot/rollback.',
        'final-verified': 'Snapshot/rollback final state was verified.'}
    status['disposition'] = compound_summary(record)
    status['message'] = (status['disposition']['message']
                         if phase in ('committed', 'remount-attempted', 'final-verified')
                         or (phase == 'bridge-attempted' and _confirmed_bridge(record)) else messages[phase])
    if (phase != 'bridge-attempted' or _confirmed_bridge(record)) and pending:
        action = 'snapshot' if record['operation'] == COMPOUND[0] else 'rollback'
        arguments = (['--name=' + record['name'], '--quiescent', '--continue', operation_id] if action == 'snapshot'
                     else ['--quiescent', '--continue', operation_id, '--', record['name']])
        status['next_action'] = _operation_command(record, action, *arguments)
    try:
        target = ready(store, path, metadata)
        if target != record['target'] or metadata['controller_profile'] != record['profile'] or metadata['native_host'] != record['host']:
            raise core.StallionError('Current backing or controller identity has changed')
        _mounts_only_at(store, path)
        row = _native.observe(path / 'volume', record['profile'])
        status['current_observation'] = row
        if pending and phase == 'unmount-attempted' and row is not None:
            try:
                _matching_mount(store, path, metadata, target, expected=record['accepted_mount'])
                status['next_action'] = _operation_command(record, 'unmount', '--continue', operation_id)
            except (core.StallionError, OSError):
                status['next_action'] = None
        if pending and phase == 'remount-attempted' and row is not None and not _mount_completion_evidence(record, row):
            status['next_action'] = None
            status['recovery'] = 'Check the displayed path and arrange normal withdrawal separately before continuing.'
        if phase == 'final-verified':
            expected = record['final_evidence']['observation']
            status['current_mount_matches_completion'] = row == expected
            if row != expected: status['next_action'] = None
    except (core.StallionError, OSError, KeyError) as error:
        status['current_observation_error'] = str(error)
        status['next_action'] = None
    return status


def _attempt(operation, kind):
    attempts = operation.record[kind + '_attempts']
    attempt = {'launched': False, 'response': None}
    attempts.append(attempt)
    operation.command_context = {'stage': kind, 'attempt': len(attempts) - 1}
    operation.persist()
    return attempt


def _qualified(operation, metadata, attempt):
    filesystem = _native.qualify(operation, metadata)
    if filesystem != _native.PROFILES[operation.record['profile']]['type']:
        raise core.StallionError('Qualified filesystem profile changed')
    attempt['qualified'] = {'profile': operation.record['profile'], 'filesystem': filesystem,
                            'host': operation.record['host'], 'discovery': operation.record.get('discovery')}
    operation.persist()
    return filesystem


def _unmount_compound(store, path, metadata, operation):
    record, target = operation.record, operation.record['target']
    attempt = _attempt(operation, 'unmount')
    _qualified(operation, metadata, attempt)
    with _native.resource_binding(path, target, record) as check:
        _, row = _matching_mount(store, path, metadata, target, expected=record['accepted_mount'])
        attempt['before'] = row
        record['phase'] = 'unmount-attempted'
        attempt['launched'] = True
        operation.persist()
        result = operation.command('unmount', ['/sbin/umount', str(path / 'volume')])
        attempt['response'] = {'returncode': result['returncode'], 'outcome': result['outcome']}
        operation.persist()
        if result['returncode'] != 0:
            raise core.StallionError('Normal unmount failed; no snapshot/rollback was started')
        _native._observe_until(path / 'volume', record['profile'], False)
        check()
        _offline_admission(store, path, operation)


def _offline_admission(store, path, operation):
    absent(store, path)
    receipt = _native.guarded(operation.record['target'])
    operation.record['offline_admission'] = receipt
    operation.record['phase'] = 'offline'
    operation.persist()
    _native._persist(path / 'native-mount.json', {'state': 'absent', 'target': operation.record['target'],
        'operation': operation.record['id'], 'current_guard': receipt})


def _terminal_attempt(record, kind):
    attempts = record[kind + '_attempts']
    launched = [index for index, attempt in enumerate(attempts) if attempt['launched']]
    if not launched: return False
    index = launched[-1]
    label = 'unmount' if kind == 'unmount' else 'mount'
    helpers = [item for item in record['helpers'] if item.get('stage') == kind
               and item.get('attempt') == index and item.get('label') == label]
    if len(helpers) != 1: return False
    # check_helpers validates both reaped execution and the executor's
    # affirmative no-child disposition. Neither permits stored-PID cleanup.
    try:
        _native.check_helpers({'child_pending': False, 'helpers': helpers}, {label})
    except core.StallionError:
        return False
    return helpers[0]['reaped'] is True or helpers[0]['outcome'] == 'not-launched'


def _anchor_guard(operation):
    record = operation.record
    try:
        receipt = _native.guarded(record['target'], expected_anchor=record['committed_anchor'])
    except BaseException as error:
        # No fresh observation can replace the original committed anchor.
        if isinstance(error, OSError) and error.errno == errno.ESTALE:
            raise _native.failure('Snapshot/rollback committed, but the current image has changed. Remount was not attempted.', record) from error
        raise
    if not _native._consumed(receipt, record['target'], record['committed_anchor']):
        raise _native.failure('Snapshot/rollback committed, but the current image has changed. Remount was not attempted.', record)
    return receipt


def _remount_compound(store, path, metadata, operation):
    record, target = operation.record, operation.record['target']
    record['phase'] = 'committed'
    attempt = _attempt(operation, 'remount')
    filesystem = _qualified(operation, metadata, attempt)
    with _native.resource_binding(path, target, record) as check:
        absent(store, path)
        attempt['guard'] = _anchor_guard(operation)
        operation.persist()
        absent(store, path)
        check()
        record['phase'] = 'remount-attempted'
        attempt['launched'] = True
        operation.persist()
        result = operation.command('mount', ['/sbin/mount', '-t', filesystem, str(path), str(path / 'volume')])
        attempt['response'] = {'returncode': result['returncode'], 'outcome': result['outcome']}
        operation.persist()
        if result['returncode'] != 0:
            raise core.StallionError('Snapshot/rollback committed; remount failed. Inspect the retained operation')
        row = _native._observe_until(path / 'volume', record['profile'], True)
        _mounts_only_at(store, path)
        check()
        repo = _native._usable(store, path, metadata)
        # Only this same operation can record qualified observation + usability.
        attempt['evidence'] = {'observation': row, 'repo': repo, 'usable': True}
        operation.persist()
        _native._persist(path / 'native-mount.json', {'state': 'mounted', 'target': target,
            'profile': record['profile'], 'observation': row, 'operation': record['id']})
    return row


def _mount_completion_evidence(record, row):
    if not _terminal_attempt(record, 'remount'): return False
    attempt = record['remount_attempts'][-1]
    evidence, qualified = attempt.get('evidence'), attempt.get('qualified')
    return (isinstance(evidence, dict) and evidence.get('usable') is True
            and evidence.get('repo') == str(Path(record['target']['directory']) / 'volume/repo')
            and evidence.get('observation') == row and row is not None
            and isinstance(qualified, dict) and qualified.get('profile') == record['profile']
            and qualified.get('host') == record['host']
            and qualified.get('filesystem') == _native.PROFILES[record['profile']]['type']
            and _native._consumed(attempt.get('guard'), record['target'], record['committed_anchor']))


def _verify_final(store, path, metadata, operation):
    with _native.resource_binding(path, operation.record['target'], operation.record) as check:
        record = operation.record
        if record['originally_mounted']:
            _mounts_only_at(store, path)
            row = _native.observe(path / 'volume', record['profile'])
            if not _mount_completion_evidence(record, row):
                raise core.StallionError('Mount completion is unknown or its verified observation changed. Do not repeat snapshot/rollback.')
            _native._usable(store, path, metadata)
            # May recover a missing native-mount record only from this operation's
            # durable qualified evidence, never from a merely similar catalog.
            _native._persist(path / 'native-mount.json', {'state': 'mounted', 'target': record['target'],
                'profile': record['profile'], 'observation': row, 'operation': record['id']})
        else:
            absent(store, path)
            _anchor_guard(operation)
            row = None
        record['final_evidence'] = {'observation': row}
        record['phase'] = 'final-verified'
        operation.persist()
        check()


def compound_locked(store, path, metadata, action, name, *, operation_id=None, withdrawal=False):
    target = ready(store, path, metadata)
    if metadata.get('controller_profile') not in _native.PROFILES:
        raise core.StallionError('Unknown native controller profile')
    if operation_id is not None:
        record, pending = _load_compound(store, path, operation_id)
        expected = 'native-mounted-' + action
        if (record['operation'] != expected or record['name'] != name or record['target'] != target
                or metadata['controller_profile'] != record['profile'] or metadata['native_host'] != record['host']):
            raise core.StallionError('Continuation does not match the retained workspace, action, name or controller')
        _terminal(record)
        if not pending:
            return _compound_response(record, status=compound_status(store, path, metadata, operation_id))
        operation = _native.Operation.resume(store, path, record)
    else:
        core.Store._native_name(name)
        _mounts_only_at(store, path)
        row = _native.observe(path / 'volume', metadata['controller_profile'])
        accepted = _matching_mount(store, path, metadata, target)[0] if row is not None else None
        details = {'phase': 'prepared', 'name': name, 'originally_mounted': row is not None,
            'accepted_mount': accepted, 'profile': metadata['controller_profile'], 'host': metadata['native_host'],
            'bridge_attempted': False, 'bridge_returned': False, 'unmount_attempts': [], 'remount_attempts': []}
        if action == 'restore':
            import uuid
            details['recovery_name'] = 'recovery-' + uuid.uuid4().hex
        operation = _native.Operation(store, path, 'native-mounted-' + action, target, details=details)
        record = operation.record
    try:
        if withdrawal and (record['bridge_attempted'] or not record['originally_mounted']):
            raise core.StallionError('Explicit withdrawal is permitted only before catalog mutation of an originally mounted workspace')
        if withdrawal and record['phase'] == 'offline':
            _offline_admission(store, path, operation)
        if record['phase'] == 'bridge-attempted' and _confirmed_bridge(record):
            # The original call returned affirmatively and its receipt was
            # durable; only the following phase-marker write was interrupted.
            record.update(phase='committed', committed_anchor=anchor(record['native_image_result']['receipt']))
            operation.persist()
        if record['phase'] == 'final-verified':
            _verify_final(store, path, metadata, operation)
        else:
            if record['phase'] in ('prepared', 'unmount-attempted'):
                if record['phase'] == 'unmount-attempted' and not withdrawal:
                    if not _terminal_attempt(record, 'unmount'):
                        raise core.StallionError('Unmount terminal evidence is missing; no continuation was started')
                    # Fresh absence/admission authorizes the first bridge call;
                    # it does not claim the lost unmount response was successful.
                    _offline_admission(store, path, operation)
                elif record['originally_mounted']:
                    _unmount_compound(store, path, metadata, operation)
                else:
                    _offline_admission(store, path, operation)
            if withdrawal:
                return {'unmounted': path.name, 'native_operation': record, 'mutation_started': False}
            if record['phase'] == 'offline':
                absent(store, path)
                store._open(path.name, path, metadata)
                record.update(phase='bridge-attempted', bridge_attempted=True)
                operation.persist()
                names = (record['name'],) + ((record['recovery_name'],) if action == 'restore' else ())
                result = core.native_operation(target, action, *names)
                record.update(native_image_result=result, bridge_returned=True)
                operation.persist()
                if not _confirmed_bridge(record):
                    raise core.StallionError('Snapshot/rollback outcome is incomplete. Do not repeat it.')
                record.update(phase='committed', committed_anchor=anchor(result['receipt']))
                operation.persist()
            if record['phase'] == 'bridge-attempted':
                raise core.StallionError('Snapshot/rollback outcome is incomplete. Do not repeat it.')
            if record['originally_mounted']:
                if record['phase'] == 'remount-attempted':
                    if not _terminal_attempt(record, 'remount'):
                        raise core.StallionError('Mount completion is unknown. Do not repeat snapshot/rollback.')
                    _mounts_only_at(store, path)
                    if _native.observe(path / 'volume', record['profile']) is None:
                        _remount_compound(store, path, metadata, operation)
                    # A present mount requires durable same-operation evidence.
                else:
                    _remount_compound(store, path, metadata, operation)
            _verify_final(store, path, metadata, operation)
        operation.finish()
        return _compound_response(record)
    except BaseException as error:
        _retain_compound_failure(error, operation)
        raise


def _retain_compound_failure(error, operation):
    # Receipt failures must never hide or replace the first operation failure.
    try:
        record = operation.record
        if (record['phase'] == 'bridge-attempted' and not record['bridge_returned']
                and 'native_image_result' not in record):
            details = core.native_failure_details(error)
            if details is not None and details is not record:
                record['native_image_result'] = copy.deepcopy(details)
        detail = {'type': type(error).__name__, 'message': str(error),
                  'errno': getattr(error, 'errno', None), 'phase': record['phase']}
        os_result = getattr(error, 'native_os_result', None)
        if isinstance(os_result, dict):
            detail['native_os_result'] = copy.deepcopy(os_result)
            detail['helper_index'] = next((index for index, helper in enumerate(record['helpers'])
                                           if helper is os_result), None)
        if 'helper_index' not in detail and record['helpers']:
            helper = record['helpers'][-1]
            stage = 'remount' if record['phase'] in ('committed', 'remount-attempted') else 'unmount'
            attempts = record[stage + '_attempts']
            if (record['phase'] != 'bridge-attempted' and attempts and helper.get('stage') == stage
                    and helper.get('attempt') == len(attempts) - 1):
                detail['helper_index'] = len(record['helpers']) - 1
                detail['native_os_result'] = copy.deepcopy(helper)
        receipt = getattr(error, 'native_current_guard', None)
        candidate = getattr(error, 'native_candidate_result', None)
        if receipt is None and isinstance(candidate, dict) and candidate is not record:
            receipt = candidate.get('current_guard')
        cause = error.__cause__
        if cause is not None:
            detail['cause'] = {'type': type(cause).__name__, 'message': str(cause), 'errno': getattr(cause, 'errno', None)}
            if receipt is None:
                receipt = getattr(cause, 'native_current_guard', None)
        if receipt is not None:
            detail['native_current_guard'] = copy.deepcopy(receipt)
            if 'failed_current_guard' not in record:
                record['failed_current_guard'] = copy.deepcopy(receipt)
        if 'error' not in record:
            if 'native_image_result' in record:
                detail['native_image_result'] = copy.deepcopy(record['native_image_result'])
            record['error'] = detail
        else:
            later = record.setdefault('later_errors', {'count': 0})
            later['count'] = min(later['count'] + 1, (1 << 63) - 1)
            later['latest'] = detail
        record['outcome'] = 'incomplete'
        try:
            operation.persist()
        except BaseException as saving:
            record['receipt_error'] = type(saving).__name__
        error.native_candidate_result = record
        error.add_note(pending_message(record))
    except BaseException:
        pass


def _compound_response(record, *, status=None):
    response = {'workspace': record['workspace'], 'backend': 'native-image',
                'native_image_result': record['native_image_result'], 'native_operation': record,
                'mutation': 'committed', 'mount': 'verified' if record['originally_mounted'] else 'kept-unmounted',
                'cooperative_outage': True}
    if record['operation'] == COMPOUND[0]: response.update(id=record['name'], name=record['name'])
    else: response.update(snapshot=record['name'], recovery=record['recovery_name'])
    if status is not None: response['current_status'] = status
    return response


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
    from ._native_create_authority import installed
    installed(path, metadata)
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
    from ._native_create_authority import installed
    installed(path, metadata)
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
