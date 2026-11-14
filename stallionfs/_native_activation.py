"""Versioned, one-use activation intent within the granted resource directory."""
from __future__ import annotations

import contextlib
import fcntl
import os
from pathlib import Path
import re
import stat
import uuid

from . import core

MAGIC = 'stallionfs-activation-v1'
ACTIONS = ('native-mount', 'native-mounted-snapshot', 'native-mounted-restore')
KEYS = ('version', 'operation', 'action', 'transaction', 'workspace', 'nonce',
        'parent', 'file', 'uuid', 'generation', 'root_digest', 'committed_end', 'physical_end')


def require(value):
    if not value:
        raise core.StallionError('Invalid current native activation intent')


def encode(value):
    require(type(value) is dict and set(value) == set(KEYS))
    require(type(value['version']) is int and value['version'] == 1 and value['action'] in ACTIONS)
    for key in ('operation', 'transaction', 'workspace', 'nonce', 'uuid'):
        require(type(value[key]) is str and re.fullmatch('[0-9a-f]{32}', value[key]))
    require(type(value['root_digest']) is str and re.fullmatch('[0-9a-f]{64}', value['root_digest']))
    for key in ('parent', 'file'):
        require(type(value[key]) is list and len(value[key]) == 2
                and all(type(n) is int and 0 <= n < 2**64 for n in value[key]))
    for key in ('generation', 'committed_end', 'physical_end'):
        require(type(value[key]) is int and 0 < value[key] < 2**64)
    require(value['committed_end'] <= value['physical_end'])
    fields = [MAGIC, value['action'], value['operation'], value['transaction'], value['workspace'], value['nonce'],
              *map(str, value['parent']), *map(str, value['file']), value['uuid'], str(value['generation']),
              value['root_digest'], str(value['committed_end']), str(value['physical_end']), 'rw', 'owners', 'pending']
    data = ('\n'.join(fields) + '\n').encode('ascii')
    require(len(data) <= 1024)
    return data


def argv(value, filesystem, path):
    encode(value)
    require(Path(path).name == value['workspace'])
    return ['/sbin/mount', '-F', '-t', filesystem, '-o',
            'rw,owners,sfs_activation=' + value['operation'] + '.' + value['nonce'], str(path), str(Path(path)/'volume')]


def validate_helper(record, helper, filesystem, path, transaction, guard, *, attempt=None):
    """New evidence is exact; absence selects only the historical contract."""
    evidence = record if attempt is None else attempt
    require(type(evidence) is dict)
    if 'activation_protocol' not in evidence:
        require('activation' not in helper and 'activation_version' not in helper)
        old = ['/sbin/mount', '-t', filesystem, str(path), str(Path(path)/'volume')]
        require(helper['argv'] in (old, old[:1] + ['-F'] + old[1:]))
        return
    require(type(evidence['activation_protocol']) is int and evidence['activation_protocol'] == 1)
    require('activation' in helper and 'activation_version' in helper)
    value = helper['activation']
    encode(value)
    require(helper.get('activation_version') == 1 and type(helper['activation_version']) is int)
    require(value['operation'] == record['id'] and value['action'] == record['operation']
            and value['workspace'] == record['workspace'] and value['file'] == record['target']['file']
            and value['parent'] == record['target']['parent'] and value['uuid'] == record['target']['uuid'])
    from . import _native
    require(value['transaction'] == transaction and _native._consumed(guard, record['target']))
    require(all(value[k] == guard.get(k) for k in ('generation', 'root_digest', 'committed_end', 'physical_end')))
    require(helper['argv'] == argv(value, filesystem, path))


def _directory(parent, name):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        st = os.fstat(fd)
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and st.st_mode & 0o777 == 0o700)
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextlib.contextmanager
def pending(operation, metadata, guard):
    """Hold a live controller lease through one helper; retain all attempt files.

    The consumer must observe this lock, validate the immutable request and
    exclusively create its claim before acquiring any writable backing fd.
    Closing this context prevents later transfers without PID inference. A
    transfer already linearized under the gate retains its one-use grant.
    """
    from . import _native
    target = operation.record['target']
    require(_native._consumed(guard, target))
    value = dict(version=1, operation=operation.record['id'], action=operation.record['operation'],
                 transaction=metadata['transaction'], workspace=metadata['id'], nonce=uuid.uuid4().hex,
                 parent=target['parent'], file=target['file'], uuid=target['uuid'],
                 generation=guard['generation'], root_digest=guard['root_digest'],
                 committed_end=guard['committed_end'], physical_end=guard['physical_end'])
    data = encode(value)
    fds = []
    primary = None
    gate = None
    try:
        root = _directory(None, str(operation.path)); fds.append(root)
        require([os.fstat(root).st_dev, os.fstat(root).st_ino] == target['parent'])
        operations = _directory(root, 'native-operations'); fds.append(operations)
        owner = _directory(operations, value['operation']); fds.append(owner)
        name = 'activation-' + value['nonce']
        os.mkdir(name, mode=0o700, dir_fd=owner)
        directory = _directory(owner, name); fds.append(directory)
        gate = os.open('gate', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        fds.append(gate)
        lease = os.open('lease', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        fds.append(lease); fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        request = os.open('request', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            view = memoryview(data)
            while view:
                written = os.write(request, view); require(written > 0); view = view[written:]
            os.fsync(request)
        finally:
            os.close(request)
        os.fsync(directory); os.fsync(owner)
        yield value
    except BaseException as error:
        primary = error
        raise
    finally:
        # A shared gate serializes normal revocation with the consumer's
        # transfer point. If occupied, an admitted attempt may already own its
        # one-use grant. Closing the lease prevents every later transfer; it
        # does not retroactively revoke a transfer that already linearized.
        errors = []
        if gate is not None:
            try: fcntl.flock(gate, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: pass
            except OSError as error: errors.append(error)
        for fd in reversed(fds):
            try: os.close(fd)
            except OSError as error: errors.append(error)
        if errors:
            if primary is None: raise errors[0]
            primary.add_note('Activation control descriptor close failed')


def mount(operation, metadata, filesystem, guard):
    context = getattr(operation, 'command_context', {})
    evidence = operation.record
    if operation.record['operation'] != 'native-mount':
        require(context.get('stage') == 'remount' and type(context.get('attempt')) is int)
        attempts = operation.record['remount_attempts']
        require(0 <= context['attempt'] < len(attempts))
        evidence = attempts[context['attempt']]
    require(type(evidence.get('activation_protocol')) is int and evidence['activation_protocol'] == 1)
    with pending(operation, metadata, guard) as value:
        previous = getattr(operation, 'command_context', {})
        operation.command_context = {**previous, 'activation_version': 1, 'activation': value}
        try:
            return operation.command('mount', argv(value, filesystem, operation.path))
        finally:
            operation.command_context = previous
