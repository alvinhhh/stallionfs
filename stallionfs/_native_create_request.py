"""Durable immutable requests and controller identity for native creation."""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

from . import core
from ._native_create_recovery import Admission, KEYS, pair, require, safe

PROTOCOL = 3
METHOD = 'git-exact-checkout-v3'
LEGACY_METHOD = 'git-exact-checkout-v2'
DEFAULT_BUDGET = {
    'policy': 'finite-traversal-v2-derived',
    'header_sha256': '9e4d18292efc23bda796609d9c4a0e695fca921d859562096eac6440fcad868c',
    'implementation_sha256': 'a9d2934ba3b2b21f184dc67148892d9fbc9e52f62a670d624218dec2b46460a1',
}
PREINSTALL = {'specified', 'preflight', 'clone', 'branch', 'import'}
FIELDS = {'protocol', 'workspace', 'transaction', 'seed', 'seed_identity', 'commit', 'name', 'branch',
          'capacity_gib', 'jobs', 'budget', 'install', 'profile', 'host', 'stage', 'stage_identity',
          'input_identity', 'object', 'store_lock', 'seed_lock', 'lease', 'workspace_lock', 'method', 'runtime', 'parent'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def branch_name(name, workspace):
    core.identifier(workspace, 32)
    require(isinstance(name, str) and (not name or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', name)), 'invalid-name')
    # Generated ref must obey Git's grammar, including names otherwise valid as labels.
    require('..' not in name and '@{' not in name, 'invalid-branch-name')
    return f"stallionfs/{name + '-' if name else ''}{workspace}"


def immutable(a, path, value):
    """Exclusive publication, complete data/namespace fencing, and exact readback."""
    a.check()
    parent = a.directory(path.parent)
    data = json.dumps({'format': 1, **value}, sort_keys=True, allow_nan=False).encode() + b'\n'
    fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        require(os.write(fd, data) == len(data), 'short-write', path)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent)
    require(a.read(path) == value, 'request-readback', path)
    a.check()


def publish(a, path, value):
    a.publish(path, value)
    require(a.read(path) == value, 'journal-readback', path)
    a.check()


def marker(record):
    return {**{key: record[key] for key in KEYS}, 'protocol': record['protocol'], 'spec_digest': record['spec_digest']}




def bind_lock(a, path, expected):
    """Check an already-held descriptor and its namespace, never create a replacement."""
    a.check(path)
    require(a.bindings[path] == expected, 'lock-substitution', path)


def bind_controller(a, spec):
    lease = a.root / 'locks' / ('use-' + spec['workspace'])
    work = a.root / 'locks' / ('workspace-' + spec['workspace'])
    bind_lock(a, lease, spec['lease']['file'])
    require(os.pread(a.fds[lease], 66, 0) == (spec['lease']['generation'] + '\n').encode(), 'lease-generation')
    bind_lock(a, work, spec['workspace_lock'])


def validate(a, record, *, stage_required=True):
    """Bind request/marker/journal without inspecting the old input or partial image."""
    from ._native_create_recovery import ownership, PRODUCER, PROTOCOL2
    require(type(record) is dict and set(record) <= PRODUCER | PROTOCOL2 | {'installation'}
            and record.get('phase') in PREINSTALL | {'complete', 'install'}
            and ('completion_file' not in record or 'disposal' in record)
            and type(record.get('creation_attempted')) is bool, 'request-journal-schema')
    stage = ownership(a, record, record['workspace'])
    require(type(record.get('protocol')) is int and record['protocol'] in (2, PROTOCOL), 'legacy-request')
    spec = a.read(stage / 'create-spec.json')
    schema(spec)
    require(spec['protocol'] == record['protocol'], 'request-protocol')
    require(spec['stage'] == str(a.root / 'staging' / ('native-create-' + spec['transaction'])), 'request-stage')
    require(digest(spec) == record.get('spec_digest'), 'request-digest')
    require(a.read(stage / 'native-create') == marker(record), 'marker-journal-disagreement')
    require(all(spec[key] == record[key] for key in ('workspace', 'transaction', 'seed', 'stage', 'stage_identity', 'object')), 'request-owner')
    require(spec['branch'] == branch_name(spec['name'], spec['workspace']), 'request-branch')
    require(spec['budget'] == DEFAULT_BUDGET or (type(spec['budget']) is dict and set(spec['budget']) == {'explicit'}), 'request-budget')
    bind_lock(a, a.root / '.lock', spec['store_lock'])
    require(a.bindings[stage] == spec['stage_identity'], 'stage-substitution')
    lease = a.root / 'locks' / ('use-' + record['workspace'])
    work = a.root / 'locks' / ('workspace-' + record['workspace'])
    if lease in a.fds:
        bind_lock(a, lease, spec['lease']['file'])
        require(os.pread(a.fds[lease], 66, 0) == (spec['lease']['generation'] + '\n').encode(), 'lease-generation')
    if work in a.fds:
        bind_lock(a, work, spec['workspace_lock'])
    if stage_required:
        for path, expected in ((stage / 'input', spec['input_identity']), (stage / 'owned', spec['object'])):
            info = os.stat(path.name, dir_fd=a.directory(stage), follow_symlinks=False)
            require(safe(info, True) and pair(info) == expected, 'directory-substitution', path)
    return spec



def phase(a, journal, record, value):
    require(value in PREINSTALL | {'complete', 'install'}, 'invalid-phase')
    record['phase'] = value
    publish(a, journal, record)


def encoded(value):
    return json.dumps({'format': 1, **value}, sort_keys=True, allow_nan=False).encode() + b'\n'


def generation(parent, workspace, transaction):
    parent_digest = parent['spec_digest'] if parent else None
    return hashlib.sha256(b'sfs replacement lease v1\0' + json.dumps(
        [parent_digest, workspace, transaction], separators=(',', ':')).encode()).hexdigest()


def _control(a, path, expected, *, finish=False):
    """Only append an exact expected suffix to the same bootstrap inode."""
    parent = a.directory(path.parent)
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    if not a.exists(path):
        require(finish, 'bootstrap-missing', path)
        flags |= os.O_CREAT | os.O_EXCL
    fd = os.open(path.name, flags, 0o600, dir_fd=parent)
    try:
        info = os.fstat(fd)
        require(safe(info) and info.st_size <= len(expected), 'unsafe-bootstrap-control', path)
        data = os.pread(fd, len(expected) + 1, 0)
        require(expected.startswith(data), 'bootstrap-prefix', path)
        require(pair(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == pair(info), 'bootstrap-substitution')
        if finish:
            if len(data) != len(expected):
                os.lseek(fd, len(data), os.SEEK_SET)
                require(os.write(fd, expected[len(data):]) == len(expected) - len(data), 'bootstrap-short-write')
            os.fsync(fd)
            os.fsync(parent)
            require(os.pread(fd, len(expected) + 1, 0) == expected, 'bootstrap-readback')
        return len(data) == len(expected)
    finally:
        os.close(fd)


@contextlib.contextmanager
def prepare_controller(root, held, seed_path, seed_meta, *, workspace, transaction, name, jobs, capacity,
                       budget, install_profile, host, runtime, parent=None, resume=False):
    """One bounded bootstrap, optionally completing a reserved control-only prefix."""
    from ._native_create_recovery import settings
    profile, effective_host = settings(install_profile or 'production', host)
    core.identifier(workspace, 32); core.identifier(transaction, 32)
    a = Admission(root)
    stage = a.root / 'staging' / ('native-create-' + transaction)
    lease = a.root / 'locks' / ('use-' + workspace)
    work = a.root / 'locks' / ('workspace-' + workspace)
    journal = a.root / 'journals' / (workspace + '.json')
    paths = [stage, stage / 'input', stage / 'owned', lease, work,
             stage / 'create-spec.json', stage / 'native-create', journal]
    try:
        a.directory(a.root)
        for path, descriptor in ((a.root / '.lock', held[0]),
                                 (a.root / 'locks' / ('seed-' + seed_meta['id']), held[1])):
            a.directory(path.parent)
            a.fds[path] = os.dup(descriptor)
            a.bindings[path] = pair(os.fstat(descriptor))
            a.check(path)
            os.fsync(descriptor)
            os.fsync(a.directory(path.parent))
        present = [os.path.lexists(path) for path in paths]
        require(resume or not any(present), 'bootstrap-collision')
        require(not a.exists(a.root / 'workspaces' / workspace)
                and not a.exists(a.root / 'lifecycle' / (workspace + '.json')), 'bootstrap-final-collision')
        # Only a dependency prefix can have been produced before the effect barrier.
        require(present == sorted(present, reverse=True), 'bootstrap-dependency-gap')
        if present[0]:
            require(set(a.names(stage)) <= {'input', 'owned', 'create-spec.json', 'native-create'}, 'bootstrap-extra')
        for path, exists in zip(paths[1:3], present[1:3]):
            if exists:
                require(not a.names(path), 'bootstrap-payload')
        lease_data = (generation(parent, workspace, transaction) + '\n').encode()
        if present[3]:
            complete = _control(a, lease, lease_data)
            require(complete or not any(present[4:]), 'bootstrap-dependency-incomplete')
        if present[4]:
            require(_control(a, work, b''), 'bootstrap-workspace-lock')

        def values():
            spec = {'protocol': PROTOCOL, 'workspace': workspace, 'transaction': transaction, 'seed': seed_meta['id'],
                'seed_identity': pair(seed_path.lstat()), 'commit': seed_meta['commit'], 'name': name,
                'branch': branch_name(name, workspace), 'capacity_gib': capacity, 'jobs': jobs,
                'budget': {'explicit': budget} if budget is not None else DEFAULT_BUDGET.copy(),
                'install': install_profile is not None, 'profile': profile, 'host': effective_host,
                'stage': str(stage), 'stage_identity': pair(stage.lstat()), 'input_identity': pair((stage / 'input').lstat()),
                'object': pair((stage / 'owned').lstat()), 'store_lock': pair(os.fstat(held[0])),
                'seed_lock': pair(os.fstat(held[1])), 'lease': {'file': pair(lease.lstat()), 'generation': lease_data.decode().strip()},
                'workspace_lock': pair(work.lstat()), 'method': METHOD, 'runtime': runtime, 'parent': parent}
            record = {'operation': 'native-create', 'transaction': transaction, 'workspace': workspace, 'seed': seed_meta['id'],
                'stage': str(stage), 'stage_identity': spec['stage_identity'], 'candidate': str(stage / 'owned'),
                'object': spec['object'], 'final': str(a.root / 'workspaces' / workspace),
                'creation_attempted': False, 'outcome': 'preparing',
                'native_image': {'component': 'image.sfs', 'file': None, 'uuid': None, 'anchor': None},
                'protocol': PROTOCOL, 'spec_digest': digest(spec), 'phase': 'specified', 'actors': []}
            return spec, record
        # Validate every existing control BEFORE completing even an earlier suffix.
        if present[5]:
            spec, record = values()
            for index, expected in ((5, spec), (6, marker(record)), (7, record)):
                if present[index]:
                    complete = _control(a, paths[index], encoded(expected))
                    require(complete or not any(present[index + 1:]), 'bootstrap-dependency-incomplete')
        for path in paths[:3]:
            if not os.path.lexists(path):
                os.mkdir(path.name, mode=0o700, dir_fd=a.directory(path.parent))
            a.directory(path)
            os.fsync(a.directory(path))
            os.fsync(a.directory(path.parent))
        # Holding a descriptor is not permission to refresh an existing identity.
        for path, expected in ((lease, lease_data), (work, b'')):
            if not a.exists(path):
                fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=a.directory(path.parent))
                os.close(fd)
            a.lock(path)
            _control(a, path, expected, finish=True)
        spec, record = values()
        for path, value in ((paths[5], spec), (paths[6], marker(record)), (journal, record)):
            _control(a, path, encoded(value), finish=True)
            require(a.read(path) == value, 'bootstrap-readback')
        validate(a, record)
        yield a, spec, record
        a.check()
    finally:
        a.close()


def schema(spec):
    from ._native_create_recovery import settings, BUDGET_KEYS
    from . import _bundle
    from ._bundle import PUBLISHER_TEAM
    require(type(spec) is dict and set(spec) == FIELDS and type(spec['protocol']) is int
            and spec['protocol'] in (2, PROTOCOL)
            and spec['method'] == (LEGACY_METHOD if spec['protocol'] == 2 else METHOD), 'request-schema')
    for key, length in (('workspace', 32), ('transaction', 32), ('seed', 64)):
        core.identifier(spec[key], length)
    require(type(spec['commit']) is str and re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', spec['commit'])
            and spec['branch'] == branch_name(spec['name'], spec['workspace'])
            and type(spec['capacity_gib']) is int and 1 <= spec['capacity_gib'] <= 65536
            and type(spec['jobs']) is int and 1 <= spec['jobs'] <= 4
            and type(spec['install']) is bool, 'request-values')
    settings(spec['profile'], spec['host'])
    for key in ('seed_identity', 'stage_identity', 'input_identity', 'object', 'store_lock', 'seed_lock', 'workspace_lock'):
        require(type(spec[key]) is list and len(spec[key]) == 2
                and all(type(n) is int and n >= 0 for n in spec[key]), 'request-identity')
    lease = spec['lease']
    require(type(lease) is dict and set(lease) == {'file', 'generation'} and type(lease['file']) is list
            and len(lease['file']) == 2 and all(type(n) is int and n >= 0 for n in lease['file'])
            and type(lease['generation']) is str and re.fullmatch('[0-9a-f]{64}', lease['generation']), 'request-lease')
    parent = spec['parent']
    if parent is not None:
        require(type(parent) is dict and set(parent) == {'workspace', 'transaction', 'spec_digest'}, 'request-parent')
        core.identifier(parent['workspace'], 32); core.identifier(parent['transaction'], 32); core.identifier(parent['spec_digest'], 64)
    require(lease['generation'] == generation(parent, spec['workspace'], spec['transaction']), 'request-generation')
    budget = spec['budget']
    if budget != DEFAULT_BUDGET:
        require(type(budget) is dict and set(budget) == {'explicit'} and type(budget['explicit']) is dict
                and set(budget['explicit']) == BUDGET_KEYS
                and all(type(n) is int and 0 < n < 1 << 64 for n in budget['explicit'].values()), 'request-budget')
    runtime = spec['runtime']
    contract = _bundle.LEGACY_GIT_CONTRACT if spec['protocol'] == 2 else _bundle.GIT_CONTRACT
    require(type(runtime) is dict and set(runtime) == set(contract) | {'input_inventory_sha256', 'payload_entries', 'payload_sha256',
                'descriptor_sha256', 'executable_sha256', 'source_build_id', 'publisher'}
            and all(runtime[key] == value for key, value in contract.items())
            and runtime['publisher'] == PUBLISHER_TEAM and type(runtime['payload_entries']) is int
            and 0 < runtime['payload_entries'] <= 4096, 'request-runtime')
    for key in ('input_inventory_sha256', 'payload_sha256', 'descriptor_sha256', 'executable_sha256', 'source_build_id'):
        core.identifier(runtime[key], 64)
