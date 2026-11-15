"""One-hop fresh replacement, with the old journal as its sole reservation."""
import os
from pathlib import Path
import re
import uuid

from . import core, _native
from . import _native_create_request as request, _native_create_git as git
from ._native_create_recovery import require, pair, load, finalize, preflight_archive, installed_result

INHERITED = {'seed', 'seed_identity', 'commit', 'name', 'capacity_gib', 'jobs', 'budget',
             'install', 'profile', 'host', 'method', 'runtime', 'store_lock', 'seed_lock'}


def actors(record, spec, *, pending):
    rows = record.get('actors')
    require(type(rows) is list and len(rows) <= 5, 'unknown-actors')
    roles = ('00-config', '01-refs', '02-head', '03-head-state', '04-checkout')
    stage = Path(record['stage'])
    repo = stage / 'input/repo'
    prefix = ['--git-dir=' + str(repo / '.git'), '--work-tree=' + str(repo)]
    commands = [
        ['config', '--file', str(repo / '.git/config'), '--no-includes', '--null', '--list'],
        [*prefix, 'for-each-ref', '--include-root-refs', '--format=%(refname)'],
        [*prefix, 'rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}'],
        [*prefix, 'symbolic-ref', '--quiet', 'HEAD'],
        [*prefix, 'checkout', '-b', spec['branch']],
    ]
    for index, item in enumerate(rows):
        require(type(item) is dict and item.get('role') == roles[index]
                and item.get('runtime') == spec['runtime'] and item.get('environment') == git.POLICY
                and item.get('cwd') == str(stage / 'actors/environment/inspect')
                and item.get('stdout') == str(stage / 'actors' / roles[index] / 'stdout')
                and item.get('stderr') == str(stage / 'actors' / roles[index] / 'stderr')
                and type(item.get('argv')) is list and type(item.get('input')) is dict
                and type(item.get('child_pending')) is bool, 'unqualified-actor')
        executable = item.get('executable')
        require(type(executable) is dict and set(executable) == {'path', 'sha256'}
                and type(executable['path']) is str and Path(executable['path']).is_absolute()
                and Path(executable['path']).name == 'git' and executable['sha256'] == spec['runtime']['executable_sha256']
                and item['argv'] == [executable['path'], *git.PREFIX, *commands[index]], 'unqualified-actor-command')
        admitted = item['input']
        require(set(admitted) == {'repository', 'git', 'config'} and type(admitted['config']) is dict
                and set(admitted['config']) == {'file', 'sha256'}, 'unqualified-actor-input')
        core.identifier(admitted['config']['sha256'], 64)
        for identity in (admitted['repository'], admitted['git'], admitted['config']['file']):
            require(type(identity) is list and len(identity) == 2
                    and all(type(n) is int and n >= 0 for n in identity), 'unqualified-actor-input')
        require(index == 0 or admitted == rows[0]['input'], 'actor-input-disagreement')
        if item['child_pending'] or item.get('outcome') == 'unknown':
            require(pending and index == len(rows) - 1 and item.get('outcome') in ('launch-pending', 'running', 'unknown')
                    and (item['child_pending'] or item.get('reaped') is True and type(item.get('returncode')) is int),
                    'unverified-writer')
        elif item.get('outcome') == 'not-launched':
            require(item.get('pid') is None and item.get('reaped') is False and item.get('returncode') is None, 'unqualified-actor')
        else:
            require(item.get('reaped') is True and type(item.get('returncode')) is int
                    and type(item.get('pid')) is int and item['pid'] > 0
                    and item.get('streams_eof') is True and item.get('streams_durable') is True
                    and item.get('outcome') in ('success', 'error'), 'unverified-writer')
            require(type(item.get('output_bytes')) is int and 0 <= item['output_bytes'] <= git.OUTPUT_CAP
                    and not any(key in item for key in ('collector_error', 'stream_close_errors', 'receipt_error',
                                                        'interrupted', 'stop_errors')), 'unverified-writer')


def acquire(a, record):
    """Store is already held; acquire seed, lease and workspace exactly once."""
    stage = Path(record['stage'])
    spec = a.read(stage / 'create-spec.json')
    require(request.digest(spec) == record.get('spec_digest'), 'request-digest')
    seed_lock = a.root / 'locks' / ('seed-' + core.identifier(record['seed'], 64))
    a.lock(seed_lock, shared=True)
    request.bind_lock(a, seed_lock, spec['seed_lock'])
    lease = a.root / 'locks' / ('use-' + core.identifier(record['workspace'], 32))
    a.lock(lease)
    work = a.root / 'locks' / ('workspace-' + record['workspace'])
    a.lock(work)
    return request.validate(a, record), (a.fds[a.root / '.lock'], a.fds[seed_lock])


def _reservation(value, spec):
    require(type(value) is dict and set(value) == {'workspace', 'transaction', 'parent_spec_digest'}, 'invalid-reservation')
    core.identifier(value['workspace'], 32); core.identifier(value['transaction'], 32)
    require(value['workspace'] != spec['workspace'] and value['transaction'] != spec['transaction']
            and value['parent_spec_digest'] == request.digest(spec), 'reservation-disagreement')
    return {'workspace': spec['workspace'], 'transaction': spec['transaction'], 'spec_digest': request.digest(spec)}


def _child(a, record, spec, reservation, parent):
    require(record.get('workspace') == reservation['workspace'] and record.get('transaction') == reservation['transaction'], 'child-owner')
    candidate = a.read(Path(record['stage']) / 'create-spec.json')
    require(candidate.get('parent') == parent and all(candidate.get(key) == spec[key] for key in INHERITED)
            and candidate.get('stage') == str(a.root / 'staging' / ('native-create-' + reservation['transaction']))
            and candidate.get('branch') == request.branch_name(spec['name'], reservation['workspace']), 'child-request-disagreement')
    return candidate


def continue_locked(store, a, record, spec, held):
    """Never retry an attempted child on behalf of its parent."""
    require(record.get('phase') in request.PREINSTALL and 'installation' not in record and 'disposal' not in record
            and not record.get('result', {}).get('candidate_complete')
            and not a.exists(a.root / 'workspaces' / record['workspace']), 'not-replaceable')
    _native.check_pending(record['workspace'], record)
    from ._native_create_authority import current
    current(spec)
    preflight_archive(a, record, Path(record['stage']))
    actors(record, spec, pending=True)
    runtime = git.qualified_runtime(spec['host'])
    require(runtime['contract'] == spec['runtime'] and spec['method'] == request.METHOD, 'runtime-changed')
    require(spec['budget'] == request.DEFAULT_BUDGET or (type(spec['budget']) is dict and set(spec['budget']) == {'explicit'}), 'budget-policy-changed')
    base, metadata = store.object('seeds', record['seed'])
    require(pair(base.lstat()) == spec['seed_identity'] and metadata['commit'] == spec['commit']
            and metadata.get('backend', 'folder') == 'folder', 'seed-changed')
    journal = a.root / 'journals' / (record['workspace'] + '.json')
    value = record.get('replacement')
    if value is None:
        value = {'workspace': uuid.uuid4().hex, 'transaction': uuid.uuid4().hex,
                 'parent_spec_digest': request.digest(spec)}
        record['replacement'] = value
        request.publish(a, journal, record)
    parent = _reservation(value, spec)
    # Reestablish the reservation barrier even after rename-before-dirsync death.
    fd = os.open(journal.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=a.directory(journal.parent))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(a.directory(journal.parent))
    require(a.read(journal) == record, 'reservation-readback')
    child_journal = a.root / 'journals' / (value['workspace'] + '.json')
    original = {'workspace': record['workspace'], 'transaction': record['transaction']}
    # A complete later journal may be observed without trying to parse a prefix.
    child_record = None
    if a.exists(child_journal):
        try:
            child_record = a.read(child_journal)
        except (ValueError, core.StallionError):
            # Exact-prefix validation belongs only to bounded bootstrap below.
            child_record = None
        if child_record is not None and child_record.get('phase') != 'specified':
            _child(a, child_record, spec, value, parent)
            lease = a.root / 'locks' / ('use-' + value['workspace'])
            work = a.root / 'locks' / ('workspace-' + value['workspace'])
            a.lock(lease); a.lock(work)
            request.validate(a, child_record, stage_required=False)
            if child_record.get('phase') in request.PREINSTALL:
                return {'status': 'retained-child', 'workspace': value['workspace'], 'transaction': value['transaction'], 'original': original}
            loaded = load(a, value['workspace'], value['transaction'])
            return {**finalize(a, loaded), 'original': original}
    final = a.root / 'workspaces' / value['workspace']
    if not a.exists(child_journal) and a.exists(final):
        # Existing installed proof is checked by the accepted phase-one loader.
        child_spec = a.read(a.root / 'staging' / ('native-create-' + value['transaction']) / 'create-spec.json')
        request.schema(child_spec)
        require(child_spec.get('parent') == parent and all(child_spec.get(key) == spec[key] for key in INHERITED), 'child-request-disagreement')
        require(child_spec['workspace'] == value['workspace'] and child_spec['transaction'] == value['transaction'], 'child-owner')
        a.lock(a.root / 'locks' / ('use-' + value['workspace']))
        a.lock(a.root / 'locks' / ('workspace-' + value['workspace']))
        request.bind_controller(a, child_spec)
        loaded = load(a, value['workspace'], value['transaction'])
        require(loaded['status'] == 'already-installed', 'child-not-finished')
        return {**installed_result(a, loaded), 'original': original}
    # No actor has ever started in a valid bootstrap prefix. Producer receives
    # held store/seed descriptors and does not open/flock the store a second time.
    response = store._build_owned_native_candidate(spec['seed'], name=spec['name'], jobs=spec['jobs'],
        native_capacity_gib=spec['capacity_gib'], native_verification_budget=spec['budget'].get('explicit'),
        install_profile=spec['profile'] if spec['install'] else None, native_host=spec['host'], _held=held,
        _attempt={**value, 'parent': parent}, _resume=True)
    if spec['install']:
        require(response.get('installed') is True and response.get('installation_confirmed') is True,
                'replacement-installation-incomplete')
        return {'status': 'installed-unmounted', 'workspace': value['workspace'], 'transaction': value['transaction'],
                'original': original, 'path': response['candidate'], 'result': response}
    return {'status': 'replacement-created', 'workspace': value['workspace'], 'transaction': value['transaction'],
            'original': original, 'result': response}


def follow_purged(store, a, completion):
    """A compact completed parent can report/continue its one child, never reserve."""
    from ._native_creation_purge import _locked_spec
    spec = completion['spec']
    _locked_spec(a, spec)
    value = completion['replacement']
    original = {'workspace': spec['workspace'], 'transaction': spec['transaction']}
    if value is None:
        return {'status': 'purged', **original}
    parent = _reservation(value, spec)
    response = {'status': 'retained-child', 'workspace': value['workspace'], 'transaction': value['transaction'], 'original': original}
    if spec['protocol'] != request.PROTOCOL:
        return response
    stage = a.root / 'staging' / ('native-create-' + value['transaction'])
    if not a.exists(stage):
        return {**response, 'code': 'child-unavailable'}
    child_spec = a.read(stage / 'create-spec.json'); request.schema(child_spec)
    require(child_spec['parent'] == parent and all(child_spec[key] == spec[key] for key in INHERITED), 'child-request-disagreement')
    require(child_spec['workspace'] == value['workspace'] and child_spec['transaction'] == value['transaction']
            and child_spec['stage'] == str(stage), 'child-owner')
    a.lock(a.root / 'locks' / ('use-' + value['workspace']))
    a.lock(a.root / 'locks' / ('workspace-' + value['workspace']))
    request.bind_controller(a, child_spec)
    loaded = load(a, value['workspace'], value['transaction'])
    if loaded['status'] == 'purge-interrupted':
        return {**response, 'status': loaded['status'], **loaded['inspection']}
    if loaded['status'] == 'retained':
        return response
    if loaded['status'] == 'already-installed':
        return {**installed_result(a, loaded), 'original': original}
    return {**finalize(a, loaded), 'original': original}
