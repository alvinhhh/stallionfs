"""Deliberate, journaled disposal of an exactly selected pre-install creation."""
from __future__ import annotations

import os
from pathlib import Path
import stat

from . import core, _native
from . import _native_create_request as request
from ._native_create_recovery import require, pair, safe, diagnostic

ACTORS = ('00-config', '01-refs', '02-head', '03-head-state', '04-checkout')


def isolation(a, record, backing):
    stage = Path(record['stage'])
    from ._scan import mounts
    require(not any(Path(row['path']) == stage or Path(row['path']).is_relative_to(stage)
                    for row in mounts()), 'occupied-stage')
    for name in a.names(a.root / 'journals'):
        if name == record['workspace'] + '.json':
            continue
        other = a.read(a.root / 'journals' / name)
        require(not any(other.get(key) == record[key] for key in ('workspace', 'transaction', 'stage', 'object')),
                'conflicting-owner')
    for kind in ('workspaces', 'trash'):
        container = a.root / kind
        for name in a.names(container):
            metadata = a.read(container / name / 'meta.json')
            target = metadata.get('native_image', {})
            require(type(target) is dict and target.get('directory') != str(stage / 'owned')
                    and (backing is None or target.get('file') != backing), 'external-backing-reference')


def writers(record):
    """A free controller lease cannot repair missing process completion evidence."""
    if 'helpers' in record or 'child_pending' in record:
        try:
            _native.check_helpers(record, {'verify-package', 'discover'})
        except core.StallionError:
            require(False, 'unverified-writer')
    actors = record.get('actors')
    require(type(actors) is list and len(actors) <= len(ACTORS), 'unverified-writer')
    for number, actor in enumerate(actors):
        require(type(actor) is dict and actor.get('role') == ACTORS[number]
                and actor.get('environment') == 'native-git-empty-environment-v3', 'unverified-writer')
        if actor.get('outcome') == 'not-launched':
            require(actor.get('pid') is None and actor.get('reaped') is False
                    and actor.get('child_pending') is False and actor.get('returncode') is None, 'unverified-writer')
        else:
            require(actor.get('child_pending') is False and actor.get('reaped') is True
                    and type(actor.get('returncode')) is int and actor.get('streams_eof') is True
                    and actor.get('streams_durable') is True and actor.get('outcome') in ('success', 'error')
                    and not actor.get('stream_close_errors') and not actor.get('receipt_error'), 'unverified-writer')


def scope(a, record, spec):
    """Fixed metadata grammar; the clone tree uses the existing native deleter."""
    stage = Path(record['stage'])
    require(record.get('phase') in request.PREINSTALL and 'installation' not in record
            and not a.exists(a.root / 'workspaces' / record['workspace']), 'installation-entered')
    require(set(a.names(stage)) <= {'input', 'owned', 'actors', 'discovery', 'create-spec.json', 'native-create'}, 'unexpected-stage-entry')
    result = []
    def entry(path, kind):
        parent = a.directory(path.parent)
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        require(info.st_dev == os.fstat(parent).st_dev, 'foreign-filesystem')
        if kind == 'tree':
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), 'unsafe-input')
        else:
            require(safe(info, kind == 'directory'), 'unsafe-disposal-entry', path)
        result.append({'path': str(path.relative_to(stage)), 'kind': kind, 'file': pair(info), 'authorized': False,
                       **({'stamp': [info.st_size, info.st_mtime_ns, info.st_ctime_ns]} if kind == 'file' else {})})
    source = stage / 'input'
    require(set(a.names(source)) <= {'repo'}, 'unexpected-input-entry')
    if a.exists(source / 'repo'):
        entry(source / 'repo', 'tree')
    owned = stage / 'owned'
    require(set(a.names(owned)) <= {'image.sfs', 'meta.json', 'native-create.json'}, 'unexpected-owned-entry')
    backing = pair(os.stat('image.sfs', dir_fd=a.directory(owned), follow_symlinks=False)) if a.exists(owned / 'image.sfs') else None
    isolation(a, record, backing)
    for name in ('image.sfs', 'meta.json', 'native-create.json'):
        if a.exists(owned / name):
            if name != 'image.sfs':
                a.read(owned / name)
            entry(owned / name, 'file')
    if a.exists(stage / 'actors'):
        actors = stage / 'actors'
        names = a.names(actors)
        require(set(names) <= {'environment', *ACTORS}, 'unexpected-actor-entry')
        for number, role in enumerate(ACTORS):
            path = actors / role
            if not a.exists(path):
                require(number >= len(record['actors']), 'missing-actor-logs')
                continue
            require(number < len(record['actors']), 'unattributed-actor-logs')
            require(set(a.names(path)) <= {'stdout', 'stderr'}, 'unexpected-actor-log')
            for name in ('stdout', 'stderr'):
                if a.exists(path / name):
                    entry(path / name, 'file')
            entry(path, 'directory')
        env = actors / 'environment'
        if a.exists(env):
            require(set(a.names(env)) <= {'home', 'xdg', 'tmp', 'inspect', 'empty-config'}, 'unexpected-environment')
            for name in ('home', 'xdg', 'tmp', 'inspect'):
                if a.exists(env / name):
                    require(not a.names(env / name), 'occupied-environment')
                    entry(env / name, 'directory')
            if a.exists(env / 'empty-config'):
                require(os.stat('empty-config', dir_fd=a.directory(env), follow_symlinks=False).st_size == 0, 'changed-empty-config')
                entry(env / 'empty-config', 'file')
            entry(env, 'directory')
        entry(actors, 'directory')
    if a.exists(stage / 'discovery'):
        discovery = stage / 'discovery'
        require(set(a.names(discovery)) <= {'record.json', '00-verify-package', '01-discover'}, 'unexpected-discovery')
        require('helpers' in record, 'unattributed-discovery')
        archived = a.read(discovery / 'record.json')
        require(archived.get('workspace') == record['workspace'] and archived.get('transaction') == record['transaction']
                and archived.get('helpers') == record['helpers'] and archived.get('child_pending') is False, 'discovery-disagreement')
        for number, role in enumerate(('00-verify-package', '01-discover')):
            path = discovery / role
            if not a.exists(path):
                require(number >= len(record['helpers']), 'missing-helper-logs')
                continue
            require(number < len(record['helpers']) and set(a.names(path)) <= {'stdout', 'stderr'}, 'unexpected-helper-logs')
            for name in ('stdout', 'stderr'):
                if a.exists(path / name):
                    entry(path / name, 'file')
            entry(path, 'directory')
        entry(discovery / 'record.json', 'file')
        entry(discovery, 'directory')
    for path in (source, owned):
        entry(path, 'directory')
    for name in ('native-create', 'create-spec.json'):
        entry(stage / name, 'file')
    result.append({'path': '.', 'kind': 'directory', 'file': spec['stage_identity'], 'authorized': False})
    return result


def _forget_binding(a, path):
    a.bindings.pop(path, None)
    a.files.pop(path, None)
    descriptor = a.fds.pop(path, None)
    if descriptor is not None:
        os.close(descriptor)


def _validate_remaining(a, stage, entries):
    """Reject substitutions and unexpected siblings before any resumed removal."""
    by_parent = {}
    for item in entries:
        path = stage if item['path'] == '.' else stage / item['path']
        require(path == stage or path.is_relative_to(stage), 'disposal-path')
        if not path.parent.exists():
            require(item['authorized'] is True, 'missing-disposal-parent')
            continue
        parent = a.directory(path.parent)
        try:
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            require(item['authorized'] is True, 'unexplained-absence')
            continue
        require(pair(info) == item['file'], 'disposal-substitution', path)
        require(stat.S_ISDIR(info.st_mode) if item['kind'] in ('tree', 'directory') else safe(info), 'unsafe-disposal-entry')
        if item['kind'] == 'file':
            require(item['stamp'] == [info.st_size, info.st_mtime_ns, info.st_ctime_ns], 'disposal-content-changed')
        by_parent.setdefault(path.parent, set()).add(path.name)
    for parent, names in by_parent.items():
        if parent == stage.parent:
            continue
        require(set(a.names(parent)) <= names, 'unexpected-disposal-entry', parent)


def completion_value(record):
    return {'operation': 'native-create-purge', 'workspace': record['workspace'], 'transaction': record['transaction'],
            'spec_digest': record['spec_digest'], 'stage': record['stage'], 'stage_identity': record['stage_identity'],
            'spec': record['disposal']['spec'], 'replacement': record.get('replacement'), 'disposal': record['disposal']}


def _completion_prefix(a, path, fd, expected, identity=None):
    info = os.fstat(fd)
    require(safe(info) and info.st_size <= len(expected), 'unsafe-completion', path)
    require(identity is None or pair(info) == identity, 'completion-substitution', path)
    data = os.pread(fd, len(expected) + 1, 0)
    after = os.stat(path.name, dir_fd=a.directory(path.parent), follow_symlinks=False)
    require(safe(after) and (pair(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            == (pair(after), after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'completion-substitution', path)
    require(len(data) == info.st_size and expected.startswith(data), 'completion-conflict', path)
    return info, len(data)


def fence_record(a, path, value):
    """Reestablish authority after a previous file/namespace fence may have failed."""
    require(a.read(path) == value, 'journal-changed', path)
    parent = a.directory(path.parent)
    fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        require(pair(os.fstat(fd)) == a.files[path][0], 'metadata-substitution', path)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent)
    require(a.read(path) == value, 'journal-readback', path)


def publish_completion(a, record):
    """Finish only the reserved exact prefix, then fence it before journal retirement."""
    from ._native_create_recovery import MAX_DOCUMENT_BYTES
    path = a.root / 'lifecycle' / (record['workspace'] + '.json')
    journal = a.root / 'journals' / (record['workspace'] + '.json')
    value = completion_value(record)
    data = request.encoded(value)
    require(len(data) <= MAX_DOCUMENT_BYTES, 'document-budget', path)
    parent = a.directory(path.parent)
    exists = a.exists(path)
    require(exists or 'completion_file' not in record, 'missing-completion', path)
    fd = os.open(path.name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                 | (0 if exists else os.O_CREAT | os.O_EXCL), 0o600, dir_fd=parent)
    try:
        info, length = _completion_prefix(a, path, fd, data, record.get('completion_file'))
        if 'completion_file' not in record:
            # Fence the reserved control inode before durably recording its identity.
            os.fsync(fd)
            os.fsync(parent)
            record['completion_file'] = pair(info)
            request.publish(a, journal, record)
            current, current_length = _completion_prefix(a, path, fd, data, record['completion_file'])
            require((current_length, current.st_mtime_ns, current.st_ctime_ns)
                    == (length, info.st_mtime_ns, info.st_ctime_ns), 'completion-substitution', path)
        os.lseek(fd, length, os.SEEK_SET)
        while length < len(data):
            written = os.write(fd, data[length:])
            require(written > 0, 'short-write', path)
            length += written
        os.fsync(fd)
        info, length = _completion_prefix(a, path, fd, data, record['completion_file'])
        require(length == len(data), 'completion-readback', path)
        # This exact inode was changed only by the admitted append above.
        a.files[path] = (pair(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    finally:
        os.close(fd)
    os.fsync(parent)
    require(a.read(path) == value, 'completion-readback', path)
    a.check()
    return value


def disposal_state(a, record, workspace, transaction=None):
    """Read-only recovery from the journal, even after its stage controls are gone."""
    from ._native_create_recovery import PRODUCER, PROTOCOL2, ownership
    require(type(record) is dict and set(record) <= PRODUCER | PROTOCOL2
            and record.get('operation') == 'native-create' and record.get('protocol') in (2, 3)
            and record.get('workspace') == workspace
            and (transaction is None or record.get('transaction') == transaction), 'transaction-mismatch')
    stage = ownership(a, record, workspace)
    disposal = record.get('disposal')
    require(type(disposal) is dict and set(disposal) == {'spec', 'entries'}, 'invalid-disposal')
    spec = disposal['spec']; request.schema(spec)
    require(request.digest(spec) == record.get('spec_digest')
            and all(spec[key] == record[key] for key in ('workspace', 'transaction', 'seed', 'stage', 'stage_identity', 'object'))
            and stage == a.root / 'staging' / ('native-create-' + spec['transaction']), 'request-digest')
    request.bind_lock(a, a.root / '.lock', spec['store_lock'])
    require(record.get('phase') in request.PREINSTALL and record.get('result', {}).get('candidate_complete') is not True
            and not a.exists(a.root / 'workspaces' / workspace), 'installation-entered')
    _entries(disposal['entries'])
    identities = {item['path']: item['file'] for item in disposal['entries']}
    require(identities['.'] == spec['stage_identity'] and identities['input'] == spec['input_identity']
            and identities['owned'] == spec['object'], 'disposal-request-disagreement')
    _validate_remaining(a, stage, disposal['entries'])
    for name, expected in (('create-spec.json', spec), ('native-create', request.marker(record))):
        if a.exists(stage) and a.exists(stage / name):
            require(a.read(stage / name) == expected, 'disposal-control-disagreement')
    if record.get('replacement') is not None:
        from ._native_create_retry import _reservation
        _reservation(record['replacement'], spec)
    identity = record.get('completion_file')
    require(identity is None or type(identity) is list and len(identity) == 2
            and all(type(n) is int and n >= 0 for n in identity), 'invalid-completion-identity')
    path = a.root / 'lifecycle' / (workspace + '.json')
    if a.exists(path):
        require(all(item.get('absent') is True for item in disposal['entries']), 'premature-completion')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=a.directory(path.parent))
        try:
            _completion_prefix(a, path, fd, request.encoded(completion_value(record)), identity)
        finally:
            os.close(fd)
    else:
        require(identity is None, 'missing-completion')
    return {'status': 'purge-interrupted', 'path': stage, 'stage': stage, 'record': record,
            'journal': a.root / 'journals' / (workspace + '.json'), 'spec': spec,
            'origin': {'id': workspace, 'transaction': record['transaction']},
            'inspection': {'stage': str(stage), 'input': str(stage / 'input/repo'),
                'backing': str(stage / 'owned/image.sfs'), 'replacement': record.get('replacement'),
                'disposal': {'entries': disposal['entries'], 'completion_pending': True}}}


def execute(a, record):
    from ._native_create_authority import current
    current(record['disposal']['spec'])
    journal = a.root / 'journals' / (record['workspace'] + '.json')
    disposal = record['disposal']
    stage = Path(record['stage'])
    _validate_remaining(a, stage, disposal['entries'])
    fence_record(a, journal, record)
    for item in disposal['entries']:
        path = stage if item['path'] == '.' else stage / item['path']
        if not item['authorized']:
            item['authorized'] = True
            request.publish(a, journal, record)
        if path.parent.exists():
            parent = a.directory(path.parent)
            try:
                info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                require(pair(info) == item['file'], 'disposal-substitution', path)
                a.check()
                if item['kind'] == 'tree':
                    core.remove_tree(path, jobs=1)
                elif item['kind'] == 'directory':
                    os.rmdir(path.name, dir_fd=parent)
                else:
                    os.unlink(path.name, dir_fd=parent)
                _forget_binding(a, path)
            os.fsync(parent)
        item['absent'] = True
        request.publish(a, journal, record)
    publish_completion(a, record)
    require(a.read(journal) == record, 'journal-changed')
    os.unlink(journal.name, dir_fd=a.directory(journal.parent))
    a.files.pop(journal, None)
    os.fsync(a.directory(journal.parent))
    return {'status': 'purged', 'workspace': record['workspace'], 'transaction': record['transaction'],
            'replacement': record.get('replacement')}


def _entries(entries):
    allowed = {'input/repo': 'tree', 'input': 'directory', 'owned': 'directory',
               'owned/image.sfs': 'file', 'owned/meta.json': 'file', 'owned/native-create.json': 'file',
               'native-create': 'file', 'create-spec.json': 'file', '.': 'directory',
               'actors': 'directory', 'actors/environment': 'directory',
               'actors/environment/empty-config': 'file', 'discovery': 'directory', 'discovery/record.json': 'file'}
    for name in ('home', 'xdg', 'tmp', 'inspect'):
        allowed['actors/environment/' + name] = 'directory'
    for parent in [*('actors/' + name for name in ACTORS), 'discovery/00-verify-package', 'discovery/01-discover']:
        allowed[parent] = 'directory'
        for name in ('stdout', 'stderr'):
            allowed[parent + '/' + name] = 'file'
    require(type(entries) is list and 0 < len(entries) <= len(allowed), 'invalid-disposal-manifest')
    seen = set()
    for item in entries:
        require(type(item) is dict and set(item) <= {'path', 'kind', 'file', 'authorized', 'absent', 'stamp'}
                and item.get('path') in allowed and item.get('kind') == allowed[item['path']]
                and item['path'] not in seen and type(item.get('authorized')) is bool
                and type(item.get('file')) is list and len(item['file']) == 2
                and all(type(n) is int and n >= 0 for n in item['file'])
                and ('absent' not in item or item['absent'] is True and item['authorized']), 'invalid-disposal-entry')
        seen.add(item['path'])
        require((item['kind'] != 'file' and 'stamp' not in item) or (item['kind'] == 'file'
                and type(item.get('stamp')) is list and len(item['stamp']) == 3
                and all(type(n) is int and n >= 0 for n in item['stamp'])), 'invalid-disposal-stamp')
    require(entries[-1]['path'] == '.' and {'input', 'owned', 'native-create', 'create-spec.json'} <= seen,
            'invalid-disposal-order')
    positions = {item['path']: index for index, item in enumerate(entries)}
    for name, index in positions.items():
        for parent in Path(name).parents:
            if str(parent) in positions:
                require(index < positions[str(parent)], 'invalid-disposal-order')


def _locked_spec(a, spec):
    request.schema(spec)
    request.bind_lock(a, a.root / '.lock', spec['store_lock'])
    seed = a.root / 'locks' / ('seed-' + core.identifier(spec['seed'], 64))
    a.lock(seed, shared=True)
    request.bind_lock(a, seed, spec['seed_lock'])
    lease = a.root / 'locks' / ('use-' + core.identifier(spec['workspace'], 32))
    a.lock(lease)
    request.bind_lock(a, lease, spec['lease']['file'])
    require(os.pread(a.fds[lease], 66, 0) == (spec['lease']['generation'] + '\n').encode(), 'lease-generation')
    work = a.root / 'locks' / ('workspace-' + spec['workspace'])
    a.lock(work)
    request.bind_lock(a, work, spec['workspace_lock'])


def purge_creation(root, workspace, transaction, *, confirm=False):
    response = {'status': 'blocked', 'workspace': workspace, 'transaction': transaction, 'files_removed': False}
    started = False
    observed_disposal = False
    try:
        core.identifier(workspace, 32)
        core.identifier(transaction, 32)
        with core.Store.existing(root, shared=False) as (_, a):
            journal = a.root / 'journals' / (workspace + '.json')
            complete = a.root / 'lifecycle' / (workspace + '.json')
            if not a.exists(journal):
                completion = completed(a, workspace, transaction)
                require(completion is not None, 'completion-conflict')
                _locked_spec(a, completion['spec'])
                if confirm:
                    fence_record(a, complete, completion)
                    os.fsync(a.directory(journal.parent))
                return {**response, 'status': 'purged', 'already_complete': True, 'replacement': completion.get('replacement')}
            record = a.read(journal)
            require(record.get('operation') == 'native-create' and record.get('protocol') in (2, 3)
                    and record.get('workspace') == workspace and record.get('transaction') == transaction, 'transaction-mismatch')
            stage = Path(record['stage'])
            require(stage.parent == a.root / 'staging' and stage.name == 'native-create-' + transaction, 'invalid-location')
            disposal = record.get('disposal')
            require(disposal is not None or 'completion_file' not in record, 'premature-completion')
            spec = disposal['spec'] if disposal is not None else a.read(stage / 'create-spec.json')
            require(request.digest(spec) == record.get('spec_digest') and spec['workspace'] == workspace
                    and spec['transaction'] == transaction and spec['stage'] == str(stage), 'request-digest')
            if disposal is not None:
                observed = disposal_state(a, record, workspace, transaction)
                response.update(observed['inspection'])
                observed_disposal = True
            from ._native_create_authority import current
            current(spec)
            _locked_spec(a, spec)
            require(record.get('phase') in request.PREINSTALL and 'installation' not in record
                    and record.get('result', {}).get('candidate_complete') is not True
                    and not a.exists(a.root / 'workspaces' / workspace), 'installation-entered')
            writers(record)
            from ._native_create_retry import actors
            actors(record, spec, pending=False)
            if disposal is None:
                request.validate(a, record)
                from ._native_create_recovery import preflight_archive
                preflight_archive(a, record, stage)
                entries = scope(a, record, spec)
                disposal = {'spec': spec, 'entries': entries}
            else:
                disposal_state(a, record, workspace, transaction)
                backing = next((item['file'] for item in disposal['entries'] if item['path'] == 'owned/image.sfs'), None)
                isolation(a, record, backing)
            response.update(stage=str(stage), input=str(stage / 'input/repo'), backing=str(stage / 'owned/image.sfs'),
                            replacement=record.get('replacement'), eligible=True)
            if not confirm:
                if 'disposal' in record:
                    return {**response, 'status': 'interrupted', 'files_removed': None,
                            'disposal': {'entries': disposal['entries'], 'completion_pending': True}}
                return {**response, 'status': 'preview'}
            _entries(disposal['entries'])
            if 'disposal' not in record:
                record['disposal'] = disposal
                request.publish(a, journal, record)
            started = True
            return execute(a, record)
    except (OSError, ValueError, TypeError, KeyError, RecursionError, core.StallionError, KeyboardInterrupt) as error:
        response.update(diagnostic(error))
        if started or observed_disposal:
            response['status'] = 'interrupted'
            response['files_removed'] = None
        elif isinstance(error, BlockingIOError) or getattr(error, 'code', None) in {'unverified-writer', 'unqualified-actor', 'unqualified-actor-command', 'unqualified-actor-input', 'actor-input-disagreement'}:
            response['status'] = 'writer-unverified'
    return response


def completed(a, workspace, transaction=None):
    path = a.root / 'lifecycle' / (workspace + '.json')
    if not a.exists(path):
        return None
    value = a.read(path)
    if value.get('operation') != 'native-create-purge':
        return None
    require(set(value) == {'operation', 'workspace', 'transaction', 'spec_digest', 'stage', 'stage_identity',
                           'spec', 'replacement', 'disposal'} and value['workspace'] == workspace
            and (transaction is None or value['transaction'] == transaction), 'completion-conflict')
    spec = value['spec']; request.schema(spec)
    require(request.digest(spec) == value['spec_digest'] and spec['workspace'] == workspace
            and spec['transaction'] == value['transaction'] and spec['stage'] == value['stage']
            and spec['stage_identity'] == value['stage_identity'] and value['disposal']['spec'] == spec
            and value['stage'] == str(a.root / 'staging' / ('native-create-' + value['transaction'])), 'completion-disagreement')
    _entries(value['disposal']['entries'])
    require(all(item.get('authorized') is True and item.get('absent') is True for item in value['disposal']['entries']),
            'incomplete-disposal')
    require(not a.exists(Path(value['stage'])) and not a.exists(a.root / 'workspaces' / workspace), 'namespace-reused')
    request.bind_lock(a, a.root / '.lock', spec['store_lock'])
    if value['replacement'] is not None:
        from ._native_create_retry import _reservation
        _reservation(value['replacement'], spec)
    journal = a.root / 'journals' / (workspace + '.json')
    if a.exists(journal):
        record = a.read(journal)
        require(all(record.get(key) == value[key] for key in ('workspace', 'transaction', 'spec_digest', 'stage', 'stage_identity'))
                and record.get('disposal') == value['disposal'] and record.get('replacement') == value['replacement'],
                'completion-journal-disagreement')
        if 'completion_file' in record:
            require(a.files[path][0] == record['completion_file'], 'completion-substitution')
    return value
