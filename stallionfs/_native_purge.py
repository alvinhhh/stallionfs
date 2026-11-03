"""Explicit, journaled deletion of one owned native trash resource."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from . import core, _native, _native_recovery as recovery

MAX_ENTRIES = 16384
MAX_INTENT_BYTES = 8 * 1024 * 1024
STAGES = ('prepared', 'container-ready', 'relocation-authorized', 'relocated',
          'image-unlink-authorized', 'image-absent', 'metadata-removal-authorized',
          'resource-removal-authorized', 'container-removal-authorized', 'complete')
PARENTS = ('trash', 'workspaces', 'staging', 'protected', 'journals', 'lifecycle')
PROOFS = {'meta.json', 'native-create.json', 'native-install.json', 'native-location.json', 'native-mount.json'}
REQUIRED = {'image.sfs', 'meta.json', 'native-create.json', 'native-install.json', 'native-location.json', 'volume', 'native-operations'}


def refuse(message):
    raise core.StallionError('Native purge retained: ' + message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'owner': info.st_uid,
            'mode': info.st_mode, 'links': info.st_nlink}


def valid_identity(value, *, directory=False):
    return (type(value) is dict and set(value) == {'device', 'inode', 'owner', 'mode', 'links'}
        and all(type(n) is int and n >= 0 for n in value.values())
        and value['owner'] == os.getuid() and not value['mode'] & 0o077
        and (stat.S_ISDIR(value['mode']) if directory else stat.S_ISREG(value['mode']) and value['links'] == 1))


def matches(info, expected, *, directory=False):
    found = identity(info)
    # Directory link counts change as the authorized child directories disappear.
    if directory: found['links'] = expected['links']
    return valid_identity(found, directory=directory) and found == expected


def at(parent, name):
    try: return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError: return None


def checked(parent, name, expected, *, directory=False, missing=False):
    info = at(parent, name)
    if info is None:
        if missing: return None
        refuse('recorded entry is missing: ' + name)
    if not matches(info, expected, directory=directory): refuse('entry identity changed: ' + name)
    return info


@contextlib.contextmanager
def descriptors(record):
    """All purge directory descriptors close even when a primary operation fails."""
    held = []
    primary = None
    def opening(parent, name, expected=None):
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        held.append(fd)
        info = os.fstat(fd)
        if not valid_identity(identity(info), directory=True): refuse('unsafe directory: ' + str(name))
        if expected is not None and not matches(info, expected, directory=True): refuse('directory replaced: ' + str(name))
        if not matches(os.stat(name, dir_fd=parent, follow_symlinks=False), identity(info), directory=True):
            refuse('directory changed while opening: ' + str(name))
        return fd
    def closing(fd):
        held.remove(fd)
        os.close(fd)
    opening.close = closing
    try: yield opening
    except BaseException as error:
        primary = error
        raise
    finally:
        first = None
        for fd in reversed(held):
            try: os.close(fd)
            except BaseException as error:
                if first is None: first = error
        if first is not None:
            try: record['descriptor_close_error'] = type(first).__name__
            except BaseException: pass
            if primary is None: raise first


def read_file(parent, name, expected=None):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    primary = None
    try:
        info = os.fstat(fd)
        if not valid_identity(identity(info)) or (expected is not None and not matches(info, expected)):
            refuse('unsafe metadata: ' + name)
        data = bytearray()
        while len(data) <= MAX_INTENT_BYTES:
            part = os.read(fd, min(65536, MAX_INTENT_BYTES + 1 - len(data)))
            if not part: break
            data.extend(part)
        if len(data) > MAX_INTENT_BYTES: raise core.MetadataLimitError('Native purge retained: metadata exceeds 8 MiB limit')
        if not matches(os.stat(name, dir_fd=parent, follow_symlinks=False), identity(info)):
            refuse('metadata changed while reading: ' + name)
        return bytes(data), identity(info)
    except BaseException as error:
        primary = error
        raise
    finally:
        try: os.close(fd)
        except BaseException:
            if primary is None: raise


def names(fd):
    result = []
    with os.scandir(fd) as entries:
        for entry in entries:
            result.append(entry.name)
            if len(result) > MAX_ENTRIES: refuse('manifest exceeds 16384 entries')
    return sorted(result)


def record_json(data):
    try:
        value = json.loads(data)
        if type(value) is not dict or value.get('format') != 1: raise ValueError('format')
        return value
    except (ValueError, UnicodeError): refuse('invalid metadata record')


def scan(opening, resource, workspace):
    """Enumerate only the fixed resource grammar; never traverse arbitrary trees."""
    result = []
    def add(fd, name, relative, directory=False, proof=False):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        ident = identity(info)
        if not valid_identity(ident, directory=directory) or info.st_dev != os.fstat(resource).st_dev:
            refuse('unsafe manifest entry: ' + relative)
        row = {'path': relative, 'kind': 'directory' if directory else 'file', 'identity': ident}
        data = None
        if proof:
            data, same = read_file(fd, name, ident)
            row['sha256'] = hashlib.sha256(data).hexdigest()
        result.append(row)
        if len(result) > MAX_ENTRIES: refuse('manifest exceeds 16384 entries')
        return data
    present = set(names(resource))
    if not REQUIRED <= present or not present <= REQUIRED | {'native-mount.json'}:
        refuse('unexpected or missing resource entries')
    for name in sorted(present):
        if name in ('volume', 'native-operations'):
            add(resource, name, name, directory=True)
            directory = opening(resource, name)
            if name == 'volume':
                if names(directory): refuse('unmounted volume must be empty')
                opening.close(directory)
                continue
            for op in names(directory):
                if not re.fullmatch('[0-9a-f]{32}', op): refuse('unexpected operation directory')
                prefix = name + '/' + op
                add(directory, op, prefix, directory=True)
                archive = opening(directory, op)
                entries = set(names(archive))
                if not entries:
                    opening.close(archive)
                    continue  # Created before any record or helper could be published.
                if 'record.json' not in entries: refuse('operation record missing')
                data = add(archive, 'record.json', prefix + '/record.json', proof=True)
                record = record_json(data)
                if record.get('id') != op: refuse('operation archive identity changed')
                if record.get('operation') in recovery.MOVES:
                    recovery.validate_intent(workspace, record, moving=True)
                else: _native.check_pending(workspace, record)
                expected = {'record.json'}
                for index, helper in enumerate(record['helpers']):
                    if index > 99: refuse('helper directory index exceeds fixed two-digit grammar')
                    label = f'{index:02}-' + helper['label']
                    expected.add(label)
                    if label not in entries: refuse('declared helper directory missing')
                    add(archive, label, prefix + '/' + label, directory=True)
                    output = opening(archive, label)
                    outputs = set(names(output))
                    if not outputs <= {'stdout', 'stderr'}: refuse('unexpected helper output entry')
                    if helper['outcome'] != 'not-launched' and outputs != {'stdout', 'stderr'}:
                        refuse('launched helper output missing')
                    for leaf in sorted(outputs): add(output, leaf, prefix + '/' + label + '/' + leaf)
                    opening.close(output)
                if entries != expected: refuse('unexpected operation archive entry')
                opening.close(archive)
            opening.close(directory)
        else: add(resource, name, name, proof=name in PROOFS)
    return result


def manifest_valid(rows):
    if type(rows) is not list or not 1 <= len(rows) <= MAX_ENTRIES: refuse('invalid manifest size')
    seen = set()
    for row in rows:
        if type(row) is not dict or set(row) not in ({'path', 'kind', 'identity'}, {'path', 'kind', 'identity', 'sha256'}):
            refuse('invalid manifest entry')
        path = row['path']; kind = row['kind']
        if not isinstance(path, str) or path in seen or kind not in ('file', 'directory'): refuse('invalid manifest path')
        parts = path.split('/')
        permitted = ((len(parts) == 1 and path in REQUIRED | {'native-mount.json'})
            or (parts[0] == 'native-operations' and 2 <= len(parts) <= 4
                and re.fullmatch('[0-9a-f]{32}', parts[1])
                and (len(parts) == 2 or (len(parts) == 3 and parts[2] == 'record.json')
                     or (re.fullmatch(r'[0-9]{2}-(verify-package|discover|mount|unmount)', parts[2])
                         and (len(parts) == 3 or parts[3] in ('stdout', 'stderr'))))))
        if not permitted or not valid_identity(row['identity'], directory=kind == 'directory'): refuse('invalid manifest binding')
        expected_dir = path in ('volume', 'native-operations') or (len(parts) == 2) or (len(parts) == 3 and parts[2] != 'record.json')
        if (kind == 'directory') != expected_dir: refuse('manifest kind differs from fixed grammar')
        if 'sha256' in row and not re.fullmatch('[0-9a-f]{64}', str(row['sha256'])): refuse('invalid proof digest')
        if path in PROOFS or path.endswith('/record.json'):
            if 'sha256' not in row: refuse('proof digest missing')
        if len(parts) > 1 and '/'.join(parts[:-1]) not in seen: refuse('manifest parent missing or unordered')
        seen.add(path)
    if not REQUIRED <= seen: refuse('manifest omits required resource entries')


def reached(record, stage):
    return STAGES.index(record['stage']) >= STAGES.index(stage)


def validate(record, workspace, *, complete=False):
    if (type(record) is not dict or record.get('operation') != ('native-purge-complete' if complete else 'native-purge')
            or type(record.get('schema')) is not int or record['schema'] != 1 or record.get('workspace') != workspace
            or record.get('authorized') is not True or record.get('stage') not in STAGES
            or not re.fullmatch('[0-9a-f]{32}', str(record.get('id')))
            or record.get('container') != 'native-purge-' + workspace + '-' + record['id']):
        refuse('invalid purge journal or completion receipt')
    required = {'schema', 'operation', 'id', 'workspace', 'authorized', 'stage', 'target', 'object',
        'parents', 'container', 'container_identity', 'marker', 'protection', 'manifest_digest',
        'data_absent', 'cleanup_complete', 'unlink_outcome', 'guard_outcome', 'ownership', 'previous_unresolved'}
    if not complete: required.add('manifest')
    optional = {'format', 'guard', 'first_error', 'last_error', 'error_count', 'failed_guard',
        'guard_receipt_unavailable', 'descriptor_close_error', 'abandoned_attempt'}
    if not required <= set(record) or not set(record) <= required | optional: refuse('unknown or missing purge fields')
    if complete and record['stage'] != 'complete': refuse('incomplete completion receipt')
    if not complete and record['stage'] == 'complete': refuse('completion must use its compact receipt')
    if 'error_count' in record and (type(record['error_count']) is not int or record['error_count'] < 1):
        refuse('invalid failure count')
    for key in ('first_error', 'last_error'):
        if key in record and (type(record[key]) is not dict or set(record[key]) != {'type', 'message'}
                or any(type(value) is not str or len(value) > 1024 for value in record[key].values())):
            refuse('invalid failure summary')

    if (type(record.get('data_absent')) is not bool or type(record.get('cleanup_complete')) is not bool
            or record.get('unlink_outcome') not in ('not-attempted', 'unknown', 'returned', 'observed-absent-after-authorization')
            or record.get('guard_outcome') not in ('not-attempted', 'unknown', 'consumed')):
        refuse('invalid purge dispositions')
    if reached(record, 'metadata-removal-authorized') and not record['data_absent']:
        refuse('metadata cleanup lacks recorded data absence')
    if type(record.get('parents')) is not dict or set(record['parents']) != set(PARENTS) | {'store'}:
        refuse('parent bindings missing')
    for ident in record['parents'].values():
        if not valid_identity(ident, directory=True): refuse('invalid parent identity')
    for key in ('object',):
        if not valid_identity(record.get(key), directory=True): refuse('invalid resource identity')
    for key in ('container_identity',):
        if record.get(key) is not None and not valid_identity(record[key], directory=True): refuse('invalid tombstone identity')
    for key in ('protection', 'marker'):
        entry = record.get(key)
        if key == 'marker' and entry is None and record['stage'] == 'prepared': continue
        if (type(entry) is not dict or set(entry) != {'identity', 'sha256'} or not valid_identity(entry['identity'])
                or not re.fullmatch('[0-9a-f]{64}', str(entry['sha256']))): refuse('invalid ' + key + ' binding')
    core.native_target({'ownership': 'external-reference', 'native_image': record.get('target')})
    if (record['target']['parent'] != [record['object']['device'], record['object']['inode']]
            or not re.fullmatch('[0-9a-f]{64}', str(record.get('manifest_digest')))):
        refuse('invalid target or manifest digest')
    if reached(record, 'container-ready') and record.get('container_identity') is None: refuse('tombstone identity missing')
    ownership = record['ownership']
    if (type(ownership) is not dict or set(ownership) != {'transaction', 'origin_target'}
            or not re.fullmatch('[0-9a-f]{32}', str(ownership['transaction']))): refuse('invalid immutable ownership binding')
    origin = ownership['origin_target']
    if (type(origin) is not dict or set(origin) != {'component', 'parent', 'object', 'file', 'uuid'}
            or origin['component'] != 'image.sfs' or origin['file'] != record['target']['file']
            or origin['uuid'] != record['target']['uuid'] or origin['object'] != record['target']['parent']
            or origin['parent'] != [record['parents']['workspaces']['device'], record['parents']['workspaces']['inode']]):
        refuse('immutable origin differs from the selected object')
    abandoned = record.get('abandoned_attempt')
    if abandoned is not None and (type(abandoned) is not dict or set(abandoned) != {'id', 'sha256'}
            or not re.fullmatch('[0-9a-f]{32}', str(abandoned['id']))
            or not re.fullmatch('[0-9a-f]{64}', str(abandoned['sha256']))
            or abandoned['id'] == record['id']):
        refuse('invalid abandoned attempt reference')
    previous = record['previous_unresolved']
    if previous is not None and (type(previous) is not dict or set(previous) != {'operation', 'id', 'outcome'}
            or not re.fullmatch('[0-9a-f]{32}', str(previous['id']))
            or previous['operation'] not in ('native-mount', 'native-unmount') + recovery.CATALOG
            or previous['outcome'] not in ('prepared', 'incomplete', 'complete')):
        refuse('invalid prior operation reference')

    if not complete:
        manifest_valid(record.get('manifest'))
        if digest(record['manifest']) != record['manifest_digest']: refuse('manifest changed')
        if any(row['identity']['device'] != record['object']['device'] for row in record['manifest']):
            refuse('manifest crosses a device boundary')
        backing = next(row for row in record['manifest'] if row['path'] == 'image.sfs')
        if record['target']['file'] != [backing['identity']['device'], backing['identity']['inode']]: refuse('manifest backing differs')
    if len(json.dumps({'format': 1, **record}, sort_keys=True, indent=2, allow_nan=False).encode()) + 1 > MAX_INTENT_BYTES:
        refuse('intent exceeds 8 MiB limit')


def check_parents(store, record):
    for name, expected in record['parents'].items():
        path = store.root if name == 'store' else store.root / name
        if not matches(path.lstat(), expected, directory=True): refuse('store parent identity changed: ' + name)


def save(store, record):
    validate(record, record['workspace'])
    check_parents(store, record)
    _native._persist(store.root / 'journals' / (record['workspace'] + '.json'), record)


def advance(store, record, stage):
    record['stage'] = stage
    save(store, record)


def failure(error, record, store):
    try:
        detail = {'type': type(error).__name__, 'message': str(error)[:1024]}
        record.setdefault('first_error', detail)
        record['last_error'] = detail
        record['error_count'] = record.get('error_count', 0) + 1
        guard = getattr(error, 'native_current_guard', None)
        if guard is not None: record['failed_guard'] = guard
        carrier = getattr(error, 'native_backing_guard', None)
        if carrier is not None and guard is None:
            try: record['failed_guard'] = carrier.close_result
            except BaseException: record['guard_receipt_unavailable'] = True
        # Completion evidence owns final cleanup; never recreate an obsolete journal.
        try:
            if record.get('operation') == 'native-purge': save(store, record)
            else:
                check_parents(store, record)
                _native._persist(store._state(record['workspace']), record)
        except BaseException: pass
        error.native_candidate_result = record
    except BaseException: pass


def references(store, record):
    recovery._no_external_references(store, record['target'])
    for path in (store.root / 'journals').iterdir():
        if path.name == record['workspace'] + '.json': continue
        other = core.read_json(path)
        action = other.get('operation', '')
        if not isinstance(action, str): refuse('malformed neighboring intent')
        if action.startswith('native-'):
            if action == 'native-purge': validate(other, path.stem)
            elif action in recovery.MOVES: recovery.validate_intent(path.stem, other, moving=True)
            else: _native.check_pending(path.stem, other)
            target = other.get('target') or other.get('native_image')
            if type(target) is not dict or type(target.get('file')) is not list:
                if action == 'native-create' and other.get('creation_attempted') is False: continue
                refuse('unknown native reference in another intent')
            if target['file'] == record['target']['file']: refuse('another intent references this backing')


def parents(store, opening, record=None):
    root = opening(None, store.root, None if record is None else record['parents']['store'])
    values = {'store': root}
    for name in PARENTS: values[name] = opening(root, name, None if record is None else record['parents'][name])
    return values


def proof(fd, name, saved, *, missing=False):
    if checked(fd, name, saved['identity'], missing=missing) is None: return False
    data, ident = read_file(fd, name, saved['identity'])
    if hashlib.sha256(data).hexdigest() != saved['sha256']: refuse('record content changed: ' + name)
    return True


def inspect_manifest(opening, resource, record, *, missing=False, image_absent=False):
    children = {}
    for row in record['manifest']:
        parent, _, leaf = row['path'].rpartition('/')
        children.setdefault(parent, {})[leaf] = row
    present = set()
    def visit(fd, prefix):
        expected = children.get(prefix, {})
        actual = set(names(fd))
        if not actual <= set(expected): refuse('unexpected resource entry')
        for leaf, row in expected.items():
            relative = row['path']
            info = checked(fd, leaf, row['identity'], directory=row['kind'] == 'directory',
                missing=missing or (relative == 'image.sfs' and image_absent))
            if info is None: continue
            if relative == 'image.sfs' and image_absent: refuse('backing reappeared after authorized removal')
            present.add(relative)
            if row['kind'] == 'directory':
                child = opening(fd, leaf, row['identity'])
                visit(child, relative)
                opening.close(child)
            elif 'sha256' in row:
                data, ident = read_file(fd, leaf, row['identity'])
                if hashlib.sha256(data).hexdigest() != row['sha256']: refuse('manifest proof content changed')
    visit(resource, '')
    return present


def entry_parent(opening, resource, record, relative):
    rows = {row['path']: row for row in record['manifest']}
    fd = resource
    held = []
    prefix = ''
    for component in relative.split('/')[:-1]:
        prefix = prefix + '/' + component if prefix else component
        fd = opening(fd, component, rows[prefix]['identity'])
        held.append(fd)
    return fd, held


def response(record, **extra):
    return {'workspace': record['workspace'], 'stage': record['stage'],
            'data_absent': record.get('data_absent', False),
            'metadata_complete': reached(record, 'resource-removal-authorized'),
            'cleanup_complete': record.get('cleanup_complete', False),
            'resume': 'sfs purge trash ' + record['workspace'] + ' --yes',
            'native_operation': record, **extra}


def initial(store, workspace, opening, fds, prior):
    path, metadata = store.object('trash', workspace)
    target = recovery.ready(store, path, metadata)
    recovery.absent(store, path)
    protection = recovery._protection(store, workspace, metadata)
    obj = identity(path.lstat())
    resource = opening(fds['trash'], workspace, obj)
    manifest = scan(opening, resource, workspace)
    protected, protect_identity = read_file(fds['protected'], protection.name)
    operation = uuid.uuid4().hex
    record = {'schema': 1, 'operation': 'native-purge', 'id': operation, 'workspace': workspace,
        'authorized': True, 'stage': 'prepared', 'target': target, 'object': obj,
        'parents': {name: identity(os.fstat(fd)) for name, fd in fds.items()},
        'container': 'native-purge-' + workspace + '-' + operation, 'container_identity': None,
        'marker': None, 'protection': {'identity': protect_identity, 'sha256': hashlib.sha256(protected).hexdigest()},
        'manifest': manifest, 'manifest_digest': digest(manifest), 'data_absent': False,
        'cleanup_complete': False, 'unlink_outcome': 'not-attempted', 'guard_outcome': 'not-attempted',
        'ownership': {'transaction': metadata['transaction'], 'origin_target': metadata['native_image']},
        'previous_unresolved': None if prior is None else {'operation': prior['operation'],
            'id': prior['id'], 'outcome': prior['outcome']}}
    validate(record, workspace)
    references(store, record)
    return record


def restart_unrelocated(store, record, opening, fds):
    """Explicit retry can abandon only an unchanged original, before relocation."""
    if reached(record, 'relocation-authorized'): return
    current = at(fds['staging'], record['container'])
    interrupted = ((current is not None and record['container_identity'] is None)
        or (current is None and record['container_identity'] is not None))
    if not interrupted: return
    if (record['data_absent'] or record['cleanup_complete']
            or record['unlink_outcome'] != 'not-attempted' or record['guard_outcome'] != 'not-attempted'):
        refuse('pre-relocation attempt has conflicting deletion evidence')
    check_parents(store, record)
    if at(fds['workspaces'], record['workspace']) is not None: refuse('workspace name was reused')
    checked(fds['trash'], record['workspace'], record['object'], directory=True)
    resource = opening(fds['trash'], record['workspace'], record['object'])
    inspect_manifest(opening, resource, record)
    proof(fds['protected'], record['workspace'] + '.json', record['protection'])
    # Re-admit all ownership/location/first-use proofs and absence/reference checks.
    replacement = initial(store, record['workspace'], opening, fds, None)
    # Parent link counts may change as reserved staging siblings appear; the
    # descriptor/namespace checks above already require the same directories.
    replacement['parents'] = record['parents']
    for key in ('target', 'object', 'parents', 'ownership', 'protection', 'manifest', 'manifest_digest'):
        if replacement[key] != record[key]: refuse('original trash changed before retry')
    replacement['previous_unresolved'] = record['previous_unresolved']
    abandoned = {'id': record['id'], 'sha256': digest(record)}
    replacement['abandoned_attempt'] = abandoned
    archive = store.root / 'lifecycle' / ('native-purge-abandoned-' + record['workspace']
        + '-' + abandoned['id'] + '-' + abandoned['sha256'] + '.json')
    # Publish immutable evidence before replacing authority. A failed publication
    # leaves the old journal valid; an existing identical archive is retryable.
    if os.path.lexists(archive):
        if core.read_json(archive) != {'format': 1, **record}: refuse('abandoned attempt archive changed')
    else:
        core.write_json(archive, record)
    os.fsync(fds['lifecycle'])
    save(store, replacement)
    record.clear(); record.update(replacement)


def admit_move_inputs(store, workspace, prior):
    """Bound later purge inputs before delegated move recovery can write receipts."""
    references(store, {'workspace': workspace, 'target': prior['target']})
    with descriptors({}) as opening:
        fds = parents(store, opening)
        for collection in ('trash', 'workspaces'):
            if at(fds[collection], workspace) is None: continue
            resource = opening(fds[collection], workspace)
            for name in PROOFS:
                if at(resource, name) is not None: record_json(read_file(resource, name)[0])
            operations = opening(resource, 'native-operations')
            for name in names(operations):
                if not re.fullmatch('[0-9a-f]{32}', name): refuse('unexpected operation directory')
                archive = opening(operations, name)
                if at(archive, 'record.json') is not None: record_json(read_file(archive, 'record.json')[0])
                opening.close(archive)
            opening.close(operations); opening.close(resource)


def container(store, record, opening, fds):
    name = record['container']
    current = at(fds['staging'], name)
    if current is None:
        if record['container_identity'] is not None: refuse('tombstone disappeared before removal authorization')
        os.mkdir(name, mode=0o700, dir_fd=fds['staging'])
        record['container_identity'] = identity(os.stat(name, dir_fd=fds['staging'], follow_symlinks=False))
        # Record the new directory before creating anything else inside it.
        save(store, record)
        os.fsync(fds['staging'])
    elif record['container_identity'] is None:
        refuse('unbound reserved tombstone exists; original trash is retained')
    fd = opening(fds['staging'], name, record['container_identity'])
    marker = store.root / 'staging' / name / 'native-purge.json'
    if record['marker'] is None:
        expected = {'format': 1, 'operation': 'native-purge-marker', 'schema': 1,
            'workspace': record['workspace'], 'id': record['id'], 'container_identity': record['container_identity'],
            'manifest_digest': record['manifest_digest']}
        present = names(fd)
        if not present: core.write_json(marker, expected)
        elif present != ['native-purge.json']: refuse('unexpected entry before tombstone marker creation')
        data, ident = read_file(fd, marker.name)
        if record_json(data) != expected: refuse('unbound marker differs from the authorized operation')
        record['marker'] = {'identity': ident, 'sha256': hashlib.sha256(data).hexdigest()}
        os.fsync(fd)
        advance(store, record, 'container-ready')
    else:
        proof(fd, marker.name, record['marker'])
        if not set(names(fd)) <= {'native-purge.json', 'owned'}: refuse('unexpected tombstone entry')
    return fd


def bound_locations(store, record, fds, tombstone):
    workspace = record['workspace']
    check_parents(store, record)
    if at(fds['workspaces'], workspace) is not None: refuse('workspace name was reused')
    source = checked(fds['trash'], workspace, record['object'], directory=True, missing=True)
    moved = None if tombstone is None else checked(tombstone, 'owned', record['object'], directory=True, missing=True)
    if source is not None and moved is not None: refuse('both original and tombstone resources exist')
    if source is None and moved is None and not reached(record, 'resource-removal-authorized'):
        refuse('resource absent before removal authorization')
    if source is not None and reached(record, 'image-unlink-authorized'):
        refuse('resource returned to trash after unlink authorization')
    return source, moved


def image_phase(store, record, opening, fds, tombstone, *, resumed):
    source, moved = bound_locations(store, record, fds, tombstone)
    parent, leaf = (fds['trash'], record['workspace']) if source is not None else (tombstone, 'owned')
    resource = opening(parent, leaf, record['object'])
    path = store.root / 'trash' / record['workspace'] if source is not None else store.root / 'staging' / record['container'] / 'owned'
    recovery.absent(store, path)
    if at(resource, 'image.sfs') is None:
        record['data_absent'] = True
        if not reached(record, 'image-unlink-authorized') or source is not None:
            refuse('image absent without exact unlink authorization')
        inspect_manifest(opening, resource, record, missing=reached(record, 'metadata-removal-authorized'), image_absent=True)
        # A later explicit request can fence a prior lost/failed unlink response.
        if not resumed: refuse('initial deletion lost its image before admission')
        record['data_absent'] = True
        if record['unlink_outcome'] != 'returned': record['unlink_outcome'] = 'observed-absent-after-authorization'
        os.fsync(resource)
        if not reached(record, 'image-absent'): advance(store, record, 'image-absent')
        return resource
    if reached(record, 'image-absent'): refuse('image reappeared after recorded absence')
    inspect_manifest(opening, resource, record)
    references(store, record)
    target = dict(record['target'], directory=str(path))
    if source is not None and not reached(record, 'relocation-authorized'):
        advance(store, record, 'relocation-authorized')
    def held(token):
        # Recheck the full immutable selection under the one backing admission.
        bound_locations(store, record, fds, tombstone)
        recovery.absent(store, path)
        references(store, record)
        inspect_manifest(opening, resource, record)
        token.verify(target)
        if source is not None:
            os.rename(record['workspace'], 'owned', src_dir_fd=fds['trash'], dst_dir_fd=tombstone)
        relocated = dict(record['target'], directory=str(store.root / 'staging' / record['container'] / 'owned'))
        token.verify(relocated)
        checked(tombstone, 'owned', record['object'], directory=True)
        os.fsync(fds['trash']); os.fsync(tombstone)
        if not reached(record, 'relocated'): advance(store, record, 'relocated')
        inspect_manifest(opening, resource, record)
        if not reached(record, 'image-unlink-authorized'): advance(store, record, 'image-unlink-authorized')
        # No verifier, helper or second core open is used after this unlink.
        image = next(row for row in record['manifest'] if row['path'] == 'image.sfs')
        checked(resource, 'image.sfs', image['identity'])
        record['unlink_outcome'] = 'unknown'
        save(store, record)
        os.unlink('image.sfs', dir_fd=resource)
        record['unlink_outcome'] = 'returned'
        record['data_absent'] = at(resource, 'image.sfs') is None
        if not record['data_absent']: refuse('image name reappeared during unlink')
        os.fsync(resource)
        advance(store, record, 'image-absent')
    record['guard_outcome'] = 'unknown'
    save(store, record)
    try:
        receipt = _native.guarded(target, held)
    except BaseException:
        if reached(record, 'image-unlink-authorized'):
            try: record['data_absent'] = at(resource, 'image.sfs') is None
            except BaseException: pass
        raise
    record['guard'] = receipt
    record['guard_outcome'] = 'consumed'
    save(store, record)
    return resource


def metadata_phase(store, record, opening, fds, tombstone, resource):
    path = store.root / 'staging' / record['container'] / 'owned'
    recovery.absent(store, path)
    present = inspect_manifest(opening, resource, record,
        missing=reached(record, 'metadata-removal-authorized'), image_absent=True)
    os.fsync(resource)
    if not reached(record, 'metadata-removal-authorized'): advance(store, record, 'metadata-removal-authorized')
    for row in sorted(record['manifest'], key=lambda item: item['path'].count('/'), reverse=True):
        relative = row['path']
        if relative not in present: continue
        check_parents(store, record)
        checked(fds['staging'], record['container'], record['container_identity'], directory=True)
        checked(tombstone, 'owned', record['object'], directory=True)
        parent, _, leaf = relative.rpartition('/')
        fd, held = entry_parent(opening, resource, record, relative)
        checked(fd, leaf, row['identity'], directory=row['kind'] == 'directory')
        os.fsync(fd)
        if row['kind'] == 'directory':
            child = opening(fd, leaf, row['identity'])
            if names(child): refuse('directory gained unexpected entries')
            os.fsync(child)
            opening.close(child)
            os.rmdir(leaf, dir_fd=fd)
        else:
            if 'sha256' in row: proof(fd, leaf, {'identity': row['identity'], 'sha256': row['sha256']})
            os.unlink(leaf, dir_fd=fd)
        os.fsync(fd)
        for child in reversed(held): opening.close(child)
    if names(resource): refuse('resource is not empty after manifested cleanup')
    os.fsync(resource)
    advance(store, record, 'resource-removal-authorized')
    checked(tombstone, 'owned', record['object'], directory=True)
    os.rmdir('owned', dir_fd=tombstone)
    os.fsync(tombstone)


def compact(record):
    result = {key: value for key, value in record.items() if key != 'manifest'}
    result.update(operation='native-purge-complete', stage='complete', data_absent=True, cleanup_complete=False)
    return result


def same_completion(record, journal):
    for key in ('workspace', 'id', 'target', 'parents', 'object', 'container', 'container_identity', 'marker', 'protection', 'manifest_digest'):
        if record.get(key) != journal.get(key): refuse('completion and journal disagree')


def finish(store, record, opening, fds, *, mutate):
    workspace = record['workspace']
    check_parents(store, record)
    for parent, name in ((fds['trash'], workspace), (fds['workspaces'], workspace), (fds['staging'], record['container'])):
        if at(parent, name) is not None: refuse('completed name was reused')
    protection_name = workspace + '.json'
    protected = proof(fds['protected'], protection_name, record['protection'], missing=True)
    pending = at(fds['journals'], protection_name)
    if pending is not None:
        other = record_json(read_file(fds['journals'], protection_name)[0])
        validate(other, workspace); same_completion(record, other)
        # A completion write can succeed before its caller sees an error. Keep
        # the later journal's bounded failure facts when finishing that receipt.
        if 'first_error' not in record and 'first_error' in other: record['first_error'] = other['first_error']
        if other.get('error_count', 0) >= record.get('error_count', 0):
            for key in ('last_error', 'error_count', 'failed_guard', 'guard_receipt_unavailable', 'descriptor_close_error'):
                if key in other: record[key] = other[key]
    if not mutate: return response(record, would_delete=True, pending=bool(protected or pending))
    if record['cleanup_complete'] and not protected and pending is None:
        return response(record, already_purged=True)
    # Retry required fences using the receipt's exact surviving parent bindings.
    os.fsync(fds['trash']); os.fsync(fds['staging'])
    if protected: os.unlink(protection_name, dir_fd=fds['protected'])
    os.fsync(fds['protected'])
    if pending is not None:
        # The root publication lock excludes cooperating journal replacement.
        current = record_json(read_file(fds['journals'], protection_name)[0])
        validate(current, workspace); same_completion(record, current)
        os.unlink(protection_name, dir_fd=fds['journals'])
    os.fsync(fds['journals'])
    record['cleanup_complete'] = True
    _native._persist(store._state(workspace), record)
    return response(record)


def admit_resume_inputs(opening, fds, record):
    """Read surviving manifested proofs before retry can publish any progress."""
    if at(fds['trash'], record['workspace']) is not None:
        resource = opening(fds['trash'], record['workspace'], record['object'])
        inspect_manifest(opening, resource, record, missing=True)
        opening.close(resource)
    if record['container_identity'] is not None and at(fds['staging'], record['container']) is not None:
        tombstone = opening(fds['staging'], record['container'], record['container_identity'])
        if at(tombstone, 'native-purge.json') is not None:
            read_file(tombstone, 'native-purge.json')
        if at(tombstone, 'owned') is not None:
            resource = opening(tombstone, 'owned', record['object'])
            inspect_manifest(opening, resource, record, missing=True)
            opening.close(resource)
        opening.close(tombstone)


def execute(store, record, opening, fds, *, resumed):
    workspace = record['workspace']
    if record['target']['directory'] != str(store.root / 'trash' / workspace) or record['target']['component'] != 'image.sfs':
        refuse('source target is outside the selected trash resource')
    proof(fds['protected'], workspace + '.json', record['protection'])
    references(store, record)
    admit_resume_inputs(opening, fds, record)
    restart_unrelocated(store, record, opening, fds)
    recovery.absent(store, store.root / 'staging' / record['container'])
    if not reached(record, 'container-removal-authorized'):
        tombstone = container(store, record, opening, fds)
        source, moved = bound_locations(store, record, fds, tombstone)
        if source is not None or moved is not None:
            resource = image_phase(store, record, opening, fds, tombstone, resumed=resumed)
            metadata_phase(store, record, opening, fds, tombstone, resource)
        else:
            os.fsync(tombstone)  # Retried after a lost armed resource rmdir response.
        advance(store, record, 'container-removal-authorized')
    else:
        tombstone = None
        if at(fds['staging'], record['container']) is not None:
            tombstone = opening(fds['staging'], record['container'], record['container_identity'])
        source, moved = bound_locations(store, record, fds, tombstone)
        if source is not None or moved is not None: refuse('resource exists after container cleanup authorization')
    if tombstone is not None:
        if not set(names(tombstone)) <= {'native-purge.json'}: refuse('unexpected remaining tombstone entry')
        if proof(tombstone, 'native-purge.json', record['marker'], missing=True):
            os.unlink('native-purge.json', dir_fd=tombstone)
        os.fsync(tombstone)
        checked(fds['staging'], record['container'], record['container_identity'], directory=True)
        if names(tombstone): refuse('tombstone is not empty')
        os.rmdir(record['container'], dir_fd=fds['staging'])
    os.fsync(fds['staging'])
    completed = compact(record)
    validate(completed, workspace, complete=True)
    _native._persist(store._state(workspace), completed)
    # Preserve the compact disposition even if subsequent bookkeeping fails.
    record.clear(); record.update(completed)
    return finish(store, record, opening, fds, mutate=True)


def purge_locked(store, workspace, *, yes=False):
    """Caller owns publication, workspace and retention locks in that order."""
    with core.json_read_limit(MAX_INTENT_BYTES):
        return _purge_locked(store, workspace, yes=yes)


def _purge_locked(store, workspace, *, yes=False):
    journal = store.root / 'journals' / (workspace + '.json')
    record = {}
    try:
        prior = core.read_json(journal) if os.path.lexists(journal) else None
        state = core.read_json(store._state(workspace)) if os.path.lexists(store._state(workspace)) else None
        completed = state is not None and state.get('operation') == 'native-purge-complete'
        if completed:
            record = state; validate(record, workspace, complete=True)
        elif prior is not None and prior.get('operation') == 'native-purge':
            record = prior; validate(record, workspace)
        elif prior is not None and prior.get('operation') in recovery.MOVES:
            recovery.validate_intent(workspace, prior, moving=True)
            if not yes: return {'workspace': workspace, 'would_delete': True, 'pending': 'native-move', 'requires': 'explicit purge confirmation or restore'}
            admit_move_inputs(store, workspace, prior)
            path, metadata, resolved = recovery.recover_move(store, workspace)
            if path.parent != store.root / 'trash': refuse('resolved move is not protected trash')
            prior = None
        elif prior is not None: _native.check_pending(workspace, prior)
        resumed = bool(record)
        with descriptors(record) as opening:
            fds = parents(store, opening, record if record else None)
            if record and (record['target']['directory'] != str(store.root / 'trash' / workspace)
                    or record['target']['component'] != 'image.sfs'):
                refuse('source target is outside the selected trash resource')
            if completed: return finish(store, record, opening, fds, mutate=yes)
            if not record:
                record.update(initial(store, workspace, opening, fds, prior))
                if not yes:
                    return response(record, would_delete=True, scope='current filesystem and all in-image snapshots; not secure erasure')
                save(store, record)
            elif not yes:
                return response(record, would_delete=True, pending=True)
            return execute(store, record, opening, fds, resumed=resumed)
    except BaseException as error:
        if record.get('operation') in ('native-purge', 'native-purge-complete'):
            if yes and not isinstance(error, core.MetadataLimitError): failure(error, record, store)
            else:
                try: error.native_candidate_result = record
                except BaseException: pass
        raise
