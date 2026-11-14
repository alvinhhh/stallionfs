"""Bounded observation and exact, offline continuation of completed native creates."""
from __future__ import annotations

import contextlib
import copy
import fcntl
import json
import math
import os
from pathlib import Path
import re
import stat
import uuid

from . import core, _native

MAX_ENTRIES = 16384
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
PARENTS = ('journals', 'staging', 'workspaces', 'locks', 'lifecycle')
KEYS = {'operation', 'workspace', 'transaction', 'seed', 'stage', 'stage_identity', 'candidate', 'object', 'final'}
PRODUCER = KEYS | {'creation_attempted', 'outcome', 'native_image', 'result', 'helpers', 'child_pending', 'discovery'}
PROTOCOL2 = {'protocol', 'spec_digest', 'phase', 'actors', 'replacement', 'disposal', 'completion_file'}
META = {'id', 'seed', 'transaction', 'name', 'branch', 'commit', 'created', 'backend', 'ownership', 'state',
        'capacity_gib', 'native_image', 'creation_proof'}
PROOF = {'operation', 'id', 'transaction', 'seed', 'native_image', 'import_contract', 'result'}


class Refusal(core.StallionError):
    def __init__(self, code, path=None):
        super().__init__(code)
        self.code, self.path = code, str(path) if path is not None else None


class BudgetRefusal(Refusal, core.MetadataLimitError):
    """Admission exhaustion with structured diagnostics and public no-write semantics."""


def budget_require(condition, code, path):
    if not condition:
        raise BudgetRefusal(code, path)


def require(condition, code, path=None):
    if not condition:
        raise Refusal(code, path)


def pair(info):
    return [info.st_dev, info.st_ino]


def safe(info, directory=False):
    return (info.st_uid == os.getuid() and not info.st_mode & 0o077
            and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1))


def semantic(value):
    result = dict(value)
    result.pop('format', None)
    return result


class Admission:
    """Existing descriptors only; no repair, automatic reconciliation or seed access."""
    def __init__(self, root):
        self.root = Path(root).expanduser().absolute()
        self.fds, self.bindings, self.files = {}, {}, {}
        self.entries = self.bytes = 0

    def close(self):
        first = None
        for fd in reversed(list(self.fds.values())):
            try:
                os.close(fd)
            except BaseException as error:
                if first is None:
                    first = error
        self.fds.clear()
        if first is not None:
            raise first

    def directory(self, path):
        path = Path(path)
        if path in self.fds:
            self.check(path)
            return self.fds[path]
        if path == self.root:
            require(path.resolve() == path, 'aliased-root', path)
            parent_fd, name = None, str(path)
        else:
            require(path.is_relative_to(self.root), 'outside-store', path)
            parent_fd, name = self.directory(path.parent), path.name
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        self.fds[path] = fd
        info = os.fstat(fd)
        require(safe(info, True), 'unsafe-directory', path)
        require(path == self.root or info.st_dev == os.fstat(self.fds[self.root]).st_dev, 'foreign-filesystem', path)
        core.private_directory(path)
        self.bindings[path] = pair(info)
        self.check(path)
        return fd

    def check(self, path=None):
        paths = list(self.bindings) if path is None else [Path(path)]
        for item in paths:
            parent = self.fds.get(item.parent)
            info = os.stat(item.name if parent is not None else item, dir_fd=parent, follow_symlinks=False)
            expected = self.bindings[item]
            require(pair(info) == expected and pair(os.fstat(self.fds[item])) == expected
                    and safe(info, stat.S_ISDIR(os.fstat(self.fds[item]).st_mode)), 'binding-changed', item)

    def exists(self, path):
        parent = self.directory(path.parent)
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def names(self, path):
        fd = self.directory(path)
        result = []
        with os.scandir(fd) as entries:
            for item in entries:
                self.entries += 1
                budget_require(self.entries <= MAX_ENTRIES, 'entry-budget', path)
                result.append(item.name)
        self.check(path)
        return sorted(result)

    def read(self, path):
        parent = self.directory(path.parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(safe(before), 'unsafe-metadata', path)
            scoped_limit = core._json_read_limit.get()
            limit = MAX_DOCUMENT_BYTES if scoped_limit is None else min(MAX_DOCUMENT_BYTES, scoped_limit)
            budget_require(before.st_size <= limit, 'document-budget', path)
            data = bytearray()
            while True:
                allowance = min(limit - len(data), MAX_TOTAL_BYTES - self.bytes)
                block = os.read(fd, min(65536, allowance + 1))
                if not block:
                    break
                data.extend(block)
                self.bytes += len(block)
                budget_require(len(data) <= limit, 'document-budget', path)
                budget_require(self.bytes <= MAX_TOTAL_BYTES, 'read-budget', path)
            after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            require(safe(after) and (pair(before), before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    == (pair(after), after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'metadata-changed', path)
            stamp = (pair(after), after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            require(path not in self.files or self.files[path] == stamp, 'metadata-substitution', path)
            self.files[path] = stamp
            value = json.loads(data, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
                               object_pairs_hook=unique_object)
            require(type(value) is dict and type(value.get('format')) is int and value['format'] == 1,
                    'unknown-format', path)
            self.check(path.parent)
            return semantic(value)
        finally:
            os.close(fd)

    def lock(self, path, shared=False):
        parent = self.directory(path.parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        self.fds[path] = fd
        info = os.fstat(fd)
        require(safe(info), 'unsafe-lock', path)
        self.bindings[path] = pair(info)
        fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        self.check(path)

    def publish(self, path, value):
        """Atomic descriptor-relative publication; interruptions retain temporary evidence."""
        self.check()
        parent = self.directory(path.parent)
        if self.exists(path):
            self.read(path)  # Refuse aliases and hardlinked metadata before replacement.
        data = json.dumps({'format': 1, **value}, sort_keys=True, allow_nan=False).encode() + b'\n'
        budget_require(len(data) <= MAX_DOCUMENT_BYTES, 'document-budget', path)
        temporary = '.' + path.name + '.' + uuid.uuid4().hex
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        try:
            remaining = memoryview(data)
            while remaining:
                written = os.write(fd, remaining)
                require(written > 0, 'short-write', path)
                remaining = remaining[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        self.check()
        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        self.files[path] = (pair(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        os.fsync(parent)


def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate-json-key')
        result[key] = value
    return result


@contextlib.contextmanager
def existing(root, *, shared):
    admission = Admission(root)
    primary = None
    try:
        admission.directory(admission.root)
        admission.lock(admission.root / '.lock', shared=shared)
        marker = admission.read(admission.root / 'store.json')
        require(marker == {'application': 'stallionfs'}, 'invalid-store')
        for name in PARENTS:
            admission.directory(admission.root / name)
        store = core.Store.__new__(core.Store)
        store.root = admission.root
        yield store, admission
        admission.check()
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            admission.close()
        except BaseException:
            if primary is None:
                raise


def ownership(a, record, workspace):
    require(type(record) is dict and KEYS <= record.keys() and record['operation'] == 'native-create', 'invalid-owner')
    core.identifier(workspace, 32)
    core.identifier(record['transaction'], 32)
    core.identifier(record['seed'], 64)
    require(record['workspace'] == workspace, 'workspace-mismatch')
    stage = Path(record['stage'])
    require(stage.parent == a.root / 'staging' and stage.name not in ('', '.', '..')
            and str(stage) == record['stage'] and record['candidate'] == str(stage / 'owned')
            and record['final'] == str(a.root / 'workspaces' / workspace), 'invalid-location')
    for key in ('stage_identity', 'object'):
        require(type(record[key]) is list and len(record[key]) == 2
                and all(type(n) is int and n >= 0 for n in record[key]), 'invalid-identity')
    return stage


# Exact current _image.c import_json/append_receipt transport; additions require explicit review.
RECEIPT_UINT = {'generation', 'committed_end', 'physical_end', 'device', 'inode'}
RECEIPT_ENUM = {'status', 'phase', 'system_errno', 'coverage', 'incomplete_reason', 'limit_reason',
                'fence_attempted', 'fence_succeeded'}
RECEIPT_KEYS = RECEIPT_UINT | RECEIPT_ENUM | {'uuid', 'root_digest', 'transaction_active', 'poisoned'}
BUDGET_KEYS = {'raw_cells', 'metadata_read_bytes', 'metadata_hash_bytes', 'checks', 'auxiliary_bytes', 'auxiliary_io_bytes'}
RESULT_KEYS = {'ok', 'candidate_complete', 'creation_attempted', 'creation_disposition', 'import_committed',
               'verified', 'outcome', 'reason', 'error_code', 'local_error', 'descriptor_close_error', 'failed_record',
               'observed_file', 'identity', 'anchor', 'resources', 'budget_explicit', 'budget_saturated', 'parent_steps',
               'creation', 'original', 'commit', 'abort', 'verify', 'close', 'reopen', 'reopen_close',
               'failure_path_error', 'xattr_names_scratch_high_water', 'failure_path'}


def uint64(value, *, positive=False):
    return type(value) is int and (1 if positive else 0) <= value < 1 << 64


def completed_result(result, target):
    require(type(result) is dict and set(result) == RESULT_KEYS, 'unknown-result-schema')
    require(all(result[key] is True for key in ('ok', 'candidate_complete', 'creation_attempted', 'import_committed', 'verified'))
            and result['creation_disposition'] == 'known_created' and result['outcome'] == 'candidate-created'
            and result['reason'] == 'none' and result['failure_path'] is None and result['abort'] is None
            and all(type(result[key]) is int and result[key] == 0 for key in
                    ('error_code', 'local_error', 'descriptor_close_error', 'failure_path_error'))
            and type(result['failed_record']) is int and result['failed_record'] == (1 << 64) - 1,
            'incomplete-result')
    require(type(result['identity']) is dict and set(result['identity']) == {'file', 'uuid'}
            and result['identity'] == {'file': target['file'], 'uuid': target['uuid']}
            and type(result['observed_file']) is list and result['observed_file'] == target['file']
            and all(uint64(n) for n in result['observed_file']) and result['anchor'] == target['anchor'], 'invalid-result-identity')
    for operation in ('creation', 'original', 'commit', 'verify', 'close', 'reopen', 'reopen_close'):
        receipt = result[operation]
        require(type(receipt) is dict and set(receipt) == RECEIPT_KEYS, 'unknown-result-receipt')
        require(all(uint64(receipt[key]) for key in RECEIPT_UINT)
                and all(type(receipt[key]) is int for key in RECEIPT_ENUM)
                and all(receipt[key] == 0 for key in ('status', 'system_errno', 'incomplete_reason', 'limit_reason'))
                and 0 <= receipt['phase'] <= 16 and 0 <= receipt['coverage'] <= 3
                and 0 <= receipt['fence_attempted'] <= 3 and receipt['fence_succeeded'] == receipt['fence_attempted']
                and receipt['transaction_active'] is False and receipt['poisoned'] is False
                and [receipt['device'], receipt['inode']] == target['file'] and receipt['uuid'] == target['uuid']
                and isinstance(receipt['root_digest'], str) and re.fullmatch('[0-9a-f]{64}', receipt['root_digest'])
                and receipt['generation'] > 0 and receipt['committed_end'] >= 16384
                and receipt['committed_end'] % 4096 == 0 and receipt['physical_end'] >= receipt['committed_end'],
                'invalid-result-receipt')
        if operation != 'creation':
            require(all(receipt[key] == value for key, value in target['anchor'].items()), 'result-anchor-mismatch')
    require(result['creation']['generation'] == 1 and result['commit']['generation'] == 2
            and result['commit']['fence_attempted'] == 3 and result['verify']['coverage'] == 1, 'incomplete-result')
    resources = result['resources']
    require(type(resources) is dict and set(resources) == {'entries', 'scratch_bytes', 'xattr_memory_high_water', 'policy', 'budget'}
            and resources['policy'] == 'finite-traversal-v2'
            and all(uint64(resources[key]) for key in ('entries', 'scratch_bytes', 'xattr_memory_high_water'))
            and type(resources['budget']) is dict and set(resources['budget']) == BUDGET_KEYS
            and all(uint64(value, positive=True) for value in resources['budget'].values())
            and all(type(result[key]) is bool for key in ('budget_explicit', 'budget_saturated'))
            and uint64(result['parent_steps']) and uint64(result['xattr_names_scratch_high_water']), 'invalid-result-resources')


def origin_metadata(metadata, proof):
    require(set(metadata) == META and set(proof) in (PROOF, PROOF | {'writer'}), 'unknown-creation-schema')
    core.validate_native_creation_proof(metadata, proof)
    completed_result(proof['result'], metadata['native_image'])
    name = metadata['name']
    require(isinstance(name, str) and (not name or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', name)), 'invalid-name')
    require(metadata['branch'] == f"stallionfs/{name + '-' if name else ''}{metadata['id']}"
            and isinstance(metadata['commit'], str) and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', metadata['commit'])
            and type(metadata['created']) in (int, float) and math.isfinite(metadata['created']) and metadata['created'] > 0
            and type(metadata['capacity_gib']) is int and 1 <= metadata['capacity_gib'] <= 65536
            and metadata['creation_proof'] == 'native-create.json', 'invalid-origin')


def settings(profile, host):
    host = str(host or _native.HOST)
    path = Path(host)
    require(profile in _native.PROFILES and '\0' not in host and path.is_absolute()
            and path.name == 'StallionFS' and path.parent.name == 'MacOS' and '..' not in path.parts,
            'invalid-settings')
    return profile, host


def installed_metadata(origin, parent, profile, host):
    profile, host = settings(profile, host)
    target = {**origin['native_image'], 'parent': parent}
    target.pop('anchor')
    return {**origin, 'state': 'installed-unconfirmed', 'origin': origin, 'native_image': target,
            'installation_proof': 'native-install.json', 'controller_profile': profile, 'native_host': host}


def backing(a, path, origin):
    fd = a.directory(path)
    require(pair(os.fstat(fd)) == origin['native_image']['object'], 'object-substitution')
    info = os.stat('image.sfs', dir_fd=fd, follow_symlinks=False)
    require(safe(info) and pair(info) == origin['native_image']['file'], 'backing-substitution')
    return {'directory': str(path), 'component': 'image.sfs', 'parent': origin['native_image']['object'],
            'file': origin['native_image']['file'], 'uuid': origin['native_image']['uuid']}


def install_proof(proof, metadata, target):
    require(set(proof) <= {'operation', 'id', 'transaction', 'target', 'complete', 'guard', 'previous_installation',
                           'first_mount_attempted', 'first_use', 'continuation_receipts', 'lifecycle'}
            and proof.get('operation') == 'native-install' and proof.get('id') == metadata['id']
            and proof.get('transaction') == metadata['transaction'] and proof.get('target') == metadata['native_image']
            and proof.get('complete') is True and type(proof.get('previous_installation')) is dict
            and proof['previous_installation'].get('metadata') == dict(metadata, state='installed-unconfirmed')
            and proof['previous_installation'].get('first_mount_attempted') is False
            and proof['previous_installation'].get('rename_attempted') is True
            and type(proof.get('first_mount_attempted')) is bool
            and type(proof.get('first_use')) is dict and type(proof['first_use'].get('accepted')) is bool
            and (proof['first_mount_attempted'] or proof['first_use'] == {'accepted': False})
            and _native._consumed(proof.get('guard'), target, metadata['origin']['native_image']['anchor']), 'invalid-install-proof')
    if 'lifecycle' in proof:
        require(valid_lifecycle(proof['lifecycle'], metadata['id'], metadata['origin'])
                and ('lifecycle' not in proof['previous_installation']
                     or proof['lifecycle'] == proof['previous_installation']['lifecycle']), 'lifecycle-proof-conflict')


def valid_lifecycle(state, workspace, origin):
    return (type(state) is dict and set(state) == {'id', 'generation', 'status', 'enrolled', 'object', 'payload'}
            and state['id'] == workspace and isinstance(state['generation'], str)
            and re.fullmatch('[0-9a-f]{32}', state['generation']) and state['status'] == 'open'
            and state['enrolled'] is False and state['object'] == origin['native_image']['object']
            and state['payload'] == origin['native_image']['file'])


def lifecycle(a, workspace, origin, expected=None):
    require(expected is None or valid_lifecycle(expected, workspace, origin), 'invalid-lifecycle-intent')
    path = a.root / 'lifecycle' / (workspace + '.json')
    if not a.exists(path):
        return None
    state = a.read(path)
    require(valid_lifecycle(state, workspace, origin), 'lifecycle-conflict')
    if expected is not None:
        require(state == expected, 'lifecycle-generation-conflict')
    return state


def preflight_archive(a, record, stage):
    archive = stage / 'discovery'
    if 'helpers' in record or 'child_pending' in record:
        require('helpers' in record and 'child_pending' in record and a.exists(archive), 'missing-helper-archive')
        archived = a.read(archive / 'record.json')
        expected = {k: record[k] for k in KEYS | {'helpers', 'child_pending'}}
        if 'discovery' in record:
            require(type(record['discovery']) is dict and record['discovery'].get('protocol') == 1
                    and record['discovery'].get('ok') is True and type(record['discovery'].get('modules')) is list,
                    'invalid-discovery')
            expected['discovery'] = record['discovery']
        expected.update(creation_attempted=False, outcome='preparing',
                        native_image={'component': 'image.sfs', 'file': None, 'uuid': None, 'anchor': None})
        if record.get('protocol') in (2, 3):
            expected.update(protocol=record['protocol'], spec_digest=record['spec_digest'], phase='preflight', actors=[])
        require(archived == expected, 'archive-journal-disagreement')
    else:
        require('discovery' not in record and not a.exists(archive), 'unexpected-helper-archive')


def load(a, workspace, transaction=None, *, profile=None, host=None):
    journal = a.root / 'journals' / (workspace + '.json')
    final = a.root / 'workspaces' / workspace
    from ._native_creation_purge import completed, disposal_state
    if a.exists(journal):
        record = a.read(journal)
        if 'disposal' in record:
            return disposal_state(a, record, workspace, transaction)
    completion = completed(a, workspace, transaction)
    if completion is not None:
        return {'status': 'purged', 'path': Path(completion['stage']), 'record': completion,
                'origin': {'id': workspace, 'transaction': completion['transaction']}}
    if not a.exists(journal):
        require(a.exists(final), 'no-authoritative-journal')
        metadata = a.read(final / 'meta.json')
        origin = metadata.get('origin')
        require(type(origin) is dict, 'no-installed-lineage')
        origin_metadata(origin, a.read(final / 'native-create.json'))
        require(metadata == dict(installed_metadata(origin, metadata['native_image']['parent'], metadata.get('controller_profile'),
                                                   metadata.get('native_host')), state='installed'), 'installed-metadata-mismatch')
        require(origin['id'] == workspace and (transaction is None or origin['transaction'] == transaction), 'transaction-mismatch')
        require((profile is None or profile == metadata['controller_profile']) and (host is None or str(host) == metadata['native_host']),
                'settings-frozen')
        from ._native_binding import resolve, historical_target
        store = core.Store.__new__(core.Store); store.root = a.root
        current = resolve(store, final, metadata, admission=a)
        require(current is not None or metadata['native_image']['parent'] == a.bindings[final.parent],
                'installed-collection-changed')
        target = current or backing(a, final, origin)
        proof = a.read(final / 'native-install.json')
        install_proof(proof, metadata, historical_target(final, metadata))
        if not proof['first_mount_attempted']:
            expected_state = proof.get('lifecycle', proof.get('previous_installation', {}).get('lifecycle'))
            require(valid_lifecycle(expected_state, workspace, origin), 'missing-lifecycle-binding')
            require(lifecycle(a, workspace, origin, expected_state) is not None,
                    'missing-lifecycle')
        return {'status': 'already-installed', 'path': final, 'metadata': metadata, 'origin': origin,
                'target': target, 'proof': proof, 'journal': journal}
    record = a.read(journal)
    require(set(record) <= PRODUCER | {'installation'} | (PROTOCOL2 if record.get('protocol') in (2, 3) else set()), 'unknown-journal-schema')
    stage = ownership(a, record, workspace)
    require(transaction is None or record['transaction'] == transaction, 'transaction-mismatch')
    a.directory(stage)
    require(a.bindings[stage] == record['stage_identity'], 'stage-substitution')
    marker = a.read(stage / 'native-create')
    if record.get('protocol') in (2, 3):
        from . import _native_create_request as request
        spec = request.validate(a, record, stage_required=False)
        if record.get('phase') in request.PREINSTALL and record.get('result', {}).get('candidate_complete') is not True:
            return {'status': 'retained', 'path': stage, 'stage': stage, 'record': record, 'journal': journal,
                    'spec': spec, 'origin': {'id': workspace, 'transaction': record['transaction']}}
    else:
        require(set(marker) <= PRODUCER and {k: record.get(k) for k in PRODUCER if k in record} == marker,
                'marker-journal-disagreement')
    require(record.get('creation_attempted') is True and record.get('outcome') == 'candidate-created'
            and set(record.get('native_image', {})) == {'component', 'file', 'uuid', 'anchor'}, 'incomplete-candidate')
    _native.check_pending(workspace, record)
    preflight_archive(a, record, stage)
    source = stage / 'owned'
    present_source, present_final = a.exists(source), a.exists(final)
    require(present_source != present_final, 'ambiguous-location')
    path = source if present_source else final
    metadata = a.read(path / 'meta.json')
    origin = metadata if metadata.get('state') == 'candidate' else metadata.get('origin')
    require(type(origin) is dict, 'missing-origin')
    proof = a.read(path / 'native-create.json')
    origin_metadata(origin, proof)
    require(origin['id'] == workspace and origin['transaction'] == record['transaction'] and origin['seed'] == record['seed']
            and origin['native_image']['parent'] == record['stage_identity'] and origin['native_image']['object'] == record['object']
            and proof['result'] == record.get('result')
            and record['native_image'] == {k: origin['native_image'][k] for k in ('component', 'file', 'uuid', 'anchor')},
            'creation-proof-disagreement')
    target = backing(a, path, origin)
    installation = record.get('installation')
    if installation is None:
        require(present_source and metadata == origin, 'missing-installation')
        installed = installed_metadata(origin, a.bindings[final.parent], profile or 'production', host)
    else:
        require(type(installation) is dict and set(installation) <= {'metadata', 'first_mount_attempted', 'rename_attempted',
                'guard', 'outcome', 'continuation_receipts', 'lifecycle'} and installation.get('first_mount_attempted') is False
                and type(installation.get('rename_attempted')) is bool and installation.get('outcome') in ('prepared', 'rename-attempted'),
                'invalid-installation')
        require({'metadata', 'first_mount_attempted', 'rename_attempted', 'guard', 'outcome'} <= installation.keys()
                and (installation['outcome'] == 'rename-attempted') == installation['rename_attempted']
                and (installation['guard'] is None or type(installation['guard']) is dict), 'invalid-installation')
        installed = installation.get('metadata')
        require(type(installed) is dict and installed == installed_metadata(origin, a.bindings[final.parent],
                installed.get('controller_profile'), installed.get('native_host')), 'installation-metadata-mismatch')
        require((profile is None or profile == installed['controller_profile']) and (host is None or str(host) == installed['native_host']),
                'settings-frozen')
        require(metadata in (origin, installed) if present_source else metadata in (installed, dict(installed, state='installed')),
                'metadata-transition-mismatch')
        if not present_source:
            require(installation['rename_attempted'], 'missing-rename-authority')
        receipts = installation.get('continuation_receipts', [])
        require(type(receipts) is list and len(receipts) < 128, 'receipt-limit')
        for item in receipts:
            require(type(item) is dict and set(item) <= {'attempt', 'outcome', 'guard'}
                    and isinstance(item.get('attempt'), str) and re.fullmatch('[0-9a-f]{32}', item['attempt'])
                    and item.get('outcome') in ('guard-pending', 'failed', 'consumed')
                    and (item.get('guard') is None or type(item['guard']) is dict), 'invalid-continuation-receipt')
            if item['outcome'] == 'consumed':
                require(_native._consumed(item.get('guard'), target, origin['native_image']['anchor']), 'invalid-continuation-receipt')
    names = a.names(path)
    require(set(names) <= {'image.sfs', 'meta.json', 'native-create.json', 'native-install.json', 'volume'}
            | {n for n in names if re.fullmatch(r'\.(meta\.json|native-install\.json)\.[0-9a-f]{32}', n)}, 'unexpected-object-entry')
    if 'volume' in names:
        require(not a.names(path / 'volume'), 'occupied-volume')
    elif not present_source:
        raise Refusal('missing-volume')
    installed_proof = a.read(path / 'native-install.json') if 'native-install.json' in names else None
    if installed_proof is not None:
        require(not present_source, 'premature-install-proof')
        install_proof(installed_proof, installed, target)
        if 'lifecycle' in installed_proof:
            require(installation is not None and installed_proof['lifecycle'] == installation.get('lifecycle'), 'lifecycle-proof-conflict')
        require(installed_proof['first_mount_attempted'] is False and installed_proof['first_use'] == {'accepted': False},
                'first-mount-handoff')
    state = lifecycle(a, workspace, origin, installation.get('lifecycle') if installation else None)
    require(state is None or (installation is not None and 'lifecycle' in installation), 'unattributed-lifecycle')
    return {'status': 'candidate' if present_source else 'installed-unconfirmed', 'record': record, 'journal': journal,
            'path': path, 'source': source, 'final': final, 'stage': stage, 'origin': origin, 'metadata': installed,
            'target': target, 'proof': installed_proof, 'state': state}


def diagnostic(error, path=None):
    return {'status': 'blocked', 'code': getattr(error, 'code', type(error).__name__),
            'path': getattr(error, 'path', None) or (str(path) if path is not None else None)}


def discover(a):
    rows, owners, affected = [], [], []
    for container in ('journals', 'staging'):
        parent = a.root / container
        try:
            names = a.names(parent)
        except (OSError, ValueError, RecursionError, core.StallionError) as error:
            rows.append(diagnostic(error, parent)); affected.append(str(parent))
            continue
        for name in names:
            path = parent / name
            try:
                if container == 'journals':
                    temporary = re.fullmatch(r'\.([0-9a-f]{32})\.json\.[0-9a-f]{32}', name)
                    if temporary:
                        info = os.stat(name, dir_fd=a.directory(parent), follow_symlinks=False)
                        require(safe(info) and info.st_size <= MAX_DOCUMENT_BYTES, 'unsafe-publication-remnant', path)
                        # This reserved name identifies a destination, never a transaction or valid payload.
                        rows.append({'path': str(path), 'kind': 'publication-remnant', 'status': 'retained',
                                     'destination_workspace': temporary[1], 'authoritative': False})
                        continue
                    record = a.read(path)
                    row = {'path': str(path), 'kind': 'journal', 'status': 'unclassified'}
                    if record.get('operation') == 'native-create':
                        ownership(a, record, name.removesuffix('.json'))
                        require(name == record['workspace'] + '.json', 'journal-basename')
                        row.update(workspace=record['workspace'], transaction=record['transaction'], status='retained')
                    else:
                        row.update(status='blocked', code='unsupported-journal-operation')
                    owners.append((str(path), record))
                else:
                    a.directory(path)
                    # Fixed children only: input repositories and backing bytes are never read.
                    children = a.names(path)
                    row = {'path': str(path), 'kind': 'stage', 'status': 'unclassified',
                           'remnants': [n for n in ('native-create', 'discovery', 'owned', 'image.sfs', 'meta.json') if n in children]}
                    if 'native-create' in children:
                        record = a.read(path / 'native-create')
                        ownership(a, record, record.get('workspace'))
                        require(record['stage'] == str(path), 'marker-location')
                        row.update(workspace=record['workspace'], transaction=record['transaction'], status='retained')
                        owners.append((str(path / 'native-create'), record))
                    for relative in ('discovery/record.json', 'owned/meta.json', 'owned/native-create.json'):
                        child = path / relative
                        if child.parent.name in children and a.exists(child):
                            record = a.read(child)
                            row.setdefault('records', []).append({'path': relative, 'operation': record.get('operation'),
                                                                  'state': record.get('state')})
                            if relative == 'discovery/record.json':
                                owners.append((str(child), record))
                rows.append(row)
            except (OSError, ValueError, TypeError, RecursionError, core.StallionError) as error:
                rows.append(diagnostic(error, path)); affected.append(str(path))
    return rows, owners, affected


def conflicts(a, loaded, owners):
    if loaded['status'] == 'purged':
        completion = loaded['record']
        for path, other in owners:
            related = any(other.get(key) == completion[key] for key in ('workspace', 'transaction', 'stage'))
            if related:
                require(path == str(a.root / 'journals' / (completion['workspace'] + '.json'))
                        and other.get('disposal') == completion['disposal']
                        and other.get('spec_digest') == completion['spec_digest'], 'conflicting-owner', path)
        return
    record = loaded.get('record')
    if record is None:
        record = {'workspace': loaded['origin']['id'], 'transaction': loaded['origin']['transaction'],
                  'object': loaded['origin']['native_image']['object']}
    for path, other in owners:
        related = any(other.get(key) == record[key] for key in ('workspace', 'transaction', 'stage', 'object') if key in record)
        if not related:
            continue
        if 'stage' not in record:
            # Surviving marker is diagnostic, never needed to authorize an independent install proof.
            require(other.get('workspace') == record['workspace'] and other.get('transaction') == record['transaction']
                    and other.get('object') == record['object'], 'conflicting-owner', path)
        else:
            require(all(other.get(key) == record[key] for key in KEYS), 'conflicting-owner', path)
            expected_paths = {str(loaded['journal']), str(loaded['stage'] / 'native-create'),
                              str(loaded['stage'] / 'discovery' / 'record.json')}
            require(path in expected_paths, 'duplicate-owner', path)


def inventory(root, workspace=None):
    """Read-only bounded inventory. Completeness is scoped to the requested ID when supplied."""
    result = {'status': 'observed', 'inventory_complete': False, 'scope': workspace or 'store',
              'entries': [], 'incomplete_paths': [], 'targeted_inspection': True}
    try:
        if workspace is not None:
            core.identifier(workspace, 32)
        with core.Store.existing(root, shared=True) as (_, a):
            result['store'] = str(a.root)
            if workspace is None:
                rows, owners, affected = discover(a)
                result['entries'].extend(rows)
                result['incomplete_paths'].extend(affected)
                identifiers = {r['workspace'] for r in rows if 'workspace' in r}
                for name in a.names(a.root / 'lifecycle'):
                    if re.fullmatch(r'[0-9a-f]{32}\.json', name):
                        if name[:-5] in identifiers:
                            continue  # Its journal loader admits any partial completion.
                        try:
                            state = a.read(a.root / 'lifecycle' / name)
                            if state.get('operation') == 'native-create-purge':
                                identifiers.add(name[:-5])
                        except (OSError, ValueError, TypeError, RecursionError, core.StallionError) as error:
                            result['entries'].append(diagnostic(error, a.root / 'lifecycle' / name))
                            result['incomplete_paths'].append(str(a.root / 'lifecycle' / name))
                identifiers = sorted(identifiers)
            else:
                identifiers, owners = [workspace], []
            for value in identifiers:
                try:
                    loaded = load(a, value)
                    conflicts(a, loaded, owners)
                    result['entries'].append({'workspace': value, 'transaction': loaded['origin']['transaction'],
                                              'status': loaded['status'], 'path': str(loaded['path']),
                                              'authoritative': True,
                                              **loaded.get('inspection', {}),
                                              **({'replacement': loaded['record']['replacement']}
                                                 if loaded.get('record', {}).get('replacement') else {})})
                except (OSError, ValueError, TypeError, RecursionError, core.StallionError) as error:
                    result['entries'].append(dict(diagnostic(error), workspace=value))
                    if isinstance(error, (OSError, ValueError, RecursionError)) or getattr(error, 'code', '') in ('entry-budget', 'document-budget', 'read-budget'):
                        result['incomplete_paths'].append(str(a.root / 'journals' / (value + '.json')))
            result['inventory_complete'] = not result['incomplete_paths']
    except (OSError, ValueError, TypeError, RecursionError, core.StallionError) as error:
        result.update(status='busy' if isinstance(error, BlockingIOError) else 'unavailable', inventory_complete=False)
        result['entries'].append(diagnostic(error, root))
    return result


def finalize(a, loaded):
    """Publish only missing installation stages, without recreating lifecycle generations."""
    origin, metadata, record = loaded['origin'], loaded['metadata'], loaded['record']
    source, final, journal = loaded['source'], loaded['final'], loaded['journal']
    target = loaded['target']
    anchor = origin['native_image']['anchor']
    from ._native_create_authority import proof
    proof(origin, a.read(loaded['path'] / 'native-create.json'))
    tokens = []

    def relocate(token):
        tokens.append(token)
        a.check()
        token.verify(target)
        require(backing(a, loaded['path'], origin) == target, 'backing-changed')
        installation = record.get('installation')
        if installation is None:
            installation = {'metadata': metadata, 'first_mount_attempted': False, 'rename_attempted': False,
                            'guard': None, 'outcome': 'prepared'}
            record['installation'] = installation
        if 'lifecycle' not in installation:
            installation['lifecycle'] = {'id': origin['id'], 'generation': uuid.uuid4().hex, 'status': 'open',
                'enrolled': False, 'object': origin['native_image']['object'], 'payload': origin['native_image']['file']}
        attempts = installation.setdefault('continuation_receipts', [])
        attempts.append({'attempt': uuid.uuid4().hex, 'outcome': 'guard-pending'})
        a.publish(journal, record)
        if loaded['path'] == source:
            volume = source / 'volume'
            if not a.exists(volume):
                a.check()
                os.mkdir('volume', mode=0o700, dir_fd=a.directory(source))
                os.fsync(a.directory(source))
            require(not a.names(volume), 'occupied-volume')
            if a.read(source / 'meta.json') != metadata:
                a.publish(source / 'meta.json', metadata)
            installation.update(rename_attempted=True, outcome='rename-attempted')
            a.publish(journal, record)
            a.check()
            token.verify(target)
            require(not a.exists(final), 'destination-appeared')
            # Existing move uses RENAME_EXCL; a newly appeared destination is never replaced.
            _native._scan.move(source, final)
            # Transfer existing pins to their new names before validating post-move binding.
            moved = [p for p in a.fds if p == source or p.is_relative_to(source)]
            for old in moved:
                new = final / old.relative_to(source)
                a.fds[new] = a.fds.pop(old)
                a.bindings[new] = a.bindings.pop(old)
            for old in list(a.files):
                if old.is_relative_to(source):
                    a.files[final / old.relative_to(source)] = a.files.pop(old)
        current = dict(target, directory=str(final))
        a.check()
        require(backing(a, final, origin) == current, 'postmove-backing-changed')
        token.verify(current)
        os.fsync(a.directory(final.parent))
        os.fsync(a.directory(source.parent))

    try:
        receipt = _native.guarded(target, relocate, anchor=anchor, expected_anchor=anchor)
    except BaseException as error:
        if tokens:
            receipt = getattr(tokens[0], 'close_result', None)
            attempts = record.get('installation', {}).get('continuation_receipts', [])
            if attempts:
                attempts[-1] = {**attempts[-1], 'outcome': 'failed', 'guard': receipt}
                try:
                    a.publish(journal, record)
                except BaseException:
                    pass  # The durable pending attempt still records uncertainty.
        raise
    installation = record['installation']
    installation['continuation_receipts'][-1].update(outcome='consumed', guard=receipt)
    a.publish(journal, record)
    proof = loaded['proof']
    if proof is None:
        proof = {'operation': 'native-install', 'id': origin['id'], 'transaction': origin['transaction'],
                 'target': metadata['native_image'], 'complete': True, 'guard': receipt,
                 'previous_installation': copy.deepcopy(installation), 'first_mount_attempted': False,
                 'first_use': {'accepted': False}, 'lifecycle': copy.deepcopy(installation['lifecycle'])}
        a.publish(final / 'native-install.json', proof)
    else:
        # Never erase a historical failed guard or first-use record in an existing proof.
        install_proof(proof, metadata, dict(target, directory=str(final)))
        receipts = proof.setdefault('continuation_receipts', [])
        require(type(receipts) is list and len(receipts) < 128, 'receipt-limit')
        receipts.append(copy.deepcopy(installation['continuation_receipts'][-1]))
        require('lifecycle' not in proof or proof['lifecycle'] == installation['lifecycle'], 'lifecycle-proof-conflict')
        proof['lifecycle'] = copy.deepcopy(installation['lifecycle'])
        a.publish(final / 'native-install.json', proof)
    installed = dict(metadata, state='installed')
    if a.read(final / 'meta.json') != installed:
        a.publish(final / 'meta.json', installed)
    state_path = a.root / 'lifecycle' / (origin['id'] + '.json')
    state = lifecycle(a, origin['id'], origin, installation['lifecycle'])
    if state is None:
        a.publish(state_path, installation['lifecycle'])
    a.check()
    completed_proof = a.read(final / 'native-install.json')
    install_proof(completed_proof, installed, dict(target, directory=str(final)))
    require(completed_proof.get('lifecycle') == installation['lifecycle'], 'lifecycle-proof-conflict')
    require(a.read(final / 'meta.json') == installed, 'final-metadata-changed')
    lifecycle(a, origin['id'], origin, installation['lifecycle'])
    os.fsync(a.directory(final))
    os.fsync(a.directory(state_path.parent))
    require(a.read(journal) == record, 'journal-changed')
    a.check()
    os.unlink(journal.name, dir_fd=a.directory(journal.parent))
    os.fsync(a.directory(journal.parent))
    from ._native_binding import enroll
    store = core.Store.__new__(core.Store); store.root = a.root
    enroll(store, a, final, installed)
    return {'status': 'installed-unmounted', 'workspace': origin['id'], 'transaction': origin['transaction'], 'path': str(final)}


def installed_result(a, loaded):
    response = {'workspace': loaded['origin']['id'], 'transaction': loaded['origin']['transaction'],
                'path': str(loaded['path'])}
    if loaded['proof']['first_mount_attempted']:
        return {**response, 'status': 'already-installed', 'handoff': 'mount-state'}
    from ._native_create_authority import proof
    proof(loaded['origin'], a.read(loaded['path'] / 'native-create.json'))
    require(not a.names(loaded['path'] / 'volume'), 'occupied-volume')
    from ._native_binding import NAME, enroll
    if not a.exists(loaded['path'] / NAME):
        # Installation may have finished and removed its journal before binding
        # publication. An exact retry must finish that guarded enrollment too.
        store = core.Store.__new__(core.Store); store.root = a.root
        enroll(store, a, loaded['path'], a.read(loaded['path'] / 'meta.json'))
    else:
        anchor = loaded['origin']['native_image']['anchor']
        _native.guarded(loaded['target'], lambda token: a.check(), anchor=anchor, expected_anchor=anchor)
    a.check()
    os.fsync(a.directory(loaded['journal'].parent))
    return {**response, 'status': 'installed-unmounted', 'already_installed': True}


def continue_creation(root, workspace, transaction, *, profile=None, host=None):
    """Exact transaction continuation. Internal statuses carry no CLI wording."""
    response = {'status': 'blocked', 'workspace': workspace, 'transaction': transaction}
    try:
        core.identifier(workspace, 32)
        core.identifier(transaction, 32)
        with core.Store.existing(root, shared=False) as (store, a):
            from ._native_creation_purge import completed, disposal_state
            journal = a.root / 'journals' / (workspace + '.json')
            if a.exists(journal):
                record = a.read(journal)
                if 'disposal' in record:
                    loaded = disposal_state(a, record, workspace, transaction)
                    return {**response, 'status': loaded['status'], **loaded['inspection']}
            completion = completed(a, workspace, transaction)
            if completion is not None:
                from ._native_create_retry import follow_purged
                return follow_purged(store, a, completion)
            journal = a.root / 'journals' / (workspace + '.json')
            if a.exists(journal):
                record = a.read(journal)
                if record.get('protocol') in (2, 3):
                    from . import _native_create_request as request, _native_create_retry as retry
                    require(record.get('transaction') == transaction, 'transaction-mismatch')
                    if record.get('phase') in request.PREINSTALL and record.get('result', {}).get('candidate_complete') is not True:
                        spec, held = retry.acquire(a, record)
                        require((profile is None or profile == spec['profile'])
                                and (host is None or str(host) == spec['host']), 'settings-frozen')
                        return retry.continue_locked(store, a, record, spec, held)
            a.lock(a.root / 'locks' / ('use-' + workspace))
            a.lock(a.root / 'locks' / ('workspace-' + workspace))
            rows, owners, affected = discover(a)
            require(not affected, 'inventory-incomplete')
            loaded = load(a, workspace, transaction, profile=profile, host=host)
            conflicts(a, loaded, owners)
            if loaded['status'] == 'already-installed':
                response.update(installed_result(a, loaded))
            else:
                response.update(finalize(a, loaded))
    except (OSError, ValueError, TypeError, RecursionError, core.StallionError) as error:
        response.update(diagnostic(error))
        if isinstance(error, BlockingIOError):
            response['status'] = 'busy'
    return response
