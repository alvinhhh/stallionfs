"""Explicit, hash-scoped admission of present offline legacy backing."""
import hashlib
import json
import os
import re
import uuid
from . import core, _native
from ._native_create_recovery import require, MAX_DOCUMENT_BYTES, budget_require


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def legacy_closes(records, path, metadata, endpoints):
    from ._native_binding import _chain_member, _same_evidence, completed_operation
    from ._native_interval import FIELDS
    candidates = {}
    for name, row in records.items():
        if row.get('operation') != 'native-unmount' or row.get('outcome') != 'complete':
            continue
        completed_operation(row, path, metadata, name)
        before, after, guard, closed = _chain_member(row, path, metadata, name)
        if before is not None and closed and not FIELDS.intersection(row):
            candidates.setdefault(digest([row['target'], before]), []).append(guard)
    guards = []
    selected = set()
    latest = {key: max(rows, key=lambda row: row['generation']) for key, rows in candidates.items()}
    for name in endpoints:
        row = records[name]
        require(not FIELDS.intersection(row), 'reconciliation-not-legacy')
        before, after, guard, closed = _chain_member(row, path, metadata, name)
        key = digest([row['target'], after])
        require(key in latest, 'reconciliation-missing-close')
        final = latest[key]
        require(final['generation'] >= guard['generation'], 'reconciliation-guard-order')
        if final['generation'] == guard['generation']:
            require(all(_same_evidence(final[k], guard[k]) for k in ('generation', 'committed_end', 'root_digest')), 'binding-conflicting-anchors')
        selected.add(key)
    for key in selected:
        guards.extend(candidates[key])
    return guards


def scope(a, path, metadata, records, stable, target):
    from ._native_binding import evidence
    from ._native_interval import FIELDS
    fingerprint, proof = evidence(a, path, metadata)
    from ._native_binding import archive_anchor
    marker_path = path / 'native-mount.json'
    marker = a.read(marker_path) if a.exists(marker_path) else None
    # Discover only the exact missing predicate after all other archive checks.
    # This temporary value is never published or used as a binding basis.
    provisional = {'scope': {'endpoints': sorted(records)}, 'guard': proof['guard']}
    _, missing = archive_anchor(records, path, metadata, marker, proof,
                                reconciliation=provisional, collect_legacy=True)
    endpoints = sorted(missing)
    require(endpoints, 'reconciliation-no-legacy-ambiguity')
    return dict(workspace=path.name, transaction=metadata['transaction'], fingerprint=fingerprint,
                historical_target=metadata['native_image'], stable=stable, target=target,
                endpoints=endpoints, inventory=[dict(id=n, action=records[n]['operation'],
                sha256=a.raw_hashes[path / 'native-operations' / n / 'record.json']) for n in sorted(records)],
                evidence_hashes={name: a.raw_hashes[path / name] for name in ('meta.json', 'native-create.json', 'native-install.json')},
                acceptance=proof.get('first_use'))


def validate_scope(a, path, metadata, receipt):
    from ._native_binding import evidence, _same_evidence, _pair_guard
    from ._native_interval import load
    require(type(receipt) is dict and set(receipt) == {'schema', 'id', 'authority', 'scope', 'scope_digest', 'marker', 'marker_hash', 'guard', 'complete'}
            and type(receipt['schema']) is int and receipt['schema'] == 1
            and receipt['authority'] == 'legacy-offline-reconciliation' and receipt['complete'] is True
            and type(receipt['id']) is str and re.fullmatch('[0-9a-f]{32}', receipt['id']), 'reconciliation-schema')
    sealed = receipt['scope']
    require(type(sealed) is dict and set(sealed) == {'workspace', 'transaction', 'fingerprint', 'historical_target', 'stable', 'target', 'endpoints', 'inventory', 'evidence_hashes', 'acceptance'}
            and digest(sealed) == receipt['scope_digest'] and sealed['workspace'] == path.name
            and sealed['transaction'] == metadata['transaction']
            and _same_evidence(sealed['historical_target'], metadata['native_image']), 'reconciliation-scope')
    fingerprint, proof = evidence(a, path, metadata)
    require(fingerprint == sealed['fingerprint'] and _same_evidence(proof.get('first_use'), sealed['acceptance']), 'reconciliation-evidence')
    from ._native_create_recovery import semantic
    require(_same_evidence(a.read(path / 'meta.json'), semantic(metadata)), 'reconciliation-metadata-changed')
    for name in ('meta.json', 'native-create.json', 'native-install.json'):
        require(a.raw_hashes.get(path / name) == sealed['evidence_hashes'].get(name), 'reconciliation-evidence-changed')
    core.native_target({'ownership': 'external-reference', 'native_image': sealed['target']})
    records = load(a, path)
    require(type(sealed['inventory']) is list and type(sealed['endpoints']) is list, 'reconciliation-scope')
    names = []
    for row in sealed['inventory']:
        require(type(row) is dict and set(row) == {'id', 'action', 'sha256'} and type(row['id']) is str
                and re.fullmatch('[0-9a-f]{32}', row['id']) and row['id'] in records, 'reconciliation-scope')
        name = row['id']; names.append(name)
        require(records[name].get('operation') == row['action']
                and a.raw_hashes[path / 'native-operations' / name / 'record.json'] == row['sha256'], 'reconciliation-history-changed')
    require(names == sorted(set(names)) and sealed['endpoints'] == sorted(set(sealed['endpoints']))
            and set(sealed['endpoints']) <= set(names), 'reconciliation-scope')
    legacy_closes(records, path, metadata, sealed['endpoints'])
    _pair_guard(receipt['guard'], sealed['target'])
    require(receipt['guard'].get('physical_end') == receipt['guard']['committed_end'], 'reconciliation-physical-end')
    from ._native_binding import archive_anchor
    closed, missing = archive_anchor({name: records[name] for name in names}, path, metadata,
                            receipt['marker'], proof, reconciliation=receipt, collect_legacy=True)
    require(sorted(missing) == sealed['endpoints'], 'reconciliation-widened-scope')
    require(all(_same_evidence(closed[k], receipt['guard'][k]) for k in
                ('generation', 'committed_end', 'root_digest')), 'reconciliation-stale-guard')
    return records


def binding_basis(a, path, receipt):
    location = path / 'native-reconciliations' / (receipt['id'] + '.json')
    require(a.read(location) == receipt, 'reconciliation-receipt-changed')
    return dict(version=1, reconciliation=receipt['id'], sha256=a.raw_hashes[location], scope_digest=receipt['scope_digest'])


def read_basis(a, path, metadata, basis):
    require(type(basis) is dict and set(basis) == {'version', 'reconciliation', 'sha256', 'scope_digest'}
            and type(basis['version']) is int and basis['version'] == 1
            and type(basis['reconciliation']) is str and re.fullmatch('[0-9a-f]{32}', basis['reconciliation']), 'reconciliation-basis')
    directory = path / 'native-reconciliations'
    names = [name for name in a.names(directory) if not name.startswith('.')]
    require(names == [basis['reconciliation'] + '.json'], 'reconciliation-conflicting-receipt')
    location = directory / (basis['reconciliation'] + '.json')
    receipt = a.read(location)
    require(a.raw_hashes[location] == basis['sha256'] and receipt.get('id') == basis['reconciliation']
            and receipt.get('scope_digest') == basis['scope_digest'], 'reconciliation-basis')
    validate_scope(a, path, metadata, receipt)
    return receipt


def publish(a, path, receipt):
    from . import _scan
    directory = path / 'native-reconciliations'
    parent = a.directory(path)
    try:
        os.mkdir(directory.name, 0o700, dir_fd=parent)
        os.fsync(parent)
    except FileExistsError:
        pass
    fd_parent = a.directory(directory)
    data = json.dumps(dict(format=1, **receipt), sort_keys=True, allow_nan=False).encode() + b'\n'
    budget_require(len(data) <= MAX_DOCUMENT_BYTES, 'document-budget', directory)
    name = receipt['id'] + '.json'; temporary = '.' + name + '.' + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd_parent)
    try:
        remaining = memoryview(data)
        while remaining:
            count = os.write(fd, remaining); require(count > 0, 'reconciliation-short-write'); remaining = remaining[count:]
        os.fsync(fd)
        a.check()
        _scan._publish_no_replace(fd_parent, temporary, name)
        os.fsync(fd_parent)
    finally:
        os.close(fd)
    require(a.read(directory / name) == receipt, 'reconciliation-publication')


def reconcile_current(root, workspace, transaction):
    from . import _native_binding as b
    from ._native_interval import load
    from ._native_create_recovery import diagnostic, discover, conflicts
    response = dict(workspace=workspace, transaction=transaction, status='blocked')
    try:
        core.identifier(workspace, 32); core.identifier(transaction, 32)
        with core.Store.existing(root, shared=False) as (store, a):
            a.lock(a.root / 'locks' / ('use-' + workspace)); a.lock(a.root / 'locks' / ('workspace-' + workspace))
            path = a.root / 'workspaces' / workspace
            metadata = a.read(path / 'meta.json')
            require(metadata.get('id') == workspace and metadata.get('transaction') == transaction, 'transaction-mismatch')
            from ._native_create_authority import installed
            installed(path, metadata)
            _, owners, affected = discover(a)
            require(not affected, 'inventory-incomplete')
            conflicts(a, {'status': 'already-installed', 'origin': metadata['origin']}, owners)
            require(not a.exists(path / b.NAME), 'reconciliation-existing-binding')
            records = load(a, path)
            with b.descriptors(a, path, metadata) as (stable, target, observe):
                sealed = scope(a, path, metadata, records, stable, target)
                marker_path = path / 'native-mount.json'; marker = a.read(marker_path) if a.exists(marker_path) else None
                provisional = dict(scope=sealed, guard={'generation': 0, 'committed_end': 0, 'root_digest': '0' * 64})
                # Validate historical predicates without inventing a current guard.
                candidate_guards = legacy_closes(records, path, metadata, sealed['endpoints'])
                provisional['guard'] = max(candidate_guards, key=lambda r: r['generation'])
                closed = b.exclusions(store, a, path, metadata, reconciliation=provisional)
                def held(token):
                    require(observe() == (stable, target), 'hosting-binding-changed')
                    require(scope(a, path, metadata, load(a, path), stable, target) == sealed, 'reconciliation-scope-changed')
                    b.exclusions(store, a, path, metadata, reconciliation=provisional)
                guard = _native.guarded(target, held)
                b._pair_guard(guard, target)
                require(guard.get('physical_end') == guard['committed_end'] and guard['generation'] >= closed['generation'], 'reconciliation-guard-order')
                if guard['generation'] == closed['generation']:
                    require(all(b._same_evidence(guard[k], closed[k]) for k in ('generation', 'committed_end', 'root_digest')), 'binding-conflicting-anchors')
                held(None)
                receipt = dict(schema=1, id=uuid.uuid4().hex, authority='legacy-offline-reconciliation', scope=sealed,
                               scope_digest=digest(sealed), marker=marker, marker_hash=a.raw_hashes.get(marker_path), guard=guard, complete=True)
                directory = path / 'native-reconciliations'
                retained = []
                if a.exists(directory):
                    for name in a.names(directory):
                        if name.startswith('.'):
                            continue
                        require(re.fullmatch(r'[0-9a-f]{32}\.json', name), 'reconciliation-inventory')
                        old = a.read(directory / name)
                        validate_scope(a, path, metadata, old)
                        require(old['id'] + '.json' == name and old['scope'] == sealed, 'reconciliation-conflicting-receipt')
                        retained.append(old)
                require(len(retained) <= 1, 'reconciliation-conflicting-receipt')
                if retained:
                    receipt = retained[0]
                    os.fsync(a.directory(directory))
                else:
                    publish(a, path, receipt)
                validate_scope(a, path, metadata, receipt)
                b.enroll(store, a, path, metadata, adopt=True, reconciliation=receipt)
                response.update(status='current-image-reconciled', authority=receipt['authority'], reconciliation=receipt['id'], scope_digest=receipt['scope_digest'])
    except (OSError, ValueError, TypeError, KeyError, core.StallionError) as error:
        response.update(diagnostic(error))
    return response
