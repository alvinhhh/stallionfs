"""Bounded ordinary lifecycle identity; no stored reference is opened."""
import re
from . import core, _native
from ._native_create_recovery import Admission, require

FIELDS = {'lifecycle_version', 'interval_seed', 'ordinary_interval'}


def load(a, path):
    records = {}
    if a.exists(path / 'native-operations'):
        for name in a.names(path / 'native-operations'):
            require(re.fullmatch('[0-9a-f]{32}', name), 'binding-operation-schema')
            records[name] = a.read(path / 'native-operations' / name / 'record.json')
    return records


def seed(name, path, target):
    return dict(mount_operation=name, workspace=path.name, target=target)


def token(name, path, metadata, target, observation):
    from ._native_binding import _chain_observation
    authority = _chain_observation(observation, path, metadata)
    require(authority is not None, 'interval-observation')
    return dict(version=1, **seed(name, path, target), observation=authority)


def validate(value, path, metadata):
    from ._native_binding import _same_evidence, _chain_observation
    require(type(value) is dict and set(value) == {'version', 'mount_operation', 'workspace', 'target', 'observation'}
            and type(value['version']) is int and value['version'] == 1
            and type(value['mount_operation']) is str and re.fullmatch('[0-9a-f]{32}', value['mount_operation'])
            and type(value['workspace']) is str and value['workspace'] == path.name,
            'interval-schema')
    target = value['target']
    require(type(target) is dict and set(target) == {'directory', 'component', 'parent', 'file', 'uuid'}
            and all(type(target.get(k)) is str for k in ('directory', 'component', 'uuid')), 'interval-target')
    core.native_target({'ownership': 'external-reference', 'native_image': target})
    observation = value['observation']
    require(type(observation) is dict and set(observation) == {'path', 'filesystem', 'owner', 'flags', 'fsid'}, 'interval-schema')
    require(_same_evidence(observation, _chain_observation(dict(observation, readonly=False, ignore_ownership=False), path, metadata)), 'interval-schema')
    return value['mount_operation']


def versioned(record):
    present = FIELDS.intersection(record)
    if not present:
        return False
    require(type(record.get('lifecycle_version')) is int and record['lifecycle_version'] == 1, 'interval-version')
    return True


def validate_marker(marker, path, metadata):
    """Apply the ordinary lifecycle schema at every marker authority boundary."""
    require(type(marker) is dict, 'interval-marker')
    if versioned(marker):
        require('interval_seed' not in marker, 'interval-marker')
        if 'ordinary_interval' in marker:
            validate(marker['ordinary_interval'], path, metadata)


def mount_interval(name, record, path, metadata):
    """Validate the existing pre-observation or positive ordinary M schema."""
    from ._native_binding import _same_evidence, _chain_member
    require(_same_evidence(record.get('interval_seed'), seed(name, path, record.get('target'))), 'interval-seed')
    if 'ordinary_interval' not in record:
        require(record.get('outcome') != 'complete' and record.get('observed_mount') is None, 'interval-missing')
        return None
    value = record['ordinary_interval']
    require(validate(value, path, metadata) == name
            and _same_evidence(value, token(name, path, metadata, record['target'], record.get('observed_mount'))),
            'interval-origin')
    _chain_member(record, path, metadata, name)
    return value


def pending_ordinary(records, pending, path, metadata):
    """Admit only the actual terminal ordinary owner, never a stored reference."""
    from ._native_binding import _same_evidence, _chain_member
    require(type(pending) is dict and type(pending.get('id')) is str
            and pending['id'] in records and _same_evidence(pending, records[pending['id']]),
            'interval-owner-conflict')
    _chain_member(pending, path, metadata, pending['id'])
    # Mounted and consumed-close phases are both valid here. The pure index
    # checks origins and carries without imposing the offline all-closed gate.
    Index(records, path, metadata)
    return pending


def correlate_marker(records, marker, path, metadata, pending=None):
    """Check marker identity against its owner, without requiring offline history."""
    from ._native_binding import _same_evidence, _chain_member, _chain_observation, _pair_guard, completed_operation
    from ._native_recovery import COMPOUND, validate_compound, _mounted_marker_evidence
    validate_marker(marker, path, metadata)
    name = marker.get('operation')
    require(name is None or type(name) is str and re.fullmatch('[0-9a-f]{32}', name),
            'binding-resolution-marker')
    owner = records.get(name)
    if owner is None:
        require(not FIELDS.intersection(marker), 'binding-resolution-marker')
        # Old installations can predate the ordinary archive. Once an interval
        # exists, an unarchived marker cannot stand in for its owner. A checked
        # pending ordinary owner may still recover before publishing its marker.
        if any(type(row) is dict and 'ordinary_interval' in row for row in records.values()):
            pending_ordinary(records, pending, path, metadata)
            require('ordinary_interval' in pending, 'interval-owner-conflict')
        return
    require(type(owner) is dict and owner.get('id') == name and owner.get('workspace') == path.name,
            'interval-owner')
    if type(pending) is dict and pending.get('id') == name:
        if owner.get('operation') in COMPOUND:
            # Compound persistence is journal-first. Its existing continuation
            # owns newer phase facts; an older archive cannot replace them.
            require(all(_same_evidence(owner.get(k), pending.get(k)) for k in
                        ('id', 'workspace', 'operation', 'target', 'accepted_mount', 'name', 'recovery_name')),
                    'interval-owner-conflict')
            owner = pending
        else:
            require(_same_evidence(owner, pending), 'interval-owner-conflict')
    else:
        require(owner.get('outcome') == 'complete', 'interval-owner-conflict')
    core.native_target({'ownership': 'external-reference', 'native_image': owner.get('target')})
    require(_same_evidence(marker.get('target'), owner['target']), 'binding-resolution-marker')
    fields = ('lifecycle_version', 'ordinary_interval')
    require(_same_evidence({k: marker[k] for k in fields if k in marker},
                           {k: owner[k] for k in fields if k in owner}), 'binding-resolution-marker')
    # Only ordinary lifecycle and compound lifecycle producers publish markers.
    # Offline catalog and move operations retain the preceding marker owner;
    # a token-free body cannot grant them marker authority.
    require(owner.get('operation') in ('native-mount', 'native-unmount') + COMPOUND,
            'interval-operation')
    if owner.get('outcome') == 'complete':
        completed_operation(owner, path, metadata, name)
    if owner.get('operation') in COMPOUND:
        require(not FIELDS.intersection(marker) and not FIELDS.intersection(owner), 'interval-operation')
        validate_compound(path.name, owner, metadata.get('transaction'))
        _native.check_helpers(owner, {'verify-package', 'discover', 'mount', 'unmount'})
        if marker.get('state') == 'mounted':
            require(owner['originally_mounted'] is True
                    and marker.get('profile') == owner['profile']
                    and _mounted_marker_evidence(owner, marker.get('observation')),
                    'binding-resolution-marker')
            observation = _chain_observation(marker.get('observation'), path, metadata)
            require(observation is not None, 'binding-resolution-marker')
        else:
            _pair_guard(marker.get('current_guard'), owner['target'])
            require(marker.get('state') == 'absent'
                    and owner['phase'] not in ('prepared', 'unmount-attempted')
                    and _same_evidence(marker.get('current_guard'), owner.get('offline_admission')),
                    'binding-resolution-marker')
        return
    if versioned(owner):
        if owner['operation'] == 'native-mount':
            require(mount_interval(name, owner, path, metadata) is not None, 'interval-missing')
        else:
            require('interval_seed' not in owner, 'interval-seed')
            if 'ordinary_interval' in owner:
                origin = validate(owner['ordinary_interval'], path, metadata)
                require(origin in records and records[origin].get('operation') == 'native-mount'
                        and versioned(records[origin])
                        and _same_evidence(owner['ordinary_interval'],
                                           mount_interval(origin, records[origin], path, metadata)), 'interval-origin')
    before, after, guard, closed = _chain_member(owner, path, metadata, name)
    if marker.get('state') == 'mounted':
        require(owner['operation'] == 'native-mount' and after is not None
                and _same_evidence(_chain_observation(marker.get('observation'), path, metadata), after),
                'binding-resolution-marker')
    else:
        _pair_guard(marker.get('current_guard'), owner['target'])
        require(marker.get('state') == 'absent' and owner['operation'] == 'native-unmount'
                and closed and _same_evidence(marker.get('current_guard'), guard), 'binding-resolution-marker')


class Index:
    def __init__(self, records, path, metadata, *, active_compound=None):
        from ._native_binding import _same_evidence, _chain_member, completed_operation
        self.origins, self.closes, self.tokens = {}, {}, {}
        self.closed_guards = []
        self.records = records
        paths = {str(path / 'native-operations' / name / 'record.json'): name
                 for name in records if type(name) is str}
        incoming, predecessors = {}, {}
        for name, row in records.items():
            reference = row.get('previous_unresolved') if type(row) is dict else None
            if type(reference) is dict:
                targets = set()
                if type(reference.get('id')) is str and reference['id'] in records:
                    targets.add(reference['id'])
                if type(reference.get('record')) is str and reference['record'] in paths:
                    targets.add(paths[reference['record']])
                for target in targets:
                    incoming.setdefault(target, []).append(name)
        # Every origin is checked, including healthy mounts outside recovery chains.
        for name, record in records.items():
            require(type(name) is str and re.fullmatch('[0-9a-f]{32}', name)
                    and type(record) is dict and type(record.get('id')) is str
                    and record['id'] == name and record.get('workspace') == path.name,
                    'interval-owner')
            core.native_target({'ownership': 'external-reference', 'native_image': record.get('target')})
            if record.get('outcome') == 'complete':
                completed_operation(record, path, metadata, name)
            elif record.get('operation') in ('native-mount', 'native-unmount'):
                _native.check_pending(path.name, record)
            else:
                from ._native_recovery import COMPOUND, validate_compound
                require(name == active_compound and record.get('operation') in COMPOUND
                        and record.get('phase') in ('prepared', 'unmount-attempted')
                        and record.get('bridge_attempted') is False, 'interval-unresolved-action')
                validate_compound(path.name, record, metadata.get('transaction'))
                _native.check_helpers(record, {'verify-package', 'discover', 'mount', 'unmount'})
            if not versioned(record):
                continue
            require(record.get('operation') in ('native-mount', 'native-unmount'), 'interval-operation')
            require('previous_unresolved' in record, 'interval-reference')
            reference = record['previous_unresolved']
            if reference is not None:
                require(type(reference) is dict and type(reference.get('id')) is str
                        and reference['id'] in records and reference['id'] != name, 'interval-reference')
                prior = records[reference['id']]
                require(type(prior) is dict and _same_evidence(reference,
                        dict(id=reference['id'], operation=prior.get('operation'), outcome=prior.get('outcome'),
                             record=str(path / 'native-operations' / reference['id'] / 'record.json')))
                        and incoming.get(reference['id']) == [name]
                        and _same_evidence(record['target'], prior.get('target')), 'interval-reference')
                predecessors[name] = reference['id']
            if record['operation'] == 'native-mount':
                value = mount_interval(name, record, path, metadata)
                if value is None:
                    continue
                if record['outcome'] == 'complete':
                    completed_operation(record, path, metadata, name)
                self.origins[name] = value
            else:
                require('interval_seed' not in record, 'interval-seed')
                _chain_member(record, path, metadata, name)
                if record['outcome'] == 'complete':
                    completed_operation(record, path, metadata, name)
            if 'ordinary_interval' in record:
                validate(record['ordinary_interval'], path, metadata)
                self.tokens[name] = record['ordinary_interval']
        checked = set()
        for start in predecessors:
            current, trail, visiting = start, [], set()
            while current in predecessors and current not in checked:
                require(current not in visiting, 'interval-reference-cycle')
                visiting.add(current); trail.append(current); current = predecessors[current]
            checked.update(trail)
        # Absence without a consumed guard leaves the origin open. A later
        # helper-free operation can obtain its own guard along this unique
        # linear chain; it never repairs or supplies a guard to an old record.
        absent_links, states, members, absence_roots = {}, {}, {}, {}
        self.unresolved_absence, self.fresh_resolutions = set(), set()
        self.incoming = incoming
        for name, value in self.tokens.items():
            record = records[name]
            origin = value['mount_operation']
            require(origin in self.origins and _same_evidence(value, self.origins[origin])
                    and _same_evidence(record['target'], value['target']), 'interval-origin')
            if record['operation'] == 'native-mount':
                continue
            before, after, guard, closed = _chain_member(record, path, metadata, name)
            members[name] = (before, after, guard, closed)
            require(before is None or _same_evidence(before, value['observation']), 'interval-observation')
            if after is not None:
                continue
            if before is not None:
                require(origin not in absence_roots, 'interval-competing-close')
                absence_roots[origin] = name
                if closed:
                    require(origin not in self.closes, 'interval-competing-close')
                    self.closes[origin] = name
                    self.closed_guards.append(guard)
                    states[name] = 'closed'
                else:
                    states[name] = 'unresolved'
                    self.unresolved_absence.add(name)
            else:
                previous = predecessors.get(name)
                require(previous in self.tokens
                        and records[previous].get('operation') == 'native-unmount'
                        and _same_evidence(self.tokens[previous], value)
                        and records[previous].get('observed_mount', False) is None,
                        'interval-carry')
                absent_links[name] = previous
        # Each suffix is resolved once; graph size is already Admission-bounded.
        for start in absent_links:
            chain, visiting, current = [], set(), start
            while current not in states:
                require(current not in visiting and current in absent_links, 'interval-carry')
                visiting.add(current); chain.append(current); current = absent_links[current]
            for name in reversed(chain):
                previous = absent_links[name]
                guard = members[name][2]
                if states[previous] == 'unresolved':
                    if guard is None:
                        states[name] = 'unresolved'
                        self.unresolved_absence.add(name)
                    else:
                        origin = self.tokens[name]['mount_operation']
                        require(origin not in self.closes, 'interval-competing-close')
                        self.closes[origin] = name
                        self.closed_guards.append(guard)
                        self.fresh_resolutions.add(name)
                        states[name] = 'closed'
                else:
                    require(guard is not None and _same_evidence(guard, members[previous][2]), 'interval-carry')
                    states[name] = 'closed'
        from . import _native_recovery as recovery
        from ._native_binding import _pair_guard, _chain_observation
        for name, record in records.items():
            if record.get('operation') not in recovery.COMPOUND:
                continue
            for number, attempt in enumerate(record.get('unmount_attempts', [])):
                if 'input_interval_close' not in attempt:
                    continue
                close = attempt['input_interval_close']
                require(type(close) is dict and set(close) == {'version', 'ordinary_interval', 'attempt', 'before', 'observed_mount', 'guard'}
                        and type(close['version']) is int and close['version'] == 1
                        and type(close['attempt']) is int and close['attempt'] == number
                        and close['observed_mount'] is None, 'interval-compound-close')
                value = close['ordinary_interval']; origin = validate(value, path, metadata)
                require(origin in self.origins and _same_evidence(value, self.origins[origin])
                        and _same_evidence(value, attempt.get('ordinary_interval'))
                        and _same_evidence(value, record.get('accepted_mount', {}).get('ordinary_interval'))
                        and _same_evidence(value['target'], record['target'])
                        and _same_evidence(_chain_observation(close['before'], path, metadata), value['observation'])
                        and _same_evidence(close['before'], attempt.get('before'))
                        and recovery._terminal_attempt(record, 'unmount', number)
                        and any(h.get('stage') == 'unmount' and h.get('attempt') == number
                                and h.get('label') == 'unmount' and h.get('outcome') == 'success'
                                and type(h.get('returncode')) is int and h['returncode'] == 0
                                for h in record['helpers']), 'interval-compound-close')
                _pair_guard(close['guard'], record['target'])
                if record['outcome'] == 'complete':
                    completed_operation(record, path, metadata, name)
                    require(origin not in self.closes, 'interval-competing-close')
                    self.closes[origin] = name
                    self.closed_guards.append(close['guard'])
        for origin, name in self.closes.items():
            initial = records[origin]['current_guard']
            record = records[name]
            final = (record['current_guard'] if record['operation'] == 'native-unmount' else
                     next(a['input_interval_close']['guard'] for a in record['unmount_attempts']
                          if 'input_interval_close' in a))
            require(final['generation'] >= initial['generation'], 'interval-guard-order')
            if final['generation'] == initial['generation']:
                require(all(_same_evidence(final[k], initial[k]) for k in ('generation', 'committed_end', 'root_digest')), 'binding-conflicting-anchors')
        self.open = set(self.origins) - set(self.closes)


def absent_owner(index, pending, value, *, allow_unresolved=False):
    """Check a terminal absent owner; unresolved evidence grants only a retry."""
    from ._native_binding import _same_evidence
    require(type(pending) is dict and pending.get('operation') == 'native-unmount'
            and pending.get('observed_mount', False) is None
            and pending.get('id') in index.records
            and _same_evidence(index.records[pending['id']], pending)
            and _same_evidence(pending.get('ordinary_interval'), value)
            and not index.incoming.get(pending['id']), 'interval-carry')
    origin = value['mount_operation']
    if pending['id'] in index.unresolved_absence:
        require(allow_unresolved and index.open == {origin}, 'interval-carry')
    else:
        require(origin in index.closes and not index.open
                and pending.get('current_guard') is not None, 'interval-carry')


def capture(store, path, metadata, target, observation, *, unmount_recovery=False, captured=None):
    """Read one admitted inventory before allocating an ordinary unmount owner."""
    from ._native_binding import _same_evidence, _chain_observation
    a = Admission(store.root)
    try:
        records = load(a, path)
        index = Index(records, path, metadata)
        journal = store.root / 'journals' / (path.name + '.json')
        pending = a.read(journal) if a.exists(journal) else None
        marker_path = path / 'native-mount.json'
        marker = a.read(marker_path) if a.exists(marker_path) else {}
        correlate_marker(records, marker, path, metadata, pending)
        if pending is not None:
            _native.check_pending(path.name, pending)
            require(pending.get('id') in records and _same_evidence(pending, records[pending['id']])
                    and _same_evidence(pending.get('target'), target), 'interval-owner-conflict')
            value = pending.get('ordinary_interval')
        else:
            value = marker.get('ordinary_interval') if observation is not None else None
        if value is not None:
            origin = validate(value, path, metadata)
            require(origin in index.origins and _same_evidence(value, index.origins[origin])
                    and _same_evidence(value['target'], target), 'interval-origin')
            if observation is not None:
                require(index.open == {origin} and _same_evidence(value['observation'], _chain_observation(observation, path, metadata)), 'interval-open-conflict')
                if pending is None:
                    require(marker.get('operation') == origin and marker.get('state') == 'mounted'
                            and versioned(marker) and _same_evidence(marker.get('target'), target)
                            and _same_evidence(_chain_observation(marker.get('observation'), path, metadata), value['observation']), 'interval-marker')
            else:
                absent_owner(index, pending, value, allow_unresolved=unmount_recovery)
        else:
            require(not index.open, 'interval-missing')
            if observation is not None and FIELDS.intersection(marker):
                require(versioned(marker) and 'ordinary_interval' not in marker and pending is not None, 'interval-marker')
        a.check()
        if captured is not None:
            captured['predecessor'] = pending
        return value
    finally:
        a.close()


def check_input(store, path, metadata, target, observation, value, *, owner):
    from ._native_binding import _same_evidence, _chain_observation
    a = Admission(store.root)
    try:
        records = load(a, path)
        require(owner in records and _same_evidence(a.read(store.root / 'journals' / (path.name + '.json')), records[owner]), 'interval-owner-conflict')
        index = Index(records, path, metadata, active_compound=owner)
        origin = validate(value, path, metadata)
        require(index.open == {origin} and _same_evidence(index.origins[origin], value)
                and _same_evidence(target, value['target'])
                and _same_evidence(_chain_observation(observation, path, metadata), value['observation']), 'interval-open-conflict')
    finally:
        a.close()


def recheck_capture(store, path, metadata, operation, *, expected_predecessor):
    from ._native_binding import _same_evidence
    a = Admission(store.root)
    try:
        records = load(a, path)
        own = records.pop(operation.record['id'], None)
        require(_same_evidence(own, operation.record) and own.get('outcome') == 'prepared'
                and own.get('helpers') == [] and own.get('child_pending') is False
                and _same_evidence(a.read(operation.journal), own), 'interval-owner-conflict')
        reference = own.get('previous_unresolved')
        if expected_predecessor is None:
            require(reference is None, 'interval-owner-conflict')
        else:
            previous = expected_predecessor['id']
            require(_same_evidence(records.get(previous), expected_predecessor)
                    and _same_evidence(reference, dict(id=previous,
                        operation=expected_predecessor['operation'], outcome=expected_predecessor['outcome'],
                        record=str(path / 'native-operations' / previous / 'record.json'))), 'interval-owner-conflict')
        index = Index(records, path, metadata)
        value = own.get('ordinary_interval')
        if value is not None and own['before_mount'] is not None:
            origin = value['mount_operation']
            require(index.open == {origin} and _same_evidence(index.origins[origin], value), 'interval-open-conflict')
        elif value is not None:
            require(own['operation'] == 'native-unmount', 'interval-operation')
            absent_owner(index, expected_predecessor, value, allow_unresolved=True)
        else:
            require(not index.open, 'interval-missing')
        a.check()
    finally:
        a.close()
