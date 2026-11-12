"""Read-only existing-store observation and structural resource consistency."""
import ctypes
import copy
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

COLLECTIONS = ('seeds', 'workspaces', 'trash', 'staging', 'locks', 'journals',
               'lifecycle', 'snapshots', 'recovery', 'protected')
LIMITS = dict(entries=16384, document=8*1024*1024, control_bytes=32*1024*1024,
              roots=64, output=64*1024*1024)

class Refusal(ValueError):
    def __init__(self, code, path=None):
        self.code, self.path = code, str(path) if path is not None else None
        super().__init__(code)

def require(condition, code, path=None):
    if not condition:
        raise Refusal(code, path)

def identifier(value, length):
    require(type(value) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}', value), 'invalid-identifier')
    return value

def failure(message, details=None):
    return Refusal('unresolved-helper-lifetime')

def unique_object(items):
    value = {}
    for key, item in items:
        require(key not in value, 'duplicate-json-key')
        value[key] = item
    return value

def stamp(info):
    return [getattr(info, key) for key in ('st_dev', 'st_ino', 'st_uid', 'st_gid',
            'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]

def pair(info):
    return [info.st_dev, info.st_ino]

def empty_acl(fd, *, ancestor=False):
    """Read Darwin ACLs. Deny-only ancestors are accepted; controls require no ACL."""
    require(sys.platform == 'darwin', 'unsupported-acl-platform')
    c = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    for name, arguments, result in (
        ('acl_get_fd_np', [ctypes.c_int, ctypes.c_int], ctypes.c_void_p),
        ('acl_get_entry', [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)], ctypes.c_int),
        ('acl_get_tag_type', [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)], ctypes.c_int),
        ('acl_valid', [ctypes.c_void_p], ctypes.c_int),
        ('acl_free', [ctypes.c_void_p], ctypes.c_int)):
        function = getattr(c, name); function.argtypes = arguments; function.restype = result
    ctypes.set_errno(0)
    acl = c.acl_get_fd_np(fd, 0x100)
    if not acl:
        require(ctypes.get_errno() == errno.ENOENT, 'acl-unreadable')
        return
    try:
        require(c.acl_valid(acl) == 0, 'invalid-acl')
        entry = ctypes.c_void_p(); index = 0
        while True:
            ctypes.set_errno(0)
            result = c.acl_get_entry(acl, index, ctypes.byref(entry)); index = -1
            if result:
                require(ctypes.get_errno() == errno.EINVAL, 'acl-unreadable')
                break
            tag = ctypes.c_int()
            require(ancestor and c.acl_get_tag_type(entry, ctypes.byref(tag)) == 0
                    and tag.value == 2, 'unsupported-acl')
    finally:
        require(c.acl_free(acl) == 0, 'acl-close-failed')

class Existing:
    """Descriptor-relative, no-create observation; all held bindings rechecked."""
    def __init__(self, literal, limits):
        require(type(literal) is not str or not literal.startswith('//'), 'unsupported-root-spelling', literal)
        require(type(literal) is str and literal.startswith('/') and '\0' not in literal
                and '..' not in literal.split('/') and '.' not in literal.split('/'), 'invalid-root', literal)
        self.root = Path(literal)
        self.limits, self.fds, self.stamps, self.paths = limits, {}, {}, {}
        self.entries = self.bytes = 0
        self.device = None

    def admit(self):
        path = Path('/')
        self._open(path, ancestor=True)
        for component in self.root.parts[1:]:
            path = path / component
            self._open(path, ancestor=path != self.root)
        self.device = os.fstat(self.fds[self.root]).st_dev
        return pair(os.fstat(self.fds[self.root]))

    def _open(self, path, *, ancestor=False, directory=True):
        if path in self.fds:
            self.check_one(path)
            return self.fds[path]
        parent = None if path == Path('/') else self.fds[path.parent]
        name = '/' if parent is None else path.name
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        mode = before.st_mode
        require(stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode) and before.st_nlink == 1,
                'unsafe-type-or-hardlink', path)
        require(before.st_uid in ((0, os.getuid()) if ancestor else (os.getuid(),))
                and not mode & (0o022 if ancestor else 0o077), 'unsafe-owner-mode', path)
        if self.device is not None:
            require(before.st_dev == self.device, 'foreign-volume', path)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                     | (os.O_DIRECTORY if directory else 0), dir_fd=parent)
        self.fds[path] = fd
        self.stamps[path] = stamp(before)
        require(stamp(os.fstat(fd)) == stamp(before), 'binding-changed', path)
        empty_acl(fd, ancestor=ancestor)
        self.paths[path] = ancestor
        return fd

    def directory(self, path):
        if path not in self.fds:
            self.directory(path.parent)
        return self._open(path)

    def names(self, path):
        names = []
        with os.scandir(self.directory(path)) as entries:
            for item in entries:
                self.entries += 1
                require(self.entries <= self.limits['entries'], 'entry-budget', path)
                names.append(item.name)
        self.check_one(path)
        return sorted(names)

    def read(self, path, *, document=True):
        self.directory(path.parent)
        fd = self._open(path, directory=False)
        require(os.fstat(fd).st_size <= self.limits['document'], 'document-budget', path)
        data = bytearray()
        while True:
            remaining = min(self.limits['document']-len(data), self.limits['control_bytes']-self.bytes)
            block = os.pread(fd, min(65536, remaining+1), len(data))
            if not block:
                break
            data.extend(block); self.bytes += len(block)
            require(len(data) <= self.limits['document'], 'document-budget', path)
            require(self.bytes <= self.limits['control_bytes'], 'control-byte-budget', path)
        self.check_one(path)
        if not document:
            return bytes(data)
        value = json.loads(data, object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refusal('nonfinite-json')))
        require(type(value) is dict and type(value.get('format')) is int and value['format'] == 1,
                'unknown-format', path)
        return {key: item for key, item in value.items() if key != 'format'}

    def lock(self, path):
        self.directory(path.parent)
        fd = self._open(path, directory=False)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refusal('busy-lock', path) from None
        finally:
            # Never hold a lock as a maintenance reservation.
            fcntl.flock(fd, fcntl.LOCK_UN)
        self.check_one(path)

    def check_one(self, path):
        parent = None if path == Path('/') else self.fds[path.parent]
        info = os.stat('/' if parent is None else path.name, dir_fd=parent, follow_symlinks=False)
        # Ancestor directory size/times can change due to unrelated siblings.
        current, saved = stamp(info), self.stamps[path]
        held = stamp(os.fstat(self.fds[path]))
        indexes = range(6) if self.paths.get(path, False) else range(9)
        require(all(current[i] == saved[i] == held[i] for i in indexes), 'binding-changed', path)

    def finish(self):
        failures = []
        for path in self.fds:
            try:
                self.check_one(path); empty_acl(self.fds[path], ancestor=self.paths.get(path, False))
            except (OSError, Refusal) as error:
                failures.append(dict(code='exit-recheck-failed', path=str(path), detail=str(error)))
        for path, fd in reversed(list(self.fds.items())):
            try:
                os.close(fd)
            except OSError as error:
                failures.append(dict(code='close-failed', path=str(path), detail=str(error)))
        self.fds.clear()
        return failures

def diagnostic(error, path):
    return dict(code=getattr(error, 'code', type(error).__name__),
                path=getattr(error, 'path', None) or str(path), detail=str(error))

def pending(a, path, record, runtime):
    """Observe native-create intent; no continuation and no runtime substitution."""
    workspace = path.stem
    stage = ownership(a, record, workspace)
    require(set(record) <= PRODUCER | PROTOCOL2 | {'installation'}, 'unknown-journal-schema', path)
    row = dict(path=str(path), operation='native-create', status='pending', blocking=True,
               workspace=workspace, transaction=record['transaction'], backend='native-image',
               ownership='store-created', next_action='exact-original-runtime-recovery')
    if record.get('protocol') in (2, 3):
        spec = a.read(stage / 'create-spec.json')
        schema(spec)
        require(digest(spec) == record.get('spec_digest') and spec['protocol'] == record['protocol'],
                'request-digest', path)
        require(a.read(stage / 'native-create') == marker(record), 'marker-journal-disagreement', stage)
        require(all(spec[k] == record[k] for k in ('workspace', 'transaction', 'seed', 'stage', 'stage_identity', 'object')),
                'request-owner', path)
        require(pair(os.fstat(a.directory(stage))) == spec['stage_identity'], 'stage-substitution', stage)
        for child, expected in (('input', spec['input_identity']), ('owned', spec['object'])):
            require(pair(os.fstat(a.directory(stage / child))) == expected, 'directory-substitution', stage / child)
        bindings = [('.lock', spec['store_lock']), ('locks/seed-'+spec['seed'], spec['seed_lock']),
                    ('locks/use-'+workspace, spec['lease']['file']), ('locks/workspace-'+workspace, spec['workspace_lock'])]
        for relative, expected in bindings:
            a.lock(a.root / relative)
            require(pair(os.fstat(a.fds[a.root / relative])) == expected, 'lock-substitution', relative)
        require(os.pread(a.fds[a.root / ('locks/use-'+workspace)], 66, 0)
                == (spec['lease']['generation']+'\n').encode(), 'lease-generation')
        row.update(protocol=spec['protocol'], phase=record.get('phase'), request_digest=digest(spec),
                   runtime=spec['runtime'], profile=spec['profile'], host=spec['host'],
                   runtime_matches=spec['runtime'] == runtime,
                   configuration_matches=spec['profile'] == 'production'
                       and spec['host'] == '/Applications/StallionFS.app/Contents/MacOS/StallionFS')
        row['next_action'] = 'exact-original-runtime-recovery' if row['runtime_matches'] and row['configuration_matches'] else 'retain-original-runtime-binding'
    else:
        row.update(protocol=record.get('protocol'), next_action='unsupported-legacy-retain')
    if 'helpers' in record or 'child_pending' in record:
        try:
            check_helpers(record, {'verify-package', 'discover'})
            row['helper_activity'] = 'terminal-retained'
        except Refusal:
            row['helper_activity'] = 'unresolved'
    else:
        row['helper_activity'] = 'unobserved'
    row['actors'] = record.get('actors', [])
    # Writer actor validation/OS descendant attribution is intentionally not granted here.
    if row['actors']:
        row['actor_activity'] = 'requires-exact-actor-and-OS-attribution'
    return row

def observe_root(item, limits, runtime):
    row = dict(input=item, complete=True, blockers=[], entries=[], coverage=[], omitted=[])
    a = None
    try:
        require(type(item) is dict and set(item) == {'literal','reason'}
                and item['reason'] in ('default','environment','explicit'), 'invalid-root-input')
        a = Existing(item['literal'], limits)
        identity = a.admit(); row['physical_identity'] = identity
        names = a.names(a.root)
        required = set(COLLECTIONS) | {'.lock', 'store.json'}
        for name in sorted(required - set(names)):
            row['blockers'].append(dict(code='required-missing', path=str(a.root/name)))
            row['complete'] = False
        for name in sorted(set(names)-required-{'cleanup.json'}):
            row['blockers'].append(dict(code='unknown-top-level', path=str(a.root/name)))
        a.lock(a.root/'.lock')
        require(a.read(a.root/'store.json') == {'application':'stallionfs'}, 'invalid-store')
        row['coverage'].extend(['store.json', '.lock'])
        if 'cleanup.json' in names:
            policy = a.read(a.root/'cleanup.json')
            require(set(policy) <= {'enabled', 'cursor'} and type(policy.get('enabled')) is bool
                    and (policy.get('cursor') is None or re.fullmatch('[0-9a-f]{32}', str(policy['cursor']))), 'cleanup-schema')
            row['cleanup'] = policy
        row['coverage'].append('cleanup.json' if 'cleanup.json' in names else 'cleanup.json:absent')
        for collection in COLLECTIONS:
            parent = a.root/collection
            try:
                children = a.names(parent); row['coverage'].append(collection)
                for index, name in enumerate(children):
                    path = parent/name
                    try:
                        if collection == 'locks':
                            require(re.fullmatch(r'(seed-[0-9a-f]{64}|(?:use|workspace)-[0-9a-f]{32}|retention)', name),
                                    'unknown-lock', path)
                            a.lock(path)
                            entry = dict(path=str(path), status='idle-at-observation', blocking=False)
                        elif collection == 'journals':
                            if re.fullmatch(r'\.[0-9a-f]{32}\.json\.[0-9a-f]{32}', name):
                                a.read(path, document=False)
                                entry = dict(path=str(path), status='retained-publication-remnant',
                                             authoritative=False, blocking=True,
                                             next_action='retain-unclassified-publication-evidence')
                            else:
                                record = a.read(path)
                                require(record.get('operation') == 'native-create', 'unsupported-journal-operation', path)
                                entry = pending(a, path, record, runtime)
                        else:
                            info = os.stat(name, dir_fd=a.directory(parent), follow_symlinks=False)
                            # Do not descend into ordinary user payload or opaque image bytes.
                            if stat.S_ISDIR(info.st_mode):
                                a.directory(path)
                            elif name.endswith('.json'):
                                a.read(path)
                            else:
                                require(False, 'unsupported-opaque-entry', path)
                            entry = dict(path=str(path), identity=pair(info), status='retained-unqualified',
                                         blocking=True, next_action='retain-and-qualify-schema')
                        row['entries'].append(entry)
                        if entry['blocking']:
                            row['blockers'].append(dict(code='pending-or-unqualified', path=str(path)))
                    except (OSError, ValueError, TypeError, RecursionError) as error:
                        row['blockers'].append(diagnostic(error, path)); row['complete'] = False
                        row['omitted'].append(str(path))
            except (OSError, ValueError, TypeError, RecursionError) as error:
                row['blockers'].append(diagnostic(error, parent)); row['complete'] = False
                row['omitted'].append(str(parent)+'/*')
    except FileNotFoundError as error:
        # Missing final default only: all physical parents have already been admitted.
        if item['reason'] == 'default' and a.root not in a.fds and a.root.parent in a.fds:
            row.update(status='absent-default', complete=True)
        else:
            row['blockers'].append(diagnostic(error, a.root)); row['complete'] = False
            row['omitted'].append(str(a.root)+'/**')
    except (OSError, ValueError, TypeError, RecursionError) as error:
        row['blockers'].append(diagnostic(error, a.root if a else item)); row['complete'] = False
        row['omitted'].append(str(a.root if a else item)+'/**')
    finally:
        failures = a.finish() if a else []
        if failures:
            row['blockers'].extend(failures); row['complete'] = False
    return row

def observe(request, *, limits=None):
    request = copy.deepcopy(request)
    limits = {**LIMITS, **(limits or {})}
    started = time.time_ns()
    roots = request.get('roots')
    root_items = roots if type(roots) is list else []
    report = dict(schema=1, scope='one-user-declared-roots-cooperative-offline-snapshot',
                  user=os.getuid(), platform=sys.platform, operation=request['operation'],
                  old=request.get('old'), candidate=request.get('candidate'), archives=request.get('archives'),
                  runtime=request.get('runtime'), declared_roots=roots, root_contract=request.get('root_contract'),
                  request_binding=digest(request), declaration_complete=True,
                  observer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  started_ns=started, roots=[], blockers=[], limits=limits,
                  public_upgrade_support=[], activity=request.get('activity'),
                  maintenance_clearance=False)
    try:
        require(type(roots) is list and bool(roots), 'empty-or-invalid-root-request')
        contract = request.get('root_contract')
        require(type(contract) is dict and set(contract) == {'default','environment'}
                and type(contract['default']) is str and bool(contract['default'])
                and (contract['environment'] is None or type(contract['environment']) is str
                     and bool(contract['environment'])), 'invalid-root-contract')
        require(all(type(item) is dict and set(item) == {'literal','reason'}
                    and item['reason'] in ('default','environment','explicit')
                    and type(item['literal']) is str for item in roots), 'invalid-root-input')
        defaults = [item['literal'] for item in roots if item['reason'] == 'default']
        environments = [item['literal'] for item in roots if item['reason'] == 'environment']
        require(defaults == [contract['default']], 'default-root-not-accounted')
        require(environments == ([] if contract['environment'] is None else [contract['environment']]),
                'environment-root-not-accounted')
    except Refusal as error:
        report['declaration_complete'] = False
        report['blockers'].append(diagnostic(error, 'declared-root-request'))
    if len(root_items) > limits['roots']:
        report['blockers'].append(dict(code='request-root-budget', omitted=roots))
    else:
        seen = {}
        for item in root_items:
            row = observe_root(item, limits, request.get('runtime'))
            identity = tuple(row.get('physical_identity', []))
            if identity and not row['blockers']:
                if identity in seen:
                    row['duplicate_of'] = seen[identity]
                else:
                    seen[identity] = item['literal']
            report['roots'].append(row)
    activity = request.get('activity')
    if type(activity) is not dict or activity.get('cooperative_downtime') is not True:
        report['blockers'].append(dict(code='cooperative-downtime-unconfirmed'))
    elif any(activity.get(key) != [] for key in ('mounts', 'helpers', 'descendants', 'uncertainties')):
        report['blockers'].append(dict(code='activity-busy-or-unresolved', observations=activity))
    report['complete'] = report['declaration_complete'] and len(report['roots']) == len(root_items) and all(row['complete'] for row in report['roots'])
    blocked = not report['complete'] or report['blockers'] or any(row['blockers'] for row in report['roots'])
    report['status'] = 'blocked' if blocked else 'no-known-blockers-at-observation'
    report['exit_code'] = 1 if blocked else 0
    report['finished_ns'] = time.time_ns()
    # Retain findings in the caller's report. Refuse output instead of emitting truncated success.
    if len(json.dumps(report, sort_keys=True).encode()) > limits['output']:
        report['blockers'].append(dict(code='output-budget', omitted='serialization; full findings retained in memory'))
        report.update(status='blocked', exit_code=1, complete=False, output_refused=True)
    return report

def serialize(report):
    require(not report.get('output_refused'), 'output-budget')
    data = json.dumps(report, sort_keys=True, allow_nan=False).encode()
    require(len(data) <= report['limits']['output'], 'output-budget')
    return data

def restore_coverage(state, retained_request):
    """Check report consistency against the independently retained original request."""
    if state.get('complete') is False or state.get('requested_roots_unavailable') is True:
        return False
    if type(retained_request) is not dict:
        return False
    try:
        binding = digest(retained_request)
    except (ValueError, TypeError, RecursionError):
        return False
    report = state.get('observation')
    required = retained_request.get('roots')
    runtime, old = retained_request.get('runtime'), retained_request.get('old')
    evidence = state.get('root_access')
    if (type(report) is not dict or type(required) is not list or not required
            or state.get('required_roots') != required
            or type(evidence) is not list or len(evidence) != len(required)
            or report.get('declared_roots') != required or report.get('declaration_complete') is not True
            or report.get('complete') is not True or report.get('status') != 'no-known-blockers-at-observation'
            or report.get('exit_code') != 0 or report.get('blockers') != []
            or state.get('request_binding') != binding or report.get('request_binding') != binding
            or not runtime or not old
            or state.get('old_runtime') != runtime or state.get('old_identity') != old):
        return False
    expected = {key: retained_request.get(key) for key in
                ('operation', 'root_contract', 'runtime', 'old', 'candidate', 'archives', 'activity')}
    expected['declared_roots'] = required
    if any(report.get(key) != value for key, value in expected.items()):
        return False
    rows = report.get('roots')
    if type(rows) is not list or len(rows) != len(required):
        return False
    for item, row, access in zip(required, rows, evidence):
        if (type(row) is not dict or type(access) is not dict or row.get('input') != item
                or row.get('complete') is not True or row.get('blockers') != [] or row.get('omitted') != []
                or access.get('input') != item or access.get('candidate_access') != 'provably-none'
                or access.get('request_binding') != binding
                or access.get('old_runtime') != runtime or access.get('old_identity') != old
                or 'physical_identity' not in access
                or access.get('physical_identity') != row.get('physical_identity')
                or not (row.get('physical_identity') or row.get('status') == 'absent-default')):
            return False
    return True

def recovery_policy(state, retained_request):
    if state.get('old_pending') and state.get('candidate_access') != 'provably-none':
        return 'stop-mixed-runtime-preserve-all'
    if state.get('candidate_access') != 'provably-none':
        return 'same-candidate-repair-only-after-downtime' if state.get('downtime') is True else 'stop-activity'
    if not restore_coverage(state, retained_request):
        return 'stop-incomplete-required-root-evidence'
    if state.get('missing_or_broken'):
        if not (state.get('missing_app_route_qualified') is True and state.get('downtime') is True
                and state.get('last_exact_version_known') is True):
            return 'stop-missing-app-uncertainty'
        return 'restore-exact-same-version-then-observe'
    return 'old-samepath-restore-eligible-for-qualified-manual-procedure' if state.get('downtime') is True else 'stop-activity'

def link_state(kind, *, owned=False, dangling=False):
    if kind == 'absent': return 'no-link'
    if kind == 'symlink' and owned: return 'owned-dangling' if dangling else 'owned-link'
    return 'foreign-entry-preserve'

def inspect_link(path, expected):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return 'no-link'
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or os.readlink(path) != str(expected):
        return 'foreign-entry-preserve'
    return 'owned-link' if os.path.lexists(expected) else 'owned-dangling'

def runtime_contract(actual, expected):
    require(actual == expected, 'runtime-contract-mismatch')
    require(actual['flags'] == ['-I', '-B', '-S'], 'runtime-flags')
    require(actual['executable'] == '/Applications/StallionFS.app/Contents/Resources/Runtime/CPython/bin/python3.13',
            'runtime-path')
    return True

# Retained request parsers; recognition does not qualify an installed upgrade pair.
KEYS = {'operation', 'workspace', 'transaction', 'seed', 'stage', 'stage_identity', 'candidate', 'object', 'final'}

PRODUCER = KEYS | {'creation_attempted', 'outcome', 'native_image', 'result', 'helpers', 'child_pending', 'discovery'}

PROTOCOL2 = {'protocol', 'spec_digest', 'phase', 'actors', 'replacement', 'disposal', 'completion_file'}

BUDGET_KEYS = {'raw_cells', 'metadata_read_bytes', 'metadata_hash_bytes', 'checks', 'auxiliary_bytes', 'auxiliary_io_bytes'}

def ownership(a, record, workspace):
    require(type(record) is dict and KEYS <= record.keys() and (record['operation'] == 'native-create'), 'invalid-owner')
    core.identifier(workspace, 32)
    core.identifier(record['transaction'], 32)
    core.identifier(record['seed'], 64)
    require(record['workspace'] == workspace, 'workspace-mismatch')
    stage = Path(record['stage'])
    require(stage.parent == a.root / 'staging' and stage.name not in ('', '.', '..') and (str(stage) == record['stage']) and (record['candidate'] == str(stage / 'owned')) and (record['final'] == str(a.root / 'workspaces' / workspace)), 'invalid-location')
    for key in ('stage_identity', 'object'):
        require(type(record[key]) is list and len(record[key]) == 2 and all((type(n) is int and n >= 0 for n in record[key])), 'invalid-identity')
    return stage

def settings(profile, host):
    host = str(host or _native.HOST)
    path = Path(host)
    require(profile in _native.PROFILES and '\x00' not in host and path.is_absolute() and (path.name == 'StallionFS') and (path.parent.name == 'MacOS') and ('..' not in path.parts), 'invalid-settings')
    return (profile, host)

PROTOCOL = 3

METHOD = 'git-exact-checkout-v3'

LEGACY_METHOD = 'git-exact-checkout-v2'

DEFAULT_BUDGET = {'policy': 'finite-traversal-v2-derived', 'header_sha256': '9e4d18292efc23bda796609d9c4a0e695fca921d859562096eac6440fcad868c', 'implementation_sha256': 'a9d2934ba3b2b21f184dc67148892d9fbc9e52f62a670d624218dec2b46460a1'}

FIELDS = {'protocol', 'workspace', 'transaction', 'seed', 'seed_identity', 'commit', 'name', 'branch', 'capacity_gib', 'jobs', 'budget', 'install', 'profile', 'host', 'stage', 'stage_identity', 'input_identity', 'object', 'store_lock', 'seed_lock', 'lease', 'workspace_lock', 'method', 'runtime', 'parent'}

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()

def branch_name(name, workspace):
    core.identifier(workspace, 32)
    require(isinstance(name, str) and (not name or re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,63}', name)), 'invalid-name')
    require('..' not in name and '@{' not in name, 'invalid-branch-name')
    return f"stallionfs/{(name + '-' if name else '')}{workspace}"

def generation(parent, workspace, transaction):
    parent_digest = parent['spec_digest'] if parent else None
    return hashlib.sha256(b'sfs replacement lease v1\x00' + json.dumps([parent_digest, workspace, transaction], separators=(',', ':')).encode()).hexdigest()

def marker(record):
    return {**{key: record[key] for key in KEYS}, 'protocol': record['protocol'], 'spec_digest': record['spec_digest']}

def schema(spec):
    require(type(spec) is dict and set(spec) == FIELDS and (type(spec['protocol']) is int) and (spec['protocol'] in (2, PROTOCOL)) and (spec['method'] == (LEGACY_METHOD if spec['protocol'] == 2 else METHOD)), 'request-schema')
    for key, length in (('workspace', 32), ('transaction', 32), ('seed', 64)):
        core.identifier(spec[key], length)
    require(type(spec['commit']) is str and re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', spec['commit']) and (spec['branch'] == branch_name(spec['name'], spec['workspace'])) and (type(spec['capacity_gib']) is int) and (1 <= spec['capacity_gib'] <= 65536) and (type(spec['jobs']) is int) and (1 <= spec['jobs'] <= 4) and (type(spec['install']) is bool), 'request-values')
    settings(spec['profile'], spec['host'])
    for key in ('seed_identity', 'stage_identity', 'input_identity', 'object', 'store_lock', 'seed_lock', 'workspace_lock'):
        require(type(spec[key]) is list and len(spec[key]) == 2 and all((type(n) is int and n >= 0 for n in spec[key])), 'request-identity')
    lease = spec['lease']
    require(type(lease) is dict and set(lease) == {'file', 'generation'} and (type(lease['file']) is list) and (len(lease['file']) == 2) and all((type(n) is int and n >= 0 for n in lease['file'])) and (type(lease['generation']) is str) and re.fullmatch('[0-9a-f]{64}', lease['generation']), 'request-lease')
    parent = spec['parent']
    if parent is not None:
        require(type(parent) is dict and set(parent) == {'workspace', 'transaction', 'spec_digest'}, 'request-parent')
        core.identifier(parent['workspace'], 32)
        core.identifier(parent['transaction'], 32)
        core.identifier(parent['spec_digest'], 64)
    require(lease['generation'] == generation(parent, spec['workspace'], spec['transaction']), 'request-generation')
    budget = spec['budget']
    if budget != DEFAULT_BUDGET:
        require(type(budget) is dict and set(budget) == {'explicit'} and (type(budget['explicit']) is dict) and (set(budget['explicit']) == BUDGET_KEYS) and all((type(n) is int and 0 < n < 1 << 64 for n in budget['explicit'].values())), 'request-budget')
    runtime = spec['runtime']
    contract = _bundle.LEGACY_GIT_CONTRACT if spec['protocol'] == 2 else _bundle.GIT_CONTRACT
    require(type(runtime) is dict and set(runtime) == set(contract) | {'input_inventory_sha256', 'payload_entries', 'payload_sha256', 'descriptor_sha256', 'executable_sha256', 'source_build_id', 'publisher'} and all((runtime[key] == value for key, value in contract.items())) and (runtime['publisher'] == PUBLISHER_TEAM) and (type(runtime['payload_entries']) is int) and (0 < runtime['payload_entries'] <= 4096), 'request-runtime')
    for key in ('input_inventory_sha256', 'payload_sha256', 'descriptor_sha256', 'executable_sha256', 'source_build_id'):
        core.identifier(runtime[key], 64)

PROFILES = {'production': {'type': 'stallionfs', 'bundle': 'com.alvinhhh.stallionfs.module'}, 'private-sfsro27': {'type': 'sfsro27', 'bundle': 'com.alvinhhh.stallionfs.module'}}

def check_helpers(record, allowed):
    """Validate retained terminal receipts; never signal or reap a saved PID."""

    def malformed():
        raise failure('Operation still has unresolved process ownership. Keep its controller running; no continuation was started.', {'intent': record})
    if record.get('child_pending') is not False or not isinstance(record.get('helpers'), list):
        malformed()
    for item in record['helpers']:
        if not isinstance(item, dict) or not isinstance(item.get('label'), str) or item['label'] not in allowed or (type(item.get('child_pending')) is not bool) or item['child_pending'] or (not {'pid', 'returncode', 'reaped'}.issubset(item)) or (type(item.get('reaped')) is not bool) or (not isinstance(item.get('argv'), list)) or (not item['argv']) or any((not isinstance(arg, str) for arg in item['argv'])) or any((not isinstance(item.get(key), str) for key in ('stdout', 'stderr'))):
            malformed()
        if item.get('outcome') == 'not-launched':
            if item.get('pid') is not None or item.get('returncode') is not None or item['reaped']:
                malformed()
        elif item.get('outcome') not in ('success', 'error', 'unknown') or not item['reaped'] or type(item.get('pid')) is not int or (item['pid'] <= 0) or (type(item.get('returncode')) is not int) or (item['outcome'] == 'success' and item['returncode'] != 0) or (item['outcome'] == 'error' and item['returncode'] == 0):
            malformed()
        if record.get('protocol') in (2, 3):
            if any((key in item for key in ('collector_error', 'stream_close_errors', 'receipt_error'))):
                malformed()
            if item['outcome'] != 'not-launched' and (item['outcome'] not in ('success', 'error') or item.get('streams_eof') is not True or item.get('streams_durable') is not True or (type(item.get('output_bytes')) is not int) or (not 0 <= item['output_bytes'] <= 2 * 1024 * 1024) or ('interrupted' in item) or ('stop_errors' in item)):
                malformed()

LEGACY_GIT_CONTRACT = {'schema': 1, 'contract': 'native-create-git-v2', 'source_sha256': '26c56c296b38c0695b26fa95f475f1d01704d2d38e73465ca30b0b2f5dc789d3', 'build_config_sha256': 'f33556ec8016cf7a0340e01e732f4e13c50cf2df97b561d952734275f0996f5d', 'input_inventory_sha256': '4e2ee05194ed0e8779e1123452647ceaee43ae2382ef96fa1bf2d3343f0cfd37', 'payload_format': 'git-tree-v1'}

GIT_CONTRACT = {'schema': 1, 'contract': 'native-create-git-v3', 'source_sha256': LEGACY_GIT_CONTRACT['source_sha256'], 'source_distribution_sha256': 'ed174876799b682ab7f21f02559407f76f04f3ef073a9bea9d72ec800aa3fd46', 'build_config_sha256': LEGACY_GIT_CONTRACT['build_config_sha256'], 'combined_patch_sha256': '951f39fdd898ebaf3b075e148d4a7685c9f81069d17068d07adaf6aa8f9568ef', 'notice_patch_sha256': '13867c0f3bd16a38b022664d0bfb5c2dd2458a97417d363b121bbefe55afec0f', 'curl_archive_sha256': '4d1709a3c7338cf99feee139ebf73321c6a9e2225a0a2f2f5843e7a401d6c8cb', 'curl_header_manifest_sha256': 'f6aba83faccf2554b40308815bc2f1359cdf9f7ebe8dec87cae90f19fbac9228', 'alias_source_sha256': '2f277d0e5d8e525f725cf6dc3542b369274f5880f18d1b1ea06ab316a4aa4527', 'payload_format': 'git-tree-v1'}

PUBLISHER_TEAM = '4CQS5J4848'
core = types.SimpleNamespace(identifier=identifier)
_bundle = types.SimpleNamespace(LEGACY_GIT_CONTRACT=LEGACY_GIT_CONTRACT, GIT_CONTRACT=GIT_CONTRACT)
_native = types.SimpleNamespace(PROFILES=PROFILES, HOST=Path('/Applications/StallionFS.app/Contents/MacOS/StallionFS'))

RESOURCE_LIMIT = 32768
OBSERVER_LIMIT = 128 * 1024
RESOURCE_ROLES = {'observer': 'Contents/Resources/Maintenance/observer.py',
                  'native': 'Contents/Resources/Maintenance/stallionfs-maintenance',
                  'compatibility': 'Contents/Resources/Maintenance/compatibility.json'}
RUNTIME_CONTRACT = {'implementation': 'cpython', 'python_version': '3.13.18',
                    'soabi': 'cpython-313-darwin', 'architecture': 'arm64',
                    'cache_tag': 'cpython-313', 'abiflags': '', 'gil': True,
                    'flags': ['-I', '-B', '-S'],
                    'executable': '/Applications/StallionFS.app/Contents/Resources/Runtime/CPython/bin/python3.13',
                    'initial_paths': [
                        '/Applications/StallionFS.app/Contents/Resources/Runtime/CPython/lib/python313.zip',
                        '/Applications/StallionFS.app/Contents/Resources/Runtime/CPython/lib/python3.13',
                        '/Applications/StallionFS.app/Contents/Resources/Runtime/CPython/lib/python3.13/lib-dynload'],
                    'site_packages': '/Applications/StallionFS.app/Contents/Resources/Runtime/CLI/lib/python3.13/site-packages'}
PARSER_CONTRACT = {'store_format': 1, 'request_protocols': [2, 3],
                   'request_methods': [LEGACY_METHOD, METHOD],
                   'git_contracts': ['native-create-git-v2', 'native-create-git-v3']}


def compatibility_build(value):
    require(type(value) is dict and set(value) == {
        'bundle_id', 'bundle_version', 'package_version', 'source_build_id'}, 'compatibility-build')
    require(type(value['bundle_id']) is str and re.fullmatch(r'[A-Za-z0-9]+(?:\.[A-Za-z0-9-]+)+', value['bundle_id'])
            and len(value['bundle_id']) <= 255, 'compatibility-bundle-id')
    for key in ('bundle_version', 'package_version'):
        require(type(value[key]) is str and len(value[key]) <= 32
                and re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,2}', value[key]), 'compatibility-version')
    identifier(value['source_build_id'], 64)
    return value


def compatibility_tuple(value):
    require(type(value) is dict and set(value) == {'predecessor_descriptor_sha256',
        'candidate_build', 'runtime_contract', 'parser_contract', 'observer_sha256'}, 'compatibility-tuple')
    identifier(value['predecessor_descriptor_sha256'], 64)
    identifier(value['observer_sha256'], 64)
    compatibility_build(value['candidate_build'])
    require(digest(value['runtime_contract']) == digest(RUNTIME_CONTRACT)
            and digest(value['parser_contract']) == digest(PARSER_CONTRACT), 'compatibility-contract')
    return value


def create_compatibility(observer, build):
    """Describe unsigned build inputs; final descriptor identity remains external."""
    require(type(observer) is bytes and 0 < len(observer) <= OBSERVER_LIMIT, 'compatibility-observer-size')
    compatibility_build(build)
    value = {'schema': 1, 'roles': dict(RESOURCE_ROLES), 'build': copy.deepcopy(build),
             'observer': {'sha256': hashlib.sha256(observer).hexdigest(), 'size': len(observer)},
             'runtime_contract': copy.deepcopy(RUNTIME_CONTRACT),
             'parser_contract': copy.deepcopy(PARSER_CONTRACT), 'public_upgrade_support': []}
    data = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()
    validate_compatibility(data, observer, build)
    return data


def validate_compatibility(data, observer, expected_build):
    """Compare separately retained bytes and build fields; authenticate nothing."""
    require(type(data) is bytes and 0 < len(data) <= RESOURCE_LIMIT, 'compatibility-size')
    require(type(observer) is bytes and 0 < len(observer) <= OBSERVER_LIMIT, 'compatibility-observer-size')
    compatibility_build(expected_build)
    try:
        value = json.loads(data, object_pairs_hook=unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(Refusal('nonfinite-json')))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Refusal('compatibility-json') from error
    require(type(value) is dict and set(value) == {'schema', 'roles', 'build', 'observer',
        'runtime_contract', 'parser_contract', 'public_upgrade_support'}
        and type(value['schema']) is int and value['schema'] == 1, 'compatibility-schema')
    require(value['roles'] == RESOURCE_ROLES, 'compatibility-roles')
    compatibility_build(value['build'])
    require(value['build'] == expected_build, 'compatibility-build-mismatch')
    row = value['observer']
    require(type(row) is dict and set(row) == {'sha256', 'size'} and type(row['size']) is int
            and row['size'] == len(observer) and row['sha256'] == hashlib.sha256(observer).hexdigest(),
            'compatibility-observer-mismatch')
    require(digest(value['runtime_contract']) == digest(RUNTIME_CONTRACT)
            and digest(value['parser_contract']) == digest(PARSER_CONTRACT), 'compatibility-contract')
    support = value['public_upgrade_support']
    require(type(support) is list and len(support) <= 16, 'compatibility-support-limit')
    seen = set()
    for item in support:
        compatibility_tuple(item)
        require(item['candidate_build'] == expected_build and item['observer_sha256'] == row['sha256'],
                'compatibility-tuple-binding')
        binding = digest(item)
        require(binding not in seen, 'compatibility-duplicate-tuple')
        seen.add(binding)
    return value


def compatible_predecessor(data, observer, expected_build, requested_tuple):
    """Exact structural match only; publisher admission must precede execution."""
    value = validate_compatibility(data, observer, expected_build)
    compatibility_tuple(requested_tuple)
    require(requested_tuple in value['public_upgrade_support'], 'unsupported-predecessor')
    return {'structurally_consistent': True, 'authenticated': False}

# Parser reports never grant maintenance authority. Only this entry point
# acquires and retains its own inputs before opening any store.
APP = '/Applications/StallionFS.app'
DESCRIPTOR = 'Contents/Resources/Runtime/runtime.json'
NATIVE_LIMIT = 16 * 1024 * 1024
_UNRESOLVED_TOOLS = []


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False, separators=(',', ':'))+'\n').encode()


def retained_read(path, limit=1024*1024, *, private=False):
    """Open every component without following links; bind bytes to the fd."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'invalid-retained-path', path)
    fds = []; bindings = []
    try:
        current = Path('/')
        for index, name in enumerate(path.parts):
            if index == 0: name = '/'
            else: current /= name
            final = index == len(path.parts)-1
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                         | (0 if final else os.O_DIRECTORY), dir_fd=fds[-1] if fds else None)
            fds.append(fd)
            info = os.fstat(fd); bindings.append((name, stamp(info)))
            require(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022,
                    'unsafe-retained-owner-mode', current)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 if final else stat.S_ISDIR(info.st_mode),
                    'unsafe-retained-type', current)
            empty_acl(fd, ancestor=not final)
        before = os.fstat(fd)
        require(not private or before.st_uid == os.getuid() and not before.st_mode & 0o077,
                'unsafe-private-control', path)
        require(before.st_size <= limit, 'retained-byte-limit', path)
        data = os.pread(fd, limit+1, 0)
        require(len(data) == before.st_size and len(data) <= limit and stamp(os.fstat(fd)) == stamp(before),
                'retained-binding-changed', path)
        require(stamp(os.stat(path, follow_symlinks=False)) == stamp(before), 'retained-path-changed', path)
        for index, (name, saved) in enumerate(bindings):
            held = stamp(os.fstat(fds[index]))
            named = stamp(os.stat(name, dir_fd=fds[index-1] if index else None, follow_symlinks=False))
            indexes = range(9) if index == len(bindings)-1 else range(6)
            require(all(held[i] == saved[i] == named[i] for i in indexes), 'retained-ancestor-changed')
        return data
    finally:
        for fd in reversed(fds): os.close(fd)


class Retention:
    """One existing private external directory; never erase partial controls."""
    def __init__(self, directory):
        self.path = Path(directory)
        self.access = Existing(str(self.path), LIMITS)
        self.access.admit()
        self.fd = self.access.fds[self.path]
        self.identity = pair(os.fstat(self.fd))
        self.safe_for_failures = False
        self.check()

    def check(self):
        require(pair(os.stat(self.path, follow_symlinks=False)) == self.identity
                == pair(os.fstat(self.fd)), 'retention-directory-changed')
        info = os.fstat(self.fd)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                'retention-directory-mode')
        empty_acl(self.fd)

    def write(self, name, data, mode=0o600):
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,63}', name), 'retention-name')
        require(type(data) is bytes and len(data) <= LIMITS['output'], 'retention-byte-limit')
        self.check()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     mode, dir_fd=self.fd)
        try:
            os.fchmod(fd, mode); empty_acl(fd)
            offset = 0
            while offset < len(data):
                count = os.write(fd, data[offset:]); require(count > 0, 'retention-short-write'); offset += count
            os.fsync(fd)
            info = os.fstat(fd)
            require(info.st_uid == os.getuid() and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == mode and info.st_size == len(data), 'retention-write-binding')
        finally:
            os.close(fd)
        os.fsync(self.fd)
        require(retained_read(self.path/name, len(data), private=True) == data, 'retention-readback')
        self.check()
        return hashlib.sha256(data).hexdigest()

    def close(self):
        failures = []
        for fd in reversed(list(self.access.fds.values())):
            try: os.close(fd)
            except OSError as error: failures.append(str(error))
        self.access.fds.clear()
        require(not failures, 'retention-close-uncertainty', failures)


def original_request(operation, explicit, authorization):
    import pwd
    require(operation in ('remove', 'reinstall', 'restore'), 'maintenance-operation')
    home = pwd.getpwuid(os.getuid()).pw_dir
    require(home == authorization['home'] and os.path.isabs(home), 'home-identity-mismatch')
    default = home+'/Library/Application Support/stallionfs'
    ambient = os.environ.get('STALLIONFS_HOME')
    roots = [dict(literal=default, reason='default')]
    if ambient is not None: roots.append(dict(literal=ambient, reason='environment'))
    require(type(explicit) is list and all(type(p) is str for p in explicit), 'explicit-root-list')
    roots.extend(dict(literal=p, reason='explicit') for p in explicit)
    return dict(operation=operation, roots=roots, root_contract=dict(default=default, environment=ambient),
                old=authorization['artifact'], candidate=None, archives=authorization['archive'],
                runtime=authorization['store_runtime'], environment=dict(STALLIONFS_HOME=ambient),
                cooperation=authorization['cooperation'],
                acquisition=dict(uid=os.getuid(), home=home, pid=os.getpid(), acquired_ns=time.time_ns()))


def actual_runtime(expected):
    """Check routing before importing further stdlib modules."""
    require(expected == RUNTIME_CONTRACT, 'unsupported-runtime-expectation')
    require(list(sys.path) == expected['initial_paths'], 'runtime-search-path')
    require(sys.flags.isolated == 1 and sys.flags.ignore_environment == 1
            and sys.flags.no_user_site == 1 and sys.flags.no_site == 1
            and sys.flags.dont_write_bytecode == 1 and sys.flags.safe_path, 'runtime-isolation')
    import sysconfig
    actual = dict(implementation=sys.implementation.name,
        python_version='.'.join(map(str, sys.version_info[:3])), soabi=sysconfig.get_config_var('SOABI'),
        architecture=os.uname().machine, cache_tag=sys.implementation.cache_tag,
        abiflags=sys.abiflags, gil=sysconfig.get_config_var('Py_GIL_DISABLED') in (None,0,'0',''),
        flags=['-I','-B','-S'], executable=sys.executable, initial_paths=list(sys.path),
        site_packages=expected['site_packages'])
    require(actual == expected, 'runtime-contract-mismatch')
    require(not any(name == 'site' or name.startswith('stallionfs') for name in sys.modules),
            'runtime-unexpected-import')
    return actual


def static_signature(path, requirement, retention, label):
    """Only the system verifier runs; timeout never claims helper cleanup."""
    import subprocess
    import select
    require(type(requirement) is str and requirement.startswith('anchor apple generic and ')
            and '\0' not in requirement and len(requirement) <= 1024, 'publisher-requirement')
    argv = ['/usr/bin/codesign','--verify','--deep','--strict','-R','='+requirement,str(path)]
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, close_fds=True, env={'PATH':'/usr/bin:/bin','LANG':'C'})
    data = bytearray(); eof = False; collector_error = None
    try:
        deadline = time.monotonic()+30
        os.set_blocking(process.stdout.fileno(), False)
        while time.monotonic() < deadline and len(data) <= 2*1024*1024:
            if select.select([process.stdout], [], [], min(.05, max(0, deadline-time.monotonic())))[0]:
                block = os.read(process.stdout.fileno(), min(65536, 2*1024*1024+1-len(data)))
                if not block: eof = True
                else: data.extend(block)
            if eof and process.poll() is not None: break
    except BaseException as error:
        collector_error = dict(kind=type(error).__name__, detail=str(error))
    try: status = process.poll()
    except BaseException as error:
        status = None
        collector_error = dict(kind=type(error).__name__, detail=str(error))
    complete = not collector_error and eof and status is not None and len(data) <= 2*1024*1024
    if complete:
        try: process.stdout.close()
        except (OSError,ValueError) as error:
            complete = False; collector_error = dict(kind=type(error).__name__,detail=str(error))
    receipt = dict(argv=argv, pid=process.pid, returncode=status, reaped=status is not None,
                   streams_eof=eof, complete=bool(complete), output_sha256=hashlib.sha256(data).hexdigest(),
                   output_bytes=len(data), cleanup_complete=bool(complete),collector_error=collector_error)
    if not complete: _UNRESOLVED_TOOLS.append(process)
    output_error = None
    try: retention.write(label+'.output', bytes(data))
    except (OSError,ValueError) as error:
        output_error = diagnostic(error,'signature-output')
        receipt.update(complete=False,cleanup_complete=False,output_retention_error=output_error)
        if process not in _UNRESOLVED_TOOLS: _UNRESOLVED_TOOLS.append(process)
    retention.write(label+'.json', json_bytes(receipt))
    require(complete and not output_error, 'signature-helper-lifetime-or-output-unresolved',
            'owned-verifier-pid:'+str(process.pid))
    require(status == 0, 'publisher-or-signature-refused', path)
    return receipt


def validate_authorization(data, expected_sha256, expected_publisher):
    require(hashlib.sha256(data).hexdigest() == identifier(expected_sha256, 64), 'authorization-digest')
    value = json.loads(data, object_pairs_hook=unique_object)
    require(type(value) is dict and set(value) == {'schema','artifact','archive','home','runtime','roles',
            'publisher','inventory','last_installed','executable_history','store_history','store_runtime','cooperation'},
            'authorization-schema')
    require(type(value['schema']) is int and value['schema'] == 1, 'authorization-schema')
    require(value['publisher'] == expected_publisher and expected_publisher == PUBLISHER_TEAM,
            'independent-publisher-mismatch')
    require(value['roles'] == RESOURCE_ROLES and value['runtime'] == RUNTIME_CONTRACT, 'authorization-contract')
    runtime = value['store_runtime']
    require(type(runtime) is dict and set(runtime) == set(GIT_CONTRACT) | {'input_inventory_sha256',
        'payload_entries','payload_sha256','descriptor_sha256','executable_sha256','source_build_id','publisher'}
        and all(runtime.get(key) == expected for key,expected in GIT_CONTRACT.items())
        and runtime['publisher'] == expected_publisher and type(runtime['payload_entries']) is int
        and 0 < runtime['payload_entries'] <= 4096, 'authorization-store-runtime')
    for key in ('input_inventory_sha256','payload_sha256','descriptor_sha256','executable_sha256','source_build_id'):
        identifier(runtime[key],64)
    require(type(value['artifact']) is dict and set(value['artifact']) == {'id','descriptor_sha256',
            'observer_sha256','native_sha256','compatibility_sha256'}, 'artifact-schema')
    for item in value['artifact'].values(): identifier(item, 64)
    require(runtime['descriptor_sha256'] == value['artifact']['descriptor_sha256'], 'authorization-store-descriptor')
    require(type(value['archive']) is dict and set(value['archive']) == {'path','sha256'}, 'archive-schema')
    identifier(value['archive']['sha256'], 64)
    require(type(value['inventory']) is list and bool(value['inventory']), 'authorization-inventory')
    require(type(value['cooperation']) is dict and set(value['cooperation']) == {'scope','users','confirmed_ns','boot_id'}
            and value['cooperation']['scope'] in ('single-user-controlled','all-possible-users-cooperative')
            and type(value['cooperation']['users']) is list and os.getuid() in value['cooperation']['users']
            and all(type(uid) is int and uid >= 0 for uid in value['cooperation']['users'])
            and type(value['cooperation']['confirmed_ns']) is int
            and type(value['cooperation']['boot_id']) is str and value['cooperation']['boot_id'], 'shared-app-cooperation')
    return value


def publisher_requirement(identifier_value, publisher):
    require(re.fullmatch(r'[A-Za-z0-9.-]{1,255}', identifier_value) and re.fullmatch(r'[A-Z0-9]{10}',publisher),
            'publisher-identity')
    return ('anchor apple generic and identifier "'+identifier_value
            +'" and certificate leaf[subject.OU] = "'+publisher+'"')


def native_activity(native, completion, request, *, leaf_path, collector_pid):
    """Known activity and unattributable live identities prevent withdrawal."""
    require(type(completion) is dict and completion.get('complete') is True
            and completion.get('reaped') is True and completion.get('streams_eof') is True
            and completion.get('output_durable') is True and completion.get('output_readback') is True
            and completion.get('returncode') == 0 and completion.get('outcome') == 'success'
            and completion.get('directory_bound') is True
            and completion.get('output_bound') is True and completion.get('cleanup_complete') is True
            and completion.get('io_error') is False and completion.get('close_errors') is False,
            'native-completion-unresolved')
    require(type(native) is dict and type(native.get('schema')) is int and native.get('schema') == 1 and native.get('scope') == 'global-kernel-snapshot'
            and native.get('complete') is True and native.get('uncertainties') == []
            and type(native.get('boot_id')) is str and native['boot_id'], 'native-incomplete')
    require(native['boot_id'] == request['cooperation']['boot_id'], 'cooperation-reconfirmation-after-reboot-required')
    require(native['started_ns'] >= request['acquisition']['acquired_ns']
            and native['finished_ns'] >= native['started_ns'], 'native-stale-observation')
    for key in ('mounts','processes','sessions'): require(type(native.get(key)) is list, 'native-schema')
    known = {os.getpid(): sys.executable, collector_pid: str(leaf_path),
             completion.get('worker_pid'): str(leaf_path)}
    processes = native['processes']; by_pid = {}
    require(bool(processes), 'native-process-enumeration-empty')
    for row in processes:
        require(type(row) is dict and type(row.get('pid')) is int and row['pid'] not in by_pid
                and row.get('stable') is True and type(row.get('ppid')) is int
                and type(row.get('uid')) is int and type(row.get('start_sec')) is int
                and type(row.get('start_usec')) is int and 0 <= row['start_usec'] < 1000000
                and (row.get('path') is None or type(row.get('path')) is str), 'native-process-identity')
        by_pid[row['pid']] = row
    helpers = []; unknown = []
    for row in processes:
        path = row.get('path')
        if row['pid'] == 0 and row.get('kernel') is True: continue
        if not path or row.get('path_errno') not in (0, None): unknown.append(row); continue
        if row['pid'] in known and path == known[row['pid']]: continue
        if path == APP or path.startswith(APP+'/') or 'stallionfs' in path.lower() or Path(path).name == 'sfs': helpers.append(row)
    relevant = {row['pid'] for row in helpers}; descendants = []
    while True:
        added = [r for r in processes if r.get('ppid') in relevant and r['pid'] not in relevant]
        if not added: break
        descendants.extend(added); relevant.update(r['pid'] for r in added)
    mounts = []
    for row in native['mounts']:
        require(type(row) is dict and all(type(row.get(k)) is str for k in ('source','target','type')), 'native-mount-schema')
        if row['type'] in ('stallionfs','sfsro27') or 'stallionfs' in (row['source']+' '+row['target']).lower(): mounts.append(row)
        elif row['type'].lower() in ('fskit','fskitfs'): unknown.append(dict(unknown_mount=row))
    sessions = native['sessions']
    import pwd
    for row in sessions:
        require(type(row) is dict and type(row.get('user')) is str, 'native-session-schema')
        try: uid = pwd.getpwnam(row['user']).pw_uid
        except KeyError: uid = None
        if uid is None or uid != row.get('uid') or uid not in request['cooperation']['users']:
            unknown.append(dict(uncovered_session=row))
        elif uid != os.getuid() and request['cooperation']['scope'] != 'all-possible-users-cooperative':
            unknown.append(dict(other_session=row))
    return dict(cooperative_downtime=True, mounts=mounts, helpers=helpers, descendants=descendants,
                uncertainties=unknown, boot_id=native['boot_id'], native_sha256=digest(native),
                completion_sha256=digest(completion), observed_ns=native['finished_ns'], scope=request['cooperation']['scope'])


def software_plan(authorization, activity, app_state, *, request_retained, leaf_available):
    """Executable availability and STORE permission are separate."""
    require(app_state in ('absent','partial','intact-wrong','intact-exact'), 'app-state')
    blockers = []; artifact = authorization['artifact']
    if authorization.get('last_installed') != artifact['id']: blockers.append('last-installed-artifact-unknown-or-different')
    if authorization.get('executable_history') != [artifact['id']]: blockers.append('newer-or-unknown-executable-history')
    if not leaf_available: blockers.append('recover-leaf-from-statically-admitted-exact-archive')
    if (type(activity) is not dict or activity.get('cooperative_downtime') is not True
            or any(activity.get(k) != [] for k in ('mounts','helpers','descendants','uncertainties'))):
        blockers.append('fresh-native-downtime-required')
    history = authorization.get('store_history')
    store_blockers = [] if history == {'runtime': artifact['id'], 'mutation': 'known-same-artifact'} else ['unknown-or-mixed-store-history']
    if not request_retained: store_blockers.append('original-root-request-unavailable-preserve-scope')
    return dict(schema=1, app_state=app_state, software_only_eligible=not blockers, software_blockers=blockers,
        next_action=('verify-installed-exact-then-observe' if app_state == 'intact-exact' else
                     'finder-restore-exact-artifact-at-fixed-path') if not blockers else 'stop-preserve-all',
        store_access_eligible=False, store_blockers=store_blockers,
        pending_requests='retain-exact-runtime-binding-until-separate-qualified-recovery',
        command_link='inspect-separately-after-static-app-admission', enablement='verify-separately-before-store-use',
        qualification='installed-fixed-path-interruption-restart-and-persistence-trials-required')


def physical_directory(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'invalid-physical-directory')
    held = []
    try:
        for index, name in enumerate(path.parts):
            fd = os.open('/' if index == 0 else name,
                os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,
                dir_fd=held[-1] if held else None)
            held.append(fd)
            info = os.fstat(fd)
            require(info.st_uid in (0,os.getuid()) and not info.st_mode & 0o022, 'physical-directory-owner-mode')
            empty_acl(fd,ancestor=index != len(path.parts)-1)
        return os.dup(held[-1])
    finally:
        for fd in reversed(held): os.close(fd)


def app_inventory(app):
    """Inspect fixed paths without traversing symlinks or importing app code."""
    app = Path(app); rows = []; total = 0
    root = physical_directory(app)
    try:
        initial = os.fstat(root)
        require(initial.st_uid in (0, os.getuid()) and not initial.st_mode & 0o022, 'app-owner-mode')
        empty_acl(root)
        def visit(fd, prefix):
            nonlocal total
            before = os.fstat(fd); empty_acl(fd)
            for name in sorted(os.listdir(fd)):
                require(len(rows) < 65536, 'app-entry-limit')
                relative = prefix+name
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(info.st_uid in (0, os.getuid()) and (stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o7022), 'app-member-owner-mode', relative)
                row = dict(path=relative, mode=oct(stat.S_IMODE(info.st_mode)))
                if stat.S_ISLNK(info.st_mode):
                    link = os.readlink(name, dir_fd=fd)
                    require(link and not link.startswith('/') and '\\' not in link and '\0' not in link,
                            'app-link-target', relative)
                    row.update(type='symlink', size=len(os.fsencode(link)), link=link)
                else:
                    require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                            'app-member-type', relative)
                    child = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK
                                    | (os.O_DIRECTORY if stat.S_ISDIR(info.st_mode) else 0), dir_fd=fd)
                    try:
                        require(stamp(os.fstat(child)) == stamp(info), 'app-member-binding', relative)
                        empty_acl(child)
                        if stat.S_ISDIR(info.st_mode):
                            row.update(type='dir', size=0); visit(child, relative+'/')
                        else:
                            total += info.st_size
                            require(info.st_size <= 128*1024*1024 and total <= 512*1024*1024, 'app-file-limit', relative)
                            hasher = hashlib.sha256(); offset = 0
                            while offset < info.st_size:
                                block = os.pread(child, min(65536,info.st_size-offset), offset)
                                require(block, 'app-short-read', relative); hasher.update(block); offset += len(block)
                            row.update(type='file', size=info.st_size, sha256=hasher.hexdigest())
                        require(stamp(os.fstat(child)) == stamp(info), 'app-member-changed', relative)
                    finally:
                        os.close(child)
                require(stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)) == stamp(info), 'app-path-changed', relative)
                rows.append(row)
            require(stamp(os.fstat(fd)) == stamp(before), 'app-directory-changed', prefix)
        visit(root, '')
        require(stamp(os.stat(app, follow_symlinks=False)) == stamp(initial), 'app-root-changed')
        table = {r['path']:r for r in rows}
        for row in rows:
            if row['type'] != 'symlink': continue
            pending = row['path'].split('/'); resolved = []; expansions = 0
            while pending:
                part = pending.pop(0)
                if part in ('','.'): continue
                if part == '..':
                    require(resolved, 'app-link-escape'); resolved.pop(); continue
                name = '/'.join([*resolved,part]); require(name in table, 'app-link-missing')
                target = table[name]
                if target['type'] == 'symlink':
                    expansions += 1; require(expansions <= 64, 'app-link-cycle')
                    pending = target['link'].split('/')+pending
                else:
                    require(not pending or target['type'] == 'dir', 'app-link-nondirectory'); resolved.append(part)
        return sorted(rows, key=lambda row:row['path'])
    finally:
        os.close(root)


def acquire_native(retention, leaf, authorization, request):
    import subprocess
    expected = authorization['artifact']['native_sha256']
    data = retained_read(leaf, 8*1024*1024, private=True)
    require(hashlib.sha256(data).hexdigest() == expected, 'external-leaf-digest')
    static_signature(leaf, publisher_requirement('com.alvinhhh.stallionfs.maintenance', authorization['publisher']),
                     retention, 'external-leaf-signature')
    require(retained_read(leaf, len(data), private=True) == data, 'external-leaf-changed')
    retention.check()
    os.mkdir('native', 0o700, dir_fd=retention.fd)
    directory = retention.path/'native'
    process = subprocess.Popen([str(leaf),'retain',str(directory)], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
        env={'PATH':'/usr/bin:/bin','LANG':'C'})
    try:
        status = process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        _UNRESOLVED_TOOLS.append(process)
        retention.write('native-launch.json', json_bytes(dict(pid=process.pid, reaped=False, complete=False)))
        raise Refusal('native-controller-lifetime-unresolved') from None
    retention.write('native-launch.json', json_bytes(dict(pid=process.pid, reaped=True, returncode=status)))
    completion = json.loads(retained_read(directory/'native-completion.json', 32768, private=True), object_pairs_hook=unique_object)
    native_bytes = retained_read(directory/'native.json', NATIVE_LIMIT, private=True)
    require(completion.get('output_bytes') == len(native_bytes)
            and completion.get('output_sha256') == hashlib.sha256(native_bytes).hexdigest(), 'native-retained-output-binding')
    native = json.loads(native_bytes, object_pairs_hook=unique_object)
    require(status == 0, 'native-controller-refused')
    require(hashlib.sha256(retained_read(leaf,len(data),private=True)).hexdigest() == expected, 'external-leaf-changed')
    activity = native_activity(native, completion, request, leaf_path=leaf, collector_pid=process.pid)
    return activity


def acquisition(operation, explicit, authorization, retention):
    """Installed-runtime entry: static admission precedes stores; all effects are external."""
    request = original_request(operation, explicit, authorization)
    def normalized(path):
        import unicodedata
        literal = os.fspath(path)
        if literal.startswith('~/'): literal = authorization['home']+literal[1:]
        value = os.path.abspath(os.path.normpath(literal))
        parts = tuple(unicodedata.normalize('NFC',part).casefold() for part in Path(value).parts)
        if parts[:4] == ('/','system','volumes','data'): parts = ('/',*parts[4:])
        return parts
    output = normalized(retention.path)
    protected = [normalized(APP), *[normalized(row['literal']) for row in request['roots']]]
    require(all(output[:len(path)] != path and path[:len(output)] != output for path in protected),
            'retention-overlaps-app-or-store')
    ancestor_ids = {tuple(pair(os.fstat(fd))) for fd in retention.access.fds.values()}
    for protected_path in [Path(APP), *[Path(row['literal']).expanduser().absolute() for row in request['roots']]]:
        for index, path in enumerate([protected_path,*protected_path.parents]):
            try: identity = tuple(pair(os.stat(path)))
            except OSError as error:
                if error.errno in (errno.ENOENT,errno.ENOTDIR): continue
                raise Refusal('retention-scope-metadata-unavailable',path) from error
            require(not (index == 0 and identity in ancestor_ids) and identity != tuple(retention.identity),
                    'retention-physical-overlap-app-or-store',path)
    retention.safe_for_failures = True
    retention.write('request.json', json_bytes(request))
    retention.write('authorization.json', json_bytes(authorization))
    require(len(request['roots']) <= LIMITS['roots'], 'request-root-budget')
    artifact = authorization['artifact']
    require(hashlib.sha256(retained_read(Path(__file__), OBSERVER_LIMIT, private=True)).hexdigest()
            == artifact['observer_sha256'], 'external-observer-digest')
    runtime = actual_runtime(authorization['runtime'])
    before = app_inventory(APP)
    require(before == authorization['inventory'], 'installed-inventory-mismatch')
    app = Path(APP)
    static_signature(app, publisher_requirement('com.alvinhhh.stallionfs', authorization['publisher']),
                     retention, 'app-signature')
    for name, identity in (('Contents/Extensions/StallionFS.appex','com.alvinhhh.stallionfs.module'),
                           (RESOURCE_ROLES['native'],'com.alvinhhh.stallionfs.maintenance'),
                           ('Contents/Resources/Runtime/CPython/bin/python3.13',None)):
        requirement = publisher_requirement(identity,authorization['publisher']) if identity else (
            'anchor apple generic and certificate leaf[subject.OU] = "'+authorization['publisher']+'"')
        static_signature(app/name,requirement,retention,'role-'+str(len(os.listdir(retention.fd))))
    for name, key in ((DESCRIPTOR,'descriptor_sha256'),(RESOURCE_ROLES['observer'],'observer_sha256'),
                      (RESOURCE_ROLES['compatibility'],'compatibility_sha256'),(RESOURCE_ROLES['native'],'native_sha256')):
        require(hashlib.sha256(retained_read(app/name, 8*1024*1024)).hexdigest() == artifact[key], 'installed-role-digest', name)
    leaf_data = retained_read(app/RESOURCE_ROLES['native'], 8*1024*1024)
    retention.write('stallionfs-maintenance', leaf_data, 0o700)
    activity = acquire_native(retention, retention.path/'stallionfs-maintenance', authorization, request)
    request['activity'] = activity
    # Original denominator is retained before acquisition; the report binds that
    # request plus separately retained fresh evidence without replacing its roots.
    retention.write('activity.json', json_bytes(activity))
    report = observe(request)
    report.update(acquired_runtime=runtime, original_request_sha256=hashlib.sha256(
        retained_read(retention.path/'request.json', LIMITS['output'], private=True)).hexdigest(),
        native_evidence='native/native.json', maintenance_clearance=False,
        software_plan=software_plan(authorization,activity,'intact-exact',request_retained=True,leaf_available=True))
    require(app_inventory(APP) == before, 'installed-app-changed-during-observation')
    retention.write('observation.json', serialize(report))
    return report


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Observe maintenance state')
    parser.add_argument('operation', choices=('remove','reinstall','restore'))
    parser.add_argument('--root', action='append', default=[])
    parser.add_argument('--authorization', required=True)
    parser.add_argument('--authorization-sha256', required=True)
    parser.add_argument('--publisher', required=True)
    parser.add_argument('--retain', required=True, help='Existing private external 0700 directory')
    args = parser.parse_args(argv)
    retention = None
    try:
        authority = validate_authorization(retained_read(args.authorization,4*1024*1024,private=True),
                                           args.authorization_sha256,args.publisher)
        retention = Retention(args.retain)
        require(not list(os.listdir(retention.fd)), 'retention-not-empty')
        report = acquisition(args.operation,args.root,authority,retention)
        result = dict(status=report['status'],exit_code=report['exit_code'],
                      maintenance_clearance=False,retained=str(retention.path))
    except (OSError,ValueError,KeyError,TypeError) as error:
        result = dict(status='blocked',exit_code=1,maintenance_clearance=False,error=diagnostic(error,'maintenance'))
        if retention is not None and retention.safe_for_failures:
            try: retention.write('failure.json',json_bytes(result))
            except (OSError,ValueError): pass
    finally:
        if retention is not None:
            try: retention.close()
            except (OSError,ValueError) as error:
                result = dict(status='blocked',exit_code=1,maintenance_clearance=False,
                              cleanup_complete=False,error=diagnostic(error,'retention-close'))
    result.setdefault('cleanup_complete',not bool(_UNRESOLVED_TOOLS))
    if _UNRESOLVED_TOOLS:
        result.update(status='blocked',exit_code=1,owned_helpers_unresolved=[p.pid for p in _UNRESOLVED_TOOLS])
    print(json.dumps(result,sort_keys=True))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
