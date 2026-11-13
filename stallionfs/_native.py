"""Owned native installation and ordinary, observed macOS mount operations.

OS receipts describe commands and namespace observations, not authenticated
adapter sessions or historical writeback receipts. No operation here grants
snapshot, retirement or deletion authority.
"""
from __future__ import annotations

import contextlib
import errno
import json
import os
from pathlib import Path
import plistlib
import platform
import re
import selectors
import signal
import stat
import subprocess
import time
import threading
import uuid

from . import _image, _scan

PROFILES = {
    'production': {'type': 'stallionfs', 'bundle': 'com.alvinhhh.stallionfs.module'},
    'private-sfsro27': {'type': 'sfsro27', 'bundle': 'com.alvinhhh.stallionfs.module'},
}
HOST = Path('/Applications/StallionFS.app/Contents/MacOS/StallionFS')
DEADLINE = 30.0
GRACE = 2.0
OBSERVATION_WINDOW = 5.0
DISCOVERY_BYTES = 1_048_576  # Matches the Host whole-result transport limit.


def failure(message, result):
    from .core import StallionError
    error = StallionError(message)
    error.native_candidate_result = result
    return error


def _persist(path, value):
    from .lifecycle import replace_json
    from .core import sync_directory
    replace_json(path, value)
    sync_directory(path.parent)


def _same(info):
    return [info.st_dev, info.st_ino]



def _consumed(receipt, target, anchor=None):
    return (isinstance(receipt, dict) and receipt.get('core_consumed') is True
            and receipt.get('status') == 0 and receipt.get('parent_close_errno') == 0
            and receipt.get('poisoned') is False and receipt.get('transaction_active') is False
            and [receipt.get('device'), receipt.get('inode')] == target['file']
            and receipt.get('uuid') == target['uuid']
            and (anchor is None or all(receipt.get(k) == v for k, v in anchor.items())))


def guarded(target, callback=None, *, anchor=None, expected_anchor=None):
    """One synchronous guard invocation. A fresh receipt never repairs an old one."""
    tokens = []
    def held(token):
        tokens.append(token)
        token.verify(target)
        if callback is not None:
            return callback(token)
    try:
        if expected_anchor is None:
            _image.with_backing_guard(target, held)
        else:
            _image.with_backing_guard(target, held, expected_anchor)
    except BaseException as error:
        # Extraction is diagnostic only. Allocation failure or an exception
        # subclass refusing attribute access must not replace the primary error.
        try:
            if not tokens:
                carrier = error
                seen = set()
                while carrier is not None and id(carrier) not in seen:
                    seen.add(id(carrier))
                    token = getattr(carrier, 'native_backing_guard', None)
                    if token is not None:
                        tokens.append(token)
                        break
                    carrier = carrier.__context__
            if tokens:
                error.native_current_guard = tokens[0].close_result
        except BaseException:
            pass  # The original exception still owns its native guard carrier.
        raise
    receipt = tokens[0].close_result
    if not _consumed(receipt, target, anchor):
        raise failure('Native backing admission or consumed close is incomplete', {'current_guard': receipt})
    return receipt


@contextlib.contextmanager
def _owned_signals(record):
    """Defer ordinary termination until the direct child handle is retained.

    Python delivers signal handlers only on its main thread. Other calling
    threads leave process-wide handlers untouched; their owned helpers still
    have deadlines and exception cleanup.
    """
    previous = {}
    primary = None
    def receive(number, frame):
        record.setdefault('interruption_signal', number)
        record['signal_count'] = record.get('signal_count', 0) + 1
    def check():
        if 'interruption_signal' in record:
            raise KeyboardInterrupt('Native helper interrupted by signal ' + str(record['interruption_signal']))
    try:
        if threading.current_thread() is threading.main_thread():
            for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                old = signal.getsignal(number)
                if old != signal.SIG_IGN:
                    previous[number] = old
                    signal.signal(number, receive)
        yield check
    except BaseException as error:
        primary = error
        raise
    finally:
        failures = []
        for number, old in previous.items():
            try:
                signal.signal(number, old)
            except BaseException as error:
                failures.append(error)
        if failures:
            record['signal_restore_errors'] = [type(error).__name__ for error in failures]
            if primary is None:
                raise failures[0]
            try:
                primary.add_note('Native helper signal handlers could not all be restored')
            except (AttributeError, MemoryError):
                pass


def execute_owned(argv, record, persist, directory, *, deadline=DEADLINE, cwd=None, env=None, output_limit=None):
    """Own exactly one helper until reaped, including timeout/interruption.

    Streams stay in retained files. Failed stop/reap attempts keep supervising
    under the caller's lease; they never allow a second mutating invocation.
    """
    directory = Path(directory)
    stdout_path, stderr_path = directory / 'stdout', directory / 'stderr'
    record.update(argv=list(argv), outcome='launch-pending', child_pending=True, pid=None,
                  stdout=str(stdout_path), stderr=str(stderr_path), returncode=None, reaped=False)
    persist()
    primary, child, streams = None, None, []
    try:
        with _owned_signals(record) as interrupted:
            try:
                stdout = stdout_path.open('xb'); streams.append(stdout)
                stderr = stderr_path.open('xb'); streams.append(stderr)
                if output_limit is not None:
                    for stream in streams:
                        os.fchmod(stream.fileno(), 0o600)
                interrupted()
                expires = time.monotonic() + deadline
                child = subprocess.Popen(list(argv), stdin=subprocess.DEVNULL,
                                         stdout=subprocess.PIPE if output_limit is not None else stdout,
                                         stderr=subprocess.PIPE if output_limit is not None else stderr,
                                         close_fds=True, cwd=cwd, env=env)
                record.update(pid=child.pid, outcome='running')
                persist()
                interrupted()
                if output_limit is not None:
                    _collect_owned(child, stdout, stderr, record, output_limit, expires, interrupted)
                while child.poll() is None:
                    interrupted()
                    remaining = expires - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(list(argv), deadline)
                    try:
                        child.wait(timeout=min(remaining, 0.2))
                    except subprocess.TimeoutExpired:
                        continue
                child.wait()
                interrupted()
            except BaseException as error:
                primary = error
            if child is not None:
                if primary is not None:
                    record.update(outcome='unknown', interrupted=type(primary).__name__)
                    _stop_and_reap(child, record, persist)
                record.update(returncode=child.returncode, child_pending=False, reaped=True)
            elif primary is not None:
                record.update(outcome='not-launched', child_pending=False, reaped=False)
            if primary is None:
                record['outcome'] = 'success' if child.returncode == 0 else 'error'
            if child is not None and output_limit is not None:
                # Popen owns these pipes even if persistence/interruption stops
                # execution before the collector starts. Attempt both closes.
                for pipe in (child.stdout, child.stderr):
                    try:
                        pipe.close()
                    except BaseException as error:
                        record.setdefault('stream_close_errors', []).append(type(error).__name__)
                        if primary is None:
                            primary = error
            for stream in reversed(streams):
                try:
                    try:
                        if output_limit is not None:
                            stream.flush()
                            os.fsync(stream.fileno())
                    finally:
                        stream.close()
                except BaseException as error:
                    record.setdefault('stream_close_errors', []).append(type(error).__name__)
                    if primary is None:
                        primary = error
            if output_limit is not None:
                record['streams_durable'] = primary is None and record.get('streams_eof') is True
                if primary is not None:
                    record['outcome'] = 'unknown' if child is not None else 'not-launched'
            try:
                interrupted()
            except BaseException as error:
                record['outcome'] = 'unknown' if child is not None else 'not-launched'
                if primary is None:
                    primary = error
            try:
                persist()
            except BaseException as error:
                record['receipt_error'] = type(error).__name__
                if primary is None:
                    primary = error
            if primary is not None:
                raise primary
    except BaseException as error:
        try:
            error.native_os_result = record
        except (AttributeError, MemoryError):
            pass
        raise
    return record


def _collect_owned(child, stdout, stderr, record, limit, expires, interrupted):
    """Drain both pipes with one combined bound, including after direct-child exit."""
    record.update(streams_eof=False, streams_durable=False, output_bytes=0)
    with selectors.DefaultSelector() as selector:
        for pipe, destination in ((child.stdout, stdout), (child.stderr, stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, destination)
        while selector.get_map():
            interrupted()
            if time.monotonic() >= expires:
                raise subprocess.TimeoutExpired(child.args, DEADLINE)
            for key, _ in selector.select(min(0.1, max(0, expires - time.monotonic()))):
                block = os.read(key.fileobj.fileno(), min(65536, limit - record['output_bytes'] + 1))
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                record['output_bytes'] += len(block)
                if record['output_bytes'] > limit:
                    record['collector_error'] = 'output-limit'
                    raise ValueError('Native actor output limit exceeded')
                if key.data.write(block) != len(block):
                    raise OSError(errno.EIO, 'Native actor output short write')
        record['streams_eof'] = True


def _supervision_error(record, error, phase):
    detail = {'type': type(error).__name__, 'errno': getattr(error, 'errno', None), 'phase': phase}
    summary = record.setdefault('stop_errors', {'count': 0, 'first': detail, 'last': detail})
    summary['count'] += 1
    summary['last'] = detail


def _stop_and_reap(child, record, persist):
    terminated = False
    while True:
        try:
            if child.poll() is not None:
                child.wait()
                return
            if not terminated:
                terminated = True
                child.terminate()
            else:
                child.kill()
            child.wait(timeout=GRACE)
        except BaseException as error:
            _supervision_error(record, error, 'stop-reap')
            record['child_pending'] = True
            try:
                persist()
            except BaseException as saving_error:
                _supervision_error(record, saving_error, 'persist-pending')
            # Remain the supervisor under the caller's lease until this exact
            # child is reaped. Another interruption cannot release that hold.
            try:
                time.sleep(0.1)
            except BaseException as waiting_error:
                _supervision_error(record, waiting_error, 'supervise')


@contextlib.contextmanager
def resource_binding(path, target, transport=None):
    """Bind host resource outside the overmounted volume directory."""
    from .core import private_directory
    private_directory(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
    def check():
        parent, named = os.fstat(fd), Path(path).lstat()
        backing = os.stat('image.sfs', dir_fd=fd, follow_symlinks=False)
        if (_same(parent) != target['parent'] or _same(named) != target['parent']
                or not stat.S_ISDIR(named.st_mode) or _same(backing) != target['file']
                or not stat.S_ISREG(backing.st_mode) or backing.st_nlink != 1
                or backing.st_uid != os.getuid()):
            raise failure('Native resource identity changed', {'target': target})
    if transport is None:
        transport = {'target': target}
    primary = None
    try:
        check()
        yield check
        check()
    except BaseException as error:
        primary = error
        try:
            error.native_candidate_result = transport
        except (AttributeError, MemoryError):
            pass
        raise
    finally:
        try:
            os.close(fd)
        except OSError as error:
            transport['resource_close_errno'] = error.errno
            if primary is None:
                error.native_candidate_result = transport
                raise
            try:
                primary.add_note('Native resource descriptor close failed: ' + str(error.errno))
            except (AttributeError, MemoryError):
                pass


def observe(path, profile):
    """Use a NEW mounted-root FD; table source text is informational only."""
    path = Path(path)
    rows = [row for row in _scan.mounts() if row['path'] == str(path)]
    if len(rows) > 1:
        raise failure('Conflicting mount rows at managed target', {'mount_rows': rows})
    if not rows:
        return None
    row = {**rows[0], 'fsid': list(rows[0]['fsid'])}
    if (row['filesystem'] != PROFILES[profile]['type'] or row['owner'] != os.getuid()
            or row['readonly'] or row['ignore_ownership']):
        raise failure('Managed target has a conflicting mount', {'mount_row': row})
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
    primary = None
    try:
        fresh = _scan.mount_for_descriptor(fd)
        fresh['fsid'] = list(fresh['fsid'])
        if any(fresh[key] != row[key] for key in ('path', 'filesystem', 'owner', 'flags', 'fsid')):
            raise failure('Mounted descriptor and mount table disagree', {'mount_row': row, 'descriptor': fresh})
        after = [item for item in _scan.mounts() if item['path'] == str(path)]
        if len(after) == 1:
            after[0]['fsid'] = list(after[0]['fsid'])
        if len(after) != 1 or any(after[0][key] != row[key] for key in ('filesystem', 'owner', 'flags', 'fsid')):
            raise failure('Mount changed during observation', {'before': row, 'after': after})
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            os.close(fd)
        except OSError as closing_error:
            if primary is None:
                raise
            try:
                primary.add_note('Mounted observation descriptor close failed: ' + str(closing_error.errno))
            except (AttributeError, MemoryError):
                pass
    return row


def installed_target(store, path, metadata, *, confirmed=True, _location=None):
    from .core import private_directory, read_json, validate_native_creation_proof, native_target
    from .lifecycle import identity
    path = Path(path)
    if (path.parent not in (store.root / 'workspaces', store.root / 'trash') or path.name != metadata.get('id')
            or metadata.get('backend') != 'native-image' or metadata.get('ownership') != 'store-created'
            or metadata.get('state') not in ('installed', 'installed-unconfirmed')):
        raise failure('Invalid installed native workspace', {'workspace': metadata.get('id')})
    private_directory(path)
    origin = metadata.get('origin')
    if not isinstance(origin, dict):
        raise failure('Missing native creation lineage', {'workspace': path.name})
    created = validate_native_creation_proof(origin, read_json(path / 'native-create.json'))
    target = metadata.get('native_image')
    if (not isinstance(target, dict) or set(target) != {'component', 'parent', 'object', 'file', 'uuid'}
            or target['component'] != 'image.sfs' or target['parent'] != identity(store.root / 'workspaces')
            or target['object'] != identity(path) or target['object'] != created['object']
            or target['file'] != created['file']
            or target['uuid'] != created['uuid'] or metadata.get('transaction') != origin.get('transaction')
            or any(metadata.get(key) != origin.get(key) for key in
                   ('id', 'seed', 'commit', 'branch', 'name', 'created', 'capacity_gib'))):
        raise failure('Installed native lineage or location changed', {'workspace': path.name})
    from ._native_recovery import location
    location(store, path, metadata, override=_location)
    backing = (path / 'image.sfs').lstat()
    if (not stat.S_ISREG(backing.st_mode) or backing.st_nlink != 1 or backing.st_uid != os.getuid()
            or _same(backing) != target['file']):
        raise failure('Installed native backing changed', {'workspace': path.name})
    resolved = {'directory': str(path), 'component': 'image.sfs', 'parent': target['object'],
                'file': target['file'], 'uuid': target['uuid']}
    native_target({'ownership': 'external-reference', 'native_image': resolved})
    if confirmed:
        proof = read_json(path / 'native-install.json')
        if (metadata['state'] != 'installed' or proof.get('operation') != 'native-install'
                or proof.get('id') != path.name or proof.get('transaction') != metadata['transaction']
                or proof.get('target') != target or proof.get('complete') is not True
                or not _consumed(proof.get('guard'), resolved, created['anchor'])):
            raise failure('Native installation needs current first-install recovery', {'workspace': path.name})
    return resolved


def install_candidate(store, response, intent, metadata, profile, host):
    """Continue the producer's store/seed/workspace lock scope into one rename."""
    from .core import owned_native_target, read_json, sync_directory
    from ._native_create_authority import proof
    proof(metadata, read_json(Path(response['candidate']) / 'native-create.json'))
    from .lifecycle import identity
    if profile not in PROFILES:
        raise failure('Unknown native controller profile', response)
    source = Path(response['candidate'])
    final = store.root / 'workspaces' / metadata['id']
    journal = Path(response['journal'])
    old = owned_native_target(source, metadata)
    if os.path.lexists(final):
        raise failure('Native installation destination exists', response)
    (source / 'volume').mkdir(mode=0o700)
    current = {**metadata['native_image'], 'parent': identity(final.parent)}
    current.pop('anchor')
    installed = {**metadata, 'state': 'installed-unconfirmed', 'origin': metadata,
                 'native_image': current, 'installation_proof': 'native-install.json',
                 'controller_profile': profile, 'native_host': str(host or HOST)}
    response.update(installed=False, installation_confirmed=False, workspace=metadata['id'])
    intent['installation'] = {'metadata': installed, 'first_mount_attempted': False,
                              'rename_attempted': False, 'guard': None, 'outcome': 'prepared'}
    _persist(journal, intent)
    _persist(source / 'meta.json', installed)
    tokens = []
    def move(token):
        tokens.append(token)
        token.verify(old)
        intent['installation'].update(rename_attempted=True, outcome='rename-attempted')
        _persist(journal, intent)
        _scan.move(source, final)
        response.update(installed=True, candidate=str(final), metadata=installed)
        destination = dict(old, directory=str(final))
        token.verify(destination)
        sync_directory(final.parent)
        sync_directory(source.parent)
    try:
        _image.with_backing_guard(old, move)
        receipt = tokens[0].close_result
        intent['installation']['guard'] = receipt
        _persist(journal, intent)
        target = dict(old, directory=str(final))
        if not _consumed(receipt, target, metadata['native_image']['anchor']):
            raise failure('Installed image has an unconfirmed initial anchor or close', response)
        _complete_install(store, final, installed, intent, journal, receipt)
        response.update(installed=True, installation_confirmed=True, outcome='installed',
                        candidate=str(final), metadata=read_json(final / 'meta.json'))
        return response
    except BaseException as error:
        if os.path.lexists(final):
            response.update(candidate=str(final), installed=True)
        if tokens:
            try:
                response['installation_guard'] = tokens[0].close_result
            except MemoryError:
                response['installation_receipt_unavailable'] = True
        response['outcome'] = 'installed-unconfirmed' if response['installed'] else 'installation-incomplete'
        try:
            error.native_candidate_result = response
        except (AttributeError, MemoryError):
            pass
        raise


def _complete_install(store, path, metadata, intent, journal, receipt):
    from .core import sync_directory
    from ._native_create_authority import installed
    installed(path, metadata)
    target = installed_target(store, path, metadata, confirmed=False)
    if not _consumed(receipt, target, metadata['origin']['native_image']['anchor']):
        raise failure('First-install anchor differs from verified import', {'current_guard': receipt})
    proof = {'operation': 'native-install', 'id': metadata['id'], 'transaction': metadata['transaction'],
             'target': metadata['native_image'], 'complete': True, 'guard': receipt,
             'previous_installation': intent['installation'], 'first_mount_attempted': False,
             'first_use': {'accepted': False}}
    _persist(path / 'native-install.json', proof)
    installed = {**metadata, 'state': 'installed'}
    _persist(path / 'meta.json', installed)
    store._open(metadata['id'], path, installed, enrolled=False)
    # Installed ownership is independently durable before the intent disappears.
    installed_target(store, path, installed)
    sync_directory(path)
    journal.unlink()
    sync_directory(journal.parent)


def recover_install(store, path, metadata):
    """Fresh guard only: no repeated import or rename, old outcome stays recorded."""
    from .core import read_json
    from ._native_create_authority import installed
    installed(path, metadata)
    journal = store.root / 'journals' / (metadata['id'] + '.json')
    if not journal.exists():
        return installed_target(store, path, metadata)
    intent = read_json(journal)
    if intent.get('operation') != 'native-create':
        return installed_target(store, path, metadata)
    check_pending(metadata['id'], intent)
    installation = intent.get('installation')
    proof = read_json(path / 'native-install.json') if (path / 'native-install.json').exists() else {}
    # read_json retains the validated top-level serialization envelope. The
    # producer's metadata nested in the intent has no such envelope; compare
    # every substantive field with only the allowed installation-state change.
    expected_metadata = dict(metadata, state='installed-unconfirmed')
    expected_metadata.pop('format', None)
    if (proof.get('first_mount_attempted') is True or not isinstance(installation, dict) or installation.get('first_mount_attempted') is not False
            or intent.get('final') != str(path) or intent.get('workspace') != metadata['id']
            or intent.get('transaction') != metadata.get('transaction')
            or intent.get('object') != metadata.get('origin', {}).get('native_image', {}).get('object')
            or installation.get('metadata') != expected_metadata
            or not isinstance(intent.get('candidate'), str) or os.path.lexists(Path(intent['candidate']))):
        raise failure('Native installation lineage or first-mount history is uncertain', {'intent': intent})
    target = installed_target(store, path, metadata, confirmed=False)
    receipt = guarded(target, anchor=metadata['origin']['native_image']['anchor'])
    _complete_install(store, path, metadata, intent, journal, receipt)
    return target


class Operation:
    def __init__(self, store, path, action, target, *, details=None, operation_id=None):
        from .core import read_json, sync_directory
        self.path = Path(path)
        self.journal = store.root / 'journals' / (path.name + '.json')
        previous = read_json(self.journal) if self.journal.exists() else None
        if previous is not None:
            check_pending(path.name, previous)
            if previous.get('target') != target:
                raise failure('Native operation target identity changed', {'intent': previous})
        parent = path / 'native-operations'
        parent.mkdir(mode=0o700, exist_ok=True)
        from .core import private_directory
        private_directory(parent)
        self.directory = parent / (operation_id or uuid.uuid4().hex)
        self.directory.mkdir(mode=0o700)
        self.record = {'operation': action, 'workspace': path.name, 'id': self.directory.name,
                       'target': target, 'outcome': 'prepared', 'child_pending': False,
                       'helpers': [], 'previous_unresolved': self.previous_reference(previous)}
        if details is not None:
            self.record.update(details)
        self.persist()
        sync_directory(parent)

    def previous_reference(self, previous):
        if previous is None:
            return None
        # The prior operation already owns a durable receipt. Do not recursively
        # copy its history into every subsequent recovery attempt.
        return {'operation': previous['operation'], 'id': previous['id'],
                'record': str(self.path / 'native-operations' / previous['id'] / 'record.json'),
                'outcome': previous['outcome']}

    @classmethod
    def resume(cls, store, path, record):
        operation = cls.__new__(cls)
        operation.path = path
        operation.journal = store.root / 'journals' / (path.name + '.json')
        operation.directory = path / 'native-operations' / record['id']
        from .core import private_directory
        private_directory(operation.directory)
        operation.record = record
        return operation

    def persist(self):
        self.record['child_pending'] = any(item.get('child_pending') is True for item in self.record['helpers'])
        from ._native_recovery import COMPOUND
        if self.record.get('operation') in COMPOUND:
            from .core import read_json
            if self.journal.exists():
                current = read_json(self.journal)
                immutable = ('id', 'workspace', 'operation', 'target', 'name', 'recovery_name',
                             'profile', 'host', 'originally_mounted', 'accepted_mount')
                if any(current.get(key) != self.record.get(key) for key in immutable):
                    raise failure('Native operation owner changed; retained unchanged', self.record)
            # The journal is authoritative until finish. Publish child ownership
            # there first, so a stale archival copy cannot authorize continuation.
            _persist(self.journal, self.record)
            _persist(self.directory / 'record.json', self.record)
        else:
            _persist(self.directory / 'record.json', self.record)
            _persist(self.journal, self.record)

    def command(self, label, argv):
        directory = self.directory / f'{len(self.record["helpers"]):02}-{label}'
        directory.mkdir(mode=0o700)
        result = {'label': label, **getattr(self, 'command_context', {})}
        if self.record.get('protocol') == 3:
            result.update(cwd=str(self.directory), environment='native-preflight-empty-environment-v3')
        self.record['helpers'].append(result)
        options = ({'output_limit': 2 * 1024 * 1024, 'env': {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                    'cwd': self.directory} if self.record.get('protocol') in (2, 3) else {})
        return execute_owned(argv, result, self.persist, directory, **options)

    def finish(self):
        from .core import sync_directory, read_json
        if not self.journal.exists() or read_json(self.journal).get('id') != self.record['id']:
            raise failure('Native operation owner changed; completion retained', self.record)
        self.record['outcome'] = 'complete'
        self.persist()
        self.journal.unlink()
        sync_directory(self.journal.parent)


def check_pending(workspace, record):
    """Require affirmative terminal evidence before replacing a native intent."""
    from ._native_recovery import ACTIONS, COMPOUND, validate_intent, pending_message
    if isinstance(record, dict) and record.get('operation') in COMPOUND:
        raise failure(pending_message(record), {'intent': record})
    if isinstance(record, dict) and record.get('operation') in ACTIONS:
        validate_intent(workspace, record)
        return
    def malformed():
        raise failure('Malformed or unresolved native helper intent; retained unchanged', {'intent': record})
    if (not isinstance(record, dict) or record.get('workspace') != workspace
            or not re.fullmatch(r'[0-9a-f]{32}', workspace)
            or record.get('operation') not in ('native-create', 'native-mount', 'native-unmount')):
        malformed()
    if record['operation'] == 'native-create':
        # The producer may persist before controller preflight exists. Only its
        # explicit producer schema permits absence of both helper fields.
        if (not isinstance(record.get('transaction'), str)
                or not re.fullmatch(r'[0-9a-f]{32}', record['transaction'])
                or type(record.get('creation_attempted')) is not bool
                or not isinstance(record.get('native_image'), dict)
                or any(not isinstance(record.get(key), str) for key in ('stage', 'candidate', 'final'))
                or any(not isinstance(record.get(key), list) or len(record[key]) != 2
                       or any(type(part) is not int for part in record[key])
                       for key in ('stage_identity', 'object'))):
            malformed()
        if 'helpers' not in record and 'child_pending' not in record:
            return
    elif (not isinstance(record.get('id'), str) or not re.fullmatch(r'[0-9a-f]{32}', record['id'])
          or record.get('outcome') not in ('prepared', 'incomplete', 'complete')
          or not isinstance(record.get('target'), dict)):
        malformed()
    if type(record.get('child_pending')) is not bool or not isinstance(record.get('helpers'), list):
        malformed()
    if record['child_pending']:
        malformed()
    allowed = {'native-create': {'verify-package', 'discover'},
               'native-mount': {'verify-package', 'discover', 'mount'},
               'native-unmount': {'unmount'}}[record['operation']]
    check_helpers(record, allowed)


def check_helpers(record, allowed):
    """Validate retained terminal receipts; never signal or reap a saved PID."""
    def malformed():
        raise failure('Operation still has unresolved process ownership. Keep its controller running; no continuation was started.',
                      {'intent': record})
    if record.get('child_pending') is not False or not isinstance(record.get('helpers'), list):
        malformed()
    for item in record['helpers']:
        if (not isinstance(item, dict) or not isinstance(item.get('label'), str) or item['label'] not in allowed
                or type(item.get('child_pending')) is not bool or item['child_pending']
                or not {'pid', 'returncode', 'reaped'}.issubset(item)
                or type(item.get('reaped')) is not bool
                or not isinstance(item.get('argv'), list) or not item['argv']
                or any(not isinstance(arg, str) for arg in item['argv'])
                or any(not isinstance(item.get(key), str) for key in ('stdout', 'stderr'))):
            malformed()
        if item.get('outcome') == 'not-launched':
            if item.get('pid') is not None or item.get('returncode') is not None or item['reaped']:
                malformed()
        elif (item.get('outcome') not in ('success', 'error', 'unknown') or not item['reaped']
              or type(item.get('pid')) is not int or item['pid'] <= 0
              or type(item.get('returncode')) is not int
              or (item['outcome'] == 'success' and item['returncode'] != 0)
              or (item['outcome'] == 'error' and item['returncode'] == 0)):
            malformed()
        if record.get('protocol') in (2, 3):
            # Protocol 2 collects bounded pipes. A reaped direct child alone
            # cannot establish completion after collection or receipt failure.
            if any(key in item for key in ('collector_error', 'stream_close_errors', 'receipt_error')):
                malformed()
            if item['outcome'] != 'not-launched' and (
                    item['outcome'] not in ('success', 'error')
                    or item.get('streams_eof') is not True or item.get('streams_durable') is not True
                    or type(item.get('output_bytes')) is not int or not 0 <= item['output_bytes'] <= 2 * 1024 * 1024
                    or 'interrupted' in item or 'stop_errors' in item):
                malformed()


def _bounded_plist(path, record):
    try:
        with Path(path).open('rb') as stream:
            data = stream.read(DISCOVERY_BYTES + 1)
        if len(data) > DISCOVERY_BYTES:
            raise ValueError('package metadata exceeds discovery transport budget')
        value = plistlib.loads(data)
        if not isinstance(value, dict):
            raise ValueError('package metadata is not a dictionary')
        return value
    except (ValueError, plistlib.InvalidFileException) as error:
        raise failure('Invalid native package metadata: ' + str(error), record) from error


def _version(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,2}', value):
        return None
    try:
        pieces = tuple(int(part) for part in value.split('.'))
    except ValueError:
        return None
    return pieces + (0,) * (3 - len(pieces))


def verify_package(operation, host):
    from ._bundle import PUBLISHER_TEAM
    host = Path(host)
    if not host.is_absolute() or host.name != 'StallionFS' or host.parent.name != 'MacOS':
        raise failure('Native discovery host path is invalid', operation.record)
    app = host.parent.parent.parent
    signed = operation.command('verify-package', package_argv(host))
    if signed['returncode'] != 0:
        raise failure('Native package signature verification failed', operation.record)
    return signed


def package_argv(host):
    from ._bundle import PUBLISHER_TEAM
    requirement = ('anchor apple generic and identifier "com.alvinhhh.stallionfs" '
                   'and certificate leaf[subject.OU] = "' + PUBLISHER_TEAM + '"')
    return ['/usr/bin/codesign', '--verify', '--deep', '--strict', '-R', '=' + requirement,
            str(Path(host).parent.parent.parent)]


def qualify(operation, metadata):
    """Validate a signed compiled-profile package and public module discovery.

    This does not attest which module handles a live mount. The extension still
    independently requires both compiled write flags and caller/resource rights.
    """
    from ._bundle import PUBLISHER_TEAM
    profile = metadata['controller_profile']
    if profile not in PROFILES:
        raise failure('Unknown native controller profile', operation.record)
    host = Path(metadata['native_host'])
    if not host.is_absolute() or host.name != 'StallionFS' or host.parent.name != 'MacOS':
        raise failure('Native discovery host path is invalid', operation.record)
    app = host.parent.parent.parent
    module = app / 'Contents/Extensions/StallionFS.appex'
    host_info = _bounded_plist(app / 'Contents/Info.plist', operation.record)
    module_info = _bounded_plist(module / 'Contents/Info.plist', operation.record)
    attributes = module_info.get('EXAppExtensionAttributes')
    factory = module_info.get('StallionFSCompiledFactory')
    if (not isinstance(factory, dict) or factory.get('schema') != 1
            or factory.get('policy') != 'contextual-writes'
            or not isinstance(factory.get('architectures'), list) or not factory['architectures']
            or any(arch not in ('arm64', 'arm64e', 'x86_64') for arch in factory['architectures'])
            or len(set(factory['architectures'])) != len(factory['architectures'])
            or not isinstance(factory.get('pre_sign_sha256'), str)
            or not re.fullmatch(r'[0-9a-f]{64}', factory['pre_sign_sha256'])):
        raise failure('Native package lacks a compiled writable factory declaration', operation.record)
    minimum, running = _version(module_info.get('LSMinimumSystemVersion')), _version(platform.mac_ver()[0])
    if minimum is None or running is None or running < minimum:
        raise failure('Native package minimum macOS version is not satisfied', operation.record)
    if (not isinstance(attributes, dict) or host_info.get('CFBundleIdentifier') != 'com.alvinhhh.stallionfs'
            or host_info.get('StallionFSControllerProtocol') != 1
            or module_info.get('CFBundleIdentifier') != PROFILES[profile]['bundle']
            or attributes.get('FSShortName') != PROFILES[profile]['type']
            or module_info.get('StallionFSAccessPolicy') != 'contextual-writes'):
        raise failure('Install a qualified writable StallionFS package with discovery protocol 1', operation.record)
    verify_package(operation, host)
    discovery = operation.command('discover', [str(host), '--discover-json'])
    if discovery['returncode'] != 0:
        raise failure('Native module discovery failed; inspect its retained error', operation.record)
    try:
        with Path(discovery['stdout']).open('rb') as stream:
            data = stream.read(DISCOVERY_BYTES + 1)
        if len(data) > DISCOVERY_BYTES:
            raise ValueError('discovery output exceeds transport budget')
        inventory = json.loads(data)
    except (ValueError, UnicodeError) as error:
        raise failure('Malformed native discovery result', operation.record) from error
    if (not isinstance(inventory, dict) or inventory.get('ok') is not True
            or inventory.get('protocol') != 1 or not isinstance(inventory.get('modules'), list)):
        raise failure('Native discovery did not return a complete inventory', operation.record)
    if any(not isinstance(row, dict) or type(row.get('enabled')) is not bool
           or not isinstance(row.get('bundle_id'), str) or not isinstance(row.get('url'), str)
           or any(row.get(key) is not None and not isinstance(row[key], str)
                  for key in ('short_name', 'version', 'minimum_os', 'access_policy', 'signing_identifier', 'team_identifier'))
           or type(row.get('signature_status')) is not int
           for row in inventory['modules']):
        raise failure('Native discovery did not return a complete inventory', operation.record)
    rows = inventory['modules']
    matching = [row for row in rows if row.get('bundle_id') == PROFILES[profile]['bundle']
                and row.get('url') == str(module)]
    collisions = [row for row in rows if row.get('enabled') is True and row.get('short_name') == PROFILES[profile]['type']]
    if len(matching) != 1 or matching[0].get('enabled') is not True:
        raise failure('Enable the qualified StallionFS module in File System Extensions settings', operation.record)
    row = matching[0]
    if (len(collisions) != 1 or collisions[0] != row or row.get('signature_status') != 0
            or row.get('signing_identifier') != PROFILES[profile]['bundle']
            or row.get('team_identifier') != PUBLISHER_TEAM
            or row.get('version') != module_info.get('CFBundleVersion')
            or row.get('minimum_os') != module_info.get('LSMinimumSystemVersion')
            or row.get('access_policy') != 'contextual-writes'):
        raise failure('Native module identity, signature, type or writable declaration is not qualified', operation.record)
    operation.record['discovery'] = inventory
    operation.persist()
    return PROFILES[profile]['type']


def _guard_current(target):
    expires = time.monotonic() + OBSERVATION_WINDOW
    while True:
        try:
            return guarded(target)
        except OSError as error:
            if error.errno != errno.EBUSY or time.monotonic() >= expires:
                raise
            time.sleep(0.05)


def _observe_until(volume, profile, present):
    expires = time.monotonic() + OBSERVATION_WINDOW
    while True:
        row = observe(volume, profile)
        if bool(row) == present:
            return row
        if time.monotonic() >= expires:
            raise failure('Native namespace did not reach the requested state', {'observed_mount': row})
        time.sleep(0.05)


def _usable(store, path, metadata, *, initial=False, operation=None):
    repo = path / 'volume/repo'
    info = repo.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise failure('Native repository path is not a real directory', {'workspace': path.name})
    from ._native_create_git import qualified_runtime
    runtime = qualified_runtime(metadata.get('native_host'))
    store._standalone_git(repo, runtime=runtime)
    if initial:
        from ._native_create_git import readiness
        if readiness(repo, metadata) != (metadata['commit'], metadata['branch']):
            raise failure('Initial native repository does not match the prepared branch and commit', operation.record)
        probe = repo / ('.stallionfs-write-' + uuid.uuid4().hex)
        operation.record['write_probe'] = {'path': str(probe), 'complete': False}
        operation.persist()
        fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            data = b'stallionfs writable path\n'
            if os.write(fd, data) != len(data):
                raise OSError(errno.EIO, 'Short mounted write probe')
            os.fsync(fd)
        finally:
            os.close(fd)
        probe.unlink()
        operation.record['write_probe']['complete'] = True
        operation.persist()
    return str(repo)


def _record_failure(error, operation, volume, profile):
    operation.record['outcome'] = 'incomplete'
    current_guard = getattr(error, 'native_current_guard', None)
    if current_guard is not None:
        operation.record['failed_current_guard'] = current_guard
    try:
        operation.record['observed_mount'] = observe(volume, profile)
    except BaseException as observed_error:
        operation.record['observation_error'] = {'type': type(observed_error).__name__, 'message': str(observed_error)}
    try:
        operation.persist()
    except BaseException as saving_error:
        operation.record['receipt_error'] = type(saving_error).__name__
    try:
        error.native_candidate_result = operation.record
    except (AttributeError, MemoryError):
        pass



def _retain_failure(error, operation, volume, profile):
    try:
        _record_failure(error, operation, volume, profile)
    except BaseException as recording_error:
        try:
            error.add_note('Native failure receipt update failed: ' + type(recording_error).__name__)
            error.native_candidate_result = operation.record
        except (AttributeError, MemoryError):
            pass


def mount_locked(store, path, metadata):
    from .core import private_directory, read_json
    target = recover_install(store, path, metadata)
    metadata = read_json(path / 'meta.json')
    profile = metadata['controller_profile']
    volume = path / 'volume'
    from ._native_recovery import CATALOG, catalog_locked
    journal = store.root / 'journals' / (path.name + '.json')
    if journal.exists() and read_json(journal).get('operation') in CATALOG:
        catalog_locked(store, path, metadata, 'snapshots')
    state_path = path / 'native-mount.json'
    proof = read_json(path / 'native-install.json')
    first_use = proof.get('first_use')
    if not isinstance(first_use, dict) or type(first_use.get('accepted')) is not bool:
        raise failure('Native initial acceptance record is malformed', {'workspace': path.name})
    if first_use['accepted']:
        probe = first_use.get('write_probe')
        if (proof.get('first_mount_attempted') is not True
                or not isinstance(first_use.get('operation'), str)
                or not re.fullmatch(r'[0-9a-f]{32}', first_use['operation'])
                or not isinstance(probe, dict) or probe.get('complete') is not True
                or not isinstance(probe.get('path'), str)
                or Path(probe['path']).parent != volume / 'repo'
                or not re.fullmatch(r'\.stallionfs-write-[0-9a-f]{32}', Path(probe['path']).name)):
            raise failure('Native initial acceptance evidence is incomplete', {'workspace': path.name})
    initial = not first_use['accepted']
    transport = {'workspace': path.name, 'target': target}
    with resource_binding(path, target, transport) as check:
        row = observe(volume, profile)
        if row is not None:
            if (store.root / 'journals' / (path.name + '.json')).exists():
                raise failure('Native mount completion is unresolved; explicitly unmount before retrying',
                              {'workspace': path.name, 'observed_mount': row, 'observed_usable': (volume / 'repo').is_dir()})
            state = read_json(state_path) if state_path.exists() else {}
            if (initial or state.get('state') != 'mounted' or state.get('target') != target
                    or not isinstance(state.get('observation'), dict)
                    or any(state['observation'].get(key) != row[key] for key in ('path', 'filesystem', 'owner', 'flags', 'fsid'))):
                raise failure('Expected native mount is present with unresolved completion; explicitly unmount before retrying',
                              {'workspace': path.name, 'observed_mount': row, 'observed_usable': (volume / 'repo').is_dir()})
            return {**metadata, 'path': _usable(store, path, metadata), 'mount': row}
        private_directory(volume)
        operation = Operation(store, path, 'native-mount', target)
        transport['native_operation'] = operation.record
        try:
            operation.record['current_guard'] = _guard_current(target)
            operation.persist()
            filesystem = qualify(operation, metadata)
            if observe(volume, profile) is not None:
                raise failure('Native target became mounted before launch', operation.record)
            proof = read_json(path / 'native-install.json')
            proof['first_mount_attempted'] = True
            _persist(path / 'native-install.json', proof)
            operation.record['mount_attempted'] = True
            operation.persist()
            command = operation.command('mount', ['/sbin/mount', '-F', '-t', filesystem, str(path), str(volume)])
            if command['returncode'] != 0:
                raise failure('Native mount command failed; installed workspace retained', operation.record)
            row = _observe_until(volume, profile, True)
            check()
            repo = _usable(store, path, metadata, initial=initial, operation=operation)
            if initial:
                proof['first_use'] = {'accepted': True, 'operation': operation.record['id'],
                                      'write_probe': operation.record['write_probe']}
                _persist(path / 'native-install.json', proof)
            transport['path'] = repo
            state = {'state': 'mounted', 'target': target, 'profile': profile, 'observation': row, 'operation': operation.record['id']}
            _persist(state_path, state)
            operation.record['observed_mount'] = row
            operation.finish()
            return {**metadata, 'path': repo, 'mount': row, 'native_operation': operation.record}
        except BaseException as error:
            _retain_failure(error, operation, volume, profile)
            raise


def unmount_locked(store, path, metadata):
    target = recover_install(store, path, metadata)
    from .core import read_json
    metadata = read_json(path / 'meta.json')
    profile, volume = metadata['controller_profile'], path / 'volume'
    transport = {'workspace': path.name, 'target': target}
    with resource_binding(path, target, transport) as check:
        # observe closes its mounted descriptor before umount is launched.
        row = observe(volume, profile)
        operation = Operation(store, path, 'native-unmount', target)
        transport['native_operation'] = operation.record
        try:
            operation.record['before_mount'] = row
            if row is not None:
                command = operation.command('unmount', ['/sbin/umount', str(volume)])
                if command['returncode'] != 0:
                    raise failure('Native unmount command failed; current state retained', operation.record)
                _observe_until(volume, profile, False)
            else:
                operation.record['already_absent'] = True
            check()
            receipt = _guard_current(target)
            operation.record['current_guard'] = receipt
            operation.record['observed_mount'] = None
            _persist(path / 'native-mount.json', {'state': 'absent', 'target': target,
                'operation': operation.record['id'], 'current_guard': receipt})
            store._open(path.name, path, metadata)
            operation.finish()
            return {'unmounted': path.name, 'already_absent': row is None, 'native_operation': operation.record}
        except BaseException as error:
            _retain_failure(error, operation, volume, profile)
            raise


def preflight_create(store, response, intent, stage, journal, profile, host, *, discover=True):
    """Read-only qualification under the producer's already-held creation lease."""
    if profile not in PROFILES:
        raise failure('Unknown native controller profile', response)
    operation = Operation.__new__(Operation)
    operation.path = stage / 'owned'
    operation.directory = stage / 'discovery'
    operation.directory.mkdir(mode=0o700)
    operation.journal = journal
    operation.record = intent
    operation.record['helpers'] = []
    operation.record['child_pending'] = False
    response['controller_preflight'] = intent
    # Publish this transition before qualification can inspect or launch helpers.
    operation.persist()
    if discover:
        qualify(operation, {'controller_profile': profile, 'native_host': str(host or HOST)})
    else:
        verify_package(operation, host or HOST)
