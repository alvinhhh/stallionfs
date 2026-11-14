"""Bounded image-test observations around explicitly selected native operations."""
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import plistlib
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from unittest.mock import patch

ATTEMPTS, SECONDS, CAPTURE_BYTES, EVENTS, FILE_BYTES = 4, 12, 128 * 1024, 32, 64 * 1024
BEFORE_CAPTURE_BYTES, BEFORE_EVENTS, BEFORE_FILE_BYTES = 32 * 1024, 5, 16 * 1024
EJECT_CAPTURE_BYTES, EJECT_RETAINED_BYTES = 16 * 1024, 2048
DA_SUBSYSTEM = 'com.apple.DiskArbitration.diskarbitrationd'
REPORT = "image-failures.jsonl"
_metadata = {'operation_id', 'phase', 'timestamp_ns'}
_fields = {
    'failure': {'operation', 'error', 'message', 'expected_busy', 'observation', 'stage', 'workspace', 'failed_device', 'expected_mountpoint'},
    'unavailable': {'reason'},
    'mapping': {'image', 'devices', 'mountpoint', 'volume_device', 'expected_mountpoint', 'mountpoint_matches', 'backing_device', 'backing_inode', 'backing_identity_matches_first'},
    'lsof': {'returncode', 'stdout', 'stderr', 'timeout', 'truncated', 'reaped', 'capture_error', 'cleanup_error', 'display_truncated', 'backing_identity_status', 'backing_device_after', 'backing_inode_after'},
    'eject_log': {'target', 'window_start_ns', 'window_end_ns', 'query_status', 'records',
                  'returncode', 'timeout', 'truncated', 'reaped', 'capture_error', 'cleanup_error', 'reason'},
}
_fields['observation'] = _fields['failure']
_fields['validation'] = {'read', 'sample_timestamp_ns', 'sample_status', 'reason',
                         'selected_device', 'volume_device', 'mountpoint_state', 'entities'}
_fields['eject_outcome'] = {'commands', 'first_status', 'continuation_status', 'outcome'}
_scope = ContextVar("image_failure_scope", default=None)
_detach_observation = ContextVar("image_detach_observation", default=None)
_detach_call = ContextVar("image_detach_call", default=None)
_validation_read = ContextVar("image_validation_read", default=None)
_create_scope = ContextVar("image_create_observation", default=None)
_create_patch_lock = threading.Lock()
_active_create = None
_device = re.compile(r"/dev/disk[0-9]+(?:s[0-9]+)*\Z")
_hints = {'', 'GUID_partition_scheme', 'Apple_partition_scheme', 'FDisk_partition_scheme',
          'Apple_APFS', 'Apple_APFS_ISC', 'Apple_APFS_Recovery', 'Apple_HFS', 'Apple_Boot',
          'Apple_Free', 'EFI', '[unrecognized]'}


def _entities(entries):
    """Project a bounded inventory without retaining free-form native fields."""
    if not isinstance(entries, list) or not 0 < len(entries) <= 32:
        raise ValueError('invalid entity count')
    result, size = [], 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('invalid entity')
        device = entry.get('dev-entry')
        if not isinstance(device, str) or len(device) > 64 or not _device.fullmatch(device):
            raise ValueError('invalid entity device')
        hints = []
        for name in ('content-hint', 'unmapped-content-hint'):
            value = entry.get(name)
            if value is not None and not isinstance(value, str):
                raise ValueError('invalid entity hint')
            hints.append(value if value is None or len(value) <= 64 and value in _hints else '[unrecognized]')
        mountable = entry.get('potentially-mountable')
        if mountable is not None and type(mountable) is not bool:
            raise ValueError('invalid entity flag')
        size += 160 + len(device) + sum(len(value or '') for value in hints)
        if size > 4096:
            raise ValueError('entity projection limit')
        result.append(dict(device=device, content_hint=hints[0], unmapped_content_hint=hints[1],
                           potentially_mountable=mountable))
    return result


def _finish_eject(observation, error):
    if not observation or observation.get('finalized'):
        return
    reporter, status = observation.get('diagnostics'), observation.get('command_status')
    if (reporter is None or reporter.closed or observation.get('command_error') is not error or
            type(status) is not int or status == 0 or
            (observation.get('scope') or {}).get('expected', False)):
        return
    observation['finalized'] = True
    if reporter.eject_failure_claimed:
        return
    reporter.eject_failure_claimed = True
    try:
        reporter.eject_log(observation)
    except BaseException as unavailable:
        try:
            error.add_note('Eject log unavailable: ' + type(unavailable).__name__)
        except BaseException:
            pass


@contextmanager
def observe_seed_create(base):
    """Select only the initial seed creation in the snapshot/rollback fixture."""
    previous = _create_scope.get()
    if previous is not None:
        previous['disabled'] = True
        active = _active_create
        if active is not None:
            active.disarm()
        yield
        return
    token = _create_scope.set(dict(base=Path(base), used=False, disabled=False))
    try:
        yield
    finally:
        _create_scope.reset(token)


class CreateObservation:
    """Status only; the ordinary communicate remains the pipe reader and waiter."""
    def __init__(self, argv):
        self.argv, self.owner = argv, threading.get_ident()
        self.child = self.thread = None
        self.ready, self.done, self.disarmed = (threading.Event() for _ in range(3))
        self.query_stopped = threading.Event()
        self.gate = threading.Lock()
        self.in_flight = False
        self.query_uncertain = self.shutdown_uncertain = False
        self.outcome = 'pending'
        self.start = None
        self.records = self.bytes = 0
        self.write_unavailable = False

    def constructor_entry(self, child, args, kwargs):
        argv = args[0] if args else kwargs.get('args')
        if (self.child is None and threading.get_ident() == self.owner and
                isinstance(argv, (list, tuple)) and tuple(argv) == self.argv):
            self.child = child
        else:
            # Before the foreign constructor can spawn or reap anything.
            self.disarm()

    def disarm(self):
        self.disarmed.set()
        self.stop_queries()

    def launch(self):
        try:
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()
        except Exception:
            self.shutdown_uncertain = True
            self.thread = None

    def communicating(self, child):
        if child is self.child:
            self.start = time.monotonic()
            self.ready.set()

    def stop_queries(self):
        # Never wait for a query/property/log write to finish before stopping.
        self.query_stopped.set()
        if self.gate.acquire(blocking=False):
            try:
                if self.in_flight:
                    self.query_uncertain = True
            finally:
                self.gate.release()
        else:
            self.query_uncertain = True

    def close(self):
        self.stop_queries()
        self.done.set()
        self.ready.set()
        if self.thread is not None:
            try:
                self.thread.join(0.05)
                self.shutdown_uncertain |= self.thread.is_alive()
            except Exception:
                self.shutdown_uncertain = True

    def _emit(self, phase, **values):
        # Called only by the daemon. No TextIO lock, flush, retry or fd mutation.
        if self.write_unavailable or self.records >= 4:
            return
        data = (json.dumps(dict(kind='create_status', phase=phase, **values),
                           sort_keys=True) + '\n').encode('ascii')
        if len(data) > 1024 or self.bytes + len(data) > 4096:
            self.write_unavailable = True
            return
        self.records += 1
        self.bytes += len(data)
        try:
            self.write_unavailable = os.write(2, data) != len(data)
        except Exception:
            self.write_unavailable = True

    def _sample(self):
        unknown = dict(state='unknown', byte_counts='unobserved', eof='unobserved',
                       api='unobserved', returncode_before=None, returncode_after=None)
        child = self.child
        try:
            before = child.returncode
            unknown['returncode_before'] = before
            closed = dict(stdout_closed=child.stdout.closed, stderr_closed=child.stderr.closed)
            if before is not None:
                return unknown | closed
            required = ('waitid', 'P_PID', 'WEXITED', 'WNOHANG', 'WNOWAIT')
            if not all(hasattr(os, name) for name in required):
                return unknown | closed | dict(api='unavailable', reason='api_unavailable')
            unknown['api'] = 'available'
            pid = child.pid
            # Properties above may block: recheck at the final query admission.
            with self.gate:
                if self.query_stopped.is_set() or self.disarmed.is_set():
                    return unknown | closed | dict(reason='stopped_or_disarmed')
                self.in_flight = True
            try:
                status = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            finally:
                with self.gate:
                    if self.query_stopped.is_set() or self.disarmed.is_set():
                        self.query_uncertain = True
                    self.in_flight = False
            after = child.returncode
            unknown['returncode_after'] = after
            if self.query_stopped.is_set() or self.disarmed.is_set() or after is not None:
                return unknown | closed | dict(reason='completion_or_disarm_race')
            if status is None:
                return unknown | closed | dict(state='no_exit_observed')
            if status.si_pid != pid:
                return unknown | closed | dict(reason='identity_mismatch')
            codes = {getattr(os, 'CLD_EXITED', None): 'exit',
                     getattr(os, 'CLD_KILLED', None): 'signal',
                     getattr(os, 'CLD_DUMPED', None): 'signal_core'}
            category = codes.get(status.si_code)
            if category is None:
                return unknown | closed | dict(reason='unknown_status_code')
            return unknown | closed | dict(state='exited_status_observed', category=category,
                                          status=status.si_status)
        except Exception:
            return unknown | dict(reason='observation_unavailable')

    def _run(self):
        try:
            self._emit('start', elapsed_seconds=0)
            self.ready.wait()
            if not self.done.is_set():
                for checkpoint in (60, 120):
                    if self.done.wait(max(0, self.start + checkpoint - time.monotonic())):
                        break
                    sample = self._sample()
                    if self.done.is_set():
                        break
                    self._emit(str(checkpoint), elapsed_seconds=max(0, time.monotonic() - self.start), **sample)
            self.done.wait()
            self._emit('finish', outcome=self.outcome, query_uncertain=self.query_uncertain,
                       disarmed=self.disarmed.is_set(), elapsed_seconds=None if self.start is None
                       else max(0, time.monotonic() - self.start))
        except Exception:
            self.write_unavailable = True


def _observed_create(original, args):
    global _active_create
    scope = _create_scope.get()
    if scope is None or scope['used'] or scope['disabled']:
        return original(*args, '-verbose')
    scope['used'] = True
    try:
        base, image = scope['base'], Path(args[-1])
        _private(base, True)
        _private(image.parent, True)
        if (base.resolve() != base or image.resolve() != image or
                image.parent.parent != base / 'store' / 'staging' or
                not image.parent.name.startswith('build-') or image.name != 'workspace.sparseimage'):
            raise ValueError('unbound creation')
    except Exception:
        return original(*args, '-verbose')
    if not _create_patch_lock.acquire(blocking=False):
        active = _active_create
        if active is not None:
            active.disarm()
        return original(*args, '-verbose')
    try:
        saved = subprocess.Popen
        try:
            observation = CreateObservation(tuple(str(arg) for arg in (*args, '-verbose')))

            class ObservedPopen(saved):
                def __init__(self, *argv, **kwargs):
                    try:
                        observation.constructor_entry(self, argv, kwargs)
                    except Exception:
                        observation.disarm()
                    super().__init__(*argv, **kwargs)

                def communicate(self, *argv, **kwargs):
                    selected = self is observation.child
                    if selected:
                        try:
                            observation.communicating(self)
                        except Exception:
                            observation.disarm()
                    try:
                        return super().communicate(*argv, **kwargs)
                    finally:
                        if selected:
                            try:
                                observation.stop_queries()
                            except Exception:
                                observation.query_uncertain = True

            patcher = patch.object(subprocess, 'Popen', ObservedPopen)
            patcher.__enter__()
        except Exception:
            # Setup failure must not prevent or repeat the requested command.
            subprocess.Popen = saved
            return original(*args, '-verbose')
        _active_create = observation
        try:
            try:
                observation.launch()
            except Exception:
                observation.shutdown_uncertain = True
            try:
                result = original(*args, '-verbose')
                observation.outcome = 'returned'
                return result
            except BaseException:
                observation.outcome = 'raised'
                raise
            finally:
                try:
                    observation.close()
                except Exception:
                    observation.shutdown_uncertain = True
                    observation.query_uncertain = True
                    observation.query_stopped.set()
                    observation.done.set()
                    observation.ready.set()
        finally:
            try:
                patcher.__exit__(None, None, None)
            except Exception:
                subprocess.Popen = saved
    finally:
        _active_create = None
        _create_patch_lock.release()


@contextmanager
def failure_scope(base, image=None, *, workspace=None, mountpoint=None, stage='body', expected=False):
    token = _scope.set(dict(base=Path(base), image=Path(image) if image else None,
                           workspace=workspace, mountpoint=Path(mountpoint) if mountpoint else None,
                           stage=stage, expected=expected))
    try:
        yield
    finally:
        _scope.reset(token)


def detach_observation_selection():
    value = os.environ.get('STALLIONFS_TEST_SNAPSHOT_OBSERVATION', 'initial-unmount')
    if value not in ('initial-unmount', 'closed-snapshot', 'enospc-initial-detach',
                     'enospc-sibling-detach', 'restored-cleanup'):
        raise ValueError('Invalid detach observation selection')
    return value


@contextmanager
def observe_detach():
    """Observe before validation of the first detach in this test operation."""
    observation = dict(started=False, operation_id=None, pre_observation='unavailable')
    token = _detach_observation.set(observation)
    try:
        yield
    except Exception as error:
        _finish_eject(observation, error)
        raise
    finally:
        _detach_observation.reset(token)


def _private(path, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("diagnostic path is not private and owned")
    if not directory and info.st_nlink != 1:
        raise ValueError("diagnostic file has multiple links")
    return info


def artifact_available(directory):
    """Validate only the fixed artifact; never enumerate or authorize deletion."""
    directory = Path(directory)
    try:
        if not directory.is_absolute() or directory.resolve() != directory:
            return False
        _private(directory, True)
        path = directory / REPORT
        if _private(path).st_size > FILE_BYTES:
            return False
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            data = stream.read(FILE_BYTES + 1)
        if not data or len(data) > FILE_BYTES or not data.endswith(b'\n'):
            return False
        lines = data.splitlines()
        if len(lines) > EVENTS:
            return False
        for line in lines:
            value = json.loads(line)
            if not isinstance(value, dict) or value.get('kind') not in _fields:
                return False
            required = _fields[value['kind']] | _metadata
            optional = {'pre_observation'} if value['kind'] in ('observation', 'failure') else set()
            if not required <= set(value) - {'kind'} <= required | optional:
                return False
            if ('pre_observation' in value and
                    value['pre_observation'] not in ('attempted', 'unavailable', 'not-selected')):
                return False
            if (type(value['operation_id']) is not int or value['operation_id'] < 0 or
                    value['phase'] not in ('before', 'after', 'standalone') or
                    type(value['timestamp_ns']) is not int or value['timestamp_ns'] <= 0):
                return False
            for name in ('backing_device', 'backing_inode', 'backing_device_after', 'backing_inode_after'):
                if name in value and (value[name] is None and value['kind'] == 'mapping' or
                        value[name] is not None and (type(value[name]) is not int or value[name] < 0)):
                    return False
            if (value['kind'] == 'mapping' and value['backing_identity_matches_first'] is not None and
                    type(value['backing_identity_matches_first']) is not bool):
                return False
            if value['kind'] == 'validation':
                if (value['phase'] != 'after' or value['read'] not in ('current', 'confirmed') or
                        type(value['sample_timestamp_ns']) is not int or value['sample_timestamp_ns'] <= 0 or
                        value['sample_status'] not in ('validated', 'unavailable') or
                        value['mountpoint_state'] not in (None, 'expected', 'unmounted', 'other') or
                        value['reason'] not in (None, 'normal_inventory_unavailable', 'normal_validation_failed',
                                                'invalid_validation_metadata')):
                    return False
                for name in ('selected_device', 'volume_device'):
                    item = value[name]
                    if item is not None and (not isinstance(item, str) or len(item) > 64 or not _device.fullmatch(item)):
                        return False
                entities = value['entities']
                if not isinstance(entities, list) or len(entities) > 32:
                    return False
                for entry in entities:
                    if not isinstance(entry, dict) or set(entry) != {'device', 'content_hint', 'unmapped_content_hint', 'potentially_mountable'}:
                        return False
                    if (not isinstance(entry['device'], str) or len(entry['device']) > 64 or not _device.fullmatch(entry['device']) or
                            any(entry[name] is not None and entry[name] not in _hints for name in ('content_hint', 'unmapped_content_hint')) or
                            entry['potentially_mountable'] is not None and type(entry['potentially_mountable']) is not bool):
                        return False
                if value['sample_status'] == 'validated' and (not entities or value['reason'] is not None):
                    return False
                if value['sample_status'] == 'unavailable' and (entities or value['reason'] is None or
                        any(value[name] is not None for name in ('selected_device', 'volume_device', 'mountpoint_state'))):
                    return False
            if value['kind'] == 'eject_outcome':
                if (value['phase'] != 'after' or type(value['commands']) is not int or
                        value['commands'] not in (1, 2) or
                        value['outcome'] not in ('recovered', 'failed', 'interrupted', 'refused') or
                        any(value[name] is not None and type(value[name]) is not int
                            for name in ('first_status', 'continuation_status'))):
                    return False
            if value['kind'] == 'lsof' and value['backing_identity_status'] not in (
                    'matched', 'mismatch', 'changed', 'unavailable', 'not_queried'):
                return False
            if value['kind'] == 'eject_log':
                target, records = value['target'], value['records']
                if (value['query_status'] not in ('matched', 'empty', 'unavailable', 'incomplete') or
                        not isinstance(records, str) or len(records.encode()) > EJECT_RETAINED_BYTES or
                        (target is not None and (not isinstance(target, str) or not re.fullmatch(r'/dev/disk[0-9]+', target))) or
                        any(value[name] is not None and (type(value[name]) is not int or value[name] <= 0)
                            for name in ('window_start_ns', 'window_end_ns')) or
                        any(type(value[name]) is not bool for name in ('timeout', 'truncated', 'reaped')) or
                        (value['query_status'] == 'matched' and not records) or
                        (value['query_status'] in ('empty', 'unavailable') and records)):
                    return False
                for record in records.splitlines(keepends=True):
                    if target is None or not re.fullmatch(
                            r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}\+00:00 '
                            r'(?:native_eject_failed|approval_dissent) ' + re.escape(target) + r' 0x[0-9A-Fa-f]{8}\n', record):
                        return False
            if len(line) > 8192:
                return False
            for name, item in value.items():
                if name == 'entities' and value['kind'] == 'validation':
                    continue
                if name == 'devices':
                    if not isinstance(item, list) or len(item) > 32 or not all(isinstance(d, str) and _device.fullmatch(d) for d in item):
                        return False
                elif not (item is None or isinstance(item, (str, bool, int))):
                    return False
        return True
    except (OSError, ValueError, TypeError):
        return False


def _message(value):
    # Native error/warning lines can mention unrelated mounts. Do not upload them.
    lines = str(value)[:2048].splitlines()
    return "\n".join("[path-bearing diagnostic omitted]" if "/" in s else s for s in lines)


def _eject_records(raw, target, start_ns, end_ns):
    """Retain only documented daemon stage/status formats, never raw log text."""
    records, reason, limited = [], None, False
    try:
        lines = raw.decode('utf-8').splitlines()
    except UnicodeDecodeError:
        return '', 'malformed_output', False
    for line in lines:
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError('not a record')
            if 'finished' in value:
                continue
            if (value.get('subsystem') != DA_SUBSYSTEM or
                    Path(value.get('processImagePath', '')).name != 'diskarbitrationd'):
                continue
            if not isinstance(value['timestamp'], str):
                raise ValueError('timestamp is not text')
            stamp = datetime.fromisoformat(value['timestamp'].replace('Z', '+00:00'))
            if stamp.tzinfo is None:
                raise ValueError('timestamp has no zone')
            stamp = stamp.astimezone(timezone.utc)
            delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
            event_ns = (delta.days * 86400 + delta.seconds) * 10**9 + delta.microseconds * 1000
            if not start_ns <= event_ns <= end_ns:
                continue
            message = value['eventMessage']
            if not isinstance(message, str):
                raise ValueError('message is not text')
            if '<private>' in message:
                reason = 'redacted_records'
                continue
            native = re.fullmatch(r'unable to eject (/dev/disk[0-9]+) \(status code (0x[0-9A-Fa-f]{8})\)\.', message)
            approval = re.fullmatch(r'\s*dispatched response, id = [0-9A-Fa-f]{16}:[0-9A-Fa-f]{16}, '
                r'kind = ([A-Za-z0-9_ ]{1,64}), disk = (/dev/disk[0-9]+), dissented, status = (0x[0-9A-Fa-f]{8})\.', message)
            if native and native[1] == target:
                stage, code = 'native_eject_failed', native[2]
            elif (approval and approval[2] == target and
                    all(word in approval[1].lower() for word in ('eject', 'approval'))):
                stage, code = 'approval_dissent', approval[3]
            else:
                continue
            record = f'{stamp.isoformat(timespec="microseconds")} {stage} {target} {code}\n'
            if len((''.join(records) + record).encode()) > EJECT_RETAINED_BYTES:
                limited = True
                break
            records.append(record)
        except (KeyError, TypeError, ValueError):
            reason = 'malformed_records'
    return ''.join(records), reason, limited


class Diagnostics:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.remaining = CAPTURE_BYTES
        self.events = self.written = self.attempts = 0
        self.lock = threading.Lock()
        self.fd = None
        self.capture_disabled = False
        self.operations = self.before_attempts = 0
        self.operation_id, self.phase = 0, 'standalone'
        self.before_events = self.before_written = 0
        self.backing_identities = {}
        self.eject_contexts = {}
        self.eject_log_attempted = False
        self.eject_failure_claimed = False
        self.patches = []
        self.closed = False

    def close(self):
        self.closed = True
        for target, name, original, wrapper in reversed(self.patches):
            if getattr(target, name, None) is wrapper:
                previous = getattr(original, '__dict__', {}).get('_image_diagnostics')
                while previous is not None and previous[0].closed:
                    original = previous[1]
                    previous = getattr(original, '__dict__', {}).get('_image_diagnostics')
                setattr(target, name, original)
        self.patches.clear()
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)

    def validation(self, invocation):
        """Flush only the failed call's cached normal reads, after public unwind."""
        scope = invocation['scope']
        if self.closed or not scope or scope['expected']:
            return
        deadline = invocation.get('deadline', time.monotonic() + SECONDS)
        if not self.lock.acquire(timeout=max(0, deadline - time.monotonic())):
            return
        try:
            operation_id = invocation.get('operation_id')
            if operation_id is None:
                if self.attempts >= ATTEMPTS:
                    return
                self.attempts += 1
                self.operations += 1
                operation_id = self.operations
            self.operation_id, self.phase = operation_id, 'after'
            for sample in invocation['samples']:
                self._emit(deadline, 'validation', **sample)
            if invocation.get('command_error') is not None and invocation.get('outcome') is not None:
                statuses = invocation.get('command_statuses', [])
                self._emit(deadline, 'eject_outcome', commands=invocation['command_count'],
                           first_status=invocation.get('command_status'),
                           continuation_status=statuses[1] if len(statuses) == 2 else None,
                           outcome=invocation['outcome'])
        finally:
            self.operation_id, self.phase = 0, 'standalone'
            self.lock.release()

    def _emit(self, deadline, kind, **values):
        metadata = dict(operation_id=self.operation_id, phase=self.phase, timestamp_ns=time.time_ns())
        data = (json.dumps(dict(kind=kind, **metadata, **values), ensure_ascii=True) + "\n").encode()
        if len(data) > 8192:
            data = (json.dumps(dict(kind='unavailable', **metadata,
                reason='diagnostic event exceeds serialization cap')) + "\n").encode()
        if self.phase == 'before' and (self.events - self.before_events >= BEFORE_EVENTS or
                self.written - self.before_written + len(data) > BEFORE_FILE_BYTES):
            return
        if self.events >= EVENTS or self.written + len(data) > FILE_BYTES:
            return
        if self.fd is None:
            if not self.directory.is_absolute() or self.directory.parent.resolve() != self.directory.parent:
                raise ValueError("noncanonical diagnostic directory")
            self.directory.mkdir(mode=0o700)  # Refuse adoption or symlink replacement.
            self.fd = os.open(self.directory / REPORT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.events += 1
        view = memoryview(data)
        while view:
            if time.monotonic() >= deadline:
                raise TimeoutError("diagnostic write deadline")
            count = os.write(self.fd, view)
            if not 0 < count <= len(view):
                raise OSError("short diagnostic write")
            self.written += count
            view = view[count:]

    def _capture(self, argv, deadline):
        """One bounded pipe reader; the caller's deadline includes kill/reap."""
        if self.capture_disabled or self.remaining <= 0 or time.monotonic() >= deadline - 1:
            raise TimeoutError("diagnostic collection budget exhausted")
        selector = selectors.DefaultSelector()
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, bufsize=0, start_new_session=True, umask=0o077)
        except BaseException:
            selector.close()
            raise
        output = [bytearray(), bytearray()]
        timed_out = truncated = False
        reaped = False
        capture_error = cleanup_error = None
        terminated = True
        try:
            for index, pipe in enumerate((proc.stdout, proc.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, index)
            while selector.get_map():
                left = deadline - 1 - time.monotonic()
                if left <= 0 or self.remaining <= 0:
                    timed_out, truncated = left <= 0, self.remaining <= 0
                    break
                for key, _ in selector.select(min(left, 0.1)):
                    if self.remaining <= 0:
                        break
                    try:
                        chunk = os.read(key.fileobj.fileno(), min(4096, self.remaining))
                    except BlockingIOError:
                        continue
                    if chunk:
                        output[key.data].extend(chunk)
                        self.remaining -= len(chunk)
                    else:
                        selector.unregister(key.fileobj)
            if not selector.get_map():
                try:
                    proc.wait(timeout=max(0, deadline - 1 - time.monotonic()))
                except subprocess.TimeoutExpired:
                    timed_out = True
        except Exception as error:
            capture_error = type(error).__name__
        finally:
            # A descendant can retain a pipe after the leader exits. Kill only
            # this new diagnostic process group, never the observed image service.
            try:
                try:
                    if selector.get_map() or proc.poll() is None:
                        terminated = False
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                            terminated = True
                        except ProcessLookupError:
                            terminated = True
                except Exception as error:
                    cleanup_error = 'group termination: ' + type(error).__name__
                finally:
                    try:
                        proc.wait(timeout=max(0, deadline - time.monotonic()))
                        reaped = True
                    except Exception as error:
                        cleanup_error = cleanup_error or 'leader reap: ' + type(error).__name__
            finally:
                # This also runs when cleanup itself raises or is interrupted.
                if cleanup_error or not terminated or not reaped:
                    self.capture_disabled = True
                    self.remaining = 0
                selector.close()
                proc.stdout.close()
                proc.stderr.close()
        return dict(returncode=proc.returncode, stdout=bytes(output[0]), stderr=bytes(output[1]),
                    timeout=timed_out, truncated=truncated, reaped=reaped, capture_error=capture_error, cleanup_error=cleanup_error)

    @staticmethod
    def _complete(value):
        return (value["returncode"] == 0 and value["reaped"] and not value["timeout"] and
                not value["truncated"] and not value.get("capture_error") and not value.get("cleanup_error"))

    def _mapping(self, args, scope, deadline):
        base, expected_image = scope['base'], scope['image']
        if not base.is_absolute() or base.resolve() != base:
            raise ValueError("unknown fixture scope")
        _private(base, True)
        creating = args[1] == "create"
        selecting = not creating and args[2] is None
        target = str(args[-1] if creating else args[2])
        if not creating and not selecting and not _device.fullmatch(target):
            raise ValueError("invalid failed device")
        image = Path(target) if creating else expected_image
        if image is not None and (not image.is_absolute() or image.resolve() != image or not image.is_relative_to(base)):
            raise ValueError("failed image is outside fixture")
        value = self._capture(['/usr/bin/hdiutil', 'info', '-plist'], deadline)
        if not self._complete(value):
            raise ValueError("attachment observation incomplete" + (": " + value["cleanup_error"] if value.get("cleanup_error") else ""))
        records = plistlib.loads(value['stdout']).get('images', [])
        matches = []
        for record in records:
            entities = record.get('system-entities', [])
            if (((creating or selecting) and record.get('image-path') == str(image)) or
                    (not creating and not selecting and any(e.get('dev-entry') == target for e in entities))):
                matches.append(record)
        if len(matches) != 1:
            raise ValueError("missing or ambiguous attachment")
        record = matches[0]
        backing = Path(record['image-path'])
        if (record.get('owner-uid') != os.getuid() or not backing.is_absolute() or
                backing.resolve() != backing or not backing.is_relative_to(base) or
                (image is not None and backing != image)):
            raise ValueError("attachment owner/path mismatch")
        backing_stat = _private(backing)
        identity = (backing_stat.st_dev, backing_stat.st_ino)
        entities = record['system-entities']
        devices = [e.get('dev-entry') for e in entities]
        if (not 0 < len(devices) <= 32 or len(set(devices)) != len(devices) or
                not all(isinstance(d, str) and _device.fullmatch(d) for d in devices)):
            raise ValueError("invalid or duplicate device mapping")
        volumes = [e for e in entities if e.get('mount-point')]
        if len(volumes) > 1:
            raise ValueError("ambiguous mountpoint")
        point = Path(volumes[0]['mount-point']) if volumes else None
        if point is not None:
            if not point.is_absolute() or point.resolve() != point or not point.is_relative_to(base) or point == base:
                raise ValueError("mountpoint outside fixture")
            _private(point, True)
        # Reuse native inventory in a child so its wait/output share this deadline.
        value = self._capture([sys.executable, '-I', '-B', '-c',
            'import json; from stallionfs._scan import mounts; print(json.dumps(mounts()))'], deadline)
        if not self._complete(value):
            raise ValueError("native mount observation incomplete" + (": " + value["cleanup_error"] if value.get("cleanup_error") else ""))
        native = json.loads(value['stdout'])
        related = [r for r in native if r.get('device') in devices or (point and r.get('path') == str(point))]
        if point is None:
            if related:
                raise ValueError("unmapped native mount")
            return str(backing), devices, None, None, identity
        if (len(related) != 1 or related[0].get('device') != volumes[0]['dev-entry'] or
                related[0].get('path') != str(point) or related[0].get('filesystem') != 'apfs'):
            raise ValueError("native mount mismatch")
        return str(backing), devices, str(point), volumes[0]['dev-entry'], identity

    @staticmethod
    def _raw_devices(devices):
        # Derive only counterparts of the independently validated attachment graph.
        # Missing nodes remain an inconclusive lsof result, not proof of no holder.
        if (not isinstance(devices, list) or not 0 < len(devices) <= 32 or
                not all(isinstance(device, str) and _device.fullmatch(device) for device in devices) or
                len(set(devices)) != len(devices)):
            raise ValueError('invalid device mapping')
        return ['/dev/r' + device.removeprefix('/dev/') for device in devices]

    @staticmethod
    def _holder_identity(lines, image, identity):
        # lsof's D is hexadecimal st_dev; i is the decimal inode number.
        # A pathname without both fields cannot establish the held backing inode.
        matches, process, record = [], {}, {}
        files = 0
        for line in [*lines, None]:
            if line is None or line.startswith(('p', 'f')):
                if record:
                    if not {'f', 't', 'n'} <= record.keys():
                        return 'unavailable'
                    if record['n'] == image:
                        matches.append((record.get('D'), record.get('i')))
                    files += 1
                    record = {}
                if line is None or line.startswith('p'):
                    if process and (set(process) != {'p', 'c'} or not files):
                        return 'unavailable'
                    process, files = {}, 0
                elif set(process) != {'p', 'c'}:
                    return 'unavailable'
            if line is None:
                break
            if not re.fullmatch(r'(?:p[1-9][0-9]*|[cft][A-Za-z0-9 ._+-]{1,64}|D0x[0-9a-fA-F]{1,16}|i[0-9]{1,20}|n[^\x00\r\n]+)', line):
                return 'unavailable'
            field, value = line[0], line[1:]
            target = process if field in ('p', 'c') else record
            if field in target or (field == 'c' and ('p' not in process or record or files)) or (
                    field not in ('p', 'c', 'f') and 'f' not in record):
                return 'unavailable'
            target[field] = int(value, 16) if field == 'D' else int(value) if field == 'i' else value
        if image is None:
            return 'not_queried'  # Empty no-match or valid filesystem records.
        if not matches or any(None in value for value in matches):
            return 'unavailable'
        return 'matched' if all(value == identity for value in matches) else 'mismatch'

    def eject_log(self, observation):
        """Query once after public detach unwinds, retaining a recovered first failure."""
        deadline = observation.get('deadline')
        if deadline is None:
            return
        if not self.lock.acquire(timeout=max(0, deadline - time.monotonic())):
            return
        raw_target = observation.get('target')
        event = dict(target=raw_target if isinstance(raw_target, str) and re.fullmatch(r'/dev/disk[0-9]+', raw_target) else None,
                     window_start_ns=observation.get('start_ns') if type(observation.get('start_ns')) is int else None,
                     window_end_ns=observation.get('end_ns') if type(observation.get('end_ns')) is int else None,
                     query_status='unavailable', records='',
                     returncode=None, timeout=False, truncated=False, reaped=False,
                     capture_error=None, cleanup_error=None, reason=None)
        saved_remaining = None
        try:
            if self.eject_log_attempted:
                return
            self.eject_log_attempted = True
            self.operation_id, self.phase = observation.get('operation_id') or 0, 'after'
            context = self.eject_contexts.get(self.operation_id)
            scope = observation.get('scope')
            target, start, end = event['target'], event['window_start_ns'], event['window_end_ns']
            if not scope or scope['expected']:
                event['reason'] = 'no_unexpected_owned_scope'
                return
            if observation.get('target_changed') or not context or context['target'] != target or context['image'] != str(scope['image']):
                event['reason'] = 'no_verified_attachment_mapping'
                return
            deadline = min(deadline, context['deadline'])
            if not isinstance(target, str) or not re.fullmatch(r'/dev/disk[0-9]+', target):
                event['reason'] = 'invalid_eject_target'
                return
            elapsed = observation.get('end_mono', -1) - observation.get('start_mono', 0)
            if (type(start) is not int or type(end) is not int or not 0 < start <= end or
                    not 0 <= elapsed <= 30 or not 0 <= end - start <= 30 * 10**9 or
                    abs((end - start) / 10**9 - elapsed) > 1):
                event['reason'] = 'unavailable_command_window'
                return
            first, last = start // 10**9, (end + 10**9 - 1) // 10**9
            if last - first > 30:
                event['reason'] = 'command_window_exceeds_bound'
                return
            if (self.capture_disabled or self.remaining <= 0 or time.monotonic() >= deadline - 1 or
                    self.events >= EVENTS or self.written + 8192 > FILE_BYTES):
                event['reason'] = 'diagnostic_budget_exhausted'
                return
            identity = _private(Path(context['image']))
            if (identity.st_dev, identity.st_ino) != context['identity']:
                event['reason'] = 'backing_identity_changed'
                return
            dates = [datetime.fromtimestamp(second, timezone.utc).strftime('%Y-%m-%d %H:%M:%S+0000')
                     for second in (first, last)]
            predicate = (f'process == "diskarbitrationd" AND subsystem == "{DA_SUBSYSTEM}" AND '
                         f'((eventMessage CONTAINS "unable to eject {target} (status code ") OR '
                         f'(eventMessage CONTAINS "dispatched response, id = " AND '
                         f'eventMessage CONTAINS[c] "eject" AND eventMessage CONTAINS[c] "approval" AND '
                         f'eventMessage CONTAINS "disk = {target}, dissented, status = "))')
            argv = ['/usr/bin/log', 'show', '--style', 'ndjson', '--start', dates[0], '--end', dates[1],
                    '--timezone', 'UTC', '--no-pager', '--no-info', '--no-debug', '--no-signpost',
                    '--no-loss', '--predicate', predicate]
            saved_remaining = self.remaining
            allowance = min(saved_remaining, EJECT_CAPTURE_BYTES)
            self.remaining = allowance
            value = self._capture(argv, deadline)
            for name in ('returncode', 'timeout', 'truncated', 'reaped', 'capture_error', 'cleanup_error'):
                event[name] = value[name]
            records, parse_reason, limited = _eject_records(value['stdout'], target, start, end)
            incomplete = (value['timeout'] or value['truncated'] or not value['reaped'] or
                          value['capture_error'] or value['cleanup_error'] or parse_reason or limited)
            if value['returncode'] != 0:
                event['reason'] = 'log_query_failed'
            else:
                event.update(records=records, query_status='incomplete' if incomplete else 'matched' if records else 'empty',
                             reason=parse_reason or ('retained_output_limit' if limited else
                                    'incomplete_capture' if incomplete else 'public_status_records' if records else
                                    'no_matching_public_status_records'))
            identity = _private(Path(context['image']))
            if (identity.st_dev, identity.st_ino) != context['identity']:
                event.update(records='', query_status='unavailable', reason='backing_identity_changed')
        except Exception as error:
            event.update(records='', query_status='unavailable', reason='log_query_unavailable',
                         capture_error=type(error).__name__)
        finally:
            if saved_remaining is not None:
                self.remaining = 0 if self.capture_disabled else saved_remaining - (allowance - self.remaining)
            try:
                if event['reason'] is not None and time.monotonic() < deadline:
                    self._emit(deadline, 'eject_log', **event)
            finally:
                self.operation_id, self.phase = 0, 'standalone'
                self.lock.release()

    def before(self, args, scope, observation=None):
        return self._observe(args, None, scope, phase='before', observation=observation)

    def report(self, args, error, scope, operation_id=None, observation=None):
        # Intentional refusal tests must not consume unexpected-failure capacity.
        if scope and scope['expected']:
            return
        return self._observe(args, error, scope, phase='after', operation_id=operation_id,
                             observation=observation)

    def _observe(self, args, error, scope, *, phase, operation_id=None, observation=None):
        before = phase == 'before'
        if ((self.before_attempts >= 1 if before else self.attempts >= ATTEMPTS) or
                self.events >= EVENTS or self.written >= FILE_BYTES):
            return operation_id
        deadline = time.monotonic() + SECONDS
        if not self.lock.acquire(timeout=SECONDS):
            return operation_id
        saved_remaining = None
        try:
            if ((self.before_attempts >= 1 if before else self.attempts >= ATTEMPTS) or
                    self.events >= EVENTS or self.written >= FILE_BYTES):
                return operation_id
            # Reserve failure capacity before taking the pre-snapshot allowance.
            if before and (self.remaining < 2 * BEFORE_CAPTURE_BYTES or
                           self.events + BEFORE_EVENTS + 5 > EVENTS or
                           self.written + BEFORE_FILE_BYTES + 8192 > FILE_BYTES):
                return operation_id
            if operation_id is None:
                self.operations += 1
                operation_id = self.operations
            if observation is not None:
                observation['operation_id'] = operation_id
                observation['deadline'] = deadline
                if before:
                    # Admission is not proof that mapping/capture completed.
                    observation['pre_observation'] = 'attempted'
            self.operation_id, self.phase = operation_id, phase
            if before:
                saved_remaining = self.remaining
                before_budget = min(saved_remaining, BEFORE_CAPTURE_BYTES)
                self.before_attempts += 1
                self.before_events, self.before_written = self.events, self.written
                self.remaining = before_budget
            else:
                self.attempts += 1
            self._emit(deadline, 'observation' if before else 'failure', operation=args[1],
                       error=None if before else type(error).__name__,
                       message=None if before else _message(error),
                       expected_busy=bool(scope and scope['expected']),
                       stage=scope['stage'] if scope else None, workspace=scope['workspace'] if scope else None,
                       failed_device=args[2] if args[1] == 'eject' and isinstance(args[2], str) and _device.fullmatch(args[2]) else None,
                       expected_mountpoint=str(scope['mountpoint']) if scope and scope['mountpoint'] else None,
                       pre_observation=(observation.get('pre_observation', 'unavailable')
                                        if observation is not None else 'not-selected'),
                       observation='before detach validation' if before else 'post-failure observation')
            if scope is None:
                self._emit(deadline, 'unavailable', reason='no explicit owned fixture context')
                return operation_id
            try:
                image, devices, point, volume, identity = self._mapping(args, scope, deadline)
            except Exception as unavailable:
                self._emit(deadline, 'unavailable', reason=_message(unavailable))
                return operation_id
            expected_point = str(scope['mountpoint']) if scope['mountpoint'] else None
            matches = point is not None and point == expected_point
            if before:
                self.backing_identities.setdefault(operation_id, identity)
            first_identity = self.backing_identities.get(operation_id)
            same_backing = first_identity == identity if first_identity is not None else None
            if before and observation is not None:
                targets = [device for device in devices if re.fullmatch(r'/dev/disk[0-9]+', device)]
                observation['observed_target'] = targets[0] if targets else None
            if not before and same_backing is not False:
                self.eject_contexts[operation_id] = dict(image=image, target=args[2],
                                                        identity=identity, deadline=deadline)
            self._emit(deadline, 'mapping', image=image, devices=devices, mountpoint=point, volume_device=volume,
                       expected_mountpoint=expected_point, mountpoint_matches=matches,
                       backing_device=identity[0], backing_inode=identity[1],
                       backing_identity_matches_first=same_backing)
            if same_backing is False:
                self._emit(deadline, 'unavailable', reason='backing identity changed between operation observations')
            if point != expected_point:
                self._emit(deadline, 'unavailable', reason='expected/observed mountpoint mismatch; filesystem lsof omitted')
            # Exact backing/device queries remain useful when detached or remapped.
            # Only the caller's expected, independently observed mount can scope +f.
            point = point if matches else None
            raw_devices = self._raw_devices(devices)
            queries = [([], [image, *devices, *raw_devices])]
            if point is not None:
                queries.append((['+f'], [point]))
            for options, names in queries:
                try:
                    current = _private(Path(image))
                except (OSError, ValueError):
                    self._emit(deadline, 'unavailable', reason='backing identity unavailable before holder observation')
                    break
                if (current.st_dev, current.st_ino) != identity:
                    self._emit(deadline, 'unavailable', reason='backing identity changed before holder observation')
                    break
                if options and (not os.path.ismount(point) or not stat.S_ISBLK(os.stat(volume).st_mode) or
                                os.stat(point).st_dev != os.stat(volume).st_rdev):
                    self._emit(deadline, 'unavailable', reason='mount changed; filesystem lsof omitted')
                    break
                value = self._capture(['/usr/sbin/lsof', '-nP', '-F', 'pcftDin', *options, '--', *names], deadline)
                raw_lines = value.pop('stdout').decode(errors='replace').splitlines()
                lines = []
                display_truncated = False
                for line in raw_lines:
                    if line.startswith('n'):
                        name = line[1:]
                        allowed = name in [image, *devices, *raw_devices, point] or (point is not None and name.startswith(point + '/') and '..' not in Path(name).parts)
                        # Ambiguous name/annotation text must not smuggle a second path.
                        allowed = allowed and not any(c.isspace() for c in name)
                        display_truncated |= allowed and len(line) > 512
                        lines.append(line[:512] if allowed else 'n[unscoped name omitted]')
                    elif re.fullmatch(r'(?:p[0-9]+|[cft][A-Za-z0-9 ._+-]{1,64}|D0x[0-9a-fA-F]{1,16}|i[0-9]{1,20})', line):
                        lines.append(line)
                stderr = value.pop('stderr').decode(errors='replace')
                stdout = '\n'.join(lines)
                display_truncated |= len(stdout) > 2048 or len(stderr) > 2048
                try:
                    after = _private(Path(image))
                    after_identity = (after.st_dev, after.st_ino)
                except (OSError, ValueError):
                    after_identity = (None, None)
                identity_status = self._holder_identity(raw_lines, None if options else image, identity)
                if after_identity == (None, None):
                    identity_status = 'unavailable'
                elif after_identity != identity:
                    identity_status = 'changed'
                elif display_truncated or value['timeout'] or value['truncated'] or not value['reaped'] or value.get('capture_error') or value.get('cleanup_error'):
                    identity_status = 'unavailable'
                self._emit(deadline, 'lsof', **value, stdout=stdout[:2048], stderr=_message(stderr),
                           display_truncated=display_truncated, backing_identity_status=identity_status,
                           backing_device_after=after_identity[0], backing_inode_after=after_identity[1])
                if not value['reaped'] or value['timeout'] or value['truncated'] or value.get('capture_error') or value.get('cleanup_error'):
                    break
        finally:
            if saved_remaining is not None:
                self.remaining = 0 if self.capture_disabled else saved_remaining - (before_budget - self.remaining)
            self.operation_id, self.phase = 0, 'standalone'
            self.lock.release()
        return operation_id


def install(images, directory):
    diagnostics = Diagnostics(directory)

    def validation_wrapper(name, original):
        def wrapped(image):
            invocation = _detach_call.get()
            if (diagnostics.closed or getattr(images, name) is not wrapped or not invocation or
                    invocation['diagnostics'] is not diagnostics or invocation['command_started'] or
                    image != invocation['scope']['image']):
                return original(image)
            if name == '_attachments':
                result = original(image)
                reading = _validation_read.get()
                if reading is not None and reading['invocation'] is invocation:
                    try:
                        if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
                            raise ValueError('normal inventory unavailable')
                        reading['entities'] = _entities(result[0].get('system-entities'))
                    except Exception:
                        reading['entities'] = None
                return result
            index = invocation['reads']
            invocation['reads'] += 1
            if index >= 2:
                return original(image)
            sample = dict(read=('current', 'confirmed')[index], sample_timestamp_ns=time.time_ns(),
                          sample_status='unavailable', reason='normal_inventory_unavailable',
                          selected_device=None, volume_device=None, mountpoint_state=None, entities=[])
            reading = dict(invocation=invocation, entities=None)
            token = _validation_read.set(reading)
            try:
                try:
                    result = original(image)
                except BaseException:
                    sample['reason'] = 'normal_validation_failed'
                    raise
                try:
                    if not isinstance(result, dict) or result.get('image') != str(invocation['scope']['image']):
                        raise ValueError('normal mapping unavailable')
                    device, volume = result.get('device'), result.get('volume_device')
                    if (not isinstance(device, str) or len(device) > 64 or not _device.fullmatch(device) or
                            volume is not None and (not isinstance(volume, str) or len(volume) > 64 or not _device.fullmatch(volume))):
                        raise ValueError('invalid normal mapping')
                    invocation['targets'].append(device)
                    if reading['entities'] is not None:
                        point = result.get('mountpoint')
                        sample.update(sample_status='validated', reason=None, selected_device=device,
                                      volume_device=volume, entities=reading['entities'],
                                      mountpoint_state='unmounted' if point is None else
                                      'expected' if point == str(invocation['scope']['mountpoint']) else 'other')
                except Exception:
                    sample['reason'] = 'invalid_validation_metadata'
                return result
            finally:
                sample['sample_timestamp_ns'] = time.time_ns()
                invocation['samples'].append(sample)
                _validation_read.reset(token)
        return wrapped

    for name in ('_attachments', 'mounted'):
        previous_function = getattr(images, name, None)
        if previous_function is not None:
            previous = getattr(previous_function, '__dict__', {}).get('_image_diagnostics')
            original_function = previous[2] if previous is not None else previous_function
            wrapper = validation_wrapper(name, original_function)
            wrapper._image_diagnostics = (diagnostics, previous_function, original_function)
            diagnostics.patches.append((images, name, previous_function, wrapper))
            setattr(images, name, wrapper)
    # Preserve surrounding installations without executing nested collectors.
    previous_command = images._command
    previous = getattr(previous_command, '__dict__', {}).get('_image_diagnostics')
    original = previous[2] if previous is not None else previous_command

    def command(*args):
        if diagnostics.closed or images._command is not command:
            return original(*args)
        creating = len(args) >= 3 and args[:2] == ('/usr/bin/hdiutil', 'create')
        ejecting = (len(args) == 3 and args[:2] == ('/usr/sbin/diskutil', 'eject')
                    and isinstance(args[2], str) and re.fullmatch(r'/dev/disk[0-9]+', args[2]))
        if not (creating or ejecting):
            return original(*args)
        invocation = _detach_call.get() if ejecting else None
        if invocation is not None and invocation['diagnostics'] is not diagnostics:
            invocation = None
        observation = invocation['observation'] if invocation is not None else _detach_observation.get() if ejecting else None
        record = invocation or observation
        if record is not None:
            record.setdefault('diagnostics', diagnostics)
            record.setdefault('scope', _scope.get())
            record.setdefault('target', args[2])
            record.setdefault('start_ns', time.time_ns())
            record.setdefault('start_mono', time.monotonic())
            if invocation is not None:
                invocation['command_started'] = True
                invocation['command_count'] += 1
                invocation['command_targets'].append(args[2])
        if observation is not None:
            observation['diagnostics'] = diagnostics
            observation.setdefault('scope', _scope.get())
            observation.setdefault('target', args[2])
            observation['target_changed'] = (observation.get('target_changed', False) or
                                             observation['target'] != args[2] or
                                             observation.get('observed_target') != args[2])
            if invocation is None or invocation['command_count'] == 1:
                diagnostics.eject_contexts.pop(observation['operation_id'], None)
            if 'start_ns' not in observation:
                observation['start_ns'], observation['start_mono'] = record['start_ns'], record['start_mono']
        try:
            if creating:
                return _observed_create(original, args)
            result = original(*args)
            if invocation is not None:
                invocation['command_statuses'].append(0)
            return result
        except Exception as error:
            if diagnostics.closed:
                raise
            if invocation is not None:
                invocation['command_statuses'].append(getattr(error, 'returncode', None))
            if record is not None and 'command_error' not in record:
                record['command_error'] = error
                record['command_status'] = getattr(error, 'returncode', None)
                record['end_ns'], record['end_mono'] = time.time_ns(), time.monotonic()
                record['deadline'] = record['end_mono'] + SECONDS
            if observation is not None and record is not observation:
                for key in ('command_error', 'command_status', 'start_ns', 'start_mono', 'end_ns', 'end_mono'):
                    observation.setdefault(key, record[key])
            reporting = observation or record
            try:
                operation_id = diagnostics.report(args, error, _scope.get(),
                                                  operation_id=reporting.get('operation_id') if reporting else None,
                                                  observation=reporting)
                if invocation is not None:
                    invocation['operation_id'] = operation_id or (reporting or {}).get('operation_id')
                    if reporting and 'deadline' in reporting:
                        invocation['deadline'] = min(invocation['deadline'], reporting['deadline'])
            except BaseException as unavailable:
                try:
                    error.add_note('Image diagnostics unavailable: ' + type(unavailable).__name__)
                except BaseException:
                    pass
            raise

    command._image_diagnostics = (diagnostics, previous_command, original)
    diagnostics.patches.append((images, '_command', previous_command, command))
    images._command = command
    previous_detach = getattr(images, 'detach', None)
    if previous_detach is not None:
        previous = getattr(previous_detach, '__dict__', {}).get('_image_diagnostics')
        original_detach = previous[2] if previous is not None else previous_detach
        def detach(image, mountpoint):
            if diagnostics.closed or images.detach is not detach:
                return original_detach(image, mountpoint)
            observation, scope = _detach_observation.get(), _scope.get()
            if observation is not None and observation['started']:
                observation = None  # A surrounding selection belongs only to its first public call.
            if observation is not None and not observation['started']:
                observation['started'] = True
                identity = None
                try:
                    if (scope is not None and scope['image'] == Path(image) and
                            scope['mountpoint'] == Path(mountpoint) and
                            scope['base'].is_absolute() and scope['base'].resolve() == scope['base'] and
                            scope['image'].is_absolute() and scope['image'].resolve() == scope['image'] and
                            scope['image'].is_relative_to(scope['base'])):
                        _private(scope['base'], True)
                        info = _private(scope['image'])
                        identity = (info.st_dev, info.st_ino)
                        diagnostics.before(('/usr/sbin/diskutil', 'eject', None), scope, observation)
                except Exception:
                    pass  # Observation failure cannot prevent ordinary validation.
                if identity is not None:
                    try:
                        info = _private(scope['image'])
                        unchanged = identity == (info.st_dev, info.st_ino)
                    except Exception:
                        unchanged = False
                    if not unchanged:
                        from stallionfs.images import _error
                        raise _error('Owned backing identity changed during detach observation')
            owned_scope = (scope if scope is not None and scope['image'] == Path(image) and
                           scope['mountpoint'] == Path(mountpoint) else None)
            invocation = dict(diagnostics=diagnostics, scope=owned_scope, reads=0, samples=[], targets=[],
                              command_started=False, command_count=0, command_targets=[], command_statuses=[],
                              pre_observation='not-selected', observation=observation)
            token = _detach_call.set(invocation if owned_scope is not None else None)
            selected_token = _detach_observation.set(observation)
            try:
                result = original_detach(image, mountpoint)
                if invocation.get('command_error') is not None:
                    invocation['outcome'] = 'recovered'
                    try:
                        diagnostics.validation(invocation)
                        invocation['target_changed'] = (invocation['reads'] != 2 or
                            invocation['command_count'] != 2 or
                            invocation['targets'] != [invocation.get('target')] * 2 or
                            invocation['command_targets'] != [invocation.get('target')] * 2)
                        _finish_eject(invocation, invocation['command_error'])
                        if observation is not None:
                            observation['finalized'] = True
                    except BaseException:
                        pass  # Successful recovery cannot be replaced by diagnostics.
                return result
            except BaseException as error:
                invocation['outcome'] = ('interrupted' if not isinstance(error, Exception) else
                                         'failed' if invocation['command_count'] == 2 else 'refused')
                try:
                    diagnostics.validation(invocation)
                except BaseException:
                    pass
                try:
                    if observation is not None and invocation.get('command_error') is error:
                        invocation['target_changed'] = observation.get('target_changed', False)
                        observation['finalized'] = True
                    else:
                        invocation['target_changed'] = (invocation['reads'] != 2 or
                            invocation['command_count'] not in (1, 2) or
                            invocation['targets'] != [invocation.get('target')] * 2 or
                            invocation['command_targets'] != [invocation.get('target')] * invocation['command_count'])
                    _finish_eject(invocation, error)
                except BaseException:
                    pass  # A collector cannot replace the original failure or interrupt.
                raise
            finally:
                _detach_observation.reset(selected_token)
                _detach_call.reset(token)

        detach._image_diagnostics = (diagnostics, previous_detach, original_detach)
        diagnostics.patches.append((images, 'detach', previous_detach, detach))
        images.detach = detach
    return diagnostics
