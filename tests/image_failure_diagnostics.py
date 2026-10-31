"""Bounded image-test observations around explicitly selected detach operations."""
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import errno
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
_scope = ContextVar("image_failure_scope", default=None)
_detach_observation = ContextVar("image_detach_observation", default=None)
_device = re.compile(r"/dev/disk[0-9]+(?:s[0-9]+)*\Z")


@contextmanager
def failure_scope(base, image=None, *, workspace=None, mountpoint=None, stage='body', expected=False):
    token = _scope.set(dict(base=Path(base), image=Path(image) if image else None,
                           workspace=workspace, mountpoint=Path(mountpoint) if mountpoint else None,
                           stage=stage, expected=expected))
    try:
        yield
    finally:
        _scope.reset(token)


@contextmanager
def observe_detach():
    """Observe only the first detach command in this explicit test operation."""
    observation = dict(started=False, operation_id=None)
    token = _detach_observation.set(observation)
    try:
        yield
    except Exception as error:
        reporter = observation.get('diagnostics')
        if (reporter is not None and getattr(error, 'returncode', None) == errno.EBUSY and
                not (observation.get('scope') or {}).get('expected', False)):
            try:
                reporter.eject_log(observation)
            except Exception as unavailable:
                try:
                    error.add_note('Eject log unavailable: ' + type(unavailable).__name__)
                except Exception:
                    pass
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
            if not isinstance(value, dict) or value.get('kind') not in _fields or set(value) - {'kind'} != _fields[value['kind']] | _metadata:
                return False
            if (type(value['operation_id']) is not int or value['operation_id'] < 0 or
                    value['phase'] not in ('before', 'after', 'standalone') or
                    type(value['timestamp_ns']) is not int or value['timestamp_ns'] <= 0):
                return False
            for name in ('backing_device', 'backing_inode', 'backing_device_after', 'backing_inode_after'):
                if name in value and (value[name] is None and value['kind'] == 'mapping' or
                        value[name] is not None and (type(value[name]) is not int or value[name] < 0)):
                    return False
            if value['kind'] == 'mapping' and type(value['backing_identity_matches_first']) is not bool:
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

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)

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
        target = str(args[-1] if creating else args[2])
        if not creating and not _device.fullmatch(target):
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
            if (creating and record.get('image-path') == str(image)) or (not creating and any(e.get('dev-entry') == target for e in entities)):
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
    def _holder_identity(lines, image, identity):
        # lsof's D is hexadecimal st_dev; i is the decimal inode number.
        # A pathname without both fields cannot establish the held backing inode.
        matches, record = [], {}
        for line in [*lines, 'f']:
            if line.startswith(('p', 'f')):
                if record.get('n') == image:
                    matches.append((record.get('D'), record.get('i')))
                record = {}
            elif re.fullmatch(r'D0x[0-9a-fA-F]{1,16}', line):
                record['D'] = int(line[1:], 16)
            elif re.fullmatch(r'i[0-9]{1,20}', line):
                record['i'] = int(line[1:])
            elif line.startswith('n'):
                record['n'] = line[1:]
        if not matches or any(None in value for value in matches):
            return 'unavailable'
        return 'matched' if all(value == identity for value in matches) else 'mismatch'

    def eject_log(self, observation):
        """Query once after the public detach operation has failed, never between attempts."""
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
                         f'(eventMessage CONTAINS "{target}," OR eventMessage CONTAINS "{target} (")')
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
                       failed_device=args[2] if args[1] == 'detach' and _device.fullmatch(args[2]) else None,
                       expected_mountpoint=str(scope['mountpoint']) if scope and scope['mountpoint'] else None,
                       observation='immediately before detach command' if before else 'post-failure observation')
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
            first_identity = self.backing_identities.setdefault(operation_id, identity)
            same_backing = first_identity == identity
            if not before and same_backing:
                self.eject_contexts[operation_id] = dict(image=image, target=args[2],
                                                        identity=identity, deadline=deadline)
            self._emit(deadline, 'mapping', image=image, devices=devices, mountpoint=point, volume_device=volume,
                       expected_mountpoint=expected_point, mountpoint_matches=matches,
                       backing_device=identity[0], backing_inode=identity[1],
                       backing_identity_matches_first=same_backing)
            if not same_backing:
                self._emit(deadline, 'unavailable', reason='backing identity changed between operation observations')
            if point != expected_point:
                self._emit(deadline, 'unavailable', reason='expected/observed mountpoint mismatch; filesystem lsof omitted')
            # Exact backing/device queries remain useful when detached or remapped.
            # Only the caller's expected, independently observed mount can scope +f.
            point = point if matches else None
            queries = [([], [image, *devices])]
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
                        allowed = name in [image, *devices, point] or (point is not None and name.startswith(point + '/') and '..' not in Path(name).parts)
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
                identity_status = 'not_queried' if options else self._holder_identity(raw_lines, image, identity)
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
    original = images._command

    def command(*args):
        if len(args) < 3 or args[0] != '/usr/bin/hdiutil' or args[1] not in ('create', 'detach'):
            return original(*args)
        observation = _detach_observation.get() if args[1] == 'detach' else None
        if observation is not None and not observation['started']:
            observation['started'] = True
            try:
                diagnostics.before(args, _scope.get(), observation)
            except Exception:
                pass  # Observation failure cannot prevent the requested detach.
        if observation is not None:
            observation['diagnostics'] = diagnostics
            observation.setdefault('scope', _scope.get())
            observation.setdefault('target', args[2])
            observation['target_changed'] = observation.get('target_changed', False) or observation['target'] != args[2]
            diagnostics.eject_contexts.pop(observation['operation_id'], None)
            if 'start_ns' not in observation:
                observation['start_ns'], observation['start_mono'] = time.time_ns(), time.monotonic()
        try:
            return original(*args, '-verbose')
        except Exception as error:
            if observation is not None:
                observation['end_ns'], observation['end_mono'] = time.time_ns(), time.monotonic()
            try:
                diagnostics.report(args, error, _scope.get(),
                                   operation_id=observation['operation_id'] if observation else None,
                                   observation=observation)
            except Exception as unavailable:
                try:
                    error.add_note('Image diagnostics unavailable: ' + type(unavailable).__name__)
                except Exception:
                    pass
            raise

    images._command = command
    return diagnostics
