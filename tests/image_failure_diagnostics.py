"""Bounded, failure-only observations for the installed-wheel image tests."""
from contextlib import contextmanager
from contextvars import ContextVar
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
REPORT = "image-failures.jsonl"
_fields = {
    'failure': {'operation', 'error', 'message', 'expected_busy', 'observation', 'stage', 'workspace', 'failed_device', 'expected_mountpoint'},
    'unavailable': {'reason'},
    'mapping': {'image', 'devices', 'mountpoint', 'volume_device', 'expected_mountpoint', 'mountpoint_matches'},
    'lsof': {'returncode', 'stdout', 'stderr', 'timeout', 'truncated', 'reaped', 'capture_error', 'cleanup_error', 'display_truncated'},
}
_scope = ContextVar("image_failure_scope", default=None)
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
            if not isinstance(value, dict) or value.get('kind') not in _fields or set(value) - {'kind'} != _fields[value['kind']]:
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


class Diagnostics:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.remaining = CAPTURE_BYTES
        self.events = self.written = self.attempts = 0
        self.lock = threading.Lock()
        self.fd = None

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)

    def _emit(self, deadline, kind, **values):
        data = (json.dumps(dict(kind=kind, **values), ensure_ascii=True) + "\n").encode()
        if len(data) > 8192:
            data = b'{"kind":"unavailable","reason":"diagnostic event exceeds serialization cap"}\n'
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
        if self.remaining <= 0 or time.monotonic() >= deadline - 1:
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
        _private(backing)
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
            return str(backing), devices, None, None
        if (len(related) != 1 or related[0].get('device') != volumes[0]['dev-entry'] or
                related[0].get('path') != str(point) or related[0].get('filesystem') != 'apfs'):
            raise ValueError("native mount mismatch")
        return str(backing), devices, str(point), volumes[0]['dev-entry']

    def report(self, args, error, scope):
        if self.attempts >= ATTEMPTS or self.events >= EVENTS or self.written >= FILE_BYTES:
            return
        deadline = time.monotonic() + SECONDS
        if not self.lock.acquire(timeout=SECONDS):
            return
        try:
            if self.attempts >= ATTEMPTS or self.events >= EVENTS or self.written >= FILE_BYTES:
                return
            self.attempts += 1
            self._emit(deadline, 'failure', operation=args[1], error=type(error).__name__,
                       message=_message(error), expected_busy=bool(scope and scope['expected']),
                       stage=scope['stage'] if scope else None, workspace=scope['workspace'] if scope else None,
                       failed_device=args[2] if args[1] == 'detach' and _device.fullmatch(args[2]) else None,
                       expected_mountpoint=str(scope['mountpoint']) if scope and scope['mountpoint'] else None,
                       observation='post-failure only; pre-operation mapping unknown')
            if scope is None:
                self._emit(deadline, 'unavailable', reason='no explicit owned fixture context')
                return
            try:
                image, devices, point, volume = self._mapping(args, scope, deadline)
            except Exception as unavailable:
                self._emit(deadline, 'unavailable', reason=_message(unavailable))
                return
            expected_point = str(scope['mountpoint']) if scope['mountpoint'] else None
            matches = point is not None and point == expected_point
            self._emit(deadline, 'mapping', image=image, devices=devices, mountpoint=point, volume_device=volume,
                       expected_mountpoint=expected_point, mountpoint_matches=matches)
            if point != expected_point:
                self._emit(deadline, 'unavailable', reason='expected/observed mountpoint mismatch; filesystem lsof omitted')
            # Exact backing/device queries remain useful when detached or remapped.
            # Only the caller's expected, independently observed mount can scope +f.
            point = point if matches else None
            queries = [([], [image, *devices])]
            if point is not None:
                queries.append((['+f'], [point]))
            for options, names in queries:
                if options and (not os.path.ismount(point) or not stat.S_ISBLK(os.stat(volume).st_mode) or
                                os.stat(point).st_dev != os.stat(volume).st_rdev):
                    self._emit(deadline, 'unavailable', reason='mount changed; filesystem lsof omitted')
                    break
                value = self._capture(['/usr/sbin/lsof', '-nP', '-F', 'pcftn', *options, '--', *names], deadline)
                lines = []
                display_truncated = False
                for line in value.pop('stdout').decode(errors='replace').splitlines():
                    if line.startswith('n'):
                        name = line[1:]
                        allowed = name in [image, *devices, point] or (point is not None and name.startswith(point + '/') and '..' not in Path(name).parts)
                        # Ambiguous name/annotation text must not smuggle a second path.
                        allowed = allowed and not any(c.isspace() for c in name)
                        display_truncated |= allowed and len(line) > 512
                        lines.append(line[:512] if allowed else 'n[unscoped name omitted]')
                    elif re.fullmatch(r'(?:p[0-9]+|[cft][A-Za-z0-9 ._+-]{1,64})', line):
                        lines.append(line)
                stderr = value.pop('stderr').decode(errors='replace')
                stdout = '\n'.join(lines)
                display_truncated |= len(stdout) > 2048 or len(stderr) > 2048
                self._emit(deadline, 'lsof', **value, stdout=stdout[:2048], stderr=_message(stderr),
                           display_truncated=display_truncated)
                if not value['reaped'] or value['timeout'] or value['truncated'] or value.get('capture_error') or value.get('cleanup_error'):
                    break
        finally:
            self.lock.release()


def install(images, directory):
    diagnostics = Diagnostics(directory)
    original = images._command

    def command(*args):
        if len(args) < 3 or args[0] != '/usr/bin/hdiutil' or args[1] not in ('create', 'detach'):
            return original(*args)
        try:
            return original(*args, '-verbose')
        except Exception as error:
            try:
                diagnostics.report(args, error, _scope.get())
            except Exception as unavailable:
                try:
                    error.add_note('Image diagnostics unavailable: ' + type(unavailable).__name__)
                except Exception:
                    pass
            raise

    images._command = command
    return diagnostics
