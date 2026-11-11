"""Bounded build commands with retained process and stream receipts."""
import json
import os
from pathlib import Path
import subprocess
import selectors
import signal
import time

_COMMAND_STREAM_CAP = 1024 * 1024

_COMMAND_DRAIN_SECONDS = 2

_COMMAND_REAP_SECONDS = 2

_COMMAND_ENV = None

_command_state = {'failure': None, 'active': None, 'first_signal': None, 'signal_count': 0}

def _exclusive(path, value):
    data = value.encode() if isinstance(value, str) else value
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        stream.write(data)

def _latch_command(kind, detail):
    if _command_state['failure'] is None:
        _command_state['failure'] = {'kind': kind, 'detail': detail}

def _cancel_command(signum, _frame, *, state):
    if state.get('cancellation_closed', False):
        return
    if state['first_signal'] is None:
        state['first_signal'] = signum
    state['signal_count'] += 1
    if state['failure'] is None:
        state['failure'] = {'kind': 'cancelled', 'detail': f'signal {signum}'}

def _install_command_handlers():
    state = _command_state

    def cancel(signum, frame):
        _cancel_command(signum, frame, state=state)

    previous = {}
    for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        previous[number] = signal.signal(number, cancel)
    return previous

def _restore_command_handlers(previous):
    for number, handler in previous.items():
        signal.signal(number, handler)

def _owned_command(argv, *, cwd, timeout, stem):
    if _command_state['failure'] is not None:
        raise RuntimeError(f'Further build commands refused: {_command_state["failure"]}')
    assert _command_state['active'] is None
    stem = Path(stem)
    record = {'label': stem.name, 'argv': argv, 'cwd': str(cwd) if cwd else None,
              'timeout_seconds': timeout, 'stream_cap_bytes': _COMMAND_STREAM_CAP,
              'pid': None, 'pgid': None, 'phase': 'preparing', 'returncode': None,
              'timeout': False, 'cap_reached': [], 'cleanup_errors': [],
              'cleanup_uncertain': False, 'kill_attempts': 0, 'cleanup_started': False,
              'stdout_retained_bytes': 0, 'stderr_retained_bytes': 0,
              'stdout_discarded_bytes': 0, 'stderr_discarded_bytes': 0}
    _command_state['active'] = record
    proc = None
    selector = None
    outputs = {}
    primary = None
    started = time.monotonic()

    def capture(cleaning=False):
        for event, _ in selector.select(0.05):
            name = event.data
            try:
                chunk = os.read(event.fileobj.fileno(), 65536)
            except BlockingIOError:
                continue
            if not chunk:
                selector.unregister(event.fileobj)
                event.fileobj.close()
                continue
            key = name + '_retained_bytes'
            keep = min(len(chunk), _COMMAND_STREAM_CAP - record[key])
            written = outputs[name].write(chunk[:keep])
            valid_write = type(written) is int and 0 <= written <= keep
            retained = written if valid_write else 0
            record[key] += retained
            record[name + '_discarded_bytes'] += len(chunk) - retained
            if not valid_write or written != keep:
                raise OSError('Git build command capture short write')
            if record[key] >= _COMMAND_STREAM_CAP:
                if name not in record['cap_reached']:
                    record['cap_reached'].append(name)
                _latch_command('capture_limit', stem.name)
                if not cleaning:
                    raise RuntimeError(f'Git build command capture limit: {stem}')

    def cleanup_poll():
        try:
            return proc.poll()
        except BaseException as error:
            record['cleanup_errors'].append(repr(error))
            record['cleanup_uncertain'] = True
            return None

    try:
        selector = selectors.DefaultSelector()
        _exclusive(str(stem) + '.started.json', json.dumps(record, indent=2) + '\n')
        for name in ('stdout', 'stderr'):
            path = Path(str(stem) + '.' + name + '.bin')
            record[name + '_path'] = str(path)
            outputs[name] = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb', buffering=0)
        if _command_state['failure'] is not None:
            raise RuntimeError(f'Git build command cancelled before launch: {_command_state["failure"]}')
        record['phase'] = 'spawning'
        proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, env=_COMMAND_ENV)
        record.update(pid=proc.pid, pgid=proc.pid, phase='running')
        for name, pipe in (('stdout', proc.stdout), ('stderr', proc.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while selector.get_map() or proc.poll() is None:
            if _command_state['first_signal'] is not None:
                raise RuntimeError(f'Git build command cancelled by signal {_command_state["first_signal"]}')
            if time.monotonic() - started >= timeout:
                record['timeout'] = True
                raise subprocess.TimeoutExpired(argv, timeout)
            capture()
        if proc.returncode:
            _latch_command('exit', f'{stem.name}: {proc.returncode}')
        try:
            os.killpg(proc.pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise RuntimeError('Git build command left an owned process group alive')
    except BaseException as error:
        primary = error
        if isinstance(error, subprocess.TimeoutExpired):
            record['timeout'] = True
            _latch_command('timeout', stem.name)
        else:
            _latch_command('command_error', repr(error))
    finally:
        if proc is not None and (_command_state['failure'] is not None or primary is not None):
            record['cleanup_started'] = True
            record['phase'] = 'cleaning'
            record['drain_deadline'] = time.monotonic() + _COMMAND_DRAIN_SECONDS
            record['reap_deadline'] = record['drain_deadline'] + _COMMAND_REAP_SECONDS
            leader_reaped = proc.returncode is not None
            if leader_reaped:
                # Reaping releases the PID; its numeric group no longer proves ownership.
                record['group_signal_skipped_reason'] = 'leader_already_reaped'
                record['group_ownership_after_cleanup'] = 'unknown_after_reap'
                record['group_alive_after_cleanup'] = None
                record['cleanup_uncertain'] = True
            else:
                record['kill_attempts'] += 1
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except BaseException as error:
                    record['cleanup_errors'].append(repr(error))
                    record['cleanup_uncertain'] = True
            while selector is not None and selector.get_map() and time.monotonic() < record['drain_deadline']:
                try:
                    capture(cleaning=True)
                except BaseException as error:
                    record['cleanup_errors'].append(repr(error))
                    record['cleanup_uncertain'] = True
                    break
            if selector is not None and selector.get_map():
                record['cleanup_uncertain'] = True
            if cleanup_poll() is None:
                try:
                    proc.wait(timeout=min(_COMMAND_REAP_SECONDS, max(0, record['reap_deadline'] - time.monotonic())))
                except BaseException as error:
                    record['cleanup_errors'].append(repr(error))
                    record['cleanup_uncertain'] = True
            if cleanup_poll() is None:
                record['cleanup_uncertain'] = True
            if not leader_reaped:
                try:
                    os.killpg(proc.pid, 0)
                except ProcessLookupError:
                    record['group_alive_after_cleanup'] = False
                except BaseException as error:
                    record['cleanup_errors'].append(repr(error))
                    record['cleanup_uncertain'] = True
                else:
                    record['group_alive_after_cleanup'] = True
                    record['cleanup_uncertain'] = True
        if proc is not None:
            record['returncode'] = cleanup_poll()
            for pipe in (proc.stdout, proc.stderr):
                try:
                    pipe.close()
                except BaseException as error:
                    record['cleanup_errors'].append(repr(error))
                    record['cleanup_uncertain'] = True
        try:
            if selector is not None:
                selector.close()
        except BaseException as error:
            record['cleanup_errors'].append(repr(error))
            record['cleanup_uncertain'] = True
        for stream in outputs.values():
            try:
                stream.close()
            except BaseException as error:
                record['cleanup_errors'].append(repr(error))
                record['cleanup_uncertain'] = True
        record.update(phase='done', first_signal=_command_state['first_signal'],
                      signal_count=_command_state['signal_count'], elapsed_seconds=time.monotonic() - started)
        if record['cleanup_uncertain']:
            _latch_command('cleanup_uncertain', stem.name)
        record['first_failure'] = _command_state['failure']
        record['primary_exception'] = repr(primary) if primary is not None else None
        try:
            _exclusive(str(stem) + '.command.json', json.dumps(record, indent=2) + '\n')
        except BaseException as error:
            _latch_command('receipt_error', repr(error))
            if primary is None:
                primary = error
            elif hasattr(primary, 'add_note'):
                primary.add_note(f'Command receipt capture also failed: {error!r}')
        _command_state['active'] = None
    try:
        stdout = Path(record['stdout_path']).read_bytes() if 'stdout_path' in record and Path(record['stdout_path']).is_file() else b''
        stderr = Path(record['stderr_path']).read_bytes() if 'stderr_path' in record and Path(record['stderr_path']).is_file() else b''
    except BaseException as error:
        _latch_command('capture_read_error', repr(error))
        if primary is not None:
            raise primary from error
        raise
    if isinstance(primary, subprocess.TimeoutExpired):
        if primary.output is None:
            primary.output = stdout
        if primary.stderr is None:
            primary.stderr = stderr
    if primary is not None:
        raise primary
    if _command_state['failure'] is not None and not record['returncode']:
        raise RuntimeError(f'Git build command failed or incomplete: {_command_state["failure"]}')
    try:
        return subprocess.CompletedProcess(argv, record['returncode'], stdout.decode(), stderr.decode())
    except BaseException as error:
        _latch_command('decode_error', repr(error))
        raise
