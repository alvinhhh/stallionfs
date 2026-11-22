"""Installed CI suite lifecycle and direct-child closure evidence.

The supervisor owns only its retained Popen. EOF and reaping do not establish
closure of escaped descendants or services. No arbitrary selectors are accepted.
"""
import datetime
import json
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import threading
import time
import unittest
import uuid

PHASES = ('setup', 'suite', 'close', 'admission', 'accounting', 'exit')
DIAGNOSTIC_CAP = 1024 * 1024
OUTPUT_CAP = 16 * 1024 * 1024
RESERVE = 130  # tail actions consume one shared remainder; each is admitted separately
TAIL_PHASES = ('validation', 'suite-upload', 'image-upload', 'interface-upload', 'wheel-upload')


EXCEPTIONS = frozenset(('Exception', 'AssertionError', 'ValueError', 'TypeError',
                        'RuntimeError', 'OSError', 'TimeoutError', 'SystemExit',
                        'KeyboardInterrupt', 'MemoryError', 'RecursionError'))
COUNTS = ('tests', 'failures', 'errors', 'skips')
BINDING = {'invocation', 'mode', 'pid', 'job'}


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate key')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite')))
    except (RecursionError, UnicodeError) as error:
        raise ValueError('Invalid JSON') from error


def totals(result):
    return dict(tests=0 if result is None else result.testsRun,
                failures=0 if result is None else len(result.failures),
                errors=0 if result is None else len(result.errors),
                skips=0 if result is None else len(result.skipped))


def check_counts(record):
    if any(type(record.get(k)) is not int or not 0 <= record[k] <= 1000000 for k in COUNTS):
        raise ValueError('Result totals')
    # testsRun counts methods; subtests and class/module fixtures contribute
    # outcome entries independently. Keep their actual totals, including when
    # a fixture prevents every method from starting.


class Events:
    def __init__(self, path):
        self.binding = dict(invocation=os.environ['CI_INVOCATION'],
                            mode=os.environ['CI_MODE'], job=os.environ['CI_JOB_BINDING'],
                            pid=os.getpid())
        self.stream = open(path, 'x', encoding='utf-8')
        self.lock = threading.Lock()
        self.count = self.bytes = 0

    def emit(self, value):
        with self.lock:
            value = dict(value, time=time.monotonic(), **self.binding)
            data = json.dumps(value, separators=(',', ':')) + '\n'
            if self.count >= 35 or self.bytes + len(data.encode()) > DIAGNOSTIC_CAP:
                raise RuntimeError('Diagnostic cap')
            self.stream.write(data)
            self.stream.flush()
            self.count += 1
            self.bytes += len(data.encode())

    def phase(self, name, state, **fields):
        self.emit(dict(kind='phase', phase=name, state=state, **fields))

    def snapshots(self, delays=(30, 60, 90)):
        # Daemon remains alive through threading._shutdown; no source lines,
        # function names, paths, local values, argv or environment are serialized.
        for delay in delays:
            time.sleep(delay)
            frames = sys._current_frames()
            threads = threading.enumerate()
            rows = []
            for thread in threads[:64]:
                frame = frames.get(thread.ident)
                locations = []
                while frame is not None and len(locations) < 64:
                    locations.append({'location': 'redacted', 'line': frame.f_lineno})
                    frame = frame.f_back
                rows.append(dict(id=thread.ident, native_id=thread.native_id,
                                 alive=thread.is_alive(), daemon=thread.daemon,
                                 frames=locations, truncated=frame is not None))
            self.emit(dict(kind='stack', threads=rows, truncated=len(threads) > 64,
                           child_ownership='unavailable'))


def suite_watchdog(stop, interval):
    while not stop.wait(interval):
        lines = [f'Timeout ({datetime.timedelta(seconds=interval)})!']
        for identity, frame in list(sys._current_frames().items())[:64]:
            lines.append(f'Thread 0x{identity:x} (most recent call first):')
            depth = 0
            while frame is not None and depth < 64:
                filename = json.dumps(frame.f_code.co_filename[:500], ensure_ascii=True)
                name = frame.f_code.co_name[:500]
                lines.append(f'  File {filename}, line {frame.f_lineno} in {name}')
                frame = frame.f_back
                depth += 1
            if frame is not None:
                lines.append('  ...')
            frame = None
            lines.append('')
        data = ('\n'.join(lines) + '\n').encode('utf-8', errors='backslashreplace')
        while data and not stop.is_set():
            try:
                written = os.write(2, data)
            except OSError:
                return
            if not written:
                return
            data = data[written:]


def lifecycle(factory, events, snapshot_delays=(30, 60, 90), watchdog_interval=300):
    failed = False
    result = None
    def phase(name, operation):
        nonlocal failed
        events.phase(name, 'start')
        try:
            value = operation()
        except BaseException as error:
            failed = True
            # Exception types can be user-defined; use a fixed category.
            category = type(error).__name__ if type(error).__module__ == 'builtins' and type(error).__name__ in EXCEPTIONS else 'Exception'
            events.phase(name, 'error', error=category)
            return None
        events.phase(name, 'end', **(totals(value) if name == 'suite' else {}))
        return value
    prepared = phase('setup', factory)
    if prepared is None:
        return 1
    suite, close, admission, account, resultclass = prepared
    stop_watchdog = threading.Event()
    threading.Thread(target=suite_watchdog, args=(stop_watchdog, watchdog_interval), daemon=True).start()
    try:
        result = phase('suite', lambda: unittest.TextTestRunner(verbosity=2, resultclass=resultclass).run(suite()))
    finally:
        stop_watchdog.set()
        # During-suite watchdog retained without a join; bounded, sanitized observer
        # replaces it for the previously unobserved post-suite/finalization tail.
        try:
            threading.Thread(target=events.snapshots, args=(snapshot_delays,), daemon=True).start()
        except RuntimeError:
            failed = True
            events.emit(dict(kind='stack', threads=[], truncated=True, child_ownership='unavailable'))
    phase('close', close)
    phase('admission', admission)
    def accounting():
        if result is None:
            return True
        return bool(account(result))
    outcome = phase('accounting', accounting)
    code = int(failed or outcome is not False or result is None or not result.wasSuccessful())
    events.phase('exit', 'start', code=code, **totals(result))
    events.phase('exit', 'end')
    return code


def validate(path, binding=None, launched=0, collected=None):
    with path.open('rb') as stream:
        data = stream.read(DIAGNOSTIC_CAP + 1)
    return validate_data(data, binding, launched, collected)


def validate_data(data, binding=None, launched=0, collected=None):
    if len(data) > DIAGNOSTIC_CAP or not data.endswith(b'\n'):
        raise ValueError('Diagnostic size or truncated marker')
    records = [strict_json(line) for line in data.splitlines()]
    if len(records) > 35:
        raise ValueError('Event cap')
    phase_index = 0
    active = False
    previous = 0
    stacks = 0
    failed = False
    exit_record = None
    suite_totals = None
    collected = time.monotonic() if collected is None else collected
    for record in records:
        if type(record) is not dict:
            raise ValueError('Object required')
        if not BINDING <= record.keys():
            raise ValueError('Missing binding')
        if (type(record['invocation']) is not str or len(record['invocation']) != 32
                or any(c not in '0123456789abcdef' for c in record['invocation'])
                or type(record['job']) is not str or len(record['job']) != 64
                or any(c not in '0123456789abcdef' for c in record['job'])
                or type(record['pid']) is not int or record['pid'] <= 0
                or type(record['mode']) is not str or record['mode'] not in ('suite', 'pass', 'fail', 'synthetic')):
            raise ValueError('Binding schema')
        actual = {k: record[k] for k in BINDING}
        if binding is None:
            binding = actual
        if actual != binding:
            raise ValueError('Mixed invocation')
        stamp = record.get('time')
        if type(stamp) not in (float, int) or not math.isfinite(stamp) or stamp < previous or not launched <= stamp <= collected:
            raise ValueError('Invalid monotonic time')
        previous = stamp
        if record.get('kind') == 'stack':
            stacks += 1
            if (set(record) != {'kind', 'time', 'threads', 'truncated', 'child_ownership'} | BINDING
                    or stacks > 3 or record['child_ownership'] != 'unavailable'
                    or phase_index < 2 or type(record['truncated']) is not bool
                    or type(record['threads']) is not list or len(record['threads']) > 64):
                raise ValueError('Stack schema')
            for row in record['threads']:
                if type(row) is not dict or set(row) != {'id', 'native_id', 'alive', 'daemon', 'frames', 'truncated'}:
                    raise ValueError('Thread schema')
                if any(type(row[k]) is not bool for k in ('alive', 'daemon', 'truncated')):
                    raise ValueError('Thread flags')
                if any(row[k] is not None and (type(row[k]) is not int or row[k] <= 0) for k in ('id', 'native_id')):
                    raise ValueError('Thread identity')
                if type(row['frames']) is not list or len(row['frames']) > 64 or any(type(f) is not dict or set(f) != {'location', 'line'} or f['location'] != 'redacted'
                        or type(f['line']) is not int or f['line'] < 0 for f in row['frames']):
                    raise ValueError('Frame schema')
            continue
        allowed = {'kind', 'phase', 'state', 'time'} | BINDING
        if record.get('state') == 'error':
            allowed.add('error')
            if type(record.get('error')) is not str or record['error'] not in EXCEPTIONS:
                raise ValueError('Exception category')
            failed = True
        if record.get('phase') == 'suite' and record.get('state') == 'end':
            allowed.update(COUNTS)
            check_counts(record)
            suite_totals = {k: record[k] for k in COUNTS}
            if not (record['tests'] or record['errors'] or record['skips']):
                raise ValueError('Empty suite')
        if record.get('phase') == 'exit' and record.get('state') == 'start':
            allowed.update(('code', 'tests', 'failures', 'errors', 'skips'))
            check_counts(record)
            if type(record.get('code')) is not int or record['code'] not in (0, 1):
                raise ValueError('Exit code')
            if suite_totals is not None and {k: record[k] for k in COUNTS} != suite_totals:
                raise ValueError('Changed accounting')
            if record['code'] == 0 and (failed or not (record['tests'] or record['skips']) or record['failures'] or record['errors']):
                raise ValueError('False success')
            if not failed and binding['mode'] in ('pass', 'fail'):
                want = dict(tests=1, failures=int(binding['mode'] == 'fail'), errors=0, skips=0)
                if {k: record[k] for k in COUNTS} != want or record['code'] != want['failures']:
                    raise ValueError('Probe accounting')
            exit_record = record
        if (set(record) != allowed or record.get('kind') != 'phase' or phase_index >= len(PHASES)
                or record.get('phase') != PHASES[phase_index]):
            raise ValueError('Phase schema/order')
        if not active and record['state'] == 'start':
            active = True
        elif active and record['state'] in ('end', 'error'):
            active = False
            phase_index += 1
        else:
            raise ValueError('Phase state')
    return records, phase_index == len(PHASES) and not active, failed, exit_record



def validate_receipt(data):
    if len(data) > 2 * DIAGNOSTIC_CAP:
        raise ValueError('Receipt cap')
    r = strict_json(data)
    if type(r) is not dict:
        raise ValueError('Receipt object')
    if r.get('reason') == 'entry_refusal':
        if set(r) == {'success', 'reason'} and r['success'] is False:
            return r
        if (set(r) != {'success', 'qualification', 'reason', 'mode', 'job', 'capture', 'error'}
                or r['success'] is not False or r['qualification'] is not False
                or r['mode'] not in (None, 'pass', 'fail', 'suite')
                or type(r['error']) is not str or r['error'] not in EXCEPTIONS
                or (r['job'] is not None and (type(r['job']) is not str or len(r['job']) != 64
                    or any(c not in '0123456789abcdef' for c in r['job'])))
                or (r['mode'] is None and (r['job'] is not None or r['capture'] is not None))):
            raise ValueError('Entry refusal')
        if r['capture'] is not None:
            if type(r['capture']) is not dict or r['job'] is None:
                raise ValueError('Entry refusal capture')
            capture = validate_receipt(json.dumps(r['capture'], allow_nan=False))
            if capture.get('job') != r['job'] or capture.get('qualification') is True:
                raise ValueError('Entry refusal binding')
            if capture.get('reason') != 'capture_unavailable' and (
                    not {'pid', 'eof', 'returncode', 'invocation', 'mode'} <= capture.keys()
                    or capture['mode'] != r['mode']):
                raise ValueError('Entry refusal mode')
        return r
    if r.get('reason') == 'capture_unavailable':
        if (set(r) != {'success', 'reason', 'job', 'cleanup_uncertainty'}
                or r['success'] is not False or r['cleanup_uncertainty'] is not True
                or type(r['job']) is not str or len(r['job']) != 64
                or any(c not in '0123456789abcdef' for c in r['job'])):
            raise ValueError('Unavailable capture')
        return r
    if r.get('reason') == 'allocation_refusal':
        if 'capture' in r:
            if (set(r) != {'kind', 'phase', 'job', 'capture', 'success', 'qualification', 'reason', 'error'}
                    or r['kind'] not in ('sparse', 'tail') or r['success'] is not False
                    or r['qualification'] is not False or type(r['error']) is not str or r['error'] not in EXCEPTIONS
                    or (r['kind'] == 'sparse' and r['phase'] != 'sparse')
                    or (r['kind'] == 'tail' and r['phase'] not in TAIL_PHASES)
                    or (r['job'] is not None and (type(r['job']) is not str or len(r['job']) != 64
                        or any(c not in '0123456789abcdef' for c in r['job'])))):
                raise ValueError('Budget refusal')
            if r['capture'] is not None:
                if r['kind'] != 'sparse' or type(r['capture']) is not dict:
                    raise ValueError('Refusal capture')
                capture = validate_receipt(json.dumps(r['capture'], allow_nan=False))
                if capture.get('job') != r['job'] and ('job' in capture or capture.get('pid') is not None):
                    raise ValueError('Refusal binding')
            return r
        if r.get('kind') == 'tail':
            if (set(r) != {'kind', 'phase', 'admitted', 'reason'} or r['admitted'] is not False
                    or r['phase'] not in TAIL_PHASES):
                raise ValueError('Tail refusal')
        elif (set(r) == {'success', 'reason', 'mode'} and r['success'] is False
              and r['mode'] in ('pass', 'fail', 'suite')):
            pass
        elif not (set(r) == {'success', 'reason', 'qualification'}
                  and r['success'] is False and r['qualification'] is False):
            raise ValueError('Allocation refusal')
        return r
    if r.get('kind') == 'tail':
        if (set(r) != {'kind', 'phase', 'admitted', 'job', 'remaining', 'action_cap'}
                or r['admitted'] is not True or type(r['action_cap']) is not int or r['action_cap'] != 60
                or type(r['remaining']) not in (int, float) or not math.isfinite(r['remaining'])
                or r['remaining'] < 65
                or r['phase'] not in TAIL_PHASES
                or type(r['job']) is not str or len(r['job']) != 64
                or any(c not in '0123456789abcdef' for c in r['job'])):
            raise ValueError('Tail receipt')
        return r
    if r.get('kind') == 'sparse':
        if (set(r) != {'kind', 'capture', 'qualification', 'job', 'success'}
                or type(r['capture']) is not dict or r['qualification'] is not False
                or type(r['success']) is not bool or r['job'] != r['capture'].get('job')):
            raise ValueError('Workload receipt')
        capture = validate_receipt(json.dumps(r['capture'], allow_nan=False))
        if r['success'] and not (capture['returncode'] == 0 and capture['reaped']
                and all(capture['eof'].values()) and capture['reason'] is None
                and not capture['cleanup_uncertainty']):
            raise ValueError('Workload success')
        return r
    refusal = {'success', 'valid', 'complete', 'reaped', 'pid', 'reason', 'cleanup_uncertainty'}
    if set(r) == refusal:
        if (any(r[k] is not False for k in ('success', 'valid', 'complete', 'reaped', 'cleanup_uncertainty'))
                or r['pid'] is not None or r['reason'] != 'setup_error'):
            raise ValueError('Refusal schema')
        return r
    required = refusal | {'eof', 'bytes', 'returncode', 'last_phase', 'escaped_descendants', 'timeout'}
    optional = {'invocation', 'mode', 'job', 'launched', 'collected', 'events',
                'diagnostic_error', 'cleanup_error', 'qualification'}
    if not required <= r.keys() or r.keys() - required - optional:
        raise ValueError('Receipt schema')
    if any(type(r[k]) is not bool for k in ('success', 'valid', 'complete', 'reaped', 'cleanup_uncertainty')):
        raise ValueError('Receipt flags')
    if ('qualification' in r and (type(r['qualification']) is not bool
            or r['qualification'] and not (r['success'] and r.get('mode') == 'suite'))):
        raise ValueError('Qualification')
    if (type(r['eof']) is not dict or set(r['eof']) != {'stdout', 'stderr'}
            or any(type(v) is not bool for v in r['eof'].values())
            or type(r['bytes']) is not int or not 0 <= r['bytes'] <= OUTPUT_CAP + 65536
            or type(r['timeout']) not in (float, int) or not math.isfinite(r['timeout'])
            or not 0 < r['timeout'] <= 60 * 60 - RESERVE
            or r['escaped_descendants'] != 'unavailable'):
        raise ValueError('Receipt capture')
    if r['reason'] not in (None, 'spawn_error', 'collection_error', 'cancelled', 'deadline', 'no_eof', 'output_cap'):
        raise ValueError('Receipt reason')
    if r['pid'] is not None and (type(r['pid']) is not int or r['pid'] <= 0):
        raise ValueError('Receipt child')
    if r['returncode'] is not None and type(r['returncode']) is not int:
        raise ValueError('Receipt exit')
    if r['reaped'] != (r['returncode'] is not None):
        raise ValueError('Receipt reap')
    if r['pid'] is None:
        if (r['reaped'] or r['bytes'] or any(r['eof'].values())
                or r['valid'] or r['complete'] or r['success']
                or r['reason'] != 'spawn_error' or not r['cleanup_uncertainty']
                or 'launched' in r or 'collected' in r):
            raise ValueError('Absent child')
    else:
        if (not {'invocation', 'mode', 'job', 'launched', 'collected'} <= r.keys()
                or type(r['invocation']) is not str or len(r['invocation']) != 32
                or any(c not in '0123456789abcdef' for c in r['invocation'])
                or type(r['job']) is not str or len(r['job']) != 64
                or any(c not in '0123456789abcdef' for c in r['job'])
                or type(r['mode']) is not str or r['mode'] not in ('pass', 'fail', 'suite', 'synthetic')):
            raise ValueError('Receipt binding')
        if (r['reason'] == 'spawn_error'
                or ((not r['reaped'] or not all(r['eof'].values()) or 'cleanup_error' in r)
                    and not r['cleanup_uncertainty'])):
            raise ValueError('Receipt cleanup')
    if 'collected' in r and 'launched' not in r:
        raise ValueError('Missing launch')
    for k in ('launched', 'collected'):
        if k in r and (type(r[k]) not in (int, float) or not math.isfinite(r[k]) or r[k] < 0):
            raise ValueError('Receipt interval')
    # Collection ends after cleanup even when events are absent or incomplete.
    # Its boundary does not assert that the child exited or reached both EOFs.
    if 'collected' in r and r['collected'] < r['launched']:
        raise ValueError('Receipt interval order')
    for k, v in (('diagnostic_error', 'invalid_or_unavailable'), ('cleanup_error', 'owned_child_cleanup_incomplete')):
        if k in r and r[k] != v:
            raise ValueError('Receipt error')
    if r['valid']:
        if type(r.get('events')) is not list or len(r['events']) > 35:
            raise ValueError('Receipt events')
        events, complete, failed, final = validate_data(
            (''.join(json.dumps(e, allow_nan=False) + '\n' for e in r['events'])).encode(),
            {k: r[k] for k in BINDING}, r['launched'], r['collected'])
        phases = [e for e in events if e['kind'] == 'phase']
        if r['complete'] != complete or r['last_phase'] != (phases[-1] if phases else None):
            raise ValueError('Receipt phase')
        success = (complete and not failed and final['code'] == 0 and r['returncode'] == 0
                   and r['reaped'] and all(r['eof'].values()) and not r['cleanup_uncertainty']
                   and r['reason'] is None)
        if r['success'] != success:
            raise ValueError('Receipt success')
    elif r['success'] or r['complete'] or r['last_phase'] is not None or 'events' in r:
        raise ValueError('Unvalidated receipt')
    return r


def allocation_clock_ns():
    # Explicit Darwin clock IDs share an origin across Python versions; the
    # system Python's time.monotonic() may instead start at each process.
    try:
        if sys.platform != 'darwin':
            raise ValueError('Darwin allocation clock required')
        value = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    except (AttributeError, OSError) as error:
        raise ValueError('Allocation clock unavailable') from error
    if type(value) is not int or value < 0:
        raise ValueError('Invalid allocation clock')
    return value


def remainder(start_ns, minutes, now_ns=None, *, tail=False):
    now_ns = allocation_clock_ns() if now_ns is None else now_ns
    if (type(minutes) is not int or minutes not in (15, 20, 30, 45, 60)
            or type(start_ns) is not int or type(now_ns) is not int
            or not 0 <= start_ns <= now_ns or type(tail) is not bool):
        raise ValueError('Invalid worker allocation')
    limit_ns = (minutes * 60 - (10 if tail else RESERVE)) * 10**9
    return max(0, min(limit_ns, start_ns + limit_ns - now_ns)) / 10**9


class CaptureResult:
    """One invocation's capture, independent of receipt persistence.

    None means positively prelaunch. An unavailable record makes no assertion
    about launch or closure. A collected receipt retains the actual observations.
    """
    def __init__(self):
        self.capture = None


def supervise(argv, event_path, timeout, *, output_cap=OUTPUT_CAP, echo=True, cancelled=None,
              mode='synthetic', job=None, result=None):
    result = CaptureResult() if result is None else result
    result.capture = None
    event_path = Path(event_path)
    receipt_path = event_path.with_suffix(event_path.suffix + '.receipt.json')
    # Reserve the receipt before launching; never replace earlier evidence.
    with receipt_path.open('x', encoding='utf-8') as stream:
        receipt = dict(success=False, valid=False, complete=False, reaped=False,
                       pid=None, reason='setup_error', cleanup_uncertainty=False)
        try:
            if event_path.exists() or event_path.is_symlink():
                raise ValueError('Preexisting events')
            if mode not in ('suite', 'pass', 'fail', 'synthetic'):
                raise ValueError('Fixed mode required')
            invocation = uuid.uuid4().hex
            job = job or ('0' * 64)
            if type(job) is not str or len(job) != 64 or any(c not in '0123456789abcdef' for c in job):
                raise ValueError('Job binding')
        except (Exception, KeyboardInterrupt):
            pass
        else:
            # Do not infer no launch if collection unexpectedly cannot return.
            result.capture = dict(success=False, reason='capture_unavailable',
                                  job=job, cleanup_uncertainty=True)
            receipt = _supervise(argv, event_path, timeout, output_cap=output_cap,
                                 echo=echo, cancelled=cancelled, mode=mode,
                                 invocation=invocation, job=job)
            # A missing or non-object result supplies no capture. Keep the
            # unavailable marker; collection cannot restore prelaunch None.
            if type(receipt) is not dict:
                raise ValueError('Collection capture object')
            # Internal receipt/event consistency cannot identify this call.
            # Reject another invocation before exposing any of its closure.
            if any(type(receipt.get(key)) is not str or receipt[key] != expected
                   for key, expected in (('invocation', invocation), ('mode', mode), ('job', job))):
                raise ValueError('Collection capture binding')
            # Publish to the caller before validation or any persistence step.
            # Keep exceptions unchanged; they must still fail the invocation.
            result.capture = receipt
        data = json.dumps(receipt, allow_nan=False, sort_keys=True) + '\n'
        validate_receipt(data)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return receipt


def _supervise(argv, event_path, timeout, *, output_cap, echo, cancelled, mode, invocation, job):
    """Capture only a newly spawned direct child, with bounded post-reap drain."""
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0 or timeout > 60 * 60 - RESERVE:
        raise ValueError('Suite deadline')
    receipt = dict(pid=None, eof={'stdout': False, 'stderr': False}, bytes=0,
                   reason=None, reaped=False, returncode=None, last_phase=None,
                   escaped_descendants='unavailable', cleanup_uncertainty=False,
                   valid=False, complete=False, success=False, timeout=timeout,
                   invocation=invocation, mode=mode, job=job)
    selector = selectors.DefaultSelector()
    launched = time.monotonic()
    env = dict(os.environ, CI_INVOCATION=invocation, CI_MODE=mode, CI_JOB_BINDING=job)
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    except OSError:
        receipt.update(reason='spawn_error', cleanup_uncertainty=True)
        selector.close()
        return receipt
    receipt['pid'] = child.pid
    receipt['launched'] = launched
    deadline = time.monotonic() + timeout
    ended = None
    try:
        for name in ('stdout', 'stderr'):
            stream = getattr(child, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map() or child.poll() is None:
            now = time.monotonic()
            if cancelled is not None and cancelled():
                receipt['reason'] = 'cancelled'; break
            if now >= deadline:
                receipt['reason'] = 'deadline'; break
            if child.poll() is not None:
                ended = now if ended is None else ended
                if now - ended >= 2:
                    receipt['reason'] = 'no_eof'; break
            for key, _ in selector.select(min(.05, max(0, deadline - now))):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    receipt['eof'][key.data] = True
                    selector.unregister(key.fileobj)
                    continue
                receipt['bytes'] += len(data)
                if receipt['bytes'] > output_cap:
                    receipt['reason'] = 'output_cap'; break
                if echo:
                    getattr(sys, key.data).buffer.write(data)
                    getattr(sys, key.data).flush()
            if receipt['reason']:
                break
    except BaseException as error:
        receipt['reason'] = 'collection_error'
    finally:
        # Popen retains wait ownership; no PID search, group signalling or
        # assumptions about children of this child. Preserve uncertain cleanup.
        try:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            receipt['cleanup_uncertainty'] = True
            receipt['cleanup_error'] = 'owned_child_cleanup_incomplete'
        receipt['reaped'] = child.poll() is not None
        receipt['returncode'] = child.returncode
        receipt['cleanup_uncertainty'] |= not all(receipt['eof'].values()) or not receipt['reaped']
        for resource in (selector, child.stdout, child.stderr):
            try:
                resource.close()
            except Exception:
                receipt['reason'] = 'collection_error'
                receipt['cleanup_uncertainty'] = True
    try:
        receipt['collected'] = time.monotonic()
        records, complete, failed, exit_record = validate(event_path,
            dict(invocation=invocation, mode=mode, job=job, pid=child.pid),
            launched, receipt['collected'])
        if exit_record is not None and child.returncode != exit_record['code'] and receipt['reason'] is None:
            raise ValueError('Exit mismatch')
        receipt.update(valid=True, complete=complete, events=records)
        phases = [r for r in records if r['kind'] == 'phase']
        receipt['last_phase'] = phases[-1] if phases else None
        receipt['success'] = (complete and not failed and exit_record['code'] == 0
                              and child.returncode == 0 and receipt['reason'] is None
                              and not receipt['cleanup_uncertainty'])
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        receipt['diagnostic_error'] = 'invalid_or_unavailable'
    return receipt


CONTEXTUAL_TEST = 'test_fskit.FSKitInterfaces.test_contextual_and_legacy_callbacks_and_production_builds'
ACTIVATION_TEST = 'test_fskit.FSKitInterfaces.test_managed_activation_and_pending_lock_lifetime'
ADAPTER_TEST = 'test_native_activation.ActivationAdapter.test_producer_consumer_and_terminal_callback_drain'


class ContextualResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.contextual_successes = 0
        self.activation_successes = 0

    def addSuccess(self, test):
        super().addSuccess(test)
        if test.id() == CONTEXTUAL_TEST:
            self.contextual_successes += 1
        if test.id() == ACTIVATION_TEST:
            self.activation_successes += 1


def account_result(result, probe, require_contextual, contextual_test):
    if probe:
        return not result.wasSuccessful() or bool(result.skipped) or result.testsRun != 1
    capability_skips = [
        (test, reason) for test, reason in result.skipped
        if test.id() == 'setUpClass (test_fskit.FSKitInterfaces)'
        and reason.startswith('FSKit capability unavailable: ')
    ]
    activation_successes = getattr(result, 'activation_successes', 0)
    activation_covered = type(activation_successes) is int and activation_successes == 1
    # The managed selector compiles its driver and runs this exact adapter test,
    # asserting one successful, unskipped nested result before it can pass.
    adapter_skips = [
        (test, reason) for test, reason in result.skipped
        if test.id() == ADAPTER_TEST and reason == 'requires compiled offline activation driver'
        and (activation_covered or (not require_contextual and len(capability_skips) == 1))
    ]
    ownership_tests = {
        'test_ownership.Ownership.' + name for name in (
            'test_privileged_copy_clone_move_preserve_foreign_ownership',
            'test_unprivileged_copy_refuses_loss_clone_uses_darwin_ownership_move_preserves',
            'test_move_round_trip_preserves_acl_xattrs_resource_fork_and_aliases',
            'test_image_import_preserves_foreign_ownership_and_aliases',
        )
    }
    ownership_skips = [
        (test, reason) for test, reason in result.skipped
        if test.id() in ownership_tests
        and reason.startswith('Ownership fixtures require root or passwordless sudo: ')
    ]
    sigkill_tests = {
        'test_sigkill.ProcessDeath.' + name for name in (
            'test_killed_copy_clone_preserve_source_and_allow_partial_destination',
            'test_killed_move_has_exactly_one_complete_inode_tree',
            'test_killed_preparation_is_unpublished_reported_and_not_cached',
            'test_killed_rollback_reconciles_both_sides_of_exchange_without_replay',
        )
    }
    sigkill_skips = [
        (test, reason) for test, reason in result.skipped
        if test.id() in sigkill_tests
        and reason.startswith('SIGKILL pause hook unavailable: ')
    ]
    sigkill_root_tests = {
        'test_sigkill.ProcessDeath.' + name for name in (
            'test_killed_preparation_is_unpublished_reported_and_not_cached',
            'test_killed_rollback_reconciles_both_sides_of_exchange_without_replay',
        )
    }
    sigkill_root_skips = [
        (test, reason) for test, reason in result.skipped
        if test.id() in sigkill_root_tests
        and reason == 'SIGKILL Git fixtures require a non-root test process'
    ]
    allowed_skips = capability_skips + adapter_skips + ownership_skips + sigkill_skips + sigkill_root_skips
    qualification = os.environ.get('STALLIONFS_QUALIFICATION') == '1'
    qualification_skips = [
        (test, reason) for test, reason in result.skipped
        if qualification and test.id() in ownership_tests | sigkill_tests | sigkill_root_tests
    ]
    for test, reason in qualification_skips:
        print(f'Qualification requires {test.id()}: skipped: {reason}', file=sys.stderr)
    for _, reason in allowed_skips:
        print(reason, file=sys.stderr)
    required_skips = (qualification or os.environ.get('STALLIONFS_TEST_IMAGES') == '1') and [
        entry for entry in result.skipped if entry not in allowed_skips
    ]
    if required_skips:
        print('Required filesystem tests were skipped.', file=sys.stderr)
    missing_contextual = require_contextual and result.contextual_successes != 1
    if missing_contextual:
        print(f'Required {contextual_test} successes: expected 1, observed {result.contextual_successes}', file=sys.stderr)
    missing_activation = require_contextual and not activation_covered
    if missing_activation:
        print(f'Required {ACTIVATION_TEST} successes: expected 1, observed {activation_successes}', file=sys.stderr)
    return not result.wasSuccessful() or bool(required_skips) or bool(qualification_skips) or missing_contextual or missing_activation


def installed(probe=None):
    import os
    from pathlib import Path
    import platform
    import re
    import subprocess
    import sys
    import unittest
    import stallionfs
    from stallionfs import images, _scan

    require_contextual = os.environ.get('STALLIONFS_REQUIRE_CONTEXTUAL_FSKIT') == '1'
    contextual_test = CONTEXTUAL_TEST

    def require_contextual_environment():
        host = (sys.platform, platform.mac_ver()[0], platform.machine())
        print('Contextual FSKit host:', host, flush=True)
        def version(label, argv):
            child = subprocess.run(argv, capture_output=True, text=True, timeout=15)
            print(f'{label}: {child.stdout.strip()!r}; stderr: {child.stderr.strip()!r}', flush=True)
            child.check_returncode()
            return child.stdout.strip()
        build = version('macOS build', ['/usr/bin/sw_vers', '-buildVersion'])
        xcode = version('Selected Xcode', ['/usr/bin/xcodebuild', '-version'])
        sdk = version('Selected macOS SDK', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version'])
        if (host[0] != 'darwin' or not re.fullmatch(r'\d+(?:\.\d+)*', host[1])
                or int(host[1].split('.')[0]) < 27 or host[2] != 'arm64'
                or not re.fullmatch(r'\d+[A-Z]\d+[a-z]?', build)
                or not re.fullmatch(r'Xcode 27\.1\nBuild version [A-Za-z0-9]+', xcode)
                or sdk != '27.0'):
            raise RuntimeError('Contextual FSKit requires macOS 27+ ARM64 with selected Xcode 27.1 and SDK 27.0')

    if require_contextual:
        require_contextual_environment()

    checkout = Path(os.environ['GITHUB_WORKSPACE']).resolve()
    assert not Path(stallionfs.__file__).resolve().is_relative_to(checkout)
    assert not Path(_scan.__file__).resolve().is_relative_to(checkout)
    import importlib.util
    spec = importlib.util.spec_from_file_location('ci_build', checkout / 'tools/ci_build.py')
    controller = importlib.util.module_from_spec(spec); spec.loader.exec_module(controller)
    temporary = Path(os.environ['RUNNER_TEMP']).resolve()
    wheel_receipts = []
    retain_wheel = not probe and os.environ.get('CI_RETAIN_INTEL_WHEEL') == '1'
    receipt_option = {'wheel_receipt': wheel_receipts.append} if retain_wheel else {}
    admitted = controller.initialize_installed(checkout, temporary / 'qualified-wheel', **receipt_option)
    admitted['check']()
    import sysconfig
    native_cli = Path(sysconfig.get_path('scripts')) / 'stallionfs'
    assert native_cli.is_absolute() and native_cli.is_relative_to(Path(sys.prefix).resolve())
    with Path(os.environ['GITHUB_ENV']).open('a') as output:
        output.write('CI_STALLIONFS=' + str(native_cli) + '\n')
    sys.path.insert(0, str(checkout / 'tests'))
    from image_failure_diagnostics import install
    diagnostics = install(images, Path(os.environ['RUNNER_TEMP']).resolve() / 'image-failure-diagnostics')
    def suite():
        if probe:
            class Probe(unittest.TestCase):
                def runTest(self):
                    self.assertTrue(probe == 'pass', 'controlled CI assertion failure')
            return unittest.TestSuite([Probe()])
        return unittest.defaultTestLoader.discover(str(checkout / 'tests'))
    def account(result):
        return account_result(result, probe, require_contextual, contextual_test)
    def final_admission():
        admitted['check']()
        if not probe:
            # Preserve the original post-test runtime/doctor obligations inside
            # the same retained suite-child deadline and admission boundary.
            container = Path(os.environ['CI_CONTAINER'])
            subprocess.run([sys.executable, '-I', '-B', str(container / 'bootstrap.py'),
                            'check', str(container)], check=True)
            subprocess.run([str(native_cli), '--root',
                            str(Path(os.environ['RUNNER_TEMP']) / 'stallionfs-smoke'),
                            'doctor'], check=True)
            admitted['check']()
            if retain_wheel:
                try:
                    contract = admitted['contract']
                    candidate = temporary / 'installed-wheel-candidate.json'
                    pending = candidate.with_suffix('.pending')
                    controller.write(pending, {
                        'job': os.environ['CI_JOB_BINDING'], 'pid': os.getpid(),
                        'invocation': os.environ['CI_INVOCATION'], 'source_sha': os.environ['GITHUB_SHA'],
                        'build_result_sha256': wheel_receipts[0], 'descriptor_sha256': contract['descriptor_sha256'],
                        'inventory_sha256': contract['input_inventory_sha256']})
                    os.link(pending, candidate)
                    pending.unlink()
                except Exception:
                    print('Installed Intel wheel candidate unavailable', file=sys.stderr)
    return suite, diagnostics.close, final_admission, account, ContextualResult


def exception_category(error):
    category = type(error).__name__
    if type(error).__module__ != 'builtins' or category not in EXCEPTIONS:
        category = 'OSError' if isinstance(error, OSError) else 'Exception'
    return category


def write_refusal(receipt, label, category, *, token=None):
    """Persist a validated failure without replacing earlier evidence."""
    try:
        token = uuid.uuid4().hex if token is None else token
        root = Path(os.environ['RUNNER_TEMP']).resolve()
        for index in range(4):
            path = root / ('suite-closure-refusal-' + token + '-' + str(index) + '.json')
            try:
                with path.open('x') as stream:
                    data = json.dumps(receipt, allow_nan=False) + '\n'
                    validate_receipt(data)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                return 1
            except FileExistsError:
                continue
        raise FileExistsError('Refusal targets exhausted')
    except Exception:
        # Keep the primary error even if its refusal cannot be persisted.
        print(label + ' refusal: ' + category + '; receipt unavailable', file=sys.stderr)
        return 1


def entry_refusal(mode, job, capture, error):
    category = exception_category(error)
    receipt = dict(success=False, qualification=False, reason='entry_refusal',
                   mode=mode, job=job, capture=capture, error=category)
    return write_refusal(receipt, 'entry', category)


def main():
    state = dict(mode=None, job=None, result=CaptureResult())
    try:
        return _main(state)
    except (Exception, KeyboardInterrupt) as error:
        return entry_refusal(state['mode'], state['job'], state['result'].capture, error)


def _main(state):
    if len(sys.argv) > 1:
        if len(sys.argv) != 4 or sys.argv[1] != '--child' or sys.argv[3] not in ('suite', 'pass', 'fail'):
            raise ValueError('Fixed CI entry required')
        mode = sys.argv[3]
        if os.environ['CI_MODE'] != mode:
            raise ValueError('Mode mismatch')
        return lifecycle(lambda: installed(None if mode == 'suite' else mode), Events(sys.argv[2]))
    root = Path(os.environ['RUNNER_TEMP']).resolve() / 'suite-closure'
    root.mkdir(mode=0o700)
    import importlib.util
    spec = importlib.util.spec_from_file_location('ci_job_budget', Path(__file__).with_name('ci_job_budget.py'))
    budget_module = importlib.util.module_from_spec(spec); spec.loader.exec_module(budget_module)
    # Budget loader shares this module without relying on the working directory.
    budget_module.entry_module = type('Entry', (), dict(strict_json=staticmethod(strict_json), remainder=staticmethod(remainder)))
    cancelled = []
    previous = {s: signal.signal(s, lambda signum, frame: cancelled.append(signum)) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        for mode in ('pass', 'fail', 'suite'):
            job = None
            result = CaptureResult()
            state.update(mode=mode, job=None, result=result)
            events = root / (mode + '.jsonl')
            try:
                # Bind the attempted allocation even if claiming its phase fails.
                _, job, _ = budget_module.load()
                state['job'] = job
                job, budget = budget_module.claim(mode)
                state['job'] = job
                receipt = dict(supervise([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                                     '--child', str(events), mode], events, budget, cancelled=lambda: bool(cancelled), mode=mode, job=job, result=result))
                if receipt.get('reason') == 'setup_error':
                    receipt['mode'] = mode
                receipt['qualification'] = mode == 'suite' and receipt['success']
                with (root / (mode + '.json')).open('x') as stream:
                    data = json.dumps(receipt, allow_nan=False, sort_keys=True) + '\n'
                    if receipt.get('reason') != 'setup_error':
                        validate_receipt(data)
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
                if mode == 'fail':
                    exits = [r for r in receipt.get('events', []) if r.get('phase') == 'exit' and r['state'] == 'start']
                    expected = (receipt['valid'] and receipt['complete'] and receipt['reaped']
                                and receipt['returncode'] == 1 and receipt['reason'] is None
                                and not receipt['cleanup_uncertainty'] and len(exits) == 1
                                and exits[0]['failures'] == 1 and exits[0]['errors'] == 0
                                and exits[0]['tests'] == 1 and exits[0]['skips'] == 0
                                and not any(r.get('state') == 'error' for r in receipt['events']))
                    if not expected:
                        return 1
                elif not receipt['success']:
                    return 1
                budget_module.finish(mode, job)
            except (Exception, KeyboardInterrupt) as error:
                return entry_refusal(mode, job, result.capture, error)

        return 0
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    sys.exit(main())
