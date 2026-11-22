"""Retained worker allocation and ordered consumption within the existing limit."""
import hashlib
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import signal
import time
import uuid

def entry_module_load():
    import importlib.util
    spec = importlib.util.spec_from_file_location('ci_test_entry', Path(__file__).with_name('ci_test_entry.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


IDENTITY = ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB', 'CI_WORKER')
ALLOCATION_SCHEMA = 1
ALLOCATION_CLOCK = 'darwin-CLOCK_MONOTONIC_RAW-ns-v1'
NS = 10**9
SPARSE_WORK_SECONDS = 506  # 480 s existing command maxima, plus 26 s cleanup/wrapper margin.
SPARSE_ADMISSION_SECONDS = 30
SPARSE_SAMPLE_COUNT = 7
SPARSE_SAMPLE_INTERVAL = 4
SPARSE_SAMPLE_CAP = 16384


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(*, tail=False):
    entry = globals().get('entry_module')
    if entry is None:
        entry = entry_module_load()
    root = Path(os.environ['RUNNER_TEMP']).resolve()
    path = root / 'ci-allocation.json'
    with path.open('rb') as stream:
        data = stream.read(4097)
    if len(data) > 4096 or digest(data) != os.environ['CI_ALLOCATION_SHA256']:
        raise ValueError('Allocation changed')
    record = entry.strict_json(data)
    if (type(record) is not dict
            or set(record) != {'schema', 'clock', 'start_ns', 'minutes', 'identity', 'token'}
            or type(record['schema']) is not int or record['schema'] != ALLOCATION_SCHEMA
            or type(record['clock']) is not str or record['clock'] != ALLOCATION_CLOCK):
        raise ValueError('Allocation schema')
    expected = {key: os.environ[key] for key in IDENTITY}
    if (record['identity'] != expected or any(type(v) is not str or not v for v in expected.values())
            or type(record['token']) is not str or len(record['token']) != 32
            or any(c not in '0123456789abcdef' for c in record['token'])
            or type(record['start_ns']) is not int or type(record['minutes']) is not int):
        raise ValueError('Allocation identity')
    remaining = entry.remainder(record['start_ns'], record['minutes'], tail=tail)
    if remaining <= 0:
        raise ValueError('Allocation exhausted')
    return record, digest(data), remaining


def claim(phase):
    record, job, remaining = load()
    root = Path(os.environ['RUNNER_TEMP']).resolve()
    # A retained phase ledger refuses replay or reset within an honest job.
    order = ('sparse', 'pass', 'fail', 'suite') if os.environ.get('CI_SPARSE_REQUIRED') == '1' else ('pass', 'fail', 'suite')
    index = order.index(phase)
    for earlier in order[:index]:
        with (root / ('ci-phase-' + earlier + '.json')).open('rb') as stream:
            data = stream.read(1025)
        if len(data) > 1024:
            raise ValueError('Ledger cap')
        entry = globals().get('entry_module')
        if entry is None:
            entry = entry_module_load()
        prior = entry.strict_json(data)
        if type(prior) is not dict or type(prior.get('complete')) is not bool or prior != {'job': job, 'phase': earlier, 'complete': True}:
            raise ValueError('Missing prior phase')
    path = root / ('ci-phase-' + phase + '.json')
    with path.open('x') as stream:
        json.dump({'job': job, 'phase': phase, 'complete': False}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    return job, remaining


def finish(phase, job):
    record, current, remaining = load()
    if current != job:
        raise ValueError('Allocation changed')
    path = Path(os.environ['RUNNER_TEMP']).resolve() / ('ci-phase-' + phase + '.json')
    with path.open('w') as stream:
        json.dump({'job': job, 'phase': phase, 'complete': True}, stream)
        stream.flush()
        os.fsync(stream.fileno())


def write_receipt(entry, stream, receipt):
    data = json.dumps(receipt, allow_nan=False) + '\n'
    entry.validate_receipt(data)
    stream.write(data)
    stream.flush()
    os.fsync(stream.fileno())


def refusal(entry, kind, phase, job, capture, error):
    category = entry.exception_category(error)
    receipt = dict(kind=kind, phase=phase, job=job, capture=capture,
                   success=False, qualification=False, reason='allocation_refusal', error=category)
    # Null capture is positively prelaunch; null job has no validated allocation.
    return entry.write_refusal(receipt, kind, category, token=uuid.uuid4().hex)


def sparse_remainder(entry):
    record, job, shared = load()
    raw = os.environ['CI_SPARSE_DEADLINE_NS']
    if not raw.isascii() or not raw.isdecimal() or str(int(raw)) != raw:
        raise ValueError('Sparse deadline')
    deadline = int(raw)
    job_deadline = record['start_ns'] + (record['minutes'] * 60 - entry.RESERVE) * NS
    if os.environ.get('CI_JOB_BINDING') != job or deadline > job_deadline:
        raise ValueError('Sparse allocation binding')
    return min(shared, (deadline - entry.allocation_clock_ns()) / NS)


def require_sparse_work_budget(entry=None):
    entry = entry_module_load() if entry is None else entry
    remaining = sparse_remainder(entry)
    if remaining < SPARSE_WORK_SECONDS:
        raise ValueError('Insufficient sparse work remainder')
    return remaining


def sparse_vm_sample(entry, root, index, timeout, job):
    # Reuse exact-child capture, including bounded reads and owned cleanup.
    # vm_stat produces no suite events; only its process/stream closure applies.
    buffers = [io.BytesIO(), io.BytesIO()]
    streams = [io.TextIOWrapper(buffer, encoding='utf-8') for buffer in buffers]
    with contextlib.redirect_stdout(streams[0]), contextlib.redirect_stderr(streams[1]):
        capture = entry.supervise(['/usr/bin/vm_stat'], root / ('vm-stat-%02d.jsonl' % index),
                                  timeout, output_cap=SPARSE_SAMPLE_CAP, echo=True, job=job)
    raw = [buffer.getvalue() for buffer in buffers]
    return capture, raw[0], raw[1]


def sparse_resource_admission():
    """Recheck valid transient memory shortage within the original phase clock."""
    entry = entry_module_load()
    root = Path(os.environ['RUNNER_TEMP']).resolve() / 'sparse-closure'
    with (root / 'admission.jsonl').open('x') as stream:
        def retain(row):
            data = json.dumps(row, allow_nan=False, sort_keys=True) + '\n'
            if len(data.encode()) > 128 * 1024:
                raise ValueError('Sparse observation cap')
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

        try:
            started = entry.allocation_clock_ns()
            window_end = started + SPARSE_ADMISSION_SECONDS * NS
            for index in range(1, SPARSE_SAMPLE_COUNT + 1):
                require_sparse_work_budget(entry)
                disk = shutil.disk_usage(root.parent).free
                if disk < 2 * 1024**3:
                    retain(dict(kind='disk', index=index, free_bytes=disk))
                    raise ValueError('Insufficient sparse disk headroom')
                _, job, _ = load()
                remaining = require_sparse_work_budget(entry)
                window = (window_end - entry.allocation_clock_ns()) / NS
                # The existing collector may spend 2 s terminating and 2 s killing/
                # waiting for its owned child. Keep that inside this window too.
                timeout = min(5, window - 4, remaining - SPARSE_WORK_SECONDS - 4)
                if timeout <= 0:
                    raise ValueError('Sparse admission window exhausted')
                sample_start = entry.allocation_clock_ns()
                capture, stdout, stderr = sparse_vm_sample(entry, root, index, timeout, job)
                row = dict(kind='sample', index=index, start_ns=sample_start,
                           end_ns=entry.allocation_clock_ns(), disk_bytes=disk, capture=capture,
                           raw_complete=(capture.get('reason') is None
                                         and capture.get('reaped') is True
                                         and capture.get('cleanup_uncertainty') is False
                                         and capture.get('eof') == {'stdout': True, 'stderr': True}
                                         and capture.get('bytes') == len(stdout) + len(stderr)),
                           stdout_base64=base64.b64encode(stdout).decode('ascii'),
                           stderr_base64=base64.b64encode(stderr).decode('ascii'))
                try:
                    if (capture.get('reason') is not None or capture.get('returncode') != 0
                            or capture.get('reaped') is not True
                            or capture.get('cleanup_uncertainty') is not False
                            or capture.get('eof') != {'stdout': True, 'stderr': True}
                            or not row['raw_complete']
                            or len(stdout) + len(stderr) > SPARSE_SAMPLE_CAP or stderr):
                        raise ValueError('Sparse sampler failure or uncertain closure')
                    text = stdout.decode('ascii')
                    pages = re.findall(r'page size of (\d+) bytes', text)
                    if len(pages) != 1 or int(pages[0]) not in (4096, 16384):
                        raise ValueError('Sparse sampler page size')
                    pairs = re.findall(r'^([^:\n]+):\s+(\d+)\.', text, re.MULTILINE)
                    fields = {key.strip(): int(value) for key, value in pairs}
                    if len(fields) != len(pairs):
                        raise ValueError('Sparse sampler duplicate counters')
                    counts = {key: fields[key] for key in
                              ('Pages free', 'Pages inactive', 'Pages speculative')}
                    memory = int(pages[0]) * sum(counts.values())
                    row.update(page_bytes=int(pages[0]), counters=counts, memory_bytes=memory)
                except Exception:
                    retain(dict(row, valid=False))
                    raise
                retain(dict(row, valid=True))
                require_sparse_work_budget(entry)
                if entry.allocation_clock_ns() > window_end:
                    raise ValueError('Sparse admission window exhausted')
                print('Large metadata admission:', index, disk, memory, flush=True)
                if memory >= 3 * 1024**3:
                    retain(dict(kind='admitted', samples=index,
                                time_ns=entry.allocation_clock_ns()))
                    return
                if index == SPARSE_SAMPLE_COUNT:
                    raise ValueError('Insufficient sparse memory headroom')
                remaining = require_sparse_work_budget(entry)
                window = (window_end - entry.allocation_clock_ns()) / NS
                if min(window, remaining - SPARSE_WORK_SECONDS) <= SPARSE_SAMPLE_INTERVAL + 4:
                    raise ValueError('Insufficient sparse recheck remainder')
                time.sleep(SPARSE_SAMPLE_INTERVAL)
            raise AssertionError('Sparse admission did not finish')
        except Exception as error:
            retain(dict(kind='refused', error=type(error).__name__, detail=str(error),
                        time_ns=entry.allocation_clock_ns()))
            raise


def sparse():
    entry = entry_module_load()
    job = capture = None
    result = entry.CaptureResult()
    previous = {}
    try:
        # Obtain the attempted job binding before any collision can reject it.
        _, job, _ = load()
        root = Path(os.environ['RUNNER_TEMP']).resolve() / 'sparse-closure'
        root.mkdir(mode=0o700)
        with (root / 'receipt.json').open('x') as stream:
            cancelled = []
            for sig in (signal.SIGTERM, signal.SIGINT):
                previous[sig] = signal.signal(sig, lambda signum, frame: cancelled.append(signum))
            job, remaining = claim('sparse')
            script = root / 'workload.py'
            script.write_text(sys.stdin.read(65537))
            if script.stat().st_size > 65536:
                raise ValueError('Workload cap')
            # Same exact-child capture/cleanup policy; never suite evidence.
            record, current, _ = load()
            if current != job:
                raise ValueError('Allocation changed')
            started = entry.allocation_clock_ns()
            deadline = min(started + 536 * NS,
                           record['start_ns'] + (record['minutes'] * 60 - entry.RESERVE) * NS)
            old_deadline = os.environ.get('CI_SPARSE_DEADLINE_NS')
            os.environ['CI_SPARSE_DEADLINE_NS'] = str(deadline)
            try:
                capture = entry.supervise([sys.executable, '-I', '-B', str(script)],
                                          root / 'events.jsonl', (deadline - started) / NS, job=job,
                                          cancelled=lambda: bool(cancelled), result=result)
            finally:
                if old_deadline is None:
                    os.environ.pop('CI_SPARSE_DEADLINE_NS', None)
                else:
                    os.environ['CI_SPARSE_DEADLINE_NS'] = old_deadline
            receipt = dict(kind='sparse', capture=capture, qualification=False, job=job,
                           success=(capture.get('returncode') == 0 and capture.get('reaped') is True
                                    and capture.get('reason') is None
                                    and capture.get('cleanup_uncertainty') is False))
            if receipt['success']:
                finish('sparse', job)
            write_receipt(entry, stream, receipt)
            return int(not receipt['success'])
    except Exception as error:
        return refusal(entry, 'sparse', 'sparse', job, result.capture, error)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def tail(phase):
    entry = entry_module_load()
    if phase not in entry.TAIL_PHASES:
        raise ValueError('Fixed tail phase required')
    job = None
    try:
        record, job, remaining = load(tail=True)
        root = Path(os.environ['RUNNER_TEMP']).resolve() / 'suite-closure'
        root.mkdir(mode=0o700, exist_ok=True)
        # Reserve exclusively before exposing admission to the next action.
        with (root / ('tail-' + phase + '.json')).open('x') as stream:
            wheel = None
            if phase == 'wheel-upload':
                # Both staging and upload are capped at one minute. Admit this
                # optional work only after the existing diagnostic tail.
                if remaining < 125:
                    raise ValueError('Insufficient wheel staging and upload remainder')
                checkout = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
                import importlib.util
                spec = importlib.util.spec_from_file_location('ci_build', checkout / 'tools/ci_build.py')
                controller = importlib.util.module_from_spec(spec); spec.loader.exec_module(controller)
                wheel = controller.stage_intel_wheel(checkout, root.parent, entry, job)
                _, current, remaining = load(tail=True)
                if current != job:
                    raise ValueError('Allocation changed during wheel staging')
            if remaining < 65:
                raise ValueError('Insufficient action remainder')
            receipt = dict(kind='tail', phase=phase, admitted=True, job=job,
                           remaining=remaining, action_cap=60)
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
                write_receipt(entry, stream, receipt)
                if wheel is not None:
                    output.write('wheel=' + wheel + '\n')
                output.write('admitted=true\n')
        return 0
    except Exception as error:
        if phase == 'wheel-upload':
            print('Installed Intel wheel upload admission refused:', entry.exception_category(error), file=sys.stderr)
        try:
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
                output.write('admitted=false\n')
        except Exception:
            pass
        return refusal(entry, 'tail', phase, job, None, error)


if __name__ == '__main__':
    if sys.argv[1:] == ['sparse']:
        raise SystemExit(sparse())
    if len(sys.argv) == 3 and sys.argv[1] == 'tail':
        raise SystemExit(tail(sys.argv[2]))
    raise SystemExit('Fixed workload required')
