"""Retained worker allocation and ordered consumption within the existing limit."""
import hashlib
import json
import os
from pathlib import Path
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
    if type(record) is not dict or set(record) != {'start', 'minutes', 'identity', 'token'}:
        raise ValueError('Allocation schema')
    expected = {key: os.environ[key] for key in IDENTITY}
    if (record['identity'] != expected or any(type(v) is not str or not v for v in expected.values())
            or type(record['token']) is not str or len(record['token']) != 32
            or any(c not in '0123456789abcdef' for c in record['token'])
            or type(record['start']) not in (int, float) or type(record['minutes']) is not int):
        raise ValueError('Allocation identity')
    remaining = entry.remainder(record['start'], record['minutes'])
    if tail:
        remaining = record['start'] + record['minutes'] * 60 - 10 - time.monotonic()
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
            capture = entry.supervise([sys.executable, '-I', '-B', str(script)],
                                      root / 'events.jsonl', min(536, remaining), job=job,
                                      cancelled=lambda: bool(cancelled), result=result)
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
    if phase not in ('validation', 'suite-upload', 'image-upload', 'interface-upload'):
        raise ValueError('Fixed tail phase required')
    entry = entry_module_load()
    job = None
    try:
        record, job, remaining = load(tail=True)
        root = Path(os.environ['RUNNER_TEMP']).resolve() / 'suite-closure'
        root.mkdir(mode=0o700, exist_ok=True)
        # Reserve exclusively before exposing admission to the next action.
        with (root / ('tail-' + phase + '.json')).open('x') as stream:
            if remaining < 65:
                raise ValueError('Insufficient action remainder')
            receipt = dict(kind='tail', phase=phase, admitted=True, job=job,
                           remaining=remaining, action_cap=60)
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
                write_receipt(entry, stream, receipt)
                output.write('admitted=true\n')
        return 0
    except Exception as error:
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
