"""Shared deadlines and bounded setup output for installed collectors."""
import base64
import json
import math
import os
from pathlib import Path
import selectors
import subprocess
import tempfile
import time

DEADLINE = 'STALLIONFS_BENCHMARK_DEADLINE'
OUTPUT_LIMIT = 8 * 1024 * 1024


class ChildCompletionUnknown(RuntimeError):
    """Retain disposable storage; the primary error is available as __cause__."""
    def __init__(self, receipt):
        self.receipt = receipt
        super().__init__('Command completion is uncertain; preserve its fixture')


def remaining(timeout=None):
    value = os.environ.get(DEADLINE)
    if value is None:
        return timeout
    deadline = float(value)
    if not math.isfinite(deadline):
        raise ValueError('Invalid benchmark deadline')
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError('Benchmark time budget exhausted; retain its files')
    return left if timeout is None else min(float(timeout), left)


def check():
    remaining()


def _drain(process, deadline, receipt, output, output_limit=None):
    """Read bounded chunks without a competing waiter or background watchdog."""
    limit = OUTPUT_LIMIT if output_limit is None else output_limit
    buffers = [bytearray(), bytearray()]
    try:
        with selectors.DefaultSelector() as selector:
            for index, stream in enumerate((process.stdout, process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map():
                left = remaining(deadline - time.monotonic())
                if left <= 0:
                    raise subprocess.TimeoutExpired(receipt['argv'], 0)
                for key, _ in selector.select(min(left, 0.1)):
                    chunk = os.read(key.fd, 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    receipt['observed_output_bytes'] = receipt.get('observed_output_bytes', 0) + len(chunk)
                    keep = chunk[:max(0, limit - receipt.get('output_bytes', 0))]
                    if output is None:
                        buffers[key.data].extend(keep)
                        written = len(keep)
                    else:
                        written = output.write(keep)
                    if type(written) is not int or written != len(keep):
                        raise OSError('Benchmark output short write; retained length uncertain')
                    receipt['output_bytes'] = receipt.get('output_bytes', 0) + written
                    name = ('stdout', 'stderr')[key.data]
                    receipt[name + '_retained_bytes'] = receipt.get(name + '_retained_bytes', 0) + written
                    receipt['discarded_output_bytes'] = receipt.get('discarded_output_bytes', 0) + len(chunk) - written
                    if len(keep) != len(chunk):
                        receipt['output_limit_exceeded'] = True
                        raise RuntimeError('Benchmark command output limit exceeded')
            process.wait(timeout=max(0.000001, remaining(deadline - time.monotonic())))
    except BaseException as primary:
        if output is None:
            # Only bytes actually read and retained within the cap are evidence.
            try:
                for name, value in zip(('stdout', 'stderr'), buffers):
                    receipt[name + '_partial_b64'] = base64.b64encode(value).decode('ascii')
            except BaseException as secondary:
                primary.add_note('Partial diagnostic encoding also failed: ' + str(secondary))
        raise
    return tuple(bytes(value) for value in buffers)


def _receipt(receipt):
    directory = os.environ.get('STALLIONFS_BENCHMARK_RECEIPTS')
    if directory:
        path = Path(directory)
        info = path.stat()
        if path.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700:
            raise RuntimeError('Benchmark receipt directory identity changed')
        fd, _ = tempfile.mkstemp(prefix='setup-', suffix='.json', dir=path)
        with os.fdopen(fd, 'w') as stream:
            json.dump(receipt, stream)


def command(argv, *, cwd=None, environment=None, timeout=600, umask=-1,
            output=None, persist_success=True, receipt=None, output_limit=None):
    """Cap setup output; use the existing sole-owner cleanup helper on failure.

    Timed workspace calls omit successful receipt writes. Failed calls are invalid
    samples and persist recovery evidence before propagating uncertainty.
    """
    from ._benchmark_runtime.native_metrics import _stop_group
    process = None
    if receipt is None:
        receipt = {}
    receipt.update(argv=[os.fspath(arg) for arg in argv], completion_uncertain=False)
    try:
        allowed = remaining(timeout)
        deadline = time.monotonic() + allowed
        process = subprocess.Popen(receipt['argv'], cwd=cwd, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True, umask=umask)
        receipt['pid'] = process.pid
        stdout, stderr = _drain(process, deadline, receipt, output, output_limit)
        receipt['exit_code'] = process.returncode
    except BaseException as primary:
        receipt['error'] = f'{type(primary).__name__}: {primary}'
        if process is not None:
            receipt['completion_uncertain'] = True
            # Cleanup must never call communicate() on unbounded output pipes.
            for name in ('stdout', 'stderr'):
                stream = getattr(process, name)
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException as secondary:
                        primary.add_note('Benchmark pipe close also failed: ' + str(secondary))
                    setattr(process, name, None)
            try:
                _stop_group(process, receipt, 1.0)
            except BaseException as secondary:
                receipt['cleanup_error'] = str(secondary)
                primary.add_note('Benchmark command cleanup also failed: ' + str(secondary))
        try:
            _receipt(receipt)
        except BaseException as secondary:
            primary.add_note('Benchmark command receipt also failed: ' + str(secondary))
        if process is not None:
            raise ChildCompletionUnknown(receipt) from primary
        raise
    if process is not None:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
    if persist_success:
        _receipt(receipt)
    return subprocess.CompletedProcess(receipt['argv'], process.returncode, stdout, stderr)
