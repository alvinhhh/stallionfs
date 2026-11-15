"""Bounded offline adapter fixture execution; no signals or installed routing."""
import os
import hashlib
import json
import uuid
from contextlib import contextmanager
import tempfile
from pathlib import Path
import selectors
import subprocess
import time


def run(argv, cwd, *, timeout=20, cap=65536):
    stem = Path(cwd) / ('command-' + uuid.uuid4().hex)
    receipt = dict(argv=[str(a) for a in argv], timeout=timeout, cap=cap,
                   executable_sha256=hashlib.sha256(Path(argv[0]).resolve().read_bytes()).hexdigest(),
                   inputs={str(a): hashlib.sha256(Path(a).read_bytes()).hexdigest()
                           for a in argv[1:] if Path(a).is_absolute() and Path(a).is_file()},
                   eof=False, reaped=False)
    stem.with_suffix('.json').write_text(json.dumps(receipt, indent=2))
    child = subprocess.Popen([str(a) for a in argv], cwd=cwd, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    selector = selectors.DefaultSelector()
    output = [bytearray(), bytearray()]
    deadline = time.monotonic() + timeout
    try:
        for index, stream in enumerate((child.stdout, child.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, index)
        while selector.get_map() or child.poll() is None:
            if time.monotonic() >= deadline:
                raise RuntimeError('Owned fixture deadline; closure unknown, no PID cleanup attempted')
            for key, _ in selector.select(min(.1, max(0, deadline-time.monotonic()))):
                data = os.read(key.fileobj.fileno(), 8192)
                if not data:
                    selector.unregister(key.fileobj); key.fileobj.close()
                else:
                    output[key.data].extend(data)
                    if sum(map(len, output)) > cap:
                        raise RuntimeError('Owned fixture output cap exceeded')
        receipt['eof'] = True
        status = child.wait(timeout=max(.01, deadline-time.monotonic()))
        receipt.update(reaped=True, exit=status)
        if status:
            raise AssertionError(f'Fixture exit {status}: {bytes(output[1]).decode(errors="replace")}')
        return bytes(output[0]).decode()
    finally:
        for stream in (child.stdout, child.stderr): stream.close()
        selector.close()
        for index, label in enumerate(('stdout', 'stderr')):
            stem.with_suffix('.'+label).write_bytes(output[index])
        receipt['pid'] = child.pid
        stem.with_suffix('.json').write_text(json.dumps(receipt, indent=2))
        # Normal completion has EOF and wait above. Failure gets one bounded
        # reap opportunity and reports an unknown child instead of signalling.
        if child.poll() is None:
            try: child.wait(timeout=2)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError('Owned fixture remains unconfirmed; no stale-PID action') from error


@contextmanager
def owned_directory():
    # Retain failure and success fixtures for the bounded campaign's evidence.
    yield tempfile.mkdtemp(prefix='sfs-managed-activation-')
