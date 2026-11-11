"""Protocol-2 helper authority on tiny stores and inert owned subprocesses."""
import contextlib
import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

from stallionfs import core, _native, _native_create_request as request
from stallionfs import _native_create_recovery as recovery, _native_creation_purge as purge
from stallionfs import _native_create_git as git
from stallionfs._bundle import GIT_CONTRACT, PUBLISHER_TEAM


class HelperReceipts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='sfs-helper-receipts-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / 'store'
        self.store = core.Store(self.root)
        self.seed = 'b' * 64
        self.seed_path = self.root / 'seeds' / self.seed
        self.seed_path.mkdir(mode=0o700)
        from native_writer_fixture import INPUT, qualify
        qualify(self)
        self.contract = {**GIT_CONTRACT, 'input_inventory_sha256': INPUT, 'payload_entries': 239, 'payload_sha256': '1' * 64,
            'descriptor_sha256': '2' * 64, 'executable_sha256': '3' * 64,
            'source_build_id': '4' * 64, 'publisher': PUBLISHER_TEAM}

    @contextlib.contextmanager
    def operation(self):
        workspace, transaction = uuid.uuid4().hex, uuid.uuid4().hex
        with core.lock(self.root / '.lock') as store, core.lock(self.root / 'locks' / ('seed-' + self.seed)) as seed:
            with request.prepare_controller(self.root, (store, seed), self.seed_path,
                    {'id': self.seed, 'commit': '5' * 40}, workspace=workspace, transaction=transaction,
                    name='', jobs=1, capacity=1, budget=None, install_profile=None, host=None,
                    runtime=self.contract) as (a, spec, record):
                op = _native.Operation.__new__(_native.Operation)
                op.path = Path(record['stage']) / 'owned'
                op.directory = Path(record['stage']) / 'discovery'
                op.directory.mkdir(mode=0o700)
                op.journal = self.root / 'journals' / (workspace + '.json')
                op.record = record
                request.phase(a, op.journal, record, 'preflight')
                record.update(helpers=[], child_pending=False)
                op.persist()
                yield op

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.lstat().st_ino, p.lstat().st_mode,
                os.readlink(p) if p.is_symlink() else p.read_bytes() if p.is_file() else None)
                for p in self.root.rglob('*')}

    def refused(self, record):
        before = self.snapshot()
        for confirm in (False, True):
            result = purge.purge_creation(self.root, record['workspace'], record['transaction'], confirm=confirm)
            self.assertEqual(result['status'], 'writer-unverified', result)
            self.assertFalse(result.get('eligible', False)); self.assertFalse(result['files_removed'])
            self.assertEqual(self.snapshot(), before)
        rejected = []
        validate = _native.check_pending
        def checked(*args):
            try:
                return validate(*args)
            except core.StallionError as error:
                rejected.append(str(error)); raise
        with patch.object(git, 'qualified_runtime', side_effect=AssertionError('runtime effect')) as runtime, \
                patch.object(_native, 'check_pending', checked):
            result = recovery.continue_creation(self.root, record['workspace'], record['transaction'])
            self.assertEqual(result['status'], 'blocked', result)
            self.assertEqual(result['code'], 'StallionError', result)
            self.assertEqual(len(rejected), 1)
            self.assertTrue(any(text in rejected[0] for text in
                            ('unresolved process ownership', 'unresolved native helper intent')), rejected)
            runtime.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_real_helper_failures_cannot_authorize_purge_or_replacement(self):
        for boundary in ('timeout', 'overflow', 'write', 'fsync', 'close', 'receipt'):
            with self.subTest(boundary=boundary), self.operation() as op:
                real_execute, real_open, real_fsync = _native.execute_owned, Path.open, os.fsync
                real_persist = op.persist
                log_fds = set()
                injected = []
                class Log:
                    def __init__(self, stream): self.stream = stream
                    def __getattr__(self, key): return getattr(self.stream, key)
                    def write(self, data):
                        if boundary == 'write':
                            injected.append('write'); raise OSError(errno.ENOSPC, 'log write')
                        return self.stream.write(data)
                    def close(self):
                        log_fds.discard(self.stream.fileno())
                        self.stream.close()
                        if boundary == 'close':
                            injected.append('close'); raise OSError(errno.EIO, 'consumed log close')
                def opened(path, *args, **kwargs):
                    stream = real_open(path, *args, **kwargs)
                    if path.name == 'stdout' and args and args[0] == 'xb':
                        log_fds.add(stream.fileno())
                        return Log(stream)
                    return stream
                def fsync(fd):
                    if boundary == 'fsync' and fd in log_fds:
                        injected.append('fsync'); raise OSError(errno.EIO, 'log fsync')
                    return real_fsync(fd)
                def persist():
                    if boundary == 'receipt' and op.record['helpers'][-1]['outcome'] == 'success':
                        injected.append('receipt'); raise OSError(errno.ENOSPC, 'terminal receipt')
                    return real_persist()
                def execute(*args, **kwargs):
                    kwargs.update(output_limit=128, deadline=.2 if boundary == 'timeout' else 5)
                    return real_execute(*args, **kwargs)
                script = 'import time; time.sleep(5)' if boundary == 'timeout' else 'print("x" * 1024)' if boundary == 'overflow' else 'print("inert")'
                with patch.object(Path, 'open', opened), patch.object(os, 'fsync', fsync), \
                        patch.object(op, 'persist', persist), patch.object(_native, 'execute_owned', execute):
                    with self.assertRaises((OSError, ValueError, subprocess.TimeoutExpired)):
                        op.command('verify-package', [sys.executable, '-c', script])
                item = op.record['helpers'][0]
                self.assertTrue(item['reaped']); self.assertFalse(item['child_pending'])
                with self.assertRaises(core.StallionError): _native.check_helpers(op.record, {'verify-package'})
                if boundary not in ('timeout', 'overflow'): self.assertIn(boundary, injected)
            with self.subTest(refusal=boundary): self.refused(op.record)

    def test_missing_or_uncertain_receipt_fields_are_read_only_refusals(self):
        changes = [('missing-eof', lambda h: h.pop('streams_eof')),
                   ('missing-durable', lambda h: h.pop('streams_durable')),
                   ('missing-count', lambda h: h.pop('output_bytes')),
                   ('count-overflow', lambda h: h.update(output_bytes=2 * 1024 * 1024 + 1)),
                   ('unknown', lambda h: h.update(outcome='unknown')),
                   ('collector', lambda h: h.update(collector_error='output-limit')),
                   ('close', lambda h: h.update(stream_close_errors=['OSError'])),
                   ('receipt', lambda h: h.update(receipt_error='OSError'))]
        for label, change in changes:
            with self.subTest(label=label), self.operation() as op:
                op.command('verify-package', [sys.executable, '-c', 'pass'])
                change(op.record['helpers'][0]); op.persist()
            self.refused(op.record)

    def test_valid_success_error_and_not_launched_controls(self):
        for outcome in ('success', 'error', 'not-launched'):
            with self.subTest(outcome=outcome), self.operation() as op:
                if outcome == 'not-launched':
                    with patch.object(subprocess, 'Popen', side_effect=OSError(errno.EAGAIN, 'launch refused')):
                        with self.assertRaises(OSError): op.command('verify-package', [sys.executable, '-c', 'pass'])
                else:
                    op.command('verify-package', [sys.executable, '-c', 'raise SystemExit(' + ('0' if outcome == 'success' else '3') + ')'])
                self.assertEqual(op.record['helpers'][0]['outcome'], outcome)
                _native.check_helpers(op.record, {'verify-package'})
                _native.check_pending(op.record['workspace'], op.record)
                purge.writers(op.record)
            before = self.snapshot()
            result = purge.purge_creation(self.root, op.record['workspace'], op.record['transaction'], confirm=False)
            self.assertEqual(result['status'], 'preview', result); self.assertTrue(result['eligible'])
            self.assertEqual(self.snapshot(), before)

    def test_phase1_terminal_compatibility_is_separate(self):
        helper = {'label': 'verify-package', 'argv': ['inert'], 'stdout': 'out', 'stderr': 'err',
                  'pid': 123, 'returncode': -15, 'reaped': True, 'child_pending': False, 'outcome': 'unknown'}
        record = {'helpers': [helper], 'child_pending': False}
        _native.check_helpers(record, {'verify-package'})
        record['protocol'] = 2
        with self.assertRaises(core.StallionError): _native.check_helpers(record, {'verify-package'})
        record['helpers'][0] = {**helper, 'outcome': 'not-launched', 'pid': None, 'returncode': None, 'reaped': False,
                                'receipt_error': 'OSError'}
        with self.assertRaises(core.StallionError): _native.check_helpers(record, {'verify-package'})
