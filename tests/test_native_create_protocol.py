"""Controller/stream protocol regressions on bounded disposable fixtures."""
import copy
import contextlib
import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from stallionfs import core, _native
from stallionfs import _native_create_request as request
from stallionfs._native_create_recovery import Admission


class CreationProtocol(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sfs-create-protocol-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'store'
        self.store = core.Store(self.root)
        self.workspace = 'a' * 32
        self.seed = 'b' * 64
        self.seed_path = self.root / 'seeds' / self.seed
        self.seed_path.mkdir(mode=0o700)
        from stallionfs._bundle import GIT_CONTRACT, PUBLISHER_TEAM
        from native_writer_fixture import INPUT, qualify
        qualify(self)
        self.contract = {**GIT_CONTRACT, 'input_inventory_sha256': INPUT, 'payload_entries': 239, 'payload_sha256': '1' * 64,
            'descriptor_sha256': '2' * 64, 'executable_sha256': '3' * 64,
            'source_build_id': '4' * 64, 'publisher': PUBLISHER_TEAM}

    def prepare(self, workspace):
        return request.prepare_controller(self.root, self.held, self.seed_path,
            {'id': self.seed, 'commit': '5' * 40}, workspace=workspace, transaction=workspace,
            name='', jobs=1, capacity=1, budget=None, install_profile=None, host=None, runtime=self.contract)

    @contextlib.contextmanager
    def controller(self, workspace):
        with core.lock(self.root / '.lock') as store, core.lock(self.root / 'locks' / ('seed-' + self.seed)) as seed:
            self.held = (store, seed)
            with self.prepare(workspace) as (a, spec, record):
                yield a, spec['lease']

    def test_exclusive_lease_is_durable_before_callback(self):
        with self.controller(self.workspace) as (a, lease):
            path = self.root / 'locks' / ('use-' + self.workspace)
            self.assertEqual(path.read_text(), lease['generation'] + '\n')
            self.assertEqual(a.bindings[path], lease['file'])
            with self.assertRaises(core.StallionError):
                with self.prepare(self.workspace):
                    self.fail('lease reused')
            child = subprocess.run([sys.executable, '-c',
                'import fcntl,sys; f=open(sys.argv[1]); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)', str(path)],
                capture_output=True, timeout=5)
            self.assertNotEqual(child.returncode, 0)
        self.assertTrue(path.exists())

    def test_lease_failure_never_enters_effect_scope(self):
        for operation in ('write', 'fsync', 'pread'):
            with self.subTest(operation=operation):
                workspace = {'write': 'b', 'fsync': 'c', 'pread': 'd'}[operation] * 32
                kwargs = {'return_value': 0 if operation == 'write' else b'wrong'} if operation != 'fsync' else {
                    'side_effect': OSError(errno.ENOSPC, 'full')}
                with patch.object(request.os, operation, **kwargs):
                    with self.assertRaises((OSError, core.StallionError)):
                        with self.controller(workspace):
                            self.fail('effect after failed lease durability')

    def test_immutable_exclusive_and_readback(self):
        a = Admission(self.root)
        self.addCleanup(a.close)
        path = self.root / 'journals' / 'request.json'
        request.immutable(a, path, {'request': 'bound'})
        self.assertEqual(a.read(path), {'request': 'bound'})
        with self.assertRaises(FileExistsError):
            request.immutable(a, path, {'request': 'changed'})
        self.assertEqual(a.read(path), {'request': 'bound'})

    def test_branch_dots_refused(self):
        with self.assertRaises(core.StallionError):
            request.branch_name('a..b', self.workspace)
        self.assertEqual(request.branch_name('a.b', self.workspace), 'stallionfs/a.b-' + self.workspace)

    def execute(self, program, **kwargs):
        log = self.base / 'logs'
        log.mkdir(mode=0o700)
        record, receipts = {}, []
        def persist():
            receipts.append(copy.deepcopy(record))
        try:
            _native.execute_owned([sys.executable, '-c', program], record, persist, log,
                cwd=self.base, env={'PATH': '/usr/bin:/bin', 'ONLY': 'selected'}, **kwargs)
        finally:
            self.record, self.receipts, self.log = record, receipts, log
        return record

    def test_pipe_receipt_order_environment_and_durable_eof(self):
        result = self.execute('import os; print(os.environ["ONLY"]); print(os.getcwd())', output_limit=4096)
        self.assertTrue(self.receipts[0]['child_pending'])
        self.assertIsNone(self.receipts[0]['pid'])
        self.assertTrue(result['reaped'])
        self.assertTrue(result['streams_durable'])
        self.assertTrue(result['streams_eof'])
        self.assertEqual((self.log / 'stdout').read_text(), 'selected\n' + str(self.base) + '\n')

    def test_exit_zero_cannot_override_output_overflow(self):
        with self.assertRaises(ValueError):
            self.execute('import os; os.write(1,b"x"*4097)', output_limit=4096)
        self.assertEqual(self.record['collector_error'], 'output-limit')
        self.assertFalse(self.record['streams_durable'])
        self.assertEqual(self.record['outcome'], 'unknown')
        self.assertTrue(self.record['reaped'])
        self.assertLessEqual((self.log / 'stdout').stat().st_size, 4096)

    def test_two_mib_limit_is_combined_across_both_pipes(self):
        with self.assertRaises(ValueError):
            self.execute('import os; os.write(1,b"x"*(1024*1024)); os.write(2,b"y"*(1024*1024+1))',
                         output_limit=2 * 1024 * 1024)
        self.assertEqual(self.record['collector_error'], 'output-limit')
        self.assertEqual(self.record['outcome'], 'unknown')
        self.assertLessEqual(sum((self.log / name).stat().st_size for name in ('stdout', 'stderr')), 2 * 1024 * 1024)

    def test_output_fsync_failure_overrides_exit_zero(self):
        with patch.object(_native.os, 'fsync', side_effect=OSError(errno.ENOSPC, 'full')):
            with self.assertRaises(OSError):
                self.execute('print("complete")', output_limit=4096)
        self.assertEqual(self.record['returncode'], 0)
        self.assertFalse(self.record['streams_durable'])
        self.assertEqual(self.record['outcome'], 'unknown')

    def test_inherited_pipe_is_not_terminal_completion(self):
        # This controlled child exits while its descendant briefly owns the pipes.
        # Both handles terminate naturally within the bounded fixture duration.
        with self.assertRaises(subprocess.TimeoutExpired):
            self.execute('import os,time; pid=os.fork(); time.sleep(.4) if pid==0 else None',
                         output_limit=4096, deadline=.1)
        self.assertFalse(self.record['streams_eof'])
        self.assertFalse(self.record['streams_durable'])

    def test_pipes_close_when_failure_precedes_collection(self):
        for boundary in ('running-persist', 'interrupt', 'first-register', 'second-register'):
            with self.subTest(boundary=boundary):
                log = self.base / boundary; log.mkdir(mode=0o700)
                record, children, descriptors = {}, [], []
                original_launch = subprocess.Popen
                original_selector = _native.selectors.DefaultSelector
                primary = KeyboardInterrupt('after launch') if boundary == 'interrupt' else OSError(errno.ENOSPC, boundary)
                def launch(*args, **kwargs):
                    child = original_launch(*args, **kwargs)
                    children.append(child)
                    descriptors.extend(pipe.fileno() for pipe in (child.stdout, child.stderr))
                    return child
                def persist():
                    if record['outcome'] == 'running' and boundary in ('running-persist', 'interrupt'):
                        raise primary
                def selector():
                    result = original_selector(); register = result.register; calls = []
                    def failing_register(*args, **kwargs):
                        calls.append(True)
                        if len(calls) == (1 if boundary == 'first-register' else 2): raise primary
                        return register(*args, **kwargs)
                    if boundary.endswith('register'): result.register = failing_register
                    return result
                with patch.object(subprocess, 'Popen', launch), patch.object(_native.selectors, 'DefaultSelector', selector):
                    with self.assertRaises(type(primary)) as caught:
                        _native.execute_owned([sys.executable, '-c', 'import time; time.sleep(5)'], record, persist,
                            log, cwd=self.base, env={'PATH': '/usr/bin:/bin'}, output_limit=4096)
                self.assertIs(caught.exception, primary)
                self.assertTrue(record['reaped']); self.assertFalse(record['child_pending'])
                self.assertEqual(record['outcome'], 'unknown'); self.assertFalse(record['streams_durable'])
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll())
                self.assertTrue(children[0].stdout.closed); self.assertTrue(children[0].stderr.closed)
                for fd in descriptors:
                    with self.assertRaises(OSError) as closed: os.fstat(fd)
                    self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_pipe_close_failure_preserves_primary_and_closes_other_pipe(self):
        for has_primary in (True, False):
            with self.subTest(has_primary=has_primary):
                log = self.base / str(has_primary); log.mkdir(mode=0o700)
                record, children, pipes = {}, [], []
                original_launch = subprocess.Popen
                primary = OSError(errno.ENOSPC, 'running persistence')
                close_error = OSError(errno.EIO, 'consumed pipe close')
                class Pipe:
                    def __init__(self, stream): self.stream = stream
                    def __getattr__(self, key): return getattr(self.stream, key)
                    def close(self):
                        self.stream.close()
                        raise close_error
                def launch(*args, **kwargs):
                    child = original_launch(*args, **kwargs)
                    children.append(child); pipes.extend((child.stdout, child.stderr))
                    child.stdout = Pipe(child.stdout)
                    return child
                def persist():
                    if has_primary and record['outcome'] == 'running': raise primary
                with patch.object(subprocess, 'Popen', launch):
                    with self.assertRaises(OSError) as caught:
                        _native.execute_owned([sys.executable, '-c', 'print("bounded")'], record, persist, log,
                            cwd=self.base, env={'PATH': '/usr/bin:/bin'}, output_limit=4096)
                self.assertIs(caught.exception, primary if has_primary else close_error)
                self.assertTrue(all(pipe.closed for pipe in pipes))
                self.assertTrue(record['reaped']); self.assertEqual(record['outcome'], 'unknown')
                self.assertFalse(record['streams_durable'])
                self.assertEqual(record['stream_close_errors'], ['OSError'])
