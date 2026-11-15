"""Owned native fixtures and read-only kernel snapshots; no installed execution."""
import errno
import json
import os
from pathlib import Path
import pwd
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'filesystem/fskit/maintenance_native.c'


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('xcrun'), 'Darwin native SDK required')
class NativeMaintenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = Path(tempfile.mkdtemp(prefix='maintenance-native-tests-')).resolve()
        cls.retained_worker = None
        cls.base.chmod(0o700)
        cls.binaries = {}

    @classmethod
    def tearDownClass(cls):
        if cls.retained_worker is not None:
            print('Retained unresolved worker fixture: ' + json.dumps(cls.retained_worker, sort_keys=True), file=sys.stderr)
        else:
            shutil.rmtree(cls.base)

    def binary(self, **macros):
        key = tuple(sorted(macros.items()))
        if key not in self.binaries:
            target = self.base / ('leaf-' + str(len(self.binaries)))
            result = subprocess.run(['xcrun', 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                                     *[f'-D{k}={v}' for k, v in key], str(SOURCE), '-o', str(target)],
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.binaries[key] = target
        return self.binaries[key]

    def run_leaf(self, *args, binary=None, **kwargs):
        return subprocess.run([str(binary or self.binary()), *map(str, args)],
                              capture_output=True, timeout=8, **kwargs)

    def directory(self):
        path = Path(tempfile.mkdtemp(prefix='retained-', dir=self.base))
        path.chmod(0o700)
        return path

    def test_read_only_host_snapshot_keeps_unknown_paths(self):
        result = self.run_leaf('observe')
        self.assertIn(result.returncode, (0, 1))
        report = json.loads(result.stdout)
        self.assertEqual(report['schema'], 1)
        self.assertEqual(report['scope'], 'global-kernel-snapshot')
        self.assertTrue(report['boot_id'])
        self.assertGreaterEqual(report['finished_ns'], report['started_ns'])
        self.assertTrue(report['processes'])
        self.assertIn(os.getpid(), [row['pid'] for row in report['processes']])
        for row in report['processes']:
            self.assertTrue({'pid', 'ppid', 'uid', 'start_sec', 'start_usec', 'path',
                             'path_errno', 'postquery_errno', 'stable', 'status', 'kernel'} <= row.keys())
            if row['path'] is None and not row['kernel'] and row['status'] != 5:
                self.assertFalse(report['complete'])
                self.assertIn('live-process-path-unavailable', report['uncertainties'])
        self.assertEqual(result.returncode == 0, report['complete'])
        self.assertEqual(set(report), {'schema', 'scope', 'boot_id', 'started_ns', 'finished_ns',
                                       'mounts', 'processes', 'sessions', 'activity', 'complete', 'uncertainties'})

    def test_no_python_decision_commands_accept_only_clear_typed_fixture(self):
        document=(SOURCE.parents[2]/'docs/fskit-maintenance.md').read_text()
        marker='<!-- native-activity-decision -->'
        commands=document.split(marker,1)[1].split('```sh',1)[1].split('```',1)[0]
        for fault in (17,18,19,20,21):
            parent=self.directory();observation=parent/'fresh'
            info=parent.stat()
            environment={'PATH':'/usr/bin:/bin:/usr/sbin','LANG':'C',
                'LEAF':str(self.binary(SFS_TEST_FAULT=fault)), 'RETAIN_PARENT':str(parent),
                'OBSERVATION':str(observation),'EXPECTED_PARENT_ID':f'{info.st_dev}:{info.st_ino}'}
            result=subprocess.run(['/bin/sh','-c',commands],env=environment,capture_output=True,timeout=15)
            with self.subTest(fault=fault):
                self.assertEqual(result.returncode==0,fault==17,result.stderr.decode())
                report=json.loads((observation/'native.json').read_bytes())
                self.assertEqual(report['activity']['clear_at_observation'],fault==17)
                if fault==18:
                    self.assertEqual(report['activity']['helpers'],1)
                    self.assertEqual(report['activity']['descendants'],1)
                if fault==19:self.assertEqual(report['activity']['mounts'],1)
                if fault==21:self.assertEqual(report['activity']['other_user_sessions'],1)
                if fault in (18,19,21):self.assertTrue(report['complete'])

    def test_finite_arguments_and_hostile_environment(self):
        for args in ((), ('--help',), ('observe', 'extra'), ('retain',), ('retain', 'relative')):
            result = self.run_leaf(*args)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b'')
        environment = {**os.environ, 'PYTHONHOME': '/hostile', 'PYTHONPATH': '/hostile',
                       'SFS_TEST_FAULT': '6', 'SFS_DEADLINE_MS': '0'}
        result = self.run_leaf('observe', env=environment)
        self.assertIn(result.returncode, (0, 1))
        self.assertEqual(json.loads(result.stdout)['scope'], 'global-kernel-snapshot')

    def test_denial_truncation_pid_reuse_and_caps_are_not_clearance(self):
        cases = [({'SFS_TEST_FAULT': 1}, 'mount-enumeration-denied'),
                 ({'SFS_TEST_FAULT': 2}, 'process-enumeration-denied'),
                 ({'SFS_TEST_FAULT': 3}, 'process-identity-changed-or-unavailable'),
                 ({'SFS_TEST_FAULT': 4}, 'live-process-path-unavailable'),
                 ({'SFS_TEST_FAULT': 5}, 'session-enumeration-unavailable'),
                 ({'SFS_TEST_FAULT': 9}, 'process-enumeration-truncated-or-changed'),
                 ({'SFS_PROCESS_CAP': 1}, 'process-capacity-or-truncation'),
                 ({'SFS_MOUNT_CAP': 1}, 'mount-capacity-or-truncation'),
                 ({'SFS_OUTPUT_CAP': 512}, 'output-capacity')]
        for macros, reason in cases:
            with self.subTest(macros=macros):
                result = self.run_leaf('observe', binary=self.binary(**macros))
                self.assertEqual(result.returncode, 1)
                report = json.loads(result.stdout)
                self.assertFalse(report['complete'])
                self.assertIn(reason, report['uncertainties'])
                if macros.get('SFS_TEST_FAULT') == 4:
                    self.assertTrue(report['processes'])
                    self.assertTrue(all(row['path'] is None for row in report['processes']))

    def test_retained_transport_and_exclusive_reuse_refusal(self):
        directory = self.directory()
        result = self.run_leaf('retain', directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads((directory/'native-completion.json').read_bytes())
        report = json.loads((directory/'native.json').read_bytes())
        self.assertTrue(receipt['complete'])
        self.assertTrue(all(receipt[key] for key in ('reaped', 'streams_eof', 'output_durable',
                        'directory_bound', 'output_bound', 'cleanup_complete','output_readback')))
        self.assertEqual(receipt['returncode'] == 0, report['complete'])
        self.assertEqual(receipt['output_bytes'], (directory/'native.json').stat().st_size)
        import hashlib
        self.assertEqual(receipt['output_sha256'],hashlib.sha256((directory/'native.json').read_bytes()).hexdigest())
        self.assertEqual(receipt['deadline_ms'], 5000)
        self.assertEqual(receipt['output_cap'], 16*1024*1024)
        before = {p.name: p.read_bytes() for p in directory.iterdir()}
        self.assertEqual(self.run_leaf('retain', directory).returncode, 2)
        self.assertEqual(before, {p.name: p.read_bytes() for p in directory.iterdir()})
        for path in directory.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)

    def test_retained_truncation_and_same_length_tamper_refuse(self):
        for fault in (13,14):
            directory=self.directory()
            result=self.run_leaf('retain',directory,binary=self.binary(SFS_TEST_FAULT=fault))
            self.assertEqual(result.returncode,1)
            receipt=json.loads((directory/'native-completion.json').read_bytes())
            self.assertFalse(receipt['complete']);self.assertFalse(receipt['output_readback'])
            self.assertTrue(receipt['io_error'])

    def test_receipt_truncation_cannot_exit_success(self):
        directory=self.directory()
        result=self.run_leaf('retain',directory,binary=self.binary(SFS_TEST_FAULT=15))
        self.assertEqual(result.returncode,1)
        self.assertEqual((directory/'native-completion.json').read_bytes(),b'')
        self.assertTrue((directory/'native.json').exists())

    def test_physical_protected_app_ancestor_refuses_before_create(self):
        directory=self.directory()
        result=self.run_leaf('retain',directory,binary=self.binary(SFS_TEST_FAULT=16))
        self.assertEqual(result.returncode,2);self.assertEqual(list(directory.iterdir()),[])

    def test_private_no_follow_and_acl_refusals(self):
        for mode in (0o755, 0o770, 0o1700):
            directory = self.directory(); directory.chmod(mode)
            self.assertEqual(self.run_leaf('retain', directory).returncode, 2)
            self.assertEqual(list(directory.iterdir()), [])
        directory = self.directory(); (directory/'foreign').write_text('preserve')
        self.assertEqual(self.run_leaf('retain', directory).returncode, 2)
        self.assertEqual((directory/'foreign').read_text(), 'preserve')
        directory = self.directory(); alias = directory.with_name(directory.name+'-alias'); alias.symlink_to(directory)
        self.assertEqual(self.run_leaf('retain', alias).returncode, 2)
        self.assertEqual(list(directory.iterdir()), [])
        alias_parent = self.directory(); (alias_parent/'alias').symlink_to(directory)
        self.assertEqual(self.run_leaf('retain', alias_parent/'alias').returncode, 2)
        directory = self.directory()
        acl = subprocess.run(['/bin/chmod', '+a', f'user:{pwd.getpwuid(os.getuid()).pw_name} allow read', str(directory)],
                             capture_output=True, timeout=5)
        self.assertEqual(acl.returncode, 0, acl.stderr)
        try:
            self.assertEqual(self.run_leaf('retain', directory).returncode, 2)
            self.assertEqual(list(directory.iterdir()), [])
        finally:
            subprocess.run(['/bin/chmod', '-N', str(directory)], check=True, timeout=5)

    def test_owned_worker_deadline_retains_partial_and_reaps(self):
        directory = self.directory()
        started = time.monotonic()
        result = self.run_leaf('retain', directory,
                               binary=self.binary(SFS_TEST_FAULT=6, SFS_DEADLINE_MS=100))
        self.assertLess(time.monotonic()-started, 2)
        self.assertEqual(result.returncode, 1)
        receipt = json.loads((directory/'native-completion.json').read_bytes())
        self.assertFalse(receipt['complete'])
        self.assertEqual(receipt['outcome'], 'timeout')
        self.assertTrue(receipt['reaped'])
        self.assertTrue(receipt['cleanup_complete'])
        self.assertTrue(receipt['streams_eof'])
        self.assertEqual((directory/'native.json').read_bytes(), b'{"partial":')

    def test_owned_worker_output_limit_retains_bounded_partial(self):
        directory = self.directory()
        result = self.run_leaf('retain', directory,
                               binary=self.binary(SFS_TEST_FAULT=7, SFS_OUTPUT_CAP=4096))
        self.assertEqual(result.returncode, 1)
        receipt = json.loads((directory/'native-completion.json').read_bytes())
        self.assertEqual(receipt['outcome'], 'output-limit')
        self.assertFalse(receipt['complete'])
        self.assertTrue(receipt['reaped'])
        self.assertTrue(receipt['cleanup_complete'])
        self.assertEqual(receipt['output_bytes'], 4096)
        self.assertEqual((directory/'native.json').stat().st_size, 4096)

    def test_worker_closes_inherited_nonstandard_descriptors(self):
        directory = self.directory()
        fd = os.open('/dev/null', os.O_RDONLY)
        old42 = None
        try:
            try: old42 = os.dup(42)
            except OSError: pass
            os.dup2(fd, 42, inheritable=True)
            result = self.run_leaf('retain', directory, binary=self.binary(SFS_TEST_FAULT=11), pass_fds=(42,))
        finally:
            if old42 is not None:
                os.dup2(old42, 42); os.close(old42)
            else: os.close(42)
            os.close(fd)
        self.assertEqual(result.returncode, 0)
        receipt = json.loads((directory/'native-completion.json').read_bytes())
        self.assertNotEqual(receipt['returncode'], 126)
        self.assertTrue(receipt['complete'])

    def test_directory_replacement_and_close_uncertainty_are_not_complete(self):
        directory = self.directory()
        process = subprocess.Popen([str(self.binary(SFS_TEST_FAULT=6, SFS_DEADLINE_MS=200)),
                                    'retain', str(directory)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic()+2
            while not (directory/'native.json').exists() or not (directory/'native.json').stat().st_size:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            parked = directory.with_name(directory.name+'-parked')
            directory.rename(parked); directory.mkdir(mode=0o700)
            process.communicate(timeout=3)
            self.assertEqual(process.returncode, 1)
            receipt = json.loads((parked/'native-completion.json').read_bytes())
            self.assertFalse(receipt['complete'])
            self.assertFalse(receipt['directory_bound'])
            self.assertEqual(list(directory.iterdir()), [])
        finally:
            if process.poll() is None:
                process.kill(); process.communicate(timeout=3)
        directory = self.directory()
        result = self.run_leaf('retain', directory, binary=self.binary(SFS_TEST_FAULT=12))
        self.assertEqual(result.returncode, 1)
        receipt = json.loads((directory/'native-completion.json').read_bytes())
        self.assertFalse(receipt['complete'])
        self.assertTrue(receipt['reaped'])
        self.assertTrue(receipt['close_errors'])
        self.assertFalse(receipt['cleanup_complete'])

    def test_worker_has_independent_lifetime_after_controller_loss(self):
        target = self.base/'lifetime-fixture'
        built = subprocess.run(['xcrun', 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                                str(Path(__file__).with_name('maintenance_lifetime_fixture.c')), '-o', str(target)],
                               capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stderr)
        fields = {'pid', 'ppid', 'uid', 'start_sec', 'start_usec', 'status'}

        def identity(data, controller):
            value = json.loads(data)
            self.assertEqual(set(value), fields)
            self.assertTrue(all(type(v) is int for v in value.values()))
            self.assertGreater(value['pid'], 1)
            self.assertEqual(value['ppid'], controller)
            self.assertEqual(value['uid'], os.getuid())
            self.assertGreater(value['start_sec'], 0)
            self.assertTrue(0 <= value['start_usec'] < 1000000)
            self.assertNotIn(value['status'], (0, 5))
            return value

        def live(worker):
            result = subprocess.run([str(target), 'exact', str(worker['pid'])], capture_output=True, timeout=0.5)
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(result.stdout)
            if value is None:
                return False
            self.assertEqual(set(value), fields)
            self.assertTrue(all(type(v) is int for v in value.values()))
            return all(value[k] == worker[k] for k in ('pid', 'uid', 'start_sec', 'start_usec')) and value['status'] != 5

        valid = dict(pid=99, ppid=88, uid=os.getuid(), start_sec=1, start_usec=2, status=2)
        for invalid in (b'', b'{', b'{}', json.dumps({**valid, 'ppid': 1}),
                        json.dumps({**valid, 'uid': os.getuid()+1}), json.dumps({**valid, 'status': 5})):
            with self.subTest(invalid=invalid), self.assertRaises((ValueError, AssertionError)):
                identity(invalid, 88)

        for delay, failure in ((0, None), (0.25, None), (0, 'eof'), (0, 'timeout'), (0, 'invalid-release')):
            directory = self.directory()
            ready_read, ready_write = os.pipe()
            release_read, release_write = os.pipe()
            process = None
            worker = None
            try:
                process = subprocess.Popen([str(target), str(ready_write), str(release_read), 'retain', str(directory)],
                    pass_fds=(ready_write, release_read), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                os.close(ready_write); ready_write = -1
                os.close(release_read); release_read = -1
                self.assertTrue(select.select([ready_read], [], [], 1)[0], 'Worker readiness missing')
                data = os.read(ready_read, 513)
                self.assertTrue(0 < len(data) <= 512 and data.endswith(b'\n'), 'Invalid worker readiness')
                worker = identity(data, process.pid)
                deadline = time.monotonic()+3
                self.assertEqual((directory/'native.json').read_bytes(), b'{"partial":')
                time.sleep(delay)
                self.assertIsNone(process.poll(), 'Controller exited before loss transition')
                self.assertTrue(live(worker), 'Worker exited before controller loss')
                self.assertEqual((directory/'native-completion.json').read_bytes(), b'')
                if failure == 'eof':
                    os.close(release_write); release_write = -1
                elif failure == 'invalid-release':
                    os.write(release_write, b'X')
                elif failure is None:
                    process.kill()  # Only the retained direct child is signalled.
                process.communicate(timeout=1.2)
                self.assertEqual(process.returncode, {'eof': 124, 'timeout': 123, 'invalid-release': 125}.get(failure, -9))
                self.assertEqual((directory/'native-completion.json').read_bytes(), b'')
                self.assertEqual((directory/'native.json').read_bytes(), b'{"partial":')
                while live(worker):
                    self.assertLess(time.monotonic(), deadline, 'Independent worker alarm did not expire')
                    time.sleep(0.025)
            finally:
                cleanup_complete = False
                cleanup_errors = []
                try:
                    try:
                        if process is not None and process.poll() is None:
                            process.kill(); process.communicate(timeout=1)
                    except BaseException as error:
                        cleanup_errors.append(error)
                    finally:
                        for fd in (ready_read, ready_write, release_read, release_write):
                            if fd >= 0:
                                try:
                                    os.close(fd)
                                except BaseException as error:
                                    cleanup_errors.append(error)
                    if cleanup_errors:
                        raise cleanup_errors[0]
                    if worker is None and process is not None:
                        raise AssertionError('Worker identity unavailable for cleanup')
                    if worker is not None:
                        cleanup_deadline = time.monotonic()+3
                        while live(worker):
                            self.assertLess(time.monotonic(), cleanup_deadline, 'Owned worker cleanup uncertain')
                            time.sleep(0.025)
                    cleanup_complete = True
                finally:
                    if not cleanup_complete:
                        type(self).retained_worker = dict(directory=str(directory), identity=worker,
                            cleanup_errors=[type(error).__name__ for error in cleanup_errors])

    def test_unresolved_lifetime_cleanup_stops_before_another_launch(self):
        for uncertainty in ('live', 'identity'):
            case = NativeMaintenance('test_worker_has_independent_lifetime_after_controller_loss')
            case.base = self.directory()
            child = Mock(pid=1234, returncode=None)
            child.poll.side_effect = lambda: child.returncode
            child.kill.side_effect = lambda: setattr(child, 'returncode', -9)
            child.communicate.return_value = (b'', b'')
            worker = dict(pid=99, ppid=1234, uid=os.getuid(), start_sec=1, start_usec=2, status=2)
            def command(argv, **kwargs):
                if argv[1:2] == ['exact'] and uncertainty == 'identity':
                    raise RuntimeError('Exact identity unavailable')
                return subprocess.CompletedProcess(argv, 0, json.dumps(worker).encode() if argv[1:2] == ['exact'] else b'', b'')
            clocks = iter(range(100))
            previous = NativeMaintenance.retained_worker
            try:
                with patch.object(subprocess, 'run', side_effect=command), patch.object(subprocess, 'Popen', return_value=child) as launch, \
                        patch.object(select, 'select', side_effect=lambda reads, *args: (reads, [], [])), \
                        patch.object(os, 'read', return_value=json.dumps(worker).encode()+b'\n'), \
                        patch.object(time, 'monotonic', side_effect=lambda: next(clocks)), patch.object(time, 'sleep'), \
                        patch.object(Path, 'read_bytes', autospec=True, side_effect=lambda path: b'{"partial":' if path.name == 'native.json' else b''), self.assertRaises((AssertionError, RuntimeError)):
                    case.test_worker_has_independent_lifetime_after_controller_loss()
                self.assertEqual(launch.call_count, 1)
                self.assertEqual(NativeMaintenance.retained_worker['identity'], worker)
                self.assertTrue(Path(NativeMaintenance.retained_worker['directory']).exists())
            finally:
                NativeMaintenance.retained_worker = previous

    def test_lifetime_controller_cleanup_error_closes_every_owned_pipe(self):
        real_pipe, real_close = os.pipe, os.close
        for error, close_error in ((subprocess.TimeoutExpired('owned fixture', 1), False),
                                   (KeyboardInterrupt('cancelled'), False),
                                   (subprocess.TimeoutExpired('owned fixture', 1), True)):
            case = NativeMaintenance('test_worker_has_independent_lifetime_after_controller_loss')
            case.base = self.directory()
            child = Mock(pid=1234, returncode=None)
            child.poll.side_effect = lambda: child.returncode
            child.kill.side_effect = lambda: setattr(child, 'returncode', -9)
            child.communicate.side_effect = error
            endpoints, closed = [], []
            def pipe():
                pair = real_pipe(); endpoints.extend(pair); return pair
            def close(fd):
                closed.append(fd); real_close(fd)
                if close_error and fd == endpoints[0]:
                    raise OSError('injected pipe close uncertainty')
            previous = NativeMaintenance.retained_worker
            try:
                with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')), \
                        patch.object(subprocess, 'Popen', return_value=child) as launch, \
                        patch.object(select, 'select', return_value=([], [], [])), \
                        patch.object(os, 'pipe', side_effect=pipe), patch.object(os, 'close', side_effect=close), \
                        self.assertRaises(type(error)) as caught:
                    case.test_worker_has_independent_lifetime_after_controller_loss()
                self.assertIs(caught.exception, error)
                self.assertEqual(launch.call_count, 1)
                self.assertEqual(len(endpoints), 4)
                self.assertEqual(set(closed), set(endpoints))
                for fd in endpoints:
                    with self.assertRaises(OSError) as unavailable:
                        os.fstat(fd)
                    self.assertEqual(unavailable.exception.errno, errno.EBADF)
                retained = NativeMaintenance.retained_worker
                self.assertTrue(Path(retained['directory']).exists())
                self.assertIsNone(retained['identity'])
                self.assertEqual(retained['cleanup_errors'],
                    [type(error).__name__] + (['OSError'] if close_error else []))
            finally:
                NativeMaintenance.retained_worker = previous
                for fd in endpoints:
                    try:
                        real_close(fd)
                    except OSError:
                        pass

    def test_separately_signed_leaf_survives_copy_and_tampering_refuses(self):
        directory = self.directory(); leaf = directory/'maintenance-native'
        shutil.copyfile(self.binary(), leaf); leaf.chmod(0o700)
        signed = subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--identifier',
                                 'com.alvinhhh.stallionfs.maintenance', str(leaf)],
                                capture_output=True, timeout=10)
        self.assertEqual(signed.returncode, 0, signed.stderr)
        copied = directory/'copied-maintenance-native'; shutil.copyfile(leaf, copied); copied.chmod(0o700)
        requirement = '=identifier "com.alvinhhh.stallionfs.maintenance"'
        verify = subprocess.run(['/usr/bin/codesign','--verify','--strict','-R',requirement,str(copied)],
                                capture_output=True, timeout=10)
        self.assertEqual(verify.returncode, 0, verify.stderr)
        self.assertEqual(copied.read_bytes(), leaf.read_bytes())
        self.assertEqual(json.loads(self.run_leaf('observe', binary=copied).stdout)['schema'], 1)
        wrong = subprocess.run(['/usr/bin/codesign','--verify','--strict','-R','=identifier "wrong.publisher"',str(copied)],
                               capture_output=True, timeout=10)
        self.assertNotEqual(wrong.returncode, 0)
        with copied.open('r+b') as stream:
            first = stream.read(1); stream.seek(0); stream.write(bytes([first[0] ^ 1]))
        tampered = subprocess.run(['/usr/bin/codesign','--verify','--strict','-R',requirement,str(copied)],
                                  capture_output=True, timeout=10)
        self.assertNotEqual(tampered.returncode, 0)

    def test_typed_identity_mount_and_encoding_predicates(self):
        wrapper = self.base/'predicates.c'
        wrapper.write_text('#define main leaf_main\n#include '+json.dumps(str(SOURCE))+'\n#undef main\n'
            '#include <assert.h>\nint main(void) {\n'
            'assert(app_overlap("/System/Volumes/Data/Applications/StallionFS.app/private"));\n'
            'assert(app_overlap("/Applications/StallionFS.app"));\n'
            'assert(app_overlap("/Applications/StallionFS.app/private-empty-output"));\n'
            'assert(app_overlap("/applications/stallionfs.APP/private-empty-output"));\n'
            'assert(!app_overlap("/Applications/StallionFS.app-other"));\n'
            'assert(!app_overlap("/private/tmp/retained"));\n'
            'struct kinfo_proc a = {0}, b = {0}; a.kp_proc.p_pid = b.kp_proc.p_pid = 42;\n'
            'assert(identity_equal(&a,&b)); b.kp_proc.p_starttime.tv_usec=1; assert(!identity_equal(&a,&b));\n'
            'b=a; b.kp_eproc.e_ppid=2; assert(!identity_equal(&a,&b));\n'
            'struct statfs m={0},n={0}; assert(mount_equal(&m,&n)); n.f_flags_ext=1; assert(!mount_equal(&m,&n));\n'
            'assert(valid_utf8("\\xc3\\xa9",2)); assert(!valid_utf8("\\xc0\\x80",2));\n'
            'assert(!valid_utf8("\\xed\\xa0\\x80",3)); assert(!valid_utf8("\\xf4\\x90\\x80\\x80",4));\n'
            'return 0; }\n')
        target = self.base/'predicates'
        result = subprocess.run(['xcrun','clang','-std=c11','-Wall','-Wextra','-Werror',str(wrapper),'-o',str(target)],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        subprocess.run([str(target)], check=True, timeout=5)


if __name__ == '__main__':
    unittest.main()
