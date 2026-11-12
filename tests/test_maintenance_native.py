"""Owned native fixtures and read-only kernel snapshots; no installed execution."""
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'filesystem/fskit/maintenance_native.c'


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('xcrun'), 'Darwin native SDK required')
class NativeMaintenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='maintenance-native-tests-')
        cls.base = Path(cls.temporary.name).resolve()
        cls.base.chmod(0o700)
        cls.binaries = {}

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

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
        directory = self.directory()
        process = subprocess.Popen([str(self.binary(SFS_TEST_FAULT=6, SFS_DEADLINE_MS=100)),
                                    'retain', str(directory)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic()+2
            while not (directory/'native.json').exists() or not (directory/'native.json').stat().st_size:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            before = json.loads(self.run_leaf('observe').stdout)
            worker = [row for row in before['processes'] if row['ppid'] == process.pid]
            self.assertEqual(len(worker), 1)
            identity = {key: worker[0][key] for key in ('pid', 'start_sec', 'start_usec')}
            # This is the direct child created by this test. The worker is never signalled here.
            process.kill(); process.communicate(timeout=3)
            time.sleep(2.1)
            after = json.loads(self.run_leaf('observe').stdout)
            live = [row for row in after['processes']
                    if all(row[key] == value for key, value in identity.items()) and row['status'] != 5]
            self.assertEqual(live, [])
            self.assertEqual((directory/'native-completion.json').read_bytes(), b'')
            self.assertEqual((directory/'native.json').read_bytes(), b'{"partial":')
        finally:
            if process.poll() is None:
                process.kill(); process.communicate(timeout=3)

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
