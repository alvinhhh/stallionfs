"""Integration checks for the installed native launcher and its Python helper."""
from importlib.metadata import distribution, version
import os
import json
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import unittest
import hashlib
import fcntl
import textwrap

from stallionfs import __version__


@unittest.skipUnless(sys.platform == 'darwin', 'Native image CLI requires macOS/APFS')
class NativeImageCLI(unittest.TestCase):
    """Installed ordinary bridge plus isolated diagnostic linkage of the same source."""
    @classmethod
    def setUpClass(cls):
        import test_image as capture
        cls.capture = capture
        destination = os.environ.get('STALLIONFS_NATIVE_CLI_ARTIFACT_DIR')
        cls.keep_artifacts = destination is not None
        if destination:
            cls.artifacts = Path(destination).resolve()
            cls.artifacts.mkdir(mode=0o700)  # Fresh path only; never reuse prior products.
        else:
            cls.artifacts = Path(tempfile.mkdtemp(prefix='stallionfs-native-cli-')).resolve()
        cls.failed = True
        cls.sequence = 0
        cls.previous = capture._install_command_handlers()
        cls.addClassCleanup(cls.finish)
        source = Path(__file__).resolve().parents[1]
        tests, filesystem = source / 'tests', source / 'filesystem'
        clang = cls.owned('find-clang', ['/usr/bin/xcrun', '--find', 'clang'], 15).stdout.strip()
        sdk = cls.owned('find-sdk', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'], 15).stdout.strip()
        flags = [clang, '-std=c11', '-Wall', '-Wextra', '-O1', '-g', '-isysroot', sdk, '-I', filesystem,
                 '-I', sysconfig.get_path('include')]
        cls.fixture = cls.artifacts / 'fixture'
        cls.owned('fixture-build', [*flags, tests / 'native_image_fixture.c', filesystem / 'image.c', '-o', cls.fixture])
        normal = cls.artifacts / 'diagnostic-core.o'
        replacements = ('pwrite', 'malloc', 'calloc', 'clock_gettime')
        cls.owned('diagnostic-core', [*flags, *(f'-D{name}=sfs_diag_{name}' for name in replacements),
                    '-Dpread=sfs_bridge_test_pread', '-Dfcntl=sfs_bridge_test_fcntl', '-Dclose=sfs_bridge_test_close',
                    '-include', tests / 'native_image_bridge_hooks.h', '-c', filesystem / 'image.c', '-o', normal])
        bridge = cls.artifacts / 'diagnostic-bridge.o'
        cls.owned('diagnostic-bridge', [*flags, '-Dclock_gettime=sfs_bridge_test_clock',
                    '-Dclose=sfs_bridge_test_parent_close', '-Dsfs_image_open_readonly=sfs_bridge_test_guard_open',
                    '-DPyLong_FromLongLong=sfs_bridge_test_signed', '-DPyLong_FromUnsignedLongLong=sfs_bridge_test_unsigned',
                    '-DPyUnicode_FromStringAndSize=sfs_bridge_test_text',
                    '-Dsfs_image_snapshot=sfs_bridge_test_snapshot', '-Dsfs_image_prepare_restore=sfs_bridge_test_restore',
                    '-include', tests / 'native_image_bridge_hooks.h', '-c', source / 'stallionfs/_image.c', '-o', bridge])
        importer = cls.artifacts / 'diagnostic-importer.o'
        cls.owned('diagnostic-importer', [*flags, '-Dsfs_image_verify=sfs_bridge_test_import_verify',
                    '-Dsfs_image_open_readonly=sfs_bridge_test_import_open', '-Dsfs_image_close=sfs_bridge_test_import_close',
                    '-Dsfs_image_write=sfs_bridge_test_import_write', '-Dmalloc=sfs_bridge_test_import_malloc',
                    '-Dpwrite=sfs_bridge_test_import_pwrite',
                    '-include', tests / 'native_image_bridge_hooks.h',
                    '-c', source / 'stallionfs/_native_import.c', '-o', importer])
        hooks = cls.artifacts / 'diagnostic-hooks.o'
        cls.owned('diagnostic-hooks', [*flags, '-c', tests / 'native_image_bridge_hooks.c', '-o', hooks])
        cls.diagnostic = cls.artifacts / ('_image' + sysconfig.get_config_var('EXT_SUFFIX'))
        cls.owned('diagnostic-link', [clang, '-isysroot', sdk, '-bundle', '-undefined', 'dynamic_lookup', bridge, importer, normal, hooks, '-o', cls.diagnostic])
        cls.failed = False

    @classmethod
    def owned(cls, label, argv, timeout=90):
        cls.sequence += 1
        child = cls.capture._owned_command([str(value) for value in argv], cwd=cls.artifacts,
                    timeout=timeout, stem=cls.artifacts / f'{cls.sequence:03}-{label}')
        if child.returncode:
            cls.failed = True
            raise AssertionError(f'{label} failed: {child.stderr[-4000:]}')
        return child

    @classmethod
    def finish(cls):
        cls.capture._restore_command_handlers(cls.previous)
        state = cls.capture._command_state
        if state['failure'] is not None or state['active'] is not None or state['first_signal'] is not None or state['signal_count']:
            cls.failed = True
        if cls.failed or cls.keep_artifacts:
            print(f'Native CLI evidence retained: {cls.artifacts}', file=sys.stderr)
        else:
            shutil.rmtree(cls.artifacts)

    def setUp(self):
        self.prior_failures = len(self._outcome.result.failures) + len(self._outcome.result.errors)
        self.base = self.artifacts / self._testMethodName
        self.base.mkdir(mode=0o700)
        self.store = self.base / 'store'
        self.launcher = Path(sysconfig.get_path('scripts')) / 'sfs'
        self.assertTrue(self.launcher.is_file(), 'Install the candidate wheel before this test')

    def tearDown(self):
        if len(self._outcome.result.failures) + len(self._outcome.result.errors) > self.prior_failures:
            type(self).failed = True

    def command(self, *args, status=0):
        # The capture expects a clean child; the small adapter records the public
        # command's intentional nonzero status without treating it as a crash.
        script = 'import json,subprocess,sys; p=subprocess.run(sys.argv[1:],capture_output=True,text=True,timeout=15); print(json.dumps(dict(returncode=p.returncode,stdout=p.stdout,stderr=p.stderr)))'
        child = self.owned('public-cli', [sys.executable, '-I', '-c', script, self.launcher,
                            '--root', self.store, '--json', *args], 25)
        observed = json.loads(child.stdout)
        self.assertEqual(observed['returncode'], status, observed['stderr'])
        return json.loads(observed['stdout'] if status == 0 else observed['stderr'])

    def seed(self, suffix='image'):
        directory = self.base / suffix
        directory.mkdir(mode=0o700)
        self.owned('seed', [self.fixture, 'seed', directory])
        return directory

    def register(self, directory):
        return self.command('register-native-image', directory / 'image.sfs')['id']

    def test_installed_registration_snapshot_rollback_exact_state_and_recovery(self):
        directory = self.seed()
        image = directory / 'image.sfs'
        identity, digest = (image.stat().st_dev, image.stat().st_ino), hashlib.sha256(image.read_bytes()).hexdigest()
        workspace = self.register(directory)
        self.assertEqual((image.stat().st_dev, image.stat().st_ino), identity)
        self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(), digest)
        self.assertEqual(self.command('snapshot', workspace, '--name', 'before')['id'], 'before')
        newer = self.owned('edit', [self.fixture, 'edit', directory]).stdout.strip()
        self.command('snapshot', workspace, '--name', 'newer')
        before = self.command('snapshots', workspace)
        restored = self.command('rollback', workspace, 'before')
        self.assertTrue(restored['native_image_result']['committed'])
        self.assertEqual(restored['native_image_result']['receipt']['fence_succeeded'], 3)
        self.assertEqual(restored['native_image_result']['close_receipt']['status'], 0)
        after = self.command('snapshots', workspace)
        self.assertEqual(after[:len(before)], before)
        self.assertEqual(after[-1]['id'], restored['recovery'])
        self.owned('verify-target', [self.fixture, 'verify', directory, 'before', newer])
        self.owned('verify-recovery', [self.fixture, 'verify-edited', directory, restored['recovery']])
        self.assertEqual((image.stat().st_dev, image.stat().st_ino), identity)
        for kind in ('snapshots', 'recovery', 'journals'):
            self.assertEqual(list((self.store / kind).iterdir()), [])
        from stallionfs import _image
        symbols = self.owned('production-symbols', ['/usr/bin/nm', _image.__file__]).stdout.lower()
        self.assertFalse(any(word in symbols for word in ('sfs_diag_', 'sfs_bridge_test_', 'sfs_image_diagnostic_')))

    def test_scoped_backing_guard_retains_exact_inode_and_consumes_after_exceptions(self):
        from stallionfs import _image
        import errno
        import threading
        directory = self.seed()
        def target(parent, component='image.sfs', identity=None):
            info = parent.stat()
            value = dict(directory=str(parent), component=component,
                         parent=[info.st_dev, info.st_ino], file=None)
            if identity is None:
                inspected = _image.inspect(value)
                self.assertTrue(inspected['ok'], inspected)
                identity = inspected['identity']
            return value | identity
        original = target(directory)
        tokens = []
        def blocked(value):
            with self.assertRaises(OSError) as caught:
                _image.with_backing_guard(value, lambda token: self.fail('competing scope entered'))
            self.assertEqual(caught.exception.errno, errno.EBUSY)
        moved = self.base / 'moved'
        moved.mkdir(mode=0o700)
        destination = target(moved, identity={k: original[k] for k in ('file', 'uuid')})
        alias = self.base / 'alias'
        alias.symlink_to(directory, target_is_directory=True)
        aliased = original | dict(directory=str(alias / '..' / directory.name))
        def action(token):
            tokens.append(token)
            with self.assertRaises(TypeError):
                type(token)()
            token.verify(original)
            blocked(original)
            blocked(aliased)
            # A failed independently opened handle must not release this flock.
            blocked(original)
            errors = []
            def foreign_thread():
                try:
                    token.verify(original)
                except RuntimeError as error:
                    errors.append(error)
            thread = threading.Thread(target=foreign_thread)
            thread.start(); thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            (directory / 'image.sfs').rename(moved / 'image.sfs')
            token.verify(destination)
            for wrong in (destination | dict(file=[0, 0]), destination | dict(uuid='00' * 16)):
                with self.assertRaises(OSError):
                    token.verify(wrong)
            blocked(destination)
            return 'host action complete'
        self.assertEqual(_image.with_backing_guard(original, action), 'host action complete')
        self.assertEqual(tokens[0].close_result['status'], 0)
        with self.assertRaises(RuntimeError):
            tokens[0].verify(destination)
        self.assertEqual(_image.with_backing_guard(destination, lambda token: 42), 42)
        for primary in (RuntimeError('action failure'), KeyboardInterrupt('cancel action')):
            def fail(token):
                tokens.append(token)
                raise primary
            with self.assertRaises(type(primary)) as caught:
                _image.with_backing_guard(destination, fail)
            self.assertIs(caught.exception, primary)
            self.assertIs(primary.native_backing_guard, tokens[-1])
            self.assertEqual(tokens[-1].close_result['status'], 0)
            self.assertEqual(_image.with_backing_guard(destination, lambda token: 7), 7)
        class RejectDisposition(RuntimeError):
            def __setattr__(self, name, value):
                if name == 'native_backing_guard':
                    raise MemoryError('cannot attach disposition')
                super().__setattr__(name, value)
        primary = RejectDisposition('preserved original')
        def fail_attachment(token):
            raise primary
        with self.assertRaises(RejectDisposition) as caught:
            _image.with_backing_guard(destination, fail_attachment)
        self.assertIs(caught.exception, primary)
        self.assertEqual(primary.__context__.native_backing_guard.close_result['status'], 0)
        for replacement in (destination | dict(file=[0, 0]), destination | dict(uuid='00' * 16)):
            with self.assertRaises(OSError):
                _image.with_backing_guard(replacement, lambda token: self.fail('replaced identity entered'))
        replacement_dir = self.seed('replacement')
        (moved / 'image.sfs').rename(moved / 'saved.sfs')
        (replacement_dir / 'image.sfs').rename(moved / 'image.sfs')
        with self.assertRaises(OSError):
            _image.with_backing_guard(destination, lambda token: self.fail('replacement inode entered'))
        (moved / 'image.sfs').rename(replacement_dir / 'image.sfs')
        (moved / 'saved.sfs').rename(moved / 'image.sfs')
        symlink = moved / 'link.sfs'
        symlink.symlink_to('image.sfs')
        with self.assertRaises(OSError):
            _image.with_backing_guard(destination | dict(component='link.sfs'),
                                      lambda token: self.fail('symlink backing entered'))
        hardlink = moved / 'alias.sfs'
        os.link(moved / 'image.sfs', hardlink)
        with self.assertRaises(OSError):
            _image.with_backing_guard(destination, lambda token: self.fail('hardlink entered'))
        hardlink.unlink()
        def unlink(token):
            tokens.append(token)
            (moved / 'image.sfs').unlink()
            # Deliberate unlink is followed only by terminal consuming close.
        _image.with_backing_guard(destination, unlink)
        self.assertEqual(tokens[-1].close_result['status'], 0)

    def test_guard_wrapper_retains_precallback_carrier_and_primary_extraction_errors(self):
        from stallionfs import _native
        from unittest.mock import patch
        receipt = {'core_consumed': True, 'status': 0, 'parent_close_errno': 0}
        class Token:
            fail = False
            @property
            def close_result(self):
                if self.fail: raise MemoryError('receipt allocation')
                return receipt
        for fallback in (False, True):
            token = Token()
            error = OSError('pre-callback failure')
            carrier = RuntimeError('fallback') if fallback else error
            carrier.native_backing_guard = token
            if fallback: error.__context__ = carrier
            with patch('stallionfs._native._image.with_backing_guard', side_effect=error):
                with self.assertRaises(OSError) as caught: _native.guarded({}, expected_anchor={})
            self.assertIs(caught.exception, error)
            self.assertIs(error.native_current_guard, receipt)
            self.assertIs(carrier.native_backing_guard, token)
            token.fail = True
            del error.native_current_guard
            with patch('stallionfs._native._image.with_backing_guard', side_effect=error):
                with self.assertRaises(OSError) as caught: _native.guarded({}, expected_anchor={})
            self.assertIs(caught.exception, error)
            self.assertIs(carrier.native_backing_guard, token)
        for denied in ('native_backing_guard', '__context__'):
            class HostileError(Exception):
                def __getattribute__(self, name):
                    if name == denied: raise RuntimeError('diagnostic attribute refused')
                    return super().__getattribute__(name)
            error = HostileError('original')
            with patch('stallionfs._native._image.with_backing_guard', side_effect=error):
                with self.assertRaises(HostileError) as caught: _native.guarded({}, expected_anchor={})
            self.assertIs(caught.exception, error)
        error = OSError('original before diagnostic allocation failure')
        token = Token(); error.native_backing_guard = token
        with patch('stallionfs._native._image.with_backing_guard', side_effect=error), \
             patch('stallionfs._native.set', side_effect=MemoryError('seen allocation'), create=True):
            with self.assertRaises(OSError) as caught: _native.guarded({}, expected_anchor={})
        self.assertIs(caught.exception, error)
        self.assertIs(error.native_backing_guard, token)

    def test_scoped_backing_guard_expected_anchor_exact_and_copied_before_open(self):
        from stallionfs import _image
        import errno
        directory = self.seed()
        info = directory.stat()
        target = dict(directory=str(directory), component='image.sfs', parent=[info.st_dev, info.st_ino], file=None)
        inspected = _image.inspect(target); target.update(inspected['identity'])
        expected = {key: inspected['receipt'][key] for key in ('generation', 'root_digest', 'committed_end')}
        tokens = []
        def held(token):
            tokens.append(token)
            with self.assertRaises(OSError) as caught: _image.with_backing_guard(target, lambda _: None)
            self.assertEqual(caught.exception.errno, errno.EBUSY)
            return 17
        self.assertEqual(_image.with_backing_guard(target, held), 17)
        self.assertEqual(_image.with_backing_guard(target, held, None), 17)
        self.assertEqual(_image.with_backing_guard(target, held, expected), 17)
        self.assertEqual(len(tokens), 3)
        for token in tokens:
            self.assertTrue(token.close_result['core_consumed'])
            with self.assertRaises(RuntimeError): token.verify(target)
        for key in expected:
            mismatch = dict(expected)
            mismatch[key] = '0' * 64 if key == 'root_digest' else mismatch[key] + 1
            with self.assertRaises(OSError) as caught:
                _image.with_backing_guard(target, lambda _: self.fail('stale callback invoked'), mismatch)
            self.assertEqual(caught.exception.errno, errno.ESTALE)
            self.assertTrue(caught.exception.native_anchor_mismatch)
            receipt = caught.exception.native_backing_guard.close_result
            self.assertTrue(receipt['core_consumed'])
            self.assertEqual(receipt['status'], 0)
            self.assertEqual(receipt['parent_close_errno'], 0)
        class AnchorDict(dict): pass
        class AnchorInteger(int): pass
        class AnchorDigest(str): pass
        invalid = [{}, dict(expected, extra=1), {key: value for key, value in expected.items() if key != 'generation'}]
        invalid += [AnchorDict(expected), dict(expected, generation=AnchorInteger(expected['generation'])),
                    dict(expected, committed_end=AnchorInteger(expected['committed_end'])),
                    dict(expected, root_digest=AnchorDigest(expected['root_digest']))]
        for key in ('generation', 'committed_end'):
            invalid += [dict(expected, **{key: value}) for value in (True, False, -1, 1 << 64, 1.0, '1')]
        invalid += [dict(expected, root_digest=value) for value in ('A' * 64, 'g' * 64, '0' * 63, b'0' * 64)]
        for value in invalid:
            # Invalid expected values must fail before a nonexistent resource is opened.
            with self.assertRaises((ValueError, TypeError, OverflowError)):
                _image.with_backing_guard(dict(target, directory='/nonexistent-native-anchor-test'),
                                          lambda _: self.fail('invalid anchor callback invoked'), value)
        mutable = dict(expected)
        class Directory:
            def __fspath__(self):
                mutable['generation'] += 1
                return str(directory)
        self.assertEqual(_image.with_backing_guard(dict(target, directory=Directory()), lambda _: 19, mutable), 19)
        self.assertTrue(_image.snapshot(target, 'advance-anchor')['ok'])
        with self.assertRaises(OSError) as caught:
            _image.with_backing_guard(target, lambda _: self.fail('old committed anchor accepted'), expected)
        self.assertTrue(caught.exception.native_anchor_mismatch)
        self.assertEqual(caught.exception.native_backing_guard.close_result['status'], 0)

    def test_scoped_backing_guard_anchor_mismatch_retains_close_and_allocation_failures(self):
        directory = self.seed()
        script = textwrap.dedent('''            import ctypes,importlib.util,json,sys
            from pathlib import Path
            module_path,directory=sys.argv[1:]
            spec=importlib.util.spec_from_file_location('stallionfs._image',module_path)
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            control=ctypes.CDLL(module_path).sfs_bridge_test_configure
            control.argtypes=[ctypes.c_int]*4;control.restype=None
            info=Path(directory).stat()
            target=dict(directory=directory,component='image.sfs',parent=[info.st_dev,info.st_ino],file=None)
            observed=module.inspect(target);target.update(observed['identity'])
            anchor={k:observed['receipt'][k] for k in ('generation','root_digest','committed_end')}
            stale=dict(anchor,generation=anchor['generation']+1)
            for flags in (0,1048576,262144,64,1048576|262144|64):
                called=[];control(0,0,flags,0)
                try:module.with_backing_guard(target,lambda token:called.append(token),stale)
                except OSError as error:
                    assert error.native_anchor_mismatch and not called
                    carrier=error.native_backing_guard
                    if flags & 64:
                        try:carrier.close_result
                        except MemoryError:pass
                        else:raise AssertionError('report allocation fault not exercised')
                    receipt=carrier.close_result
                    assert receipt['core_consumed']
                    assert (receipt['status'] != 0) == bool(flags & 1048576)
                    assert (receipt['parent_close_errno'] != 0) == bool(flags & 262144)
                else:raise AssertionError('mismatch returned success')
                control(0,0,0,0)
                assert module.with_backing_guard(target,lambda _:7,anchor)==7
            control(0,0,524288,0);called=[]
            try:module.with_backing_guard(target,lambda token:called.append(token),anchor)
            except KeyboardInterrupt as error:
                assert not called
                assert error.native_backing_guard.close_result['core_consumed']
            else:raise AssertionError('pre-callback cancellation was lost')
            control(0,0,0,0)
            print('PASS expected-anchor mismatch, consumed close, parent close, report allocation and cancellation')
        ''')
        child = self.owned('guard-expected-faults', [sys.executable, '-I', '-B', '-c', script,
                                                    self.diagnostic, directory])
        self.assertEqual(child.stdout, 'PASS expected-anchor mismatch, consumed close, parent close, report allocation and cancellation\n')
        self.assertEqual(child.stderr, '')

    def test_scoped_backing_guard_preserves_consumed_close_error_and_primary(self):
        directory = self.seed()
        script = textwrap.dedent('''            import ctypes,importlib.util,json,sys
            from pathlib import Path
            module_path,directory=sys.argv[1:]
            spec=importlib.util.spec_from_file_location('stallionfs._image',module_path)
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            control=ctypes.CDLL(module_path).sfs_bridge_test_configure
            control.argtypes=[ctypes.c_int]*4;control.restype=None
            info=Path(directory).stat()
            target=dict(directory=directory,component='image.sfs',parent=[info.st_dev,info.st_ino],file=None)
            target.update(module.inspect(target)['identity'])
            for primary in (None,KeyboardInterrupt('original cancellation')):
                tokens=[]
                def action(token):
                    tokens.append(token)
                    control(0,0,128,0)
                    if primary is not None:raise primary
                    return 'mutation completed'
                try:
                    module.with_backing_guard(target,action)
                    raise AssertionError('close failure returned success')
                except BaseException as error:
                    if primary is not None:assert error is primary
                    else:assert isinstance(error,OSError)
                    assert error.native_backing_guard is tokens[0]
                    assert tokens[0].close_result['status'] != 0
                control(0,0,0,0)
                assert module.with_backing_guard(target,lambda token:'released')=='released'
                try:tokens[0].verify(target)
                except RuntimeError:pass
                else:raise AssertionError('consumed token reused')
            print('PASS consuming guard close dispositions')
        ''')
        child = self.owned('guard-consumed-close', [sys.executable, '-I', '-B', '-c',
                                                   script, self.diagnostic, directory])
        self.assertEqual(child.stdout, 'PASS consuming guard close dispositions\n')
        self.assertEqual(child.stderr, '')

    def test_scoped_backing_guard_excludes_prestarted_process(self):
        from stallionfs import _image
        import selectors
        directory = self.seed()
        info = directory.stat()
        target = dict(directory=str(directory), component='image.sfs',
                      parent=[info.st_dev, info.st_ino], file=None)
        target.update(_image.inspect(target)['identity'])
        script = """import json,sys
from stallionfs import _image
print('ready',flush=True)
for line in sys.stdin:
    try:
        value=_image.with_backing_guard(json.loads(line),lambda token: 'entered')
        print(value,flush=True)
    except OSError as error:
        print(error.errno,flush=True)
"""
        # Start before acquisition; the child never inherits an active core lock.
        child = subprocess.Popen([sys.executable, '-I', '-B', '-c', script],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True)
        def response():
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(10), 'competitor response timed out')
            return child.stdout.readline().strip()
        def attempt():
            child.stdin.write(json.dumps(target) + '\n'); child.stdin.flush()
            return response()
        try:
            self.assertEqual(response(), 'ready')
            def action(token):
                self.assertEqual(attempt(), str(__import__('errno').EBUSY))
                self.assertEqual(attempt(), str(__import__('errno').EBUSY))
                token.verify(target)
            _image.with_backing_guard(target, action)
            self.assertEqual(attempt(), 'entered')
            child.stdin.close(); child.stdin = None
            stdout, stderr = child.communicate(timeout=10)
            self.assertEqual((child.returncode, stdout, stderr), (0, '', ''))
        finally:
            if child.poll() is None:
                child.kill(); child.communicate(timeout=10)

    def test_duplicate_registrations_share_inode_lock_and_native_data_is_not_cleanup_owned(self):
        from stallionfs.core import Store
        directory = self.seed()
        first, second = self.register(directory), self.register(directory)
        image = directory / 'image.sfs'
        with image.open('rb') as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            blocked = self.command('snapshot', second, '--name', 'blocked', status=1)
            self.assertEqual(blocked['native_image_result']['error_code'], __import__('errno').EBUSY)
        with Store(self.store)._lease(first):
            self.assertIn('managed use', self.command('snapshot', first, '--name', 'blocked', status=1)['error'])
        self.command('snapshot', first, '--name', 'visible')
        self.assertEqual(self.command('snapshots', second)[0]['id'], 'visible')
        digest = hashlib.sha256(image.read_bytes()).hexdigest()
        for args in (('enroll', first), ('close', first, '--quiescent'), ('remove', first), ('mount', first), ('unmount', first)):
            self.command(*args, status=1)
        self.command('cleanup', '--enable')
        self.assertEqual(self.command('cleanup', '--apply')['retired'], [])
        self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(), digest)

    def test_registration_alias_and_identity_failures_and_fresh_reopen(self):
        directory = self.seed()
        alias = self.base / 'alias'; alias.symlink_to(directory, target_is_directory=True)
        workspace = self.command('register-native-image', alias / 'image.sfs')['id']
        final_link = directory / 'link.sfs'; final_link.symlink_to(directory / 'image.sfs')
        self.command('register-native-image', final_link, status=1)
        directory.chmod(0o755)
        try:
            self.command('snapshot', workspace, '--name', 'never', status=1)
        finally:
            directory.chmod(0o700)
        original = directory / 'image.sfs'
        old = directory / 'old.sfs'; original.rename(old); shutil.copy2(old, original)
        mismatch = self.command('snapshot', workspace, '--name', 'never', status=1)
        self.assertEqual(mismatch['native_image_result']['error_code'], __import__('errno').ESTALE)
        original.unlink(); old.rename(original)
        self.command('snapshot', workspace, '--name', 'valid')
        # A malformed pair cannot be hidden by a prior healthy registration.
        with original.open('r+b') as stream:
            byte = stream.read(1); stream.seek(0); stream.write(bytes([byte[0] ^ 1])); stream.flush(); os.fsync(stream.fileno())
        failed = self.command('snapshots', workspace, status=1)
        self.assertFalse(failed['native_image_result']['ok'])
        self.assertNotEqual(failed['native_image_result']['receipt']['status'], 0)

    def test_no_implicit_eviction_when_snapshot_catalog_is_full(self):
        directory = self.seed(); workspace = self.register(directory)
        for index in range(32):
            self.command('snapshot', workspace, '--name', f'root-{index}')
        before = self.command('snapshots', workspace)
        failed = self.command('rollback', workspace, 'root-0', status=1)
        self.assertFalse(failed['native_image_result']['committed'])
        self.assertFalse(failed['native_image_result']['commit_attempted'])
        self.assertEqual(self.command('snapshots', workspace), before)
        self.command('snapshot', workspace, '--name', 'overflow', status=1)
        self.assertEqual(self.command('snapshots', workspace), before)

    def test_native_import_large_resource_fork(self):
        from stallionfs import _image
        script = textwrap.dedent('''
            import ctypes, hashlib, importlib.util, json, os, sys
            from pathlib import Path
            module_path, base = sys.argv[1:]
            spec = importlib.util.spec_from_file_location('stallionfs._image', module_path)
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            base = Path(base); base.mkdir(mode=0o700)
            source = base / 'input' / 'repo'; source.parent.mkdir(mode=0o700); source.mkdir(mode=0o700)
            destination = base / 'owned'; destination.mkdir(mode=0o700)
            path = source / 'file'; path.write_bytes(b'file')
            value = b'v' * (16 * 1024 * 1024) + b'!'
            libc = ctypes.CDLL(None, use_errno=True)
            libc.setxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
            status = libc.setxattr(os.fsencode(path), b'com.apple.ResourceFork', value, len(value), 0, 1)
            assert status == 0, ctypes.get_errno()
            def pair(path):
                st = path.stat(); return [st.st_dev, st.st_ino]
            result = module.create_from_tree({'directory': str(source), 'root': pair(source)},
                {'directory': str(destination), 'parent': pair(destination), 'component': 'image.sfs',
                 'before_create': lambda: None}, 1 << 28)
            assert result['candidate_complete'], result
            assert result['resources']['xattr_memory_high_water'] == len(value), result
            assert result['resources']['scratch_bytes'] > len(value), result
            print(json.dumps({'directory': str(destination), 'size': len(value), 'sha256': hashlib.sha256(value).hexdigest(), 'result': result}))
        ''')
        child = self.owned('large-resource-fork', [sys.executable, '-I', '-c', script,
            _image.__file__, self.base / 'large'], 60)
        expected = json.loads(child.stdout)
        actual = self.owned('large-resource-check', [self.fixture, 'describe', expected['directory'], 'repo/file'], 30)
        observed = json.loads(actual.stdout)['xattrs'][b'com.apple.ResourceFork'.hex()]
        self.assertEqual(observed, {key: expected[key] for key in ('size', 'sha256')})

    def test_native_import_diagnostic_failure_receipts(self):
        script = textwrap.dedent('''
            import ctypes, importlib.util, json, os, sys
            from pathlib import Path
            module_path, base, case, kind, ordinal, flags = sys.argv[1:]
            spec = importlib.util.spec_from_file_location('stallionfs._image', module_path)
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            control = ctypes.CDLL(module_path).sfs_bridge_test_configure
            control.argtypes = [ctypes.c_int] * 4; control.restype = None
            base = Path(base); base.mkdir(mode=0o700)
            source = base / 'input' / 'repo'; source.parent.mkdir(mode=0o700); source.mkdir(mode=0o700)
            destination = base / 'owned'; destination.mkdir(mode=0o700)
            (source / 'file').write_bytes(b'imported bytes')
            (source / 'second').write_bytes(b'second file')
            os.environ['SFS_TEST_MUTATE_PATH'] = str(source / ('added' if case == 'directory-change' else 'file'))
            if case == 'source-allocation':
                libc = ctypes.CDLL(None, use_errno=True)
                libc.setxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
                assert libc.setxattr(os.fsencode(source / 'file'), b'org.example.value', b'value', 5, 0, 1) == 0
            def pair(path):
                st = path.stat(); return [st.st_dev, st.st_ino]
            def before():
                if case == 'precreate-signal': raise KeyboardInterrupt('precreate interrupted')
            control(int(kind), int(ordinal), int(flags), 0)
            exception = None
            try:
                result = module.create_from_tree({'directory': str(source), 'root': pair(source)},
                    {'directory': str(destination), 'parent': pair(destination), 'component': 'image.sfs',
                     'before_create': before}, 1 << 26)
            except (MemoryError, KeyboardInterrupt) as error:
                exception = type(error).__name__
                result = json.loads(bytes(error.native_image_carrier['data']).split(b'\\0', 1)[0])
            print(json.dumps({'result': result, 'exception': exception,
                              'exists': (destination / 'image.sfs').exists()}))
        ''')
        cases = [('precreate-signal', 0, 0, 0), ('create-allocation', 7, 1, 0),
                 ('create-write', 1, 1, 0), ('create-fence', 4, 1, 0),
                 ('commit-first-fence', 4, 4, 0), ('commit-final-fence', 4, 5, 0),
                 ('verify-budget', 0, 0, 256), ('close', 0, 0, 1024),
                 ('reopen-read', 0, 0, 512), ('reopen-close', 0, 0, 2048),
                 ('response-allocation', 0, 0, 4096), ('creation-signal', 0, 0, 2),
                 ('import-signal', 0, 0, 8192), ('read-change', 0, 0, 16384),
                 ('directory-change', 0, 0, 32768), ('source-allocation', 0, 0, 65536), ('scratch-full', 0, 0, 131072)]
        for case, kind, ordinal, flags in cases:
            with self.subTest(case=case):
                child = self.owned('import-' + case, [sys.executable, '-I', '-c', script,
                    self.diagnostic, self.base / case, case, kind, ordinal, flags], 30)
                observed = json.loads(child.stdout); result = observed['result']
                if case == 'response-allocation':
                    self.assertEqual(observed['exception'], 'MemoryError')
                    self.assertTrue(result['candidate_complete'])
                    self.assertTrue(result['verified'])
                    self.assertEqual(result['reopen_close']['status'], 0)
                else:
                    self.assertFalse(result['candidate_complete'], observed)
                if case in ('precreate-signal', 'source-allocation', 'scratch-full'):
                    if case == 'precreate-signal': self.assertEqual(observed['exception'], 'KeyboardInterrupt')
                    self.assertFalse(observed['exists'])
                    self.assertFalse(result['creation_attempted'])
                else:
                    self.assertTrue(observed['exists'], observed)
                    self.assertTrue(result['creation_attempted'])
                if case == 'create-allocation':
                    self.assertIsNone(result['identity'])
                    self.assertIsNotNone(result['observed_file'])
                if case.startswith('commit-'):
                    self.assertFalse(result['import_committed'])
                    self.assertIsNotNone(result['commit'])
                    if case == 'commit-final-fence':
                        self.assertEqual(result['commit']['status'], 8)  # SFS_OUTCOME_UNKNOWN
                        self.assertIsNone(result['abort'])
                    else:
                        self.assertTrue(result['commit']['poisoned'])
                        self.assertFalse(result['commit']['transaction_active'])
                        self.assertIsNone(result['abort'])
                if case in ('verify-budget', 'close', 'reopen-read', 'reopen-close'):
                    self.assertTrue(result['import_committed'])
                    self.assertIsNotNone(result['anchor'])
                if case == 'verify-budget':
                    self.assertNotEqual(result['verify']['incomplete_reason'], 0)
                    self.assertFalse(result['verified'])
                if case == 'close':
                    self.assertNotEqual(result['close']['status'], 0)
                    self.assertIsNone(result['reopen'])
                if case == 'reopen-read': self.assertNotEqual(result['reopen']['status'], 0)
                if case == 'reopen-close': self.assertNotEqual(result['reopen_close']['status'], 0)
                if case in ('creation-signal', 'import-signal'): self.assertEqual(observed['exception'], 'KeyboardInterrupt')
                if case in ('import-signal', 'read-change'):
                    self.assertFalse(result['import_committed'])
                    self.assertEqual(result['abort']['status'], 0)
                    self.assertFalse(result['abort']['transaction_active'])
                if case in ('read-change', 'directory-change'):
                    self.assertEqual(result['reason'], 'source-changed')
                if case == 'directory-change': self.assertTrue(result['import_committed'])

    def test_diagnostic_receipts_signals_deadline_and_transient_output_allocation(self):
        script = textwrap.dedent('''
            import ctypes, importlib.util, io, json, sys
            from contextlib import redirect_stdout, redirect_stderr
            import stallionfs
            from stallionfs.__main__ import main
            module_path, root, workspace, case, kind, ordinal, flags, deadline = sys.argv[1:]
            spec = importlib.util.spec_from_file_location('stallionfs._image', module_path)
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            sys.modules['stallionfs._image'] = module; stallionfs._image = module
            control = ctypes.CDLL(module_path).sfs_bridge_test_configure
            control.argtypes = [ctypes.c_int] * 4; control.restype = None
            control(int(kind), int(ordinal), int(flags), int(deadline))
            if case == 'format-oom':
                from stallionfs import core
                original_strerror = core.os.strerror
                def fail_format(_number):
                    core.os.strerror = original_strerror
                    raise MemoryError('transient error formatting failure')
                core.os.strerror = fail_format
            operation = ['snapshots',workspace] if case == 'list-oom' else ['rollback', workspace, 'base'] if case in ('budget','prepare-signal','oom','signal-oom','close-oom','format-oom') else ['snapshot',workspace,'--name','attempt']
            with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
                status = main(['--root',root,'--json',*operation])
            expected = 130 if case in ('stage-signal','prepare-signal','signal-oom') else 1
            assert status == expected, (case,status,out.getvalue(),err.getvalue())
            assert out.getvalue() == ''
            error = json.loads(err.getvalue()); result = error['native_image_result']
            if case in ('close','oom','signal-oom','close-oom','format-oom'):
                assert result['committed'] and result['receipt']['status'] == 0 and result['receipt']['fence_succeeded'] == 3
                if case in ('oom','signal-oom','close-oom'):
                    assert result['recovery'].startswith('recovery-') and not result['response_complete']
                    assert result['staged_receipt']['physical_end'] > result['staged_receipt']['committed_end']
                    assert (result['close_receipt']['status'] == 0) == (case != 'close-oom')
                else: assert result['close_receipt']['status'] != 0
            elif case == 'final-fence':
                assert result['outcome'] == 'unknown' and result['receipt']['fence_attempted'] == 3 and result['receipt']['fence_succeeded'] == 1
            elif case == 'first-fence':
                assert not result['committed'] and result['receipt']['fence_attempted'] == 1 and result['receipt']['fence_succeeded'] == 0
            elif case in ('budget','prepare-signal'):
                assert not result['committed'] and result['receipt']['incomplete_reason'] != 0 and not result['receipt']['transaction_active']
            elif case in ('stage-signal','deadline'):
                assert not result['committed'] and result['abort_attempted'] and result['abort_receipt']['status'] == 0
                assert result['staged_receipt']['transaction_active']
            elif case == 'list-oom':
                assert not result['committed'] and not result['response_complete'] and 'snapshots' not in result
            if case == 'signal-oom': assert result['interrupted'] and 'interrupted' in error['error']
            print(json.dumps(error))
        ''')
        cases = [('first-fence',4,1,0,0), ('final-fence',4,2,0,0), ('close',0,0,1,0),
                 ('stage-signal',0,0,4,0), ('prepare-signal',0,0,8,0), ('budget',0,0,16,0),
                 ('deadline',0,0,0,5), ('oom',0,0,32,0), ('signal-oom',0,0,34,0),
                 ('close-oom',0,0,33,0), ('format-oom',0,0,1,0), ('list-oom',0,0,64,0)]
        for index, (case, kind, ordinal, flags, deadline) in enumerate(cases):
            with self.subTest(case=case):
                directory = self.seed(f'case-{index}'); workspace = self.register(directory)
                self.command('snapshot', workspace, '--name', 'base')
                child = self.owned('diagnostic-case', [sys.executable, '-I', '-c', script, self.diagnostic,
                            self.store, workspace, case, kind, ordinal, flags, deadline])
                observed = json.loads(child.stdout)['native_image_result']
                roots = self.command('snapshots', workspace)
                if case in ('close','oom','signal-oom','close-oom','format-oom'):
                    self.assertEqual(len(roots), 2)
                    if observed.get('recovery'):
                        self.assertEqual(roots[-1]['id'], observed['recovery'])
                elif case != 'final-fence':
                    self.assertEqual([row['id'] for row in roots], ['base'])


@unittest.skipUnless(sys.platform == 'darwin', 'Native launcher requires macOS')
class InstalledCLI(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='stallionfs CLI ')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.launcher = Path(sysconfig.get_path('scripts')) / 'stallionfs'
        self.assertTrue(self.launcher.is_file(), f'Installed launcher missing: {self.launcher}')
        self.assertTrue(os.access(self.launcher, os.X_OK))
        with self.launcher.open('rb') as stream:
            self.assertIn(stream.read(4), (bytes.fromhex('cffaedfe'), bytes.fromhex('feedfacf'),
                                          bytes.fromhex('cafebabe'), bytes.fromhex('bebafeca'),
                                          bytes.fromhex('cafebabf'), bytes.fromhex('bfbafeca')))
        self.shortcut = self.launcher.with_name('sfs')
        self.assertTrue(self.shortcut.is_file(), f'Installed shortcut missing: {self.shortcut}')
        self.assertTrue(os.access(self.shortcut, os.X_OK))
        self.environment = {**os.environ, 'PATH': '/usr/bin:/bin',
                            'STALLIONFS_HOME': str(self.base / 'unused-store')}

    def command(self, *arguments, launcher=None, status=0, environment=None):
        result = subprocess.run([str(launcher or self.launcher), *arguments], cwd=self.base,
                                env=environment or self.environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, status, result.stderr)
        return result

    def native_only(self, name='stallionfs'):
        directory = self.base / 'without helper'; directory.mkdir(mode=0o700)
        launcher = directory / name
        shutil.copy2(self.launcher.with_name(name), launcher)
        self.assertFalse((directory / 'stallionfs-python').exists())
        return launcher

    def test_sfs_installation_native_operations_and_error_status_parity(self):
        installed = distribution('stallionfs')
        recorded = {Path(installed.locate_file(file)).resolve() for file in installed.files}
        for launcher in (self.launcher, self.shortcut):
            self.assertIn(launcher.resolve(), recorded)
        self.assertEqual(self.shortcut.read_bytes(), self.launcher.read_bytes())
        self.assertEqual(self.shortcut.stat().st_mode, self.launcher.stat().st_mode)
        launcher = self.native_only('sfs')
        source = self.base / 'source'; source.mkdir(mode=0o700)
        (source / 'file').write_bytes(b'original')
        self.command('clone', '--', 'source', 'copied', launcher=launcher)
        self.assertEqual((self.base / 'copied' / 'file').read_bytes(), b'original')
        self.assertEqual(json.loads(self.command('--json', 'scan', 'copied', launcher=launcher).stdout),
                         dict(files=1, directories=0, symlinks=0, other=0,
                              logical_bytes=8, skipped_mounts=0))
        self.command('move', '--', 'copied', 'moved', launcher=launcher)
        self.command('delete', '-r', '--', 'moved', launcher=launcher)
        self.assertFalse((self.base / 'moved').exists())
        self.assertEqual(self.command('--version', launcher=launcher).stdout, __version__ + '\n')
        missing_helper = self.command('--help', launcher=launcher, status=1)
        self.assertIn('cannot run installed Python helper', missing_helper.stderr)
        for arguments, status in ((('--json', 'move', '--', 'missing', 'never-created'), 1),
                                  (('clone', '--jobs=5', '--', 'source', 'never-created'), 2)):
            old = self.command(*arguments, status=status)
            short = self.command(*arguments, launcher=launcher, status=status)
            self.assertEqual((short.stdout, short.stderr), (old.stdout, old.stderr))
        self.assertFalse((self.base / 'never-created').exists())
        self.assertFalse((self.base / 'unused-store').exists())

    def test_native_json_roundtrip_errors_and_no_helper(self):
        launcher = self.native_only()
        source = '--source café 🐎 "\\\t\n\x01'
        destination = '--copy café 🐎 "\\\t\n\x02'
        moved = '--moved café 🐎 "\\\t\n\x03'
        (self.base / source).write_bytes(b'original')
        store = self.base / 'unused-store'
        result = self.command('--root=' + str(store), '--json', 'clone', '--jobs=1', '--',
                              source, destination, launcher=launcher)
        self.assertEqual(json.loads(result.stdout), {'source': source, 'destination': destination})
        result = self.command('--json', '--root', str(store), 'move', '--', destination, moved,
                              launcher=launcher)
        self.assertEqual(json.loads(result.stdout), {'source': destination, 'destination': moved})
        self.assertEqual((self.base / moved).read_bytes(), b'original')
        result = self.command('--json', 'delete', '--', moved, launcher=launcher)
        self.assertEqual(json.loads(result.stdout), {'path': moved})
        self.assertFalse((self.base / moved).exists())
        volumes = json.loads(self.command('--json', 'volumes', launcher=launcher).stdout)
        self.assertTrue(any(row['path'] == '/' for row in volumes))
        for row in volumes:
            self.assertEqual(set(row), {'path', 'device', 'filesystem', 'readonly', 'ignore_ownership', 'owner'})
            self.assertIsInstance(row['readonly'], bool)
            self.assertIsInstance(row['ignore_ownership'], bool)
            self.assertIsInstance(row['owner'], int)
        bad_name = os.fsdecode(b'missing-\xff-\xc0\xaf-\xed\xa0\x80-\xf4\x90\x80\x80-\xf0\x9f-"\\\n')
        failed = self.command('--json', 'move', '--', bad_name, 'never-created',
                              launcher=launcher, status=1)
        self.assertEqual(failed.stdout, '')
        self.assertIn(os.fsencode(bad_name), os.fsencode(json.loads(failed.stderr)['error']))
        self.assertFalse((self.base / 'never-created').exists())
        invalid = self.command('--json', 'clone', '--jobs=5', '--', source, 'invalid',
                               launcher=launcher, status=2)
        self.assertEqual(invalid.stdout, '')
        self.assertFalse(invalid.stderr.lstrip().startswith('{'))
        self.assertFalse((self.base / 'invalid').exists())
        self.assertEqual((self.base / source).read_bytes(), b'original')
        self.assertFalse(store.exists())

    def test_native_scan_counts_failures_and_closed_output(self):
        from stallionfs._scan import scan
        launcher = self.native_only()
        source = self.base / '--scan café 🐎'; source.mkdir(mode=0o700)
        (source / 'empty').mkdir()
        (source / 'second').mkdir()
        (source / 'second' / 'nested').write_bytes(b'worker')
        (source / 'file').write_bytes(b'abc')
        with (source / 'sparse').open('wb') as stream: stream.truncate(1 << 20)
        os.link(source / 'file', source / 'hardlink')
        (source / 'dangling').symlink_to('absent')
        (source / 'outside').symlink_to('/')
        os.mkfifo(source / 'fifo')
        expected = scan(source)
        output = self.command('--root', str(self.base / 'unused-store'), '--json',
                              'scan', '--', source.name, launcher=launcher)
        self.assertEqual(json.loads(output.stdout), expected)
        for options in (('--jobs', '1'), ('--jobs=2',), ('--jobs', '4')):
            output = self.command('--json', 'scan', *options, '--', source.name, launcher=launcher)
            self.assertEqual(json.loads(output.stdout), expected)
        for jobs in ('0', '5', '-1', '4294967297', '-18446744073709551615'):
            output = self.command('--json', 'scan', '--jobs=' + jobs, '--', source.name,
                                  launcher=launcher, status=2)
            self.assertEqual(output.stdout, '')
        output = self.command('scan', '--', source.name, launcher=launcher)
        self.assertEqual(output.stdout, f"{expected['files']} files, {expected['directories']} directories, "
                         f"{expected['symlinks']} symlinks, {expected['other']} other entries\n"
                         f"{expected['logical_bytes']} logical bytes; {expected['skipped_mounts']} nested volumes skipped\n")
        denied = source / 'denied'; denied.mkdir(); denied.chmod(0)
        try:
            failed = self.command('--json', 'scan', '--', source.name, launcher=launcher, status=1)
            self.assertEqual(failed.stdout, '')
            self.assertIsInstance(json.loads(failed.stderr)['error'], str)
        finally:
            denied.chmod(0o700)
        for arguments in (('--json', 'scan', '--', source.name), ('--json', 'volumes'), ('--version',)):
            read_fd, write_fd = os.pipe()
            os.close(read_fd)
            try:
                result = subprocess.run([str(launcher), *arguments], cwd=self.base,
                                        env=self.environment, stdout=write_fd, stderr=subprocess.PIPE, timeout=15)
            finally:
                os.close(write_fd)
            self.assertNotEqual(result.returncode, 0, 'Output failure was reported as success')
        self.assertFalse((self.base / 'unused-store').exists())

    def test_native_file_operations_with_literal_leading_dashes(self):
        source = self.base / '--source'; source.mkdir(mode=0o700)
        (source / 'file').write_bytes(b'original')
        (source / 'dangling').symlink_to('missing')
        for jobs in ('-18446744073709551615', '0', '5'):
            with self.subTest(jobs=jobs):
                self.command('clone', '--jobs', jobs, '--', '--source', '--invalid', status=2)
                self.command('delete', '--jobs', jobs, '-r', '--', '--source', status=2)
                self.assertFalse((self.base / '--invalid').exists())
                self.assertEqual((source / 'file').read_bytes(), b'original')
                self.assertEqual(os.readlink(source / 'dangling'), 'missing')
        self.command('clone', '--', '--source', '--copy')
        copied = self.base / '--copy'
        first = copied / 'file'; second = self.base / '--other'
        second.write_bytes(b'other')
        self.assertEqual(first.read_bytes(), b'original')
        self.assertEqual(os.readlink(copied / 'dangling'), 'missing')
        first_inode, second_inode = first.stat().st_ino, second.stat().st_ino
        self.command('move', '--', '--copy/file', '--other', status=1)
        self.assertEqual((first.read_bytes(), second.read_bytes()), (b'original', b'other'))
        self.command('move', '--exchange', '--', '--copy/file', '--other')
        self.assertEqual((first.stat().st_ino, second.stat().st_ino), (second_inode, first_inode))
        self.assertEqual((first.read_bytes(), second.read_bytes()), (b'other', b'original'))
        self.command('move', '--', '--other', '--moved')
        self.assertFalse(second.exists())
        self.assertEqual((self.base / '--moved').stat().st_ino, first_inode)
        self.command('delete', '-r', '--', '--copy')
        self.command('delete', '--', '--moved')
        self.assertFalse(copied.exists())
        self.assertFalse((self.base / '--moved').exists())
        self.assertEqual((source / 'file').read_bytes(), b'original')
        volumes = [line.split('\t', 2) for line in self.command('volumes').stdout.splitlines()]
        self.assertTrue(any(len(row) == 3 and row[2] == '/' for row in volumes))
        self.assertTrue(all(len(row) == 3 and row[1] in ('read-only', 'writable') for row in volumes))
        self.assertFalse((self.base / 'unused-store').exists())

    def test_native_exports_load_once_on_first_access(self):
        result = subprocess.run([sys.executable, '-I', '-c', """
import sys, threading, stallionfs
from concurrent.futures import ThreadPoolExecutor
names = ('clone', 'copy', 'delete', 'mounts', 'move', 'scan')
assert stallionfs.__all__ == list(names)
assert set(names) | {'_scan'} <= set(dir(stallionfs))
assert not hasattr(stallionfs, 'not_an_export')
assert 'stallionfs._scan' not in sys.modules
requested = ('_scan', *names)
barrier = threading.Barrier(len(requested), timeout=5)
def get(name):
    barrier.wait()
    return getattr(stallionfs, name)
with ThreadPoolExecutor(max_workers=len(requested)) as pool:
    values = dict(zip(requested, pool.map(get, requested)))
from stallionfs import _scan
namespace = {}
exec('from stallionfs import *', namespace)
assert set(namespace) - {'__builtins__'} == set(names)
assert values['_scan'] is _scan
for name in names:
    assert namespace[name] is values[name] is getattr(_scan, name)
    assert getattr(stallionfs, name) is vars(stallionfs)[name] is values[name]
"""], cwd=self.base, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_native_extension_fails_before_store_creation(self):
        import stallionfs
        help_text = self.command('--help').stdout
        for damage in ('missing', 'corrupt'):
            with self.subTest(damage=damage):
                package = self.base / damage / 'stallionfs'; package.mkdir(parents=True)
                for source in Path(stallionfs.__file__).parent.glob('*.py'):
                    shutil.copyfile(source, package / source.name)
                if damage == 'corrupt':
                    (package / ('_scan' + sysconfig.get_config_var('EXT_SUFFIX'))).write_bytes(b'invalid')
                store = package.parent / 'must-not-exist'
                environment = {key: value for key, value in self.environment.items()
                               if not key.startswith('PYTHON')}
                environment.update(PYTHONPATH=str(package.parent), PYTHONNOUSERSITE='1',
                                   PYTHONDONTWRITEBYTECODE='1', STALLIONFS_HOME=str(store))
                self.assertEqual(self.command('--help', environment=environment).stdout, help_text)
                self.assertEqual(self.command('--version', environment=environment).stdout, __version__ + '\n')
                failed = self.command('--root', str(store), 'list', status=1, environment=environment)
                self.assertEqual(failed.stdout, '')
                self.assertIn('ModuleNotFoundError' if damage == 'missing' else 'ImportError', failed.stderr)
                self.assertFalse(store.exists())

    def test_helper_dispatch_from_installed_and_symlinked_launcher(self):
        self.assertEqual(__version__, version('stallionfs'))
        native = self.native_only()
        self.assertEqual(self.command('--version', launcher=native).stdout, __version__ + '\n')
        for arguments in (('--ver',), ('--json', '--version'), ('--version', 'ignored')):
            failed = self.command(*arguments, launcher=native, status=1)
            self.assertEqual(failed.stdout, '')
            self.assertIn('cannot run installed Python helper', failed.stderr)
        alias = self.base / 'linked launcher'
        alias.symlink_to(self.launcher)
        for launcher in (self.launcher, self.shortcut, alias):
            with self.subTest(launcher=str(launcher)):
                self.assertEqual(self.command('--version', launcher=launcher).stdout.strip(), __version__)
                help_text = self.command('--help', launcher=launcher).stdout
                for name in ('clone', 'move', 'delete', 'volumes'):
                    self.assertIn(name, help_text)
                self.assertIn('--jobs', self.command('clone', '--help', launcher=launcher).stdout)
                self.assertIn('--jobs', self.command('scan', '--help', launcher=launcher).stdout)
        home = self.base / 'home'; home.mkdir()
        fixture = home / 'fixture'; fixture.mkdir(); (fixture / 'file').write_bytes(b'abc')
        result = self.command('--json', 'scan', '--jobs', '1', '~/fixture',
                              environment={**self.environment, 'HOME': str(home)})
        self.assertEqual(json.loads(result.stdout), dict(files=1, directories=0, symlinks=0,
                                                        other=0, logical_bytes=3, skipped_mounts=0))
        self.assertFalse((self.base / 'unused-store').exists())


if __name__ == '__main__':
    unittest.main()
