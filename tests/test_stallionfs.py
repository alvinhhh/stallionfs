"""Run on APFS: python3 -m unittest discover -s tests -v."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import errno
from functools import wraps
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import ANY, patch

from stallionfs.core import Store, StallionError, clone_tree, git, remove_tree, run


def native_creation_test(method):
    @wraps(method)
    def controlled(self, *args, **kwargs):
        with self.native_creation_fixture():
            return method(self, *args, **kwargs)
    return controlled


@unittest.skipUnless(sys.platform == "darwin", "APFS integration tests require macOS")
class Workspaces(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="stallionfs-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.source = self.base / "source with spaces"
        self.source.mkdir()
        git(self.source, "init", "-b", "main")
        git(self.source, "config", "user.email", "test@example.invalid")
        git(self.source, "config", "user.name", "Test")
        (self.source / "file").write_text("original\n")
        (self.source / ".gitignore").write_text("dependencies/\n.env\n")
        (self.source / "executable").write_text("#!/bin/sh\nexit 0\n")
        (self.source / "executable").chmod(0o755)
        (self.source / "link").symlink_to("file")
        git(self.source, "add", ".")
        git(self.source, "commit", "-m", "Fixture")
        self.store = Store(self.base / "storage")

    def prepare(self, **kwargs):
        return self.store.prepare(self.source, key="test-v1", **kwargs)

    @contextmanager
    def native_creation_fixture(self):
        """Controlled runtime/verifier seams, never signed-runtime evidence."""
        from stallionfs import _bundle, _native_create_git
        configured = os.environ.get('STALLIONFS_TEST_QUALIFIED_GIT')
        if not configured:
            self.skipTest('requires explicitly qualified private Git fixture')
        executable = Path(configured).resolve(strict=True)
        self.assertTrue(executable.is_file() and os.access(executable, os.X_OK))
        runtime = {'executable': str(executable),
                   'exec_path': str(executable.parent.parent / 'libexec/git-core'),
                   'contract': {**_bundle.GIT_CONTRACT, 'payload_entries': 239,
                       'payload_sha256': '1' * 64, 'descriptor_sha256': '2' * 64,
                       'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
                       'source_build_id': '3' * 64, 'publisher': _bundle.PUBLISHER_TEAM},
                   'check': lambda: None}
        # Keep real preflight persistence; only the package verifier is controlled.
        with patch.object(_native_create_git, 'qualified_runtime', return_value=runtime), \
             patch('stallionfs._native.verify_package', return_value={'returncode': 0}):
            yield runtime

    @contextmanager
    def native_clock(self):
        """Elapsed time advances at waits, never because a caller reads it."""
        class Clock:
            now = 0.0
            def monotonic(self): return self.now
            def advance(self, seconds):
                if seconds < 0: raise ValueError('Negative simulated wait')
                self.now += seconds
            def sleep(self, seconds): self.advance(seconds)
        clock = Clock()
        # Do not replace the shared time module used by other code or runners.
        with patch('stallionfs._native.time', clock):
            yield clock

    @contextmanager
    def native_controller_fixture(self):
        """Fake OS namespace/owned executor; never a mounted persistence proof."""
        from stallionfs import _native
        from stallionfs.core import read_json
        state = {'rows': {}, 'commands': [], 'observed_fds': set(), 'sequence': 0}
        original_open, original_close = os.open, os.close
        executor = _native.execute_owned
        def opened(path, flags, *args, **kwargs):
            fd = original_open(path, flags, *args, **kwargs)
            if str(path) in state['rows']:
                state['observed_fds'].add(fd)
            return fd
        def closed(fd):
            state['observed_fds'].discard(fd)
            return original_close(fd)
        def rows():
            return [dict(row) for row in state['rows'].values()]
        def descriptor(fd):
            self.assertIn(fd, state['observed_fds'])
            return next(dict(row) for path, row in state['rows'].items()
                        if Path(path).stat().st_ino == os.fstat(fd).st_ino)
        def command(argv, record, persist, directory, **kwargs):
            if argv[0] == runtime['executable']:
                return executor(argv, record, persist, directory, **kwargs)
            self.assertIn(argv[0], ('/sbin/mount', '/sbin/umount'))
            state['commands'].append(list(argv))
            record.update(argv=list(argv), child_pending=True, outcome='running', returncode=None,
                          pid=123, reaped=False, stdout=str(directory / 'stdout'), stderr=str(directory / 'stderr'))
            persist()
            self.assertFalse(state['observed_fds'], 'Controller kept a mounted observation FD open at mutation')
            if argv[0] == '/sbin/mount':
                self.assertEqual(argv[:3], ['/sbin/mount', '-t', 'stallionfs'])
                path, volume = Path(argv[3]), Path(argv[4])
                metadata = read_json(path / 'meta.json')
                proof = read_json(path / 'native-install.json')
                self.assertTrue(proof['complete'])
                self.assertTrue(proof['first_mount_attempted'])
                self.assertEqual(metadata['state'], 'installed')
                if not (volume / 'repo').exists():
                    clone_tree(self.store.root / 'seeds' / metadata['seed'] / 'repo', volume / 'repo')
                    git(volume / 'repo', 'checkout', '-b', metadata['branch'])
                state['sequence'] += 1
                state['rows'][str(volume)] = {'path': str(volume), 'filesystem': 'stallionfs',
                    'device': 'informational resource name', 'owner': os.getuid(),
                    'readonly': False, 'ignore_ownership': False, 'flags': 0, 'fsid': (71, state['sequence'])}
                result = state.get('mount_status', 0)
            else:
                self.assertEqual(argv[0], '/sbin/umount')
                self.assertEqual(len(argv), 2)
                result = state.get('unmount_status', 0)
                if not result: state['rows'].pop(argv[1], None)
            record.update(child_pending=False, reaped=True, returncode=result, outcome='success' if not result else 'error')
            persist()
            if state.get('interrupt'):
                record['outcome'] = 'unknown'; persist()
                raise subprocess.TimeoutExpired(argv, 30)
            return record
        with self.native_creation_fixture() as runtime, \
             patch('stallionfs._native.qualify', return_value='stallionfs'), \
             patch('stallionfs._native.execute_owned', side_effect=command), \
             patch('stallionfs._scan.mounts', side_effect=rows), \
             patch('stallionfs._scan.mount_for_descriptor', side_effect=descriptor, create=True), \
             patch('stallionfs._native.os.open', side_effect=opened), \
             patch('stallionfs._native.os.close', side_effect=closed):
            yield state

    @native_creation_test
    def test_native_preflight_persists_own_transition_before_qualification(self):
        from stallionfs import _native
        from stallionfs.core import read_json
        seed = self.prepare()
        observed = []
        def inspect(operation, metadata):
            expected = {'format': 1, **operation.record}
            self.assertEqual(read_json(operation.journal), expected)
            self.assertEqual(read_json(operation.directory / 'record.json'), expected)
            self.assertEqual(expected['helpers'], [])
            self.assertIs(expected['child_pending'], False)
            self.assertIs(expected['creation_attempted'], False)
            observed.append(operation.directory)
            raise OSError(errno.EIO, 'qualification stopped after checking durable preflight')
        with patch('stallionfs._native.qualify', side_effect=inspect), \
             patch('stallionfs._image.create_from_tree') as importer:
            with self.assertRaises(OSError):
                self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            importer.assert_not_called()
        self.assertEqual(len(observed), 1)
        self.assertTrue((observed[0] / 'record.json').is_file())
        original = _native._persist
        partial = []
        def fail_journal(path, value):
            if Path(path).parent == self.store.root / 'journals':
                partial.append((Path(value['stage']) / 'discovery/record.json', Path(path)))
                raise OSError(errno.EIO, 'preflight journal persistence failed')
            return original(path, value)
        with patch('stallionfs._native._persist', side_effect=fail_journal), \
             patch('stallionfs._native.qualify') as qualify, \
             patch('stallionfs._image.create_from_tree') as importer:
            with self.assertRaises(OSError):
                self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            qualify.assert_not_called()
            importer.assert_not_called()
        self.assertEqual(len(partial), 1)
        retained, journal = partial[0]
        self.assertEqual(read_json(retained)['helpers'], [])
        self.assertIs(read_json(retained)['child_pending'], False)
        self.assertNotIn('helpers', read_json(journal))
        self.assertNotIn('child_pending', read_json(journal))

    def test_native_owned_install_controller_paths_and_remount_records(self):
        from stallionfs import _native, _image
        from stallionfs.core import read_json
        seed = self.prepare()
        with self.native_controller_fixture() as os_state:
            first = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            second = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            self.assertNotEqual(first['native_image']['uuid'], second['native_image']['uuid'])
            self.assertEqual(Path(first['path']), self.store.root / 'workspaces' / first['id'] / 'volume/repo')
            self.assertTrue(first['installation']['installation_confirmed'])
            path = Path(first['path']).parent.parent
            original_proof = (path / 'native-create.json').read_bytes()
            self.assertFalse((self.store.root / 'journals' / (first['id'] + '.json')).exists())
            self.assertFalse(read_json(self.store._state(first['id']))['enrolled'])
            self.assertNotIn('closed_at', read_json(self.store._state(first['id'])))
            self.assertEqual(self.store.run(first['id'], [sys.executable, '-c',
                "from pathlib import Path; Path('changed').write_text('later content')"])['returncode'], 0)
            self.store.unmount(first['id'])
            target = _native.installed_target(self.store, path, read_json(path / 'meta.json'))
            # Offline core mutation changes the current anchor. This is not a
            # claim that the fake mounted namespace delivered native writes.
            _image.snapshot(target, 'fixture-current-anchor')
            mounted = self.store.mount(first['id'])
            self.assertEqual(Path(mounted['path'], 'changed').read_text(), 'later content')
            self.assertEqual((path / 'native-create.json').read_bytes(), original_proof)
            self.store.unmount(first['id'])
            already = self.store.unmount(first['id'])
            self.assertTrue(already['already_absent'])
            self.assertTrue(already['native_operation']['current_guard']['core_consumed'])
            self.assertFalse(os_state['observed_fds'])
            alias = self.base / 'owned-alias'; alias.symlink_to(path, target_is_directory=True)
            with self.assertRaises(StallionError): self.store.register_native_image(alias / 'image.sfs')
            for action in (lambda: self.store.move(first['id']),
                           lambda: self.store.run(first['id'], ['true'], auto_retire=True)):
                with self.assertRaises(StallionError): action()
            folder = self.store.create(seed['id']); self.store.move(folder['id'])
            self.assertEqual(self.store.gc(older_than=0, yes=True), [folder['id']])

    def test_native_install_postrename_unknown_recovers_without_replay(self):
        from stallionfs import _native, _scan
        from stallionfs.core import read_json, native_failure_details
        seed = self.prepare()
        original = _scan.move
        moved = []
        def uncertain(source, destination, **kwargs):
            original(source, destination, **kwargs); moved.append(Path(destination))
            raise OSError(errno.EIO, 'rename completed but response lost')
        with self.native_controller_fixture(), patch('stallionfs._scan.move', side_effect=uncertain):
            with self.assertRaises(OSError) as caught:
                self.store.create(seed['id'], backend='native-image', capacity_gib=1)
        self.assertEqual(len(moved), 1)
        path = moved[0]; backing = (path / 'image.sfs').stat().st_ino
        intent = read_json(self.store.root / 'journals' / (path.name + '.json'))
        self.assertEqual(intent['installation']['outcome'], 'rename-attempted')
        self.assertFalse(intent['installation']['first_mount_attempted'])
        self.assertEqual(read_json(path / 'meta.json')['format'], 1)
        self.assertNotIn('format', intent['installation']['metadata'])
        self.assertEqual(native_failure_details(caught.exception)['candidate'], str(path))
        with self.native_controller_fixture(), patch('stallionfs._scan.move', side_effect=AssertionError('rename replay')), \
             patch('stallionfs._image.create_from_tree', side_effect=AssertionError('import replay')):
            result = self.store.mount(path.name)
        self.assertEqual(result['path'], str(path / 'volume/repo'))
        self.assertEqual((path / 'image.sfs').stat().st_ino, backing)
        proof = read_json(path / 'native-install.json')
        self.assertEqual(proof['previous_installation']['outcome'], 'rename-attempted')
        self.assertTrue(proof['guard']['core_consumed'])

    def test_native_mount_error_retains_object_and_explicit_unmount_recovers(self):
        from stallionfs.core import native_failure_details, read_json
        seed = self.prepare()
        with self.native_controller_fixture() as state:
            state['mount_status'] = 1
            with self.assertRaises(StallionError) as caught:
                self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            details = native_failure_details(caught.exception)
            installation = details['installation']
            path = Path(installation['candidate']); workspace = path.name
            self.assertTrue(installation['installation_confirmed'])
            self.assertEqual(read_json(path / 'meta.json')['state'], 'installed')
            before = len(state['commands'])
            with self.assertRaises(StallionError): self.store.mount(workspace)
            self.assertEqual(len(state['commands']), before)
            self.store.unmount(workspace)
            state['mount_status'] = 0
            self.assertEqual(self.store.mount(workspace)['path'], str(path / 'volume/repo'))
            history = [read_json(p) for p in (path / 'native-operations').glob('*/record.json')]
            self.assertTrue(any(any(h.get('returncode') == 1 for h in r['helpers']) for r in history))

    def test_native_pending_owned_child_blocks_new_mutators(self):
        from stallionfs.core import read_json
        from stallionfs.lifecycle import replace_json
        seed = self.prepare()
        with self.native_controller_fixture() as state:
            result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            journal = self.store.root / 'journals' / (result['id'] + '.json')
            replace_json(journal, {'operation': 'native-mount', 'workspace': result['id'],
                                  'child_pending': True, 'helpers': [{'child_pending': True}]})
            before = len(state['commands'])
            for action in (lambda: self.store.mount(result['id']), lambda: self.store.unmount(result['id']),
                           lambda: self.store.run(result['id'], ['true'])):
                with self.assertRaises(StallionError): action()
            self.assertEqual(len(state['commands']), before)
            self.assertTrue(read_json(journal)['child_pending'])

    def test_native_owned_helper_timeout_and_interrupt_stop_reap_before_return(self):
        from stallionfs import _native
        from stallionfs.core import lock
        for interrupt in (False, True):
            with self.subTest(interrupt=interrupt):
                directory = self.base / ('signal-child' if interrupt else 'timeout-child'); directory.mkdir()
                record, observations, signals = {}, [], []
                primary = KeyboardInterrupt('owned interruption') if interrupt else subprocess.TimeoutExpired(['helper'], 0.1)
                class Child:
                    pid = 41
                    returncode = None
                    stopped = False
                    def poll(self): return self.returncode
                    def wait(self, timeout=None):
                        if self.stopped:
                            self.returncode = -9; return -9
                        if not interrupt and timeout is not None:
                            clock.advance(timeout)
                        raise primary
                    def terminate(self): signals.append('terminate')
                    def kill(self): signals.append('kill'); self.stopped = True
                # Use the actual existing lease while the injected helper
                # ignores terminate, then acknowledges only its owned kill.
                lease = self.store.root / 'locks' / ('use-' + '0' * 32)
                def persist():
                    with self.assertRaises(BlockingIOError):
                        with lock(lease, blocking=False): pass
                    observations.append(dict(record))
                with lock(lease), self.native_clock() as clock, \
                     patch('stallionfs._native.subprocess.Popen', return_value=Child()):
                    with self.assertRaises(type(primary)) as caught:
                        _native.execute_owned(['helper'], record, persist, directory, deadline=0.1)
                if interrupt:
                    self.assertIs(caught.exception, primary)
                else:
                    # The polling timeout advances time; execute_owned must
                    # raise its own deadline error after observing expiry.
                    self.assertIsNot(caught.exception, primary)
                    self.assertEqual(caught.exception.timeout, 0.1)
                    self.assertGreaterEqual(clock.now, 0.1)
                self.assertEqual(signals, ['terminate', 'kill'])
                self.assertFalse(record['child_pending'])
                self.assertEqual(record['outcome'], 'unknown')
                self.assertEqual(record['returncode'], -9)
                self.assertTrue(any(row.get('child_pending') is True for row in observations))

    def test_native_install_current_anchor_mismatch_retains_unconfirmed(self):
        from stallionfs import _native, _image
        from stallionfs.core import native_failure_details, owned_native_target, read_json
        seed = self.prepare()
        original = _native.install_candidate
        def changed(store, response, intent, metadata, profile, host):
            target = owned_native_target(Path(response['candidate']), metadata)
            _image.snapshot(target, 'changed-before-install')
            return original(store, response, intent, metadata, profile, host)
        with self.native_controller_fixture() as state, patch('stallionfs._native.install_candidate', side_effect=changed):
            with self.assertRaises(StallionError) as caught:
                self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            details = native_failure_details(caught.exception)
            path = Path(details['candidate'])
            self.assertTrue(details['installed'])
            self.assertFalse(details['installation_confirmed'])
            self.assertEqual(read_json(path / 'meta.json')['state'], 'installed-unconfirmed')
            inode = (path / 'image.sfs').stat().st_ino
            with self.assertRaises(StallionError): self.store.mount(path.name)
            self.assertEqual((path / 'image.sfs').stat().st_ino, inode)
            self.assertEqual(state['commands'], [])
            self.assertTrue((self.store.root / 'journals' / (path.name + '.json')).exists())

    def test_native_install_consumed_close_then_proof_error_recovers_fresh(self):
        from stallionfs import _native, _image
        from stallionfs.core import read_json, native_failure_details
        seed = self.prepare()
        original_guard = _image.with_backing_guard
        consumed = []
        def guarded(target, callback):
            tokens = []
            def held(token):
                tokens.append(token)
                return callback(token)
            try:
                return original_guard(target, held)
            finally:
                if tokens: consumed.append(tokens[0].close_result)
        with self.native_controller_fixture(), patch('stallionfs._image.with_backing_guard', side_effect=guarded), \
             patch('stallionfs._native._complete_install', side_effect=OSError(errno.EIO, 'proof persistence')):
            with self.assertRaises(OSError) as caught:
                self.store.create(seed['id'], backend='native-image', capacity_gib=1)
        self.assertTrue(consumed[-1]['core_consumed'])
        self.assertEqual(consumed[-1]['status'], 0)
        path = Path(native_failure_details(caught.exception)['candidate'])
        intent = read_json(self.store.root / 'journals' / (path.name + '.json'))
        self.assertEqual(read_json(path / 'meta.json')['format'], 1)
        self.assertNotIn('format', intent['installation']['metadata'])
        before = len(consumed)
        with self.native_controller_fixture(), patch('stallionfs._image.with_backing_guard', side_effect=guarded), \
             patch('stallionfs._scan.move', side_effect=AssertionError('rename replay')), \
             patch('stallionfs._image.create_from_tree', side_effect=AssertionError('import replay')):
            self.store.mount(path.name)
        self.assertGreater(len(consumed), before)
        proof = read_json(path / 'native-install.json')
        self.assertEqual(proof['previous_installation']['guard'], consumed[0])
        self.assertTrue(proof['complete'])

    def test_native_unmount_error_and_busy_guard_never_grant_closure(self):
        from stallionfs import _native
        from stallionfs.core import read_json
        seed = self.prepare()
        with self.native_controller_fixture() as state:
            result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            path = Path(result['path']).parent.parent
            state['unmount_status'] = 1
            with self.assertRaises(StallionError): self.store.unmount(path.name)
            self.assertIn(str(path / 'volume'), state['rows'])
            self.assertNotIn('closed_at', read_json(self.store._state(path.name)))
            state['unmount_status'] = 0
            with self.native_clock() as clock, \
                 patch('stallionfs._native.guarded', side_effect=OSError(errno.EBUSY, 'held image')) as busy:
                with self.assertRaises(OSError) as caught: self.store.unmount(path.name)
                self.assertGreater(busy.call_count, 1)
                self.assertGreaterEqual(clock.now, _native.OBSERVATION_WINDOW)
                self.assertLessEqual(clock.now, _native.OBSERVATION_WINDOW + 0.05 + 1e-8)
            self.assertEqual(caught.exception.errno, errno.EBUSY)
            self.assertNotIn(str(path / 'volume'), state['rows'])
            journal = self.store.root / 'journals' / (path.name + '.json')
            self.assertEqual(read_json(journal)['outcome'], 'incomplete')
            self.assertNotIn('closed_at', read_json(self.store._state(path.name)))
            commands = len(state['commands'])
            recovered = self.store.unmount(path.name)
            self.assertTrue(recovered['already_absent'])
            self.assertEqual(len(state['commands']), commands)
            self.assertTrue(recovered['native_operation']['current_guard']['core_consumed'])

    def test_native_discovery_qualification_complete_inventory_and_refusals(self):
        import copy
        import plistlib
        from stallionfs import _bundle, _native
        app = self.base / 'StallionFS.app'
        module = app / 'Contents/Extensions/StallionFS.appex'
        host = app / 'Contents/MacOS/StallionFS'
        host.parent.mkdir(parents=True)
        (module / 'Contents').mkdir(parents=True)
        host_info = {'CFBundleIdentifier': 'com.alvinhhh.stallionfs', 'StallionFSControllerProtocol': 1}
        module_info = {'CFBundleIdentifier': 'com.alvinhhh.stallionfs.module', 'CFBundleVersion': '9',
                       'LSMinimumSystemVersion': '27.0', 'StallionFSAccessPolicy': 'contextual-writes',
                       'StallionFSCompiledFactory': {'schema': 1, 'policy': 'contextual-writes',
                           'architectures': ['arm64'], 'pre_sign_sha256': 'a' * 64},
                       'EXAppExtensionAttributes': {'FSShortName': 'stallionfs'}}
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(host_info))
        (module / 'Contents/Info.plist').write_bytes(plistlib.dumps(module_info))
        expected = {'bundle_id': 'com.alvinhhh.stallionfs.module', 'url': str(module), 'enabled': True,
                    'short_name': 'stallionfs', 'version': '9', 'minimum_os': '27.0',
                    'access_policy': 'contextual-writes', 'signature_status': 0,
                    'signing_identifier': 'com.alvinhhh.stallionfs.module', 'team_identifier': _bundle.PUBLISHER_TEAM}
        inventory = {'ok': True, 'protocol': 1, 'modules': [expected]}
        output = self.base / 'discovery-output'
        class Operation:
            def __init__(self, value, status=0): self.record, self.value, self.status, self.calls = {}, value, status, []
            def command(self, label, argv):
                self.calls.append((label, argv))
                output.write_text(self.value if isinstance(self.value, str) else json.dumps(self.value))
                return {'returncode': self.status if label == 'discover' else 0, 'stdout': str(output)}
            def persist(self): pass
        metadata = {'controller_profile': 'production', 'native_host': str(host)}
        with patch('stallionfs._native.platform.mac_ver', return_value=('27.0', (), '')):
            operation = Operation(inventory)
            self.assertEqual(_native.qualify(operation, metadata), 'stallionfs')
            self.assertEqual(operation.calls, [
                ('verify-package', ['/usr/bin/codesign', '--verify', '--deep', '--strict', '-R',
                    'anchor apple generic and identifier "com.alvinhhh.stallionfs" '
                    'and certificate leaf[subject.OU] = "' + _bundle.PUBLISHER_TEAM + '"', str(app)]),
                ('discover', [str(host), '--discover-json'])])
            variants = [('disabled', {'enabled': False}), ('wrong-url', {'url': '/different/module'}),
                        ('signature', {'signature_status': -1}), ('team', {'team_identifier': None}),
                        ('wrong-team', {'team_identifier': 'OTHER'}),
                        ('version', {'version': '8'}), ('readonly', {'access_policy': 'read-only'}),
                        ('non-scalar', {'short_name': []}), ('wrong-type', {'short_name': 'sfsro27'})]
            for case, change in variants:
                with self.subTest(case=case):
                    value = copy.deepcopy(inventory); value['modules'][0].update(change)
                    with self.assertRaises(StallionError): _native.qualify(Operation(value), metadata)
            collision = copy.deepcopy(inventory)
            collision['modules'].append({**expected, 'bundle_id': 'other', 'url': '/other'})
            for value in (collision, {'ok': True, 'protocol': 1, 'modules': []},
                          {'ok': False, 'error': 'fetch'}, {'ok': True, 'protocol': 1, 'modules': [None]},
                          '{', 'x' * (_native.DISCOVERY_BYTES + 1)):
                with self.assertRaises(StallionError): _native.qualify(Operation(value), metadata)
            with self.assertRaises(StallionError): _native.qualify(Operation(inventory, status=1), metadata)
            for factory in (None, {}, {'schema': 1, 'policy': 'read-only',
                            'architectures': ['arm64'], 'pre_sign_sha256': 'a' * 64}):
                changed = dict(module_info, StallionFSCompiledFactory=factory)
                (module / 'Contents/Info.plist').write_bytes(plistlib.dumps(changed) if factory is not None
                    else plistlib.dumps({key: val for key, val in module_info.items() if key != 'StallionFSCompiledFactory'}))
                operation = Operation(inventory)
                with self.assertRaises(StallionError): _native.qualify(operation, metadata)
                self.assertEqual(operation.calls, [])
            changed = copy.deepcopy(module_info)
            changed['EXAppExtensionAttributes']['FSShortName'] = 'sfsro27'
            (module / 'Contents/Info.plist').write_bytes(plistlib.dumps(changed))
            private_inventory = copy.deepcopy(inventory)
            private_inventory['modules'][0]['short_name'] = 'sfsro27'
            self.assertEqual(_native.qualify(Operation(private_inventory),
                dict(metadata, controller_profile='private-sfsro27')), 'sfsro27')
            with self.assertRaises(StallionError): _native.qualify(Operation(private_inventory), metadata)
            (module / 'Contents/Info.plist').write_bytes(plistlib.dumps(module_info))
        with patch('stallionfs._native.platform.mac_ver', return_value=('26.0', (), '')):
            operation = Operation(inventory)
            with self.assertRaises(StallionError): _native.qualify(operation, metadata)
            self.assertEqual(operation.calls, [])

    def test_native_helper_signal_during_launch_keeps_handle_and_reaps(self):
        from stallionfs import _native
        directory = self.base / 'launch-signal'; directory.mkdir()
        record, signals, handlers = {}, [], {}
        class Child:
            pid = 73
            returncode = None
            def poll(self): return self.returncode
            def terminate(self): signals.append('terminate'); self.returncode = -15
            def kill(self): raise AssertionError('unnecessary kill')
            def wait(self, timeout=None): return self.returncode
        child = Child()
        def set_handler(number, handler): handlers[number] = handler
        def launch(*args, **kwargs):
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            return child
        with patch('stallionfs._native.signal.getsignal', return_value=signal.SIG_DFL), \
             patch('stallionfs._native.signal.signal', side_effect=set_handler), \
             patch('stallionfs._native.subprocess.Popen', side_effect=launch):
            with self.assertRaises(KeyboardInterrupt):
                _native.execute_owned(['helper'], record, lambda: None, directory)
        self.assertEqual(signals, ['terminate'])
        self.assertEqual(record['pid'], child.pid)
        self.assertEqual(record['returncode'], -15)
        self.assertFalse(record['child_pending'])
        self.assertEqual(record['outcome'], 'unknown')
        self.assertTrue(all(value == signal.SIG_DFL for value in handlers.values()))

    def test_native_installed_directory_and_recovery_intent_cannot_be_substituted(self):
        import copy
        from stallionfs import _native, _scan
        from stallionfs.core import read_json, native_failure_details
        from stallionfs.lifecycle import replace_json, identity
        seed = self.prepare()
        with self.native_controller_fixture():
            result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            self.store.unmount(result['id'])
        path = Path(result['path']).parent.parent
        metadata = read_json(path / 'meta.json')
        retained = path.with_name(path.name + '-retained')
        path.rename(retained)
        path.mkdir(mode=0o700)
        # Transplant the SAME backing inode and copied proofs into a new resource
        # directory, then update all mutable location fields to that new inode.
        for item in retained.iterdir(): item.rename(path / item.name)
        metadata['native_image']['object'] = identity(path)
        replace_json(path / 'meta.json', metadata)
        proof = read_json(path / 'native-install.json')
        proof['target'] = metadata['native_image']
        replace_json(path / 'native-install.json', proof)
        with self.assertRaises(StallionError): _native.installed_target(self.store, path, metadata)
        original_move = _scan.move
        def lost(source, destination, **kwargs):
            original_move(source, destination, **kwargs)
            raise OSError(errno.EIO, 'rename response lost')
        with self.native_controller_fixture(), patch('stallionfs._scan.move', side_effect=lost):
            with self.assertRaises(OSError) as caught:
                self.store.create(seed['id'], backend='native-image', capacity_gib=1)
        path = Path(native_failure_details(caught.exception)['candidate'])
        journal = self.store.root / 'journals' / (path.name + '.json')
        original = read_json(journal)
        for field in ('object', 'installation-metadata'):
            intent = copy.deepcopy(original)
            if field == 'object': intent['object'][1] += 1
            else: intent['installation']['metadata']['native_host'] = '/substituted/host'
            replace_json(journal, intent)
            before = journal.read_bytes()
            with self.native_controller_fixture() as state:
                with self.assertRaises(StallionError): self.store.mount(path.name)
                self.assertEqual(state['commands'], [])
            self.assertEqual(journal.read_bytes(), before)
        replace_json(journal, original)
        with self.native_controller_fixture(): self.store.mount(path.name)

    def test_native_malformed_helper_dispositions_retain_exact_journal(self):
        import copy
        from stallionfs.core import read_json
        from stallionfs.lifecycle import replace_json
        seed = self.prepare()
        with self.native_controller_fixture() as state:
            result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            path = Path(result['path']).parent.parent
            self.store.unmount(path.name)
            baseline = next(read_json(p) for p in (path / 'native-operations').glob('*/record.json')
                            if read_json(p)['operation'] == 'native-mount')
            journal = self.store.root / 'journals' / (path.name + '.json')
            variants = []
            for key in ('child_pending', 'helpers'):
                value = copy.deepcopy(baseline); value.pop(key); variants.append(value)
            for pending in ('false', 0, 1, None):
                value = copy.deepcopy(baseline); value['child_pending'] = pending; variants.append(value)
                value = copy.deepcopy(baseline); value['helpers'][0]['child_pending'] = pending; variants.append(value)
            for helper in ({}, None, {'child_pending': False}):
                value = copy.deepcopy(baseline); value['helpers'] = [helper]; variants.append(value)
            for outcome in ('running', 'launch-pending'):
                value = copy.deepcopy(baseline); value['helpers'][0]['outcome'] = outcome; variants.append(value)
            for key in ('child_pending', 'pid', 'returncode', 'reaped'):
                value = copy.deepcopy(baseline); value['helpers'][0].pop(key); variants.append(value)
            value = copy.deepcopy(baseline); value['workspace'] = 'f' * 32; variants.append(value)
            value = copy.deepcopy(baseline); value['operation'] = 'native-unmount'; variants.append(value)
            value = copy.deepcopy(baseline); value['helpers'][0].update(outcome='unknown', reaped=False); variants.append(value)
            value = copy.deepcopy(baseline); value['target']['file'][1] += 1; variants.append(value)
            for index, value in enumerate(variants):
                with self.subTest(index=index):
                    replace_json(journal, value); before = journal.read_bytes()
                    commands = len(state['commands'])
                    for action in (lambda: self.store.mount(path.name), lambda: self.store.unmount(path.name),
                                   lambda: self.store.run(path.name, ['true'])):
                        with self.assertRaises(StallionError): action()
                        self.assertEqual(journal.read_bytes(), before)
                    self.assertEqual(len(state['commands']), commands)

    def test_native_recovered_first_use_requires_git_and_actual_write_acceptance(self):
        from stallionfs import _native
        from stallionfs.core import read_json
        seed = self.prepare()
        installed = []
        original_install = _native.install_candidate
        def stop_after_install(*args, **kwargs):
            response = original_install(*args, **kwargs)
            installed.append(Path(response['candidate']))
            raise OSError(errno.EIO, 'stopped before first mount')
        with self.native_controller_fixture(), patch('stallionfs._native.install_candidate', side_effect=stop_after_install):
            with self.assertRaises(OSError): self.store.create(seed['id'], backend='native-image', capacity_gib=1)
        path = installed[0]
        self.assertEqual(read_json(path / 'native-install.json')['first_use'], {'accepted': False})
        repo = path / 'volume/repo'
        clone_tree(self.store.root / 'seeds' / seed['id'] / 'repo', repo)
        git(repo, 'checkout', '-b', 'wrong-initial-branch')
        with self.native_controller_fixture() as mounted:
            with self.assertRaises(StallionError): self.store.mount(path.name)
            self.assertFalse(read_json(path / 'native-install.json')['first_use']['accepted'])
            self.store.unmount(path.name)
            metadata = read_json(path / 'meta.json')
            git(repo, 'checkout', '-b', metadata['branch'])
            git(repo, 'config', 'user.email', 'test@example.invalid')
            git(repo, 'config', 'user.name', 'Test')
            git(repo, 'commit', '--allow-empty', '-m', 'Wrong initial commit')
            with self.assertRaises(StallionError): self.store.mount(path.name)
            self.store.unmount(path.name)
            git(repo, 'reset', '--hard', metadata['commit'])
            original_open = os.open
            for number in (errno.EROFS, errno.EACCES):
                def deny(probe, flags, *args, **kwargs):
                    if Path(probe).name.startswith('.stallionfs-write-'): raise OSError(number, 'write denied')
                    return original_open(probe, flags, *args, **kwargs)
                with patch('stallionfs._native.os.open', side_effect=deny):
                    with self.assertRaises(OSError) as caught: self.store.mount(path.name)
                self.assertEqual(caught.exception.errno, number)
                self.assertFalse(read_json(path / 'native-install.json')['first_use']['accepted'])
                journal = read_json(self.store.root / 'journals' / (path.name + '.json'))
                self.assertFalse(journal['write_probe']['complete'])
                self.assertEqual(journal['outcome'], 'incomplete')
                self.store.unmount(path.name)
            immutable = {name: (path / name).read_bytes() for name in ('native-create.json', 'meta.json')}
            ownership = read_json(path / 'native-install.json')
            for key in ('first_mount_attempted', 'first_use'): ownership.pop(key)
            original_write, original_fsync, original_close = os.write, os.fsync, os.close
            original_unlink = Path.unlink
            for fault in ('short-write', 'fsync', 'close', 'unlink'):
                with self.subTest(probe_fault=fault):
                    absent = (path / 'native-mount.json').read_bytes()
                    self.assertEqual(read_json(path / 'native-mount.json')['state'], 'absent')
                    probe = {'path': None, 'fd': None, 'data': None}
                    fired, closed = [], []
                    def opened(candidate, flags, *args, **kwargs):
                        fd = original_open(candidate, flags, *args, **kwargs)
                        candidate = Path(candidate)
                        if candidate.parent == repo and candidate.name.startswith('.stallionfs-write-'):
                            self.assertIsNone(probe['path'])
                            probe.update(path=candidate, fd=fd)
                        return fd
                    def written(fd, data):
                        if fd == probe['fd']:
                            probe['data'] = data[:-1] if fault == 'short-write' else data
                            if fault == 'short-write':
                                fired.append(fault)
                                count = original_write(fd, probe['data'])
                                self.assertEqual(count, len(probe['data']))
                                return count
                        return original_write(fd, data)
                    def synced(fd):
                        if fd == probe['fd'] and fault == 'fsync':
                            fired.append(fault)
                            raise OSError(errno.EIO, 'probe fsync failed')
                        return original_fsync(fd)
                    def finished(fd):
                        current = fd == probe['fd']
                        result = original_close(fd)
                        if current:
                            probe['fd'] = None
                            closed.append(fd)
                            if fault == 'close':
                                fired.append(fault)
                                raise OSError(errno.EIO, 'probe close report failed')
                        return result
                    def unlinked(candidate, *args, **kwargs):
                        if candidate == probe['path'] and fault == 'unlink':
                            fired.append(fault)
                            raise OSError(errno.EIO, 'probe unlink failed')
                        return original_unlink(candidate, *args, **kwargs)
                    with patch('stallionfs._native.os.open', side_effect=opened), \
                         patch('stallionfs._native.os.write', side_effect=written), \
                         patch('stallionfs._native.os.fsync', side_effect=synced), \
                         patch('stallionfs._native.os.close', side_effect=finished), \
                         patch.object(Path, 'unlink', unlinked):
                        with self.assertRaises(OSError) as caught: self.store.mount(path.name)
                    self.assertEqual(caught.exception.errno, errno.EIO)
                    self.assertEqual(fired, [fault])
                    self.assertIsNone(probe['fd'])
                    self.assertEqual(len(closed), 1)
                    self.assertEqual(probe['path'].read_bytes(), probe['data'])
                    installed_proof = read_json(path / 'native-install.json')
                    self.assertTrue(installed_proof.pop('first_mount_attempted'))
                    self.assertEqual(installed_proof.pop('first_use'), {'accepted': False})
                    self.assertEqual(installed_proof, ownership)
                    for name, data in immutable.items(): self.assertEqual((path / name).read_bytes(), data)
                    journal = read_json(self.store.root / 'journals' / (path.name + '.json'))
                    self.assertEqual(journal['write_probe'], {'path': str(probe['path']), 'complete': False})
                    self.assertEqual(journal['outcome'], 'incomplete')
                    self.assertEqual((path / 'native-mount.json').read_bytes(), absent)
                    self.assertIn(str(path / 'volume'), mounted['rows'])
                    self.store.unmount(path.name)
            self.store.mount(path.name)
            self.assertTrue(read_json(path / 'native-install.json')['first_use']['accepted'])
            self.store.unmount(path.name)
            git(repo, 'checkout', '-b', 'legitimate-later-branch')
            git(repo, 'commit', '--allow-empty', '-m', 'Legitimate later commit')
            self.store.mount(path.name)
            self.assertEqual(git(repo, 'branch', '--show-current'), 'legitimate-later-branch')

    def test_native_repeated_operations_and_supervision_have_bounded_receipts(self):
        from stallionfs import _native
        from stallionfs.core import read_json
        path = self.store.root / 'workspaces' / ('e' * 32); path.mkdir(mode=0o700)
        target = {'directory': str(path), 'component': 'image.sfs', 'parent': [1, 2], 'file': [1, 3], 'uuid': 'a' * 32}
        previous = None
        for number in range(100):
            operation = _native.Operation(self.store, path, 'native-unmount', target)
            operation.record['outcome'] = 'incomplete'; operation.persist()
            if previous:
                reference = operation.record['previous_unresolved']
                self.assertEqual(reference['id'], previous.record['id'])
                self.assertEqual(read_json(Path(reference['record']))['outcome'], 'incomplete')
                self.assertNotIn('previous_unresolved', reference)
            self.assertLess(len(json.dumps(operation.record)), 1600)
            previous = operation
        record, attempts = {}, []
        class Child:
            pid = 101
            returncode = None
            def poll(self): return self.returncode
            def terminate(self): raise OSError(errno.EPERM, 'cannot terminate yet')
            def kill(self):
                attempts.append(1)
                if len(attempts) < 100: raise OSError(errno.EPERM, 'cannot stop yet')
                self.returncode = -9
            def wait(self, timeout=None): return self.returncode
        primary = KeyboardInterrupt('primary interrupted outcome')
        child = Child()
        directory = self.base / 'repeated-helper'; directory.mkdir()
        def wait_once(timeout=None):
            if child.returncode is None: raise primary
            return child.returncode
        child.wait = wait_once
        def persist():
            if record.get('stop_errors'): raise OSError(errno.EIO, 'receipt persistence failed')
        with self.native_clock() as clock, \
             patch('stallionfs._native.subprocess.Popen', return_value=child), \
             patch.object(clock, 'sleep', side_effect=InterruptedError('supervision interrupted')):
            with self.assertRaises(KeyboardInterrupt) as caught:
                _native.execute_owned(['helper'], record, persist, directory)
        self.assertIs(caught.exception, primary)
        self.assertTrue(record['reaped'])
        self.assertFalse(record['child_pending'])
        self.assertEqual(record['outcome'], 'unknown')
        self.assertEqual(record['stop_errors']['count'], 300)
        self.assertEqual(record['stop_errors']['first']['phase'], 'stop-reap')
        self.assertEqual(record['stop_errors']['last']['phase'], 'supervise')
        self.assertLess(len(json.dumps(record)), 1600)

    def test_native_helper_stream_close_preserves_primary_interruption(self):
        from stallionfs import _native
        directory = self.base / 'close-error-helper'; directory.mkdir()
        record = {}
        primary = KeyboardInterrupt('primary')
        class Stream:
            def close(self): raise OSError(errno.EIO, 'stream close')
        class Child:
            pid = 42
            returncode = None
            def poll(self): return self.returncode
            def wait(self, timeout=None):
                if self.returncode is None: raise primary
                return self.returncode
            def terminate(self): self.returncode = -15
        with patch('pathlib.Path.open', return_value=Stream()), \
             patch('stallionfs._native.subprocess.Popen', return_value=Child()):
            with self.assertRaises(KeyboardInterrupt) as caught:
                _native.execute_owned(['helper'], record, lambda: None, directory)
        self.assertIs(caught.exception, primary)
        self.assertEqual(record['stream_close_errors'], ['OSError', 'OSError'])
        self.assertTrue(record['reaped'])
        self.assertEqual(record['outcome'], 'unknown')

    def test_native_install_target_exists_and_late_guard_receipts_fail_closed(self):
        from stallionfs import _native, _image
        from stallionfs.core import native_failure_details, read_json
        seed = self.prepare()
        original = _native.install_candidate
        def occupied(store, response, intent, metadata, profile, host):
            (store.root / 'workspaces' / metadata['id']).mkdir(mode=0o700)
            return original(store, response, intent, metadata, profile, host)
        with self.native_controller_fixture() as state, patch('stallionfs._native.install_candidate', side_effect=occupied):
            with self.assertRaises(StallionError): self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            self.assertEqual(state['commands'], [])
        real_guard = _image.with_backing_guard
        for field, value in (('parent_close_errno', errno.EIO), ('status', -errno.EIO), ('core_consumed', False)):
            def late(target, callback):
                class Token:
                    def __init__(self, token): self.token = token
                    def verify(self, target): return self.token.verify(target)
                    @property
                    def close_result(self): return dict(self.token.close_result, **{field: value})
                return real_guard(target, lambda token: callback(Token(token)))
            with self.native_controller_fixture() as state, patch('stallionfs._image.with_backing_guard', side_effect=late):
                with self.assertRaises(StallionError) as caught:
                    self.store.create(seed['id'], backend='native-image', capacity_gib=1)
                details = native_failure_details(caught.exception)
                path = Path(details['candidate'])
                self.assertTrue(details['installed'])
                self.assertEqual(read_json(path / 'meta.json')['state'], 'installed-unconfirmed')
                self.assertEqual(state['commands'], [])

    def test_native_install_and_first_use_durable_write_interruptions(self):
        from stallionfs import _native
        from stallionfs.core import read_json, native_failure_details
        seed = self.prepare()
        original = _native._persist
        phases = ('prepared-intent', 'source-metadata', 'rename-intent', 'guard-receipt',
                  'install-proof', 'installed-metadata', 'first-mount', 'first-use', 'mount-state')
        for phase in phases:
            fired = []
            def interrupt(path, value):
                installation = value.get('installation', {})
                matches = {
                    'prepared-intent': installation.get('outcome') == 'prepared',
                    'source-metadata': Path(path).name == 'meta.json' and value.get('state') == 'installed-unconfirmed',
                    'rename-intent': installation.get('outcome') == 'rename-attempted' and installation.get('guard') is None,
                    'guard-receipt': installation.get('guard') is not None,
                    'install-proof': Path(path).name == 'native-install.json' and value.get('first_mount_attempted') is False,
                    'installed-metadata': Path(path).name == 'meta.json' and value.get('state') == 'installed',
                    'first-mount': Path(path).name == 'native-install.json' and value.get('first_mount_attempted') is True,
                    'first-use': Path(path).name == 'native-install.json' and value.get('first_use', {}).get('accepted') is True,
                    'mount-state': Path(path).name == 'native-mount.json' and value.get('state') == 'mounted',
                }
                if matches[phase] and not fired:
                    fired.append(Path(path)); raise OSError(errno.EIO, phase)
                return original(path, value)
            with self.subTest(phase=phase), self.native_controller_fixture() as state, \
                 patch('stallionfs._native._persist', side_effect=interrupt):
                with self.assertRaises(OSError): self.store.create(seed['id'], backend='native-image', capacity_gib=1)
                self.assertEqual(len(fired), 1)
                self.assertLessEqual(len(state['commands']), 1)
                if phase == 'first-use':
                    path = fired[0].parent
                    self.assertFalse(read_json(path / 'native-install.json')['first_use']['accepted'])
                    self.assertFalse((path / 'native-mount.json').exists())
                if phase == 'mount-state':
                    self.assertTrue(read_json(fired[0].parent / 'native-install.json')['first_use']['accepted'])
                    self.assertTrue((self.store.root / 'journals' / (fired[0].parent.name + '.json')).exists())

    def test_native_mount_descriptor_disagreement_never_returns_usable_access(self):
        seed = self.prepare()
        with self.native_controller_fixture() as state:
            def wrong(fd):
                row = dict(next(iter(state['rows'].values())))
                row['fsid'] = [999, 999]
                return row
            with patch('stallionfs._scan.mount_for_descriptor', side_effect=wrong):
                with self.assertRaises(StallionError): self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            self.assertEqual(len(state['commands']), 1)
            self.assertFalse(state['observed_fds'])
            volume = Path(next(iter(state['rows'])))
            self.assertFalse((volume.parent / 'native-mount.json').exists())

    def test_cli_native_create_flags_and_timeout_receipt(self):
        from stallionfs.__main__ import main
        seed = '1' * 64
        host = self.base / 'StallionFS.app/Contents/MacOS/StallionFS'
        with patch.object(Store, 'create', return_value={'path': '/usable/repo'}) as create, \
             patch('sys.stdout', new_callable=StringIO) as stdout:
            status = main(['--root', str(self.store.root), 'create', seed, '--backend', 'native-image',
                           '--capacity-gib', '2', '--native-profile', 'private-sfsro27', '--native-host', str(host)])
        self.assertEqual(status, 0)
        self.assertEqual(stdout.getvalue(), '/usable/repo\n')
        create.assert_called_once_with(seed, name='', jobs=4, backend='native-image', capacity_gib=2,
                                       native_profile='private-sfsro27', native_host=host)
        error = subprocess.TimeoutExpired(['owned-helper'], 30)
        error.native_candidate_result = {'workspace': '2' * 32, 'outcome': 'incomplete'}
        with patch.object(Store, 'mount', side_effect=error), patch('sys.stderr', new_callable=StringIO) as stderr:
            self.assertEqual(main(['--root', str(self.store.root), '--json', 'mount', '2' * 32]), 1)
        self.assertEqual(json.loads(stderr.getvalue())['native_image_result']['workspace'], '2' * 32)

    @contextmanager
    def native_wall_clock(self, value=1_000_000.0):
        from types import SimpleNamespace
        current = [value]
        clock = SimpleNamespace(time=lambda: current[0])
        with patch('stallionfs.lifecycle.time', clock), patch('stallionfs._native_recovery.time', clock):
            yield current

    def native_purge_fixture(self, seed, now):
        """Produce real native trash with an empty simulated unmounted directory."""
        from stallionfs.core import read_json
        from stallionfs.lifecycle import STALE_SECONDS
        result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
        workspace = result['id']; path = Path(result['path']).parent.parent
        self.store.unmount(workspace)
        self.store.snapshot(workspace, name='retained-data')
        self.store.enroll(workspace); self.store.close(workspace, quiescent=True)
        # The namespace fixture materializes a host Git clone; real unmount hides
        # that mounted tree. Remove only this disposable fixture's host clone.
        remove_tree(path / 'volume/repo')
        for archive in (path / 'native-operations').iterdir():
            record = read_json(archive / 'record.json')
            for index, helper in enumerate(record['helpers']):
                for stream in ('stdout', 'stderr'):
                    output = archive / f'{index:02}-{helper["label"]}' / stream
                    output.write_bytes(b'fixture helper output\n'); output.chmod(0o600)
        now[0] += STALE_SECONDS
        self.store.move(workspace)
        return workspace, self.store.root / 'trash' / workspace

    def test_native_purge_pre_relocation_crash_retry_preserves_orphan(self):
        from stallionfs import _native, _native_purge
        from stallionfs.core import read_json
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            for crash in ('unbound-container', 'missing-bound-container'):
                with self.subTest(crash=crash):
                    workspace, path = self.native_purge_fixture(seed, now)
                    record = self.store.purge('trash', workspace)['native_operation']
                    journal = self.store.root / 'journals' / (workspace + '.json')
                    orphan = self.store.root / 'staging' / record['container']
                    orphan.mkdir(mode=0o700)
                    if crash == 'missing-bound-container':
                        record['container_identity'] = _native_purge.identity(orphan.stat())
                    # Materialize only the crash-persisted state, without an exception
                    # handler publishing an in-memory container identity afterward.
                    _native._persist(journal, record)
                    if crash == 'missing-bound-container': orphan.rmdir()
                    else:
                        (orphan / 'unknown').write_bytes(b'unknown orphan retained')
                        orphan_identity = orphan.stat().st_ino
                    before = journal.read_bytes()
                    with patch('stallionfs._native_purge.restart_unrelocated', side_effect=AssertionError('preview restarted')):
                        self.assertTrue(self.store.purge('trash', workspace)['pending'])
                    self.assertEqual(journal.read_bytes(), before)
                    self.assertTrue((path / 'image.sfs').exists())
                    result = self.store.purge('trash', workspace, yes=True)
                    self.assertTrue(result['cleanup_complete'])
                    self.assertNotEqual(result['native_operation']['id'], record['id'])
                    abandoned = result['native_operation']['abandoned_attempt']
                    archive = self.store.root / 'lifecycle' / ('native-purge-abandoned-' + workspace
                        + '-' + abandoned['id'] + '-' + abandoned['sha256'] + '.json')
                    self.assertEqual(read_json(archive), json.loads(before))
                    self.assertFalse(path.exists())
                    if crash == 'unbound-container':
                        self.assertEqual(orphan.stat().st_ino, orphan_identity)
                        self.assertEqual((orphan / 'unknown').read_bytes(), b'unknown orphan retained')
                        self.assertIn('native purge', _native_purge.core.native_retention_reason(orphan))
                    else: self.assertFalse(orphan.exists())

    def test_native_purge_pre_relocation_retry_publication_failures_remain_recoverable(self):
        from stallionfs import _native, core
        from stallionfs.core import read_json
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            for boundary in ('archive-before', 'archive-after', 'archive-fsync', 'replacement-before', 'replacement-after'):
                with self.subTest(boundary=boundary):
                    workspace, path = self.native_purge_fixture(seed, now)
                    record = self.store.purge('trash', workspace)['native_operation']
                    journal = self.store.root / 'journals' / (workspace + '.json')
                    _native._persist(journal, record)
                    orphan = self.store.root / 'staging' / record['container']; orphan.mkdir(mode=0o700)
                    (orphan / 'unknown').write_bytes(b'retain')
                    before = journal.read_bytes(); fired = []
                    write, persist, sync = core.write_json, _native._persist, os.fsync
                    def publishing(target, value):
                        if Path(target).name.startswith('native-purge-abandoned-') and boundary.startswith('archive-') and boundary != 'archive-fsync':
                            fired.append(True)
                            if boundary == 'archive-after': write(target, value)
                            raise OSError(errno.EIO, boundary)
                        return write(target, value)
                    def replacing(target, value):
                        if Path(target) == journal and value.get('id') != record['id'] and boundary.startswith('replacement-'):
                            fired.append(True)
                            if boundary == 'replacement-after': persist(target, value)
                            raise OSError(errno.EIO, boundary)
                        return persist(target, value)
                    def syncing(fd):
                        if boundary == 'archive-fsync' and os.fstat(fd).st_ino == (self.store.root / 'lifecycle').stat().st_ino:
                            fired.append(True); raise OSError(errno.EIO, boundary)
                        return sync(fd)
                    with patch('stallionfs.core.write_json', side_effect=publishing), \
                         patch('stallionfs._native._persist', side_effect=replacing), \
                         patch('stallionfs._native_purge.os.fsync', side_effect=syncing), \
                         patch('stallionfs._native_purge.failure'):
                        with self.assertRaises(OSError): self.store.purge('trash', workspace, yes=True)
                    self.assertTrue(fired)
                    self.assertTrue((path / 'image.sfs').exists())
                    if boundary != 'replacement-after': self.assertEqual(journal.read_bytes(), before)
                    else:
                        replacement = read_json(journal)
                        self.assertEqual(replacement['abandoned_attempt']['id'], record['id'])
                        self.assertTrue(list((self.store.root / 'lifecycle').glob('native-purge-abandoned-' + workspace + '-*.json')))
                    self.assertTrue(self.store.purge('trash', workspace, yes=True)['cleanup_complete'])
                    self.assertEqual((orphan / 'unknown').read_bytes(), b'retain')

    def test_native_purge_bounded_metadata_ingress_refuses_before_decode_or_mutation(self):
        from stallionfs import _native, _native_purge, core
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            workspace, path = self.native_purge_fixture(seed, now)
            journal = self.store.root / 'journals' / (workspace + '.json')
            neighbor = self.store.root / 'journals' / ('e' * 32 + '.json')
            record = self.store.purge('trash', workspace)['native_operation']
            _native._persist(journal, record)
            archive_record = next((path / 'native-operations').glob('*/record.json'))
            original_state = self.store._state(workspace).read_bytes()
            reference = self.store.root / 'workspaces' / ('d' * 32)
            reference.mkdir(mode=0o700)
            core.write_json(reference / 'meta.json', {'backend': 'fixture'})
            cases = [('selected-journal', journal), ('completion', self.store._state(workspace)),
                ('neighbor', neighbor), ('reference-metadata', reference / 'meta.json'),
                ('metadata', path / 'meta.json'),
                ('creation-proof', path / 'native-create.json'), ('installation-proof', path / 'native-install.json'),
                ('location-proof', path / 'native-location.json'),
                ('protection', self.store.root / 'protected' / (workspace + '.json')),
                ('operation-proof', archive_record)]
            limit = _native_purge.MAX_INTENT_BYTES
            loads = json.loads
            for label, target in cases:
                with self.subTest(input=label):
                    saved = target.read_bytes() if target.exists() else None
                    payload = saved or b'{"format":1,"operation":"native-purge"}'
                    if label == 'completion': payload = b'{"format":1,"operation":"native-purge-complete"}'
                    target.write_bytes(payload + b' ' * (limit + 1 - len(payload))); target.chmod(0o600)
                    before = {str(p): p.read_bytes() for p in self.store.root.rglob('*.json')}
                    def decoding(data, *args, **kwargs):
                        self.assertLessEqual(len(data.encode() if isinstance(data, str) else data), limit)
                        return loads(data, *args, **kwargs)
                    with patch('stallionfs.core.json.loads', side_effect=decoding), \
                         patch('stallionfs._native._persist', side_effect=AssertionError('receipt rewrite')), \
                         patch('stallionfs.core.write_json', side_effect=AssertionError('metadata write')), \
                         patch('stallionfs._native_purge.os.rename', side_effect=AssertionError('rename')), \
                         patch('stallionfs._native_purge.os.unlink', side_effect=AssertionError('unlink')):
                        with self.assertRaises(core.MetadataLimitError): self.store.purge('trash', workspace, yes=True)
                    self.assertEqual({str(p): p.read_bytes() for p in self.store.root.rglob('*.json')}, before)
                    self.assertTrue((path / 'image.sfs').exists())
                    self.assertIsNone(core._json_read_limit.get())
                    if saved is None: target.unlink()
                    else: target.write_bytes(saved)
            self.assertEqual(self.store._state(workspace).read_bytes(), original_state)
            (reference / 'meta.json').unlink(); reference.rmdir()
            # With no pending purge, these same proof reads are delegated through
            # installed_target/ready; they still refuse before any progress write.
            journal.unlink()
            for name in ('native-create.json', 'native-install.json', 'native-location.json'):
                target = path / name; saved = target.read_bytes()
                target.write_bytes(saved + b' ' * (limit + 1 - len(saved)))
                with patch('stallionfs.core.json.loads', side_effect=decoding), \
                     patch('stallionfs._native._persist', side_effect=AssertionError('receipt rewrite')):
                    with self.assertRaises(core.MetadataLimitError): self.store.purge('trash', workspace, yes=True)
                target.write_bytes(saved)
            # Exact-limit valid input remains admissible; whitespace counts as input.
            target = path / 'meta.json'; saved = target.read_bytes()
            target.write_bytes(saved + b' ' * (limit - len(saved)))
            self.assertTrue(self.store.purge('trash', workspace)['would_delete'])
            target.write_bytes(saved)
            with core.json_read_limit(64):
                with self.assertRaises(core.MetadataLimitError):
                    with core.json_read_limit(16): core.read_json(target)
                self.assertEqual(core._json_read_limit.get(), 64)
            self.assertIsNone(core._json_read_limit.get())
            self.assertEqual(core.read_json(target)['id'], workspace)
            self.assertTrue(self.store.purge('trash', workspace, yes=True)['cleanup_complete'])

    def test_native_purge_pending_move_bounds_future_proofs_before_recovery(self):
        from stallionfs import _native, _native_purge, core
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            workspace, path = self.native_purge_fixture(seed, now)
            persist = _native._persist
            def interrupted(target, value):
                if Path(target).name == 'native-location.json': raise OSError(errno.EIO, 'return location response')
                return persist(target, value)
            with patch('stallionfs._native._persist', side_effect=interrupted):
                with self.assertRaises(OSError): self.store.move(workspace, restore=True)
            path = self.store.root / 'workspaces' / workspace
            archive = next((path / 'native-operations').glob('*/record.json'))
            saved = archive.read_bytes()
            archive.write_bytes(saved + b' ' * (_native_purge.MAX_INTENT_BYTES + 1 - len(saved)))
            before = {str(p): p.read_bytes() for p in self.store.root.rglob('*.json')}
            with patch('stallionfs._native_recovery.recover_move', side_effect=AssertionError('recovery mutation')):
                with self.assertRaises(core.MetadataLimitError): self.store.purge('trash', workspace, yes=True)
            self.assertEqual({str(p): p.read_bytes() for p in self.store.root.rglob('*.json')}, before)
            self.assertTrue((path / 'image.sfs').exists()); self.assertIsNone(core._json_read_limit.get())
            archive.write_bytes(saved)

    def test_native_purge_preview_full_retention_success_and_completed_repeat(self):
        from stallionfs.core import read_json, write_json
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            workspace, path = self.native_purge_fixture(seed, now)
            self.assertEqual(set(read_json(path / 'meta.json')['native_image']),
                {'component', 'parent', 'object', 'file', 'uuid'})
            other, retained = self.native_purge_fixture(seed, now)
            for index in range(30):
                write_json(self.store.root / 'protected' / f'{index:032x}.json', {'fixture': True})
            self.assertEqual(len(list((self.store.root / 'protected').iterdir())), 32)
            def records(): return {str(p.relative_to(self.store.root)): p.read_bytes() for p in self.store.root.rglob('*.json')}
            before = records()
            preview = self.store.purge('trash', workspace)
            self.assertTrue(preview['would_delete']); self.assertFalse(preview['data_absent'])
            self.assertEqual(records(), before)
            with patch.object(self.store, '_retention', side_effect=AssertionError('purge requested a new slot')):
                result = self.store.purge('trash', workspace, yes=True)
            self.assertTrue(result['data_absent']); self.assertTrue(result['metadata_complete']); self.assertTrue(result['cleanup_complete'])
            self.assertFalse(path.exists()); self.assertTrue((retained / 'image.sfs').exists())
            receipt = read_json(self.store._state(workspace))
            self.assertEqual(receipt['operation'], 'native-purge-complete'); self.assertNotIn('manifest', receipt)
            self.assertEqual(receipt['guard_outcome'], 'consumed'); self.assertEqual(receipt['unlink_outcome'], 'returned')
            self.assertFalse((self.store.root / 'staging' / receipt['container']).exists())
            after = records()
            self.assertTrue(self.store.purge('trash', workspace, yes=True)['already_purged'])
            self.assertEqual(records(), after)
            self.assertTrue(self.store.purge('trash', workspace)['would_delete']); self.assertEqual(records(), after)
            with self.assertRaises(StallionError): self.store.purge('trash', 'f' * 32, yes=True)
            with patch.object(self.store, '_retention', side_effect=AssertionError('restore requested a new slot')):
                self.store.move(other, restore=True)
            self.assertTrue((self.store.root / 'workspaces' / other / 'image.sfs').exists())

    def test_native_purge_pending_move_preview_never_reconciles(self):
        from stallionfs import _native, _native_recovery
        from stallionfs.core import read_json
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            workspace, trash = self.native_purge_fixture(seed, now)
            original = _native._persist
            def interrupted(path, value):
                if Path(path).name == 'native-location.json': raise OSError(errno.EIO, 'return location response')
                return original(path, value)
            with patch('stallionfs._native._persist', side_effect=interrupted):
                with self.assertRaises(OSError): self.store.move(workspace, restore=True)
            journal = self.store.root / 'journals' / (workspace + '.json')
            before = journal.read_bytes()
            with patch('stallionfs._native_recovery.recover_move', side_effect=AssertionError('preview reconciled move')):
                preview = self.store.purge('trash', workspace)
            self.assertEqual(preview['pending'], 'native-move'); self.assertEqual(journal.read_bytes(), before)
            with self.assertRaisesRegex(StallionError, 'not protected trash'):
                self.store.purge('trash', workspace, yes=True)
            self.assertTrue((self.store.root / 'workspaces' / workspace / 'image.sfs').exists())

    def test_native_purge_manifest_bounds_and_unexpected_entries_refuse_before_unlink(self):
        from stallionfs import _native_purge
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            workspace, path = self.native_purge_fixture(seed, now)
            for kind in ('extra', 'volume', 'symlink', 'hardlink', 'public-mode', 'helper-record', 'entries', 'bytes'):
                with self.subTest(kind=kind):
                    saved = None
                    if kind == 'extra': (path / 'extra').write_bytes(b'retain')
                    if kind == 'volume': (path / 'volume/file').write_bytes(b'retain')
                    if kind == 'symlink': (path / 'extra').symlink_to(self.source)
                    if kind == 'hardlink': os.link(path / 'image.sfs', self.base / 'backing-alias')
                    if kind == 'public-mode': (path / 'meta.json').chmod(0o644)
                    if kind == 'helper-record':
                        archive = next((path / 'native-operations').glob('*/record.json'))
                        saved = archive.read_bytes(); value = json.loads(saved); value['child_pending'] = True
                        archive.write_text(json.dumps(value))
                    bound = 'MAX_ENTRIES' if kind == 'entries' else 'MAX_INTENT_BYTES'
                    with patch.object(_native_purge, bound, 1 if kind in ('entries', 'bytes') else getattr(_native_purge, bound)):
                        with self.assertRaises(StallionError): self.store.purge('trash', workspace, yes=True)
                    self.assertTrue((path / 'image.sfs').exists())
                    self.assertFalse((self.store.root / 'journals' / (workspace + '.json')).exists())
                    if kind in ('extra', 'symlink'): (path / 'extra').unlink()
                    if kind == 'volume': (path / 'volume/file').unlink()
                    if kind == 'hardlink': (self.base / 'backing-alias').unlink()
                    if kind == 'public-mode': (path / 'meta.json').chmod(0o600)
                    if saved is not None: archive.write_bytes(saved)
            self.store.purge('trash', workspace, yes=True)

    def test_native_purge_lease_mount_core_reference_and_single_guard_exclusion(self):
        from stallionfs import _native, _image, core
        from stallionfs.core import read_json, write_json, lock
        seed = self.prepare()
        with self.native_controller_fixture() as mounted, self.native_wall_clock() as now:
            workspace, path = self.native_purge_fixture(seed, now)
            target = _native.installed_target(self.store, path, read_json(path / 'meta.json'))
            with self.store._lease(workspace):
                with self.assertRaises(StallionError): self.store.purge('trash', workspace, yes=True)
            mounted['rows'][str(path / 'volume/nested')] = {'path': str(path / 'volume/nested')}
            with self.assertRaises(StallionError): self.store.purge('trash', workspace, yes=True)
            mounted['rows'].clear()
            def busy(token):
                with self.assertRaises(OSError): self.store.purge('trash', workspace, yes=True)
            _image.with_backing_guard(target, busy)
            journal = self.store.root / 'journals' / (workspace + '.json')
            record = read_json(journal)
            self.assertFalse(record['data_absent'])
            # A conflicting published external reference is rejected even after preparation.
            registration = self.store.root / 'workspaces' / ('e' * 32); registration.mkdir(mode=0o700)
            write_json(registration / 'meta.json', {'id': registration.name, 'backend': 'native-image',
                'ownership': 'external-reference', 'native_image': target})
            with self.assertRaises(StallionError): self.store.purge('trash', workspace, yes=True)
            (registration / 'meta.json').unlink(); registration.rmdir()
            unlink = os.unlink; admissions = []
            guard = _native.guarded
            def guarded(target, callback=None, **kwargs):
                admissions.append(target)
                return guard(target, callback, **kwargs)
            def deleting(name, *args, **kwargs):
                if name == 'image.sfs':
                    self.assertEqual(len(admissions), 1)
                    moved_target = dict(target, directory=str(self.store.root / 'staging' / record['container'] / 'owned'))
                    self.assertEqual(_image.snapshot(moved_target, 'competing')['error_code'], errno.EBUSY)
                    with self.assertRaises(BlockingIOError):
                        with lock(self.store.root / '.lock', blocking=False): pass
                return unlink(name, *args, **kwargs)
            with patch('stallionfs._native.guarded', side_effect=guarded), \
                 patch('stallionfs._native_purge.os.unlink', side_effect=deleting):
                result = self.store.purge('trash', workspace, yes=True)
            self.assertTrue(result['cleanup_complete']); self.assertEqual(len(admissions), 1)

    def test_native_purge_journal_stage_faults_resume_only_authorized_work(self):
        from stallionfs import _native, _native_purge
        from stallionfs.core import read_json, native_failure_details
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            for stage in _native_purge.STAGES:
                for after in (False, True):
                    with self.subTest(stage=stage, after=after):
                        workspace, path = self.native_purge_fixture(seed, now)
                        primary = OSError(errno.ENOSPC, 'stage publication')
                        persist = _native._persist; fired = []
                        def saving(target, record):
                            match = record.get('workspace') == workspace and record.get('stage') == stage and not fired
                            if match and not after: fired.append(True); raise primary
                            result = persist(target, record)
                            if match and after: fired.append(True); raise primary
                            return result
                        with patch('stallionfs._native._persist', side_effect=saving):
                            with self.assertRaises(OSError) as caught: self.store.purge('trash', workspace, yes=True)
                        self.assertIs(caught.exception, primary); self.assertEqual(fired, [True])
                        held = native_failure_details(primary)
                        self.assertEqual(held['workspace'], workspace)
                        journal = self.store.root / 'journals' / (workspace + '.json')
                        saved = read_json(journal) if journal.exists() else read_json(self.store._state(workspace))
                        tombstone = self.store.root / 'staging' / saved['container']
                        data_absent = not (path / 'image.sfs').exists() and not (tombstone / 'owned/image.sfs').exists()
                        guard = _native.guarded
                        with patch('stallionfs._native.guarded', side_effect=AssertionError('absent image reopened') if data_absent else guard):
                            result = self.store.purge('trash', workspace, yes=True)
                        self.assertTrue(result['cleanup_complete']); self.assertFalse(path.exists()); self.assertFalse(tombstone.exists())
                        self.assertEqual(read_json(self.store._state(workspace))['first_error']['type'], 'OSError')

    def test_native_purge_unlink_close_and_resource_sync_failures_keep_data_loss_facts(self):
        from stallionfs import _native, _native_purge
        from stallionfs.core import read_json, native_failure_details
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            for phase in ('unlink-response', 'resource-sync', 'close', 'parent-close', 'lost-receipt', 'callback-and-close', 'cancel'):
                with self.subTest(phase=phase):
                    workspace, path = self.native_purge_fixture(seed, now)
                    object_inode = path.stat().st_ino
                    primary = KeyboardInterrupt('after unlink') if phase == 'cancel' else MemoryError('lost guard receipt') if phase == 'lost-receipt' else OSError(errno.EIO, phase)
                    unlink, fsync, guard = os.unlink, os.fsync, _native.guarded
                    removed = []; fired = []
                    def deleting(name, *args, **kwargs):
                        result = unlink(name, *args, **kwargs)
                        if name == 'image.sfs':
                            removed.append(True)
                            if phase in ('unlink-response', 'callback-and-close', 'cancel'):
                                fired.append(True); raise primary
                        return result
                    def syncing(fd):
                        if phase == 'resource-sync' and removed and os.fstat(fd).st_ino == object_inode and not fired:
                            fired.append(True); raise primary
                        return fsync(fd)
                    def guarded(target, callback=None, **kwargs):
                        try: receipt = guard(target, callback, **kwargs)
                        except BaseException as error:
                            if phase == 'callback-and-close': error.native_current_guard = {'consumed': True, 'status': 8}
                            raise
                        if phase in ('close', 'parent-close', 'lost-receipt'):
                            fired.append(True)
                            if phase != 'lost-receipt': primary.native_current_guard = dict(receipt, status=8, parent_close_errno=errno.EIO)
                            raise primary
                        return receipt
                    with patch('stallionfs._native_purge.os.unlink', side_effect=deleting), \
                         patch('stallionfs._native_purge.os.fsync', side_effect=syncing), \
                         patch('stallionfs._native.guarded', side_effect=guarded):
                        with self.assertRaises(type(primary)) as caught: self.store.purge('trash', workspace, yes=True)
                    self.assertIs(caught.exception, primary); self.assertEqual(removed, [True]); self.assertEqual(fired, [True])
                    held = native_failure_details(primary); self.assertTrue(held['data_absent'])
                    tombstone = self.store.root / 'staging' / held['container']
                    self.assertTrue((tombstone / 'owned/meta.json').exists())
                    with patch('stallionfs._native.guarded', side_effect=AssertionError('historical close demanded')):
                        result = self.store.purge('trash', workspace, yes=True)
                    self.assertTrue(result['cleanup_complete'])
                    receipt = read_json(self.store._state(workspace))
                    self.assertEqual(receipt['first_error']['type'], type(primary).__name__)
                    self.assertNotEqual(receipt['guard_outcome'], 'consumed')

    def test_native_purge_partial_metadata_replacement_is_never_adopted(self):
        from stallionfs import _native
        from stallionfs.core import read_json
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            workspace, path = self.native_purge_fixture(seed, now)
            persist = _native._persist; replacement = []; original = self.base / 'original-proof'
            def saving(target, record):
                result = persist(target, record)
                if record.get('stage') == 'metadata-removal-authorized' and not replacement:
                    proof = self.store.root / 'staging' / record['container'] / 'owned/meta.json'
                    data = proof.read_bytes(); proof.rename(original); proof.write_bytes(data); proof.chmod(0o600)
                    replacement.append(proof)
                return result
            with patch('stallionfs._native._persist', side_effect=saving):
                with self.assertRaises(StallionError): self.store.purge('trash', workspace, yes=True)
            proof = replacement[0]; ident = proof.stat().st_ino
            with self.assertRaises(StallionError): self.store.purge('trash', workspace, yes=True)
            self.assertEqual(proof.stat().st_ino, ident); self.assertTrue(original.exists())
            proof.unlink(); original.rename(proof)
            with patch('stallionfs._native.guarded', side_effect=AssertionError('missing image reopened')):
                self.assertTrue(self.store.purge('trash', workspace, yes=True)['cleanup_complete'])

    def test_native_purge_syscall_response_losses_and_fences_resume_exact_names(self):
        from stallionfs import _native
        from stallionfs.core import read_json
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            for phase in ('marker', 'rename', 'metadata-unlink', 'resource-rmdir', 'marker-unlink', 'container-rmdir', 'protection-unlink', 'journal-unlink'):
                for after in (False, True):
                    with self.subTest(phase=phase, after=after):
                        workspace, path = self.native_purge_fixture(seed, now)
                        primary = OSError(errno.EIO, phase + ' response lost')
                        write, rename, unlink, rmdir = __import__('stallionfs.core', fromlist=['write_json']).write_json, os.rename, os.unlink, os.rmdir
                        fired = []; renames = []
                        def writing(target, record):
                            if not after and phase == 'marker' and Path(target).name == 'native-purge.json' and not fired:
                                fired.append(True); raise primary
                            result = write(target, record)
                            if phase == 'marker' and Path(target).name == 'native-purge.json' and not fired:
                                fired.append(True); raise primary
                            return result
                        def renaming(source, destination, *args, **kwargs):
                            if not after and phase == 'rename' and source == workspace and destination == 'owned' and not fired:
                                fired.append(True); raise primary
                            result = rename(source, destination, *args, **kwargs)
                            if source == workspace and destination == 'owned':
                                renames.append(True)
                                if phase == 'rename' and not fired: fired.append(True); raise primary
                            return result
                        def deleting(name, *args, **kwargs):
                            parent = os.fstat(kwargs['dir_fd']).st_ino if 'dir_fd' in kwargs else None
                            match = ((phase == 'metadata-unlink' and name == 'meta.json')
                                or (phase == 'marker-unlink' and name == 'native-purge.json')
                                or (phase == 'protection-unlink' and name == workspace + '.json' and parent == (self.store.root / 'protected').stat().st_ino)
                                or (phase == 'journal-unlink' and name == workspace + '.json' and parent == (self.store.root / 'journals').stat().st_ino))
                            if match and not after and not fired: fired.append(True); raise primary
                            result = unlink(name, *args, **kwargs)
                            if match and not fired: fired.append(True); raise primary
                            return result
                        def removing(name, *args, **kwargs):
                            match = ((phase == 'resource-rmdir' and name == 'owned') or
                                (phase == 'container-rmdir' and str(name).startswith('native-purge-')))
                            if match and not after and not fired: fired.append(True); raise primary
                            result = rmdir(name, *args, **kwargs)
                            if not fired and ((phase == 'resource-rmdir' and name == 'owned') or
                                    (phase == 'container-rmdir' and str(name).startswith('native-purge-'))):
                                fired.append(True); raise primary
                            return result
                        with patch('stallionfs.core.write_json', side_effect=writing), \
                             patch('stallionfs._native_purge.os.rename', side_effect=renaming), \
                             patch('stallionfs._native_purge.os.unlink', side_effect=deleting), \
                             patch('stallionfs._native_purge.os.rmdir', side_effect=removing):
                            with self.assertRaises(OSError) as caught: self.store.purge('trash', workspace, yes=True)
                        self.assertIs(caught.exception, primary); self.assertEqual(fired, [True])
                        journal = self.store.root / 'journals' / (workspace + '.json')
                        record = read_json(journal) if journal.exists() else read_json(self.store._state(workspace))
                        tombstone = self.store.root / 'staging' / record['container']
                        before = {str(p): p.read_bytes() for p in self.store.root.rglob('*.json')}
                        self.store.purge('trash', workspace)
                        self.assertEqual({str(p): p.read_bytes() for p in self.store.root.rglob('*.json')}, before)
                        with patch('stallionfs._native_purge.os.rename', side_effect=renaming):
                            self.assertTrue(self.store.purge('trash', workspace, yes=True)['cleanup_complete'])
                        self.assertEqual(renames, [True]); self.assertFalse(tombstone.exists())

    def test_native_purge_completion_receipt_rejects_reused_names_and_protection(self):
        from stallionfs.core import read_json, write_json
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            workspace, path = self.native_purge_fixture(seed, now)
            self.store.purge('trash', workspace, yes=True)
            receipt = read_json(self.store._state(workspace))
            for replacement in (self.store.root / 'trash' / workspace, self.store.root / 'workspaces' / workspace,
                                self.store.root / 'staging' / receipt['container']):
                replacement.mkdir(mode=0o700); marker = replacement / 'retain'; marker.write_bytes(b'untouched')
                with self.assertRaises(StallionError): self.store.purge('trash', workspace, yes=True)
                self.assertEqual(marker.read_bytes(), b'untouched'); marker.unlink(); replacement.rmdir()
            protected = self.store.root / 'protected' / (workspace + '.json')
            write_json(protected, {'id': workspace, 'replacement': True})
            before = protected.read_bytes()
            with self.assertRaises(StallionError): self.store.purge('trash', workspace, yes=True)
            self.assertEqual(protected.read_bytes(), before)

    def test_native_purge_marker_journal_and_reserved_names_independently_hold_staging(self):
        from stallionfs.core import native_retention_reason, write_json
        for variant in ('marker', 'journal', 'malformed-reserved'):
            name = 'native-purge-' + 'a' * 32 + '-' + 'b' * 32 if variant == 'malformed-reserved' else 'build-retained-' + variant
            container = self.store.root / 'staging' / name
            container.mkdir(mode=0o700)
            if variant == 'marker': write_json(container / 'native-purge.json', {'operation': 'native-purge-marker'})
            elif variant == 'journal': write_json(self.store.root / 'journals' / ('a' * 32 + '.json'), {'operation': 'native-purge', 'container': container.name})
            else: (container / 'native-purge.json').write_text('malformed')
            if variant != 'journal': self.assertIsNotNone(native_retention_reason(container))
            with patch('stallionfs.core.tempfile.mkdtemp', return_value=str(container)):
                with self.assertRaises(StallionError):
                    with self.store.staging(): pass
            self.assertTrue(container.exists())
            for entry in container.iterdir(): entry.unlink()
            container.rmdir()
            journal = self.store.root / 'journals' / ('a' * 32 + '.json')
            if journal.exists(): journal.unlink()

    def test_native_purge_completed_receipt_survives_outer_close(self):
        from stallionfs import core
        from stallionfs.core import native_failure_details
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            for boundary in ('.lock', 'retention', 'workspace'):
                workspace, path = self.native_purge_fixture(seed, now)
                primary = OSError(errno.EIO, boundary + ' close')
                lock = core.lock
                @contextmanager
                def closing(target, *args, **kwargs):
                    with lock(target, *args, **kwargs): yield
                    if Path(target).name == ('workspace-' + workspace if boundary == 'workspace' else boundary): raise primary
                with patch('stallionfs.core.lock', side_effect=closing):
                    with self.assertRaises(OSError) as caught: self.store.purge('trash', workspace, yes=True)
                self.assertIs(caught.exception, primary)
                self.assertTrue(native_failure_details(primary)['cleanup_complete'])
                self.assertFalse(path.exists())
                self.assertTrue(self.store.purge('trash', workspace, yes=True)['already_purged'])

    def test_native_purge_parent_fsync_failures_hold_and_retry_recorded_directories(self):
        from stallionfs import _native
        from stallionfs.core import read_json
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            for phase in ('relocation-source', 'relocation-container', 'metadata-parent', 'resource-parent', 'staging-parent', 'protection-parent', 'journal-parent'):
                with self.subTest(phase=phase):
                    workspace, path = self.native_purge_fixture(seed, now)
                    object_inode = path.stat().st_ino
                    fsync = os.fsync; fired = []
                    journal = self.store.root / 'journals' / (workspace + '.json')
                    protection = self.store.root / 'protected' / (workspace + '.json')
                    primary = OSError(errno.EIO, phase)
                    def syncing(fd):
                        info = os.fstat(fd)
                        if not __import__('stat').S_ISDIR(info.st_mode): return fsync(fd)
                        record = read_json(journal) if journal.exists() else read_json(self.store._state(workspace))
                        stage = record.get('stage')
                        container = self.store.root / 'staging' / record.get('container', 'absent')
                        owned = container / 'owned'
                        match = ((phase == 'relocation-source' and stage == 'relocation-authorized' and owned.exists() and info.st_ino == path.parent.stat().st_ino)
                            or (phase == 'relocation-container' and stage == 'relocation-authorized' and owned.exists() and info.st_ino == container.stat().st_ino)
                            or (phase == 'metadata-parent' and stage == 'metadata-removal-authorized' and info.st_ino == object_inode)
                            or (phase == 'resource-parent' and stage == 'resource-removal-authorized' and container.exists() and not owned.exists() and info.st_ino == container.stat().st_ino)
                            or (phase == 'staging-parent' and stage == 'container-removal-authorized' and not container.exists() and info.st_ino == (self.store.root / 'staging').stat().st_ino)
                            or (phase == 'protection-parent' and not protection.exists() and record.get('data_absent') and info.st_ino == protection.parent.stat().st_ino)
                            or (phase == 'journal-parent' and not journal.exists() and record.get('operation') == 'native-purge-complete' and info.st_ino == journal.parent.stat().st_ino))
                        if match and not fired: fired.append(True); raise primary
                        return fsync(fd)
                    with patch('stallionfs._native_purge.os.fsync', side_effect=syncing):
                        with self.assertRaises(OSError) as caught: self.store.purge('trash', workspace, yes=True)
                    self.assertIs(caught.exception, primary); self.assertEqual(fired, [True])
                    self.assertEqual(caught.exception.errno, errno.EIO)
                    record = read_json(journal) if journal.exists() else read_json(self.store._state(workspace))
                    if phase not in ('protection-parent', 'journal-parent'): self.assertTrue(protection.exists())
                    self.assertTrue(self.store.purge('trash', workspace, yes=True)['cleanup_complete'])
                    self.assertEqual(read_json(self.store._state(workspace))['last_error'],
                        {'type': 'OSError', 'message': str(primary)})

    def test_native_purge_bound_parent_resource_and_manifest_substitutions_hold(self):
        from stallionfs import _native
        from stallionfs.core import read_json
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            for changed in ('trash-parent', 'staging-parent', 'container', 'resource', 'image', 'proof'):
                with self.subTest(changed=changed):
                    workspace, path = self.native_purge_fixture(seed, now)
                    persist = _native._persist; fired = []
                    def pause(target, record):
                        result = persist(target, record)
                        if record.get('stage') == 'container-ready' and not fired:
                            fired.append(True); raise OSError(errno.EIO, 'pause before admission')
                        return result
                    with patch('stallionfs._native._persist', side_effect=pause):
                        with self.assertRaises(OSError): self.store.purge('trash', workspace, yes=True)
                    journal = self.store.root / 'journals' / (workspace + '.json'); record = read_json(journal)
                    container = self.store.root / 'staging' / record['container']
                    target = {'trash-parent': path.parent, 'staging-parent': container.parent, 'container': container,
                              'resource': path, 'image': path / 'image.sfs', 'proof': path / 'meta.json'}[changed]
                    saved = self.base / ('saved-' + changed + '-' + workspace)
                    directory = target.is_dir(); data = target.read_bytes() if changed == 'proof' else b'replacement untouched'
                    target.rename(saved)
                    if directory:
                        target.mkdir(mode=0o700); marker = target / 'retain'; marker.write_bytes(data)
                        if changed == 'resource':
                            (target / 'meta.json').write_bytes((saved / 'meta.json').read_bytes()); (target / 'meta.json').chmod(0o600)
                    else: target.write_bytes(data); target.chmod(0o600); marker = target
                    identity = target.stat().st_ino
                    with self.assertRaises((StallionError, FileNotFoundError)):
                        self.store.purge('trash', workspace, yes=True)
                    self.assertEqual(target.stat().st_ino, identity); self.assertEqual(marker.read_bytes(), data)
                    if directory:
                        for child in target.iterdir(): child.unlink()
                        target.rmdir()
                    else: target.unlink()
                    saved.rename(target)
                    self.assertTrue(self.store.purge('trash', workspace, yes=True)['cleanup_complete'])

    def test_native_purge_blocks_concurrent_registrar_until_image_is_absent(self):
        from stallionfs.core import read_json, lock
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            workspace, path = self.native_purge_fixture(seed, now)
            started = threading.Event(); attempted = []
            unlink = os.unlink
            def registering(backing):
                with self.assertRaises(BlockingIOError):
                    with lock(self.store.root / '.lock', shared=False, blocking=False):
                        self.fail('purge released root publication lock before unlink')
                started.set()
                return self.store.register_native_image(backing)
            with ThreadPoolExecutor(max_workers=1) as pool:
                def deleting(name, *args, **kwargs):
                    if name == 'image.sfs':
                        record = read_json(self.store.root / 'journals' / (workspace + '.json'))
                        backing = self.store.root / 'staging' / record['container'] / 'owned/image.sfs'
                        attempted.append(pool.submit(registering, backing))
                        self.assertTrue(started.wait(5)); self.assertFalse(attempted[0].done())
                    return unlink(name, *args, **kwargs)
                with patch('stallionfs._native_purge.os.unlink', side_effect=deleting):
                    self.store.purge('trash', workspace, yes=True)
                with self.assertRaises((StallionError, FileNotFoundError)): attempted[0].result(timeout=10)
            self.assertFalse(self.store.list())

    def test_native_purge_absence_without_authorization_and_conflicting_completion_hold(self):
        from stallionfs import _native
        from stallionfs.core import read_json
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            workspace, path = self.native_purge_fixture(seed, now)
            persist = _native._persist; fired = []
            def pause(target, record):
                result = persist(target, record)
                if record.get('stage') == 'relocated' and not fired:
                    fired.append(True); raise OSError(errno.EIO, 'pause before unlink authorization')
                return result
            with patch('stallionfs._native._persist', side_effect=pause):
                with self.assertRaises(OSError): self.store.purge('trash', workspace, yes=True)
            journal = self.store.root / 'journals' / (workspace + '.json'); record = read_json(journal)
            image = self.store.root / 'staging' / record['container'] / 'owned/image.sfs'
            held = self.base / 'held-image'; image.rename(held)
            with self.assertRaises(StallionError): self.store.purge('trash', workspace, yes=True)
            self.assertTrue(held.exists()); held.rename(image)
            self.store.purge('trash', workspace, yes=True)
            complete = read_json(self.store._state(workspace))
            # Retain a valid-shaped incompatible prior journal: completion cannot erase it.
            record['id'] = 'd' * 32; record['container'] = 'native-purge-' + workspace + '-' + record['id']
            _native._persist(journal, record)
            before = journal.read_bytes()
            with self.assertRaises(StallionError): self.store.purge('trash', workspace, yes=True)
            self.assertEqual(journal.read_bytes(), before)

    def test_native_purge_consumed_descriptor_close_error_keeps_completed_receipt(self):
        from stallionfs.core import native_failure_details, read_json
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            workspace, path = self.native_purge_fixture(seed, now)
            root_inode = self.store.root.stat().st_ino
            close = os.close; fired = []
            primary = OSError(errno.EIO, 'purge directory descriptor close')
            def closing(fd):
                info = os.fstat(fd)
                state = read_json(self.store._state(workspace))
                match = info.st_ino == root_inode and state.get('cleanup_complete') is True and not fired
                result = close(fd)
                if match: fired.append(True); raise primary
                return result
            with patch('stallionfs._native_purge.os.close', side_effect=closing):
                with self.assertRaises(OSError) as caught: self.store.purge('trash', workspace, yes=True)
            self.assertIs(caught.exception, primary); self.assertEqual(fired, [True])
            receipt = native_failure_details(primary)
            self.assertTrue(receipt['cleanup_complete']); self.assertTrue(receipt['data_absent'])
            self.assertEqual(receipt['descriptor_close_error'], 'OSError')
            self.assertTrue(self.store.purge('trash', workspace, yes=True)['already_purged'])

    @contextmanager
    def compound_controller_fixture(self):
        """Qualified fake namespace, with flat owned helper receipts for recovery."""
        from stallionfs import _native, _native_recovery
        with self.native_controller_fixture() as state:
            def qualify(operation, metadata):
                if operation.record['operation'] in _native_recovery.COMPOUND:
                    host = Path(metadata['native_host'])
                    commands = [('verify-package', _native.package_argv(host)),
                                ('discover', [str(host), '--discover-json'])]
                    for label, argv in commands:
                        operation.record['helpers'].append({'label': label, **operation.command_context,
                            'argv': argv, 'pid': 123, 'returncode': 0, 'reaped': True, 'child_pending': False,
                            'outcome': 'success', 'stdout': 'fixture-stdout', 'stderr': 'fixture-stderr'})
                        operation.persist()
                return 'stallionfs'
            with patch('stallionfs._native.qualify', side_effect=qualify):
                yield state

    def test_compound_native_snapshot_and_restore_keep_one_owner(self):
        from stallionfs import core, _native_recovery
        seed = self.prepare()
        with self.compound_controller_fixture() as state:
            created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = created['id']; path = Path(created['path']).parent.parent
            journal = self.store.root / 'journals' / (workspace + '.json')
            owners = []
            original = core.native_operation
            def mutate(target, action, *names):
                record = core.read_json(journal)
                self.assertEqual(record['phase'], 'bridge-attempted')
                self.assertTrue(record['bridge_attempted'])
                self.assertFalse(state['rows'])
                owners.append(record['id'])
                with self.assertRaises(StallionError):
                    with self.store._lease(workspace): pass
                return original(target, action, *names)
            with patch('stallionfs.core.native_operation', side_effect=mutate):
                saved = self.store.snapshot(workspace, name='mounted-base', quiescent=True)
                restored = self.store.rollback(workspace, 'mounted-base', quiescent=True)
            for result in (saved, restored):
                record = result['native_operation']
                _native_recovery.validate_compound(workspace, record)
                self.assertIn(record['id'], owners)
                self.assertEqual(record['phase'], 'final-verified')
                self.assertEqual(record['outcome'], 'complete')
                self.assertEqual([item['label'] for item in record['helpers']],
                    ['verify-package', 'discover', 'unmount', 'verify-package', 'discover', 'mount'])
                self.assertTrue(record['bridge_returned'])
                self.assertTrue(record['native_image_result']['committed'])
                self.assertEqual(core.read_json(path / 'native-operations' / record['id'] / 'record.json')['outcome'], 'complete')
            self.assertFalse(journal.exists())
            self.assertTrue(state['rows'])
            self.assertTrue(restored['recovery'].startswith('recovery-'))
            self.assertTrue(all('-f' not in argv for argv in state['commands']))
            count = len(state['commands'])
            self.store.unmount(workspace)
            count += 1
            closed = self.store.snapshot(workspace, name='already-closed', quiescent=True)
            self.assertEqual(closed['mount'], 'kept-unmounted')
            self.assertEqual(len(state['commands']), count)

    def test_compound_native_binding_and_opt_in_refuse_before_unmount(self):
        import copy
        from stallionfs import core
        seed = self.prepare()
        with self.compound_controller_fixture() as state:
            created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = created['id']; path = Path(created['path']).parent.parent
            mount_path = path / 'native-mount.json'
            accepted = core.read_json(mount_path)
            count = len(state['commands'])
            with patch('stallionfs.core.native_operation') as bridge:
                with self.assertRaises(StallionError): self.store.snapshot(workspace, name='no-opt-in')
                with self.store._lease(workspace):
                    with self.assertRaises(StallionError): self.store.snapshot(workspace, name='busy', quiescent=True)
                for key in ('path', 'filesystem', 'owner', 'flags', 'fsid'):
                    with self.subTest(field=key):
                        changed = copy.deepcopy(accepted)
                        changed['observation'][key] = 'mismatch'
                        from stallionfs import _native
                        _native._persist(mount_path, changed)
                        with self.assertRaises(StallionError): self.store.snapshot(workspace, name='bound', quiescent=True)
                for key in ('target', 'profile', 'state'):
                    changed = copy.deepcopy(accepted); changed[key] = 'mismatch'
                    _native._persist(mount_path, changed)
                    with self.assertRaises(StallionError): self.store.snapshot(workspace, name='bound', quiescent=True)
                mount_path.unlink()
                with self.assertRaises(StallionError): self.store.snapshot(workspace, name='missing', quiescent=True)
                _native._persist(mount_path, accepted)
                nested = str(path / 'volume/nested')
                state['rows'][nested] = {'path': nested}
                with self.assertRaises(StallionError): self.store.snapshot(workspace, name='nested', quiescent=True)
                state['rows'].pop(nested)
                state['rows'][str(path / 'volume')]['filesystem'] = 'foreign'
                with self.assertRaises(StallionError): self.store.snapshot(workspace, name='foreign', quiescent=True)
                bridge.assert_not_called()
            self.assertEqual(len(state['commands']), count)
            self.assertFalse((self.store.root / 'journals' / (workspace + '.json')).exists())

    def test_compound_native_unknown_bridge_never_repaired_by_catalog(self):
        from stallionfs import core, _native
        seed = self.prepare()
        with self.compound_controller_fixture() as state:
            created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = created['id']; path = Path(created['path']).parent.parent
            original = core.native_operation
            def lost(target, action, *names):
                result = original(target, action, *names)
                error = OSError(errno.EIO, 'lost original response')
                error.native_image_result = result
                raise error
            with patch('stallionfs.core.native_operation', side_effect=lost):
                with self.assertRaises(OSError): self.store.snapshot(workspace, name='once', quiescent=True)
            journal = self.store.root / 'journals' / (workspace + '.json')
            retained = core.read_json(journal)
            operation = retained['id']
            self.assertFalse(retained['bridge_returned'])
            self.assertTrue(retained['native_image_result']['committed'])
            target = _native.installed_target(self.store, path, core.read_json(path / 'meta.json'))
            self.assertIn('once', [item['name'] for item in original(target, 'snapshots')['snapshots']])
            before = journal.read_bytes()
            for command in (lambda: self.store.mount(workspace), lambda: self.store.unmount(workspace),
                            lambda: self.store.snapshots(workspace), lambda: self.store.snapshot(workspace, name='other'),
                            lambda: self.store.rollback(workspace, 'once'), lambda: self.store.close(workspace, quiescent=True),
                            lambda: self.store.enroll(workspace), lambda: self.store.move(workspace),
                            lambda: self.store.run(workspace, ['/usr/bin/true'])):
                with self.assertRaises(StallionError): command()
                self.assertEqual(journal.read_bytes(), before)
            status = self.store.snapshots(workspace, operation_id=operation)
            self.assertIn('Do not repeat', status['message'])
            self.assertIsNone(status['next_action'])
            with patch('stallionfs.core.native_operation') as bridge:
                with self.assertRaises(StallionError):
                    self.store.snapshot(workspace, name='once', quiescent=True, continue_operation=operation)
                bridge.assert_not_called()
            self.assertFalse(state['rows'])

    def test_compound_native_prepared_unmount_loss_and_withdrawal(self):
        from stallionfs import core, _native_recovery
        seed = self.prepare()
        with self.compound_controller_fixture() as state:
            created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = created['id']; path = Path(created['path']).parent.parent
            with patch('stallionfs._native_recovery._unmount_compound', side_effect=OSError(errno.EIO, 'before unmount')):
                with self.assertRaises(OSError): self.store.snapshot(workspace, name='prepared', quiescent=True)
            journal = self.store.root / 'journals' / (workspace + '.json')
            op = core.read_json(journal)['id']
            self.assertEqual(self.store.snapshots(workspace, operation_id=op)['phase'], 'prepared')
            state['unmount_status'] = 1
            with patch('stallionfs.core.native_operation') as bridge:
                with self.assertRaises(StallionError): self.store.snapshot(workspace, name='prepared', quiescent=True, continue_operation=op)
                with self.assertRaises(StallionError): self.store.snapshot(workspace, name='prepared', quiescent=True, continue_operation=op)
                bridge.assert_not_called()
            state['unmount_status'] = 0
            withdrawn = self.store.continue_unmount(workspace, op)
            self.assertFalse(withdrawn['mutation_started'])
            self.assertEqual(withdrawn['native_operation']['phase'], 'offline')
            result = self.store.snapshot(workspace, name='prepared', quiescent=True, continue_operation=op)
            self.assertEqual(result['native_operation']['id'], op)
            # Lose the owned unmount response after terminal bookkeeping.
            state['interrupt'] = True
            with self.assertRaises(subprocess.TimeoutExpired): self.store.snapshot(workspace, name='lost-unmount', quiescent=True)
            op = core.read_json(journal)['id']
            self.assertEqual(core.read_json(journal)['phase'], 'unmount-attempted')
            count = sum(argv[0] == '/sbin/umount' for argv in state['commands'])
            state['interrupt'] = False
            result = self.store.snapshot(workspace, name='lost-unmount', quiescent=True, continue_operation=op)
            self.assertEqual(sum(argv[0] == '/sbin/umount' for argv in state['commands']), count)
            _native_recovery.validate_compound(workspace, result['native_operation'])

    def test_compound_native_commit_continuation_anchor_and_intent_checks(self):
        from stallionfs import core, _native, _native_recovery
        seed = self.prepare()
        with self.compound_controller_fixture() as state:
            created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = created['id']; path = Path(created['path']).parent.parent
            with patch('stallionfs._native_recovery._remount_compound', side_effect=OSError(errno.EIO, 'before remount')):
                with self.assertRaises(OSError): self.store.snapshot(workspace, name='committed', quiescent=True)
            journal = self.store.root / 'journals' / (workspace + '.json')
            record = core.read_json(journal); op = record['id']
            self.assertEqual(record['phase'], 'committed')
            before_commands = len(state['commands'])
            with patch('stallionfs.core.native_operation') as bridge:
                for command in (lambda: self.store.snapshot(workspace, name='different', quiescent=True, continue_operation=op),
                                lambda: self.store.rollback(workspace, 'committed', quiescent=True, continue_operation=op),
                                lambda: self.store.snapshot(workspace, name='committed', continue_operation=op),
                                lambda: self.store.snapshot(workspace, quiescent=True, continue_operation=op)):
                    with self.assertRaises(StallionError): command()
                original_guard = _native.guarded
                for field in ('generation', 'root_digest', 'committed_end'):
                    def drift(target, *args, **kwargs):
                        self.assertEqual(kwargs['expected_anchor'], record['committed_anchor'])
                        observed = original_guard(target)
                        observed[field] = ('f' * 64 if field == 'root_digest' else observed[field] + 1)
                        return observed
                    with patch('stallionfs._native.guarded', side_effect=drift):
                        with self.assertRaisesRegex(StallionError, 'current image has changed'):
                            self.store.snapshot(workspace, name='committed', quiescent=True, continue_operation=op)
                self.assertEqual(len(state['commands']), before_commands)
                result = self.store.snapshot(workspace, name='committed', quiescent=True, continue_operation=op)
                bridge.assert_not_called()
            self.assertEqual(result['native_operation']['committed_anchor'], record['committed_anchor'])
            self.assertEqual(result['mount'], 'verified')
            _native_recovery.validate_compound(workspace, result['native_operation'])

    def test_compound_native_lost_mount_response_requires_durable_evidence(self):
        from stallionfs import core, _native, _native_recovery
        seed = self.prepare()
        with self.compound_controller_fixture() as state:
            created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = created['id']; path = Path(created['path']).parent.parent
            original = _native.execute_owned
            def lose_mount(argv, *args, **kwargs):
                result = original(argv, *args, **kwargs)
                if argv[0] == '/sbin/mount': raise OSError(errno.EIO, 'mount response lost')
                return result
            with patch('stallionfs._native.execute_owned', side_effect=lose_mount):
                with self.assertRaises(OSError): self.store.snapshot(workspace, name='lost-mount', quiescent=True)
            journal = self.store.root / 'journals' / (workspace + '.json')
            op = core.read_json(journal)['id']
            count = len(state['commands'])
            with patch('stallionfs.core.native_operation') as bridge:
                with self.assertRaisesRegex(StallionError, 'Mount completion is unknown'):
                    self.store.snapshot(workspace, name='lost-mount', quiescent=True, continue_operation=op)
                self.assertEqual(len(state['commands']), count)
                # Represents separately arranged normal withdrawal; controller
                # never claims authority from the unbound present observation.
                state['rows'].clear()
                result = self.store.snapshot(workspace, name='lost-mount', quiescent=True, continue_operation=op)
                bridge.assert_not_called()
            self.assertEqual(len(result['native_operation']['remount_attempts']), 2)
            # Interrupt after same-operation observation/usability is durable.
            with patch('stallionfs._native_recovery._verify_final', side_effect=OSError(errno.EIO, 'finish interrupted')):
                with self.assertRaises(OSError): self.store.snapshot(workspace, name='observed', quiescent=True)
            record = core.read_json(journal); op = record['id']
            record['remount_attempts'][-1]['response'] = None
            _native._persist(journal, record)
            count = len(state['commands'])
            with patch('stallionfs.core.native_operation') as bridge:
                result = self.store.snapshot(workspace, name='observed', quiescent=True, continue_operation=op)
                bridge.assert_not_called()
            self.assertEqual(len(state['commands']), count)
            self.assertIsNone(result['native_operation']['remount_attempts'][-1]['response'])
            _native_recovery.validate_compound(workspace, result['native_operation'])

    def test_compound_native_busy_close_failure_and_unresolved_child_stop(self):
        from stallionfs import core, _native
        seed = self.prepare()
        with self.compound_controller_fixture() as state:
            created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = created['id']; path = Path(created['path']).parent.parent
            with patch('stallionfs._native.guarded', side_effect=OSError(errno.EBUSY, 'still held')), \
                 patch('stallionfs.core.native_operation') as bridge:
                with self.assertRaises(OSError): self.store.snapshot(workspace, name='busy-guard', quiescent=True)
                bridge.assert_not_called()
            journal = self.store.root / 'journals' / (workspace + '.json')
            record = core.read_json(journal); op = record['id']
            record['helpers'][-1].update(child_pending=True, reaped=False, returncode=None, outcome='running')
            record['child_pending'] = True
            _native._persist(journal, record)
            before = journal.read_bytes()
            with patch('os.kill') as kill, patch('os.waitpid') as waitpid, patch('stallionfs.core.native_operation') as bridge:
                with self.store._lease(workspace):
                    status = self.store.snapshots(workspace, operation_id=op)
                self.assertIn('unresolved process ownership', status['message'])
                self.assertNotIn('current_observation', status)
                with self.assertRaises(StallionError): self.store.snapshot(workspace, name='busy-guard', quiescent=True, continue_operation=op)
                kill.assert_not_called(); waitpid.assert_not_called(); bridge.assert_not_called()
            self.assertEqual(before, journal.read_bytes())
            # Restore the owned supervisor's terminal fixture evidence.
            record['helpers'][-1].update(child_pending=False, reaped=True, returncode=0, outcome='unknown')
            record['child_pending'] = False
            _native._persist(journal, record)
            original = core.native_operation
            def bad_close(target, action, *names):
                result = original(target, action, *names)
                result['ok'] = False; result['close_receipt']['status'] = 1
                return result
            with patch('stallionfs.core.native_operation', side_effect=bad_close):
                with self.assertRaises(StallionError): self.store.snapshot(workspace, name='busy-guard', quiescent=True, continue_operation=op)
            with patch('stallionfs.core.native_operation') as bridge:
                with self.assertRaises(StallionError): self.store.snapshot(workspace, name='busy-guard', quiescent=True, continue_operation=op)
                bridge.assert_not_called()
            self.assertFalse(state['rows'])

    def test_compound_native_finish_order_and_historical_completion(self):
        from stallionfs import core, _native
        seed = self.prepare()
        with self.compound_controller_fixture() as state:
            created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = created['id']; path = Path(created['path']).parent.parent
            journal = self.store.root / 'journals' / (workspace + '.json')
            unlink = Path.unlink
            interrupted = []
            def check_finish(candidate, *args, **kwargs):
                if candidate == journal:
                    record = core.read_json(journal)
                    archive = core.read_json(path / 'native-operations' / record['id'] / 'record.json')
                    self.assertEqual(record['outcome'], 'complete')
                    self.assertEqual(archive['outcome'], 'complete')
                    self.assertEqual(record['phase'], 'final-verified')
                    if not interrupted:
                        interrupted.append(record['id'])
                        raise OSError(errno.EIO, 'journal removal interrupted')
                return unlink(candidate, *args, **kwargs)
            with patch.object(Path, 'unlink', check_finish):
                with self.assertRaises(OSError): self.store.snapshot(workspace, name='finish', quiescent=True)
                op = interrupted[0]
                self.store.snapshot(workspace, name='finish', quiescent=True, continue_operation=op)
            self.assertFalse(journal.exists())
            count = len(state['commands'])
            state['rows'][str(path / 'volume')]['fsid'] = (71, 9000)
            with patch('stallionfs.core.native_operation') as bridge:
                historical = self.store.snapshot(workspace, name='finish', quiescent=True, continue_operation=op)
                bridge.assert_not_called()
            self.assertFalse(historical['current_status']['current_mount_matches_completion'])
            self.assertEqual(historical['native_operation']['outcome'], 'complete')
            self.assertEqual(len(state['commands']), count)

    def test_compound_native_bridge_dispositions_and_phase_marker_interruption(self):
        import copy
        from stallionfs import core, _native, _native_recovery
        seed = self.prepare()
        with self.compound_controller_fixture():
            created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = created['id']; path = Path(created['path']).parent.parent
            # Retain the affirmative returned receipt before its phase advance.
            original = _native.Operation.persist
            stopped = []
            def interrupt_phase(operation):
                if operation.record.get('phase') == 'bridge-attempted' and operation.record.get('bridge_returned') and not stopped:
                    stopped.append(operation.record['id'])
                    original(operation)
                    raise OSError(errno.EIO, 'after returned receipt, before phase advance')
                return original(operation)
            with patch.object(_native.Operation, 'persist', interrupt_phase):
                with self.assertRaises(OSError): self.store.snapshot(workspace, name='receipt', quiescent=True)
            journal = self.store.root / 'journals' / (workspace + '.json')
            record = core.read_json(journal)
            self.assertTrue(_native_recovery._confirmed_bridge(record))
            for key, value in (('ok', False), ('committed', False), ('commit_attempted', False),
                               ('outcome', 'unknown'), ('close_attempted', False), ('guard_close_errno', errno.EIO),
                               ('interrupted', True), ('deadline_expired', True), ('path_errno', errno.EIO)):
                malformed = copy.deepcopy(record); malformed['native_image_result'][key] = value
                self.assertFalse(_native_recovery._confirmed_bridge(malformed), key)
            for receipt in ('receipt', 'close_receipt'):
                for key, value in (('status', 1), ('poisoned', True), ('transaction_active', True),
                                   ('generation', 900000), ('root_digest', 'f' * 64), ('committed_end', 900000),
                                   ('uuid', 'f' * 32), ('inode', 900000)):
                    malformed = copy.deepcopy(record); malformed['native_image_result'][receipt][key] = value
                    self.assertFalse(_native_recovery._confirmed_bridge(malformed), (receipt, key))
            self.assertIn('committed', self.store.snapshots(workspace, operation_id=stopped[0])['message'])
            with patch('stallionfs.core.native_operation') as bridge:
                self.store.snapshot(workspace, name='receipt', quiescent=True, continue_operation=stopped[0])
                bridge.assert_not_called()

    def test_compound_native_qualification_and_identity_drift_stop(self):
        from stallionfs import core, _native, _native_recovery
        seed = self.prepare()
        with self.compound_controller_fixture() as state:
            created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = created['id']; path = Path(created['path']).parent.parent
            before = len(state['commands'])
            with patch('stallionfs._native.qualify', side_effect=StallionError('module changed')), \
                 patch('stallionfs.core.native_operation') as bridge:
                with self.assertRaises(StallionError): self.store.snapshot(workspace, name='qualification', quiescent=True)
                bridge.assert_not_called()
            self.assertEqual(len(state['commands']), before)
            journal = self.store.root / 'journals' / (workspace + '.json')
            record = core.read_json(journal); op = record['id']
            self.assertEqual(record['phase'], 'prepared')
            target = dict(record['target'], uuid='f' * 32)
            with patch('stallionfs._native_recovery.ready', return_value=target):
                with self.assertRaises(StallionError): self.store.snapshot(workspace, name='qualification', quiescent=True, continue_operation=op)
            metadata = core.read_json(path / 'meta.json')
            for key, value in (('controller_profile', 'private-sfsro27'), ('native_host', '/different/Contents/MacOS/StallionFS')):
                _native._persist(path / 'meta.json', {**metadata, key: value})
                with self.assertRaises(StallionError): self.store.snapshot(workspace, name='qualification', quiescent=True, continue_operation=op)
                _native._persist(path / 'meta.json', metadata)
            self.assertEqual(len(state['commands']), before)
            result = self.store.snapshot(workspace, name='qualification', quiescent=True, continue_operation=op)
            _native_recovery.validate_compound(workspace, result['native_operation'])

    def test_compound_native_failed_catalog_mutation_keeps_image_unmounted(self):
        from stallionfs import core
        seed = self.prepare()
        for action in ('duplicate', 'missing', 'full'):
            with self.subTest(action=action), self.compound_controller_fixture() as state:
                created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
                workspace = created['id']; path = Path(created['path']).parent.parent
                self.store.snapshot(workspace, name='existing', quiescent=True)
                if action == 'full':
                    self.store.unmount(workspace)
                    for index in range(31): self.store.snapshot(workspace, name='fill-' + str(index))
                    self.store.mount(workspace)
                    command = lambda **kwargs: self.store.snapshot(workspace, name='overflow', quiescent=True, **kwargs)
                elif action == 'duplicate':
                    command = lambda **kwargs: self.store.snapshot(workspace, name='existing', quiescent=True, **kwargs)
                else:
                    command = lambda **kwargs: self.store.rollback(workspace, 'missing', quiescent=True, **kwargs)
                with self.assertRaises(StallionError): command()
                journal = self.store.root / 'journals' / (workspace + '.json')
                retained = core.read_json(journal)
                self.assertEqual(retained['phase'], 'bridge-attempted')
                self.assertFalse(retained['bridge_returned'])
                self.assertFalse(retained['native_image_result']['committed'])
                self.assertFalse(state['rows'])
                with patch('stallionfs.core.native_operation') as bridge:
                    with self.assertRaises(StallionError): command(continue_operation=retained['id'])
                    bridge.assert_not_called()

    def test_compound_native_not_launched_remount_uses_actual_executor_receipt(self):
        import copy
        from stallionfs import core, _native
        seed = self.prepare()
        executor = _native.execute_owned
        with self.compound_controller_fixture() as state:
            created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = created['id']; path = Path(created['path']).parent.parent
            fake = _native.execute_owned
            def execute(argv, *args, **kwargs):
                if argv[0] == '/sbin/mount':
                    with patch('stallionfs._native.subprocess.Popen', side_effect=OSError(errno.EAGAIN, 'launch unavailable')):
                        return executor(argv, *args, **kwargs)
                return fake(argv, *args, **kwargs)
            original_bridge = core.native_operation
            with patch('stallionfs.core.native_operation', wraps=original_bridge) as bridge:
                with patch('stallionfs._native.execute_owned', side_effect=execute):
                    with self.assertRaises(OSError): self.store.snapshot(workspace, name='launch-once', quiescent=True)
                self.assertEqual(bridge.call_count, 1)
                journal = self.store.root / 'journals' / (workspace + '.json')
                record = core.read_json(journal); op = record['id']; helper = record['helpers'][-1]
                self.assertEqual(helper['outcome'], 'not-launched')
                self.assertIsNone(helper['pid']); self.assertIsNone(helper['returncode'])
                self.assertIs(helper['reaped'], False); self.assertIs(helper['child_pending'], False)
                self.assertEqual(record['error']['errno'], errno.EAGAIN)
                self.assertEqual(record['error']['native_os_result'], helper)
                self.assertEqual(record['error']['helper_index'], len(record['helpers']) - 1)
                status = self.store.snapshots(workspace, operation_id=op)
                self.assertEqual(status['disposition']['mount'], 'not-launched')
                self.assertIn('Remount was not launched', status['message'])
                first = json.dumps(record['error'], sort_keys=True)
                variants = []
                pending = copy.deepcopy(record); pending['child_pending'] = True
                pending['helpers'][-1].update(child_pending=True, outcome='launch-pending')
                variants.append(pending)
                unreaped = copy.deepcopy(record)
                unreaped['helpers'][-1].update(pid=123, reaped=False, outcome='unknown')
                variants.append(unreaped)
                malformed = copy.deepcopy(record); malformed['helpers'][-1].pop('stdout')
                variants.append(malformed)
                for invalid in variants:
                    _native._persist(journal, invalid)
                    before = journal.read_bytes()
                    with patch('os.kill') as kill, patch('os.waitpid') as waitpid:
                        with self.assertRaises(StallionError):
                            self.store.snapshot(workspace, name='launch-once', quiescent=True, continue_operation=op)
                        kill.assert_not_called(); waitpid.assert_not_called()
                    self.assertEqual(journal.read_bytes(), before)
                _native._persist(journal, record)
                with patch('stallionfs._native.guarded', wraps=_native.guarded) as guard:
                    completed = self.store.snapshot(workspace, name='launch-once', quiescent=True, continue_operation=op)
                    self.assertTrue(any(call.kwargs.get('expected_anchor') == record['committed_anchor'] for call in guard.call_args_list))
                self.assertEqual(bridge.call_count, 1)
                self.assertEqual(json.dumps(completed['native_operation']['error'], sort_keys=True), first)
                self.assertEqual(len(completed['native_operation']['remount_attempts']), 2)
                self.assertTrue(state['rows'])
                def refuse_unmount_launch(argv, *args, **kwargs):
                    if argv[0] == '/sbin/umount':
                        with patch('stallionfs._native.subprocess.Popen', side_effect=OSError(errno.EAGAIN, 'unmount launch unavailable')):
                            return executor(argv, *args, **kwargs)
                    return fake(argv, *args, **kwargs)
                with patch('stallionfs._native.execute_owned', side_effect=refuse_unmount_launch):
                    with self.assertRaises(OSError): self.store.snapshot(workspace, name='withdraw-once', quiescent=True)
                unmount_record = core.read_json(journal); unmount_op = unmount_record['id']
                self.assertEqual(unmount_record['helpers'][-1]['outcome'], 'not-launched')
                self.assertEqual(bridge.call_count, 1)
                with self.assertRaises(StallionError):
                    self.store.snapshot(workspace, name='withdraw-once', quiescent=True, continue_operation=unmount_op)
                withdrawn = self.store.continue_unmount(workspace, unmount_op)
                self.assertFalse(withdrawn['mutation_started'])
                self.assertEqual(bridge.call_count, 1)
                self.store.snapshot(workspace, name='withdraw-once', quiescent=True, continue_operation=unmount_op)
                self.assertEqual(bridge.call_count, 2)

    def test_compound_native_first_failure_and_receipts_survive_refused_retries(self):
        from stallionfs import core, _native
        seed = self.prepare()
        with self.compound_controller_fixture():
            created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = created['id']; path = Path(created['path']).parent.parent
            original = core.native_operation
            def response_loss(target, action, *names):
                error = OSError(errno.EIO, 'original bridge response lost')
                error.native_image_result = original(target, action, *names)
                raise error
            with patch('stallionfs.core.native_operation', side_effect=response_loss):
                with self.assertRaises(OSError): self.store.snapshot(workspace, name='receipt-held', quiescent=True)
            journal = self.store.root / 'journals' / (workspace + '.json')
            initial = core.read_json(journal); op = initial['id']
            first = json.dumps(initial['error'], sort_keys=True)
            carrier = json.dumps(initial['native_image_result'], sort_keys=True)
            self.assertEqual(initial['error']['errno'], errno.EIO)
            self.assertEqual(initial['error']['native_image_result'], initial['native_image_result'])
            with patch('stallionfs.core.native_operation') as bridge:
                for index in range(3):
                    with self.assertRaises(StallionError):
                        self.store.snapshot(workspace, name='receipt-held', quiescent=True, continue_operation=op)
                    with self.assertRaises(StallionError): self.store.continue_unmount(workspace, op)
                    current = core.read_json(journal)
                    self.assertEqual(json.dumps(current['error'], sort_keys=True), first)
                    self.assertEqual(json.dumps(current['native_image_result'], sort_keys=True), carrier)
                    self.assertFalse(current['bridge_returned'])
                    self.assertEqual(current['later_errors']['count'], 2 * (index + 1))
                    self.assertEqual(set(current['later_errors']), {'count', 'latest'})
                bridge.assert_not_called()

    def test_compound_native_committed_failure_keeps_first_guard_after_withdrawal(self):
        from stallionfs import core, _native
        seed = self.prepare()
        with self.compound_controller_fixture():
            created = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = created['id']; path = Path(created['path']).parent.parent
            first_error = OSError(errno.EIO, 'original guard failed')
            first_receipt = {'status': 1, 'diagnostic': 'original guard'}
            first_error.native_candidate_result = {'current_guard': first_receipt}
            with patch('stallionfs._native_recovery._remount_compound', side_effect=first_error):
                with self.assertRaises(OSError): self.store.snapshot(workspace, name='guard-held', quiescent=True)
            journal = self.store.root / 'journals' / (workspace + '.json')
            initial = core.read_json(journal); op = initial['id']
            first = json.dumps(initial['error'], sort_keys=True)
            carrier = json.dumps(initial['native_image_result'], sort_keys=True)
            later_error = OSError(errno.EBUSY, 'later guard failed')
            later_error.native_current_guard = {'status': 2, 'diagnostic': 'later guard'}
            with patch('stallionfs.core.native_operation') as bridge:
                for index in range(3):
                    with self.assertRaises(StallionError): self.store.continue_unmount(workspace, op)
                    with patch('stallionfs._native_recovery._remount_compound', side_effect=later_error):
                        with self.assertRaises(OSError):
                            self.store.snapshot(workspace, name='guard-held', quiescent=True, continue_operation=op)
                    current = core.read_json(journal)
                    self.assertEqual(json.dumps(current['error'], sort_keys=True), first)
                    self.assertEqual(json.dumps(current['native_image_result'], sort_keys=True), carrier)
                    self.assertEqual(current['failed_current_guard'], first_receipt)
                    self.assertEqual(current['later_errors']['count'], 2 * (index + 1))
                    self.assertEqual(current['later_errors']['latest']['native_current_guard'], later_error.native_current_guard)
                bridge.assert_not_called()

    def test_owned_native_catalog_real_content_round_trip_and_names(self):
        import hashlib
        import test_image as capture
        from stallionfs import _native
        from stallionfs.core import read_json
        repository = Path(__file__).resolve().parents[1]
        compiler = capture._owned_command(['/usr/bin/xcrun', '--sdk', 'macosx', '--find', 'clang'], cwd=self.base,
            timeout=15, stem=self.base / 'recovery-find-clang')
        self.assertEqual(compiler.returncode, 0, compiler.stderr)
        sdk = capture._owned_command(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'], cwd=self.base,
            timeout=15, stem=self.base / 'recovery-find-sdk')
        self.assertEqual(sdk.returncode, 0, sdk.stderr)
        checker = self.base / 'recovery-fixture'
        compiled = capture._owned_command([compiler.stdout.strip(), '-std=c11', '-Wall', '-Wextra',
            '-Wno-deprecated-declarations', '-O1', '-isysroot', sdk.stdout.strip(),
            '-I', str(repository / 'filesystem'),
            str(repository / 'tests/native_image_fixture.c'), str(repository / 'filesystem/image.c'),
            '-o', str(checker)], cwd=self.base, timeout=90, stem=self.base / 'recovery-fixture-build')
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        seed = self.prepare()
        with self.native_controller_fixture():
            result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = result['id']; path = Path(result['path']).parent.parent
            self.store.unmount(workspace)
            original = _native.installed_target(self.store, path, read_json(path / 'meta.json'))
            self.store.snapshot(workspace, name='A')
            changed = capture._owned_command([str(checker), 'write-path', str(path), 'repo/file', 'committed B'],
                cwd=self.base, timeout=30, stem=self.base / 'recovery-write-B')
            self.assertEqual(changed.returncode, 0, changed.stderr)
            restored = self.store.rollback(workspace, 'A')
            for label, expected in (('A', b'original\n'), ('B', b'committed B')):
                if label == 'B': self.store.rollback(workspace, restored['recovery'])
                observed = capture._owned_command([str(checker), 'describe', str(path), 'repo/file'],
                    cwd=self.base, timeout=30, stem=self.base / ('recovery-read-' + label))
                self.assertEqual(observed.returncode, 0, observed.stderr)
                self.assertEqual(json.loads(observed.stdout)['sha256'], hashlib.sha256(expected).hexdigest())
            current = _native.installed_target(self.store, path, read_json(path / 'meta.json'))
            self.assertEqual(current, original)
            names = [item['name'] for item in self.store.snapshots(workspace)]
            self.assertIn('A', names); self.assertIn(restored['recovery'], names)
            for bad in ('', '.', '..', 'a/b', 'nul\0name', 'x' * 256):
                with self.assertRaises(StallionError): self.store.rollback(workspace, bad)
            with self.assertRaises(StallionError): self.store.snapshot(workspace, name='A')
            with self.assertRaises(StallionError): self.store.rollback(workspace, 'missing')
        self.assertEqual((self.source / 'file').read_text(), 'original\n')
        self.assertEqual((self.store.root / 'seeds' / seed['id'] / 'repo/file').read_text(), 'original\n')
        # Reads above use the real core, not the fake mounted directory.

    def test_owned_native_catalog_limit_and_full_catalog_retirement(self):
        from stallionfs import _native, _image
        from stallionfs.core import read_json
        from stallionfs.lifecycle import STALE_SECONDS
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = result['id']; path = Path(result['path']).parent.parent
            self.store.unmount(workspace)
            for index in range(31): self.store.snapshot(workspace, name='entry-' + str(index))
            self.assertEqual(len(self.store.snapshots(workspace)), 31)
            self.store.snapshot(workspace, name='entry-31')
            target = _native.installed_target(self.store, path, read_json(path / 'meta.json'))
            before = _image.inspect(target)['receipt']
            with self.assertRaises(StallionError): self.store.snapshot(workspace, name='overflow')
            with self.assertRaises(StallionError): self.store.rollback(workspace, 'entry-0')
            after = _image.inspect(target)['receipt']
            self.assertEqual([after[k] for k in ('generation', 'root_digest', 'committed_end')],
                             [before[k] for k in ('generation', 'root_digest', 'committed_end')])
            self.assertEqual(len(self.store.snapshots(workspace)), 32)
            self.store.enroll(workspace); self.store.close(workspace, quiescent=True)
            now[0] += STALE_SECONDS
            self.store.move(workspace)
            restored = self.store.move(workspace, restore=True)
            self.assertFalse(restored['mounted'])
            self.assertEqual(len(self.store.snapshots(workspace)), 32)

    def test_owned_native_catalog_unresolved_receipt_observes_without_replay(self):
        from stallionfs import core
        from stallionfs.core import read_json
        seed = self.prepare()
        with self.native_controller_fixture() as state:
            result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = result['id']; path = Path(result['path']).parent.parent
            with self.assertRaises(StallionError): self.store.snapshot(workspace, name='mounted')
            self.store.unmount(workspace)
            nested = str(path / 'volume/nested')
            state['rows'][nested] = {'path': nested}
            with self.assertRaises(StallionError): self.store.snapshots(workspace)
            state['rows'].pop(nested)
            original = core.native_operation
            calls = []
            def lost(target, action, *names):
                calls.append(action)
                outcome = original(target, action, *names)
                if action == 'snapshot':
                    error = OSError(errno.EIO, 'committed response lost')
                    error.native_image_result = outcome
                    raise error
                return outcome
            with patch('stallionfs.core.native_operation', side_effect=lost):
                with self.assertRaises(OSError): self.store.snapshot(workspace, name='committed-once')
            journal = self.store.root / 'journals' / (workspace + '.json')
            unresolved = read_json(journal)
            self.assertEqual(unresolved['operation'], 'native-snapshot')
            self.assertTrue(unresolved['native_image_result']['committed'])
            self.assertEqual(unresolved['outcome'], 'incomplete')
            with patch('stallionfs.core.native_operation', wraps=original) as current:
                self.assertIn('committed-once', [row['name'] for row in self.store.snapshots(workspace)])
                self.assertEqual([call.args[1] for call in current.call_args_list], ['snapshots'])
            archived = read_json(path / 'native-operations' / unresolved['id'] / 'record.json')
            self.assertEqual(archived['outcome'], 'incomplete')
            self.assertFalse(journal.exists())
            with self.store._lease(workspace):
                with self.assertRaises(StallionError): self.store.snapshot(workspace, name='managed-busy')
            from stallionfs import _image, _native
            target = _native.installed_target(self.store, path, read_json(path / 'meta.json'))
            def locked(token):
                with self.assertRaises(StallionError): self.store.snapshots(workspace)
            _image.with_backing_guard(target, locked)
            self.assertIn('committed-once', [row['name'] for row in self.store.snapshots(workspace)])

    def test_owned_native_catalog_bridge_fault_dispositions_never_replay(self):
        from stallionfs import _image, _native
        from stallionfs.core import read_json
        seed = self.prepare()
        with self.native_controller_fixture():
            result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = result['id']; path = Path(result['path']).parent.parent
            self.store.unmount(workspace); self.store.snapshot(workspace, name='base')
            target = _native.installed_target(self.store, path, read_json(path / 'meta.json'))
            phases = ('before-stage', 'before-commit', 'ambiguous-commit', 'close', 'parent-close', 'report-allocation')
            for action in ('snapshot', 'restore'):
                real = getattr(_image, action)
                for phase in phases:
                    with self.subTest(action=action, phase=phase):
                        calls = []
                        def fault(value, *names):
                            calls.append(names)
                            if phase == 'before-stage': raise OSError(errno.EIO, 'bridge refused before staging')
                            if phase == 'before-commit':
                                outcome = dict(_image.inspect(value), operation=action, ok=False,
                                    error_code=errno.EIO, commit_attempted=False, committed=False, outcome='not_committed')
                            else:
                                outcome = dict(real(value, *names), ok=False, error_code=errno.EIO)
                                if phase == 'ambiguous-commit': outcome.update(outcome='unknown', committed=False)
                                if phase == 'close': outcome['close_receipt'] = dict(outcome['close_receipt'], status=8)
                                if phase == 'parent-close': outcome['guard_close_errno'] = errno.EIO
                                if phase == 'report-allocation':
                                    outcome['response_complete'] = False
                                    error = MemoryError('bridge response allocation')
                                    error.native_image_carrier = {'data': bytearray(json.dumps(outcome).encode()),
                                        'snapshot': names[0], 'recovery': names[1] if action == 'restore' else None}
                                    raise error
                            return outcome
                        # These faults test controller receipt handling at the
                        # bridge boundary; test_cli separately injects C faults.
                        with patch('stallionfs._image.' + action, side_effect=fault):
                            with self.assertRaises((StallionError, OSError, MemoryError)):
                                if action == 'snapshot': self.store.snapshot(workspace, name='fault-' + phase)
                                else: self.store.rollback(workspace, 'base')
                        self.assertEqual(len(calls), 1)
                        journal = self.store.root / 'journals' / (workspace + '.json')
                        unresolved = read_json(journal)
                        self.assertEqual(unresolved['outcome'], 'incomplete')
                        if phase != 'before-stage':
                            self.assertFalse(unresolved['native_image_result']['ok'])
                        with patch('stallionfs._image.snapshot', side_effect=AssertionError('snapshot replay')), \
                             patch('stallionfs._image.restore', side_effect=AssertionError('restore replay')):
                            self.assertIn('base', [row['name'] for row in self.store.snapshots(workspace)])
                        archived = read_json(path / 'native-operations' / unresolved['id'] / 'record.json')
                        self.assertEqual(archived['outcome'], 'incomplete')
                        self.assertFalse(journal.exists())
            self.assertEqual(_image.inspect(target)['identity']['file'], target['file'])

    def test_owned_native_idle_baselines_require_enrollment_age_and_current_anchor(self):
        from stallionfs import _native, _image
        from stallionfs.core import read_json
        from stallionfs.lifecycle import STALE_SECONDS
        seed = self.prepare()
        with self.native_controller_fixture() as mounted, self.native_wall_clock() as now:
            result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = result['id']; path = Path(result['path']).parent.parent
            self.assertFalse(self.store.cleanup(apply=True)['enabled'])
            self.store.cleanup_config(enabled=True)
            self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
            self.store.enroll(workspace)
            self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
            self.assertNotIn('native_idle', read_json(self.store._state(workspace)))
            self.store.unmount(workspace)
            self.assertTrue(read_json(self.store._state(workspace))['enrolled'])
            self.store.cleanup(apply=False)
            self.assertNotIn('native_idle', read_json(self.store._state(workspace)))
            self.store.cleanup(apply=True)
            initial = read_json(self.store._state(workspace))
            self.assertEqual(initial['native_idle']['observed_at'], now[0])
            self.assertNotIn('closed_at', initial)
            now[0] += STALE_SECONDS - 1
            self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
            target = _native.installed_target(self.store, path, read_json(path / 'meta.json'))
            _image.snapshot(target, 'external-current-change')
            now[0] += 1
            self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
            changed = read_json(self.store._state(workspace))
            self.assertNotEqual(changed['generation'], initial['generation'])
            self.assertEqual(changed['native_idle']['observed_at'], now[0])
            self.store.mount(workspace)
            self.assertTrue(read_json(self.store._state(workspace))['enrolled'])
            self.assertNotIn('native_idle', read_json(self.store._state(workspace)))
            self.store.close(workspace, quiescent=True)
            closed = read_json(self.store._state(workspace))
            self.assertEqual(closed['closed_at'], now[0])
            now[0] += STALE_SECONDS
            self.assertEqual(self.store.cleanup(apply=False)['would_retire'], [workspace])
            self.assertEqual(self.store.cleanup(apply=True)['retired'], [workspace])
            self.assertFalse(mounted['rows'])

    def test_owned_native_final_anchor_race_resets_only_after_clean_close(self):
        from stallionfs import _native, _image
        from stallionfs.core import read_json
        from stallionfs.lifecycle import STALE_SECONDS
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = result['id']; path = Path(result['path']).parent.parent
            self.store.enroll(workspace); self.store.close(workspace, quiescent=True)
            self.store.cleanup_config(enabled=True)
            now[0] += STALE_SECONDS
            original = _native.guarded
            for index, (change, fail_close) in enumerate((('anchor', False), ('generation', False),
                                                         ('enrollment', False), ('anchor', True))):
                if index:
                    self.store.enroll(workspace)
                    self.store.close(workspace, quiescent=True); now[0] += STALE_SECONDS
                changed = []
                def race(target, callback=None, *, anchor=None, expected_anchor=None):
                    if expected_anchor is not None:
                        changed.append(1)
                        if change == 'anchor':
                            self.assertTrue(_image.snapshot(target, 'race-' + str(fail_close))['ok'])
                        else:
                            changed_state = read_json(self.store._state(workspace))
                            changed_state['generation' if change == 'generation' else 'enrolled'] = ('f' * 32 if change == 'generation' else False)
                            _native._persist(self.store._state(workspace), changed_state)
                    try:
                        return original(target, callback, anchor=anchor, expected_anchor=expected_anchor)
                    except BaseException as error:
                        if fail_close and getattr(error, 'native_anchor_mismatch', False):
                            error.native_current_guard = dict(error.native_current_guard, parent_close_errno=errno.EIO)
                        raise
                with patch('stallionfs._native.guarded', side_effect=race):
                    observed = self.store.cleanup(apply=True)
                self.assertEqual(changed, [1])
                self.assertEqual(observed['retired'], [])
                self.assertTrue(path.exists())
                protection = self.store.root / 'protected' / (workspace + '.json')
                journal = self.store.root / 'journals' / (workspace + '.json')
                self.assertEqual(protection.exists(), fail_close)
                self.assertEqual(journal.exists(), fail_close)
                if fail_close:
                    with patch('stallionfs._scan.move', side_effect=AssertionError('rename replay')):
                        self.store.move(workspace, restore=True)
                    self.assertFalse(protection.exists()); self.assertFalse(journal.exists())
                self.assertNotIn('native_idle', read_json(self.store._state(workspace)))

    def test_owned_native_move_restore_at_full_retention_preserves_origin_and_first_use(self):
        from stallionfs.core import read_json, write_json, lock
        from stallionfs import _image, _native
        from stallionfs.lifecycle import STALE_SECONDS
        seed = self.prepare()
        with self.native_controller_fixture() as mounted, self.native_wall_clock() as now:
            result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = result['id']; path = Path(result['path']).parent.parent
            git(path / 'volume/repo', 'checkout', '-b', 'legitimate-current-branch')
            (path / 'volume/repo/later').write_text('accepted writable host fixture')
            immutable = {name: (path / name).read_bytes() for name in ('native-create.json', 'native-install.json', 'meta.json')}
            self.store.enroll(workspace); self.store.close(workspace, quiescent=True)
            now[0] += STALE_SECONDS
            for index in range(31):
                write_json(self.store.root / 'protected' / (f'{index:032x}' + '.json'), {'id': f'{index:032x}'})
            original = _native.guarded
            checks = []
            def guarded(target, callback=None, **kwargs):
                if callback is None: return original(target, callback, **kwargs)
                def held(token):
                    with self.assertRaises(BlockingIOError):
                        with lock(self.store.root / '.lock', blocking=False): pass
                    self.assertEqual(_image.snapshot(target, 'competing-core')['error_code'], errno.EBUSY)
                    checks.append(1)
                    return callback(token)
                return original(target, held, **kwargs)
            with patch('stallionfs._native.guarded', side_effect=guarded): self.store.move(workspace)
            self.assertEqual(checks, [1])
            trash = self.store.root / 'trash' / workspace
            self.assertEqual(len(list((self.store.root / 'protected').iterdir())), 32)
            second = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            self.store.enroll(second['id']); self.store.close(second['id'], quiescent=True)
            now[0] += STALE_SECONDS
            with self.assertRaises(StallionError): self.store.move(second['id'])
            self.assertTrue((self.store.root / 'workspaces' / second['id']).exists())
            self.assertEqual(self.store.list('trash')[0]['id'], workspace)
            for name, content in immutable.items(): self.assertEqual((trash / name).read_bytes(), content)
            with self.assertRaises(StallionError): self.store.register_native_image(trash / 'image.sfs')
            self.assertEqual(self.store.gc(older_than=0, yes=True), [])
            with self.assertRaises(StallionError): self.store.purge('trash', workspace, yes=True)
            with patch.object(self.store, '_retention', side_effect=AssertionError('restore requested a new slot')):
                restored = self.store.move(workspace, restore=True)
            self.assertFalse(restored['mounted']); self.assertFalse(mounted['rows'])
            self.assertEqual(len(list((self.store.root / 'protected').iterdir())), 31)
            self.assertNotIn('native_idle', read_json(self.store._state(workspace)))
            for name, content in immutable.items(): self.assertEqual((path / name).read_bytes(), content)
            self.store.mount(workspace)
            self.assertEqual(git(path / 'volume/repo', 'branch', '--show-current'), 'legitimate-current-branch')
            self.assertTrue((path / 'volume/repo/later').exists())

    def test_owned_native_move_interruptions_recover_from_top_level_journal(self):
        from stallionfs import _native, _scan, core
        from stallionfs.core import read_json
        from stallionfs.lifecycle import STALE_SECONDS
        seed = self.prepare()
        phases = ('before-protection', 'after-protection', 'rename-response', 'source-sync',
                  'destination-sync', 'state-sync', 'location-before', 'location-after', 'close-error')
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            for phase in phases:
                with self.subTest(phase=phase):
                    result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
                    workspace = result['id']; path = Path(result['path']).parent.parent
                    immutable = {name: (path / name).read_bytes() for name in ('native-create.json', 'native-install.json')}
                    self.store.enroll(workspace); self.store.close(workspace, quiescent=True)
                    now[0] += STALE_SECONDS
                    fired = []
                    write_json, persist, move, guard = core.write_json, _native._persist, _scan.move, _native.guarded
                    sync = core.sync_directory
                    def syncing(parent):
                        failed = {'source-sync': 'workspaces', 'destination-sync': 'trash', 'state-sync': 'lifecycle'}.get(phase)
                        if failed and Path(parent) == self.store.root / failed and not fired:
                            fired.append(1); raise OSError(errno.EIO, phase)
                        return sync(parent)
                    def before_protection(target, record):
                        if phase == 'before-protection' and Path(target).parent == self.store.root / 'protected':
                            fired.append(1); raise OSError(errno.EIO, phase)
                        return write_json(target, record)
                    def moving(source, destination, **kwargs):
                        value = move(source, destination, **kwargs)
                        if phase == 'rename-response': fired.append(1); raise OSError(errno.EIO, phase)
                        return value
                    def saving(target, record):
                        match = Path(target).name == 'native-location.json' and not fired
                        if match and phase == 'location-before': fired.append(1); raise OSError(errno.EIO, phase)
                        value = persist(target, record)
                        if match and phase == 'location-after': fired.append(1); raise OSError(errno.EIO, phase)
                        return value
                    def guarding(target, callback=None, **kwargs):
                        final = kwargs.get('expected_anchor') is not None
                        if final and phase == 'after-protection': fired.append(1); raise OSError(errno.EIO, phase)
                        value = guard(target, callback, **kwargs)
                        if final and phase == 'close-error':
                            fired.append(1); error = OSError(errno.EIO, phase)
                            error.native_current_guard = dict(value, status=8); raise error
                        return value
                    with patch('stallionfs.core.write_json', side_effect=before_protection), \
                         patch('stallionfs._native._persist', side_effect=saving), \
                         patch('stallionfs._scan.move', side_effect=moving), \
                         patch('stallionfs._native.guarded', side_effect=guarding), \
                         patch('stallionfs.core.sync_directory', side_effect=syncing):
                        with self.assertRaises(OSError): self.store.move(workspace)
                    self.assertEqual(fired, [1])
                    journal = self.store.root / 'journals' / (workspace + '.json')
                    record = read_json(journal)
                    self.assertEqual(record['outcome'], 'incomplete')
                    trash = self.store.root / 'trash' / workspace
                    self.assertNotEqual(path.exists(), trash.exists())
                    moved_already = trash.exists()
                    if phase in ('after-protection', 'rename-response'):
                        actual = trash if moved_already else path
                        entries = set((self.store.root / 'workspaces').iterdir())
                        alias = self.base / ('collection-alias-' + workspace)
                        alias.symlink_to(actual.parent, target_is_directory=True)
                        for reference in (actual / 'image.sfs', alias / workspace / 'image.sfs'):
                            with self.assertRaises(StallionError): self.store.register_native_image(reference)
                        link = self.base / ('hardlink-' + workspace)
                        os.link(actual / 'image.sfs', link)
                        try:
                            with self.assertRaises(StallionError): self.store.register_native_image(link)
                        finally: link.unlink()
                        self.assertEqual(set((self.store.root / 'workspaces').iterdir()), entries)
                        self.assertEqual(read_json(journal)['id'], record['id'])
                    with patch('stallionfs._scan.move', wraps=move) as rename, \
                         patch('stallionfs._image.create_from_tree', side_effect=AssertionError('import replay')):
                        self.store.move(workspace, restore=True)
                        self.assertEqual(rename.call_count, int(moved_already))
                    self.assertTrue(path.exists()); self.assertFalse(trash.exists()); self.assertFalse(journal.exists())
                    for name, content in immutable.items(): self.assertEqual((path / name).read_bytes(), content)
                    retained = read_json(path / 'native-operations' / record['id'] / 'record.json')
                    self.assertEqual(retained['outcome'], 'incomplete')
                    self.assertIn('resolution', retained)

    def test_owned_native_recovery_fences_parents_and_state_before_releasing_hold(self):
        from stallionfs import _native, _scan, core
        from stallionfs.core import read_json, native_failure_details
        from stallionfs.lifecycle import STALE_SECONDS
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            for failed_parent in ('trash', 'workspaces', 'lifecycle'):
                with self.subTest(parent=failed_parent):
                    result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
                    workspace = result['id']; path = Path(result['path']).parent.parent
                    self.store.enroll(workspace); self.store.close(workspace, quiescent=True)
                    now[0] += STALE_SECONDS
                    self.store.move(workspace)
                    rename, sync, persist, unlink = _scan.move, core.sync_directory, _native._persist, Path.unlink
                    journal = self.store.root / 'journals' / (workspace + '.json')
                    protection = self.store.root / 'protected' / (workspace + '.json')
                    def lost(source, destination, **kwargs):
                        rename(source, destination, **kwargs)
                        raise OSError(errno.EIO, 'rename completed before either parent fence')
                    with patch('stallionfs._scan.move', side_effect=lost):
                        with self.assertRaises(OSError): self.store.move(workspace, restore=True)
                    original = read_json(journal)
                    primary = OSError(errno.EIO, failed_parent + ' sync')
                    reached = []
                    def failing_sync(parent):
                        if Path(parent) == self.store.root / failed_parent:
                            reached.append(failed_parent)
                            self.assertTrue(journal.exists()); self.assertTrue(protection.exists())
                            raise primary
                        return sync(parent)
                    with patch('stallionfs.core.sync_directory', side_effect=failing_sync), \
                         patch('stallionfs._scan.move', side_effect=AssertionError('rename replay')):
                        with self.assertRaises(OSError) as caught: self.store.move(workspace, restore=True)
                    self.assertIs(caught.exception, primary); self.assertEqual(reached, [failed_parent])
                    held = read_json(journal)
                    self.assertEqual(held['outcome'], original['outcome'])
                    self.assertNotIn('resolution', held)
                    self.assertEqual(native_failure_details(primary)['id'], original['id'])
                    self.assertTrue(protection.exists()); self.assertTrue(path.exists())
                    fences = []
                    def syncing(parent):
                        value = sync(parent)
                        if Path(parent) in (self.store.root / name for name in ('trash', 'workspaces', 'lifecycle')):
                            fences.append(Path(parent).name)
                        return value
                    def saving(target, record):
                        if 'resolution' in record:
                            self.assertEqual(fences[:3], ['trash', 'workspaces', 'lifecycle'])
                        return persist(target, record)
                    def removing(target, *args, **kwargs):
                        if target in (journal, protection):
                            self.assertEqual(fences[:3], ['trash', 'workspaces', 'lifecycle'])
                            self.assertIn('resolution', read_json(path / 'native-operations' / original['id'] / 'record.json'))
                        return unlink(target, *args, **kwargs)
                    with patch('stallionfs.core.sync_directory', side_effect=syncing), \
                         patch('stallionfs._native._persist', side_effect=saving), \
                         patch.object(Path, 'unlink', removing), \
                         patch('stallionfs._scan.move', side_effect=AssertionError('rename replay')):
                        response = self.store.move(workspace, restore=True)
                    self.assertEqual(response['native_operation']['id'], original['id'])
                    self.assertEqual(response['native_operation']['resolution']['prior_outcome'], 'incomplete')
                    self.assertFalse(journal.exists()); self.assertFalse(protection.exists())
                    self.assertNotIn('native_idle', read_json(self.store._state(workspace)))

    def test_owned_native_use_requires_durable_idle_invalidation(self):
        from stallionfs import core
        from stallionfs.core import read_json
        seed = self.prepare()
        with self.native_controller_fixture():
            for action in ('mount', 'run', 'snapshot', 'rollback', 'enroll'):
                with self.subTest(action=action):
                    result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
                    workspace = result['id']
                    self.store.unmount(workspace); self.store.snapshot(workspace, name='before')
                    self.store.enroll(workspace); self.store.close(workspace, quiescent=True)
                    self.assertIn('native_idle', read_json(self.store._state(workspace)))
                    sync = core.sync_directory
                    primary = OSError(errno.EIO, 'native state parent sync')
                    def failing_sync(parent):
                        if Path(parent) == self.store.root / 'lifecycle': raise primary
                        return sync(parent)
                    actions = {'mount': lambda: self.store.mount(workspace),
                        'run': lambda: self.store.run(workspace, ['unused']),
                        'snapshot': lambda: self.store.snapshot(workspace, name='after'),
                        'rollback': lambda: self.store.rollback(workspace, 'before'),
                        'enroll': lambda: self.store.enroll(workspace, enabled=False)}
                    with patch('stallionfs.core.sync_directory', side_effect=failing_sync), \
                         patch('stallionfs.core.native_operation') as bridge, \
                         patch('stallionfs._native.qualify') as qualifier, \
                         patch('stallionfs._native.execute_owned') as helper, \
                         patch('stallionfs.lifecycle.subprocess.run') as command:
                        with self.assertRaises(OSError) as caught: actions[action]()
                        self.assertIs(caught.exception, primary)
                        bridge.assert_not_called(); qualifier.assert_not_called()
                        helper.assert_not_called(); command.assert_not_called()
                    if action in ('snapshot', 'rollback'):
                        held = read_json(self.store.root / 'journals' / (workspace + '.json'))
                        self.assertFalse(held['bridge_attempted']); self.assertEqual(held['outcome'], 'incomplete')
                    # After a successful fence, helper entry sees the replacement generation.
                    if action == 'mount':
                        fences = []
                        def syncing(parent):
                            value = sync(parent)
                            if Path(parent) == self.store.root / 'lifecycle': fences.append(True)
                            return value
                        def qualified(*args):
                            self.assertEqual(fences, [True])
                            self.assertNotIn('native_idle', read_json(self.store._state(workspace)))
                            return 'stallionfs'
                        with patch('stallionfs.core.sync_directory', side_effect=syncing), \
                             patch('stallionfs._native.qualify', side_effect=qualified):
                            self.store.mount(workspace)

    def test_owned_native_completed_responses_survive_outer_close_errors(self):
        from stallionfs import core, _scan
        from stallionfs.core import native_failure_details, read_json
        from stallionfs.lifecycle import STALE_SECONDS
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            for action in ('snapshot', 'rollback', 'retire', 'return'):
                for boundary in ('workspace', 'lease', 'root', 'retention') if action in ('retire', 'return') else ('workspace', 'lease'):
                    with self.subTest(action=action, boundary=boundary):
                        result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
                        workspace = result['id']; path = Path(result['path']).parent.parent
                        self.store.unmount(workspace); self.store.snapshot(workspace, name='before')
                        if action in ('retire', 'return'):
                            self.store.enroll(workspace); self.store.close(workspace, quiescent=True)
                            now[0] += STALE_SECONDS
                            if action == 'return': self.store.move(workspace)
                        primary = OSError(errno.EIO, boundary + ' close')
                        lock, lease = core.lock, self.store._lease
                        @contextmanager
                        def closing_lock(target, *args, **kwargs):
                            with lock(target, *args, **kwargs): yield
                            target_name = {'root': '.lock', 'retention': 'retention', 'workspace': 'workspace-' + workspace}.get(boundary)
                            if Path(target).name == target_name:
                                raise primary
                        @contextmanager
                        def closing_lease(value):
                            with lease(value) as descriptor: yield descriptor
                            if boundary == 'lease': raise primary
                        actions = {'snapshot': lambda: self.store.snapshot(workspace, name='after'),
                            'rollback': lambda: self.store.rollback(workspace, 'before'),
                            'retire': lambda: self.store.move(workspace),
                            'return': lambda: self.store.move(workspace, restore=True)}
                        with patch('stallionfs.core.lock', side_effect=closing_lock), \
                             patch.object(self.store, '_lease', side_effect=closing_lease), \
                             patch('stallionfs.core.native_operation', wraps=core.native_operation) as bridge, \
                             patch('stallionfs._scan.move', wraps=_scan.move) as rename:
                            with self.assertRaises(OSError) as caught: actions[action]()
                        self.assertIs(caught.exception, primary)
                        response = native_failure_details(primary)
                        operation = response['native_operation']
                        self.assertEqual(operation['outcome'], 'complete')
                        self.assertFalse((self.store.root / 'journals' / (workspace + '.json')).exists())
                        if action in ('snapshot', 'rollback'):
                            self.assertEqual(bridge.call_count, 1); rename.assert_not_called()
                            self.assertTrue(response['native_image_result']['committed'])
                        else:
                            self.assertEqual(rename.call_count, 1); bridge.assert_not_called()
                            self.assertEqual(response['restored' if action == 'return' else 'retired'], workspace)
                            self.assertFalse(response['mounted'])
                            if action == 'retire': path = self.store.root / 'trash' / workspace
                        self.assertEqual(read_json(path / 'native-operations' / operation['id'] / 'record.json')['outcome'], 'complete')

    def test_owned_native_missing_or_malformed_protection_never_allows_restore_or_delete(self):
        from stallionfs import _scan
        from stallionfs.lifecycle import STALE_SECONDS
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = result['id']
            self.store.enroll(workspace); self.store.close(workspace, quiescent=True)
            now[0] += STALE_SECONDS
            self.store.move(workspace)
            trash = self.store.root / 'trash' / workspace
            protection = self.store.root / 'protected' / (workspace + '.json')
            saved = protection.read_bytes()
            for damaged in (None, b'{"format": 1, "id": "wrong"}'):
                with self.subTest(protection=damaged):
                    if damaged is None: protection.unlink()
                    else: protection.write_bytes(damaged)
                    with patch('stallionfs._scan.move', wraps=_scan.move) as rename:
                        with self.assertRaises((StallionError, FileNotFoundError)):
                            self.store.move(workspace, restore=True)
                        rename.assert_not_called()
                    # Missing protection still cannot defeat native data retention.
                    if damaged is None:
                        with self.assertRaises(StallionError): self.store.gc(older_than=0, yes=True)
                    else: self.assertEqual(self.store.gc(older_than=0, yes=True), [])
                    with self.assertRaises(StallionError): self.store.purge('trash', workspace, yes=True)
                    self.assertTrue((trash / 'image.sfs').is_file())
                    protection.write_bytes(saved)
            self.store.move(workspace, restore=True)

    def test_owned_native_restore_rename_response_loss_never_replays(self):
        from stallionfs import _scan
        from stallionfs.core import read_json
        from stallionfs.lifecycle import STALE_SECONDS
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = result['id']; path = Path(result['path']).parent.parent
            self.store.enroll(workspace); self.store.close(workspace, quiescent=True); now[0] += STALE_SECONDS
            self.store.move(workspace)
            original = _scan.move
            def lost(source, destination, **kwargs):
                original(source, destination, **kwargs)
                raise OSError(errno.EIO, 'restore rename response lost')
            with patch('stallionfs._scan.move', side_effect=lost):
                with self.assertRaises(OSError): self.store.move(workspace, restore=True)
            journal = self.store.root / 'journals' / (workspace + '.json')
            self.assertEqual(read_json(journal)['operation'], 'native-return')
            with patch('stallionfs._scan.move', side_effect=AssertionError('restore rename replay')):
                restored = self.store.move(workspace, restore=True)
            self.assertFalse(restored['mounted']); self.assertTrue(path.exists())
            self.assertFalse(journal.exists())
            self.assertFalse((self.store.root / 'protected' / (workspace + '.json')).exists())

    def test_owned_native_idle_invalid_busy_pending_and_reopened_state_never_retires(self):
        import copy
        from stallionfs import _native
        from stallionfs.core import read_json
        from stallionfs.lifecycle import replace_json, STALE_SECONDS
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = result['id']; path = Path(result['path']).parent.parent
            self.store.enroll(workspace); self.store.close(workspace, quiescent=True)
            self.store.cleanup_config(enabled=True); now[0] += STALE_SECONDS
            saved = read_json(self.store._state(workspace))
            variants = []
            for value in (-1, True, float('inf'), now[0] + 1):
                changed = copy.deepcopy(saved); changed['closed_at'] = value; variants.append(changed)
            changed = copy.deepcopy(saved); changed['generation'] = 'f' * 32; variants.append(changed)
            changed = copy.deepcopy(saved); changed['enrolled'] = False; variants.append(changed)
            changed = copy.deepcopy(saved); changed['native_idle']['observed_at'] = now[0] + 1; variants.append(changed)
            for changed in variants:
                # Malformed nonfinite state is read-only JSON evidence, not a
                # request to weaken the normal finite-state writer.
                if changed.get('closed_at') == float('inf'):
                    self.store._state(workspace).write_text(json.dumps(changed))
                else: replace_json(self.store._state(workspace), changed)
                self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
                self.assertTrue(path.exists())
            replace_json(self.store._state(workspace), saved)
            with patch('stallionfs._native.guarded', side_effect=OSError(errno.EBUSY, 'direct core owner')):
                self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
            with self.store._lease(workspace):
                self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
            journal = self.store.root / 'journals' / (workspace + '.json')
            replace_json(journal, {'operation': 'native-mount', 'workspace': workspace, 'child_pending': True})
            self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
            journal.unlink()
            self.store.enroll(workspace, enabled=False)
            self.assertEqual(self.store.cleanup(apply=True)['retired'], [])

    def test_owned_native_leases_exclude_move_restore_and_allow_independent_cleanup(self):
        from stallionfs.lifecycle import STALE_SECONDS
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            workspaces = []
            for _ in range(2):
                result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
                workspaces.append(result['id'])
                self.store.enroll(result['id']); self.store.close(result['id'], quiescent=True)
            first, second = workspaces
            self.store.cleanup_config(enabled=True); now[0] += STALE_SECONDS
            with self.store._lease(first):
                with self.assertRaises(StallionError): self.store.mount(first)
                with self.assertRaises(StallionError): self.store.move(first)
                observed = self.store.cleanup(apply=True)
            self.assertEqual(observed['retired'], [second])
            self.assertTrue((self.store.root / 'workspaces' / first).exists())
            self.assertTrue((self.store.root / 'trash' / second).exists())
            with self.store._lease(second):
                with self.assertRaises(StallionError): self.store.move(second, restore=True)
            self.store.move(second, restore=True)
            self.assertTrue((self.store.root / 'workspaces' / second).exists())

    def test_owned_native_current_location_substitution_and_existing_destination_refuse(self):
        import copy
        from stallionfs.core import read_json
        from stallionfs.lifecycle import replace_json, STALE_SECONDS
        seed = self.prepare()
        with self.native_controller_fixture(), self.native_wall_clock() as now:
            result = self.store.create(seed['id'], backend='native-image', capacity_gib=1)
            workspace = result['id']; source = Path(result['path']).parent.parent
            self.store.enroll(workspace); self.store.close(workspace, quiescent=True); now[0] += STALE_SECONDS
            self.store.move(workspace)
            trash = self.store.root / 'trash' / workspace
            saved = read_json(trash / 'native-location.json')
            for field in ('parent', 'object', 'file', 'uuid', 'origin_target'):
                changed = copy.deepcopy(saved)
                if field in ('parent', 'object', 'file'): changed[field][1] += 1
                elif field == 'uuid': changed[field] = 'f' * 32
                else: changed[field]['file'][1] += 1
                replace_json(trash / 'native-location.json', changed)
                with self.assertRaises(StallionError): self.store.move(workspace, restore=True)
                self.assertTrue(trash.exists()); self.assertFalse(source.exists())
            replace_json(trash / 'native-location.json', saved)
            alias = self.base / 'owned-backing-alias'; os.link(trash / 'image.sfs', alias)
            try:
                with self.assertRaises(StallionError): self.store.move(workspace, restore=True)
            finally: alias.unlink()
            source.mkdir(mode=0o700)
            with self.assertRaises(StallionError): self.store.move(workspace, restore=True)
            source.rmdir()
            displaced = trash.with_name(workspace + '-displaced'); trash.rename(displaced)
            trash.symlink_to(displaced, target_is_directory=True)
            try:
                with self.assertRaises((StallionError, OSError)): self.store.move(workspace, restore=True)
            finally:
                trash.unlink(); displaced.rename(trash)
            self.store.move(workspace, restore=True)
            self.assertTrue(source.exists()); self.assertFalse(trash.exists())

    @native_creation_test
    def test_owned_native_candidate_retained_with_fresh_identity_and_branch(self):
        from stallionfs.core import owned_native_target, read_json
        (self.source / '.env').write_text('source-only secret')
        seed = self.prepare(command=[sys.executable, '-c',
            "from pathlib import Path; p=Path('dependencies'); p.mkdir(); (p/'module').write_bytes(b'dependency\\x00bytes'); Path('.hidden').write_text('hidden'); Path('empty').mkdir()"])
        seed_repo = self.store.root / 'seeds' / seed['id'] / 'repo'
        seed_head = git(seed_repo, 'rev-parse', 'HEAD')
        seed_identity = seed_repo.stat().st_ino
        first = self.store._build_owned_native_candidate(seed['id'], name='native', native_capacity_gib=1)
        second = self.store._build_owned_native_candidate(seed['id'], name='native', native_capacity_gib=1)
        for candidate in (first, second):
            self.assertTrue(candidate['candidate_created'])
            self.assertTrue(candidate['host_cleanup_complete'])
            self.assertNotIn('path', candidate)
            directory = Path(candidate['candidate'])
            metadata = read_json(directory / 'meta.json')
            target = owned_native_target(directory, metadata)
            self.assertEqual(target['directory'], str(directory))
            self.assertFalse((self.store.root / 'workspaces' / metadata['id']).exists())
            self.assertFalse((self.store.root / 'lifecycle' / (metadata['id'] + '.json')).exists())
            journal = read_json(self.store.root / 'journals' / (metadata['id'] + '.json'))
            self.assertEqual(journal['operation'], 'native-create')
            self.assertTrue(journal['creation_attempted'])
            self.assertEqual(journal['outcome'], 'candidate-created')
            self.assertEqual([actor['role'] for actor in journal['actors']],
                ['00-config', '01-refs', '02-head', '03-head-state', '04-checkout'])
            for actor in journal['actors']:
                self.assertEqual(actor['argv'][0], str(Path(os.environ['STALLIONFS_TEST_QUALIFIED_GIT']).resolve()))
                self.assertGreater(actor['pid'], 0)
                self.assertTrue(actor['reaped'])
                self.assertFalse(actor['child_pending'])
                self.assertTrue(actor['streams_durable'])
                self.assertTrue(actor['streams_eof'])
                self.assertEqual(Path(actor['stdout']).parent,
                    directory.parent / 'actors' / actor['role'])
                self.assertTrue(Path(actor['stdout']).is_file())
                self.assertTrue(Path(actor['stderr']).is_file())
            self.assertTrue(candidate['native_image_result']['verified'])
            self.assertEqual(candidate['native_image_result']['verify']['coverage'], 1)
            with self.assertRaises(StallionError):
                self.store.register_native_image(directory / 'image.sfs')
            with self.assertRaises((StallionError, FileNotFoundError)):
                self.store.object('workspaces', metadata['id'])
        self.assertNotEqual(first['metadata']['native_image']['uuid'], second['metadata']['native_image']['uuid'])
        self.assertNotEqual(first['metadata']['native_image']['file'], second['metadata']['native_image']['file'])
        self.assertEqual(self.store.list(), [])
        self.assertEqual(git(seed_repo, 'rev-parse', 'HEAD'), seed_head)
        self.assertEqual(seed_repo.stat().st_ino, seed_identity)
        self.assertEqual(git(seed_repo, 'branch', '--show-current'), '')
        self.assertEqual((self.source / '.env').read_text(), 'source-only secret')

    @native_creation_test
    def test_native_candidate_proof_tampering_and_interruption_holds(self):
        import copy
        from stallionfs import core
        from stallionfs.core import owned_native_target, read_json, native_failure_details
        seed = self.prepare()
        candidate = self.store._build_owned_native_candidate(seed['id'], native_capacity_gib=1)
        owned = Path(candidate['candidate'])
        metadata = read_json(owned / 'meta.json')
        proof_path = owned / 'native-create.json'
        proof_bytes = proof_path.read_bytes()
        original = json.loads(proof_bytes)
        for case in ('seed', 'transaction', 'coverage', 'close', 'anchor', 'identity', 'complete'):
            with self.subTest(tamper=case):
                proof = copy.deepcopy(original)
                if case == 'seed': proof['seed'] = '0' * 64
                elif case == 'transaction': proof['transaction'] = '0' * 32
                elif case == 'coverage': proof['result']['verify']['coverage'] = 0
                elif case == 'close': proof['result']['close']['status'] = 2
                elif case == 'anchor': proof['result']['commit']['root_digest'] = '0' * 64
                elif case == 'identity': proof['result']['identity']['file'][1] += 1
                else: proof['result']['candidate_complete'] = False
                proof_path.write_text(json.dumps(proof))
                with self.assertRaises(StallionError): owned_native_target(owned, metadata)
                proof_path.write_bytes(proof_bytes)
        alias = self.base / 'backing-alias'
        os.link(owned / 'image.sfs', alias)
        with self.assertRaises(StallionError): owned_native_target(owned, metadata)
        alias.unlink()
        self.assertEqual(owned_native_target(owned, metadata)['file'], metadata['native_image']['file'])
        original_write = core.write_json
        for target in ('native-create.json', 'meta.json'):
            with self.subTest(interruption=target):
                def stop(path, value):
                    if path.parent.name == 'owned' and path.name == target:
                        raise OSError(errno.ENOSPC, 'publication interrupted')
                    return original_write(path, value)
                with patch('stallionfs.core.write_json', side_effect=stop):
                    with self.assertRaises(OSError) as caught:
                        self.store._build_owned_native_candidate(seed['id'], native_capacity_gib=1)
                details = native_failure_details(caught.exception)
                retained = Path(details['candidate'])
                self.assertTrue((retained / 'image.sfs').is_file())
                self.assertTrue(details['native_image_result']['candidate_complete'])
                self.assertTrue((Path(details['host_input']) / 'repo/.git').is_dir())
                intent = read_json(Path(details['journal']))
                self.assertTrue(intent['creation_attempted'])
                self.assertEqual(intent['native_image']['file'], details['native_image_result']['identity']['file'])
                with self.assertRaises(StallionError): self.store.register_native_image(retained / 'image.sfs')
                with self.assertRaises(StallionError): self.store._reconcile(intent['workspace'])
                self.assertFalse((self.store.root / 'workspaces' / intent['workspace']).exists())
        self.assertEqual(self.store.list(), [])

    @native_creation_test
    def test_failed_native_preflight_keeps_candidate_without_blocking_unrelated_purge(self):
        from stallionfs import core
        seed = self.prepare()
        created = self.store.create(seed['id'])
        workspace, repo = created['id'], Path(created['path'])
        snapshot = self.store.snapshot(workspace, quiescent=True)['id']
        (repo / 'file').write_text('recovery contents\n')
        recovery = self.store.rollback(workspace, snapshot, quiescent=True)['recovery']
        self.store.move(workspace)
        with patch('stallionfs._native.preflight_create', side_effect=StallionError('preflight refused')), \
             patch('stallionfs._image.create_from_tree') as importer:
            with self.assertRaisesRegex(StallionError, 'preflight refused'):
                self.store.create(seed['id'], backend='native-image', capacity_gib=1)
        importer.assert_not_called()
        journal = next((self.store.root / 'journals').iterdir())
        record = core.read_json(journal)
        stage, candidate = Path(record['stage']), Path(record['candidate'])
        before = {path: path.read_bytes() for path in (journal, stage / 'native-create')}
        identities = [(path.stat().st_dev, path.stat().st_ino) for path in (stage, candidate)]
        for kind, value in (('snapshots', snapshot), ('recovery', recovery), ('trash', workspace)):
            with self.subTest(kind=kind):
                retained = self.store.root / kind / value
                self.assertEqual(self.store.purge(kind, value), {'would_delete': str(retained)})
                self.assertTrue((retained / 'repo/file').is_file())
                self.assertEqual(self.store.purge(kind, value, yes=True), {'deleted': str(retained)})
                self.assertFalse(retained.exists())
                self.assertEqual({path: path.read_bytes() for path in before}, before)
                self.assertEqual([(path.stat().st_dev, path.stat().st_ino) for path in (stage, candidate)], identities)
        self.assertEqual(list((self.store.root / 'journals').iterdir()), [journal])

    @native_creation_test
    def test_uncertain_native_create_intents_still_block_unrelated_purge(self):
        import copy
        from stallionfs import core
        seed = self.prepare()
        created = self.store.create(seed['id'])
        snapshot = self.store.snapshot(created['id'], quiescent=True)['id']
        retained = self.store.root / 'snapshots' / snapshot
        with patch('stallionfs._native.preflight_create', side_effect=StallionError('preflight refused')):
            with self.assertRaises(StallionError):
                self.store.create(seed['id'], backend='native-image', capacity_gib=1)
        journal = next((self.store.root / 'journals').iterdir())
        record = core.read_json(journal)
        original = journal.read_bytes()
        stage, candidate, final = (Path(record[key]) for key in ('stage', 'candidate', 'final'))
        marker = (stage / 'native-create').read_bytes()
        cases = {
            'unknown': {'operation': 'unknown'},
            'rollback': {'operation': 'rollback', 'backend': 'folder'},
            'workspace': {'workspace': 'f' * 32},
            'malformed': {'transaction': None},
            'pending-helper': {'child_pending': True, 'helpers': []},
            'malformed-helper': {'child_pending': False, 'helpers': [{}]},
            'stage-outside': {'stage': str(self.base / 'outside')},
            'stage-relative': {'stage': 'staging/build-relative'},
            'stage-noncanonical': {'stage': str(stage.parent) + '/./' + stage.name},
            'candidate-outside': {'candidate': str(retained)},
            'final-outside': {'final': str(retained)},
            'stage-identity': {'stage_identity': [record['stage_identity'][0], record['stage_identity'][1] + 1]},
            'candidate-identity': {'object': [record['object'][0], record['object'][1] + 1]},
        }
        def refused():
            pending = journal.read_bytes()
            for yes in (False, True):
                with self.assertRaisesRegex(StallionError, 'pending rollback|uncertain native'):
                    self.store.purge('snapshots', snapshot, yes=yes)
                self.assertTrue((retained / 'repo/file').is_file())
                self.assertEqual(journal.read_bytes(), pending)
                self.assertEqual((stage / 'native-create').read_bytes(), marker)
        for name, updates in cases.items():
            with self.subTest(case=name):
                changed = copy.deepcopy(record); changed.update(updates)
                journal.write_text(json.dumps(changed))
                refused()
        journal.write_bytes(original)
        final.mkdir(mode=0o700)
        core.write_json(final / 'meta.json', {'id': journal.stem, 'backend': 'folder'})
        try:
            with self.subTest(case='final-exists'): refused()
        finally:
            (final / 'meta.json').unlink()
            final.rmdir()
        for path in (stage, candidate):
            held = path.with_name(path.name + '-held')
            path.rename(held); path.symlink_to(held, target_is_directory=True)
            try:
                with self.subTest(case='symlink-' + path.name): refused()
            finally:
                path.unlink(); held.rename(path)
        self.assertEqual(journal.read_bytes(), original)

    @native_creation_test
    def test_native_candidate_precreate_intent_failure_never_calls_importer(self):
        seed = self.prepare()
        with patch('stallionfs.core.sync_directory', side_effect=OSError(errno.ENOSPC, 'full')), \
             patch('stallionfs._image.create_from_tree') as creator:
            with self.assertRaises(OSError):
                self.store._build_owned_native_candidate(seed['id'], native_capacity_gib=1)
        creator.assert_not_called()
        self.assertEqual(self.store.list(), [])
        stages = list((self.store.root / 'staging').iterdir())
        self.assertEqual(len(stages), 1)
        self.assertTrue((stages[0] / 'native-create').exists())
        self.assertFalse((stages[0] / 'owned' / 'image.sfs').exists())

    @native_creation_test
    def test_native_candidate_failure_keeps_unknown_output_and_intent(self):
        from stallionfs.core import read_json
        seed = self.prepare()
        def failed(source, destination, capacity):
            destination['before_create']()
            (Path(destination['directory']) / 'image.sfs').write_bytes(b'')
            raise MemoryError('response allocation')
        with patch('stallionfs._image.create_from_tree', side_effect=failed):
            with self.assertRaises(MemoryError):
                self.store._build_owned_native_candidate(seed['id'], native_capacity_gib=1)
        stages = list((self.store.root / 'staging').iterdir())
        self.assertEqual(len(stages), 1)
        self.assertTrue((stages[0] / 'owned' / 'image.sfs').exists())
        self.assertTrue((stages[0] / 'input' / 'repo' / '.git').is_dir())
        intent = read_json(next((self.store.root / 'journals').iterdir()))
        self.assertTrue(intent['creation_attempted'])
        self.assertIsNone(intent['native_image']['file'])
        with self.assertRaisesRegex(StallionError, 'without reconciliation'):
            self.store._reconcile(intent['workspace'])
        self.assertEqual(self.store.list(), [])

    @native_creation_test
    def test_native_prepared_tree_independent_fidelity(self):
        import hashlib
        import stat
        import test_image as capture
        from stallionfs import _image
        preparation = r"""from pathlib import Path
import os, ctypes
libc=ctypes.CDLL(None,use_errno=True)
libc.setxattr.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint32,ctypes.c_int]
def setx(path, name, value, **kwargs):
    if libc.setxattr(os.fsencode(path),name.encode(),value,len(value),0,1):
        raise OSError(ctypes.get_errno(), 'setxattr')
Path('dependencies').mkdir(); Path('dependencies/module').write_bytes(b'dependency\x00bytes')
Path('.hidden').write_text('hidden'); Path('empty').mkdir()
Path('allocated-zero').write_bytes(bytes(8192))
with open('all-hole', 'wb') as f: f.truncate(16385)
with open('islands', 'wb') as f:
    f.truncate(32775); f.seek(0); f.write(b'A'*4096); f.seek(24576); f.write(bytes(4096)); f.seek(32768); f.write(b'partial')
fd=os.open('raw-é'.encode(), os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o640); os.write(fd,b'raw name'); os.close(fd)
os.link('file','hard'); os.link('link','link-alias',follow_symlinks=False)
os.link('file','dependencies/hard'); os.link('link','dependencies/link-alias',follow_symlinks=False)
Path('dangling').symlink_to('missing/../still-missing')
setx('file','org.example.binary',b'\x00\xff\x02')
setx('file','org.example.empty',b'')
setx('file','com.apple.ResourceFork',b'fork\x00\xff')
setx('.','org.example.root',b'root')
setx('empty','org.example.directory',b'directory')
setx('link','org.example.link',b'link-only',follow_symlinks=False)
os.utime('file',ns=(-1234567890123,-9876543210123))
os.chflags('file',0x8001)
"""
        seed = self.prepare(command=[sys.executable, '-c', preparation])
        repository = Path(__file__).resolve().parents[1]
        checker = self.base / 'native-checker'
        result = capture._owned_command(['cc', '-O0', '-Wno-deprecated-declarations', '-Wno-deprecated-pragma',
            '-I', str(repository / 'filesystem'), str(repository / 'tests/native_image_fixture.c'),
            str(repository / 'filesystem/image.c'), '-o', str(checker)], cwd=self.base, timeout=60,
            stem=self.base / 'checker-build')
        self.assertEqual(result.returncode, 0, result.stderr)
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        libc.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        libc.listxattr.restype = ctypes.c_ssize_t
        libc.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
        libc.getxattr.restype = ctypes.c_ssize_t
        def host_xattrs(path):
            path = os.fsencode(path)
            length = libc.listxattr(path, None, 0, 1)
            self.assertGreaterEqual(length, 0)
            names = ctypes.create_string_buffer(length)
            self.assertEqual(libc.listxattr(path, names, length, 1), length)
            result = {}
            for name in names.raw.split(b'\0'):
                if not name: continue
                size = libc.getxattr(path, name, None, 0, 0, 1)
                self.assertGreaterEqual(size, 0)
                value = ctypes.create_string_buffer(size)
                self.assertEqual(libc.getxattr(path, name, value, size, 0, 1), size)
                result[name.hex()] = {'size': size, 'sha256': hashlib.sha256(value.raw).hexdigest()}
            return result
        expected = {}
        original = _image.create_from_tree
        def snapshot(source, destination, capacity, *budget):
            root = Path(source['directory'])
            paths = [root]
            for parent, directories, files in os.walk(root, followlinks=False):
                paths.extend(Path(parent) / name for name in directories + files)
            original_flags = {path: path.lstat().st_flags & ~0x40 for path in paths}
            for path in paths:
                info = path.lstat()
                row = {'xattrs': host_xattrs(path)}
                if stat.S_ISREG(info.st_mode):
                    row['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                    row['mapped'] = []
                    with path.open('rb') as stream:
                        offset = 0
                        while offset < info.st_size:
                            try:
                                data = os.lseek(stream.fileno(), offset, os.SEEK_DATA)
                            except OSError as error:
                                if error.errno == errno.ENXIO:
                                    break
                                raise
                            end = os.lseek(stream.fileno(), data, os.SEEK_HOLE)
                            row['mapped'].extend(range(data // 4096, (end + 4095) // 4096))
                            offset = end
                elif stat.S_ISLNK(info.st_mode):
                    row['target'] = os.fsencode(os.readlink(path)).hex()
                else:
                    row['children'] = sorted(os.fsencode(name).hex() for name in os.listdir(path))
                expected[str(path.relative_to(root))] = row
            # The host may add UF_TRACKED while inspecting documents. This
            # fixture exercises supported flags; remove that unsupported host
            # annotation and preserve all other flags at the import boundary.
            for path, flags in original_flags.items():
                os.chflags(path, flags, follow_symlinks=False)
            for host_index, path in enumerate(paths):
                info = path.lstat()
                times = capture._owned_command([str(checker), 'host-times', str(path)], cwd=self.base,
                    timeout=30, stem=self.base / f'host-times-{host_index:04}')
                self.assertEqual(times.returncode, 0, times.stderr)
                exact_times = json.loads(times.stdout)
                row = expected[str(path.relative_to(root))]
                row.update(mode=info.st_mode, uid=info.st_uid, gid=info.st_gid, flags=info.st_flags,
                           links=1 if stat.S_ISDIR(info.st_mode) else info.st_nlink,
                           birth=exact_times['birth'], access=exact_times['access'],
                           modification=exact_times['modification'], host_inode=info.st_ino)
                if not stat.S_ISDIR(info.st_mode):
                    row['size'] = info.st_size
            for path, flags in original_flags.items():
                os.chflags(path, flags, follow_symlinks=False)
                expected[str(path.relative_to(root))]['flags'] = flags
                self.assertEqual(path.lstat().st_flags, flags)
            return original(source, destination, capacity, *budget)
        def retain_host(path, **kwargs):
            raise OSError(errno.EACCES, 'retain expected host tree for independent check')
        with patch('stallionfs._image.create_from_tree', side_effect=snapshot), patch('stallionfs.core.remove_tree', side_effect=retain_host):
            candidate = self.store._build_owned_native_candidate(seed['id'], name='fidelity', native_capacity_gib=1)
        self.assertTrue(candidate['candidate_created'])
        self.assertFalse(candidate['host_cleanup_complete'])
        host = Path(candidate['host_input']) / 'repo'
        self.assertEqual(git(host, 'branch', '--show-current'), candidate['metadata']['branch'])
        self.assertEqual(git(host, 'rev-parse', 'HEAD'), seed['commit'])
        self.assertIn('.git/HEAD', expected)
        self.assertIn('dependencies/module', expected)
        native_inodes = {}
        for index, (relative, want) in enumerate(sorted(expected.items())):
            actual = capture._owned_command([str(checker), 'describe', candidate['candidate'],
                'repo' if relative == '.' else 'repo/' + relative], cwd=self.base, timeout=30,
                stem=self.base / f'check-{index:04}')
            self.assertEqual(actual.returncode, 0, (relative, actual.stderr))
            observed = json.loads(actual.stdout)
            host_inode = want.pop('host_inode')
            for key, value in want.items():
                if key == 'children':
                    self.assertEqual(sorted(observed[key]), value, (relative, key))
                else:
                    self.assertEqual(observed[key], value, (relative, key))
            if 'mapped' in want:
                self.assertEqual(observed['mapped_bytes'], len(want['mapped']) * 4096)
            if host_inode in native_inodes:
                self.assertEqual(observed['inode'], native_inodes[host_inode], relative)
            native_inodes[host_inode] = observed['inode']
        self.assertEqual(expected['all-hole']['mapped'], [])
        self.assertEqual(expected['dangling']['target'], os.fsencode('missing/../still-missing').hex())

    def test_native_preflight_refusals_mutation_and_capacity_retain_output(self):
        from stallionfs import _image
        cases = ('special', 'external-hardlink', 'absolute-link', 'escaping-link', 'loop-link',
                 'acl', 'flags', 'source-change', 'capacity')
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                stage = self.base / f'refusal-{index}'
                stage.mkdir(mode=0o700)
                source, destination = stage / 'input' / 'repo', stage / 'owned'
                source.parent.mkdir(mode=0o700); source.mkdir(mode=0o700); destination.mkdir(mode=0o700)
                path = source / 'file'
                path.write_bytes(b'original bytes')
                if case == 'special': os.mkfifo(source / 'fifo')
                elif case == 'external-hardlink': os.link(path, stage / 'external')
                elif case == 'absolute-link': (source / 'link').symlink_to(str(path))
                elif case == 'escaping-link': (source / 'link').symlink_to('../outside')
                elif case == 'loop-link': (source / 'link').symlink_to('link')
                elif case == 'acl': run(['/bin/chmod', '+a', 'everyone allow read', path])
                elif case == 'flags': os.chflags(path, 2)
                def pair(item):
                    info = item.stat()
                    return [info.st_dev, info.st_ino]
                attempted = []
                def before():
                    attempted.append(True)
                    if case == 'source-change': path.write_bytes(b'changed source')
                try:
                    result = _image.create_from_tree({'directory': str(source), 'root': pair(source)},
                        {'directory': str(destination), 'parent': pair(destination), 'component': 'image.sfs',
                         'before_create': before}, 16384 if case == 'capacity' else 1 << 26)
                finally:
                    if case == 'flags': os.chflags(path, 0)
                self.assertFalse(result['candidate_complete'], result)
                if case in ('source-change', 'capacity'):
                    self.assertTrue(result['creation_attempted'], result)
                    self.assertTrue((destination / 'image.sfs').exists())
                    self.assertFalse(result['import_committed'], result)
                    self.assertIsNotNone(result['close'], result)
                else:
                    self.assertFalse(result['creation_attempted'], result)
                    self.assertFalse(attempted)
                    self.assertFalse((destination / 'image.sfs').exists())
                reasons = {'special': 'unsupported-kind', 'external-hardlink': 'external-hardlink',
                           'absolute-link': 'unsafe-path', 'escaping-link': 'unsafe-path', 'loop-link': 'unsafe-path',
                           'acl': 'unsupported-acl', 'flags': 'unsupported-metadata', 'source-change': 'source-changed',
                           'capacity': 'capacity'}
                self.assertEqual(result['reason'], reasons[case], result)

    def test_native_symlink_acl_host_capability(self):
        import ctypes
        from stallionfs import _image
        source = self.base / 'acl-stage' / 'input' / 'repo'
        source.parent.mkdir(mode=0o700, parents=True); source.mkdir(mode=0o700)
        stage = source.parent.parent; stage.chmod(0o700)
        destination = stage / 'owned'; destination.mkdir(mode=0o700)
        target = source / 'file'; target.write_bytes(b'link target')
        link = source / 'link'; link.symlink_to('file')
        run(['/bin/chmod', '+a', 'everyone allow read', target])
        libc = ctypes.CDLL(None, use_errno=True)
        for name in ('acl_get_file', 'acl_get_link_np'):
            function = getattr(libc, name)
            function.argtypes = [ctypes.c_char_p, ctypes.c_int]
            function.restype = ctypes.c_void_p
        libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
        libc.acl_get_fd_np.restype = ctypes.c_void_p
        libc.acl_set_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
        libc.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
        libc.acl_free.argtypes = [ctypes.c_void_p]
        def has_entry(function, argument):
            ctypes.set_errno(0)
            acl = function(argument, 0x100)
            if not acl:
                self.assertEqual(ctypes.get_errno(), errno.ENOENT)
                return False
            try:
                entry = ctypes.c_void_p()
                ctypes.set_errno(0)
                status = libc.acl_get_entry(acl, 0, ctypes.byref(entry))
                if status == 0: return True
                self.assertEqual(status, -1)
                self.assertEqual(ctypes.get_errno(), errno.EINVAL)
                return False
            finally:
                self.assertEqual(libc.acl_free(acl), 0)
        descriptor = os.open(link, os.O_RDONLY | os.O_CLOEXEC | os.O_SYMLINK)
        try:
            self.assertEqual(os.fstat(descriptor).st_ino, link.lstat().st_ino)
            self.assertTrue(has_entry(libc.acl_get_file, os.fsencode(target)))
            self.assertFalse(has_entry(libc.acl_get_link_np, os.fsencode(link)))
            self.assertFalse(has_entry(libc.acl_get_fd_np, descriptor))
            acl = libc.acl_get_file(os.fsencode(target), 0x100)
            self.assertTrue(acl)
            try:
                ctypes.set_errno(0)
                status = libc.acl_set_link_np(os.fsencode(link), 0x100, acl)
                error = ctypes.get_errno()
            finally:
                self.assertEqual(libc.acl_free(acl), 0)
            if status != 0:
                self.assertEqual(status, -1)
                self.assertEqual(error, errno.ENOTSUP)
                self.assertFalse(has_entry(libc.acl_get_link_np, os.fsencode(link)))
                self.assertFalse(has_entry(libc.acl_get_fd_np, descriptor))
                self.assertTrue(has_entry(libc.acl_get_file, os.fsencode(target)))
                print(json.dumps({'capability': 'nonempty-symlink-acl', 'supported': False,
                                  'errno': error, 'path_and_held_empty_acl': 'verified',
                                  'importer_link_acl_refusal': 'NOT EXECUTED: host rejected ACL creation'}), file=sys.stderr)
                return
            run(['/bin/chmod', '-N', target])
            self.assertFalse(has_entry(libc.acl_get_file, os.fsencode(target)))
            self.assertTrue(has_entry(libc.acl_get_link_np, os.fsencode(link)))
            self.assertTrue(has_entry(libc.acl_get_fd_np, descriptor))
            def pair(path):
                info = path.stat(); return [info.st_dev, info.st_ino]
            attempted = []
            result = _image.create_from_tree({'directory': str(source), 'root': pair(source)},
                {'directory': str(destination), 'parent': pair(destination), 'component': 'image.sfs',
                 'before_create': lambda: attempted.append(True)}, 1 << 26)
            self.assertFalse(result['candidate_complete'])
            self.assertEqual(result['reason'], 'unsupported-acl')
            self.assertEqual(result['failure_path'], 'link')
            self.assertFalse(result['creation_attempted'])
            self.assertFalse(attempted)
            self.assertFalse((destination / 'image.sfs').exists())
            print(json.dumps({'capability': 'nonempty-symlink-acl', 'supported': True,
                              'importer_link_acl_refusal': 'verified'}), file=sys.stderr)
        finally:
            os.close(descriptor)

    def test_native_creator_owns_callback_across_path_conversion(self):
        import gc
        import weakref
        from stallionfs import _image
        stage = self.base / 'callback-owner'
        stage.mkdir(mode=0o700)
        source, destination_path = stage / 'input' / 'repo', stage / 'owned'
        source.parent.mkdir(mode=0o700)
        source.mkdir(mode=0o700)
        destination_path.mkdir(mode=0o700)
        (source / 'data').write_bytes(b'callback lifetime')
        def pair(path):
            info = path.stat()
            return [info.st_dev, info.st_ino]
        events = []
        class Callback:
            def __call__(self):
                events.append('called')
            def __del__(self):
                events.append('released')
        destination = {'directory': str(destination_path), 'parent': pair(destination_path),
                       'component': 'image.sfs', 'before_create': Callback()}
        reference = weakref.ref(destination['before_create'])
        class SourcePath:
            def __fspath__(self):
                destination.pop('before_create')
                gc.collect()
                self_alive = reference() is not None
                events.append('retained' if self_alive else 'freed-early')
                return str(source)
        result = _image.create_from_tree({'directory': SourcePath(), 'root': pair(source)}, destination, 1 << 26)
        self.assertTrue(result['candidate_complete'], result)
        self.assertEqual(events, ['retained', 'called', 'released'])
        self.assertIsNone(reference())
        destination['before_create'] = Callback()
        reference = weakref.ref(destination['before_create'])
        with self.assertRaises(ValueError):
            _image.create_from_tree({'directory': str(source), 'root': []}, destination, 1 << 26)
        destination.pop('before_create')
        gc.collect()
        self.assertIsNone(reference(), 'early argument failure leaked owned callback')

    def test_native_explicit_budgets_exhaust_without_false_completion(self):
        from stallionfs import _image
        dimensions = ('raw_cells', 'metadata_read_bytes', 'metadata_hash_bytes',
                      'checks', 'auxiliary_bytes', 'auxiliary_io_bytes')
        for index, dimension in enumerate((None, *dimensions)):
            with self.subTest(dimension=dimension):
                stage = self.base / f'budget-{index}'
                source, destination = stage / 'input' / 'repo', stage / 'owned'
                stage.mkdir(mode=0o700)
                source.parent.mkdir(mode=0o700)
                source.mkdir(mode=0o700)
                destination.mkdir(mode=0o700)
                (source / 'data').write_bytes(b'x' * 8192)
                def pair(path):
                    info = path.stat()
                    return [info.st_dev, info.st_ino]
                attempted = []
                budget = dict.fromkeys(dimensions, (1 << 64) - 1)
                if dimension is not None:
                    budget[dimension] = 1
                result = _image.create_from_tree({'directory': str(source), 'root': pair(source)},
                    {'directory': str(destination), 'parent': pair(destination), 'component': 'image.sfs',
                     'before_create': lambda: attempted.append(True)}, 1 << 26, budget)
                self.assertTrue(attempted)
                self.assertTrue(result['creation_attempted'], result)
                self.assertTrue(result['budget_explicit'], result)
                self.assertTrue((destination / 'image.sfs').exists())
                if dimension is None:
                    self.assertTrue(result['candidate_complete'], result)
                    self.assertTrue(result['verified'], result)
                else:
                    self.assertFalse(result['candidate_complete'], result)
                    self.assertFalse(result['verified'], result)
                    self.assertEqual(result['reason'], 'verification-incomplete', result)
                    receipts = [result.get('original') or {}, result.get('verify') or {}]
                    self.assertTrue(any(receipt.get('status') == 14 and receipt.get('incomplete_reason') for receipt in receipts), result)

    def test_registered_backing_with_held_core_handle_blocks_generic_paths(self):
        from stallionfs import _image
        seed = self.prepare()
        workspace = self.store.create(seed['id'])['id']
        self.store.move(workspace)
        path = self.store.root / 'trash' / workspace
        parent = path / 'repo' / 'private'
        parent.mkdir(mode=0o700)
        stage = self.base / 'held-backing'
        stage.mkdir(mode=0o700)
        source, destination = stage / 'input' / 'repo', stage / 'owned'
        source.parent.mkdir(mode=0o700)
        source.mkdir(mode=0o700)
        destination.mkdir(mode=0o700)
        (source / 'data').write_bytes(b'held backing bytes')
        def pair(item):
            info = item.stat()
            return [info.st_dev, info.st_ino]
        result = _image.create_from_tree({'directory': str(source), 'root': pair(source)},
            {'directory': str(destination), 'parent': pair(destination), 'component': 'image.sfs',
             'before_create': lambda: None}, 1 << 26)
        self.assertTrue(result['candidate_complete'], result)
        backing = parent / 'registered.bin'
        (destination / 'image.sfs').rename(backing)
        registration = self.store.register_native_image(backing)
        original = (pair(path), pair(backing), backing.read_bytes())
        def held(token):
            for action in (lambda: self.store.gc(older_than=0, yes=False, jobs=1),
                           lambda: self.store.gc(older_than=0, yes=True, jobs=1),
                           lambda: self.store.move(workspace, restore=True),
                           lambda: self.store.purge('trash', workspace, yes=True)):
                with self.assertRaisesRegex(StallionError, 'Registered native backing'):
                    action()
                self.assertEqual((pair(path), pair(backing), backing.read_bytes()), original)
        _image.with_backing_guard(registration['native_image'], held)
        self.assertEqual((pair(path), pair(backing), backing.read_bytes()), original)

    @native_creation_test
    def test_native_candidate_outer_lock_errors_keep_store_receipt(self):
        from stallionfs.core import native_failure_details
        seed = self.prepare()
        for lock_name in ('.lock', 'seed-' + seed['id']):
            for cleanup_fails in (False, True):
                with self.subTest(lock=lock_name, cleanup_fails=cleanup_fails):
                    original_open, original_close = os.open, os.close
                    target, injected = [], []
                    closing_error = OSError(errno.EIO, 'outer lock close')
                    raw = {}
                    def capture_open(path, *args, **kwargs):
                        descriptor = original_open(path, *args, **kwargs)
                        if not target and Path(path).name == lock_name:
                            target.append(descriptor)
                        return descriptor
                    def close_fail(descriptor):
                        original_close(descriptor)
                        if target == [descriptor] and not injected:
                            injected.append(True)
                            raise closing_error
                    def create(source, destination, capacity):
                        destination['before_create']()
                        path = Path(destination['directory']) / 'image.sfs'
                        path.write_bytes(b'candidate receipt fixture')
                        info = path.stat()
                        raw.update(candidate_complete=True, import_committed=True, verified=True,
                                   outcome='candidate-created', identity={'file': [info.st_dev, info.st_ino], 'uuid': 'ab' * 16},
                                   anchor={'generation': 2, 'root_digest': 'cd' * 32, 'committed_end': 16384})
                        return raw
                    original_remove = remove_tree
                    def cleanup(path, **kwargs):
                        if cleanup_fails and Path(path).name == 'input':
                            raise OSError(errno.EACCES, 'host cleanup')
                        return original_remove(path, **kwargs)
                    with patch('stallionfs.core.os.open', side_effect=capture_open), \
                         patch('stallionfs.core.os.close', side_effect=close_fail), \
                         patch('stallionfs._image.create_from_tree', side_effect=create), \
                         patch('stallionfs.core.owned_native_target', return_value={}), \
                         patch('stallionfs.core.remove_tree', side_effect=cleanup):
                        with self.assertRaises(OSError) as caught:
                            self.store._build_owned_native_candidate(seed['id'], native_capacity_gib=1)
                    self.assertIs(caught.exception, closing_error)
                    receipt = native_failure_details(caught.exception)
                    self.assertTrue(receipt['candidate_created'])
                    self.assertTrue(receipt['image_verified'])
                    self.assertIs(receipt['native_image_result'], raw)
                    self.assertEqual(receipt['host_cleanup_complete'], not cleanup_fails)
                    self.assertTrue(Path(receipt['candidate'], 'image.sfs').exists())
                    self.assertTrue(Path(receipt['journal']).exists())
                    self.assertEqual(Path(receipt['candidate']).parent, Path(receipt['retained_stage']))
                    self.assertEqual(Path(receipt['host_input']).exists(), cleanup_fails)

    @native_creation_test
    def test_native_candidate_receipt_allocation_fallback_and_primary_error(self):
        from stallionfs.core import native_failure_details
        seed = self.prepare()
        class RefuseReceipt(MemoryError):
            def __setattr__(self, name, value):
                if name in ('native_image_result', 'native_candidate_result'):
                    raise MemoryError('cannot attach response')
                super().__setattr__(name, value)
        primary = RefuseReceipt('primary allocation failure')
        recovered = {'candidate_complete': False, 'creation_attempted': True,
                     'creation_disposition': 'unknown', 'outcome': 'retained-incomplete'}
        primary.native_image_carrier = {'data': bytearray(json.dumps(recovered).encode() + b'\0'),
                                        'snapshot': None, 'recovery': None}
        def no_note(_note):
            raise MemoryError('annotation allocation')
        primary.add_note = no_note
        def create(source, destination, capacity):
            destination['before_create']()
            (Path(destination['directory']) / 'image.sfs').write_bytes(b'unknown')
            raise primary
        original_close, original_open = os.close, os.open
        target, injected = [], []
        def opened(path, *args, **kwargs):
            fd = original_open(path, *args, **kwargs)
            if not target and Path(path).name == 'seed-' + seed['id']:
                target.append(fd)
            return fd
        def closed(fd):
            original_close(fd)
            if target == [fd] and not injected:
                injected.append(True)
                raise OSError(errno.EIO, 'secondary lock close')
        with patch('stallionfs._image.create_from_tree', side_effect=create), \
             patch('stallionfs.core.os.open', side_effect=opened), patch('stallionfs.core.os.close', side_effect=closed):
            with self.assertRaises(RefuseReceipt) as caught:
                self.store._build_owned_native_candidate(seed['id'], native_capacity_gib=1)
        self.assertIs(caught.exception, primary)
        receipt = native_failure_details(caught.exception)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt['lock_close_errno'], errno.EIO)
        self.assertTrue(receipt['native_image_result']['creation_attempted'])
        self.assertEqual(receipt['native_image_result']['creation_disposition'], 'unknown')
        self.assertTrue(Path(receipt['journal']).exists())
        self.assertTrue(Path(receipt['candidate'], 'image.sfs').exists())
        self.assertIsNone(receipt['host_cleanup_complete'])

    def test_native_candidate_capacity_types_refuse_before_stage(self):
        for capacity in (True, False, 0, -1, 65537, 1.0, '1', None):
            with self.subTest(capacity=capacity), self.assertRaises(StallionError):
                self.store._build_owned_native_candidate('0' * 64, native_capacity_gib=capacity)
        self.assertEqual(list((self.store.root / 'staging').iterdir()), [])

    def test_lifecycle_and_git_isolation(self):
        (self.source / ".env").write_text("secret never copied")
        seed = self.prepare(command=[sys.executable, "-c", "from pathlib import Path; p=Path('dependencies'); p.mkdir(); (p/'module').write_text('module')"])
        workspace = self.store.create(seed["id"], name="feature")
        repo = Path(workspace["path"])
        seed_repo = self.store.root / "seeds" / seed["id"] / "repo"
        self.assertFalse((repo / ".env").exists())
        self.assertEqual((repo / "dependencies/module").read_text(), "module")
        self.assertEqual(os.readlink(repo / "link"), "file")
        self.assertTrue(os.access(repo / "executable", os.X_OK))
        self.assertNotEqual((repo / "file").stat().st_ino, (seed_repo / "file").stat().st_ino)
        (repo / "file").write_text("changed\n")
        (repo / "dependencies/module").write_text("changed module")
        self.assertEqual((seed_repo / "file").read_text(), "original\n")
        self.assertEqual((seed_repo / "dependencies/module").read_text(), "module")
        self.assertEqual((self.source / "file").read_text(), "original\n")
        git(repo, "add", "file")
        git(repo, "-c", "user.email=test@example.invalid", "-c", "user.name=Test", "commit", "-m", "Independent change")
        self.assertNotEqual(git(repo, "rev-parse", "HEAD"), seed["commit"])
        self.assertEqual(git(seed_repo, "rev-parse", "HEAD"), seed["commit"])
        self.assertEqual(git(self.source, "status", "--porcelain"), "")
        moved = self.store.move(workspace["id"])
        self.assertFalse(repo.exists())
        self.assertEqual(self.store.gc(older_than=0), [workspace["id"]])
        self.assertTrue(Path(moved["path"]).exists())
        restored = self.store.move(workspace["id"], restore=True)
        self.assertEqual(git(restored["path"], "log", "-1", "--format=%s"), "Independent change")
        self.store.move(workspace["id"])
        self.assertEqual(self.store.gc(older_than=0, yes=True), [workspace["id"]])
        self.assertEqual(self.store.list("trash"), [])

    def test_cache_identity_and_concurrent_prepare(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            seeds = list(pool.map(lambda _: self.prepare(), range(4)))
        self.assertEqual(len({s["id"] for s in seeds}), 1)
        self.assertEqual(sum(not s["cached"] for s in seeds), 1)
        self.assertNotEqual(seeds[0]["id"], self.store.prepare(self.source, key="test-v2")["id"])
        (self.source / "file").write_text("next commit\n")
        git(self.source, "commit", "-am", "Change")
        self.assertNotEqual(self.prepare()["id"], seeds[0]["id"])

    def test_parallel_create_and_process_cli(self):
        seed = self.prepare()["id"]
        command = [sys.executable, "-m", "stallionfs", "--root", str(self.store.root), "--json", "create", seed]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: json.loads(run(command)), range(4)))
        self.assertEqual(len({r["id"] for r in results}), 4)
        for result in results:
            self.assertEqual(git(result["path"], "branch", "--show-current"), result["branch"])
        self.assertEqual(len(self.store.list()), 4)
        self.assertEqual(list((self.store.root / "staging").iterdir()), [])

    def test_worker_limit_is_forwarded_and_invalid_limits_leave_storage_unchanged(self):
        seed = self.prepare()["id"]
        with patch("stallionfs.core.clone_tree", wraps=clone_tree) as copying:
            workspace = self.store.create(seed, jobs=1)
            copying.assert_called_once_with(self.store.root / "seeds" / seed / "repo", ANY, jobs=1)
        self.assertEqual(git(workspace["path"], "branch", "--show-current"), workspace["branch"])
        self.store.move(workspace["id"])
        before = sorted(str(path.relative_to(self.store.root)) for path in self.store.root.rglob("*"))
        for jobs in (0, 5, True, 1.5, "1"):
            with self.subTest(jobs=jobs):
                with self.assertRaises(StallionError): self.store.create(seed, jobs=jobs)
                with self.assertRaises(StallionError): self.store.gc(older_than=0, yes=True, jobs=jobs)
                self.assertEqual(sorted(str(path.relative_to(self.store.root)) for path in self.store.root.rglob("*")), before)
        with patch("stallionfs.core.remove_tree", wraps=remove_tree) as reclaiming:
            self.assertEqual(self.store.gc(older_than=0, yes=True, jobs=1), [workspace["id"]])
            reclaiming.assert_called_once_with(ANY, jobs=1)
            retired = reclaiming.call_args.args[0]
            self.assertEqual(retired.name, "expired")
            self.assertEqual(retired.parent.parent, self.store.root / "staging")
        self.assertEqual(list((self.store.root / "staging").iterdir()), [])

    def test_failure_does_not_publish_partial_seed_or_workspace(self):
        with self.assertRaises(StallionError) as failed:
            self.prepare(command=[sys.executable, "-c", "raise SystemExit(17)"])
        self.assertEqual(self.store.list("seeds"), [])
        retained = set((self.store.root / "staging").iterdir())
        self.assertEqual(len(retained), 1)
        first = next(iter(retained))
        self.assertEqual(failed.exception.__notes__, [f"Unfinished files retained at {first}"])
        self.assertEqual((first / "repo/file").read_text(), "original\n")
        seed = self.prepare()["id"]
        error = OSError(28, "disk full")
        def partial(source, destination, *, jobs=4):
            destination.mkdir()
            (destination / "partial").write_text("partial")
            raise error
        with patch("stallionfs.core.clone_tree", partial), self.assertRaises(OSError) as failed:
            self.store.create(seed)
        self.assertIs(failed.exception, error)
        self.assertEqual(self.store.list(), [])
        added = set((self.store.root / "staging").iterdir()) - retained
        self.assertEqual(len(added), 1)
        second = next(iter(added))
        self.assertEqual((second / "repo/partial").read_text(), "partial")
        self.assertEqual(error.__notes__, [f"Unfinished files retained at {second}"])

    def test_source_and_command_validation(self):
        (self.source / "file").write_text("uncommitted")
        with self.assertRaisesRegex(StallionError, "Commit or stash"):
            self.prepare()
        git(self.source, "checkout", "--", "file")
        with self.assertRaisesRegex(StallionError, "tracked files"):
            self.prepare(command=[sys.executable, "-c", "from pathlib import Path; Path('file').write_text('change')"])
        with self.assertRaisesRegex(StallionError, "overlap"):
            Store(self.source / "storage").prepare(self.source, key="test")

    def test_escaping_symlinks_and_special_files_rejected(self):
        for statement in ("Path('escape').symlink_to('../outside')", "Path('escape').symlink_to('/tmp')", "__import__('os').mkfifo('pipe')"):
            with self.subTest(statement=statement), self.assertRaises(StallionError):
                self.prepare(command=[sys.executable, "-c", f"from pathlib import Path; {statement}"])

    def test_id_paths_storage_permissions_and_corruption(self):
        for value in ("../source", "/", "", "A" * 32):
            with self.assertRaises(StallionError):
                self.store.move(value)
        with self.assertRaises(StallionError):
            self.store.gc(older_than=float("nan"), yes=True)
        insecure = self.base / "insecure"
        insecure.mkdir(mode=0o755)
        insecure.chmod(0o755)
        self.assertEqual(insecure.stat().st_mode & 0o777, 0o755)
        with self.assertRaisesRegex(StallionError, "0700"):
            Store(insecure)
        alias = self.base / "alias"
        alias.symlink_to(self.store.root)
        with self.assertRaisesRegex(StallionError, "symlink"):
            Store(alias)
        seed = self.prepare()["id"]
        meta = self.store.root / "seeds" / seed / "meta.json"
        meta.write_text('{"format": 1, "id": "wrong"}')
        with self.assertRaisesRegex(StallionError, "mismatch"):
            self.store.create(seed)

    def test_trash_symlink_never_deletes_target(self):
        victim = self.base / "victim"
        victim.mkdir()
        (victim / "precious").write_text("keep")
        (self.store.root / "trash" / ("a" * 32)).symlink_to(victim)
        with self.assertRaises(StallionError):
            self.store.gc(older_than=0, yes=True)
        self.assertEqual((victim / "precious").read_text(), "keep")

    def test_gc_excludes_native_registration_through_quarantined_destruction(self):
        from contextlib import contextmanager
        from stallionfs import core, _image
        seed = self.prepare()['id']
        workspace = self.store.create(seed)
        self.store.move(workspace['id'])
        stage = self.base / 'image-stage'; stage.mkdir(mode=0o700)
        source = stage / 'input' / 'repo'; source.parent.mkdir(mode=0o700); source.mkdir(mode=0o700)
        (source / 'file').write_bytes(b'image payload')
        destination = stage / 'owned'; destination.mkdir(mode=0o700)
        def pair(path):
            info = path.stat(); return [info.st_dev, info.st_ino]
        result = _image.create_from_tree({'directory': str(source), 'root': pair(source)},
            {'directory': str(destination), 'parent': pair(destination), 'component': 'image.sfs',
             'before_create': lambda: None}, 1 << 26)
        self.assertTrue(result['candidate_complete'])
        directory = self.store.root / 'trash' / workspace['id'] / 'repo' / 'private'
        directory.mkdir(mode=0o700)
        (destination / 'image.sfs').rename(directory / 'backing.bin')
        quarantined, excluded, resume = threading.Event(), threading.Event(), threading.Event()
        backing, registration_thread = [], []
        original_remove, original_lock = core.remove_tree, core.lock
        def reclaim(path, *, jobs=4):
            backing.append(path / 'repo/private/backing.bin')
            self.assertEqual(pair(backing[0]), result['identity']['file'])
            quarantined.set()
            self.assertTrue(resume.wait(5))
            original_remove(path, jobs=jobs)
        @contextmanager
        def observe_lock(path, **options):
            if registration_thread == [threading.get_ident()] and path == self.store.root / '.lock':
                self.assertFalse(options.get('shared', False))
                with self.assertRaises(BlockingIOError):
                    with original_lock(path, blocking=False):
                        self.fail('Registration acquired exclusive store lock during destruction')
                excluded.set()
            with original_lock(path, **options):
                yield
        def register():
            registration_thread.append(threading.get_ident())
            return self.store.register_native_image(backing[0])
        with patch('stallionfs.core.remove_tree', reclaim), patch('stallionfs.core.lock', observe_lock):
            with ThreadPoolExecutor(max_workers=2) as pool:
                collected = pool.submit(self.store.gc, older_than=0, yes=True)
                try:
                    self.assertTrue(quarantined.wait(5))
                    registered = pool.submit(register)
                    self.assertTrue(excluded.wait(5))
                    self.assertEqual(list((self.store.root / 'workspaces').iterdir()), [])
                finally:
                    resume.set()
                self.assertEqual(collected.result(timeout=10), [workspace['id']])
                with self.assertRaises((FileNotFoundError, StallionError)):
                    registered.result(timeout=10)
        self.assertFalse(backing[0].exists())
        self.assertEqual(self.store.list(), [])
        self.assertEqual(list((self.store.root / 'staging').iterdir()), [])

    def test_parallel_gc_preserves_symlink_targets_and_reports_errors(self):
        seed = self.prepare()["id"]
        victim = self.base / "keep"
        victim.mkdir()
        (victim / "precious").write_text("keep")
        identifiers = []
        for _ in range(4):
            workspace = self.store.create(seed)
            (Path(workspace["path"]) / "external").symlink_to(victim)
            self.store.move(workspace["id"])
            identifiers.append(workspace["id"])
        original = remove_tree
        barrier = threading.Barrier(4, timeout=5)

        def reclaim(path, *, jobs=4):
            self.assertEqual(jobs, 1)  # Four roots share the four-worker budget.
            barrier.wait()  # Fails if reclamation regresses to serial traversal.
            original(path, jobs=jobs)

        with patch("stallionfs.core.remove_tree", reclaim):
            self.assertCountEqual(self.store.gc(older_than=0, yes=True), identifiers)
        self.assertEqual((victim / "precious").read_text(), "keep")
        self.assertEqual(self.store.list("trash"), [])
        workspace = self.store.create(seed)
        (Path(workspace["path"]) / "external").symlink_to(victim)
        self.store.move(workspace["id"])
        expired = self.store.root / "trash" / workspace["id"]
        os.utime(expired, (time.time() - 120,) * 2)
        recent = self.store.create(seed)
        self.store.move(recent["id"])
        failure = PermissionError("denied after partial deletion")

        def partial(path, *, jobs=4):
            self.assertEqual(json.loads((path / "meta.json").read_text())["id"], workspace["id"])
            (path / "meta.json").unlink()
            raise failure

        with patch("stallionfs.core.remove_tree", partial), self.assertRaises(PermissionError) as caught:
            self.store.gc(older_than=60, yes=True)
        self.assertIs(caught.exception, failure)
        retained = list((self.store.root / "staging").iterdir())
        self.assertEqual(len(retained), 1)
        stage = retained[0]
        self.assertFalse(stage.is_symlink())
        self.assertEqual((stage.stat().st_uid, stage.stat().st_mode & 0o777), (os.getuid(), 0o700))
        self.assertEqual(failure.__notes__, [f"Unfinished files retained at {stage}"])
        self.assertFalse(expired.exists())
        self.assertFalse((stage / "expired/meta.json").exists())
        self.assertEqual((stage / "expired/repo/file").read_text(), "original\n")
        self.assertTrue((stage / "expired/repo/external").is_symlink())
        self.assertEqual((victim / "precious").read_text(), "keep")
        self.assertEqual([row["id"] for row in self.store.list("trash")], [recent["id"]])
        self.assertEqual(self.store.gc(older_than=60), [])
        self.assertEqual(self.store.gc(older_than=60, yes=True), [])
        self.assertEqual(list((self.store.root / "staging").iterdir()), retained)
        restored = self.store.move(recent["id"], restore=True)
        self.assertEqual((Path(restored["path"]) / "file").read_text(), "original\n")
        self.assertEqual(self.store.list("trash"), [])

    def test_linked_worktree_source_and_environment_isolation(self):
        linked = self.base / "linked"
        git(self.source, "worktree", "add", "--detach", str(linked), "HEAD")
        seed = self.store.prepare(linked, key="linked")["id"]
        with patch.dict(os.environ, {"GIT_DIR": str(self.source / ".git"), "GIT_WORK_TREE": str(self.source)}):
            result = self.store.create(seed)
        self.assertTrue((Path(result["path"]) / ".git").is_dir())
        self.assertEqual(git(self.source, "branch", "--show-current"), "main")

    def test_doctor_and_cli_errors(self):
        self.assertEqual(self.store.doctor()["isolation"], "passed")
        command = [sys.executable, "-m", "stallionfs", "--root", str(self.store.root), "--json", "remove", "../oops"]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("error", json.loads(result.stderr))

    def test_deleting_seed_preserves_workspaces(self):
        seed = self.prepare()["id"]
        workspace = self.store.create(seed)
        self.assertEqual(self.store.forget(seed), {"would_delete": seed})
        self.store.forget(seed, yes=True)
        self.assertEqual(self.store.list("seeds"), [])
        self.assertEqual(git(workspace["path"], "show", "HEAD:file"), "original")
        self.assertEqual((Path(workspace["path"]) / "file").read_text(), "original\n")

    def test_native_clone_rejects_fallback_and_handles_interruption(self):
        seed = self.prepare()["id"]
        shim = self.base / "unsupported.c"
        shim.write_text('''#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/clonefile.h>
static int unsupported(int a, int b, const char *c, unsigned f) {
    (void)a; (void)b; (void)c; (void)f;
    if (getenv("STALLIONFS_TEST_INTERRUPT")) { raise(SIGINT); errno = EINTR; return -1; }
    errno = ENOTSUP; return -1;
}
__attribute__((used, section("__DATA,__interpose")))
static struct { const void *replacement; const void *original; } interpose = {
    (const void *)unsupported, (const void *)fclonefileat
};
''')
        library = self.base / "unsupported.dylib"
        run(["cc", "-dynamiclib", str(shim), "-o", str(library)])
        program = f'''import errno, os
from pathlib import Path
from stallionfs.core import Store
store = Store({str(self.store.root)!r})
before = set((store.root / "staging").iterdir())
try:
    store.create({seed!r})
except (OSError, KeyboardInterrupt) as exc:
    if os.environ.get("STALLIONFS_TEST_INTERRUPT"):
        assert isinstance(exc, KeyboardInterrupt), exc
    else:
        assert isinstance(exc, OSError) and exc.errno == errno.ENOTSUP, exc
    assert any("Unfinished files retained at" in note for note in exc.__notes__)
else:
    raise AssertionError("unsupported clone silently fell back to copying")
assert store.list() == []
assert len(set((store.root / "staging").iterdir()) - before) == 1
'''
        for fault in ({}, {"STALLIONFS_TEST_INTERRUPT": "1"}):
            result = subprocess.run([sys.executable, "-c", program], capture_output=True, text=True,
                                    env={**os.environ, "DYLD_INSERT_LIBRARIES": str(library), **fault})
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_clone_preserves_metadata_and_never_follows_links(self):
        source = self.base / "clone-source"
        source.mkdir()
        directory = source / "nested"
        directory.mkdir()
        target = directory / "file"
        target.write_bytes(b"original")
        target.chmod(0o754)
        directory.chmod(0o750)
        principal = pwd.getpwuid(os.getuid()).pw_name
        for path in (source, directory, target):
            run(["xattr", "-w", "com.stallionfs.test", "metadata", path])
            run(["chmod", "+a", f"user:{principal} allow read,write", path])
        (source / "external").symlink_to(self.source, target_is_directory=True)
        (source / "dangling").symlink_to("absent")
        os.utime(target, ns=(1_700_000_000_123456789,) * 2)
        os.utime(directory, ns=(1_700_000_000_987654321,) * 2)
        destination = self.base / "clone-destination"
        clone_tree(source, destination)
        for path in (source, directory, target):
            copied = destination / path.relative_to(source)
            self.assertEqual(copied.stat().st_mode, path.stat().st_mode)
            self.assertEqual(copied.stat().st_mtime_ns, path.stat().st_mtime_ns)
            self.assertEqual(run(["xattr", "-p", "com.stallionfs.test", copied]), "metadata")
            self.assertEqual(run(["ls", "-lde", copied]).splitlines()[1:], run(["ls", "-lde", path]).splitlines()[1:])
        self.assertEqual(os.readlink(destination / "external"), str(self.source))
        self.assertEqual(os.readlink(destination / "dangling"), "absent")
        (destination / "nested/file").write_bytes(b"changed")
        self.assertEqual(target.read_bytes(), b"original")
        with self.assertRaises(FileExistsError):
            clone_tree(source, destination)
        with self.assertRaises(OSError):
            clone_tree(source / "external", self.base / "must-not-exist")
        self.assertFalse((self.base / "must-not-exist").exists())
        os.mkfifo(source / "fifo")
        with self.assertRaises(OSError) as error:
            clone_tree(source, self.base / "unsupported")
        self.assertEqual(error.exception.errno, errno.ENOTSUP)

    def test_interrupted_preparation_is_not_cached(self):
        marker = self.base / "started"
        setup = f"from pathlib import Path; import time; Path({str(marker)!r}).touch(); time.sleep(20)"
        command = [sys.executable, "-m", "stallionfs", "--root", str(self.store.root), "--json",
                   "prepare", str(self.source), "--key", "interrupt", "--", sys.executable, "-c", setup]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists())
            process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 130)
            self.assertEqual(stdout, "")
            self.assertEqual(self.store.list("seeds"), [])
            retained = list((self.store.root / "staging").iterdir())
            self.assertEqual(len(retained), 1)
            self.assertEqual(json.loads(stderr), {"error": "interrupted", "notes": [f"Unfinished files retained at {retained[0]}"]})
            self.assertEqual((retained[0] / "repo/file").read_text(), "original\n")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_cli_plain_interrupt_preserves_notes(self):
        from stallionfs.__main__ import main

        interrupted = KeyboardInterrupt()
        note = f"Unfinished files retained at {self.store.root / 'staging/build-test'}"
        interrupted.add_note(note)
        with patch.object(Store, "prepare", side_effect=interrupted), \
                patch("sys.stdout", new_callable=StringIO) as stdout, \
                patch("sys.stderr", new_callable=StringIO) as stderr:
            status = main(["--root", str(self.store.root), "prepare", str(self.source), "--key", "interrupt"])
        self.assertEqual(status, 130)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), f"stallionfs: interrupted\n{note}\n")

    def test_failed_setup_retains_files_used_by_descendant(self):
        owned = Path(tempfile.mkdtemp(prefix="stallionfs-descendant-")).resolve()
        observer = '''from pathlib import Path
import sys, time
root = Path(sys.argv[1])
deadline = time.monotonic() + 4
(root / 'ready').touch()
while not (root / 'stop').exists() and time.monotonic() < deadline:
    if not Path('file').is_file(): (root / 'missing').touch()
    time.sleep(0.01)
(root / 'finished').touch()
'''
        setup = f'''from pathlib import Path
import subprocess, sys, time
root = Path({str(owned)!r})
subprocess.Popen([sys.executable, '-I', '-B', '-c', {observer!r}, str(root)],
                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
deadline = time.monotonic() + 2
while not (root / 'ready').exists():
    if time.monotonic() >= deadline: raise RuntimeError('Observer startup timeout')
    time.sleep(0.01)
raise SystemExit(17)
'''
        try:
            command = [sys.executable, '-I', '-B', '-m', 'stallionfs', '--json', '--root', str(owned / 'store'),
                       'prepare', str(self.source), '--key', 'descendant', '--', sys.executable, '-I', '-B', '-c', setup]
            failed = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(failed.returncode, 1, failed.stderr)
            self.assertEqual(failed.stdout, '')
            error = json.loads(failed.stderr)
            retained = list((owned / 'store/staging').iterdir())
            self.assertEqual(len(retained), 1)
            self.assertEqual(error['notes'], [f'Unfinished files retained at {retained[0]}'])
            self.assertEqual((retained[0] / 'repo/file').read_text(), 'original\n')
            self.assertFalse((owned / 'finished').exists(), 'Observer exited before failure was checked')
            time.sleep(0.05)
            self.assertFalse((owned / 'missing').exists(), 'Setup failure deleted files used by its descendant')
        finally:
            (owned / 'stop').touch()
            deadline = time.monotonic() + 5
            while not (owned / 'finished').exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if (owned / 'finished').exists():
                # The marker is the observer's final filesystem operation.
                remove_tree(owned)
            else:
                raise RuntimeError(f'Observer completion unknown; retained fixture at {owned}')

    def test_relocatable_git_and_trash_age(self):
        with self.assertRaisesRegex(StallionError, "core.worktree"):
            self.prepare(command=["git", "config", "core.worktree", str(self.source)])
        seed = self.prepare()["id"]
        workspace = self.store.create(seed)
        moved = self.store.move(workspace["id"])
        self.assertEqual(self.store.gc(), [])
        path = Path(moved["path"]).parent
        old = time.time() - 2 * 86400
        os.utime(path, (old, old))
        self.assertEqual(self.store.gc(), [workspace["id"]])


if __name__ == "__main__":
    unittest.main()
