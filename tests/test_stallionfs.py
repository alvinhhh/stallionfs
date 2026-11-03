"""Run on APFS: python3 -m unittest discover -s tests -v."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import errno
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
        with patch('stallionfs._native.qualify', return_value='stallionfs'), \
             patch('stallionfs._native.execute_owned', side_effect=command), \
             patch('stallionfs._scan.mounts', side_effect=rows), \
             patch('stallionfs._scan.mount_for_descriptor', side_effect=descriptor, create=True), \
             patch('stallionfs._native.os.open', side_effect=opened), \
             patch('stallionfs._native.os.close', side_effect=closed):
            yield state

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
            for action in (lambda: self.store.move(first['id']), lambda: self.store.snapshot(first['id']),
                           lambda: self.store.snapshots(first['id']), lambda: self.store.rollback(first['id'], 'x'),
                           lambda: self.store.enroll(first['id']), lambda: self.store.close(first['id'], quiescent=True),
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
        from stallionfs import _native
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
                    'signing_identifier': 'com.alvinhhh.stallionfs.module', 'team_identifier': 'FIXTURE'}
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
                ('verify-package', ['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)]),
                ('discover', [str(host), '--discover-json'])])
            variants = [('disabled', {'enabled': False}), ('wrong-url', {'url': '/different/module'}),
                        ('signature', {'signature_status': -1}), ('team', {'team_identifier': None}),
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
        with self.native_controller_fixture():
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
