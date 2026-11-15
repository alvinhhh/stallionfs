"""Installation recovery must precede a new ordinary-use generation."""
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock


class NativeInstallOrder(unittest.TestCase):
    def setUp(self):
        # Load the actual Python methods in a separate package. Native extensions
        # and external commands are unavailable in these state-ordering tests.
        self.package = '_native_install_order_' + str(id(self))
        source = Path(__file__).resolve().parents[1] / 'stallionfs'
        package = ModuleType(self.package)
        package.__path__ = [str(source)]
        sys.modules[self.package] = package
        self.addCleanup(self.unload_modules)

        def unavailable(*args, **kwargs):
            raise AssertionError('Native helper is outside this test')

        for name in ('_scan', '_image'):
            module = ModuleType(self.package + '.' + name)
            module.__path__ = []
            module.__getattr__ = unavailable
            if name == '_scan':
                module._private_directory = unavailable
            sys.modules[module.__name__] = module
            setattr(package, name, module)

        def load(name):
            qualified = self.package + '.' + name
            spec = importlib.util.spec_from_file_location(qualified, source / (name + '.py'))
            module = importlib.util.module_from_spec(spec)
            sys.modules[qualified] = module
            setattr(package, name, module)
            spec.loader.exec_module(module)
            return module

        self.core = load('core')
        self.lifecycle = sys.modules[self.package + '.lifecycle']
        self.native = load('_native')
        self.recovery = load('_native_create_recovery')
        self.temporary = tempfile.TemporaryDirectory(prefix='native-install-order-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        for name in ('workspaces', 'lifecycle', 'journals', 'protected'):
            (self.root / name).mkdir(mode=0o700)
        self.workspace = '1' * 32
        self.path = self.root / 'workspaces' / self.workspace
        self.path.mkdir(mode=0o700)
        (self.path / 'image.sfs').touch(mode=0o600)
        self.metadata = {
            'id': self.workspace, 'backend': 'native-image', 'ownership': 'store-created',
            'state': 'installed-unconfirmed',
            'native_image': {'object': self.lifecycle.identity(self.path),
                             'file': self.lifecycle.identity(self.path / 'image.sfs')},
        }
        self.expected = {
            'id': self.workspace, 'generation': 'a' * 32, 'status': 'open', 'enrolled': False,
            'object': self.metadata['native_image']['object'],
            'payload': self.metadata['native_image']['file'],
        }
        self.intent = {'installation': {'lifecycle': dict(self.expected)}}
        self.journal = self.root / 'journals' / (self.workspace + '.json')
        self.lifecycle.replace_json(self.journal, self.intent)
        self.lifecycle.replace_json(self.path / 'meta.json', self.metadata)
        self.events = []
        self.locked = self.leased = False
        self.store = self.core.Store.__new__(self.core.Store)
        self.store.root = self.root
        self.store.object = lambda *args: (self.path, self.core.read_json(self.path / 'meta.json'))
        self.store._payload = lambda *args: self.path / 'image.sfs'
        self.store._workspace_lock = self.workspace_lock
        self.store._lease = self.lease
        self.store._reconcile = lambda *args: None
        self.store._mount = self.mount
        original_open = self.store._open

        def opened(*args, **kwargs):
            self.assertTrue(self.locked)
            self.events.append('open')
            return original_open(*args, **kwargs)

        self.store._open = opened
        for target, name, replacement in (
            (self.native, 'recover_install', self.recover),
            (self.core, 'lock', self.workspace_lock),
            (self.core, 'private_directory', self.private_directory),
            (self.lifecycle, 'subprocess', SimpleNamespace(run=self.command)),
        ):
            patch = mock.patch.object(target, name, replacement)
            patch.start()
            self.addCleanup(patch.stop)

    def unload_modules(self):
        for name in list(sys.modules):
            if name == self.package or name.startswith(self.package + '.'):
                del sys.modules[name]

    def private_directory(self, path):
        # The native ACL checker is outside this ordering test. Limit its
        # substitute to the newly created private test tree.
        path = Path(path)
        self.assertTrue(path == self.root or path.is_relative_to(self.root))
        info = path.lstat()
        self.assertTrue(stat.S_ISDIR(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
        self.assertEqual(info.st_uid, os.getuid())

    @contextmanager
    def workspace_lock(self, *args, **kwargs):
        self.assertFalse(self.locked)
        self.locked = True
        try:
            yield
        finally:
            self.locked = False

    @contextmanager
    def lease(self, *args):
        self.leased = True
        try:
            yield 123
        finally:
            self.leased = False

    def recover(self, store, path, metadata):
        self.assertTrue(self.locked)
        self.events.append('recover')
        admission = self.recovery.Admission(self.root)
        try:
            # Use the real producer-generation predicate and durable publisher.
            self.recovery.publish_lifecycle(admission, self.metadata, self.expected)
        finally:
            admission.close()
        self.lifecycle.replace_json(path / 'meta.json', dict(metadata, state='installed'))

    def mount(self, path, metadata):
        self.assertTrue(self.locked)
        self.events.append('mount')
        state = self.core.read_json(self.store._state(self.workspace))
        self.assertEqual(state['status'], 'open')
        self.assertNotEqual(state['generation'], self.expected['generation'])
        if metadata.get('ownership') == 'store-created':
            self.assertEqual(metadata['state'], 'installed')
        return {'path': str(path / 'repo')}

    def command(self, argv, **kwargs):
        self.assertFalse(self.locked)
        self.assertTrue(self.leased)
        self.events.append('command')
        return SimpleNamespace(returncode=0)

    def invoke(self, method):
        if method == 'mount':
            return self.store.mount(self.workspace)
        return self.store.run(self.workspace, ['synthetic-command'])

    def test_mount_recovers_frozen_generation_before_open(self):
        before = self.journal.read_bytes()
        self.invoke('mount')
        self.assertEqual(self.events, ['recover', 'open', 'mount'])
        self.assertEqual(self.journal.read_bytes(), before)

    def test_run_recovers_before_open_and_launches_only_with_lease(self):
        before = self.journal.read_bytes()
        self.invoke('run')
        self.assertEqual(self.events, ['recover', 'open', 'mount', 'command'])
        self.assertEqual(self.journal.read_bytes(), before)

    def test_matching_durable_producer_generation_is_preserved_through_recovery(self):
        self.lifecycle.replace_json(self.store._state(self.workspace), self.expected)
        self.invoke('mount')
        self.assertEqual(self.events, ['recover', 'open', 'mount'])

    def test_foreign_generation_refuses_without_writes_or_launch(self):
        self.lifecycle.replace_json(self.store._state(self.workspace), dict(self.expected, generation='b' * 32))
        paths = (self.journal, self.store._state(self.workspace), self.path / 'meta.json')
        before = [path.read_bytes() for path in paths]
        for method in ('mount', 'run'):
            with self.subTest(method=method), self.assertRaisesRegex(self.recovery.Refusal, 'lifecycle-generation-conflict'):
                self.invoke(method)
            self.assertEqual(self.events, ['recover'])
            self.assertEqual([path.read_bytes() for path in paths], before)
            self.events.clear()

    def test_recovery_error_cannot_publish_generation_or_launch(self):
        before = self.journal.read_bytes()
        for method in ('mount', 'run'):
            with self.subTest(method=method), mock.patch.object(self.native, 'recover_install', side_effect=OSError('recovery refused')):
                with self.assertRaisesRegex(OSError, 'recovery refused'):
                    self.invoke(method)
            self.assertFalse(self.store._state(self.workspace).exists())
            self.assertEqual(self.journal.read_bytes(), before)
            self.assertEqual(self.events, [])

    def test_non_native_order_does_not_recover(self):
        self.lifecycle.replace_json(self.path / 'meta.json', {'id': self.workspace, 'backend': 'folder'})
        for method in ('mount', 'run'):
            with self.subTest(method=method):
                self.invoke(method)
            self.assertEqual(self.events, ['open', 'mount'] + (['command'] if method == 'run' else []))
            self.events.clear()

    def test_external_native_registration_does_not_recover_installation(self):
        self.lifecycle.replace_json(self.path / 'meta.json', dict(self.metadata, ownership='external-reference'))
        for method in ('mount', 'run'):
            with self.subTest(method=method), mock.patch.object(self.store, '_mount', side_effect=self.core.StallionError('external mount refused')):
                with self.assertRaisesRegex(self.core.StallionError, 'external mount refused'):
                    self.invoke(method)
            self.assertEqual(self.events, ['open'])
            self.events.clear()

    def test_mount_failure_retains_open_generation_without_command(self):
        with mock.patch.object(self.store, '_mount', side_effect=OSError('mount response lost')):
            with self.assertRaisesRegex(OSError, 'mount response lost'):
                self.invoke('run')
        self.assertEqual(self.events, ['recover', 'open'])
        self.assertEqual(self.core.read_json(self.store._state(self.workspace))['status'], 'open')


if __name__ == '__main__':
    unittest.main()
