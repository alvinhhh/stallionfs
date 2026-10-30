"""Mocks only: no disk-image commands, mounts, or diagnostic subprocesses."""
import errno
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import tempfile
import time
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

if __package__:
    from . import image_failure_diagnostics as diagnostics
    from . import test_image_store as lifecycle
    from . import test_fileops as fileops
    from . import test_images_space as space
else:
    import image_failure_diagnostics as diagnostics
    import test_image_store as lifecycle
    import test_fileops as fileops
    import test_images_space as space


def captured(stdout=b'', stderr=b'', status=0, **extra):
    return dict(stdout=stdout, stderr=stderr, returncode=status, timeout=False,
                truncated=False, reaped=True, capture_error=None, cleanup_error=None, **extra)


class DirectImageFixtureTests(unittest.TestCase):
    def file_fixture(self):
        fixture = fileops.FileOperations()
        fixture.setUp()
        self.addCleanup(shutil.rmtree, fixture.base, ignore_errors=True)
        return fixture

    def assert_scope(self, base, image, point, stage):
        self.assertEqual(diagnostics._scope.get(), dict(base=base, image=image, workspace=None,
                         mountpoint=point, stage=stage, expected=False))

    def run_file_body(self, fixture):
        method = fileops.FileOperations.test_actual_mounted_subtree_refused_and_cross_volume_clone_move_fail
        getattr(method, '__wrapped__', method)(fixture)

    def test_failed_build_registers_image_before_return_and_retains_attached_base(self):
        fixture = self.file_fixture()
        image, point = fixture.base / 'test.sparseimage', fixture.base / 'victim/mounted'
        primary = OSError('build failed before returning')
        def build(source, destination, capacity):
            self.assertEqual(fixture.images, {image: point})
            self.assert_scope(fixture.base, image, None, 'preparation')
            destination.write_bytes(b'backing image')
            raise primary
        with patch.object(fileops.images, 'build', side_effect=build), \
                patch.object(fileops.images, 'attach') as attach, \
                patch.object(fileops.images, 'detach') as detach:
            with self.assertRaises(OSError) as caught:
                self.run_file_body(fixture)
            self.assertIs(caught.exception, primary)
            attach.assert_not_called()
            detach.assert_not_called()
        self.assertIsNone(diagnostics._scope.get())
        self.check_file_cleanup_retains(fixture, dict(mountpoint=None, device='/dev/disk999'))
        self.assertTrue(image.exists())

    def check_file_cleanup_retains(self, fixture, state):
        image = fixture.base / 'test.sparseimage'
        fixture.images[image] = fixture.base / 'victim/mounted'
        def inspect(actual):
            self.assertEqual(actual, image)
            self.assert_scope(fixture.base, image, fixture.images[image], 'cleanup')
            if isinstance(state, BaseException):
                raise state
            return state
        with patch.object(fileops.images, 'mounted', side_effect=inspect), \
                patch.object(fileops._scan, 'mounts') as mounts, \
                patch.object(fileops.os, 'walk') as walk, \
                patch.object(fileops.os, 'chmod') as chmod, \
                patch.object(fileops.shutil, 'rmtree') as remove:
            with self.assertRaises((RuntimeError, OSError)):
                fixture.tearDown()
            for operation in (mounts, walk, chmod, remove):
                operation.assert_not_called()
        self.assertTrue(fixture.base.exists())
        self.assertIsNone(diagnostics._scope.get())

    def test_attachment_inspection_error_retains_base_before_traversal(self):
        self.check_file_cleanup_retains(self.file_fixture(), OSError('inspection failed'))

    def test_confirmed_detached_image_still_requires_native_mount_check(self):
        for mounted in (False, True):
            with self.subTest(mounted=mounted):
                fixture = self.file_fixture()
                image = fixture.base / 'test.sparseimage'
                fixture.images[image] = fixture.base / 'victim/mounted'
                native = [dict(path=str(fixture.base / 'unexpected'))] if mounted else []
                with patch.object(fileops.images, 'mounted', return_value=None), \
                        patch.object(fileops._scan, 'mounts', return_value=native), \
                        patch.object(fileops.os, 'walk', return_value=[]) as walk, \
                        patch.object(fileops.shutil, 'rmtree') as remove:
                    if mounted:
                        with self.assertRaises(RuntimeError): fixture.tearDown()
                        walk.assert_not_called()
                        remove.assert_not_called()
                    else:
                        fixture.tearDown()
                        remove.assert_called_once_with(fixture.base)
                self.assertIsNone(diagnostics._scope.get())

    def test_body_and_cleanup_scopes_preserve_original_exception(self):
        fixture = self.file_fixture()
        image, point = fixture.base / 'test.sparseimage', fixture.base / 'victim/mounted'
        primary = AssertionError('body failure')
        def attach(actual, mounted):
            self.assert_scope(fixture.base, image, point, 'body')
            raise primary
        def inspect(actual):
            self.assert_scope(fixture.base, image, point, 'cleanup')
            raise OSError('cleanup failed')
        with patch.object(fileops.images, 'build'), \
                patch.object(fileops.images, 'attach', side_effect=attach), \
                patch.object(fileops.images, 'mounted', side_effect=inspect):
            with self.assertRaises(AssertionError) as caught:
                self.run_file_body(fixture)
        self.assertIs(caught.exception, primary)
        self.assertIn('cleanup failed', '\n'.join(primary.__notes__))
        self.assertIsNone(diagnostics._scope.get())

    def test_space_failed_setup_has_preparation_scope_and_registered_cleanup(self):
        fixture = space.ImageSpace()
        primary = OSError('build failed')
        def build(source, image, capacity):
            self.addCleanup(shutil.rmtree, fixture.base, ignore_errors=True)
            self.assertTrue(fixture._cleanups)
            self.assert_scope(fixture.base, image, None, 'preparation')
            raise primary
        with patch.object(space.shutil, 'disk_usage', return_value=SimpleNamespace(free=4 * 1024 ** 3)), \
                patch.object(space, 'fullsync', side_effect=lambda path, value: path.write_bytes(value)), \
                patch.object(space.subprocess, 'run'), \
                patch.object(space.images, 'build', side_effect=build):
            with self.assertRaises(OSError) as caught: fixture.setUp()
        self.assertIs(caught.exception, primary)
        self.assertIsNone(diagnostics._scope.get())

    def test_space_body_scopes_full_sibling_and_seed_separately(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = space.ImageSpace()
            fixture.base = Path(temporary).resolve()
            fixture.source = fixture.base / 'source'
            fixture.seed = fixture.base / 'seed.sparseimage'
            fixture.image_points = {}
            repo, untouched = fixture.base / 'repo', fixture.base / 'untouched'
            repo.mkdir(); untouched.mkdir()
            filler = repo / 'filler'
            filler.touch()
            stream = Mock()
            stream.write.side_effect = [1, OSError(errno.ENOSPC, 'mock disk full')]
            opened = Mock()
            opened.__enter__ = Mock(return_value=stream)
            opened.__exit__ = Mock(return_value=False)
            original_open = Path.open
            def open_path(path, *args, **kwargs):
                return opened if path == filler else original_open(path, *args, **kwargs)
            def clone(seed, image):
                self.assert_scope(fixture.base, image, None, 'preparation')
            def digest(image):
                self.assert_scope(fixture.base, image, None, 'body')
                return 'unchanged'
            seen = []
            def attach(image, point):
                self.assert_scope(fixture.base, image, point, 'body')
                seen.append(image.name)
                return repo if image.name == 'full.sparseimage' else untouched
            def detach(image, point):
                self.assert_scope(fixture.base, image, point, 'body')
            with patch.object(space.images, 'clone', side_effect=clone), \
                    patch.object(space, 'digest', side_effect=digest), \
                    patch.object(space.images, 'attach', side_effect=attach), \
                    patch.object(space.images, 'detach', side_effect=detach), \
                    patch.object(fixture, 'assert_original'), \
                    patch.object(space, 'fullsync', side_effect=lambda path, value: path.write_bytes(value)), \
                    patch.object(Path, 'open', open_path), patch('builtins.print'):
                fixture.test_volume_full_preserves_existing_data_and_other_images()
            self.assertEqual(seen, ['full.sparseimage', 'full.sparseimage', 'sibling.sparseimage', 'seed.sparseimage'])
            self.assertIsNone(diagnostics._scope.get())

    def test_space_cleanup_scopes_each_image_and_resets_after_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = space.ImageSpace()
            fixture.base = Path(temporary).resolve()
            fixture.image_points = {}
            for name in ('seed', 'sibling'):
                image = fixture.base / f'{name}.sparseimage'
                image.touch()
                fixture.image_points[image] = fixture.base / name
            seen = []
            def inspect(image):
                self.assert_scope(fixture.base, image, fixture.image_points[image], 'cleanup')
                seen.append(image)
                return dict(mountpoint=None) if seen.count(image) == 1 else None
            def detach(image, point):
                self.assert_scope(fixture.base, image, point, 'cleanup')
            with patch.object(space.images, 'mounted', side_effect=inspect), \
                    patch.object(space.images, 'detach', side_effect=detach) as detached, \
                    patch.object(space.os, 'walk', return_value=[]), \
                    patch.object(space.shutil, 'rmtree') as remove:
                fixture.clean()
                self.assertEqual(detached.call_count, 2)
                remove.assert_called_once_with(fixture.base)
                remove.reset_mock()
                with patch.object(space.images, 'mounted', side_effect=OSError('inspection failed')):
                    with self.assertRaisesRegex(RuntimeError, 'Test files retained'):
                        fixture.clean()
                remove.assert_not_called()
            self.assertIsNone(diagnostics._scope.get())


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.base = Path('/owned-fixture')
        self.ids = ['a' * 32, 'b' * 32, 'c' * 32]
        self.store = Mock(root=self.base / 'store')
        self.store.list.return_value = [dict(id=i, backend='image',
            path=str(self.store.root / 'workspaces' / i / 'volume/repo')) for i in self.ids]
        self.remove = patch.object(lifecycle, 'remove_tree').start()
        self.addCleanup(patch.stopall)

    def test_primary_identity_traceback_and_multiple_cleanup_errors(self):
        primary = AssertionError('original assertion')
        self.store.unmount.side_effect = [OSError('first cleanup'), OSError('second cleanup'), None]
        def body():
            raise primary
        try:
            with lifecycle.image_fixture(self.store, self.base):
                body()
        except AssertionError as actual:
            self.assertIs(actual, primary)
            self.assertEqual(traceback.extract_tb(actual.__traceback__)[-1].name, 'body')
            self.assertIn('first cleanup', '\n'.join(actual.__notes__))
            self.assertIn('second cleanup', '\n'.join(actual.__notes__))
        else:
            self.fail('primary exception lost')
        self.assertEqual(self.store.unmount.call_args_list, [call(i) for i in self.ids])
        self.remove.assert_not_called()

    def test_cleanup_only_keeps_first_exception_and_traceback(self):
        first, second = OSError('first'), OSError('second')
        self.store.unmount.side_effect = [first, second, None]
        try:
            with lifecycle.image_fixture(self.store, self.base):
                pass
        except OSError as error:
            self.assertIs(error, first)
            self.assertIn('cleanup', [f.name for f in traceback.extract_tb(error.__traceback__)])
            self.assertIn('second', '\n'.join(error.__notes__))
        else:
            self.fail('cleanup exception lost')
        self.remove.assert_not_called()

    def test_failed_workspace_not_retried_other_owned_once(self):
        self.store.unmount.side_effect = [OSError('busy'), None, None]
        with self.assertRaisesRegex(OSError, 'busy'):
            with lifecycle.image_fixture(self.store, self.base) as fixture:
                fixture.call(self.store.unmount, self.ids[0], workspace=self.ids[0])
        self.assertEqual(self.store.unmount.call_args_list, [call(i) for i in self.ids])
        self.remove.assert_not_called()

    def test_explicit_body_and_cleanup_context(self):
        seen = []
        self.store.unmount.side_effect = lambda identifier: seen.append(dict(diagnostics._scope.get()))
        with lifecycle.image_fixture(self.store, self.base) as fixture:
            fixture.call(self.store.unmount, self.ids[0], workspace=self.ids[0])
        self.assertEqual([scope['stage'] for scope in seen], ['body', 'cleanup', 'cleanup', 'cleanup'])
        self.assertEqual([scope['workspace'] for scope in seen], [self.ids[0], *self.ids])
        for scope in seen:
            expected = self.store.root / 'workspaces' / scope['workspace']
            self.assertEqual(scope['image'], expected / 'workspace.sparseimage')
            self.assertEqual(scope['mountpoint'], expected / 'volume')
        self.assertIsNone(diagnostics._scope.get())

    def test_expected_busy_does_not_skip_later_cleanup(self):
        self.store.move.side_effect = OSError('intentional busy')
        with lifecycle.image_fixture(self.store, self.base) as fixture:
            with self.assertRaises(OSError):
                fixture.call(self.store.move, self.ids[0], workspace=self.ids[0], expected='busy')
            self.assertFalse(fixture.failed)
        self.assertEqual(self.store.unmount.call_args_list, [call(i) for i in self.ids])
        self.remove.assert_called_once_with(self.base)

    def test_unknown_operation_and_bad_list_retain(self):
        for bad in (OSError('list failed'), [{'id': '../outside', 'backend': 'image'}],
                    [self.store.list.return_value[0]] * 2):
            with self.subTest(bad=bad):
                self.store.list.side_effect = bad if isinstance(bad, Exception) else None
                if not isinstance(bad, Exception):
                    self.store.list.return_value = bad
                with self.assertRaises((OSError, lifecycle.StallionError)):
                    with lifecycle.image_fixture(self.store, self.base):
                        pass
                self.store.unmount.assert_not_called()
                self.remove.assert_not_called()

    def test_unknown_failed_operation_stops_uncertain_cleanup(self):
        operation = Mock(side_effect=OSError('unknown create outcome'))
        with self.assertRaises(OSError):
            with lifecycle.image_fixture(self.store, self.base) as fixture:
                fixture.call(operation)
        self.store.list.assert_not_called()
        self.store.unmount.assert_not_called()
        self.remove.assert_not_called()

    def test_attached_unmounted_or_inspection_error_keeps_base(self):
        for error in (lifecycle.StallionError('attached device without mount; detach refused'),
                      OSError('attachment inspection failed')):
            with self.subTest(error=error):
                self.store.unmount.side_effect = error
                with self.assertRaises(type(error)):
                    with lifecycle.image_fixture(self.store, self.base):
                        pass
                self.remove.assert_not_called()

    def test_body_and_cleanup_interrupts_stop_cleanup(self):
        for error in (KeyboardInterrupt(), SystemExit(3)):
            with self.subTest(error=error):
                self.store.unmount.reset_mock()
                with self.assertRaises(type(error)):
                    with lifecycle.image_fixture(self.store, self.base):
                        raise error
                self.store.unmount.assert_not_called()
                self.store.unmount.side_effect = error
                with self.assertRaises(type(error)):
                    with lifecycle.image_fixture(self.store, self.base):
                        pass
                self.store.unmount.assert_called_once()
                self.remove.assert_not_called()

    def test_reporting_failure_cannot_replace_primary(self):
        class NoteFailure(AssertionError):
            def add_note(self, note):
                raise OSError('notes failed')
        error = NoteFailure('body')
        with self.assertRaises(NoteFailure) as caught:
            with lifecycle.image_fixture(self.store, self.base):
                raise error
        self.assertIs(caught.exception, error)
        self.remove.assert_not_called()


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='image-diagnostic-mock-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.image = self.base / 'workspace.sparseimage'
        self.image.write_bytes(b'mock, not a disk image')
        self.image.chmod(0o600)
        self.point = self.base / 'volume'
        self.point.mkdir(mode=0o700)
        self.reporter = diagnostics.Diagnostics(self.base / 'diagnostics')
        self.addCleanup(self.reporter.close)
        # A missed mock must fail before any actual command can start.
        self.spawn = patch.object(diagnostics.subprocess, 'Popen', side_effect=AssertionError('unmocked subprocess')).start()
        self.addCleanup(patch.stopall)
        self.args = ('/usr/bin/hdiutil', 'detach', '/dev/disk999')
        self.record = {'owner-uid': os.getuid(), 'image-path': str(self.image),
                       'system-entities': [{'dev-entry': '/dev/disk999'}]}

    def scope(self, **changes):
        return dict(base=self.base, image=self.image, workspace='a' * 32, mountpoint=self.point,
                    stage='body', expected=False) | changes

    def events(self):
        return [json.loads(s) for s in (self.reporter.directory / diagnostics.REPORT).read_text().splitlines()]

    def mapping_capture(self, records=None, native=None):
        return [captured(plistlib.dumps({'images': records if records is not None else [self.record]})),
                captured(json.dumps(native or []).encode()),
                captured(b'p10\ncworker\nf3\ntREG\nn' + str(self.image).encode() + b'\n', b'partial visibility\n', 1)]

    def test_unmounted_attachment_exact_targets_and_exit1_output(self):
        with patch.object(self.reporter, '_capture', side_effect=self.mapping_capture()) as capture:
            self.reporter.report(self.args, OSError('resource busy'), self.scope())
        self.assertEqual(capture.call_count, 3)
        command = capture.call_args_list[-1].args[0]
        self.assertEqual(command[-3:], ['--', str(self.image), '/dev/disk999'])
        self.assertNotIn('+f', command)
        self.assertNotIn(str(self.point), command)
        event = self.events()[-1]
        self.assertEqual(event['returncode'], 1)
        self.assertIn('p10', event['stdout'])
        self.assertIn('partial visibility', event['stderr'])
        self.assertIsNone(self.events()[1]['mountpoint'])
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_physical_and_synthesized_apfs_devices_mounted_and_unmounted(self):
        devices = ['/dev/disk2', '/dev/disk2s1', '/dev/disk3', '/dev/disk3s1']
        real_stat = os.stat
        def device_stat(path, *args, **kwargs):
            if kwargs.get('follow_symlinks') is not False:
                if str(path) == devices[-1]:
                    return SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=42)
                if str(path) == str(self.point):
                    return SimpleNamespace(st_dev=42)
            return real_stat(path, *args, **kwargs)
        for mounted in (True, False):
            with self.subTest(mounted=mounted):
                entities = [{'dev-entry': d} for d in devices]
                if mounted:
                    entities[-1]['mount-point'] = str(self.point)
                record = dict(self.record, **{'system-entities': entities})
                native = [{'device': devices[-1], 'path': str(self.point), 'filesystem': 'apfs'}] if mounted else []
                values = self.mapping_capture([record], native) + ([captured(status=1)] if mounted else [])
                with patch.object(self.reporter, '_capture', side_effect=values) as capture, \
                        patch.object(diagnostics.os.path, 'ismount', return_value=mounted), \
                        patch.object(diagnostics.os, 'stat', side_effect=device_stat):
                    self.reporter.report(('/usr/bin/hdiutil', 'detach', devices[0]), OSError('busy'), self.scope())
                self.assertEqual(capture.call_count, 4 if mounted else 3)
                self.assertEqual(capture.call_args_list[2].args[0][-6:], ['--', str(self.image), *devices])
                if mounted:
                    self.assertEqual(capture.call_args_list[3].args[0][-3:], ['+f', '--', str(self.point)])
                else:
                    self.assertNotIn('+f', capture.call_args_list[-1].args[0])
                mapping = [e for e in self.events() if e['kind'] == 'mapping'][-1]
                self.assertEqual(mapping['devices'], devices)
                self.assertEqual(mapping['mountpoint_matches'], mounted)
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_other_mount_under_same_base_records_mismatch_without_filesystem_query(self):
        other = self.base / 'other-volume'
        other.mkdir(mode=0o700)
        self.record['system-entities'].append({'dev-entry': '/dev/disk999s1', 'mount-point': str(other)})
        native = [{'device': '/dev/disk999s1', 'path': str(other), 'filesystem': 'apfs'}]
        with patch.object(self.reporter, '_capture', side_effect=self.mapping_capture(native=native)) as capture, \
                patch.object(diagnostics.os.path, 'ismount', return_value=True) as mounted:
            self.reporter.report(self.args, OSError('busy'), self.scope(stage='cleanup'))
        self.assertEqual(capture.call_count, 3)
        mounted.assert_not_called()
        self.assertNotIn('+f', capture.call_args_list[-1].args[0])
        failure, mapping = self.events()[:2]
        self.assertEqual(failure['stage'], 'cleanup')
        self.assertEqual(failure['workspace'], 'a' * 32)
        self.assertEqual(failure['failed_device'], '/dev/disk999')
        self.assertEqual(failure['expected_mountpoint'], str(self.point))
        self.assertEqual(mapping['expected_mountpoint'], str(self.point))
        self.assertEqual(mapping['mountpoint'], str(other))
        self.assertFalse(mapping['mountpoint_matches'])
        self.assertIn('mismatch', self.events()[2]['reason'])
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_wrong_owner_path_device_and_duplicate_mapping_stop(self):
        cases = [[], [self.record, self.record], [dict(self.record, **{'owner-uid': os.getuid() + 1})],
                 [dict(self.record, **{'image-path': '/outside/workspace.sparseimage'})],
                 [dict(self.record, **{'system-entities': [{'dev-entry': '/dev/disk998'}]})],
                 [dict(self.record, **{'system-entities': [{'dev-entry': '/dev/disk999'}, {'dev-entry': '/dev/disk999'}]})]]
        for records in cases:
            with self.subTest(records=records), patch.object(self.reporter, '_capture', side_effect=self.mapping_capture(records)) as capture:
                with self.assertRaises((ValueError, OSError)):
                    self.reporter._mapping(self.args, self.scope(), time.monotonic() + 12)
                self.assertEqual(capture.call_count, 1)

    def test_mount_mismatch_and_disappeared_mount_never_query_host_fs(self):
        self.record['system-entities'].append({'dev-entry': '/dev/disk999s1', 'mount-point': str(self.point)})
        native = [{'device': '/dev/disk999s1', 'path': str(self.point), 'filesystem': 'apfs'}]
        with patch.object(self.reporter, '_capture', side_effect=self.mapping_capture(native=native)) as capture, \
                patch.object(diagnostics.os.path, 'ismount', return_value=False):
            self.reporter.report(self.args, OSError('busy'), self.scope())
        self.assertEqual(capture.call_count, 3)
        self.assertEqual(self.events()[-1]['kind'], 'unavailable')
        with patch.object(self.reporter, '_capture', side_effect=self.mapping_capture(native=[dict(native[0], device='/dev/disk3')])):
            with self.assertRaisesRegex(ValueError, 'native mount mismatch'):
                self.reporter._mapping(self.args, self.scope(), time.monotonic() + 12)

    def test_wrapper_success_no_diagnostics_and_failure_identity(self):
        images = SimpleNamespace(_command=Mock(return_value=b'ok'))
        collector = diagnostics.install(images, self.base / 'other')
        self.addCleanup(collector.close)
        with patch.object(collector, 'report') as report:
            self.assertEqual(images._command(*self.args), b'ok')
            report.assert_not_called()
        error = OSError('primary')
        def original(*args):
            raise error
        images = SimpleNamespace(_command=original)
        collector = diagnostics.install(images, self.base / 'unused')
        with patch.object(collector, 'report', side_effect=OSError('diagnostics failed')):
            try:
                images._command(*self.args)
            except OSError as caught:
                self.assertIs(caught, error)
                self.assertEqual(traceback.extract_tb(caught.__traceback__)[-1].name, 'original')
            else:
                self.fail('primary lost')

    def test_filesystem_query_requires_matching_live_device(self):
        native_stat = os.stat
        def device_stat(path, *args, **kwargs):
            if str(path) == '/dev/disk999s1':
                return SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=42)
            if str(path) == str(self.point):
                return SimpleNamespace(st_dev=42)
            return native_stat(path, *args, **kwargs)
        with patch.object(self.reporter, '_mapping', return_value=(str(self.image), ['/dev/disk999'], str(self.point), '/dev/disk999s1')), \
                patch.object(self.reporter, '_capture', side_effect=[captured(), captured(status=1)]) as capture, \
                patch.object(diagnostics.os.path, 'ismount', return_value=True), patch.object(diagnostics.os, 'stat', side_effect=device_stat):
            self.reporter.report(self.args, OSError('busy'), self.scope())
        self.assertEqual(capture.call_count, 2)
        self.assertEqual(capture.call_args_list[-1].args[0][-3:], ['+f', '--', str(self.point)])

    def test_interrupts_do_not_start_diagnostics(self):
        for error in (KeyboardInterrupt(), SystemExit(2)):
            images = SimpleNamespace(_command=Mock(side_effect=error))
            collector = diagnostics.install(images, self.base / 'unused')
            with patch.object(collector, 'report') as report, self.assertRaises(type(error)):
                images._command(*self.args)
            report.assert_not_called()

    def test_shared_deadline_and_attempt_budget(self):
        with patch.object(self.reporter, '_capture', side_effect=[v for _ in range(4) for v in self.mapping_capture()]) as capture:
            for _ in range(6):
                self.reporter.report(self.args, OSError('busy'), self.scope(expected=True))
        self.assertEqual(self.reporter.attempts, 4)
        self.assertEqual(capture.call_count, 12)
        for index in range(0, 12, 3):
            self.assertEqual(len({c.args[1] for c in capture.call_args_list[index:index + 3]}), 1)
        self.assertTrue(self.events()[0]['expected_busy'])

    def test_checked_partial_writes_caps_and_artifact_allowlist(self):
        real_write = os.write
        with patch.object(diagnostics.os, 'write', side_effect=lambda fd, data: real_write(fd, data[:3])):
            self.reporter._emit(time.monotonic() + 10, 'unavailable', reason='short writes completed')
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))
        for _ in range(50):
            self.reporter._emit(time.monotonic() + 10, 'unavailable', reason='x' * 4000)
        self.assertLessEqual(self.reporter.events, diagnostics.EVENTS)
        self.assertLessEqual((self.reporter.directory / diagnostics.REPORT).stat().st_size, diagnostics.FILE_BYTES)
        (self.reporter.directory / 'workspace.sparseimage').write_bytes(b'never selected')
        self.assertFalse(diagnostics.artifact_available(self.reporter.directory / '..'))
        self.reporter.close()
        report = self.reporter.directory / diagnostics.REPORT
        report.unlink()
        report.symlink_to(self.image)
        self.assertFalse(diagnostics.artifact_available(self.reporter.directory))

    def test_failed_write_retains_partial_file_and_original_exception(self):
        real_write = os.write
        count = 0
        def write(fd, data):
            nonlocal count
            count += 1
            if count == 1:
                return real_write(fd, data[:5])
            raise OSError(errno.ENOSPC, 'full')
        with patch.object(diagnostics.os, 'write', side_effect=write), self.assertRaises(OSError):
            self.reporter._emit(time.monotonic() + 10, 'unavailable', reason='preserve prefix')
        self.assertEqual((self.reporter.directory / diagnostics.REPORT).stat().st_size, 5)
        self.assertFalse(diagnostics.artifact_available(self.reporter.directory))

    def test_unknown_scope_event_cap_and_zero_write(self):
        self.reporter.report(self.args, OSError('busy'), None)
        self.spawn.assert_not_called()
        self.assertEqual(self.events()[-1]['kind'], 'unavailable')
        for _ in range(40):
            self.reporter._emit(time.monotonic() + 10, 'unavailable', reason='bounded')
        self.assertEqual(self.reporter.events, diagnostics.EVENTS)
        with patch.object(self.reporter, '_capture') as capture:
            self.reporter.report(self.args, OSError('busy'), self.scope())
        capture.assert_not_called()
        other = diagnostics.Diagnostics(self.base / 'zero-write')
        self.addCleanup(other.close)
        with patch.object(diagnostics.os, 'write', return_value=0), self.assertRaises(OSError):
            other._emit(time.monotonic() + 10, 'unavailable', reason='zero write')

    def test_unrelated_inventory_and_lsof_paths_not_persisted(self):
        unrelated = dict(self.record, **{'image-path': '/other-user/private', 'system-entities': [{'dev-entry': '/dev/disk111'}]})
        values = self.mapping_capture([unrelated, self.record])
        values[-1] = captured(b'p1\nf3\nn/other-user/secret\nn' + str(self.image).encode() + b'\n', b'warning /other-user/secret\nvisible warning', 1)
        with patch.object(self.reporter, '_capture', side_effect=values):
            self.reporter.report(self.args, OSError('busy'), self.scope())
        text = (self.reporter.directory / diagnostics.REPORT).read_text()
        self.assertNotIn('other-user', text)
        self.assertNotIn('disk111', text)
        self.assertIn('visible warning', text)
        self.assertIn('unscoped name omitted', text)
        with patch.object(self.reporter, '_mapping', return_value=(str(self.image), ['/dev/disk999'], str(self.point), '/dev/disk999s1')), \
                patch.object(self.reporter, '_capture', return_value=captured(('n' + str(self.point) + '/file -> /other-user/private\n').encode(), status=1)), \
                patch.object(diagnostics.os.path, 'ismount', return_value=False):
            self.reporter.report(self.args, OSError('busy'), self.scope())
        self.assertNotIn('other-user', (self.reporter.directory / diagnostics.REPORT).read_text())

    def test_spawn_failure_closes_selector_and_does_not_invent_output(self):
        selector = Mock()
        with patch.object(diagnostics.selectors, 'DefaultSelector', return_value=selector), \
                patch.object(diagnostics.subprocess, 'Popen', side_effect=OSError('spawn failed')), \
                self.assertRaisesRegex(OSError, 'spawn failed'):
            self.reporter._capture(['mock-only'], time.monotonic() + 12)
        selector.close.assert_called_once()

    def test_display_excerpt_and_serialization_cap_are_explicit(self):
        values = self.mapping_capture()
        values[-1] = captured(b'cworker\n' * 600, b'warning' * 600, 1)
        with patch.object(self.reporter, '_capture', side_effect=values):
            self.reporter.report(self.args, OSError('busy'), self.scope())
        event = self.events()[-1]
        self.assertTrue(event['display_truncated'])
        self.assertFalse(event['truncated'])
        self.assertLessEqual(len(event['stdout']), 2048)
        self.reporter._emit(time.monotonic() + 10, 'unavailable', reason='\u2603' * 2048)
        self.assertEqual(self.events()[-1]['reason'], 'diagnostic event exceeds serialization cap')

    def test_cleanup_failure_disables_all_later_capture(self):
        for failure in ('kill-eperm', 'wait-error', 'wait-timeout'):
            with self.subTest(failure=failure):
                self.reporter.remaining = 1024
                out, err = Mock(), Mock()
                out.fileno.return_value, err.fileno.return_value = 11, 12
                process = Mock(pid=123456, stdout=out, stderr=err, returncode=1)
                process.poll.return_value = 1
                if failure == 'wait-error':
                    process.wait.side_effect = OSError(errno.ECHILD, 'wait failed')
                elif failure == 'wait-timeout':
                    process.wait.side_effect = subprocess.TimeoutExpired('mock-only', 1)
                selector = Mock()
                selector.get_map.return_value = {out: 0, err: 1}
                selector.select.return_value = [(SimpleNamespace(fileobj=out, data=0), 1)]
                with patch.object(diagnostics.subprocess, 'Popen', return_value=process) as spawn, \
                        patch.object(diagnostics.selectors, 'DefaultSelector', return_value=selector), \
                        patch.object(diagnostics.os, 'set_blocking'), \
                        patch.object(diagnostics.os, 'read', side_effect=OSError('read stopped')), \
                        patch.object(diagnostics.os, 'killpg', side_effect=PermissionError(errno.EPERM, 'denied') if failure == 'kill-eperm' else None):
                    result = self.reporter._capture(['mock-only'], time.monotonic() + 12)
                    self.assertEqual(self.reporter.remaining, 0)
                    self.assertTrue(result['cleanup_error'])
                    self.assertEqual(result['reaped'], failure == 'kill-eperm')
                    self.assertFalse(self.reporter._complete(result))
                    with self.assertRaises(TimeoutError):
                        self.reporter._capture(['must-not-spawn'], time.monotonic() + 12)
                    # A separate failure report cannot restart collection either.
                    self.reporter.report(self.args, OSError('later failure'), self.scope())
                    spawn.assert_called_once()
                out.close.assert_called_once()
                err.close.assert_called_once()

    def test_mapping_cleanup_error_is_retained_as_bounded_status(self):
        value = captured()
        value['cleanup_error'] = 'group termination: PermissionError'
        with patch.object(self.reporter, '_capture', return_value=value) as capture:
            self.reporter.report(self.args, OSError('busy'), self.scope())
        capture.assert_called_once()
        self.assertIn('group termination: PermissionError', self.events()[-1]['reason'])
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_pipe_capture_cap_deadline_error_and_child_reaping(self):
        for mode in ('cap', 'timeout', 'read-error', 'normal', 'unreaped'):
            with self.subTest(mode=mode):
                self.reporter.remaining = 4
                out, err = Mock(), Mock()
                out.fileno.return_value, err.fileno.return_value = 11, 12
                process = Mock(pid=123456, stdout=out, stderr=err, returncode=1)
                process.poll.return_value = 1  # Descendant can still retain both pipes.
                if mode == 'unreaped':
                    process.wait.side_effect = subprocess.TimeoutExpired('mock-only', 1)
                selector = Mock()
                live = {out: 0, err: 1}
                selector.get_map.side_effect = lambda: live
                selector.unregister.side_effect = lambda pipe: live.pop(pipe)
                selector.select.side_effect = lambda timeout: [] if mode in ('timeout', 'unreaped') else [(SimpleNamespace(fileobj=p, data=i), 1) for p, i in list(live.items())]
                now = [0.0]
                def clock():
                    now[0] += 2 if mode in ('timeout', 'unreaped') else 0.01
                    return now[0]
                chunks = [b'abcd'] if mode == 'cap' else ([b'ab', OSError('read failed')] if mode == 'read-error' else [b'ab', b'', b''])
                with patch.object(diagnostics.subprocess, 'Popen', return_value=process), \
                        patch.object(diagnostics.selectors, 'DefaultSelector', return_value=selector), \
                        patch.object(diagnostics.os, 'set_blocking'), patch.object(diagnostics.os, 'read', side_effect=chunks), \
                        patch.object(diagnostics.os, 'killpg') as kill, patch.object(diagnostics.time, 'monotonic', side_effect=clock):
                    result = self.reporter._capture(['mock-only'], 12)
                self.assertEqual(result['reaped'], mode != 'unreaped')
                if mode == 'unreaped':
                    self.assertEqual(self.reporter.remaining, 0)
                self.assertGreaterEqual(process.wait.call_count, 1)
                out.close.assert_called_once()
                err.close.assert_called_once()
                self.assertLessEqual(len(result['stdout']) + len(result['stderr']), 4)
                if mode in ('cap', 'read-error', 'timeout'):
                    kill.assert_called_once_with(process.pid, diagnostics.signal.SIGKILL)
                if mode == 'cap':
                    self.assertTrue(result['truncated'])
                if mode == 'timeout':
                    self.assertTrue(result['timeout'])
                if mode == 'read-error':
                    self.assertEqual(result['capture_error'], 'OSError')
                    self.assertEqual(result['stdout'], b'ab')


if __name__ == '__main__':
    unittest.main()
