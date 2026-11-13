"""Mocks only: no disk-image commands, mounts, or diagnostic subprocesses."""
import ast
import errno
from contextlib import contextmanager, nullcontext
from contextvars import Context
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
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
    from . import test_images as image_cases
else:
    import image_failure_diagnostics as diagnostics
    import test_image_store as lifecycle
    import test_fileops as fileops
    import test_images_space as space
    import test_images as image_cases


def captured(stdout=b'', stderr=b'', status=0, **extra):
    return dict(stdout=stdout, stderr=stderr, returncode=status, timeout=False,
                truncated=False, reaped=True, capture_error=None, cleanup_error=None, **extra)


class CreateStatusObservationTests(unittest.TestCase):
    """Fake children only: never launch, wait for, signal or inspect a real child."""
    def setUp(self):
        self.waitid = self.enterContext(patch.object(diagnostics.os, 'waitid', create=True,
            side_effect=AssertionError('unexpected native waitid')))
        for name, value in (('P_PID', 1), ('WEXITED', 4), ('WNOHANG', 1),
                            ('WNOWAIT', 32), ('CLD_EXITED', 1), ('CLD_KILLED', 2), ('CLD_DUMPED', 3)):
            self.enterContext(patch.object(diagnostics.os, name, value, create=True))
        self.writer = self.enterContext(patch.object(diagnostics.os, 'write', side_effect=lambda fd, data: len(data)))
        self.thread = self.enterContext(patch.object(diagnostics.threading, 'Thread'))
        self.thread.return_value.is_alive.return_value = False
        self.enterContext(patch.object(diagnostics.subprocess, 'Popen', side_effect=AssertionError('unexpected child')))

    def observer(self):
        value = diagnostics.CreateObservation(('selected',))
        value.child = SimpleNamespace(pid=123, returncode=None,
            stdout=SimpleNamespace(closed=False), stderr=SimpleNamespace(closed=True))
        return value

    def exit_status(self, code=1, status=0):
        return SimpleNamespace(si_pid=123, si_code=code, si_status=status)

    def test_nonreaping_status_and_local_close_only(self):
        for result, state in ((None, 'no_exit_observed'), (self.exit_status(), 'exited_status_observed')):
            with self.subTest(state=state):
                value = self.observer()
                self.waitid.side_effect = None
                self.waitid.return_value = result
                record = value._sample()
                self.assertEqual(record['state'], state)
                self.assertFalse(record['stdout_closed'])
                self.assertTrue(record['stderr_closed'])
                self.assertEqual((record['eof'], record['byte_counts']), ('unobserved', 'unobserved'))
                self.waitid.assert_called_with(1, 123, 4 | 1 | 32)
                self.assertIsNone(value.child.returncode)
                self.assertFalse(value.in_flight)
        for code, category in ((1, 'exit'), (2, 'signal'), (3, 'signal_core')):
            self.waitid.return_value = self.exit_status(code, 9)
            record = self.observer()._sample()
            self.assertEqual((record['category'], record['status']), (category, 9))

    def test_errors_identity_and_completion_are_unknown(self):
        for error in (ChildProcessError(), OSError('unavailable')):
            self.waitid.side_effect = error
            self.assertEqual(self.observer()._sample()['state'], 'unknown')
        self.waitid.side_effect = None
        for status in (SimpleNamespace(si_pid=999, si_code=1, si_status=0), self.exit_status(99)):
            self.waitid.return_value = status
            self.assertEqual(self.observer()._sample()['state'], 'unknown')
        value = self.observer()
        def completion(*args):
            value.child.returncode = 0
            return self.exit_status()
        self.waitid.side_effect = completion
        self.assertEqual(value._sample()['reason'], 'completion_or_disarm_race')

    def test_stop_or_foreign_entry_during_property_prevents_query(self):
        for foreign in (False, True):
            value = self.observer()
            class ClosingProperty:
                @property
                def closed(self):
                    if foreign:
                        value.constructor_entry(object(), (['foreign'],), {})
                    else:
                        value.stop_queries()
                    return False
            value.child.stdout = ClosingProperty()
            self.assertEqual(value._sample()['reason'], 'stopped_or_disarmed')
        self.waitid.assert_not_called()

    def test_final_gate_checks_after_properties_and_before_query(self):
        value = self.observer()
        class Gate:
            def __enter__(self):
                value.disarmed.set()
            def __exit__(self, *args):
                return False
        value.gate = Gate()
        self.assertEqual(value._sample()['reason'], 'stopped_or_disarmed')
        self.waitid.assert_not_called()

    def test_inflight_stop_discards_result(self):
        value = self.observer()
        def query(*args):
            self.assertTrue(value.in_flight)
            value.stop_queries()
            return self.exit_status()
        self.waitid.side_effect = query
        self.assertEqual(value._sample()['reason'], 'completion_or_disarm_race')
        self.assertTrue(value.query_uncertain)
        self.assertFalse(value.in_flight)
        self.waitid.reset_mock()
        value._sample()
        self.waitid.assert_not_called()

    def test_foreign_entry_alone_latches_inflight_uncertainty(self):
        value = self.observer()
        def query(*args):
            self.assertTrue(value.in_flight)
            value.constructor_entry(object(), (['foreign'],), {})
            self.assertTrue(value.query_uncertain)
            return self.exit_status()
        self.waitid.side_effect = query
        self.assertEqual(value._sample()['reason'], 'completion_or_disarm_race')
        self.assertTrue(value.disarmed.is_set())
        self.assertTrue(value.query_stopped.is_set())
        self.assertTrue(value.query_uncertain)
        self.assertFalse(value.in_flight)
        self.waitid.reset_mock()
        value._sample()
        self.waitid.assert_not_called()

    def test_stop_while_query_releases_gate_latches_uncertainty(self):
        value = self.observer()
        real_gate = value.gate
        entries = []
        class Gate:
            def __enter__(self):
                entries.append(True)
                real_gate.acquire()
                if len(entries) == 2:
                    # Stop was published while its nonblocking gate acquisition
                    # could not see in_flight. The worker must retain that race.
                    value.query_stopped.set()
            def __exit__(self, *args):
                real_gate.release()
        value.gate = Gate()
        self.waitid.side_effect = None
        self.waitid.return_value = self.exit_status()
        self.assertEqual(value._sample()['reason'], 'completion_or_disarm_race')
        self.assertTrue(value.query_uncertain)

    def test_stop_during_returncode_after_query_discards_result(self):
        for foreign in (False, True):
            value = self.observer()
            reads = []
            class Child:
                pid = 123
                stdout = stderr = SimpleNamespace(closed=False)
                @property
                def returncode(self):
                    reads.append(True)
                    if len(reads) == 2:
                        if foreign:
                            value.constructor_entry(object(), (['foreign'],), {})
                        else:
                            value.stop_queries()
                    return None
            value.child = Child()
            self.waitid.side_effect = None
            self.waitid.return_value = self.exit_status()
            self.assertEqual(value._sample()['reason'], 'completion_or_disarm_race')
            self.assertFalse(value.in_flight)
            self.waitid.reset_mock()
            value._sample()
            self.waitid.assert_not_called()

    def test_missing_api_property_error_and_reaped_child_do_not_query(self):
        value = self.observer()
        with patch.object(diagnostics, 'hasattr', side_effect=lambda obj, name: name != 'WNOWAIT', create=True):
            self.assertEqual(value._sample()['reason'], 'api_unavailable')
        value.child.stdout = None
        self.assertEqual(value._sample()['state'], 'unknown')
        value.child.returncode = 0
        value._sample()
        self.waitid.assert_not_called()

    def test_constructor_selection_requires_owner_exact_args_and_one_instance(self):
        for argv, owner in ((['other'], None), (['selected'], 'other_thread')):
            value = diagnostics.CreateObservation(('selected',))
            with patch.object(diagnostics.threading, 'get_ident',
                              return_value=value.owner if owner is None else value.owner + 1):
                value.constructor_entry(object(), (argv,), {})
            self.assertIsNone(value.child)
            self.assertTrue(value.disarmed.is_set())
        value = diagnostics.CreateObservation(('selected',))
        first, duplicate = object(), object()
        value.constructor_entry(first, (), {'args': ['selected']})
        self.assertIs(value.child, first)
        self.assertFalse(value.disarmed.is_set())
        value.constructor_entry(duplicate, (['selected'],), {})
        self.assertIs(value.child, first)
        self.assertTrue(value.disarmed.is_set())

    def test_writer_caps_partial_write_and_error_without_textio(self):
        value = self.observer()
        for phase in ('start', '60', '120', 'finish', 'extra'):
            value._emit(phase, state='unknown')
        self.assertEqual(self.writer.call_count, 4)
        payloads = [entry.args[1] for entry in self.writer.call_args_list]
        self.assertTrue(all(entry.args[0] == 2 for entry in self.writer.call_args_list))
        self.assertLessEqual(sum(map(len, payloads)), 4096)
        self.assertTrue(all(len(data) <= 1024 for data in payloads))
        self.assertNotIn(b'123', b''.join(payloads))
        for failure in ('partial', 'error'):
            value = self.observer()
            self.writer.reset_mock()
            self.writer.side_effect = OSError('blocked sink') if failure == 'error' else lambda *args: 1
            value._emit('start')
            value._emit('finish')
            self.writer.assert_called_once()
            self.assertTrue(value.write_unavailable)
        value = self.observer()
        self.writer.reset_mock()
        value._emit('start', invalid='x' * 1024)
        self.writer.assert_not_called()

    def test_worker_schedule_and_early_completion_use_no_real_waits(self):
        value = self.observer()
        value.start = 0
        value.ready = Mock()
        value.done = Mock()
        value.done.is_set.side_effect = [False, False, False]
        value.done.wait.side_effect = [False, False, True]
        with patch.object(value, '_sample', return_value={'state': 'unknown'}) as sample, \
                patch.object(diagnostics.time, 'monotonic', return_value=0):
            value._run()
        self.assertEqual(sample.call_count, 2)
        self.assertEqual(value.done.wait.call_args_list, [call(60), call(120), call()])
        self.assertEqual([json.loads(c.args[1])['phase'] for c in self.writer.call_args_list],
                         ['start', '60', '120', 'finish'])
        self.writer.reset_mock()
        value = self.observer()
        value.done.set()
        value.ready.set()
        value._run()
        self.assertEqual([json.loads(c.args[1])['phase'] for c in self.writer.call_args_list], ['start', 'finish'])
        self.waitid.assert_not_called()

    def test_thread_start_and_bounded_join_preserve_uncertainty(self):
        value = self.observer()
        self.thread.return_value.start.side_effect = RuntimeError('thread unavailable')
        value.launch()
        self.assertTrue(value.shutdown_uncertain)
        value.close()
        self.thread.return_value.start.side_effect = None
        value = self.observer()
        value.launch()
        self.writer.assert_not_called()  # start/finish never write on operation thread
        self.thread.return_value.is_alive.return_value = True
        value.close()
        self.thread.return_value.join.assert_called_with(0.05)
        self.assertTrue(value.shutdown_uncertain)
        self.assertTrue(value.query_stopped.is_set())
        self.assertTrue(value.done.is_set())

    def test_late_worker_after_pending_write_cannot_query(self):
        value = self.observer()
        value.start = 0
        value.ready.set()
        value.launch()
        def write(fd, data):
            if json.loads(data)['phase'] == 'start':
                # Model close completing while this worker's write is pending.
                self.thread.return_value.is_alive.return_value = True
                value.close()
            return len(data)
        self.writer.side_effect = write
        value._run()
        self.waitid.assert_not_called()
        self.assertTrue(value.shutdown_uncertain)
        self.assertEqual([json.loads(c.args[1])['phase'] for c in self.writer.call_args_list], ['start', 'finish'])
        self.thread.return_value.join.assert_called_once_with(0.05)

    def test_selected_constructor_binding_foreign_entry_and_restoration(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        base = Path(temporary).resolve()
        parent = base / 'store' / 'staging' / 'build-test'
        parent.mkdir(parents=True, mode=0o700)
        args = ('/usr/bin/hdiutil', 'create', parent / 'workspace.sparseimage')
        constructions, communications, observations = [], [], []
        class FakePopen:
            def __init__(self, argv, **kwargs):
                observations.append(diagnostics._active_create)
                if argv == ['foreign']:
                    self_test.assertTrue(diagnostics._active_create.disarmed.is_set())
                self.pid, self.returncode = 123, None
                self.stdout = self.stderr = SimpleNamespace(closed=False)
                constructions.append((argv, kwargs))
            def communicate(self, *args, **kwargs):
                communications.append((args, kwargs))
                self.returncode = 0
                return b'out', b'err'
        self_test = self
        def original(*actual):
            child = subprocess.Popen([str(v) for v in actual], marker=7)
            subprocess.Popen(['foreign'])  # never communicates; must disarm at entry
            return child.communicate(input=None, timeout=None)
        with patch.object(subprocess, 'Popen', FakePopen):
            with diagnostics.observe_seed_create(base):
                self.assertEqual(diagnostics._observed_create(original, args), (b'out', b'err'))
            self.assertIs(subprocess.Popen, FakePopen)
        self.assertEqual(communications, [((), {'input': None, 'timeout': None})])
        self.assertEqual(constructions[0], ([str(v) for v in (*args, '-verbose')], {'marker': 7}))
        self.assertIs(observations[0], observations[1])
        self.assertTrue(observations[0].disarmed.is_set())
        self.assertEqual(observations[0].outcome, 'returned')
        self.assertIsNone(diagnostics._active_create)
        self.assertIsNone(diagnostics._create_scope.get())
        self.writer.assert_not_called()
        self.waitid.assert_not_called()

    def test_setup_start_and_close_errors_preserve_single_operation(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        base = Path(temporary).resolve()
        parent = base / 'store' / 'staging' / 'build-test'
        parent.mkdir(parents=True, mode=0o700)
        args = ('/usr/bin/hdiutil', 'create', parent / 'workspace.sparseimage')
        class FakePopen:
            pass
        for method in ('setup', 'launch', 'close'):
            for primary in (None, OSError('native failure'), KeyboardInterrupt()):
                original = Mock(return_value=b'unchanged', side_effect=primary)
                target, attribute = ((diagnostics, 'CreateObservation') if method == 'setup'
                                     else (diagnostics.CreateObservation, method))
                with patch.object(subprocess, 'Popen', FakePopen), \
                        patch.object(target, attribute, side_effect=RuntimeError('observer failure')), \
                        diagnostics.observe_seed_create(base):
                    if primary is None:
                        self.assertEqual(diagnostics._observed_create(original, args), b'unchanged')
                    else:
                        with self.assertRaises(type(primary)) as caught:
                            diagnostics._observed_create(original, args)
                        self.assertIs(caught.exception, primary)
                    self.assertIs(subprocess.Popen, FakePopen)
                original.assert_called_once_with(*args, '-verbose')
                self.assertIsNone(diagnostics._active_create)
                self.assertTrue(diagnostics._create_patch_lock.acquire(blocking=False))
                diagnostics._create_patch_lock.release()
        self.writer.assert_not_called()
        self.waitid.assert_not_called()

    def test_selected_communicate_exception_and_scope_use_are_preserved(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        base = Path(temporary).resolve()
        parent = base / 'store' / 'staging' / 'build-test'
        parent.mkdir(parents=True, mode=0o700)
        args = ('/usr/bin/hdiutil', 'create', parent / 'workspace.sparseimage')
        for primary in (OSError('communicate failed'), KeyboardInterrupt(), SystemExit(9)):
            communications, observations = [], []
            class FakePopen:
                def __init__(self, argv):
                    self.pid, self.returncode = 123, None
                    self.stdout = self.stderr = SimpleNamespace(closed=False)
                def communicate(self, *actual, **kwargs):
                    communications.append((actual, kwargs))
                    raise primary
            def original(*actual):
                observations.append(diagnostics._active_create)
                return subprocess.Popen([str(v) for v in actual]).communicate(b'input', timeout=7)
            with patch.object(subprocess, 'Popen', FakePopen), diagnostics.observe_seed_create(base):
                with self.assertRaises(type(primary)) as caught:
                    diagnostics._observed_create(original, args)
                self.assertIs(caught.exception, primary)
                self.assertIs(subprocess.Popen, FakePopen)
                # A second command in the same scope must bypass observation.
                later = Mock(return_value=b'later')
                self.assertEqual(diagnostics._observed_create(later, args), b'later')
                later.assert_called_once_with(*args, '-verbose')
            self.assertEqual(communications, [((b'input',), {'timeout': 7})])
            self.assertEqual(len(observations), 1)
            self.assertTrue(observations[0].query_stopped.is_set())
            self.assertTrue(observations[0].done.is_set())
            self.assertEqual(observations[0].outcome, 'raised')
        self.waitid.assert_not_called()

    def test_primary_exception_nested_scope_and_lock_restoration(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        base = Path(temporary).resolve()
        parent = base / 'store' / 'staging' / 'build-test'
        parent.mkdir(parents=True, mode=0o700)
        args = ('/usr/bin/hdiutil', 'create', parent / 'workspace.sparseimage')
        class FakePopen:
            pass
        for primary in (OSError('launch failed'), KeyboardInterrupt(), SystemExit(3)):
            original = Mock(side_effect=primary)
            with patch.object(subprocess, 'Popen', FakePopen), diagnostics.observe_seed_create(base):
                with self.assertRaises(type(primary)) as caught:
                    diagnostics._observed_create(original, args)
                self.assertIs(caught.exception, primary)
                self.assertIs(subprocess.Popen, FakePopen)
            original.assert_called_once_with(*args, '-verbose')
            self.assertIsNone(diagnostics._active_create)
            self.assertTrue(diagnostics._create_patch_lock.acquire(blocking=False))
            diagnostics._create_patch_lock.release()
        with diagnostics.observe_seed_create(base):
            outer = diagnostics._create_scope.get()
            with diagnostics.observe_seed_create(base):
                self.assertIs(diagnostics._create_scope.get(), outer)
                self.assertTrue(outer['disabled'])
            original = Mock(return_value=b'normal')
            self.assertEqual(diagnostics._observed_create(original, args), b'normal')
        self.waitid.assert_not_called()


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
        for selection in ('initial-unmount', 'closed-snapshot', 'enospc-initial-detach',
                          'enospc-sibling-detach', 'restored-cleanup'):
            with self.subTest(selection=selection), tempfile.TemporaryDirectory() as temporary:
                fixture = space.ImageSpace()
                fixture.base = Path(temporary).resolve()
                fixture.source = fixture.base / 'source'
                fixture.seed = fixture.base / 'seed.sparseimage'
                fixture.image_points = {}
                fixture.observation = selection
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
                seen, observed_detaches = [], []
                def attach(image, point):
                    self.assert_scope(fixture.base, image, point, 'body')
                    seen.append(image.name)
                    return repo if image.name == 'full.sparseimage' else untouched
                def detach(image, point):
                    self.assert_scope(fixture.base, image, point,
                                      'sibling-detach' if image.name == 'sibling.sparseimage' else 'body')
                    observed_detaches.append(diagnostics._detach_observation.get() is not None)
                with patch.object(space.images, 'clone', side_effect=clone), \
                        patch.object(space, 'digest', side_effect=digest), \
                        patch.object(space.images, 'attach', side_effect=attach), \
                        patch.object(space.images, 'detach', side_effect=detach), \
                        patch.object(fixture, 'assert_original'), \
                        patch.object(space, 'fullsync', side_effect=lambda path, value: path.write_bytes(value)), \
                        patch.object(Path, 'open', open_path), patch('builtins.print'):
                    fixture.test_volume_full_preserves_existing_data_and_other_images()
                self.assertEqual(seen, ['full.sparseimage', 'full.sparseimage', 'sibling.sparseimage', 'seed.sparseimage'])
                self.assertEqual(observed_detaches, [selection == 'enospc-initial-detach',
                                 selection not in ('enospc-initial-detach', 'enospc-sibling-detach'),
                                 selection == 'enospc-sibling-detach', False])
                self.assertFalse(getattr(fixture, 'retain', False))
                self.assertIsNone(diagnostics._detach_observation.get())
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


class SpaceRetentionTests(unittest.TestCase):
    def fixture(self):
        fixture = space.ImageSpace()
        fixture.base = Path(tempfile.mkdtemp(prefix='space-retention-mock-')).resolve()
        self.addCleanup(shutil.rmtree, fixture.base, ignore_errors=True)
        fixture.image_points = {}
        fixture.observation = 'initial-unmount'
        for name in ('seed.sparseimage', 'sibling.sparseimage', 'sentinel'):
            (fixture.base / name).write_bytes(name.encode())
        return fixture

    def assert_retained(self, fixture):
        before = {p.name: p.read_bytes() for p in fixture.base.iterdir() if p.is_file()}
        with patch.object(space.images, 'mounted') as inspect, patch.object(space.images, 'detach') as detach, \
                patch.object(space.os, 'walk') as walk, patch.object(space.shutil, 'rmtree') as remove:
            fixture.clean()
        for operation in (inspect, detach, walk, remove):
            operation.assert_not_called()
        self.assertEqual({p.name: p.read_bytes() for p in fixture.base.iterdir() if p.is_file()}, before)

    def test_setup_errors_before_and_after_image_creation_keep_original_and_all_files(self):
        for stage in ('write', 'xattr', 'build', 'interrupt', 'exit'):
            with self.subTest(stage=stage):
                fixture = space.ImageSpace()
                error = KeyboardInterrupt() if stage == 'interrupt' else SystemExit(7) if stage == 'exit' else OSError(stage)
                def write(path, value):
                    self.addCleanup(shutil.rmtree, fixture.base, ignore_errors=True)
                    if stage in ('write', 'interrupt', 'exit'):
                        raise error
                    path.write_bytes(value)
                def build(source, image, capacity):
                    image.write_bytes(b'unknown attached image')
                    raise error
                with patch.object(space.shutil, 'disk_usage', return_value=SimpleNamespace(free=4 * 1024**3)), \
                        patch.object(space, 'fullsync', side_effect=write), \
                        patch.object(space.subprocess, 'run', side_effect=error if stage == 'xattr' else None), \
                        patch.object(space.images, 'build', side_effect=build), self.assertRaises(type(error)) as caught:
                    fixture.setUp()
                self.assertIs(caught.exception, error)
                self.assertIn(str(fixture.base), '\n'.join(error.__notes__))
                self.assert_retained(fixture)

    def test_body_failures_and_late_skip_retain_without_cleanup_probes(self):
        for error in (AssertionError('body'), OSError(errno.ENOSPC, 'unexpected full'), KeyboardInterrupt(), SystemExit(3), unittest.SkipTest('late')):
            with self.subTest(error=type(error).__name__):
                fixture = self.fixture()
                fixture.seed = fixture.base / 'seed.sparseimage'
                with patch.object(space.images, 'clone', side_effect=error), self.assertRaises(type(error)) as caught:
                    fixture.test_volume_full_preserves_existing_data_and_other_images()
                self.assertIs(caught.exception, error)
                self.assert_retained(fixture)

    def test_retained_path_note_failure_cannot_replace_base_exception(self):
        class NoteFailure(KeyboardInterrupt):
            def add_note(self, text):
                raise SystemExit(9)
        fixture, error = self.fixture(), NoteFailure()
        @space.retain_failure
        def body(value):
            raise error
        with self.assertRaises(NoteFailure) as caught:
            body(fixture)
        self.assertIs(caught.exception, error)
        self.assert_retained(fixture)

    def test_body_eject_failure_is_not_repeated_by_registered_cleanup(self):
        fixture = self.fixture()
        fixture.seed, fixture.source = fixture.base / 'seed.sparseimage', fixture.base / 'source'
        repo = fixture.base / 'repo'; repo.mkdir()
        filler = repo / 'filler'; filler.touch()
        stream = Mock(); stream.write.side_effect = [1, OSError(errno.ENOSPC, 'expected full')]
        opened = Mock(); opened.__enter__ = Mock(return_value=stream); opened.__exit__ = Mock(return_value=False)
        original_open = Path.open
        def open_path(path, *args, **kwargs):
            return opened if path == filler else original_open(path, *args, **kwargs)
        error = OSError(errno.EBUSY, 'body eject')
        with patch.object(space.images, 'clone'), patch.object(space, 'digest', return_value='same'), \
                patch.object(space.images, 'attach', return_value=repo), patch.object(fixture, 'assert_original'), \
                patch.object(space, 'fullsync', side_effect=lambda path, value: path.write_bytes(value)), \
                patch.object(Path, 'open', open_path), patch.object(space.images, 'detach', side_effect=error) as eject, \
                self.assertRaises(type(error)) as caught:
            fixture.test_volume_full_preserves_existing_data_and_other_images()
        self.assertIs(caught.exception, error)
        eject.assert_called_once()
        self.assert_retained(fixture)

    def test_enospc_selector_observes_first_detach_before_failure(self):
        for selection in ('initial-unmount', 'closed-snapshot', 'enospc-initial-detach'):
            with self.subTest(selection=selection):
                fixture = self.fixture()
                fixture.observation = selection
                fixture.seed, fixture.source = fixture.base/'seed.sparseimage', fixture.base/'source'
                repo = fixture.base/'repo'; repo.mkdir()
                filler = repo/'filler'; filler.touch()
                stream = Mock(); stream.write.side_effect = [1, OSError(errno.ENOSPC, 'full')]
                opened = Mock(); opened.__enter__ = Mock(return_value=stream); opened.__exit__ = Mock(return_value=False)
                original_open = Path.open
                def open_path(path, *args, **kwargs):
                    return opened if path == filler else original_open(path, *args, **kwargs)
                error = OSError(errno.EBUSY, 'selected eject')
                def detach(*args):
                    self.assertEqual(diagnostics._detach_observation.get() is not None,
                                     selection == 'enospc-initial-detach')
                    raise error
                with patch.object(space.images, 'clone'), patch.object(space, 'digest', return_value='same'), \
                        patch.object(space.images, 'attach', return_value=repo), patch.object(fixture, 'assert_original'), \
                        patch.object(space, 'fullsync', side_effect=lambda path, value: path.write_bytes(value)), \
                        patch.object(Path, 'open', open_path), patch.object(space.images, 'detach', side_effect=detach) as eject, \
                        self.assertRaises(OSError) as caught:
                    fixture.test_volume_full_preserves_existing_data_and_other_images()
                self.assertIs(caught.exception, error)
                eject.assert_called_once()
                self.assert_retained(fixture)

    def test_selector_is_validated_before_space_fixture_allocation(self):
        for value in ('enospc-initial-detach', 'unknown', ''):
            with self.subTest(value=value), patch.dict(os.environ, STALLIONFS_TEST_SNAPSHOT_OBSERVATION=value), \
                    patch.object(space.tempfile, 'mkdtemp', side_effect=OSError('stop before allocation')) as allocate:
                fixture = space.ImageSpace()
                with self.assertRaises(OSError if value == 'enospc-initial-detach' else ValueError):
                    fixture.setUp()
                self.assertEqual(allocate.call_count, int(value == 'enospc-initial-detach'))

    def test_headroom_skip_cleans_only_the_empty_owned_directory(self):
        fixture = space.ImageSpace()
        with patch.object(space.shutil, 'disk_usage', return_value=SimpleNamespace(free=0)), \
                patch.object(space.images, 'build') as build, patch.object(space.subprocess, 'run') as command, \
                self.assertRaises(unittest.SkipTest):
            fixture.setUp()
        self.assertFalse(getattr(fixture, 'retain', False))
        self.assertEqual(list(fixture.base.iterdir()), [])
        fixture.clean()
        self.assertFalse(fixture.base.exists())
        build.assert_not_called(); command.assert_not_called()


class InvocationIsolationTests(unittest.TestCase):
    def test_mocked_detach_suite_preserves_outer_collector_for_later_owned_failure(self):
        if __package__:
            from . import test_image_detach
        else:
            import test_image_detach
        from stallionfs import images
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            collector = diagnostics.install(images, base / 'outer-diagnostics')
            self.addCleanup(collector.close)
            wrappers = {name: getattr(images, name)
                        for name in ('_command', 'detach', 'mounted', '_attachments')}
            with patch.object(diagnostics.subprocess, 'Popen',
                              side_effect=AssertionError('unexpected native command')) as spawn:
                suite = unittest.defaultTestLoader.loadTestsFromTestCase(test_image_detach.DetachContinuationTests)
                result = unittest.TestResult()
                suite.run(result)
                self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
                self.assertGreater(result.testsRun, diagnostics.ATTEMPTS)
                self.assertEqual((collector.attempts, collector.before_attempts, collector.events,
                                  collector.remaining), (0, 0, 0, diagnostics.CAPTURE_BYTES))
                self.assertFalse(collector.directory.exists())
                for name, wrapper in wrappers.items():
                    self.assertIs(getattr(images, name), wrapper)
                image = base / 'later.sparseimage'
                image.write_bytes(b'owned mock backing'); image.chmod(0o600)
                identity = image.stat()
                mapped = (str(image), ['/dev/disk999'], None, None,
                          (identity.st_dev, identity.st_ino))
                with patch.object(images.subprocess, 'run', return_value=subprocess.CompletedProcess(
                        [], 64, b'', b'later owned eject failed')), \
                        patch.object(collector, '_mapping', return_value=mapped) as mapping, \
                        patch.object(collector, '_capture', side_effect=lambda *args: captured(status=1)), \
                        diagnostics.failure_scope(base, image, stage='later-owned'), \
                        self.assertRaises(images._CommandFailure):
                    images._command('/usr/sbin/diskutil', 'eject', '/dev/disk999')
                mapping.assert_called_once()
                self.assertEqual(collector.attempts, 1)
                events = [json.loads(line) for line in
                          (collector.directory / diagnostics.REPORT).read_text().splitlines()]
                self.assertEqual([e['stage'] for e in events if e['kind'] == 'failure'], ['later-owned'])
                self.assertEqual([e['image'] for e in events if e['kind'] == 'mapping'], [str(image)])
                self.assertTrue(diagnostics.artifact_available(collector.directory))
                spawn.assert_not_called()

    def check_later_scope(self, first_fails):
        for missing_scope in (False, True):
            with self.subTest(first_fails=first_fails, missing_scope=missing_scope), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                first, second = base / 'first.sparseimage', base / 'second.sparseimage'
                for image in (first, second):
                    image.write_bytes(b'owned ordinary fixture'); image.chmod(0o600)
                point = base / 'volume'; point.mkdir(mode=0o700)
                errors = [OSError('selected command'), OSError('later command')]
                for error in errors:
                    error.returncode = errno.EBUSY
                images, inside, commands = SimpleNamespace(), [], []
                def command(*args):
                    commands.append(args)
                    if len(commands) == 2 or first_fails:
                        raise errors[len(commands) - 1]
                    return b'original return'
                images._command = command
                def detach(image, mountpoint):
                    inside.append(True)
                    try:
                        return images._command('/usr/sbin/diskutil', 'eject', '/dev/disk999')
                    finally:
                        inside.pop()
                images.detach = detach
                collector = diagnostics.install(images, base / 'diagnostics')
                self.addCleanup(collector.close)
                def before(args, scope, observation):
                    collector.operations += 1
                    observation.update(operation_id=collector.operations, observed_target='/dev/disk999')
                def mapping(args, scope, deadline):
                    image = scope['image']; info = image.stat()
                    return str(image), ['/dev/disk999'], None, None, (info.st_dev, info.st_ino)
                report, seen = collector.report, []
                def recorded(args, error, scope, operation_id=None, observation=None):
                    seen.append((operation_id, observation))
                    return report(args, error, scope, operation_id, observation)
                def query(observation):
                    self.assertFalse(inside)
                    self.assertIs(observation['command_error'], errors[0])
                with patch.object(collector, 'before', side_effect=before) as observed, \
                        patch.object(collector, '_mapping', side_effect=mapping), \
                        patch.object(collector, '_capture', return_value=captured(status=1)), \
                        patch.object(collector, 'report', side_effect=recorded), \
                        patch.object(collector, 'eject_log', side_effect=query) as queried:
                    with diagnostics.observe_detach():
                        selected = diagnostics._detach_observation.get()
                        with diagnostics.failure_scope(base, first, mountpoint=point):
                            if first_fails:
                                with self.assertRaises(OSError) as caught:
                                    images.detach(first, point)
                                self.assertIs(caught.exception, errors[0])
                            else:
                                self.assertEqual(images.detach(first, point), b'original return')
                        later = nullcontext() if missing_scope else diagnostics.failure_scope(base, second)
                        with later, self.assertRaises(OSError) as caught:
                            images.detach(second, point)
                        self.assertIs(caught.exception, errors[1])
                        self.assertIs(diagnostics._detach_observation.get(), selected)
                        self.assertIsNone(diagnostics._detach_call.get())
                    observed.assert_called_once()
                    self.assertEqual(queried.call_count, int(first_fails))
                self.assertEqual(seen[-1], (None, None))
                events = [json.loads(line) for line in (collector.directory / diagnostics.REPORT).read_text().splitlines()]
                failures = [event for event in events if event['kind'] == 'failure']
                self.assertEqual(failures[-1]['operation_id'], 2)
                self.assertEqual(failures[-1]['pre_observation'], 'not-selected')
                self.assertEqual(commands, [('/usr/sbin/diskutil', 'eject', '/dev/disk999')] * 2)
                self.assertIsNone(diagnostics._detach_observation.get())
                self.assertIsNone(diagnostics._validation_read.get())

    def test_selected_success_then_missing_or_inexact_scope_is_fresh(self):
        self.check_later_scope(False)

    def test_selected_failure_then_missing_or_inexact_scope_is_fresh(self):
        self.check_later_scope(True)


class PassiveValidationTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(space.images, '_device_identity', return_value=(2, 100, 20, 0o60600)))
        self.temporary = tempfile.TemporaryDirectory(prefix='passive-image-mock-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.image, self.point = self.base / 'owned.sparseimage', self.base / 'volume'
        self.image.write_bytes(b'ordinary synthetic file'); self.image.chmod(0o600)
        self.point.mkdir(mode=0o700)
        self.record = {'image-path': str(self.image), 'owner-uid': os.getuid(), 'system-entities': [
            {'dev-entry': '/dev/disk999', 'content-hint': 'GUID_partition_scheme'},
            {'dev-entry': '/dev/disk999s1', 'content-hint': 'Apple_APFS'},
            {'dev-entry': '/dev/disk998', 'content-hint': 'Apple_APFS'},
            {'dev-entry': '/dev/disk998s1', 'potentially-mountable': True}]}
        self.identity = (self.image.stat().st_dev, self.image.stat().st_ino)
        self.inventory = {'images': [self.record]}
        self.inside = False
        real_detach = space.images.detach
        def detach(image, point):
            self.inside = True
            try:
                return real_detach(image, point)
            finally:
                self.inside = False
        self.enterContext(patch.object(space.images, 'detach', detach))
        self.plist = self.enterContext(patch.object(space.images, '_plist', side_effect=lambda *args: self.inventory))
        self.command = self.enterContext(patch.object(space.images, '_command'))
        self.collector = diagnostics.install(space.images, self.base / 'diagnostics')
        self.addCleanup(self.collector.close)
        self.enterContext(patch.object(self.collector, '_mapping', return_value=(str(self.image),
            ['/dev/disk999', '/dev/disk999s1', '/dev/disk998', '/dev/disk998s1'], None, None, self.identity)))
        def capture(argv, deadline):
            if argv[0] == '/usr/bin/log':
                self.assertFalse(self.inside, 'status lookup occurred before public unwind')
            return captured(status=0 if argv[0] == '/usr/bin/log' else 1)
        self.capture = self.enterContext(patch.object(self.collector, '_capture', side_effect=capture))

    def invoke(self):
        with diagnostics.failure_scope(self.base, self.image, mountpoint=self.point):
            return space.images.detach(self.image, self.point)

    def events(self):
        return [json.loads(line) for line in (self.collector.directory / diagnostics.REPORT).read_text().splitlines()]

    def fail_command(self):
        error = space.images._error('normal eject failed'); error.returncode = errno.EBUSY
        self.command.side_effect = error
        return error

    def test_current_confirmed_inventory_flushes_only_failed_call_after_unwind(self):
        error = self.fail_command()
        emitted = self.collector._emit
        def emit(deadline, kind, **fields):
            if kind == 'validation':
                self.assertFalse(self.inside)
            return emitted(deadline, kind, **fields)
        with patch.object(self.collector, '_emit', side_effect=emit), self.assertRaises(type(error)) as caught:
            self.invoke()
        self.assertIs(caught.exception, error)
        self.command.assert_called_once_with('/usr/sbin/diskutil', 'eject', '/dev/disk999')
        self.assertEqual(self.plist.call_count, 2)
        events = self.events()
        samples = [event for event in events if event['kind'] == 'validation']
        self.assertEqual([event['read'] for event in samples], ['current', 'confirmed'])
        self.assertEqual({event['sample_status'] for event in samples}, {'validated'})
        self.assertEqual(samples[0]['entities'][0]['content_hint'], 'GUID_partition_scheme')
        self.assertEqual({event['operation_id'] for event in samples}, {events[0]['operation_id']})
        self.assertEqual({event['pre_observation'] for event in events if event['kind'] == 'failure'}, {'not-selected'})
        self.assertIsNone(next(event for event in events if event['kind'] == 'mapping')['backing_identity_matches_first'])
        self.assertEqual(sum(event['kind'] == 'eject_log' for event in events), 1)
        self.assertEqual(self.collector.before_attempts, 0)
        self.assertTrue(diagnostics.artifact_available(self.collector.directory))
        self.assertIsNone(diagnostics._detach_call.get()); self.assertIsNone(diagnostics._validation_read.get())

    def test_success_post_eject_read_cannot_overwrite_or_publish_validation_cache(self):
        def command(*args):
            self.inventory = {'images': []}
            return b'normal output'
        self.command.side_effect = command
        self.assertIsNone(self.invoke())
        self.assertEqual(self.plist.call_count, 3)
        self.capture.assert_not_called()
        self.assertFalse(self.collector.directory.exists())
        self.assertIsNone(diagnostics._detach_call.get())

    def test_post_eject_refusal_cannot_be_mislabeled_as_confirmed(self):
        def command(*args):
            self.inventory = {'images': [dict(self.record, **{'system-entities': [
                {'dev-entry': '/dev/disk997', 'content-hint': 'EFI'}]})]}
        self.command.side_effect = command
        with self.assertRaises(lifecycle.StallionError):
            self.invoke()
        samples = [event for event in self.events() if event['kind'] == 'validation']
        self.assertEqual([event['read'] for event in samples], ['current', 'confirmed'])
        self.assertEqual([event['entities'][0]['content_hint'] for event in samples],
                         ['GUID_partition_scheme', 'GUID_partition_scheme'])
        self.assertEqual(self.plist.call_count, 3)
        self.capture.assert_not_called()
        self.command.assert_called_once()

    def test_unknown_and_oversized_metadata_cannot_change_eject_or_expose_text(self):
        for value in ('/private/unrelated ' * 10000, ['invalid']):
            with self.subTest(value=type(value).__name__):
                self.record['system-entities'][0]['content-hint'] = value
                error = self.fail_command()
                with self.assertRaises(type(error)) as caught:
                    self.invoke()
                self.assertIs(caught.exception, error)
        samples = [event for event in self.events() if event['kind'] == 'validation']
        self.assertEqual(samples[0]['entities'][0]['content_hint'], '[unrecognized]')
        self.assertEqual(samples[-1]['sample_status'], 'unavailable')
        self.assertNotIn('/private/unrelated', (self.collector.directory / diagnostics.REPORT).read_text())
        self.assertEqual(self.plist.call_count, 4)
        self.assertEqual(self.command.call_count, 2)
        self.assertEqual(sum(event['kind'] == 'eject_log' for event in self.events()), 1)

    def test_validation_refusal_never_replays_or_queries_a_command(self):
        self.record['owner-uid'] += 1
        with self.assertRaises(lifecycle.StallionError):
            self.invoke()
        self.command.assert_not_called(); self.capture.assert_not_called()
        self.assertEqual(self.plist.call_count, 1)
        sample = next(event for event in self.events() if event['kind'] == 'validation')
        self.assertEqual((sample['sample_status'], sample['reason']), ('unavailable', 'normal_validation_failed'))

    def test_collector_interrupt_cannot_replace_command_failure(self):
        error = self.fail_command()
        with patch.object(self.collector, 'validation', side_effect=KeyboardInterrupt()), self.assertRaises(type(error)) as caught:
            self.invoke()
        self.assertIs(caught.exception, error)
        self.assertEqual(self.plist.call_count, 2)
        self.command.assert_called_once()

    def test_mounted_volume_uses_only_normal_validation_probes(self):
        self.record['system-entities'][-1]['mount-point'] = str(self.point)
        real_stat = os.stat
        def device_stat(path, *args, **kwargs):
            if kwargs.get('follow_symlinks') is not False:
                if str(path) == '/dev/disk998s1':
                    return SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=42)
                if str(path) == str(self.point):
                    return SimpleNamespace(st_dev=42)
            return real_stat(path, *args, **kwargs)
        error = self.fail_command()
        with patch('stallionfs._scan.mounts', return_value=[dict(path=str(self.point), device='/dev/disk998s1',
                filesystem='apfs', readonly=False, ignore_ownership=False)]) as mounts, \
                patch.object(space.images.os, 'stat', side_effect=device_stat), \
                patch.object(space.images.os.path, 'ismount', return_value=True), self.assertRaises(type(error)):
            self.invoke()
        self.assertEqual(mounts.call_count, 2)
        self.assertEqual(self.plist.call_count, 2)
        self.assertEqual({event['mountpoint_state'] for event in self.events() if event['kind'] == 'validation'}, {'expected'})

    def test_success_then_reused_device_and_report_reentrancy_never_reuse_cache(self):
        self.enterContext(diagnostics.observe_detach())
        def success(*args):
            self.inventory = {'images': []}
        self.command.side_effect = success
        self.invoke()
        other = self.base / 'other.sparseimage'
        other.write_bytes(b'other identity'); other.chmod(0o600)
        self.image = other
        self.record = dict(self.record, **{'image-path': str(other), 'system-entities': [
            {'dev-entry': '/dev/disk999', 'content-hint': 'EFI'}]})
        self.inventory = {'images': [self.record]}
        identity = (other.stat().st_dev, other.stat().st_ino)
        self.collector._mapping.return_value = str(other), ['/dev/disk999'], None, None, identity
        error = self.fail_command()
        report = self.collector.report
        def reentrant(*args, **kwargs):
            Context().run(space.images.mounted, other)
            return report(*args, **kwargs)
        with patch.object(self.collector, 'report', side_effect=reentrant), self.assertRaises(type(error)):
            self.invoke()
        samples = [event for event in self.events() if event['kind'] == 'validation']
        self.assertEqual([event['read'] for event in samples], ['current', 'confirmed'])
        self.assertEqual([event['entities'][0]['content_hint'] for event in samples], ['EFI', 'EFI'])
        self.assertEqual(self.plist.call_count, 6)
        after = [event for event in self.events() if event['kind'] == 'mapping' and event['phase'] == 'after']
        self.assertEqual({event['image'] for event in after}, {str(other)})
        before_id = next(event['operation_id'] for event in self.events() if event['kind'] == 'observation')
        self.assertNotEqual(after[0]['operation_id'], before_id)
        self.assertIsNone(after[0]['backing_identity_matches_first'])

    def test_nested_install_close_restores_every_validation_slot(self):
        saved = {name: original for _, name, original, _ in self.collector.patches}
        outer_slots = {name: getattr(space.images, name) for name in saved}
        inner = diagnostics.install(space.images, self.base / 'inner')
        self.addCleanup(inner.close)
        inner.close()
        for name, wrapper in outer_slots.items():
            self.assertIs(getattr(space.images, name), wrapper)
        inner = diagnostics.install(space.images, self.base / 'inner-again')
        self.collector.close()
        inner.close()
        for name, original in saved.items():
            self.assertIs(getattr(space.images, name), original)

    def test_projection_count_and_report_budget_are_bounded_before_serialization(self):
        self.record['system-entities'].extend({'dev-entry': f'/dev/disk999s{index}'}
                                             for index in range(2, 35))
        error = self.fail_command()
        with self.assertRaises(type(error)):
            self.invoke()
        samples = [event for event in self.events() if event['kind'] == 'validation']
        self.assertEqual({event['sample_status'] for event in samples}, {'unavailable'})
        self.assertTrue(all(not event['entities'] for event in samples))
        self.assertTrue(diagnostics.artifact_available(self.collector.directory))
        self.collector.written = diagnostics.FILE_BYTES
        before = self.capture.call_count
        with self.assertRaises(type(error)) as caught:
            self.invoke()
        self.assertIs(caught.exception, error)
        self.assertEqual(self.capture.call_count, before)
        self.assertEqual(self.command.call_count, 2)

    def test_artifact_rejects_invalid_validation_fields_and_raw_hints(self):
        error = self.fail_command()
        with self.assertRaises(type(error)):
            self.invoke()
        path = self.collector.directory / diagnostics.REPORT
        original = self.events()
        index = next(i for i, value in enumerate(original) if value['kind'] == 'validation')
        for change in ({'phase': 'before'}, {'read': 'post-eject'}, {'sample_timestamp_ns': True},
                       {'entities': [{'device': '/dev/disk999', 'content_hint': '/private/secret',
                        'unmapped_content_hint': None, 'potentially_mountable': None}]}):
            with self.subTest(change=change):
                values = [dict(value) for value in original]
                values[index].update(change)
                path.write_text(''.join(json.dumps(value) + '\n' for value in values))
                self.assertFalse(diagnostics.artifact_available(self.collector.directory))
        path.write_text(''.join(json.dumps(value) + '\n' for value in original))


class WorkflowTests(unittest.TestCase):
    def workflow(self):
        text = (Path(__file__).resolve().parents[1] / '.github/workflows/checks.yml').read_text()
        worker = text.split('  test-execution:\n', 1)[1].split('\n  test:\n', 1)[0]
        gate = text.split('\n  test:\n', 1)[1].split('\n  hosted-docs-screen:\n', 1)[0]
        return worker, gate

    def sanitizer_script(self):
        worker, _ = self.workflow()
        step = worker.split('      - name: Check native code with sanitizers\n', 1)[1].split(
            '      - name: Check installed runtime and doctor\n', 1)[0]
        return textwrap.dedent(step.split(" <<'PY'\n", 1)[1].rsplit('\n          PY', 1)[0])

    def test_phase_coverage_and_legacy_context_convergence(self):
        worker, gate = self.workflow()
        expected = [('macos-15', '3.12', '0'), ('macos-26', '3.11', '1'),
                    ('macos-26', '3.13', '1'), ('macos-26', '3.14', '1'),
                    ('macos-26-intel', '3.13', '1'), ('xcode-27', '3.13', '1')]
        rows = re.findall(r"^          - \{os: ([\w-]+), python: '([^']+)', images: '([^']+)', phase: (\w+)\}$",
                          worker, re.MULTILINE)
        self.assertEqual([row[:3] for row in rows if row[3] == 'installed'], expected)
        self.assertEqual([row[:3] for row in rows if row[3] == 'sanitizer'], [row for row in expected if row[1] == '3.13'])
        self.assertEqual(len(rows), 9)
        legacy = re.findall(r"^          - \{os: ([\w-]+), python: '([^']+)', images: '([^']+)'\}$", gate, re.MULTILINE)
        self.assertEqual(legacy, expected)
        self.assertIn('    name: test (${{ matrix.os }}, ${{ matrix.python }}, ${{ matrix.images }})\n', gate)
        self.assertIn('    needs: test-execution\n', gate)
        self.assertIn("    if: always() && github.event_name != 'workflow_dispatch'\n", gate)
        self.assertIn('EXECUTION_RESULT: ${{ needs.test-execution.result }}', gate)
        self.assertIn('    if: github.event_name != \'workflow_dispatch\'\n', worker)
        self.assertIn('    runs-on: ${{ matrix.os }}\n', worker)
        self.assertIn("    timeout-minutes: ${{ (matrix.os == 'macos-26-intel' || matrix.os == 'xcode-27') && 30 || (matrix.os == 'macos-26' && matrix.python == '3.13') && 20 || 15 }}\n", worker)
        self.assertIn('      fail-fast: false\n', worker)
        self.assertNotIn('continue-on-error:', worker + gate)
        sanitizer = worker.split('      - name: Check native code with sanitizers\n', 1)[1]
        self.assertTrue(sanitizer.startswith("        if: matrix.phase == 'sanitizer'\n"))
        self.assertIn('          ASAN_OPTIONS: halt_on_error=1\n', sanitizer)
        self.assertIn('          UBSAN_OPTIONS: halt_on_error=1:print_stacktrace=1\n', sanitizer)
        self.assertIn('          TSAN_OPTIONS: halt_on_error=1\n', sanitizer)
        smoke = sanitizer.split('      - name: Check installed runtime and doctor\n', 1)[1]
        self.assertTrue(smoke.startswith('        run: |\n'))
        self.assertIn('bootstrap.py" check "${CI_CONTAINER:?}"', smoke)
        self.assertIn('"${CI_STALLIONFS:?}" --root "$RUNNER_TEMP/stallionfs-smoke" doctor', smoke)
        tree = ast.parse(self.sanitizer_script())
        names = next(ast.literal_eval(n.value) for n in ast.walk(tree)
                     if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'names' for t in n.targets))
        self.assertEqual(names, ('test_fileops.FileOperations.test_native_swaps_enospc_no_fallback_cancellation_and_fd_cleanup',
                                 'test_scan.Scan.test_native_cancellation_close_errors_and_no_partial_cli_totals', 'test_image.ImageCore'))
        loop = next(n for n in ast.walk(tree) if isinstance(n, ast.For))
        self.assertEqual(ast.literal_eval(loop.iter), ('address,undefined', 'thread'))
        image = ast.parse((Path(__file__).with_name('test_image.py')).read_text())
        core = next(n for n in image.body if isinstance(n, ast.ClassDef) and n.name == 'ImageCore')
        methods = [n.name for n in core.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
        self.assertEqual(len(methods), 50)
        coverage = {(os, python, mode, method) for os, python, _, phase in rows if phase == 'sanitizer'
                    for mode in ast.literal_eval(loop.iter) for method in [*names[:2], *methods]}
        self.assertEqual(len(coverage), 312)

    def test_legacy_gate_runs_actual_success_only_command(self):
        _, gate = self.workflow()
        script = re.search(r'^        run: (.+)$', gate, re.MULTILINE)[1]
        self.assertEqual(script, 'test "${EXECUTION_RESULT:-}" = success')
        for outcome in (None, '', 'success', 'failure', 'cancelled', 'skipped', 'unknown', 'success\n', '$(printf success)'):
            with self.subTest(outcome=outcome):
                environment = dict(os.environ)
                environment.pop('EXECUTION_RESULT', None)
                if outcome is not None:
                    environment['EXECUTION_RESULT'] = outcome
                result = subprocess.run(['/bin/sh', '-e', '-c', script], env=environment,
                                        capture_output=True, text=True, timeout=2)
                self.assertEqual(result.returncode == 0, outcome == 'success')

    def test_sanitizer_process_requires_own_admission_both_modes_and_full_results(self):
        import importlib.util
        import sysconfig
        import stallionfs
        from stallionfs import _scan
        script = compile(self.sanitizer_script(), '<sanitizer-workflow>', 'exec')
        for profile in ('success', 'failure', 'skip', 'short-suite', 'short-result', 'initial-admission', 'final-admission', 'checkout-import'):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                checkout = base / 'checkout'
                environment = base / 'environment'; environment.touch()
                order, modes = [], []
                def check():
                    order.append('check')
                    if (profile == 'initial-admission' and len(order) == 2 or
                            profile == 'final-admission' and order.count('check') == 2):
                        raise RuntimeError('Runtime identity differs')
                def initialize(actual_checkout, wheel):
                    self.assertEqual((actual_checkout, wheel), (checkout, base / 'qualified-wheel'))
                    order.append('admit')
                    return {'check': check}
                controller = SimpleNamespace(initialize_installed=initialize)
                spec = SimpleNamespace(loader=Mock())
                suite = Mock(); suite.countTestCases.return_value = 51 if profile == 'short-suite' else 52
                def run(actual):
                    self.assertIs(actual, suite)
                    flags = os.environ['CFLAGS']
                    mode = 'thread' if '-fsanitize=thread' in flags else 'address,undefined'
                    self.assertEqual(flags, f'-g -fno-omit-frame-pointer -fsanitize={mode} -fno-sanitize-recover=all')
                    modes.append(mode); order.append(mode)
                    return SimpleNamespace(wasSuccessful=lambda: profile != 'failure',
                                           skipped=[('required', 'unavailable')] if profile == 'skip' else [],
                                           testsRun=51 if profile == 'short-result' else 52)
                with patch.dict(os.environ, GITHUB_WORKSPACE=str(checkout), RUNNER_TEMP=str(base), GITHUB_ENV=str(environment)), \
                        patch.object(sys, 'path', list(sys.path)), \
                        patch.object(stallionfs, '__file__', str((checkout if profile == 'checkout-import' else base) / 'site/stallionfs/__init__.py')), \
                        patch.object(_scan, '__file__', str(base / 'site/stallionfs/_scan.so'), create=True), \
                        patch.object(importlib.util, 'spec_from_file_location', return_value=spec) as load, \
                        patch.object(importlib.util, 'module_from_spec', return_value=controller), \
                        patch.object(sysconfig, 'get_path', return_value=str(Path(sys.prefix).resolve() / 'bin')), \
                        patch.object(unittest.defaultTestLoader, 'loadTestsFromNames', return_value=suite), \
                        patch.object(unittest, 'TextTestRunner', return_value=SimpleNamespace(run=run)):
                    if profile == 'success':
                        exec(script, {'__name__': '__main__'})
                    else:
                        with self.assertRaises((SystemExit, AssertionError, RuntimeError)):
                            exec(script, {'__name__': '__main__'})
                if profile == 'checkout-import':
                    self.assertEqual(order, []); load.assert_not_called()
                    continue
                load.assert_called_once_with('ci_build', checkout / 'tools/ci_build.py')
                spec.loader.exec_module.assert_called_once_with(controller)
                self.assertEqual(order[:2], ['admit', 'check'])
                self.assertEqual(order.count('check'), 1 if profile == 'initial-admission' else 2)
                self.assertEqual(modes, [] if profile in ('initial-admission', 'short-suite') else
                                 ['address,undefined', 'thread'] if profile in ('success', 'final-admission') else ['address,undefined'])


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
        self.enterContext(patch.object(space.images, '_device_identity', return_value=(2, 100, 20, 0o60600)))
        # These legacy observers use projected mappings; full graph mount refusal
        # and native node identity are exercised by test_image_detach.
        self.enterContext(patch.object(space.images, '_no_graph_mounts'))
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
        self.args = ('/usr/sbin/diskutil', 'eject', '/dev/disk999')
        self.record = {'owner-uid': os.getuid(), 'image-path': str(self.image),
                       'system-entities': [{'dev-entry': '/dev/disk999'}]}

    def scope(self, **changes):
        return dict(base=self.base, image=self.image, workspace='a' * 32, mountpoint=self.point,
                    stage='body', expected=False) | changes

    def test_discovery_order_reserves_single_before_capture_for_enospc(self):
        class FinishedLifecycle(Exception):
            pass
        state = {'stage': None}
        attached, repos, points, commands, before_images = set(), {}, {}, [], []
        primary = space.images._error('ENOSPC first detach failed'); primary.returncode = 64

        def clone(source, destination):
            if source in attached:
                raise space.images._error('attached source')
            shutil.copyfile(source, destination); destination.chmod(0o600)

        def attach(image, point):
            if image not in repos:
                point.mkdir(parents=True, mode=0o700)
                repo = point/'repo'; repo.mkdir()
                (repo/'file').write_bytes(b'original'); (repo/'file').chmod(0o640)
                (repo/'link').symlink_to('file'); (repo/'filler').touch()
                repos[image], points[image] = repo, point
            attached.add(image)
            return repos[image]

        def mounted(image):
            from stallionfs._scan import mounts
            record = mounts()[0]
            if record['readonly'] or record['ignore_ownership'] or record['device'] != '/dev/disk998':
                raise space.images._error('changed mapping')
            return dict(image=str(image), device='/dev/disk999', mountpoint=str(points[image]),
                        volume_device='/dev/disk998') if image in attached else None

        def command(*args):
            scope = diagnostics._scope.get()
            commands.append((state['stage'], scope['image'], diagnostics._detach_observation.get() is not None))
            if state['stage'] == 'space':
                raise primary
            attached.remove(scope['image'])
            return b''

        def detach(image, point):
            if point != points[image] or diagnostics._scope.get()['expected']:
                raise space.images._error('intentional detach refusal')
            return space.images._command(*self.args)

        def backing(base):
            base.mkdir(mode=0o700)
            seed = base/'seed.sparseimage'; seed.write_bytes(b'owned backing'); seed.chmod(0o600)
            return seed

        lifecycle_base = self.base/'lifecycle'; backing(lifecycle_base)
        identifier = 'b'*32
        image = lifecycle_base/'workspace.sparseimage'; image.write_bytes(b'owned backing'); image.chmod(0o600)
        point = lifecycle_base/'store/workspaces'/identifier/'volume'
        repo = attach(image, point)
        store = Mock(root=lifecycle_base/'store')
        store.prepare.return_value = {'id': 'seed'}
        store.create.return_value = {'id': identifier, 'path': str(repo)}
        def lifecycle_detach():
            with diagnostics.failure_scope(lifecycle_base, image, mountpoint=point):
                space.images.detach(image, point)
        store.unmount.side_effect = lambda *args: lifecycle_detach()
        snapshots = []
        def snapshot(*args):
            snapshots.append(args)
            if len(snapshots) == 1:
                raise lifecycle.StallionError('external worktree')
            attach(image, point); lifecycle_detach()
            raise FinishedLifecycle()
        store.snapshot.side_effect = snapshot

        clone_fixture = image_cases.Images('test_clone_ownership_busy_detach_and_recovery')
        clone_fixture.base = self.base/'images'; clone_fixture.seed = backing(clone_fixture.base)
        clone_fixture.observation = 'enospc-initial-detach'
        native = [dict(path=str(clone_fixture.base/'first'), device='/dev/disk998', readonly=False, ignore_ownership=False)]
        space_fixture = space.ImageSpace()
        space_fixture.base = self.base/'space'; space_fixture.seed = backing(space_fixture.base)
        space_fixture.source = space_fixture.base/'source'; space_fixture.image_points = {}
        space_fixture.observation = 'enospc-initial-detach'
        space_first = space_fixture.base/'full.sparseimage'
        stream = Mock(); stream.write.side_effect = [1, OSError(errno.ENOSPC, 'full')]
        opened = Mock(); opened.__enter__ = Mock(return_value=stream); opened.__exit__ = Mock(return_value=False)
        original_open = Path.open
        def open_path(path, *args, **kwargs):
            return opened if path.name == 'filler' else original_open(path, *args, **kwargs)

        with patch.dict(os.environ, STALLIONFS_TEST_SNAPSHOT_OBSERVATION='enospc-initial-detach'), \
                patch.object(space.images, 'clone', side_effect=clone), patch.object(space.images, 'attach', side_effect=attach), \
                patch.object(space.images, 'mounted', side_effect=mounted), patch.object(space.images, 'detach', side_effect=detach), \
                patch.object(space.images, '_command', side_effect=command), \
                patch.object(lifecycle.tempfile, 'mkdtemp', return_value=str(lifecycle_base)), \
                patch.object(lifecycle, 'Store', return_value=store), patch.object(lifecycle, 'git'), \
                patch.object(lifecycle, 'image_fixture', return_value=nullcontext(SimpleNamespace(call=lambda fn, *args, **kwargs: fn(*args)))), \
                patch.object(image_cases.subprocess, 'check_output', return_value=b'attribute'), \
                patch('stallionfs._scan.mounts', return_value=native), \
                patch.object(space_fixture, 'assert_original'), patch.object(space, 'digest', return_value='same'), \
                patch.object(space, 'fullsync', side_effect=lambda path, value: path.write_bytes(value)), patch.object(Path, 'open', open_path):
            collector = diagnostics.install(space.images, self.reporter.directory)
            self.addCleanup(collector.close); self.reporter = collector
            def mapping(args, scope, deadline):
                info = scope['image'].stat()
                if collector.phase == 'before': before_images.append(scope['image'])
                return str(scope['image']), ['/dev/disk999'], str(scope['mountpoint']), '/dev/disk998', (info.st_dev, info.st_ino)
            order = sorted((Path(module.__file__).name, name) for module, name in
                           ((lifecycle, 'lifecycle'), (image_cases, 'images'), (space, 'space')))
            self.assertEqual([name for _, name in order], ['lifecycle', 'images', 'space'])
            with patch.object(collector, '_mapping', side_effect=mapping), patch.object(collector, '_capture', side_effect=lambda *args: captured(b'', status=1)):
                for _, name in order:
                    state['stage'] = name
                    if name == 'lifecycle':
                        with self.assertRaises(FinishedLifecycle):
                            lifecycle.ImageStoreTests.test_snapshot_rollback_and_protected_retirement(self)
                    elif name == 'images':
                        clone_fixture.test_clone_ownership_busy_detach_and_recovery()
                    else:
                        with self.assertRaises(type(primary)) as caught:
                            space_fixture.test_volume_full_preserves_existing_data_and_other_images()
                        self.assertIs(caught.exception, primary)
                    self.assertEqual(collector.before_attempts, int(name == 'space'))
                    if name != 'space': self.assertEqual(collector.attempts, 0, name)
            self.assertEqual(before_images, [space_first])
            self.assertEqual(len(commands), 7)
            self.assertEqual([selected for _, _, selected in commands], [False]*6+[True])
            events = self.events()
            before = next(event for event in events if event['phase'] == 'before')
            failed = next(event for event in events if event['kind'] == 'failure')
            self.assertEqual(before['operation_id'], failed['operation_id'])
            self.assertEqual(failed['pre_observation'], 'attempted')
            self.assertEqual(collector.attempts, 1, (getattr(primary, '__notes__', []), events))

    def test_clone_fixture_selector_validates_before_allocation(self):
        for value in ('enospc-initial-detach', '', 'unknown'):
            with patch.dict(os.environ, STALLIONFS_TEST_SNAPSHOT_OBSERVATION=value), \
                    patch.object(image_cases.tempfile, 'mkdtemp', side_effect=OSError('stop before allocation')) as allocate:
                fixture = image_cases.Images()
                with self.assertRaises(OSError if value == 'enospc-initial-detach' else ValueError):
                    fixture._prepare()
                self.assertEqual(allocate.call_count, int(value == 'enospc-initial-detach'))

    def events(self):
        return [json.loads(s) for s in (self.reporter.directory / diagnostics.REPORT).read_text().splitlines()]

    def eject_observation(self, **changes):
        identity = self.image.stat()
        self.reporter.eject_contexts[1] = dict(image=str(self.image), target=self.args[2],
            identity=(identity.st_dev, identity.st_ino), deadline=time.monotonic() + 12)
        return dict(operation_id=1, deadline=self.reporter.eject_contexts[1]['deadline'],
                    scope=self.scope(), target=self.args[2],
                    start_ns=1700000000 * 10**9, end_ns=1700000002 * 10**9,
                    start_mono=10, end_mono=12) | changes

    def log_record(self, message, **changes):
        value = dict(timestamp='2023-11-14 22:13:21.000000+0000', subsystem=diagnostics.DA_SUBSYSTEM,
                     processImagePath='/usr/libexec/diskarbitrationd', eventMessage=message,
                     unused_private_field='/Users/unrelated/private-file') | changes
        return (json.dumps(value) + '\n').encode()

    def test_eject_log_retains_only_exact_public_stage_and_status(self):
        native = 'unable to eject /dev/disk999 (status code 0x00000010).'
        approval = ('  dispatched response, id = 1234567890ABCDEF:0123456789ABCDEF, '
                    'kind = DADiskEjectApprovalCallback, disk = /dev/disk999, dissented, status = 0xF8DA0002.')
        raw = (self.log_record(native) + self.log_record(approval) +
               self.log_record(native.replace('disk999', 'disk9990')) +
               self.log_record(native.replace('disk999', 'disk999s1')) +
               self.log_record(native, subsystem='unrelated') +
               self.log_record(native, processImagePath='/usr/bin/unrelated') +
               self.log_record(native, timestamp='2023-11-14 22:13:19.000000+0000') +
               self.log_record('private reason: /Users/unrelated/private-file') + b'{"finished":true}\n')
        observation = self.eject_observation()
        def capture(argv, deadline):
            self.assertEqual(self.reporter.remaining, diagnostics.EJECT_CAPTURE_BYTES)
            self.assertEqual(deadline, self.reporter.eject_contexts[1]['deadline'])
            self.assertEqual(argv[:4], ['/usr/bin/log', 'show', '--style', 'ndjson'])
            self.assertEqual(argv[argv.index('--start') + 1], '2023-11-14 22:13:20+0000')
            self.assertEqual(argv[argv.index('--end') + 1], '2023-11-14 22:13:22+0000')
            self.assertIn('--no-debug', argv)
            self.assertIn('--no-info', argv)
            self.assertIn('subsystem == "' + diagnostics.DA_SUBSYSTEM + '"', argv[-1])
            self.assertIn('process == "diskarbitrationd"', argv[-1])
            self.assertIn('"unable to eject /dev/disk999 (status code "', argv[-1])
            self.assertIn('"disk = /dev/disk999, dissented, status = "', argv[-1])
            self.assertNotIn(str(self.image), argv[-1])
            self.reporter.remaining -= len(raw)
            return captured(raw)
        initial = self.reporter.remaining
        with patch.object(self.reporter, '_capture', side_effect=capture) as query:
            self.reporter.eject_log(observation)
            self.reporter.eject_log(observation)
        query.assert_called_once()
        event = self.events()[-1]
        self.assertEqual(event['query_status'], 'matched')
        self.assertIn('native_eject_failed /dev/disk999 0x00000010', event['records'])
        self.assertIn('approval_dissent /dev/disk999 0xF8DA0002', event['records'])
        self.assertEqual(len(event['records'].splitlines()), 2)
        for secret in ('1234567890ABCDEF', 'unused_private_field', '/Users/', 'disk9990', 'disk999s1'):
            self.assertNotIn(secret, (self.reporter.directory / diagnostics.REPORT).read_text())
        self.assertEqual(self.reporter.remaining, initial - len(raw))
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_eject_query_filters_both_status_families_and_exact_device_before_capture(self):
        observation = self.eject_observation()
        with patch.object(self.reporter, '_capture', return_value=captured()) as query:
            self.reporter.eject_log(observation)
        argv = query.call_args.args[0]
        predicate = argv[argv.index('--predicate') + 1]
        process, subsystem, statuses = predicate.split(' AND ', 2)
        self.assertEqual(process, 'process == "diskarbitrationd"')
        self.assertEqual(subsystem, 'subsystem == "' + diagnostics.DA_SUBSYSTEM + '"')
        self.assertTrue(statuses.startswith('((') and statuses.endswith('))'))
        branches = statuses[1:-1].split(' OR ')
        self.assertEqual(len(branches), 2)

        def accepts(message):
            # Evaluate the emitted CONTAINS branches, without invoking log show.
            matches = []
            for branch in branches:
                self.assertTrue(branch.startswith('(') and branch.endswith(')'))
                clauses = branch[1:-1].split(' AND ')
                values = []
                for clause in clauses:
                    parsed = re.fullmatch(r'eventMessage CONTAINS(\[c\])? "([^"]*)"', clause)
                    self.assertIsNotNone(parsed)
                    insensitive, needle = parsed.groups()
                    values.append(needle.lower() in message.lower() if insensitive else needle in message)
                matches.append(all(values))
            return any(matches)

        native = 'unable to eject /dev/disk999 (status code 0x00000010).'
        approval = ('dispatched response, id = 1234567890ABCDEF:0123456789ABCDEF, '
                    'kind = DADiskEjectApprovalCallback, disk = /dev/disk999, dissented, status = 0xF8DA0002.')
        for message in (native, approval, approval.replace('EjectApproval', 'eJeCtApPrOvAl')):
            with self.subTest(accepted=message):
                self.assertTrue(accepts(message))
        rejected = [native.replace('disk999', disk) for disk in ('disk9990', 'disk999s1')]
        rejected += [approval.replace('disk999', disk) for disk in ('disk9990', 'disk999s1')]
        rejected += [native.replace('status code ', 'reason '),
                     approval.replace('dispatched response', 'dispatched request'),
                     approval.replace('EjectApproval', 'UnmountApproval'),
                     approval.replace('EjectApproval', 'EjectCompletion'),
                     approval.replace('dissented, status', 'approved, status'),
                     'unrelated activity for /dev/disk999, and /dev/disk999 (']
        for message in rejected:
            with self.subTest(rejected=message):
                self.assertFalse(accepts(message))
        self.assertNotIn(str(self.image), predicate)
        query.assert_called_once()

    def test_clipped_final_record_preserves_prior_status_and_incomplete_result(self):
        raw = (self.log_record('unable to eject /dev/disk999 (status code 0x00000010).') +
               b'{"eventMessage":"dispatched response, id = ')
        with patch.object(self.reporter, '_capture', return_value=captured(raw) | dict(truncated=True)) as query:
            self.reporter.eject_log(self.eject_observation())
        query.assert_called_once()
        event = self.events()[-1]
        self.assertEqual((event['query_status'], event['reason'], event['truncated']),
                         ('incomplete', 'malformed_records', True))
        self.assertEqual(event['records'],
                         '2023-11-14T22:13:21.000000+00:00 native_eject_failed /dev/disk999 0x00000010\n')
        self.assertNotIn('dispatched response', json.dumps(event))
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_eject_log_empty_denied_malformed_redacted_and_partial_are_inconclusive(self):
        native = self.log_record('unable to eject /dev/disk999 (status code 0x00000010).')
        cases = [('empty', captured(b'{"finished":true}\n'), 'empty'),
                 ('denied', captured(b'private reason', b'/private/unrelated', 1), 'unavailable'),
                 ('malformed', captured(b'not json\n'), 'incomplete'),
                 ('redacted', captured(self.log_record('unable to eject /dev/disk999 <private>')), 'incomplete'),
                 ('timeout', captured(native) | dict(timeout=True), 'incomplete'),
                 ('truncated', captured(native) | dict(truncated=True), 'incomplete'),
                 ('cleanup', captured(native) | dict(cleanup_error='PermissionError'), 'incomplete'),
                 ('spawn', OSError('private path /Users/unrelated'), 'unavailable')]
        for label, response, expected in cases:
            with self.subTest(label=label):
                self.reporter.eject_log_attempted = False
                observation = self.eject_observation()
                with patch.object(self.reporter, '_capture', side_effect=response if isinstance(response, Exception) else None,
                                  return_value=response):
                    self.reporter.eject_log(observation)
                event = self.events()[-1]
                self.assertEqual(event['query_status'], expected)
                self.assertNotIn('/Users/', json.dumps(event))
                self.assertNotIn('/private/unrelated', json.dumps(event))
        records, reason, limited = diagnostics._eject_records(native * 100, self.args[2],
            1700000000 * 10**9, 1700000002 * 10**9)
        self.assertTrue(limited)
        self.assertIsNone(reason)
        self.assertLessEqual(len(records.encode()), diagnostics.EJECT_RETAINED_BYTES)
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_eject_log_requires_owned_mapping_time_window_and_remaining_budget(self):
        for label in ('expected', 'mapping', 'identity', 'target', 'window', 'clock', 'disabled', 'bytes', 'events', 'deadline', 'no_deadline'):
            with self.subTest(label=label):
                self.reporter.eject_log_attempted = self.reporter.capture_disabled = False
                self.reporter.remaining = diagnostics.CAPTURE_BYTES
                self.reporter.events = self.reporter.written = 0
                observation = self.eject_observation()
                context = self.reporter.eject_contexts[1]
                if label == 'expected': observation['scope']['expected'] = True
                elif label == 'mapping': self.reporter.eject_contexts.clear()
                elif label == 'identity': context['identity'] = (-1, -1)
                elif label == 'target': observation['target'] = '/Users/private/" OR TRUE'
                elif label == 'window': observation.update(end_ns=observation['start_ns'] + 31 * 10**9, end_mono=41)
                elif label == 'clock': observation['end_ns'] += 2 * 10**9
                elif label == 'disabled': self.reporter.capture_disabled = True
                elif label == 'bytes': self.reporter.remaining = 0
                elif label == 'events': self.reporter.events = diagnostics.EVENTS
                elif label == 'deadline': context['deadline'] = time.monotonic() + 0.5
                elif label == 'no_deadline': observation.pop('deadline')
                with patch.object(self.reporter, '_capture') as capture, patch.object(self.reporter, '_emit') as emit:
                    self.reporter.eject_log(observation)
                capture.assert_not_called()
                if label == 'no_deadline':
                    emit.assert_not_called()  # No existing observation budget to spend.
                    continue
                self.assertEqual(emit.call_args.kwargs['query_status'], 'unavailable')
                self.assertEqual(emit.call_args.kwargs['records'], '')
                self.assertNotIn('/Users/private', str(emit.call_args))

    def test_eject_log_uses_only_budget_remaining_after_earlier_captures(self):
        now = [100.0]
        raw = self.log_record('unable to eject /dev/disk999 (status code 0x00000010).')
        with patch.object(diagnostics.time, 'monotonic', side_effect=lambda: now[0]):
            observation = self.eject_observation()
            observation.pop('deadline')
            self.reporter.eject_contexts.clear()
            identity = self.image.stat()
            # Prior observation work used time and output, but did not renew its deadline.
            earlier_output = self.holder_output()
            def earlier_capture(argv, deadline):
                self.assertEqual(argv[0], '/usr/sbin/lsof')
                now[0] += 6.5
                self.reporter.remaining -= len(earlier_output)
                return captured(earlier_output, status=1)
            with patch.object(self.reporter, '_mapping', return_value=(str(self.image),
                    [self.args[2]], None, None, (identity.st_dev, identity.st_ino))), \
                    patch.object(self.reporter, '_capture', side_effect=earlier_capture):
                self.reporter.report(self.args, OSError('busy'), self.scope(), 1, observation)
            self.assertEqual(observation['deadline'], 112.0)
            initial = self.reporter.remaining
            def capture(argv, deadline):
                self.assertEqual(deadline, 112.0)
                self.assertEqual(deadline - now[0], 5.5)
                self.assertEqual(self.reporter.remaining, diagnostics.EJECT_CAPTURE_BYTES)
                self.assertEqual(argv[:2], ['/usr/bin/log', 'show'])
                self.reporter.remaining -= len(raw)
                now[0] = deadline - 0.8  # Collection and reap stay inside the original deadline.
                return captured(raw, status=-9) | dict(timeout=True)
            with patch.object(self.reporter, '_capture', side_effect=capture) as query, \
                    patch.object(self.reporter, 'lock', wraps=self.reporter.lock) as lock:
                self.reporter.eject_log(observation)
                self.reporter.eject_log(observation)
        query.assert_called_once()
        self.assertEqual(lock.acquire.call_args_list[0], call(timeout=5.5))
        self.assertEqual(self.reporter.remaining, initial - len(raw))
        event = self.events()[-1]
        self.assertEqual(event['query_status'], 'unavailable')
        self.assertEqual(event['reason'], 'log_query_failed')
        self.assertEqual(event['returncode'], -9)
        self.assertTrue(event['timeout'])
        self.assertTrue(event['reaped'])
        self.assertEqual(event['records'], '')
        self.assertLessEqual(self.reporter.written, diagnostics.FILE_BYTES)
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_eject_log_rechecks_context_after_lock_without_extending_deadline(self):
        for changed in ('removed', 'later_deadline', 'expired_deadline'):
            with self.subTest(changed=changed):
                self.reporter.eject_log_attempted = False
                with patch.object(diagnostics.time, 'monotonic', return_value=100.0):
                    observation = self.eject_observation()
                def acquire(*, timeout):
                    self.assertEqual(timeout, 5.5)
                    context = self.reporter.eject_contexts.pop(1)
                    if changed != 'removed':
                        self.reporter.eject_contexts[1] = dict(context,
                            deadline=130.0 if changed == 'later_deadline' else 105.0)
                    return True
                lock = Mock()
                lock.acquire.side_effect = acquire
                with patch.object(diagnostics.time, 'monotonic', return_value=106.5), \
                        patch.object(self.reporter, 'lock', lock), \
                        patch.object(self.reporter, '_capture', return_value=captured(b'{"finished":true}\n')) as query, \
                        patch.object(self.reporter, '_emit') as emit:
                    self.reporter.eject_log(observation)
                lock.release.assert_called_once()
                if changed == 'later_deadline':
                    query.assert_called_once()
                    self.assertEqual(query.call_args.args[1], 112.0)
                    self.assertEqual(emit.call_args.kwargs['query_status'], 'empty')
                else:
                    query.assert_not_called()
                    if changed == 'removed':
                        self.assertEqual(emit.call_args.kwargs['reason'], 'no_verified_attachment_mapping')
                        self.assertEqual(emit.call_args.kwargs['query_status'], 'unavailable')
                    else:
                        emit.assert_not_called()

    def test_eject_log_expired_existing_budget_cannot_wait_capture_or_write(self):
        observation = self.eject_observation()
        deadline = self.reporter.eject_contexts[1]['deadline']
        initial = self.reporter.remaining
        with patch.object(diagnostics.time, 'monotonic', return_value=deadline + 1), \
                patch.object(self.reporter, '_capture') as query, \
                patch.object(self.reporter, '_emit') as emit, \
                patch.object(self.reporter, 'lock', wraps=self.reporter.lock) as lock:
            self.reporter.eject_log(observation)
            self.reporter.eject_log(observation)
        self.assertEqual(lock.acquire.call_args_list, [call(timeout=0)] * 2)
        query.assert_not_called()
        emit.assert_not_called()
        self.assertTrue(self.reporter.eject_log_attempted)
        self.assertEqual(self.reporter.remaining, initial)
        self.assertFalse(self.reporter.directory.exists())

    def test_eject_log_keeps_one_second_cleanup_reserve_in_existing_budget(self):
        observation = self.eject_observation()
        deadline = self.reporter.eject_contexts[1]['deadline']
        with patch.object(diagnostics.time, 'monotonic', return_value=deadline - 0.5), \
                patch.object(self.reporter, '_capture') as query:
            self.reporter.eject_log(observation)
        query.assert_not_called()
        event = self.events()[-1]
        self.assertEqual(event['query_status'], 'unavailable')
        self.assertEqual(event['reason'], 'diagnostic_budget_exhausted')
        self.assertEqual(event['records'], '')
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_eject_log_uncertain_capture_cannot_restore_budget(self):
        observation = self.eject_observation()
        def capture(argv, deadline):
            self.assertEqual(self.reporter.remaining, diagnostics.EJECT_CAPTURE_BYTES)
            self.reporter.capture_disabled = True
            self.reporter.remaining = 0
            return captured() | dict(cleanup_error='PermissionError', reaped=False)
        with patch.object(self.reporter, '_capture', side_effect=capture) as query:
            self.reporter.eject_log(observation)
            self.reporter.eject_log(observation)
        query.assert_called_once()
        self.assertEqual(self.reporter.remaining, 0)
        self.assertEqual(self.events()[-1]['query_status'], 'incomplete')

    def test_actual_intentional_refusal_scope_leaves_recovery_failure_unexpected(self):
        fixture = image_cases.Images('test_clone_ownership_busy_detach_and_recovery')
        fixture.base = self.base / 'busy-case'
        fixture.base.mkdir(mode=0o700)
        fixture.seed = fixture.base / 'seed.sparseimage'
        fixture.seed.write_bytes(b'synthetic backing')
        first = fixture.base / 'first.sparseimage'
        first_mount = fixture.base / 'first'
        native = [dict(path=str(first_mount), device='/dev/disk998', readonly=False, ignore_ownership=False)]
        attached, scopes, observations = {}, [], []
        primary = image_cases.StallionError('unexpected recovery failure')
        def clone(source, destination):
            if source in attached:
                raise image_cases.StallionError('attached source')
            shutil.copyfile(source, destination)
        def attach(image, point):
            if image not in attached:
                point.mkdir(mode=0o700)
                repo = point / 'repo'
                repo.mkdir()
                (repo / 'file').write_bytes(b'original')
                (repo / 'file').chmod(0o640)
                (repo / 'link').symlink_to('file')
                attached[image] = repo
            return attached[image]
        def mounted(image):
            from stallionfs._scan import mounts
            record = mounts()[0]
            if record['readonly'] or record['ignore_ownership'] or record['device'] != '/dev/disk998':
                raise image_cases.StallionError('changed mapping')
            return dict(mountpoint=str(first_mount), device='/dev/disk999')
        def detach(image, point):
            if point != first_mount:
                raise image_cases.StallionError('wrong mountpoint')
            scope = diagnostics._scope.get()
            scopes.append(scope)
            observations.append(diagnostics._detach_observation.get() is not None)
            error = image_cases.StallionError('intentional busy') if scope['expected'] else primary
            self.reporter.report(self.args, error, scope)
            raise error
        with patch.object(image_cases.images, 'clone', side_effect=clone), \
                patch.object(image_cases.images, 'attach', side_effect=attach), \
                patch.object(image_cases.images, 'mounted', side_effect=mounted), \
                patch.object(image_cases.images, 'detach', side_effect=detach), \
                patch.object(image_cases.subprocess, 'check_output', return_value=b'attribute'), \
                patch('stallionfs._scan.mounts', return_value=native), self.assertRaises(type(primary)) as caught:
            image_cases.Images.test_clone_ownership_busy_detach_and_recovery(fixture)
        self.assertIs(caught.exception, primary)
        self.assertEqual(scopes, [dict(base=fixture.base, image=first, workspace=None,
            mountpoint=first_mount, stage='body', expected=True),
            dict(base=fixture.base, image=first, workspace=None,
                 mountpoint=first_mount, stage='body', expected=False)])
        self.assertEqual(self.reporter.attempts, 1)
        self.assertEqual(self.events()[0]['message'], 'unexpected recovery failure')
        self.assertEqual(observations, [False, False])
        self.assertIsNone(diagnostics._detach_observation.get())
        self.assertIsNone(diagnostics._scope.get())

    def test_seed_setup_retains_actual_build_failure_without_spending_observation(self):
        for interrupt in (False, True):
            with self.subTest(interrupt=interrupt):
                fixture = image_cases.Images()
                base = self.base / ('setup-interrupt' if interrupt else 'setup-error')
                base.mkdir(mode=0o700)
                primary = KeyboardInterrupt('interrupted') if interrupt else image_cases.StallionError('eject failed')
                primary.returncode = 64
                point = base / 'prepare-mount'; point.mkdir(mode=0o700)
                def command(*args):
                    if args[1] == 'create':
                        fixture.seed.write_bytes(b'retained seed'); fixture.seed.chmod(0o600)
                    return b''
                def detach(image, mountpoint):
                    self.assertEqual((image, mountpoint), (fixture.seed, point))
                    self.assertEqual(diagnostics._scope.get()['stage'], 'setup')
                    self.assertIsNone(diagnostics._detach_observation.get())
                    raise primary
                with patch.object(image_cases.tempfile, 'mkdtemp', side_effect=[str(base), str(point)]), \
                        patch.object(image_cases.subprocess, 'run'), \
                        patch.object(image_cases.images, '_require_supported'), \
                        patch('stallionfs.core.validate_tree'), \
                        patch.object(image_cases.images.os, 'chown'), \
                        patch.object(image_cases.images, '_command', side_effect=command), \
                        patch.object(image_cases.images, 'attach', return_value=point / 'repo'), \
                        patch.object(image_cases.images, 'detach', side_effect=detach) as native, \
                        patch.object(image_cases.images, 'mounted') as inspect, \
                        patch.object(image_cases.shutil, 'rmtree') as remove:
                    with self.assertRaises(type(primary)) as caught:
                        fixture.setUp()
                    fixture.tearDown()
                self.assertIs(caught.exception, primary)
                native.assert_called_once(); inspect.assert_not_called(); remove.assert_not_called()
                self.assertEqual(fixture.failed_images, {fixture.seed})
                self.assertTrue(fixture.retain)
                self.assertEqual(fixture.seed.read_bytes(), b'retained seed')
                self.assertEqual(self.reporter.before_attempts, 0)
                self.assertIsNone(diagnostics._scope.get())

    def test_actual_clone_fixture_selects_remounted_detach_and_never_retries_failure(self):
        for failure in ('none', 'release', 'selected', 'interrupt', 'body'):
            with self.subTest(failure=failure):
                fixture = image_cases.Images('test_clone_ownership_busy_detach_and_recovery')
                fixture.base = self.base / ('clone-' + failure); fixture.base.mkdir(mode=0o700)
                fixture.seed = fixture.base / 'seed.sparseimage'
                fixture.seed.write_bytes(b'seed'); fixture.seed.chmod(0o600)
                first, second = fixture.base / 'first.sparseimage', fixture.base / 'second.sparseimage'
                first_point = fixture.base / 'first'
                attached, points, repos, calls, selected = set(), {}, {}, [], []
                primary = KeyboardInterrupt('selected interrupt') if failure == 'interrupt' else image_cases.StallionError(failure)
                primary.returncode = 64
                native = [dict(path=str(first_point), device='/dev/disk998', readonly=False, ignore_ownership=False)]
                def clone(source, destination):
                    if source in attached:
                        raise image_cases.StallionError('attached source')
                    shutil.copyfile(source, destination)
                    destination.chmod(0o600)
                def attach(image, point):
                    if image not in repos:
                        point.mkdir(mode=0o700)
                        repo = point / 'repo'; repo.mkdir()
                        (repo / 'file').write_bytes(b'original'); (repo / 'file').chmod(0o640)
                        (repo / 'link').symlink_to('file')
                        repos[image], points[image] = repo, point
                    attached.add(image)
                    return repos[image]
                def mounted(image):
                    from stallionfs._scan import mounts
                    record = mounts()[0]
                    if record['readonly'] or record['ignore_ownership'] or record['device'] != '/dev/disk998':
                        raise image_cases.StallionError('changed mapping')
                    return dict(image=str(image), device='/dev/disk999', mountpoint=str(points[image]),
                                volume_device='/dev/disk998') if image in attached else None
                def command(*args):
                    scope = diagnostics._scope.get()
                    image = scope['image']
                    observed = diagnostics._detach_observation.get() is not None
                    calls.append(image); selected.append(observed)
                    if ((failure == 'release' and image == first and not observed) or
                            (failure in ('selected', 'interrupt') and observed)):
                        raise primary
                    attached.remove(image)
                    return b''
                def detach(image, point):
                    if points[image] != point:
                        raise image_cases.StallionError('wrong mountpoint')
                    if diagnostics._scope.get()['expected']:
                        raise image_cases.StallionError('intentional busy')
                    return image_cases.images._command(*self.args)
                def xattr(*args):
                    if failure == 'body':
                        raise primary
                    return b'attribute'
                with patch.object(image_cases.images, 'clone', side_effect=clone), \
                        patch.object(image_cases.images, 'attach', side_effect=attach), \
                        patch.object(image_cases.images, 'mounted', side_effect=mounted), \
                        patch.object(image_cases.images, 'detach', side_effect=detach), \
                        patch.object(image_cases.images, '_command', side_effect=command), \
                        patch.object(image_cases.subprocess, 'check_output', side_effect=xattr), \
                        patch('stallionfs._scan.mounts', return_value=native), \
                        patch.object(image_cases.shutil, 'rmtree') as remove:
                    collector = diagnostics.install(image_cases.images, fixture.base / 'diagnostics')
                    self.addCleanup(collector.close)
                    def mapping(args, scope, deadline):
                        image = scope['image']; info = image.stat()
                        return str(image), ['/dev/disk999'], None, None, (info.st_dev, info.st_ino)
                    with patch.object(collector, '_mapping', side_effect=mapping), \
                            patch.object(collector, '_capture', return_value=captured(b'', status=1)), \
                            patch.object(collector, 'eject_log') as query:
                        if failure == 'none':
                            fixture._callTestMethod(fixture.test_clone_ownership_busy_detach_and_recovery)
                            self.assertFalse(fixture.failed_images or fixture.retain)
                            self.assertEqual((repos[first] / 'file').read_bytes(), b'changed')
                            self.assertEqual((repos[second] / 'file').read_bytes(), b'original')
                            self.assertEqual((repos[fixture.seed] / 'file').read_bytes(), b'original')
                        else:
                            with self.assertRaises(type(primary)) as caught:
                                fixture._callTestMethod(fixture.test_clone_ownership_busy_detach_and_recovery)
                            self.assertIs(caught.exception, primary)
                        before_cleanup = list(calls)
                        fixture.tearDown()
                        self.assertEqual(calls, before_cleanup)
                        self.assertEqual(query.call_count, int(failure in ('release', 'selected')))
                    if failure == 'none':
                        remove.assert_called_once_with(fixture.base)
                        self.assertFalse(attached)
                    else:
                        remove.assert_not_called()
                        self.assertTrue(fixture.retain)
                        self.assertTrue(fixture.seed.exists() and first.exists() and second.exists())
                self.assertEqual(selected, [] if failure == 'body' else [False] if failure == 'release'
                                 else [False, True] if failure != 'none' else [False, True, False, False])
                self.assertEqual(collector.before_attempts, int(failure not in ('body', 'release')))
                self.assertIsNone(diagnostics._scope.get()); self.assertIsNone(diagnostics._detach_observation.get())

    def test_cleanup_uncertainty_retains_actual_fixture_and_primary(self):
        for failure in ('detach', 'inventory', 'interrupt', 'postinventory'):
            with self.subTest(failure=failure):
                fixture = image_cases.Images()
                fixture.base = self.base / ('cleanup-' + failure); fixture.base.mkdir(mode=0o700)
                image = fixture.base / 'copy.sparseimage'; image.write_bytes(b'keep')
                point = fixture.base / 'volume'
                primary = KeyboardInterrupt() if failure == 'interrupt' else image_cases.StallionError(failure)
                state = dict(mountpoint=str(point))
                states = [primary] if failure == 'inventory' else [state, primary] if failure == 'postinventory' else [state]
                def detach(actual_image, actual_point):
                    self.assertEqual((actual_image, actual_point), (image, str(point)))
                    self.assertEqual(diagnostics._scope.get()['stage'], 'cleanup')
                    self.assertIsNone(diagnostics._detach_observation.get())
                    if failure != 'postinventory':
                        raise primary
                with patch.object(image_cases.images, 'mounted', side_effect=states) as inspect, \
                        patch.object(image_cases.images, 'detach', side_effect=detach) as command, \
                        patch.object(image_cases.shutil, 'rmtree') as remove:
                    with self.assertRaises(type(primary)) as caught:
                        fixture.tearDown()
                    count = inspect.call_count
                    fixture.tearDown()
                self.assertIs(caught.exception, primary)
                self.assertEqual(inspect.call_count, count)
                self.assertEqual(command.call_count, int(failure != 'inventory'))
                remove.assert_not_called()
                self.assertEqual(image.read_bytes(), b'keep')

    def test_one_eject_failure_keeps_command_identity_and_exact_arguments(self):
        primary = space.images._error('eject failed'); primary.returncode = 64
        order = []
        def original(*args):
            order.append('eject')
            raise primary
        current = dict(image=str(self.image), device='/dev/disk999', mountpoint=str(self.point),
                       volume_device='/dev/disk999s1')
        with patch.object(space.images, '_command', side_effect=original) as command, \
                patch.object(space.images, 'mounted', return_value=current):
            collector = diagnostics.install(space.images, self.base / 'unused')
            self.addCleanup(collector.close)
            def before(args, scope, observation):
                order.append('before'); observation['operation_id'] = 1
            def query(observation):
                command.assert_called_once_with(*self.args)
                self.assertIs(observation['command_error'], primary)
                self.assertEqual(observation['command_status'], 64)
                self.assertEqual(observation['target'], '/dev/disk999')
                self.assertLessEqual(observation['start_ns'], observation['end_ns'])
                order.append('log')
            with patch.object(collector, 'before', side_effect=before), \
                    patch.object(collector, 'report', side_effect=lambda *a, **k: order.append('report')), \
                    patch.object(collector, 'eject_log', side_effect=query), \
                    diagnostics.failure_scope(self.base, self.image, mountpoint=self.point), \
                    self.assertRaises(type(primary)) as caught:
                with diagnostics.observe_detach():
                    space.images.detach(self.image, self.point)
        self.assertIs(caught.exception, primary)
        self.assertEqual(order, ['before', 'eject', 'report', 'log'])
        self.assertIsNone(diagnostics._detach_observation.get())

    def test_real_detach_observes_before_validation_and_refuses_changed_owned_backing(self):
        cases = ('stable', 'observer_error', 'observer_timeout', 'exhausted', 'missing',
                 'replaced', 'symlink', 'private', 'error_replaced', 'disappeared',
                 'reused', 'owner', 'mountpoint', 'between_device', 'between_backing')
        for change in cases:
            with self.subTest(change=change), tempfile.TemporaryDirectory(dir=self.base) as temporary:
                base = Path(temporary)
                image, point = base / 'workspace.sparseimage', base / 'volume'
                image.write_bytes(b'owned backing'); image.chmod(0o600)
                point.mkdir(mode=0o700)
                current = dict(image=str(image), device='/dev/disk999', mountpoint=str(point),
                               volume_device='/dev/disk999s1')
                primary = space.images._error('original eject failed'); primary.returncode = 64
                order, validation_calls = [], []
                fixture = image_cases.Images()
                fixture.base = base

                def replace():
                    image.rename(base / 'retained-original')
                    image.write_bytes(b'replacement'); image.chmod(0o600)

                def before(args, scope, observation):
                    self.assertEqual(args, ('/usr/sbin/diskutil', 'eject', None))
                    order.append('before')
                    observation['observed_target'] = '/dev/disk999'
                    if change in ('replaced', 'error_replaced'):
                        replace()
                    elif change == 'missing':
                        image.rename(base / 'retained-original')
                    elif change == 'symlink':
                        image.rename(base / 'retained-original')
                        image.symlink_to(base / 'retained-original')
                    elif change == 'private':
                        image.chmod(0o644)
                    if change in ('observer_error', 'error_replaced'):
                        raise OSError('observation failed')
                    if change == 'observer_timeout':
                        raise TimeoutError('observation deadline')

                def mounted(actual):
                    self.assertEqual(actual, image)
                    validation_calls.append(actual)
                    order.append('validation')
                    if change == 'disappeared':
                        return None
                    if change == 'owner':
                        raise space.images._error('attachment owner changed')
                    if change == 'reused':
                        return dict(current, image=str(base / 'another-image'))
                    if change == 'mountpoint':
                        return dict(current, mountpoint=str(base / 'another-volume'))
                    if len(validation_calls) == 2:
                        if change == 'between_device':
                            return dict(current, device='/dev/disk998')
                        if change == 'between_backing':
                            replace()
                    return current

                def command(*args):
                    order.append('eject')
                    self.assertEqual(order[-3:], ['validation', 'validation', 'eject'])
                    raise primary

                with patch.object(space.images, 'mounted', side_effect=mounted), \
                        patch.object(space.images.os.path, 'ismount', return_value=True), \
                        patch.object(space.images, '_command', side_effect=command) as eject:
                    collector = diagnostics.install(space.images, base / 'diagnostics')
                    self.addCleanup(collector.close)
                    if change == 'exhausted':
                        collector.remaining = 0
                    observer = collector.before if change == 'exhausted' else before
                    with patch.object(collector, 'before', side_effect=observer), \
                            patch.object(collector, 'report') as report, \
                            patch.object(collector, 'eject_log') as query, \
                            patch.object(collector, '_capture') as capture, \
                            self.assertRaises(lifecycle.StallionError) as caught:
                        with diagnostics.observe_detach():
                            observation = diagnostics._detach_observation.get()
                            fixture._detach(image, point)
                    capture.assert_not_called()
                    refused = change in ('missing', 'replaced', 'symlink', 'private', 'error_replaced')
                    if refused:
                        self.assertIn('Owned backing identity changed', str(caught.exception))
                        self.assertEqual(validation_calls, [])
                    else:
                        self.assertGreaterEqual(len(validation_calls), 1)
                    commanded = change in ('stable', 'observer_error', 'observer_timeout', 'exhausted')
                    self.assertEqual(eject.call_count, int(commanded))
                    self.assertEqual(report.call_count, int(commanded))
                    self.assertEqual(query.call_count, int(commanded))
                    if commanded:
                        self.assertIs(caught.exception, primary)
                        self.assertEqual(caught.exception.returncode, 64)
                        eject.assert_called_once_with(*self.args)
                    else:
                        self.assertNotIn('start_ns', observation)
                        self.assertNotIn('command_status', observation)
                    if change != 'exhausted':
                        self.assertEqual(order[0], 'before')
                    self.assertTrue(fixture.retain)
                    self.assertEqual(fixture.failed_images, {image})
                    with patch.object(image_cases.shutil, 'rmtree') as remove:
                        fixture.tearDown()
                    remove.assert_not_called()
                    self.assertTrue(base.exists())
                    retained = base / 'retained-original'
                    self.assertEqual((retained if retained.exists() else image).read_bytes(), b'owned backing')
                    collector.close()
                self.assertIsNone(diagnostics._scope.get())
                self.assertIsNone(diagnostics._detach_observation.get())

    def test_pre_mapping_selects_owned_image_and_changed_target_cannot_authorize_log(self):
        unrelated = dict(self.record, **{'image-path': str(self.base / 'unrelated'),
                                        'system-entities': [{'dev-entry': '/dev/disk998'}]})
        with patch.object(self.reporter, '_capture', side_effect=self.mapping_capture([unrelated, self.record])):
            observation = {}
            self.reporter.before(('/usr/sbin/diskutil', 'eject', None), self.scope(), observation)
        self.assertEqual(observation['observed_target'], '/dev/disk999')
        self.assertEqual(next(e for e in self.events() if e['kind'] == 'mapping')['image'], str(self.image))
        self.assertEqual(self.events()[0]['observation'], 'before detach validation')
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

        primary = space.images._error('fresh target failed'); primary.returncode = 64
        current = dict(image=str(self.image), device='/dev/disk998', mountpoint=str(self.point),
                       volume_device='/dev/disk998s1')
        with patch.object(space.images, 'mounted', return_value=current), \
                patch.object(space.images, '_command', side_effect=primary) as command:
            collector = diagnostics.install(space.images, self.base / 'changed-target')
            self.addCleanup(collector.close)
            def before(args, scope, selected):
                selected['observed_target'] = '/dev/disk999'
            with patch.object(collector, 'before', side_effect=before), \
                    patch.object(collector, '_capture', side_effect=self.mapping_capture([
                        dict(self.record, **{'system-entities': [{'dev-entry': '/dev/disk998'}]})])), \
                    diagnostics.failure_scope(self.base, self.image, mountpoint=self.point), \
                    self.assertRaises(type(primary)) as caught:
                with diagnostics.observe_detach():
                    selected = diagnostics._detach_observation.get()
                    space.images.detach(self.image, self.point)
            self.assertIs(caught.exception, primary)
            command.assert_called_once_with('/usr/sbin/diskutil', 'eject', '/dev/disk998')
            self.assertTrue(selected['target_changed'])
            events = [json.loads(line) for line in (collector.directory / diagnostics.REPORT).read_text().splitlines()]
            log = next(event for event in events if event['kind'] == 'eject_log')
            self.assertEqual((log['query_status'], log['records'], log['reason']),
                             ('unavailable', '', 'no_verified_attachment_mapping'))
            self.assertTrue(diagnostics.artifact_available(collector.directory))
            collector.close()

    def test_real_detach_success_keeps_one_command_after_both_validations(self):
        current = dict(image=str(self.image), device='/dev/disk999', mountpoint=str(self.point),
                       volume_device='/dev/disk999s1')
        order = []
        def mounted(image):
            order.append('validation')
            return current if order.count('validation') <= 2 else None
        def before(args, scope, observation):
            order.append('before')
            observation['observed_target'] = '/dev/disk999'
        def eject(*args):
            order.append('eject')
            return b'ok'
        with patch.object(space.images, 'mounted', side_effect=mounted), \
                patch.object(space.images.os.path, 'ismount', return_value=False), \
                patch.object(space.images, '_command', side_effect=eject) as command:
            collector = diagnostics.install(space.images, self.base / 'unused')
            self.addCleanup(collector.close)
            with patch.object(collector, 'before', side_effect=before), \
                    patch.object(collector, 'report') as report, \
                    diagnostics.failure_scope(self.base, self.image, mountpoint=self.point), diagnostics.observe_detach():
                self.assertIsNone(space.images.detach(self.image, self.point))
            self.assertEqual(order, ['before', 'validation', 'validation', 'eject', 'validation'])
            command.assert_called_once_with(*self.args)
            report.assert_not_called()
            collector.close()

    def test_direct_command_never_takes_pre_observation(self):
        original = Mock(return_value=b'ok')
        images = SimpleNamespace(_command=original)
        collector = diagnostics.install(images, self.base / 'unused')
        self.addCleanup(collector.close)
        with patch.object(collector, 'before') as before, diagnostics.observe_detach():
            self.assertEqual(images._command(*self.args), b'ok')
        before.assert_not_called()
        original.assert_called_once_with(*self.args)

    def test_install_close_preserves_slot_ownership_and_disables_stale_collectors(self):
        command, detach = Mock(return_value=b'command'), Mock(return_value='detached')
        images = SimpleNamespace(_command=command, detach=detach)
        first = diagnostics.install(images, self.base / 'first')
        stale_command, stale_detach = images._command, images.detach
        second = diagnostics.install(images, self.base / 'second')
        self.assertFalse(first.closed)
        self.assertIsNot(images._command, stale_command)
        with patch.object(first, 'before') as before, patch.object(first, 'report') as report, \
                patch.object(second, 'before') as active_before, \
                diagnostics.failure_scope(self.base, self.image, mountpoint=self.point), diagnostics.observe_detach():
            self.assertEqual(stale_detach(self.image, self.point), 'detached')
            self.assertEqual(stale_command(*self.args), b'command')
            self.assertFalse(diagnostics._detach_observation.get()['started'])
            self.assertEqual(images.detach(self.image, self.point), 'detached')
            self.assertEqual(images._command(*self.args), b'command')
        before.assert_not_called(); report.assert_not_called()
        active_before.assert_called_once()
        second.close(); second.close()
        self.assertIs(images._command, stale_command)
        self.assertIs(images.detach, stale_detach)
        with patch.object(first, 'before') as resumed, \
                diagnostics.failure_scope(self.base, self.image, mountpoint=self.point), diagnostics.observe_detach():
            self.assertEqual(images.detach(self.image, self.point), 'detached')
        resumed.assert_called_once()
        first.close()
        with patch.object(first, 'before') as before, patch.object(first, 'report') as report, \
                diagnostics.failure_scope(self.base, self.image, mountpoint=self.point), diagnostics.observe_detach():
            self.assertEqual(stale_detach(self.image, self.point), 'detached')
            self.assertEqual(stale_command(*self.args), b'command')
        before.assert_not_called(); report.assert_not_called()
        first.close()
        self.assertIs(images._command, command)
        self.assertIs(images.detach, detach)
        outer = diagnostics.install(images, self.base / 'outer')
        outer_slots = images._command, images.detach
        middle = diagnostics.install(images, self.base / 'middle')
        inner = diagnostics.install(images, self.base / 'inner')
        middle.close()
        inner.close()
        self.assertEqual((images._command, images.detach), outer_slots)
        outer.close()
        self.assertIs(images._command, command)
        self.assertIs(images.detach, detach)
        third = diagnostics.install(images, self.base / 'third')
        foreign_command, foreign_detach = Mock(), Mock()
        images._command, images.detach = foreign_command, foreign_detach
        third.close()
        self.assertIs(images._command, foreign_command)
        self.assertIs(images.detach, foreign_detach)
        images._command, images.detach = command, detach
        fourth = diagnostics.install(images, self.base / 'fourth')
        with patch.object(images, 'detach', foreign_detach):
            fourth.close()
        with patch.object(fourth, 'before') as before, diagnostics.observe_detach():
            self.assertEqual(images.detach(self.image, self.point), 'detached')
        before.assert_not_called()

    def test_unavailable_or_mismatched_owned_scope_skips_observation_and_keeps_original(self):
        for invalid in ('missing', 'nonprivate', 'image', 'mountpoint', 'no_scope'):
            with self.subTest(invalid=invalid):
                original = Mock(return_value='original result')
                images = SimpleNamespace(_command=Mock(), detach=original)
                collector = diagnostics.install(images, self.base / 'unused')
                image = self.base / 'missing' if invalid == 'missing' else self.image
                scope_image = self.base / 'other' if invalid == 'image' else image
                scope_point = self.base / 'other' if invalid == 'mountpoint' else self.point
                if invalid == 'nonprivate':
                    self.image.chmod(0o644)
                scope = (nullcontext() if invalid == 'no_scope' else
                         diagnostics.failure_scope(self.base, scope_image, mountpoint=scope_point))
                with scope, diagnostics.observe_detach(), patch.object(collector, 'before') as before:
                    self.assertEqual(images.detach(image, self.point), 'original result')
                before.assert_not_called()
                original.assert_called_once_with(image, self.point)
                collector.close()
                self.image.chmod(0o600)

    def test_workflow_selects_each_installed_observation_row(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/checks.yml').read_text()
        worker = workflow.split('  test-execution:\n', 1)[1].split('\n  test:\n', 1)[0]
        step = worker.split('      - name: Test installed wheel with image failure diagnostics\n', 1)[1].split('        run: |', 1)[0]
        self.assertIn("        if: matrix.phase == 'installed'\n", step)
        expression = re.search(r'^          STALLIONFS_TEST_SNAPSHOT_OBSERVATION: (.+)$', step, re.MULTILINE)[1]
        self.assertEqual(expression, "${{ matrix.os == 'macos-26' && matrix.python == '3.11' && 'restored-cleanup' || matrix.os == 'macos-26' && matrix.python == '3.14' && 'enospc-initial-detach' || matrix.os == 'macos-26-intel' && 'closed-snapshot' || 'initial-unmount' }}")
        rows = re.findall(r"^          - \{os: ([\w-]+), python: '([^']+)', images: '([^']+)', phase: installed\}$", worker, re.MULTILINE)
        self.assertEqual(len(rows), 6)
        self.assertEqual(worker.count('STALLIONFS_TEST_SNAPSHOT_OBSERVATION:'), 1)
        choices = ['restored-cleanup' if (runner, python) == ('macos-26', '3.11') else
                   'enospc-initial-detach' if (runner, python) == ('macos-26', '3.14') else
                   'closed-snapshot' if runner == 'macos-26-intel' else 'initial-unmount'
                   for runner, python, images in rows]
        self.assertEqual(choices.count('enospc-initial-detach'), 1)
        self.assertEqual(choices.count('closed-snapshot'), 1)
        self.assertEqual(choices.count('restored-cleanup'), 1)
        self.assertEqual(choices.count('initial-unmount'), 3)

    def test_snapshot_observation_selector_validates_once_before_fixture_work(self):
        key = 'STALLIONFS_TEST_SNAPSHOT_OBSERVATION'
        valid = (None, 'initial-unmount', 'closed-snapshot', 'enospc-initial-detach',
                 'enospc-sibling-detach', 'restored-cleanup')
        values = (*valid, '', 'unknown', 'INITIAL-UNMOUNT', 'Closed-snapshot',
                  ' initial-unmount', 'closed-snapshot ', 'initial-unmount\n')
        sentinel = OSError('stop before fixture allocation')
        for value in values:
            with self.subTest(value=value), patch.dict(os.environ):
                os.environ.pop(key, None)
                if value is not None:
                    os.environ[key] = value
                with patch.object(os.environ, 'get', wraps=os.environ.get) as read, \
                        patch.object(lifecycle.tempfile, 'mkdtemp', side_effect=sentinel) as allocate, \
                        patch.object(lifecycle, 'Store') as store, patch.object(lifecycle, 'git') as git, \
                        patch.object(lifecycle, 'image_fixture') as fixture, \
                        self.assertRaises(OSError if value in valid else ValueError) as caught:
                    lifecycle.ImageStoreTests.test_snapshot_rollback_and_protected_retirement(self)
                self.assertEqual([entry for entry in read.call_args_list if entry.args[0] == key],
                                 [call(key, 'initial-unmount')])
                self.assertEqual(allocate.call_count, int(value in valid))
                if value in valid:
                    self.assertIs(caught.exception, sentinel)
                store.assert_not_called(); git.assert_not_called(); fixture.assert_not_called()

    def test_snapshot_observation_selects_one_operation_and_preserves_selected_or_earlier_failure(self):
        cases = ((None, None), ('initial-unmount', None), ('closed-snapshot', None),
                 ('initial-unmount', 'initial-unmount'), ('closed-snapshot', 'closed-snapshot'),
                 ('closed-snapshot', 'initial-unmount'), ('enospc-initial-detach', None),
                 ('enospc-initial-detach', 'initial-unmount'))
        for selection, failure in cases:
            with self.subTest(selection=selection, failure=failure), \
                    tempfile.TemporaryDirectory(dir=self.base) as temporary, patch.dict(os.environ):
                key = 'STALLIONFS_TEST_SNAPSHOT_OBSERVATION'
                os.environ.pop(key, None)
                if selection is not None:
                    os.environ[key] = selection
                selected = selection or 'initial-unmount'
                base = Path(temporary)
                identifier = 'b' * 32
                root = base / 'store'
                point = root / 'workspaces' / identifier / 'volume'
                repo = point / 'repo'
                repo.mkdir(parents=True, mode=0o700)
                point.parent.chmod(0o700)
                image = point.parent / 'workspace.sparseimage'
                image.write_bytes(b'owned retained backing'); image.chmod(0o600)
                identity = (image.stat().st_dev, image.stat().st_ino)
                workspace = dict(id=identifier, backend='image', path=str(repo))
                store = Mock(root=root)
                store.prepare.return_value = dict(id='seed')
                store.create.return_value = workspace
                store.list.return_value = [workspace]
                store.cleanup.return_value = dict(retired=[identifier])
                store.gc.return_value = []
                store.close.return_value = dict(closed_at=100000)
                primary = space.images._error('original selected or earlier eject failure'); primary.returncode = 64
                state = dict(operation='initial-unmount', attached=True, mounted=True)
                commands, before_operations, log_windows = [], [], []
                saved = base / 'saved-repo'
                snapshot_calls = []

                def mounted(actual):
                    self.assertEqual(actual, image)
                    return (dict(image=str(image), device='/dev/disk999',
                                 mountpoint=str(point) if state['mounted'] else None,
                                 volume_device='/dev/disk999s1' if state['mounted'] else None)
                            if state['attached'] else None)

                def command(*args):
                    commands.append((state['operation'], args, diagnostics._detach_observation.get() is not None))
                    state['mounted'] = False
                    if state['operation'] == failure:
                        raise primary
                    state['attached'] = False
                    # Selection was read once before any fixture work.
                    os.environ[key] = 'invalid-after-initial-unmount'
                    return b''

                def snapshot(*args):
                    snapshot_calls.append(args)
                    if len(snapshot_calls) == 1:
                        raise lifecycle.StallionError('external worktree')
                    if len(snapshot_calls) == 2:
                        state.update(operation='closed-snapshot', attached=True, mounted=True)
                        space.images.detach(image, point)
                        repo.rename(saved)
                    return dict(id='snapshot')

                def rollback(*args):
                    (repo / 'file').write_text('snapshot state\n')
                    recovery = root / 'recovery' / 'saved'
                    recovery.mkdir(parents=True)
                    (recovery / 'workspace.sparseimage').write_bytes(b'recovery')
                    return dict(recovery='saved')

                def restore(*args, **kwargs):
                    store.list.return_value = []
                    return workspace

                store.unmount.side_effect = lambda *args: space.images.detach(image, point)
                store.snapshot.side_effect = snapshot
                store.mount.side_effect = lambda *args: saved.rename(repo)
                store.rollback.side_effect = rollback
                store.move.side_effect = restore
                with patch.object(space.images, 'mounted', side_effect=mounted), \
                        patch.object(space.images.os.path, 'ismount', return_value=False), \
                        patch.object(space.images, '_command', side_effect=command), \
                        patch.object(lifecycle, 'Store', return_value=store), \
                        patch.object(lifecycle.tempfile, 'mkdtemp', return_value=str(base)), \
                        patch.object(lifecycle, 'git'), patch.object(lifecycle, 'read_json', return_value=dict(status='open')), \
                        patch('stallionfs.lifecycle.replace_json'), patch.object(lifecycle, 'remove_tree') as remove:
                    collector = diagnostics.install(space.images, base / 'diagnostics')
                    self.addCleanup(collector.close)

                    def mapping(args, scope, deadline):
                        if collector.phase == 'before':
                            before_operations.append(state['operation'])
                        return (str(image), ['/dev/disk999', '/dev/disk999s1'],
                                str(point) if state['mounted'] else None,
                                '/dev/disk999s1' if state['mounted'] else None, identity)

                    def capture(argv, deadline):
                        if argv[0] == '/usr/bin/log':
                            observed = diagnostics._detach_observation.get() or diagnostics._detach_call.get()
                            log_windows.append((observed['start_ns'], observed['end_ns']))
                        return captured(b'', status=0 if argv[0] == '/usr/bin/log' else 1)

                    with patch.object(collector, '_mapping', side_effect=mapping), \
                            patch.object(collector, '_capture', side_effect=capture):
                        if failure is None:
                            lifecycle.ImageStoreTests.test_snapshot_rollback_and_protected_retirement(self)
                        else:
                            with self.assertRaises(type(primary)) as caught:
                                lifecycle.ImageStoreTests.test_snapshot_rollback_and_protected_retirement(self)
                            self.assertIs(caught.exception, primary)
                            self.assertEqual(caught.exception.returncode, 64)
                    store.unmount.assert_called_once_with(identifier)
                    expected_operations = ['initial-unmount'] if failure == 'initial-unmount' else ['initial-unmount', 'closed-snapshot']
                    self.assertEqual([item[0] for item in commands], expected_operations)
                    self.assertEqual([item[1] for item in commands], [self.args] * len(commands))
                    self.assertEqual([item[2] for item in commands], [item == selected for item in expected_operations])
                    observed = selected in expected_operations
                    self.assertEqual(before_operations, [selected] if observed else [])
                    self.assertEqual(collector.before_attempts, int(observed))
                    self.assertEqual(collector.attempts, int(failure is not None))
                    report = collector.directory / diagnostics.REPORT
                    events = [json.loads(line) for line in report.read_text().splitlines()] if report.exists() else []
                    if failure is not None:
                        remove.assert_not_called()
                        for later in (store.mount, store.rollback, store.enroll, store.close, store.cleanup_config,
                                      store.cleanup, store.gc, store.move):
                            later.assert_not_called()
                        self.assertEqual(len(snapshot_calls), 1 if failure == 'initial-unmount' else 2)
                        failed = next(event for event in events if event['kind'] == 'failure')
                        self.assertEqual((failed['pre_observation'], failed['failed_device'], failed['workspace']),
                                         ('attempted' if observed else 'not-selected', '/dev/disk999', identifier))
                        mappings = [event for event in events if event['kind'] == 'mapping']
                        self.assertEqual([event['phase'] for event in mappings], ['before', 'after'] if observed else ['after'])
                        self.assertEqual({event['operation_id'] for event in mappings}, {failed['operation_id']})
                        logs = [event for event in events if event['kind'] == 'eject_log']
                        self.assertEqual(len(logs), 1)
                        self.assertEqual((logs[0]['operation_id'], logs[0]['target']), (failed['operation_id'], '/dev/disk999'))
                        self.assertEqual((logs[0]['window_start_ns'], logs[0]['window_end_ns']), log_windows[0])
                        self.assertEqual(logs[0]['query_status'], 'empty')
                    else:
                        self.assertEqual(len(snapshot_calls), 3)
                        remove.assert_called_once_with(base)
                    self.assertEqual(image.read_bytes(), b'owned retained backing')
                    self.assertLessEqual(collector.events, diagnostics.EVENTS)
                    self.assertLessEqual(collector.written, diagnostics.FILE_BYTES)
                    self.assertLessEqual(collector.remaining, diagnostics.CAPTURE_BYTES)
                    self.assertEqual(diagnostics.artifact_available(collector.directory), bool(observed or failure))
                    collector.close()
                self.assertIsNone(diagnostics._scope.get())
                self.assertIsNone(diagnostics._detach_observation.get())

    def test_actual_lifecycle_selects_final_replacement_only(self):
        for case in ('success', 'final-failure', 'final-interrupt', 'earlier-failure', 'assertion', 'bad-owner', 'unknown'):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=self.base) as temporary, patch.dict(os.environ):
                os.environ['STALLIONFS_TEST_SNAPSHOT_OBSERVATION'] = 'restored-cleanup'
                base = Path(temporary)
                identifier = 'b' * 32
                root = base / 'store'
                point = root / 'workspaces' / identifier / 'volume'
                repo = point / 'repo'
                repo.mkdir(parents=True, mode=0o700); point.parent.chmod(0o700)
                image = point.parent / 'workspace.sparseimage'
                image.write_bytes(b'original'); image.chmod(0o600)
                original_identity = (image.stat().st_dev, image.stat().st_ino)
                workspace = dict(id=identifier, backend='image', path=str(repo))
                store = Mock(root=root)
                store.prepare.return_value = dict(id='seed')
                store.create.return_value = workspace
                store.list.return_value = [workspace]
                store.gc.return_value = []
                store.close.return_value = dict(closed_at=100000)
                primary = space.images._error('preserved original eject failure'); primary.returncode = 64
                interruption = KeyboardInterrupt('preserved cleanup interrupt')
                state = dict(operation='initial-unmount', attached=True, mounted=True)
                commands, before_operations, validations, fixtures = [], [], [], []
                saved = base / 'saved-repo'
                snapshots = []
                real_fixture = lifecycle.image_fixture

                @contextmanager
                def tracked_fixture(*args):
                    with real_fixture(*args) as fixture:
                        fixtures.append(fixture)
                        yield fixture

                def mounted(actual):
                    self.assertEqual(actual, image)
                    space.images._attachments(image)
                    invocation = diagnostics._detach_call.get()
                    if invocation is not None:
                        validations.append((state['operation'], image.stat().st_ino, invocation.get('reads')))
                    return (dict(image=str(image), device='/dev/disk999',
                                 mountpoint=str(point) if state['mounted'] else None,
                                 volume_device='/dev/disk999s1' if state['mounted'] else None)
                            if state['attached'] else None)

                def command(*args):
                    self.assertEqual(args, ('/usr/sbin/diskutil', 'eject', '/dev/disk999'))
                    commands.append((state['operation'], diagnostics._detach_observation.get() is not None))
                    state['mounted'] = False
                    if case == 'earlier-failure' and state['operation'] == 'initial-unmount':
                        raise primary
                    if state['operation'] == 'cleanup':
                        self.assertEqual(diagnostics._scope.get()['stage'], 'cleanup')
                        if case == 'final-failure': raise primary
                        if case == 'final-interrupt': raise interruption
                    state['attached'] = False
                    return b''

                def unmount(*args):
                    if diagnostics._scope.get()['stage'] == 'cleanup': state['operation'] = 'cleanup'
                    return space.images.detach(image, point)

                def snapshot(*args):
                    snapshots.append(args)
                    if len(snapshots) == 1: raise lifecycle.StallionError('external worktree')
                    if len(snapshots) == 2:
                        state.update(operation='closed-snapshot', attached=True, mounted=True)
                        space.images.detach(image, point); repo.rename(saved)
                    return dict(id='snapshot')

                def mount(*args):
                    state.update(attached=True, mounted=True)
                    saved.rename(repo)

                def rollback(*args):
                    state.update(operation='rollback', attached=True, mounted=True)
                    space.images.detach(image, point)
                    recovery = root / 'recovery' / 'saved'; recovery.mkdir(parents=True)
                    image.rename(recovery / 'workspace.sparseimage')
                    image.write_bytes(b'replacement'); image.chmod(0o600)
                    (repo / 'file').write_text('snapshot state\n')
                    state.update(attached=True, mounted=True)
                    return dict(recovery='saved')

                def retire(*args, **kwargs):
                    state['operation'] = 'retirement'
                    space.images.detach(image, point)
                    return dict(retired=[identifier])

                def restore(*args, **kwargs):
                    state.update(operation='restored', attached=True, mounted=True)
                    if case == 'assertion': (repo / 'file').write_text('wrong restored content')
                    if case == 'bad-owner': store.list.return_value = [dict(workspace, path='/foreign')]
                    if case == 'unknown': fixtures[0].unknown = True
                    return workspace

                store.unmount.side_effect = unmount
                store.snapshot.side_effect = snapshot
                store.mount.side_effect = mount
                store.rollback.side_effect = rollback
                store.cleanup.side_effect = retire
                store.move.side_effect = restore
                def attachments(actual):
                    entities = [{'dev-entry':'/dev/disk999'}, {'dev-entry':'/dev/disk999s1'}]
                    if state['mounted']: entities[1]['mount-point'] = str(point)
                    return [dict(**{'owner-uid':os.getuid(), 'image-path':str(image), 'system-entities':entities})] if state['attached'] else []
                with patch.object(space.images, '_attachments', side_effect=attachments), \
                        patch.object(space.images, 'mounted', side_effect=mounted), \
                        patch.object(space.images.os.path, 'ismount', return_value=False), \
                        patch.object(space.images, '_command', side_effect=command), \
                        patch.object(lifecycle, 'Store', return_value=store), \
                        patch.object(lifecycle.tempfile, 'mkdtemp', return_value=str(base)), \
                        patch.object(lifecycle, 'image_fixture', side_effect=tracked_fixture), \
                        patch.object(lifecycle, 'git'), patch.object(lifecycle, 'read_json', return_value=dict(status='open')), \
                        patch('stallionfs.lifecycle.replace_json'), patch.object(lifecycle, 'remove_tree') as remove:
                    collector = diagnostics.install(space.images, base / 'diagnostics')
                    self.addCleanup(collector.close)
                    def mapping(args, scope, deadline):
                        self.assertEqual(scope['image'], image)
                        if collector.phase == 'before': before_operations.append(state['operation'])
                        return (str(image), ['/dev/disk999', '/dev/disk999s1'],
                                str(point) if state['mounted'] else None,
                                '/dev/disk999s1' if state['mounted'] else None,
                                (image.stat().st_dev, image.stat().st_ino))
                    with patch.object(collector, '_mapping', side_effect=mapping), \
                            patch.object(collector, '_capture', side_effect=lambda *a: captured(b'', status=1)):
                        error_type = {'final-failure': lifecycle.StallionError, 'earlier-failure': lifecycle.StallionError,
                                      'final-interrupt': KeyboardInterrupt, 'assertion': AssertionError,
                                      'bad-owner': lifecycle.StallionError, 'unknown': lifecycle.StallionError}.get(case)
                        if error_type:
                            with self.assertRaises(error_type) as caught:
                                lifecycle.ImageStoreTests.test_snapshot_rollback_and_protected_retirement(self)
                            if case in ('final-failure', 'earlier-failure'): self.assertIs(caught.exception, primary)
                            if case == 'final-interrupt': self.assertIs(caught.exception, interruption)
                            remove.assert_not_called()
                        else:
                            lifecycle.ImageStoreTests.test_snapshot_rollback_and_protected_retirement(self)
                            remove.assert_called_once_with(base)
                        before_repeat = list(commands)
                        if case in ('success', 'final-failure', 'earlier-failure', 'bad-owner', 'unknown'):
                            fixtures[0].cleanup(observe=True)
                            self.assertEqual(commands, before_repeat)
                    selected = case in ('success', 'final-failure', 'final-interrupt')
                    self.assertEqual(before_operations, ['cleanup'] if selected else [])
                    self.assertEqual([op for op, observed in commands if observed], ['cleanup'] if selected else [])
                    expected = ['initial-unmount'] if case == 'earlier-failure' else ['initial-unmount', 'closed-snapshot', 'rollback', 'retirement']
                    if case not in ('earlier-failure', 'bad-owner', 'unknown'): expected += ['cleanup']
                    self.assertEqual([op for op, observed in commands], expected)
                    self.assertEqual(collector.before_attempts, int(selected))
                    report = collector.directory / diagnostics.REPORT
                    events = [json.loads(line) for line in report.read_text().splitlines()] if report.exists() else []
                    if case == 'final-failure':
                        failure = next(e for e in events if e['kind'] == 'failure')
                        self.assertEqual((failure['stage'], failure['workspace'], failure['pre_observation']),
                                         ('cleanup', identifier, 'attempted'))
                        mappings = [e for e in events if e['kind'] == 'mapping']
                        identity = (image.stat().st_dev, image.stat().st_ino)
                        self.assertNotEqual(identity, original_identity)
                        self.assertEqual([(e['backing_device'], e['backing_inode']) for e in mappings], [identity, identity])
                        self.assertEqual({e['operation_id'] for e in mappings}, {failure['operation_id']})
                        samples = [e for e in events if e['kind'] == 'validation']
                        self.assertEqual(len(samples), 2)
                        self.assertEqual({e['operation_id'] for e in samples}, {failure['operation_id']})
                        self.assertEqual([e['sample_status'] for e in samples], ['validated', 'validated'])
                        self.assertEqual([e['selected_device'] for e in samples], ['/dev/disk999', '/dev/disk999'])
                        eject = next(e for e in events if e['kind'] == 'eject_log')
                        self.assertEqual(eject['operation_id'], failure['operation_id'])
                        self.assertEqual(eject['target'], '/dev/disk999')
                        self.assertLessEqual(eject['window_start_ns'], eject['window_end_ns'])
                    self.assertEqual(image.read_bytes(), b'original' if case == 'earlier-failure' else b'replacement')
                    self.assertTrue(base.exists())
                    self.assertLessEqual(collector.events, diagnostics.EVENTS)
                    self.assertLessEqual(collector.written, diagnostics.FILE_BYTES)
                    self.assertLessEqual(collector.remaining, diagnostics.CAPTURE_BYTES)
                    collector.close()
                self.assertIsNone(diagnostics._scope.get()); self.assertIsNone(diagnostics._detach_observation.get())

    def test_exact_owned_workspace_and_exceptional_arming(self):
        a, b = 'a' * 32, 'b' * 32
        for case in ('normal', 'exception', 'interrupt', 'ownership', 'failed-workspace'):
            with self.subTest(case=case):
                base = self.base
                store = Mock(root=base / 'store')
                store.list.return_value = [dict(id=i, backend='image', path=str(store.root/'workspaces'/i/'volume/repo')) for i in (a,b)]
                observed = []
                store.unmount.side_effect = lambda i: observed.append((i, diagnostics._detach_observation.get() is not None))
                primary = KeyboardInterrupt() if case=='interrupt' else AssertionError('primary')
                with patch.object(lifecycle, 'remove_tree') as remove:
                    if case in ('exception','interrupt'):
                        with self.assertRaises(type(primary)) as caught:
                            with lifecycle.image_fixture(store, base) as fixture:
                                fixture.cleanup_observation = b
                                raise primary
                        self.assertIs(caught.exception, primary); remove.assert_not_called()
                        self.assertFalse(any(selected for i,selected in observed))
                        if case=='interrupt': store.list.assert_not_called(); store.unmount.assert_not_called()
                    else:
                        fixture=lifecycle.ImageFixture(store,base); fixture.cleanup_observation=b
                        if case=='ownership': store.list.return_value[1]['path']='/foreign'
                        if case=='failed-workspace': fixture.failed.add(b)
                        fixture.cleanup(observe=True)
                        self.assertEqual(observed, [] if case=='ownership' else [(a,False)] if case=='failed-workspace' else [(a,False),(b,True)])
                        fixture.cleanup(observe=True)
                        self.assertFalse(any(selected for i,selected in observed[len(observed)//2:]))

    def test_snapshot_fixture_observes_first_unmount_failure_without_retry(self):
        base = self.base / 'unmount-fixture'
        base.mkdir(mode=0o700)
        identifier = 'a' * 32
        root = base / 'store'
        point = root / 'workspaces' / identifier / 'volume'
        repo = point / 'repo'
        repo.mkdir(parents=True, mode=0o700)
        point.parent.chmod(0o700)
        image = point.parent / 'workspace.sparseimage'
        image.write_bytes(b'retained backing'); image.chmod(0o600)
        identity = (image.stat().st_dev, image.stat().st_ino)
        workspace = dict(id=identifier, path=str(repo), backend='image')
        store = Mock(root=root)
        store.prepare.return_value = dict(id='seed')
        store.create.return_value = workspace
        store.list.return_value = [workspace]
        store.snapshot.side_effect = lifecycle.StallionError('external worktree')
        store.unmount.side_effect = lambda *args: space.images.detach(image, point)
        primary = space.images._error('unmount primary busy'); primary.returncode = 1
        state = dict(mounted=True)
        commands, log_windows = [], []
        current = dict(image=str(image), device='/dev/disk999', mountpoint=str(point),
                       volume_device='/dev/disk999s1')

        def command(*args):
            commands.append(args)
            state['mounted'] = False
            raise primary

        def mapping(args, scope, deadline):
            actual = scope['image']
            info = actual.stat()
            return (str(actual), ['/dev/disk999', '/dev/disk999s1'],
                    str(point) if actual == image and state['mounted'] else None,
                    '/dev/disk999s1' if actual == image and state['mounted'] else None,
                    (info.st_dev, info.st_ino))

        def capture(argv, deadline):
            if argv[0] == '/usr/bin/log':
                observation = diagnostics._detach_observation.get()
                log_windows.append((observation['start_ns'], observation['end_ns']))
            return captured(b'', status=0 if argv[0] == '/usr/bin/log' else 1)

        real_stat = os.stat
        def device_stat(path, *args, **kwargs):
            if kwargs.get('follow_symlinks') is not False:
                if str(path) == '/dev/disk999s1':
                    return SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=42)
                if str(path) == str(point):
                    return SimpleNamespace(st_dev=42)
            return real_stat(path, *args, **kwargs)

        with patch.dict(os.environ, STALLIONFS_TEST_SNAPSHOT_OBSERVATION='initial-unmount'), \
                patch.object(space.images, '_command', side_effect=command), \
                patch.object(space.images, 'mounted', return_value=current), \
                patch.object(space.images.os.path, 'ismount', side_effect=lambda path: state['mounted']), \
                patch.object(diagnostics.os, 'stat', side_effect=device_stat), \
                patch.object(lifecycle, 'Store', return_value=store), \
                patch.object(lifecycle.tempfile, 'mkdtemp', return_value=str(base)), \
                patch.object(lifecycle, 'git'), patch.object(lifecycle, 'remove_tree') as remove:
            collector = diagnostics.install(space.images, self.reporter.directory)
            self.addCleanup(collector.close)
            self.reporter = collector
            with patch.object(collector, '_mapping', side_effect=mapping), \
                    patch.object(collector, '_capture', side_effect=capture), \
                    self.assertRaises(type(primary)) as caught:
                lifecycle.ImageStoreTests.test_snapshot_rollback_and_protected_retirement(self)
            self.assertIs(caught.exception, primary)
            self.assertEqual(caught.exception.returncode, 1)
            store.unmount.assert_called_once_with(identifier)
            store.snapshot.assert_called_once_with(identifier)
            for operation in (store.mount, store.rollback, store.enroll, store.close,
                              store.cleanup_config, store.cleanup, store.gc, store.move, remove):
                operation.assert_not_called()

            # A later selection cannot borrow this operation's prestate or budget.
            later_error = space.images._error('later failure'); later_error.returncode = 1
            later_command = Mock(side_effect=later_error)
            later = SimpleNamespace(_command=later_command)
            with patch.object(diagnostics, 'Diagnostics', return_value=collector):
                diagnostics.install(later, collector.directory)
            with patch.object(collector, '_mapping', side_effect=mapping), \
                    patch.object(collector, '_capture', side_effect=capture), \
                    diagnostics.failure_scope(self.base, self.image, mountpoint=self.point), \
                    self.assertRaises(type(later_error)) as later_caught:
                with diagnostics.observe_detach():
                    later._command(*self.args)
            self.assertIs(later_caught.exception, later_error)
            later_command.assert_called_once_with(*self.args)

        self.assertEqual(commands, [self.args])
        self.assertEqual(collector.before_attempts, 1)
        self.assertEqual(collector.attempts, 2)
        self.assertTrue(base.exists() and image.exists())
        self.assertEqual(image.read_bytes(), b'retained backing')
        events = self.events()
        mappings = [event for event in events if event['kind'] == 'mapping']
        first = mappings[0]['operation_id']
        paired = [event for event in mappings if event['operation_id'] == first]
        self.assertEqual([event['phase'] for event in paired], ['before', 'after'])
        self.assertEqual([event['mountpoint'] for event in paired], [str(point), None])
        self.assertEqual({(event['backing_device'], event['backing_inode']) for event in paired}, {identity})
        failures = [event for event in events if event['kind'] == 'failure']
        self.assertEqual([event['pre_observation'] for event in failures], ['attempted', 'unavailable'])
        self.assertEqual([event['workspace'] for event in failures], [identifier, None])
        later_id = failures[1]['operation_id']
        self.assertNotEqual(first, later_id)
        later_mappings = [event for event in mappings if event['operation_id'] == later_id]
        later_identity = (self.image.stat().st_dev, self.image.stat().st_ino)
        self.assertNotEqual(identity, later_identity)
        self.assertEqual([event['phase'] for event in later_mappings], ['after'])
        self.assertEqual({(event['backing_device'], event['backing_inode']) for event in later_mappings}, {later_identity})
        eject = [event for event in events if event['kind'] == 'eject_log']
        self.assertEqual(len(eject), 1)
        self.assertEqual(len(log_windows), 1)
        self.assertEqual((eject[0]['operation_id'], eject[0]['target']), (first, '/dev/disk999'))
        self.assertEqual((eject[0]['window_start_ns'], eject[0]['window_end_ns']), log_windows[0])
        self.assertLessEqual(collector.events, diagnostics.EVENTS)
        self.assertLessEqual(collector.written, diagnostics.FILE_BYTES)
        self.assertLessEqual(collector.remaining, diagnostics.CAPTURE_BYTES)
        self.assertTrue(diagnostics.artifact_available(collector.directory))
        self.assertIsNone(diagnostics._scope.get())
        self.assertIsNone(diagnostics._detach_observation.get())

    def test_snapshot_fixture_preserves_preallowance_and_retains_original_failure(self):
        from stallionfs import lifecycle as store_lifecycle
        base = self.base / 'snapshot-fixture'
        base.mkdir(mode=0o700)
        identifier = 'a' * 32
        root = base / 'store'
        path = root / 'workspaces' / identifier
        point = path / 'volume'
        repo = point / 'repo'
        repo.mkdir(parents=True, mode=0o700)
        path.chmod(0o700)
        image = path / 'workspace.sparseimage'
        image.write_bytes(b'rollback backing')
        image.chmod(0o600)
        earlier_identity = (image.stat().st_dev, image.stat().st_ino)
        workspace = dict(id=identifier, path=str(repo), backend='image')
        store = Mock(root=root)
        store.prepare.return_value = dict(id='seed')
        store.create.return_value = workspace
        store.list.return_value = [workspace]
        saved_repo = base / 'saved-repo'
        snapshot_calls = []

        def snapshot(*args):
            snapshot_calls.append(args)
            if len(snapshot_calls) == 1:
                raise lifecycle.StallionError('external worktree')
            if len(snapshot_calls) == 2:
                repo.rename(saved_repo)
            return dict(id='snapshot')

        store.snapshot.side_effect = snapshot
        store.mount.side_effect = lambda *args: saved_repo.rename(repo)
        first = space.images._error('close primary busy')
        first.returncode = 64
        attachment = dict(operation='rollback', attached=True, mounted=True)
        commands, before_operations, log_windows = [], [], []
        current = dict(image=str(image), device='/dev/disk999', mountpoint=str(point), volume_device='/dev/disk999s1')

        def mounted(actual_image):
            self.assertEqual(actual_image, image)
            return (dict(current, mountpoint=str(point) if attachment['mounted'] else None,
                         volume_device='/dev/disk999s1' if attachment['mounted'] else None)
                    if attachment['attached'] else None)

        def original(*args):
            commands.append((attachment['operation'], args, diagnostics._detach_observation.get() is not None))
            attachment['mounted'] = False
            if attachment['operation'] == 'rollback':
                attachment['attached'] = False
                return b''
            raise first

        def rollback(*args):
            space.images.detach(image, point)
            replacement = path / 'replacement'
            replacement.write_bytes(b'close backing, same device label')
            replacement.chmod(0o600)
            replacement.replace(image)
            (repo / 'file').write_text('snapshot state\n')
            recovery = root / 'recovery' / 'saved'
            recovery.mkdir(parents=True)
            (recovery / 'workspace.sparseimage').write_bytes(b'retained rollback image')
            attachment.update(operation='close', attached=True, mounted=True)
            return dict(recovery='saved')

        store.rollback.side_effect = rollback
        open_state = dict(status='open', generation='unchanged')
        state_file = path / 'state.json'
        state_file.write_text(json.dumps(open_state))
        original_state = state_file.read_bytes()
        store._workspace_lock.side_effect = lambda *args: nullcontext()
        store.object.return_value = (path, dict(backend='image'))
        store._open.return_value = open_state
        store._payload.return_value = image
        store._state.return_value = state_file
        store._closed_payload.side_effect = lambda *args, **kwargs: store_lifecycle.Lifecycle._closed_payload(store, *args, **kwargs)
        store.close.side_effect = lambda *args, **kwargs: store_lifecycle.Lifecycle.close(store, *args, **kwargs)
        with patch.dict(os.environ, STALLIONFS_TEST_SNAPSHOT_OBSERVATION='initial-unmount'), \
                patch.object(space.images, '_command', side_effect=original), \
                patch.object(space.images, 'mounted', side_effect=mounted), \
                patch.object(space.images.os.path, 'ismount', return_value=False), \
                patch('stallionfs._scan.mounts', return_value=[]), \
                patch.object(space.images, 'flush') as flush, \
                patch.object(store_lifecycle, 'replace_json') as publish, \
                patch.object(lifecycle, 'Store', return_value=store), \
                patch.object(lifecycle.tempfile, 'mkdtemp', return_value=str(base)), \
                patch.object(lifecycle, 'git'), patch.object(lifecycle, 'remove_tree') as remove:
            collector = diagnostics.install(space.images, self.reporter.directory)
            self.addCleanup(collector.close)
            self.reporter = collector

            def mapping(args, scope, deadline):
                self.assertEqual((args, scope['image'], scope['workspace']), (self.args, image, identifier))
                identity = (image.stat().st_dev, image.stat().st_ino)
                if collector.phase == 'before':
                    before_operations.append((attachment['operation'], identity))
                return (str(image), ['/dev/disk999', '/dev/disk999s1'],
                        str(point) if attachment['mounted'] else None,
                        '/dev/disk999s1' if attachment['mounted'] else None, identity)

            def capture(argv, deadline):
                if argv[0] == '/usr/bin/log':
                    log_windows.append(argv)
                return captured(b'', status=0 if argv[0] == '/usr/bin/log' else 1)

            with patch.object(collector, '_mapping', side_effect=mapping), \
                    patch.object(collector, '_capture', side_effect=capture), \
                    self.assertRaises(type(first)) as caught:
                lifecycle.ImageStoreTests.test_snapshot_rollback_and_protected_retirement(self)
            self.assertIs(caught.exception, first)
            flush.assert_not_called()
            publish.assert_not_called()
            remove.assert_not_called()
        current_identity = (image.stat().st_dev, image.stat().st_ino)
        self.assertNotEqual(earlier_identity, current_identity)
        self.assertEqual(before_operations, [])
        self.assertEqual(collector.before_attempts, 0)
        self.assertEqual(collector.attempts, 1)
        self.assertEqual(commands, [('rollback', self.args, False), ('close', self.args, False)])
        store.rollback.assert_called_once_with(identifier, 'snapshot')
        store.close.assert_called_once_with(identifier, quiescent=True)
        store.unmount.assert_called_once_with(identifier)
        self.assertEqual(open_state, dict(status='open', generation='unchanged'))
        self.assertEqual(state_file.read_bytes(), original_state)
        self.assertTrue(base.exists() and image.exists())
        self.assertEqual(len(log_windows), 1)
        events = self.events()
        mappings = [event for event in events if event['kind'] == 'mapping']
        self.assertEqual([event['mountpoint'] for event in mappings], [None])
        self.assertEqual({(event['backing_device'], event['backing_inode']) for event in mappings}, {current_identity})
        failures = [event for event in events if event['kind'] == 'failure']
        self.assertEqual([event['message'] for event in failures], ['close primary busy'])
        self.assertEqual({event['pre_observation'] for event in failures}, {'not-selected'})
        self.assertEqual(len({event['operation_id'] for event in events}), 1)
        self.assertEqual(sum(event['kind'] == 'eject_log' for event in events), 1)
        self.assertLessEqual(collector.events, diagnostics.EVENTS)
        self.assertLessEqual(collector.written, diagnostics.FILE_BYTES)
        self.assertLessEqual(collector.remaining, diagnostics.CAPTURE_BYTES)
        self.assertTrue(diagnostics.artifact_available(collector.directory))
        self.assertIsNone(diagnostics._scope.get())
        self.assertIsNone(diagnostics._detach_observation.get())

        # The same suite-wide collector still admits the later selected lifetime.
        later = SimpleNamespace(_command=Mock(side_effect=first))
        later.detach = lambda image, point: later._command(*self.args)
        with patch.object(diagnostics, 'Diagnostics', return_value=collector):
            diagnostics.install(later, collector.directory)
        info = self.image.stat()
        with patch.object(collector, '_mapping', return_value=(str(self.image), ['/dev/disk999'],
                          None, None, (info.st_dev, info.st_ino))), \
                patch.object(collector, '_capture', return_value=captured(b'', status=1)), \
                diagnostics.failure_scope(self.base, self.image, mountpoint=self.point), \
                self.assertRaises(type(first)) as caught:
            with diagnostics.observe_detach():
                later.detach(self.image, self.point)
        self.assertIs(caught.exception, first)
        self.assertEqual(collector.before_attempts, 1)
        before = [event for event in self.events() if event['kind'] == 'mapping' and event['phase'] == 'before']
        self.assertEqual(len(before), 1)
        self.assertEqual((before[0]['backing_device'], before[0]['backing_inode']), (info.st_dev, info.st_ino))

    def test_second_detach_pairs_mounted_prestate_with_failed_eject_and_retained_cleanup(self):
        first, final = space.images._error('primary busy'), space.images._error('fallback busy')
        first.returncode = final.returncode = errno.EBUSY
        state = dict(attached=True, mounted=True)
        identity = (self.image.stat().st_dev, self.image.stat().st_ino)
        order, commands, log_windows = [], [], []
        current = dict(image=str(self.image), device='/dev/disk999', mountpoint=str(self.point), volume_device='/dev/disk999s1')
        def mounted(image):
            self.assertEqual(image, self.image)
            return (dict(current, mountpoint=str(self.point) if state['mounted'] else None,
                         volume_device='/dev/disk999s1' if state['mounted'] else None)
                    if state['attached'] else None)
        def original(*args):
            commands.append(args)
            order.append('detach')
            state['mounted'] = False
            if len(commands) == 1:
                state['attached'] = False
                return b''
            raise first if len(commands) == 2 else final
        real_stat = os.stat
        def device_stat(path, *args, **kwargs):
            if kwargs.get('follow_symlinks') is not False:
                if str(path) == '/dev/disk999s1':
                    return SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=42)
                if str(path) == str(self.point):
                    return SimpleNamespace(st_dev=42)
            return real_stat(path, *args, **kwargs)
        with patch.object(space.images, '_command', side_effect=original), \
                patch.object(space.images, 'mounted', side_effect=mounted), \
                patch.object(space.images.os.path, 'ismount', side_effect=lambda path: state['mounted']), \
                patch('stallionfs._scan.mounts', return_value=[]), \
                patch.object(diagnostics.os, 'stat', side_effect=device_stat):
            collector = diagnostics.install(space.images, self.reporter.directory)
            self.addCleanup(collector.close)
            self.reporter = collector
            def mapping(args, scope, deadline):
                self.assertEqual((args[2], scope['image']), (None if collector.phase == 'before' else '/dev/disk999', self.image))
                return (str(self.image), ['/dev/disk999', '/dev/disk999s1'],
                        str(self.point) if state['mounted'] else None,
                        '/dev/disk999s1' if state['mounted'] else None, identity)
            def capture(argv, deadline):
                if argv[0] == '/usr/bin/log':
                    observation = diagnostics._detach_observation.get()
                    self.assertEqual(len(commands), 2)
                    self.assertLessEqual(observation['start_ns'], observation['end_ns'])
                    log_windows.append((observation['start_ns'], observation['end_ns']))
                    order.append('log')
                    return captured(b'')
                order.append(collector.phase + '-capture-complete')
                return captured(self.holder_output(), status=1)
            with patch.object(collector, '_mapping', side_effect=mapping), \
                    patch.object(collector, '_capture', side_effect=capture):
                # The first detach succeeds without spending the selected pre-observation.
                with diagnostics.failure_scope(self.base, self.image, mountpoint=self.point):
                    space.images.detach(self.image, self.point)
                self.assertEqual(collector.before_attempts, 0)
                self.assertFalse(collector.directory.exists())
                state.update(attached=True, mounted=True)  # Synthetic remount after successful detach.
                with diagnostics.failure_scope(self.base, self.image, mountpoint=self.point), \
                        self.assertRaises(type(first)) as caught:
                    with diagnostics.observe_detach():
                        space.images.detach(self.image, self.point)
                self.assertIs(caught.exception, first)
                fixture = space.ImageSpace()
                fixture.base, fixture.image_points = self.base, {self.image: self.point}
                with patch.object(space.shutil, 'rmtree') as remove, \
                        self.assertRaisesRegex(RuntimeError, 'Test files retained'):
                    fixture.clean()
                remove.assert_not_called()
        self.assertTrue(self.image.exists())
        self.assertEqual(commands, [self.args] * 3)
        events = self.events()
        selected = events[0]['operation_id']
        paired = [event for event in events if event['operation_id'] == selected]
        mappings = [event for event in paired if event['kind'] == 'mapping']
        self.assertEqual([event['mountpoint'] for event in mappings], [str(self.point), None])
        self.assertEqual({(event['backing_device'], event['backing_inode']) for event in mappings}, {identity})
        failures = [event for event in paired if event['kind'] == 'failure']
        self.assertEqual([event['message'] for event in failures], ['primary busy'])
        self.assertEqual({event['pre_observation'] for event in failures}, {'attempted'})
        self.assertEqual([event['stage'] for event in events if event['kind'] == 'failure'],
                         ['body', 'cleanup'])
        eject = next(event for event in paired if event['kind'] == 'eject_log')
        self.assertEqual((eject['window_start_ns'], eject['window_end_ns']), log_windows[0])
        self.assertEqual((eject['target'], eject['query_status']), ('/dev/disk999', 'empty'))
        self.assertEqual(order[:4], ['detach', 'before-capture-complete', 'before-capture-complete', 'detach'])
        self.assertEqual(order.count('log'), 1)
        self.assertTrue(diagnostics.artifact_available(collector.directory))
        self.assertIsNone(diagnostics._detach_observation.get())

    def test_exhausted_preallowance_reports_unavailable_without_borrowing_reused_device_identity(self):
        earlier = self.base / 'earlier.sparseimage'
        earlier.write_bytes(b'earlier backing, same device label')
        earlier.chmod(0o600)
        earlier_identity = (earlier.stat().st_dev, earlier.stat().st_ino)
        current_identity = (self.image.stat().st_dev, self.image.stat().st_ino)
        self.assertNotEqual(earlier_identity, current_identity)
        busy = space.images._error('selected eject busy')
        busy.returncode = errno.EBUSY
        images = SimpleNamespace(_command=Mock(side_effect=busy))
        images.detach = lambda image, point: images._command(*self.args)
        collector = diagnostics.install(images, self.reporter.directory)
        self.addCleanup(collector.close)
        self.reporter = collector
        def mapping(args, scope, deadline):
            image = scope['image']
            identity = earlier_identity if image == earlier else current_identity
            return str(image), ['/dev/disk999'], None, None, identity
        with patch.object(collector, '_mapping', side_effect=mapping), \
                patch.object(collector, '_capture', return_value=captured(b'', status=1)):
            earlier_operation = collector.before(self.args, self.scope(image=earlier))
            self.assertEqual(collector.before_attempts, 1)
            with diagnostics.failure_scope(self.base, self.image, mountpoint=self.point), \
                    self.assertRaises(type(busy)) as caught:
                with diagnostics.observe_detach():
                    try:
                        images.detach(self.image, self.point)
                    except type(busy):
                        images.detach(self.image, self.point)
        self.assertIs(caught.exception, busy)
        events = self.events()
        failures = [event for event in events if event['kind'] == 'failure']
        self.assertEqual(len(failures), 2)
        selected_ids = {event['operation_id'] for event in failures}
        self.assertEqual(len(selected_ids), 2)
        self.assertNotIn(earlier_operation, selected_ids)
        self.assertEqual([event['pre_observation'] for event in failures], ['unavailable', 'not-selected'])
        selected_mappings = [event for event in events if event['kind'] == 'mapping' and event['operation_id'] in selected_ids]
        self.assertEqual({event['phase'] for event in selected_mappings}, {'after'})
        self.assertEqual({(event['backing_device'], event['backing_inode']) for event in selected_mappings}, {current_identity})
        self.assertEqual({event['failed_device'] for event in failures}, {'/dev/disk999'})
        self.assertEqual(collector.before_attempts, 1)
        self.assertTrue(diagnostics.artifact_available(collector.directory))

    def test_preobservation_availability_is_optional_typed_and_scoped_to_observation_records(self):
        self.reporter.report(self.args, OSError('unselected failure'), None)
        events = self.events()
        self.assertEqual(events[0]['pre_observation'], 'not-selected')
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))
        path = self.reporter.directory / diagnostics.REPORT
        legacy = [{key: value for key, value in event.items() if key != 'pre_observation'} for event in events]
        def write(records):
            path.write_text(''.join(json.dumps(event) + '\n' for event in records))
        write(legacy)
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))
        write([dict(legacy[0], pre_observation='captured'), *legacy[1:]])
        self.assertFalse(diagnostics.artifact_available(self.reporter.directory))
        write([legacy[0], dict(legacy[1], pre_observation='unavailable')])
        self.assertFalse(diagnostics.artifact_available(self.reporter.directory))

    def test_eject_log_requires_the_observed_commands_integer_failure_status(self):
        cases = [(status, False) for status in (0, None, True, False, '16', 1, 5, 16, 64, -1)]
        cases += [(16, True)]
        for status, expected in cases:
            with self.subTest(status=status, expected=expected):
                error = space.images._error('command failed')
                if status is not None:
                    error.returncode = status
                original = Mock(side_effect=error)
                images = SimpleNamespace(_command=original)
                collector = diagnostics.install(images, self.base / 'unused')
                self.addCleanup(collector.close)
                with patch.object(collector, 'before'), patch.object(collector, 'report'), \
                        patch.object(collector, 'eject_log') as query, \
                        diagnostics.failure_scope(self.base, self.image, expected=expected):
                    with self.assertRaises(type(error)) as caught:
                        with diagnostics.observe_detach():
                            images._command(*self.args)
                self.assertIs(caught.exception, error)
                original.assert_called_once_with(*self.args)
                self.assertEqual(query.call_count, int(type(status) is int and status != 0 and not expected))

    def test_later_errors_and_interrupts_cannot_authorize_eject_log(self):
        for case in ('success', 'inspection', 'replacement', 'unrelated', 'interrupt', 'exit'):
            with self.subTest(case=case):
                command_error = space.images._error('command failed'); command_error.returncode = 64
                later = KeyboardInterrupt() if case == 'interrupt' else SystemExit(2) if case == 'exit' else OSError('later failure')
                later.returncode = 16
                images = SimpleNamespace(_command=Mock(side_effect=command_error if case == 'replacement'
                                                       else later if case in ('interrupt', 'exit') else None,
                                                       return_value=b'ok'))
                collector = diagnostics.install(images, self.base / 'unused')
                self.addCleanup(collector.close)
                with patch.object(collector, 'before'), patch.object(collector, 'report'), \
                        patch.object(collector, 'eject_log') as query, \
                        diagnostics.failure_scope(self.base, self.image):
                    def operation():
                        with diagnostics.observe_detach():
                            if case != 'unrelated':
                                try:
                                    images._command(*self.args)
                                except type(command_error):
                                    raise later
                            if case != 'success':
                                raise later
                    if case == 'success':
                        operation()
                    else:
                        with self.assertRaises(type(later)) as caught:
                            operation()
                        self.assertIs(caught.exception, later)
                query.assert_not_called()

    def test_log_error_cannot_replace_the_single_eject_failure(self):
        primary = space.images._error('eject failed'); primary.returncode = 64
        original = Mock(side_effect=primary)
        images = SimpleNamespace(_command=original)
        collector = diagnostics.install(images, self.base / 'unused')
        self.addCleanup(collector.close)
        with patch.object(collector, 'before'), patch.object(collector, 'report'), \
                patch.object(collector, 'eject_log', side_effect=OSError('log failed')) as query, \
                diagnostics.failure_scope(self.base, self.image), self.assertRaises(type(primary)) as caught:
            with diagnostics.observe_detach():
                images._command(*self.args)
        self.assertIs(caught.exception, primary)
        original.assert_called_once_with(*self.args)
        query.assert_called_once()
        self.assertIn('Eject log unavailable: OSError', primary.__notes__)

    def test_only_exact_normal_whole_device_eject_is_intercepted(self):
        commands = (('/usr/bin/hdiutil', 'detach', '/dev/disk999'),
                    ('/usr/sbin/diskutil', 'eject', '/dev/disk999s1'),
                    ('/usr/sbin/diskutil', 'eject', '/dev/disk999', 'force'),
                    ('/usr/sbin/diskutil', 'eject', '/dev/rdisk999'),
                    ('/usr/sbin/diskutil', 'unmountDisk', '/dev/disk999'),
                    ('/usr/sbin/diskutil', 'eject', Path('/dev/disk999')))
        for args in commands:
            with self.subTest(args=args):
                primary = OSError('unselected error'); primary.returncode = 64
                original = Mock(side_effect=primary)
                images = SimpleNamespace(_command=original)
                collector = diagnostics.install(images, self.base / 'unused')
                self.addCleanup(collector.close)
                with patch.object(collector, 'before') as before, patch.object(collector, 'report') as report, \
                        patch.object(collector, 'eject_log') as query, \
                        diagnostics.failure_scope(self.base, self.image), self.assertRaises(type(primary)) as caught:
                    with diagnostics.observe_detach():
                        images._command(*args)
                self.assertIs(caught.exception, primary)
                original.assert_called_once_with(*args)
                before.assert_not_called(); report.assert_not_called(); query.assert_not_called()

    def test_artifact_rejects_unscoped_eject_log_records(self):
        observation = self.eject_observation()
        with patch.object(self.reporter, '_capture', return_value=captured(
                self.log_record('unable to eject /dev/disk999 (status code 0x00000010).'))):
            self.reporter.eject_log(observation)
        self.reporter.close()
        path = self.reporter.directory / diagnostics.REPORT
        original = path.read_text()
        event = json.loads(original)
        for change in ({'target': '/Users/unrelated'}, {'records': 'private /Users/unrelated\n'},
                       {'window_start_ns': -1}, {'query_status': 'empty'}):
            with self.subTest(change=change):
                path.write_text(json.dumps(event | change) + '\n')
                self.assertFalse(diagnostics.artifact_available(self.reporter.directory))
        path.write_text(original)
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def holder_output(self, *, device=None, inode=None):
        info = self.image.stat()
        device = info.st_dev if device is None else device
        inode = info.st_ino if inode is None else inode
        return f'p10\ncworker\nf3\ntREG\nD{device:#x}\ni{inode}\nn{self.image}\n'.encode()

    def mapping_capture(self, records=None, native=None):
        return [captured(plistlib.dumps({'images': records if records is not None else [self.record]})),
                captured(json.dumps(native or []).encode()),
                captured(self.holder_output(), b'partial visibility\n', 1)]

    def test_unmounted_attachment_exact_targets_and_exit1_output(self):
        with patch.object(self.reporter, '_capture', side_effect=self.mapping_capture()) as capture:
            self.reporter.report(self.args, OSError('resource busy'), self.scope())
        self.assertEqual(capture.call_count, 3)
        command = capture.call_args_list[-1].args[0]
        self.assertEqual(command[-4:], ['--', str(self.image), '/dev/disk999', '/dev/rdisk999'])
        self.assertNotIn('+f', command)
        self.assertNotIn(str(self.point), command)
        event = self.events()[-1]
        self.assertEqual(event['returncode'], 1)
        self.assertIn('p10', event['stdout'])
        self.assertIn('partial visibility', event['stderr'])
        info = self.image.stat()
        self.assertEqual((self.events()[1]['backing_device'], self.events()[1]['backing_inode']),
                         (info.st_dev, info.st_ino))
        self.assertEqual(event['backing_identity_status'], 'matched')
        self.assertIn(f'D{info.st_dev:#x}', event['stdout'])
        self.assertIn(f'i{info.st_ino}', event['stdout'])
        self.assertIsNone(self.events()[1]['mountpoint'])
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_raw_device_aliases_reject_unmapped_or_malformed_inputs(self):
        for devices in ([], ['/dev/rdisk999'], ['/dev/disk999', '/dev/disk999'],
                        ['/dev/disk999/../disk0'], ['/dev/disk999 private'], [None],
                        [f'/dev/disk{i}' for i in range(33)]):
            with self.subTest(devices=devices), self.assertRaises(ValueError):
                self.reporter._raw_devices(devices)

    def test_missing_raw_node_remains_a_bounded_inconclusive_holder_query(self):
        values = self.mapping_capture()
        values[-1] = captured(self.holder_output(), b'lsof: /dev/rdisk999: No such file or directory\n', 1)
        with patch.object(self.reporter, '_capture', side_effect=values) as capture:
            self.reporter.report(self.args, OSError('resource busy'), self.scope())
        self.assertEqual(capture.call_count, 3)
        self.assertIn('/dev/rdisk999', capture.call_args_list[-1].args[0])
        event = self.events()[-1]
        self.assertEqual(event['returncode'], 1)
        self.assertTrue(event['reaped']); self.assertFalse(event['timeout']); self.assertFalse(event['truncated'])
        self.assertIn('path-bearing diagnostic omitted', event['stderr'])
        self.assertNotIn('No such file', event['stderr'])
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
                    self.reporter.report(('/usr/sbin/diskutil', 'eject', devices[0]), OSError('busy'), self.scope())
                self.assertEqual(capture.call_count, 4 if mounted else 3)
                command = capture.call_args_list[2].args[0]
                self.assertEqual(command[command.index('--'):], ['--', str(self.image), *devices,
                    '/dev/rdisk2', '/dev/rdisk2s1', '/dev/rdisk3', '/dev/rdisk3s1'])
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
        with patch.object(self.reporter, '_mapping', return_value=(str(self.image), ['/dev/disk999'], str(self.point), '/dev/disk999s1', (self.image.stat().st_dev, self.image.stat().st_ino))), \
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

    def test_expected_busy_preserves_unexpected_deadline_and_attempt_budget(self):
        with patch.object(self.reporter, '_capture', side_effect=[v for _ in range(4) for v in self.mapping_capture()]) as capture:
            for _ in range(6):
                self.reporter.report(self.args, OSError('intentional busy'), self.scope(expected=True))
            self.assertEqual(self.reporter.attempts, 0)
            self.assertEqual(self.reporter.remaining, diagnostics.CAPTURE_BYTES)
            self.assertEqual((self.reporter.events, self.reporter.written), (0, 0))
            self.assertFalse(self.reporter.directory.exists())
            capture.assert_not_called()
            for _ in range(6):
                self.reporter.report(self.args, OSError('unexpected busy'), self.scope())
        self.assertEqual(self.reporter.attempts, 4)
        self.assertEqual(capture.call_count, 12)
        for index in range(0, 12, 3):
            self.assertEqual(len({c.args[1] for c in capture.call_args_list[index:index + 3]}), 1)
        self.assertFalse(self.events()[0]['expected_busy'])
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_pre_detach_pairs_first_call_and_later_call_has_fresh_identity(self):
        error = OSError('actual detach failure')
        order = []
        def original(*args):
            order.append('detach')
            raise error
        images = SimpleNamespace(_command=original)
        images.detach = lambda image, point: images._command(*self.args)
        collector = diagnostics.install(images, self.reporter.directory)
        self.addCleanup(collector.close)
        self.reporter = collector
        def capture(argv, deadline):
            order.append('observe')
            if argv[0] == '/usr/bin/hdiutil':
                return captured(plistlib.dumps({'images': [self.record]}))
            if argv[0] == diagnostics.sys.executable:
                return captured(b'[]')
            return captured(self.holder_output(), status=1)
        with patch.object(collector, '_capture', side_effect=capture), \
                diagnostics.failure_scope(self.base, self.image, mountpoint=self.point), diagnostics.observe_detach():
            for _ in range(2):
                with self.assertRaises(OSError) as caught:
                    images.detach(self.image, self.point)
                self.assertIs(caught.exception, error)
        events = self.events()
        self.assertEqual(order[:4], ['observe', 'observe', 'observe', 'detach'])
        self.assertEqual(collector.before_attempts, 1)
        self.assertEqual(collector.attempts, 2)
        failures = [event for event in events if event['kind'] == 'failure']
        self.assertEqual(failures[0]['operation_id'], events[0]['operation_id'])
        self.assertNotEqual(failures[1]['operation_id'], failures[0]['operation_id'])
        self.assertEqual([e['phase'] for e in events[:4]], ['before'] * 4)
        self.assertTrue(all(e['phase'] == 'after' for e in events[4:]))
        self.assertEqual([e['timestamp_ns'] for e in events], sorted(e['timestamp_ns'] for e in events))
        self.assertEqual(events[0]['kind'], 'observation')
        self.assertEqual(sum(e['kind'] == 'failure' for e in events), 2)
        self.assertTrue(diagnostics.artifact_available(collector.directory))
        self.assertIsNone(diagnostics._detach_observation.get())

    def replace_backing(self):
        self.image.rename(self.base / 'previous-backing')
        self.image.write_bytes(b'replacement, not a disk image')
        self.image.chmod(0o600)

    def test_same_path_replacement_is_distinct_across_operation_snapshots(self):
        original = self.image.stat()
        with patch.object(self.reporter, '_capture', side_effect=self.mapping_capture()):
            operation = self.reporter.before(self.args, self.scope())
        self.replace_backing()
        replacement = self.image.stat()
        self.assertNotEqual(original.st_ino, replacement.st_ino)
        with patch.object(self.reporter, '_capture', side_effect=self.mapping_capture()):
            self.reporter.report(self.args, OSError('actual detach failure'), self.scope(), operation)
        mappings = [e for e in self.events() if e['kind'] == 'mapping']
        self.assertEqual([e['backing_inode'] for e in mappings], [original.st_ino, replacement.st_ino])
        self.assertEqual([e['backing_identity_matches_first'] for e in mappings], [True, False])
        self.assertTrue(any('identity changed between' in e.get('reason', '') for e in self.events()))
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_backing_replacement_around_holder_query_is_not_a_match(self):
        original = self.image.stat()
        values = iter(self.mapping_capture())
        def capture(argv, deadline):
            value = next(values)
            if argv[0] == '/usr/sbin/lsof':
                self.replace_backing()
            return value
        with patch.object(self.reporter, '_capture', side_effect=capture):
            self.reporter.report(self.args, OSError('actual detach failure'), self.scope())
        event = self.events()[-1]
        self.assertEqual(event['kind'], 'lsof')
        self.assertEqual(event['backing_identity_status'], 'changed')
        self.assertIn(f'i{original.st_ino}', event['stdout'])
        self.assertEqual(event['backing_inode_after'], self.image.stat().st_ino)
        self.assertNotEqual(event['backing_inode_after'], original.st_ino)
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_backing_replacement_before_holder_query_omits_holder_query(self):
        values = iter(self.mapping_capture())
        def capture(argv, deadline):
            value = next(values)
            if argv[0] == diagnostics.sys.executable:
                self.replace_backing()
            return value
        with patch.object(self.reporter, '_capture', side_effect=capture) as captured_calls:
            self.reporter.report(self.args, OSError('actual detach failure'), self.scope())
        self.assertEqual(captured_calls.call_count, 2)
        self.assertIn('identity changed before holder', self.events()[-1]['reason'])
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_holder_identity_requires_valid_matching_device_and_inode(self):
        info = self.image.stat()
        outputs = [
            (f'p10\nf3\nn{self.image}\n'.encode(), 'unavailable'),
            (self.holder_output(inode=info.st_ino + 1), 'mismatch'),
            (self.holder_output(device=info.st_dev + 1), 'mismatch'),
            (self.holder_output().replace(f'D{info.st_dev:#x}'.encode(), b'Dnot-a-device'), 'unavailable'),
        ]
        for output, expected in outputs:
            with self.subTest(expected=expected):
                values = self.mapping_capture()
                values[-1] = captured(output, status=1)
                with patch.object(self.reporter, '_capture', side_effect=values):
                    self.reporter.report(self.args, OSError('actual detach failure'), self.scope())
                self.assertEqual(self.events()[-1]['backing_identity_status'], expected)
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_artifact_rejects_invalid_backing_identity_fields(self):
        with patch.object(self.reporter, '_capture', side_effect=self.mapping_capture()):
            self.reporter.report(self.args, OSError('actual detach failure'), self.scope())
        path = self.reporter.directory / diagnostics.REPORT
        original = path.read_text()
        for field, invalid in (('backing_inode', 'unknown'), ('backing_device', -1),
                               ('backing_identity_matches_first', 'yes')):
            with self.subTest(field=field):
                events = [json.loads(line) for line in original.splitlines()]
                next(e for e in events if e['kind'] == 'mapping')[field] = invalid
                path.write_text(''.join(json.dumps(event) + '\n' for event in events))
                self.assertFalse(diagnostics.artifact_available(self.reporter.directory))
        path.write_text(original)
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_partial_before_event_and_actual_failure_keep_operation_association(self):
        primary = OSError('actual detach failure')
        images = SimpleNamespace(_command=Mock(side_effect=primary))
        images.detach = lambda image, point: images._command(*self.args)
        collector = diagnostics.install(images, self.reporter.directory)
        self.addCleanup(collector.close)
        self.reporter = collector
        emit = collector._emit
        def partial(deadline, kind, **values):
            if collector.phase == 'before' and kind != 'observation':
                raise TimeoutError('pre-observation deadline after first row')
            return emit(deadline, kind, **values)
        captures = self.mapping_capture()[:2] + self.mapping_capture()
        with patch.object(collector, '_emit', side_effect=partial), \
                patch.object(collector, '_capture', side_effect=captures), \
                diagnostics.failure_scope(self.base, self.image, mountpoint=self.point), diagnostics.observe_detach():
            with self.assertRaises(OSError) as caught:
                images.detach(self.image, self.point)
        self.assertIs(caught.exception, primary)
        events = self.events()
        self.assertEqual(events[0]['kind'], 'observation')
        self.assertEqual(events[1]['kind'], 'failure')
        self.assertEqual({e['operation_id'] for e in events}, {events[0]['operation_id']})
        self.assertEqual(collector.before_attempts, 1)
        self.assertEqual(collector.attempts, 1)
        self.assertLessEqual(collector.events, diagnostics.EVENTS)
        self.assertLessEqual(collector.written, diagnostics.FILE_BYTES)
        self.assertTrue(diagnostics.artifact_available(collector.directory))
        self.assertIsNone(diagnostics._detach_observation.get())

    def test_pre_snapshot_cap_reserves_failure_bytes_and_observation_capacity(self):
        def consume(argv, deadline):
            self.assertEqual(self.reporter.remaining, diagnostics.BEFORE_CAPTURE_BYTES)
            self.reporter.remaining = 0
            value = captured(b'x' * diagnostics.BEFORE_CAPTURE_BYTES)
            value['truncated'] = True
            return value
        # A full pre-snapshot capture can leave no useful mapping, but cannot take
        # the output allowance reserved for the subsequent failure observation.
        with patch.object(self.reporter, '_capture', side_effect=consume) as capture:
            operation = self.reporter.before(self.args, self.scope())
            self.reporter.before(self.args, self.scope())
        capture.assert_called_once()
        self.assertEqual(self.reporter.attempts, 0)
        self.assertEqual(self.reporter.remaining, diagnostics.CAPTURE_BYTES - diagnostics.BEFORE_CAPTURE_BYTES)
        self.assertLessEqual(self.reporter.events, diagnostics.BEFORE_EVENTS)
        self.assertLessEqual(self.reporter.written, diagnostics.BEFORE_FILE_BYTES)
        with patch.object(self.reporter, '_capture', side_effect=self.mapping_capture()):
            self.reporter.report(self.args, OSError('actual failure'), self.scope(), operation)
        self.assertEqual(self.events()[-1]['phase'], 'after')
        self.assertEqual({e['operation_id'] for e in self.events()}, {operation})
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))

    def test_pre_snapshot_artifact_caps_leave_room_for_failure(self):
        def oversized_observation(args, scope, deadline):
            for _ in range(50):
                self.reporter._emit(deadline, 'unavailable', reason='x' * 4000)
            raise ValueError('pre-snapshot mapping unavailable')
        with patch.object(self.reporter, '_mapping', side_effect=oversized_observation):
            operation = self.reporter.before(self.args, self.scope())
        self.assertLessEqual(self.reporter.events, diagnostics.BEFORE_EVENTS)
        self.assertLessEqual(self.reporter.written, diagnostics.BEFORE_FILE_BYTES)
        self.reporter.report(self.args, OSError('actual failure'), None, operation)
        self.assertEqual(self.events()[-2]['kind'], 'failure')
        self.assertEqual(self.events()[-2]['phase'], 'after')
        self.assertTrue(diagnostics.artifact_available(self.reporter.directory))
        self.reporter.before_attempts = 0
        self.reporter.events = diagnostics.EVENTS - diagnostics.BEFORE_EVENTS
        with patch.object(self.reporter, '_mapping') as mapping:
            self.reporter.before(self.args, self.scope())
        mapping.assert_not_called()
        self.reporter.events = 0
        self.reporter.remaining = diagnostics.BEFORE_CAPTURE_BYTES
        with patch.object(self.reporter, '_capture') as capture:
            self.reporter.before(self.args, self.scope())
        capture.assert_not_called()

    def test_pre_observation_error_preserves_success_and_actual_detach_error(self):
        for error in (None, OSError('actual detach failure')):
            with self.subTest(error=error):
                images = SimpleNamespace(_command=Mock(return_value=b'ok', side_effect=error))
                images.detach = lambda image, point: images._command(*self.args)
                collector = diagnostics.install(images, self.base / 'unused')
                with patch.object(collector, 'before', side_effect=TimeoutError('observation deadline')), \
                        patch.object(collector, 'report') as report, \
                        diagnostics.failure_scope(self.base, self.image, mountpoint=self.point), diagnostics.observe_detach():
                    if error is None:
                        self.assertEqual(images.detach(self.image, self.point), b'ok')
                        report.assert_not_called()
                    else:
                        with self.assertRaises(OSError) as caught:
                            images.detach(self.image, self.point)
                        self.assertIs(caught.exception, error)
                        report.assert_called_once()
                self.assertIsNone(diagnostics._detach_observation.get())

    def test_pre_snapshot_uncertain_child_cleanup_disables_later_capture(self):
        def unsafe(argv, deadline):
            self.reporter.capture_disabled = True
            self.reporter.remaining = 0
            value = captured()
            value['cleanup_error'] = 'group termination: PermissionError'
            return value
        with patch.object(self.reporter, '_capture', side_effect=unsafe):
            self.reporter.before(self.args, self.scope())
        self.assertEqual(self.reporter.remaining, 0)
        with self.assertRaises(TimeoutError):
            self.reporter._capture(['must-not-spawn'], time.monotonic() + 12)
        self.spawn.assert_not_called()

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
        values[-1] = captured(b'p1\nf3\nn/other-user/secret\nn' + str(self.image).encode() +
            b'\nn/dev/rdisk999\nn/dev/rdisk999s1\nn/dev/rdisk111\n',
            b'warning /other-user/secret\nvisible warning', 1)
        with patch.object(self.reporter, '_capture', side_effect=values):
            self.reporter.report(self.args, OSError('busy'), self.scope())
        text = (self.reporter.directory / diagnostics.REPORT).read_text()
        self.assertNotIn('other-user', text)
        self.assertNotIn('disk111', text)
        self.assertNotIn('rdisk999s1', text)
        self.assertIn('n/dev/rdisk999', text)
        self.assertIn('visible warning', text)
        self.assertIn('unscoped name omitted', text)
        with patch.object(self.reporter, '_mapping', return_value=(str(self.image), ['/dev/disk999'], str(self.point), '/dev/disk999s1', (self.image.stat().st_dev, self.image.stat().st_ino))), \
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
                self.reporter.capture_disabled = False
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
