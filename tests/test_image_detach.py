"""Deterministic native receipts and inventories; no real disk commands."""
from copy import deepcopy
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from stallionfs import images, _scan
from stallionfs.core import StallionError
from image_failure_diagnostics import install, failure_scope, observe_detach, REPORT, artifact_available


class DetachContinuationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.base.chmod(0o700)
        # Keep synthetic eject failures out of an enclosing real-image collector.
        collector = install(images, self.base / 'mock-diagnostics')
        self.addCleanup(collector.close)
        self.enterContext(patch.object(collector, '_capture', side_effect=lambda *args: dict(
            stdout=b'', stderr=b'', returncode=1, timeout=False, truncated=False,
            reaped=True, capture_error=None, cleanup_error=None)))
        self.image, self.point = self.base / 'owned.sparseimage', self.base / 'volume'
        self.image.write_bytes(b'owned backing'); self.image.chmod(0o600)
        self.point.mkdir(mode=0o700)
        self.entry = {'image-path': str(self.image), 'owner-uid': os.getuid(), 'writeable': True,
                      'system-entities': [
                          {'dev-entry': '/dev/disk7', 'content-hint': 'GUID_partition_scheme'},
                          {'dev-entry': '/dev/disk7s1', 'content-hint': 'Apple_APFS'},
                          {'dev-entry': '/dev/disk8', 'content-hint': 'Apple_APFS'},
                          {'dev-entry': '/dev/disk8s1', 'potentially-mountable': True,
                           'mount-point': str(self.point)}]}
        self.closed = deepcopy(self.entry)
        del self.closed['system-entities'][-1]['mount-point']
        self.sequence = [self.entry, self.entry, self.closed, self.closed, None]
        self.active = None
        self.reads = 0
        self.runs = []
        self.first = self.failure()
        self.results = [self.first, subprocess.CompletedProcess([], 0, b'', b'')]
        self.command_hook = lambda: None
        self.read_hook = lambda: None
        self.live_mounts = lambda: None
        self.node_change = False
        self.forced_point_mount = False
        self.real_stat, self.real_lstat = os.stat, os.lstat
        def device_stat(path, *args, **kwargs):
            if str(path).startswith('/dev/disk'):
                return SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_dev=2,
                                       st_ino=100 + int(self.node_change),
                                       st_rdev=self.real_stat(self.point).st_dev)
            return self.real_stat(path, *args, **kwargs)
        def device_lstat(path, *args, **kwargs):
            if str(path).startswith('/dev/disk'):
                return device_stat(path)
            return self.real_lstat(path, *args, **kwargs)
        def mount_table():
            custom = self.live_mounts()
            if custom is not None:
                if isinstance(custom, BaseException):
                    raise custom
                return custom
            if self.active and self.active['system-entities'][-1].get('mount-point'):
                return [dict(device='/dev/disk8s1', path=str(self.point), filesystem='apfs',
                             readonly=False, ignore_ownership=False)]
            return []
        self.enterContext(patch.object(images, '_plist', side_effect=self.inventory))
        self.enterContext(patch.object(images.subprocess, 'run', side_effect=self.command))
        self.enterContext(patch.object(images.os, 'stat', side_effect=device_stat))
        self.enterContext(patch.object(images.os, 'lstat', side_effect=device_lstat))
        self.enterContext(patch.object(_scan, 'mounts', side_effect=mount_table))
        self.enterContext(patch.object(images.os.path, 'ismount', side_effect=lambda p:
            self.forced_point_mount or bool(self.active and
                self.active['system-entities'][-1].get('mount-point'))))

    @staticmethod
    def failure(stderr=b'Volume failed to eject', status=1):
        return subprocess.CompletedProcess([], status, b'', stderr)

    def inventory(self, *args):
        self.assertEqual(args, ('/usr/bin/hdiutil', 'info', '-plist'))
        value = self.sequence[self.reads]
        self.reads += 1
        self.active = deepcopy(value) if not isinstance(value, BaseException) else None
        self.read_hook()
        if isinstance(value, BaseException):
            raise value
        return {'images': [] if value is None else [value]}

    def command(self, args, **kwargs):
        self.assertLess(len(self.runs), 1 + len(images._BUSY_DETACH_DELAYS) + 1)
        expected = ('/usr/sbin/diskutil', 'eject') if not self.runs else ('/usr/bin/hdiutil', 'detach')
        self.assertEqual(args, [*expected, '/dev/disk7'])
        self.runs.append(tuple(args))
        self.command_hook()
        value = self.results[len(self.runs) - 1]
        if isinstance(value, BaseException):
            raise value
        return value

    def refused(self, commands=1):
        with self.assertRaises(StallionError) as caught:
            images.detach(self.image, self.point)
        self.assertIsInstance(caught.exception, images._CommandFailure)
        self.assertEqual(caught.exception.stderr, b'Volume failed to eject')
        self.assertEqual(len(self.runs), commands)
        self.assertEqual(self.image.read_bytes(), b'owned backing')
        return caught.exception

    def test_partial_unmount_continues_once_and_requires_absence(self):
        images.detach(self.image, self.point)
        self.assertEqual(self.reads, 5)
        self.assertEqual(len(self.runs), 2)
        self.assertEqual(self.runs, [('/usr/sbin/diskutil', 'eject', '/dev/disk7'),
                                     ('/usr/bin/hdiutil', 'detach', '/dev/disk7')])
        self.assertEqual(self.image.read_bytes(), b'owned backing')

    @classmethod
    def busy(cls, device='disk7', status=16):
        return cls.failure(f'hdiutil: couldn\'t eject "{device}" - Resource busy'.encode(), status)

    def test_transient_busy_detach_is_retried_with_fresh_validation(self):
        self.results = [self.first, self.busy(), self.busy(), subprocess.CompletedProcess([], 0, b'', b'')]
        self.sequence = [self.entry, self.entry, *[self.closed] * 6, None]
        with patch.object(images.time, 'sleep') as sleep:
            images.detach(self.image, self.point)
        self.assertEqual(self.runs, [('/usr/sbin/diskutil', 'eject', '/dev/disk7'),
                                     *[('/usr/bin/hdiutil', 'detach', '/dev/disk7')] * 3])
        self.assertEqual([call.args for call in sleep.call_args_list], [(0.25,), (0.5,)])
        self.assertEqual(self.reads, 9)
        self.assertEqual(self.image.read_bytes(), b'owned backing')

    def test_diagnostic_attempt_bound_matches_busy_retries(self):
        import image_failure_diagnostics
        self.assertEqual(image_failure_diagnostics.EJECT_ATTEMPTS, 2 + len(images._BUSY_DETACH_DELAYS))

    def test_persistent_busy_detach_is_bounded_and_preserves_first(self):
        attempts = len(images._BUSY_DETACH_DELAYS) + 1
        self.results = [self.first, *[self.busy()] * attempts]
        self.sequence = [self.entry, self.entry, *[self.closed] * (2 * attempts)]
        with patch.object(images.time, 'sleep') as sleep:
            error = self.refused(commands=1 + attempts)
        self.assertEqual(sleep.call_count, attempts - 1)
        self.assertEqual(error.__cause__.returncode, 16)
        self.assertIn(f'after {attempts} ordinary detach attempts', ' '.join(error.__cause__.__notes__))

    def test_busy_detach_after_macos_27_deprecation_warning_is_retried(self):
        warned = self.failure(images._DETACH_DEPRECATION + b'\n' + self.busy().stderr + b'\n', 16)
        self.results = [self.first, warned, subprocess.CompletedProcess([], 0, b'', images._DETACH_DEPRECATION)]
        self.sequence = [self.entry, self.entry, *[self.closed] * 4, None]
        with patch.object(images.time, 'sleep') as sleep:
            images.detach(self.image, self.point)
        self.assertEqual(len(self.runs), 3)
        self.assertEqual(sleep.call_count, 1)

    def test_other_detach_failures_are_not_retried(self):
        warning = images._DETACH_DEPRECATION + b'\n'
        for result in (self.busy('disk9'), self.busy(status=1),
                       self.failure(b'hdiutil: other warning\n' + self.busy().stderr, 16),
                       self.failure(warning + self.busy('disk9').stderr, 16),
                       self.failure(self.busy().stderr + b'\n' + images._DETACH_DEPRECATION, 16)):
            with self.subTest(stderr=result.stderr, status=result.returncode):
                self.reads = 0; self.runs.clear()
                self.results = [self.first, result]
                with patch.object(images.time, 'sleep') as sleep:
                    self.refused(commands=2)
                sleep.assert_not_called()

    def test_busy_continuation_changes_refuse_without_further_detach(self):
        self.results = [self.first, self.busy(), subprocess.CompletedProcess([], 0, b'', b'')]
        self.sequence = [self.entry, self.entry, self.closed, self.closed, self.entry]
        with patch.object(images.time, 'sleep'):
            error = self.refused(commands=2)
        self.assertIn('same unmounted graph', str(error.__cause__))

    def test_store_unmount_keeps_one_public_call_and_holds_workspace_lock(self):
        from stallionfs import core
        store = core.Store(self.base / 'store')
        workspace = 'a' * 32
        path = store.root / 'workspaces' / workspace
        path.mkdir(mode=0o700)
        metadata = {'id': workspace, 'commit': 'c' * 40, 'backend': 'image'}
        core.write_json(path / 'meta.json', metadata)
        self.image.rename(path / 'workspace.sparseimage')
        self.point.rmdir()
        self.image, self.point = path / 'workspace.sparseimage', path / 'volume'
        self.point.mkdir(mode=0o700)
        for entry in (self.entry, self.closed):
            entry['image-path'] = str(self.image)
        self.entry['system-entities'][-1]['mount-point'] = str(self.point)
        def locked():
            with self.assertRaises(BlockingIOError), core.lock(
                    store.root / 'locks' / f'workspace-{workspace}', blocking=False):
                self.fail('workspace lock was not held')
        self.command_hook = locked
        with patch.object(images, 'detach', wraps=images.detach) as detach:
            self.assertEqual(store.unmount(workspace), {'unmounted': workspace})
        detach.assert_called_once_with(self.image, self.point)
        self.assertEqual(len(self.runs), 2)
        self.assertEqual(core.read_json(store._state(workspace))['status'], 'open')

    def test_diagnostics_keep_initial_failure_and_successful_recovery_outcome(self):
        self.diagnostic_outcome('recovered', 2, 0)

    def test_diagnostics_keep_both_failures_and_failed_recovery_outcome(self):
        self.results[1] = self.failure(b'second failure', 64)
        self.diagnostic_outcome('failed', 2, 64)

    def test_diagnostics_keep_initial_failure_and_refusal_outcome(self):
        self.sequence[2] = self.entry
        self.diagnostic_outcome('refused', 1, None)

    def test_diagnostics_admit_busy_retries_before_recovery(self):
        self.results = [self.first, self.busy(), subprocess.CompletedProcess([], 0, b'', b'')]
        self.sequence = [self.entry, self.entry, *[self.closed] * 4, None]
        with patch.object(images.time, 'sleep'):
            self.diagnostic_outcome('recovered', 3, 0)

    def test_busy_retry_recovery_keeps_verified_target_for_eject_log(self):
        import image_failure_diagnostics
        changed = []
        finish = image_failure_diagnostics._finish_eject
        def spy(observation, error):
            changed.append(observation.get('target_changed'))
            return finish(observation, error)
        self.results = [self.first, self.busy(), self.busy(), subprocess.CompletedProcess([], 0, b'', b'')]
        self.sequence = [self.entry, self.entry, *[self.closed] * 6, None]
        with patch.object(images.time, 'sleep'), patch.object(image_failure_diagnostics, '_finish_eject', spy):
            self.diagnostic_outcome('recovered', 4, 0)
        self.assertEqual(changed, [False])

    def test_diagnostics_keep_persistent_busy_failure_outcome(self):
        attempts = len(images._BUSY_DETACH_DELAYS) + 1
        self.results = [self.first, *[self.busy()] * attempts]
        self.sequence = [self.entry, self.entry, *[self.closed] * (2 * attempts)]
        with patch.object(images.time, 'sleep'):
            self.diagnostic_outcome('failed', 1 + attempts, 16)

    def diagnostic_outcome(self, expected, commands, continuation_status):
        collector = install(images, self.base / 'diagnostics')
        self.addCleanup(collector.close)
        identity = self.image.stat()
        mapped = (str(self.image), ['/dev/disk7', '/dev/disk7s1', '/dev/disk8', '/dev/disk8s1'],
                  None, None, (identity.st_dev, identity.st_ino))
        captured = dict(stdout=b'', stderr=b'', returncode=1, timeout=False, truncated=False,
                        reaped=True, capture_error=None, cleanup_error=None)
        with patch.object(collector, '_mapping', return_value=mapped), \
                patch.object(collector, '_capture', side_effect=lambda *args: dict(captured)), \
                failure_scope(self.base, self.image, mountpoint=self.point), observe_detach():
            if expected == 'recovered':
                images.detach(self.image, self.point)
            else:
                self.refused(commands)
        events = [json.loads(line) for line in (collector.directory / REPORT).read_text().splitlines()]
        failures = [e for e in events if e['kind'] == 'failure']
        self.assertEqual(len(failures), 2 if expected == 'failed' else 1)
        self.assertEqual(failures[0]['error'], '_CommandFailure')
        outcome = next(e for e in events if e['kind'] == 'eject_outcome')
        self.assertEqual((outcome['commands'], outcome['first_status'], outcome['continuation_status'],
                          outcome['outcome']), (commands, 1, continuation_status, expected))
        self.assertEqual(outcome['operation_id'], failures[0]['operation_id'])
        self.assertTrue(artifact_available(collector.directory))
        self.assertEqual(len(self.runs), commands)

    def test_postcontinuation_backing_or_mount_changes_preserve_first(self):
        original_closed = deepcopy(self.closed)
        for change in ('mode', 'mount', 'unknown-mounts', 'inventory'):
            with self.subTest(change=change):
                self.reads = 0; self.runs.clear()
                self.image.chmod(0o600)
                self.forced_point_mount = False
                self.live_mounts = lambda: None
                self.sequence = [self.entry, self.entry, original_closed, original_closed,
                                 StallionError('post inventory unknown') if change == 'inventory' else None]
                def mutate():
                    if len(self.runs) != 2:
                        return
                    if change == 'mode':
                        self.image.chmod(0o644)
                    elif change == 'mount':
                        self.forced_point_mount = True
                    elif change == 'unknown-mounts':
                        self.live_mounts = lambda: OSError('post mounts unknown')
                self.command_hook = mutate
                self.refused(commands=2)

    def test_both_native_failures_preserve_first_and_second(self):
        self.results[1] = self.failure(b'second eject denied', 64)
        error = self.refused(commands=2)
        self.assertEqual(error.__cause__.stderr, b'second eject denied')
        self.assertIn('second eject denied', ' '.join(error.__notes__))

    def test_success_status_with_attachment_remaining_is_a_failure(self):
        self.sequence[-1] = self.closed
        error = self.refused(commands=2)
        self.assertIn('remains attached', str(error.__cause__))

    def test_continuation_timeout_preserves_first_failure_without_third_attempt(self):
        timeout = subprocess.TimeoutExpired(['/usr/bin/hdiutil', 'detach', '/dev/disk7'], 1)
        self.results[1] = timeout
        error = self.refused(commands=2)
        self.assertIs(error.__cause__, timeout)
        self.assertEqual(self.reads, 4)

    def test_continuation_interrupt_propagates_without_third_attempt(self):
        interruption = KeyboardInterrupt('detach interrupted')
        self.results[1] = interruption
        with self.assertRaises(KeyboardInterrupt) as caught:
            images.detach(self.image, self.point)
        self.assertIs(caught.exception, interruption)
        self.assertIn('First eject failure', ' '.join(interruption.__notes__))
        self.assertEqual((len(self.runs), self.reads), (2, 4))

    def test_still_mounted_or_disappeared_refuses_continuation(self):
        for entry in (self.entry, None):
            with self.subTest(entry=entry):
                self.reads = 0; self.runs.clear()
                self.sequence[2] = entry
                self.refused()

    def test_full_graph_and_attachment_mutations_refuse(self):
        changes = []
        for field, value in (('owner-uid', os.getuid() + 1), ('writeable', False),
                             ('image-path', str(self.base / 'missing'))):
            changed = deepcopy(self.closed); changed[field] = value; changes.append(changed)
        changed = deepcopy(self.closed); changed['system-entities'].reverse(); changes.append(changed)
        changed = deepcopy(self.closed); changed['system-entities'][1]['dev-entry'] = '/dev/disk7s2'; changes.append(changed)
        changed = deepcopy(self.closed); changed['system-entities'][1]['content-hint'] = 'EFI'; changes.append(changed)
        changed = deepcopy(self.closed); changed['system-entities'][1]['extra'] = True; changes.append(changed)
        changed = deepcopy(self.closed); changed['system-entities'].append(changed['system-entities'][0]); changes.append(changed)
        changed = deepcopy(self.closed); changed['system-entities'][-1]['mount-point'] = ''; changes.append(changed)
        for changed in changes:
            with self.subTest(changed=changed):
                self.reads = 0; self.runs.clear(); self.sequence[2] = changed
                self.refused()

    def test_mount_table_overrides_omitted_native_mount_metadata(self):
        for device in ('/dev/disk7', '/dev/disk7s1', '/dev/disk8', '/dev/disk8s1'):
            with self.subTest(device=device):
                self.reads = 0; self.runs.clear()
                self.live_mounts = lambda: ([dict(device=device, path='/another/mount')]
                                          if self.runs else None)
                self.refused()

    def test_unknown_mount_inventory_and_expected_point_mount_refuse(self):
        for value in (OSError('cannot read mounts'), {}, [dict(path='/unknown')]):
            with self.subTest(value=value):
                self.reads = 0; self.runs.clear()
                self.live_mounts = lambda: value if self.runs else None
                self.refused()
        self.live_mounts = lambda: None
        self.reads = 0; self.runs.clear()
        self.command_hook = lambda: setattr(self, 'forced_point_mount', True)
        self.refused()

    def test_last_precontinuation_read_rechecks_backing_and_node_identity(self):
        # Mutate at the last inventory read, after earlier recovery checks passed.
        for change in ('inode', 'device', 'mode', 'nlink', 'owner', 'node'):
            with self.subTest(change=change):
                self.reads = 0; self.runs.clear(); self.node_change = False
                self.image.chmod(0o600)
                real_identity = images._backing_identity
                def identity(image):
                    value = real_identity(image)
                    if self.reads < 4 or change not in ('device', 'owner'):
                        return value
                    modified = list(value); modified[0 if change == 'device' else 2] += 1
                    return tuple(modified)
                def mutate():
                    if self.reads != 4:
                        return
                    if change == 'inode':
                        self.image.rename(self.base / 'original')
                        self.image.write_bytes(b'owned backing'); self.image.chmod(0o600)
                    elif change == 'mode':
                        self.image.chmod(0o640)
                    elif change == 'nlink':
                        os.link(self.image, self.base / 'linked')
                    elif change == 'node':
                        self.node_change = True
                self.read_hook = mutate
                with patch.object(images, '_backing_identity', side_effect=identity):
                    self.refused()
                if (self.base / 'linked').exists():
                    (self.base / 'linked').unlink()

    def test_unknown_attachment_inventory_preserves_first(self):
        self.sequence[2] = StallionError('inventory unknown')
        error = self.refused()
        self.assertIn('inventory unknown', str(error.__cause__))

    def test_ineligible_command_errors_never_start_reconciliation(self):
        cases = [self.failure(b'Permission denied'), self.failure(b'Volume failed to eject', 5),
                 self.failure(b'Volume failed to eject\nPermission denied'), self.failure(status=-15),
                 subprocess.CompletedProcess([], 1, b'Permission denied', b'Volume failed to eject'),
                 PermissionError('launch denied'), subprocess.TimeoutExpired('diskutil', 1),
                 KeyboardInterrupt('interrupted'), StallionError('synthetic error')]
        cases[-1].returncode = 1
        for result in cases:
            with self.subTest(result=result):
                self.reads = 0; self.runs.clear(); self.results[0] = result
                with self.assertRaises(BaseException) as caught:
                    images.detach(self.image, self.point)
                if isinstance(result, BaseException):
                    self.assertIs(caught.exception, result)
                self.assertEqual(len(self.runs), 1)
                self.assertEqual(self.reads, 2)

    def test_interrupted_recovery_retains_first_and_propagates_interrupt(self):
        self.sequence[2] = KeyboardInterrupt('inventory interrupted')
        with self.assertRaises(KeyboardInterrupt) as caught:
            images.detach(self.image, self.point)
        self.assertIn('First eject failure', ' '.join(caught.exception.__notes__))
        self.assertEqual(len(self.runs), 1)

    def test_original_snapshot_is_immutable_and_ambiguous_device_refuses(self):
        state = images.mounted(self.image)
        captured = state['attachment']
        self.entry['system-entities'][1]['content-hint'] = 'changed'
        self.assertEqual(state['attachment'], captured)
        self.assertEqual(plistlib.loads(captured)['system-entities'][1]['content-hint'], 'Apple_APFS')
        other = self.base / 'other.sparseimage'; other.write_bytes(b'other'); other.chmod(0o600)
        inventory = {'images': [self.entry, dict(self.closed, **{'image-path': str(other)})]}
        with patch.object(images, '_plist', return_value=inventory), self.assertRaises(StallionError):
            images.mounted(self.image)
