"""Initial write probe faults on fresh owned paths, without native mounts."""
import copy
import errno
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from stallionfs import _native, core


class WriteProbe(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sfs-probe-unit-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.repo = self.path / 'volume/repo'
        self.repo.mkdir(parents=True)
        self.meta = dict(commit='a' * 40, branch='main')
        self.store = SimpleNamespace(_standalone_git=Mock())
        self.saved = []
        self.calls = []
        self.errors = {}
        self.short = False
        self.operation = SimpleNamespace(record={'helpers': [], 'operation': 'native-mount'},
                                         persist=self.persist)
        for target, kwargs in (
            ('stallionfs._native_create_git.qualified_runtime', dict(return_value='owned-runtime')),
            ('stallionfs._native_create_git.readiness', dict(return_value=('a' * 40, 'main'))),
            ('stallionfs._native.os.open', dict(side_effect=self.open)),
            ('stallionfs._native.os.write', dict(side_effect=self.write)),
            ('stallionfs._native.os.fsync', dict(side_effect=lambda fd: self.event('fsync'))),
            ('stallionfs._native.os.close', dict(side_effect=lambda fd: self.event('close'))),
            ('stallionfs._native.Path.unlink', dict(autospec=True, side_effect=self.unlink)),
        ):
            self.enterContext(patch(target, **kwargs))

    def event(self, step):
        self.calls.append(step)
        if step in self.errors:
            raise self.errors[step]

    def persist(self):
        step = 'completion-persist' if self.operation.record['write_probe']['complete'] else 'persist'
        self.event(step)
        self.saved.append(copy.deepcopy(self.operation.record))

    def open(self, path, flags, mode):
        self.assertEqual(Path(path).parent, self.repo)
        self.assertEqual(flags, _native.os.O_WRONLY | _native.os.O_CREAT |
                         _native.os.O_EXCL | _native.os.O_NOFOLLOW)
        self.assertEqual(mode, 0o600)
        self.assertEqual(len(self.saved), 1)
        self.assertFalse(self.saved[0]['write_probe']['complete'])
        self.event('open')
        return 917

    def write(self, fd, data):
        self.assertEqual(fd, 917)
        self.event('write')
        return len(data) - int(self.short)

    def unlink(self, path):
        self.assertEqual(str(path), self.operation.record['write_probe']['path'])
        self.event('unlink')

    def run_probe(self, initial=True):
        return _native._usable(self.store, self.path, self.meta,
                               initial=initial, operation=self.operation)

    def test_write_error_survives_close_error(self):
        primary = OSError(errno.EINVAL, 'primary-private-detail')
        self.errors = dict(write=primary, close=OSError(errno.EBADF, 'cleanup-private-detail'))
        with self.assertRaises(OSError) as caught:
            self.run_probe()
        self.assertIs(caught.exception, primary)

    def assert_failure(self, step, cleanup=False, short=False):
        primary = OSError(errno.EINVAL, 'private-detail' * 1000)
        self.short = short
        if not short:
            self.errors[step] = primary
        if cleanup:
            self.errors['close'] = OSError(errno.EBADF, 'cleanup-private-detail')
        with self.assertRaises(OSError) as caught:
            self.run_probe()
        if short:
            self.assertEqual(caught.exception.errno, errno.EIO)
        else:
            self.assertIs(caught.exception, primary)
        steps = ['persist', 'open', 'write', 'fsync', 'close', 'unlink', 'completion-persist']
        expected = steps[:steps.index(step) + 1]
        if step in ('write', 'fsync'):
            expected.append('close')
        self.assertEqual(self.calls, expected)
        diagnostic = self.operation.record['write_probe_diagnostic']
        self.assertEqual(diagnostic['attempted_steps'], expected)
        self.assertEqual(diagnostic['failed_step'], step)
        self.assertEqual(diagnostic['error'], dict(type='OSError', errno=errno.EIO if short else errno.EINVAL))
        if cleanup:
            self.assertEqual(diagnostic['cleanup_error'], dict(step='close', type='OSError', errno=errno.EBADF))
        else:
            self.assertNotIn('cleanup_error', diagnostic)
        self.assertEqual(self.operation.record['write_probe']['complete'], step == 'completion-persist')
        self.assertLess(len(json.dumps(diagnostic)), 512)
        self.assertNotIn('private-detail', json.dumps(diagnostic))
        # Exercise the existing failure handler, retaining diagnostics without a new probe attempt.
        with patch.object(_native, 'observe', return_value=None), \
             patch.object(self.operation, 'persist') as retained:
            _native._record_failure(caught.exception, self.operation, self.path / 'volume', 'production')
        retained.assert_called_once_with()
        self.assertIs(caught.exception.native_candidate_result, self.operation.record)
        self.assertEqual(self.operation.record['outcome'], 'incomplete')
        self.assertEqual(self.calls, expected)

    def test_first_persistence_failure(self): self.assert_failure('persist')
    def test_open_failure(self): self.assert_failure('open')
    def test_short_write(self): self.assert_failure('write', short=True)
    def test_write_and_close_failure(self): self.assert_failure('write', cleanup=True)
    def test_fsync_and_close_failure(self): self.assert_failure('fsync', cleanup=True)
    def test_close_only_failure(self): self.assert_failure('close')
    def test_unlink_failure(self): self.assert_failure('unlink')
    def test_completion_persistence_failure(self): self.assert_failure('completion-persist')

    def test_success(self):
        self.assertEqual(self.run_probe(), str(self.repo))
        expected = ['persist', 'open', 'write', 'fsync', 'close', 'unlink', 'completion-persist']
        self.assertEqual(self.calls, expected)
        self.assertEqual(len(self.saved), 2)
        self.assertTrue(self.saved[-1]['write_probe']['complete'])
        self.assertEqual(self.operation.record['write_probe_diagnostic'], dict(attempted_steps=expected))

    def test_later_readiness_does_not_probe(self):
        self.assertEqual(self.run_probe(initial=False), str(self.repo))
        self.assertEqual(self.calls, [])
        self.assertNotIn('write_probe', self.operation.record)

    def test_initial_readiness_mismatch_does_not_probe(self):
        with patch('stallionfs._native_create_git.readiness', return_value=('wrong', 'main')):
            with self.assertRaises(core.StallionError):
                self.run_probe()
        self.assertEqual(self.calls, [])
        self.assertNotIn('write_probe', self.operation.record)

    def test_failure_handler_persists_diagnostics_in_existing_order(self):
        operation = _native.Operation.__new__(_native.Operation)
        operation.record = self.operation.record
        operation.directory = self.path / 'archive'
        operation.journal = self.path / 'journal.json'
        self.operation = operation
        primary = OSError(errno.EINVAL, 'primary')
        self.errors = dict(write=primary, close=OSError(errno.EBADF, 'cleanup'))
        published = []
        def persist(path, record):
            published.append((path, copy.deepcopy(record)))
        def opened(*args):
            self.assertEqual([p for p, r in published],
                             [operation.directory / 'record.json', operation.journal])
            self.event('open')
            return 917
        with patch.object(_native, '_persist', side_effect=persist), \
             patch.object(_native, 'observe', return_value=None):
            with patch.object(_native.os, 'open', side_effect=opened):
                with self.assertRaises(OSError) as caught:
                    self.run_probe()
            _native._record_failure(caught.exception, operation, self.path / 'volume', 'production')
        self.assertIs(caught.exception, primary)
        self.assertEqual([p for p, r in published],
                         [operation.directory / 'record.json', operation.journal] * 2)
        self.assertFalse(published[0][1]['write_probe']['complete'])
        self.assertEqual(published[0][1]['write_probe_diagnostic'], dict(attempted_steps=['persist']))
        self.assertEqual(published[-1][1]['write_probe_diagnostic'], operation.record['write_probe_diagnostic'])
        self.assertEqual(published[-1][1]['outcome'], 'incomplete')
        self.assertEqual(self.calls, ['open', 'write', 'close'])

    def test_recovery_readiness_uses_completion_evidence(self):
        from stallionfs import _native_recovery as recovery
        store = SimpleNamespace(root=self.path)
        path = self.path / 'workspaces' / ('a' * 32)
        proof = dict(first_mount_attempted=True,
                     first_use=dict(accepted=True, operation='b' * 32,
                                    write_probe=dict(complete=True, path=str(path / 'volume/repo' /
                                        ('.stallionfs-write-' + 'c' * 32)))))
        with patch('stallionfs._native_create_authority.installed'), \
             patch.object(_native, 'installed_target', return_value='owned-target'), \
             patch.object(core, 'read_json', return_value=proof):
            self.assertEqual(recovery.ready(store, path, self.meta), 'owned-target')
            proof['first_use']['write_probe_diagnostic'] = dict(attempted_steps=['completion-persist'])
            for field in ('complete', 'path'):
                bad = copy.deepcopy(proof)
                bad['first_use']['write_probe'][field] = False if field == 'complete' else '/invalid'
                with patch.object(core, 'read_json', return_value=bad):
                    with self.assertRaises(core.StallionError):
                        recovery.ready(store, path, self.meta)
