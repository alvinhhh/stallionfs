"""Native mount routing and failed-command retention without system mounts."""
from contextlib import nullcontext
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from stallionfs import _native, _native_recovery, _native_activation
from stallionfs.core import StallionError


class NativeMountCommand(unittest.TestCase):
    @staticmethod
    def intent(workspace):
        # Only request filesystem publication is doubled here; mount dispatch
        # and its no-retry failure handling remain real. Producer IO has its own
        # offline integration regression.
        return dict(version=1, operation='2'*32, action='native-mount', transaction='4'*32,
                    workspace=workspace.name, nonce='3'*32, parent=[1,2], file=[1,3], uuid='5'*32,
                    generation=1, root_digest='6'*64, committed_end=16384, physical_end=16384)

    def test_failed_compound_remount_uses_fskit_without_legacy_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / ('workspaces/' + '1'*32)
            for profile, settings in _native.PROFILES.items():
                with self.subTest(profile=profile):
                    metadata = {'controller_profile': profile}
                    target = {'directory': str(workspace)}
                    operation = Mock(path=workspace, record={'operation':'native-mounted-snapshot', 'target': target, 'profile': profile,
                                             'host': 'fixture-host', 'remount_attempts': []})
                    operation.command.return_value = {'returncode': 72, 'outcome': 'error'}
                    check = Mock()
                    with patch.object(_native, 'qualify', return_value=settings['type']), \
                            patch.object(_native, 'resource_binding', return_value=nullcontext(check)), \
                            patch.object(_native_recovery, 'absent') as absent, \
                            patch.object(_native_recovery, '_anchor_guard', return_value={}), \
                            patch.object(_native, '_observe_until') as observe, \
                            patch.object(_native, '_persist') as persist, \
                            patch.object(_native_activation, 'pending', return_value=nullcontext(self.intent(workspace))):
                        with self.assertRaisesRegex(StallionError, 'committed; remount failed'):
                            _native_recovery._remount_compound(None, workspace, metadata, operation)
                    operation.command.assert_called_once_with('mount', [
                        '/sbin/mount', '-F', '-t', settings['type'], '-o', 'rw,owners,sfs_activation='+'2'*32+'.'+'3'*32, str(workspace), str(workspace / 'volume')])
                    self.assertEqual(operation.record['phase'], 'remount-attempted')
                    self.assertEqual(operation.record['remount_attempts'][-1]['response'],
                                     {'returncode': 72, 'outcome': 'error'})
                    self.assertTrue(operation.record['remount_attempts'][-1]['launched'])
                    self.assertEqual(absent.call_count, 2)
                    check.assert_called_once_with()
                    observe.assert_not_called()
                    persist.assert_not_called()

    def test_failed_fskit_mount_is_retained_without_legacy_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'workspaces').mkdir(mode=0o700)
            (root / 'journals').mkdir(mode=0o700)
            workspace = root / ('workspaces/' + '1'*32)
            workspace.mkdir(mode=0o700)
            metadata = {'controller_profile': 'production'}
            proof = {'first_use': {'accepted': False}}
            operation = Mock(path=workspace, command_context={}, record={'operation':'native-mount', 'activation_protocol':1})
            operation.command.return_value = {'returncode': 72}
            with patch.object(_native, 'recover_install', return_value='owned-target'), \
                    patch('stallionfs.core.read_json', side_effect=[metadata, proof, proof]), \
                    patch('stallionfs.core.private_directory'), \
                    patch.object(_native, 'resource_binding', return_value=nullcontext(Mock())), \
                    patch.object(_native, 'observe', return_value=None), \
                    patch.object(_native, 'Operation', return_value=operation), \
                    patch.object(_native, '_guard_current', return_value={}), \
                    patch.object(_native, 'qualify', return_value='stallionfs'), \
                    patch.object(_native, '_persist'), \
                    patch.object(_native, '_retain_failure') as retain, \
                    patch.object(_native_activation, 'pending', return_value=nullcontext(self.intent(workspace))):
                with self.assertRaisesRegex(StallionError, 'Native mount command failed') as raised:
                    _native.mount_locked(SimpleNamespace(root=root), workspace, metadata)
            operation.command.assert_called_once_with('mount', [
                '/sbin/mount', '-F', '-t', 'stallionfs', '-o', 'rw,owners,sfs_activation='+'2'*32+'.'+'3'*32, str(workspace), str(workspace / 'volume')])
            self.assertTrue(proof['first_mount_attempted'])
            self.assertTrue(operation.record['mount_attempted'])
            retain.assert_called_once_with(raised.exception, operation, workspace / 'volume', 'production')
            operation.finish.assert_not_called()
