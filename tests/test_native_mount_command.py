"""Native mount routing and failed-command retention without system mounts."""
from contextlib import nullcontext
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from stallionfs import _native
from stallionfs.core import StallionError


class NativeMountCommand(unittest.TestCase):
    def test_failed_fskit_mount_is_retained_without_legacy_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / 'workspaces/owned-image'
            metadata = {'controller_profile': 'production'}
            proof = {'first_use': {'accepted': False}}
            operation = Mock(record={})
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
                    patch.object(_native, '_retain_failure') as retain:
                with self.assertRaisesRegex(StallionError, 'Native mount command failed') as raised:
                    _native.mount_locked(SimpleNamespace(root=root), workspace, metadata)
            operation.command.assert_called_once_with('mount', [
                '/sbin/mount', '-F', '-t', 'stallionfs', str(workspace), str(workspace / 'volume')])
            self.assertTrue(proof['first_mount_attempted'])
            self.assertTrue(operation.record['mount_attempted'])
            retain.assert_called_once_with(raised.exception, operation, workspace / 'volume', 'production')
            operation.finish.assert_not_called()
