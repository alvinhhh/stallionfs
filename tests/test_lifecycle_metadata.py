import errno
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from stallionfs import core, lifecycle


class LifecycleMetadata(unittest.TestCase):
    def test_replacement_syncs_directory_after_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            core.write_json(path, {'state': 'old'})
            sync_directory = core.sync_directory

            def check_published(parent):
                self.assertEqual(core.read_json(path)['state'], 'new')
                sync_directory(parent)

            with patch.object(core, 'sync_directory', side_effect=check_published) as sync:
                lifecycle.replace_json(path, {'state': 'new'})
            sync.assert_called_once_with(path.parent)

    def test_directory_sync_failure_propagates_after_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            core.write_json(path, {'state': 'old'})
            error = OSError(errno.EIO, 'directory sync failed')

            with patch.object(core, 'sync_directory', side_effect=error):
                with self.assertRaises(OSError) as raised:
                    lifecycle.replace_json(path, {'state': 'new'})
            self.assertIs(raised.exception, error)
            self.assertEqual(core.read_json(path)['state'], 'new')
            self.assertEqual(list(path.parent.iterdir()), [path])
