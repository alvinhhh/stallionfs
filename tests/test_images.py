"""Real APFS image lifecycle checks; never touch an existing volume."""
import os
from contextlib import nullcontext
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from stallionfs import images
if __package__:
    from .image_failure_diagnostics import failure_scope, observe_detach, detach_observation_selection
else:
    from image_failure_diagnostics import failure_scope, observe_detach, detach_observation_selection
from stallionfs.core import StallionError


@unittest.skipUnless(os.environ.get('STALLIONFS_TEST_IMAGES') == '1' and sys.platform == 'darwin' and int(platform.mac_ver()[0].split('.')[0] or 0) >= 26,
                     'Set STALLIONFS_TEST_IMAGES=1 on macOS 26 or newer to run real mount checks')
class Images(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.failed_images = set()
        self.retain = False
        self.observation = 'initial-unmount'

    def _detach(self, image, point, *, stage='body', expected=False, command=None):
        with failure_scope(self.base, image, mountpoint=point, stage=stage, expected=expected):
            try:
                return (command or images.detach)(image, point)
            except BaseException as error:
                if not (expected and isinstance(error, StallionError)):
                    self.failed_images.add(Path(image))
                    self.retain = True
                raise

    def _callTestMethod(self, method):
        try:
            super()._callTestMethod(method)
        except BaseException:
            self.retain = True
            raise
        finally:
            if self._outcome is not None and not self._outcome.success:
                self.retain = True

    def setUp(self):
        try:
            self._prepare()
        except BaseException:
            self.retain = True
            raise

    def _prepare(self):
        self.observation = detach_observation_selection()
        self.base = Path(tempfile.mkdtemp(prefix='stallionfs-images-')).resolve()
        self.source = self.base / 'source'
        self.source.mkdir(mode=0o700)
        (self.source / 'file').write_bytes(b'original')
        (self.source / 'file').chmod(0o640)
        subprocess.run(['/usr/bin/xattr', '-w', 'com.stallionfs.test', 'attribute', str(self.source / 'file')], check=True)
        (self.source / 'link').symlink_to('file')
        self.seed = self.base / 'seed.sparseimage'
        original_detach = images.detach
        def observed_detach(image, point):
            return self._detach(image, point, stage='setup', command=original_detach)
        with failure_scope(self.base, self.seed, stage='setup'), \
                patch.object(images, 'detach', side_effect=observed_detach):
            images.build(self.source, self.seed, 1)

    def tearDown(self):
        # Any failed body or uncertain cleanup retains the entire disposable fixture.
        if self.retain or self.failed_images:
            return
        try:
            for image in self.base.glob('*.sparseimage'):
                state = images.mounted(image)
                if state:
                    point = state['mountpoint'] or self.base / 'unused'
                    self._detach(image, point, stage='cleanup')
            for image in self.base.glob('*.sparseimage'):
                if images.mounted(image) is not None:
                    raise StallionError(f'Image remains attached; retain fixture: {self.base}')
            shutil.rmtree(self.base)
        except BaseException:
            self.retain = True
            raise

    def test_clone_ownership_busy_detach_and_recovery(self):
        first, second = self.base / 'first.sparseimage', self.base / 'second.sparseimage'
        images.clone(self.seed, first)
        images.clone(self.seed, second)
        first_mount, second_mount = self.base / 'first', self.base / 'second'
        repo = images.attach(first, first_mount)
        sibling = images.attach(second, second_mount)
        info = (repo / 'file').stat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)),
                         (os.getuid(), os.getgid(), 0o640))
        self.assertEqual(subprocess.check_output(['/usr/bin/xattr', '-p', 'com.stallionfs.test', str(repo / 'file')]).rstrip(b'\n'), b'attribute')
        self.assertEqual(os.readlink(repo / 'link'), 'file')
        self.assertEqual(stat.S_IMODE(first_mount.stat().st_mode), 0o700)
        self.assertEqual(images.attach(first, first_mount), repo)
        from stallionfs._scan import mounts
        actual_mounts = mounts()
        for changed in ({'readonly': True}, {'ignore_ownership': True}, {'device': '/dev/disk999'}):
            records = [record | changed if record['path'] == str(first_mount) else record for record in actual_mounts]
            with self.subTest(changed=changed), patch('stallionfs._scan.mounts', return_value=records):
                with self.assertRaises(StallionError):
                    images.mounted(first)
        with self.assertRaises(StallionError):
            self._detach(first, second_mount, expected=True)
        with self.assertRaises(StallionError):
            images.clone(first, self.base / 'unsafe.sparseimage')
        (repo / 'file').write_bytes(b'changed')
        self.assertEqual((sibling / 'file').read_bytes(), b'original')
        with (repo / 'file').open('rb') as busy:
            with failure_scope(self.base, first, mountpoint=first_mount, stage='body', expected=True):
                with self.assertRaises(StallionError):
                    self._detach(first, first_mount, expected=True)
            self.assertEqual(busy.read(), b'changed')
            self.assertIsNotNone(images.mounted(first))
        self.assertTrue(busy.closed)
        self._detach(first, first_mount)
        self.assertIsNone(images.mounted(first))
        repo = images.attach(first, first_mount)
        self.assertEqual((repo / 'file').read_bytes(), b'changed')
        with observe_detach() if self.observation != 'enospc-initial-detach' else nullcontext():
            self._detach(first, first_mount)
        self._detach(second, second_mount)
        seed_repo = images.attach(self.seed, self.base / 'seed')
        self.assertEqual((seed_repo / 'file').read_bytes(), b'original')
        self._detach(self.seed, self.base / 'seed')

    def test_attach_interruption_is_discoverable_and_paths_are_checked(self):
        image, point = self.base / 'copy.sparseimage', self.base / 'copy'
        images.clone(self.seed, image)
        original = images._plist
        def interrupted(*args):
            result = original(*args)
            if args[:3] == ('/usr/sbin/diskutil', 'image', 'attach'):
                raise KeyboardInterrupt('after native mount')
            return result
        with patch.object(images, '_plist', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt) as interrupted_error:
                images.attach(image, point)
            self.assertIn('needs recovery', ' '.join(interrupted_error.exception.__notes__))
        self.assertEqual(images.mounted(image)['mountpoint'], str(point))
        self.assertEqual((images.attach(image, point) / 'file').read_bytes(), b'original')
        self._detach(image, point)
        alias = self.base / 'alias.sparseimage'
        alias.symlink_to(image)
        with self.assertRaises(StallionError):
            images.mounted(alias)
        alias.unlink()
        hardlink = self.base / 'hardlink.sparseimage'
        os.link(image, hardlink)
        with self.assertRaises(StallionError):
            images.mounted(image)
        hardlink.unlink()
        link = self.base / 'mount-link'
        link.symlink_to(point)
        with self.assertRaises(StallionError):
            images.attach(image, link)
        self._detach(image, point)

class ImageFormatErrors(unittest.TestCase):
    def test_invalid_plist_reports_an_actionable_error(self):
        for raw in (b'not a property list', b'<?xml version="1.0"?><plist><dict>', b'<?xml version="1.0"?><plist><array/></plist>'):
            with self.subTest(raw=raw), patch.object(images, '_command', return_value=raw):
                with self.assertRaises(StallionError):
                    images._plist('test-tool')


if __name__ == '__main__':
    unittest.main()
