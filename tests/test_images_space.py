"""Opt-in, bounded ENOSPC check inside disposable one-GiB APFS images."""
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import platform
import random
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

from stallionfs import images


def fullsync(path, value):
    with path.open('wb', buffering=0) as stream:
        if stream.write(value) != len(value):
            raise RuntimeError('Short sentinel write')
        os.fsync(stream.fileno())
        fcntl.fcntl(stream.fileno(), fcntl.F_FULLFSYNC)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


@unittest.skipUnless(
    os.environ.get('STALLIONFS_TEST_IMAGES') == '1' and sys.platform == 'darwin'
    and int(platform.mac_ver()[0].split('.')[0] or 0) >= 26,
    'Set STALLIONFS_TEST_IMAGES=1 on macOS 26+ for the bounded disk-full test',
)
class ImageSpace(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='stallionfs-space-')).resolve()
        # Registered before setup so a failed build never leaves an unexamined mount.
        self.addCleanup(self.clean)
        if shutil.disk_usage(self.base).free < 3 * 1024 ** 3:
            self.skipTest('This disposable one-GiB image test needs three GiB host headroom')
        self.source = self.base / 'source'
        self.source.mkdir(mode=0o700)
        self.original = random.Random(7).randbytes(4096)
        fullsync(self.source / 'sentinel', self.original)
        (self.source / 'sentinel').chmod(0o640)
        subprocess.run(['/usr/bin/xattr', '-w', 'com.stallionfs.space', 'retained',
                        str(self.source / 'sentinel')], check=True)
        (self.source / 'link').symlink_to('sentinel')
        self.seed = self.base / 'seed.sparseimage'
        images.build(self.source, self.seed, 1)

    def clean(self):
        # A failed/unknown/busy detach aborts cleanup and retains every image.
        try:
            for image in self.base.glob('*.sparseimage'):
                state = images.mounted(image)
                if state:
                    point = state['mountpoint'] or self.base / 'unmounted'
                    images.detach(image, point)
            for image in self.base.glob('*.sparseimage'):
                if images.mounted(image) is not None:
                    raise RuntimeError(f'Image is still attached: {image}')
            # Also reject unexpected mounts under the owned test directory.
            for directory, children, _ in os.walk(self.base, followlinks=False):
                for name in children:
                    path = Path(directory) / name
                    if path.is_mount():
                        raise RuntimeError(f'Unexpected mount: {path}')
            shutil.rmtree(self.base)
        except BaseException as exc:
            raise RuntimeError(f'Test files retained at {self.base}; cleanup stopped: {exc}') from exc

    def assert_original(self, repo):
        path = repo / 'sentinel'
        self.assertEqual(path.read_bytes(), self.original)
        info = path.stat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)),
                         (os.getuid(), os.getgid(), 0o640))
        self.assertEqual(subprocess.check_output([
            '/usr/bin/xattr', '-p', 'com.stallionfs.space', str(path),
        ]).rstrip(b'\n'), b'retained')
        self.assertEqual(os.readlink(repo / 'link'), 'sentinel')

    def test_volume_full_preserves_existing_data_and_other_images(self):
        first, sibling = self.base / 'full.sparseimage', self.base / 'sibling.sparseimage'
        images.clone(self.seed, first)
        images.clone(self.seed, sibling)
        seed_digest, sibling_digest = digest(self.seed), digest(sibling)
        point = self.base / 'full'
        repo = images.attach(first, point)
        self.assert_original(repo)
        # An explicitly durable user write precedes the out-of-space condition.
        fullsync(repo / 'acknowledged', b'present before volume filled')
        filler = repo / 'filler'
        block = random.Random(42).randbytes(1024 * 1024)
        written, saw_full = 0, False
        ceiling = 1200 * 1024 * 1024
        with filler.open('xb', buffering=0) as stream:
            try:
                while written < ceiling:
                    count = stream.write(block[:min(len(block), ceiling - written)])
                    self.assertGreater(count, 0, 'Write returned zero without an error')
                    written += count
                    if written % (16 * len(block)) == 0:
                        os.fsync(stream.fileno())
                os.fsync(stream.fileno())
            except OSError as exc:
                if exc.errno != errno.ENOSPC:
                    raise
                saw_full = True
        self.assertTrue(saw_full, f'No ENOSPC before the bounded {ceiling}-byte ceiling')
        self.assertGreater(written, 0)
        self.assert_original(repo)
        self.assertEqual((repo / 'acknowledged').read_bytes(), b'present before volume filled')
        filler.unlink()
        fullsync(repo / 'recovered', b'write after freeing space')
        images.detach(first, point)
        repo = images.attach(first, point)
        self.assert_original(repo)
        self.assertEqual((repo / 'acknowledged').read_bytes(), b'present before volume filled')
        self.assertEqual((repo / 'recovered').read_bytes(), b'write after freeing space')
        self.assertFalse((repo / 'filler').exists())
        images.detach(first, point)
        # Compare closed bytes before mounting these untouched images for content checks.
        self.assertEqual(digest(self.seed), seed_digest)
        self.assertEqual(digest(sibling), sibling_digest)
        self.assert_original(self.source)
        for image, name in ((sibling, 'sibling'), (self.seed, 'seed')):
            mounted = self.base / name
            untouched = images.attach(image, mounted)
            self.assert_original(untouched)
            for extra in ('acknowledged', 'recovered', 'filler'):
                self.assertFalse((untouched / extra).exists())
            images.detach(image, mounted)
        print(f'\nAPFS ENOSPC after {written} acknowledged bytes; remount and isolation passed', flush=True)


if __name__ == '__main__':
    unittest.main()
