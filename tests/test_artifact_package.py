"""Unsigned artifact archive boundaries; no native compilation or execution."""
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import build_fskit_artifact as artifact


class ArtifactPackage(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.payload = self.root / 'payload'
        self.payload.mkdir()
        self.names = [*artifact.APP_FILES, 'matching.whl', 'mount-witness', 'LICENSE', 'provenance.json']
        for name in self.names:
            path = self.payload / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('public fixture: ' + name).encode())

    def test_round_trip_inventory_bytes_and_executable_modes(self):
        output = self.root / 'artifact.tar.gz'
        expected = artifact.payload_files(self.payload, self.names)
        result = artifact.archive_payload(self.payload, self.names, output)
        self.assertEqual(result, artifact.digest(output.read_bytes()))
        with tarfile.open(output) as archive:
            self.assertEqual({member.name for member in archive}, set(self.names))
            for name in self.names:
                member = archive.getmember(name)
                self.assertTrue(member.isfile())
                self.assertEqual(archive.extractfile(member).read(), expected[name])
                self.assertEqual(member.mode, 0o755 if name == 'mount-witness' or '/MacOS/' in name else 0o644)
        with self.assertRaises(FileExistsError):
            artifact.archive_payload(self.payload, self.names, output)

    def test_missing_extra_symlink_and_hardlink_members_refuse_before_archive(self):
        for change in ('missing', 'extra', 'symlink-file', 'symlink-directory', 'hardlink'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'file').write_bytes(b'allowlisted')
                if change == 'missing': (root / 'file').unlink()
                elif change == 'extra': (root / 'private-receipt.json').write_bytes(b'private')
                elif change == 'symlink-file':
                    (root / 'file').unlink()
                    (root / 'file').symlink_to(self.payload / 'provenance.json')
                elif change == 'symlink-directory': (root / 'private').symlink_to(self.payload, target_is_directory=True)
                else: os.link(root / 'file', root / 'second')
                output = self.root / (change + '.tar.gz')
                with self.assertRaises(ValueError): artifact.archive_payload(root, ['file'], output)
                self.assertFalse(output.exists())

    def test_oversized_member_refuses_before_payload_read(self):
        root = self.root / 'bounded'
        root.mkdir()
        (root / 'file').write_bytes(b'two bytes exceed the one byte cap')
        with patch.object(artifact, 'MAX_ARCHIVE_BYTES', 1), patch.object(artifact.os, 'fdopen') as read:
            with self.assertRaisesRegex(ValueError, 'byte limit'):
                artifact.archive_payload(root, ['file'], self.root / 'oversized.tar.gz')
            read.assert_not_called()
        self.assertFalse((self.root / 'oversized.tar.gz').exists())

    def test_reopened_archive_rejects_duplicate_links_and_changed_bytes(self):
        expected = {'file': b'exact public bytes'}
        for change in ('duplicate', 'link', 'bytes', 'extra'):
            output = self.root / (change + '.tar.gz')
            with tarfile.open(output, 'w:gz') as archive:
                entry = tarfile.TarInfo('file')
                data = b'changed' if change == 'bytes' else expected['file']
                entry.size = len(data)
                if change == 'link':
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = '/private/runtime'
                    entry.size = 0
                archive.addfile(entry, io.BytesIO(data))
                if change in ('duplicate', 'extra'):
                    entry = tarfile.TarInfo('file' if change == 'duplicate' else 'unlisted')
                    archive.addfile(entry, io.BytesIO())
            with self.subTest(change=change), self.assertRaises(ValueError):
                artifact.verify_archive(output, expected)


class WheelAdmission(unittest.TestCase):
    def test_filename_selection_retains_prior_product_names_without_relabelling(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / 'stallionfs-0.6.3-cp313-cp313-macosx_15_0_arm64.whl'
            wheel.write_bytes(b'inert historical name; payload admission is separate')
            self.assertEqual(artifact.select_wheel(wheel.parent), wheel)

    def test_requires_exactly_one_cp313_macos15_arm64_wheel(self):
        expected = 'stallionfs-0.7.0-cp313-cp313-macosx_15_0_arm64.whl'
        for names in ([], [expected, 'extra.whl'],
                      ['stallionfs-0.7.0-cp313-cp313-macosx_15_0_universal2.whl'],
                      ['stallionfs-0.7.0-cp312-cp312-macosx_15_0_arm64.whl'],
                      ['stallionfs-0.7.0-cp313-cp313-macosx_27_0_arm64.whl']):
            with self.subTest(names=names), tempfile.TemporaryDirectory(prefix='private-wheel-dir-') as directory:
                root = Path(directory)
                for name in names: (root / name).write_bytes(b'inert wheel')
                with self.assertRaises(ValueError) as refused: artifact.select_wheel(root)
                message = str(refused.exception)
                self.assertNotIn(directory, message)
                self.assertIn('"wheel_count": ' + str(len(names)), message)
                for name in names: self.assertIn(name, message)
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / expected
            wheel.write_bytes(b'inert selected wheel; full validation remains mandatory')
            self.assertEqual(artifact.select_wheel(wheel.parent), wheel)

    def test_refusal_diagnostics_bound_count_names_and_name_length(self):
        with tempfile.TemporaryDirectory(prefix='private-wheel-dir-') as directory:
            root = Path(directory)
            for index in range(12): (root / (str(index) + '-' + 'x' * 180 + '.whl')).touch()
            with self.assertRaises(ValueError) as refused: artifact.select_wheel(root)
            message = str(refused.exception)
            self.assertNotIn(directory, message)
            self.assertLess(len(message), 1600)
            self.assertIn('"wheel_count": 12', message)
            self.assertIn('"names_truncated": true', message)

    def test_explicit_platform_tag_requires_matching_native_deployment(self):
        artifact.validate_wheel_targets([{'target': {'minimum_os': version}} for version in ('11.0', '15', '15.0.0')])
        for version in ('15.1', '26.0', '27.0'):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, 'exceeds'):
                artifact.validate_wheel_targets([{'target': {'minimum_os': '15.0'}}, {'target': {'minimum_os': version}}])


if __name__ == '__main__':
    unittest.main()
