import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
import zlib
from unittest import mock

spec = importlib.util.spec_from_file_location('native_fixtures', Path(__file__).parent/'perf/native_fixtures.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class NativeFixtures(unittest.TestCase):
    def test_png_containers_pixels_sidecars_and_exclusive_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = fixtures.photo_library(Path(directory)/'images', files=3, width=8, height=6)
            paths = sorted(root.rglob('*.png'))
            self.assertEqual(len(paths), 3)
            data_hashes = set()
            decoded_pixels = set()
            for index, path in enumerate(paths):
                data = path.read_bytes(); data_hashes.add(data)
                self.assertEqual(data[:8], b'\x89PNG\r\n\x1a\n')
                position = 8; chunks = []
                while position < len(data):
                    length, = struct.unpack('>I', data[position:position+4])
                    kind = data[position+4:position+8]
                    payload = data[position+8:position+8+length]
                    crc, = struct.unpack('>I', data[position+8+length:position+12+length])
                    self.assertEqual(crc, zlib.crc32(kind+payload))
                    chunks.append((kind, payload)); position += length+12
                self.assertEqual([k for k, _ in chunks], [b'IHDR', b'tEXt', b'IDAT', b'IEND'])
                self.assertEqual(struct.unpack('>IIBBBBB', chunks[0][1]), (8, 6, 8, 2, 0, 0, 0))
                raw = zlib.decompress(chunks[2][1])
                decoded_pixels.add(raw)
                self.assertEqual(len(raw), 6*(1+8*3))
                self.assertTrue(all(raw[row*25] == 0 for row in range(6)))
                self.assertEqual(json.loads(path.with_suffix('.json').read_text())['id'], index)
            self.assertEqual(len(data_hashes), 3)
            self.assertEqual(len(decoded_pixels), 3)
            repeat = fixtures.photo_library(Path(directory)/'repeat', files=3, width=8, height=6)
            expected = {path.relative_to(root): path.read_bytes() for path in root.rglob('*') if path.is_file()}
            actual = {path.relative_to(repeat): path.read_bytes() for path in repeat.rglob('*') if path.is_file()}
            self.assertEqual(actual, expected)
            with self.assertRaises(FileExistsError): fixtures.photo_library(root, files=1, width=1, height=1)

    def test_deep_tree_distribution_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = fixtures.deep_tree(Path(directory)/'deep', files=12, depth=4)
            paths = list(root.rglob('file-*'))
            self.assertEqual(len(paths), 12)
            self.assertEqual(sorted(len(p.relative_to(root).parts) for p in paths), [2]*3+[3]*3+[4]*3+[5]*3)
            self.assertTrue((root/'dangling-link').is_symlink())
            self.assertEqual((root/'d/d/d/d/relative-link').read_bytes(), (root/'d/d/d/d/file-000011').read_bytes())
            self.assertTrue(all(len(p.read_bytes()) == 512 for p in paths))

    def test_shared_scan_layouts_keep_counts_links_sparse_file_and_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            for layout in ('flat', 'nested', 'deep40'):
                root = Path(directory) / layout
                expected = fixtures.scan_fixture(root, 103, layout)
                observed = dict(files=0, directories=0, symlinks=0, other=0, logical_bytes=0, skipped_mounts=0)
                for path in root.rglob('*'):
                    info = path.lstat()
                    if stat.S_ISREG(info.st_mode):
                        observed['files'] += 1; observed['logical_bytes'] += info.st_size
                    elif stat.S_ISDIR(info.st_mode): observed['directories'] += 1
                    elif stat.S_ISLNK(info.st_mode): observed['symlinks'] += 1
                    else: observed['other'] += 1
                self.assertEqual(observed, expected)
                extras = root.joinpath(*(['d'] * 40)) if layout == 'deep40' else root
                self.assertTrue(stat.S_ISFIFO((extras / 'pipe').lstat().st_mode))
                self.assertEqual((extras / 'sparse').stat().st_ino, (extras / 'hard-link').stat().st_ino)
                self.assertEqual((extras / 'space and \n café 🐎').read_bytes(), b'hello')
                self.assertEqual(os.readlink(extras / 'outside-link'), '/')


class LinuxMetadataCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import sys
        sys.path.insert(0, str(Path(__file__).parent/'perf'))

    def test_linux_preparation_keeps_payload_layout_and_uses_posix_acl_and_hole_punch(self):
        import ctypes
        import fcntl
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'tree'; root.mkdir()
            libc = mock.Mock(); libc.fallocate.return_value = 0
            with mock.patch.object(fixtures.sys, 'platform', 'linux'), \
                 mock.patch.object(ctypes, 'CDLL', return_value=libc), \
                 mock.patch.object(fcntl, 'fcntl') as darwin_punch, \
                 mock.patch.object(os, 'setxattr', create=True) as xattr:
                receipt = fixtures.enrich_metadata(root, receipt={})
            data = root/receipt['path']
            self.assertEqual(data.stat().st_size, 8*1024*1024)
            with data.open('rb') as stream:
                self.assertEqual(stream.read(1), b'x')
                stream.seek(-1, 2); self.assertEqual(stream.read(1), b'y')
            self.assertEqual((root/'metadata-fixture/subdir/alias').stat().st_ino, data.stat().st_ino)
            self.assertEqual(receipt['sparse']['interior'], [1024*1024, 7*1024*1024])
            self.assertIsNone(receipt['resource_fork_bytes'])
            darwin_punch.assert_not_called()
            self.assertEqual(libc.fallocate.call_args.args[1:], (3, 1024*1024, 6*1024*1024))
            self.assertEqual([call.args[1] for call in xattr.call_args_list],
                             [b'user.stallionfs-test', b'system.posix_acl_access'])
            acl = bytes.fromhex(receipt['posix_acl_access_hex'])
            self.assertEqual(struct.unpack_from('<I', acl)[0], 2)
            self.assertEqual([struct.unpack_from('<HHI', acl, offset)[0] for offset in range(4, len(acl), 8)],
                             [1, 2, 4, 16, 32])

    def test_linux_coverage_requires_acl_xattr_links_observed_hole_and_allocation(self):
        import copy
        import hashlib
        size = 8*1024*1024
        receipt = {'platform': 'linux', 'path': 'sparse', 'data_size': size,
                   'posix_acl_access_hex': '0200000002000400feff0000', 'hardlinks': ['alias', 'sparse'],
                   'sparse': {'size': size, 'interior': [1024*1024, 7*1024*1024], 'endpoints': True}}
        entry = {'kind': 'file', 'size': size, 'device_inode': [1, 2], 'allocated_bytes': 8192,
                 'acl': {'access_hex': receipt['posix_acl_access_hex'], 'unavailable': None},
                 'xattrs': {b'user.stallionfs-test'.hex(): fixtures.METADATA_XATTRS[b'user.stallionfs-test'].hex()},
                 'holes': {'ranges': [[4096, size-4096]], 'unavailable': None},
                 'sha256': hashlib.sha256(b'x' + bytes(size-2) + b'y').hexdigest()}
        observed = {'entries': {'sparse': entry, 'alias': copy.deepcopy(entry)}, 'unavailable_fields': [],
                    'metadata_capabilities': {'platform': 'linux'}, 'hardlink_groups': [['alias', 'sparse']]}
        self.assertTrue(fixtures.verify_metadata_coverage(observed, receipt)['populated'])
        for defect in ('acl', 'xattr', 'links', 'inode', 'holes', 'unknown_holes', 'allocation', 'payload', 'unavailable'):
            changed = copy.deepcopy(observed); row = changed['entries']['sparse']
            if defect == 'acl': row['acl']['access_hex'] = None
            elif defect == 'xattr': row['xattrs'] = {}
            elif defect == 'links': changed['hardlink_groups'] = []
            elif defect == 'inode': row['device_inode'] = [2, 3]
            elif defect == 'holes': row['holes']['ranges'] = []
            elif defect == 'unknown_holes': row['holes']['ranges'] = None
            elif defect == 'allocation': row['allocated_bytes'] = size
            elif defect == 'payload': row['sha256'] = '0'*64
            elif defect == 'unavailable': changed['unavailable_fields'] = ['acl']
            with self.subTest(defect=defect), self.assertRaises(RuntimeError):
                fixtures.verify_metadata_coverage(changed, receipt)


class MetadataCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import sys
        if sys.platform != 'darwin': raise unittest.SkipTest('Darwin metadata fixture')
        sys.path.insert(0, str(Path(__file__).parent/'perf'))
        import native_correctness
        cls.checks = native_correctness

    def test_single_file_preserves_data_fork_and_has_populated_metadata(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'single'
            payload = bytes(range(256))*16
            root.write_bytes(payload)
            receipt = fixtures.enrich_metadata(root, receipt={})
            observed = self.checks.snapshot(root)
            coverage = fixtures.verify_metadata_coverage(observed, receipt)
            self.assertTrue(coverage['populated'])
            self.assertGreater(coverage['seeded_acl_text_bytes'], 0)
            self.assertEqual(coverage['regular_files'], 1)
            self.assertEqual(coverage['logical_bytes'], 4096)
            self.assertEqual(root.read_bytes(), payload)
            self.assertEqual(observed['entries']['']['sha256'], hashlib.sha256(payload).hexdigest())
            self.assertEqual(receipt['added_regular_entries'], 0)
            self.assertEqual(receipt['added_logical_bytes'], 0)
            self.assertIsNone(receipt['hardlinks'])
            self.assertIsNone(receipt['sparse'])

    def test_directory_enrichment_and_each_missing_feature_fails(self):
        import copy
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'tree'; root.mkdir()
            (root/'original').write_bytes(b'unchanged')
            receipt = fixtures.enrich_metadata(root, receipt={})
            observed = self.checks.snapshot(root)
            self.assertTrue(fixtures.verify_metadata_coverage(observed, receipt))
            self.assertEqual((root/'original').read_bytes(), b'unchanged')
            self.assertEqual(receipt['added_regular_entries'], 2)
            self.assertEqual(receipt['added_directories'], 2)
            self.assertEqual(receipt['added_logical_bytes'], 16*1024*1024)
            self.assertEqual(receipt['added_xattr_value_bytes'], sum(map(len, fixtures.METADATA_XATTRS.values())))
            for defect in ('acl_empty', 'acl_header_only', 'acl_unavailable', 'fork', 'xattr',
                           'links', 'inode', 'holes_empty', 'holes_unknown', 'allocated', 'payload'):
                with self.subTest(defect=defect):
                    changed = copy.deepcopy(observed)
                    entry = changed['entries'][receipt['path']]
                    if defect == 'acl_empty': entry['acl']['text_hex'] = ''
                    elif defect == 'acl_header_only': entry['acl']['text_hex'] = b'!#acl 1\n'.hex()
                    elif defect == 'acl_unavailable': entry['acl']['unavailable'] = 'denied'
                    elif defect == 'fork': entry['xattrs'].pop(b'com.apple.ResourceFork'.hex())
                    elif defect == 'xattr': entry['xattrs'].pop(b'user.stallionfs-test'.hex())
                    elif defect == 'links': changed['hardlink_groups'] = []
                    elif defect == 'inode': entry['device_inode'] = [-1, -1]
                    elif defect == 'holes_empty': entry['holes']['ranges'] = []
                    elif defect == 'holes_unknown': entry['holes']['ranges'] = None
                    elif defect == 'allocated': entry['allocated_bytes'] = entry['size']
                    elif defect == 'payload': entry['sha256'] = '0'*64
                    with self.assertRaises(RuntimeError): fixtures.verify_metadata_coverage(changed, receipt)

    def test_scan_enrichment_preserves_entries_sizes_and_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            for layout in ('flat', 'nested', 'deep40'):
                with self.subTest(layout=layout):
                    root = Path(directory)/layout
                    expected = fixtures.scan_fixture(root, 103, layout)
                    before = self.checks.snapshot(root, allow_special=True)
                    receipt = fixtures.enrich_metadata(root, receipt={}, scan_layout=layout)
                    after = self.checks.snapshot(root, allow_special=True)
                    coverage = fixtures.verify_metadata_coverage(after, receipt)
                    self.assertTrue(coverage['populated'])
                    self.assertEqual(coverage['regular_files'], expected['files'])
                    self.assertEqual(coverage['directories'], expected['directories'] + 1)
                    self.assertEqual(coverage['symlinks'], expected['symlinks'])
                    self.assertEqual(coverage['special_entries'], expected['other'])
                    projection = lambda snap: {path: (row['kind'], row.get('size'), row['device_inode'])
                                               for path, row in snap['entries'].items()}
                    self.assertEqual(projection(before), projection(after))
                    self.assertEqual(receipt['added_directories'], 0)
                    self.assertEqual(receipt['added_regular_entries'], 0)
                    self.assertEqual(sum(row.get('size', 0) for row in after['entries'].values()), expected['logical_bytes'])

    def test_failed_or_interrupted_acl_setup_keeps_partial_receipt(self):
        import fileops
        import subprocess
        from unittest import mock
        for failure in ('exit', 'timeout'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)/'single'
                root.write_bytes(b'keep data')
                receipt = {}
                result = subprocess.CompletedProcess([], 1, b'', b'ACL denied')
                with mock.patch.object(fixtures.os, 'setxattr', return_value=None, create=True), \
                     mock.patch.object(fileops, 'command', return_value=result,
                                       side_effect=subprocess.TimeoutExpired('chmod', 120) if failure == 'timeout' else None):
                    with self.assertRaises(subprocess.TimeoutExpired if failure == 'timeout' else RuntimeError):
                        fixtures.enrich_metadata(root, receipt=receipt)
                self.assertEqual(receipt['path'], '')
                self.assertEqual(receipt['data_size'], len(b'keep data'))
                self.assertEqual(receipt['acl_command']['argv'], ['/bin/chmod', '+a', 'everyone allow read', str(root)])
                self.assertEqual(receipt['acl_command']['exit_code'], None if failure == 'timeout' else 1)
                if failure == 'exit': self.assertEqual(receipt['acl_command']['stderr'], 'ACL denied')
                self.assertEqual(root.read_bytes(), b'keep data')


if __name__ == '__main__': unittest.main()
