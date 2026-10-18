"""Clone-sharing decoding and adjudication with synthetic records; no native calls."""
from copy import deepcopy
import base64
import ctypes
import errno
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('native_sharing_checks', Path(__file__).parent/'perf/native_correctness.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def payload(*, mask=0x1300, clone_id=42, flags=0x41, references=2):
    return struct.pack('<I5IQQI', 44, 0x80000000, 0, 0, 0, mask, clone_id, flags, references)


def pair():
    source = {'entries': {'file': {'kind': 'file', 'device_inode': [1, 10], 'size': 64,
                'sha256': 'same', 'holes': {'ranges': []},
                'clone_attributes': checks._parse_clone_attributes(payload())}}}
    destination = deepcopy(source)
    destination['entries']['file']['device_inode'] = [1, 11]
    return source, destination


class CloneSharing(unittest.TestCase):
    def test_fixed_packing_returned_masks_and_missing_attributes(self):
        raw = payload(clone_id=0x1122334455667788)
        self.assertEqual(raw[24:32], b'\x88\x77\x66\x55\x44\x33\x22\x11')
        parsed = checks._parse_clone_attributes(raw)
        self.assertTrue(parsed['available'])
        self.assertEqual(parsed['clone_id'], 0x1122334455667788)
        self.assertEqual(parsed['clone_refcount'], 2)
        for bit, name in ((0x100, 'clone_id'), (0x200, 'extended_flags'), (0x1000, 'clone_refcount')):
            parsed = checks._parse_clone_attributes(payload(mask=0x1300 & ~bit))
            self.assertFalse(parsed['available'])
            self.assertIsNone(parsed[name])
        for raw in (b'', payload()[:-1], payload()+b'\0', b'\x28\0\0\0'+payload()[4:],
                    payload(mask=0x5300), payload()[:4]+b'\0'*4+payload()[8:]):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                checks._parse_clone_attributes(raw)

    def test_observation_uses_supplied_fd_and_known_options(self):
        library = mock.Mock()
        def read(fd, pointer, buffer, length, options):
            request = ctypes.cast(pointer, ctypes.POINTER(checks._AttrList)).contents
            self.assertEqual((fd, length, options), (77, 44, 0x28))
            self.assertEqual((request.bitmapcount, request.common, request.fork), (5, 0x80000000, 0x1300))
            ctypes.memmove(buffer, payload(), 44)
            return 0
        library.fgetattrlist.side_effect = read
        with mock.patch.object(checks, '_darwin_metadata_api', return_value=library), \
             mock.patch.object(checks.sys, 'platform', 'darwin'), mock.patch.object(checks.sys, 'byteorder', 'little'):
            self.assertTrue(checks._clone_attributes(77)['available'])
        library.fgetattrlist.assert_called_once()

    def test_unsupported_is_unknown_but_permissions_fail_closed(self):
        library = mock.Mock()
        with mock.patch.object(checks, '_darwin_metadata_api', return_value=library), \
             mock.patch.object(checks.sys, 'platform', 'darwin'), mock.patch.object(checks.sys, 'byteorder', 'little'):
            for code in (errno.ENOTSUP, errno.EINVAL, errno.EACCES):
                def fail(*args):
                    ctypes.set_errno(code)
                    return -1
                library.fgetattrlist.side_effect = fail
                if code == errno.EACCES:
                    with self.assertRaises(PermissionError): checks._clone_attributes(77)
                else:
                    self.assertFalse(checks._clone_attributes(77)['available'])
        with mock.patch.object(checks.sys, 'platform', 'other'), \
             mock.patch.object(checks, '_darwin_metadata_api') as native:
            self.assertFalse(checks._clone_attributes(77)['available'])
            native.assert_not_called()

    def test_positive_uses_file_attributes_without_volume_capability_or_refcount_threshold(self):
        source, destination = pair()
        source['volume_clone_mapping'] = destination['volume_clone_mapping'] = False
        destination['entries']['file']['clone_attributes']['clone_refcount'] = 1
        observed = checks.clone_sharing(source, destination)
        self.assertIs(observed['full_data_stream_sharing'], True)
        self.assertEqual(observed['counts']['shared'], 1)
        self.assertEqual(observed['exceptions'], [])
        self.assertEqual(observed['observations_sha256'], checks.clone_sharing(source, destination)['observations_sha256'])
        compressed = base64.b64decode(observed['observations_gzip_b64'], validate=True)
        raw = gzip.decompress(compressed)
        self.assertEqual(compressed[4:8], b'\0' * 4)
        self.assertEqual(len(raw), observed['observations_bytes'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), observed['observations_sha256'])
        records = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['path'], 'file')
        self.assertEqual(records[0]['source'], source['entries']['file']['clone_attributes'])
        self.assertEqual(records[0]['destination'], destination['entries']['file']['clone_attributes'])
        self.assertEqual(records[0]['source_identity'], [1, 10])

    def test_nonpositive_and_unknown_never_become_positive(self):
        for attributes, expected in ((payload(clone_id=99), False), (payload(flags=1), False),
                                     (payload(clone_id=0), None), (payload(mask=0x300), None)):
            source, destination = pair()
            destination['entries']['file']['clone_attributes'] = checks._parse_clone_attributes(attributes)
            result = checks.clone_sharing(source, destination)
            self.assertIs(result['full_data_stream_sharing'], expected)
            records = gzip.decompress(base64.b64decode(result['observations_gzip_b64'])).splitlines()
            self.assertEqual(json.loads(records[0])['destination']['raw_hex'], attributes.hex())
        source, destination = pair()
        del source['entries']['file']['clone_attributes']
        self.assertIsNone(checks.clone_sharing(source, destination)['full_data_stream_sharing'])

    def test_identity_content_and_path_mismatch_fail_even_with_positive_attributes(self):
        for field, value in (('device_inode', [1, 10]), ('device_inode', [2, 11]),
                             ('size', 63), ('sha256', 'different')):
            source, destination = pair()
            destination['entries']['file'][field] = value
            self.assertIs(checks.clone_sharing(source, destination)['full_data_stream_sharing'], False)
        source, destination = pair()
        destination['entries'].clear()
        self.assertIs(checks.clone_sharing(source, destination)['full_data_stream_sharing'], False)

    def test_empty_holes_only_and_partial_sparse_streams_are_explicit(self):
        for size, holes in ((0, []), (64, [[0, 64]])):
            source, destination = pair()
            for snapshot in (source, destination):
                snapshot['entries']['file'].update(size=size, holes={'ranges': holes}, clone_attributes={'available': False})
            result = checks.clone_sharing(source, destination)
            self.assertIsNone(result['full_data_stream_sharing'])
            self.assertEqual(result['counts']['not_applicable'], 1)
            source['entries']['data'] = pair()[0]['entries']['file']
            destination['entries']['data'] = pair()[1]['entries']['file']
            self.assertIs(checks.clone_sharing(source, destination)['full_data_stream_sharing'], True)
        source, destination = pair()
        for snapshot in (source, destination): snapshot['entries']['file']['holes']['ranges'] = [[0, 32]]
        self.assertIs(checks.clone_sharing(source, destination)['full_data_stream_sharing'], True)
        self.assertIsNone(checks.clone_sharing({'entries': {}}, {'entries': {}})['full_data_stream_sharing'])


if __name__ == '__main__': unittest.main()
