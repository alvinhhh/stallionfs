"""Sparse restoration on independent, disposable ditto operands."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PERF = Path(__file__).parent / 'perf'
with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
    spec = importlib.util.spec_from_file_location('sparse_setup_suite', PERF / 'native_suite.py')
    suite = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(suite)


@unittest.skipUnless(sys.platform == 'darwin', 'Darwin ditto operand preparation')
class SparseOperandSetup(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sparse-operand-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'; self.source.mkdir()
        suite.native_fixtures.enrich_metadata(self.source, receipt={})
        self.expected = suite.native_correctness.snapshot(self.source)
        self.target = self.root / 'target'
        subprocess.run(['/usr/bin/ditto', '--rsrc', '--extattr', '--acl',
                        str(self.source), str(self.target)], check=True, capture_output=True)
        self.data = self.target / 'metadata-fixture/sparse'

    def test_ditto_operand_keeps_sparse_holes_and_hardlinks(self):
        before = suite.native_correctness.verify_clone(
            self.expected, suite.native_correctness.snapshot(self.target))
        self.assertTrue(before['strict_equal'])
        self.assertFalse(before['sparse_preserved'])
        timestamp = self.data.stat()
        repair = getattr(suite, 'restore_setup_sparse_holes', lambda *_: [])
        repairs = repair(self.target, self.expected)
        self.assertTrue(suite.preserved(suite.native_correctness.verify_clone(
            self.expected, suite.native_correctness.snapshot(self.target))))
        self.assertEqual(len(repairs), 1)
        self.assertEqual(self.data.stat().st_mtime_ns, timestamp.st_mtime_ns)
        self.assertTrue(os.path.samefile(self.data, self.target / 'metadata-fixture/subdir/alias'))
        self.assertEqual(repair(self.target, self.expected), [])
        self.assertTrue(suite.native_correctness.verify_source(
            self.expected, suite.native_correctness.snapshot(self.source))['unchanged'])

    def test_corrupt_data_is_not_repaired(self):
        with self.data.open('r+b') as stream:
            stream.seek(2 * 1024 * 1024); stream.write(b'bad')
        with self.assertRaisesRegex(RuntimeError, 'content'):
            suite.restore_setup_sparse_holes(self.target, self.expected)
        with self.data.open('rb') as stream:
            stream.seek(2 * 1024 * 1024); self.assertEqual(stream.read(3), b'bad')

    def test_source_alias_is_rejected(self):
        self.data.unlink()
        os.link(self.source / 'metadata-fixture/sparse', self.data)
        with self.assertRaisesRegex(RuntimeError, 'aliases a source inode'):
            suite.restore_setup_sparse_holes(self.target, self.expected)

    def test_punch_failure_restores_timestamps_and_fails_closed(self):
        before = self.data.stat()
        with mock.patch.object(suite.fcntl, 'fcntl', side_effect=OSError('punch failed')):
            with self.assertRaisesRegex(OSError, 'punch failed'):
                suite.restore_setup_sparse_holes(self.target, self.expected)
        self.assertEqual(self.data.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(self.data.stat().st_atime_ns, before.st_atime_ns)

    def test_no_sparse_entries_need_no_repairs(self):
        self.assertEqual(suite.restore_setup_sparse_holes(self.target, {'entries': {}}), [])
