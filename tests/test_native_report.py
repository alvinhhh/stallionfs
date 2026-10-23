"""Journal durability ordering, revisions and bounded report serialization."""
from array import array
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

PERF = Path(__file__).parent / 'perf'
with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
    spec = importlib.util.spec_from_file_location('native_report_under_test', PERF / 'native_report.py')
    journal = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(journal)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / 'result.json'

    def writer(self):
        value = journal.ReportJournal(self.output)
        self.addCleanup(value.close)
        return value

    def reader(self):
        value = journal.ReportJournal.open_existing(self.output)
        self.addCleanup(value.close)
        return value

    def test_revisions_stream_to_same_schema_with_separate_lists(self):
        writer = self.writer()
        state = {'schema': 1, 'complete': False, 'selection': {'fixture': 'tiny'}}
        expected = dict(state)
        for kind in journal.KINDS:
            initial = {'kind': kind, 'validated': False, 'path': 'name\udcff'}
            writer.append(kind, 0, initial)
            writer.checkpoint(state)
            initial['validated'] = True
            writer.append(kind, 0, initial)
            expected[kind] = [dict(initial)]
        expected['complete'] = True
        writer.finish({**state, 'complete': True})
        self.assertEqual(json.loads(self.output.read_text()), expected)
        reader = self.reader()
        self.assertEqual(reader.state, {**state, 'complete': True})
        for kind in journal.KINDS:
            self.assertEqual(list(reader.iter_latest(kind)), expected[kind])
        lines = writer.journal_path.read_bytes().splitlines()
        self.assertEqual(len(lines), 2 * len(journal.KINDS))
        self.assertFalse(json.loads(lines[0])['payload']['validated'])
        with self.assertRaises(ValueError): writer.append('rows', 1, {})
        with self.assertRaises(ValueError): reader.checkpoint({})

    def test_exclusive_creation_preserves_existing_artifacts(self):
        for suffix in ('', '.journal', '.manifest'):
            with self.subTest(suffix=suffix):
                path = Path(str(self.output) + suffix)
                path.write_bytes(b'owned elsewhere')
                with self.assertRaises(ValueError): journal.ReportJournal(self.output)
                self.assertEqual(path.read_bytes(), b'owned elsewhere')
                path.unlink()
        target = self.output.parent / 'target'
        target.write_bytes(b'data')
        Path(str(self.output) + '.journal').symlink_to(target)
        with self.assertRaises(ValueError): journal.ReportJournal(self.output)
        self.assertEqual(target.read_bytes(), b'data')

    def test_finish_does_not_replace_new_output(self):
        writer = self.writer()
        writer.append('rows', 0, {'validated': True})
        self.output.write_bytes(b'not our output')
        with self.assertRaises(FileExistsError): writer.finish({'schema': 1})
        self.assertEqual(self.output.read_bytes(), b'not our output')
        self.assertEqual(list(self.reader().iter_latest('rows')), [{'validated': True}])
        self.assertEqual(list(self.output.parent.glob('.native-report-*')), [])

    def test_journal_fsynced_before_atomic_manifest(self):
        writer = self.writer()
        events = []
        real_fsync = os.fsync
        real_write = journal.fileops.write_json
        writer.append('rows', 0, {'validated': False})
        def fsync(fd):
            if fd == writer._stream.fileno(): events.append('journal fsync')
            return real_fsync(fd)
        def write(path, value, previous):
            self.assertEqual(events, ['journal fsync'])
            self.assertEqual(hashlib.sha256(writer.journal_path.read_bytes()).hexdigest(), value['prefix_sha256'])
            events.append('manifest')
            return real_write(path, value, previous)
        with mock.patch.object(journal.os, 'fsync', side_effect=fsync), mock.patch.object(journal.fileops, 'write_json', side_effect=write):
            writer.checkpoint({'schema': 1})
        self.assertEqual(events, ['journal fsync', 'manifest'])

    def test_manifest_failure_retains_raw_tail_and_previous_commit(self):
        writer = self.writer()
        before = writer.manifest_path.read_bytes()
        writer.append('rows', 0, {'exit_code': 0, 'validated': False})
        with mock.patch.object(journal.fileops, 'write_json', side_effect=OSError('disk full')):
            with self.assertRaises(OSError): writer.checkpoint({'schema': 1})
        self.assertEqual(writer.manifest_path.read_bytes(), before)
        self.assertIn(b'"validated":false', writer.journal_path.read_bytes())
        with self.assertRaisesRegex(ValueError, 'uncommitted tail'): self.reader()
        with self.assertRaises(ValueError): writer.append('rows', 1, {})
        self.assertFalse(self.output.exists())

    def test_fsync_failure_never_advances_manifest(self):
        writer = self.writer()
        before = writer.manifest_path.read_bytes()
        writer.append('rows', 0, {'validated': False})
        with mock.patch.object(journal.os, 'fsync', side_effect=OSError('sync failed')), mock.patch.object(journal.fileops, 'write_json') as publish:
            with self.assertRaises(OSError): writer.checkpoint({})
        publish.assert_not_called()
        self.assertEqual(writer.manifest_path.read_bytes(), before)
        self.assertTrue(writer.journal_path.stat().st_size)

    def test_manifest_exact_limit_and_one_byte_over_preserve_previous_commit(self):
        writer = self.writer()
        writer.append('rows', 0, {'validated': True})
        writer.checkpoint({'schema': 1})
        state = {'schema': 1, 'label': '\u00e9' * 20}
        expected = dict(writer._manifest, state=state)
        boundary = len((json.dumps(expected, indent=2, sort_keys=True) + '\n').encode('utf-8'))
        with mock.patch.object(journal, 'MAX_MANIFEST_BYTES', boundary):
            writer.checkpoint(state)
            before = writer.manifest_path.read_bytes()
            self.assertEqual(len(before), boundary)
            with mock.patch.object(journal.fileops, 'write_json') as publish:
                with self.assertRaisesRegex(ValueError, 'Oversized journal manifest'):
                    writer.checkpoint({**state, 'label': state['label'] + 'x'})
            publish.assert_not_called()
            self.assertEqual(writer.manifest_path.read_bytes(), before)
            reader = self.reader()
            self.assertEqual(reader.state, state)
            self.assertEqual(list(reader.iter_latest('rows')), [{'validated': True}])
            with self.assertRaises(ValueError): writer.append('rows', 1, {})

    def test_torn_extra_and_same_length_corrupt_prefix_rejected(self):
        writer = self.writer()
        writer.append('rows', 0, {'validated': False})
        writer.checkpoint({'schema': 1})
        writer.close()
        raw = writer.journal_path.read_bytes()
        for broken in (raw[:-1], raw + b'{', raw.replace(b'false', b'true ')):
            with self.subTest(length=len(broken)):
                writer.journal_path.write_bytes(broken)
                with self.assertRaises(ValueError): self.reader()
                self.assertEqual(writer.journal_path.read_bytes(), broken)
        writer.journal_path.write_bytes(raw)
        self.assertEqual(list(self.reader().iter_latest('rows')), [{'validated': False}])

    def test_replaced_journal_or_manifest_is_not_modified(self):
        writer = self.writer()
        for path in (writer.journal_path, writer.manifest_path):
            with self.subTest(path=path.name):
                saved = path.with_name(path.name + '.saved')
                path.rename(saved)
                path.write_bytes(b'replacement')
                with self.assertRaisesRegex(ValueError, 'path changed'): writer.append('rows', 0, {})
                self.assertEqual(path.read_bytes(), b'replacement')
                path.unlink()
                saved.rename(path)

    def test_provenance_matches_exact_manifest_bytes_and_prefix(self):
        writer = self.writer()
        writer.append('rows', 0, {'validated': False})
        writer.checkpoint({'schema': 1})
        writer.append('rows', 0, {'validated': True})
        writer.checkpoint({'schema': 1, 'complete': True})
        raw_manifest = writer.manifest_path.read_bytes()
        raw_journal = writer.journal_path.read_bytes()
        expected = {'original_manifest_sha256': hashlib.sha256(raw_manifest).hexdigest(),
                    'committed_prefix_sha256': hashlib.sha256(raw_journal).hexdigest(),
                    'committed_bytes': len(raw_journal), 'event_count': 2}
        writer.verify()
        self.assertEqual(writer.provenance, expected)
        reader = self.reader()
        reader.verify()
        self.assertEqual(reader.provenance, expected)
        copy = reader.provenance
        copy['event_count'] = 99
        self.assertEqual(reader.provenance, expected)

    def test_verify_detects_same_inode_manifest_mutation(self):
        writer = self.writer()
        writer.append('rows', 0, {'validated': True})
        writer.checkpoint({'schema': 1, 'complete': False})
        reader = self.reader()
        original = writer.manifest_path.read_bytes()
        inode = writer.manifest_path.stat().st_ino
        changed = original.replace(b'false', b'true ')
        self.assertNotEqual(original, changed)
        writer.manifest_path.write_bytes(changed)
        self.assertEqual(writer.manifest_path.stat().st_ino, inode)
        for instance in (writer, reader):
            with self.assertRaisesRegex(ValueError, 'Manifest content changed'):
                instance.verify()
            with self.assertRaisesRegex(ValueError, 'Manifest content changed'):
                list(instance.iter_latest('rows'))
        self.assertEqual(writer.manifest_path.read_bytes(), changed)

    def test_schema_sequence_and_noncontiguous_ids_fail_closed(self):
        writer = self.writer()
        writer.append('rows', 0, {})
        writer.checkpoint({})
        writer.close()
        manifest = json.loads(writer.manifest_path.read_text())
        valid = json.loads(writer.journal_path.read_text())
        malformed = [dict(valid, sequence=1), dict(valid, id=1), dict(valid, id=True), dict(valid, kind='extra'), dict(valid, payload=[]), dict(valid, extra=True)]
        for event in malformed:
            with self.subTest(event=event):
                raw = json.dumps(event).encode() + b'\n'
                writer.journal_path.write_bytes(raw)
                writer.manifest_path.write_text(json.dumps(dict(manifest, committed_bytes=len(raw), prefix_sha256=hashlib.sha256(raw).hexdigest())))
                with self.assertRaises(ValueError): self.reader()

    def test_validation_rejects_array_state_and_invalid_ids(self):
        writer = self.writer()
        for kind, id, payload in [('unknown', 0, {}), ('rows', True, {}), ('rows', -1, {}), ('rows', 1, {}), ('rows', 0, [])]:
            with self.assertRaises(ValueError): writer.append(kind, id, payload)
        for state in ([], {'rows': []}, {'metadata_preparation': []}):
            with self.assertRaises(ValueError): writer.checkpoint(state)
        writer.append('rows', 0, {})
        writer.checkpoint({'schema': 1})
        self.assertEqual(list(writer.iter_latest('rows')), [{}])

    def test_partial_serialization_retained_and_poisoned(self):
        writer = self.writer()
        before = writer.manifest_path.read_bytes()
        with self.assertRaises(ValueError): writer.append('rows', 0, {'value': float('nan')})
        writer._stream.flush()
        self.assertGreater(writer.journal_path.stat().st_size, 0)
        self.assertEqual(writer.manifest_path.read_bytes(), before)
        with self.assertRaises(ValueError): writer.checkpoint({})
        with self.assertRaises(ValueError): self.reader()

    def test_state_and_payload_not_retained_and_journal_grows_linearly(self):
        writer = self.writer()
        state = {'schema': 1, 'selection': {'samples': 10}}
        payload = {'value': 'x' * 2048, 'validated': False}
        writer.append('rows', 0, payload)
        writer.checkpoint(state)
        payload['value'] = 'mutated'
        state['selection']['samples'] = 999
        self.assertEqual(writer.state['selection']['samples'], 10)
        self.assertEqual(list(writer.iter_latest('rows'))[0]['value'], 'x' * 2048)
        for id in range(1, 100):
            writer.append('rows', id, {'value': 'x' * 2048, 'validated': False})
            writer.checkpoint({'schema': 1})
        size100 = writer.journal_path.stat().st_size
        for id in range(100, 200):
            writer.append('rows', id, {'value': 'x' * 2048, 'validated': False})
            writer.checkpoint({'schema': 1})
        self.assertLess(writer.journal_path.stat().st_size, size100 * 2.02)
        self.assertLess(writer.manifest_path.stat().st_size, 512)
        self.assertIsInstance(writer._offsets['rows'], array)
        self.assertEqual(writer._offsets['rows'].itemsize, 8)
        self.assertEqual(len(writer._offsets['rows']), 200)
        self.assertNotIn('x' * 2048, repr(vars(writer)))
        self.assertEqual(len(list(self.reader().iter_latest('rows'))), 200)

    def test_finish_streams_each_payload_without_whole_report_encoding(self):
        writer = self.writer()
        for id in range(3): writer.append('rows', id, {'id': id, 'value': 'x' * 4096})
        original = journal.ENCODER.iterencode
        def bounded(value, *args, **kwargs):
            if isinstance(value, dict):
                self.assertFalse(set(value).intersection(journal.KINDS))
            self.assertNotIsInstance(value, list)
            return original(value, *args, **kwargs)
        with mock.patch.object(journal.ENCODER, 'iterencode', side_effect=bounded):
            writer.finish({'schema': 1})
        self.assertEqual(len(json.loads(self.output.read_text())['rows']), 3)


if __name__ == '__main__':
    unittest.main()
