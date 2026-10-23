"""Generated-report export policy, exact path boundaries and exclusive output."""
import base64
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import struct
import tempfile
import unittest
import weakref
from unittest import mock

PERF = Path(__file__).parent / 'perf'
with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
    spec = importlib.util.spec_from_file_location('export_native_under_test', PERF / 'export_native.py')
    exporter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exporter)


def report():
    raw = b'failed /Users/example/work/item: permission\n\xff\x00'
    return {'schema': 1, 'source_sha256': {'native_suite.py': 'a' * 64},
            'selection': {'fixtures': ['tiny_4kib'], 'binary': '/Users/example/bin/stallionfs',
                          'scratch': '/Users/example/scratch', 'output': '/Users/example/result.json'},
            'rows': [{'fixture': 'tiny_4kib', 'argv': ['/Users/example/bin/stallionfs', 'clone', '/Users/example/work/item'],
                      'cwd': '/Users/example/work', 'wall_s': 0.012, 'cpu_s': 0.0,
                      'rss_bytes': 1024, 'validated': False, 'exit_code': 1,
                      'correctness': {'candidate_losses': [{'path': 'item', 'field': 'mode', 'expected': 420, 'actual': 384}]},
                      'error': "copy '/Users/example/work/item' failed",
                      'stdout': '/Users/example/work/item',
                      'stdout_b64': base64.b64encode(raw).decode(), 'stderr_b64': '',
                      'partial_stderr_b64': base64.b64encode(b'/Users/example/work/partial').decode()}],
            'executables': {'/Users/example/bin/stallionfs': 'b' * 64},
            'unavailable': [], 'all_metrics_won': False}


def sharing_record():
    attrs = exporter.native_correctness._parse_clone_attributes(
        struct.pack('<I5IQQI', 44, 0x80000000, 0, 0, 0, 0x1300, 123456789012345, 65, 2))
    return dict(path='/Users/example/work/file', source=attrs, destination=copy.deepcopy(attrs),
                source_identity=[17, 101], destination_identity=[17, 102], status='shared',
                reason='Matching nonzero clone IDs and full-sharing flags')


def sharing(records=None, raw=None):
    records = [sharing_record()] if records is None else records
    if raw is None:
        raw = b''.join(json.dumps(row, sort_keys=True, separators=(',', ':')).encode() + b'\n' for row in records)
    counts = dict.fromkeys(exporter.SHARING_REASONS, 0)
    for row in records: counts[row['status']] += 1
    outcome = False if counts['not_shared'] else None if counts['unknown'] or not counts['shared'] else True
    return dict(full_data_stream_sharing=outcome, counts=counts,
                exceptions=[{key: row[key] for key in ('path', 'status', 'reason')} for row in records if row['status'] != 'shared'],
                observations_gzip_b64=base64.b64encode(gzip.compress(raw, mtime=0)).decode(),
                observations_bytes=len(raw), observations_sha256=hashlib.sha256(raw).hexdigest(),
                observations_encoding=exporter.SHARING_ENCODING, scope=exporter.SHARING_SCOPE,
                evidence=exporter.SHARING_EVIDENCE, required=True)


def sharing_report(value=None):
    data = report()
    data['rows'][0].update(operation='clone', data_stream_sharing=sharing() if value is None else value)
    return data


def scan_report(method='find-stat', raw=None, fixture='scan_flat_20k'):
    if raw is None:
        raw = (b'100640\t9\t7\n100640\t9\t7\n40750\t0\t7\n40750\t0\t8\n120777\t99\t7\n10600\t0\t7\n'
               if method == 'find-stat' else
               b'{ "files":2, "directories":2, "symlinks":1, "other":1, "logical_bytes":18, "skipped_mounts":1 }\n')
    data = report()
    data['selection'].update(fixtures=[fixture], operations=['scan'])
    row = data['rows'][0]
    row.pop('stdout'); row.pop('stdout_b64')
    row.update(fixture=fixture, operation='scan', method=method, completion_uncertain=False,
               stdout_gzip_b64=base64.b64encode(gzip.compress(raw, mtime=0)).decode(),
               stdout_sha256=hashlib.sha256(raw).hexdigest(), stdout_bytes=len(raw),
               correctness={'passed': False, 'expected': {'files': 3}, 'observed': {'files': 2}})
    return data


def dependency_report():
    data = sharing_report()
    data['selection'].update(fixtures=['installed_dependencies'], node='/Users/example/bin/node',
                             npm='/Users/example/npm/bin/npm-cli.js', npm_cache='/Users/example/npm-cache')
    data['rows'][0].update(fixture='installed_dependencies', run=1)
    data['source_sha256'].update({'tests/perf/fixture/' + key: value for key, value in exporter.LOCKED_DEPENDENCY_INPUTS.items()})
    root, node, npm, cache = '/Users/example/scratch/deps', '/Users/example/bin/node', '/Users/example/npm/bin/npm-cli.js', '/Users/example/npm-cache'
    common = [node, npm, '--prefix', root, '--userconfig', root + '/empty-user.npmrc',
              '--globalconfig', root + '/empty-global.npmrc', '--cache', cache]
    commands = [[node, '--version'], [node, '-p', 'JSON.stringify({platform:process.platform,arch:process.arch})'],
                [*common, '--version'], [*common, 'ci', '--offline', '--ignore-scripts', '--no-audit', '--no-fund'],
                [node, root + '/check.cjs'], [node, root + '/node_modules/typescript/bin/tsc', '--version']]
    receipt = dict(run=1, fixture='installed_dependencies', status='prepared', root=root, cache=cache,
        node_path=node, npm_cli_path=npm, npm_package_manifest='/Users/example/npm/package.json',
        node_sha256='1' * 64, npm_entrypoint_sha256='2' * 64, npm_package_manifest_sha256='3' * 64,
        installed_lock_sha256='4' * 64, manifest_sha256='5' * 64, npm_package_version='11.15.0',
        npm_version='11.15.0', node_version='v24.19.0', node_platform={'platform': 'darwin', 'arch': 'arm64'},
        typescript_platform={'name': '@typescript/typescript-darwin-arm64', 'version': '7.0.2'},
        typescript_cli_version='Version 7.0.2', runtime_pin_scope=exporter.DEPENDENCY_PIN_SCOPE,
        policy=exporter.DEPENDENCY_POLICY, locked_inputs=dict(exporter.LOCKED_DEPENDENCY_INPUTS),
        source=root + '/node_modules', regular_files=11564, logical_bytes=85568073,
        dependencies={'axios': '1.20.0', 'date-fns': '4.4.0', 'eslint': '10.12.0', 'lodash': '4.18.1',
                      'prettier': '3.9.9', 'react': '19.3.0', 'react-dom': '19.3.0', 'rxjs': '7.8.2',
                      'typescript': '7.0.2', 'zod': '4.6.5'},
        commands=[dict(argv=argv, exit_code=0, stdout='', stderr='diagnostic /Users/example/npm-cache/log') for argv in commands])
    data['preparation'] = [receipt]
    return data


class ExportNative(unittest.TestCase):
    def test_existing_scans_preserve_numeric_stdout_and_failure_evidence(self):
        for fixture in ('scan_flat_20k', 'scan_nested_20k', 'scan_deep40_20k'):
            for method in ('find-stat', 'stallionfs'):
                original = scan_report(method, fixture=fixture); frozen = copy.deepcopy(original)
                actual, _ = exporter.redact_report(original, [('/Users/example', 'HOME')])
                row, before = actual['rows'][0], frozen['rows'][0]
                self.assertEqual(gzip.decompress(base64.b64decode(row['stdout_gzip_b64'])),
                                 gzip.decompress(base64.b64decode(before['stdout_gzip_b64'])))
                for key in ('stdout_sha256', 'stdout_bytes', 'correctness', 'validated', 'exit_code',
                            'wall_s', 'cpu_s', 'rss_bytes', 'completion_uncertain'):
                    self.assertEqual(row[key], before[key])
                self.assertEqual(actual['source_sha256'], frozen['source_sha256'])
                self.assertEqual(row['cwd'], '${HOME}/work')
                self.assertEqual(original, frozen)

    def test_scan_stdout_rejects_bad_encoding_digest_size_and_bounds(self):
        def compressed(row, transform):
            raw = base64.b64decode(row['stdout_gzip_b64'])
            row['stdout_gzip_b64'] = base64.b64encode(transform(raw)).decode()
        mutations = [lambda r: r.update(stdout_gzip_b64='!'), lambda r: r.update(stdout_gzip_b64=[]),
                     lambda r: r.update(stdout_sha256='0' * 64), lambda r: r.update(stdout_sha256=1),
                     lambda r: r.update(stdout_bytes=True), lambda r: r.update(stdout_bytes=-1),
                     lambda r: r.update(stdout_bytes=r['stdout_bytes']-1),
                     lambda r: compressed(r, lambda b: b[:-1]),
                     lambda r: compressed(r, lambda b: b + b'junk'),
                     lambda r: compressed(r, lambda b: b + gzip.compress(b''))]
        for change in mutations:
            data = scan_report(); change(data['rows'][0])
            with self.subTest(change=change), self.assertRaises(ValueError):
                exporter.redact_report(data, [('/Users/example', 'HOME')])
        for field, maximum in (('MAX_SCAN_BYTES', 16), ('MAX_SCAN_COMPRESSED', 8)):
            with mock.patch.object(exporter, field, maximum), self.assertRaises(ValueError):
                exporter.redact_report(scan_report(), [('/Users/example', 'HOME')])
        bomb = scan_report(raw=b'x' * 4096); bomb['rows'][0]['stdout_bytes'] = 16
        with mock.patch.object(exporter, 'MAX_SCAN_BYTES', 16), self.assertRaises(ValueError):
            exporter.redact_report(bomb, [('/Users/example', 'HOME')])

    def test_scan_stdout_proves_numeric_protocol_before_export(self):
        counts = dict.fromkeys(exporter.native_suite.SCAN_FIELDS, 0)
        cases = [('find-stat', raw) for raw in (b'/Users/example/secret\n', b'100644\t0\t7',
                 b'100644\t-1\t7\n', b'0\t1\t7\n', b'100644\t1\t2147483648\n',
                 b'100644\t9223372036854775807\t7\n' * 3)]
        cases += [('stallionfs', json.dumps(value).encode()) for value in
                  ([], counts | {'files': True}, counts | {'files': -1}, counts | {'files': 1 << 64},
                   counts | {'secret': '/Users/example/secret'}, counts | {'other': 1.5})]
        cases += [('stallionfs', b'{"files":0,' + json.dumps(counts).encode()[1:]),
                  ('stallionfs', b'\xff'), ('stallionfs', b'')]
        for method, raw in cases:
            with self.subTest(method=method, raw=raw), self.assertRaises(ValueError):
                exporter.redact_report(scan_report(method, raw), [('/Users/example', 'HOME')])

    def test_scan_export_discards_optional_gzip_header_paths_only(self):
        original = scan_report(); row = original['rows'][0]
        raw = gzip.decompress(base64.b64decode(row['stdout_gzip_b64']))
        buffer = io.BytesIO()
        with gzip.GzipFile(filename='/Users/example/secret', fileobj=buffer, mode='wb', mtime=123) as stream:
            stream.write(raw)
        row['stdout_gzip_b64'] = base64.b64encode(buffer.getvalue()).decode()
        actual, _ = exporter.redact_report(original, [('/Users/example', 'HOME')])
        compressed = base64.b64decode(actual['rows'][0]['stdout_gzip_b64'])
        self.assertEqual(compressed[3:8], b'\0' * 5)
        self.assertNotIn(b'secret', compressed)
        self.assertEqual(gzip.decompress(compressed), raw)
        self.assertEqual(actual['rows'][0]['stdout_sha256'], row['stdout_sha256'])

    def test_scan_allowlist_and_payload_placement_fail_closed(self):
        mutations = [lambda d: d['selection'].update(fixtures=['scan_future']),
                     lambda d: d['selection'].update(fixtures=['scan_flat_20k', 'tiny_4kib']),
                     lambda d: d['selection'].update(operations=['clone']),
                     lambda d: d['selection'].update(operations=['scan', 'clone']),
                     lambda d: d['selection'].pop('operations'),
                     lambda d: d['rows'][0].update(operation='clone'),
                     lambda d: d['rows'][0].update(method='future'),
                     lambda d: d['rows'][0].update(stdout='duplicate'),
                     lambda d: d['rows'][0].update(stdout_b64=''),
                     lambda d: d['rows'][0].pop('stdout_bytes'),
                     lambda d: d['rows'][0].update(completion_uncertain=True),
                     lambda d: d['rows'][0].update(other_gzip_b64='opaque'),
                     lambda d: d.update(extra={'stdout_gzip_b64':'opaque'}),
                     lambda d: d.update(comparisons=[{'fixture':'scan_flat_20k','operation':'clone'}])]
        for change in mutations:
            data = scan_report(); change(data)
            with self.subTest(change=change), self.assertRaises(ValueError):
                exporter.redact_report(data, [('/Users/example', 'HOME')])
        data = report(); data['rows'][0]['operation'] = 'scan'
        with self.assertRaises(ValueError): exporter.redact_report(data, [('/Users/example', 'HOME')])

    def test_uncertain_scan_receipts_keep_raw_diagnostics_and_outcomes(self):
        data = scan_report(); row = data['rows'][0]
        for field in ('stdout_gzip_b64', 'stdout_sha256', 'stdout_bytes'): row.pop(field)
        row.update(completion_uncertain=True, exit_code=None, partial_stdout_b64=base64.b64encode(
            b'/Users/example/work/partial\x00\xff').decode())
        frozen = copy.deepcopy(data)
        actual, _ = exporter.redact_report(data, [('/Users/example', 'HOME')])
        self.assertEqual(base64.b64decode(actual['rows'][0]['partial_stdout_b64']), b'${HOME}/work/partial\x00\xff')
        self.assertTrue(actual['rows'][0]['completion_uncertain'])
        self.assertIsNone(actual['rows'][0]['exit_code'])
        self.assertFalse(actual['rows'][0]['validated'])
        self.assertEqual(data, frozen)
        row['completion_uncertain'] = 1
        with self.assertRaises(ValueError): exporter.redact_report(data, [('/Users/example', 'HOME')])

    def test_scan_file_export_preserves_original_report_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            source, target = Path(folder)/'private.json', Path(folder)/'export.json'
            raw = json.dumps(scan_report(), indent=2).encode(); source.write_bytes(raw)
            actual = exporter.export_report(source, target, [('/Users/example', 'HOME')])
            self.assertEqual(source.read_bytes(), raw)
            self.assertEqual(actual['export']['original_report_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(json.loads(target.read_text()), actual)
            with self.assertRaises(FileExistsError): exporter.export_report(source, target, [('/Users/example', 'HOME')])

    def test_dependency_selection_preserves_relative_runtime_paths(self):
        data = dependency_report()
        relative = {'node': '../runtime/bin/node', 'npm': 'runtime/npm/bin/npm-cli.js', 'npm_cache': 'work/npm-cache'}
        data['selection'].update(relative)
        # A path resolution here would depend on the export machine's cwd.
        with mock.patch.object(Path, 'resolve', side_effect=AssertionError('Do not resolve report input paths')):
            actual, _ = exporter.redact_report(data, [('/Users/example', 'HOME')])
        for key, value in relative.items(): self.assertEqual(actual['selection'][key], value)
        self.assertEqual(actual['preparation'][0]['node_path'], '${HOME}/bin/node')
        self.assertEqual(actual['preparation'][0]['cache'], '${HOME}/npm-cache')
        for invalid in ('', 'bad\x00path', None, 7):
            malformed = copy.deepcopy(data); malformed['selection']['npm_cache'] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                exporter.redact_report(malformed, [('/Users/example', 'HOME')])
        malformed = copy.deepcopy(data); malformed['preparation'][0]['cache'] = 'work/npm-cache'
        with self.assertRaisesRegex(ValueError, 'Invalid dependency preparation path'):
            exporter.redact_report(malformed, [('/Users/example', 'HOME')])

    def test_locked_dependency_receipt_redaction_retains_evidence(self):
        data = dependency_report(); frozen = copy.deepcopy(data)
        actual, _ = exporter.redact_report(data, [('/Users/example', 'HOME')])
        receipt, original = actual['preparation'][0], frozen['preparation'][0]
        for key in ('regular_files', 'logical_bytes', 'manifest_sha256', 'locked_inputs', 'node_sha256',
                    'npm_entrypoint_sha256', 'npm_package_manifest_sha256', 'installed_lock_sha256',
                    'dependencies', 'node_platform', 'typescript_platform', 'runtime_pin_scope'):
            self.assertEqual(receipt[key], original[key])
        self.assertEqual(actual['selection']['npm_cache'], '${HOME}/npm-cache')
        self.assertEqual(receipt['commands'][3]['argv'][1], '${HOME}/npm/bin/npm-cli.js')
        self.assertEqual(receipt['commands'][3]['stderr'], 'diagnostic ${HOME}/npm-cache/log')
        self.assertNotIn('/Users/example', json.dumps(actual))
        self.assertEqual(data, frozen)

    def test_dependency_policy_rejects_unknown_or_unverified_inputs(self):
        mutations = [lambda d: d['source_sha256'].update({'tests/perf/fixture/package-lock.json': '0' * 64}),
                     lambda d: d['selection'].pop('npm_cache'),
                     lambda d: d['selection'].update(input_path='/Users/example/project'),
                     lambda d: d['preparation'][0]['locked_inputs'].update({'package.json': '0' * 64}),
                     lambda d: d['preparation'][0].update(status='preparing'),
                     lambda d: d['preparation'][0].update(environment={'secret': 'not exportable'}),
                     lambda d: d['preparation'][0]['commands'][3]['argv'].remove('--ignore-scripts'),
                     lambda d: d['preparation'][0]['commands'][3]['argv'].remove('--offline'),
                     lambda d: d['preparation'][0]['commands'][3].update(exit_code=1),
                     lambda d: d['preparation'][0]['commands'][0].update(secret='unknown'),
                     lambda d: d['preparation'][0].update(node_sha256='bad'),
                     lambda d: d['preparation'][0].update(runtime_pin_scope='everything pinned'),
                     lambda d: d['preparation'][0].update(manifest_sha256=None),
                     lambda d: d['preparation'][0]['dependencies'].update(typescript='different'),
                     lambda d: d['rows'][0].update(run=2),
                     lambda d: d.update(preparation=[]),
                     lambda d: d['rows'][0].update(unknown_gzip_b64='opaque')]
        for mutate in mutations:
            data = dependency_report(); mutate(data)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                exporter.redact_report(data, [('/Users/example', 'HOME')])

    def test_metrics_losses_and_raw_bytes_preserved(self):
        original = report(); frozen = copy.deepcopy(original)
        actual, manifest = exporter.redact_report(original, [('/Users/example', 'HOME')])
        self.assertEqual(original, frozen)
        row = actual['rows'][0]
        for key in ('wall_s', 'cpu_s', 'rss_bytes', 'validated', 'exit_code', 'correctness'):
            self.assertEqual(row[key], original['rows'][0][key])
        self.assertEqual(row['argv'][0], '${HOME}/bin/stallionfs')
        self.assertEqual(row['cwd'], '${HOME}/work')
        self.assertEqual(row['error'], "copy '${HOME}/work/item' failed")
        self.assertEqual(base64.b64decode(row['stdout_b64']), b'failed ${HOME}/work/item: permission\n\xff\x00')
        self.assertEqual(base64.b64decode(row['partial_stderr_b64']), b'${HOME}/work/partial')
        self.assertIn('${HOME}/bin/stallionfs', actual['executables'])
        self.assertNotIn('/Users/example', json.dumps(actual))
        self.assertEqual(set(manifest[0]), {'alias', 'replacement_count'})

    def test_current_generated_fixture_policy(self):
        for name in ('huge_2x10gib', 'deep_20000', 'photo_library'):
            data = report()
            data['selection'].update(fixtures=[name], operations=['clone', 'delete'])
            data['rows'][0]['fixture'] = name
            actual, _ = exporter.redact_report(data, [('/Users/example', 'HOME')])
            self.assertEqual(actual['selection']['fixtures'], [name])

    def test_path_boundaries(self):
        data = report()
        data['notes'] = ['/Users/example', '/Users/example/a', '/Users/example-other/a',
                         '/Users/example.txt', '/other/Users/example/a', 'prefix/Users/example/a',
                         'path=/Users/example/a', "'/Users/example'", 'é/Users/example/a']
        actual, _ = exporter.redact_report(data, [('/Users/example', 'HOME')])
        self.assertEqual(actual['notes'], ['${HOME}', '${HOME}/a', '/Users/example-other/a',
                         '/Users/example.txt', '/other/Users/example/a', 'prefix/Users/example/a',
                         'path=${HOME}/a', "'${HOME}'", 'é/Users/example/a'])

    def test_sharing_requires_a_clone_row(self):
        data = report()
        data['rows'][0]['data_stream_sharing'] = {'observations_gzip_b64': 'opaque encoded observations'}
        with self.assertRaisesRegex(ValueError, 'Clone-sharing observations'):
            exporter.redact_report(data, [('/Users/example', 'HOME')])

    def test_sharing_redaction_preserves_evidence_and_original_digest(self):
        data = sharing_report(); frozen = copy.deepcopy(data)
        actual, _ = exporter.redact_report(data, [('/Users/example', 'HOME')])
        value = actual['rows'][0]['data_stream_sharing']
        raw = gzip.decompress(base64.b64decode(value['observations_gzip_b64'], validate=True))
        pair = json.loads(raw)
        expected = sharing_record(); expected['path'] = '${HOME}/work/file'
        self.assertEqual(pair, expected)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), value['observations_sha256'])
        self.assertEqual(len(raw), value['observations_bytes'])
        for key in ('observations_sha256', 'observations_bytes'):
            self.assertEqual(value['original_' + key], frozen['rows'][0]['data_stream_sharing'][key])
        for key in ('counts', 'full_data_stream_sharing', 'required'):
            self.assertEqual(value[key], frozen['rows'][0]['data_stream_sharing'][key])
        self.assertEqual(data, frozen)
        self.assertNotIn('/Users/example', raw.decode())

    def test_sharing_unknown_and_empty_records_preserved(self):
        for attrs in (None, {'available': False, 'unavailable': 'Requires little-endian Darwin'},
                      {'available': False, 'error_number': 45, 'raw_hex': '00' * 44,
                       'unavailable': 'Clone attributes unsupported'}):
            pair = sharing_record(); pair.update(source=attrs, status='unknown', reason='Missing attributes or zero clone identifier')
            data = sharing_report(sharing([pair]))
            actual, _ = exporter.redact_report(data, [('/Users/example', 'HOME')])
            value = actual['rows'][0]['data_stream_sharing']
            self.assertIsNone(value['full_data_stream_sharing'])
            self.assertEqual(value['exceptions'][0]['path'], '${HOME}/work/file')
            self.assertEqual(json.loads(gzip.decompress(base64.b64decode(value['observations_gzip_b64'])))['source'], attrs)
        actual, _ = exporter.redact_report(sharing_report(sharing([])), [('/Users/example', 'HOME')])
        self.assertEqual(actual['rows'][0]['data_stream_sharing']['observations_bytes'], 0)
        pair = sharing_record()
        pair.update(source={'available': 0, 'unavailable': 'Requires little-endian Darwin'},
                    status='unknown', reason='Missing attributes or zero clone identifier')
        with self.assertRaisesRegex(ValueError, 'Unknown unavailable sharing attributes'):
            exporter.redact_report(sharing_report(sharing([pair])), [('/Users/example', 'HOME')])

    def test_sharing_root_file_and_surrogateescaped_paths(self):
        for path in ('', '/Users/example/work/file-\udcff', 'relative-\udc80'):
            for status in ('shared', 'unknown'):
                pair = sharing_record(); pair['path'] = path
                if status == 'unknown':
                    pair.update(source=None, status='unknown', reason='Missing attributes or zero clone identifier')
                data = sharing_report(sharing([pair])); frozen = copy.deepcopy(data)
                actual, _ = exporter.redact_report(data, [('/Users/example', 'HOME')])
                value = actual['rows'][0]['data_stream_sharing']
                raw = gzip.decompress(base64.b64decode(value['observations_gzip_b64'], validate=True))
                observed = json.loads(raw)
                expected_path = path.replace('/Users/example', '${HOME}')
                self.assertEqual(observed['path'], expected_path)
                self.assertEqual(os.fsencode(observed['path']), os.fsencode(expected_path))
                if path and '\udcff' in path: self.assertIn(b'\\udcff', raw)
                if status == 'unknown': self.assertEqual(value['exceptions'][0]['path'], expected_path)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), value['observations_sha256'])
                self.assertEqual(len(raw), value['observations_bytes'])
                self.assertEqual(data, frozen)

    def test_shared_status_requires_matching_attributes_and_independent_identity(self):
        def attribute(pair, **changes):
            values = dict(clone_id=123456789012345, flags=65, masks=0x1300)
            values.update(changes)
            pair['destination'] = exporter.native_correctness._parse_clone_attributes(struct.pack(
                '<I5IQQI', 44, 0x80000000, 0, 0, 0, values['masks'], values['clone_id'], values['flags'], 2))
        mutations = [lambda p: p.update(source=None, destination=None),
                     lambda p: p.update(source={'available': False, 'unavailable': 'Requires little-endian Darwin'}),
                     lambda p: attribute(p, clone_id=0), lambda p: attribute(p, clone_id=99),
                     lambda p: attribute(p, flags=1), lambda p: attribute(p, masks=0x300),
                     lambda p: p.update(source_identity=None),
                     lambda p: p.update(destination_identity=[18, 102]),
                     lambda p: p.update(destination_identity=[17, 101])]
        for mutate in mutations:
            pair = sharing_record(); mutate(pair)
            with self.subTest(pair=pair), self.assertRaisesRegex(ValueError, 'Shared status contradicts'):
                exporter.redact_report(sharing_report(sharing([pair])), [('/Users/example', 'HOME')])

    def test_sharing_rejects_corruption_unknown_schema_and_summary(self):
        def corrupt_tail(value):
            data = base64.b64decode(value['observations_gzip_b64'])
            value['observations_gzip_b64'] = base64.b64encode(data[:-2]).decode()
        def concatenate(value):
            data = base64.b64decode(value['observations_gzip_b64']) + gzip.compress(b'')
            value['observations_gzip_b64'] = base64.b64encode(data).decode()
        mutations = [lambda v: v.update(observations_gzip_b64='!'), corrupt_tail, concatenate,
                     lambda v: v.update(observations_sha256='0' * 64),
                     lambda v: v.update(observations_bytes=v['observations_bytes'] - 1),
                     lambda v: v.update(observations_bytes=True), lambda v: v.update(extra='unknown'),
                     lambda v: v['counts'].update(shared=2), lambda v: v['counts'].update(shared=True),
                     lambda v: v.update(full_data_stream_sharing=False),
                     lambda v: v.update(exceptions=[{'path': '/Users/example/hidden'}]),
                     lambda v: v.update(observations_encoding='future')]
        for mutate in mutations:
            value = sharing(); mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                exporter.redact_report(sharing_report(value), [('/Users/example', 'HOME')])
        for mutate in (lambda p: p.update(extra=1), lambda p: p.update(status='future'),
                       lambda p: p.update(reason=[]), lambda p: p.update(source_identity=[True, 101]),
                       lambda p: p['source'].update(clone_id=7), lambda p: p['source'].update(extra=1)):
            pair = sharing_record(); mutate(pair)
            # Use a valid summary with deliberately malformed encoded records.
            value = sharing(raw=json.dumps(pair).encode() + b'\n')
            with self.subTest(record=pair), self.assertRaises(ValueError):
                exporter.redact_report(sharing_report(value), [('/Users/example', 'HOME')])
        for raw in (b'\xff\n', b'{}', b'{"path":"a","path":"b"}\n', b'{"path":NaN}\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                exporter.redact_report(sharing_report(sharing(raw=raw)), [('/Users/example', 'HOME')])

    def test_sharing_bounded_decode_and_existing_policy(self):
        with mock.patch.object(exporter, 'MAX_SHARING_BYTES', 16), self.assertRaises(ValueError):
            exporter.redact_report(sharing_report(), [('/Users/example', 'HOME')])
        value = sharing(raw=b'x' * 4096); value['observations_bytes'] = 16
        with mock.patch.object(exporter, 'MAX_SHARING_BYTES', 16), self.assertRaises(ValueError):
            exporter.redact_report(sharing_report(value), [('/Users/example', 'HOME')])
        with mock.patch.object(exporter, 'MAX_SHARING_COMPRESSED', 8), self.assertRaises(ValueError):
            exporter.redact_report(sharing_report(), [('/Users/example', 'HOME')])
        for mutate in (lambda d: d['selection'].update(fixtures=['installed_dependencies']),
                       lambda d: d['selection'].update(fixtures=['scan_flat_20k']),
                       lambda d: d['selection'].update(operations=['scan']),
                       lambda d: d['rows'][0].update(other_gzip_b64='opaque'),
                       lambda d: d['selection'].update(npm='/private/npm')):
            data = sharing_report(); mutate(data)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                exporter.redact_report(data, [('/Users/example', 'HOME')])

    def test_alias_ambiguity_and_collision(self):
        for aliases in [ [('/', 'ROOT')], [('/Users/example/', 'HOME')],
                         [('/Users/example', 'HOME'), ('/Users/example/work', 'WORK')],
                         [('/Users/example', 'HOME'), ('/tmp', 'HOME')],
                         [('/Users/example', 'HOME'), ('/Users/example', 'OTHER')],
                         [('/Users/example/../other', 'HOME')], [('/tmp', 'bad-name')] ]:
            with self.subTest(aliases=aliases), self.assertRaises(ValueError):
                exporter.redact_report(report(), aliases)
        for field in ('text', 'raw'):
            data = report()
            if field == 'text': data['note'] = '${HOME}/collision'
            else: data['rows'][0]['stderr_b64'] = base64.b64encode(b'${HOME}').decode()
            with self.assertRaises(ValueError): exporter.redact_report(data, [('/Users/example', 'HOME')])

    def test_reject_other_input_policies_and_bad_raw(self):
        for mutate in [lambda d: d['selection'].update(fixtures=['user_directory']),
                       lambda d: d['selection'].update(input_path='/data'),
                       lambda d: d['rows'][0].update(fixture='unselected_fixture'),
                       lambda d: d.update(source_sha256={}),
                       lambda d: d.update(schema=2),
                       lambda d: d.update(export={}),
                       lambda d: d['rows'][0].update(stderr_b64='!not base64')]:
            data = report(); mutate(data)
            with self.assertRaises(ValueError): exporter.redact_report(data, [('/Users/example', 'HOME')])

    def test_exclusive_export_and_original_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'private.json'; output = Path(folder) / 'public.json'
            raw = json.dumps(report(), indent=2).encode(); source.write_bytes(raw)
            exported = exporter.export_report(source, output, [('/Users/example', 'HOME')])
            self.assertEqual(source.read_bytes(), raw)
            self.assertEqual(exported['export']['original_report_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(json.loads(output.read_text()), exported)
            first = output.read_bytes()
            with self.assertRaises(Exception): exporter.export_report(source, output, [('/Users/example', 'HOME')])
            self.assertEqual(output.read_bytes(), first)
            with self.assertRaises(Exception): exporter.export_report(source, source, [('/Users/example', 'HOME')])
            self.assertEqual(source.read_bytes(), raw)


class JournalExportNative(unittest.TestCase):
    def journal(self, folder, data, *, revisions=False):
        data = copy.deepcopy(data)
        for kind in exporter.JOURNAL_KINDS: data.setdefault(kind, [])
        output = Path(folder)/'original.json'
        writer = exporter.native_report.ReportJournal(output)
        try:
            for kind in exporter.JOURNAL_KINDS:
                for index, payload in enumerate(data[kind]):
                    if revisions:
                        writer.append(kind, index, dict(payload, earlier='/Users/example/earlier'))
                    writer.append(kind, index, payload)
            writer.finish({key:value for key,value in data.items() if key not in exporter.JOURNAL_KINDS})
        finally:
            writer.close()
        return output, writer.manifest_path, writer.journal_path

    def test_legacy_and_journal_export_value_parity_and_alias_counts(self):
        for data in (sharing_report(), scan_report(), scan_report('stallionfs'), dependency_report()):
            with self.subTest(fixture=data['selection']['fixtures']), tempfile.TemporaryDirectory() as folder:
                data['metadata_preparation'] = [{'fixture':data['selection']['fixtures'][0],
                    'seed':{'acl_command':{'argv':['/Users/example/tool','/Users/example/file'],'exit_code':0}}}]
                if 'preparation' in data:
                    data['preparation'].append({'fixture':'installed_dependencies','correctness':{
                        'candidate_losses':[{'path':'/Users/example/operand','expected':123,'actual':456}]}})
                source, manifest, journal = self.journal(folder, data, revisions=True)
                original = {path:hashlib.sha256(path.read_bytes()).hexdigest() for path in (source, manifest, journal)}
                legacy = exporter.export_report(source, Path(folder)/'legacy.json', [('/Users/example','HOME')])
                receipt = exporter.export_report(manifest, Path(folder)/'streamed.json', [('/Users/example','HOME')])
                actual = json.loads((Path(folder)/'streamed.json').read_text())
                self.assertEqual(actual['export'], receipt)
                self.assertEqual(actual['export']['redaction_manifest'], legacy['export']['redaction_manifest'])
                self.assertEqual(actual['export']['original_manifest_sha256'], original[manifest])
                committed = json.loads(manifest.read_text())
                self.assertEqual(actual['export']['committed_prefix_sha256'], committed['prefix_sha256'])
                for key in ('committed_bytes','event_count'): self.assertEqual(actual['export'][key], committed[key])
                self.assertNotIn('original_report_sha256', actual['export'])
                actual.pop('export'); legacy.pop('export')
                self.assertEqual(actual, legacy)
                self.assertFalse(any('earlier' in row for row in actual['rows']))
                self.assertEqual(original, {path:hashlib.sha256(path.read_bytes()).hexdigest() for path in original})

    def test_journal_streams_records_without_whole_campaign_read_or_retention(self):
        data = report()
        data['rows'] = [dict(data['rows'][0], sample=index) for index in range(80)]
        with tempfile.TemporaryDirectory() as folder:
            _, manifest, _ = self.journal(folder, data)
            original_iterator = exporter.native_report.ReportJournal.iter_latest
            references = []
            class Payload(dict):
                __slots__ = ('__weakref__',)
            def one_at_a_time(reader, kind):
                for row in original_iterator(reader, kind):
                    payload = Payload(row)
                    references.append(weakref.ref(payload))
                    self.assertLessEqual(sum(reference() is not None for reference in references), 2)
                    yield payload
                    del payload
            with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('Whole-file read prohibited')), \
                    mock.patch.object(exporter.native_report.ReportJournal, 'iter_latest', one_at_a_time):
                exporter.export_report(manifest, Path(folder)/'streamed.json', [('/Users/example','HOME')])
            actual = json.loads((Path(folder)/'streamed.json').read_text())
            self.assertEqual(len(actual['rows']), 80)
            self.assertEqual([row['sample'] for row in actual['rows']], list(range(80)))

    def test_journal_rejects_corruption_tail_schema_and_path_references(self):
        def manifest_change(path, **changes):
            value = json.loads(path.read_text()); value.update(changes); path.write_text(json.dumps(value))
        changes = [lambda m,j: j.write_bytes(j.read_bytes() + b'garbage'),
                   lambda m,j: j.write_bytes(j.read_bytes()[:-1]),
                   lambda m,j: j.write_bytes(b'!' + j.read_bytes()[1:]),
                   lambda m,j: manifest_change(m, storage_schema=2),
                   lambda m,j: manifest_change(m, journal='../other.journal')]
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as folder:
                _, manifest, journal = self.journal(folder, report())
                change(manifest, journal)
                output = Path(folder)/'export.json'
                with self.assertRaises((ValueError, OSError)):
                    exporter.export_report(manifest, output, [('/Users/example','HOME')])
                self.assertFalse(output.exists())
                self.assertEqual(list(Path(folder).glob('.native-export-*')), [])

    def test_journal_rechecks_integrity_after_final_record(self):
        for mutate_manifest in (False, True):
            with self.subTest(manifest=mutate_manifest), tempfile.TemporaryDirectory() as folder:
                _, manifest, journal = self.journal(folder, report())
                iterator = exporter.native_report.ReportJournal.iter_latest
                def tamper(reader, kind):
                    yield from iterator(reader, kind)
                    if kind == 'unavailable':
                        path = manifest if mutate_manifest else journal
                        with path.open('r+b') as stream:
                            stream.write(b'!')  # Same-inode mutation after the last iteration's precheck.
                output = Path(folder)/'export.json'
                with mock.patch.object(exporter.native_report.ReportJournal, 'iter_latest', tamper), self.assertRaises(ValueError):
                    exporter.export_report(manifest, output, [('/Users/example','HOME')])
                self.assertFalse(output.exists())
                self.assertEqual(list(Path(folder).glob('.native-export-*')), [])

    def test_journal_preserves_existing_outputs_and_cleans_failed_temporary(self):
        with tempfile.TemporaryDirectory() as folder:
            source, manifest, journal = self.journal(folder, sharing_report())
            for output in (source, manifest, journal):
                before = output.read_bytes()
                with self.assertRaises(FileExistsError):
                    exporter.export_report(manifest, output, [('/Users/example','HOME')])
                self.assertEqual(output.read_bytes(), before)
        for invalid in ('unknown-gzip', 'wrong-dependency-run', 'nested-scan'):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as folder:
                data = dependency_report() if invalid == 'wrong-dependency-run' else report()
                if invalid == 'unknown-gzip': data['rows'][0]['unknown_gzip_b64'] = 'opaque'
                elif invalid == 'wrong-dependency-run': data['rows'][0]['run'] = 999
                else: data['notes'] = {'rows': scan_report()['rows']}
                _, manifest, _ = self.journal(folder, data)
                output = Path(folder)/'export.json'
                with self.assertRaises(ValueError):
                    exporter.export_report(manifest, output, [('/Users/example','HOME')])
                self.assertFalse(output.exists())
                self.assertEqual(list(Path(folder).glob('.native-export-*')), [])

    def test_nested_scan_output_and_future_journal_kinds_fail_closed(self):
        data = scan_report(); data['notes'] = {'rows':copy.deepcopy(data['rows'])}
        with self.assertRaises(ValueError): exporter.redact_report(data, [('/Users/example','HOME')])
        with tempfile.TemporaryDirectory() as folder:
            _, manifest, _ = self.journal(folder, report())
            with mock.patch.object(exporter.native_report, 'KINDS', (*exporter.JOURNAL_KINDS,'future')), self.assertRaises(ValueError):
                exporter.export_report(manifest, Path(folder)/'export.json', [('/Users/example','HOME')])


if __name__ == '__main__':
    unittest.main()
