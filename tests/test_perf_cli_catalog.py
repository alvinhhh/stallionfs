"""Contracts and paired orchestration for the remaining fixed CLI cases."""
from contextlib import ExitStack, redirect_stderr
import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

PERF = Path(__file__).parent / 'perf'
with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
    spec = importlib.util.spec_from_file_location('catalog_cli_cases', PERF / 'cli.py')
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)


class CatalogContracts(unittest.TestCase):
    def test_parser_routes_each_native_mode_with_paired_defaults(self):
        for operation in cli.CATALOG_POLICIES:
            argv = ['cli.py', '--native-' + operation, '--candidate', '/binary',
                    '--scratch', '/scratch', '--output', '/output']
            with self.subTest(operation=operation), mock.patch.dict(cli.os.environ, {}, clear=True), \
                    mock.patch.object(cli.sys, 'argv', argv), mock.patch.object(cli, 'native_catalog', return_value=0) as collect:
                self.assertEqual(cli.main(), 0)
                args, selected = collect.call_args.args
                self.assertEqual(selected, operation)
                self.assertEqual((args.samples, args.cache), (10, ['warm']))
                self.assertNotIn('STALLIONFS_BENCHMARK_DEADLINE', cli.os.environ)

    def test_parser_rejects_baseline_bad_pair_counts_and_duplicate_cache_modes(self):
        for operation in cli.CATALOG_POLICIES:
            for extra in (['--baseline', '/older'], ['--samples', '9'], ['--cache', 'warm', 'warm']):
                argv = ['cli.py', '--native-' + operation, '--candidate', '/binary',
                        '--scratch', '/scratch', '--output', '/output', *extra]
                with self.subTest(operation=operation, extra=extra), mock.patch.object(cli.sys, 'argv', argv), \
                        redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as rejected:
                    cli.main()
                self.assertEqual(rejected.exception.code, 2)

    def test_mount_projection_readonly_spaces_and_root(self):
        self.assertEqual(cli.mount_projection(
            b'/dev/root on / (apfs, sealed, read-only, local)\n'
            b'map auto_home on /System/Volumes/Data/home (autofs, automounted)\n'
            b'/dev/disk9 on /Volumes/A disk (apfs)\n'),
            [('/', 'apfs', True), ('/System/Volumes/Data/home', 'autofs', False),
             ('/Volumes/A disk', 'apfs', False)])
        self.assertEqual(cli.mount_projection(b''), [])
        for value in (b'not a mount\n', b'x on relative (apfs)\n', b'x on / (apfs\n', b'x on /\0 (apfs)\n'):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                cli.mount_projection(value)

    def validate(self, operation, method, form, output, **options):
        defaults = dict(expected=None, source=Path('/unused'), destination=None, counts=None,
                        inventory=[{'path': '/', 'filesystem': 'apfs', 'readonly': True}])
        cli.validate_catalog_output(operation, method, form, output, **(defaults | options))

    def test_volumes_validates_projection_and_full_candidate_contract(self):
        inventory = [{'path': '/', 'filesystem': 'apfs', 'readonly': True}]
        for method, form, output in (
                ('native', 'plain', b'disk on / (apfs, read-only)\n'),
                ('candidate', 'plain', cli.volumes_text(inventory)),
                ('candidate', 'json', json.dumps(inventory).encode())):
            self.validate('volumes', method, form, output)
        for method, form, output in (
                ('native', 'plain', b'disk on / (apfs)\n'),
                ('candidate', 'plain', b''), ('native', 'plain', b''),
                ('candidate', 'json', b'[]'), ('candidate', 'json', b'not json'),
                ('candidate', 'json', b'[{"path":"/","filesystem":"apfs","readonly":1}]')):
            with self.subTest(method=method, form=form, output=output), self.assertRaises((ValueError, RuntimeError)):
                self.validate('volumes', method, form, output)

    def test_scan_empty_counts_text_and_numeric_protocol(self):
        counts = dict.fromkeys(cli.native_suite.SCAN_FIELDS, 0)
        for method, form, output in (('native', 'plain', b''),
                ('candidate', 'plain', cli.scan_text(counts)),
                ('candidate', 'json', json.dumps(counts).encode())):
            self.validate('scan', method, form, output, counts=counts, source=Path(__file__))
        for method, form, output in (('native', 'plain', b'broken\n'),
                ('candidate', 'plain', b''), ('candidate', 'json', b'{}'),
                ('candidate', 'json', json.dumps(counts | {'files': True}).encode())):
            with self.subTest(output=output), self.assertRaises((ValueError, RuntimeError)):
                self.validate('scan', method, form, output, counts=counts, source=Path(__file__))

    def test_move_requires_completion_and_inode_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / 'source', Path(directory) / 'destination'
            source.write_bytes(b'original')
            expected, before = cli.manifest(source), source.lstat()
            source.rename(destination)
            wanted = json.dumps({'source': str(source), 'destination': str(destination)}).encode()
            options = dict(source=source, destination=destination, expected=expected, prepared=before)
            self.validate('move', 'candidate', 'json', wanted, **options)
            self.validate('move', 'native', 'plain', b'', **options)
            with self.assertRaises((ValueError, RuntimeError)):
                self.validate('move', 'candidate', 'json', b'{}', **options)
            shutil.copy2(destination, source)
            replacement = source.lstat()
            source.unlink()
            with self.assertRaisesRegex(RuntimeError, 'copied'):
                self.validate('move', 'native', 'plain', b'', **(options | {'prepared': replacement}))

    def test_comparison_requires_policy_complete_pairs_and_valid_warmups(self):
        for operation, policy in cli.CATALOG_POLICIES.items():
            for phase in ('timing', 'resources'):
                rows = [dict(method=method, fixture_policy=policy, phase=phase, pair_id=i,
                             warmup=phase == 'timing' and i == 0, ok=True, validated=True,
                             wall_s=2.0 if method == 'native' else 1.0,
                             cpu_s=2.0 if method == 'native' else 1.0,
                             rss_bytes=2000 if method == 'native' else 1000)
                        for method in ('native', 'candidate')
                        for i in (range(32) if phase == 'timing' else range(1, 11))]
                metrics = cli.catalog_comparison(rows, phase, 10, policy)
                self.assertEqual({value['complete_pairs'] for value in metrics.values()},
                                 {31 if phase == 'timing' else 10})
                with self.assertRaises(RuntimeError):
                    cli.catalog_comparison([], phase, 10, policy)
                for change in ({'fixture_policy': 'wrong'}, {'validated': False},
                               {'completion_uncertain': True}, {'method': 'other'}, {'pair_id': 99}):
                    with self.subTest(operation=operation, phase=phase, change=change):
                        invalid = copy.deepcopy(rows); invalid[0].update(change)
                        with self.assertRaises(RuntimeError):
                            cli.catalog_comparison(invalid, phase, 10, policy)


class CatalogCollection(unittest.TestCase):
    def configure(self, stack, directory, *, cache=('warm',), failure=None):
        root = Path(directory)
        binary = root / 'candidate'; binary.write_bytes(b'controlled runtime')
        self.args = SimpleNamespace(candidate=binary, scratch=root, output=root / 'result.json',
                                    samples=10, cache=list(cache))
        self.inventory = [{'path': '/', 'filesystem': 'apfs', 'readonly': False}]
        self.counts = {name: dict.fromkeys(cli.native_suite.SCAN_FIELDS, 0) for name in ('empty', 'nested_1000')}
        self.counts['nested_1000'].update(files=1, logical_bytes=7)
        def fixtures(base):
            tiny, empty, nested = base / 'tiny', base / 'empty', base / 'nested'
            tiny.write_bytes(bytes(range(256)) * 16); tiny.chmod(0o640)
            empty.mkdir(); nested.mkdir(); (nested / 'file').write_bytes(b'fixture')
            (base / 'outside-sentinel').write_bytes(b'keep outside linked trees\n')
            return {'tiny_4kib': tiny, 'empty': empty, 'nested_1000': nested}, self.counts
        def command(argv, **options):
            if argv[0] == '/bin/cp': shutil.copy2(argv[-2], argv[-1])
            return subprocess.CompletedProcess(argv, 0, json.dumps(self.inventory).encode()
                                               if '--json' in argv else b'', b'')
        def collect(argv, *, phase, **options):
            candidate = argv[0] == str(binary)
            operation = argv[2] if candidate and argv[1] == '--json' else argv[1] if candidate else (
                'move' if argv[0] == '/bin/mv' else 'scan' if argv[0] == '/usr/bin/find' else 'volumes')
            output = b''
            if operation == 'move':
                Path(argv[-2]).rename(argv[-1])
                if candidate and '--json' in argv:
                    output = json.dumps({'source': argv[-2], 'destination': argv[-1]}).encode()
            elif operation == 'scan':
                source = Path(argv[-1] if candidate else argv[3])
                counts = self.counts['empty' if source.name == 'empty' else 'nested_1000']
                if candidate: output = json.dumps(counts).encode() if '--json' in argv else cli.scan_text(counts)
                elif counts['files']:
                    info = (source / 'file').lstat()
                    output = f'{info.st_mode:o}\t{info.st_size}\t{info.st_dev}\n'.encode()
            elif candidate:
                output = json.dumps(self.inventory).encode() if '--json' in argv else cli.volumes_text(self.inventory)
            else: output = b'disk on / (apfs, local)\n'
            return dict(argv=argv, phase=phase, ok=True, exit_code=0, completion_uncertain=False,
                        stdout_b64=base64.b64encode(output).decode(),
                        stderr_b64=base64.b64encode(b'bad' if failure == 'diagnostics' else b'').decode(),
                        wall_s=1.0, cpu_s=1.0, rss_bytes=1000)
        pins = {'runtime': 'stable', 'cold_tools': {'purge': {'content_hash_status': 'unavailable', 'sha256': None}}}
        for patch in (mock.patch.object(cli.platform, 'system', return_value='Darwin'),
                      mock.patch.object(cli, 'installed', return_value={'binary': binary}),
                      mock.patch.object(cli, 'catalog_pins', side_effect=[pins, {'changed': True}]
                          if failure == 'pins' else lambda *_: copy.deepcopy(pins)),
                      mock.patch.object(cli, 'scratch_volume', return_value={'filesystem': 'apfs'}),
                      mock.patch.object(cli, 'make_fixtures', side_effect=fixtures),
                      mock.patch.object(cli, 'command', side_effect=command),
                      mock.patch.object(cli, 'no_mounts_below')):
            stack.enter_context(patch)
        self.collect = stack.enter_context(mock.patch.object(cli.native_metrics, 'collect', side_effect=collect))
        self.condition = stack.enter_context(mock.patch.object(cli.native_suite, 'cache_prepare',
            side_effect=lambda mode, timeout: {'mode': mode, 'exit_code': 1 if mode == 'cold' else 0}))

    def test_all_modes_publish_valid_case_reports_and_independent_output_pairs(self):
        for operation in cli.CATALOG_POLICIES:
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, directory)
                self.assertEqual(cli.native_catalog(self.args, operation), 0)
                result = json.loads(self.args.output.read_text())
                self.assertTrue(result['passed'] and result['source_checks_passed'] and result['cleanup_passed'])
                self.assertEqual(len(result['rows']), 336 if operation == 'scan' else 168)
                self.assertTrue(all(row['validated'] and row['correctness']['passed'] for row in result['rows']))
                self.assertEqual(len(result['comparisons']), 8 if operation == 'scan' else 4)
                if operation == 'scan':
                    children = [json.loads(Path(stage['output']).read_text()) for stage in result['stages']]
                    self.assertEqual([child['case_id'] for child in children], ['cli/scan/empty', 'cli/scan/nested_1000'])
                    self.assertTrue(all(len(child['rows']) == 168 and
                        all(row['case_id'] == child['case_id'] for row in child['rows']) for child in children))

    def test_failed_validation_or_pins_retain_invalid_evidence(self):
        for failure in ('diagnostics', 'pins'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                self.configure(stack, directory, failure=failure)
                with self.assertRaises(RuntimeError): cli.native_catalog(self.args, 'move')
                result = json.loads(self.args.output.read_text())
                self.assertFalse(result['passed'])
                self.assertEqual(result['status'], 'failed')
                self.assertTrue(Path(result['retained_fixture']).is_dir())
                if failure == 'diagnostics': self.assertFalse(result['rows'][0]['validated'])

    def test_denied_cold_purge_is_not_retried_and_keeps_both_scan_case_ids(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.configure(stack, directory, cache=('cold',))
            self.assertEqual(cli.native_catalog(self.args, 'scan'), 1)
            self.assertEqual(self.condition.call_count, 1)
            self.collect.assert_not_called()
            result = json.loads(self.args.output.read_text())
            self.assertTrue(result['cleanup_passed'] and result['source_checks_passed'])
            self.assertTrue(result['cold_tool_identity_verified'] and result['denial_runtime_verified'])
            self.assertEqual(len(result['stages']), 2)
