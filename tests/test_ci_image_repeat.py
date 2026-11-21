"""Inert contracts for the bounded installed-wheel image diagnostic."""
import copy
import importlib.util
from contextlib import contextmanager, redirect_stderr
import io
import json
import os
import stat
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ci_image_repeat', ROOT / 'tools/ci_image_repeat.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def environment():
    return {'GITHUB_EVENT_NAME': 'workflow_dispatch', 'IMAGE_REPEAT_MODE': runner.MODE,
            'EXPECTED_SOURCE_SHA': 'a' * 40, 'GITHUB_SHA': 'a' * 40,
            'STALLIONFS_TEST_IMAGES': '1', 'STALLIONFS_TEST_SNAPSHOT_OBSERVATION': runner.OBSERVATION,
            'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'ARM64', 'IMAGE_REPEAT_COUNT': '20'}


def events():
    common = {'phase': 'before', 'operation_id': 1}
    observation = dict(common, kind='observation', operation='eject', stage='sibling-detach',
        expected_busy=False, error=None, observation='before detach validation',
        pre_observation='attempted', expected_mountpoint='/fixture/sibling')
    mapping = dict(common, kind='mapping', image='/fixture/sibling.sparseimage',
        mountpoint_matches=True, mountpoint='/fixture/sibling', expected_mountpoint='/fixture/sibling',
        volume_device='/dev/disk9s1', devices=['/dev/disk8', '/dev/disk9s1'],
        backing_identity_matches_first=True, backing_device=1, backing_inode=2)
    holder = dict(common, kind='lsof', returncode=0,
        stdout='p10\ncworker\nf3\ntREG\nD0x1\ni2\nn/fixture/sibling.sparseimage',
        stderr='', reaped=True, timeout=False, truncated=False,
        display_truncated=False, capture_error=None, cleanup_error=None, backing_device_after=1,
        backing_inode_after=2, backing_identity_status='matched')
    return [observation, mapping, holder, dict(holder, stdout='', backing_identity_status='not_queried')]


class Requests(unittest.TestCase):
    def test_counts_source_mode_and_observation_refuse_before_launch(self):
        self.assertEqual(runner.gate(environment()), 20)
        for value in ('0', '21', '-1', '01', '+1', '1.0', '', ' 2', '2\n', '$(id)', True, 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner.count(value)
        for key, values in {'GITHUB_EVENT_NAME': ['push', 'pull_request'], 'IMAGE_REPEAT_MODE': ['compare'],
                            'EXPECTED_SOURCE_SHA': ['', 'a' * 39, 'A' * 40, 'b' * 40],
                            'STALLIONFS_TEST_IMAGES': ['0'],
                            'STALLIONFS_TEST_SNAPSHOT_OBSERVATION': ['restored-cleanup', 'enospc-initial-detach'],
                            'RUNNER_ARCH': ['X64'], 'RUNNER_OS': ['Linux']}.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    runner.gate(dict(environment(), **{key: value}))

    def test_selector_and_actual_platform_refuse_before_any_test_import(self):
        with self.assertRaisesRegex(ValueError, 'Exact test selector'):
            runner.invoke(ROOT, Path('/unused'), 'test_images_space')
        with patch.object(runner.platform, 'mac_ver', return_value=('27.0', (), '')), \
                self.assertRaisesRegex(ValueError, 'actual macOS 26'):
            runner.invoke(ROOT, Path('/unused'), runner.SELECTOR)


class Repetitions(unittest.TestCase):
    def execute(self, count=20, failure=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / 'results'
            calls = []
            def command(argv, **kwargs):
                calls.append((argv, kwargs, dict(capture._COMMAND_ENV)))
                invocation = kwargs['cwd']
                index = len(calls)
                value = {'scope': 'diagnostic-only', 'full_qualification': False, 'passed': True,
                         'selector': runner.SELECTOR, 'observation': runner.OBSERVATION}
                if index == 2:
                    if failure == 'exception': raise TimeoutError('inert capture timeout')
                    if failure == 'failure': return subprocess.CompletedProcess(argv, 1)
                    if failure == 'missing': return subprocess.CompletedProcess(argv, 0)
                    if failure == 'observation': value['observation'] = 'restored-cleanup'
                    if failure == 'result': value['passed'] = False
                    if failure == 'scope': value['full_qualification'] = True
                    if failure == 'cleanup': (invocation / 'tmp/retained').write_bytes(b'fixture')
                    if failure == 'capture': capture._command_state['failure'] = 'uncertain'
                (invocation / 'result.json').write_text(json.dumps(value))
                return subprocess.CompletedProcess(argv, 0)
            capture = SimpleNamespace(_owned_command=command, _command_state={})
            if failure:
                with self.assertRaises((ValueError, RuntimeError, OSError, subprocess.CalledProcessError)):
                    runner.repeat(ROOT, root, count, capture)
            else:
                runner.repeat(ROOT, root, count, capture)
            summary = json.loads((root / 'summary.json').read_bytes())
            self.assertEqual(summary['passed'], not bool(failure))
            self.assertIs(summary['full_qualification'], False)
            self.assertEqual(summary['completed'], 1 if failure else count)
            self.assertEqual(len(calls), 2 if failure else count)
            self.assertEqual(len({str(kwargs['cwd']) for _, kwargs, _ in calls}), len(calls))
            for argv, kwargs, env in calls:
                self.assertEqual(argv[:3], [sys.executable, '-I', '-B'])
                self.assertEqual(argv[-2:], ['--selector', runner.SELECTOR])
                self.assertEqual(kwargs['timeout'], runner.CHILD_SECONDS)
                self.assertEqual(env['TMPDIR'], str(kwargs['cwd'] / 'tmp'))
                self.assertEqual(kwargs['stem'], kwargs['cwd'] / 'child')
            self.assertTrue((root / 'iteration-02').exists() if failure else (root / f'iteration-{count:02d}').exists())

    def test_exact_one_and_twenty_fresh_invocations(self):
        self.execute(1)
        self.execute(20)

    def test_real_collector_uses_fresh_python_and_tmpdir_for_each_invocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inert = root / 'inert.py'
            inert.write_text("import json, os; from pathlib import Path; "
                "Path('result.json').write_text(json.dumps({'scope':'diagnostic-only', "
                "'full_qualification':False, 'passed':True, 'selector':" + repr(runner.SELECTOR) +
                ", 'observation':" + repr(runner.OBSERVATION) +
                ", 'pid':os.getpid(), 'tmp':os.environ['TMPDIR']}))")
            capture = runner.load('inert_repeat_capture', ROOT / 'tools/_git_capture.py')
            original = capture._owned_command
            def command(argv, **kwargs):
                # Exercise real capture with a harmless script in place of ImageSpace.
                return original([*argv[:3], str(inert)], **kwargs)
            with patch.object(capture, '_owned_command', side_effect=command):
                runner.repeat(ROOT, root / 'results', 2, capture)
            paths = sorted((root / 'results').glob('iteration-*'))
            values = [json.loads((path / 'result.json').read_bytes()) for path in paths]
            self.assertNotEqual(values[0]['pid'], values[1]['pid'])
            for path, value in zip(paths, values):
                self.assertEqual(value['tmp'], str(path / 'tmp'))
                record = json.loads((path / 'child.command.json').read_bytes())
                self.assertEqual(record['returncode'], 0)
                self.assertFalse(record['cleanup_uncertain'])
                self.assertIsNone(record['first_failure'])

    def test_first_failure_skip_observation_cleanup_or_capture_stops(self):
        for failure in ('exception', 'failure', 'missing', 'observation', 'result', 'scope', 'cleanup', 'capture'):
            with self.subTest(failure=failure): self.execute(failure=failure)

    def test_invalid_count_or_existing_root_never_spawns(self):
        capture = Mock()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for count in (0, 21, True, '2'):
                with self.assertRaises(ValueError): runner.repeat(ROOT, root / 'unused', count, capture)
            with self.assertRaises(FileExistsError): runner.repeat(ROOT, root, 1, capture)
            capture._owned_command.assert_not_called()


class IntelCampaigns(unittest.TestCase):
    def env(self):
        return dict(environment(), IMAGE_REPEAT_MODE=runner.INTEL_MODE, RUNNER_ARCH='X64',
                    IMAGE_REPEAT_COUNT='10', GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1',
                    GITHUB_JOB='image-space-repeat')

    def test_gate_binds_architecture_count_and_hosted_run(self):
        self.assertEqual(runner.gate(self.env()), 10)
        for key, value in [('RUNNER_ARCH', 'ARM64'), ('IMAGE_REPEAT_COUNT', '11'),
                           ('GITHUB_RUN_ID', ''), ('GITHUB_RUN_ATTEMPT', '0'), ('GITHUB_JOB', '')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                runner.gate(dict(self.env(), **{key: value}))
        self.assertEqual(runner.selectors_for(environment()), (runner.SELECTOR,))
        self.assertEqual(runner.selectors_for(self.env()), (runner.SELECTOR, runner.SNAPSHOT))

    def test_pairs_stop_at_first_incomplete_test_with_honest_counts(self):
        for failure in (None, 'space', 'snapshot', 'binding', 'skip', 'cleanup'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary, \
                    patch.dict(os.environ, self.env()):
                root = Path(temporary).resolve() / 'campaign'
                calls = []
                def command(argv, **kwargs):
                    selector = argv[-1]
                    calls.append(selector)
                    directory = kwargs['cwd']
                    value = dict(scope='diagnostic-only', full_qualification=False, passed=True,
                                 selector=selector, observation=runner.OBSERVATION if selector == runner.SELECTOR else None,
                                 binding=runner.binding(os.environ))
                    if (failure == 'space' and len(calls) == 1) or (failure == 'snapshot' and len(calls) == 2):
                        return subprocess.CompletedProcess(argv, 1)
                    if len(calls) == 2:
                        if failure == 'binding': value['binding']['GITHUB_RUN_ATTEMPT'] = '2'
                        if failure == 'skip': value['passed'] = False
                        if failure == 'cleanup': (directory / 'tmp/retained').write_bytes(b'inert')
                    (directory / 'result.json').write_text(json.dumps(value))
                    self.assertEqual(kwargs['timeout'], 180)
                    self.assertEqual(capture._COMMAND_ENV['TMPDIR'], str(directory / 'tmp'))
                    return subprocess.CompletedProcess(argv, 0)
                capture = SimpleNamespace(_owned_command=command, _command_state={})
                if failure:
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        runner.repeat(ROOT, root, 3, capture)
                else:
                    runner.repeat(ROOT, root, 3, capture)
                status = json.loads((root / 'summary.json').read_bytes())
                self.assertEqual(status['completed'], 0 if failure else 3)
                self.assertEqual(status['completed_tests'], (0 if failure == 'space' else 1) if failure else 6)
                self.assertEqual(status['attempted_tests'], len(calls))
                self.assertEqual(calls, [runner.SELECTOR] if failure == 'space' else
                                 [runner.SELECTOR, runner.SNAPSHOT] * (1 if failure else 3))
                self.assertEqual(len(list(root.glob('iteration-*'))), len(calls))
                self.assertEqual(status['passed'], failure is None)

    def test_snapshot_requires_complete_evidence_for_any_raw_failure(self):
        for field in ('capture_disabled', 'attempts', 'before_attempts'):
            diagnostic = SimpleNamespace(capture_disabled=False, attempts=0, before_attempts=0)
            runner.snapshot_complete(diagnostic, None)
            setattr(diagnostic, field, True)
            with self.assertRaises(ValueError): runner.snapshot_complete(diagnostic, None)

    def test_snapshot_suite_accepts_only_one_complete_success(self):
        for outcome in ('pass', 'skip', 'failure', 'expected-failure', 'zero', 'two'):
            class Fixture(unittest.TestCase):
                def runTest(self):
                    if outcome == 'skip': self.skipTest('inert')
                    if outcome in ('failure', 'expected-failure'): self.fail('inert')
            if outcome == 'expected-failure': Fixture.runTest = unittest.expectedFailure(Fixture.runTest)
            suite = unittest.TestSuite([Fixture() for _ in range(0 if outcome == 'zero' else 2 if outcome == 'two' else 1)])
            diagnostic = SimpleNamespace(capture_disabled=False, attempts=0, before_attempts=0)
            with self.subTest(outcome=outcome), redirect_stderr(io.StringIO()):
                if outcome == 'pass': runner.run_suite(suite, None, diagnostic, None, [])
                else:
                    with self.assertRaisesRegex(ValueError, 'Exact test failed'):
                        runner.run_suite(suite, None, diagnostic, None, [])

    def test_snapshot_selector_cannot_enter_arm_or_wrong_intel_interpreter(self):
        with patch.dict(os.environ, environment()), self.assertRaisesRegex(ValueError, 'Exact test selector'):
            runner.invoke(ROOT, Path('/unused'), runner.SNAPSHOT)
        for architecture, python in [('arm64', (3, 13)), ('x86_64', (3, 11))]:
            with patch.dict(os.environ, self.env()), patch.object(runner.sys, 'platform', 'darwin'), \
                    patch.object(runner.platform, 'mac_ver', return_value=('26.0', (), '')), \
                    patch.object(runner.platform, 'machine', return_value=architecture), \
                    patch.object(runner.sys, 'version_info', python), \
                    self.assertRaisesRegex(ValueError, 'actual macOS 26'):
                runner.invoke(ROOT, Path('/unused'), runner.SNAPSHOT)


class Observations(unittest.TestCase):
    def validate(self, rows, available=True, **kwargs):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'image-failures.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
            parser = runner.load('inert_image_parser', ROOT / 'tests/image_failure_diagnostics.py')
            module = SimpleNamespace(REPORT='image-failures.jsonl', artifact_available=Mock(return_value=available),
                                     Diagnostics=parser.Diagnostics)
            diagnostic = SimpleNamespace(capture_disabled=False, before_attempts=1, attempts=0)
            diagnostic.__dict__.update(kwargs)
            with patch.dict(sys.modules, image_failure_diagnostics=module):
                runner.observation_complete(diagnostic, directory)

    def test_complete_exact_observation(self):
        self.validate(events())

    @contextmanager
    def collected(self, overrides=None, observed=None):
        module = runner.load('inert_image_diagnostics', ROOT / 'tests/image_failure_diagnostics.py')
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            image = base / 'sibling.sparseimage'
            image.write_bytes(b'inert fixture'); image.chmod(0o600)
            point = base / 'sibling'; point.mkdir(mode=0o700)
            info = image.stat()
            collector = module.Diagnostics(base / 'diagnostics')
            captured = dict(returncode=0, stderr=b'', timeout=False, truncated=False,
                            reaped=True, capture_error=None, cleanup_error=None)
            holder = f'p10\ncworker\nf3\ntREG\nD{info.st_dev:#x}\ni{info.st_ino}\nn{image}\n'.encode()
            captures = [dict(captured, stdout=holder), dict(captured, stdout=b'')]
            devices, volume = ['/dev/disk8', '/dev/disk9s1'], '/dev/disk9s1'
            if observed:
                mapping = observed[1]
                devices, volume = mapping['devices'], mapping['volume_device']
                for index, row in enumerate(observed[2:]):
                    captures[index] = {key: row[key] for key in captured}
                    captures[index]['stderr'] = row['stderr'].encode()
                    captures[index]['stdout'] = row['stdout'].replace(mapping['image'], str(image)).replace(
                        f"D{mapping['backing_device']:#x}", f'D{info.st_dev:#x}').replace(
                        f"i{mapping['backing_inode']}\n", f'i{info.st_ino}\n').encode()
            for index, values in (overrides or {}).items():
                captures[index].update(values)
                if callable(captures[index]['stdout']):
                    captures[index]['stdout'] = captures[index]['stdout'](holder)
            real_stat = os.stat
            def device_stat(path, *args, **kwargs):
                if str(path) == volume: return SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=42)
                if str(path) == str(point): return SimpleNamespace(st_dev=42)
                return real_stat(path, *args, **kwargs)
            with patch.object(collector, '_mapping', return_value=(str(image), devices,
                    str(point), volume, (info.st_dev, info.st_ino))), \
                    patch.object(collector, '_capture', side_effect=captures) as capture, \
                    patch.object(module.os.path, 'ismount', return_value=True), patch.object(module.os, 'stat', side_effect=device_stat):
                collector.before(('/usr/bin/hdiutil', 'eject', devices[0]),
                    dict(base=base, image=image, mountpoint=point, stage='sibling-detach', workspace=None, expected=False),
                    observation={})
                if observed:
                    self.assertEqual([call.args[0] for call in capture.call_args_list], [
                        ['/usr/sbin/lsof', '-nP', '-F', 'pcftDin', '--', str(image), *devices,
                         *['/dev/r' + device.removeprefix('/dev/') for device in devices]],
                        ['/usr/sbin/lsof', '-nP', '-F', 'pcftDin', '+f', '--', str(point)]])
            try:
                with patch.dict(sys.modules, image_failure_diagnostics=module):
                    yield module, collector, image
            finally:
                collector.close()

    def test_accepts_existing_collector_output_without_native_commands(self):
        with self.collected() as (_, collector, _):
            runner.observation_complete(collector, collector.directory)

    def test_collector_empty_no_match_query_succeeds(self):
        with self.collected({1: dict(returncode=1, stdout=b'')}) as (module, collector, _):
            self.assertTrue(module.artifact_available(collector.directory))
            runner.observation_complete(collector, collector.directory)

    def test_exact_sanitized_mixed_selection_receipt_and_collector_replay(self):
        # Preserve the observed structured stdout and both exit-1 results. The
        # collector replay binds only paths and inode identity to an inert file.
        raw = (ROOT / 'tests/fixtures/image-space-mixed-selection.jsonl').read_bytes()
        rows = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual([row['returncode'] for row in rows[2:]], [1, 1])
        module = runner.load('inert_image_diagnostics', ROOT / 'tests/image_failure_diagnostics.py')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            report = directory / module.REPORT
            report.write_bytes(raw); report.chmod(0o600)
            diagnostic = SimpleNamespace(capture_disabled=False, before_attempts=1, attempts=0)
            with patch.dict(sys.modules, image_failure_diagnostics=module):
                runner.observation_complete(diagnostic, directory)
            self.assertEqual(report.read_bytes(), raw)
        with self.collected(observed=rows) as (module, collector, _):
            self.assertTrue(module.artifact_available(collector.directory))
            runner.observation_complete(collector, collector.directory)
            replay = [json.loads(line) for line in (collector.directory / module.REPORT).read_bytes().splitlines()]
            self.assertEqual([row['returncode'] for row in replay[2:]], [1, 1])
            self.assertTrue(replay[2]['stdout'].startswith('p2993\ncdiskimages-helper\nf3\ntREG\n'))
            self.assertEqual(replay[3]['stdout'], '')

    def assert_refused_and_retained(self, module, collector, image):
        report = collector.directory / module.REPORT
        raw = report.read_bytes()
        with self.assertRaises(ValueError):
            runner.observation_complete(collector, collector.directory)
        class Fixture(unittest.TestCase):
            cleaned = False
            retain = False
            def setUp(self): self.addCleanup(self.clean)
            def runTest(self): pass
            def clean(self):
                self.cleaned = True
                if not self.retain: image.unlink()
        test = Fixture()
        with redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, 'Exact test failed'):
            runner.run_suite(unittest.TestSuite([test]), Fixture, collector, collector.directory, [])
        self.assertTrue(test.retain)
        self.assertFalse(test.cleaned)
        self.assertEqual(image.read_bytes(), b'inert fixture')
        self.assertEqual(report.read_bytes(), raw)

    def test_collector_holder_errors_in_either_query_fail_and_retain_fixture(self):
        for index in (0, 1):
            for returncode in (0, 1):
                with self.subTest(query=index, returncode=returncode), self.collected({index: dict(
                        returncode=returncode, stderr=b'lsof: Permission denied')}) as (module, collector, image):
                    # A complete artifact is evidence of capture, not a successful query.
                    self.assertTrue(module.artifact_available(collector.directory))
                    self.assert_refused_and_retained(module, collector, image)

    def test_collector_partial_queries_fail_and_retain_fixture(self):
        for index in (0, 1):
            for values in (dict(returncode=2), dict(truncated=True), dict(timeout=True),
                           dict(reaped=False), dict(capture_error='read'), dict(cleanup_error='reap')):
                overrides = dict(values)
                if index == 1: overrides['stdout'] = lambda holder: holder
                with self.subTest(query=index, values=values), self.collected({index: overrides}) as (module, collector, image):
                    self.assert_refused_and_retained(module, collector, image)

    def test_collector_malformed_stdout_in_either_query_fails_and_retains(self):
        for index in (0, 1):
            for returncode in (0, 1):
                for malformed in (b'garbage\n', b'p10\ncworker\nf3\n', b'f3\ntREG\nn/name\n',
                                  b'p10\ncworker\nf3\ntREG\nDnot-device\ni2\nn/name\n'):
                    with self.subTest(query=index, status=returncode, stdout=malformed), self.collected({index:
                            dict(returncode=returncode, stdout=malformed)}) as (module, collector, image):
                        self.assert_refused_and_retained(module, collector, image)
        for index in (0, 1):
            # A matched backing record must not hide malformed trailing output.
            for suffix in (b'garbage\n', b'f4\n', b'p20\ncother\n', b'i2\n'):
                with self.subTest(query=index, suffix=suffix), self.collected({index:
                        dict(returncode=1, stdout=lambda holder: holder + suffix)}) as (module, collector, image):
                    self.assert_refused_and_retained(module, collector, image)

    def test_valid_nonempty_filesystem_output_with_exit_one_is_accepted(self):
        def records(holder):
            return holder + b'f4\ntCHR\nn/dev/rdisk8\np20\ncother\nf5' + holder.split(b'f3', 1)[1]
        with self.collected({0: dict(returncode=1), 1: dict(returncode=1,
                stdout=records)}) as (_, collector, _):
            runner.observation_complete(collector, collector.directory)

    def test_empty_backing_query_cannot_establish_identity(self):
        with self.collected({0: dict(returncode=1, stdout=b'')}) as (module, collector, image):
            self.assert_refused_and_retained(module, collector, image)

    def test_malformed_retained_stdout_cannot_claim_a_valid_identity(self):
        for index in (2, 3):
            for stdout in ('garbage', 'p10\ncworker\nf3', 'f3\ntREG\nn/name'):
                rows = events(); rows[index]['stdout'] = stdout
                with self.subTest(query=index, stdout=stdout), self.assertRaises(ValueError):
                    self.validate(rows)

    def test_malformed_holder_errors_fail_and_retain_fixture(self):
        for index in (2, 3):
            for value in (None, False, [], 'lsof: Permission denied'):
                with self.subTest(query=index, stderr=value), self.collected() as (module, collector, image):
                    report = collector.directory / module.REPORT
                    rows = [json.loads(line) for line in report.read_bytes().splitlines()]
                    rows[index]['stderr'] = value
                    report.write_text(''.join(json.dumps(row) + '\n' for row in rows))
                    self.assert_refused_and_retained(module, collector, image)

    def test_incomplete_mapping_capture_identity_and_wrong_selection_refuse(self):
        for index, key, value in [(0, 'stage', 'body'), (0, 'pre_observation', 'unavailable'),
                (1, 'mountpoint_matches', False), (1, 'backing_identity_matches_first', False),
                (1, 'image', '/fixture/full.sparseimage'), (1, 'operation_id', 2),
                (2, 'returncode', 2), (2, 'reaped', False), (2, 'timeout', True), (2, 'truncated', True),
                (2, 'display_truncated', True), (2, 'capture_error', 'read'), (3, 'cleanup_error', 'reap'),
                (2, 'backing_identity_status', 'unavailable'), (3, 'backing_inode_after', 9)]:
            rows = copy.deepcopy(events()); rows[index][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.validate(rows)
        for rows in ([], events()[:-1], [*events(), {'kind': 'unavailable'}]):
            with self.assertRaises(ValueError): self.validate(rows)
        for options in ({'available': False}, {'capture_disabled': True}, {'attempts': 1}, {'before_attempts': 0}):
            with self.assertRaises(ValueError): self.validate(events(), **options)

    def test_incomplete_observation_retains_fixture_before_cleanup(self):
        class Fixture(unittest.TestCase):
            cleaned = False
            retain = False
            def setUp(self): self.addCleanup(self.clean)
            def runTest(self): pass
            def clean(self): type(self).cleaned = True
        test = Fixture()
        with patch.object(runner, 'observation_complete', side_effect=ValueError('incomplete')), redirect_stderr(io.StringIO()):
            with self.assertRaises(ValueError):
                runner.run_suite(unittest.TestSuite([test]), Fixture, None, None, [])
        self.assertTrue(test.retain)
        self.assertFalse(Fixture.cleaned)

    def test_skip_and_failure_cannot_qualify(self):
        for outcome in ('skip', 'failure'):
            class Fixture(unittest.TestCase):
                def setUp(self): self.addCleanup(self.clean)
                def runTest(self):
                    if outcome == 'skip': self.skipTest('inert')
                    self.fail('inert')
                def clean(self): pass
            with patch.object(runner, 'observation_complete'), redirect_stderr(io.StringIO()), self.assertRaises(ValueError):
                runner.run_suite(unittest.TestSuite([Fixture()]), Fixture, None, None, [])

    def test_direct_command_children_are_reaped_without_signaling(self):
        with runner.owned_children() as children:
            child = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'pass'])
            child.wait(timeout=5)
            self.assertEqual(runner.child_status(children), [{'pid': child.pid, 'returncode': 0}])
        live = Mock(pid=999); live.poll.return_value = None
        with self.assertRaisesRegex(ValueError, 'completion uncertain'): runner.child_status([live])
        live.kill.assert_not_called(); live.terminate.assert_not_called()
        live.poll.side_effect = OSError('unknown reap')
        self.assertEqual(runner.child_status([live], complete=False),
                         [{'pid': 999, 'returncode': None, 'error': 'OSError'}])
        with self.assertRaises(ValueError): runner.child_status([live])

    def test_close_admission_and_retained_fixture_prevent_child_success(self):
        for selector, failure in [(s, f) for s in (runner.SELECTOR, runner.SNAPSHOT)
                                  for f in (None, 'close', 'admission', 'fixture')]:
            with self.subTest(selector=selector, failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve(); (root / 'tmp').mkdir()
                diagnostic = Mock(attempts=0)
                if failure == 'close': diagnostic.close.side_effect = OSError('close failed')
                admitted = {'check': Mock(side_effect=[None, ValueError('late admission')] if failure == 'admission' else None)}
                fixture = SimpleNamespace(__file__=str(ROOT / 'tests/test_images_space.py'), ImageSpace=Mock())
                package = SimpleNamespace(__file__='/installed/stallionfs/__init__.py',
                    images=SimpleNamespace(__file__='/installed/stallionfs/images.py'),
                    _scan=SimpleNamespace(__file__='/installed/stallionfs/_scan.so'))
                modules = {'stallionfs': package, 'test_images_space': fixture,
                    'image_failure_diagnostics': SimpleNamespace(install=Mock(return_value=diagnostic))}
                if selector == runner.SNAPSHOT:
                    fixture.__file__ = str(ROOT / 'tests/test_image_store.py')
                    modules['test_image_store'] = fixture
                env = environment() if selector == runner.SELECTOR else IntelCampaigns().env()
                version = (3, 11) if selector == runner.SELECTOR else (3, 13)
                machine = 'arm64' if selector == runner.SELECTOR else 'x86_64'
                test = Mock(); test.id.return_value = selector
                suite = [test]
                class Suite(list):
                    def countTestCases(self): return 1
                if failure == 'fixture': (root / 'tmp/retained').write_bytes(b'inert')
                with patch.dict(sys.modules, modules), patch.dict(os.environ, dict(env, TMPDIR=str(root / 'tmp'), RUNNER_TEMP=str(root))), \
                        patch.object(runner.sys, 'platform', 'darwin'), patch.object(runner.sys, 'version_info', version), \
                        patch.object(runner.platform, 'mac_ver', return_value=('26.0', (), '')), \
                        patch.object(runner.platform, 'machine', return_value=machine), patch.object(runner.Path, 'cwd', return_value=root), \
                        patch.object(runner, 'load', return_value=SimpleNamespace(initialize_installed=Mock(return_value=admitted))), \
                        patch.object(runner.unittest.defaultTestLoader, 'loadTestsFromName', return_value=Suite(suite)), \
                        patch.object(runner, 'run_suite') as run, patch.object(runner, 'observation_complete'), \
                        patch.object(runner, 'snapshot_complete'), patch.object(runner, 'bind_test_sources', return_value=Mock()):
                    if failure:
                        with self.assertRaises((ValueError, OSError)): runner.invoke(ROOT, root, selector)
                    else:
                        runner.invoke(ROOT, root, selector)
                self.assertEqual(run.call_args.args[1], fixture.ImageSpace if selector == runner.SELECTOR else None)
                value = json.loads((root / 'result.json').read_bytes())
                self.assertEqual(value['passed'], failure is None)
                self.assertIs(value['full_qualification'], False)
                self.assertEqual(value['owned_children'], [])
                diagnostic.close.assert_called_once()
                self.assertTrue((root / 'tmp/retained').exists() if failure == 'fixture' else True)

    def test_child_cap_refuses_before_spawn(self):
        with patch.object(runner, 'MAX_CHILDREN', 0), runner.owned_children():
            with self.assertRaisesRegex(ValueError, 'child count'):
                subprocess.Popen([sys.executable, '-I', '-B', '-c', 'raise SystemExit(8)'])


@contextmanager
def inert_sources():
    # The extension is not built here. Any use of its sole import must fail.
    # Exercise the real Python detach, diagnostic producer and fixture context.
    before = set(sys.modules)
    sys.path.insert(0, str(ROOT / 'tests'))
    try:
        with patch.dict(sys.modules, {'stallionfs._scan': SimpleNamespace(
                _private_directory=Mock(side_effect=AssertionError('native extension forbidden')))}):
            from stallionfs import images
            import image_failure_diagnostics as diagnostics
            import test_image_store as lifecycle
            with patch.object(subprocess, 'Popen', side_effect=AssertionError('native command forbidden')):
                yield images, diagnostics, lifecycle
    finally:
        sys.path.pop(0)
        for name in set(sys.modules) - before:
            if name.startswith('stallionfs') or name in ('test_image_store', 'image_failure_diagnostics'):
                sys.modules.pop(name, None)


class RecoveryAcceptance(unittest.TestCase):
    @contextmanager
    def recovered(self, *, selected=False, recover=True, busy=0):
        import plistlib
        with inert_sources() as (images, module, lifecycle), tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            image, point = base / ('sibling.sparseimage' if selected else 'owned.sparseimage'), base / 'volume'
            image.write_bytes(b'inert owned fixture'); image.chmod(0o600)
            point.mkdir(mode=0o700)
            device = '/dev/disk999'
            entries = [{'dev-entry': device}, {'dev-entry': device+'s1', 'mount-point': str(point)}]
            current = dict(image=str(image), device=device, mountpoint=str(point), volume_device=device+'s1',
                           attachment=plistlib.dumps({'system-entities': entries}))
            unmounted = dict(current, mountpoint=None, volume_device=None,
                             attachment=images._unmounted_snapshot(current, point))
            states = iter([current, current, *[unmounted] * (2 * (busy + 1)), None])
            def mounted(path):
                images._attachments(path)  # Real producer records only normal pre-command inventories.
                return next(states)
            args = ('/usr/sbin/diskutil', 'eject', device)
            failure = images._CommandFailure(args, subprocess.CompletedProcess(args, 1 if recover else 16, b'', b'Volume failed to eject'))
            captured = dict(returncode=1, stdout=b'', stderr=b'', reaped=True, timeout=False,
                            truncated=False, capture_error=None, cleanup_error=None)
            detach = ('/usr/bin/hdiutil', 'detach', device)
            held = images._CommandFailure(detach, subprocess.CompletedProcess(detach, 16, b'',
                f'hdiutil: couldn\'t eject "{device.removeprefix("/dev/")}" - Resource busy'.encode()))
            with patch.object(images, '_command', side_effect=[failure, *[held] * busy, b'']) as command, \
                    patch.object(images.time, 'sleep'), \
                    patch.object(images, 'mounted', side_effect=mounted), \
                    patch.object(images, '_attachments', return_value=[{'system-entities': entries}]), \
                    patch.object(images, '_device_identity', return_value=(2, 100, 20, 0o60600)), \
                    patch.object(images, '_no_graph_mounts'), patch.object(images, '_directory'):
                collector = module.install(images, base / 'diagnostics')
                try:
                    with patch.object(collector, '_mapping', return_value=(str(image), [device, device+'s1'],
                            None, None, (image.stat().st_dev, image.stat().st_ino))), \
                            patch.object(collector, '_capture', return_value=captured), \
                            module.failure_scope(base, image, mountpoint=point):
                        if recover:
                            images.detach(image, point)
                        else:
                            with self.assertRaises(images._CommandFailure): images.detach(image, point)
                    self.assertEqual(command.call_count, 2 + busy if recover else 1)
                    self.assertEqual(collector.attempts, 1)
                    self.assertTrue(module.artifact_available(collector.directory))
                    yield collector, module, lifecycle, image
                finally:
                    module.Diagnostics.close(collector)

    def test_actual_producer_recovery_qualifies_without_erasing_raw_failure(self):
        with self.recovered() as (collector, module, _, _):
            runner.snapshot_complete(collector, collector.directory)
            rows = [json.loads(line) for line in (collector.directory / module.REPORT).read_bytes().splitlines()]
            self.assertEqual(len([r for r in rows if r['kind'] == 'failure']), 1)
            self.assertEqual(collector.attempts, 1)
            with patch.dict(os.environ, IMAGE_REPEAT_MODE=runner.INTEL_MODE):
                runner.recovery_complete(collector, rows)

    def test_busy_detach_retries_qualify_as_one_recovery(self):
        with self.recovered(busy=2) as (collector, module, _, _):
            runner.snapshot_complete(collector, collector.directory)
            rows = [json.loads(line) for line in (collector.directory / module.REPORT).read_bytes().splitlines()]
            self.assertEqual(len([r for r in rows if r['kind'] == 'failure']), 1)
            self.assertEqual([r['attempt'] for r in rows if r['kind'] == 'eject_command'], [1, 2, 3])
            self.assertEqual(next(r for r in rows if r['kind'] == 'eject_outcome')['commands'], 4)
            with patch.dict(os.environ, IMAGE_REPEAT_MODE=runner.INTEL_MODE):
                runner.recovery_complete(collector, rows)
                for key, value in (('returncode', 1), ('attempt', 5), ('device', '/dev/disk123')):
                    changed = copy.deepcopy(rows)
                    [r for r in changed if r['kind'] == 'eject_command'][1][key] = value
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        runner.recovery_complete(collector, changed)

    def test_actual_unqualified_failure_refuses(self):
        with self.recovered(recover=False) as (collector, _, _, _):
            with self.assertRaises(ValueError):
                runner.snapshot_complete(collector, collector.directory)

    def test_saturated_raw_failure_budget_refuses(self):
        with self.recovered() as (collector, module, _, _):
            collector.attempts = module.ATTEMPTS
            with self.assertRaisesRegex(ValueError, 'artifact incomplete'):
                runner.snapshot_complete(collector, collector.directory)

    def test_unmatched_incomplete_or_unqualified_recovery_refuses(self):
        with self.recovered() as (collector, module, _, _):
            report = collector.directory / module.REPORT
            original = [json.loads(line) for line in report.read_bytes().splitlines()]
            mutations = [('eject_outcome', 'commands', 1), ('eject_outcome', 'continuation_status', 1),
                         ('eject_outcome', 'outcome', 'failed'), ('eject_outcome', 'operation_id', 999),
                         ('eject_command', 'returncode', 16), ('eject_command', 'complete', False),
                         ('eject_command', 'device', '/dev/disk123'), ('validation', 'selected_device', '/dev/disk123'),
                         ('failure', 'operation', 'create'), ('failure', 'expected_busy', True)]
            candidates = []
            for kind, key, value in mutations:
                rows = copy.deepcopy(original)
                next(r for r in rows if r['kind'] == kind)[key] = value
                candidates.append(rows)
            for kind in ('failure', 'eject_command', 'validation', 'eject_outcome'):
                candidates.append([r for r in original if r['kind'] != kind])
            candidates.append(original + [next(r for r in original if r['kind'] == 'failure')])
            for rows in candidates:
                with self.subTest(rows=rows):
                    report.write_text(''.join(json.dumps(r)+'\n' for r in rows))
                    with self.assertRaises(ValueError): runner.snapshot_complete(collector, collector.directory)

    def test_intel_space_accepts_qualified_recovery_and_arm_still_refuses(self):
        with self.recovered() as (collector, module, _, _):
            after = [json.loads(line) for line in (collector.directory / module.REPORT).read_bytes().splitlines()]
            for row in after: row['operation_id'] = 2
            with Observations().collected() as (before_module, before_collector, _):
                report = before_collector.directory / before_module.REPORT
                before = [json.loads(line) for line in report.read_bytes().splitlines()]
                report.write_text(''.join(json.dumps(r)+'\n' for r in before + after))
                before_collector.attempts = 1
                with patch.dict(os.environ, IMAGE_REPEAT_MODE=runner.INTEL_MODE):
                    runner.observation_complete(before_collector, before_collector.directory)
                    after[-2]['operation_id'] = 999
                    report.write_text(''.join(json.dumps(r)+'\n' for r in before + after))
                    with self.assertRaises(ValueError):
                        runner.observation_complete(before_collector, before_collector.directory)
                with patch.dict(os.environ, IMAGE_REPEAT_MODE=runner.MODE), self.assertRaises(ValueError):
                    runner.observation_complete(before_collector, before_collector.directory)

    def test_source_binding_detects_cleanup_source_change(self):
        import shutil
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            names = ('tools/ci_image_repeat.py', 'tests/test_images_space.py',
                     'tests/test_image_store.py', 'tests/image_failure_diagnostics.py')
            for name in names:
                path = checkout / name; path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, path)
            def show(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 0, (checkout / argv[-1].split(':', 1)[1]).read_bytes())
            with patch.object(subprocess, 'run', side_effect=show), patch.dict(os.environ, GITHUB_SHA='a'*40):
                check = runner.bind_test_sources(checkout)
            check()
            (checkout / 'tests/test_image_store.py').write_text('changed cleanup')
            with self.assertRaisesRegex(ValueError, 'cleanup source differs'): check()

    def test_real_fixture_guard_runs_before_removal_and_preserves_on_refusal(self):
        for failure in (None, 'diagnostics', 'child', 'close', 'source'):
            with self.subTest(failure=failure), self.recovered() as (collector, module, lifecycle, image):
                base = image.parent / 'fixture'; base.mkdir()
                sentinel = base / 'sentinel'; sentinel.write_bytes(b'keep')
                store = SimpleNamespace(root=base / 'store', list=lambda: [])
                class Fixture(unittest.TestCase):
                    def runTest(self):
                        with lifecycle.image_fixture(store, base):
                            pass
                check = Mock(side_effect=ValueError('source changed') if failure == 'source' else None)
                child = Mock(pid=999); child.poll.return_value = None if failure == 'child' else 0
                if failure == 'diagnostics': collector.capture_disabled = True
                if failure == 'close': self.enterContext(patch.object(collector, 'close', side_effect=OSError('close failed')))
                def remove(path):
                    self.assertEqual(path, base)
                    self.assertTrue(collector.closed)
                    check.assert_called_once()
                    sentinel.unlink(); base.rmdir()
                with patch.object(lifecycle, 'remove_tree', side_effect=remove) as removed, redirect_stderr(io.StringIO()):
                    if failure:
                        with self.assertRaises(ValueError):
                            runner.run_suite(unittest.TestSuite([Fixture()]), None, collector, collector.directory,
                                             [child], snapshot_module=lifecycle, acceptance=check)
                        removed.assert_not_called()
                        self.assertEqual(sentinel.read_bytes(), b'keep')
                    else:
                        runner.run_suite(unittest.TestSuite([Fixture()]), None, collector, collector.directory,
                                         [child], snapshot_module=lifecycle, acceptance=check)
                        removed.assert_called_once_with(base)


class Workflow(unittest.TestCase):
    def test_manual_route_reuses_setup_and_preserves_required_gates(self):
        from test_ci_build import job, step, INSTALLED, SANITIZERS, rows
        text = (ROOT / '.github/workflows/checks.yml').read_text()
        manual = job(text, runner.MODE)
        for value in ("if: github.event_name == 'workflow_dispatch' && (inputs.mode == 'image-space-repeat' || inputs.mode == 'image-space-repeat-intel')",
                      "runs-on: ${{ inputs.mode == 'image-space-repeat-intel' && 'macos-26-intel' || 'macos-26' }}",
                      "python-version: ${{ inputs.mode == 'image-space-repeat-intel' && '3.13' || '3.11' }}", 'persist-credentials: false',
                      'ref: ${{ github.sha }}', 'STALLIONFS_TEST_SNAPSHOT_OBSERVATION: enospc-sibling-detach',
                      'IMAGE_REPEAT_COUNT: ${{ inputs.repeat-count }}', 'module.gate(os.environ)',
                      'if: always()', '/iteration-*/diagnostics/image-failures.jsonl'):
            self.assertIn(value, manual)
        self.assertNotIn('needs:', manual)
        for anchor in ('ci-owned-python', 'ci-wheel-backend', 'ci-component-fetch', 'ci-wheel-build', 'ci-wheel-install'):
            self.assertIn('run: &' + anchor + ' |', job(text, 'test-execution'))
            self.assertIn('run: *' + anchor, manual)
        self.assertLess(manual.index('module.gate(os.environ)'), manual.index('run: *ci-owned-python'))
        cells = rows(job(text, 'test-execution'), True)
        self.assertCountEqual([row[:3] for row in cells if row[3] == 'installed'], INSTALLED)
        self.assertCountEqual([row[:3] for row in cells if row[3] == 'sanitizer'], SANITIZERS)
        self.assertIn("if: github.event_name != 'workflow_dispatch'", job(text, 'test-execution'))
        aggregate = job(text, 'test')
        self.assertIn('needs: [preflight, test-execution]', aggregate)
        self.assertIn('run: test "${PREFLIGHT_RESULT:-}" = success && { test "${EXECUTION_RESULT:-}" = success', aggregate)
        self.assertIn("'tools/ci_test_entry.py'", step(job(text, 'test-execution'), 'Test installed wheel with image failure diagnostics'))
        self.assertIn('defaultTestLoader.discover', (ROOT / 'tools/ci_test_entry.py').read_text())


if __name__ == '__main__':
    unittest.main()
