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
    holder = dict(common, kind='lsof', returncode=0, stdout='', stderr='', reaped=True, timeout=False, truncated=False,
        display_truncated=False, capture_error=None, cleanup_error=None, backing_device_after=1,
        backing_inode_after=2, backing_identity_status='matched')
    return [observation, mapping, holder, dict(holder, backing_identity_status='not_queried')]


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


class Observations(unittest.TestCase):
    def validate(self, rows, available=True, **kwargs):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'image-failures.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
            module = SimpleNamespace(REPORT='image-failures.jsonl', artifact_available=Mock(return_value=available))
            diagnostic = SimpleNamespace(capture_disabled=False, before_attempts=1, attempts=0)
            diagnostic.__dict__.update(kwargs)
            with patch.dict(sys.modules, image_failure_diagnostics=module):
                runner.observation_complete(diagnostic, directory)

    def test_complete_exact_observation(self):
        self.validate(events())

    @contextmanager
    def collected(self, overrides=None):
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
            for index, values in (overrides or {}).items():
                captures[index].update(values)
            real_stat = os.stat
            def device_stat(path, *args, **kwargs):
                if str(path) == '/dev/disk9s1': return SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=42)
                if str(path) == str(point): return SimpleNamespace(st_dev=42)
                return real_stat(path, *args, **kwargs)
            with patch.object(collector, '_mapping', return_value=(str(image), ['/dev/disk8', '/dev/disk9s1'],
                    str(point), '/dev/disk9s1', (info.st_dev, info.st_ino))), \
                    patch.object(collector, '_capture', side_effect=captures), \
                    patch.object(module.os.path, 'ismount', return_value=True), patch.object(module.os, 'stat', side_effect=device_stat):
                collector.before(('/usr/bin/hdiutil', 'eject', '/dev/disk8'),
                    dict(base=base, image=image, mountpoint=point, stage='sibling-detach', workspace=None, expected=False),
                    observation={})
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
            for values in (dict(returncode=1), dict(truncated=True), dict(timeout=True),
                           dict(reaped=False), dict(capture_error='read'), dict(cleanup_error='reap')):
                overrides = dict(values)
                if index == 1: overrides['stdout'] = b'p10\ncworker\nf3\n'
                with self.subTest(query=index, values=values), self.collected({index: overrides}) as (module, collector, image):
                    self.assert_refused_and_retained(module, collector, image)

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
        for failure in (None, 'close', 'admission', 'fixture'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve(); (root / 'tmp').mkdir()
                diagnostic = Mock()
                if failure == 'close': diagnostic.close.side_effect = OSError('close failed')
                admitted = {'check': Mock(side_effect=[None, ValueError('late admission')] if failure == 'admission' else None)}
                fixture = SimpleNamespace(__file__=str(ROOT / 'tests/test_images_space.py'), ImageSpace=Mock())
                package = SimpleNamespace(__file__='/installed/stallionfs/__init__.py',
                    images=SimpleNamespace(__file__='/installed/stallionfs/images.py'),
                    _scan=SimpleNamespace(__file__='/installed/stallionfs/_scan.so'))
                modules = {'stallionfs': package, 'test_images_space': fixture,
                    'image_failure_diagnostics': SimpleNamespace(install=Mock(return_value=diagnostic))}
                test = Mock(); test.id.return_value = runner.SELECTOR
                suite = [test]
                class Suite(list):
                    def countTestCases(self): return 1
                if failure == 'fixture': (root / 'tmp/retained').write_bytes(b'inert')
                with patch.dict(sys.modules, modules), patch.dict(os.environ, dict(environment(), TMPDIR=str(root / 'tmp'), RUNNER_TEMP=str(root))), \
                        patch.object(runner.sys, 'platform', 'darwin'), patch.object(runner.sys, 'version_info', (3, 11)), \
                        patch.object(runner.platform, 'mac_ver', return_value=('26.0', (), '')), \
                        patch.object(runner.platform, 'machine', return_value='arm64'), patch.object(runner.Path, 'cwd', return_value=root), \
                        patch.object(runner, 'load', return_value=SimpleNamespace(initialize_installed=Mock(return_value=admitted))), \
                        patch.object(runner.unittest.defaultTestLoader, 'loadTestsFromName', return_value=Suite(suite)), \
                        patch.object(runner, 'run_suite'), patch.object(runner, 'observation_complete'):
                    if failure:
                        with self.assertRaises((ValueError, OSError)): runner.invoke(ROOT, root, runner.SELECTOR)
                    else:
                        runner.invoke(ROOT, root, runner.SELECTOR)
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


class Workflow(unittest.TestCase):
    def test_manual_route_reuses_setup_and_preserves_required_gates(self):
        from test_ci_build import job, step, INSTALLED, SANITIZERS, rows
        text = (ROOT / '.github/workflows/checks.yml').read_text()
        manual = job(text, runner.MODE)
        for value in ("if: github.event_name == 'workflow_dispatch' && inputs.mode == 'image-space-repeat'",
                      'runs-on: macos-26', "python-version: '3.11'", 'persist-credentials: false',
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
        self.assertIn('needs: test-execution', aggregate)
        self.assertIn('run: test "${EXECUTION_RESULT:-}" = success', aggregate)
        self.assertIn('defaultTestLoader.discover', step(job(text, 'test-execution'), 'Test installed wheel with image failure diagnostics'))


if __name__ == '__main__':
    unittest.main()
