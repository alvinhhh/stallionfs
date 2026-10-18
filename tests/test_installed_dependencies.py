"""Locked dependency fixture preparation; npm execution is mocked."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PERF = Path(__file__).parent/'perf'
with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
    import fileops
    spec = importlib.util.spec_from_file_location('dependency_fixtures_under_test', PERF/'native_fixtures.py')
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)


class InstalledDependencies(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='installed-dependencies-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.locked = self.base/'fixture'; self.locked.mkdir()
        for name in fixtures.LOCKED_FILES: shutil.copy2(PERF/'fixture'/name, self.locked/name)
        self.node = self.base/'node'; self.node.write_text('inert Node'); self.node.chmod(0o700)
        npm_root = self.base/'npm'; (npm_root/'bin').mkdir(parents=True)
        self.npm = npm_root/'bin/npm-cli.js'; self.npm.write_text('inert npm')
        (npm_root/'package.json').write_text(json.dumps({'name':'npm', 'version':'11.6.0'}))
        self.omit_platform_package = False
        self.cache = self.base/'cache'; self.cache.mkdir()
        (self.cache/'sentinel').write_bytes(b'keep cache')
        self.root = self.base/'prepared'; self.receipt = {}; self.calls = []
        self.checkpoints = []
        self.declared = json.loads((self.locked/'package.json').read_text())['dependencies']

    def command(self, argv, **kwargs):
        argv = list(map(str, argv)); self.calls.append((argv, kwargs))
        output = b''
        if argv == [str(self.node), '--version']: output = b'v24.10.0\n'
        elif argv[:2] == [str(self.node), '-p']: output = b'{"platform":"darwin","arch":"arm64"}\n'
        elif argv[:2] == [str(self.node), str(self.npm)] and argv[-1] == '--version': output = b'11.6.0\n'
        elif 'ci' in argv:
            source = self.root/'node_modules'; source.mkdir()
            (source/'.package-lock.json').write_text('{"lockfileVersion":3}')
            for name, version in self.declared.items():
                path = source/name; path.mkdir(parents=True)
                (path/'package.json').write_text(json.dumps({'name':name, 'version':version}))
            if not self.omit_platform_package:
                platform = source/'@typescript/typescript-darwin-arm64'; platform.mkdir(parents=True)
                (platform/'package.json').write_text(json.dumps({'version':self.declared['typescript']}))
        elif argv == [str(self.node), str(self.root/'node_modules/typescript/bin/tsc'), '--version']:
            output = ('Version '+self.declared['typescript']+'\n').encode()
        elif argv != [str(self.node), str(self.root/'check.cjs')]:
            raise AssertionError(f'Unexpected command: {argv}')
        return subprocess.CompletedProcess(argv, 0, output, b'')

    def prepare(self, command=None, **overrides):
        values = dict(node=self.node, npm=self.npm, cache=self.cache,
                      receipt=self.receipt, checkpoint=lambda: self.checkpoints.append(json.loads(json.dumps(self.receipt))), timeout=30)
        values.update(overrides)
        with mock.patch.object(fixtures, '__file__', str(self.base/'native_fixtures.py')), \
             mock.patch.dict(sys.modules, {'fileops':fileops}), \
             mock.patch.object(fileops, 'command', side_effect=command or self.command):
            return fixtures.installed_dependencies(self.root, **values)

    def test_offline_install_records_pins_versions_and_checked_tree(self):
        with mock.patch.dict(os.environ, {'NODE_OPTIONS':'--require secret', 'NPM_CONFIG_REGISTRY':'https://invalid.example'}):
            source = self.prepare()
        self.assertEqual(source, self.root/'node_modules')
        self.assertEqual(self.receipt['status'], 'prepared')
        self.assertEqual(self.receipt['dependencies'], self.declared)
        self.assertEqual(self.receipt['node_version'], 'v24.10.0')
        self.assertEqual(self.receipt['npm_version'], '11.6.0')
        for name in fixtures.LOCKED_FILES:
            self.assertEqual((self.root/name).read_bytes(), (self.locked/name).read_bytes())
            self.assertEqual(self.receipt['locked_inputs'][name], hashlib.sha256((self.locked/name).read_bytes()).hexdigest())
        self.assertEqual(self.receipt['node_sha256'], fileops.digest(self.node))
        self.assertEqual(self.receipt['npm_entrypoint_sha256'], fileops.digest(self.npm))
        self.assertEqual(self.receipt['npm_package_manifest_sha256'], fileops.digest(self.npm.parent.parent/'package.json'))
        self.assertIn('not fully pinned', self.receipt['runtime_pin_scope'])
        self.assertEqual(self.receipt['typescript_platform']['name'], '@typescript/typescript-darwin-arm64')
        self.assertEqual((self.cache/'sentinel').read_bytes(), b'keep cache')
        install = [argv for argv, _ in self.calls if 'ci' in argv]
        self.assertEqual(len(install), 1)
        for flag in ('--offline', '--ignore-scripts', '--no-audit', '--no-fund'): self.assertIn(flag, install[0])
        self.assertEqual(install[0][install[0].index('--cache')+1], str(self.cache))
        self.assertTrue(all(argv[0] == str(self.node) for argv, _ in self.calls))
        self.assertIn([str(self.node), str(self.root/'check.cjs')], [argv for argv, _ in self.calls])
        self.assertEqual(self.calls[-1][0], [str(self.node), str(self.root/'node_modules/typescript/bin/tsc'), '--version'])
        for argv, _ in self.calls:
            if argv[1] == str(self.npm):
                self.assertEqual(argv[argv.index('--prefix')+1], str(self.root))
                for option in ('--userconfig', '--globalconfig'):
                    self.assertEqual(Path(argv[argv.index(option)+1]).read_bytes(), b'')
        self.assertTrue(all('NODE_OPTIONS' not in opts['environment'] and 'NPM_CONFIG_REGISTRY' not in opts['environment'] for _, opts in self.calls))
        self.assertFalse(any('install' in argv or 'run' in argv for argv, _ in self.calls))
        self.assertTrue(self.checkpoints)

    def test_failed_npm_does_not_run_fixture_check_or_delete_owned_data(self):
        def command(argv, **kwargs):
            if 'ci' in argv:
                (self.root/'partial-install').write_bytes(b'partial')
                return subprocess.CompletedProcess(argv, 9, b'', b'offline cache missing')
            return self.command(argv, **kwargs)
        with self.assertRaisesRegex(RuntimeError, 'preparation failed'): self.prepare(command)
        self.assertTrue((self.root/'partial-install').is_file())
        self.assertEqual(self.receipt['commands'][-1]['exit_code'], 9)
        self.assertIn('offline cache missing', self.receipt['commands'][-1]['stderr'])
        self.assertNotIn('prepared', self.receipt.values())
        self.assertFalse(any(str(self.root/'check.cjs') in argv for argv, _ in self.calls))

    def test_lock_and_runtime_changes_fail_before_returning_tree(self):
        for label in ('lock', 'runtime'):
            with self.subTest(change=label):
                self.root = self.base/('changed-'+label)
                self.receipt = {}; self.calls = []
                def command(argv, **kwargs):
                    result = self.command(argv, **kwargs)
                    if str(self.root/'check.cjs') in map(str, argv):
                        path = self.root/'package-lock.json' if label == 'lock' else self.node
                        path.write_text(path.read_text()+'\n')
                    return result
                with self.assertRaisesRegex(RuntimeError, 'changed'): self.prepare(command)
                self.assertTrue(self.root.is_dir())

    def test_successful_npm_missing_optional_platform_package_is_rejected(self):
        self.omit_platform_package = True
        with self.assertRaisesRegex(RuntimeError, 'TypeScript platform package missing'):
            self.prepare()
        self.assertTrue((self.root/'node_modules/typescript/package.json').is_file())
        self.assertFalse(any(str(self.root/'check.cjs') in argv for argv, _ in self.calls))
        self.assertNotEqual(self.receipt.get('status'), 'prepared')

    def test_missing_runtime_or_cache_never_starts_setup(self):
        for name in ('node', 'npm', 'cache'):
            with self.subTest(missing=name):
                with self.assertRaises(FileNotFoundError): self.prepare(**{name:self.base/('missing-'+name)})
                self.assertEqual(self.calls, [])
                self.assertFalse(self.root.exists())

    def test_uncertain_install_propagates_and_preserves_partial_source(self):
        def command(argv, **kwargs):
            if 'ci' in argv:
                (self.root/'node_modules').mkdir()
                (self.root/'node_modules/partial').write_bytes(b'partial')
                raise fileops.ChildCompletionUnknown('npm completion unknown')
            return self.command(argv, **kwargs)
        with self.assertRaises(fileops.ChildCompletionUnknown): self.prepare(command)
        self.assertTrue((self.root/'node_modules/partial').is_file())
        self.assertIn('ci', self.receipt['commands'][-1]['argv'])
        self.assertFalse(any(str(self.root/'check.cjs') in argv for argv, _ in self.calls))


if __name__ == '__main__': unittest.main()
