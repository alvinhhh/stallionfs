"""Admission boundaries before controlled real-Git fixture execution."""
import ast
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile


def admission_module():
    path = Path(__file__).resolve().parents[1] / 'tools/ci_git_input.py'
    spec = importlib.util.spec_from_file_location('uninitialized_ci_git_input', path)
    admission = importlib.util.module_from_spec(spec); spec.loader.exec_module(admission)
    return admission


class UninitializedInput(unittest.TestCase):
    def test_runtime_refuses_without_pre_discovery_admission(self):
        admission = admission_module()
        with self.assertRaisesRegex(RuntimeError, 'before test discovery'):
            admission.runtime()

    def test_binding_refuses_a_change_after_the_validated_read(self):
        from stallionfs import _bundle
        admission = admission_module()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'input'; path.write_bytes(b'input')
            retained = admission._Bindings(_bundle)
            def reader(path, expected=None):
                data = path.read_bytes(); path.write_bytes(data + b' ')
                return data
            retained.reader = reader
            with self.assertRaisesRegex(ValueError, 'changed during validation'):
                retained.read(path)

    def test_binding_does_not_replace_its_first_validated_identity(self):
        from stallionfs import _bundle
        admission = admission_module()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'input'; path.write_bytes(b'input')
            retained = admission._Bindings(_bundle)
            calls = []
            def reader(path, expected=None):
                calls.append(path); return path.read_bytes()
            retained.reader = reader
            retained.read(path)
            path.rename(path.with_name('retained')); path.write_bytes(b'input')
            with self.assertRaisesRegex(ValueError, 'validation identity changed'):
                retained.read(path)
            self.assertEqual(len(calls), 1)

    def test_python_children_preserve_admitted_inputs_only_with_bytecode_suppression(self):
        from stallionfs import _bundle
        capture_path = Path(__file__).resolve().parents[1] / 'tools/_git_capture.py'
        cases = (('isolated-control', ['-I'], False), ('isolated-bytecode-disabled', ['-I', '-B'], True),
                 ('ordinary-environment', [], True), ('console-helper-environment', None, True))
        for name, flags, preserved in cases:
            with self.subTest(child=name), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                package = base / 'owned_fixture'; package.mkdir(mode=0o700)
                source = package / '__init__.py'
                source.write_text("import json, sys\ndef main():\n    print(json.dumps({"
                                  "'isolated': sys.flags.isolated, 'dont_write_bytecode': sys.dont_write_bytecode}))\n"
                                  "    return 0\n")
                helper = base / 'console-helper.py'
                helper.write_text("import sys\nfrom owned_fixture import main\n"
                                  "if __name__ == '__main__':\n    sys.exit(main())\n")
                retained = admission_module()._Bindings(_bundle)
                retained.reader = lambda path, expected=None: path.read_bytes()
                retained.tree(package)
                original = retained.read(source)
                identities = dict(retained.identities)
                members = retained.trees[package]
                spec = importlib.util.spec_from_file_location('bytecode_capture', capture_path)
                capture = importlib.util.module_from_spec(spec); spec.loader.exec_module(capture)
                script = "import sys; sys.path.insert(0, sys.argv[1]); from owned_fixture import main; sys.exit(main())"
                argv = ([sys.executable, str(helper)] if flags is None
                        else [sys.executable, *flags, '-c', script, str(base)])
                with patch.object(capture, '_COMMAND_ENV', {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}):
                    result = capture._owned_command(argv, cwd=base, timeout=10, stem=base / 'child')
                self.assertEqual(result.returncode, 0, result.stderr)
                observed = json.loads(result.stdout)
                self.assertEqual(observed['isolated'], int(flags is not None and '-I' in flags))
                self.assertEqual(observed['dont_write_bytecode'], preserved)
                self.assertEqual(source.read_bytes(), original)
                actual_members = frozenset({package, *package.rglob('*')})
                if preserved:
                    retained.check()
                    self.assertEqual(actual_members, members)
                    self.assertEqual({path: _bundle._identity(path.lstat()) for path in identities}, identities)
                else:
                    self.assertTrue((package / '__pycache__').is_dir())
                    self.assertNotEqual(actual_members, members)
                    self.assertNotEqual(_bundle._identity(package.lstat()), identities[package])
                    with self.assertRaisesRegex(ValueError, '^CI validated input changed$'):
                        retained.check()
                self.assertIsNone(capture._command_state['failure'])
                self.assertIsNone(capture._command_state['active'])

    def test_declared_wheel_budget_refuses_before_any_member_body_read(self):
        admission = admission_module()
        members = []
        for index, size in enumerate((64 * 1024 ** 2, 64 * 1024 ** 2, 1)):
            info = zipfile.ZipInfo(str(index)); info.file_size = size
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            members.append(info)
        class Archive:
            opened = 0
            def infolist(self): return members
            def open(self, member):
                self.opened += 1; raise AssertionError('Member body must not be opened')
        archive = Archive()
        with self.assertRaisesRegex(ValueError, 'Wheel byte limit'):
            admission._wheel_files(archive)
        self.assertEqual(archive.opened, 0)

    def test_wheel_stream_reads_are_bounded_and_match_declared_sizes(self):
        admission = admission_module()
        for size, body, accepted in ((1, b'ab', False), (2, b'a', False), (3, b'abc', True)):
            with self.subTest(size=size, body=body):
                info = zipfile.ZipInfo('member'); info.file_size = size
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                requests = []
                class Stream(io.BytesIO):
                    def read(self, count=-1):
                        requests.append(count); return super().read(count)
                class Archive:
                    def infolist(self): return [info]
                    def open(self, member): return Stream(body)
                if accepted:
                    files, _ = admission._wheel_files(Archive())
                    self.assertEqual(files, {'member': body})
                else:
                    with self.assertRaises(ValueError): admission._wheel_files(Archive())
                self.assertTrue(requests)
                self.assertTrue(all(0 < count <= 65536 for count in requests))


class InstalledNativeDiagnostic(unittest.TestCase):
    prefix = 'Installed native architecture, deployment or dependency differs'
    roles = ('_scan', '_image', 'sfs', 'stallionfs')

    def slice(self, **changes):
        return dict({'architecture': 'arm64', 'minimum': (13, 0, 0),
                     'dependencies': ['/usr/lib/libSystem.B.dylib'], 'rpaths': []}, **changes)

    def guard(self, module, role, slices, *, writer=None):
        """Execute the actual installed-native loop with inert parser observations."""
        tree = ast.parse(Path(module.__file__).read_text())
        initialize = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'initialize')
        assignment = next(node for node in initialize.body if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == 'installed_native_paths' for target in node.targets))
        loop = initialize.body[initialize.body.index(assignment) + 1]
        self.assertIsInstance(loop, ast.For)
        output = io.StringIO(); parsed = []; discovered = []
        paths = [Path('/inert/package/_scan.so'), Path('/inert/package/_image.so'),
                 Path('/inert/bin/sfs'), Path('/inert/bin/stallionfs')]
        def parse(path):
            parsed.append(path)
            return copy.deepcopy(slices if role is not None and path == paths[self.roles.index(role)] else [self.slice()])
        scope = dict(vars(module), _scan=SimpleNamespace(__file__=str(paths[0])),
                     _image=SimpleNamespace(__file__=str(paths[1])), scripts_directory=paths[2].parent,
                     builder=SimpleNamespace(macho=parse), wheel=SimpleNamespace(name='stallionfs-0.7.0-cp311-cp311-macosx_13_0_arm64.whl'),
                     wheel_sha256='a' * 64, architecture='arm64', floor=(13, 0, 0),
                     sys=SimpleNamespace(stderr=output), discovered=discovered)
        if writer is not None: scope['print'] = writer
        body = [assignment, loop, *ast.parse("discovered.append('after-admission')").body]
        error = None
        try: exec(compile(ast.Module(body=body, type_ignores=[]), module.__file__, 'exec'), scope)
        except BaseException as caught: error = caught
        return error, output.getvalue(), parsed, discovered

    def test_actual_guard_reports_each_role_and_failed_dimension(self):
        cases = [([], ['slice_count']), ([self.slice(), self.slice()], ['slice_count']),
                 ([self.slice(architecture='x86_64')], ['architecture']),
                 ([self.slice(minimum=(14, 0, 0))], ['minimum']),
                 ([self.slice(rpaths=['@loader_path'])], ['rpaths']),
                 ([self.slice(dependencies=['/tmp/external.dylib'])], ['dependencies'])]
        for role in self.roles:
            for slices, dimensions in cases:
                with self.subTest(role=role, dimensions=dimensions):
                    module = admission_module(); error, text, parsed, discovered = self.guard(module, role, slices)
                    self.assertIsInstance(error, ValueError); self.assertEqual(str(error), self.prefix)
                    self.assertEqual(discovered, []); self.assertEqual(len(parsed), self.roles.index(role) + 1)
                    self.assertEqual(len(text.splitlines()), 1)
                    record = json.loads(text)
                    self.assertEqual(record['schema'], 1); self.assertEqual(record['role'], role)
                    self.assertEqual(record['wheel']['sha256'], 'a' * 64)
                    self.assertIn('macosx_13_0_arm64.whl', record['wheel']['filename']['value'])
                    self.assertEqual(record['expected'], {'architecture': 'arm64', 'floor': [13, 0, 0]})
                    self.assertEqual(record['slice_count'], len(slices))
                    self.assertEqual(record['failed_dimensions'], dimensions)
                    self.assertIsNone(module._state)

    def test_below_and_equal_floor_preserve_success_without_diagnostic(self):
        for minimum in ((11, 0, 0), (13, 0, 0)):
            for role in self.roles:
                with self.subTest(minimum=minimum, role=role):
                    error, text, parsed, discovered = self.guard(admission_module(), role, [self.slice(minimum=minimum)])
                    self.assertIsNone(error); self.assertEqual(text, ''); self.assertEqual(len(parsed), 4)
                    self.assertEqual(discovered, ['after-admission'])

    def test_combined_failures_and_late_offending_dependency_are_retained(self):
        dependencies = ['/usr/lib/allowed.dylib'] * 20 + ['/tmp/first-bad.dylib', '/tmp/later-bad.dylib']
        bad = self.slice(architecture='x86_64', minimum=(14, 0, 0), rpaths=['@rpath'], dependencies=dependencies)
        error, text, _, discovered = self.guard(admission_module(), '_image', [self.slice(), bad])
        self.assertEqual(str(error), self.prefix); self.assertEqual(discovered, [])
        record = json.loads(text)
        self.assertEqual(record['failed_dimensions'], ['slice_count', 'architecture', 'minimum', 'rpaths', 'dependencies'])
        item = record['slices']['items'][1]['dependencies']
        self.assertEqual(item['count'], 22); self.assertEqual(len(item['items']), 4); self.assertTrue(item['truncated'])
        first = record['first_offending_dependency']
        self.assertEqual((first['slice_index'], first['dependency_index']), (1, 20))
        self.assertEqual(first['dependency']['value'], '/tmp/first-bad.dylib')

    def test_escaped_bounded_record_has_counts_and_explicit_truncation(self):
        module = admission_module(); huge = '\U0001f40e\n\r\t\x00"\\' * 2000
        slices = [self.slice(architecture=huge, dependencies=['/usr/lib/' + huge] * 10,
                             rpaths=[huge] * 5) for _ in range(9)]
        slices[-1]['dependencies'] += ['/tmp/first-bad-' + huge]
        encoded = module._native_failure_record('sfs', huge, 'b' * 64, 'arm64', (13, 0, 0), slices)
        self.assertLessEqual(len(encoded.encode('ascii')) + 1, 16 * 1024)
        self.assertEqual(len(encoded.splitlines()), 1)
        self.assertTrue(all(ord(character) >= 32 and ord(character) < 127 for character in encoded))
        record = json.loads(encoded)
        self.assertEqual(record['slice_count'], 9); self.assertEqual(len(record['slices']['items']), 8)
        self.assertTrue(record['slices']['truncated']); self.assertTrue(record['wheel']['filename']['truncated'])
        self.assertEqual(record['wheel']['filename']['characters'], len(huge))
        first = record['first_offending_dependency']
        self.assertEqual((first['slice_index'], first['dependency_index']), (8, 10))
        self.assertTrue(first['dependency']['value'].startswith('/tmp/first-bad-'))
        self.assertTrue(first['dependency']['truncated'])
        for item in record['slices']['items']:
            self.assertEqual(item['dependencies']['count'], 10); self.assertTrue(item['dependencies']['truncated'])
            self.assertEqual(item['rpaths']['count'], 5); self.assertTrue(item['rpaths']['truncated'])

    def test_formatter_serialization_and_output_failures_cannot_allow_discovery(self):
        for failure in (ValueError('formatter'), OSError('formatter'), SystemExit(0), KeyboardInterrupt()):
            module = admission_module()
            with self.subTest(failure=type(failure).__name__), patch.object(module, '_native_failure_record', side_effect=failure):
                error, text, _, discovered = self.guard(module, 'stallionfs', [])
            self.assertIsInstance(error, ValueError); self.assertEqual(str(error), self.prefix)
            self.assertEqual(text, ''); self.assertEqual(discovered, [])
        module = admission_module(); original = module.json.dumps
        def failed_serialization(value, *args, **kwargs):
            if isinstance(value, dict) and value.get('kind') == 'installed-native-refusal': raise OSError('serializer')
            return original(value, *args, **kwargs)
        with patch.object(module.json, 'dumps', side_effect=failed_serialization):
            error, text, _, discovered = self.guard(module, '_scan', [])
        self.assertEqual(str(error), self.prefix); self.assertEqual(text, ''); self.assertEqual(discovered, [])
        with patch.object(module, '_diagnostic_text', return_value={'value': 'x' * 20000, 'characters': 20000, 'truncated': False}):
            error, text, _, discovered = self.guard(module, '_scan', [])
        self.assertEqual(str(error), self.prefix); self.assertEqual(text, ''); self.assertEqual(discovered, [])
        for failure in (OSError('output'), BrokenPipeError('output'), SystemExit(0)):
            def failed_output(*args, **kwargs): raise failure
            with self.subTest(output=type(failure).__name__):
                error, text, _, discovered = self.guard(admission_module(), '_scan', [], writer=failed_output)
            self.assertIsInstance(error, ValueError); self.assertEqual(str(error), self.prefix)
            self.assertEqual(discovered, [])


@unittest.skipUnless(os.environ.get('STALLIONFS_TEST_QUALIFIED_GIT'), 'requires explicitly qualified private Git fixture')
class AdmittedInput(unittest.TestCase):
    def test_installed_package_removal_and_mode_changes_refuse(self):
        import stallionfs
        from stallionfs import _scan, _image
        from qualified_git_fixture import runtime
        targets = [Path(_scan.__file__).resolve(), Path(_image.__file__).resolve(),
                   Path(stallionfs.__file__).resolve().with_name('core.py')]
        original = Path.lstat
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        for target in targets:
            for change in ('missing', 'mode'):
                with self.subTest(target=target.name, change=change):
                    value = runtime(); reads = []
                    def changed(path, *args, **kwargs):
                        if path == target:
                            reads.append(path)
                            if change == 'missing': raise FileNotFoundError('Simulated installed member removal')
                            info = original(path, *args, **kwargs)
                            data = {field: getattr(info, field) for field in fields}; data['st_mode'] ^= 0o100
                            return SimpleNamespace(**data)
                        return original(path, *args, **kwargs)
                    with patch.object(Path, 'lstat', changed):
                        with self.assertRaises((ValueError, OSError)): value['check']()
                    self.assertTrue(reads)

    def test_contract_uses_the_registered_native_payload(self):
        from qualified_git_fixture import runtime
        from stallionfs import _bundle
        value = runtime()
        contract = value['contract']
        required = {'input_inventory_sha256', 'payload_entries', 'payload_sha256',
                    'descriptor_sha256', 'executable_sha256', 'source_build_id', 'publisher'}
        self.assertEqual(set(contract), set(_bundle.GIT_CONTRACT) | required)
        _bundle.git_contract({key: contract[key] for key in set(_bundle.GIT_CONTRACT) | {'input_inventory_sha256'}})
        payload = _bundle.git_payload(Path(value['executable']).parent.parent)
        self.assertEqual(contract['payload_entries'], payload['entries'])
        self.assertEqual(contract['payload_sha256'], payload['sha256'])
        self.assertEqual(contract['executable_sha256'], payload['executable_sha256'])
        value['check']()

    def test_external_fixture_path_is_refused(self):
        from qualified_git_fixture import runtime
        with patch.dict(os.environ, STALLIONFS_TEST_QUALIFIED_GIT='/usr/bin/git'):
            with self.assertRaisesRegex(ValueError, 'External fixture executable'):
                runtime()

    def test_runtime_substitution_refuses_before_actor(self):
        from qualified_git_fixture import runtime
        value = runtime()
        value['executable'] = '/usr/bin/git'
        with self.assertRaisesRegex(ValueError, 'Fixture runtime changed'):
            value['check']()
        value = runtime()
        value['contract']['input_inventory_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'Fixture runtime changed'):
            value['check']()
