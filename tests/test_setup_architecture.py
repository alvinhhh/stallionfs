"""Host-target packaging controls; compiler calls are inert observations."""
import ast
import builtins
import functools
import hashlib
import importlib.metadata
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import sysconfig
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1]
BACKEND_FILES = {
    'setuptools/_distutils/sysconfig.py': '134e6ebcd2e33e62112813ce44e59eb083fa4304f9b77ebab747fd0107b06330',
    'setuptools/_distutils/compilers/C/unix.py': '6b6e1b8325dd70dd54146a3fe98e9435e1ada067a9345323f797c861978f8677',
    'setuptools/_distutils/compilers/platform/macos.py': 'e52e0ea5ae6db15ad2c30df7496ef2cf6c61cb23f582c43dcdd0f521b6d6f53d',
    'setuptools/build_meta.py': '6f4a583e1b6bb0d5ef3af2ac0a6e9a033d06f364e4a550e3b112812674b38419',
}


def selected(data, name, namespace, owner=None):
    tree = ast.parse(data)
    if owner is not None:
        tree = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == owner)
    node = next(node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name)
    module = ast.Module(body=[ast.ImportFrom(module='__future__', names=[ast.alias(name='annotations')], level=0), node], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), '<packaging-source>', 'exec'), namespace)
    return namespace[name]


def select_host(system, machine):
    tree = ast.parse((SOURCE / 'setup.py').read_bytes())
    boundary = next(index for index, node in enumerate(tree.body) if isinstance(node, ast.ImportFrom)
                    and node.module.split('.')[0] in ('setuptools', 'distutils'))
    original = builtins.__import__
    def imported(name, *args, **kwargs):
        if name == 'platform': return SimpleNamespace(machine=lambda: machine)
        if name == 'sys': return SimpleNamespace(platform=system)
        return original(name, *args, **kwargs)
    scope = {'__file__': str(SOURCE / 'setup.py'), '__builtins__': dict(vars(builtins), __import__=imported)}
    exec(compile(ast.Module(body=tree.body[:boundary], type_ignores=[]), '<setup-before-backend>', 'exec'), scope)


class HostArchitecture(unittest.TestCase):
    def backend(self):
        try: distribution = importlib.metadata.distribution('setuptools')
        except importlib.metadata.PackageNotFoundError:
            if os.environ.get('GITHUB_ACTIONS') == 'true': raise
            self.skipTest('requires the pinned CI build backend')
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            self.assertEqual(distribution.version, '84.2.1', 'Packaging controls require tools/ci-build-requirements.txt')
        if distribution.version != '84.2.1': self.skipTest('requires the pinned CI build backend')
        values = {name: Path(distribution.locate_file(name)).read_bytes() for name in BACKEND_FILES}
        for name, data in values.items(): self.assertEqual(hashlib.sha256(data).hexdigest(), BACKEND_FILES[name])
        return values

    def test_unsupported_darwin_refuses_before_environment_write_or_backend_import(self):
        source = (SOURCE / 'setup.py').read_bytes()
        original = builtins.__import__
        for machine in ('unsupported-host', '', None, 42, False, b'arm64', ['arm64'], {'host': 'arm64'}):
            with self.subTest(machine=machine):
                imports = []; writes = []
                class Environment(dict):
                    def __setitem__(self, key, value):
                        writes.append((key, value))
                        raise AssertionError('Environment changed before host refusal')
                environment = Environment(ARCHFLAGS='preserved', CFLAGS='preserved compile flags')
                def imported(name, *args, **kwargs):
                    imports.append(name)
                    if name == 'os': return SimpleNamespace(environ=environment)
                    if name == 'platform': return SimpleNamespace(machine=lambda: machine)
                    if name == 'sys': return SimpleNamespace(platform='darwin')
                    if name.split('.')[0] in ('setuptools', 'distutils'):
                        raise AssertionError('Backend imported before host refusal')
                    return original(name, *args, **kwargs)
                scope = {'__file__': str(SOURCE / 'setup.py'),
                         '__builtins__': dict(vars(builtins), __import__=imported)}
                with self.assertRaisesRegex(ValueError, '^Unsupported Darwin architecture$'):
                    exec(compile(source, '<setup-unsupported-host>', 'exec'), scope)
                self.assertEqual(imports, ['os', 'platform', 'sys'])
                self.assertEqual(writes, [])
                self.assertEqual(environment, {'ARCHFLAGS': 'preserved', 'CFLAGS': 'preserved compile flags'})

    def test_selection_precedes_backend_imports_and_preserves_other_platforms(self):
        for system, machine, prior in (('darwin', 'arm64', '-arch x86_64 -arch arm64'),
                                       ('darwin', 'x86_64', '-arch arm64'), ('linux', 'x86_64', 'unchanged'),
                                       ('linux', None, 'unchanged')):
            with self.subTest(system=system, machine=machine), patch.dict(os.environ,
                    {'ARCHFLAGS': prior, 'CFLAGS': 'preserved compile flags', 'LDFLAGS': 'preserved link flags'}, clear=True):
                select_host(system, machine)
                self.assertEqual(os.environ['ARCHFLAGS'], '-arch ' + machine if system == 'darwin' else prior)
                self.assertEqual(os.environ['CFLAGS'], 'preserved compile flags')
                self.assertEqual(os.environ['LDFLAGS'], 'preserved link flags')
        with patch.dict(os.environ, {}, clear=True):
            select_host('linux', 'x86_64'); self.assertNotIn('ARCHFLAGS', os.environ)

    def test_registered_extensions_and_native_scripts_share_the_backend(self):
        tree = ast.parse((SOURCE / 'setup.py').read_bytes())
        setup = next(node.value for node in tree.body if isinstance(node, ast.Expr)
                     and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == 'setup')
        keywords = {node.arg: node.value for node in setup.keywords}
        self.assertEqual([node.args[0].value for node in keywords['ext_modules'].elts], ['stallionfs._scan', 'stallionfs._image'])
        for extension in keywords['ext_modules'].elts:
            self.assertEqual({node.arg: node.value.id for node in extension.keywords if node.arg in ('extra_compile_args', 'extra_link_args')},
                             {'extra_compile_args': 'FLAGS', 'extra_link_args': 'LINK_FLAGS'})
        commands = dict(zip((node.value for node in keywords['cmdclass'].keys), (node.id for node in keywords['cmdclass'].values)))
        self.assertEqual(commands['build_scripts'], 'NativeScripts'); self.assertEqual(commands['bdist_wheel'], 'PayloadWheel')

    def test_pinned_backend_replaces_universal_arches_for_extensions_and_launchers(self):
        backend = self.backend(); unix = backend['setuptools/_distutils/compilers/C/unix.py']
        osx = (Path(sysconfig.get_path('stdlib')) / '_osx_support.py').read_bytes()
        fixup = selected(osx, 'compiler_fixup', {'os': os, 'sys': sys,
            '_supports_universal_builds': lambda: True, '_supports_arm64_builds': lambda: True})
        override = selected(osx, '_override_all_archs', {'os': os, 're': re,
            '_UNIVERSAL_CONFIG_VARS': ('CFLAGS', 'LDFLAGS', 'CPPFLAGS', 'BASECFLAGS', 'BLDSHARED', 'LDSHARED', 'CC', 'CXX'),
            '_save_modified_value': lambda values, name, value: values.__setitem__(name, value)})
        customize = selected(backend['setuptools/_distutils/sysconfig.py'], 'customize_compiler', {'functools': functools})
        for machine in ('arm64', 'x86_64'):
            for cached in (False, True):
                with self.subTest(machine=machine, cached=cached), patch.dict(os.environ,
                        {'ARCHFLAGS': '-arch x86_64 -arch arm64'}, clear=True):
                    config = dict(CC='clang', CXX='clang++', CFLAGS='-O2 -arch x86_64 -arch arm64 -mmacosx-version-min=13.0 ',
                        CCSHARED='', LDSHARED='clang -bundle -arch x86_64 -arch arm64 -mmacosx-version-min=13.0 ',
                        LDCXXSHARED='clang++ -bundle -arch x86_64 -arch arm64 ', SHLIB_SUFFIX='.so', AR='ar', ARFLAGS='rc')
                    namespace = {'os': os, '_require_config_vars': lambda *names: [config[name] for name in names],
                        'sysconfig': SimpleNamespace(get_config_vars=lambda: config), 'macos': SimpleNamespace(customize_compiler=override)}
                    namespace['_add_flags'] = selected(unix, '_add_flags', {'os': os, 'pass_none': lambda f: f})
                    configure = selected(unix, 'configure_system', namespace, 'Compiler')
                    compile_one = selected(unix, '_compile', {'compiler_fixup': fixup, 'subprocess': subprocess, 'CompileError': RuntimeError}, 'Compiler')
                    link = selected(unix, 'link', {'compiler_fixup': fixup, 'subprocess': subprocess, 'LinkError': RuntimeError,
                        'base': SimpleNamespace(Compiler=SimpleNamespace(EXECUTABLE='executable')), 'os': os,
                        'gen_lib_options': lambda *args: []}, 'Compiler')
                    commands = []; copies = []
                    compiler = type('CompilerFixture', (), {})()
                    vars(compiler).update(executables={'ranlib': None}, objects=[], compiler_cxx=None,
                        detect_language=lambda name: 'c', call=lambda argv: commands.append(argv),
                        _fix_object_args=lambda objects, output: (objects, output), _fix_lib_args=lambda *args: ([], [], []),
                        _need_link=lambda *args: True, mkpath=lambda *args: None)
                    def executables(**values):
                        for key, value in values.items(): setattr(compiler, key, shlex.split(value))
                    compiler.set_executables = executables
                    compiler.configure_system = lambda: configure(compiler)
                    if cached: customize(compiler)
                    select_host('darwin', machine)
                    if not cached: customize(compiler)
                    for name in ('_scan', '_image'):
                        compile_one(compiler, name + '.o', name + '.c', '.c', ['-c'], ['-Wall'], [])
                        link(compiler, 'shared', [name + '.o'], name + '.so')
                    def compile_scripts(sources, output_dir, extra_postargs, **kwargs):
                        for source in sources: compile_one(compiler, source + '.o', source, '.c', ['-c'], extra_postargs, [])
                        return [source + '.o' for source in sources]
                    compiler.compile = compile_scripts
                    compiler.link_executable = lambda objects, name, output_dir, extra_postargs: link(
                        compiler, 'executable', objects, name, output_dir=output_dir, extra_postargs=extra_postargs)
                    scope = {'Path': Path, '__file__': str(SOURCE / 'setup.py')}
                    tree = ast.parse((SOURCE / 'setup.py').read_bytes())
                    constants = [node for node in tree.body if isinstance(node, ast.Assign)
                                 and any(isinstance(target, ast.Name) and target.id in ('NATIVE', 'HEADER', 'SOURCE_ROOT', 'FLAGS', 'LINK_FLAGS') for target in node.targets)]
                    exec(compile(ast.Module(body=constants, type_ignores=[]), '<setup-inputs>', 'exec'), scope)
                    scope.update(new_compiler=lambda **kwargs: compiler, customize_compiler=customize,
                                 copy2=lambda source, destination: copies.append((source, destination)))
                    run = selected((SOURCE / 'setup.py').read_bytes(), 'run', scope, 'NativeScripts')
                    value = SimpleNamespace(build_dir='/inert/scripts', dry_run=False, force=True, mkpath=lambda *args: None,
                        get_finalized_command=lambda name: SimpleNamespace(build_temp='/inert/objects'),
                        distribution=SimpleNamespace(get_version=lambda: '0.7.0'))
                    run(value)
                    self.assertEqual(len(commands), 8); self.assertEqual(len(copies), 1)
                    self.assertEqual(Path(copies[0][0]).name, 'stallionfs'); self.assertEqual(Path(copies[0][1]).name, 'sfs')
                    for command in commands:
                        self.assertEqual([command[index + 1] for index, item in enumerate(command) if item == '-arch'], [machine])
                    self.assertIn('-mmacosx-version-min=13.0', commands[0])
                    self.assertIn('-mmacosx-version-min=13.0', commands[1])

    def test_wheel_editable_and_metadata_frontends_execute_setup(self):
        tree = ast.parse(self.backend()['setuptools/build_meta.py'])
        backend = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == '_BuildMetaBackend')
        methods = {node.name: node for node in ast.walk(backend) if isinstance(node, ast.FunctionDef)}
        calls = lambda name: {node.func.attr for node in ast.walk(methods[name]) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertIn('run_setup', calls('prepare_metadata_for_build_wheel'))
        self.assertIn('run_setup', calls('_build_with_temp_dir'))
        self.assertIn('_build_with_temp_dir', calls('build_wheel'))
        self.assertIn('_build_with_temp_dir', calls('build_editable'))
        self.assertIn('prepare_metadata_for_build_wheel', calls('prepare_metadata_for_build_editable'))

    def test_tag_requires_each_parsed_file_to_be_single_host_slice(self):
        class Base:
            def get_tag(self): return ('cp313', 'cp313', 'metadata-platform')
        for machine in ('arm64', 'x86_64'):
            other = 'x86_64' if machine == 'arm64' else 'arm64'
            cases = {'thin': [[machine], [machine]], 'fat': [[machine, other]],
                     'mixed': [[machine], [other]], 'duplicate': [[machine, machine]],
                     'foreign': [[other]], 'non-macho': [[], []]}
            for name, values in cases.items():
                with self.subTest(machine=machine, case=name), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary); library = root / 'lib'; scripts = root / 'scripts'; library.mkdir(); scripts.mkdir()
                    (library / 'module.so').write_bytes(b'inert'); (scripts / 'stallionfs').write_bytes(b'inert')
                    def macho(path):
                        arches = values[0 if path.parent == library else min(1, len(values) - 1)]
                        return [{'architecture': architecture, 'minimum': (13, 0, 0)} for architecture in arches]
                    scope = {'bdist_wheel': Base, 'Path': Path, 'host': SimpleNamespace(machine=lambda: machine),
                             'git_builder': lambda: SimpleNamespace(macho=macho)}
                    wheel = selected((SOURCE / 'setup.py').read_bytes(), 'PayloadWheel', scope)()
                    wheel.get_finalized_command = lambda command: SimpleNamespace(build_lib=str(library), build_dir=str(scripts))
                    if name in ('fat', 'mixed', 'duplicate', 'foreign'):
                        with self.assertRaisesRegex(ValueError, 'Wheel payload architecture differs'): wheel.get_tag()
                    else:
                        self.assertEqual(wheel.get_tag(), ('cp313', 'cp313', 'metadata-platform' if name == 'non-macho' else 'macosx_13_0_' + machine))

    def test_empty_prebuild_and_maximum_deployment_floor_remain(self):
        class Base:
            def get_tag(self): return ('cp313', 'cp313', 'linux_x86_64')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def macho(path): return [{'architecture': 'arm64', 'minimum': (14, 2, 0) if path.name == 'launcher' else (13, 0, 0)}]
            scope = {'bdist_wheel': Base, 'Path': Path, 'host': SimpleNamespace(machine=lambda: 'arm64'),
                     'git_builder': lambda: SimpleNamespace(macho=macho)}
            wheel = selected((SOURCE / 'setup.py').read_bytes(), 'PayloadWheel', scope)()
            wheel.get_finalized_command = lambda command: SimpleNamespace(build_lib=str(root), build_dir=str(root / 'absent'))
            self.assertEqual(wheel.get_tag(), ('cp313', 'cp313', 'linux_x86_64'))
            (root / 'module').write_bytes(b'inert'); (root / 'launcher').write_bytes(b'inert')
            self.assertEqual(wheel.get_tag(), ('cp313', 'cp313', 'macosx_14_0_arm64'))


if __name__ == '__main__': unittest.main()
