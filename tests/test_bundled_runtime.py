"""Synthetic bundle layout/dispatch fixtures; supplied runtimes are never executed."""
from contextlib import nullcontext
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from stallionfs import _bundle

SOURCE = Path(__file__).resolve().parents[1]


class GitProvenance(unittest.TestCase):
    def test_exact_native_input_registration(self):
        profiles = {
            '9b9401eaea9d2f2b3e88c8c87509b52414b5522016c505718c050cd562725700': 'arm64',
            '020c08613be10d2d21d46a4defd6c4c98724b0af61426a9a2096e1bee48d546a': 'x86_64',
        }
        self.assertEqual(_bundle.QUALIFIED_GIT_INPUTS, frozenset(profiles))
        self.assertEqual(_bundle.QUALIFIED_GIT_ARCHITECTURES, profiles)
        for inventory, architecture in profiles.items():
            contract = dict(_bundle.GIT_CONTRACT, input_inventory_sha256=inventory)
            self.assertIs(_bundle.git_contract(contract, architecture=architecture), contract)

    def test_registration_keeps_contract_and_inventory_fences(self):
        contract = dict(_bundle.GIT_CONTRACT, input_inventory_sha256=next(iter(_bundle.QUALIFIED_GIT_INPUTS)))
        for changed in (dict(_bundle.LEGACY_GIT_CONTRACT),
                        dict(contract, input_inventory_sha256='0' * 64),
                        dict(contract, input_inventory_sha256='502cd32f075e275a2638b0b11533ba5b9909e2750f29ea272f7e05f9d9d49107'),
                        dict(contract, combined_patch_sha256='0' * 64),
                        dict(contract, schema=True),
                        {key: value for key, value in contract.items() if key != 'notice_patch_sha256'}):
            with self.subTest(contract=changed), self.assertRaises(_bundle.BundleError):
                _bundle.git_contract(changed)
        unregistered = dict(contract, input_inventory_sha256='0' * 64)
        self.assertIs(_bundle.git_contract(unregistered, qualified=False), unregistered)


def put(path, data=b'fixture', mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


def json_file(path, value):
    return put(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


class PrivateFixture(unittest.TestCase):
    def setUp(self):
        old = os.umask(0o077)
        self.addCleanup(os.umask, old)
        self.temporary = tempfile.TemporaryDirectory(prefix='bundle-fixture-', dir=SOURCE.parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)

    def bundle(self, name='Original With Spaces.app'):
        app = self.root / name
        for key, value in _bundle.RELATIVE_PATHS.items():
            target = app / value
            if key in ('site_packages', 'git_exec_path', 'git_template_dir'):
                target.mkdir(parents=True, exist_ok=True)
            else:
                put(target, mode=0o755)
        site = app / _bundle.RELATIVE_PATHS['site_packages']
        for name in ('__init__.py', '__main__.py', '_bundle.py', '_scan.cpython-313-darwin.so', '_image.cpython-313-darwin.so'):
            put(site / 'stallionfs' / name)
        for name in ('sfs', 'stallionfs'):
            put((app / _bundle.RELATIVE_PATHS['helper']).with_name(name), mode=0o755)
        payload = _bundle.git_payload((app / _bundle.RELATIVE_PATHS['git']).parent.parent)
        descriptor = {'schema': 2, 'git': dict(_bundle.GIT_CONTRACT, input_inventory_sha256='6' * 64,
                      payload_entries=payload['entries'], payload_sha256=payload['sha256']),
                      'python_version': '3.13.18', 'soabi': 'cpython-313-darwin',
                      'package_version': '0.7.0', 'source_build_id': 'a' * 64, 'bundle_version': '9',
                      'paths': dict(_bundle.RELATIVE_PATHS)}
        json_file(app / _bundle.DESCRIPTOR, descriptor)
        app.chmod(0o755)
        return app, site / 'stallionfs/_bundle.py'

    def bootstrap(self, app, module, arguments, *, extra_search_paths=(), preloaded=None):
        namespace = runpy.run_path(str(module), run_name='direct_script_definitions')
        runtime = app / 'Contents/Resources/Runtime/CPython'
        paths = [str(runtime / 'lib/python313.zip'), str(runtime / 'lib/python3.13'),
                 str(runtime / 'lib/python3.13/lib-dynload')]
        flags = SimpleNamespace(**{name: getattr(sys.flags, name) for name in dir(sys.flags)
                                   if not name.startswith('_') and isinstance(getattr(sys.flags, name), (int, bool))})
        for name in ('isolated', 'ignore_environment', 'safe_path', 'no_user_site', 'no_site', 'dont_write_bytecode'):
            setattr(flags, name, 1)
        with patch.dict(sys.modules), patch.object(sys, 'path', paths + list(extra_search_paths)), \
                patch.object(sys, 'argv', [str(module), str(app / _bundle.RELATIVE_PATHS['helper']), *arguments]), \
                patch.object(sys, 'executable', str(app / _bundle.RELATIVE_PATHS['python'])), \
                patch.object(sys, 'version_info', (3, 13, 18)), patch.object(sys, 'flags', flags), \
                patch.object(sys, 'implementation', SimpleNamespace(name='cpython', cache_tag='cpython-313')), \
                patch.object(sys, 'abiflags', '', create=True), patch.object(sys, '_is_gil_enabled', return_value=True, create=True):
            for name in tuple(sys.modules):
                if name == 'stallionfs' or name.startswith('stallionfs.'):
                    sys.modules.pop(name)
            sys.modules.update(preloaded or {})
            return namespace['main']()


class ApplicationsAnchor(unittest.TestCase):
    def walk(self, path, *, overrides=None, event=None, group=80, admin_record=None,
             admin_error=None, file=False):
        """Route the real descriptor walk through a small synthetic directory tree."""
        path = Path(path)
        nodes = {'/': SimpleNamespace(st_dev=1, st_ino=1, st_mode=stat.S_IFDIR | 0o755,
                 st_uid=0, st_gid=0, st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)}
        current = Path('/')
        for part in path.parts[1:]:
            current /= part
            nodes[str(current)] = SimpleNamespace(st_dev=1, st_ino=len(nodes) + 1,
                    st_mode=stat.S_IFDIR | (0o775 if str(current) == '/Applications' else 0o755),
                    st_uid=0 if str(current) == '/Applications' else 501,
                    st_gid=group if str(current) == '/Applications' else 20,
                    st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
        for name, values in (overrides or {}).items():
            nodes[name] = SimpleNamespace(**(vars(nodes[name]) | values))
        active, anchor_stats, flags_seen = {}, [], []
        numbers = iter(range(10, 100))

        def allocate(name, info):
            fd = next(numbers)
            active[fd] = (name, info)
            return fd

        def open_(name, flags, *, dir_fd=None):
            resolved = name if dir_fd is None else str(Path(active[dir_fd][0]) / name)
            flags_seen.append(flags)
            self.assertEqual(flags & _bundle.NOFOLLOW, _bundle.NOFOLLOW)
            if event == 'open-error' and resolved == '/Applications':
                raise OSError('fixture open failure')
            info = nodes[resolved]
            if stat.S_ISDIR(info.st_mode):
                self.assertTrue(flags & os.O_DIRECTORY)
            if event == 'before-open' and resolved == '/Applications':
                info = SimpleNamespace(**(vars(info) | {'st_ino': 99}))
            return allocate(resolved, info)

        def stat_(name, *, dir_fd, follow_symlinks):
            self.assertFalse(follow_symlinks)
            parent = active[dir_fd][0]
            resolved = str(Path(parent) / name)
            info = nodes[resolved]
            if resolved == '/Applications':
                anchor_stats.append(parent)
                if len(anchor_stats) == 2:
                    if event == 'final-stat-error':
                        raise OSError('fixture final stat failure')
                    if event in ('final-name', 'final-ctime'):
                        key = 'st_ino' if event == 'final-name' else 'st_ctime_ns'
                        info = SimpleNamespace(**(vars(info) | {key: 99}))
            return info

        def dup(fd):
            name, info = active[fd]
            if event == 'dup-error' and name == '/Applications':
                raise OSError('fixture duplicate failure')
            return allocate(name, info)

        fake_os = SimpleNamespace(**{name: getattr(os, name) for name in
                     ('O_RDONLY', 'O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK')},
                     open=open_, stat=stat_, fstat=lambda fd: active[fd][1],
                     close=lambda fd: active.pop(fd), dup=dup, getuid=lambda: 501)
        record = admin_record if admin_record is not None else SimpleNamespace(gr_name='admin', gr_gid=group)
        with patch.object(_bundle, 'os', fake_os), patch('grp.getgrnam', return_value=record,
                side_effect=admin_error) as lookup:
            try:
                result = _bundle._file(path) if file else _bundle._directory(path)
            except BaseException:
                self.assertEqual(active, {}, 'walk leaked a descriptor on refusal')
                raise
            if file:
                self.assertEqual(active, {})
            else:
                self.assertEqual(set(active), {result}, 'walk retained extra descriptors')
                fake_os.close(result)
            self.assertEqual(active, {})
            return dict(anchor_stats=anchor_stats, lookup=lookup.call_args_list, flags=flags_seen)

    def test_exact_standard_anchor_accepts_os_admin_0755_and_0775(self):
        for mode, group in ((0o755, 80), (0o775, 80), (0o775, 420)):
            with self.subTest(mode=oct(mode), group=group):
                result = self.walk('/Applications/StallionFS.app/Contents/Resources', group=group,
                        overrides={'/Applications': {'st_mode': stat.S_IFDIR | mode}})
                self.assertEqual(result['anchor_stats'], ['/', '/'])
                self.assertEqual(len(result['lookup']), 1)
                self.assertEqual(result['lookup'][0].args, ('admin',))

    def test_missing_or_invalid_admin_record_refuses(self):
        for error in (KeyError('admin'), OSError('fixture lookup failure'), ImportError('grp')):
            with self.subTest(error=type(error).__name__), self.assertRaises(ValueError):
                self.walk('/Applications/StallionFS.app/Contents', admin_error=error)
        records = [SimpleNamespace(), SimpleNamespace(gr_name='other', gr_gid=80)]
        records += [SimpleNamespace(gr_name='admin', gr_gid=value) for value in (-1, 2**32, True, '80')]
        for record in records:
            with self.subTest(record=vars(record)), self.assertRaises(ValueError):
                self.walk('/Applications/StallionFS.app/Contents', admin_record=record)

    def test_unsafe_anchor_metadata_refuses(self):
        cases = [{'st_uid': 501}, {'st_gid': 79},
                 {'st_mode': stat.S_IFREG | 0o775}, {'st_mode': stat.S_IFLNK | 0o775}]
        cases += [{'st_mode': stat.S_IFDIR | mode} for mode in (0o777, 0o1775, 0o2775, 0o4775)]
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.walk('/Applications/StallionFS.app/Contents', overrides={'/Applications': values})

    def test_other_paths_never_receive_anchor_exception(self):
        cases = [('/Other/StallionFS.app/Contents', {'/Other': {'st_mode': stat.S_IFDIR | 0o775}}),
                 ('/Applications/Sibling.app/Contents', {}),
                 ('/Applications/StallionFS.app.extra/Contents', {}),
                 ('/Applications/Nested/StallionFS.app/Contents', {}),
                 ('/private/tmp/StallionFS.app/Contents', {'/private/tmp': {'st_mode': stat.S_IFDIR | 0o1777}})]
        for path, overrides in cases:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.walk(path, overrides=overrides)
        for path in ('/workspace/StallionFS.app/Contents', '/workspace/Renamed.app/Contents'):
            with self.subTest(path=path):
                self.assertEqual(self.walk(path)['lookup'], [])

    def test_app_and_payload_permissions_remain_strict(self):
        for name in ('/Applications/StallionFS.app', '/Applications/StallionFS.app/Contents',
                     '/Applications/StallionFS.app/Contents/Applications'):
            with self.subTest(path=name), self.assertRaises(ValueError):
                self.walk('/Applications/StallionFS.app/Contents/Applications',
                          overrides={name: {'st_mode': stat.S_IFDIR | 0o775}})
        with self.assertRaises(ValueError):
            self.walk('/Applications/StallionFS.app/payload', file=True,
                      overrides={'/Applications/StallionFS.app/payload': {'st_mode': stat.S_IFREG | 0o664}})

    def test_replacement_and_open_errors_refuse_without_descriptor_leaks(self):
        for event in ('before-open', 'final-name', 'final-ctime', 'open-error', 'dup-error', 'final-stat-error'):
            with self.subTest(event=event), self.assertRaises((ValueError, OSError)):
                self.walk('/Applications/StallionFS.app/Contents/Resources', event=event)


class BundlePaths(PrivateFixture):
    def test_physical_layout_and_relocation(self):
        original, module = self.bundle()
        with patch.object(_bundle, '__file__', str(module)):
            paths = _bundle.paths()
        moved = self.root / 'Moved With Spaces.app'
        original.rename(moved)
        with patch.object(_bundle, '__file__', str(moved / module.relative_to(original))):
            relocated = _bundle.paths()
        for key in _bundle.RELATIVE_PATHS:
            self.assertEqual(paths[key].relative_to(original), relocated[key].relative_to(moved))
        with patch.object(_bundle, '__file__', str(SOURCE / 'stallionfs/_bundle.py')):
            self.assertIsNone(_bundle.paths())

    def test_invalid_apparent_bundle_never_falls_back(self):
        app, module = self.bundle()
        for mutation in ('descriptor', 'missing-git', 'mode', 'symlink', 'wrong-minor'):
            with self.subTest(mutation=mutation):
                candidate = self.root / (mutation + '.app')
                shutil.copytree(app, candidate)
                path = candidate / module.relative_to(app)
                if mutation == 'descriptor': (candidate / _bundle.DESCRIPTOR).write_text('{}')
                elif mutation == 'missing-git': (candidate / _bundle.RELATIVE_PATHS['git']).unlink()
                elif mutation == 'mode': candidate.chmod(0o777)
                elif mutation == 'symlink':
                    target = candidate / _bundle.RELATIVE_PATHS['python']
                    target.unlink()
                    target.symlink_to(self.root / 'outside')
                else: path = Path(str(path).replace('python3.13', 'python3.12'))
                with patch.object(_bundle, '__file__', str(path)), self.assertRaises((ValueError, OSError)):
                    _bundle.paths()

    def test_same_uid_cannot_make_runtime_or_ancestors_writable_or_special(self):
        app, module = self.bundle()
        cases = [('git', 0o775), ('git', 0o757), ('git', 0o4755),
                 ('site_packages', 0o2775), ('git_template_dir', 0o1755),
                 ('ancestor', 0o770), ('descriptor', 0o666)]
        for index, (key, mode) in enumerate(cases):
            with self.subTest(key=key, mode=oct(mode)):
                candidate = self.root / ('unsafe-%d.app' % index)
                shutil.copytree(app, candidate)
                target = (candidate.parent if key == 'ancestor' else
                          candidate / (_bundle.DESCRIPTOR if key == 'descriptor' else _bundle.RELATIVE_PATHS[key]))
                original_mode = stat.S_IMODE(target.stat().st_mode)
                self.assertEqual(target.stat().st_uid, os.getuid())
                target.chmod(mode)
                try:
                    if stat.S_IMODE(target.stat().st_mode) != mode:
                        self.skipTest('filesystem did not retain requested mode ' + oct(mode))
                    with patch.object(_bundle, '__file__', str(candidate / module.relative_to(app))), \
                            self.assertRaises((ValueError, OSError)):
                        _bundle.paths()
                finally:
                    target.chmod(original_mode)

    def test_runtime_directory_and_module_aliases_are_rejected(self):
        for key in ('site_packages', 'git_exec_path', 'git_template_dir', 'module', 'app'):
            with self.subTest(key=key):
                app, module = self.bundle(key + '.app')
                target = (app if key == 'app' else module if key == 'module' else
                          app / _bundle.RELATIVE_PATHS[key])
                retained = target.with_name(target.name + '-retained')
                target.rename(retained)
                target.symlink_to(retained.name, target_is_directory=retained.is_dir())
                with patch.object(_bundle, '__file__', str(module)), self.assertRaises((ValueError, OSError)):
                    _bundle.paths()

    def test_direct_script_bootstrap_preserves_cwd_argv_and_package_context(self):
        app, module = self.bundle()
        module.write_bytes((SOURCE / 'stallionfs/_bundle.py').read_bytes())
        site = module.parent.parent
        put(site / 'stallionfs/__init__.py', b'__version__ = "0.7.0"\n')
        put(site / 'stallionfs/__main__.py', b'import os, sys\ndef main():\n return {"argv": list(sys.argv), "cwd": os.getcwd(), "origin": __file__}\n')
        helper = app / _bundle.RELATIVE_PATHS['helper']
        before_cwd, before_environment = os.getcwd(), dict(os.environ)
        arguments = ['scan', '', 'spaces Ω path', 'line\nbreak', '--', '$(touch never)', '*', '"quoted"']
        result = self.bootstrap(app, module, arguments)
        self.assertEqual(result['argv'], [str(helper), *arguments])
        self.assertEqual(result['origin'], str(site / 'stallionfs/__main__.py'))
        self.assertEqual(result['cwd'], before_cwd)
        self.assertEqual(os.getcwd(), before_cwd)
        self.assertEqual(dict(os.environ), before_environment)

    def test_bootstrap_refuses_hostile_import_roots_before_importing_them(self):
        app, module = self.bundle()
        module.write_bytes((SOURCE / 'stallionfs/_bundle.py').read_bytes())
        marker = self.root / 'hostile-imported'
        hostile = self.root / 'Hostile Import Root'
        put(hostile / 'stallionfs/__init__.py',
            ('from pathlib import Path\nPath(%r).touch()\n' % str(marker)).encode())
        for injected in ('', str(hostile)):
            with self.subTest(search_path=injected), self.assertRaisesRegex(ValueError, 'search path'):
                self.bootstrap(app, module, ['--help'], extra_search_paths=[injected])
        self.assertFalse(marker.exists())

    def test_bootstrap_uses_validated_package_with_hostile_cwd_and_environment(self):
        app, module = self.bundle()
        module.write_bytes((SOURCE / 'stallionfs/_bundle.py').read_bytes())
        put(module.parent / '__init__.py', b'__version__ = "0.7.0"\n')
        put(module.parent / '__main__.py', b'import os\ndef main():\n return os.getcwd()\n')
        marker = self.root / 'hostile-imported'
        locations = [self.root / name for name in ('Caller Cwd', 'Python Path', 'User Site')]
        for location in locations:
            put(location / 'stallionfs/__init__.py',
                ('from pathlib import Path\nPath(%r).touch()\n' % str(marker)).encode())
        previous_cwd = os.getcwd()
        try:
            os.chdir(locations[0])
            with patch.dict(os.environ, {'PYTHONPATH': str(locations[1]), 'PYTHONUSERBASE': str(locations[2])}):
                environment = dict(os.environ)
                self.assertEqual(self.bootstrap(app, module, ['--help']), str(locations[0]))
                self.assertEqual(os.getcwd(), str(locations[0]))
                self.assertEqual(dict(os.environ), environment)
        finally:
            os.chdir(previous_cwd)
        self.assertFalse(marker.exists())

    def test_bootstrap_refuses_preloaded_outside_package_before_cli_dispatch(self):
        app, module = self.bundle()
        module.write_bytes((SOURCE / 'stallionfs/_bundle.py').read_bytes())
        outside = put(self.root / 'outside.py')
        package = ModuleType('stallionfs')
        package.__file__, package.__version__ = str(outside), '0.7.0'
        package.__path__ = [str(outside.parent)]
        entry = ModuleType('stallionfs.__main__')
        entry.__file__ = str(outside)
        entry.main = Mock(side_effect=AssertionError('outside CLI dispatched'))
        package.__main__ = entry
        with self.assertRaises(ValueError):
            self.bootstrap(app, module, ['--help'], preloaded={'stallionfs': package, 'stallionfs.__main__': entry})
        entry.main.assert_not_called()

    def test_shell_helper_preserves_each_argument_without_shell_evaluation(self):
        app, _ = self.bundle()
        helper = app / _bundle.RELATIVE_PATHS['helper']
        helper.write_bytes((SOURCE / 'filesystem/fskit/stallionfs-python.sh').read_bytes())
        python = app / _bundle.RELATIVE_PATHS['python']
        put(python, b'#!/bin/sh\nprintf "%s\\0" "$PWD" "$@"\n', 0o755)
        cwd = self.root / 'Caller Ω With Spaces'
        cwd.mkdir()
        marker = cwd / 'evaluated'
        arguments = ['', '--', '-n', 'line\nbreak', 'space Ω', '$(touch evaluated)',
                     '`touch evaluated`', '*', '; touch evaluated', '"quoted"', '\\backslash']
        result = subprocess.run([str(helper), *arguments], cwd=cwd, env={'PATH': '/missing'},
                                capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split(b'\0')[:-1],
                         [os.fsencode(value) for value in [str(cwd), '-I', '-B', '-S',
                          str(helper.parent / '../lib/python3.13/site-packages/stallionfs/_bundle.py'),
                          str(helper), *arguments]])
        self.assertFalse(marker.exists())

    def test_shell_helper_refuses_nonphysical_and_symlink_invocations_before_dispatch(self):
        app, _ = self.bundle()
        helper = app / _bundle.RELATIVE_PATHS['helper']
        helper.write_bytes((SOURCE / 'filesystem/fskit/stallionfs-python.sh').read_bytes())
        marker = self.root / 'python-dispatched'
        put(app / _bundle.RELATIVE_PATHS['python'],
            ('#!/bin/sh\nprintf dispatched > "%s"\n' % marker).encode(), 0o755)
        for spelling in (str(helper.parent) + '/./' + helper.name,
                         str(helper.parent) + '/../bin/' + helper.name,
                         str(helper.parent) + '//' + helper.name):
            with self.subTest(spelling=spelling):
                result = subprocess.run(['/bin/sh', spelling], capture_output=True, timeout=5, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())
        retained = helper.with_name('retained-helper')
        helper.rename(retained)
        helper.symlink_to(retained.name)
        result = subprocess.run([str(helper)], capture_output=True, timeout=5, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())

    def test_shell_helper_uses_fixed_paths_and_clears_startup_variables(self):
        app, _ = self.bundle()
        helper = app / _bundle.RELATIVE_PATHS['helper']
        helper.write_bytes((SOURCE / 'filesystem/fskit/stallionfs-python.sh').read_bytes())
        python = app / _bundle.RELATIVE_PATHS['python']
        put(python, b'#!/bin/sh\nprintf "cwd=%s\\n" "$PWD"\nprintf "arg=%s\\n" "$@"\nprintf "startup=%s:%s:%s\\n" "${ENV-unset}" "${BASH_ENV-unset}" "${CDPATH-unset}"\n', 0o755)
        marker = self.root / 'startup-marker'
        startup = put(self.root / 'startup.sh', ('printf bad > ' + str(marker) + '\n').encode())
        cwd = self.root / 'Caller Cwd'
        cwd.mkdir()
        env = dict(os.environ, ENV=str(startup), BASH_ENV=str(startup), CDPATH='/wrong', PATH='/missing')
        before = dict(os.environ)
        result = subprocess.run([str(helper), '--help', 'space Ω'], cwd=cwd, env=env,
                                capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('cwd=' + str(cwd), result.stdout)
        self.assertIn('arg=-I\narg=-B\narg=-S\n', result.stdout)
        self.assertIn('arg=' + str(helper) + '\narg=--help\narg=space Ω\n', result.stdout)
        self.assertIn('startup=unset:unset:unset', result.stdout)
        self.assertFalse(marker.exists())
        self.assertEqual(dict(os.environ), before)
        relative = os.path.relpath(helper, cwd)
        refused = subprocess.run(['/bin/sh', relative], cwd=cwd, env=env,
                                 capture_output=True, text=True, timeout=5, check=False)
        self.assertNotEqual(refused.returncode, 0)
        alias = self.root / 'helper-link'
        alias.symlink_to(helper)
        refused = subprocess.run([str(alias)], cwd=cwd, env=env,
                                 capture_output=True, text=True, timeout=5, check=False)
        self.assertNotEqual(refused.returncode, 0)

    def test_benchmark_preflight_resolves_native_helper_sibling_without_native_probes(self):
        from stallionfs import benchmark
        app, _ = self.bundle()
        helper = app / _bundle.RELATIVE_PATHS['helper']
        arguments = SimpleNamespace(full=False, fixtures=None, operations=None, jobs=4,
                                    node=None, npm=None, npm_cache=None, cache=['warm'],
                                    scratch=self.root, output=None)
        # This fixture tests selection only; native directory protection is not exercised.
        directory = SimpleNamespace(path=self.root)
        with patch.object(sys, 'platform', 'darwin'), patch.object(sys, 'argv', [str(helper)]), \
                patch.object(benchmark, 'TOOLS', ()), patch.object(benchmark, '_resources', return_value=self.root), \
                patch.object(benchmark, '_PinnedDirectory', return_value=nullcontext(directory)), \
                patch.object(benchmark.sysconfig, 'get_path', side_effect=AssertionError('wrong script root')), \
                patch.object(benchmark.shutil, 'disk_usage', return_value=SimpleNamespace(free=10**15)), \
                patch.object(benchmark.subprocess, 'run', side_effect=AssertionError('unexpected execution')):
            _, binary, parent, _, _ = benchmark._preflight(arguments)
        self.assertEqual(binary, helper.with_name('stallionfs'))
        self.assertEqual(parent, self.root)


class GitRouting(PrivateFixture):
    def setUp(self):
        super().setUp()
        scan = ModuleType('stallionfs._scan')
        scan._private_directory = lambda *args: None
        with patch.dict(sys.modules, {'stallionfs._scan': scan}):
            from stallionfs import core
        self.core = core

    def test_internal_git_sanitizes_then_selects_for_both_execution_paths(self):
        app, module = self.bundle()
        hostile = {'GIT_DIR': '/wrong', 'GIT_WORK_TREE': '/wrong', 'GIT_EXEC_PATH': '/wrong',
                   'GIT_TEMPLATE_DIR': '/wrong', 'GIT_CONFIG_COUNT': '1', 'PATH': '/fake/user/path'}
        for budgeted in (False, True):
            with self.subTest(budgeted=budgeted), patch.dict(os.environ, hostile), \
                    patch.object(_bundle, '__file__', str(module)):
                if budgeted:
                    tool = ModuleType('stallionfs._benchmark_budget')
                    tool.command = lambda *args, **kwargs: None
                    context = patch.dict(sys.modules, {'stallionfs._benchmark_budget': tool})
                    with context, patch.dict(os.environ, {'STALLIONFS_BENCHMARK_DEADLINE': 'fixture'}), \
                            patch.object(tool, 'command', return_value=SimpleNamespace(returncode=0, stdout=b'ok', stderr=b'')) as command:
                        self.assertEqual(self.core.git('/Repo spaces Ω', 'status', '--', 'file\nname'), 'ok')
                else:
                    with patch.dict(os.environ, {'STALLIONFS_BENCHMARK_DEADLINE': ''}), \
                            patch.object(self.core.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='ok', stderr='')) as command:
                        self.assertEqual(self.core.git('/Repo spaces Ω', 'status', '--', 'file\nname'), 'ok')
                call = command.call_args
                argv = call.args[0]
                environment = call.kwargs['environment' if budgeted else 'env']
                self.assertEqual(argv[0], str(app / _bundle.RELATIVE_PATHS['git']))
                self.assertNotIn('GIT_DIR', environment)
                self.assertNotIn('GIT_CONFIG_COUNT', environment)
                self.assertEqual(environment['GIT_EXEC_PATH'], str(app / _bundle.RELATIVE_PATHS['git_exec_path']))
                self.assertEqual(environment['GIT_TEMPLATE_DIR'], str(app / _bundle.RELATIVE_PATHS['git_template_dir']))
                self.assertEqual(environment['GIT_TERMINAL_PROMPT'], '0')
                self.assertTrue(environment['PATH'].endswith(':/fake/user/path'))
                self.assertIn('core.hooksPath=/dev/null', argv)
                self.assertEqual(argv[-5:], ['-C', '/Repo spaces Ω', 'status', '--', 'file\nname'])
                self.assertIsNone(call.kwargs['cwd'])
                self.assertEqual(os.environ['GIT_EXEC_PATH'], '/wrong')

    def test_internal_git_preserves_run_cwd_and_caller_argument_list(self):
        app, module = self.bundle()
        cwd = self.root / 'Caller Cwd Ω'
        cwd.mkdir()
        args = ['git', 'config', '--get', 'key with space', '', 'line\nbreak']
        original = list(args)
        for budgeted in (False, True):
            with self.subTest(budgeted=budgeted), patch.object(_bundle, '__file__', str(module)):
                if budgeted:
                    tool = ModuleType('stallionfs._benchmark_budget')
                    tool.command = Mock(return_value=SimpleNamespace(returncode=0, stdout=b'ok', stderr=b''))
                    with patch.dict(sys.modules, {'stallionfs._benchmark_budget': tool}), \
                            patch.dict(os.environ, {'STALLIONFS_BENCHMARK_DEADLINE': 'fixture'}):
                        self.assertEqual(self.core.run(args, cwd=cwd, internal_git=True), 'ok')
                    command = tool.command
                else:
                    with patch.dict(os.environ, {'STALLIONFS_BENCHMARK_DEADLINE': ''}), \
                            patch.object(self.core.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='ok', stderr='')) as command:
                        self.assertEqual(self.core.run(args, cwd=cwd, internal_git=True), 'ok')
                self.assertEqual(command.call_args.args[0], [str(app / _bundle.RELATIVE_PATHS['git']), *original[1:]])
                self.assertEqual(command.call_args.kwargs['cwd'], cwd)
                self.assertEqual(args, original)

    def test_bundled_generic_command_does_not_select_private_git(self):
        app, module = self.bundle()
        with patch.object(_bundle, '__file__', str(module)), \
                patch.dict(os.environ, {'PATH': '/caller/path', 'STALLIONFS_BENCHMARK_DEADLINE': ''}), \
                patch.object(self.core.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='', stderr='')) as command:
            self.core.run(['git', '--version'])
        self.assertEqual(command.call_args.args[0], ['git', '--version'])
        self.assertEqual(command.call_args.kwargs['env']['PATH'], '/caller/path')
        self.assertNotIn('GIT_EXEC_PATH', command.call_args.kwargs['env'])

    def test_generic_commands_and_unbundled_git_keep_existing_path(self):
        for internal in (False, True):
            with patch.object(_bundle, '__file__', str(SOURCE / 'stallionfs/_bundle.py')), \
                    patch.dict(os.environ, {'PATH': '/user/path', 'GIT_DIR': '/wrong', 'STALLIONFS_BENCHMARK_DEADLINE': ''}), \
                    patch('stallionfs._git_runtime.select', side_effect=lambda env, *, cwd=None: ('git', env)), \
                    patch.object(self.core.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='', stderr='')) as command:
                self.core.run(['git', '--version'], internal_git=internal)
            self.assertEqual(command.call_args.args[0], ['git', '--version'])
            self.assertEqual(command.call_args.kwargs['env']['PATH'], '/user/path')
            self.assertNotIn('GIT_EXEC_PATH', command.call_args.kwargs['env'])

    def test_missing_bundled_git_refuses_without_subprocess(self):
        app, module = self.bundle()
        (app / _bundle.RELATIVE_PATHS['git']).unlink()
        with patch.object(_bundle, '__file__', str(module)), patch.object(self.core.subprocess, 'run') as command:
            with self.assertRaisesRegex(self.core.StallionError, 'Invalid bundled Git'):
                self.core.git('/repo', 'status')
        command.assert_not_called()

    def test_doctor_marks_its_git_version_as_an_internal_operation(self):
        store = self.core.Store.__new__(self.core.Store)
        store.root = self.root
        (self.root / 'staging').mkdir()
        stage = self.root / 'doctor-stage'
        stage.mkdir()
        with patch.object(store, 'staging', return_value=nullcontext(stage)), \
                patch.object(self.core, 'clone_tree', side_effect=shutil.copytree), \
                patch.object(self.core, 'run', return_value='git fixture') as command:
            self.assertEqual(store.doctor()['git'], 'git fixture')
        command.assert_called_once_with(['git', '--version'], internal_git=True)


if __name__ == '__main__':
    unittest.main()
