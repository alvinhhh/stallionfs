"""Inert checks for private Git provider selection and environment routing."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from stallionfs import _bundle, _git_runtime as runtime


VERSION = (0, b'git version 2.54.0\n', b'')
MODERN = (0, b'stallionfs-capability\n', b'')
LEGACY = (129, b'', b"error: unknown subcommand: `list'\n"
          b'usage: git hook run [--ignore-missing] [--to-stdin=<path>] <hook-name> [-- <hook-args>]\n\n')
PATHS = ((0, b'/provider/etc/gitconfig\n', b''),
         (0, b'/provider/etc/gitattributes\n', b''),
         (0, b'/provider/libexec/git-core\n', b''))


class GitRoutingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sfs-routing-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.executable = str(self.root / 'dispatcher/bin/git')
        self.environment = {
            'PATH': '/caller/bin:/fallback/bin', 'HOME': '/caller/home',
            'XDG_CONFIG_HOME': '/caller/xdg', 'SSH_AUTH_SOCK': '/caller/ssh-agent',
            'GIT_TERMINAL_PROMPT': '0', 'GIT_TRACE2': '0',
            'GIT_TRACE2_EVENT': '0', 'GIT_TRACE2_PERF': '0',
        }
        self.corrected = Path(runtime.__file__).resolve().parent / '_git'

    @contextmanager
    def routing(self, *, version=VERSION, capability=MODERN, responses=None):
        query = Mock(side_effect=responses if responses is not None
                     else [version, capability, *PATHS])
        check = Mock()
        payload_check = Mock()
        payload = Mock(return_value={'check': payload_check})
        with patch.object(runtime, '_selected', return_value=(self.executable, check)) as selected, \
                patch.object(runtime, '_query', query), \
                patch.object(runtime, 'regular_payload', payload):
            yield SimpleNamespace(query=query, check=check, payload=payload,
                                  payload_check=payload_check, selected=selected)

    def assert_reason(self, reason, function, *args):
        with self.assertRaises(runtime.GitError) as caught:
            function(*args)
        self.assertEqual(caught.exception.reason, reason)

    def test_traditional_only_keeps_selected_provider_defaults_and_authentication(self):
        for version in (b'git version 2.39.5\n', b'git version 2.50.1 (Apple Git-157)\n',
                        b'git version 99.0.0\n'):
            with self.subTest(version=version), self.routing(
                    version=(0, version, b''), capability=LEGACY) as calls:
                inherited = dict(self.environment, GIT_EXEC_PATH='/external/helpers',
                                 GIT_TEMPLATE_DIR='/external/templates',
                                 GIT_CONFIG_SYSTEM='/external/gitconfig',
                                 GIT_STALLIONFS_ATTR_SYSTEM='/ambient/attributes',
                                 GIT_STALLIONFS_CONFIG_PROVIDER='/ambient/config',
                                 GIT_STALLIONFS_UNKNOWN='/ambient/unknown')
                before = inherited.copy()
                executable, result = runtime.select(inherited)
                self.assertEqual(executable, self.executable)
                self.assertEqual(result, {key: value for key, value in before.items()
                                          if not key.startswith('GIT_STALLIONFS_')})
                self.assertEqual(inherited, before)
                self.assertEqual(calls.query.call_count, 2)
                self.assertEqual(calls.check.call_count, 2)
                calls.payload.assert_not_called()

    def test_capability_not_version_selects_configured_hook_families(self):
        for version in (b'git version 2.54.0\n', b'git version 2.30.0.vendor-backport\n'):
            with self.subTest(version=version), self.routing(version=(0, version, b'')) as calls:
                executable, result = runtime.select(self.environment)
                self.assertEqual(executable, str(self.corrected / 'bin/git'))
                self.assertEqual(result['GIT_EXEC_PATH'], str(self.corrected / 'libexec/git-core'))
                self.assertEqual(result['GIT_TEMPLATE_DIR'], str(self.corrected / 'share/git-core/templates'))
                calls.payload.assert_called_once_with(self.corrected)
                self.assertEqual(calls.payload_check.call_count, 2)

    def test_older_traditional_only_diagnostics_keep_the_original_provider(self):
        usage = b'usage: git hook run [--ignore-missing] <hook-name> [-- <hook-args>]\n\n'
        for stderr in (usage, b"error: unknown subcommand: `list'\n" + usage):
            with self.subTest(stderr=stderr), self.routing(
                    version=(0, b'git version 2.37.0\n', b''), capability=(129, b'', stderr)) as calls:
                executable, environment = runtime.select(self.environment)
                self.assertEqual(executable, self.executable)
                self.assertEqual(environment, self.environment)
                calls.payload.assert_not_called()

    def test_capability_probe_uses_private_empty_hooks_and_repo(self):
        inherited = dict(self.environment, GIT_DIR='/ambient/repo',
                         GIT_EXEC_PATH='/ambient/helpers', GIT_CONFIG_COUNT='1',
                         GIT_CONFIG_KEY_0='hook.bad.command', GIT_CONFIG_VALUE_0='bad',
                         GIT_ALLOW_PROTOCOL='file', GIT_TRACE2_EVENT='/ambient/trace')
        probes = []

        def query(executable, arguments, environment, directory):
            probes.append((list(arguments), environment.copy(), directory))
            self.assertEqual(executable, self.executable)
            root = directory.parent
            self.assertEqual(directory, root / 'repo')
            self.assertEqual(environment['HOME'], str(root / 'home'))
            self.assertEqual(environment['XDG_CONFIG_HOME'], str(root / 'xdg'))
            self.assertEqual((directory / '.git/HEAD').read_text(), 'ref: refs/heads/main\n')
            self.assertIn('repositoryformatversion = 0', (directory / '.git/config').read_text())
            for name in ('home', 'xdg', 'hooks', 'repo', 'repo/.git/objects', 'repo/.git/refs'):
                info = (root / name).stat()
                self.assertEqual(info.st_uid, os.getuid())
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
            for name in ('GIT_DIR', 'GIT_EXEC_PATH', 'GIT_CONFIG_COUNT',
                         'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0'):
                self.assertNotIn(name, environment)
            for name in ('GIT_CONFIG_NOSYSTEM', 'GIT_ATTR_NOSYSTEM'):
                self.assertEqual(environment[name], '1')
            for name in ('GIT_CONFIG_SYSTEM', 'GIT_CONFIG_GLOBAL'):
                self.assertEqual(environment[name], '/dev/null')
            for name in ('GIT_TERMINAL_PROMPT', 'GIT_PROTOCOL_FROM_USER',
                         'GIT_TRACE2', 'GIT_TRACE2_EVENT', 'GIT_TRACE2_PERF'):
                self.assertEqual(environment[name], '0')
            self.assertEqual(environment['GIT_ALLOW_PROTOCOL'], '')
            self.assertEqual(environment['LC_ALL'], 'C')
            if arguments == ['--version']:
                return VERSION
            self.assertEqual(list((root / 'hooks').iterdir()), [])
            self.assertEqual(arguments, ['-c', 'core.hooksPath=' + str(root / 'hooks'),
                '-c', 'core.fsmonitor=false', '-c', 'hook.stallionfs-capability.command=/usr/bin/false',
                '-c', 'hook.stallionfs-capability.event=post-checkout', 'hook', 'list', 'post-checkout'])
            return LEGACY

        with self.routing(responses=query) as calls:
            runtime.select(inherited)
        self.assertEqual(len(probes), 2)
        self.assertEqual(probes[0][1:], probes[1][1:])
        calls.payload.assert_not_called()
        self.assertFalse(probes[0][2].exists())

    def test_modern_queries_live_defaults_and_keeps_authentication(self):
        inherited = dict(self.environment, GIT_EXEC_PATH='/external/helpers')
        with self.routing() as calls:
            _, result = runtime.select(inherited)
        queries = calls.query.call_args_list[2:]
        prefix = ['--no-pager', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false']
        self.assertEqual([call.args[1] for call in queries],
                         [[*prefix, 'var', 'GIT_CONFIG_SYSTEM'],
                          [*prefix, 'var', 'GIT_ATTR_SYSTEM'], ['--exec-path']])
        for call in queries:
            self.assertEqual(call.args[0], self.executable)
            self.assertEqual(call.args[2], dict(inherited, LC_ALL='C'))
            self.assertEqual(call.args[3].name, 'repo')
        self.assertEqual(result['GIT_CONFIG_SYSTEM'], '/provider/etc/gitconfig')
        self.assertEqual(result['GIT_STALLIONFS_ATTR_SYSTEM'], '/provider/etc/gitattributes')
        for name in ('HOME', 'XDG_CONFIG_HOME', 'SSH_AUTH_SOCK'):
            self.assertEqual(result[name], inherited[name])

    def test_external_helpers_precede_original_path_after_corrected_runtime(self):
        override = '/not-on-path/external/git-core'
        inherited = dict(self.environment, GIT_EXEC_PATH=override)
        with self.routing(responses=[VERSION, MODERN, *PATHS[:2],
                                     (0, (override + '\n').encode(), b'')]) as calls:
            _, result = runtime.select(inherited)
        self.assertEqual(calls.query.call_args_list[-1].args[2]['GIT_EXEC_PATH'], override)
        self.assertEqual(result['PATH'].split(os.pathsep),
                         [str(self.corrected / 'bin'), str(self.corrected / 'libexec/git-core'),
                          override, *inherited['PATH'].split(os.pathsep)])
        self.assertEqual(result['GIT_EXEC_PATH'], str(self.corrected / 'libexec/git-core'))
        self.assertEqual(inherited['GIT_EXEC_PATH'], override)

    def test_apple157_provider_uses_default_exec_path_separately_from_override(self):
        version = (0, b'git version 2.50.1 (Apple Git-157)\n', b'')
        inherited = dict(self.environment, GIT_EXEC_PATH='/external/helpers')
        with self.routing(responses=[version, MODERN, *PATHS[:2],
                (0, b'/external/helpers\n', b''),
                (0, b'/apple/default/libexec/git-core\n', b'')]) as calls:
            _, result = runtime.select(inherited)
        queries = calls.query.call_args_list
        self.assertEqual(queries[-2].args[1], ['--exec-path'])
        self.assertEqual(queries[-2].args[2]['GIT_EXEC_PATH'], '/external/helpers')
        self.assertEqual(queries[-1].args[1], ['--exec-path'])
        self.assertNotIn('GIT_EXEC_PATH', queries[-1].args[2])
        self.assertEqual(result['GIT_STALLIONFS_CONFIG_PROVIDER'],
                         '/apple/default/share/git-core/gitconfig')
        self.assertEqual(result['GIT_STALLIONFS_ATTR_PROVIDER'],
                         '/apple/default/share/git-core/gitattributes')
        self.assertIn(':/external/helpers:', result['PATH'])
        self.assertNotIn('/apple/default/libexec/git-core', result['PATH'])

    def test_other_apple_family_refuses_unknown_provider_defaults(self):
        with self.routing(version=(0, b'git version 2.50.1 (Apple Git-158)\n', b'')):
            self.assert_reason('git-path-query', runtime.select, self.environment)
        with self.routing(responses=[(0, b'git version 2.50.1 (Apple Git-157)\n', b''),
                MODERN, *PATHS, (0, b'/unexpected/helpers\n', b'')]):
            self.assert_reason('git-path-query', runtime.select, self.environment)

    def test_malformed_capabilities_refuse_without_payload(self):
        malformed = [(0, b'', b''), (0, b'stallionfs-capability', b''),
            (0, b'stallionfs-capability\nextra\n', b''),
            (0, b'stallionfs-capability\n', b'warning\n'),
            (1, b'', b''), (129, b'', b''), (129, b'output\n', LEGACY[2]),
            (129, b'', LEGACY[2].rstrip()), (128, b'', LEGACY[2]),
            (-9, b'', b''), (124, b'', b'timed out\n')]
        for capability in malformed:
            with self.subTest(capability=capability), self.routing(capability=capability) as calls:
                self.assert_reason('git-capability-query', runtime.select, self.environment)
                calls.payload.assert_not_called()

    def test_failed_capability_queries_refuse_instead_of_legacy(self):
        for responses in ([runtime.GitError('git-query-failed')],
                          [VERSION, runtime.GitError('git-query-failed')]):
            with self.subTest(query=len(responses)), self.routing(responses=responses) as calls:
                self.assert_reason('git-capability-query', runtime.select, self.environment)
                calls.payload.assert_not_called()
        for version in ((1, b'git version 2.54.0\n', b''),
                        (0, b'git version 2.54.0\n', b'warning'),
                        (0, b'git version 2.54.0', b''), (0, b'not git\n', b'')):
            with self.subTest(version=version), self.routing(version=version) as calls:
                self.assert_reason('git-capability-query', runtime.select, self.environment)
                self.assertEqual(calls.query.call_count, 1)

    def test_malformed_path_results_refuse(self):
        malformed = [(1, b'/valid/path\n', b''), (0, b'/valid/path\n', b'warning'),
            (0, b'/valid/path', b''), (0, b'\n', b''), (0, b'relative\n', b''),
            (0, b'/a/../b\n', b''), (0, b'/a\nb\n', b''),
            (0, b'/a\rb\n', b''), (0, b'/a\0b\n', b''),
            (0, b'/\xff\n', b''), (0, b'/' + b'a' * 4095 + b'\n', b'')]
        for result in malformed:
            with self.subTest(result=result[:1] + (result[1][:30],)):
                self.assert_reason('git-path-query', runtime._path, result)

    def test_failed_modern_path_queries_refuse(self):
        for index in range(3):
            responses = [VERSION, MODERN, *PATHS[:index], runtime.GitError('git-query-failed')]
            with self.subTest(query=index), self.routing(responses=responses) as calls:
                self.assert_reason('git-path-query', runtime.select, self.environment)
                self.assertEqual(calls.query.call_count, index + 3)

    def test_selection_change_refuses_at_each_recheck(self):
        for index in range(4):
            with self.subTest(check=index), self.routing() as calls:
                calls.check.side_effect = [None] * index + [runtime.GitError('git-selection-changed')]
                self.assert_reason('git-selection-changed', runtime.select, self.environment)
                self.assertEqual(calls.check.call_count, index + 1)

    def test_selected_dispatcher_name_and_identity_are_retained(self):
        target = self.root / 'physical-git'
        target.write_bytes(b'private provider fixture')
        target.chmod(0o700)
        selected = self.root / 'git'
        selected.symlink_to(target)
        executable, check = runtime._selected(dict(self.environment, PATH=str(self.root)))
        self.assertEqual(executable, str(selected))
        check()
        replacement = self.root / 'replacement-git'
        replacement.write_bytes(b'replacement provider fixture')
        selected.unlink()
        selected.symlink_to(replacement)
        self.assert_reason('git-selection-changed', check)

    def test_incomplete_corrected_payload_never_falls_back(self):
        with self.routing() as calls:
            calls.payload.side_effect = ValueError('Missing Git runtime support')
            with self.assertRaisesRegex(ValueError, 'Missing Git runtime support'):
                runtime.select(self.environment)
            self.assertEqual(calls.query.call_count, 2)

    def test_payload_change_refuses_before_return(self):
        for index in range(2):
            with self.subTest(check=index), self.routing() as calls:
                calls.payload_check.side_effect = [None] * index + [ValueError('Git payload changed')]
                with self.assertRaisesRegex(ValueError, 'Git payload changed'):
                    runtime.select(self.environment)
                self.assertEqual(calls.payload_check.call_count, index + 1)

    def test_app_mode_uses_bundle_without_provider_discovery(self):
        bundle = {'git': self.root / 'App/Contents/Resources/git/bin/git',
                  'git_exec_path': self.root / 'App/Contents/Resources/git/libexec/git-core',
                  'git_template_dir': self.root / 'App/Contents/Resources/git/share/git-core/templates'}
        inherited = dict(self.environment, GIT_EXEC_PATH='/ambient/helpers',
                         GIT_STALLIONFS_ATTR_SYSTEM='/ambient/attributes')
        before = inherited.copy()
        with patch.object(_bundle, 'paths', return_value=bundle), \
                patch.object(_bundle, '_app_git', return_value={'check': Mock()}) as admitted, \
                patch.object(runtime, '_selected', side_effect=AssertionError('provider discovery')), \
                patch.object(runtime, '_query', side_effect=AssertionError('provider query')), \
                patch.object(runtime, 'regular_payload', side_effect=AssertionError('package payload')):
            executable, result = _bundle.git_environment(inherited, cwd='/unused-app-selector-cwd')
        admitted.assert_called_once_with(bundle)
        self.assertEqual(executable, str(bundle['git']))
        self.assertEqual(result['GIT_EXEC_PATH'], str(bundle['git_exec_path']))
        self.assertEqual(result['GIT_TEMPLATE_DIR'], str(bundle['git_template_dir']))
        self.assertEqual(result['PATH'], os.pathsep.join(
            (str(bundle['git'].parent), str(bundle['git_exec_path']), inherited['PATH'])))
        self.assertNotIn('GIT_STALLIONFS_ATTR_SYSTEM', result)
        self.assertEqual(result['SSH_AUTH_SOCK'], inherited['SSH_AUTH_SOCK'])
        self.assertEqual(inherited, before)

    def test_unbundled_wrapper_uses_generic_routing_and_does_not_mutate_caller(self):
        before = self.environment.copy()
        with patch.object(_bundle, 'paths', return_value=None), self.routing(capability=LEGACY):
            executable, result = _bundle.git_environment(self.environment)
        self.assertEqual(executable, self.executable)
        self.assertEqual(result, before)
        self.assertEqual(self.environment, before)

    def test_dispatcher_captures_developer_directory_once_for_legacy_and_modern(self):
        self.executable = '/usr/bin/git'
        for capability in (LEGACY, MODERN):
            before = self.environment.copy()
            responses = [(0, b'/selected/Xcode.app/Contents/Developer\n', b''), VERSION, capability]
            if capability == MODERN: responses.extend(PATHS)
            replies = iter(responses); environments = []
            def query(executable, args, environment, directory):
                environments.append(environment.copy())
                return next(replies)
            with self.subTest(capability=capability), self.routing(responses=query) as calls:
                _, result = runtime.select(self.environment)
            self.assertEqual(calls.query.call_args_list[0].args[:2], ('/usr/bin/xcode-select', ['--print-path']))
            self.assertNotIn('DEVELOPER_DIR', environments[0])
            for environment in environments[1:]:
                self.assertEqual(environment['DEVELOPER_DIR'], '/selected/Xcode.app/Contents/Developer')
            self.assertEqual(result['DEVELOPER_DIR'], '/selected/Xcode.app/Contents/Developer')
            self.assertEqual(self.environment, before)

    def test_explicit_developer_directory_is_preserved_without_selector_query(self):
        self.executable = '/usr/bin/git'
        for value in ('', '/explicit/Xcode.app/Contents/Developer', '/not-installed'):
            inherited = dict(self.environment, DEVELOPER_DIR=value)
            with self.subTest(value=value), self.routing(capability=LEGACY) as calls:
                _, result = runtime.select(inherited)
            self.assertEqual(calls.query.call_args_list[0].args[1], ['--version'])
            self.assertEqual(result['DEVELOPER_DIR'], value)
            self.assertTrue(all(call.args[2]['DEVELOPER_DIR'] == value for call in calls.query.call_args_list))

    def test_dispatcher_symlink_qualifies_but_direct_git_and_wrappers_do_not(self):
        link = self.root / 'git'; link.symlink_to('/usr/bin/git')
        for name, dispatcher in ((str(link), True), ('/usr/bin/git', True), (self.executable, False)):
            self.executable = name
            responses = ([(0, b'/selected/developer\n', b'')] if dispatcher else []) + [VERSION, LEGACY]
            with self.subTest(name=name), self.routing(responses=responses) as calls:
                runtime.select(self.environment)
            self.assertEqual(calls.query.call_args_list[0].args[0] == '/usr/bin/xcode-select', dispatcher)

    def test_developer_directory_query_failures_refuse_before_git_discovery(self):
        self.executable = '/usr/bin/git'
        responses = [(1, b'/selected\n', b''), (0, b'/selected\n', b'warning'),
                     (0, b'relative\n', b''), (0, b'/one\n/two\n', b''), (0, b'/bad\0path\n', b''),
                     (0, b'/' + b'x' * 4096 + b'\n', b''), runtime.GitError('git-query-failed')]
        for response in responses:
            with self.subTest(response=response), self.routing(responses=[response]) as calls:
                self.assert_reason('git-path-query', runtime.select, self.environment)
                self.assertEqual(calls.query.call_count, 1)
                calls.payload.assert_not_called()

    def test_pinned_developer_directory_survives_apple_default_helper_query(self):
        self.executable = '/usr/bin/git'
        version = (0, b'git version 2.54.0 (Apple Git-157)\n', b'')
        inherited = dict(self.environment, GIT_EXEC_PATH='/external/helpers')
        responses = [(0, b'/selected/developer\n', b''), version, MODERN, *PATHS[:2],
                     (0, b'/external/helpers\n', b''), (0, b'/apple/default/libexec/git-core\n', b'')]
        with self.routing(responses=responses) as calls:
            _, result = runtime.select(inherited)
        normal, default = calls.query.call_args_list[-2:]
        self.assertEqual(normal.args[2]['GIT_EXEC_PATH'], '/external/helpers')
        self.assertNotIn('GIT_EXEC_PATH', default.args[2])
        self.assertEqual(normal.args[2]['DEVELOPER_DIR'], '/selected/developer')
        self.assertEqual(default.args[2], {key: value for key, value in normal.args[2].items() if key != 'GIT_EXEC_PATH'})
        self.assertEqual(result['DEVELOPER_DIR'], '/selected/developer')

    def test_path_selection_uses_actual_child_cwd_and_preserves_path_order(self):
        parent = self.root / 'parent'; child = parent / 'child:space'
        for directory in (parent / 'bin', child / 'bin', child / 'other', child):
            directory.mkdir(parents=True, exist_ok=True)
            (directory / 'git').write_bytes(b'inert executable'); (directory / 'git').chmod(0o700)
        for path, expected in (('bin', child / 'bin/git'), ('', child / 'git'),
                               (':bin', child / 'git'), ('bin:', child / 'bin/git'),
                               ('missing::other', child / 'git'), (str(parent / 'bin'), parent / 'bin/git')):
            environment = dict(self.environment, PATH=path); before = environment.copy()
            with self.subTest(path=path), patch.object(runtime.Path, 'cwd', return_value=parent):
                selected, check = runtime._selected(environment, cwd=Path('child:space'))
            self.assertEqual(Path(selected), expected); check(); self.assertEqual(environment, before)
        with patch.object(runtime.Path, 'cwd', return_value=parent):
            selected, _ = runtime._selected(dict(self.environment, PATH='bin'))
        self.assertEqual(Path(selected), parent / 'bin/git')

    def test_path_default_symlink_parent_and_invalid_cwd_semantics(self):
        physical = self.root / 'actual'; nested = physical / 'nested'; nested.mkdir(parents=True)
        (physical / 'git').write_bytes(b'inert executable'); (physical / 'git').chmod(0o700)
        link = self.root / 'link'; link.symlink_to(nested, target_is_directory=True)
        selected, _ = runtime._selected(dict(self.environment, PATH=''), cwd=link / '..')
        self.assertEqual(Path(selected).resolve(), (physical / 'git').resolve())
        with patch.object(runtime.os, 'get_exec_path', return_value=[str(physical)]) as paths:
            selected, _ = runtime._selected({}, cwd=self.root)
        paths.assert_called_once_with({}); self.assertEqual(Path(selected), physical / 'git')
        for cwd in ('', self.root / 'missing', physical / 'git'):
            with self.subTest(cwd=cwd), self.assertRaises(OSError): runtime._selected(self.environment, cwd=cwd)

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin /var alias semantics')
    def test_path_selection_preserves_darwin_alias_and_checks_physical_identity(self):
        temporary = tempfile.TemporaryDirectory(prefix='sfs-routing-alias-', dir='/var/tmp')
        self.addCleanup(temporary.cleanup)
        lexical = Path(temporary.name)
        physical = lexical.resolve(strict=True)
        self.assertNotEqual(lexical, physical)
        self.assertEqual(lexical.stat().st_ino, physical.stat().st_ino)
        actual = physical / 'actual'; nested = actual / 'nested'
        nested.mkdir(parents=True)
        executable = actual / 'git'; executable.write_bytes(b'inert executable')
        executable.chmod(0o700)
        link = lexical / 'link'; link.symlink_to(nested, target_is_directory=True)
        selected, check = runtime._selected(dict(self.environment, PATH=''), cwd=link / '..')
        self.assertEqual(Path(selected), link / '..' / 'git')
        self.assertEqual(Path(selected).resolve(), executable)
        check()
        executable.rename(executable.with_name('git-retained'))
        executable.write_bytes(b'inert executable'); executable.chmod(0o700)
        self.assert_reason('git-selection-changed', check)

    def test_core_forwards_subprocess_cwd_and_keeps_git_dash_c_separate(self):
        from stallionfs import core
        cwd = self.root / 'child'; cwd.mkdir()
        with patch.object(_bundle, 'git_environment', return_value=('/selected/git', self.environment)) as select, \
                patch.object(core.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='ok', stderr='')) as command:
            self.assertEqual(core.run(['git', '-C', '/different-repository', 'status'], cwd=cwd, internal_git=True), 'ok')
        self.assertEqual(select.call_args.kwargs, {'cwd': cwd})
        self.assertEqual(command.call_args.kwargs['cwd'], cwd)
        self.assertEqual(command.call_args.args[0][:3], ['/selected/git', '-C', '/different-repository'])

    def test_query_enforces_execution_bounds_and_complete_results(self):
        native = ModuleType('stallionfs._native')

        def execute(arguments, record, cancelled, temporary, **options):
            self.assertEqual(arguments, [self.executable, '--exec-path'])
            self.assertEqual(options, dict(cwd=self.root, env=self.environment,
                                          output_limit=65536, deadline=8))
            self.assertIsNone(cancelled())
            record.update(reaped=True, streams_eof=True, streams_durable=True, returncode=0)
            (Path(temporary) / 'stdout').write_bytes(b'/provider/libexec/git-core\n')
            (Path(temporary) / 'stderr').write_bytes(b'')

        native.execute_owned = Mock(side_effect=execute)
        with patch.dict(sys.modules, {'stallionfs._native': native}):
            self.assertEqual(runtime._query(self.executable, ['--exec-path'], self.environment, self.root), PATHS[2])
            for missing in ('reaped', 'streams_eof', 'streams_durable'):
                def incomplete(arguments, record, *args, missing=missing, **kwargs):
                    record.update(reaped=True, streams_eof=True, streams_durable=True, returncode=0)
                    record[missing] = False
                native.execute_owned.side_effect = incomplete
                self.assert_reason('git-query-failed', runtime._query,
                                   self.executable, ['--exec-path'], self.environment, self.root)
            native.execute_owned.side_effect = TimeoutError('query deadline')
            self.assert_reason('git-query-failed', runtime._query,
                               self.executable, ['--exec-path'], self.environment, self.root)

    def test_missing_provider_does_not_fall_back_to_payload(self):
        with self.routing() as calls:
            calls.selected.side_effect = FileNotFoundError(2, 'No such file', 'git')
            with self.assertRaises(FileNotFoundError):
                runtime.select(self.environment)
            calls.query.assert_not_called()
            calls.payload.assert_not_called()


if __name__ == '__main__':
    unittest.main()
