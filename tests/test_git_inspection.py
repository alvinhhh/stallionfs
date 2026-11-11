"""Bounded data inspection with separate product and qualified native routes."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from stallionfs import _bundle, _native, core, _native_create_git as git
from stallionfs.lifecycle import Lifecycle


class GitInspection(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='git-inspection-'); self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve() / 'repo'; self.repo.mkdir(mode=0o700)
        (self.repo / '.git').mkdir(mode=0o700)
        (self.repo / '.git/config').write_text('[core]\nrepositoryformatversion=0\nbare=false\n')
        (self.repo / '.git/HEAD').write_text('ref: refs/heads/main\n')
        self.runtime = {'executable': '/corrected/bin/git', 'exec_path': '/corrected/libexec/git-core', 'check': Mock()}
        self.config = b'core.repositoryformatversion\n0\0core.bare\nfalse\0'
        self.refs = b'HEAD\nrefs/heads/main\n'
        self.calls = []
        selected = patch.object(_bundle, 'product_git', return_value=self.runtime)
        selected.start(); self.addCleanup(selected.stop)
        for name in ('qualified_runtime',):
            forbidden = patch.object(git, name, side_effect=AssertionError('native authority'))
            forbidden.start(); self.addCleanup(forbidden.stop)
        generic = patch.object(_bundle, 'git_environment', side_effect=AssertionError('provider selection'))
        generic.start(); self.addCleanup(generic.stop)
        executor = patch.object(_native, 'execute_owned', side_effect=self.execute)
        executor.start(); self.addCleanup(executor.stop)

    def execute(self, argv, receipt, persist, log, **options):
        self.calls.append((argv, options))
        self.assertEqual(argv[0], self.runtime['executable'])
        self.assertEqual(argv[1:1 + len(git.PREFIX)], git.PREFIX)
        env = options['env']
        self.assertEqual(env['GIT_EXEC_PATH'], self.runtime['exec_path'])
        self.assertEqual(env['GIT_CONFIG_NOSYSTEM'], '1'); self.assertEqual(env['GIT_ATTR_NOSYSTEM'], '1')
        self.assertEqual(env['GIT_ALLOW_PROTOCOL'], '')
        for name in ('GIT_TRACE2', 'GIT_TRACE2_EVENT', 'GIT_TRACE2_PERF'): self.assertEqual(env[name], '0')
        for name in ('GIT_DIR', 'DYLD_INSERT_LIBRARIES', 'GIT_STALLIONFS_ATTR_SYSTEM'): self.assertNotIn(name, env)
        self.assertEqual(options['output_limit'], git.OUTPUT_CAP)
        data = self.refs if 'for-each-ref' in argv else self.config
        receipt.update(returncode=0, outcome='success', child_pending=False, pid=123,
                       reaped=True, streams_eof=True, streams_durable=True, output_bytes=len(data))
        (log / 'stdout').write_bytes(data)
        return receipt

    def test_config_is_admitted_before_exact_root_ref_query(self):
        hostile = {'HOME': '/ambient', 'GIT_DIR': '/ambient', 'DYLD_INSERT_LIBRARIES': '/ambient',
                   'GIT_STALLIONFS_ATTR_SYSTEM': '/ambient', 'GIT_TRACE2': '/ambient'}
        with patch.dict(os.environ, hostile):
            self.assertEqual(git.inspect_refs(self.repo), ['HEAD', 'refs/heads/main'])
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.calls[0][0][-5:], ['--file', str(self.repo / '.git/config'), '--no-includes', '--null', '--list'])
        self.assertEqual(self.calls[1][0][-3:], ['for-each-ref', '--include-root-refs', '--format=%(refname)'])
        self.assertEqual(self.calls[0][1]['env'], self.calls[1][1]['env'])

    def test_lifecycle_config_parser_never_uses_original_provider(self):
        self.assertEqual(git.inspect_standalone(self.repo, branch=True, structure_required=False),
                         {'core.repositoryformatversion': '0', 'core.bare': 'false'})
        self.assertEqual(len(self.calls), 1)

    def mounted_fixture(self):
        container = self.repo.parent / 'workspace'
        (container / 'volume').mkdir(parents=True)
        self.repo.rename(container / 'volume/repo')
        self.repo = container / 'volume/repo'
        return container, Lifecycle()

    def test_native_usable_forwards_the_exact_qualified_runtime_through_shared_inspector(self):
        container, store = self.mounted_fixture()
        self.runtime = dict(self.runtime, executable='/qualified/bin/git', exec_path='/qualified/libexec/git-core')
        with patch.object(git, 'qualified_runtime', return_value=self.runtime) as qualified, \
                patch.object(_bundle, 'product_git', side_effect=AssertionError('product fallback')) as product, \
                patch.object(core, 'validate_tree'), \
                patch.object(store, '_standalone_git', wraps=store._standalone_git) as standalone, \
                patch.object(git, 'inspect_standalone', wraps=git.inspect_standalone) as inspect, \
                patch.object(git, '_inspect', wraps=git._inspect) as parser:
            self.assertEqual(_native._usable(store, container, {'native_host': '/explicit/Host'}, initial=False), str(self.repo))
        qualified.assert_called_once_with('/explicit/Host')
        product.assert_not_called()
        for call in (standalone.call_args, inspect.call_args, parser.call_args):
            self.assertIs(call.kwargs['runtime'], self.runtime)
        self.assertEqual(len(self.calls), 1)
        self.runtime['check'].assert_called()

    def test_native_qualification_and_runtime_check_refusals_never_fall_back_or_execute_git(self):
        container, store = self.mounted_fixture()
        with patch.object(git, 'qualified_runtime', side_effect=core.StallionError('unqualified')) as qualified, \
                patch.object(_bundle, 'product_git', side_effect=AssertionError('product fallback')) as product:
            with self.assertRaises(core.StallionError): _native._usable(store, container, {})
        qualified.assert_called_once_with(None); product.assert_not_called(); self.assertFalse(self.calls)
        self.runtime['check'].side_effect = core.StallionError('runtime changed')
        with patch.object(git, 'qualified_runtime', return_value=self.runtime), \
                patch.object(_bundle, 'product_git', side_effect=AssertionError('product fallback')) as product, \
                patch.object(core, 'validate_tree'):
            with self.assertRaises(core.StallionError): _native._usable(store, container, {'native_host': '/Host'})
        product.assert_not_called(); self.assertFalse(self.calls)

    def test_supplied_empty_runtime_is_not_a_generic_selection_request(self):
        with patch.object(_bundle, 'product_git', side_effect=AssertionError('product fallback')) as product:
            with self.assertRaises(KeyError): git.inspect_standalone(self.repo, runtime={})
        product.assert_not_called(); self.assertFalse(self.calls)

    def test_shared_native_route_keeps_repo_and_git_structure_refusals(self):
        container, store = self.mounted_fixture()
        old = self.repo / '.git'; old.rename(self.repo / '.git-old'); old.symlink_to('.git-old', target_is_directory=True)
        with patch.object(git, 'qualified_runtime', return_value=self.runtime), \
                patch.object(_bundle, 'product_git', side_effect=AssertionError('product fallback')), \
                patch.object(core, 'validate_tree'):
            with self.assertRaises(core.StallionError): _native._usable(store, container, {'native_host': '/Host'})
        self.assertFalse(self.calls)
        moved = container / 'volume/moved'; self.repo.rename(moved); self.repo.symlink_to('moved', target_is_directory=True)
        with patch.object(git, 'qualified_runtime') as qualified:
            with self.assertRaises(core.StallionError): _native._usable(store, container, {'native_host': '/Host'})
        qualified.assert_not_called(); self.assertFalse(self.calls)

    def test_external_config_routes_refuse_before_ref_enumeration(self):
        for entry in (b'include.path\n/outside\0', b'includeif.gitdir:/outside.path\n/outside\0', b'core.worktree\n/outside\0'):
            self.calls.clear(); self.config = entry
            with self.subTest(entry=entry), self.assertRaises(core.StallionError): git.inspect_refs(self.repo)
            self.assertEqual(len(self.calls), 1)

    def test_truncated_and_over_budget_config_refuse_before_refs(self):
        for data in (b'core.bare\nfalse', b'k\nv\0' * (git.ENTRY_CAP + 1)):
            self.calls.clear(); self.config = data
            with self.subTest(size=len(data)), self.assertRaises(core.StallionError): git.inspect_refs(self.repo)
            self.assertEqual(len(self.calls), 1)

    def test_uncertain_captures_are_not_empty_success(self):
        original = self.execute
        for change in ({'returncode': 1}, {'outcome': 'unknown'}, {'child_pending': True}, {'streams_eof': False},
                       {'streams_durable': False}, {'reaped': False}, {'output_bytes': True}, {'collector_error': 'limit'}):
            def execute(argv, receipt, persist, log, **options):
                result = original(argv, receipt, persist, log, **options); receipt.update(change); return result
            with self.subTest(change=change), patch.object(_native, 'execute_owned', side_effect=execute), \
                    self.assertRaises(core.StallionError): git.inspect_refs(self.repo)

    def test_changed_config_cannot_reach_ref_query(self):
        original = self.execute
        def execute(argv, receipt, persist, log, **options):
            result = original(argv, receipt, persist, log, **options)
            with (self.repo / '.git/config').open('a') as stream: stream.write('# changed\n')
            return result
        with patch.object(_native, 'execute_owned', side_effect=execute), self.assertRaises(core.StallionError):
            git.inspect_refs(self.repo)
        self.assertEqual(len(self.calls), 1)

    def test_ref_output_requires_complete_bounded_decoding(self):
        for data in (b'refs/heads/main', b'\xff\n', b'a\n' * (git.TREE_CAP + 1)):
            self.refs = data
            with self.subTest(size=len(data)), self.assertRaises((core.StallionError, UnicodeError)):
                git.inspect_refs(self.repo)

    def test_loose_transient_state_refuses_before_any_product_command(self):
        (self.repo / '.git/MERGE_HEAD').write_text('0' * 40 + '\n')
        with self.assertRaises(core.StallionError): git.inspect_refs(self.repo)
        self.assertFalse(self.calls)
