"""Public creation inspection and continuation without native execution."""
import contextlib
import copy
import fcntl
import io
import json
import os
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch

from stallionfs import __main__ as cli, core, _native, _native_create_recovery as recovery


class NativeCreateCLI(unittest.TestCase):
    workspace = '1' * 32
    transaction = '2' * 32

    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for target, names in ((core.Store, ('__init__', 'opportunistic_cleanup', 'object')),
                              (core, ('git', 'run', 'clone_tree', 'remove_tree')),
                              (_native, ('execute_owned', 'qualify', 'mount', 'unmount'))):
            for name in names:
                if hasattr(target, name):
                    self.stack.enter_context(patch.object(target, name, side_effect=AssertionError('forbidden: ' + name)))
        self.stack.enter_context(patch.object(_native._image, 'create_from_tree', side_effect=AssertionError('import'), create=True))
        self.temp = tempfile.TemporaryDirectory(prefix='sfs-create-cli-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'store'

    def invoke(self, arguments):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            status = cli.main(arguments)
        return status, output.getvalue(), error.getvalue()

    def observation(self, state='candidate', **updates):
        result = {'status': 'observed', 'inventory_complete': True, 'scope': self.workspace,
                  'entries': [{'workspace': self.workspace, 'transaction': self.transaction,
                               'status': state, 'path': '/retained/owned'}],
                  'incomplete_paths': [], 'targeted_inspection': True}
        result.update(updates)
        return result

    def make_store(self):
        self.root.mkdir(mode=0o700)
        for name in recovery.PARENTS:
            (self.root / name).mkdir(mode=0o700)
        (self.root / '.lock').touch(mode=0o600)
        self.save(self.root / 'store.json', {'application': 'stallionfs'})

    @staticmethod
    def save(path, value):
        path.write_text(json.dumps({'format': 1, **value}))
        path.chmod(0o600)

    def snapshot(self):
        return {str(path.relative_to(self.base)): (path.lstat().st_mode, path.lstat().st_ino,
                    os.readlink(path) if path.is_symlink() else path.read_bytes() if path.is_file() else None)
                for path in [self.base, *self.base.rglob('*')]}

    def test_parser_help_and_rejection_before_storage(self):
        with patch.object(recovery, 'inventory', side_effect=AssertionError('inventory')), \
             patch.object(recovery, 'continue_creation', side_effect=AssertionError('continue')):
            for arguments in (['--continue', self.transaction], [self.workspace, '--continue'],
                              ['A' * 32], ['../outside'], [self.workspace, '--continue', 'f' * 31],
                              [self.workspace, '--continue', 'F' * 32], ['--native-host', '/host'],
                              [self.workspace, '--native-host', '/host'], [self.workspace, '--yes'],
                              [self.workspace, '--backend', 'native-image'], [self.workspace, '--native-profile', 'production'],
                              [self.workspace, '--seed', 'x'], [self.workspace, '--json']):
                with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    cli.main(['creations', *arguments])
                self.assertEqual(raised.exception.code, 2)
            help_output = io.StringIO()
            with contextlib.redirect_stdout(help_output), self.assertRaises(SystemExit) as raised:
                cli.main(['creations', '--help'])
            self.assertEqual(raised.exception.code, 0)
            self.assertIn('[ID]', help_output.getvalue())
            self.assertIn('--continue TRANSACTION', help_output.getvalue())
            self.assertIn('--native-host NATIVE_HOST', help_output.getvalue())
        self.assertFalse(self.root.exists())

    def test_dispatch_and_absent_host_preserves_settings(self):
        result = self.observation(scope='store', entries=[])
        with patch.object(recovery, 'inventory', return_value=result) as inventory:
            self.assertEqual(self.invoke(['--root', str(self.root), '--json', 'creations']),
                             (0, json.dumps(result, sort_keys=True) + '\n', ''))
            inventory.assert_called_once_with(self.root, None)
        result = self.observation()
        with patch.object(recovery, 'inventory', return_value=result) as inventory:
            self.assertEqual(self.invoke(['--root', str(self.root), 'creations', self.workspace])[0], 0)
            inventory.assert_called_once_with(self.root, self.workspace)
        installed = {'status': 'installed-unmounted', 'workspace': self.workspace, 'transaction': self.transaction,
                     'path': '/managed/resource'}
        for host in (None, Path('/Fixture.app/Contents/MacOS/StallionFS')):
            with self.subTest(host=host), patch.object(recovery, 'continue_creation', return_value=installed) as continuation:
                arguments = ['--root', str(self.root), 'creations', self.workspace, '--continue', self.transaction]
                if host is not None:
                    arguments += ['--native-host', str(host)]
                self.assertEqual(self.invoke(arguments)[0], 0)
                continuation.assert_called_once_with(self.root, self.workspace, self.transaction, host=host)
        self.assertFalse(self.root.exists())

    def test_status_channel_exit_and_json_preserve_full_results(self):
        cases = [(False, self.observation(state), 0) for state in ('candidate', 'installed-unconfirmed', 'already-installed')]
        cases += [(False, self.observation('blocked', scope='store'), 0),
                  (False, self.observation('retained', scope='store'), 0),
                  (False, self.observation('blocked'), 1),
                  (False, self.observation('candidate', status='busy', inventory_complete=False), 1),
                  (False, self.observation('candidate', status='unavailable', inventory_complete=False), 1),
                  (False, self.observation('candidate', inventory_complete=False, incomplete_paths=['/partial']), 1)]
        for state, code in (('installed-unmounted', 0), ('already-installed', 0), ('blocked', 1), ('busy', 1)):
            result = {'status': state, 'workspace': self.workspace, 'transaction': self.transaction,
                      'path': '/managed/resource', 'handoff': 'mount-state' if state == 'already-installed' else None,
                      'already_installed': True, 'receipt': {'evidence': [1, 2]}}
            if state == 'blocked':
                result['code'] = 'exact-refusal'
            cases.append((True, result, code))
        for continuing, result, expected in cases:
            before = copy.deepcopy(result)
            with self.subTest(result=result), patch.object(recovery, 'inventory', return_value=result), \
                 patch.object(recovery, 'continue_creation', return_value=result):
                arguments = ['--root', str(self.root), '--json', 'creations', self.workspace]
                if continuing:
                    arguments += ['--continue', self.transaction]
                status, output, error = self.invoke(arguments)
                self.assertEqual(status, expected)
                self.assertEqual(error if expected == 0 else output, '')
                payload = json.loads(output if expected == 0 else error)
                self.assertEqual(payload, result if expected == 0 else {**result, 'error': result.get('code', result['status'])})
                self.assertEqual(result, before)

    def test_human_evidence_and_copy_eligibility(self):
        rows = [{'status': state, 'workspace': self.workspace, 'transaction': self.transaction, 'path': '/retained/owned'}
                for state in ('candidate', 'installed-unconfirmed', 'already-installed', 'retained', 'blocked',
                              'unclassified', 'incomplete-candidate', 'busy', 'unavailable')]
        rows += [{'status': 'retained', 'kind': 'publication-remnant', 'authoritative': False,
                  'destination_workspace': 'a' * 32, 'path': '/a/quoted\npath'},
                 {'status': 'unclassified', 'kind': 'stage', 'path': '/stage', 'remnants': ['owned'],
                  'records': [{'path': 'owned/meta.json', 'operation': None, 'state': 'candidate'}]}]
        result = self.observation(scope='store', entries=rows)
        with patch.object(recovery, 'inventory', return_value=result):
            status, output, error = self.invoke(['--root', str(self.root), 'creations'])
        self.assertEqual((status, error), (0, ''))
        rendered = [json.loads(line.removeprefix('entry: ')) for line in output.splitlines() if line.startswith('entry: ')]
        self.assertEqual(rendered, rows)
        self.assertEqual(output.count('Creation retained. Files preserved. Workspace unavailable.'), 2)
        self.assertNotIn('creations ' + 'a' * 32, output)
        for state in ('already-installed', 'retained', 'blocked', 'unclassified', 'incomplete-candidate', 'busy', 'unavailable'):
            with self.subTest(state=state), patch.object(recovery, 'inventory', return_value=self.observation(state)):
                _, output, error = self.invoke(['creations', self.workspace])
                self.assertNotIn('Files preserved', output + error)
        for changes in ({'inventory_complete': False}, {'status': 'busy'}, {'status': 'unavailable'}):
            with patch.object(recovery, 'inventory', return_value=self.observation(**changes)):
                _, output, error = self.invoke(['creations', self.workspace])
                self.assertNotIn('Files preserved', output + error)
        installed = {'status': 'already-installed', 'handoff': 'mount-state', 'workspace': self.workspace,
                     'transaction': self.transaction, 'path': '/managed/resource'}
        with patch.object(recovery, 'continue_creation', return_value=installed):
            status, output, error = self.invoke(['creations', self.workspace, '--continue', self.transaction])
        self.assertEqual((status, error), (0, ''))
        self.assertIn('handoff: "mount-state"', output)
        self.assertNotIn('Workspace installed and unmounted.', output)

    def test_approved_commands_round_trip_selected_root_without_resolving(self):
        default = Path.home() / 'Library/Application Support/stallionfs'
        for selected, environment in ((str(default), False), (str(self.base / "a space and ' quote"), False),
                                      ('~/a space and \' quote', False), (str(self.base / "environment's store"), True)):
            root = Path(selected).expanduser().absolute()
            prefix = ['sfs'] if root == default.absolute() else ['sfs', '--root', str(root)]
            for continuing in (False, True):
                result = ({'status': 'installed-unmounted', 'workspace': self.workspace, 'transaction': self.transaction,
                           'path': '/managed/resource'} if continuing else self.observation())
                with self.subTest(selected=selected, continuing=continuing), \
                     patch.dict(os.environ, {'STALLIONFS_HOME': selected}), \
                     patch.object(recovery, 'inventory', return_value=result) as inventory, \
                     patch.object(recovery, 'continue_creation', return_value=result) as continuation, \
                     patch.object(Path, 'resolve', side_effect=AssertionError('root resolve')):
                    arguments = [] if environment else ['--root', selected]
                    arguments += ['creations', self.workspace]
                    if continuing:
                        arguments += ['--continue', self.transaction]
                    status, output, error = self.invoke(arguments)
                self.assertEqual((status, error), (0, ''))
                command = [*prefix, 'mount' if continuing else 'creations', self.workspace]
                sentence = ('Workspace installed and unmounted. Run ' + shlex.join(command) + '.' if continuing else
                            'Creation retained. Files preserved. Workspace unavailable. Run ' + shlex.join(command) + ' to inspect.')
                self.assertIn(sentence, output.splitlines())
                embedded = sentence.split('Run ', 1)[1]
                embedded = embedded[:-1] if continuing else embedded.removesuffix(' to inspect.')
                self.assertEqual(shlex.split(embedded), command)
                (continuation if continuing else inventory).assert_called_once()

    def test_explicit_builtin_root_overrides_environment_in_both_handoffs(self):
        root = (Path.home() / 'Library/Application Support/stallionfs').absolute()
        parse_args = cli.argparse.ArgumentParser.parse_args
        class ParsedCommand(Exception):
            pass
        for continuing in (False, True):
            result = ({'status': 'installed-unmounted', 'workspace': self.workspace,
                       'transaction': self.transaction, 'path': '/managed/resource'} if continuing else self.observation())
            with self.subTest(continuing=continuing), \
                 patch.dict(os.environ, {'STALLIONFS_HOME': str(self.base / "other store's data")}), \
                 patch.object(recovery, 'inventory', return_value=result), \
                 patch.object(recovery, 'continue_creation', return_value=result), \
                 patch.object(Path, 'resolve', side_effect=AssertionError('root resolve')):
                arguments = ['--root', str(root), 'creations', self.workspace]
                if continuing:
                    arguments += ['--continue', self.transaction]
                status, output, error = self.invoke(arguments)
                self.assertEqual((status, error), (0, ''))
                embedded = output.split('Run ', 1)[1]
                embedded = embedded.removesuffix('.\n') if continuing else embedded.removesuffix(' to inspect.\n')
                command = shlex.split(embedded)
                self.assertEqual(command, ['sfs', '--root', str(root), 'mount' if continuing else 'creations', self.workspace])
                def inspect_parser(parser, arguments):
                    parsed = parse_args(parser, arguments)
                    self.assertEqual(Path(parsed.root).expanduser().absolute(), root)
                    raise ParsedCommand
                with patch.object(cli.argparse.ArgumentParser, 'parse_args', autospec=True, side_effect=inspect_parser), \
                     self.assertRaises(ParsedCommand):
                    cli.main(command[1:])

    def test_real_empty_missing_busy_and_unbound_inventory_is_read_only(self):
        before = self.snapshot()
        status, output, error = self.invoke(['--root', str(self.root), '--json', 'creations'])
        self.assertEqual((status, output), (1, ''))
        self.assertEqual(json.loads(error)['status'], 'unavailable')
        self.assertEqual(before, self.snapshot())
        self.make_store()
        before = self.snapshot()
        status, output, error = self.invoke(['--root', str(self.root), '--json', 'creations'])
        self.assertEqual((status, error), (0, ''))
        self.assertEqual(json.loads(output)['entries'], [])
        self.assertEqual(before, self.snapshot())
        (self.root / '.lock').unlink()
        before = self.snapshot()
        self.assertEqual(self.invoke(['--root', str(self.root), 'creations'])[0], 1)
        self.assertEqual(before, self.snapshot())
        (self.root / '.lock').touch(mode=0o600)
        stage = self.root / 'staging' / 'unbound'
        stage.mkdir(mode=0o700)
        (stage / 'owned').mkdir(mode=0o700)
        self.save(stage / 'owned' / 'meta.json', {'state': 'candidate'})
        remnant = self.root / 'journals' / ('.' + self.workspace + '.json.' + self.transaction)
        remnant.write_bytes(b'retained publication bytes'); remnant.chmod(0o600)
        before = self.snapshot()
        status, output, error = self.invoke(['--root', str(self.root), '--json', 'creations'])
        result = json.loads(output)
        self.assertEqual((status, error), (0, ''))
        self.assertTrue(result['inventory_complete'])
        self.assertEqual({row.get('kind') for row in result['entries']}, {'stage', 'publication-remnant'})
        self.assertEqual(before, self.snapshot())
        status, output, error = self.invoke(['--root', str(self.root), '--json', 'creations', self.workspace])
        self.assertEqual((status, output), (1, ''))
        self.assertEqual(json.loads(error)['entries'][0]['code'], 'no-authoritative-journal')
        with (self.root / '.lock').open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            status, output, error = self.invoke(['--root', str(self.root), '--json', 'creations'])
            self.assertEqual((status, output), (1, ''))
            self.assertEqual(json.loads(error)['status'], 'busy')
        self.assertEqual(before, self.snapshot())
        with patch.object(recovery, 'MAX_DOCUMENT_BYTES', 8):
            status, output, error = self.invoke(['--root', str(self.root), '--json', 'creations'])
        partial = json.loads(error)
        self.assertEqual((status, output), (1, ''))
        self.assertFalse(partial['inventory_complete'])
        self.assertTrue(partial['entries'])
        self.assertEqual(before, self.snapshot())

    def test_exception_details_notes_and_interruption_keep_existing_handling(self):
        for exception in (core.StallionError('native failed'), OSError('storage failed'), KeyboardInterrupt()):
            exception.native_image_result = {'operation': 'native-create', 'outcome': 'unknown', 'receipt': {'status': 7}}
            exception.add_note('keep exact diagnostic note')
            with self.subTest(exception=type(exception)), patch.object(recovery, 'inventory', side_effect=exception):
                status, output, error = self.invoke(['--root', str(self.root), '--json', 'creations'])
            self.assertEqual((status, output), (130 if isinstance(exception, KeyboardInterrupt) else 1, ''))
            result = json.loads(error)
            self.assertEqual(result['native_image_result'], exception.native_image_result)
            self.assertEqual(result['notes'], ['keep exact diagnostic note'])
            with patch.object(recovery, 'inventory', side_effect=exception):
                status, output, error = self.invoke(['--root', str(self.root), 'creations'])
            self.assertEqual(output, '')
            self.assertIn('keep exact diagnostic note', error)
            self.assertEqual(error.count('keep exact diagnostic note'), 1)


if __name__ == '__main__':
    unittest.main()
