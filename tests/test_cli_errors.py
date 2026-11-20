"""Parser contracts do not require the macOS native extensions."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import unittest
from unittest.mock import patch

from stallionfs import __main__ as cli


class ArgumentErrors(unittest.TestCase):
    def invoke(self, argv, prog='sfs'):
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(cli.sys, 'argv', ['/bin/' + prog]), \
                redirect_stdout(output), redirect_stderr(errors):
            with self.assertRaises(SystemExit) as raised:
                cli.main(argv)
        return raised.exception.code, output.getvalue(), errors.getvalue()

    def test_json_errors_are_single_stderr_objects(self):
        cases = ([], ['unknown'], ['copy'], ['copy', '--bad'],
                 ['copy', 'a', 'b', '--jobs', '9'],
                 ['--bad', 'copy'], ['--root'],
                 ['creations', '--confirm'])
        for prog in ('sfs', 'stallionfs'):
            for args in cases:
                for prefix in (['--json'], ['--root', '/unused', '--json']):
                    with self.subTest(prog=prog, args=args, prefix=prefix):
                        code, output, errors = self.invoke(prefix + args, prog)
                        self.assertEqual(code, 2)
                        self.assertEqual(output, '')
                        value = json.loads(errors)
                        self.assertEqual(set(value), {'error'})
                        self.assertTrue(value['error'])
                        self.assertEqual(len(errors.splitlines()), 1)

    def test_plain_errors_and_help_use_invoked_alias(self):
        for prog in ('sfs', 'stallionfs'):
            for args in ([], ['unknown'], ['copy']):
                with self.subTest(prog=prog, args=args):
                    code, output, errors = self.invoke(args, prog)
                    self.assertEqual(code, 2)
                    self.assertEqual(output, '')
                    self.assertIn('usage: ' + prog, errors)
                    self.assertIn(prog + (' copy' if args == ['copy'] else '') + ': error:', errors)
            for args in (['--help'], ['copy', '--help']):
                code, output, errors = self.invoke(args, prog)
                self.assertEqual((code, errors), (0, ''))
                self.assertIn('usage: ' + prog, output)

    def test_json_after_command_is_not_a_global_option(self):
        code, output, errors = self.invoke(['copy', '--json'])
        self.assertEqual((code, output), (2, ''))
        self.assertIn('usage: sfs copy', errors)

    def test_json_is_not_detected_inside_root_or_child_arguments(self):
        for args in (['--root', '--json', 'copy'], ['run', 'id', '--', '--json']):
            self.assertFalse(cli._json_arguments(args))

    def test_abbreviated_global_options_are_recognized(self):
        for prefix in (['--roo', '/unused', '--json'], ['--ro=/unused', '--json'],
                       ['--roo', '/unused', '--js'], ['--js', '--r', '/unused']):
            with self.subTest(prefix=prefix):
                self.assertTrue(cli._json_arguments(prefix + ['prepare']))
                code, output, errors = self.invoke(prefix + ['prepare'])
                self.assertEqual((code, output), (2, ''))
                self.assertEqual(set(json.loads(errors)), {'error'})
        self.assertEqual(cli._global_arguments(['--roo', '/r', 'prepare', 'x', '--', 'make']), (False, 2))
        self.assertFalse(cli._json_arguments(['--roo', '--json', 'copy']))

    def test_helper_preserves_native_alias_and_version(self):
        with patch.dict(cli.os.environ, {'STALLIONFS_CLI_PROG': 'sfs'}):
            code, output, errors = self.invoke(['--help'], 'stallionfs-python')
            self.assertEqual((code, errors), (0, ''))
            self.assertIn('usage: sfs', output)
        code, output, errors = self.invoke(['--version'])
        self.assertEqual((code, output.strip(), errors), (0, cli.__version__, ''))
