"""Installation observations use inert app fixtures and mocked platform probes."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from stallionfs import __main__ as cli, _installation as installation

REAL_WHICH = shutil.which


class Installation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.app = self.root / 'StallionFS.app'
        (self.app / 'Contents/Extensions/StallionFS.appex').mkdir(parents=True)
        self.info = self.app / 'Contents/Info.plist'
        self.info.write_bytes(plistlib.dumps({'CFBundleShortVersionString': installation.__version__,
                                              'CFBundleVersion': '146'}))
        self.home = self.root / 'home'
        self.home.mkdir()
        self.target = self.app / 'Contents/Resources/Runtime/CLI/bin/sfs'
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b'inert executable')
        self.target.chmod(0o755)
        for item in (patch.object(installation, 'APP', self.app),
                     patch.object(installation._command, '_home', return_value=self.home),
                     patch.object(installation._command, '_acl'),
                     patch.object(installation.shutil, 'which', side_effect=lambda tool:
                                  REAL_WHICH(tool) if tool == 'sfs' else '/usr/bin/' + tool),
                     patch.object(installation.subprocess, 'run', side_effect=self.probe)):
            item.start()
            self.addCleanup(item.stop)
        self.bin = self.home / '.local/bin'
        self.bin.mkdir(parents=True)
        (self.bin / 'sfs').symlink_to(self.target)
        path = patch.dict(installation._command.os.environ, {'PATH': str(self.bin)})
        path.start()
        self.addCleanup(path.stop)

    def probe(self, argv, **kwargs):
        self.assertEqual(kwargs['timeout'], 10)
        self.assertTrue(kwargs['capture_output'])
        diagnostic = 'Authority=Developer ID Application: Example (TEAM)\n' if '-dv' in argv else ''
        return SimpleNamespace(returncode=0, stdout='', stderr=diagnostic)

    def test_ready_report_is_read_only(self):
        before = {str(path): (path.lstat().st_mode, path.lstat().st_mtime_ns)
                  for path in self.root.rglob('*')}
        with patch.object(installation.sys, 'argv', ['/installed/bin/sfs']):
            result = installation.inspect(self.root)
        self.assertTrue(result['ready'])
        self.assertEqual(result['signature']['state'], 'Developer ID')
        self.assertEqual(result['gatekeeper']['state'], 'accepted')
        self.assertEqual(result['app']['bundle_version'], '146')
        self.assertEqual(result['python_helper'], '/installed/bin/stallionfs-python')
        self.assertIn('does not imply release qualification', result['qualification'])
        self.assertIn('sfs command remove', result['removal_plan'][1])
        self.assertIn('System Settings', result['removal_plan'][2])
        self.assertIn('Trash', result['removal_plan'][3])
        self.assertIn('Your workspaces, snapshots and recovery data in ' + str(self.root), result['removal_plan'][4])
        after = {str(path): (path.lstat().st_mode, path.lstat().st_mtime_ns)
                 for path in self.root.rglob('*')}
        self.assertEqual(before, after)
        self.assertFalse((self.bin / installation._command.LOCK).exists())

    def test_command_must_be_executable_and_selected_on_path(self):
        self.target.chmod(0o644)
        result = installation.inspect(self.root)
        self.assertFalse(result['ready'])
        self.assertFalse(result['checks']['command_installed'])
        self.target.chmod(0o755)
        other_bin = self.root / 'other-bin'
        other_bin.mkdir()
        other = other_bin / 'sfs'
        other.write_bytes(b'foreign executable')
        other.chmod(0o755)
        with patch.dict(os.environ, {'PATH': str(other_bin) + os.pathsep + str(self.bin)}):
            result = installation.inspect(self.root)
        self.assertFalse(result['ready'])
        self.assertTrue(result['checks']['command_installed'])
        self.assertFalse(result['checks']['command_on_path'])
        self.assertEqual(result['command']['path_command'], str(other))

    def test_symlinked_and_dotted_managed_bin_on_path_is_selected(self):
        alias = self.root / 'bin-alias'
        alias.symlink_to(self.bin)
        dotted = str(self.home / '.local/../.local/bin')
        for entry in (str(alias), dotted):
            with self.subTest(entry=entry), patch.dict(os.environ, {'PATH': entry}):
                result = installation.inspect(self.root)
                self.assertTrue(result['checks']['command_on_path'])
                self.assertTrue(result['ready'])

    def test_tilde_path_entry_shadowing_is_detected(self):
        other_bin = self.home / 'other'
        other_bin.mkdir()
        other = other_bin / 'sfs'
        other.write_bytes(b'foreign executable')
        other.chmod(0o755)
        with patch.dict(os.environ, {'HOME': str(self.home), 'PATH': '~/other' + os.pathsep + str(self.bin)}):
            result = installation.inspect(self.root)
        self.assertFalse(result['checks']['command_on_path'])
        self.assertFalse(result['ready'])
        self.assertEqual(result['command']['path_command'], str(other))
        with patch.dict(os.environ, {'HOME': str(self.home), 'PATH': '~/.local/bin'}):
            self.assertTrue(installation.inspect(self.root)['checks']['command_on_path'])

    def test_case_variant_of_managed_bin_counts_when_filesystem_is_case_insensitive(self):
        upper = self.home / '.LOCAL/BIN'
        real_samefile = os.path.samefile
        real_is_file = Path.is_file
        def samefile(left, right):
            if Path(left) == upper:
                left = self.bin
            return real_samefile(left, right)
        def is_file(path):
            return real_is_file(self.bin / 'sfs') if path == upper / 'sfs' else real_is_file(path)
        with patch.object(installation.os.path, 'samefile', side_effect=samefile), \
                patch.object(Path, 'is_file', is_file), \
                patch.object(installation.os, 'access', return_value=True), \
                patch.dict(os.environ, {'PATH': str(upper)}):
            result = installation.inspect(self.root)
        self.assertTrue(result['checks']['command_on_path'])

    def test_nonregular_plist_is_rejected_without_opening(self):
        self.info.unlink()
        os.mkfifo(self.info)
        with patch.object(installation.os, 'open', wraps=os.open) as opened:
            result = installation.inspect(self.root)
        self.assertFalse(result['ready'])
        self.assertIn('regular file', result['app']['error'])
        self.assertNotIn(self.info, [call.args[0] for call in opened.call_args_list])
        self.info.unlink()
        self.info.mkdir()
        result = installation.inspect(self.root)
        self.assertIn('regular file', result['app']['error'])

    def test_bad_root_has_json_error_without_traceback(self):
        output, errors = io.StringIO(), io.StringIO()
        original = Path.expanduser

        def expanduser(path):
            if str(path).startswith('~nonexistent_sfs_pr70_user/'):
                raise RuntimeError('Could not determine home directory.')
            return original(path)

        with patch.object(installation.Path, 'expanduser', expanduser), \
                redirect_stdout(output), redirect_stderr(errors):
            code = cli.main(['--root', '~nonexistent_sfs_pr70_user/store', '--json', 'doctor', '--installation'])
        self.assertEqual(code, 1)
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(json.loads(errors.getvalue()), {'error': 'Could not determine home directory.'})
        self.assertEqual(len(errors.getvalue().splitlines()), 1)

    def test_gatekeeper_assessment_disables_cache(self):
        with patch.object(installation.subprocess, 'run', side_effect=self.probe) as run:
            installation.inspect(self.root)
        assessment = [call.args[0] for call in run.call_args_list if '--assess' in call.args[0]]
        self.assertEqual(assessment, [['/usr/bin/spctl', '--assess', '--no-cache', '--type', 'execute', str(self.app)]])

    def test_signature_states(self):
        cases = [('unsigned', 1, 'code object is not signed at all'),
                 ('ad-hoc', 0, 'Signature=adhoc'),
                 ('invalid', 1, 'a sealed resource is missing or invalid'),
                 ('other', 0, 'Authority=Apple Development: Example')]
        for expected, code, diagnostic in cases:
            with self.subTest(state=expected), patch.object(installation.subprocess, 'run',
                    return_value=SimpleNamespace(returncode=code, stdout='', stderr=diagnostic)):
                result = installation.inspect(self.root)
                self.assertEqual(result['signature']['state'], expected)
                self.assertTrue(result['ready'])
                self.assertFalse(result['checks']['developer_id_signature'])
                self.assertIn('Signature: ' + expected, installation.describe(result))

    def test_tools_missing_timeout_and_failure_are_reports(self):
        with patch.object(installation.shutil, 'which', side_effect=lambda tool: REAL_WHICH(tool) if tool == 'sfs' else None):
            result = installation.inspect(self.root)
            self.assertEqual(result['signature']['verify']['state'], 'unavailable')
            self.assertEqual(result['gatekeeper']['state'], 'unavailable')
            self.assertTrue(result['ready'])
        for error, expected in ((subprocess.TimeoutExpired('codesign', 10), 'timeout'),
                                (OSError('probe failed'), 'error')):
            with self.subTest(error=error), patch.object(installation.subprocess, 'run', side_effect=error):
                result = installation.inspect(self.root)
                self.assertEqual(result['signature']['verify']['state'], expected)
                self.assertEqual(result['signature']['details']['state'], expected)
                self.assertEqual(result['gatekeeper']['state'], expected)
                self.assertTrue(result['ready'])

    def test_mismatched_version_missing_extension_and_root(self):
        self.info.write_bytes(plistlib.dumps({'CFBundleShortVersionString': '0.6.0', 'CFBundleVersion': '1'}))
        (self.app / 'Contents/Extensions/StallionFS.appex').rmdir()
        absent = self.root / 'absent'
        result = installation.inspect(absent)
        self.assertFalse(result['ready'])
        for check in ('version_matches_cli', 'extension_present', 'store_root_exists'):
            self.assertFalse(result['checks'][check])
        self.assertFalse(absent.exists())
        text = installation.describe(result)
        self.assertIn('version 0.6.0 (does not match CLI)', text)
        self.assertIn('extension missing', text)
        self.assertIn('app version must match CLI', text.splitlines()[-1])
        self.assertNotIn('store', text.splitlines()[-1])

    def test_gatekeeper_rejection_does_not_hide_valid_signature(self):
        def rejected(argv, **kwargs):
            if '--assess' in argv:
                return SimpleNamespace(returncode=3, stdout='', stderr='rejected')
            return self.probe(argv, **kwargs)
        with patch.object(installation.subprocess, 'run', side_effect=rejected):
            result = installation.inspect(self.root)
        self.assertEqual(result['signature']['state'], 'Developer ID')
        self.assertEqual(result['gatekeeper']['state'], 'rejected')
        self.assertTrue(result['ready'])
        self.assertIn('not accepted by Gatekeeper', installation.describe(result))

    def test_missing_store_is_informational(self):
        absent = self.root / 'new-store'
        result = installation.inspect(absent)
        self.assertTrue(result['ready'])
        self.assertFalse(result['store_root']['exists'])
        self.assertFalse(result['checks']['store_root_exists'])
        self.assertFalse(absent.exists())
        text = installation.describe(result)
        self.assertIn('not created yet (informational)', text)
        self.assertNotIn('Not ready:', text)
        self.assertIn(str(absent) + ' are kept', text)

    def test_unreadable_store_root_is_reported(self):
        original = Path.is_dir

        def is_dir(path):
            if path.name == 'locked-store':
                raise PermissionError(13, 'Permission denied')
            return original(path)

        with patch.object(Path, 'is_dir', is_dir):
            result = installation.inspect(self.root / 'locked-store')
        self.assertFalse(result['store_root']['exists'])
        self.assertIn('Removal plan', installation.describe(result))

    def test_readable_text_without_json_blobs(self):
        result = installation.inspect(self.root)
        text = installation.describe(result)
        self.assertIn('Command: installed at ' + str(self.bin / 'sfs') + ', on PATH', text)
        self.assertIn('version ' + installation.__version__ + ' (matches CLI)', text)
        self.assertIn('extension present', text)
        self.assertIn('Signature: Developer ID (Developer ID Application: Example (TEAM))', text)
        self.assertIn('Gatekeeper: accepted', text)
        self.assertNotIn('{', text)
        self.assertNotIn('Not ready:', text)
        with patch.object(installation.shutil, 'which', side_effect=lambda tool: REAL_WHICH(tool) if tool == 'sfs' else None):
            text = installation.describe(installation.inspect(self.root))
        self.assertIn('Signature: unknown: codesign is not available', text)
        self.assertIn('Gatekeeper: unavailable: spctl is not available', text)
        self.assertNotIn('Not ready:', text)
        self.assertIn('Release signing (informational, not part of readiness): no Developer ID signature', text)
        self.assertNotIn('developer_id_signature', text)

    def test_missing_command_directory_is_not_created(self):
        (self.bin / 'sfs').unlink()
        self.bin.rmdir()
        result = installation.inspect(self.root)
        self.assertEqual(result['command']['state'], 'missing')
        self.assertFalse(self.bin.exists())

    def test_missing_and_malformed_plist_and_absent_app(self):
        self.info.unlink()
        self.assertIn('error', installation.inspect(self.root)['app'])
        self.info.write_bytes(b'<plist><broken>')
        self.assertIn('error', installation.inspect(self.root)['app'])
        with patch.object(installation, 'APP', self.root / 'missing'), \
                patch.object(installation.subprocess, 'run') as probe:
            result = installation.inspect(self.root)
            self.assertFalse(result['app']['present'])
            self.assertFalse(result['ready'])
            self.assertEqual(result['gatekeeper']['state'], 'skipped')
            probe.assert_not_called()

    def test_command_missing_dangling_foreign_and_admission_failure(self):
        link = self.bin / 'sfs'
        link.unlink()
        self.assertEqual(installation.inspect(self.root)['command']['state'], 'missing')
        link.symlink_to(self.target)
        self.target.unlink()
        result = installation.inspect(self.root)
        self.assertTrue(result['command']['dangling'])
        self.assertFalse(result['ready'])
        link.unlink()
        link.write_bytes(b'foreign')
        self.assertEqual(installation.inspect(self.root)['command']['state'], 'conflict')
        self.assertEqual(link.read_bytes(), b'foreign')
        with patch.object(installation._command, '_home', side_effect=ValueError('unsafe home')):
            self.assertEqual(installation.inspect(self.root)['command']['state'], 'error')

    def test_cli_dispatch_text_json_and_exit_status(self):
        for ready in (True, False):
            result = installation.inspect(self.root)
            result['ready'] = ready
            for structured in (True, False):
                output = io.StringIO()
                args = ['--root', str(self.root)] + (['--json'] if structured else []) + ['doctor', '--installation']
                with redirect_stdout(output), patch.object(installation, 'inspect', return_value=result) as inspect:
                    self.assertEqual(cli.main(args), 0 if ready else 1)
                inspect.assert_called_once_with(str(self.root))
                if structured:
                    self.assertEqual(json.loads(output.getvalue()), result)
                else:
                    self.assertIn('Removal plan', output.getvalue())
                    self.assertIn(result['qualification'], output.getvalue())
