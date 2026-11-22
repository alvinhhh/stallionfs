"""Installation observations use inert app fixtures and mocked platform probes."""
from contextlib import redirect_stderr, redirect_stdout
import ctypes
import errno
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from stallionfs import __main__ as cli, _installation as installation

class Installation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.app = self.root / 'StallionFS.app'
        self.extension = self.app / 'Contents/Extensions/StallionFS.appex'
        self.extension_binary = self.extension / 'Contents/MacOS/StallionFS'
        self.extension_binary.parent.mkdir(parents=True)
        self.extension_binary.write_bytes(b'inert extension')
        self.extension_binary.chmod(0o755)
        self.extension_info = self.extension / 'Contents/Info.plist'
        self.extension_metadata = {'CFBundleIdentifier': 'com.alvinhhh.stallionfs.module',
                                   'CFBundleExecutable': 'StallionFS',
                                   'CFBundleShortVersionString': installation.__version__,
                                   'CFBundleVersion': '146'}
        self.extension_info.write_bytes(plistlib.dumps(self.extension_metadata))
        self.info = self.app / 'Contents/Info.plist'
        self.host_metadata = {'CFBundleExecutable': 'StallionFS',
                              'CFBundleShortVersionString': installation.__version__,
                              'CFBundleVersion': '146'}
        self.info.write_bytes(plistlib.dumps(self.host_metadata))
        self.host_binary = self.app / 'Contents/MacOS/StallionFS'
        self.host_binary.parent.mkdir()
        self.host_binary.write_bytes(b'inert host')
        self.host_binary.chmod(0o755)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.target = self.app / 'Contents/Resources/Runtime/CLI/bin/sfs'
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b'inert executable')
        self.target.chmod(0o755)
        for item in (patch.object(installation, 'APP', self.app),
                     patch.object(installation.platform, 'mac_ver', return_value=('27.0', ('', '', ''), '')),
                     patch.object(installation.platform, 'machine', return_value='arm64'),
                     patch.object(installation._command, '_home', return_value=self.home),
                     patch.object(installation._command, '_acl'),
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
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        self.assertTrue(kwargs['capture_output'])
        diagnostic = 'Authority=Developer ID Application: Example (TEAM)\n' if '-dv' in argv else ''
        return SimpleNamespace(returncode=0, stdout='', stderr=diagnostic)

    def test_ready_report_is_read_only(self):
        before = {str(path): (path.lstat().st_mode, path.lstat().st_mtime_ns)
                  for path in self.root.rglob('*')}
        with patch.object(installation.sys, 'argv', ['/installed/bin/sfs']):
            result = installation.inspect(self.root)
        self.assertTrue(result['ready'])
        self.assertTrue(result['checks']['host_executable_usable'])
        self.assertTrue(result['checks']['extension_matches_app'])
        self.assertEqual(result['signature']['state'], 'Developer ID')
        self.assertEqual(result['gatekeeper']['state'], 'accepted')
        self.assertEqual(result['app']['bundle_version'], '146')
        self.assertEqual(result['python_helper'], '/installed/bin/stallionfs-python')
        self.assertIn('does not imply release qualification', result['qualification'])
        after = {str(path): (path.lstat().st_mode, path.lstat().st_mtime_ns)
                 for path in self.root.rglob('*')}
        self.assertEqual(before, after)
        self.assertFalse((self.bin / installation._command.LOCK).exists())

    def test_installation_needs_attention_when_host_executable_is_missing(self):
        self.host_binary.unlink()
        with redirect_stdout(io.StringIO()) as output:
            code = cli.main(['--root', str(self.root), '--json', 'doctor', '--installation'])
        self.assertEqual(code, 1)
        result = json.loads(output.getvalue())
        self.assertFalse(result['ready'])
        self.assertTrue(result['checks']['app_present'])
        self.assertFalse(result['checks']['host_executable_usable'])
        self.assertTrue(result['checks']['extension_matches_app'])
        self.assertEqual(result['app']['bundle_version'], '146')
        self.assertEqual(result['signature']['state'], 'Developer ID')
        self.assertIn('App executable is missing or unusable', installation.describe(result))

    def test_host_executable_name_and_mode_are_required(self):
        self.info.write_bytes(plistlib.dumps(dict(self.host_metadata, CFBundleExecutable='OtherExecutable')))
        result = installation.inspect(self.root)
        self.assertFalse(result['ready'])
        self.assertEqual(result['app']['host_error'], 'Unexpected app executable name')
        self.info.write_bytes(plistlib.dumps(self.host_metadata))
        self.host_binary.chmod(0o644)
        result = installation.inspect(self.root)
        self.assertFalse(result['ready'])
        self.assertEqual(result['app']['host_error'], 'App executable is missing or unusable')

    def test_installation_needs_attention_on_older_macos(self):
        with (patch('platform.mac_ver', return_value=('26.6.2', ('', '', ''), '')),
              patch('platform.machine', return_value='arm64'),
              redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as error):
            code = cli.main(['--root', str(self.root), '--json', 'doctor', '--installation'])
        self.assertEqual(code, 1)
        self.assertEqual(error.getvalue(), '')
        report = json.loads(output.getvalue())
        self.assertFalse(report['ready'])
        self.assertTrue(report['checks']['extension_matches_app'])
        self.assertFalse(report['checks']['app_platform_compatible'])
        self.assertEqual(report['app_platform']['state'], 'unsupported')
        self.assertIn('requires Apple silicon and macOS 27.0 or newer', installation.describe(report))

    def test_current_apple_silicon_needs_no_rosetta_probe(self):
        for version in ('27', '27.0', '28.0.1'):
            with (self.subTest(version=version), patch.object(installation.ctypes, 'CDLL') as library,
                  patch.object(installation.platform, 'mac_ver', return_value=(version, (), ''))):
                result = installation.inspect(self.root)
            library.assert_not_called()
            self.assertTrue(result['ready'])
            self.assertEqual(result['app_platform'], {'state': 'supported', 'macos_version': version,
                                                     'minimum_macos': '27.0', 'hardware': 'Apple silicon',
                                                     'required_hardware': 'Apple silicon'})

    def test_x86_64_observation_distinguishes_rosetta_from_intel_and_unknown(self):
        full_size = ctypes.sizeof(ctypes.c_int)
        cases = (
            (0, 1, full_size, 0, 'Apple silicon', 'supported'),
            (0, 0, full_size, 0, 'Intel', 'unsupported'),
            (-1, 0, full_size, errno.ENOENT, 'Intel', 'unsupported'),
            (-1, 0, full_size, errno.EPERM, None, 'unknown'),
            (0, 2, full_size, 0, None, 'unknown'),
            (0, 1, full_size - 1, 0, None, 'unknown'),
        )
        for code, value, length, reported_errno, hardware, state in cases:
            def probe(name, output, size, new_value, new_size):
                self.assertEqual((name, new_value, new_size), (b'sysctl.proc_translated', None, 0))
                self.assertEqual(ctypes.cast(size, ctypes.POINTER(ctypes.c_size_t))[0], full_size)
                ctypes.cast(output, ctypes.POINTER(ctypes.c_int))[0] = value
                ctypes.cast(size, ctypes.POINTER(ctypes.c_size_t))[0] = length
                return code

            with (self.subTest(code=code, value=value, length=length, errno=reported_errno),
                  patch.object(installation.platform, 'machine', return_value='x86_64'),
                  patch.object(installation.ctypes, 'CDLL') as library,
                  patch.object(installation.ctypes, 'get_errno', return_value=reported_errno)):
                library.return_value.sysctlbyname.side_effect = probe
                result = installation.inspect(self.root)
                library.assert_called_once_with(None, use_errno=True)
                library.return_value.sysctlbyname.assert_called_once()
                self.assertEqual(result['app_platform']['hardware'], hardware)
                self.assertEqual(result['app_platform']['state'], state)
                self.assertEqual(result['ready'], state == 'supported')

    def test_unknown_macos_version_needs_attention(self):
        for version in ('', '27..0', '27.0beta', '27.0.0.1'):
            with self.subTest(version=version), patch.object(installation.platform, 'mac_ver', return_value=(version, (), '')):
                result = installation.inspect(self.root)
                self.assertFalse(result['ready'])
                self.assertEqual(result['app_platform']['state'], 'unknown')
                self.assertIsNone(result['app_platform']['macos_version'])

    def test_unknown_machine_needs_attention(self):
        with (patch.object(installation.platform, 'machine', return_value=''),
              patch.object(installation.ctypes, 'CDLL') as library):
            result = installation.inspect(self.root)
        library.assert_not_called()
        self.assertFalse(result['ready'])
        self.assertEqual(result['app_platform']['state'], 'unknown')
        self.assertIsNone(result['app_platform']['hardware'])

    def test_removal_advice_requires_exact_artifact_and_downtime(self):
        for app in (self.app, self.root / 'absent-app'):
            with self.subTest(app=app), patch.object(installation, 'APP', app):
                advice = '\n'.join(installation.inspect(self.root)['removal_plan'])
                self.assertIn('docs/fskit-maintenance.md#finite-removal-and-restoration-procedure', advice)
                self.assertIn('exact last installed artifact', advice)
                self.assertIn('no newer executable', advice)
                self.assertIn('fresh, complete downtime across all users', advice)
                self.assertIn('Stop while provenance, history, or activity is uncertain', advice)
                self.assertIn('Preserve other users\' links, foreign entries, and system registrations', advice)
                self.assertIn('workspaces, snapshots and recovery data in ' + str(self.root), advice)
                self.assertNotIn('same version', advice)
                self.assertNotIn('command remove', advice)
                self.assertNotIn('Trash', advice)

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

    def test_tilde_path_entries_that_depend_on_the_shell_are_ambiguous(self):
        other_bin = self.home / 'other'
        other_bin.mkdir()
        other = other_bin / 'sfs'
        other.write_bytes(b'foreign executable')
        other.chmod(0o755)
        for path in [prefix + '/other' + os.pathsep + str(self.bin)
                     for prefix in ('~', '~+', '~-', '~0')] + ['~/.local/bin']:
            with self.subTest(path=path), \
                    patch.dict(os.environ, {'HOME': str(self.home), 'PATH': path}):
                result = installation.inspect(self.root)
                self.assertTrue(result['command']['path_ambiguous'])
                self.assertFalse(result['checks']['command_on_path'])
                self.assertFalse(result['ready'])
                text = installation.describe(result)
                self.assertIn('replace ~ with $HOME or an absolute path', text)
                self.assertNotIn('PATH selects', text)

    def test_tilde_path_entries_that_do_not_change_the_result_are_fine(self):
        with patch.dict(os.environ, {'HOME': str(self.home), 'PATH': str(self.bin) + os.pathsep + '~/other'}):
            result = installation.inspect(self.root)
        self.assertFalse(result['command']['path_ambiguous'])
        self.assertTrue(result['checks']['command_on_path'])

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

    def test_security_probes_use_fixed_system_paths(self):
        for name in ('codesign', 'spctl'):
            candidate = self.bin / name
            candidate.write_bytes(b'inert PATH entry')
            candidate.chmod(0o755)
        with patch.object(installation.subprocess, 'run', side_effect=self.probe) as run:
            installation.inspect(self.root)
        self.assertEqual([call.args[0] for call in run.call_args_list],
                         [['/usr/bin/codesign', '--verify', '--deep', '--strict', str(self.app)],
                          ['/usr/bin/codesign', '-dv', str(self.app)],
                          ['/usr/sbin/spctl', '--assess', '--no-cache', '--type', 'execute', str(self.app)]])

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
        for error, expected in ((FileNotFoundError('probe missing'), 'unavailable'),
                                (subprocess.TimeoutExpired('codesign', 10), 'timeout'),
                                (OSError('probe failed'), 'error')):
            with self.subTest(error=error), patch.object(installation.subprocess, 'run', side_effect=error):
                result = installation.inspect(self.root)
                self.assertEqual(result['signature']['verify']['state'], expected)
                self.assertEqual(result['signature']['details']['state'], expected)
                self.assertEqual(result['gatekeeper']['state'], expected)
                self.assertTrue(result['ready'])

    def test_mismatched_version_missing_extension_and_root(self):
        self.info.write_bytes(plistlib.dumps(dict(self.host_metadata, CFBundleShortVersionString='0.6.0',
                                                  CFBundleVersion='1')))
        self.extension.rename(self.root / 'parked.appex')
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

    def test_mismatched_extension_build_is_not_ready(self):
        self.assertTrue(installation.inspect(self.root)['ready'])
        self.extension_info.write_bytes(plistlib.dumps(dict(self.extension_metadata, CFBundleVersion='145')))
        result = installation.inspect(self.root)
        self.assertFalse(result['ready'])
        self.assertTrue(result['checks']['extension_present'])
        self.assertFalse(result['checks']['extension_matches_app'])
        self.assertIn('Extension build does not match the app', installation.describe(result))
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(['--root', str(self.root), '--json', 'doctor', '--installation']), 1)
        self.assertFalse(json.loads(output.getvalue())['checks']['extension_matches_app'])

    def test_extension_metadata_and_executable_are_required(self):
        for field, value, error in (
                ('CFBundleIdentifier', 'example.other', 'Unexpected extension bundle identifier'),
                ('CFBundleExecutable', 'OtherExecutable', 'Unexpected extension executable name'),
                ('CFBundleShortVersionString', '0.6.0', 'Extension version does not match the app')):
            with self.subTest(field=field):
                self.extension_info.write_bytes(plistlib.dumps(dict(self.extension_metadata, **{field: value})))
                result = installation.inspect(self.root)
                self.assertFalse(result['ready'])
                self.assertEqual(result['app']['extension_error'], error)
        self.extension_info.write_bytes(plistlib.dumps(self.extension_metadata))
        self.extension_binary.chmod(0o644)
        result = installation.inspect(self.root)
        self.assertFalse(result['ready'])
        self.assertEqual(result['app']['extension_error'], 'Extension executable is missing or unusable')
        self.extension_binary.unlink()
        self.extension_info.unlink()
        result = installation.inspect(self.root)
        self.assertFalse(result['ready'])
        self.assertTrue(result['checks']['extension_present'])
        self.assertFalse(result['checks']['extension_matches_app'])

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
        self.assertIn('recovery data in ' + str(absent), text)

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
        with patch.object(installation.subprocess, 'run', side_effect=FileNotFoundError):
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
