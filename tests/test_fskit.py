"""Direct FSKit callback checks; no installed extension or kernel-routing claim."""
from contextlib import redirect_stderr
import io
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import test_image as capture


class FSKitInterfaces(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime = platform.mac_ver()[0]
        major = int(runtime.split('.')[0]) if re.fullmatch(r'\d+(?:\.\d+)*', runtime) else 0
        if sys.platform != 'darwin' or major < 27 or platform.machine() != 'arm64':
            raise unittest.SkipTest(
                'FSKit capability unavailable: direct callbacks require macOS 27+ on ARM64; '
                f'host is {sys.platform} {runtime or "unknown version"} {platform.machine()}')
        cls.source = Path(__file__).resolve().parents[1]
        destination = os.environ.get('STALLIONFS_FSKIT_ARTIFACT_DIR')
        if destination:
            cls.base = Path(destination).resolve()
            cls.base.mkdir(mode=0o700)  # Never reuse a previous run's output.
        else:
            cls.base = Path(tempfile.mkdtemp(prefix='stallionfs-fskit-tests-')).resolve()
        cls.failed = True
        cls.previous_handlers = capture._install_command_handlers()
        cls.addClassCleanup(cls.finish)
        try:
            version = cls.command('sdk-version', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version'], 15).stdout.strip()
            if not re.fullmatch(r'\d+(?:\.\d+)*', version):
                raise AssertionError(f'Unrecognized selected SDK version: {version!r}')
            if int(version.split('.')[0]) < 27:
                raise unittest.SkipTest(
                    f'FSKit capability unavailable: selected macOS SDK {version} is older than 27')
            cls.sdk = cls.command('sdk-path', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'], 15).stdout.strip()
            header = Path(cls.sdk) / 'System/Library/Frameworks/FSKit.framework/Headers/FSVolumeHandlerResult.h'
            if not header.is_file():
                raise unittest.SkipTest(
                    'FSKit capability unavailable: selected SDK lacks FSVolumeHandlerResult.h')
            cls.tools = {}
            for tool in ('clang', 'swiftc', 'nm'):
                cls.tools[tool] = cls.command('find-' + tool, ['/usr/bin/xcrun', '--find', tool], 15).stdout.strip()
                if not Path(cls.tools[tool]).is_file():
                    raise AssertionError(f'Selected {tool} is not a file')
        except unittest.SkipTest:
            cls.failed = False
            raise
        except BaseException as error:
            capture._latch_command('fskit_setup', repr(error))
            raise

    @classmethod
    def finish(cls):
        errors = []
        try:
            capture._restore_command_handlers(cls.previous_handlers)
        except BaseException as error:
            errors.append(error)
        # Reconcile after restoring handlers, before accepting success or deleting evidence.
        state = capture._command_state
        if (state['failure'] is not None or state['first_signal'] is not None
                or state['signal_count'] or state['active'] is not None):
            errors.append(RuntimeError(f'FSKit command control did not finish cleanly: {state!r}'))
        if errors:
            cls.failed = True
        try:
            if cls.failed:
                print(f'FSKit fixtures and command evidence retained: {cls.base}', file=sys.stderr)
            else:
                shutil.rmtree(cls.base)
        except BaseException as error:
            errors.append(error)
        if errors:
            primary = errors[0]
            for secondary in errors[1:]:
                primary.add_note('Additional FSKit finalization error: ' + repr(secondary))
            # unittest retains any earlier test/setup error separately from this cleanup error.
            raise primary

    @classmethod
    def command(cls, label, argv, timeout, *, swift=None):
        child = capture._owned_command([str(value) for value in argv], cwd=cls.base,
                                       timeout=timeout, stem=cls.base / label)
        if child.returncode:
            raise AssertionError(f'{label} exited {child.returncode}; retained {cls.base}\n{child.stderr[-4000:]}')
        if swift is not None:
            allowed = {f"'{name}' was deprecated in macOS 27.0 [#DeprecatedDeclaration]"
                       for name in ('Operations', 'ReadWriteOperations', 'XattrOperations')} if swift == 'legacy' else set()
            if any('warning:' in line and line.split('warning: ', 1)[-1] not in allowed
                   for line in child.stderr.splitlines()):
                raise AssertionError(f'Unexpected Swift warning in {label}; retained {cls.base}')
        return child

    def test_contextual_and_legacy_callbacks_and_production_builds(self):
        cls = type(self)
        try:
            filesystem = self.source / 'filesystem'
            tests = self.source / 'tests'
            target = 'arm64-apple-macos27.0'
            cflags = [self.tools['clang'], '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
                      '-target', target, '-isysroot', self.sdk, '-I', filesystem]
            diagnostic = self.base / 'diagnostic-image.o'
            hooks = self.base / 'diagnostic-hooks.o'
            normal = self.base / 'normal-image.o'
            replacements = ('pread', 'pwrite', 'fcntl', 'clock_gettime', 'malloc', 'calloc')
            self.command('diagnostic-core', [*cflags, *(f'-D{name}=sfs_diag_{name}' for name in replacements),
                         '-include', tests / 'fskit_write_hooks.h', '-c', filesystem / 'image.c', '-o', diagnostic], 90)
            self.command('diagnostic-hooks', [*cflags, '-c', tests / 'fskit_write_hooks.c', '-o', hooks], 90)
            self.command('normal-core', [*cflags, '-c', filesystem / 'image.c', '-o', normal], 90)
            sources = [filesystem / 'fskit/Extension.swift', filesystem / 'fskit/Volume.swift']
            forbidden = ('sfs_diag_', 'sfs_image_diagnostic_', 'enablewritediagnostic', 'diagnosticwrite',
                         'sfs_test_', 'fixtureidentity', 'reclaimfortesting', 'ownsfortesting',
                         'diagnostictracestoragefortesting', 'diagnosticreadfortesting',
                         'diagnosticclosemodesfortesting', 'diagnosticmutationfortesting', 'diagnosticsetattributes',
                         'writecountfortesting', 'setattributesvaluefortesting', 'refusedmutationfortesting',
                         'activateresultfortesting', 'lookupresultfortesting', 'attributesresultfortesting',
                         'readlinkresultfortesting', 'xattrresultfortesting', 'xattrsresultfortesting',
                         'enumerationresultfortesting', 'readresultconstructorfortesting',
                         'preparedattributesfortesting', 'rejectresultfortesting',
                         'resultrequestfortesting', 'requirevalidfortesting', 'requireresultvalidityfortesting',
                         'linkresultfortesting', 'linkaccessfortesting', 'linkbudgetfortesting',
                         'linkpreflightfortesting', 'snapshotfortesting', 'createlinkhandler',
                         'checklinkparentpolicy', 'checklinkcount', 'sqlite')
            for variant in ('legacy', 'context'):
                directory = self.base / variant
                directory.mkdir(mode=0o700)
                images = directory / 'images'
                images.mkdir(mode=0o700)
                defines = ['-D', 'STALLION_CONTEXT_HANDLERS'] if variant == 'context' else []
                swift = [self.tools['swiftc'], *defines, '-swift-version', '6', '-strict-concurrency=complete',
                         '-target', target, '-sdk', self.sdk, '-I', filesystem / 'fskit',
                         '-g', '-Onone', '-parse-as-library']
                executable = directory / 'write-check'
                self.command(variant + '-write-build', [*swift, '-module-cache-path', directory / 'write-cache',
                             '-D', 'STALLION_ADAPTER_CHECK', '-D', 'STALLION_WRITE_DIAGNOSTIC',
                             *sources, tests / 'fskit_write_driver.swift', diagnostic, hooks, '-o', executable],
                             180, swift=variant)
                child = self.command(variant + '-write-run', [executable, images], 180)
                lines = child.stdout.splitlines()
                self.assertEqual(lines[:2], [
                    'PASS existing-file diagnostic real-core writes, attributes, failures and admission',
                    'UNQUALIFIED installed default-cache routing and syscall error propagation'])
                self.assertEqual(len(lines), 3)
                self.assertIn(lines[2], ('SDK unconstructible capability request fields: 65536',
                                        'SDK unconstructible capability request fields: 65536,131072'))
                self.assertEqual(child.stderr, '')
                extension = directory / 'readonly-extension'
                self.command(variant + '-normal-build', [*swift, '-module-cache-path', directory / 'normal-cache',
                             '-application-extension', '-Xlinker', '-e', '-Xlinker', '_NSExtensionMain',
                             *sources, normal, '-o', extension], 180, swift=variant)
                symbols = self.command(variant + '-normal-symbols', [self.tools['nm'], extension], 90)
                self.assertIn(' U _NSExtensionMain', symbols.stdout)
                self.assertFalse(any(word in symbols.stdout.lower() for word in forbidden))
            cls.failed = False
        except BaseException as error:
            capture._latch_command('fskit_interfaces', repr(error))
            raise


class FSKitFinalization(unittest.TestCase):
    """Exercise the cleanup boundary without SDK access, processes or real signals."""

    def test_cancellation_after_last_command_retains_evidence(self):
        for outcome in ('success', 'capability_skip', 'primary_failure'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary) / 'evidence'
                base.mkdir()
                receipt = base / 'last.command.json'
                receipt.write_bytes(b'{"returncode": 0}\n')
                state = {'failure': None, 'active': None, 'first_signal': None, 'signal_count': 0}
                handlers = {}
                events = []

                def last_command(*_args, **_kwargs):
                    events.append('last command returned')
                    return SimpleNamespace(returncode=0, stdout='', stderr='')

                def restore(previous):
                    self.assertIs(previous, handlers)
                    events.append('handler restoration attempted')
                    if outcome == 'primary_failure':
                        raise RuntimeError('secondary handler restoration failure')

                def cancel_after_command(cls):
                    FSKitInterfaces.command.__func__(cls, 'last', ['never-executed'], 1)
                    events.append('cancellation latched')
                    capture._cancel_command(signal.SIGTERM, None, state=state)

                class Harness(unittest.TestCase):
                    @classmethod
                    def setUpClass(cls):
                        cls.base = base
                        cls.failed = True
                        cls.previous_handlers = handlers
                        cls.addClassCleanup(FSKitInterfaces.finish.__func__, cls)
                        if outcome == 'capability_skip':
                            cancel_after_command(cls)
                            cls.failed = False
                            raise unittest.SkipTest('FSKit capability unavailable: regression fixture')

                    def runTest(self):
                        cls = type(self)
                        cancel_after_command(cls)
                        if outcome == 'primary_failure':
                            raise ValueError('primary callback assertion failure')
                        cls.failed = False

                with mock.patch.object(capture, '_command_state', state), \
                        mock.patch.object(capture, '_owned_command', side_effect=last_command) as owned, \
                        mock.patch.object(capture, '_restore_command_handlers', side_effect=restore), \
                        redirect_stderr(io.StringIO()) as diagnostic:
                    result = unittest.TestResult()
                    unittest.TestSuite([Harness()]).run(result)
                owned.assert_called_once()
                self.assertEqual(events, ['last command returned', 'cancellation latched', 'handler restoration attempted'])
                self.assertFalse(result.wasSuccessful())
                self.assertTrue(Harness.failed)
                self.assertEqual(receipt.read_bytes(), b'{"returncode": 0}\n')
                self.assertIn('evidence retained', diagnostic.getvalue())
                self.assertIn('FSKit command control did not finish cleanly', result.errors[-1][1])
                if outcome == 'primary_failure':
                    self.assertEqual(len(result.errors), 2)
                    self.assertIn('primary callback assertion failure', result.errors[0][1])
                    self.assertIn('secondary handler restoration failure', result.errors[1][1])
                else:
                    self.assertEqual(len(result.errors), 1)
                    self.assertEqual(len(result.skipped), int(outcome == 'capability_skip'))
