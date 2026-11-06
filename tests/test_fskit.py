"""Direct FSKit callback checks; no installed extension or kernel-routing claim."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import plistlib
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

    def test_readonly_host_discovery_completion_and_metadata(self):
        cls = type(self)
        cls.failed = True
        directory = self.base / 'host-discovery'
        directory.mkdir(mode=0o700)
        executable = directory / 'host-check'
        self.command('host-discovery-build', [self.tools['swiftc'], '-D', 'STALLION_HOST_CHECK',
                     '-swift-version', '6', '-strict-concurrency=complete', '-warnings-as-errors',
                     '-target', 'arm64-apple-macos27.0', '-sdk', self.sdk, '-Onone', '-parse-as-library',
                     '-module-cache-path', directory / 'cache',
                     self.source / 'filesystem/fskit/Host.swift',
                     self.source / 'tests/fskit_host_driver.swift', '-o', executable], 90, swift='current')
        child = self.command('host-discovery-run', [executable], 10)
        self.assertEqual(child.stdout,
                         'PASS: discovery single completion, independent deadline, malformed metadata and bounded JSON\n')
        self.assertEqual(child.stderr, '')
        cls.failed = False

    def test_admission_ownership_and_legacy_callbacks(self):
        cls = type(self)
        cls.failed = True
        try:
            filesystem = self.source / 'filesystem'
            tests = self.source / 'tests'
            directory = self.base / 'resource-admission'
            directory.mkdir(mode=0o700)
            target = 'arm64-apple-macos27.0'
            cflags = [self.tools['clang'], '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
                      '-target', target, '-isysroot', self.sdk, '-I', filesystem]
            normal = directory / 'normal-image.o'
            hooked = directory / 'hooked-image.o'
            hooks = directory / 'hooks.o'
            producer = directory / 'fixture-producer'
            self.command('resource-normal-core', [*cflags, '-c', filesystem / 'image.c', '-o', normal], 90)
            self.command('resource-fixture-build', [*cflags, tests / 'fskit_fixture.c', normal, '-o', producer], 90)
            fixture = directory / 'fixture'
            self.command('resource-fixture-run', [producer, fixture], 90)
            manifest = json.loads((fixture / 'manifest.json').read_text())
            self.assertTrue(manifest['full_verified'])
            self.assertTrue(manifest['consumed_close'])
            before = hashlib.sha256((fixture / 'image.sfs').read_bytes()).digest()
            replacements = ('pread', 'pwrite', 'ftruncate', 'fsync', 'close')
            self.command('resource-hooked-core', [*cflags, *(f'-D{name}=sfs_hooks_{name}' for name in replacements),
                         '-c', filesystem / 'image.c', '-o', hooked], 90)
            self.command('resource-hooks', [*cflags, '-c', tests / 'fskit_image_hooks.c', '-o', hooks], 90)
            executable = directory / 'adapter-check'
            self.command('resource-adapter-build', [self.tools['swiftc'], '-D', 'STALLION_ADAPTER_CHECK',
                         '-swift-version', '6', '-strict-concurrency=complete', '-target', target,
                         '-sdk', self.sdk, '-I', filesystem / 'fskit', '-g', '-Onone', '-parse-as-library',
                         '-module-cache-path', directory / 'cache', filesystem / 'fskit/Extension.swift',
                         filesystem / 'fskit/Volume.swift', fixture / 'FixtureIdentity.swift',
                         tests / 'fskit_adapter_driver.swift', hooked, hooks, '-o', executable], 180, swift='legacy')
            child = self.command('resource-adapter-run', [executable, fixture], 180)
            self.assertEqual(child.stdout,
                             'PASS: real-core namespace, aliases, pagination, resource limits, reclaim, lifecycle ordering, read-only refusal and consumed close\n'
                             'UNTESTED: kernel access routing, packer/buffer delivery, kernel reclaim counts, acquired security scope and signed lifecycle\n')
            self.assertEqual(child.stderr, '')
            self.assertEqual(hashlib.sha256((fixture / 'image.sfs').read_bytes()).digest(), before)
            cls.failed = False
        except BaseException as error:
            capture._latch_command('fskit_resource_admission', repr(error))
            raise

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
                         'unloadadmissionhook', 'loadconfigurationhook', 'drainresourceworkfortesting',
                         'diagnostictracestoragefortesting', 'diagnosticreadfortesting',
                         'diagnosticclosemodesfortesting', 'diagnosticmutationfortesting', 'diagnosticsetattributes', 'performwrite', 'setwritableattributes', 'enableadmittedwrites',
                         'writecountfortesting', 'setattributesvaluefortesting', 'refusedmutationfortesting',
                         'activateresultfortesting', 'lookupresultfortesting', 'attributesresultfortesting',
                         'readlinkresultfortesting', 'xattrresultfortesting', 'xattrsresultfortesting',
                         'enumerationresultfortesting', 'readresultconstructorfortesting',
                         'preparedattributesfortesting', 'rejectresultfortesting',
                         'resultrequestfortesting', 'requirevalidfortesting', 'requireresultvalidityfortesting',
                         'linkresultfortesting', 'linkaccessfortesting', 'linkbudgetfortesting',
                         'linkpreflightfortesting', 'snapshotfortesting', 'createlinkhandler',
                         'checklinkparentpolicy', 'checklinkcount',
                         'createownership', 'createoutcome', 'pendingcreate',
                         'createattributes', 'finishfailedcreate', 'createitemhandler',
                         'createstagefortesting', 'createabortfortesting', 'createreleasefortesting',
                         'createcommitreceiptfortesting', 'createoutcomefortesting', 'createtokenfortesting',
                         'createstatefortesting', 'createvisibilityfortesting', 'createresultfortesting',
                         'removeitemhandler', 'removemutationfortesting', 'removepreflightfortesting',
                         'removecommitreceiptfortesting', 'removeresultfortesting',
                         'renameitemhandler', 'renamepreflightfortesting', 'renameresultfortesting',
                         'createinput', 'createentryhandler', 'createsymlinkhandler', 'symlinkresultfortesting',
                         'checkxattrownerpolicy', 'writablexattrname', 'setxattrhandler', 'setxattrresultfortesting',
                         'sqlite')
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
                mutation_defines = ['-D', 'STALLION_CONTEXT_WRITES'] if variant == 'context' else []
                self.command(variant + '-write-build', [*swift, '-module-cache-path', directory / 'write-cache',
                             '-D', 'STALLION_ADAPTER_CHECK', '-D', 'STALLION_WRITE_DIAGNOSTIC',
                             *mutation_defines, *sources, tests / 'fskit_write_driver.swift', diagnostic, hooks, '-o', executable],
                             180, swift=variant)
                child = self.command(variant + '-write-run', [executable, images], 180)
                lines = child.stdout.splitlines()
                self.assertEqual(lines[:2], [
                    'PASS existing-file diagnostic real-core writes, attributes, failures and admission',
                    'UNQUALIFIED installed default-cache routing and syscall error propagation'])
                self.assertEqual(len(lines), 5 if variant == 'context' else 3)
                self.assertIn(lines[2], ('SDK unconstructible capability request fields: 65536',
                                        'SDK unconstructible capability request fields: 65536,131072'))
                if variant == 'context':
                    self.assertRegex(lines[3], r'^RMDIR requested mask: 0x[0-9a-f]+; final-link branch: '
                                               r'actual-result success$')
                    print(lines[3], flush=True)
                    self.assertRegex(lines[4], r'^RENAME requested mask: 0x[0-9a-f]+; replacement and same-inode '
                                               r'branches: actual-result success$')
                    print(lines[4], flush=True)
                self.assertEqual(child.stderr, '')
                extension = directory / 'readonly-extension'
                self.command(variant + '-normal-build', [*swift, '-module-cache-path', directory / 'normal-cache',
                             '-application-extension', '-Xlinker', '-e', '-Xlinker', '_NSExtensionMain',
                             *sources, normal, '-o', extension], 180, swift=variant)
                symbols = self.command(variant + '-normal-symbols', [self.tools['nm'], extension], 90)
                self.assertIn(' U _NSExtensionMain', symbols.stdout)
                self.assertFalse(any(word in symbols.stdout.lower() for word in forbidden))
            # Genuine core and no diagnostic flag: exercise retained-open
            # admission without claiming installed descriptor/cache routing.
            for variant, handlers, writes in (('neither', False, False), ('handlers', True, False),
                                              ('writes', False, True), ('both', True, True)):
                directory = self.base / (variant + '-admission')
                directory.mkdir(mode=0o700)
                images = directory / 'images'
                images.mkdir(mode=0o700)
                defines = ['-D', 'STALLION_ADAPTER_CHECK']
                if writes:
                    defines += ['-D', 'STALLION_CONTEXT_WRITES']
                if handlers:
                    defines += ['-D', 'STALLION_CONTEXT_HANDLERS']
                executable = directory / 'admission-check'
                self.command(variant + '-admission-build', [self.tools['swiftc'], *defines,
                             '-swift-version', '6', '-strict-concurrency=complete', '-target', target,
                             '-sdk', self.sdk, '-I', filesystem / 'fskit', '-g', '-Onone', '-parse-as-library',
                             '-module-cache-path', directory / 'cache', *sources,
                             tests / 'fskit_write_driver.swift', normal, hooks, '-o', executable], 180,
                             swift='context' if handlers else 'legacy')
                child = self.command(variant + '-admission-run', [executable, '--access-policy', images], 180)
                self.assertEqual(child.stdout, 'PASS immutable read-only selection, contextual open grants and retained-write delivery\n')
                self.assertEqual(child.stderr, '')
                # Inspect the actual four compiled factory configurations through
                # the same bounded artifact boundary used by packaging.
                import importlib.util
                package_spec = importlib.util.spec_from_file_location(
                    'package_fskit', self.source / 'tools/package_fskit.py')
                package = importlib.util.module_from_spec(package_spec)
                package_spec.loader.exec_module(package)
                compiled = package.read_executable(executable)
                expected_policy = 'contextual-writes' if handlers and writes else 'read-only'
                profile = package.compiled_factory_profile(compiled, expected_policy)
                self.assertEqual(profile['policy'], expected_policy)
                self.assertEqual(profile['pre_sign_sha256'], hashlib.sha256(compiled).hexdigest())
                with self.assertRaises(ValueError):
                    package.compiled_factory_profile(compiled,
                        'read-only' if handlers and writes else 'contextual-writes')
                factory_images = directory / 'factory-images'
                factory_images.mkdir(mode=0o700)
                child = self.command(variant + '-factory-run', [executable, '--factory-policy', factory_images], 180)
                self.assertEqual(child.stdout, 'PASS public factory access selection, refusal and persistence\n')
                self.assertEqual(child.stderr, '')
            module = self.base / 'context-admission-module'
            self.command('context-admission-module-build', [self.tools['swiftc'],
                         '-D', 'STALLION_CONTEXT_HANDLERS', '-D', 'STALLION_CONTEXT_WRITES',
                         '-swift-version', '6', '-strict-concurrency=complete', '-target', target,
                         '-sdk', self.sdk, '-I', filesystem / 'fskit', '-g', '-Onone', '-parse-as-library',
                         '-application-extension', '-Xlinker', '-e', '-Xlinker', '_NSExtensionMain',
                         '-module-cache-path', self.base / 'context-admission-module-cache',
                         *sources, normal, '-o', module], 180, swift='context')
            symbols = self.command('context-admission-module-symbols', [self.tools['nm'], module], 90).stdout.lower()
            self.assertIn(' u _nsextensionmain', symbols)
            self.assertIn('enableadmittedwrites', symbols)
            self.assertIn('setxattrhandler', symbols)
            self.assertIn('performwrite', symbols)
            self.assertFalse(any(word in symbols for word in
                                 ('sfs_diag_', 'sfs_test_', 'enablewritediagnostic', 'diagnosticwrite',
                                  'fixturewritablemetadata', 'fixtureidentity', 'privatetestidentity',
                                  'fortesting', 'reclaimfortesting', 'createabortfortesting')))
            # Assemble the ordinary both-flags extension, not a test driver.
            # This verifies unsigned package wiring; it does not activate FSKit.
            host = self.base / 'production-package-host'
            self.command('production-package-host-build', [self.tools['swiftc'],
                         '-swift-version', '6', '-strict-concurrency=complete', '-warnings-as-errors',
                         '-target', target, '-sdk', self.sdk, '-Onone', '-parse-as-library',
                         '-module-cache-path', self.base / 'production-package-host-cache',
                         filesystem / 'fskit/Host.swift', '-o', host], 90, swift='current')
            app = self.base / 'ProductionPackage.app'
            candidate_manifest = self.base / 'production-package-candidate.json'
            child = self.command('production-package-assemble', [sys.executable, '-I', '-B',
                         self.source / 'tools/package_fskit.py', '--host', host, '--extension', module,
                         '--out', app, '--bundle-version', '9', '--profile', 'production',
                         '--access-policy', 'contextual-writes', '--manifest-out', candidate_manifest], 90)
            self.assertEqual(child.stdout, 'Unsigned package: ' + str(app) + '\n')
            self.assertEqual(child.stderr, '')
            contents = app / 'Contents'
            extension_contents = contents / 'Extensions/StallionFS.appex/Contents'
            self.assertEqual((contents / 'MacOS/StallionFS').read_bytes(), host.read_bytes())
            self.assertEqual((extension_contents / 'MacOS/StallionFS').read_bytes(), module.read_bytes())
            host_info = plistlib.loads((contents / 'Info.plist').read_bytes())
            module_info = plistlib.loads((extension_contents / 'Info.plist').read_bytes())
            self.assertEqual(host_info['CFBundleIdentifier'], 'com.alvinhhh.stallionfs')
            self.assertEqual(host_info['CFBundlePackageType'], 'APPL')
            self.assertEqual(host_info['StallionFSControllerProtocol'], 1)
            self.assertEqual(module_info['CFBundleIdentifier'], 'com.alvinhhh.stallionfs.module')
            self.assertEqual(module_info['CFBundlePackageType'], 'XPC!')
            for info in (host_info, module_info):
                self.assertEqual(info['CFBundleVersion'], '9')
                self.assertEqual(info['CFBundleExecutable'], 'StallionFS')
                self.assertEqual(info['LSMinimumSystemVersion'], '27.0')
            self.assertEqual(module_info['StallionFSAccessPolicy'], 'contextual-writes')
            self.assertEqual(module_info['StallionFSCompiledFactory'], {
                'schema': 1, 'policy': 'contextual-writes', 'architectures': ['arm64'],
                'pre_sign_sha256': hashlib.sha256(module.read_bytes()).hexdigest()})
            attributes = module_info['EXAppExtensionAttributes']
            self.assertEqual(attributes['EXExtensionPointIdentifier'], 'com.apple.fskit.fsmodule')
            self.assertEqual(attributes['FSShortName'], 'stallionfs')
            self.assertTrue(attributes['FSSupportsPathURLs'])
            self.assertTrue(attributes['FSRequiresSecurityScopedPathURLResources'])
            self.assertFalse(attributes['FSSupportsBlockResources'])
            receipt = json.loads(candidate_manifest.read_bytes())
            self.assertEqual(receipt['kind'], 'fskit-unsigned-assembly-candidate')
            self.assertEqual(receipt['assembly'], 'no-signing-performed')
            self.assertEqual(receipt['package_profile'], 'production')
            self.assertEqual(receipt['bundle_version'], '9')
            self.assertEqual(receipt['filesystem_short_name'], 'stallionfs')
            self.assertEqual(receipt['controller_protocol'], 1)
            self.assertEqual(receipt['factory_policy'], 'contextual-writes')
            self.assertEqual(receipt['architectures'], ['arm64'])
            self.assertEqual(candidate_manifest.parent, app.parent)
            self.assertEqual(candidate_manifest.stat().st_mode & 0o777, 0o600)
            for directory in [app] + [path for path in app.rglob('*') if path.is_dir()]:
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            rows = {row['path']: row['sha256'] for row in receipt['pre_sign_package_files']}
            expected_paths = {'Contents/Info.plist', 'Contents/MacOS/StallionFS',
                'Contents/Extensions/StallionFS.appex/Contents/Info.plist',
                'Contents/Extensions/StallionFS.appex/Contents/MacOS/StallionFS'}
            self.assertEqual(set(rows), expected_paths)
            self.assertEqual(len(receipt['pre_sign_package_files']), 4)
            for path, digest in rows.items():
                self.assertEqual(digest, hashlib.sha256((app / path).read_bytes()).hexdigest())
            for name, executable, info, packaged_path in (
                    ('host', host, host_info, 'Contents/MacOS/StallionFS'),
                    ('module', module, module_info,
                     'Contents/Extensions/StallionFS.appex/Contents/MacOS/StallionFS')):
                inventory = self.command('production-package-' + name + '-architectures',
                    ['/usr/bin/lipo', '-archs', executable], 30).stdout.split()
                self.assertEqual(inventory, ['arm64'])
                observed = self.command('production-package-' + name + '-deployment',
                    ['/usr/bin/otool', '-arch', 'arm64', '-l', executable], 30).stdout
                # Independent field extraction from actual tool text, including the SDK.
                self.assertEqual(re.findall(r'^\s*platform\s+(\S+)\s*$', observed, re.MULTILINE), ['1'])
                minima = re.findall(r'^\s*minos\s+(\S+)\s*$', observed, re.MULTILINE)
                sdks = re.findall(r'^\s*sdk\s+(\S+)\s*$', observed, re.MULTILINE)
                self.assertEqual(minima, ['27.0'])
                self.assertEqual(len(sdks), 1)
                self.assertEqual(receipt[name]['slices'], [{'architecture': 'arm64',
                    'platform': 'macos', 'minimum_os': minima[0], 'sdk': sdks[0]}])
                self.assertEqual(receipt[name]['declared_minimum_os'], info['LSMinimumSystemVersion'])
                self.assertEqual(receipt[name]['bundle_id'], info['CFBundleIdentifier'])
                self.assertEqual(receipt[name]['pre_sign_input_sha256'], rows[packaged_path])
                self.assertEqual(receipt[name]['pre_sign_input_sha256'], hashlib.sha256(executable.read_bytes()).hexdigest())
            # Reuse these ordinary build bytes with isolated template dictionaries.
            # No production template or public command-line option is changed.
            template_bytes = [plistlib.dumps(value) for value in package._load_templates()]
            for floors, compatible in ((('28.0', '28.0'), True),
                                      (('26.0', '26.0'), False),
                                      (('27.0', '26.0'), False)):
                suffix = '-'.join(floors)
                template_values = [plistlib.loads(data) for data in template_bytes]
                for value, floor in zip(template_values, floors):
                    value['LSMinimumSystemVersion'] = floor
                variant_app = self.base / ('Template-' + suffix + '.app')
                variant_manifest = self.base / ('template-' + suffix + '.json')
                argv = ['package_fskit.py', '--host', str(host), '--extension', str(module),
                        '--out', str(variant_app), '--bundle-version', '9',
                        '--manifest-out', str(variant_manifest)]
                output = io.StringIO()
                previous_umask = os.umask(0o077)
                try:
                    with mock.patch.object(package, '_load_templates', return_value=template_values), \
                            mock.patch.object(sys, 'argv', argv), redirect_stdout(output):
                        if compatible:
                            package.main()
                        else:
                            with self.assertRaises(ValueError): package.main()
                finally:
                    os.umask(previous_umask)
                if compatible:
                    self.assertEqual(output.getvalue(), 'Unsigned package: ' + str(variant_app) + '\n')
                    variant = json.loads(variant_manifest.read_bytes())
                    self.assertEqual(variant['host']['declared_minimum_os'], '28.0')
                    self.assertEqual(variant['module']['slices'][0]['minimum_os'], '27.0')
                else:
                    self.assertFalse(variant_app.exists())
                    self.assertFalse(variant_manifest.exists())
                    self.assertEqual(output.getvalue(), '')
            unhooked = self.base / 'context-xattr-unhooked'
            unhooked.mkdir(mode=0o700)
            unhooked_images = unhooked / 'images'
            unhooked_images.mkdir(mode=0o700)
            unhooked_executable = unhooked / 'write-check'
            self.command('context-xattr-unhooked-build', [
                self.tools['swiftc'], '-D', 'STALLION_CONTEXT_HANDLERS', '-D', 'STALLION_ADAPTER_CHECK',
                '-D', 'STALLION_WRITE_DIAGNOSTIC', '-swift-version', '6', '-strict-concurrency=complete',
                '-target', target, '-sdk', self.sdk, '-I', filesystem / 'fskit', '-g', '-Onone', '-parse-as-library',
                '-module-cache-path', unhooked / 'cache', *sources, tests / 'fskit_write_driver.swift',
                normal, hooks, '-o', unhooked_executable], 180, swift='context')
            child = self.command('context-xattr-unhooked-run', [unhooked_executable, '--xattr-unhooked', unhooked_images], 180)
            self.assertEqual(child.stdout, 'PASS contextual xattr policies, binary values and persistence with unhooked core\n')
            self.assertEqual(child.stderr, '')
            disabled_images = unhooked / 'admission-disabled-images'
            disabled_images.mkdir(mode=0o700)
            child = self.command('context-admission-disabled-run',
                                 [unhooked_executable, '--access-policy', disabled_images], 180)
            self.assertEqual(child.stdout, 'PASS immutable read-only selection, contextual open grants and retained-write delivery\n')
            self.assertEqual(child.stderr, '')
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
