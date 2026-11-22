"""Native ZIP round-trip with inert bundle contents and fake Apple trust checks."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_maintenance_packaging


SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('build_fskit_distribution', SOURCE / 'tools/build_fskit_distribution.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


@unittest.skipUnless(sys.platform == 'darwin', 'macOS archive tools required')
class BuildDistribution(unittest.TestCase):
    def setUp(self):
        temp = subprocess.check_output(['/usr/bin/getconf', 'DARWIN_USER_TEMP_DIR'], text=True, timeout=10).strip()
        local = tempfile.TemporaryDirectory(dir=Path(temp).resolve(strict=True), prefix='distribution-fixtures-')
        self.addCleanup(local.cleanup)
        fixture = test_maintenance_packaging.Signing()
        # Keep iCloud/File Provider metadata out of the synthetic clean app.
        with patch.object(test_maintenance_packaging, 'ROOT', Path(local.name) / 'source'):
            fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.app = fixture.app
        self.app.chmod(0o755)
        host = self.app / 'Contents/Info.plist'
        info = plistlib.loads(host.read_bytes())
        info.update(CFBundleExecutable='StallionFS', CFBundleShortVersionString=fixture.build['package_version'])
        host.write_bytes(plistlib.dumps(info))
        module = 'Contents/Extensions/StallionFS.appex/Contents'
        info['CFBundleIdentifier'] = 'com.alvinhhh.stallionfs.module'
        self.module_info = fixture.write(module + '/Info.plist', plistlib.dumps(info))
        fixture.write(module + '/MacOS/StallionFS', b'inert extension executable', 0o755)
        self.publisher = fixture.o['PUBLISHER_TEAM']
        self.release = fixture.base / 'release'
        self.release.mkdir(mode=0o700)
        self.leaf = fixture.write('Contents/_CodeSignature/CodeResources', b'inert seal')
        (self.app / 'Contents/Empty').mkdir(mode=0o755)
        (self.app / 'Contents/CodeResources-link').symlink_to('_CodeSignature/CodeResources')
        self.calls = []
        self.tool = builder.package._tool_output

    def tools(self, argv, directory):
        self.calls.append(argv)
        if argv[0] == '/usr/bin/codesign' or argv[:3] == ['/usr/bin/xcrun', 'stapler', 'validate']:
            return ''
        return self.tool(argv, directory)

    def build(self, tools=None):
        with patch.object(builder.package, '_tool_output', side_effect=tools or self.tools):
            return builder.build_distribution(self.app, self.release, self.publisher)

    def assert_incomplete(self):
        self.assertFalse(list(self.release.glob('*/' + builder.BINDINGS_NAME)))

    def test_command_stages_exact_archive_and_verifies_the_extracted_app(self):
        argv = ['build_fskit_distribution.py', '--app', str(self.app),
                '--release-parent', str(self.release), '--publisher', self.publisher]
        # Ordinary transport metadata is allowed; the archive excludes it.
        subprocess.run(['/usr/bin/xattr', '-w', 'com.apple.quarantine',
                        '0081;12345678;Fixture;', self.leaf], check=True, timeout=10)
        output = io.StringIO()
        with patch.object(sys, 'argv', argv), patch.object(builder.package, '_tool_output', side_effect=self.tools), \
                redirect_stdout(output):
            builder.main()
        staged = Path(output.getvalue().strip())
        self.assertEqual(staged.parent, self.release)
        self.assertEqual(sorted(path.name for path in staged.iterdir()), sorted([builder.ARCHIVE_NAME, builder.BINDINGS_NAME]))
        archive = (staged / builder.ARCHIVE_NAME).read_bytes()
        bindings = json.loads((staged / builder.BINDINGS_NAME).read_bytes())
        self.assertEqual(bindings['archive']['sha256'], hashlib.sha256(archive).hexdigest())
        self.assertEqual(bindings['inventory'], builder.package._runtime_inventory(self.app))
        builder.package.verify_maintenance_archive(archive, bindings['inventory'], self.app.name)
        extract = next(argv for argv in self.calls if argv[:3] == ['/usr/bin/ditto', '-x', '-k'])
        restored = Path(extract[-1]) / self.app.name
        dev_id = next(argv for argv in self.calls if any('100.6.1.13' in arg for arg in argv))
        ticket, = [argv for argv in self.calls if argv[:3] == ['/usr/bin/xcrun', 'stapler', 'validate']]
        self.assertEqual(dev_id[-1], str(restored))
        self.assertIn('100.6.2.6', dev_id[-2])
        self.assertEqual(ticket[-1], str(restored))
        self.assertLess(self.calls.index(extract), self.calls.index(dev_id))
        self.assertLess(self.calls.index(dev_id), self.calls.index(ticket))
        self.assertFalse(restored.exists())
        self.assertEqual(subprocess.check_output(['/usr/bin/xattr', '-p', 'com.apple.quarantine', self.leaf],
                                                 timeout=10).strip(), b'0081;12345678;Fixture;')

    def test_mismatched_extension_build_refuses_before_archive(self):
        module = plistlib.loads(self.module_info.read_bytes())
        module['CFBundleVersion'] = '8'
        self.module_info.write_bytes(plistlib.dumps(module))
        with self.assertRaisesRegex(ValueError, 'product versions and build numbers must match'):
            self.build()
        self.assertFalse(any(argv[0] == '/usr/bin/ditto' for argv in self.calls))
        self.assertFalse(list(self.release.iterdir()))

    def test_malformed_extension_metadata_refuses_before_archive(self):
        self.module_info.write_bytes(b'<?xml version="1.0"?><plist><date>invalid</date></plist>')
        with self.assertRaisesRegex(ValueError, 'Invalid app metadata'):
            self.build()
        self.assertFalse(any(argv[0] == '/usr/bin/ditto' for argv in self.calls))
        self.assertFalse(list(self.release.iterdir()))

    def test_fails_closed_on_metadata_absent_from_exact_zip(self):
        subprocess.run(['/usr/bin/xattr', '-w', 'com.apple.ResourceFork', 'fixture', self.leaf],
                       check=True, timeout=10)
        with self.assertRaisesRegex(ValueError, 'extended attributes'):
            self.build()
        subprocess.run(['/usr/bin/xattr', '-d', 'com.apple.ResourceFork', self.leaf], check=True, timeout=10)
        subprocess.run(['/bin/chmod', '+a', 'everyone allow read', self.leaf], check=True, timeout=10)
        with self.assertRaisesRegex(ValueError, 'has an ACL'):
            self.build()
        self.assert_incomplete()
        self.assertFalse(any(argv[0] == '/usr/bin/ditto' for argv in self.calls))

    def test_failed_identity_or_ticket_has_no_final_binding(self):
        def refuse_identity(argv, directory):
            if any('100.6.1.13' in arg for arg in argv):
                raise ValueError('fixture signature failure')
            return self.tools(argv, directory)
        with self.assertRaisesRegex(ValueError, 'Developer ID Application'):
            self.build(refuse_identity)
        self.assert_incomplete()
        def refuse_ticket(argv, directory):
            if argv[:3] == ['/usr/bin/xcrun', 'stapler', 'validate']:
                raise ValueError('fixture ticket failure')
            return self.tools(argv, directory)
        argv = ['build_fskit_distribution.py', '--app', str(self.app),
                '--release-parent', str(self.release), '--publisher', self.publisher]
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, 'argv', argv), patch.object(builder.package, '_tool_output', side_effect=refuse_ticket), \
                redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(SystemExit) as failure:
            builder.main()
        self.assertEqual(failure.exception.code, 1)
        self.assertEqual(stdout.getvalue(), '')
        self.assertIn('stapled notarization ticket', stderr.getvalue())
        staged = Path(stderr.getvalue().split('Private staging path: ', 1)[1].strip())
        self.assertEqual(staged.parent, self.release)
        self.assertTrue((staged / '.verification' / builder.APP_NAME).is_dir())
        self.assert_incomplete()

    def test_successful_ticket_check_cannot_mask_a_changed_extracted_app(self):
        def change_after_ticket(argv, directory):
            result = self.tools(argv, directory)
            if argv[:3] == ['/usr/bin/xcrun', 'stapler', 'validate']:
                (Path(argv[-1]) / 'Contents/Info.plist').write_bytes(b'changed after binding')
            return result
        with self.assertRaisesRegex(ValueError, 'changed during distribution checks'):
            self.build(change_after_ticket)
        self.assert_incomplete()

    def test_zip_changed_after_binding_is_never_extracted(self):
        bind = builder.package.final_maintenance_bindings
        def replace_zip(app, archive, *, expected_publisher):
            record = bind(app, archive, expected_publisher=expected_publisher)
            with archive.open('ab') as changed:
                changed.write(b'after source verification')
            return record
        with patch.object(builder.package, 'final_maintenance_bindings', side_effect=replace_zip), \
                self.assertRaisesRegex(ValueError, 'ZIP changed before extraction'):
            self.build()
        self.assert_incomplete()
        self.assertFalse(any(argv[:3] == ['/usr/bin/ditto', '-x', '-k'] for argv in self.calls))

    def test_extracted_tree_must_match_and_named_source_must_stay_held(self):
        def mutate_extraction(argv, directory):
            result = self.tools(argv, directory)
            if argv[:3] == ['/usr/bin/ditto', '-x', '-k']:
                (Path(argv[-1]) / self.app.name / 'extra').write_text('extra')
            return result
        with self.assertRaisesRegex(ValueError, 'ZIP is incomplete'):
            self.build(mutate_extraction)
        self.assert_incomplete()
        def move_source(argv, directory):
            result = self.tools(argv, directory)
            if argv[:3] == ['/usr/bin/ditto', '-c', '-k']:
                self.app.rename(self.app.with_name('retained.app'))
                self.app.mkdir(mode=0o755)
            return result
        with self.assertRaisesRegex(ValueError, 'Directory changed during staging'):
            self.build(move_source)
        self.assert_incomplete()
