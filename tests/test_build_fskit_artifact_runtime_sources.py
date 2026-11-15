"""Exercise the hosted helper's real wheel contract without running native tools."""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import build_fskit_artifact as artifact

SOURCE = Path(__file__).resolve().parents[1]
WHEEL_NAME = 'stallionfs-0.7.0-cp313-cp313-macosx_15_0_arm64.whl'
REVISION = 'f' * 40


def source_wheel(with_git=True, corrupt_asset=False):
    """Build inert wheel bytes with current real source/resource pins and RECORD."""
    names = {'setup.py', 'pyproject.toml', 'tools/build_git_runtime.py', 'tools/_git_capture.py'}
    names.update(path.relative_to(SOURCE).as_posix() for path in (SOURCE / 'stallionfs').iterdir()
                 if path.is_file() and path.suffix in ('.py', '.c', '.h'))
    names.update('tools/git-inputs/' + name for name in
                 ('combined.patch', 'notices.patch', 'config.mak', 'header-manifest.json', 'alias.c'))
    sources = {name: (SOURCE / name).read_bytes() for name in names}
    files = {name: data for name, data in sources.items() if name.startswith('stallionfs/') and name.endswith('.py')}
    resources = {}
    for name, path in artifact.package._runtime_expected_resources(sources['setup.py']).items():
        data = (SOURCE / path).read_bytes()
        files['stallionfs/_benchmark_runtime/' + name] = data
        resources[name] = artifact.digest(data)
    files['stallionfs/_benchmark_runtime/manifest.json'] = json.dumps({
        'kind': 'build-source provenance',
        'build_source_sha256': {name: artifact.digest(data) for name, data in sources.items()},
        'resources': resources}).encode()
    files.update({
        'stallionfs/_scan.cpython-313-darwin.so': b'inert scan',
        'stallionfs/_image.cpython-313-darwin.so': b'inert image',
        'stallionfs-0.7.0.data/scripts/sfs': b'inert launcher',
        'stallionfs-0.7.0.data/scripts/stallionfs': b'inert launcher',
        'stallionfs-0.7.0.dist-info/METADATA': b'Name: stallionfs\nVersion: 0.7.0\n',
        'stallionfs-0.7.0.dist-info/WHEEL': b'Tag: cp313-cp313-macosx_15_0_arm64\n',
        'stallionfs-0.7.0.dist-info/entry_points.txt': b'stallionfs-python = stallionfs.__main__:main\n'})
    assets = {}
    if with_git:
        assets = {'COPYING': b'inert Git license', 'CURL-COPYING': b'inert curl license',
                  'SOURCES.txt': b'inert offline rebuild instructions',
                  'sources/build-scripts.tar.xz': b'inert source archive',
                  'sources/baseline/include/curl/curl.h': b'inert source header'}
        git = dict(assets, **{'bin/git': b'inert Git', 'libexec/git-core/git': b'inert alias',
                             'share/git-core/templates/description': b'inert template'})
        bundle = artifact.package._runtime_bundle()
        manifest = {'schema': 1, 'kind': 'package-git-runtime', 'build': {},
                    'source': {key: bundle.GIT_CONTRACT[key] for key in bundle.GIT_SOURCE_KEYS},
                    'files': [{'path': name, 'mode': '0o644', 'size': len(data), 'sha256': artifact.digest(data)}
                              for name, data in git.items()]}
        files.update({'stallionfs/_git/' + name: data for name, data in git.items()})
        files['stallionfs/_git/manifest.json'] = json.dumps(manifest).encode()
        if corrupt_asset:
            # RECORD remains valid; the nested package Git manifest must reject this.
            files['stallionfs/_git/COPYING'] = b'substituted license'
    record = 'stallionfs-0.7.0.dist-info/RECORD'
    files[record] = (''.join(name + ',sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
                              + ',' + str(len(data)) + '\n' for name, data in files.items()) + record + ',,\n').encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return output.getvalue(), {'stallionfs/_git/' + name: data for name, data in assets.items()}


class InertBuild(artifact.Build):
    """Replace every external command, retaining the actual helper orchestration."""
    def __init__(self, source, root, wheel):
        super().__init__(source, root)
        self.wheel = wheel

    def run(self, argv, timeout=30, cwd=None, env=None):
        args = [str(value) for value in argv]
        if args == ['git', 'rev-parse', 'HEAD']: return REVISION
        if args == ['git', 'rev-parse', 'HEAD^{tree}']: return 'e' * 40
        if args == ['git', 'status', '--porcelain', '--untracked-files=all']: return ''
        if args == ['git', 'ls-files', '-z']: return 'LICENSE\0'
        if args == ['/usr/bin/sw_vers', '-productVersion']: return '27.0'
        if args == ['/usr/bin/sw_vers', '-buildVersion']: return 'fixture'
        if args == ['/usr/bin/xcodebuild', '-version']: return 'Xcode 27.1\nBuild version FIXTURE'
        if args[:3] == ['/usr/bin/xcrun', '--sdk', 'macosx']:
            return '27.0' if args[-1] == '--show-sdk-version' else '/inert/sdk'
        if args[:2] == ['/usr/bin/xcrun', '--find']: return '/inert/' + args[-1]
        if args[-1] == '--version': return 'inert tool version'
        if args[0] == '/inert/nm':
            return ' U _NSExtensionMain enableAdmittedWrites setXattrHandler performWrite'
        if any(value.endswith('/tools/package_fskit.py') for value in args):
            for name in artifact.APP_FILES:
                path = self.root / 'payload' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(('inert component: ' + name).encode())
            Path(args[args.index('--manifest-out') + 1]).write_text('{"fixture": true}')
            return ''
        if args[1:4] == ['-m', 'pip', 'wheel']:
            Path(args[args.index('--wheel-dir') + 1], WHEEL_NAME).write_bytes(self.wheel)
            return ''
        if args[0] in ('/inert/clang', '/inert/swiftc'):
            Path(args[args.index('-o') + 1]).write_bytes(b'inert compiler output')
            return ''
        raise AssertionError('Unexpected external command: ' + repr(args))


class RuntimeWheelSources(unittest.TestCase):
    def build(self, root, wheel):
        config = {'Py_GIL_DISABLED': 0, 'Py_DEBUG': 0, 'EXT_SUFFIX': '.cpython-313-darwin.so'}
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, GITHUB_SHA=REVISION))
            stack.enter_context(patch.object(artifact.sys, 'platform', 'darwin'))
            stack.enter_context(patch.object(artifact.sys, 'version_info', (3, 13)))
            stack.enter_context(patch.object(artifact.platform, 'machine', return_value='arm64'))
            stack.enter_context(patch.object(artifact.platform, 'mac_ver', return_value=('27.0', (), '')))
            stack.enter_context(patch.object(artifact.sysconfig, 'get_config_var', side_effect=config.get))
            external = stack.enter_context(patch.object(artifact.subprocess, 'run', side_effect=AssertionError('Native execution')))
            inspect = stack.enter_context(patch.object(artifact.package, '_inspect_runtime_wheel',
                return_value=[{'target': {'minimum_os': '15.0'}}] * 4))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            InertBuild(SOURCE, root, wheel).build()
            external.assert_not_called()
            admitted = inspect.call_args.args[0]
            self.assertFalse(any(name.startswith('stallionfs/_git/') for name in admitted))

    def test_real_wheel_boundary_retains_asset_provenance_and_intact_wheel(self):
        for with_git in (True, False):
            with self.subTest(with_git=with_git), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                wheel, assets = source_wheel(with_git=with_git)
                self.build(root, wheel)
                with tarfile.open(root / 'StallionFS-unsigned-arm64.tar.gz') as archive:
                    self.assertEqual(archive.extractfile(WHEEL_NAME).read(), wheel)
                    manifest = json.loads(archive.extractfile('provenance.json').read())
                    expected = {name: {'sha256': artifact.digest(data), 'size': len(data)}
                                for name, data in assets.items()}
                    self.assertEqual(manifest['wheel']['git_source_assets'], expected)
                    self.assertEqual(set(archive.getnames()), {*artifact.APP_FILES, WHEEL_NAME,
                                     'mount-witness', 'LICENSE', 'provenance.json'})
                    self.assertFalse(manifest['installation_performed'])
                    self.assertFalse(manifest['registration_performed'])
                    self.assertFalse(manifest['mount_performed'])

    def test_nested_source_asset_corruption_refuses_before_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel, _ = source_wheel(corrupt_asset=True)
            with self.assertRaisesRegex(ValueError, 'Package Git payload differs'):
                self.build(root, wheel)
            self.assertFalse((root / 'StallionFS-unsigned-arm64.tar.gz').exists())
            self.assertFalse((root / 'payload/provenance.json').exists())


if __name__ == '__main__':
    unittest.main()
