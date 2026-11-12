"""Build and retain unsigned FSKit components; never activate or install them."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import tarfile
import tempfile

import package_fskit as package


APP_FILES = (
    'StallionFS.app/Contents/Info.plist',
    'StallionFS.app/Contents/MacOS/StallionFS',
    'StallionFS.app/Contents/Resources/Maintenance/stallionfs-maintenance',
    'StallionFS.app/Contents/Extensions/StallionFS.appex/Contents/Info.plist',
    'StallionFS.app/Contents/Extensions/StallionFS.appex/Contents/MacOS/StallionFS',
)
FORBIDDEN = ('sfs_diag_', 'sfs_image_diagnostic_', 'sfs_test_', 'enablewritediagnostic', 'diagnosticwrite',
             'fixturewritablemetadata', 'fixtureidentity', 'privatetestidentity',
             'fortesting', 'reclaimfortesting', 'createabortfortesting', 'sqlite')
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def payload_files(root, names):
    """Accept only the explicit regular-file inventory, with no linked ancestors."""
    expected = set(names)
    directories = {parent.as_posix() for name in expected
                   for parent in Path(name).parents if parent != Path('.')}
    actual = set()
    total = 0
    files = {}
    for path in root.rglob('*'):
        name = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode) and name in directories:
            continue
        if not stat.S_ISREG(mode) or path.stat().st_nlink != 1 or name not in expected:
            raise ValueError('Unexpected or linked payload member: ' + name)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_size > MAX_ARCHIVE_BYTES - total):
                raise ValueError('Artifact exceeds byte limit or member changed')
            with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                data = stream.read(before.st_size + 1)
            after = os.fstat(descriptor)
            stable = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                      'st_size', 'st_mtime_ns', 'st_ctime_ns')
            if len(data) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in stable):
                raise ValueError('Payload member changed while reading')
        finally:
            os.close(descriptor)
        total += len(data)
        files[name] = data
        actual.add(name)
    if actual != expected:
        raise ValueError('Incomplete payload inventory')
    return files


def archive_payload(root, names, output):
    files = payload_files(root, names)
    with output.open('xb') as destination, gzip.GzipFile(fileobj=destination, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as archive:
            for name, data in sorted(files.items()):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o755 if name == 'mount-witness' or '/MacOS/' in name or name.endswith('/stallionfs-maintenance') else 0o644
                archive.addfile(member, io.BytesIO(data))
    verify_archive(output, files)
    return digest(output.read_bytes())


def verify_archive(output, expected):
    with tarfile.open(output, 'r:gz') as archive:
        members = archive.getmembers()
        if len(members) != len(expected) or {item.name for item in members} != set(expected):
            raise ValueError('Archive inventory differs')
        for item in members:
            if not item.isfile() or item.size != len(expected[item.name]):
                raise ValueError('Archive member type or size differs')
            with archive.extractfile(item) as stream:
                if digest(stream.read(item.size + 1)) != digest(expected[item.name]):
                    raise ValueError('Archive member hash differs')


def select_wheel(directory):
    wheels = sorted(directory.glob('*.whl'))
    if len(wheels) != 1 or not re.fullmatch(r'stallionfs-[0-9.]+-cp313-cp313-macosx_15_0_arm64\.whl', wheels[0].name):
        observed = {'wheel_count': len(wheels), 'wheel_names': [path.name[:160] for path in wheels[:8]],
                    'names_truncated': len(wheels) > 8 or any(len(path.name) > 160 for path in wheels[:8])}
        raise ValueError('Expected exactly one cp313 ARM64 wheel; ' + json.dumps(observed, sort_keys=True))
    return wheels[0]


def validate_wheel_targets(observations):
    if any(package._version(row['target']['minimum_os']) > package._version('15.0') for row in observations):
        raise ValueError('Wheel native member exceeds its macOS 15.0 platform tag')


class Build:
    def __init__(self, source, root):
        self.source = source
        self.root = root
        self.commands = []

    def run(self, argv, timeout=30, cwd=None, env=None):
        argv = [str(value) for value in argv]
        # Public receipts replace ephemeral source/output prefixes with fixed labels.
        public = [value.replace(str(self.source), '$SOURCE').replace(str(self.root), '$BUILD') for value in argv]
        with tempfile.TemporaryFile(dir=self.root) as output:
            result = subprocess.run(argv, cwd=cwd or self.source, env=env, stdin=subprocess.DEVNULL,
                                    stdout=output, stderr=output, timeout=timeout, check=False)
            output.seek(0)
            data = output.read(4 * 1024 * 1024 + 1)
        self.commands.append({'argv': public, 'timeout_seconds': timeout, 'returncode': result.returncode})
        if result.returncode or len(data) > 4 * 1024 * 1024:
            raise RuntimeError('Build command failed or exceeded accepted output: ' + ' '.join(public))
        return data.decode('utf-8', errors='strict').strip()

    def build(self):
        source, root = self.source, self.root
        revision = self.run(['git', 'rev-parse', 'HEAD'])
        tree = self.run(['git', 'rev-parse', 'HEAD^{tree}'])
        if revision != os.environ['GITHUB_SHA'] or self.run(['git', 'status', '--porcelain', '--untracked-files=all']):
            raise ValueError('Expected the clean dispatched source commit')
        if (sys.platform != 'darwin' or platform.machine() != 'arm64'
                or not re.fullmatch(r'27(?:\.\d+){0,2}', platform.mac_ver()[0])
                or sys.version_info[:2] != (3, 13) or sysconfig.get_config_var('Py_DEBUG')
                or sysconfig.get_config_var('Py_GIL_DISABLED')):
            raise ValueError('Requires macOS 27 ARM64 and ordinary CPython 3.13')
        tools = {'macos_version': self.run(['/usr/bin/sw_vers', '-productVersion']),
                 'macos_build': self.run(['/usr/bin/sw_vers', '-buildVersion']),
                 'xcode': self.run(['/usr/bin/xcodebuild', '-version']),
                 'sdk_version': self.run(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version'])}
        if (not re.fullmatch(r'Xcode 27\.1\nBuild version [A-Za-z0-9]+', tools['xcode'])
                or tools['sdk_version'] != '27.0'):
            raise ValueError('Requires selected Xcode 27.1 and macOS SDK 27.0')
        sdk = self.run(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'])
        selected = {name: self.run(['/usr/bin/xcrun', '--find', name]) for name in ('clang', 'swiftc', 'nm')}
        tools.update({name: self.run([selected[name], '--version']) for name in ('clang', 'swiftc')})
        tools.update(python=sys.version, architecture=platform.machine(), selected_paths=selected, sdk_path=sdk)
        tracked = self.run(['git', 'ls-files', '-z']).split('\0')
        source_hashes = {name: digest((source / name).read_bytes()) for name in tracked if name}
        work = root / 'build'; work.mkdir(mode=0o700)
        payload = root / 'payload'; payload.mkdir(mode=0o700)
        target = 'arm64-apple-macos27.0'
        cflags = [selected['clang'], '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1',
                  '-target', target, '-isysroot', sdk, '-I', source / 'filesystem']
        normal = work / 'image.o'
        self.run([*cflags, '-c', source / 'filesystem/image.c', '-o', normal], 90)
        swift = [selected['swiftc'], '-swift-version', '6', '-strict-concurrency=complete',
                 '-target', target, '-sdk', sdk, '-Onone', '-parse-as-library']
        module, host = work / 'module', work / 'host'
        self.run([*swift, '-D', 'STALLION_CONTEXT_HANDLERS', '-D', 'STALLION_CONTEXT_WRITES',
                  '-I', source / 'filesystem/fskit', '-application-extension',
                  '-Xlinker', '-e', '-Xlinker', '_NSExtensionMain',
                  '-module-cache-path', work / 'module-cache', source / 'filesystem/fskit/Extension.swift',
                  source / 'filesystem/fskit/Volume.swift', normal, '-o', module], 240)
        self.run([*swift, '-warnings-as-errors', '-module-cache-path', work / 'host-cache',
                  source / 'filesystem/fskit/Host.swift', '-o', host], 120)
        for name, binary in [('module', module), ('host', host)]:
            symbols = self.run([selected['nm'], binary], 30).lower()
            if any(word in symbols for word in FORBIDDEN):
                raise ValueError('Diagnostic, fixture or test symbols in ' + name)
            if name == 'module' and not all(word in symbols for word in
                    (' u _nsextensionmain', 'enableadmittedwrites', 'setxattrhandler', 'performwrite')):
                raise ValueError('Production contextual write symbols missing')
        maintenance = work / 'stallionfs-maintenance'
        self.run([*cflags, source / 'filesystem/fskit/maintenance_native.c', '-o', maintenance], 90)
        candidate = payload / 'package-candidate.json'
        self.run([sys.executable, '-I', '-B', source / 'tools/package_fskit.py',
                  '--host', host, '--extension', module, '--maintenance-native', maintenance, '--out', payload / 'StallionFS.app',
                  '--bundle-version', '146', '--profile', 'production',
                  '--access-policy', 'contextual-writes', '--manifest-out', candidate], 180)
        package_receipt = json.loads(candidate.read_bytes())
        candidate.unlink()  # The public object is retained in provenance, outside the app.
        wheel_dir = work / 'wheels'; wheel_dir.mkdir(mode=0o700)
        env = dict(os.environ, MACOSX_DEPLOYMENT_TARGET='15.0', ARCHFLAGS='-arch arm64',
                   CFLAGS='', CPPFLAGS='', CXXFLAGS='', LDFLAGS='')
        self.run([sys.executable, '-m', 'pip', 'wheel', '--no-deps', '--wheel-dir', wheel_dir,
                  '--config-settings=--build-option=--plat-name=macosx-15.0-arm64', source], 300, env=env)
        built_wheel = select_wheel(wheel_dir)
        metadata = {'python_tag': 'cp313', 'target_triple': 'aarch64-apple-darwin',
                    'python_config_vars': {name: str(sysconfig.get_config_var(name) or 0)
                        for name in ('Py_GIL_DISABLED', 'Py_DEBUG', 'EXT_SUFFIX')}}
        files, scripts, extensions, tag, build_sources, wheel_assets = package._runtime_source_wheel(
            built_wheel.read_bytes(), metadata, {})
        observations = package._inspect_runtime_wheel(files, scripts, extensions, work)
        validate_wheel_targets(observations)
        for index in range(4):
            symbols = self.run([selected['nm'], work / ('wheel-' + str(index))], 30).lower()
            if any(word in symbols for word in FORBIDDEN):
                raise ValueError('Diagnostic, fixture or test symbols in wheel')
        wheel = payload / built_wheel.name
        shutil.copyfile(built_wheel, wheel)
        self.run([*cflags, source / 'tools/mount_witness.c', '-o', payload / 'mount-witness'], 90)
        shutil.copyfile(source / 'LICENSE', payload / 'LICENSE')
        names = [*APP_FILES, wheel.name, 'mount-witness', 'LICENSE']
        contents = payload_files(payload, names)
        manifest = {'schema': 1, 'kind': 'fskit-unsigned-hosted-components',
                    'scope': 'unsigned components only; private Python/Git runtime not included',
                    'distribution_signing_performed': False, 'installation_performed': False,
                    'registration_performed': False, 'mount_performed': False,
                    'source_commit': revision, 'source_tree': tree, 'source_sha256': source_hashes,
                    'tools': tools, 'commands': self.commands, 'wheel_build_environment': {key: env[key] for key in
                        ('MACOSX_DEPLOYMENT_TARGET', 'ARCHFLAGS', 'CFLAGS', 'CPPFLAGS', 'CXXFLAGS', 'LDFLAGS')},
                    'package': package_receipt,
                    'wheel': {'tag': tag, 'record_and_current_source_validated': True,
                              'native_members': observations,
                              'build_source_sha256': build_sources,
                              'git_source_assets': {'stallionfs/_git/' + name: {
                                  'sha256': digest(data), 'size': len(data)}
                                  for name, data in sorted(wheel_assets.items())}},
                    'symbol_checks': {'production_contextual_writes': True, 'forbidden_symbols_absent': True},
                    'files': {name: {'sha256': digest(data), 'size': len(data)} for name, data in sorted(contents.items())}}
        (payload / 'provenance.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
        output = root / 'StallionFS-unsigned-arm64.tar.gz'
        archive_hash = archive_payload(payload, [*names, 'provenance.json'], output)
        print(json.dumps({'archive': output.name, 'sha256': archive_hash, 'source_commit': revision,
                          'source_tree': tree, 'bundle_version': '146'}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path, help='Fresh private build directory')
    args = parser.parse_args()
    os.umask(0o077)
    args.out.mkdir(mode=0o700)  # A rerun must choose a fresh directory.
    Build(Path(__file__).resolve().parents[1], args.out.resolve(strict=True)).build()


if __name__ == '__main__':
    main()
