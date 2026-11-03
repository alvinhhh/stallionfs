"""Assemble a fresh unsigned FSKit app from the two explicit build products."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import tempfile


def read_executable(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111:
            raise ValueError('Input must be a regular executable: ' + str(path))
        if not 0 < before.st_size <= 64 * 1024 * 1024:
            raise ValueError('Executable exceeds package size limit')
        data = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
        stable = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size',
                  'st_mtime_ns', 'st_ctime_ns')
        if len(data) != before.st_size or any(getattr(before, name) != getattr(after, name)
                                             for name in stable):
            raise ValueError('Executable changed while reading')
        return data


def write_new(path, data, mode):
    with path.open('xb') as stream:
        if stream.write(data) != len(data):
            raise OSError('Short package write')
    path.chmod(mode)
    if hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(data).digest():
        raise OSError('Package copy mismatch')


PROFILE_SYMBOLS = {'_stallionfs_factory_read_only_v1': 'read-only',
                   '_stallionfs_factory_contextual_writes_v1': 'contextual-writes'}
PROFILE_OUTPUT_LIMIT = 1024 * 1024


def _tool_output(argv, directory):
    # Keep tool output off pipes and bound the accepted complete response.
    with tempfile.TemporaryFile(dir=directory) as output:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=output,
                                stderr=output, timeout=30, check=False)
        output.seek(0)
        data = output.read(PROFILE_OUTPUT_LIMIT + 1)
    if result.returncode != 0 or len(data) > PROFILE_OUTPUT_LIMIT:
        raise ValueError('Artifact inspection failed or exceeded its output limit')
    try:
        return data.decode('utf-8', errors='strict')
    except UnicodeError as error:
        raise ValueError('Invalid artifact inspection output') from error


def _architectures(executable, directory):
    architectures = _tool_output(['/usr/bin/lipo', '-archs', str(executable)], directory).split()
    if (not architectures or len(architectures) != len(set(architectures))
            or any(arch not in ('arm64', 'arm64e', 'x86_64') for arch in architectures)):
        raise ValueError('Missing or unsupported executable architecture inventory')
    return architectures


def _factory_profile(executable, extension, architectures, directory, requested):
    policies = []
    for architecture in architectures:
        symbols = _tool_output(['/usr/bin/nm', '-arch', architecture, '-g', '-U', '-j',
                                str(executable)], directory).splitlines()
        markers = [symbol for symbol in symbols if symbol in PROFILE_SYMBOLS]
        if len(markers) != 1:
            raise ValueError('Missing, stripped or contradictory compiled factory profile')
        policies.append(PROFILE_SYMBOLS[markers[0]])
    if len(set(policies)) != 1:
        raise ValueError('Executable architectures disagree on factory policy')
    policy = policies[0]
    if requested is not None and requested != policy:
        raise ValueError('Requested access policy differs from compiled factory')
    return {'schema': 1, 'policy': policy, 'architectures': architectures,
            'pre_sign_sha256': hashlib.sha256(extension).hexdigest()}


def compiled_factory_profile(extension, requested=None):
    """Inspect exact input bytes without execution; preserve the factory schema.

    Signing may change executable bytes later. This pre-sign digest identifies
    build input only; the eventual bundle signature seals code and declaration.
    """
    with tempfile.TemporaryDirectory(prefix='stallionfs-package-') as temporary:
        directory = Path(temporary)
        executable = directory / 'extension'
        write_new(executable, extension, 0o700)
        result = _factory_profile(executable, extension, _architectures(executable, directory),
                                  directory, requested)
        if read_executable(executable) != extension:
            raise ValueError('Executable changed during compiled factory inspection')
        return result


def _version(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,2}', value):
        raise ValueError('OS versions must contain one to three numeric components')
    parts = tuple(int(part) for part in value.split('.'))
    return parts + (0,) * (3 - len(parts))


def _deployment_target(text, architecture):
    # otool emits numbered load-command blocks. Nested linker "version" is not minos.
    blocks = re.split(r'^Load command [0-9]+\s*$', text, flags=re.MULTILINE)[1:]
    commands = []
    for block in blocks:
        names = re.findall(r'^\s*cmd(?:[ \t]+([^\n]*?))?[ \t]*$', block, flags=re.MULTILINE)
        if any((name.split() or [''])[0] in ('LC_BUILD_VERSION', 'LC_VERSION_MIN_MACOSX',
                        'LC_VERSION_MIN_IPHONEOS', 'LC_VERSION_MIN_TVOS',
                        'LC_VERSION_MIN_WATCHOS') for name in names):
            if names != ['LC_BUILD_VERSION']:
                raise ValueError('Unsupported or ambiguous deployment load command')
            commands.append(block)
    if len(commands) != 1:
        raise ValueError('Expected one LC_BUILD_VERSION deployment load command per slice')
    fields = {}
    for field in ('platform', 'minos', 'sdk'):
        values = re.findall(r'^[ \t]*' + field + r'(?:[ \t]+([^\n]*?))?[ \t]*$', commands[0], flags=re.MULTILINE)
        if len(values) != 1:
            raise ValueError('Missing or duplicate deployment field: ' + field)
        fields[field] = values[0]
    if fields['platform'] != '1':
        raise ValueError('Executable slice must target macOS platform 1')
    if _version(fields['sdk']) < _version(fields['minos']):
        raise ValueError('Executable SDK is below its deployment minimum')
    return {'architecture': architecture, 'platform': 'macos',
            'minimum_os': fields['minos'], 'sdk': fields['sdk']}


def inspect_package_artifacts(host, extension, host_floor, module_floor, requested=None):
    """Check matching inventories and each slice against its containing plist floor."""
    floors = (_version(host_floor), _version(module_floor))
    if floors[0] < floors[1]:
        raise ValueError('Host declared minimum is below the module declared minimum')
    with tempfile.TemporaryDirectory(prefix='stallionfs-package-') as temporary:
        directory = Path(temporary)
        paths = (directory / 'host', directory / 'extension')
        for path, data in zip(paths, (host, extension)):
            write_new(path, data, 0o700)
        inventories = [_architectures(path, directory) for path in paths]
        if set(inventories[0]) != set(inventories[1]):
            raise ValueError('Host and module architecture inventories differ')
        factory = _factory_profile(paths[1], extension, inventories[1], directory, requested)
        targets = []
        for path, architectures, floor in zip(paths, inventories, floors):
            slices = []
            for architecture in sorted(architectures):
                target = _deployment_target(_tool_output(
                    ['/usr/bin/otool', '-arch', architecture, '-l', str(path)], directory), architecture)
                if _version(target['minimum_os']) > floor:
                    raise ValueError('Executable deployment minimum exceeds its declared plist minimum')
                slices.append(target)
            targets.append(slices)
        for path, data in zip(paths, (host, extension)):
            if read_executable(path) != data:
                raise ValueError('Executable changed during package inspection')
        return factory, targets


def _load_templates():
    templates = Path(__file__).resolve().parents[1] / 'filesystem/fskit'
    return [plistlib.loads((templates / name).read_bytes())
            for name in ('Host.Info.plist', 'Module.Info.plist')]


def _manifest_location(path, output):
    if path is None:
        return None
    if path.suffix != '.json' or path.parent.resolve(strict=True) != output.parent:
        raise ValueError('Manifest must be a fresh .json sibling of the output app')
    location = output.parent / path.name
    if os.path.lexists(location):
        raise ValueError('Manifest must not already exist')
    return location


def _reserve_manifest(location):
    parent = os.open(location.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(location.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
    except BaseException:
        os.close(parent)
        raise
    return parent, descriptor


def _manifest_identity(parent, descriptor, name):
    opened = os.fstat(descriptor)
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
        raise OSError('Reserved manifest was replaced, unlinked or is not a private single-link file')


def _write_manifest(parent, descriptor, location, value):
    _manifest_identity(parent, descriptor, location.name)
    data = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')
    if os.write(descriptor, data) != len(data):
        raise OSError('Short manifest write')
    os.fsync(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.read(descriptor, len(data) + 1) != data:
        raise OSError('Manifest copy mismatch')
    _manifest_identity(parent, descriptor, location.name)


def _candidate_manifest(args, values, targets, factory, files, output):
    hashes = []
    for path, data, _ in files:
        staged = path.read_bytes()
        if staged != data:
            raise OSError('Package copy mismatch before manifest')
        hashes.append({'path': str(path.relative_to(output)),
                       'sha256': hashlib.sha256(staged).hexdigest()})
    artifacts = []
    for value, slices, executable in zip(values, targets, (files[2], files[3])):
        artifacts.append({'bundle_id': value['CFBundleIdentifier'],
                          'declared_minimum_os': value['LSMinimumSystemVersion'],
                          'pre_sign_input_sha256': hashlib.sha256(executable[1]).hexdigest(),
                          'slices': slices})
    return {'schema': 1, 'kind': 'fskit-unsigned-assembly-candidate',
            'assembly': 'no-signing-performed', 'package_profile': args.profile,
            'bundle_version': args.bundle_version,
            'filesystem_short_name': values[1]['EXAppExtensionAttributes']['FSShortName'],
            'controller_protocol': values[0]['StallionFSControllerProtocol'],
            'factory_policy': factory['policy'], 'architectures': sorted(factory['architectures']),
            'host': artifacts[0], 'module': artifacts[1],
            'pre_sign_package_files': hashes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, type=Path)
    parser.add_argument('--extension', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path, help='Fresh .app path; never an installed app')
    parser.add_argument('--manifest-out', type=Path, help='Fresh external sibling .json candidate receipt')
    parser.add_argument('--profile', choices=('production', 'private-sfsro27'), default='production')
    parser.add_argument('--access-policy', choices=('read-only', 'contextual-writes'),
                        help='Optional assertion; policy is derived from the compiled factory')
    parser.add_argument('--bundle-version', required=True, help='Explicit development bundle version')
    args = parser.parse_args()
    if not re.fullmatch(r'[1-9][0-9]*(?:\.[0-9]+){0,2}', args.bundle_version):
        parser.error('--bundle-version must contain one to three numeric components')
    if args.out.suffix != '.app':
        parser.error('--out must end in .app')
    output = args.out.parent.resolve(strict=True) / args.out.name
    if os.path.lexists(output):
        parser.error('--out must not already exist')
    location = _manifest_location(args.manifest_out, output)
    host, extension = read_executable(args.host), read_executable(args.extension)
    values = _load_templates()
    factory, targets = inspect_package_artifacts(host, extension,
        values[0].get('LSMinimumSystemVersion'), values[1].get('LSMinimumSystemVersion'), args.access_policy)
    plists = []
    for index, value in enumerate(values):
        if value.get('CFBundleVersion') != '__BUNDLE_VERSION__':
            raise ValueError('Unexpected bundle version template')
        if not isinstance(value.get('CFBundleIdentifier'), str) or not value['CFBundleIdentifier']:
            raise ValueError('Missing bundle identifier template')
        value['CFBundleVersion'] = args.bundle_version
        if index == 0:
            value['StallionFSControllerProtocol'] = 1
        else:
            value['EXAppExtensionAttributes']['FSShortName'] = 'stallionfs' if args.profile == 'production' else 'sfsro27'
            value['StallionFSAccessPolicy'] = factory['policy']
            value['StallionFSCompiledFactory'] = factory
        plists.append(plistlib.dumps(value, sort_keys=True))
    os.umask(0o077)
    reservation = _reserve_manifest(location) if location is not None else None
    try:
        output.mkdir(mode=0o700)
        app = output / 'Contents'
        module = app / 'Extensions/StallionFS.appex/Contents'
        for directory in (app, app / 'MacOS', app / 'Extensions', module.parent, module, module / 'MacOS'):
            directory.mkdir(mode=0o700)
        files = [(app / 'Info.plist', plists[0], 0o644),
                 (module / 'Info.plist', plists[1], 0o644),
                 (app / 'MacOS/StallionFS', host, 0o755),
                 (module / 'MacOS/StallionFS', extension, 0o755)]
        for path, data, mode in files:
            write_new(path, data, mode)
        if reservation is not None:
            _write_manifest(*reservation, location,
                            _candidate_manifest(args, values, targets, factory, files, output))
    finally:
        if reservation is not None:
            os.close(reservation[1])
            os.close(reservation[0])
    print('Unsigned package: ' + str(output))


if __name__ == '__main__':
    main()
