"""Assemble a fresh unsigned FSKit app from the two explicit build products."""
import argparse
import hashlib
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
        raise ValueError('Compiled factory inspection failed or exceeded its output limit')
    try:
        return data.decode('utf-8', errors='strict')
    except UnicodeError as error:
        raise ValueError('Invalid compiled factory inspection output') from error


def compiled_factory_profile(extension, requested=None):
    """Inspect the exact bytes copied to the package, without executing them.

    Signing may change executable bytes later. This pre-sign digest identifies
    build input only; the eventual bundle signature seals code and declaration.
    """
    with tempfile.TemporaryDirectory(prefix='stallionfs-package-') as temporary:
        directory = Path(temporary)
        executable = directory / 'extension'
        write_new(executable, extension, 0o700)
        architectures = _tool_output(['/usr/bin/lipo', '-archs', str(executable)], directory).split()
        if (not architectures or len(architectures) != len(set(architectures))
                or any(arch not in ('arm64', 'arm64e', 'x86_64') for arch in architectures)):
            raise ValueError('Missing or unsupported executable architecture inventory')
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
        if read_executable(executable) != extension:
            raise ValueError('Executable changed during compiled factory inspection')
    return {'schema': 1, 'policy': policy, 'architectures': architectures,
            'pre_sign_sha256': hashlib.sha256(extension).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, type=Path)
    parser.add_argument('--extension', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path, help='Fresh .app path; never an installed app')
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
    templates = Path(__file__).resolve().parents[1] / 'filesystem/fskit'
    host, extension = read_executable(args.host), read_executable(args.extension)
    factory = compiled_factory_profile(extension, args.access_policy)
    plists = []
    for name in ('Host.Info.plist', 'Module.Info.plist'):
        value = plistlib.loads((templates / name).read_bytes())
        if value.get('CFBundleVersion') != '__BUNDLE_VERSION__':
            raise ValueError('Unexpected bundle version template')
        value['CFBundleVersion'] = args.bundle_version
        if name == 'Host.Info.plist':
            value['StallionFSControllerProtocol'] = 1
        else:
            value['EXAppExtensionAttributes']['FSShortName'] = 'stallionfs' if args.profile == 'production' else 'sfsro27'
            value['StallionFSAccessPolicy'] = factory['policy']
            value['StallionFSCompiledFactory'] = factory
        plists.append(plistlib.dumps(value, sort_keys=True))
    os.umask(0o077)
    output.mkdir(mode=0o700)
    app = output / 'Contents'
    module = app / 'Extensions/StallionFS.appex/Contents'
    for directory in (app, app / 'MacOS', app / 'Extensions', module.parent, module, module / 'MacOS'):
        directory.mkdir(mode=0o700)
    write_new(app / 'Info.plist', plists[0], 0o644)
    write_new(module / 'Info.plist', plists[1], 0o644)
    write_new(app / 'MacOS/StallionFS', host, 0o755)
    write_new(module / 'MacOS/StallionFS', extension, 0o755)
    print('Unsigned package: ' + str(output))


if __name__ == '__main__':
    main()
