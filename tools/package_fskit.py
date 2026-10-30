"""Assemble a fresh unsigned FSKit app from the two explicit build products."""
import argparse
import hashlib
import os
from pathlib import Path
import plistlib
import re
import stat


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, type=Path)
    parser.add_argument('--extension', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path, help='Fresh .app path; never an installed app')
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
    plists = []
    for name in ('Host.Info.plist', 'Module.Info.plist'):
        value = plistlib.loads((templates / name).read_bytes())
        if value.get('CFBundleVersion') != '__BUNDLE_VERSION__':
            raise ValueError('Unexpected bundle version template')
        value['CFBundleVersion'] = args.bundle_version
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
