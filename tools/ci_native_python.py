"""Place one checksum-pinned host interpreter in an owned CI directory."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import tarfile
import urllib.parse
import urllib.request

URL = 'https://github.com/astral-sh/python-build-standalone/releases/download/20261110/cpython-3.13.18%2B20261110-x86_64-apple-darwin-install_only.tar.gz'
SHA256 = 'a46bcdeecd28ba253522b321dcb3806da1b0ff581479fc1d27e9613e3ac44764'
SIZE = 25349864
EXECUTABLE_SHA256 = '4329cc899414c0f7527fa531c37e1c430e725b10f9b3e85a3eff77c3849f166a'
PROFILES = {
    'x86_64': {'url': URL, 'sha256': SHA256, 'bytes': SIZE, 'executable_sha256': EXECUTABLE_SHA256,
               'version': '3.13.18', 'executable': 'python/bin/python3.13'},
    'arm64': {'url': 'https://github.com/astral-sh/python-build-standalone/releases/download/20261110/cpython-3.11.18%2B20261110-aarch64-apple-darwin-install_only.tar.gz',
              'sha256': '73f1ed14486aa278d331e95f7d6d452f5cfb69d90b418e26e62fd4846d53557d', 'bytes': 27111938,
              'executable_sha256': '96362363eae965731b1c9cfde891ee5a56c4da37104a513d0726e27b8564acc4',
              'version': '3.11.18', 'executable': 'python/bin/python3.11'},
}


def require(value, message):
    if not value: raise ValueError(message)


def safe(name):
    value = PurePosixPath(name)
    require(not value.is_absolute() and '..' not in value.parts and value.parts[0] == 'python'
            and value.as_posix() == name, 'Unsafe Python member')
    return value


def inventory(archive):
    members = []; names = set(); total = 0
    for member in archive:
        safe(member.name)
        require(member.name not in names and len(names) < 4096, 'Python namespace limit')
        require(member.isdir() or member.isfile() or member.issym(), 'Unexpected Python member type')
        require(0 <= member.size <= 32 * 1024 ** 2 and member.mode & ~0o777 == 0, 'Python member mode or size differs')
        names.add(member.name); members.append(member); total += member.size
        require(total <= 128 * 1024 ** 2, 'Python expanded byte limit')
        if member.issym():
            link = PurePosixPath(member.linkname)
            require(not link.is_absolute() and '..' not in link.parts and link.as_posix() == member.linkname,
                    'Python symlink escapes its directory')
    links = {member.name for member in members if member.issym()}
    for member in members:
        require(not any(str(parent) in links for parent in PurePosixPath(member.name).parents), 'Python symlink parent')
        if member.issym():
            target = str(PurePosixPath(member.name).parent / member.linkname)
            require(target in names and target not in links, 'Python link target differs')
    return members


def provision(output, architecture='x86_64'):
    require(type(architecture) is str and architecture in PROFILES, 'Unsupported interpreter architecture')
    profile = PROFILES[architecture]
    require(platform.system() == 'Darwin' and platform.machine() == architecture, 'Pinned interpreter host differs')
    output = output.parent.resolve(strict=True) / output.name
    output.mkdir(mode=0o700)
    data = bytearray()
    with urllib.request.urlopen(profile['url'], timeout=30) as response:
        final = urllib.parse.urlsplit(response.url)
        require(final.scheme == 'https' and final.netloc in ('github.com', 'release-assets.githubusercontent.com'), 'Unexpected Python origin')
        while True:
            block = response.read(min(65536, profile['bytes'] - len(data) + 1))
            require(len(data) + len(block) <= profile['bytes'], 'Python download byte limit')
            if not block: break
            data.extend(block)
    require(len(data) == profile['bytes'] and hashlib.sha256(data).hexdigest() == profile['sha256'], 'Python archive differs')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = inventory(archive)
        for member in members:
            path = output / member.name
            if member.isdir():
                path.mkdir(mode=member.mode, parents=True, exist_ok=True)
            elif member.isfile():
                path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                with archive.extractfile(member) as source, path.open('xb') as target:
                    remaining = member.size
                    while True:
                        block = source.read(min(65536, remaining + 1))
                        require(len(block) <= remaining, 'Python actual member limit')
                        if not block: break
                        target.write(block); remaining -= len(block)
                    require(remaining == 0, 'Truncated Python member')
                path.chmod(member.mode)
        for member in members:
            if member.issym(): (output / member.name).symlink_to(member.linkname)
    executable = output / profile['executable']
    require(hashlib.sha256(executable.read_bytes()).hexdigest() == profile['executable_sha256'], 'Python executable differs')
    (output / 'origin.json').write_text(json.dumps({'url': profile['url'], 'sha256': profile['sha256'], 'bytes': profile['bytes'],
        'executable_sha256': profile['executable_sha256'], 'version': profile['version'], 'architecture': architecture,
        'members': len(members)}, sort_keys=True, indent=2) + '\n')
    return executable


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--architecture', choices=tuple(PROFILES), default='x86_64')
    args = parser.parse_args()
    executable = provision(args.output.absolute(), args.architecture)
    with open(os.environ['GITHUB_ENV'], 'a') as stream:
        stream.write('CI_QUALIFICATION_PYTHON=' + str(executable) + '\n')
