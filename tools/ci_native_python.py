"""Place one checksum-pinned Intel interpreter in an owned CI directory."""
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


def provision(output):
    require(platform.system() == 'Darwin' and platform.machine() == 'x86_64', 'Intel macOS required')
    output = output.parent.resolve(strict=True) / output.name
    output.mkdir(mode=0o700)
    data = bytearray()
    with urllib.request.urlopen(URL, timeout=30) as response:
        final = urllib.parse.urlsplit(response.url)
        require(final.scheme == 'https' and final.netloc in ('github.com', 'release-assets.githubusercontent.com'), 'Unexpected Python origin')
        while True:
            block = response.read(min(65536, SIZE - len(data) + 1))
            require(len(data) + len(block) <= SIZE, 'Python download byte limit')
            if not block: break
            data.extend(block)
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA256, 'Python archive differs')
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
    executable = output / 'python/bin/python3.13'
    require(hashlib.sha256(executable.read_bytes()).hexdigest() == EXECUTABLE_SHA256, 'Python executable differs')
    (output / 'origin.json').write_text(json.dumps({'url': URL, 'sha256': SHA256, 'bytes': SIZE,
        'executable_sha256': EXECUTABLE_SHA256, 'version': '3.13.18', 'architecture': 'x86_64',
        'members': len(members)}, sort_keys=True, indent=2) + '\n')
    return executable


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    executable = provision(args.output.absolute())
    with open(os.environ['GITHUB_ENV'], 'a') as stream:
        stream.write('CI_QUALIFICATION_PYTHON=' + str(executable) + '\n')
