"""Build the pinned internal Git dependency without installing system files."""
import argparse
import ctypes
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shlex
import shutil
import stat
import struct
import tarfile
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MINIMUM = '13.0'
SOURCE_DATE = '2026-11-11'
URLS = {
    'git-2.56.0.tar.xz': 'https://www.kernel.org/pub/software/scm/git/git-2.56.0.tar.xz',
    'curl-source.tar.gz': 'https://codeload.github.com/apple-oss-distributions/curl/tar.gz/913bdd410e7bb72b815ba6d4f02a1c32e34635fe',
}
SOURCE_INSTRUCTIONS = '''Corresponding source and offline rebuild

This directory contains the complete sanitized Git source, the combined code
patch, dated modification notices, build configuration, eleven public curl
headers, alias source, and the exact build scripts used for this runtime.
COPYING and CURL-COPYING apply to their respective components. Git links the
macOS system curl library; no curl implementation is included in this runtime.

On macOS with Python 3.11 or later and Xcode command line tools, extract
sources/build-scripts.tar.xz into an empty directory. From that directory run:

python3 tools/build_git_runtime.py --delivered-sources /absolute/path/to/_git \\
    --output /absolute/path/to/new-runtime --build-directory /absolute/path/to/build

The delivered-sources path is this directory, containing SOURCES.txt. This mode
uses only the delivered source and headers and never downloads original archives.
The output and build directories must be owned, writable locations. The recipe
builds for the current arm64 or x86_64 host with a macOS 13 deployment target;
the final wheel also accounts for its Python extensions and launchers.

git-source.tar.xz omits optional non-build contributor instructions. The code
patch and separate dated notices are applied once to that source. Their hashes,
the original upstream archive identity, final modified-source hashes, tools,
normalized build flags, and actual payload hashes are in manifest.json.
'''


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def exclusive_rename(source, destination):
    library = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    function = library.renamex_np
    function.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    if function(os.fsencode(source), os.fsencode(destination), 0x00000004):
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), str(destination))


def version(number):
    return (number >> 16, (number >> 8) & 255, number & 255)


def macho(path):
    data = Path(path).read_bytes()
    if data[:4] == b'\xca\xfe\xba\xbe':
        count = struct.unpack_from('>I', data, 4)[0]
        require(0 < count <= 8 and len(data) >= 8 + count * 20, 'Invalid Mach-O slices')
        slices = [struct.unpack_from('>5I', data, 8 + i * 20)[2:4] for i in range(count)]
    elif data[:4] == b'\xcf\xfa\xed\xfe':
        slices = [(0, len(data))]
    else:
        return []
    result = []
    for start, size in slices:
        require(size >= 32 and start + size <= len(data), 'Invalid Mach-O slice')
        magic, cpu, subtype, kind, count, commands_size, flags, reserved = struct.unpack_from('<8I', data, start)
        require(magic == 0xfeedfacf and cpu in (0x100000c, 0x1000007)
                and count <= 1024 and commands_size <= size - 32, 'Unsupported Mach-O slice')
        offset, minima, dependencies, rpaths = start + 32, [], [], []
        for _ in range(count):
            require(offset + 8 <= start + 32 + commands_size, 'Invalid Mach-O command')
            command, length = struct.unpack_from('<2I', data, offset)
            require(length >= 8 and offset + length <= start + 32 + commands_size, 'Invalid Mach-O command')
            if command == 0x32:
                require(length >= 24, 'Invalid Mach-O deployment command')
                target, minimum, sdk, tools = struct.unpack_from('<4I', data, offset + 8)
                require(target == 1 and version(sdk) >= version(minimum), 'Invalid macOS deployment target')
                minima.append(version(minimum))
            elif command == 0x24:
                require(length >= 16, 'Invalid Mach-O deployment command')
                minimum, sdk = struct.unpack_from('<2I', data, offset + 8)
                require(version(sdk) >= version(minimum), 'Invalid macOS deployment target')
                minima.append(version(minimum))
            elif command in (0xc, 0x80000018, 0x8000001f, 0x20, 0x8000001c):
                name = struct.unpack_from('<I', data, offset + 8)[0]
                require(8 <= name < length, 'Invalid Mach-O library path')
                text = data[offset + name:offset + length].split(b'\0')[0].decode()
                (rpaths if command == 0x8000001c else dependencies).append(text)
            offset += length
        require(offset == start + 32 + commands_size and len(minima) == 1, 'Ambiguous Mach-O deployment target')
        result.append({'architecture': 'arm64' if cpu == 0x100000c else 'x86_64',
                       'minimum': minima[0], 'dependencies': dependencies, 'rpaths': rpaths})
    return result


def sanitized_source(original, destination):
    with tarfile.open(original) as source, tarfile.open(destination, 'w:xz', format=tarfile.PAX_FORMAT) as output:
        for member in source.getmembers():
            if member.name == 'git-2.56.0/po/AGENTS.md':
                continue
            data = source.extractfile(member).read() if member.isfile() else None
            if member.name == 'git-2.56.0/po/README.md':
                start = data.index(b'## AI-assisted translation and review\n')
                end = data.index(b'## PO helper\n', start)
                data = (data[:start] + ('Modified ' + SOURCE_DATE + ': optional contributor workflow section removed '
                        'for this source distribution.\n\n').encode() + data[end:])
                member.size = len(data)
            member.uid = member.gid = 0; member.uname = member.gname = ''
            member.pax_headers = {}
            output.addfile(member, io.BytesIO(data) if data is not None else None)


def extract_source(archive, destination):
    with tarfile.open(archive) as source:
        members = source.getmembers(); total = 0
        require(len(members) <= 6000, 'Source archive exceeds bounds')
        for member in members:
            name = PurePosixPath(member.name)
            require(name.parts and name.parts[0] == 'git-2.56.0' and not name.is_absolute()
                    and '..' not in name.parts and (member.isdir() or member.isfile() or member.issym()),
                    'Unsafe source archive entry')
            if member.issym():
                target = destination.joinpath(*name.parent.parts, member.linkname).resolve()
                require(target.is_relative_to(destination / 'git-2.56.0'), 'Unsafe source archive link')
            total += member.size
            require(member.size <= 64 * 1024**2 and total <= 512 * 1024**2, 'Source archive exceeds bounds')
        # Every name/type/link was bounded above; no archive hard links are accepted.
        source.extractall(destination)


def build(destination, temporary, *, inputs=None, delivered_sources=None):
    require(platform.system() == 'Darwin' and platform.machine() in ('arm64', 'x86_64'), 'macOS arm64 or x86_64 required')
    sources = module('_git_build_sources', ROOT / 'stallionfs/_git_sources.py')
    bundle = module('_git_build_bundle', ROOT / 'stallionfs/_bundle.py')
    capture = module('_git_build_capture', ROOT / 'tools/_git_capture.py')
    architecture = platform.machine(); destination = Path(destination).absolute()
    recipe_sha = sha(__file__); capture_sha = sha(ROOT / 'tools/_git_capture.py')
    registry_sha = sha(ROOT / 'stallionfs/_git_sources.py'); bundle_sha = sha(ROOT / 'stallionfs/_bundle.py')
    previous_identity = None
    if destination.exists() or destination.is_symlink():
        require(not destination.is_symlink(), 'Generated Git dependency changed')
        manifest = json.loads((destination / 'manifest.json').read_bytes())
        require(manifest.get('kind') == 'package-git-runtime' and manifest.get('schema') == 1,
                'Generated Git dependency changed')
        expected = {row['path']: row for row in manifest['files']}
        actual = {p.relative_to(destination).as_posix() for p in destination.rglob('*') if p.is_file() or p.is_symlink()}
        require(actual == set(expected) | {'manifest.json'}, 'Generated Git dependency changed')
        for name, row in expected.items():
            path = destination / name
            require(not path.is_symlink() and path.stat().st_nlink == 1 and sha(path) == row['sha256']
                    and oct(stat.S_IMODE(path.stat().st_mode)) == row['mode'], 'Generated Git dependency changed')
        if (manifest.get('source') == {key: bundle.GIT_CONTRACT[key] for key in bundle.GIT_SOURCE_KEYS}
                and manifest['build']['architecture'] == architecture and manifest['build']['recipe_sha256'] == recipe_sha
                and manifest['build']['capture_sha256'] == capture_sha
                and manifest['build'].get('registry_sha256') == registry_sha
                and manifest['build'].get('bundle_sha256') == bundle_sha):
            return manifest
        info = destination.stat(); previous_identity = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
    temporary = Path(temporary); temporary.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='git-', dir=temporary)).resolve(); work.chmod(0o700)
    for name in ('inputs', 'logs', 'home', 'xdg', 'tmp', 'stage', 'output'):
        (work / name).mkdir(mode=0o700)
    delivered = Path(delivered_sources).resolve(strict=True) if delivered_sources is not None else None
    inputs = delivered / 'sources' if delivered is not None else Path(
        inputs or os.environ.get('STALLIONFS_BUILD_INPUTS', ROOT / 'tools/git-inputs'))
    for name, expected in sources.INPUTS.items():
        if delivered is not None and name in URLS:
            continue
        target = work / 'inputs' / name
        local = inputs / name
        if not local.is_file() and delivered is None:
            local = ROOT / 'tools/git-inputs' / name
        if local.is_file():
            shutil.copyfile(local, target)
        else:
            require(delivered is None and name in URLS, 'Pinned Git build input is missing')
            with urllib.request.urlopen(URLS[name], timeout=30) as response, target.open('xb') as stream:
                size = 0
                while block := response.read(65536):
                    size += len(block); require(size <= 16 * 1024**2, 'Source download exceeds bounds'); stream.write(block)
        require(sha(target) == expected, 'Pinned Git build input differs')
    if delivered is None:
        sanitized_source(work / 'inputs/git-2.56.0.tar.xz', work / 'output/git-source.tar.xz')
    else:
        shutil.copyfile(inputs / 'git-source.tar.xz', work / 'output/git-source.tar.xz')
    require(sha(work / 'output/git-source.tar.xz') == bundle.GIT_CONTRACT['source_distribution_sha256'],
            'Corresponding Git source differs')
    extract_source(work / 'output/git-source.tar.xz', work)
    source = work / 'git-2.56.0'
    headers = json.loads((work / 'inputs/header-manifest.json').read_text())
    require(len(headers) == 11, 'Pinned curl header set differs')
    if delivered is not None:
        for row in headers:
            data = (inputs / row['file']).read_bytes()
            require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'], 'Pinned curl header differs')
            path = work / row['file']; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        shutil.copyfile(delivered / 'CURL-COPYING', work / 'output/CURL-COPYING')
    else:
        with tarfile.open(work / 'inputs/curl-source.tar.gz') as archive:
            for row in headers:
                data = archive.extractfile(row['archive_member']).read()
                require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'], 'Pinned curl header differs')
                path = work / row['file']; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            copying = archive.extractfile('curl-913bdd410e7bb72b815ba6d4f02a1c32e34635fe/curl/COPYING').read()
            (work / 'output/CURL-COPYING').write_bytes(copying)
    require(sha(work / 'output/CURL-COPYING') == sources.LICENSES['CURL-COPYING'], 'Pinned curl license differs')
    require(sha(source / 'COPYING') == sources.LICENSES['COPYING'], 'Pinned Git license differs')
    environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(work / 'home'),
        'XDG_CONFIG_HOME': str(work / 'xdg'), 'TMPDIR': str(work / 'tmp'), 'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': '/dev/null', 'GIT_CONFIG_GLOBAL': '/dev/null',
        'GIT_ATTR_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0', 'GIT_CEILING_DIRECTORIES': str(work),
        'GIT_TRACE2': '0', 'GIT_TRACE2_EVENT': '0', 'GIT_TRACE2_PERF': '0', 'MACOSX_DEPLOYMENT_TARGET': MINIMUM,
        'MAKEFLAGS': '', 'MFLAGS': ''}
    if 'DEVELOPER_DIR' in os.environ:
        environment['DEVELOPER_DIR'] = os.environ['DEVELOPER_DIR']
    capture._COMMAND_ENV = environment; capture._COMMAND_STREAM_CAP = 32 * 1024**2
    capture._COMMAND_DRAIN_SECONDS = capture._COMMAND_REAP_SECONDS = 2
    previous = capture._install_command_handlers(); started = time.monotonic(); step = 0
    def command(argv, cwd=work, timeout=600):
        nonlocal step
        stem = work / 'logs' / f'{step:02}'; step += 1
        try:
            require(time.monotonic() - started < 2700, 'Git build deadline exceeded')
            result = capture._owned_command(list(map(str, argv)), cwd=cwd,
                timeout=min(timeout, 2700 - (time.monotonic() - started)), stem=stem)
            record = json.loads(Path(str(stem) + '.command.json').read_bytes())
            require(not record['cleanup_uncertain'] and capture._command_state['failure'] is None and result.returncode == 0
                    and record['stdout_retained_bytes'] + record['stderr_retained_bytes']
                        + record['stdout_discarded_bytes'] + record['stderr_discarded_bytes'] <= 32 * 1024**2
                    and time.monotonic() - started < 2700, 'Git dependency build failed; retained at ' + str(work))
        except BaseException as error:
            capture._latch_command('build_refusal', repr(error))
            try:
                capture._exclusive(work / 'build-refusal.json', json.dumps({'step': step - 1, 'error': repr(error),
                    'capture_receipt': str(stem) + '.command.json', 'further_targets_or_promotion': False}) + '\n')
            except BaseException as recording:
                error.add_note('Build refusal receipt also failed: ' + repr(recording))
            raise
        return result.stdout.strip()
    try:
        tools = {name: command(['/usr/bin/xcrun', '--find', name], timeout=20) for name in ('clang', 'ar', 'ranlib', 'ld', 'make')}
        sdk = command(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'], timeout=20)
        command(['/usr/bin/patch', '-p1', '-t', '-N', '-i', work / 'inputs/combined.patch'], cwd=source, timeout=20)
        command(['/usr/bin/patch', '-p1', '-t', '-N', '-i', work / 'inputs/notices.patch'], cwd=source, timeout=20)
        shutil.copyfile(work / 'inputs/config.mak', source / 'config.mak')
        flags = ['-O2', '-g', '-arch', architecture, '-isysroot', sdk, '-mmacosx-version-min=' + MINIMUM,
                 '-ffile-prefix-map=' + str(work) + '=/usr/src/stallionfs']
        link_flags = ['-arch', architecture, '-isysroot', sdk, '-mmacosx-version-min=' + MINIMUM,
                      '-Xlinker', '-oso_prefix', '-Xlinker', str(work) + '/']
        make = [tools['make'], '-j2', 'CC=' + shlex.quote(tools['clang']), 'AR=' + shlex.quote(tools['ar']),
            'RANLIB=' + shlex.quote(tools['ranlib']), 'LD=' + shlex.quote(tools['ld']),
            'HOST_CPU=' + architecture, 'CFLAGS=' + shlex.join(flags),
            'LDFLAGS=' + shlex.join(link_flags),
            'CURL_CFLAGS=' + shlex.quote('-I' + str(work / 'baseline/include')), 'V=1', 'NO_RUST=YesPlease']
        for target in ('all', 'contrib/credential/osxkeychain/git-credential-osxkeychain',
                       'install', 'install-git-credential-osxkeychain'):
            command([*make, *(['DESTDIR=' + str(work / 'stage')] if target.startswith('install') else []), target], cwd=source)
        staged = work / 'stage/stallionfs-private-git'
        actual = {p.relative_to(staged).as_posix() for p in staged.rglob('*') if p.is_file() or p.is_symlink()}
        require(actual == set(sources.LAYOUT), 'Built Git namespace differs')
        aliases = {}
        for index, target in enumerate(sorted({row['target'] for row in sources.LAYOUT.values() if row['target']})):
            output = work / f'alias-{index}'
            shutil.copyfile(work / 'inputs/alias.c', work / 'alias.c')
            command([tools['clang'], '-isysroot', sdk, '-Os', '-arch', architecture,
                '-mmacosx-version-min=' + MINIMUM, '-ffile-prefix-map=' + str(work) + '=/usr/src/stallionfs',
                '-Xlinker', '-oso_prefix', '-Xlinker', str(work) + '/',
                '-Wl,-dead_strip', '-DTARGET="' + target + '"', work / 'alias.c', '-o', output], timeout=60)
            aliases[target] = output
        runtime = work / 'runtime'; runtime.mkdir(mode=0o755)
        for name in sources.DIRECTORIES:
            (runtime / name).mkdir(mode=0o755, parents=True, exist_ok=True)
        for name, row in sources.LAYOUT.items():
            path = staged / name
            if row['target']:
                require(path.is_symlink() and os.readlink(path) == row['target'], 'Built Git alias differs')
                path = aliases[row['target']]
            else:
                require(path.is_file() and not path.is_symlink(), 'Built Git file differs')
            target = runtime / name; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(path, target)
            target.chmod(int(row['mode'], 8))
        shutil.copyfile(source / 'COPYING', runtime / 'COPYING')
        shutil.copyfile(work / 'output/CURL-COPYING', runtime / 'CURL-COPYING')
        (runtime / 'SOURCES.txt').write_text(SOURCE_INSTRUCTIONS)
        corresponding = runtime / 'sources'; corresponding.mkdir(mode=0o755)
        shutil.copyfile(work / 'output/git-source.tar.xz', corresponding / 'git-source.tar.xz')
        for name in sources.INPUTS:
            if name not in URLS:
                shutil.copyfile(work / 'inputs' / name, corresponding / name)
        for row in headers:
            path = corresponding / row['file']; path.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(work / row['file'], path)
        with tarfile.open(corresponding / 'build-scripts.tar.xz', 'w:xz', format=tarfile.PAX_FORMAT) as archive:
            files = ['tools/build_git_runtime.py', 'tools/_git_capture.py', 'stallionfs/_git_sources.py',
                     'stallionfs/_bundle.py', *['tools/git-inputs/' + name for name in sources.INPUTS if name not in URLS]]
            for name in sorted(files):
                data = (ROOT / name).read_bytes()
                member = tarfile.TarInfo(name); member.size = len(data); member.mode = 0o644
                archive.addfile(member, io.BytesIO(data))
        rows, targets = [], []
        for path in sorted(runtime.rglob('*')):
            if not path.is_file(): continue
            relative = path.relative_to(runtime).as_posix()
            if relative not in sources.LAYOUT: path.chmod(0o644)
            rows.append({'path': relative, 'mode': oct(stat.S_IMODE(path.stat().st_mode)),
                         'size': path.stat().st_size, 'sha256': sha(path)})
            slices = macho(path)
            if relative in sources.LAYOUT and (path.read_bytes()[:2] != b'#!' and path.stat().st_mode & 0o111):
                require(slices, 'Expected Git executable is not Mach-O')
            for value in slices:
                require(value['architecture'] == architecture and value['minimum'] == (13, 0, 0)
                    and not value['rpaths'] and all(name.startswith(('/usr/lib/', '/System/Library/Frameworks/'))
                                                  for name in value['dependencies']), 'Git runtime deployment contract differs')
                targets.append(value)
        manifest = {'schema': 1, 'kind': 'package-git-runtime',
            'source': {key: bundle.GIT_CONTRACT[key] for key in bundle.GIT_SOURCE_KEYS},
            'build': {'architecture': architecture, 'minimum_os': MINIMUM, 'recipe_sha256': recipe_sha,
                'capture_sha256': capture_sha, 'tools': {name: sha(path) for name, path in tools.items()},
                'registry_sha256': registry_sha, 'bundle_sha256': bundle_sha,
                'compiler_flags': [arg.replace(str(work), '${BUILD}').replace(sdk, '${SDK}') for arg in flags],
                'linker_flags': [arg.replace(str(work), '${BUILD}').replace(sdk, '${SDK}') for arg in link_flags],
                'curl_flags': ['-I${BUILD}/baseline/include'],
                'targets': ['all', 'contrib/credential/osxkeychain/git-credential-osxkeychain',
                            'install', 'install-git-credential-osxkeychain'],
                'source_distribution_sha256': sha(corresponding / 'git-source.tar.xz'),
                'final_source_sha256': {name: sha(source / name) for name in ('hook.c', 'attr.c', 'config.c', 'config.h')},
                'macho_slices': len(targets)}, 'files': rows}
        (runtime / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
        (runtime / 'manifest.json').chmod(0o644)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if previous_identity is not None:
            info = destination.stat()
            require(previous_identity == (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns),
                    'Generated Git dependency changed')
            exclusive_rename(destination, work / 'previous-runtime')
        try:
            exclusive_rename(runtime, destination)
        except BaseException:
            if previous_identity is not None and not destination.exists():
                exclusive_rename(work / 'previous-runtime', destination)
            raise
        return manifest
    finally:
        capture._restore_command_handlers(previous)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--build-directory', type=Path, required=True)
    parser.add_argument('--delivered-sources', type=Path)
    arguments = parser.parse_args()
    build(arguments.output, arguments.build_directory, delivered_sources=arguments.delivered_sources)
