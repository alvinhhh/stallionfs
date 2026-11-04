"""Assemble a fresh unsigned FSKit app from the two explicit build products."""
import argparse
import ast
import base64
import csv
import io
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import subprocess
import tempfile
import unicodedata
import zipfile


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


RUNTIME_NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC
RUNTIME_MAX_FILES, RUNTIME_MAX_FILE, RUNTIME_MAX_TOTAL = 5000, 128 * 1024**2, 512 * 1024**2


def _runtime_require(ok, message):
    if not ok:
        raise ValueError(message)


def _runtime_sha(data):
    return hashlib.sha256(data).hexdigest()


def _runtime_relative(name):
    _runtime_require(isinstance(name, str) and 0 < len(name) < 1024 and '\x00' not in name and '\\' not in name,
            'Invalid relative pathname')
    path = PurePosixPath(name)
    _runtime_require(not path.is_absolute() and path.as_posix() == name and '..' not in path.parts and name != '.',
            'Unsafe relative pathname: ' + name)
    return name


def _runtime_directory(path):
    path = Path(path)
    _runtime_require(path.is_absolute() and '..' not in path.parts, 'Absolute ordinary directory required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | RUNTIME_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | RUNTIME_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        _runtime_require(os.fstat(fd).st_uid == os.getuid(), 'Directory ownership changed')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _runtime_subdir(root, name, create=False, mode=0o755):
    fd = os.dup(root)
    try:
        for part in _runtime_relative(name).split('/'):
            made = False
            if create:
                try:
                    os.mkdir(part, mode, dir_fd=fd)
                    made = True
                except FileExistsError:
                    pass
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | RUNTIME_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
            _runtime_require(os.fstat(fd).st_uid == os.getuid(), 'Subdirectory ownership changed')
            if made:
                os.fchmod(fd, mode)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _runtime_identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _runtime_read_at(root, name):
    parts = _runtime_relative(name).split('/')
    parent = _runtime_subdir(root, '/'.join(parts[:-1])) if len(parts) > 1 else os.dup(root)
    try:
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | RUNTIME_NOFOLLOW, dir_fd=parent)
        try:
            before = os.fstat(fd)
            _runtime_require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= RUNTIME_MAX_FILE,
                    'Nonordinary, hardlinked or oversized input')
            _runtime_require(before.st_uid == os.getuid() and not stat.S_IMODE(before.st_mode) & 0o7022,
                             'Unsafe input ownership or permissions')
            with os.fdopen(os.dup(fd), 'rb') as stream:
                data = stream.read(before.st_size + 1)
            _runtime_require(len(data) == before.st_size and _runtime_identity(before) == _runtime_identity(os.fstat(fd))
                    and _runtime_identity(before) == _runtime_identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)),
                    'Input changed during read')
            return data
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _runtime_read(path, expected=None):
    path = Path(path)
    parent = _runtime_directory(path.parent)
    try:
        data = _runtime_read_at(parent, path.name)
    finally:
        os.close(parent)
    _runtime_require(expected is None or _runtime_sha(data) == expected, 'Input digest mismatch: ' + str(path))
    return data


def _runtime_write_at(root, name, data, mode=0o644):
    parts = _runtime_relative(name).split('/')
    parent = _runtime_subdir(root, '/'.join(parts[:-1]), True) if len(parts) > 1 else os.dup(root)
    try:
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | RUNTIME_NOFOLLOW, mode, dir_fd=parent)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(os.dup(fd), 'wb') as stream:
                _runtime_require(stream.write(data) == len(data), 'Short copy write')
                stream.flush()
            _runtime_require(os.fstat(fd).st_nlink == 1, 'Output hardlink substitution')
        finally:
            os.close(fd)
        _runtime_require(_runtime_read_at(root, name) == data, 'Copy readback mismatch')
    finally:
        os.close(parent)


def _runtime_validate_links(rows):
    table = {r['path']: r for r in rows}
    def resolve(name):
        pending, resolved, seen, expansions = _runtime_relative(name).split('/'), [], set(), 0
        while pending:
            part = pending.pop(0)
            if part in ('', '.'):
                continue
            if part == '..':
                _runtime_require(resolved, 'Link escapes tree root')
                resolved.pop()
                continue
            prefix = '/'.join([*resolved, part])
            _runtime_require(prefix in table, 'Missing link target')
            row = table[prefix]
            if row['type'] == 'symlink':
                state = (prefix, tuple(pending), tuple(resolved))
                expansions += 1
                _runtime_require(state not in seen and expansions <= 64 and not row['link'].startswith('/') and '\\' not in row['link']
                        and '\x00' not in row['link'], 'Escaping/cyclic link')
                seen.add(state)
                _runtime_require(0 < len(row['link']) < 1024, 'Link text limit')
                pending = row['link'].split('/') + pending
            else:
                _runtime_require(not pending or row['type'] == 'dir', 'Nondirectory link ancestor')
                resolved.append(part)
    for row in rows:
        if row['type'] == 'symlink':
            resolve(row['path'])


def _runtime_inventory(root, descriptor=None):
    fd = _runtime_directory(root) if descriptor is None else os.dup(descriptor)
    rows, folded, total = [], set(), 0
    def walk(current, prefix=''):
        nonlocal total
        for name in sorted(os.listdir(current)):
            path = _runtime_relative(prefix + name)
            key = unicodedata.normalize('NFC', path).casefold()
            _runtime_require(key not in folded and len(rows) < RUNTIME_MAX_FILES, 'Duplicate/colliding or excessive tree members')
            folded.add(key)
            info = os.stat(name, dir_fd=current, follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            _runtime_require(info.st_uid == os.getuid(), 'Input member ownership differs')
            _runtime_require(stat.S_ISLNK(info.st_mode) or not mode & 0o7022, 'Unsafe input mode')
            row = {'path': path, 'mode': oct(mode)}
            if stat.S_ISDIR(info.st_mode):
                row.update(type='dir', size=0)
                rows.append(row)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | RUNTIME_NOFOLLOW, dir_fd=current)
                try:
                    _runtime_require(_runtime_identity(info) == _runtime_identity(os.fstat(child)), 'Directory substituted')
                    walk(child, path + '/')
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                data = _runtime_read_at(fd, path)
                total += len(data)
                _runtime_require(total <= RUNTIME_MAX_TOTAL, 'Tree byte limit')
                row.update(type='file', size=len(data), sha256=_runtime_sha(data))
                rows.append(row)
            elif stat.S_ISLNK(info.st_mode):
                text = os.readlink(name, dir_fd=current)
                _runtime_require(0 < len(text) < 1024, 'Link text limit')
                row.update(type='symlink', size=len(os.fsencode(text)), link=text)
                rows.append(row)
            else:
                raise ValueError('Special input member')
        _runtime_require(len(rows) <= RUNTIME_MAX_FILES, 'Tree count limit')
    try:
        walk(fd)
        _runtime_validate_links(rows)
        return sorted(rows, key=lambda row: row['path'])
    finally:
        os.close(fd)


def _runtime_copy_tree(source, rows, target, prefix):
    _runtime_require(_runtime_inventory(source) == sorted(rows, key=lambda r: r['path']), 'Input tree mismatch')
    fd = _runtime_directory(source)
    placed = []
    try:
        for row in rows:
            path = _runtime_relative(prefix + '/' + row['path'])
            if row['type'] == 'dir':
                child = _runtime_subdir(target, path, True)
                os.close(child)
                placed.append(dict(row, path=path, mode='0o755'))
            elif row['type'] == 'file':
                data = _runtime_read_at(fd, row['path'])
                _runtime_require(_runtime_sha(data) == row['sha256'], 'Input file changed')
                _runtime_write_at(target, path, data, 0o755 if int(row['mode'], 8) & 0o111 else 0o644)
                placed.append(dict(row, path=path, mode=oct(0o755 if int(row['mode'], 8) & 0o111 else 0o644)))
        for row in rows:
            if row['type'] == 'symlink':
                parts = (prefix + '/' + row['path']).split('/')
                parent = _runtime_subdir(target, '/'.join(parts[:-1]), True)
                try:
                    os.symlink(row['link'], parts[-1], dir_fd=parent)
                    mode = stat.S_IMODE(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False).st_mode)
                    placed.append(dict(row, path=prefix + '/' + row['path'], mode=oct(mode)))
                finally:
                    os.close(parent)
        _runtime_require(_runtime_inventory(source) == sorted(rows, key=lambda r: r['path']), 'Input changed after copy')
        return placed
    finally:
        os.close(fd)


def _runtime_wheel_members(data, metadata):
    files, folded, total = {}, set(), 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        _runtime_require(len(archive.infolist()) <= RUNTIME_MAX_FILES, 'Wheel count limit')
        for item in archive.infolist():
            path = _runtime_relative(item.filename)
            key = unicodedata.normalize('NFC', path).casefold()
            _runtime_require(key not in folded and not item.is_dir(), 'Duplicate/colliding or directory wheel member')
            folded.add(key)
            mode = item.external_attr >> 16
            # ZIP permission bits are metadata; fresh destination modes are fixed below.
            _runtime_require(stat.S_IFMT(mode) in (0, stat.S_IFREG) and not mode & 0o7000
                    and not item.external_attr & 0x18, 'Unsafe wheel member')
            total += item.file_size
            _runtime_require(item.file_size <= RUNTIME_MAX_FILE and total <= RUNTIME_MAX_TOTAL, 'Wheel byte limit')
            files[path] = archive.read(item)
            _runtime_require(len(files[path]) == item.file_size, 'Wheel member size mismatch')
    distributions = [name[:-len('/METADATA')] for name in files if name.endswith('.dist-info/METADATA')]
    _runtime_require(len(distributions) == 1, 'Exactly one wheel distribution required')
    dist = distributions[0]
    tag = metadata['python_tag']
    config = metadata['python_config_vars']
    _runtime_require(metadata['target_triple'] == 'aarch64-apple-darwin' and config['Py_GIL_DISABLED'] == '0'
            and config['Py_DEBUG'] == '0', 'Unsupported Python build')
    wheel = files[dist + '/WHEEL'].decode()
    tags = [line[5:] for line in wheel.splitlines() if line.startswith('Tag: ')]
    _runtime_require(len(tags) == 1 and tags[0] == tag + '-' + tag + '-macosx_15_0_arm64', 'Pinned wheel ABI/tag mismatch')
    _runtime_require(b'Name: stallionfs\n' in files[dist + '/METADATA'] and b'Version: 0.6.3\n' in files[dist + '/METADATA'], 'Wheel _runtime_identity mismatch')
    _runtime_require(b'stallionfs-python = stallionfs.__main__:main' in files[dist + '/entry_points.txt'], 'Wheel entry point mismatch')
    record_path = dist + '/RECORD'
    record = list(csv.reader(io.StringIO(files[record_path].decode())))
    _runtime_require(len(record) == len(files), 'Incomplete RECORD')
    seen = set()
    for row in record:
        _runtime_require(len(row) == 3 and row[0] in files and row[0] not in seen, 'Invalid/duplicate RECORD member')
        seen.add(row[0])
        expected = 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(files[row[0]]).digest()).rstrip(b'=').decode()
        _runtime_require(row[1:] == (['', ''] if row[0] == record_path else [expected, str(len(files[row[0]]))]), 'RECORD hash/size mismatch')
    scripts = dist[:-len('.dist-info')] + '.data/scripts/'
    _runtime_require({scripts + 'sfs', scripts + 'stallionfs'} <= files.keys(), 'Wheel native launchers missing')
    _runtime_require(all(not name.startswith(dist[:-len('.dist-info')] + '.data/') or name in (scripts + 'sfs', scripts + 'stallionfs') for name in files), 'Unsupported wheel data mapping')
    _runtime_require(all(name.startswith('stallionfs/') or name.startswith(dist + '/')
                         or name in (scripts + 'sfs', scripts + 'stallionfs') for name in files),
                     'Unsupported wheel import root')
    extensions = ['stallionfs/' + name + config['EXT_SUFFIX'] for name in ('_scan', '_image')]
    _runtime_require(set(extensions) <= files.keys(), 'Matching native extension suffixes missing')
    return files, scripts, extensions, tags[0]



def _runtime_pinned(item, pins):
    _runtime_require(isinstance(item, dict) and set(item) == {'path', 'sha256'}
                     and isinstance(item['path'], str) and Path(item['path']).is_absolute()
                     and isinstance(item['sha256'], str) and re.fullmatch('[0-9a-f]{64}', item['sha256']),
                     'Expected an absolute pinned input')
    data = _runtime_read(item['path'], item['sha256'])
    _runtime_require(item['path'] not in pins or pins[item['path']] == item['sha256'], 'Conflicting input pin')
    pins[item['path']] = item['sha256']
    return data


def _runtime_mapping(item, pins):
    _runtime_require(isinstance(item, dict) and set(item) == {'path', 'sha256', 'destination'},
                     'Invalid license or source mapping')
    name = _runtime_relative(item['destination'])
    data = _runtime_pinned({key: item[key] for key in ('path', 'sha256')}, pins)
    return name, data


def _runtime_expected_resources(setup_bytes):
    _runtime_require(len(setup_bytes) <= 65536, 'Setup resource declaration exceeds its limit')
    values = {}
    for statement in ast.parse(setup_bytes).body:
        if not isinstance(statement, ast.Assign):
            continue
        targets = [target.id for target in statement.targets if isinstance(target, ast.Name)
                   and target.id in ('BENCHMARK_MODULES', 'BENCHMARK_FIXTURES')]
        if targets:
            _runtime_require(len(statement.targets) == len(targets) == 1 and targets[0] not in values,
                             'Ambiguous benchmark resource declaration')
            value = ast.literal_eval(statement.value)
            _runtime_require(isinstance(value, tuple) and value and all(isinstance(name, str)
                             and _runtime_relative(name) == name and '/' not in name for name in value)
                             and len(value) == len(set(value)), 'Invalid benchmark resource declaration')
            values[targets[0]] = value
    _runtime_require(set(values) == {'BENCHMARK_MODULES', 'BENCHMARK_FIXTURES'}, 'Missing benchmark resource declaration')
    return {**{name: 'tests/perf/' + name for name in values['BENCHMARK_MODULES']},
            **{'fixture/' + name: 'tests/perf/fixture/' + name for name in values['BENCHMARK_FIXTURES']}}


def _prepare_runtime(path, output):
    pins = {}
    parent = _runtime_directory(output.parent)
    try:
        _runtime_require(stat.S_IMODE(os.fstat(parent).st_mode) == 0o700, 'Runtime output parent must be private 0700')
    finally:
        os.close(parent)
    descriptor_data = _runtime_read(path)
    _runtime_require(len(descriptor_data) <= 65536, 'Runtime input descriptor exceeds its limit')
    pins[str(path)] = _runtime_sha(descriptor_data)
    value = json.loads(descriptor_data)
    _runtime_require(isinstance(value, dict) and set(value) == {
        'schema', 'python_descriptor', 'git', 'wheel', 'licenses', 'sources'}
        and type(value['schema']) is int and value['schema'] == 1, 'Unsupported runtime input descriptor')
    python = json.loads(_runtime_pinned(value['python_descriptor'], pins))
    _runtime_require(python['python_exe'] == 'bin/python3.13', 'Unsupported runtime interpreter path')
    checked = {}
    for name in ('python_archive', 'full_archive', 'python_inventory', 'metadata', 'static_receipt', 'license_records'):
        path_key = 'metadata_file' if name == 'metadata' else name
        checked[name] = _runtime_pinned({'path': python[path_key], 'sha256': python[name + '_sha256']}, pins)
    metadata = json.loads(checked['metadata'])
    config = metadata['python_config_vars']
    _runtime_require(metadata['python_version'] == '3.13.18' and metadata['python_tag'] == 'cp313'
                     and config['SOABI'] == 'cpython-313-darwin'
                     and config['EXT_SUFFIX'] == '.cpython-313-darwin.so', 'Unsupported runtime Python ABI')
    python_rows = json.loads(checked['python_inventory'])
    _runtime_require(_runtime_inventory(python['python_root']) == python_rows, 'Python inventory differs')
    _runtime_require({'bin/python3.13', 'lib/python3.13', 'lib/python3.13/lib-dynload',
                      'lib/python3.13/encodings/__init__.py'} <= {row['path'] for row in python_rows},
                     'Python runtime support is incomplete')
    git = value['git']
    _runtime_require(isinstance(git, dict) and set(git) == {'root', 'inventory', 'qualification'},
                     'Invalid private Git input')
    git_rows = json.loads(_runtime_pinned(git['inventory'], pins))
    qualification = json.loads(_runtime_pinned(git['qualification'], pins))
    _runtime_require(isinstance(qualification, dict) and type(qualification.get('schema')) is int
                     and qualification['schema'] == 1
                     and qualification.get('inventory_sha256') == git['inventory']['sha256']
                     and qualification.get('static_closure_accepted') is True
                     and qualification.get('local_correctness_passed') is True,
                     'Private Git qualification is incomplete')
    _runtime_require(_runtime_inventory(git['root']) == git_rows, 'Private Git inventory differs')
    _runtime_require({'bin/git', 'libexec/git-core', 'share/git-core/templates'}
                     <= {row['path'] for row in git_rows}, 'Private Git support is incomplete')
    files, scripts, extensions, tag = _runtime_wheel_members(_runtime_pinned(value['wheel'], pins), metadata)
    provenance = json.loads(files['stallionfs/_benchmark_runtime/manifest.json'])
    _runtime_require(provenance.get('kind') == 'build-source provenance'
                     and isinstance(provenance.get('build_source_sha256'), dict), 'Wheel source provenance is missing')
    source = Path(__file__).resolve().parents[1]
    build_sources = provenance['build_source_sha256']
    source_names = {'setup.py', 'pyproject.toml', *(path.relative_to(source).as_posix()
                    for path in (source / 'stallionfs').iterdir()
                    if path.is_file() and path.suffix in ('.py', '.c', '.h'))}
    _runtime_require(set(build_sources) == source_names, 'Wheel lacks the current bundled source')
    for name, digest in build_sources.items():
        _runtime_relative(name)
        _runtime_require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'Invalid wheel source digest')
        data = _runtime_pinned({'path': str(source / name), 'sha256': digest}, pins)
        if name.startswith('stallionfs/') and name.endswith('.py'):
            _runtime_require(name in files, 'Wheel package source is missing: ' + name)
        if name in files:
            _runtime_require(files[name] == data, 'Wheel source differs: ' + name)
    resources = _runtime_expected_resources(_runtime_read(source / 'setup.py', build_sources['setup.py']))
    _runtime_require(isinstance(provenance.get('resources'), dict) and set(provenance['resources']) == set(resources),
                     'Wheel benchmark resource set differs')
    resource_members = {'stallionfs/_benchmark_runtime/' + name for name in resources}
    resource_members.add('stallionfs/_benchmark_runtime/manifest.json')
    allowed_package = {name for name in build_sources if name.startswith('stallionfs/')} | set(extensions) | resource_members
    _runtime_require({name for name in files if name.startswith('stallionfs/')} <= allowed_package,
                     'Wheel contains unlisted package members')
    for name, input_name in resources.items():
        member = 'stallionfs/_benchmark_runtime/' + name
        _runtime_require(member in files, 'Wheel benchmark resource is missing: ' + name)
        data = _runtime_pinned({'path': str(source / input_name), 'sha256': provenance['resources'][name]}, pins)
        _runtime_require(files[member] == data, 'Wheel benchmark resource differs: ' + name)
    licenses = []
    python_licenses = json.loads(checked['license_records'])['licenses']
    _runtime_require(isinstance(python_licenses, list) and python_licenses, 'Python license records are required')
    for row in python_licenses:
        data = _runtime_pinned({'path': str(Path(python['license_root']).parent / row['path']),
                                'sha256': row['sha256']}, pins)
        _runtime_require(len(data) == row['size'], 'Python license size differs')
        licenses.append(('CPython/' + Path(row['path']).name, data))
    _runtime_require(isinstance(value['licenses'], list) and isinstance(value['sources'], list),
                     'License/source mapping must be explicit')
    licenses += [_runtime_mapping(item, pins) for item in value['licenses']]
    sources = [_runtime_mapping(item, pins) for item in value['sources']]
    _runtime_require(any(name == 'Git/COPYING' for name, _ in licenses)
                     and len(sources) >= 2 and all(name.startswith('Git/') for name, _ in sources),
                     'Git license and complete source/build sidecar inputs are required')
    for mappings in (licenses, sources):
        names = [unicodedata.normalize('NFC', name).casefold() for name, _ in mappings]
        _runtime_require(len(names) == len(set(names)), 'Duplicate license/source destination')
    sidecar = output.with_name(output.name + '.sources')
    _runtime_require(not os.path.lexists(sidecar), 'Source sidecar must be fresh')
    roots = [Path(python['python_root']), Path(git['root'])]
    for root in roots:
        _runtime_require(root.is_absolute() and root.resolve(strict=True) == root
                         and not output.is_relative_to(root) and not root.is_relative_to(output)
                         and not sidecar.is_relative_to(root) and not root.is_relative_to(sidecar),
                         'Runtime input/output overlap or alias')
    _runtime_require(all(not Path(name).is_relative_to(output) and not Path(name).is_relative_to(sidecar)
                         for name in pins), 'Pinned file overlaps output')
    # Retain the existing inspection-tool contract; no supplied executable is launched.
    with tempfile.TemporaryDirectory(prefix='stallionfs-wheel-', dir=output.parent) as temporary:
        directory = Path(temporary)
        observations = []
        for index, name in enumerate([scripts + 'sfs', scripts + 'stallionfs', *extensions]):
            executable = directory / ('wheel-' + str(index))
            write_new(executable, files[name], 0o700)
            _runtime_require(_architectures(executable, directory) == ['arm64'], 'Wheel must be arm64')
            target = _deployment_target(_tool_output(['/usr/bin/otool', '-arch', 'arm64', '-l', str(executable)], directory), 'arm64')
            _runtime_require(_version(target['minimum_os']) <= _version('27.0'), 'Wheel exceeds the app minimum')
            if name in extensions:
                symbols = _tool_output(['/usr/bin/nm', '-arch', 'arm64', '-g', '-U', '-j', str(executable)], directory)
                _runtime_require('_PyInit_' + Path(name).name.split('.')[0] in symbols.splitlines(), 'Wheel initializer differs')
            _runtime_require(read_executable(executable) == files[name], 'Wheel changed during inspection')
            observations.append({'member': name, 'sha256': _runtime_sha(files[name]), 'target': target})
    return {'pins': pins, 'python': python, 'python_rows': python_rows, 'git': git, 'git_rows': git_rows,
            'files': files, 'scripts': scripts, 'licenses': licenses, 'sources': sources,
            'sidecar': sidecar, 'wheel_tag': tag, 'wheel_observations': observations,
            'source_build_id': _runtime_sha(json.dumps(build_sources, sort_keys=True, separators=(',', ':')).encode())}


def _runtime_file_row(name, data, mode=0o644):
    return {'path': name, 'type': 'file', 'size': len(data), 'sha256': _runtime_sha(data), 'mode': oct(mode)}


def _runtime_verify_layout(actual, expected):
    table = {}
    for row in expected:
        _runtime_require(row['path'] not in table, 'Duplicate destination mapping')
        table[row['path']] = row
    for name in list(table):
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.':
                row = {'path': str(parent), 'type': 'dir', 'size': 0, 'mode': '0o755'}
                _runtime_require(str(parent) not in table or table[str(parent)] == row, 'Conflicting destination parent')
                table[str(parent)] = row
    _runtime_require(actual == sorted(table.values(), key=lambda row: row['path']), 'Final runtime mapping changed')


def _stage_runtime(output, prepared, bundle_version):
    parent = _runtime_directory(output.parent)
    app = _runtime_subdir(parent, output.name)
    original = _runtime_identity(os.fstat(app))
    try:
        for name in ('Contents', 'Contents/MacOS', 'Contents/Extensions', 'Contents/Extensions/StallionFS.appex',
                     'Contents/Extensions/StallionFS.appex/Contents', 'Contents/Extensions/StallionFS.appex/Contents/MacOS'):
            fd = _runtime_subdir(app, name)
            os.fchmod(fd, 0o755)
            os.close(fd)
        expected = _runtime_inventory(output, app)
        expected += _runtime_copy_tree(prepared['python']['python_root'], prepared['python_rows'], app, 'Contents/Resources/Runtime/CPython')
        expected += _runtime_copy_tree(prepared['git']['root'], prepared['git_rows'], app, 'Contents/Resources/Runtime/Git')
        site = 'Contents/Resources/Runtime/CLI/lib/python3.13/site-packages/'
        for name, data in prepared['files'].items():
            script = name.startswith(prepared['scripts'])
            target = 'Contents/Resources/Runtime/CLI/bin/' + name[len(prepared['scripts']):] if script else site + name
            _runtime_write_at(app, target, data, 0o755 if script else 0o644)
            expected.append(_runtime_file_row(target, data, 0o755 if script else 0o644))
        template = Path(__file__).resolve().parents[1] / 'filesystem/fskit/stallionfs-python.sh'
        helper = _runtime_read(template)
        prepared['pins'][str(template)] = _runtime_sha(helper)
        _runtime_write_at(app, 'Contents/Resources/Runtime/CLI/bin/stallionfs-python', helper, 0o755)
        expected.append(_runtime_file_row('Contents/Resources/Runtime/CLI/bin/stallionfs-python', helper, 0o755))
        paths = {'python': 'Contents/Resources/Runtime/CPython/bin/python3.13',
                 'site_packages': site.rstrip('/'), 'helper': 'Contents/Resources/Runtime/CLI/bin/stallionfs-python',
                 'git': 'Contents/Resources/Runtime/Git/bin/git',
                 'git_exec_path': 'Contents/Resources/Runtime/Git/libexec/git-core',
                 'git_template_dir': 'Contents/Resources/Runtime/Git/share/git-core/templates'}
        descriptor = {'schema': 1, 'python_version': '3.13.18', 'soabi': 'cpython-313-darwin',
                      'package_version': '0.6.3', 'source_build_id': prepared['source_build_id'],
                      'bundle_version': bundle_version, 'paths': paths}
        descriptor_data = (json.dumps(descriptor, sort_keys=True, indent=2) + '\n').encode()
        _runtime_write_at(app, 'Contents/Resources/Runtime/runtime.json', descriptor_data)
        expected.append(_runtime_file_row('Contents/Resources/Runtime/runtime.json', descriptor_data))
        for name, data in prepared['licenses']:
            _runtime_write_at(app, 'Contents/Resources/Licenses/' + name, data)
            expected.append(_runtime_file_row('Contents/Resources/Licenses/' + name, data))
        os.mkdir(prepared['sidecar'].name, 0o700, dir_fd=parent)
        sidecar = _runtime_subdir(parent, prepared['sidecar'].name)
        try:
            for name, data in prepared['sources']:
                _runtime_write_at(sidecar, name, data)
            source_rows = _runtime_inventory(prepared['sidecar'], sidecar)
            _runtime_verify_layout(source_rows, [_runtime_file_row(name, data) for name, data in prepared['sources']])
            _runtime_require((os.fstat(sidecar).st_dev, os.fstat(sidecar).st_ino)
                             == (os.stat(prepared['sidecar'].name, dir_fd=parent, follow_symlinks=False).st_dev,
                                 os.stat(prepared['sidecar'].name, dir_fd=parent, follow_symlinks=False).st_ino),
                             'Source sidecar substituted')
        finally:
            os.close(sidecar)
        for path, digest in prepared['pins'].items():
            _runtime_read(path, digest)
        _runtime_require(_runtime_inventory(prepared['python']['python_root']) == prepared['python_rows']
                         and _runtime_inventory(prepared['git']['root']) == prepared['git_rows'], 'Runtime input changed')
        _runtime_require((os.fstat(app).st_dev, os.fstat(app).st_ino) == original[:2]
                         == (os.stat(output.name, dir_fd=parent, follow_symlinks=False).st_dev,
                             os.stat(output.name, dir_fd=parent, follow_symlinks=False).st_ino), 'App directory substituted')
        os.fchmod(app, 0o755)
        rows = _runtime_inventory(output, app)
        _runtime_verify_layout(rows, expected)
        return {'kind': 'self-contained-runtime-payload', 'complete_candidate': False,
                'distribution_signing_performed': False, 'source_build_id': prepared['source_build_id'],
                'wheel_tag': prepared['wheel_tag'], 'wheel_observations': prepared['wheel_observations'],
                'input_file_sha256': sorted(prepared['pins'].values()), 'inventory': rows,
                'licenses': [{'path': name, 'sha256': _runtime_sha(data)} for name, data in prepared['licenses']],
                'source_sidecar': {'path': prepared['sidecar'].name, 'inventory': source_rows}}
    finally:
        os.close(app)
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, type=Path)
    parser.add_argument('--extension', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path, help='Fresh .app path; never an installed app')
    parser.add_argument('--manifest-out', type=Path, help='Fresh external sibling .json candidate receipt')
    parser.add_argument('--runtime-inputs', type=Path, help='Pinned private runtime, wheel, Git and license/source inputs')
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
    if args.runtime_inputs is not None and location is None:
        parser.error('--runtime-inputs requires --manifest-out')
    host, extension = read_executable(args.host), read_executable(args.extension)
    values = _load_templates()
    factory, targets = inspect_package_artifacts(host, extension,
        values[0].get('LSMinimumSystemVersion'), values[1].get('LSMinimumSystemVersion'), args.access_policy)
    runtime = _prepare_runtime(args.runtime_inputs.absolute(), output) if args.runtime_inputs is not None else None
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
        runtime_manifest = _stage_runtime(output, runtime, args.bundle_version) if runtime is not None else None
        if reservation is not None:
            manifest = _candidate_manifest(args, values, targets, factory, files, output)
            if runtime_manifest is not None:
                manifest['runtime'] = runtime_manifest
            _write_manifest(*reservation, location, manifest)
    finally:
        if reservation is not None:
            os.close(reservation[1])
            os.close(reservation[0])
    print('Unsigned package: ' + str(output))


if __name__ == '__main__':
    main()
