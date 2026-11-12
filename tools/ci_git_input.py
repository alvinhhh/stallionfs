"""Exact installed-wheel and native-input admission for controlled CI fixtures.

This supplies no signed app or Host authority. The actual input descriptor and
source map supply hashes for the existing explicitly controlled verifier seam.
"""
import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys
import sysconfig
import zipfile

_state = None


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


class _Bindings:
    """Retain the first identities observed around each validation read."""
    def __init__(self, bundle):
        self.bundle = bundle
        self.reader = None
        self.identities = {}
        self.origins = {}
        self.trees = {}

    def _path(self, path):
        path = Path(path).absolute()
        self.bundle.require('..' not in path.parts, 'CI binding path is not physical')
        return path

    def bind(self, path):
        path = self._path(path)
        for parent in path.parents:
            info = parent.lstat()
            self.bundle.require(stat.S_ISDIR(info.st_mode), 'CI origin directory changed')
            # Unrelated siblings may change; directory inode/owner/mode may not.
            origin = self.bundle._identity(info)[:5]
            self.bundle.require(self.origins.setdefault(parent, origin) == origin, 'CI origin directory changed')
        identity = self.bundle._identity(path.lstat())
        self.bundle.require(self.identities.setdefault(path, identity) == identity, 'CI validation identity changed')
        return identity

    def read(self, path, expected=None):
        path = self._path(path)
        before = self.bind(path)
        data = self.reader(path, expected)
        self.bundle.require(self.bundle._identity(path.lstat()) == before, 'CI input changed during validation')
        self.bind(path)
        return data

    def _members(self, root, remember):
        found = {root}
        def walk(directory, depth):
            self.bundle.require(depth <= 32, 'CI tree depth limit')
            info = directory.lstat()
            self.bundle.require(stat.S_ISDIR(info.st_mode), 'CI tree directory changed')
            if remember:
                self.bind(directory)
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = directory / entry.name
                    found.add(path)
                    self.bundle.require(len(found) <= 4097, 'CI tree member limit')
                    info = path.lstat()
                    self.bundle.require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'CI tree member is not ordinary')
                    if remember:
                        self.bind(path)
                    if stat.S_ISDIR(info.st_mode):
                        walk(path, depth + 1)
        walk(root, 0)
        return frozenset(found)

    def tree(self, root):
        root = self._path(root)
        members = self._members(root, True)
        self.bundle.require(self.trees.setdefault(root, members) == members, 'CI tree namespace changed')
        self.check()

    def check(self):
        self.bundle.require(all(stat.S_ISDIR(path.lstat().st_mode)
                                and self.bundle._identity(path.lstat())[:5] == expected
                                for path, expected in self.origins.items()), 'CI origin directory changed')
        self.bundle.require(all(self.bundle._identity(path.lstat()) == expected
                                for path, expected in self.identities.items()), 'CI validated input changed')
        self.bundle.require(all(self._members(root, False) == expected for root, expected in self.trees.items()),
                            'CI tree namespace changed')

    def payload(self, root, payload):
        root = self._path(root)
        self.check()
        self.bundle.require(payload['root_identity'] == self.identities[root], 'Native inventory root changed')
        paths = {root / name: identity for name, identity in payload['identities'].items()}
        self.bundle.require(set(paths) == self.trees[root] - {root}
                            and all(self.identities[path] == identity for path, identity in paths.items()),
                            'Native inventory changed before payload hashing')


def _wheel_files(archive):
    members = archive.infolist()
    if len(members) > 4096 or len({m.filename for m in members}) != len(members):
        raise ValueError('Wheel member set differs')
    declared = 0
    for member in members:
        relative = PurePosixPath(member.filename)
        mode = member.external_attr >> 16
        if (relative.is_absolute() or '..' in relative.parts or member.is_dir()
                or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
                or type(member.file_size) is not int or not 0 <= member.file_size <= 64 * 1024 ** 2):
            raise ValueError('Unsafe wheel member')
        declared += member.file_size
        if declared > 128 * 1024 ** 2:
            raise ValueError('Wheel byte limit')
    files, modes, total = {}, {}, 0
    for member in members:
        data = bytearray()
        with archive.open(member) as stream:
            while True:
                request = min(65536, member.file_size - len(data) + 1, 128 * 1024 ** 2 - total - len(data) + 1)
                block = stream.read(request)
                if not block:
                    break
                if (len(block) > request or len(data) + len(block) > member.file_size
                        or total + len(data) + len(block) > 128 * 1024 ** 2):
                    raise ValueError('Wheel streamed byte limit')
                data.extend(block)
        if len(data) != member.file_size:
            raise ValueError('Wheel member size differs')
        total += len(data)
        files[member.filename] = bytes(data)
        modes[member.filename] = oct(stat.S_IMODE(member.external_attr >> 16))
    return files, modes


def initialize(checkout, wheel, wheel_sha256, descriptor, descriptor_sha256, *, source_pins, source_pins_sha256):
    """Admit before importing tests; every expected digest is caller-pinned."""
    global _state
    if _state is not None:
        raise RuntimeError('Qualified Git input was already initialized')
    if not sys.flags.isolated or not sys.dont_write_bytecode:
        raise RuntimeError('CI admission requires isolated Python with bytecode disabled')
    checkout = Path(checkout).resolve(strict=True)
    wheel = Path(wheel).absolute(); descriptor = Path(descriptor).absolute()
    source_pins = Path(source_pins).absolute()
    for digest in (wheel_sha256, descriptor_sha256, source_pins_sha256):
        if not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('Expected a pinned SHA256')
    from stallionfs import _bundle, _git_runtime
    import stallionfs
    package_root = Path(stallionfs.__file__).resolve(strict=True).parent
    if package_root.is_relative_to(checkout):
        raise ValueError('CI admission requires an installed wheel outside checkout')
    retained = _Bindings(_bundle)
    retained.bind(Path(__file__).absolute())
    retained.bind(checkout / 'tools/package_fskit.py')
    retained.tree(package_root)
    package = _module('_ci_native_input_reader', checkout / 'tools/package_fskit.py')
    retained.check()
    retained.reader = package._runtime_read
    package._runtime_read = retained.read
    descriptor_bytes = package._runtime_read(descriptor, descriptor_sha256)
    git = json.loads(descriptor_bytes)
    pins = {str(descriptor): descriptor_sha256}
    package._runtime_require(isinstance(git, dict) and set(git) == {'root', 'inventory', 'qualification'}, 'Invalid private Git input')
    native = Path(git['root']).absolute()
    retained.tree(native)
    admitted = package._runtime_admit_git(git, pins, architecture=platform.machine())
    retained.check()
    package._runtime_require(admitted['root'].resolve(strict=True) == native, 'Native input path changed')
    configured = os.environ.get('STALLIONFS_TEST_QUALIFIED_GIT')
    if configured is not None and Path(configured).resolve(strict=True) != native / 'bin/git':
        raise ValueError('Configured fixture executable differs from admitted input')
    archive_bytes = package._runtime_read(wheel, wheel_sha256)
    match = re.fullmatch(r'stallionfs-([0-9]+(?:\.[0-9]+){2})-(cp[0-9]+)-(cp[0-9]+)-(macosx_[0-9]+_[0-9]+_(arm64|x86_64))\.whl', wheel.name)
    if match is None:
        raise ValueError('Expected one ordinary macOS stallionfs wheel')
    version, python_tag, abi, platform_tag, architecture = match.groups()
    expected_python = 'cp' + str(sys.version_info.major) + str(sys.version_info.minor)
    if python_tag != expected_python or abi != expected_python or architecture != platform.machine():
        raise ValueError('Wheel interpreter or architecture differs')
    floor = tuple(map(int, platform_tag.removeprefix('macosx_').removesuffix('_' + architecture).split('_'))) + (0,)
    host_version = tuple(map(int, platform.mac_ver()[0].split('.'))) if sys.platform == 'darwin' else ()
    host_version = host_version + (0,) * (3 - len(host_version))
    if sys.platform != 'darwin' or host_version < floor:
        raise ValueError('Wheel deployment target exceeds the current host')
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        files, modes = _wheel_files(archive)
    dist = 'stallionfs-' + version + '.dist-info/'
    record = dist + 'RECORD'
    records = list(csv.reader(io.StringIO(files[record].decode())))
    if len(records) != len(files) or {r[0] for r in records} != set(files):
        raise ValueError('Wheel RECORD membership differs')
    for name, digest, size in records:
        if name == record:
            if digest or size:
                raise ValueError('Unexpected RECORD self-hash')
        elif (size != str(len(files[name])) or digest != 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).rstrip(b'=').decode()):
            raise ValueError('Wheel RECORD digest differs')
    expected_tag = python_tag + '-' + abi + '-' + platform_tag
    if {line[5:] for line in files[dist + 'WHEEL'].decode().splitlines() if line.startswith('Tag: ')} != {expected_tag}:
        raise ValueError('Wheel tag metadata differs')
    provenance_name = 'stallionfs/_benchmark_runtime/manifest.json'
    provenance = json.loads(files[provenance_name])
    sources = {f.relative_to(checkout).as_posix() for f in (checkout / 'stallionfs').iterdir()
               if f.is_file() and f.suffix in ('.py', '.c', '.h')}
    build_names = sources | {'setup.py', 'pyproject.toml', 'tools/build_git_runtime.py', 'tools/_git_capture.py'}
    build_names |= {'tools/git-inputs/' + name for name in ('alias.c', 'combined.patch', 'notices.patch', 'config.mak', 'header-manifest.json')}
    if set(provenance['build_source_sha256']) != build_names:
        raise ValueError('Current build source set differs')
    for name, digest in provenance['build_source_sha256'].items():
        data = package._runtime_read(checkout / name, digest)
        if name in sources and files.get(name) != data:
            raise ValueError('Wheel source bytes differ')
    resources = package._runtime_expected_resources(package._runtime_read(checkout / 'setup.py', provenance['build_source_sha256']['setup.py']))
    if set(resources) != set(provenance['resources']):
        raise ValueError('Wheel resource set differs')
    for name, source in resources.items():
        data = package._runtime_read(checkout / source, provenance['resources'][name])
        if files['stallionfs/_benchmark_runtime/' + name] != data:
            raise ValueError('Wheel resource bytes differ')
    # The producer's full input receipt also covers engine C/header inputs that
    # the wheel's existing declared source map does not contain.
    full_source_rows = json.loads(package._runtime_read(source_pins, source_pins_sha256))
    required_sources = build_names | set(resources.values()) | {'README.md', 'LICENSE', 'filesystem/image.c', 'filesystem/image.h'}
    if (not isinstance(full_source_rows, list) or len(full_source_rows) != len(required_sources)
            or any(not isinstance(row, dict) or set(row) != {'path', 'mode', 'bytes', 'sha256'} for row in full_source_rows)
            or {row['path'] for row in full_source_rows} != required_sources):
        raise ValueError('Complete producer source input set differs')
    for row in full_source_rows:
        relative = package._runtime_relative(row['path'])
        path = checkout / relative
        data = package._runtime_read(path, row['sha256'])
        if len(data) != row['bytes'] or oct(stat.S_IMODE(path.stat().st_mode)) != row['mode']:
            raise ValueError('Producer source bytes or mode differ')
    git_members = package._runtime_package_git(files)
    prefix = 'stallionfs/_git/'
    manifest = json.loads(files[prefix + 'manifest.json'])
    bindings = {'recipe_sha256': 'tools/build_git_runtime.py', 'capture_sha256': 'tools/_git_capture.py',
                'registry_sha256': 'stallionfs/_git_sources.py', 'bundle_sha256': 'stallionfs/_bundle.py'}
    if manifest['build']['architecture'] != architecture:
        raise ValueError('Git architecture differs')
    for field, name in bindings.items():
        if manifest['build'][field] != provenance['build_source_sha256'][name]:
            raise ValueError('Git build source differs from current source')
    for row in manifest['files']:
        if modes[prefix + row['path']] != row['mode']:
            raise ValueError('Git archived mode differs')
    assets = {name[len(prefix):]: files[name] for name in git_members
              if name[len(prefix):].startswith('sources/') or name[len(prefix):] in ('COPYING', 'CURL-COPYING', 'SOURCES.txt')}
    package._runtime_git_sources([('Git/' + n, d) for n, d in assets.items()],
                                [('Git/' + n, assets[n]) for n in ('COPYING', 'CURL-COPYING')],
                                admitted['contract'], provenance['build_source_sha256'], assets)
    extensions = {'stallionfs/_scan' + sysconfig.get_config_var('EXT_SUFFIX'), 'stallionfs/_image' + sysconfig.get_config_var('EXT_SUFFIX')}
    scripts_prefix = 'stallionfs-' + version + '.data/scripts/'
    metadata_names = {dist + n for n in ('licenses/LICENSE', 'METADATA', 'WHEEL', 'entry_points.txt', 'top_level.txt', 'RECORD')}
    expected = sources | extensions | git_members | metadata_names | {scripts_prefix + 'sfs', scripts_prefix + 'stallionfs', provenance_name}
    expected |= {'stallionfs/_benchmark_runtime/' + n for n in resources}
    if set(files) != expected or files[dist + 'licenses/LICENSE'] != package._runtime_read(checkout / 'LICENSE'):
        raise ValueError('Wheel finite member or license set differs')
    scripts_directory = Path(sysconfig.get_path('scripts'))
    for name in ('sfs', 'stallionfs'):
        path = scripts_directory / name
        if package._runtime_read(path) != files[scripts_prefix + name] or not os.access(path, os.X_OK):
            raise ValueError('Installed native launcher differs')
    installed_members = set()
    for name, data in files.items():
        if name.startswith('stallionfs/'):
            path = package_root.parent / name
            if (package._runtime_read(path) != data or oct(stat.S_IMODE(path.stat().st_mode)) != modes[name]):
                raise ValueError('Installed wheel member differs')
            installed_members.add(name)
    actual = {'stallionfs/' + path.relative_to(package_root).as_posix() for path in package_root.rglob('*') if path.is_file()}
    if actual != installed_members:
        raise ValueError('Installed package member set differs')
    from stallionfs import _scan, _image
    for module, name in ((_scan, 'stallionfs/_scan' + sysconfig.get_config_var('EXT_SUFFIX')),
                         (_image, 'stallionfs/_image' + sysconfig.get_config_var('EXT_SUFFIX'))):
        if Path(module.__file__).resolve(strict=True) != package_root.parent / name:
            raise ValueError('Native extension origin differs')
    native_rows = admitted['inventory']
    ordinary_rows = package._runtime_inventory(package_root / '_git')
    native_names = {row['path'] for row in native_rows}
    if [row for row in ordinary_rows if row['path'] in native_names] != native_rows:
        raise ValueError('Installed Git native projection differs')
    retained.check()
    builder = _module('_ci_git_macho_reader', checkout / 'tools/build_git_runtime.py')
    retained.check()
    installed_native_paths = [Path(_scan.__file__), Path(_image.__file__),
                              scripts_directory / 'sfs', scripts_directory / 'stallionfs']
    for path in installed_native_paths:
        slices = builder.macho(path)
        if len(slices) != 1 or any(
                value['architecture'] != architecture or tuple(value['minimum']) > floor or value['rpaths']
                or not all(name.startswith(('/usr/lib/', '/System/Library/Frameworks/')) for name in value['dependencies'])
                for value in slices):
            raise ValueError('Installed native architecture, deployment or dependency differs')
    for row in native_rows:
        if row['type'] != 'file':
            continue
        for slice in builder.macho(native / row['path']):
            if (slice['architecture'] != architecture or tuple(slice['minimum']) > floor or slice['rpaths']
                    or not all(name.startswith(('/usr/lib/', '/System/Library/Frameworks/')) for name in slice['dependencies'])):
                raise ValueError('Native Git architecture, deployment or dependency differs')
    retained.check()
    payload = _bundle.git_payload(native)
    retained.payload(native, payload)
    product = _git_runtime.regular_payload(package_root / '_git')
    retained.check()
    contract = {**admitted['contract'], 'payload_entries': payload['entries'], 'payload_sha256': payload['sha256'],
                'executable_sha256': payload['executable_sha256'], 'descriptor_sha256': descriptor_sha256,
                'source_build_id': _sha(json.dumps(provenance['build_source_sha256'], sort_keys=True, separators=(',', ':')).encode()),
                'publisher': _bundle.PUBLISHER_TEAM}

    def check():
        fd = _bundle._directory(native)
        try:
            _bundle.require(_bundle._identity(os.fstat(fd)) == payload['root_identity'], 'Native Git root changed')
        finally:
            os.close(fd)
        _bundle.require(all(_bundle._identity((native / name).lstat()) == value for name, value in payload['identities'].items()), 'Native Git member changed')
        retained.check()
        product['check']()

    check()
    _state = {'native': native, 'contract': contract, 'check': check}
    try:
        os.environ['STALLIONFS_TEST_QUALIFIED_GIT'] = str(native / 'bin/git')
        return runtime()
    except BaseException:
        _state = None
        if configured is None:
            os.environ.pop('STALLIONFS_TEST_QUALIFIED_GIT', None)
        else:
            os.environ['STALLIONFS_TEST_QUALIFIED_GIT'] = configured
        raise


def runtime():
    if _state is None:
        raise RuntimeError('Qualified Git input must be initialized before test discovery')
    state = _state
    configured = os.environ.get('STALLIONFS_TEST_QUALIFIED_GIT')
    if configured is not None and Path(configured).resolve(strict=True) != state['native'] / 'bin/git':
        raise ValueError('External fixture executable refused')
    value = {'executable': str(state['native'] / 'bin/git'),
             'exec_path': str(state['native'] / 'libexec/git-core'), 'contract': dict(state['contract'])}
    def check():
        if (value['executable'] != str(state['native'] / 'bin/git')
                or value['exec_path'] != str(state['native'] / 'libexec/git-core')
                or value['contract'] != state['contract']):
            raise ValueError('Fixture runtime changed')
        state['check']()
    value['check'] = check
    check()
    return value
