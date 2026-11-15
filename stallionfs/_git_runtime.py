"""Internal Git routing without changing ordinary user defaults."""
import errno
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import tarfile

from . import _bundle, _git_sources

BRIDGES = ('GIT_STALLIONFS_ATTR_SYSTEM', 'GIT_STALLIONFS_CONFIG_PROVIDER', 'GIT_STALLIONFS_ATTR_PROVIDER')
LEGACY_USAGE = ("error: unknown subcommand: `list'\n"
                'usage: git hook run [--ignore-missing] [--to-stdin=<path>] <hook-name> [-- <hook-args>]\n\n')
LEGACY_SHORT = 'usage: git hook run [--ignore-missing] <hook-name> [-- <hook-args>]\n\n'
LEGACY_DIAGNOSTICS = (LEGACY_USAGE.encode(), LEGACY_SHORT.encode(),
                      ("error: unknown subcommand: `list'\n" + LEGACY_SHORT).encode())
_payload_cache = None
MESSAGES = {
    'git-capability-query': 'Git hook capability could not be determined.',
    'git-path-query': 'Git runtime paths could not be read.',
    'git-selection-changed': 'Selected Git changed during discovery.',
}


class GitError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(MESSAGES.get(reason, reason))


def _fail(reason):
    raise GitError(reason)


def _query(executable, args, environment, directory):
    from ._native import execute_owned
    with tempfile.TemporaryDirectory(prefix='query-', dir=directory) as temporary:
        record = {}
        try:
            execute_owned([executable, *args], record, lambda: None, temporary,
                          cwd=directory, env=environment, output_limit=65536, deadline=8)
        except Exception as error:
            raise GitError('git-query-failed') from error
        if not all(record.get(key) is True for key in ('reaped', 'streams_eof', 'streams_durable')):
            _fail('git-query-failed')
        return record['returncode'], (Path(temporary) / 'stdout').read_bytes(), (Path(temporary) / 'stderr').read_bytes()


def _selected(environment, *, cwd=None):
    if cwd is not None and os.fspath(cwd) == '':
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), '')
    directory = Path.cwd() if cwd is None else Path(cwd)
    if not directory.is_absolute():
        directory = Path.cwd() / directory
    if not stat.S_ISDIR(directory.stat().st_mode):
        raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(directory))
    path = None
    for entry in os.get_exec_path(environment):
        base = Path(entry)
        if not base.is_absolute():
            base = directory / base
        candidate = base / 'git'
        if shutil.which(str(candidate)) is not None:
            path = candidate.absolute()
            break
    if path is None:
        raise FileNotFoundError(2, os.strerror(2), 'git')
    physical = path.resolve(strict=True)
    before = (_bundle._identity(path.lstat()), _bundle._identity(physical.stat()))
    def check():
        try:
            if path.resolve(strict=True) != physical or before != (
                    _bundle._identity(path.lstat()), _bundle._identity(physical.stat())):
                _fail('git-selection-changed')
        except OSError as error:
            raise GitError('git-selection-changed') from error
    return str(path), check


def _path(result):
    code, stdout, stderr = result
    if code or stderr or not stdout.endswith(b'\n') or not 1 < len(stdout) <= 4096:
        _fail('git-path-query')
    try:
        value = stdout[:-1].decode()
    except UnicodeError as error:
        raise GitError('git-path-query') from error
    path = PurePosixPath(value)
    if not value or any(c in value for c in '\0\n\r') or not path.is_absolute() or '..' in path.parts:
        _fail('git-path-query')
    return value


def select(environment, *, cwd=None):
    result = {key: value for key, value in environment.items() if not key.startswith('GIT_STALLIONFS_')}
    executable, check = _selected(result, cwd=cwd)
    with tempfile.TemporaryDirectory(prefix='sfs-git-routing-') as temporary:
        root = Path(temporary).resolve()
        for name in ('home', 'xdg', 'hooks', 'repo', 'repo/.git', 'repo/.git/objects', 'repo/.git/refs'):
            (root / name).mkdir(mode=0o700)
        (root / 'repo/.git/HEAD').write_text('ref: refs/heads/main\n')
        (root / 'repo/.git/config').write_text('[core]\nrepositoryformatversion = 0\nbare = false\n')
        if Path(executable).resolve() == Path('/usr/bin/git') and 'DEVELOPER_DIR' not in result:
            try:
                result['DEVELOPER_DIR'] = _path(_query('/usr/bin/xcode-select', ['--print-path'], result, root / 'repo'))
            except GitError as error:
                if error.reason == 'git-query-failed':
                    raise GitError('git-path-query') from error
                raise
            check()
        isolated = {key: value for key, value in result.items() if not key.startswith('GIT_')}
        isolated.update(HOME=str(root / 'home'), XDG_CONFIG_HOME=str(root / 'xdg'), LC_ALL='C',
            GIT_CONFIG_NOSYSTEM='1', GIT_ATTR_NOSYSTEM='1', GIT_CONFIG_SYSTEM='/dev/null',
            GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0', GIT_ALLOW_PROTOCOL='',
            GIT_PROTOCOL_FROM_USER='0', GIT_TRACE2='0', GIT_TRACE2_EVENT='0', GIT_TRACE2_PERF='0')
        try:
            version = _query(executable, ['--version'], isolated, root / 'repo')
            check()
            if version[0] or version[2] or not re.fullmatch(rb'git version [^\x00\r\n]+\n', version[1]):
                _fail('git-capability-query')
            capability = _query(executable, ['-c', 'core.hooksPath=' + str(root / 'hooks'),
                '-c', 'core.fsmonitor=false', '-c', 'hook.stallionfs-capability.command=/usr/bin/false',
                '-c', 'hook.stallionfs-capability.event=post-checkout', 'hook', 'list', 'post-checkout'],
                isolated, root / 'repo')
            check()
        except GitError as error:
            if error.reason == 'git-query-failed':
                raise GitError('git-capability-query') from error
            raise
        if capability[0] == 129 and capability[1] == b'' and capability[2] in LEGACY_DIAGNOSTICS:
            return executable, result
        if capability != (0, b'stallionfs-capability\n', b''):
            _fail('git-capability-query')
        root_runtime = Path(__file__).resolve().parent / '_git'
        payload = regular_payload(root_runtime)
        discovery = dict(result, LC_ALL='C')
        args = ['--no-pager', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false']
        try:
            system = _path(_query(executable, [*args, 'var', 'GIT_CONFIG_SYSTEM'], discovery, root / 'repo'))
            attributes = _path(_query(executable, [*args, 'var', 'GIT_ATTR_SYSTEM'], discovery, root / 'repo'))
            helpers = _path(_query(executable, ['--exec-path'], discovery, root / 'repo'))
        except GitError as error:
            if error.reason == 'git-query-failed':
                raise GitError('git-path-query') from error
            raise
        check(); payload['check']()
        result.update(GIT_CONFIG_SYSTEM=system, GIT_STALLIONFS_ATTR_SYSTEM=attributes,
            GIT_EXEC_PATH=str(root_runtime / 'libexec/git-core'),
            GIT_TEMPLATE_DIR=str(root_runtime / 'share/git-core/templates'))
        if re.search(rb'\(Apple Git-157\)\n$', version[1]):
            default = dict(discovery); default.pop('GIT_EXEC_PATH', None)
            try:
                provider_core = _path(_query(executable, ['--exec-path'], default, root / 'repo'))
            except GitError as error:
                if error.reason == 'git-query-failed':
                    raise GitError('git-path-query') from error
                raise
            provider = Path(provider_core)
            if provider.name != 'git-core' or provider.parent.name != 'libexec':
                _fail('git-path-query')
            provider = provider.parent.parent / 'share/git-core'
            result['GIT_STALLIONFS_CONFIG_PROVIDER'] = str(provider / 'gitconfig')
            result['GIT_STALLIONFS_ATTR_PROVIDER'] = str(provider / 'gitattributes')
        elif b'(Apple Git-' in version[1]:
            _fail('git-path-query')
        check(); payload['check']()
        prefix = [str(root_runtime / 'bin'), str(root_runtime / 'libexec/git-core'), helpers]
        result['PATH'] = os.pathsep.join(prefix) + os.pathsep + result.get('PATH', os.defpath)
        return str(root_runtime / 'bin/git'), result


def _headers(value):
    _bundle.require(type(value) is list and len(value) == 11, 'Unsupported Git provenance')
    names = set()
    for row in value:
        _bundle.require(type(row) is dict and set(row) == {'archive_member', 'file', 'sha256', 'bytes'}
                        and type(row['file']) is str and re.fullmatch(r'baseline/include/curl/[A-Za-z0-9_-]+\.h', row['file'])
                        and row['file'] not in names and type(row['archive_member']) is str
                        and type(row['bytes']) is int and 0 < row['bytes'] <= 1024 * 1024
                        and re.fullmatch('[0-9a-f]{64}', str(row['sha256'])), 'Unsupported Git provenance')
        names.add(row['file'])
    return value


def _identity(info):
    return (*_bundle._identity(info), getattr(info, 'st_flags', 0))


def _read_file(root, path, cap, identities, admitted):
    """Admit one opened file, preserving strict directory and later-read bindings."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open(root, flags | os.O_DIRECTORY)
    descriptor = None
    try:
        _bundle.require(_identity(os.fstat(parent)) == identities[root], 'Git payload changed')
        parts = path.relative_to(root).parts
        current = root
        for name in parts[:-1]:
            current /= name
            child = os.open(name, flags | os.O_DIRECTORY, dir_fd=parent)
            try:
                _bundle.require(current in identities and _identity(os.fstat(child)) == identities[current]
                    == _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'Git payload changed')
            except BaseException:
                os.close(child)
                raise
            os.close(parent); parent = child
        descriptor = os.open(parts[-1], flags | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(descriptor); baseline = _identity(info)
        _bundle.require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid())
            and not info.st_mode & 0o022 and info.st_nlink == 1 and 0 <= info.st_size <= cap,
            'Git payload changed')
        expected = identities[path]
        if path in admitted:
            _bundle.require(baseline == expected, 'Git payload changed')
        else:
            # Namespace discovery precedes content admission. The first opened
            # fd/path pair establishes ctime and flags; mtime and object/security fields stay bound.
            _bundle.require(baseline[:8] == expected[:8], 'Git payload changed')
        _bundle.require(_identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)) == baseline,
                        'Git payload changed')
        if path not in admitted:
            identities[path] = baseline; admitted.add(path)
        data = bytearray()
        while len(data) <= info.st_size:
            block = os.read(descriptor, min(65536, info.st_size + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        _bundle.require(len(data) == info.st_size and _identity(os.fstat(descriptor)) == baseline
            == _identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False))
            and _identity(os.fstat(parent)) == identities[path.parent], 'Git payload changed')
        return bytes(data)
    finally:
        try:
            if descriptor is not None:
                os.close(descriptor)
        finally:
            os.close(parent)


def regular_payload(root):
    global _payload_cache
    root = Path(root).absolute()
    _bundle.require(not root.is_symlink(), 'Git payload changed')
    root = root.resolve(strict=True)
    def identity(path):
        return _identity(path.lstat())
    if _payload_cache is not None and _payload_cache['root'] == root:
        _payload_cache['check']()
        return _payload_cache
    identities = {root: identity(root)}; admitted = set()
    root_info = root.stat()
    _bundle.require(stat.S_ISDIR(root_info.st_mode) and root_info.st_uid in (0, os.getuid())
                    and not root_info.st_mode & 0o022, 'Git payload changed')
    actual, directories_seen = set(), set()
    for directory, directories, files in os.walk(root, followlinks=False):
        _bundle.require(len(actual) + len(directories_seen) <= 4096, 'Git payload names exceed bounds')
        for name in [*directories, *files]:
            path = Path(directory) / name; info = path.lstat(); identities[path] = _identity(info)
            _bundle.require(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022
                            and not stat.S_ISLNK(info.st_mode), 'Git payload changed')
            relative = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                directories_seen.add(relative)
            else:
                _bundle.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                                and info.st_size <= 64 * 1024**2, 'Unsafe Git runtime file')
                actual.add(relative)
    def read(path, cap):
        return _read_file(root, path, cap, identities, admitted)
    manifest_path = root / 'manifest.json'
    _bundle.require(manifest_path in identities, 'Missing Git runtime support')
    manifest_bytes = read(manifest_path, 1024 * 1024)
    value = json.loads(manifest_bytes)
    _bundle.require(type(value) is dict and set(value) == {'schema', 'kind', 'source', 'build', 'files'}
        and type(value['schema']) is int and value['schema'] == 1 and value['kind'] == 'package-git-runtime'
        and value['source'] == {key: _bundle.GIT_CONTRACT[key] for key in _bundle.GIT_SOURCE_KEYS}
        and type(value['build']) is dict and type(value['files']) is list and len(value['files']) <= 4096,
        'Unsupported Git provenance')
    rows = {row['path']: row for row in value['files'] if type(row) is dict and type(row.get('path')) is str}
    _bundle.require(len(rows) == len(value['files']), 'Git payload names exceed bounds')
    expected = set(_git_sources.LAYOUT) | {'COPYING', 'CURL-COPYING', 'SOURCES.txt', 'sources/git-source.tar.xz'}
    expected |= {'sources/' + name for name in _git_sources.INPUTS if not name.endswith(('.tar.xz', '.tar.gz'))}
    expected.add('sources/build-scripts.tar.xz')
    header_manifest = root / 'sources/header-manifest.json'
    _bundle.require(header_manifest in identities, 'Missing Git runtime support')
    headers = _headers(json.loads(read(header_manifest, 65536)))
    for row in headers:
        name = 'sources/' + row['file']
        expected.add(name)
    _bundle.require(set(rows) == expected, 'Missing Git runtime support')
    _bundle.require(actual == set(rows) | {'manifest.json'}, 'Missing Git runtime support')
    allowed_directories = set(_git_sources.DIRECTORIES)
    for name in expected:
        allowed_directories.update(str(p) for p in PurePosixPath(name).parents if str(p) != '.')
    _bundle.require(directories_seen == allowed_directories, 'Git payload changed')
    total = 0
    for relative, row in rows.items():
        path = root / relative; info = path.lstat()
        _bundle.require(set(row) == {'path', 'mode', 'size', 'sha256'} and type(row['size']) is int
            and row['size'] == info.st_size and row['mode'] == oct(stat.S_IMODE(info.st_mode)), 'Git payload changed')
        digest = hashlib.sha256(read(path, 64 * 1024**2)).hexdigest()
        total += info.st_size; _bundle.require(total <= 128 * 1024**2, 'Git payload byte limit')
        _bundle.require(row['sha256'] == digest, 'Git payload changed')
    for name, sha in _git_sources.INPUTS.items():
        if not name.endswith(('.tar.xz', '.tar.gz')):
            _bundle.require(rows['sources/' + name]['sha256'] == sha, 'Unsupported Git provenance')
    for name, sha in _git_sources.LICENSES.items():
        _bundle.require(rows[name]['sha256'] == sha, 'Unsupported Git provenance')
    _bundle.require(value['build'].get('source_distribution_sha256') == rows['sources/git-source.tar.xz']['sha256'],
                    'Unsupported Git provenance')
    _bundle.require(rows['sources/git-source.tar.xz']['sha256'] == _bundle.GIT_CONTRACT['source_distribution_sha256'],
                    'Unsupported Git provenance')
    with tarfile.open(fileobj=io.BytesIO(read(root / 'sources/build-scripts.tar.xz', 1024 * 1024)), mode='r:xz') as archive:
        members = archive.getmembers()
        required = {'tools/build_git_runtime.py', 'tools/_git_capture.py', 'stallionfs/_git_sources.py',
                    'stallionfs/_bundle.py', *('tools/git-inputs/' + name for name in _git_sources.INPUTS
                                              if not name.endswith(('.tar.xz', '.tar.gz')))}
        _bundle.require(len(members) == len(required) and {m.name for m in members} == required
                        and all(m.isfile() and m.size <= 1024 * 1024 for m in members), 'Unsupported Git provenance')
        for name, key in (('tools/build_git_runtime.py', 'recipe_sha256'), ('tools/_git_capture.py', 'capture_sha256'),
                          ('stallionfs/_git_sources.py', 'registry_sha256'), ('stallionfs/_bundle.py', 'bundle_sha256')):
            _bundle.require(hashlib.sha256(archive.extractfile(name).read()).hexdigest() == value['build'].get(key),
                            'Unsupported Git provenance')
    for row in headers:
        _bundle.require(rows['sources/' + row['file']]['sha256'] == row['sha256'], 'Unsupported Git provenance')
    for name, row in _git_sources.LAYOUT.items():
        _bundle.require(rows[name]['mode'] == row['mode'], 'Git payload changed')
    def check():
        _bundle.require(all(identity(path) == expected for path, expected in identities.items()), 'Git payload changed')
    _bundle.require(admitted == {root / name for name in actual}, 'Missing Git runtime support')
    check()
    _payload_cache = {'root': root, 'check': check, 'manifest': value}
    return _payload_cache
