"""Paths and bootstrap for the explicitly assembled private runtime layout."""
import json
import os
from pathlib import Path
import re
import stat
import sys


class BundleError(ValueError):
    """A bundled dependency or its containing layout is invalid."""


RELATIVE_PATHS = {
    'python': 'Contents/Resources/Runtime/CPython/bin/python3.13',
    'site_packages': 'Contents/Resources/Runtime/CLI/lib/python3.13/site-packages',
    'helper': 'Contents/Resources/Runtime/CLI/bin/stallionfs-python',
    'git': 'Contents/Resources/Runtime/Git/bin/git',
    'git_exec_path': 'Contents/Resources/Runtime/Git/libexec/git-core',
    'git_template_dir': 'Contents/Resources/Runtime/Git/share/git-core/templates',
}
MODULE_SUFFIX = (*Path(RELATIVE_PATHS['site_packages']).parts, 'stallionfs', '_bundle.py')
DESCRIPTOR = 'Contents/Resources/Runtime/runtime.json'
NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC


def require(condition, message):
    if not condition:
        raise BundleError(message)


def _identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
                 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _owned(info):
    require(info.st_uid in (0, os.getuid()) and not stat.S_IMODE(info.st_mode) & 0o7022,
            'Bundled runtime ownership or permissions are unsafe')


def _applications_anchor(info):
    try:
        import grp
        admin = grp.getgrnam('admin')
    except (ImportError, KeyError, OSError):
        raise BundleError('macOS admin group is unavailable') from None
    group = getattr(admin, 'gr_gid', None)
    require(getattr(admin, 'gr_name', None) == 'admin' and type(group) is int and 0 <= group < 2**32,
            'Invalid macOS admin group')
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == group
            and stat.S_IMODE(info.st_mode) in (0o755, 0o775), 'Unsafe Applications directory')


def _directory(path):
    require(path.is_absolute() and '..' not in path.parts, 'Invalid bundled directory')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
    anchor_parent = anchor = None
    installed = path.parts[:3] == ('/', 'Applications', 'StallionFS.app')
    try:
        _owned(os.fstat(fd))
        if installed:
            anchor_parent = os.dup(fd)
        for index, part in enumerate(path.parts[1:], 1):
            before = os.stat(part, dir_fd=fd, follow_symlinks=False)
            standard_anchor = installed and index == 1 and part == 'Applications'
            if standard_anchor:
                _applications_anchor(before)
            else:
                _owned(before)
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=fd)
            try:
                require(_identity(before) == _identity(os.fstat(child)), 'Bundled directory changed')
                if standard_anchor:
                    anchor = os.dup(child)
                    anchor_identity = _identity(before)
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        if anchor is not None:
            require(anchor_identity == _identity(os.fstat(anchor))
                    == _identity(os.stat('Applications', dir_fd=anchor_parent, follow_symlinks=False)),
                    'Applications directory changed')
        return fd
    except BaseException:
        os.close(fd)
        raise
    finally:
        if anchor is not None:
            os.close(anchor)
        if anchor_parent is not None:
            os.close(anchor_parent)


def _file(path, *, executable=False, read=False):
    parent = _directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | NOFOLLOW, dir_fd=parent)
        try:
            before = os.fstat(fd)
            _owned(before)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                    'Missing ordinary bundled file: ' + path.name)
            require(not executable or before.st_mode & 0o111, 'Bundled file is not executable: ' + path.name)
            data = None
            if read:
                require(0 < before.st_size <= 16384, 'Bundled descriptor exceeds its limit')
                with os.fdopen(os.dup(fd), 'rb') as stream:
                    data = stream.read(before.st_size + 1)
                require(len(data) == before.st_size, 'Bundled descriptor changed')
            require(_identity(before) == _identity(os.fstat(fd))
                    == _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                    'Bundled file changed: ' + path.name)
            return data
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def paths():
    """Return this module's bundle paths, or None for ordinary source installs."""
    module = Path(os.path.abspath(__file__))
    apparent = any(parent.name == 'Contents' and parent.parent.suffix == '.app'
                   for parent in module.parents)
    if tuple(module.parts[-len(MODULE_SUFFIX):]) != MODULE_SUFFIX:
        require(not apparent, 'Unsupported bundled CLI layout')
        return None
    app = module.parents[len(MODULE_SUFFIX) - 1]
    require(app.suffix == '.app' and module.resolve(strict=True) == module,
            'Bundled CLI path is not physical')
    _file(module)
    return _layout(app)


def from_host(host):
    path = Path(host).absolute()
    require(path.is_absolute() and path.name == "StallionFS" and path.parent.name == "MacOS"
            and path.parent.parent.name == "Contents" and path.parent.parent.parent.suffix == ".app"
            and path.resolve(strict=True) == path, "Invalid companion Host path")
    _file(path, executable=True)
    return _layout(path.parent.parent.parent)


def _layout(app):
    value = json.loads(_file(app / DESCRIPTOR, read=True))
    require(isinstance(value, dict) and set(value) == {
        'schema', 'python_version', 'soabi', 'package_version', 'source_build_id', 'bundle_version', 'paths'}
        | ({'git'} if value.get('schema') == 2 else set()),
        'Invalid bundled runtime descriptor')
    require(type(value['schema']) is int and value['schema'] in (1, 2)
            and value['python_version'] == '3.13.18' and value['soabi'] == 'cpython-313-darwin'
            and isinstance(value['package_version'], str)
            and re.fullmatch(r'[0-9]+(?:\.[0-9]+){2}', value['package_version'])
            and isinstance(value['source_build_id'], str)
            and re.fullmatch('[0-9a-f]{64}', value['source_build_id'])
            and isinstance(value['bundle_version'], str)
            and re.fullmatch(r'[1-9][0-9]*(?:\.[0-9]+){0,2}', value['bundle_version'])
            and value['paths'] == RELATIVE_PATHS, 'Unsupported bundled runtime metadata')
    result = {key: app / name for key, name in RELATIVE_PATHS.items()}
    for key in ('site_packages', 'git_exec_path', 'git_template_dir'):
        fd = _directory(result[key])
        os.close(fd)
    for key in ('python', 'helper', 'git'):
        _file(result[key], executable=True)
    for name in ('sfs', 'stallionfs'):
        _file(result['helper'].with_name(name), executable=True)
    for name in ('__init__.py', '__main__.py', '_bundle.py', '_scan.cpython-313-darwin.so',
                 '_image.cpython-313-darwin.so'):
        _file(result['site_packages'] / 'stallionfs' / name)
    package = sys.modules.get('stallionfs')
    require(package is None or package.__version__ == value['package_version'],
            'Bundled package version differs')
    return dict(result, app=app, metadata=value)


def git_environment(environment, *, cwd=None):
    """Select private Git for an internal operation after inherited Git sanitation."""
    bundle = paths()
    if bundle is None:
        from ._git_runtime import select
        return select(environment, cwd=cwd)
    _app_git(bundle)['check']()
    result = {key: value for key, value in environment.items() if not key.startswith('GIT_STALLIONFS_')}
    result['GIT_EXEC_PATH'] = str(bundle['git_exec_path'])
    result['GIT_TEMPLATE_DIR'] = str(bundle['git_template_dir'])
    prefix = os.pathsep.join((str(bundle['git'].parent), str(bundle['git_exec_path'])))
    # Keep the remainder exactly as supplied; never change the caller's environment.
    result['PATH'] = prefix + (os.pathsep + result['PATH'] if 'PATH' in result else os.pathsep + os.defpath)
    return str(bundle['git']), result


def _app_git(bundle):
    value = bundle['metadata'].get('git')
    require(bundle['metadata']['schema'] == 2 and type(value) is dict
            and set(value) == set(GIT_CONTRACT) | {'input_inventory_sha256', 'payload_entries', 'payload_sha256'},
            'Unsupported Git provenance')
    git_contract({key: value[key] for key in set(GIT_CONTRACT) | {'input_inventory_sha256'}}, qualified=False)
    root = bundle['git'].parent.parent
    payload = git_payload(root)
    require(type(value['payload_entries']) is int and value['payload_entries'] == payload['entries']
            and value['payload_sha256'] == payload['sha256'], 'Git payload changed')
    def check():
        require(_identity(root.lstat()) == payload['root_identity']
                and all(_identity((root / name).lstat()) == expected for name, expected in payload['identities'].items()),
                'Git payload changed')
    check()
    return {'executable': str(bundle['git']), 'exec_path': str(bundle['git_exec_path']), 'check': check}


def product_git():
    """Corrected product parser; this grants no native lifetime authority."""
    bundle = paths()
    if bundle is not None:
        return _app_git(bundle)
    from ._git_runtime import regular_payload
    root = Path(__file__).resolve().parent / '_git'
    value = regular_payload(root)
    return {'executable': str(root / 'bin/git'), 'exec_path': str(root / 'libexec/git-core'), 'check': value['check']}


def main():
    require(not any(name == 'stallionfs' or name.startswith('stallionfs.') for name in sys.modules),
            'Bundled bootstrap requires a fresh package context')
    bundle = paths()
    require(bundle is not None, 'Run the installed sibling Python helper')
    require(len(sys.argv) >= 2 and sys.argv[1] == str(bundle['helper']), 'Invalid bundled helper identity')
    require(all(getattr(sys.flags, name) for name in ('isolated', 'ignore_environment', 'safe_path',
            'no_user_site', 'no_site', 'dont_write_bytecode')), 'Bundled Python must use -I -B -S')
    require(sys.implementation.name == 'cpython' and sys.version_info[:3] == (3, 13, 18)
            and sys.implementation.cache_tag == 'cpython-313' and sys.abiflags == ''
            and getattr(sys, '_is_gil_enabled', lambda: False)(), 'Bundled Python ABI differs')
    require(Path(sys.executable).resolve(strict=True) == bundle['python'], 'Wrong bundled Python executable')
    runtime = bundle['python'].parent.parent
    expected = [str(runtime / 'lib/python313.zip'), str(runtime / 'lib/python3.13'),
                str(runtime / 'lib/python3.13/lib-dynload')]
    require(len(sys.path) == len(set(sys.path)) and set(sys.path) == set(expected),
            'Unexpected bundled Python search path')
    sys.path.insert(0, str(bundle['site_packages']))
    sys.argv[:] = [str(bundle['helper']), *sys.argv[2:]]
    import stallionfs
    import stallionfs.__main__
    require(Path(stallionfs.__file__).resolve(strict=True)
            == bundle['site_packages'] / 'stallionfs/__init__.py'
            and Path(stallionfs.__main__.__file__).resolve(strict=True)
            == bundle['site_packages'] / 'stallionfs/__main__.py'
            and stallionfs.__version__ == bundle['metadata']['package_version'],
            'Wrong bundled package origin or version')
    return stallionfs.__main__.main()


LEGACY_GIT_CONTRACT = {
    'schema': 1, 'contract': 'native-create-git-v2',
    'source_sha256': '26c56c296b38c0695b26fa95f475f1d01704d2d38e73465ca30b0b2f5dc789d3',
    'build_config_sha256': 'f33556ec8016cf7a0340e01e732f4e13c50cf2df97b561d952734275f0996f5d',
    'input_inventory_sha256': '4e2ee05194ed0e8779e1123452647ceaee43ae2382ef96fa1bf2d3343f0cfd37',
    'payload_format': 'git-tree-v1',
}
GIT_CONTRACT = {
    'schema': 1, 'contract': 'native-create-git-v3',
    'source_sha256': LEGACY_GIT_CONTRACT['source_sha256'],
    'source_distribution_sha256': 'ed174876799b682ab7f21f02559407f76f04f3ef073a9bea9d72ec800aa3fd46',
    'build_config_sha256': LEGACY_GIT_CONTRACT['build_config_sha256'],
    'combined_patch_sha256': '951f39fdd898ebaf3b075e148d4a7685c9f81069d17068d07adaf6aa8f9568ef',
    'notice_patch_sha256': '13867c0f3bd16a38b022664d0bfb5c2dd2458a97417d363b121bbefe55afec0f',
    'curl_archive_sha256': '4d1709a3c7338cf99feee139ebf73321c6a9e2225a0a2f2f5843e7a401d6c8cb',
    'curl_header_manifest_sha256': 'f6aba83faccf2554b40308815bc2f1359cdf9f7ebe8dec87cae90f19fbac9228',
    'alias_source_sha256': '2f277d0e5d8e525f725cf6dc3542b369274f5880f18d1b1ea06ab316a4aa4527',
    'payload_format': 'git-tree-v1',
}
# Exact native command inputs; corresponding source is mapped separately.
QUALIFIED_GIT_ARCHITECTURES = {
    '9b9401eaea9d2f2b3e88c8c87509b52414b5522016c505718c050cd562725700': 'arm64',
    '020c08613be10d2d21d46a4defd6c4c98724b0af61426a9a2096e1bee48d546a': 'x86_64',
}
QUALIFIED_GIT_INPUTS = frozenset(QUALIFIED_GIT_ARCHITECTURES)
GIT_SOURCE_KEYS = ('source_sha256', 'source_distribution_sha256', 'build_config_sha256', 'combined_patch_sha256', 'notice_patch_sha256',
                   'curl_archive_sha256', 'curl_header_manifest_sha256', 'alias_source_sha256')


def git_contract(value, *, qualified=True, architecture=None):
    require(type(value) is dict and set(value) == set(GIT_CONTRACT) | {'input_inventory_sha256'}
            and all(value.get(key) == expected for key, expected in GIT_CONTRACT.items())
            and type(value.get('schema')) is int
            and re.fullmatch('[0-9a-f]{64}', str(value.get('input_inventory_sha256'))),
            'Unsupported Git provenance')
    require(not qualified or value['input_inventory_sha256'] in QUALIFIED_GIT_INPUTS,
            'Git build has not been qualified')
    if architecture is not None:
        require(qualified and architecture in ('arm64', 'x86_64')
                and QUALIFIED_GIT_ARCHITECTURES.get(value['input_inventory_sha256']) == architecture,
                'Git build architecture differs')
    return value

PUBLISHER_TEAM = '4CQS5J4848'


def git_payload(root):
    """Hash the finite physical runtime once; retain identities for launch checks."""
    import hashlib
    import unicodedata
    root = Path(root)
    descriptor = _directory(root)
    rows, identities, folded = [], {}, set()
    total = 0
    def walk(fd, prefix=''):
        nonlocal total
        for name in sorted(os.listdir(fd)):
            relative = prefix + name
            key = unicodedata.normalize('NFC', relative).casefold()
            require(key not in folded and len(rows) < 4096 and len(relative) < 1024, 'Git payload names exceed bounds')
            folded.add(key)
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            row = {'path': relative, 'mode': oct(stat.S_IMODE(before.st_mode))}
            identities[relative] = _identity(before)
            if stat.S_ISLNK(before.st_mode):
                require(before.st_uid in (0, os.getuid()), 'Unsafe Git runtime link owner')
                link = os.readlink(name, dir_fd=fd)
                require(0 < len(link) < 1024 and not os.path.isabs(link) and '\\' not in link, 'Unsafe Git runtime link')
                row.update(type='symlink', size=len(os.fsencode(link)), link=link)
            else:
                _owned(before)
                if stat.S_ISDIR(before.st_mode):
                    row.update(type='dir', size=0)
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=fd)
                    try:
                        require(_identity(os.fstat(child)) == _identity(before), 'Git payload changed')
                        rows.append(row)
                        walk(child, relative + '/')
                    finally:
                        os.close(child)
                else:
                    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 64 * 1024 * 1024,
                            'Unsafe Git runtime file')
                    child = os.open(name, os.O_RDONLY | os.O_NONBLOCK | NOFOLLOW, dir_fd=fd)
                    try:
                        require(_identity(os.fstat(child)) == _identity(before), 'Git payload changed')
                        value, size = hashlib.sha256(), 0
                        while True:
                            block = os.read(child, 65536)
                            if not block:
                                break
                            size += len(block); total += len(block)
                            require(size <= before.st_size and total <= 128 * 1024 * 1024, 'Git payload byte limit')
                            value.update(block)
                        require(size == before.st_size and _identity(os.fstat(child)) == _identity(before), 'Git payload changed')
                        row.update(type='file', size=size, sha256=value.hexdigest())
                    finally:
                        os.close(child)
            require(_identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == _identity(before), 'Git payload substituted')
            if row['type'] != 'dir':
                rows.append(row)
    try:
        walk(descriptor)
        table = {row['path']: row for row in rows}
        for row in rows:
            if row['type'] != 'symlink':
                continue
            # Resolve only the enumerated relative namespace, never filesystem aliases.
            pending = list(Path(row['path']).parent.parts) + row['link'].split('/')
            resolved, expansions = [], 0
            while pending:
                component = pending.pop(0)
                if component in ('', '.'):
                    continue
                if component == '..':
                    require(bool(resolved), 'Git runtime link escape')
                    resolved.pop(); continue
                resolved.append(component)
                entry = table.get('/'.join(resolved))
                require(entry is not None, 'Missing Git runtime link target')
                if entry['type'] == 'symlink':
                    expansions += 1
                    require(expansions <= 64, 'Git runtime link cycle')
                    resolved.pop(); pending = entry['link'].split('/') + pending
                else:
                    require(not pending or entry['type'] == 'dir', 'Git runtime link crosses a file')
        rows.sort(key=lambda row: row['path'])
        digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return {'entries': len(rows), 'sha256': digest, 'executable_sha256': table['bin/git']['sha256'],
                'identities': identities, 'root_identity': _identity(os.fstat(descriptor))}
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, TypeError) as error:
        print('stallionfs: invalid bundled runtime: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
