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
    value = json.loads(_file(app / DESCRIPTOR, read=True))
    require(isinstance(value, dict) and set(value) == {
        'schema', 'python_version', 'soabi', 'package_version', 'source_build_id', 'bundle_version', 'paths'},
        'Invalid bundled runtime descriptor')
    require(type(value['schema']) is int and value['schema'] == 1
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


def git_environment(environment):
    """Select private Git for an internal operation after inherited Git sanitation."""
    bundle = paths()
    if bundle is None:
        return 'git', environment
    result = dict(environment)
    result['GIT_EXEC_PATH'] = str(bundle['git_exec_path'])
    result['GIT_TEMPLATE_DIR'] = str(bundle['git_template_dir'])
    prefix = os.pathsep.join((str(bundle['git'].parent), str(bundle['git_exec_path'])))
    # Keep the remainder exactly as supplied; never change the caller's environment.
    result['PATH'] = prefix + (os.pathsep + result['PATH'] if 'PATH' in result else os.pathsep + os.defpath)
    return str(bundle['git']), result


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


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, TypeError) as error:
        print('stallionfs: invalid bundled runtime: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
