"""Install or remove this user's command link without replacing other entries."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import shlex
import stat

from . import _bundle

APP = Path('/Applications/StallionFS.app')
LINK = 'sfs'
LOCK = '.stallionfs-command.lock'


class CommandError(ValueError):
    """Command setup needs user attention."""


def require(condition, message):
    if not condition:
        raise CommandError(message)


def _home():
    import pwd
    require(os.getuid() == os.geteuid() and os.getuid() != 0, 'Run command setup as your normal user')
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, OSError):
        raise CommandError('User home is unavailable') from None
    require(home.is_absolute() and home.resolve(strict=True) == home, 'User home is not a physical directory')
    return home


def _acl(fd):
    from ._scan import _protected_directory_fd
    _protected_directory_fd(fd, False)


def _directory_identity(info):
    return tuple(getattr(info, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid'))


def _safe_directory(fd, *, user=False):
    info = os.fstat(fd)
    _bundle._owned(info)
    require(stat.S_ISDIR(info.st_mode) and (not user or info.st_uid == os.getuid()),
            'Command directory must belong to this user')
    _acl(fd)
    return _directory_identity(info)


def _check_directories(held):
    for parent, name, fd, identity in held:
        require(_directory_identity(os.fstat(fd)) == identity, 'Command directory changed')
        if parent is not None:
            require(_directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity,
                    'Command directory was replaced')
        _acl(fd)


@contextmanager
def _bin(home, *, create):
    held = []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | _bundle.NOFOLLOW)
        try:
            identity = _safe_directory(fd)
        except BaseException:
            os.close(fd)
            raise
        held.append((None, '/', fd, identity))
        components = [*home.parts[1:], '.local', 'bin']
        for index, name in enumerate(components):
            parent = held[-1][2]
            try:
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                if index < len(home.parts) - 1:
                    raise CommandError('User home is unavailable') from None
                if not create:
                    yield None
                    return
                os.mkdir(name, 0o755, dir_fd=parent)
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | _bundle.NOFOLLOW, dir_fd=parent)
            try:
                require(_bundle._identity(before) == _bundle._identity(os.fstat(child)),
                        'Command directory changed while opening')
                identity = _safe_directory(child, user=index >= len(home.parts) - 2)
            except BaseException:
                os.close(child)
                raise
            held.append((parent, name, child, identity))
        _check_directories(held)
        yield held
    finally:
        for _, _, fd, _ in reversed(held):
            os.close(fd)


def _target():
    bundle = _bundle.paths()
    require(bundle is not None and bundle['app'] == APP, 'Move the app to /Applications/StallionFS.app before command setup')
    target = bundle['helper'].with_name(LINK)
    _bundle._file(target, executable=True)
    app, parent, binary = APP.lstat(), APP.parent.lstat(), target.lstat()
    _bundle._owned(app)
    _bundle._owned(binary)
    require(stat.S_ISDIR(app.st_mode) and stat.S_ISREG(binary.st_mode) and binary.st_nlink == 1
            and binary.st_mode & 0o111, 'Command target is not an ordinary bundled executable')
    require(app.st_dev == parent.st_dev == binary.st_dev, 'Command target must be in the installed app, not a mounted volume')
    return target, (bundle, _bundle._identity(parent), _bundle._identity(app), _bundle._identity(binary))


def _link(fd):
    try:
        before = os.stat(LINK, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    text = os.readlink(LINK, dir_fd=fd) if stat.S_ISLNK(before.st_mode) else None
    require(_bundle._identity(before) == _bundle._identity(os.stat(LINK, dir_fd=fd, follow_symlinks=False)),
            'Command entry changed')
    return _bundle._identity(before), before.st_uid, text


def _ours(entry, target):
    return entry is not None and entry[1] == os.getuid() and entry[2] == str(target)


def _result(home, entry, target):
    directory = home / '.local/bin'
    return {'state': 'missing' if entry is None else 'installed' if _ours(entry, target) else 'conflict',
            'command': str(directory / LINK), 'target': str(target),
            'on_path': str(directory) in os.environ.get('PATH', os.defpath).split(os.pathsep),
            'path_setup': 'export PATH=' + shlex.quote(str(directory)) + ':"$PATH"'}


def run(action):
    require(action in ('status', 'install', 'remove'), 'Unknown command setup action')
    home = _home()
    target, admitted = _target()
    with _bin(home, create=action == 'install') as held:
        if held is None:
            return _result(home, None, target)
        directory = held[-1][2]
        if action == 'status':
            entry = _link(directory)
            _check_directories(held)
            require(_target() == (target, admitted), 'Command target changed')
            return _result(home, entry, target)
        lock = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NONBLOCK | _bundle.NOFOLLOW, 0o600, dir_fd=directory)
        try:
            info = os.fstat(lock)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600, 'Command setup lock is unsafe')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise CommandError('Command setup is in use') from None

            def revalidate():
                _check_directories(held)
                require(_bundle._identity(os.fstat(lock)) == _bundle._identity(info)
                        == _bundle._identity(os.stat(LOCK, dir_fd=directory, follow_symlinks=False)),
                        'Command setup lock changed')
                require(_target() == (target, admitted), 'Command target changed')

            revalidate()
            before = _link(directory)
            require(before is None or _ours(before, target), 'Command path already contains another entry')
            revalidate()
            require(_link(directory) == before, 'Command entry changed before setup')
            if action == 'install' and before is None:
                os.symlink(str(target), LINK, dir_fd=directory)
                os.fsync(directory)
            elif action == 'remove' and before is not None:
                # Our lock serializes cooperating setup calls, not arbitrary same-user attackers.
                os.unlink(LINK, dir_fd=directory)
                os.fsync(directory)
            revalidate()
            after = _link(directory)
            require(_ours(after, target) if action == 'install' else after is None,
                    'Command setup outcome changed; inspect command status')
            return _result(home, after, target)
        finally:
            os.close(lock)


def describe(result):
    text = {'missing': 'Command is not installed', 'installed': 'Command installed',
            'conflict': 'Command path contains another entry'}[result['state']] + ': ' + result['command']
    if not result['on_path']:
        text += '\nAdd to PATH (zsh/bash):\n' + result['path_setup']
    return text
