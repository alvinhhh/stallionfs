"""Native APFS disk-image workspaces with verified attachment ownership."""
from __future__ import annotations

import ctypes
import fcntl
import os
from pathlib import Path
import plistlib
import platform
import re
import stat
import subprocess
import sys
import tempfile
from xml.parsers.expat import ExpatError


def _error(message):
    from .core import StallionError
    return StallionError(message)


def _require_supported():
    version = platform.mac_ver()[0]
    if sys.platform != 'darwin' or not version or int(version.split('.')[0]) < 26:
        raise _error('APFS image workspaces require macOS 26 or newer')


def _command(*args):
    result = subprocess.run([str(a) for a in args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, umask=0o077)
    if result.returncode:
        raise _error(f"{args[0]} failed ({result.returncode}): "
                           + result.stderr.decode(errors="replace").strip())
    return result.stdout


def _plist(*args):
    raw = _command(*args)
    try:
        result = plistlib.loads(raw)
    except (ValueError, plistlib.InvalidFileException, ExpatError) as exc:
        raise _error(f"Invalid property list from {args[0]}") from exc
    if not isinstance(result, dict):
        raise _error(f"Invalid response from {args[0]}")
    return result


def _recovery_failure(original, message):
    if not isinstance(original, Exception):
        original.add_note(message)
        raise original
    raise _error(message) from original


def _path(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or path.is_symlink():
        raise _error(f"Use an absolute path without a final symlink: {path}")
    return path.parent.resolve(strict=True) / path.name


def _directory(path, *, private=True):
    if private:
        from .core import private_directory
        return private_directory(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise _error(f"Expected an owned directory: {path}")


def _image(value, *, new=False):
    path = _path(value)
    _directory(path.parent)
    if new:
        if os.path.lexists(path):
            raise FileExistsError(path)
        if path.suffix != ".sparseimage":
            raise _error("Disk-image filename must end with .sparseimage")
    else:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise _error(f"Expected a private, owned image file without hard links: {path}")
    return path


def _attachments(image):
    identity = image.stat()
    matches = []
    for entry in _plist('/usr/bin/hdiutil', 'info', '-plist').get('images', []):
        recorded = entry.get('image-path')
        if not isinstance(recorded, str) or Path(os.path.realpath(recorded)) != image:
            continue
        if entry.get('owner-uid') != os.getuid():
            raise _error(f"Image attachment belongs to another user: {image}")
        matches.append(entry)
    after = image.stat()
    if (identity.st_dev, identity.st_ino) != (after.st_dev, after.st_ino):
        raise _error(f"Image changed while checking its attachment: {image}")
    if len(matches) > 1:
        raise _error(f"Image has multiple attachments; inspect before continuing: {image}")
    return matches


def mounted(image):
    """Return verified attachment metadata, including an unmounted device, or None."""
    image = _image(image)
    matches = _attachments(image)
    if not matches:
        return None
    entry = matches[0]
    entities = entry.get('system-entities', [])
    devices = [e.get('dev-entry') for e in entities]
    if not devices or not all(isinstance(d, str) and re.fullmatch(r'/dev/disk[0-9]+(?:s[0-9]+)*', d) for d in devices):
        raise _error(f"Invalid attachment device metadata: {image}")
    whole = [d for d in devices if re.fullmatch(r'/dev/disk[0-9]+', d)]
    if not whole:
        raise _error(f"Image attachment has no disk device: {image}")
    volumes = [e for e in entities if e.get('mount-point')]
    if len(volumes) > 1:
        raise _error(f"Image unexpectedly contains multiple mounted volumes: {image}")
    mapping = {'image': str(image), 'device': whole[0], 'mountpoint': None, 'volume_device': None}
    if volumes:
        volume = volumes[0]
        point = _path(volume['mount-point'])
        from ._scan import mounts
        records = [record for record in mounts() if record['path'] == str(point)]
        if (len(records) != 1 or records[0]['device'] != volume['dev-entry']
                or records[0]['filesystem'] != 'apfs' or not os.path.ismount(point)):
            raise _error(f"Mount does not match the image's APFS volume: {image}")
        if records[0]['readonly'] or records[0]['ignore_ownership']:
            raise _error(f"Image must be writable with file ownership enabled: {image}")
        device = os.stat(volume['dev-entry'])
        if not stat.S_ISBLK(device.st_mode) or point.stat().st_dev != device.st_rdev:
            raise _error(f"Mount device changed during verification: {point}")
        mapping.update(mountpoint=str(point), volume_device=volume['dev-entry'])
    return mapping


def attach(image, mountpoint):
    """Attach at a stable private path; an existing matching mount is reusable."""
    _require_supported()
    image, point = _image(image), _path(mountpoint)
    _directory(point.parent)
    existing = mounted(image)
    if existing:
        if existing['mountpoint'] == str(point):
            return point / 'repo'
        raise _error(f"Image is already attached at {existing['mountpoint'] or existing['device']}: {image}")
    if os.path.lexists(point):
        _directory(point)
        if os.path.ismount(point) or any(point.iterdir()):
            raise _error(f"Mountpoint must be empty and unmounted: {point}")
    else:
        point.mkdir(mode=0o700)
    try:
        _plist('/usr/sbin/diskutil', 'image', 'attach', '--nobrowse', '--plist',
               '--mountOptions', 'owners', '--mountPoint', point, image)
        result = mounted(image)
        if not result or result['mountpoint'] != str(point):
            raise _error(f"Image did not mount at the requested path: {point}")
        return point / 'repo'
    except BaseException as original:
        # Attach can finish before its command reports completion. Leave its image intact.
        try:
            state = mounted(image)
        except Exception as inspection:
            _recovery_failure(original, f"Attachment outcome is unknown; preserve {image} and {point}: {inspection}")
        if state:
            _recovery_failure(original, f"Attachment needs recovery; preserve {image}; attached at "
                              f"{state['mountpoint'] or state['device']}")
        raise


def detach(image, mountpoint):
    """Detach only this image's verified device, never forcibly and never deleting data."""
    image, point = _image(image), _path(mountpoint)
    _directory(point.parent)
    current = mounted(image)
    if not current:
        if os.path.ismount(point):
            raise _error(f"Mountpoint belongs to another device: {point}")
        return
    if current['mountpoint'] not in (None, str(point)):
        raise _error(f"Image is mounted at a different path: {current['mountpoint']}")
    _command('/usr/bin/hdiutil', 'detach', current['device'])
    if mounted(image) is not None or os.path.ismount(point):
        raise _error(f"Image remains attached; keep its files: {image}")


def clone(source_image, dest_image):
    """Clone one closed image using APFS COW; never substitute a full byte copy."""
    source, destination = _image(source_image), _image(dest_image, new=True)
    if mounted(source):
        raise _error(f"Detach the seed before cloning: {source}")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.clonefile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    libc.clonefile.restype = ctypes.c_int
    if libc.clonefile(os.fsencode(source), os.fsencode(destination), 0):
        raise OSError(ctypes.get_errno(), 'APFS image clone failed', str(destination))
    _image(destination)


def build(source_repo, destination_image, capacity_gib):
    """Prepare and durably close an APFS image. Failed mounted images remain recoverable."""
    from .core import validate_tree
    _require_supported()
    if type(capacity_gib) is not int or capacity_gib <= 0:
        raise _error('Image capacity must be a positive integer number of GiB')
    source, destination = _path(source_repo), _image(destination_image, new=True)
    _directory(source, private=False)
    validate_tree(source)
    point = Path(tempfile.mkdtemp(prefix='.prepare-mount-', dir=destination.parent))
    try:
        _command('/usr/bin/hdiutil', 'create', '-size', f'{capacity_gib}g', '-type', 'SPARSE',
                 '-fs', 'APFS', '-volname', 'stallionfs', '-uid', os.getuid(), '-gid', os.getgid(),
                 '-mode', '0700', '-nospotlight', destination)
        _image(destination)
        repo = attach(destination, point)
        # APFS creation can ignore hdiutil's requested root mode; enforce it on the mounted root.
        os.chown(point, os.getuid(), os.getgid())
        os.chmod(point, 0o700)
        _directory(point)
        _command('/usr/bin/ditto', source, repo)
        detach(destination, point)
        fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
        finally:
            os.close(fd)
        return destination
    except BaseException as original:
        if destination.exists():
            try:
                state = mounted(destination)
                if state:
                    detach(destination, point)
            except BaseException as cleanup:
                interrupted = cleanup if not isinstance(cleanup, Exception) else original
                _recovery_failure(interrupted, f"Preparation failed; keep image {destination} and mount {point}: {cleanup}")
        raise
    finally:
        # rmdir cannot traverse data or remove a live mount; no recursive cleanup here.
        try:
            point.rmdir()
        except OSError:
            pass
