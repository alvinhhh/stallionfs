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

from .core import StallionError


class _CommandFailure(StallionError):
    """A completed native command, distinct from validation or launch failures."""
    def __init__(self, args, result):
        self.args_native = tuple(str(arg) for arg in args)
        self.returncode = result.returncode
        self.stdout, self.stderr = result.stdout, result.stderr
        super().__init__(f"{args[0]} failed ({result.returncode}): "
                         + result.stderr.decode(errors='replace').strip())


def _error(message):
    return StallionError(message)


def _require_supported():
    version = platform.mac_ver()[0]
    if sys.platform != 'darwin' or not version or int(version.split('.')[0]) < 26:
        raise _error('APFS image workspaces require macOS 26 or newer')


def _command(*args):
    result = subprocess.run([str(a) for a in args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, umask=0o077)
    if result.returncode:
        raise _CommandFailure(args, result)
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
    inventory = _plist('/usr/bin/hdiutil', 'info', '-plist').get('images')
    if not isinstance(inventory, list):
        raise _error('Invalid image attachment inventory')
    for entry in inventory:
        recorded = entry.get('image-path') if isinstance(entry, dict) else None
        if (not isinstance(recorded, str) or not recorded or '\0' in recorded
                or not Path(recorded).is_absolute()):
            raise _error('Invalid image attachment path in inventory')
        try:
            recorded_image = Path(recorded).resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise _error('Cannot classify image attachment path in inventory') from error
        if recorded_image != image:
            continue
        if entry.get('owner-uid') != os.getuid():
            raise _error(f"Image attachment belongs to another user: {image}")
        matches.append(entry)
    after = image.stat()
    if (identity.st_dev, identity.st_ino) != (after.st_dev, after.st_ino):
        raise _error(f"Image changed while checking its attachment: {image}")
    if len(matches) > 1:
        raise _error(f"Image has multiple attachments; inspect before continuing: {image}")
    if matches:
        selected_entities = matches[0].get('system-entities')
        if not isinstance(selected_entities, list):
            raise _error(f'Invalid attachment entity metadata: {image}')
        devices = {e.get('dev-entry') for e in selected_entities
                   if isinstance(e, dict) and isinstance(e.get('dev-entry'), str)}
        for entry in inventory:
            if entry is matches[0]:
                continue
            entities = entry.get('system-entities')
            if (not isinstance(entities, list) or not entities or
                    any(not isinstance(e, dict) or not isinstance(e.get('dev-entry'), str) or
                        not re.fullmatch(r'/dev/disk[0-9]+(?:s[0-9]+)*', e['dev-entry']) for e in entities)):
                raise _error('Invalid image attachment entities in inventory')
            if any(isinstance(e.get('dev-entry'), str) and e['dev-entry'] in devices for e in entities):
                raise _error(f'Ambiguous image attachment devices: {image}')
    return matches


def mounted(image):
    """Return verified attachment metadata, including an unmounted device, or None."""
    image = _image(image)
    matches = _attachments(image)
    if not matches:
        return None
    entry = matches[0]
    entities = entry.get('system-entities', [])
    if not isinstance(entities, list) or not all(isinstance(e, dict) for e in entities):
        raise _error(f"Invalid attachment entity metadata: {image}")
    devices = [e.get('dev-entry') for e in entities]
    if not devices or not all(isinstance(d, str) and re.fullmatch(r'/dev/disk[0-9]+(?:s[0-9]+)*', d) for d in devices):
        raise _error(f"Invalid attachment device metadata: {image}")
    if len(set(devices)) != len(devices):
        raise _error(f"Duplicate attachment devices: {image}")
    whole = [d for d in devices if re.fullmatch(r'/dev/disk[0-9]+', d)]
    if not whole:
        raise _error(f"Image attachment has no disk device: {image}")
    volumes = [e for e in entities if e.get('mount-point')]
    if len(volumes) > 1:
        raise _error(f"Image unexpectedly contains multiple mounted volumes: {image}")
    # Serialize the complete inventory entry from this same read. Bytes preserve
    # ordered entities and cannot be changed through a later caller's dictionary.
    mapping = {'image': str(image), 'device': whole[0], 'mountpoint': None, 'volume_device': None,
               'attachment': plistlib.dumps(entry, fmt=plistlib.FMT_BINARY)}
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


def _backing_identity(image):
    info = _image(image).lstat()
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink


def _device_identity(device):
    info = os.lstat(device)
    if not stat.S_ISBLK(info.st_mode):
        raise _error(f'Expected a block device: {device}')
    return info.st_dev, info.st_ino, info.st_rdev, info.st_mode


def _unmounted_snapshot(current, point):
    entry = plistlib.loads(current['attachment'])
    for entity in entry['system-entities']:
        if 'mount-point' in entity:
            if entity['mount-point'] != str(point):
                raise _error('Unexpected attachment mount metadata')
            del entity['mount-point']
    return plistlib.dumps(entry, fmt=plistlib.FMT_BINARY)


def _no_graph_mounts(current, point):
    from ._scan import mounts
    devices = {e['dev-entry'] for e in plistlib.loads(current['attachment'])['system-entities']}
    records = mounts()
    if (not isinstance(records, list) or any(not isinstance(r, dict) or
            not isinstance(r.get('device'), str) or not r['device'] or
            not isinstance(r.get('path'), str) or not r['path'].startswith('/') for r in records)):
        raise _error('Unknown mount inventory; preserve the image')
    if os.path.ismount(point) or any(r['device'] in devices or r['path'] == str(point) for r in records):
        raise _error('An image device or expected mountpoint is still mounted; preserve the image')


def _completed_eject_failure(error, device):
    # Exit statuses are not errno values. Match the observed diagnostic exactly;
    # fresh inventories must independently prove partial unmount below.
    return (isinstance(error, _CommandFailure) and error.returncode == 1 and
            error.args_native == ('/usr/sbin/diskutil', 'eject', device) and
            error.stdout.strip() in (b'', f'Eject failed for {device.removeprefix("/dev/")}'.encode()) and
            error.stderr.strip() == b'Volume failed to eject')


def detach(image, mountpoint):
    """Detach only this image's verified device, never forcibly and never deleting data."""
    image, point = _image(image), _path(mountpoint)
    _directory(point.parent)
    identity = _backing_identity(image)
    current = mounted(image)
    if not current:
        if os.path.ismount(point):
            raise _error(f"Mountpoint belongs to another device: {point}")
        return
    if current['mountpoint'] not in (None, str(point)):
        raise _error(f"Image is mounted at a different path: {current['mountpoint']}")
    if (current['image'] != str(image) or
            not re.fullmatch(r'/dev/disk[0-9]+', current['device'])):
        raise _error(f"Invalid image attachment target: {image}")
    # Keep the selected device from this owned image; never choose another
    # whole device if its attachment mapping changes before the command.
    device_identity = _device_identity(current['device'])
    confirmed = mounted(image)
    if (confirmed != current or identity != _backing_identity(image) or
            device_identity != _device_identity(current['device'])):
        raise _error(f"Image attachment changed before eject: {image}")

    def verify_absent():
        if mounted(image) is not None or identity != _backing_identity(image):
            raise _error(f"Image remains attached or changed; keep its files: {image}")
        _no_graph_mounts(current, point)

    try:
        _command('/usr/sbin/diskutil', 'eject', current['device'])
    except _CommandFailure as original:
        if not _completed_eject_failure(original, current['device']):
            raise
        try:
            if current['mountpoint'] != str(point):
                raise _error('Eject did not begin with the expected mounted image')
            expected = dict(current, mountpoint=None, volume_device=None,
                            attachment=_unmounted_snapshot(current, point))
            # Two fresh normal inventory reads, each with independent mount-table
            # checks, admit only the original graph with its mount-point removed.
            for _ in range(2):
                if mounted(image) != expected:
                    raise _error('Image attachment did not become the same unmounted graph')
                _no_graph_mounts(current, point)
                if (identity != _backing_identity(image) or
                        device_identity != _device_identity(current['device'])):
                    raise _error('Image or selected device identity changed before continuation')
            # This narrows name reuse races; diskutil-by-name is not atomic with
            # external detach/reattach, even under a managed workspace lock.
            _command('/usr/sbin/diskutil', 'eject', current['device'])
            verify_absent()
        except BaseException as recovery:
            original.add_note(f'Eject continuation refused or failed; keep {image}: '
                              f'{type(recovery).__name__}: {recovery}')
            if not isinstance(recovery, Exception):
                recovery.add_note(f'First eject failure: {original}')
                raise
            raise original from recovery
        return
    verify_absent()


def flush(image):
    """Flush a verified closed backing image without attaching it."""
    image = _image(image)
    before = image.stat()
    if mounted(image) is not None:
        raise _error(f'Detach the image before flushing: {image}')
    fd = os.open(image, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise _error(f'Image changed before flushing: {image}')
        fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
    finally:
        os.close(fd)
    after = image.stat()
    if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino) or mounted(image) is not None:
        raise _error(f'Image changed while flushing: {image}')


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
    detach_attempted = False
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
        detach_attempted = True
        detach(destination, point)
        flush(destination)
        return destination
    except BaseException as original:
        if not detach_attempted and destination.exists():
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
