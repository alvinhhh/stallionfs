"""Stage the final app ZIP from an already sealed and stapled StallionFS app."""

import argparse
from contextlib import contextmanager
import ctypes
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import package_fskit as package


APP_NAME = 'StallionFS.app'
ARCHIVE_NAME = 'StallionFS.zip'
BINDINGS_NAME = 'final-maintenance-bindings.json'
DITTO_OPTIONS = ('--norsrc', '--noextattr', '--noacl', '--noqtn')
TRANSPORT_XATTRS = {b'com.apple.quarantine', b'com.apple.provenance'}
XATTR_NOFOLLOW = 0x0001
DEVELOPER_ID_APPLICATION = (
    'certificate 1[field.1.2.840.113635.100.6.2.6] exists and '
    'certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
)


@contextmanager
def held_directory(path):
    descriptor = package._runtime_directory(path)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def require_named(path, descriptor):
    with held_directory(path) as current:
        if not os.path.samestat(os.fstat(current), os.fstat(descriptor)):
            raise ValueError(f'Directory changed during staging: {path}')


@contextmanager
def private_staging(release_parent):
    staging = Path(tempfile.mkdtemp(prefix='stallionfs-distribution-', dir=release_parent))
    try:
        yield staging
    except BaseException as error:
        error.add_note(f'Private staging path: {staging}')
        raise


def inspect_metadata(app, rows, staging):
    if package._tool_output(['/usr/bin/find', '-P', str(app), '-acl', '-print', '-quit'], staging):
        raise ValueError('App has an ACL the exact ZIP cannot carry')
    # Darwin returns NUL-separated names directly, including on a symlink itself.
    listxattr = ctypes.CDLL(None, use_errno=True).listxattr
    listxattr.argtypes = (ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
    listxattr.restype = ctypes.c_ssize_t
    buffer = ctypes.create_string_buffer(64 * 1024)
    flags = {}
    for relative in ('.', *(row['path'] for row in rows)):
        path = app / relative
        if entry_flags := path.lstat().st_flags:
            flags[relative] = entry_flags
        length = listxattr(os.fsencode(path), buffer, len(buffer), XATTR_NOFOLLOW)
        if not 0 <= length <= len(buffer):
            error = ctypes.get_errno()
            raise OSError(error, f'Could not inspect app extended attributes: {relative}')
        if length:
            raw = buffer[:length]
            if not raw.endswith(b'\x00') or set(raw[:-1].split(b'\x00')) - TRANSPORT_XATTRS:
                raise ValueError(f'App has extended attributes the exact ZIP cannot carry: {relative}')
    return flags


def verify_distribution(app, descriptor, bindings, staging):
    requirement = next(role['requirement'] for role in bindings['signing_roles'] if role['path'] == '.')
    require_named(app, descriptor)
    try:
        package._tool_output(['/usr/bin/codesign', '--verify', '--strict', '-R',
                              f'{requirement} and {DEVELOPER_ID_APPLICATION}', str(app)], staging)
    except (ValueError, subprocess.TimeoutExpired) as error:
        raise ValueError('Extracted app failed Developer ID Application verification') from error
    require_named(app, descriptor)
    try:
        package._tool_output(['/usr/bin/xcrun', 'stapler', 'validate', str(app)], staging)
    except (ValueError, subprocess.TimeoutExpired) as error:
        raise ValueError('Extracted app failed stapled notarization ticket validation') from error


def build_distribution(app, release_parent, publisher):
    if app.name != APP_NAME:
        raise ValueError(f'App must be named {APP_NAME}')
    with held_directory(app) as source_fd, held_directory(release_parent) as parent_fd:
        if stat.S_IMODE(os.fstat(parent_fd).st_mode) != 0o700:
            raise ValueError('Release parent must be owned and private (0700)')
        source = os.fstat(source_fd)
        if any(os.path.samestat(source, path.lstat()) for path in (release_parent, *release_parent.parents)):
            raise ValueError('Release parent must be outside the input app')
        require_named(app, source_fd)
        require_named(release_parent, parent_fd)
        if package._tool_output(['/usr/bin/find', '-P', str(release_parent), '-maxdepth', '0',
                                 '-acl', '-print', '-quit'], release_parent):
            raise ValueError('Release parent must have no ACL')
        require_named(release_parent, parent_fd)
        with private_staging(release_parent) as staging, held_directory(staging) as staging_fd:
            def require_staging():
                require_named(release_parent, parent_fd)
                require_named(staging, staging_fd)

            source_rows = package._runtime_inventory(app, source_fd)
            source_flags = inspect_metadata(app, source_rows, staging)
            require_named(app, source_fd)
            require_staging()
            archive = staging / ARCHIVE_NAME
            package._tool_output(['/usr/bin/ditto', '-c', '-k', '--keepParent', *DITTO_OPTIONS,
                                  str(app), str(archive)], staging)
            require_named(app, source_fd)
            require_staging()
            archive_identity = package._runtime_identity(archive.lstat())
            source_bindings = package.final_maintenance_bindings(app, archive, expected_publisher=publisher)
            if source_bindings['inventory'] != source_rows:
                raise ValueError('Source app changed during archive staging')
            require_named(app, source_fd)
            require_staging()
            archive_digest = package._runtime_sha(package._runtime_read_at(staging_fd, ARCHIVE_NAME))
            if archive_digest != source_bindings['archive']['sha256']:
                raise ValueError('Verified ZIP changed before extraction')

            def require_archive():
                if package._runtime_identity(archive.lstat()) != archive_identity:
                    raise ValueError('Verified ZIP changed during staging')

            extracted = staging / '.verification'
            os.mkdir(extracted.name, 0o700, dir_fd=staging_fd)
            with held_directory(extracted) as extract_fd:
                require_staging()
                require_named(extracted, extract_fd)
                require_archive()
                package._tool_output(['/usr/bin/ditto', '-x', '-k', str(archive), str(extracted)], staging)
                require_staging()
                require_named(extracted, extract_fd)
                require_archive()
                if os.listdir(extract_fd) != [APP_NAME]:
                    raise ValueError('ZIP extraction must contain only StallionFS.app')
                restored = extracted / APP_NAME
                with held_directory(restored) as restored_fd:
                    if package.final_maintenance_bindings(restored, archive, expected_publisher=publisher) != source_bindings:
                        raise ValueError('Extracted app does not match source bindings')
                    require_named(restored, restored_fd)
                    verify_distribution(restored, restored_fd, source_bindings, staging)
                    require_named(restored, restored_fd)
                    if package._runtime_inventory(restored, restored_fd) != source_rows:
                        raise ValueError('Extracted app changed during distribution checks')
                    if inspect_metadata(restored, source_rows, staging) != source_flags:
                        raise ValueError('Extracted app filesystem flags differ from the source')
                    require_named(restored, restored_fd)
                require_staging()
                require_named(extracted, extract_fd)
                if os.listdir(extract_fd) != [APP_NAME]:
                    raise ValueError('Verification directory changed after extraction')
                shutil.rmtree(extracted.name, dir_fd=staging_fd)

            require_staging()
            require_named(app, source_fd)
            if (package._runtime_inventory(app, source_fd) != source_rows
                    or inspect_metadata(app, source_rows, staging) != source_flags):
                raise ValueError('Source app changed during distribution checks')
            require_named(app, source_fd)
            require_staging()
            require_archive()
            data = (json.dumps(source_bindings, sort_keys=True, indent=2) + '\n').encode()
            package._runtime_write_at(staging_fd, '.bindings', data, 0o600)
            os.rename('.bindings', BINDINGS_NAME, src_dir_fd=staging_fd, dst_dir_fd=staging_fd)
            require_staging()
    return staging


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', required=True, type=Path, help='Admitted sealed and stapled StallionFS.app')
    parser.add_argument('--release-parent', required=True, type=Path, help='Owned private output parent (0700)')
    parser.add_argument('--publisher', required=True, help='Independently selected Apple Developer team ID')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('macOS is required')
    try:
        staging = build_distribution(args.app, args.release_parent, args.publisher)
    except (OSError, ValueError, subprocess.TimeoutExpired, zipfile.BadZipFile) as error:
        lines = [f'Distribution ZIP staging failed: {error}', *getattr(error, '__notes__', [])]
        parser.exit(1, '\n'.join(lines) + '\n')
    print(staging)


if __name__ == '__main__':
    main()
