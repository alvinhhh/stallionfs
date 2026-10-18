"""Additional deterministic fixtures for the native comparison suite."""
import json
import os
import random
import struct
import zlib


PROFILES = {'photo_library': {'files': 2000, 'width': 1024, 'height': 768},
            'deep_20000': {'files': 20000, 'depth': 40}}


def png_chunk(kind, payload):
    return struct.pack('>I', len(payload)) + kind + payload + struct.pack('>I', zlib.crc32(kind + payload))


def photo_library(root, *, files=2000, width=1024, height=768):
    """Write valid PNG images and JSON sidecars; pixels are synthetic, not photographs."""
    if min(files, width, height) <= 0 or max(width, height) > 4096:
        raise ValueError('Invalid photo fixture dimensions')
    root.mkdir(mode=0o750)
    rng = random.Random(20261010)
    header = b'\x89PNG\r\n\x1a\n' + png_chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
    for index in range(files):
        pixels = b''.join(b'\0' + rng.randbytes(width * 3) for _ in range(height))
        compressed = zlib.compress(pixels, level=1)
        folder = root / str(2020 + index // 1200) / f'{index // 100 % 12 + 1:02}'
        folder.mkdir(parents=True, mode=0o750, exist_ok=True)
        image = (header + png_chunk(b'tEXt', f'Fixture\0Image {index}'.encode())
                 + png_chunk(b'IDAT', compressed) + png_chunk(b'IEND', b''))
        path = folder / f'IMG_{index:06}.png'
        with path.open('xb') as stream:
            if stream.write(image) != len(image): raise OSError('Short fixture write')
        path.chmod(0o640)
        sidecar = path.with_suffix('.json')
        with sidecar.open('x') as stream:
            json.dump({'id': index, 'rating': index % 6, 'width': width, 'height': height}, stream)
        sidecar.chmod(0o640)
    return root


def deep_tree(root, *, files=20000, depth=40):
    if files <= 0 or not 1 <= depth <= 100:
        raise ValueError('Invalid deep-tree dimensions')
    root.mkdir(mode=0o750)
    chain, parent = [], root
    for _ in range(depth):
        parent = parent / 'd'
        parent.mkdir(mode=0o750)
        chain.append(parent)
    for index in range(files):
        path = chain[index * depth // files] / f'file-{index:06}'
        with path.open('xb') as stream:
            payload = index.to_bytes(8, 'little') + bytes([index % 256]) * 504
            if stream.write(payload) != len(payload): raise OSError('Short fixture write')
        path.chmod(0o640)
    (chain[-1] / 'relative-link').symlink_to('file-' + f'{files-1:06}')
    (root / 'dangling-link').symlink_to('absent')
    return root


LOCKED_FILES = ('package.json', 'package-lock.json', 'check.cjs')


def installed_dependencies(root, *, node, npm, cache, receipt, checkpoint, timeout):
    """Prepare the locked, offline npm tree; caller owns cleanup and receipts."""
    import os
    from pathlib import Path
    import shutil
    import fileops

    locked = Path(__file__).parent / 'fixture'
    node, npm, cache = (Path(path).resolve(strict=True) for path in (node, npm, cache))
    fileops.require(node.is_file() and os.access(node, os.X_OK) and npm.is_file() and cache.is_dir(),
                    'Require executable Node, npm CLI script and existing isolated npm cache')
    npm_manifest = npm.parent.parent/'package.json'
    npm_package = json.loads(npm_manifest.read_text())
    fileops.require(npm_package.get('name') == 'npm', 'Require npm package bin/npm-cli.js entrypoint')
    root.mkdir(mode=0o700)
    receipt.update(root=str(root), cache=str(cache), node_path=str(node), npm_cli_path=str(npm),
                   node_sha256=fileops.digest(node), npm_entrypoint_sha256=fileops.digest(npm),
                   npm_package_manifest=str(npm_manifest), npm_package_manifest_sha256=fileops.digest(npm_manifest),
                   npm_package_version=npm_package['version'],
                   runtime_pin_scope='Node executable, npm entrypoint and package manifest only; npm package tree is not fully pinned',
                   locked_inputs={name: fileops.digest(locked/name) for name in LOCKED_FILES}, commands=[])
    for name in LOCKED_FILES:
        shutil.copy2(locked/name, root/name)
    environment = {key: value for key, value in os.environ.items()
                   if not key.lower().startswith('npm_config_') and key not in ('NODE_OPTIONS', 'NODE_PATH')}
    def command(argv):
        row = {'argv': [str(value) for value in argv]}
        receipt['commands'].append(row); checkpoint()
        result = fileops.command(argv, check=False, timeout=timeout, environment=environment)
        row.update(exit_code=result.returncode, stdout=result.stdout.decode(errors='replace'),
                   stderr=result.stderr.decode(errors='replace'))
        checkpoint()
        fileops.require(result.returncode == 0, 'Locked dependency preparation failed; see command receipt')
        return row['stdout'].strip()
    receipt['node_version'] = command([node, '--version'])
    fileops.require(int(receipt['node_version'].removeprefix('v').split('.')[0]) >= 24,
                    'Locked fixture requires Node 24 or newer')
    receipt['node_platform'] = json.loads(command([node, '-p', 'JSON.stringify({platform:process.platform,arch:process.arch})']))
    runtime = receipt['node_platform']
    fileops.require(runtime.get('platform') == 'darwin' and runtime.get('arch') in ('arm64', 'x64'),
                    'Require macOS Node arm64 or x64 runtime')
    user_config, global_config = root/'empty-user.npmrc', root/'empty-global.npmrc'
    user_config.write_text(''); global_config.write_text('')
    npm_argv = [node, npm, '--prefix', root, '--userconfig', user_config, '--globalconfig', global_config, '--cache', cache]
    receipt['npm_version'] = command([*npm_argv, '--version'])
    fileops.require(receipt['npm_version'] == receipt['npm_package_version'], 'npm version differs from package manifest')
    command([*npm_argv, 'ci', '--offline', '--ignore-scripts', '--no-audit', '--no-fund'])
    source = root/'node_modules'
    fileops.require(source.is_dir() and not source.is_symlink(), 'Installed dependency tree missing')
    declared = json.loads((root/'package.json').read_text())['dependencies']
    installed = {name: json.loads((source/name/'package.json').read_text())['version'] for name in declared}
    fileops.require(installed == declared, 'Installed direct dependency versions differ from locked fixture')
    lock = json.loads((root/'package-lock.json').read_text())
    platform_package = '@typescript/typescript-' + runtime['platform'] + '-' + runtime['arch']
    locked_platform = lock['packages'].get('node_modules/'+platform_package)
    fileops.require(locked_platform is not None, 'TypeScript platform package missing from locked inputs')
    platform_manifest = source/platform_package/'package.json'
    fileops.require(platform_manifest.is_file(), 'Installed TypeScript platform package missing')
    installed_platform = json.loads(platform_manifest.read_text())
    fileops.require(installed_platform.get('version') == locked_platform['version'], 'TypeScript platform version differs from lock')
    receipt['typescript_platform'] = {'name':platform_package, 'version':installed_platform['version']}
    command([node, root/'check.cjs'])
    receipt['typescript_cli_version'] = command([node, source/'typescript/bin/tsc', '--version'])
    fileops.require(receipt['typescript_cli_version'] == 'Version '+installed['typescript'], 'TypeScript CLI version differs from lock')
    fileops.require(all(fileops.digest(root/name) == expected and fileops.digest(locked/name) == expected
                        for name, expected in receipt['locked_inputs'].items()), 'Locked fixture input changed')
    fileops.require(fileops.digest(node) == receipt['node_sha256'] and fileops.digest(npm) == receipt['npm_entrypoint_sha256']
                    and fileops.digest(npm_manifest) == receipt['npm_package_manifest_sha256'], 'Dependency runtime changed')
    receipt.update(dependencies=installed, source=str(source), installed_lock_sha256=fileops.digest(source/'.package-lock.json'),
                   status='prepared', policy='offline npm ci; lifecycle scripts, audit and funding disabled; no cache cleanup')
    checkpoint()
    return source


SCAN_PROFILES = {"scan_flat_20k": "flat", "scan_nested_20k": "nested", "scan_deep40_20k": "deep40"}


METADATA_XATTRS = {b'user.stallionfs-test': b'user attribute\x00\xff',
                  b'com.apple.ResourceFork': b'resource\x00fork\xff'}


def enrich_metadata(root, *, receipt, scan_layout=None):
    """Enrich an owned disposable fixture; return the coverage contract to verify."""
    import ctypes
    import fcntl
    import stat
    import fileops

    info = root.lstat()
    receipt.update(added_directories=0, added_regular_entries=0, added_logical_bytes=0,
                   added_unique_data_bytes=0, added_xattr_value_bytes=sum(map(len, METADATA_XATTRS.values())),
                   resource_fork_bytes=len(METADATA_XATTRS[b'com.apple.ResourceFork']))
    if stat.S_ISREG(info.st_mode):
        data, relative, alias = root, '', None
        receipt.update(data_size=info.st_size, sparse=None, hardlinks=None)
    elif stat.S_ISDIR(info.st_mode):
        if scan_layout is not None:
            fileops.require(scan_layout in SCAN_PROFILES.values(), 'Unknown scan layout')
            parent = root.joinpath(*(['d'] * 40)) if scan_layout == 'deep40' else root
            data, alias = parent/'sparse', parent/'hard-link'
            receipt['sparse'] = {'size': 1 << 20, 'interior': [0, 1 << 20], 'endpoints': False}
        else:
            parent = root/'metadata-fixture'
            parent.mkdir(mode=0o750)
            (parent/'subdir').mkdir(mode=0o750)
            data, alias = parent/'sparse', parent/'subdir'/'alias'
            with data.open('xb') as stream:
                if stream.write(b'x') != 1: raise OSError('Short fixture write')
                stream.seek(8*1024*1024-1)
                if stream.write(b'y') != 1: raise OSError('Short fixture write')
                stream.flush(); os.fsync(stream.fileno())
                # Punch an aligned interior hole; seeking alone does not prove sparse coverage.
                fcntl.fcntl(stream.fileno(), 99, struct.pack('=IIqq', 0, 0, 1024*1024, 6*1024*1024))
                os.fsync(stream.fileno())
            data.chmod(0o640)
            os.link(data, alias)
            receipt.update(added_directories=2, added_regular_entries=2,
                           added_logical_bytes=16*1024*1024, added_unique_data_bytes=8*1024*1024,
                           sparse={'size': 8*1024*1024, 'interior': [1024*1024, 7*1024*1024], 'endpoints': True})
        relative = str(data.relative_to(root))
        receipt['hardlinks'] = sorted([relative, str(alias.relative_to(root))])
        receipt['data_size'] = receipt['sparse']['size']
    else:
        raise ValueError('Metadata fixture must be a regular file or directory')
    receipt['path'] = relative
    fileops.require(stat.S_ISREG(data.lstat().st_mode), 'Metadata target must be a regular file')
    for name, value in METADATA_XATTRS.items():
        if hasattr(os, 'setxattr'):
            os.setxattr(data, name, value, follow_symlinks=False)
        else:
            libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
            libc.setxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
                                     ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
            libc.setxattr.restype = ctypes.c_int
            if libc.setxattr(os.fsencode(data), name, value, len(value), 0, 1):
                error = ctypes.get_errno(); raise OSError(error, os.strerror(error), str(data))
    receipt['acl_command'] = {'argv': ['/bin/chmod', '+a', 'everyone allow read', str(data)],
                              'exit_code': None}
    result = fileops.command(receipt['acl_command']['argv'], check=False)
    receipt['acl_command'].update(exit_code=result.returncode,
                                  stderr=result.stderr.decode(errors='replace'))
    fileops.require(result.returncode == 0, 'Metadata ACL setup failed')
    return receipt


def verify_metadata_coverage(observed, receipt):
    """Reject unavailable or vacuous feature coverage before any measurement."""
    import hashlib
    import fileops

    fileops.require(not observed['unavailable_fields'], 'Metadata observation unavailable')
    entry = observed['entries'][receipt['path']]
    fileops.require(entry['kind'] == 'file' and entry['size'] == receipt['data_size'], 'Metadata file size changed')
    acl = entry['acl']
    text = bytes.fromhex(acl['text_hex']) if acl['text_hex'] else b''
    fileops.require(acl['unavailable'] is None and any(
        len(parts := line.split(b':')) >= 6 and parts[0] == b'group' and parts[2] == b'everyone'
        and parts[-2:] == [b'allow', b'read'] for line in text.splitlines()), 'Seeded ACL entry missing')
    fileops.require(all(entry['xattrs'].get(name.hex()) == value.hex()
                        for name, value in METADATA_XATTRS.items()), 'Seeded xattr or resource fork missing')
    group = receipt['hardlinks']
    if group is not None:
        fileops.require(group in observed['hardlink_groups'] and all(
            observed['entries'][path]['device_inode'] == entry['device_inode'] for path in group),
            'Seeded hardlink topology missing')
    sparse = receipt['sparse']
    if sparse is not None:
        holes = entry['holes']['ranges']
        start, end = sparse['interior']
        fileops.require(bool(holes) and entry['allocated_bytes'] < entry['size']
                        and any(a <= start and b >= end for a, b in holes), 'Seeded sparse hole missing')
        payload = (b'x' + bytes(sparse['size']-2) + b'y') if sparse['endpoints'] else bytes(sparse['size'])
        fileops.require(entry['sha256'] == hashlib.sha256(payload).hexdigest(), 'Sparse payload changed')
    entries = observed['entries'].values()
    return {'populated': True, 'seeded_acl_text_bytes': len(text),
            'counts_include_root': True,
            'regular_files': sum(row['kind'] == 'file' for row in entries),
            'directories': sum(row['kind'] == 'directory' for row in entries),
            'symlinks': sum(row['kind'] == 'symlink' for row in entries),
            'special_entries': sum(row['kind'] == 'special' for row in entries),
            'logical_bytes': sum(row.get('size', 0) for row in entries)}


def scan_fixture(path, files, layout):
    path.mkdir()
    chain, parent = [], path
    if layout == 'deep40':
        for _ in range(40):
            parent = parent / 'd'
            parent.mkdir()
            chain.append(parent)
    for i in range(files):
        parent = (chain[i * 40 // files] if chain else
                  path / str(i // 100) if layout == 'nested' else path)
        if layout == 'nested' and i % 100 == 0:
            parent.mkdir()
        (parent / f'file-{i}').write_bytes(bytes([i % 256]) * (i % 1024))
    extras = chain[-1] if chain else path
    (extras / 'empty').mkdir()
    (extras / 'space and \n café 🐎').write_bytes(b'hello')
    (extras / 'directory-link').symlink_to('empty', target_is_directory=True)
    (extras / 'dangling-link').symlink_to('absent')
    (extras / 'outside-link').symlink_to('/')
    os.mkfifo(extras / 'pipe')
    with (extras / 'sparse').open('wb') as stream:
        stream.truncate(1 << 20)
    os.link(extras / 'sparse', extras / 'hard-link')
    return dict(files=files + 3,
                directories=1 + (40 if chain else (files + 99) // 100 if layout == 'nested' else 0),
                symlinks=3, other=1, logical_bytes=sum(i % 1024 for i in range(files)) + 5 + (2 << 20),
                skipped_mounts=0)
