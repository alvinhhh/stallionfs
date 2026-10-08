"""Paired steady-state I/O through ordinary APIs, normal APFS vs a shipped workspace.

Creates only owned disposable fixtures. Does not include image mount lifecycle,
which has its own benchmark. Publishes no result until checks and cleanup pass.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import random
import shutil
import statistics
import subprocess
import sys
import tempfile


REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO), str(Path(__file__).resolve().parent)]
from stallionfs import _scan, images
from stallionfs.core import Store, git, remove_tree, write_json
from fileops import digest as hash_file

spec = importlib.util.spec_from_file_location('fs_volume', REPO / 'tests' / 'fs_volume.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def command(*arguments):
    return subprocess.check_output([str(value) for value in arguments], stderr=subprocess.PIPE)


def volume_info(path):
    device = command('/bin/df', '-P', path).decode().splitlines()[-1].split()[0]
    detail = plistlib.loads(command('/usr/sbin/diskutil', 'info', '-plist', device))
    if detail.get('FilesystemType') != 'apfs':
        raise RuntimeError('Both compared locations must use APFS')
    mount = next((line for line in command('/sbin/mount').decode().splitlines()
                  if line.startswith(device + ' on ')), None)
    if mount is None or ' (' not in mount or not mount.endswith(')'):
        raise RuntimeError('Could not record actual mount flags')
    return {
        **{key: detail.get(key) for key in (
            'FilesystemType', 'FilesystemName', 'BlockSize', 'DeviceBlockSize',
            'VolumeSize', 'Journaled', 'WritableVolume', 'GlobalPermissionsEnabled',
        )},
        'mount_flags': mount.rsplit(' (', 1)[1][:-1].split(', '),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True,
                        help='Existing APFS directory for disposable fixtures')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    scratch_root = args.scratch.resolve()
    if not scratch_root.is_dir():
        parser.error('scratch must be an existing directory')
    volume_info(scratch_root)
    output = args.output.resolve()
    if output.exists():
        parser.error('output already exists; keep earlier results intact')
    if not output.parent.is_dir():
        parser.error('output parent directory must exist')
    if shutil.disk_usage(scratch_root).free < 4 * 1024 ** 3:
        raise RuntimeError('At least four GiB of host free space is required')
    sources = {
        path.relative_to(REPO).as_posix(): hash_file(path)
        for path in (REPO / 'stallionfs' / 'core.py', REPO / 'stallionfs' / 'images.py',
                     REPO / 'stallionfs' / '_scan.c', REPO / 'tests' / 'fs_volume.py',
                     Path(__file__).with_name('fileops.py'))
    }
    report = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'system': platform.platform(), 'python': platform.python_version(),
        'hardware': {key: command('/usr/sbin/sysctl', '-n', key).decode().strip()
                     for key in ('hw.model', 'machdep.cpu.brand_string', 'hw.memsize', 'hw.logicalcpu')},
        'source_sha256': sources, 'driver_sha256': hash_file(Path(__file__)),
        'native_binary_sha256': hash_file(Path(_scan.__file__)),
        'samples': 7, 'warmups': 1,
        'notes': [
            'Compares ordinary OS file APIs inside a normal APFS directory and an APFS image workspace.',
            'Image workspace is prepared and created by the shipped Store API with capacity 2 GiB.',
            'Only already-mounted steady-state I/O is timed; image preparation, mounting and final cleanup are excluded.',
            'One warmup pair is discarded. Seven paired rounds use deterministic shuffled order.',
            'Both methods use the same generated contents and validation; all raw samples and losses are retained.',
            'Python overhead and inline content/type/size validation are included equally.',
            'Read and stat caches are warm; no cache purges or global settings are changed.',
            'Only fullfsync-labeled write timings request durable completion; buffered creates do not.',
            'Successful fsync/fullfsync does not establish power-loss, controller-cache or device-failure recovery.',
            'The image uses shipped mount options, including enabled ownership and disabled Spotlight indexing.',
            'Speedup is folder median divided by image median; values below 1 mean the image is slower.',
        ],
        'compatibility': {}, 'volumes': {},
        'order': [], 'rows': {'apfs_folder': [], 'apfs_image': []},
    }
    base = Path(tempfile.mkdtemp(prefix='steady-io-', dir=scratch_root)).resolve()
    store = None
    workspace = None
    try:
        source = base / 'source'
        source.mkdir(mode=0o700)
        git(source, 'init', '-b', 'main')
        (source / 'fixture').write_bytes(b'stallionfs steady-state I/O fixture\n')
        git(source, 'add', '.')
        git(source, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
            'commit', '-m', 'fixture')
        store = Store(base / 'store')
        seed = store.prepare(source, key='steady-io-fixture-v1', image_size=2)
        workspace = store.create(seed['id'], name='steady-io')
        folder = base / 'ordinary'
        folder.mkdir(mode=0o700)
        roots = {'apfs_folder': folder, 'apfs_image': Path(workspace['path'])}
        # Identical starting content, with Git housekeeping outside both timed subtrees.
        (folder / 'fixture').write_bytes((source / 'fixture').read_bytes())
        checks.require((roots['apfs_image'] / 'fixture').read_bytes() == (folder / 'fixture').read_bytes(),
                       'Prepared fixture differs from ordinary folder')
        for name, root in roots.items():
            report['volumes'][name] = volume_info(root)
            scratch = root / 'compatibility'
            scratch.mkdir(mode=0o700)
            report['compatibility'][name] = checks.compatibility(scratch)
            shutil.rmtree(scratch)
        signatures = [{key: value for key, value in report['compatibility'][name].items()
                       if key != 'atomic_replace_reads'} for name in roots]
        checks.require(signatures[0] == signatures[1], 'Filesystem compatibility differs')
        rng = random.Random(20261007)
        for sample in range(8):
            order = list(roots)
            rng.shuffle(order)
            report['order'].append({'round': sample, 'warmup': sample == 0, 'methods': order})
            for name in order:
                scratch = roots[name] / f'round-{sample}'
                scratch.mkdir(mode=0o700)
                row = checks.performance(scratch)
                shutil.rmtree(scratch)
                if sample:
                    report['rows'][name].append(row)
                print(json.dumps({'round': sample, 'warmup': sample == 0, 'method': name,
                                  'seconds': {key: round(value, 6) for key, value in row.items()}}), flush=True)
        report['medians'] = {
            name: {key: statistics.median(row[key] for row in rows) for key in rows[0]}
            for name, rows in report['rows'].items()
        }
        report['image_speedup'] = {
            key: report['medians']['apfs_folder'][key] / report['medians']['apfs_image'][key]
            for key in report['medians']['apfs_folder']
        }
        for relative, digest in sources.items():
            checks.require(hash_file(REPO / relative) == digest, 'Source changed during benchmark')
        checks.require(hash_file(Path(_scan.__file__)) == report['native_binary_sha256'],
                       'Native binary changed during benchmark')
    finally:
        try:
            if store is not None:
                # create() may publish/mount before it reports failure; discover all retained objects.
                for item in store.list():
                    if item.get('backend') == 'image':
                        store.unmount(item['id'])
                # Failed prepare may retain a mounted stage instead of a published workspace.
                for image in store.root.rglob('*.sparseimage'):
                    state = images.mounted(image)
                    if state is not None:
                        raise RuntimeError(f'Backing image still attached: {image}')
            remove_tree(base)
        except BaseException as exc:
            raise RuntimeError(f'Cleanup is uncertain; preserve fixtures at {base}: {exc}') from exc
    report['passed'] = True
    write_json(output, report)
    print(f'Complete paired result: {output}', flush=True)


if __name__ == '__main__':
    main()
