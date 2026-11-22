"""Build a wheel from a pinned qualified Git component without Git compilation."""
import argparse
from email.parser import BytesHeaderParser
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import runpy
import selectors
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.parse
import urllib.request
from unittest.mock import patch
import zipfile

LIMIT = 128 * 1024 ** 2
SETUPTOOLS = '84.2.1'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')


def relative(name):
    path = PurePosixPath(name)
    require(isinstance(name, str) and name and not path.is_absolute()
            and '..' not in path.parts and path.as_posix() == name, 'Unsafe component path')
    return path


def owned_destination(path):
    path = Path(path).absolute()
    return path.parent.resolve(strict=True) / path.name


def producer_source_names(package_entries):
    package = PurePosixPath('stallionfs')
    names = {path.as_posix() for path in map(PurePosixPath, package_entries)
             if path.parent == package and path.suffix in ('.py', '.c', '.h')}
    names |= {'setup.py', 'pyproject.toml', 'README.md', 'LICENSE', 'filesystem/image.c', 'filesystem/image.h',
              'tools/build_git_runtime.py', 'tools/_git_capture.py'}
    names |= {'tools/git-inputs/' + name for name in ('alias.c', 'combined.patch', 'notices.patch', 'config.mak', 'header-manifest.json')}
    names |= {'tests/perf/' + name for name in ('fileops.py', 'native_suite.py', 'native_metrics.py',
              'native_correctness.py', 'native_fixtures.py', 'native_report.py', 'campaign.py', 'scan.py', 'run.py', 'cli.py')}
    names |= {'tests/perf/fixture/' + name for name in ('package.json', 'package-lock.json', 'check.cjs')}
    return sorted(names)


def source_names(checkout):
    return producer_source_names(p.relative_to(checkout).as_posix()
                                 for p in (checkout / 'stallionfs').iterdir() if p.is_file())


def source_receipt(checkout, bindings):
    result = []
    for name in source_names(checkout):
        path = checkout / name
        data = bindings.read(path)
        result.append({'path': name, 'mode': oct(stat.S_IMODE(path.lstat().st_mode)),
                       'bytes': len(data), 'sha256': digest(data)})
    bindings.check()
    return result


def extract_component(archive, output):
    """Budget metadata first, then stream ordinary finite members exclusively."""
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:xz') as opened:
        members = []
        names = set(); total = 0
        for member in opened:
            relative(member.name)
            require(member.name not in names and len(names) < 4096, 'Component namespace limit')
            names.add(member.name)
            require((member.isfile() or member.isdir()) and not member.pax_headers,
                    'Component member must be ordinary')
            require(member.mode in ((0o755,) if member.isdir() else (0o600, 0o644, 0o755)) and 0 <= member.size <= 64 * 1024 ** 2,
                    'Component member mode or size differs')
            total += member.size
            require(total <= LIMIT, 'Component expanded byte limit')
            members.append(member)
        for member in members:
            path = output / member.name
            if member.isdir():
                path.mkdir(mode=member.mode, parents=True, exist_ok=True)
                continue
            path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with opened.extractfile(member) as source, path.open('xb') as target:
                remaining = member.size
                while True:
                    data = source.read(min(65536, remaining + 1))
                    require(len(data) <= remaining, 'Component actual member limit')
                    if not data:
                        break
                    target.write(data); remaining -= len(data)
                require(remaining == 0, 'Component member was truncated')
            path.chmod(member.mode)


def fetch(lock, output, architecture):
    started = time.monotonic_ns()
    def phase(name, **fields):
        print(json.dumps({"phase": name, "elapsed_ns": time.monotonic_ns() - started, **fields}, sort_keys=True), flush=True)
    output = owned_destination(output)
    require(architecture in ('arm64', 'x86_64'), 'Unsupported component architecture')
    value = json.loads(Path(lock).read_bytes())
    require(set(value) == {'schema', 'components'} and value['schema'] == 1, 'Component lock schema differs')
    row = value['components'].get(architecture)
    require(isinstance(row, dict) and set(row) == {'url', 'sha256', 'bytes', 'manifest_sha256', 'inventory_sha256', 'qualification_sha256'},
            'No reviewed qualified component for this architecture')
    url = urllib.parse.urlsplit(row['url'])
    require(url.scheme == 'https' and url.netloc == 'github.com' and not url.query and not url.fragment
            and url.path.startswith('/alvinhhh/stallionfs/releases/download/'), 'Unexpected component origin')
    require(type(row['bytes']) is int and 0 < row['bytes'] <= 64 * 1024 ** 2
            and all(re.fullmatch('[0-9a-f]{64}', row[key]) for key in ('sha256', 'manifest_sha256', 'inventory_sha256', 'qualification_sha256')),
            'Component lock limits or digests differ')
    phase("input-validated-download-start", architecture=architecture)
    data = bytearray()
    with urllib.request.urlopen(row['url'], timeout=30) as response:
        final = urllib.parse.urlsplit(response.url)
        require(final.scheme == 'https' and final.netloc in ('github.com', 'release-assets.githubusercontent.com'), 'Unexpected component redirect')
        while True:
            block = response.read(min(65536, row['bytes'] - len(data) + 1))
            require(len(data) + len(block) <= row['bytes'], 'Component download byte limit')
            if not block:
                break
            data.extend(block)
    phase("download-complete", bytes=len(data))
    require(len(data) == row['bytes'] and digest(data) == row['sha256'], 'Component archive differs')
    phase("archive-accepted-extraction-start")
    output.mkdir(mode=0o700)
    extract_component(data, output)
    phase("extraction-complete-validation-start")
    validate_component(output, row['manifest_sha256'], architecture)
    require(digest((output / 'input-inventory.json').read_bytes()) == row['inventory_sha256']
            and digest((output / 'qualification.json').read_bytes()) == row['qualification_sha256'], 'Component admission pins differ')
    write(output.parent / 'component-download.json', {'architecture': architecture, **row})
    phase("admission-complete")


def validate_component(root, expected, architecture=None):
    manifest_bytes = (root / 'component-manifest.json').read_bytes()
    require(digest(manifest_bytes) == expected, 'Component finite manifest differs')
    manifest = json.loads(manifest_bytes)
    require(manifest['schema'] == 1 and manifest['kind'] == 'portable-git-native-component'
            and manifest['architecture'] == (architecture or platform.machine())
            and manifest['self_exclusion'] == 'component-manifest.json', 'Component manifest identity differs')
    files = {'component-manifest.json'}; directories = set()
    for row in manifest['files']:
        name = str(relative(row['path'])); path = root / name
        require(name not in files and path.is_file() and not path.is_symlink(), 'Component file membership differs')
        files.add(name)
        info = path.lstat()
        require(info.st_nlink == 1 and oct(stat.S_IMODE(info.st_mode)) == row['mode']
                and info.st_size == row['size'] and digest(path.read_bytes()) == row['sha256'], 'Component file differs')
    for row in manifest['directories']:
        name = str(relative(row['path'])); path = root / name
        require(name not in directories and path.is_dir() and not path.is_symlink()
                and oct(stat.S_IMODE(path.lstat().st_mode)) == row['mode'], 'Component directory differs')
        directories.add(name)
    actual_files = {path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file()}
    actual_directories = {path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_dir()}
    require(actual_files == files and actual_directories == directories, 'Component finite namespace differs')
    return manifest


def metadata(checkout):
    require(importlib.metadata.version('setuptools') == SETUPTOOLS, 'Pinned setuptools is required')
    import setuptools
    original = setuptools.setup
    captured = []
    def inspect(*args, **kwargs):
        kwargs['script_args'] = ['--no-user-cfg', '--name']
        value = original(*args, **kwargs); captured.append(value)
        return value
    with patch.object(setuptools, 'setup', inspect), patch.object(sys, 'argv', [str(checkout / 'setup.py'), '--no-user-cfg', '--name']):
        runpy.run_path(str(checkout / 'setup.py'), run_name='__main__')
    require(len(captured) == 1, 'One build distribution required')
    build_py = captured[0].get_command_obj('build_py'); build_py.ensure_finalized()
    build = captured[0].get_command_obj('build'); build.ensure_finalized()
    result = {'build_lib': str(Path(build_py.build_lib).absolute()), 'build_temp': str(Path(build.build_temp).absolute())}
    require(all(Path(path).is_relative_to(checkout) for path in result.values()), 'Build destination escaped checkout')
    return result


def reconstruct(component, destination, package, bindings):
    mapping = json.loads(bindings.read(component / 'cache-reconstruction.json'))
    require(set(mapping) == {'schema', 'directories', 'files'} and mapping['schema'] == 1, 'Cache mapping schema differs')
    require(len(mapping['files']) <= 4096 and len(mapping['directories']) <= 4096, 'Cache mapping limits differ')
    names = set()
    for row in mapping['directories']:
        require(set(row) == {'path', 'mode', 'type', 'size'} and row['type'] == 'dir' and row['size'] == 0, 'Cache directory differs')
        path = destination / relative(row['path'])
        require(row['path'] not in names and row['mode'] == '0o755', 'Cache directory mode or collision')
        names.add(row['path']); path.mkdir(mode=0o755, parents=True, exist_ok=True)
    total = 0
    for row in mapping['files']:
        require(set(row) == {'destination', 'source', 'mode', 'sha256', 'size'}, 'Cache file mapping differs')
        name = str(relative(row['destination']))
        require(name not in names and row['mode'] in ('0o644', '0o755'), 'Cache file mode or collision')
        require(type(row['size']) is int and 0 <= row['size'] <= 64 * 1024 ** 2, 'Cache member size differs')
        total += row['size']; require(total <= LIMIT, 'Cache byte limit')
        names.add(name)
        source = component / relative(row['source'])
        data = bindings.read(source, row['sha256'])
        require(len(data) == row['size'], 'Cache file size differs')
        path = destination / name; path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        with path.open('xb') as stream: stream.write(data)
        path.chmod(int(row['mode'], 8))
    expected = json.loads(bindings.read(component / 'cache-inventory.json'))
    require(package._runtime_inventory(destination) == expected, 'Reconstructed cache inventory differs')
    require(len(expected) == 265 and sum(row['type'] == 'file' for row in expected) == 250, 'Cache finite layout differs')


def build(checkout, component, output):
    require(sys.flags.isolated and sys.dont_write_bytecode and sys.platform == 'darwin', 'Isolated macOS build required')
    require(platform.machine() in ('arm64', 'x86_64'), 'Unexpected build architecture')
    checkout = checkout.resolve(strict=True); component = component.resolve(strict=True)
    output = owned_destination(output)
    output.mkdir(mode=0o700)
    require(not os.environ.get('STALLIONFS_TEST_QUALIFIED_GIT'), 'Fixture environment must start empty')
    os.chdir(checkout)
    bundle = load('_ci_build_bundle', checkout / 'stallionfs/_bundle.py')
    admission = load('_ci_build_input', checkout / 'tools/ci_git_input.py')
    package = load('_ci_build_package', checkout / 'tools/package_fskit.py')
    bindings = admission._Bindings(bundle); bindings.reader = package._runtime_read
    package._runtime_read = bindings.read
    bindings.tree(component)
    source = source_receipt(checkout, bindings)
    write(output / 'source-pins.json', source)
    git = {'root': str(component / 'Git'), 'inventory': {'path': str(component / 'input-inventory.json'),
            'sha256': digest(bindings.read(component / 'input-inventory.json'))},
        'qualification': {'path': str(component / 'qualification.json'),
            'sha256': digest(bindings.read(component / 'qualification.json'))}}
    bindings.tree(component / 'Git')
    admitted = package._runtime_admit_git(git, {}, architecture=platform.machine())
    bindings.check()
    payload = bundle.git_payload(component / 'Git'); bindings.payload(component / 'Git', payload)
    write(output / 'native-input.json', git)
    before = metadata(checkout)
    cache = Path(before['build_lib']) / 'stallionfs/_git'
    require(not cache.exists() and not os.path.lexists(Path(before['build_temp']) / 'git-dependency'), 'Fresh build/cache destination required')
    cache.mkdir(mode=0o755, parents=True)
    reconstruct(component, cache, package, bindings)
    require(package._runtime_inventory(component / 'Git') == admitted['inventory'], 'Native input changed')
    bindings.tree(cache)
    manifest_bytes = bindings.read(cache / 'manifest.json')
    manifest = json.loads(manifest_bytes)
    require(manifest['build']['architecture'] == platform.machine(), 'Component architecture differs')
    # Preserve original tool hashes and compilation_origin. Runner compilers only
    # compile the current wheel extensions/launchers, never the supplied Git tree.
    guard_module = load('_ci_cache_guard', checkout / 'tools/_ci_cache.py')
    guard = guard_module.CacheOnlyGuard(cache, digest(manifest_bytes), Path(before['build_temp']) / 'git-dependency', bindings.check)
    guard.install_audit()
    original_spec = importlib.util.spec_from_file_location
    modules = []
    def guarded_spec(name, location, *args, **kwargs):
        spec = original_spec(name, location, *args, **kwargs)
        if Path(location).absolute() == checkout / 'tools/build_git_runtime.py':
            loader = spec.loader
            class CheckedLoader:
                def create_module(self, spec): return loader.create_module(spec)
                def exec_module(self, module):
                    loader.exec_module(module); guard.wrap(module); modules.append(module)
            spec.loader = CheckedLoader()
        return spec
    from setuptools import build_meta
    with patch.object(importlib.util, 'spec_from_file_location', guarded_spec):
        name = build_meta.build_wheel(str(output), config_settings={'--global-option': ['--no-user-cfg']})
    guard.require_complete(); bindings.check()
    require(metadata(checkout) == before and source_receipt(checkout, bindings) == source, 'Build inputs changed')
    require(package._runtime_inventory(component / 'Git') == admitted['inventory'], 'Raw component changed during build')
    wheel = output / name
    require(wheel.parent == output and wheel.is_file() and len(list(output.glob('*.whl'))) == 1, 'One owned wheel required')
    write(output / 'build-result.json', {'schema': 1, 'wheel': name, 'wheel_sha256': digest(wheel.read_bytes()),
        'source_pins_sha256': digest((output / 'source-pins.json').read_bytes()),
        'descriptor_sha256': digest((output / 'native-input.json').read_bytes()),
        'interpreter_sha256': digest(Path(sys.executable).read_bytes()), 'interpreter_version': sys.version,
        'architecture': platform.machine(), 'setuptools': importlib.metadata.version('setuptools'),
        'build_destination': before, 'cache_return': guard.observations, 'guard_effects': guard.effects,
        'builder_modules_wrapped': len(modules), 'git_compilation': 'reused exact qualified component',
        'original_git_build': manifest['build']})


def initialize_installed(checkout, output, *, wheel_receipt=None):
    """Run in the same test process before adding tests to sys.path."""
    result_bytes = (output / 'build-result.json').read_bytes()
    result = json.loads(result_bytes)
    require(result['schema'] == 1 and result['cache_return'] == [{'cache_return': True, 'calls': 1}]
            and result['guard_effects'] == [], 'Current cache-only build receipt missing')
    require(result['interpreter_sha256'] == digest(Path(sys.executable).read_bytes())
            and result['interpreter_version'] == sys.version and result['architecture'] == platform.machine(),
            'Build and test interpreter differ')
    path = output / result['wheel']
    require(path.parent == output and path.is_file(), 'Build wheel path escaped')
    module = load('ci_git_input', checkout / 'tools/ci_git_input.py')
    require('ci_git_input' not in sys.modules, 'Admission module already registered')
    sys.modules['ci_git_input'] = module
    try:
        admitted = module.initialize(checkout, path, result['wheel_sha256'], output / 'native-input.json',
            result['descriptor_sha256'], source_pins=output / 'source-pins.json',
            source_pins_sha256=result['source_pins_sha256'])
    except BaseException:
        sys.modules.pop('ci_git_input', None)
        raise
    if wheel_receipt is not None:
        wheel_receipt(digest(result_bytes))
    return admitted


def git_output(checkout, *args, limit, stdin=subprocess.DEVNULL):
    # Each command has a bounded stream and a single deadline for EOF and reaping.
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_OPTIONAL_LOCKS='0', GIT_NO_LAZY_FETCH='1', GIT_CONFIG_NOSYSTEM='1',
               GIT_CONFIG_GLOBAL='/dev/null', LC_ALL='C')
    argv = ['/usr/bin/git', '--no-replace-objects', '--literal-pathspecs', *args]
    deadline = time.monotonic() + 5
    output = bytearray()
    child = subprocess.Popen(argv, cwd=checkout, env=env, stdin=stdin,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        with selectors.DefaultSelector() as streams:
            streams.register(child.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not streams.select(remaining):
                    raise subprocess.TimeoutExpired(argv, 5)
                block = os.read(child.stdout.fileno(), min(65536, limit - len(output) + 1))
                if not block:
                    break
                output.extend(block)
                require(len(output) <= limit, 'Git output exceeded source verification limit')
        require(child.wait(timeout=max(0, deadline - time.monotonic())) == 0,
                'Git source verification command failed')
    finally:
        try:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=2)
        finally:
            child.stdout.close()
    return bytes(output)


def committed_wheel_inputs(checkout, root, source, pins):
    """Bind the producer receipt to the complete source set in the commit tree."""
    lock_name = 'tools/ci-git-components.json'
    fixed = producer_source_names(())
    listing = git_output(checkout, 'ls-tree', '-rlz', '--full-tree', source, '--',
                         'stallionfs', *fixed, lock_name, limit=64 * 1024)
    require(listing.endswith(b'\0'), 'Incomplete committed source tree')
    entries = {}
    for line in listing[:-1].split(b'\0'):
        fields, name = line.split(b'\t', 1)
        name = name.decode()
        require(name not in entries, 'Duplicate committed source path')
        entries[name] = fields.split()
    names = producer_source_names(entries)
    require(len(names) > len(fixed) and set(names) | {lock_name} <= entries.keys(),
            'Committed producer source set is incomplete')
    require(type(pins) is list and len(pins) == len(names)
            and all(type(row) is dict and set(row) == {'path', 'mode', 'bytes', 'sha256'}
                    and type(row['path']) is str for row in pins), 'Producer source receipt shape differs')
    by_name = {row['path']: row for row in pins}
    require(by_name.keys() == set(names), 'Producer source receipt set differs from commit')

    source_rows = []
    for name in [*names, lock_name]:
        mode, kind, oid, size_text = entries[name]
        require(mode in (b'100644', b'100755') and kind == b'blob'
                and re.fullmatch(rb'[0-9a-f]{40}', oid) and size_text.isdigit(),
                'Committed source must be an ordinary Git blob')
        size = int(size_text)
        header = b' '.join((oid, kind, size_text)) + b'\n'
        source_rows.append((name, mode, oid, size, header))
    limit = sum(len(header) + size + 1 for _, _, _, size, header in source_rows)
    require(limit <= 8 * 1024 ** 2, 'Committed wheel input bytes exceed verification limit')
    with tempfile.TemporaryFile(dir=root) as requests:
        requests.write(b''.join(oid + b'\n' for _, _, oid, _, _ in source_rows))
        requests.seek(0)
        batch = git_output(checkout, 'cat-file', '--batch', limit=limit, stdin=requests)
    require(len(batch) == limit, 'Incomplete committed source blobs')
    metadata = {}
    offset = 0
    for name, mode, _, size, header in source_rows:
        start = offset + len(header)
        end = start + size
        require(batch[offset:start] == header and batch[end:end + 1] == b'\n',
                'Committed source blob response differs')
        data = batch[start:end]
        offset = end + 1
        if name != lock_name:
            pin = by_name[name]
            # Git tracks regular file type and the owner executable bit.
            require(type(pin['mode']) is str and re.fullmatch(r'0o(?:0|[1-7][0-7]{0,2})', pin['mode'])
                    and bool(int(pin['mode'], 8) & stat.S_IXUSR) == (mode == b'100755'),
                    'Producer source mode differs from commit')
            require(type(pin['bytes']) is int and pin['bytes'] == size and pin['sha256'] == digest(data),
                    'Producer source bytes differ from commit')
        if name in ('pyproject.toml', lock_name):
            metadata[name] = data
    project = tomllib.loads(metadata['pyproject.toml'].decode())['project']
    require(project['name'] == 'stallionfs', 'Committed project name differs')
    return project['version'], metadata[lock_name]


def verify_wheel_version(wheel, version):
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        member = archive.getinfo(f'stallionfs-{version}.dist-info/METADATA')
        require(member.file_size <= 64 * 1024, 'Wheel metadata exceeds verification limit')
        metadata = BytesHeaderParser().parsebytes(archive.read(member))
    require(metadata.get_all('Name') == ['stallionfs'] and metadata.get_all('Version') == [version],
            'Wheel metadata differs from committed project')


def stage_intel_wheel(checkout, root, entry, job):
    """Stage only the bytes admitted by the successful installed suite child."""
    env = os.environ
    worker = 'macos-26-intel-3.13-1-installed'
    require((env.get('GITHUB_REPOSITORY'), env.get('GITHUB_EVENT_NAME'), env.get('GITHUB_REF'),
             env.get('GITHUB_JOB'), env.get('CI_WORKER'), env.get('CI_RETAIN_INTEL_WHEEL'),
             env.get('STALLIONFS_TEST_IMAGES'), env.get('STALLIONFS_QUALIFICATION'),
             env.get('RUNNER_OS'), env.get('RUNNER_ARCH')) ==
            ('alvinhhh/stallionfs', 'push', 'refs/heads/main', 'test-execution', worker, '1',
             '1', '1', 'macOS', 'X64'), 'Intel installed retention lane required')
    macos = platform.mac_ver()[0]
    python = platform.python_version()
    require(sys.platform == 'darwin' and platform.machine() == 'x86_64'
            and sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 13)
            and re.fullmatch(r'26(?:\.[0-9]+){1,2}', macos)
            and re.fullmatch(r'3\.13\.[0-9]+', python), 'Intel host or interpreter differs')
    run = env['GITHUB_RUN_ID']
    attempt = env['GITHUB_RUN_ATTEMPT']
    require(all(re.fullmatch('[1-9][0-9]{0,19}', value) for value in (run, attempt)), 'Invalid run identity')
    source = env['GITHUB_SHA']
    require(re.fullmatch('[0-9a-f]{40}', source), 'Full source SHA required')
    head = git_output(checkout, 'rev-parse', '--verify', 'HEAD', limit=41)
    require(head == (source + '\n').encode(), 'Checkout HEAD differs')
    git_output(checkout, 'diff', '--quiet', '--no-ext-diff', '--no-textconv', 'HEAD', '--', limit=0)
    reader = load('_ci_wheel_reader', checkout / 'tools/package_fskit.py')._runtime_read

    ledger = entry.strict_json(reader(root / 'ci-phase-suite.json'))
    require(type(ledger.get('complete')) is bool and ledger == dict(job=job, phase='suite', complete=True),
            'Suite phase did not finish in this allocation')
    suite_data = reader(root / 'suite-closure/suite.json')
    suite = entry.validate_receipt(suite_data)
    require(suite.get('job') == job and suite.get('mode') == 'suite'
            and suite.get('qualification') is True and suite.get('success') is True,
            'Successful qualified suite closure required')
    counts = next(event for event in suite['events'] if event.get('phase') == 'exit' and event['state'] == 'start')
    require(counts['tests'] > 0, 'Suite ran no tests')
    candidate = entry.strict_json(reader(root / 'installed-wheel-candidate.json'))
    require(set(candidate) == {'job', 'pid', 'invocation', 'source_sha', 'build_result_sha256',
                                'descriptor_sha256', 'inventory_sha256'}
            and all(candidate[key] == suite[key] for key in ('job', 'pid', 'invocation'))
            and type(candidate['pid']) is int and candidate['source_sha'] == source
            and re.fullmatch('[0-9a-f]{64}', candidate['build_result_sha256']),
            'Wheel candidate belongs to a different suite or source')

    output = root / 'qualified-wheel'
    result_data = reader(output / 'build-result.json', candidate['build_result_sha256'])
    result = entry.strict_json(result_data)
    name = result['wheel']
    match = re.fullmatch(r'stallionfs-([0-9]+(?:\.[0-9]+){2})-cp313-cp313-(macosx_[0-9]+_[0-9]+_x86_64)\.whl', name)
    require(match is not None and list(output.glob('*.whl')) == [output / name]
            and result['architecture'] == 'x86_64' and result['interpreter_version'] == sys.version
            and result['interpreter_sha256'] == digest(Path(sys.executable).read_bytes())
            and result['git_compilation'] == 'reused exact qualified component', 'Selected Intel wheel differs')
    require(all(re.fullmatch('[0-9a-f]{64}', result[key]) for key in
                ('wheel_sha256', 'source_pins_sha256', 'descriptor_sha256')), 'Build digests differ')
    pins = entry.strict_json(reader(output / 'source-pins.json', result['source_pins_sha256']))
    version, lock_bytes = committed_wheel_inputs(checkout, root, source, pins)
    require(version == match[1], 'Wheel filename version differs from committed project')
    wheel = reader(output / name, result['wheel_sha256'])
    verify_wheel_version(wheel, version)

    lock = entry.strict_json(lock_bytes)
    component = lock['components']['x86_64']
    component_digests = {key: component[key] for key in
                         ('sha256', 'manifest_sha256', 'inventory_sha256', 'qualification_sha256')}
    require(lock['schema'] == 1 and all(re.fullmatch('[0-9a-f]{64}', value) for value in component_digests.values())
            and entry.strict_json(reader(root / 'component-download.json')) == {'architecture': 'x86_64', **component},
            'Component fetch and lock differ')
    native = root / 'qualified-git-component'
    for name_on_disk, digest_key in (('component-manifest.json', 'manifest_sha256'),
                                     ('input-inventory.json', 'inventory_sha256'),
                                     ('qualification.json', 'qualification_sha256')):
        reader(native / name_on_disk, component[digest_key])
    descriptor = reader(output / 'native-input.json', result['descriptor_sha256'])
    require(candidate['descriptor_sha256'] == result['descriptor_sha256']
            and candidate['inventory_sha256'] == component['inventory_sha256']
            and entry.strict_json(descriptor) == {
                'root': str(native / 'Git'),
                'inventory': {'path': str(native / 'input-inventory.json'), 'sha256': component['inventory_sha256']},
                'qualification': {'path': str(native / 'qualification.json'), 'sha256': component['qualification_sha256']}},
            'Admitted Git component differs from the locked download')

    stage = root / 'installed-intel-wheel'
    stage.mkdir(mode=0o700)
    with (stage / name).open('xb') as stream:
        stream.write(wheel)
    write(stage / 'proof.json', {
        'schema': 1, 'source_sha': source, 'source_pins_sha256': result['source_pins_sha256'],
        'wheel': {'filename': name, 'sha256': result['wheel_sha256'], 'bytes': len(wheel),
                  'version': version, 'platform_tag': match[2]},
        'target': {'runner': 'macos-26-intel', 'architecture': 'x86_64', 'macos': macos, 'python': python},
        'git_component': component_digests,
        'suite': {'status': 'passed', 'repository': env['GITHUB_REPOSITORY'],
                  'run_id': run, 'run_attempt': attempt, 'job': env['GITHUB_JOB'],
                  'worker': worker, 'allocation_sha256': job, 'invocation': suite['invocation'],
                  'closure_sha256': digest(suite_data), **{key: counts[key] for key in entry.COUNTS}}})
    return name


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('fetch', 'build'))
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--component', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.action == 'fetch':
        fetch(args.checkout / 'tools/ci-git-components.json', args.component, platform.machine())
    else:
        require(args.output is not None, 'Output is required')
        build(args.checkout, args.component, args.output.absolute())


if __name__ == '__main__':
    main()
