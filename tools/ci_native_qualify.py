"""Bounded Git build qualification and registered reproducibility rechecks."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
import tarfile
import time
from unittest.mock import patch


def require(value, message):
    if not value: raise ValueError(message)


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def write(path, value):
    with path.open('x') as stream: json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')


def require_capture(capture):
    state = capture._command_state
    require(state.get('failure') is None and state.get('active') is None
            and state.get('first_signal') is None and state.get('signal_count', 0) == 0,
            'Owned qualification capture failed or remains incomplete: ' + repr(state))


def normalized_text(data, replacements):
    text = data.decode('utf-8', errors='strict')
    for source, target in sorted(replacements, key=lambda pair: len(pair[0]), reverse=True):
        text = text.replace(source, target)
    require(not re.search(r'/Users/(?!runner(?:/|$))|/private/var/|/var/folders/|(?:gh[pousr]_|github_pat_|sk-)[A-Za-z0-9_]{20}', text), 'Unsafe transfer text')
    return text.encode()


REGISTERED_KIND = 'registered-git-recheck'
REGISTERED_RUNNERS = {'arm64': 'ARM64', 'x86_64': 'X64'}
REGISTERED_LOCK = 'd2b094d69cd02e21cb630c3992debcba71d8a3cb7beb41edd71e2476a9fc93e8'
CONTROLLERS = ('tools/ci_native_campaign.py', 'tools/ci_native_qualify.py', 'tools/ci_native_python.py',
    'tools/ci_build.py', 'tools/ci_execute.py', 'tools/_ci_cache.py', 'tools/ci_git_input.py',
    'tools/package_fskit.py', 'tools/ci-build-requirements.txt', 'tools/ci-git-components.json',
    '.github/workflows/checks.yml')


def binding_identity(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Bound input must be an ordinary file')
    return [info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def read_bound(bindings, name):
    row = bindings[name]; path = Path(row['path'])
    require(binding_identity(path) == row['identity'], 'Original registered input identity changed: ' + name)
    data = path.read_bytes()
    require(binding_identity(path) == row['identity'] and len(data) == row['size']
            and hashlib.sha256(data).hexdigest() == row['sha256'], 'Original registered input bytes changed: ' + name)
    return data


def bind_input(bindings, name, path, expected=None):
    if name in bindings:
        require(bindings[name]['path'] == str(path), 'Registered input path changed')
        data = read_bound(bindings, name)
    else:
        identity = binding_identity(path); data = path.read_bytes()
        require(binding_identity(path) == identity, 'Registered input changed during binding')
        bindings[name] = {'path': str(path), 'identity': identity, 'size': len(data),
            'mode': oct(stat.S_IMODE(identity[2])), 'sha256': hashlib.sha256(data).hexdigest()}
    require(expected is None or hashlib.sha256(data).hexdigest() == expected, 'Registered input binding differs: ' + name)


def check_bound(bindings):
    for name in bindings: read_bound(bindings, name)


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def registered_archive(root, archive, manifest_sha256, *, failed, bindings=None, execution_sha256=None):
    """Check serialized finite bodies, not just the outer archive digest."""
    with tarfile.open(archive, mode='r:xz') as opened:
        members = {}; total = 0
        for member in opened:
            require(member.isfile() and not member.pax_headers and member.name not in members
                    and len(members) < 8193 and 0 <= member.size <= 128 * 1024 ** 2,
                    'Registered archive member differs')
            name = Path(member.name)
            require(member.name and not name.is_absolute() and '..' not in name.parts
                    and name.as_posix() == member.name, 'Registered archive path differs')
            total += member.size
            require(total <= 128 * 1024 ** 2 + 4 * 1024 ** 2, 'Registered archive expanded limit')
            members[member.name] = member
        require('transfer-manifest.json' in members and members['transfer-manifest.json'].size <= 4 * 1024 ** 2
                and members['transfer-manifest.json'].mode == 0o644,
                'Registered archive manifest missing or oversized')
        manifest_bytes = opened.extractfile(members['transfer-manifest.json']).read()
        require(hashlib.sha256(manifest_bytes).hexdigest() == manifest_sha256, 'Serialized registered manifest changed')
        manifest = json.loads(manifest_bytes)
        require(manifest['architecture'] == registered_architecture(os.environ), 'Serialized registered architecture differs')
        require(manifest['kind'] == ('failed-registered-recheck-transfer' if failed else 'registered-recheck-transfer')
                and manifest['recheck_passed'] is (not failed) and manifest['runtime_binaries_included'] is (not failed),
                'Registered archive verdict differs')
        rows = manifest['files']; expected = {row['path']: row for row in rows}
        require(len(rows) == len(expected) <= 8192 and set(members) == set(expected) | {'transfer-manifest.json'},
                'Registered archive finite namespace differs')
        if not failed:
            require(bindings is not None and execution_sha256 is not None, 'Original registered success bindings required')
            names = {name for name in bindings if not name.startswith('@')}
            require(set(expected) == names, 'Registered success copied input set differs')
        for name, row in expected.items():
            member = members[name]
            require(member.size == row['size'] and oct(member.mode) == row['mode'], 'Serialized member size/mode differs')
            data = opened.extractfile(member).read()
            require(len(data) == row['size'] and hashlib.sha256(data).hexdigest() == row['sha256'],
                    'Serialized member bytes differ')
            if failed:
                require(not name.startswith(('wheel/', 'Git/')) and not name.endswith('.whl'), 'Failure archive includes native payload')
            else:
                require(row['original_sha256'] == bindings[name]['sha256'], 'Copied evidence differs from original registered input')
        if not failed:
            require(expected['evidence/execution-result.json']['original_sha256'] == execution_sha256,
                    'Archived execution result differs')


def registered_architecture(environment):
    architecture = environment.get('EXPECTED_ARCHITECTURE')
    require(type(architecture) is str and architecture in REGISTERED_RUNNERS, 'Explicit registered architecture required')
    require(environment.get('RUNNER_OS') == 'macOS' and environment.get('RUNNER_ARCH') == REGISTERED_RUNNERS[architecture],
            'Registered runner architecture differs')
    return architecture


def gate(environment, *, registered=False):
    expected = environment.get('EXPECTED_SOURCE_SHA', '')
    require(re.fullmatch('[0-9a-f]{40}', expected) and environment.get('GITHUB_SHA') == expected,
            'Exact reviewed source SHA required')
    require(environment.get('GITHUB_RUN_ATTEMPT') == '1', 'Qualification reruns are refused')
    require(environment.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and environment.get('QUALIFICATION_MODE') == (REGISTERED_KIND if registered else 'native-git-qualification'),
            'Explicit manual qualification required')
    if registered: registered_architecture(environment)
    else: require(environment.get('RUNNER_OS') == 'macOS' and environment.get('RUNNER_ARCH') == 'X64', 'Standard Intel runner required')


def registered_component(checkout, root):
    ci = load('_registered_ci', checkout / 'tools/ci_build.py')
    lock = checkout / 'tools/ci-git-components.json'
    require(sha(lock) == REGISTERED_LOCK, 'Reviewed historical v6 component lock required')
    architecture = platform.machine()
    row = json.loads(lock.read_bytes())['components'][architecture]
    component = root / 'component'
    ci.validate_component(component, row['manifest_sha256'], architecture)
    require(json.loads((root / 'component-download.json').read_bytes()) == {'architecture': architecture, **row},
            'Historical component download binding differs')
    require(sha(component / 'input-inventory.json') == row['inventory_sha256']
            and sha(component / 'qualification.json') == row['qualification_sha256'], 'Historical native pins differ')
    package = load('_registered_package', checkout / 'tools/package_fskit.py')
    package._runtime_admit_git({'root': str(component / 'Git'),
        'inventory': {'path': str(component / 'input-inventory.json'), 'sha256': row['inventory_sha256']},
        'qualification': {'path': str(component / 'qualification.json'), 'sha256': row['qualification_sha256']}},
        {}, architecture=architecture)
    manifest = json.loads((component / 'package-manifest.json').read_bytes())
    for field, name in (('recipe_sha256', 'tools/build_git_runtime.py'), ('capture_sha256', 'tools/_git_capture.py'),
                        ('registry_sha256', 'stallionfs/_git_sources.py'), ('bundle_sha256', 'stallionfs/_bundle.py')):
        require(manifest['build'][field] == sha(checkout / name), 'Unchanged native recipe binding required')
    return {'schema': 1, 'kind': 'historical-v6-native-component', 'architecture': architecture,
            'source_map_scope': 'Historical v6; not the current wheel producer', **row}


def registered_producer(checkout, producer):
    ci = load('_registered_producer_ci', checkout / 'tools/ci_build.py')
    result = json.loads((producer / 'build-result.json').read_bytes())
    require(result['schema'] == 1 and result['architecture'] == platform.machine()
            and result['interpreter_sha256'] == sha(Path(sys.executable))
            and result['interpreter_version'] == sys.version and result['setuptools'] == ci.SETUPTOOLS,
            'Current producer interpreter differs')
    require(result['cache_return'] == [{'cache_return': True, 'calls': 1}] and result['guard_effects'] == [],
            'One cache-only build required')
    pins = producer / 'source-pins.json'
    require(sha(pins) == result['source_pins_sha256'], 'Current producer source receipt differs')
    rows = json.loads(pins.read_bytes())
    require(isinstance(rows, list) and len(rows) == 55 and {r['path'] for r in rows} == set(ci.source_names(checkout)),
            'Current producer source set differs')
    for row in rows:
        require(set(row) == {'path', 'mode', 'bytes', 'sha256'}, 'Current producer source row differs')
        path = checkout / ci.relative(row['path'])
        require(path.is_file() and not path.is_symlink() and sha(path) == row['sha256']
                and path.stat().st_size == row['bytes'] and oct(stat.S_IMODE(path.stat().st_mode)) == row['mode'],
                'Current producer source changed')
    name = str(ci.relative(result['wheel']))
    wheel = producer / name
    require(wheel.parent == producer and wheel.is_file() and not wheel.is_symlink()
            and list(producer.glob('*.whl')) == [wheel] and sha(wheel) == result['wheel_sha256'],
            'One exact owned current wheel required')
    descriptor = producer / 'native-input.json'
    require(sha(descriptor) == result['descriptor_sha256'], 'Current native descriptor differs')
    return result, wheel


def admit_installed(checkout, producer):
    result, _ = registered_producer(checkout, producer)
    ci = load('_registered_admit_ci', checkout / 'tools/ci_build.py')
    admitted = ci.initialize_installed(checkout, producer)
    admitted['check']()
    write(producer / 'admission-result.json', {'schema': 1, 'kind': REGISTERED_KIND,
        'build_result_sha256': sha(producer / 'build-result.json'),
        'wheel_sha256': result['wheel_sha256'], 'source_pins_sha256': result['source_pins_sha256']})


def registered_stages(checkout, root, run, *, bindings=None):
    bindings = {} if bindings is None else bindings
    lock = checkout / 'tools/ci-git-components.json'
    require(sha(lock) == REGISTERED_LOCK, 'Reviewed historical v6 component lock required')
    run('fetch', [sys.executable, '-I', '-B', str(checkout / 'tools/ci_build.py'), 'fetch',
        '--checkout', str(checkout), '--component', str(root / 'component')], 90)
    reference = registered_component(checkout, root)
    write(root / 'component-reference.json', reference)
    component_pins = {name: sha(root / 'component' / name) for name in
        ('component-manifest.json', 'qualification-source-pins.json', 'input-inventory.json', 'qualification.json', 'package-manifest.json', 'provenance.json')}
    for name, digest in component_pins.items():
        bind_input(bindings, 'evidence/historical-component/' + name, root / 'component' / name, digest)
    bind_input(bindings, 'evidence/component-reference.json', root / 'component-reference.json', hashlib.sha256(json_bytes(reference)).hexdigest())
    bind_input(bindings, 'evidence/component-download.json', root / 'component-download.json')
    producer = root / 'producer'
    run('build', [sys.executable, '-I', '-B', str(checkout / 'tools/ci_build.py'), 'build',
        '--checkout', str(checkout), '--component', str(root / 'component'), '--output', str(producer)], 600)
    result, wheel = registered_producer(checkout, producer)
    require(json.loads((producer / 'native-input.json').read_bytes()) == {
        'root': str(root / 'component/Git'),
        'inventory': {'path': str(root / 'component/input-inventory.json'), 'sha256': reference['inventory_sha256']},
        'qualification': {'path': str(root / 'component/qualification.json'), 'sha256': reference['qualification_sha256']}},
        'Current producer must use the historical admitted native component')
    require(result['original_git_build'] == json.loads((root / 'component/package-manifest.json').read_bytes())['build'],
            'Original Git build provenance changed')
    initial_result = sha(producer / 'build-result.json')
    for name, digest in (('build-result.json', initial_result), ('source-pins.json', result['source_pins_sha256']),
                         ('native-input.json', result['descriptor_sha256'])):
        bind_input(bindings, 'evidence/current-producer/' + name, producer / name, digest)
    bind_input(bindings, 'wheel/' + wheel.name, wheel, result['wheel_sha256'])
    for row in json.loads(read_bound(bindings, 'evidence/current-producer/source-pins.json')):
        bind_input(bindings, 'source/' + row['path'], checkout / row['path'], row['sha256'])
        require(bindings['source/' + row['path']]['mode'] == row['mode'], 'Original producer source mode differs')
    run('install', [sys.executable, '-I', '-B', '-m', 'pip', '--isolated', 'install', '--no-index', '--no-deps',
        '--no-compile', '--force-reinstall', str(wheel)], 45)
    check_bound(bindings)
    run('admit', [sys.executable, '-I', '-B', str(checkout / 'tools/ci_native_qualify.py'), 'admit-installed',
        '--checkout', str(checkout), '--root', str(producer)], 45)
    require(json.loads((producer / 'admission-result.json').read_bytes()) == {'schema': 1, 'kind': REGISTERED_KIND,
        'build_result_sha256': initial_result, 'wheel_sha256': result['wheel_sha256'],
        'source_pins_sha256': result['source_pins_sha256']}, 'Fresh installed admission completion required')
    bind_input(bindings, 'evidence/current-producer/admission-result.json', producer / 'admission-result.json')
    check_bound(bindings)
    run('campaign', [sys.executable, '-I', '-B', str(checkout / 'tools/ci_native_campaign.py'),
        '--checkout', str(checkout), '--packet', str(root / 'component'), '--output', str(root / 'campaign'),
        '--registered-input', '--wheel-output', str(producer)], 900)
    campaign_bytes = (root / 'campaign/result.json').read_bytes()
    campaign = json.loads(campaign_bytes)
    require(campaign['passed'] is True and campaign['input_unchanged'] is True and campaign['input_unregistered'] is False
        and campaign['owned_commands'] == 581 and len(campaign['successes']) == 10
        and len(campaign['strict_native_environment_commands']) == 92 and len(campaign['structural_refusals']) == 27,
        'Complete registered campaign required')
    registered_producer(checkout, producer)
    require(sha(producer / 'build-result.json') == initial_result
            and registered_component(checkout, root) == reference
            and all(sha(root / 'component' / name) == value for name, value in component_pins.items()),
            'Registered recheck inputs changed')
    for name in ('before.json', 'after.json', 'commands.json', 'result.json', 'inert-guards.json'):
        path = root / 'campaign' / name
        if path.is_file(): bind_input(bindings, 'evidence/campaign/' + name, path,
            hashlib.sha256(campaign_bytes).hexdigest() if name == 'result.json' else None)
    for path in sorted((root / 'campaign/owned-commands').glob('*/*')):
        if re.fullmatch(r'[0-9]{4}', path.parent.name) and re.fullmatch(r'(?:[0-9]{2}-receipt|request|result)\.json|stdout|stderr', path.name):
            bind_input(bindings, 'evidence/campaign/owned-commands/' + path.parent.name + '/' + path.name, path)
    check_bound(bindings)
    return bindings


def build(checkout, root):
    require(sys.flags.isolated and sys.dont_write_bytecode and platform.machine() == 'x86_64'
            and sys.version_info[:3] == (3, 13, 18), 'Pinned isolated Intel interpreter required')
    ci = load('_raw_ci_build', checkout / 'tools/ci_build.py')
    bundle = load('_raw_bundle', checkout / 'stallionfs/_bundle.py')
    admission = load('_raw_bindings', checkout / 'tools/ci_git_input.py')
    package = load('_raw_package', checkout / 'tools/package_fskit.py')
    bindings = admission._Bindings(bundle); bindings.reader = package._runtime_read
    source = ci.source_receipt(checkout, bindings)
    write(root / 'source-pins.json', source)
    sources = root / 'source-component'
    ci.fetch(checkout / 'tools/ci-git-components.json', sources, 'arm64')
    bindings.tree(sources)
    os.chdir(checkout)
    backend = ci.metadata(checkout)
    cache = Path(backend['build_lib']) / 'stallionfs/_git'
    require(not os.path.lexists(cache) and not os.path.lexists(Path(backend['build_temp']) / 'git-dependency'), 'Fresh one-shot build required')
    original_spec = importlib.util.spec_from_file_location
    calls = []; active = [False]
    def offline(event, args):
        if active[0] and (event.startswith(('urllib.', 'http.client.')) or event in ('socket.__new__', 'socket.connect')):
            raise RuntimeError('Native build uses delivered sources only')
    sys.addaudithook(offline)
    def wrapped_spec(name, location, *args, **kwargs):
        spec = original_spec(name, location, *args, **kwargs)
        if Path(location).absolute() == checkout / 'tools/build_git_runtime.py':
            loader = spec.loader
            class CheckedLoader:
                def create_module(self, spec): return loader.create_module(spec)
                def exec_module(self, module):
                    loader.exec_module(module)
                    original = module.build
                    def once(destination, temporary, **options):
                        require(not calls and not options and Path(destination).absolute() == cache,
                                'Exactly one fresh Intel Git build permitted')
                        calls.append({'destination': str(destination), 'temporary': str(temporary)})
                        bindings.check(); active[0] = True
                        try:
                            return original(destination, temporary, delivered_sources=sources / 'Sources/Git')
                        finally:
                            active[0] = False; bindings.check()
                    module.build = once
            spec.loader = CheckedLoader()
        return spec
    wheels = root / 'wheels'; wheels.mkdir(mode=0o700)
    from setuptools import build_meta
    with patch.object(importlib.util, 'spec_from_file_location', wrapped_spec):
        wheel_name = build_meta.build_wheel(str(wheels), config_settings={'--global-option': ['--no-user-cfg']})
    require(len(calls) == 1 and ci.source_receipt(checkout, bindings) == source, 'One unchanged-source build required')
    manifest = json.loads((cache / 'manifest.json').read_bytes())
    require(manifest['build']['architecture'] == 'x86_64' and 'compilation_origin' not in manifest['build'], 'Fresh Intel compiler provenance required')
    registry = load('_raw_layout', checkout / 'stallionfs/_git_sources.py')
    native = root / 'Git'; native.mkdir(mode=0o755)
    for name in registry.DIRECTORIES: (native / name).mkdir(mode=0o755, parents=True, exist_ok=True)
    for name in sorted(set(registry.LAYOUT) | set(registry.LICENSES)):
        destination = native / name; destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copy2(cache / name, destination)
    inventory = package._runtime_inventory(native)
    require(len(inventory) == 241 and sum(row['type'] == 'file' for row in inventory) == 230, 'Measured Intel native namespace differs')
    write(root / 'input-inventory.json', inventory)
    inventory_sha = sha(root / 'input-inventory.json')
    require(inventory_sha not in bundle.QUALIFIED_GIT_INPUTS, 'Input is already registered; no repeat qualification')
    bundle.git_contract({**bundle.GIT_CONTRACT, 'input_inventory_sha256': inventory_sha}, qualified=False)
    builder = load('_raw_macho', checkout / 'tools/build_git_runtime.py')
    slices = []
    for row in inventory:
        if row['type'] != 'file': continue
        values = builder.macho(native / row['path'])
        if row['path'] in registry.LAYOUT and (native / row['path']).read_bytes()[:2] != b'#!' and int(row['mode'], 8) & 0o111:
            require(values, 'Native executable lacks Mach-O slice')
        for value in values:
            require(value['architecture'] == 'x86_64' and value['minimum'] == (13, 0, 0) and not value['rpaths']
                    and all(name.startswith(('/usr/lib/', '/System/Library/Frameworks/')) for name in value['dependencies']), 'Intel dependency closure differs')
        if values: slices.append({'path': row['path'], 'slices': values})
    bindings.check()
    shutil.copy2(cache / 'manifest.json', root / 'origin-package-manifest.json')
    write(root / 'native-slices.json', slices)
    wheel = wheels / wheel_name
    require(wheel.parent == wheels and wheel.is_file(), 'Owned wheel path required')
    write(root / 'build-result.json', {'schema': 1, 'source_sha': os.environ['GITHUB_SHA'], 'architecture': platform.machine(),
        'wheel': wheel_name, 'wheel_sha256': sha(wheel), 'input_inventory_sha256': inventory_sha,
        'source_pins_sha256': sha(root / 'source-pins.json'), 'original_package_manifest_sha256': sha(root / 'origin-package-manifest.json'),
        'python_sha256': sha(Path(sys.executable)), 'python_version': sys.version, 'git_build_calls': calls,
        'native_rows': len(inventory), 'native_files': 230, 'macho_slices': len(slices), 'build': manifest['build']})


def package(checkout, root, *, failed=False, registered=False, bindings=None):
    """Publish only an explicit derived technical allowlist, including failures."""
    ci = load('_transfer_ci', checkout / 'tools/ci_build.py')
    public = root / ('failure-transfer' if failed else 'transfer'); public.mkdir(mode=0o700)
    original = []
    replacements = [(str(root), '${QUALIFICATION}'), (str(root.resolve(strict=True)), '${QUALIFICATION}'),
                    (str(checkout), '${SOURCE}'), (str(checkout.resolve(strict=True)), '${SOURCE}'),
                    (str(Path(sys.executable).parent.parent), '${PYTHON}'),
                    (str(Path(sys.executable).resolve(strict=True).parent.parent), '${PYTHON}')]
    total = 0
    if registered and not failed:
        require(bindings is not None, 'Original registered transfer bindings required')
        check_bound(bindings)
    def add(name, data, *, mode=0o644, normalize=False):
        nonlocal total
        ci.relative(name)
        if registered and not failed:
            require(name in bindings and data == read_bound(bindings, name), 'Copied registered evidence changed: ' + name)
        before = hashlib.sha256(data).hexdigest()
        if normalize:
            data = normalized_text(data, replacements)
        total += len(data); require(total <= 128 * 1024 ** 2 and len(original) < 8192, 'Transfer retained-byte/member limit')
        path = public / name; path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        with path.open('xb') as stream: stream.write(data)
        path.chmod(mode)
        original.append({'path': name, 'mode': oct(mode), 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                         'original_sha256': before, 'path_normalized': normalize})
    # Source allowlist is code data, never a recursive checkout/work-directory upload.
    names = ci.source_names(checkout) + ['tools/ci_native_campaign.py', 'tools/ci_native_qualify.py',
        'tools/ci_native_python.py', 'tools/ci_build.py', 'tools/_ci_cache.py', 'tools/ci_git_input.py',
        'tools/package_fskit.py', 'tools/ci-build-requirements.txt', 'tools/ci-git-components.json']
    if registered: names += list(CONTROLLERS)
    for name in sorted(set(names)): add('source/' + name, (checkout / name).read_bytes())
    metadata_names = ('source-pins.json', 'input-inventory.json', 'origin-package-manifest.json', 'native-slices.json',
                      'build-result.json', 'execution-result.json', 'execution-before-transfer.json',
                      'transfer-invalidated.json', 'dependency-origin.json')
    for name in metadata_names:
        if (root / name).is_file(): add('evidence/' + name, (root / name).read_bytes(), normalize=True)
    if registered:
        for name in ('component-reference.json', 'controller-source-pins.json', 'registered-bindings.json'):
            if (root / name).is_file(): add('evidence/' + name, (root / name).read_bytes(), normalize=True)
        for name in ('source-pins.json', 'build-result.json', 'native-input.json', 'admission-result.json'):
            path = root / 'producer' / name
            if path.is_file(): add('evidence/current-producer/' + name, path.read_bytes(), normalize=True)
        if (root / 'component-download.json').is_file():
            add('evidence/component-download.json', (root / 'component-download.json').read_bytes(), normalize=True)
        for name in ('component-manifest.json', 'qualification-source-pins.json', 'input-inventory.json',
                     'qualification.json', 'package-manifest.json', 'provenance.json'):
            path = root / 'component' / name
            if path.is_file(): add('evidence/historical-component/' + name, path.read_bytes(), normalize=True)
        if not failed:
            producer_result, wheel = registered_producer(checkout, root / 'producer')
            wheel_bytes = wheel.read_bytes()
            require(hashlib.sha256(wheel_bytes).hexdigest() == producer_result['wheel_sha256'], 'Transfer wheel changed')
            add('wheel/' + wheel.name, wheel_bytes)
    # Only fixed collector filenames and numbered command receipts/streams qualify.
    for path in sorted(root.glob('stage-*.*')):
        if re.fullmatch(r'stage-[a-z-]+\.(command\.json|stdout\.bin|stderr\.bin)', path.name):
            add('evidence/capture/' + path.name, path.read_bytes(), normalize=True)
    campaign = root / 'campaign'
    for name in ('before.json', 'after.json', 'commands.json', 'result.json', 'inert-guards.json'):
        if (campaign / name).is_file(): add('evidence/campaign/' + name, (campaign / name).read_bytes(), normalize=True)
    for path in sorted((campaign / 'owned-commands').glob('*/*')):
        if re.fullmatch(r'[0-9]{4}', path.parent.name) and re.fullmatch(r'(?:[0-9]{2}-receipt|request|result)\.json|stdout|stderr', path.name):
            add('evidence/campaign/owned-commands/' + path.parent.name + '/' + path.name, path.read_bytes(), normalize=True)
    # Preserve complete current raw runtime plus corresponding delivered sources.
    cache_manifest = root / 'origin-package-manifest.json'
    complete_runtime = not registered and not failed and cache_manifest.is_file() and (root / 'build-result.json').is_file()
    if complete_runtime and (root / 'Git').is_dir():
        for path in sorted((root / 'Git').rglob('*')):
            if path.is_file(): add('Git/' + path.relative_to(root / 'Git').as_posix(), path.read_bytes(), mode=stat.S_IMODE(path.stat().st_mode))
    if complete_runtime:
        manifest = json.loads(cache_manifest.read_bytes())
        receipt = json.loads((root / 'build-result.json').read_bytes())
        # Build destination is recorded by the actual build-call receipt.
        cache = Path(receipt['git_build_calls'][0]['destination'])
        for row in manifest['files']:
            if row['path'].startswith('sources/') or row['path'] in ('COPYING', 'CURL-COPYING', 'SOURCES.txt'):
                data = (cache / row['path']).read_bytes()
                require(hashlib.sha256(data).hexdigest() == row['sha256'], 'Transfer source asset changed')
                add('Sources/Git/' + row['path'], data)
    kind = ('failed-registered-recheck-transfer' if failed else 'registered-recheck-transfer') if registered else ('failed-qualification-transfer' if failed else 'raw-qualification-transfer-not-qualified-component')
    manifest = {'schema': 1, 'kind': kind,
        **({'recheck_passed': not failed, 'architecture': registered_architecture(os.environ)} if registered else {'qualification_passed': not failed}),
        'runtime_binaries_included': (not failed if registered else complete_runtime),
        'source_sha': os.environ['GITHUB_SHA'], 'files': original,
        'receipt_transformation': 'Owned absolute paths replaced with declared coordinate tokens; original and derived digests retained.',
        'coordinates': ['${QUALIFICATION}', '${SOURCE}', '${PYTHON}']}
    manifest_bytes = json_bytes(manifest)
    write(public / 'transfer-manifest.json', manifest)
    archive = transfer_archive(root, failed=failed, registered=registered)
    if registered:
        staged = {row['path']: row for row in original}
        staged['transfer-manifest.json'] = {'size': len(manifest_bytes), 'mode': '0o644',
            'sha256': hashlib.sha256(manifest_bytes).hexdigest()}
        actual_files = set(); actual_dirs = set()
        for path in public.rglob('*'):
            require(not path.is_symlink(), 'Registered staging link refused')
            (actual_dirs if path.is_dir() else actual_files).add(path.relative_to(public).as_posix())
        expected_dirs = {str(parent) for name in staged for parent in Path(name).parents if str(parent) != '.'}
        require(actual_files == set(staged) and actual_dirs == expected_dirs, 'Registered staging namespace changed')
        with tarfile.open(archive, 'w:xz', format=tarfile.USTAR_FORMAT, preset=1) as output:
            for name, row in sorted(staged.items()):
                path = public / name; identity = binding_identity(path); data = path.read_bytes()
                require(binding_identity(path) == identity and len(data) == row['size']
                        and oct(stat.S_IMODE(identity[2])) == row['mode']
                        and hashlib.sha256(data).hexdigest() == row['sha256'], 'Registered staged bytes changed: ' + name)
                info = tarfile.TarInfo(name); info.size = len(data); info.mode = int(row['mode'], 8)
                output.addfile(info, io.BytesIO(data))
        registered_archive(root, archive, hashlib.sha256(manifest_bytes).hexdigest(), failed=failed,
            bindings=bindings, execution_sha256=bindings['evidence/execution-result.json']['sha256'] if not failed else None)
        if not failed: check_bound(bindings)
    else:
        with tarfile.open(archive, 'w:xz', format=tarfile.USTAR_FORMAT, preset=1) as output:
            for path in sorted(public.rglob('*')):
                if not path.is_file(): continue
                info = tarfile.TarInfo(path.relative_to(public).as_posix())
                data = path.read_bytes(); info.size = len(data); info.mode = stat.S_IMODE(path.stat().st_mode)
                output.addfile(info, io.BytesIO(data))
    require(archive.stat().st_size <= 512 * 1024 ** 2, 'Transfer archive exceeds operational limit')
    transfer_receipt = {'archive_sha256': sha(archive), 'bytes': archive.stat().st_size,
                                        'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest() if registered else sha(public / 'transfer-manifest.json'),
                                        **({'kind': REGISTERED_KIND, 'architecture': registered_architecture(os.environ), 'bindings_sha256': sha(root / 'registered-bindings.json') if not failed else None} if registered else {})}
    receipt_path = root / ('failure-transfer-result.json' if failed else 'transfer-result.json')
    write(receipt_path, transfer_receipt)
    if registered and not failed:
        bind_input(bindings, '@transfer-receipt', receipt_path, hashlib.sha256(json_bytes(transfer_receipt)).hexdigest())


def execute(checkout, root, *, registered=False):
    root = root.parent.resolve(strict=True) / root.name
    gate(os.environ, registered=registered)
    architecture = registered_architecture(os.environ) if registered else 'x86_64'
    require(platform.machine() == architecture and sys.platform == 'darwin',
            'Actual registered host differs' if registered else 'Actual Intel host required')
    require(not root.exists(), 'Qualification packet is one-shot')
    root.mkdir(mode=0o700)
    capture = load('_qualification_capture', checkout / 'tools/_git_capture.py')
    capture._COMMAND_ENV = {key: os.environ[key] for key in ('HOME', 'USER', 'LOGNAME', 'PATH', 'GITHUB_SHA', 'RUNNER_OS',
        'RUNNER_ARCH', 'RUNNER_TEMP', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT') if key in os.environ}
    (root / 'tmp').mkdir(mode=0o700)
    capture._COMMAND_ENV.update(TMPDIR=str(root / 'tmp'), PYTHONDONTWRITEBYTECODE='1', LANG='C', LC_ALL='C',
        MAKEFLAGS='-j1', CMAKE_BUILD_PARALLEL_LEVEL='1', MAX_JOBS='1')
    started = time.monotonic(); overall = started + 1620
    stages = []; failure = None
    bindings = {}; bindings_sha256 = None
    previous = capture._install_command_handlers()
    def run(label, argv, timeout):
        remaining = int(overall - time.monotonic()) - 30
        require(remaining > timeout, 'Combined qualification deadline reserve')
        stage = {'label': label, 'argv': argv, 'timeout_seconds': timeout}
        stages.append(stage)
        result = capture._owned_command(argv, cwd=root, timeout=timeout, stem=root / ('stage-' + label))
        stage['returncode'] = result.returncode
        result.check_returncode()
        require_capture(capture)
    try:
        dependency = Path(sys.executable).resolve().parents[2] / 'origin.json'
        require(dependency.is_file(), 'Owned dependency origin required')
        origin = json.loads(dependency.read_bytes())
        require(origin['executable_sha256'] == sha(Path(sys.executable)) and (registered or origin['version'] == '3.13.18'), 'Owned dependency identity differs')
        shutil.copy2(dependency, root / 'dependency-origin.json')
        controller_pins = None
        if registered:
            interpreter = load('_registered_python', checkout / 'tools/ci_native_python.py')
            profile = interpreter.PROFILES[architecture]
            require(sys.version_info[:3] == tuple(map(int, profile['version'].split('.')))
                    and origin['architecture'] == architecture
                    and all(origin[name] == profile[name] for name in ('url', 'sha256', 'bytes', 'executable_sha256', 'version')),
                    'Pinned registered interpreter origin required')
            controller_pins = {name: sha(checkout / name) for name in CONTROLLERS}
            write(root / 'controller-source-pins.json', controller_pins)
            for name, digest in controller_pins.items(): bind_input(bindings, 'source/' + name, checkout / name, digest)
            bind_input(bindings, 'evidence/controller-source-pins.json', root / 'controller-source-pins.json', hashlib.sha256(json_bytes(controller_pins)).hexdigest())
            bind_input(bindings, '@interpreter', Path(sys.executable), origin['executable_sha256'])
            bind_input(bindings, 'evidence/dependency-origin.json', root / 'dependency-origin.json', sha(dependency))
        script = str(checkout / 'tools/ci_native_qualify.py')
        for label, argv in (
            ('os-build', ['/usr/bin/sw_vers', '-buildVersion']),
            ('xcode', ['/usr/bin/xcodebuild', '-version']),
            ('sdk-version', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version']),
            ('sdk-path', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'])):
            run(label, argv, 30)
        if registered:
            registered_stages(checkout, root, run, bindings=bindings)
            require(all(sha(checkout / name) == value for name, value in controller_pins.items()), 'Controller source changed')
        else:
            run('build', [sys.executable, '-I', '-B', script, 'build', '--checkout', str(checkout), '--root', str(root)], 600)
            result = json.loads((root / 'build-result.json').read_bytes())
            wheel = root / 'wheels' / result['wheel']
            require(sha(wheel) == result['wheel_sha256'], 'Built wheel changed before install')
            run('install', [sys.executable, '-I', '-B', '-m', 'pip', '--isolated', 'install', '--no-index', '--no-deps',
                '--no-compile', '--force-reinstall', str(wheel)], 45)
            run('campaign', [sys.executable, '-I', '-B', str(checkout / 'tools/ci_native_campaign.py'),
                '--checkout', str(checkout), '--packet', str(root), '--output', str(root / 'campaign')], 900)
            campaign = json.loads((root / 'campaign/result.json').read_bytes())
            require(campaign['passed'] and campaign['input_unchanged'] and campaign['input_unregistered'] and campaign['owned_commands'] == 581
                    and len(campaign['successes']) == 10 and len(campaign['strict_native_environment_commands']) == 92
                    and len(campaign['structural_refusals']) == 27, 'Complete raw campaign required')
    except BaseException as error:
        failure = {'type': type(error).__name__, 'message': str(error)}
    finally:
        def remember(error):
            nonlocal failure
            detail = {'type': type(error).__name__, 'message': str(error)}
            if failure is None: failure = detail
            else: failure.setdefault('finalization_errors', []).append(detail)
        def outcome():
            return {'schema': 1, 'passed': failure is None, 'failure': failure,
                'elapsed_seconds': time.monotonic() - started, 'stages': stages, 'capture_state': capture._command_state,
                **({'kind': REGISTERED_KIND, 'bindings_sha256': bindings_sha256, 'architecture': architecture} if registered else {})}
        try:
            capture._restore_command_handlers(previous)
        except BaseException as error:
            remember(error)
        try:
            require_capture(capture)
        except BaseException as error:
            remember(error)
        result_path = root / 'execution-result.json'
        if registered and failure is None:
            try:
                for path in sorted(root.glob('stage-*.*')):
                    if re.fullmatch(r'stage-[a-z-]+\.(command\.json|stdout\.bin|stderr\.bin)', path.name):
                        bind_input(bindings, 'evidence/capture/' + path.name, path)
                check_bound(bindings)
                binding_bytes = json_bytes(bindings)
                bindings_sha256 = hashlib.sha256(binding_bytes).hexdigest()
                write(root / 'registered-bindings.json', bindings)
                bind_input(bindings, 'evidence/registered-bindings.json', root / 'registered-bindings.json', bindings_sha256)
            except BaseException as error:
                remember(error)
        observation = outcome()
        write(result_path, observation)
        if failure is None:
            try:
                if registered:
                    bind_input(bindings, 'evidence/execution-result.json', result_path, hashlib.sha256(json_bytes(observation)).hexdigest())
                require_capture(capture)
                package(checkout, root, **({'registered': True, 'bindings': bindings} if registered else {}))
                if registered:
                    transfer_decision(root, failed=False, registered=True, bindings=bindings)
                require_capture(capture)
            except BaseException as error:
                remember(error)
                # Preserve the exact earlier observation and any prior archive;
                # only the new overall result may describe finalization failure.
                previous_path = root / 'execution-before-transfer.json'
                require(not previous_path.exists(), 'Prior execution observation already retained')
                result_path.rename(previous_path)
                write(result_path, {**outcome(), 'previous_observation_sha256': sha(previous_path)})
        if failure is not None:
            write(root / 'transfer-invalidated.json', {'schema': 1, 'qualification_passed': False,
                'failure': failure, 'prior_transfer_sha256': sha(root / 'transfer-result.json')
                    if (root / 'transfer-result.json').is_file() else None})
            # A failed transfer contains finite technical evidence, not runtime
            # binaries whose ownership/qualification may remain unresolved.
            before = json.dumps(capture._command_state, sort_keys=True)
            transfer_error = None
            try:
                package(checkout, root, failed=True, **({'registered': True} if registered else {}))
                require(json.dumps(capture._command_state, sort_keys=True) == before,
                        'Capture state changed during failed-evidence finalization')
            except BaseException as error:
                transfer_error = error
                remember(error)
                previous_path = root / 'execution-before-failure-transfer.json'
                require(not previous_path.exists(), 'Failed transfer observation already retained')
                result_path.rename(previous_path)
                write(result_path, {**outcome(), 'previous_observation_sha256': sha(previous_path)})
                write(root / 'failure-transfer-invalidated.json', {'schema': 1, 'failure': failure,
                    'prior_transfer_sha256': sha(root / 'failure-transfer-result.json')
                        if (root / 'failure-transfer-result.json').is_file() else None})
            if transfer_error is not None:
                raise RuntimeError('Failed-evidence transfer finalization failed') from transfer_error
        else:
            require_capture(capture)
        complete_transfer(root, failed=failure is not None, registered=registered, bindings=bindings if registered and failure is None else None)
    require(failure is None, 'Qualification failed; reviewed finite failure transfer retained')


def transfer_archive(root, *, failed, registered=False):
    stem = 'registered-git-recheck-' + registered_architecture(os.environ) if registered else 'native-git-qualification'
    return root / (stem + ('.failure' if failed else '') + '.tar.xz')


def transfer_decision(root, *, failed, registered=False, bindings=None):
    require(not (root / 'failure-transfer-invalidated.json').exists(), 'Failed-evidence transfer finalization is incomplete')
    require(type(failed) is bool, 'Transfer verdict must be explicit')
    require(failed or not (root / 'transfer-invalidated.json').exists(), 'Normal transfer was invalidated')
    result_path = root / 'execution-result.json'
    receipt_path = root / ('failure-transfer-result.json' if failed else 'transfer-result.json')
    for path in (result_path, receipt_path):
        require(path.is_file() and not path.is_symlink(), 'Finalized transfer input missing')
    result_bytes = result_path.read_bytes(); result = json.loads(result_bytes)
    receipt_bytes = receipt_path.read_bytes(); receipt = json.loads(receipt_bytes)
    require(type(result.get('schema')) is int and result['schema'] == 1 and 'failure' in result
            and type(result.get('passed')) is bool and result['passed'] is (not failed)
            and (result.get('failure') is None) is (not failed), 'Finalized execution verdict differs')
    require(result.get('kind') == REGISTERED_KIND if registered else result.get('kind') != REGISTERED_KIND,
            'Execution transfer kind differs')
    require(receipt.get('kind') == REGISTERED_KIND if registered else receipt.get('kind') != REGISTERED_KIND,
            'Receipt transfer kind differs')
    if registered:
        gate(os.environ, registered=True)
        require(result['architecture'] == receipt['architecture'] == registered_architecture(os.environ),
                'Registered evidence architecture differs')
    if not failed:
        state = result['capture_state']
        require(state.get('failure') is None and state.get('active') is None
                and state.get('first_signal') is None and state.get('signal_count', 0) == 0,
                'Successful transfer capture is incomplete')
    archive = transfer_archive(root, failed=failed, registered=registered)
    require(archive.is_file() and not archive.is_symlink() and 0 < archive.stat().st_size <= 512 * 1024 ** 2
            and archive.stat().st_size == receipt['bytes'] and sha(archive) == receipt['archive_sha256'],
            'Finite transfer receipt differs')
    if registered:
        if not failed:
            saved_bytes = (root / 'registered-bindings.json').read_bytes()
            saved = json.loads(saved_bytes)
            require(hashlib.sha256(saved_bytes).hexdigest() == result['bindings_sha256'] == receipt['bindings_sha256'],
                    'Original registered closure binding differs')
            if bindings is not None:
                require(saved == {name: row for name, row in bindings.items() if name not in
                    ('evidence/registered-bindings.json', 'evidence/execution-result.json', '@transfer-receipt')}, 'Original in-memory registered bindings differ')
            else:
                bindings = saved
                bind_input(bindings, 'evidence/registered-bindings.json', root / 'registered-bindings.json', result['bindings_sha256'])
                bind_input(bindings, 'evidence/execution-result.json', result_path, hashlib.sha256(result_bytes).hexdigest())
            check_bound(bindings)
        registered_archive(root, archive, receipt['manifest_sha256'], failed=failed, bindings=bindings,
            execution_sha256=hashlib.sha256(result_bytes).hexdigest() if not failed else None)
    source = os.environ.get('GITHUB_SHA', '')
    require(re.fullmatch('[0-9a-f]{40}', source), 'Transfer source SHA missing')
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '')
    require(re.fullmatch('[1-9][0-9]*', run_id) and attempt == '1', 'Transfer run identity missing or repeated')
    return {'schema': 1, 'source_sha': source, 'run_id': run_id, 'run_attempt': attempt, 'failed': failed,
            'execution_result_sha256': hashlib.sha256(result_bytes).hexdigest(),
            'receipt_sha256': hashlib.sha256(receipt_bytes).hexdigest(),
            'archive_sha256': receipt['archive_sha256'], **({'kind': REGISTERED_KIND, 'bindings_sha256': result.get('bindings_sha256'), 'architecture': result['architecture']} if registered else {})}, archive


def complete_transfer(root, *, failed, registered=False, bindings=None):
    decision, _ = transfer_decision(root, failed=failed, registered=registered, bindings=bindings)
    pending = root / 'transfer-completion.pending.json'
    write(pending, decision)
    with pending.open('rb') as stream: os.fsync(stream.fileno())
    # Atomic, exclusive publication after all outcome/archive checks. A failed
    # or partial pending write never becomes affirmative upload eligibility.
    os.link(pending, root / 'transfer-completion.json')


def transfer_ready(root, *, registered=False):
    completion = root / 'transfer-completion.json'
    require(completion.is_file() and not completion.is_symlink(), 'Terminal transfer completion missing')
    decision = json.loads(completion.read_bytes())
    require(type(decision.get('failed')) is bool, 'Transfer completion verdict missing')
    expected, archive = transfer_decision(root, failed=decision['failed'], registered=registered)
    require(decision == expected, 'Terminal transfer completion bindings differ')
    require(os.environ.get('QUALIFICATION_STEP_OUTCOME') == ('failure' if decision['failed'] else 'success'),
            'Workflow execution outcome differs from transfer completion')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('available=true\narchive=' + str(archive) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=('gate', 'execute', 'build', 'transfer-ready', 'execute-registered', 'registered-transfer-ready', 'admit-installed'))
    parser.add_argument('--checkout', type=Path, required=True); parser.add_argument('--root', type=Path)
    args = parser.parse_args()
    if args.action == 'gate': gate(os.environ)
    else:
        require(args.root is not None, 'Root required')
        if args.action in ('transfer-ready', 'registered-transfer-ready'):
            transfer_ready(args.root.absolute(), registered=args.action == 'registered-transfer-ready')
        elif args.action == 'execute-registered':
            execute(args.checkout.resolve(strict=True), args.root.absolute(), registered=True)
        else: {'build': build, 'execute': execute, 'admit-installed': admit_installed}[args.action](args.checkout.resolve(strict=True), args.root.absolute())
