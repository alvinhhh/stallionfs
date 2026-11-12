"""One raw Intel build/campaign; never registers an input or supplies app authority."""
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


def gate(environment):
    expected = environment.get('EXPECTED_SOURCE_SHA', '')
    require(re.fullmatch('[0-9a-f]{40}', expected) and environment.get('GITHUB_SHA') == expected,
            'Exact reviewed source SHA required')
    require(environment.get('GITHUB_RUN_ATTEMPT') == '1', 'Qualification reruns are refused')
    require(environment.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and environment.get('QUALIFICATION_MODE') == 'native-git-qualification', 'Explicit manual qualification required')
    require(environment.get('RUNNER_OS') == 'macOS' and environment.get('RUNNER_ARCH') == 'X64', 'Standard Intel runner required')


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


def package(checkout, root, *, failed=False):
    """Publish only an explicit derived technical allowlist, including failures."""
    ci = load('_transfer_ci', checkout / 'tools/ci_build.py')
    public = root / ('failure-transfer' if failed else 'transfer'); public.mkdir(mode=0o700)
    original = []
    replacements = [(str(root), '${QUALIFICATION}'), (str(root.resolve(strict=True)), '${QUALIFICATION}'),
                    (str(checkout), '${SOURCE}'), (str(checkout.resolve(strict=True)), '${SOURCE}'),
                    (str(Path(sys.executable).parent.parent), '${PYTHON}'),
                    (str(Path(sys.executable).resolve(strict=True).parent.parent), '${PYTHON}')]
    total = 0
    def add(name, data, *, mode=0o644, normalize=False):
        nonlocal total
        ci.relative(name)
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
    for name in sorted(set(names)): add('source/' + name, (checkout / name).read_bytes())
    metadata_names = ('source-pins.json', 'input-inventory.json', 'origin-package-manifest.json', 'native-slices.json',
                      'build-result.json', 'execution-result.json', 'execution-before-transfer.json',
                      'transfer-invalidated.json', 'dependency-origin.json')
    for name in metadata_names:
        if (root / name).is_file(): add('evidence/' + name, (root / name).read_bytes(), normalize=True)
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
    complete_runtime = not failed and cache_manifest.is_file() and (root / 'build-result.json').is_file()
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
    write(public / 'transfer-manifest.json', {'schema': 1, 'kind': 'failed-qualification-transfer' if failed else 'raw-qualification-transfer-not-qualified-component',
        'qualification_passed': not failed, 'runtime_binaries_included': complete_runtime,
        'source_sha': os.environ['GITHUB_SHA'], 'files': original,
        'receipt_transformation': 'Owned absolute paths replaced with declared coordinate tokens; original and derived digests retained.',
        'coordinates': ['${QUALIFICATION}', '${SOURCE}', '${PYTHON}']})
    archive = root / ('native-git-qualification.failure.tar.xz' if failed else 'native-git-qualification.tar.xz')
    with tarfile.open(archive, 'w:xz', format=tarfile.USTAR_FORMAT, preset=1) as output:
        for path in sorted(public.rglob('*')):
            if not path.is_file(): continue
            info = tarfile.TarInfo(path.relative_to(public).as_posix())
            data = path.read_bytes(); info.size = len(data); info.mode = stat.S_IMODE(path.stat().st_mode)
            output.addfile(info, io.BytesIO(data))
    require(archive.stat().st_size <= 512 * 1024 ** 2, 'Transfer archive exceeds operational limit')
    write(root / ('failure-transfer-result.json' if failed else 'transfer-result.json'), {'archive_sha256': sha(archive), 'bytes': archive.stat().st_size,
                                        'manifest_sha256': sha(public / 'transfer-manifest.json')})


def execute(checkout, root):
    root = root.parent.resolve(strict=True) / root.name
    gate(os.environ)
    require(platform.machine() == 'x86_64' and sys.platform == 'darwin', 'Actual Intel host required')
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
        require(origin['executable_sha256'] == sha(Path(sys.executable)) and origin['version'] == '3.13.18', 'Owned dependency identity differs')
        shutil.copy2(dependency, root / 'dependency-origin.json')
        script = str(checkout / 'tools/ci_native_qualify.py')
        for label, argv in (
            ('os-build', ['/usr/bin/sw_vers', '-buildVersion']),
            ('xcode', ['/usr/bin/xcodebuild', '-version']),
            ('sdk-version', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version']),
            ('sdk-path', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'])):
            run(label, argv, 5)
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
                'elapsed_seconds': time.monotonic() - started, 'stages': stages, 'capture_state': capture._command_state}
        try:
            capture._restore_command_handlers(previous)
        except BaseException as error:
            remember(error)
        try:
            require_capture(capture)
        except BaseException as error:
            remember(error)
        result_path = root / 'execution-result.json'
        write(result_path, outcome())
        if failure is None:
            try:
                require_capture(capture)
                package(checkout, root)
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
                package(checkout, root, failed=True)
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
        complete_transfer(root, failed=failure is not None)
    require(failure is None, 'Qualification failed; reviewed finite failure transfer retained')


def transfer_decision(root, *, failed):
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
    if not failed:
        state = result['capture_state']
        require(state.get('failure') is None and state.get('active') is None
                and state.get('first_signal') is None and state.get('signal_count', 0) == 0,
                'Successful transfer capture is incomplete')
    archive = root / ('native-git-qualification.failure.tar.xz' if failed else 'native-git-qualification.tar.xz')
    require(archive.is_file() and not archive.is_symlink() and 0 < archive.stat().st_size <= 512 * 1024 ** 2
            and archive.stat().st_size == receipt['bytes'] and sha(archive) == receipt['archive_sha256'],
            'Finite transfer receipt differs')
    source = os.environ.get('GITHUB_SHA', '')
    require(re.fullmatch('[0-9a-f]{40}', source), 'Transfer source SHA missing')
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '')
    require(re.fullmatch('[1-9][0-9]*', run_id) and attempt == '1', 'Transfer run identity missing or repeated')
    return {'schema': 1, 'source_sha': source, 'run_id': run_id, 'run_attempt': attempt, 'failed': failed,
            'execution_result_sha256': hashlib.sha256(result_bytes).hexdigest(),
            'receipt_sha256': hashlib.sha256(receipt_bytes).hexdigest(),
            'archive_sha256': receipt['archive_sha256']}, archive


def complete_transfer(root, *, failed):
    decision, _ = transfer_decision(root, failed=failed)
    pending = root / 'transfer-completion.pending.json'
    write(pending, decision)
    with pending.open('rb') as stream: os.fsync(stream.fileno())
    # Atomic, exclusive publication after all outcome/archive checks. A failed
    # or partial pending write never becomes affirmative upload eligibility.
    os.link(pending, root / 'transfer-completion.json')


def transfer_ready(root):
    completion = root / 'transfer-completion.json'
    require(completion.is_file() and not completion.is_symlink(), 'Terminal transfer completion missing')
    decision = json.loads(completion.read_bytes())
    require(type(decision.get('failed')) is bool, 'Transfer completion verdict missing')
    expected, archive = transfer_decision(root, failed=decision['failed'])
    require(decision == expected, 'Terminal transfer completion bindings differ')
    require(os.environ.get('QUALIFICATION_STEP_OUTCOME') == ('failure' if decision['failed'] else 'success'),
            'Workflow execution outcome differs from transfer completion')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('available=true\narchive=' + str(archive) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=('gate', 'execute', 'build', 'transfer-ready'))
    parser.add_argument('--checkout', type=Path, required=True); parser.add_argument('--root', type=Path)
    args = parser.parse_args()
    if args.action == 'gate': gate(os.environ)
    else:
        require(args.root is not None, 'Root required')
        if args.action == 'transfer-ready': transfer_ready(args.root.absolute())
        else: {'build': build, 'execute': execute}[args.action](args.checkout.resolve(strict=True), args.root.absolute())
