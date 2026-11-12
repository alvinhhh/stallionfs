"""Inert, explicitly qualified writer records for controller fixtures."""
import copy
from pathlib import Path
from unittest.mock import patch

from stallionfs import _bundle, _native, _native_create_request as request, _native_create_git as git
from stallionfs import _native_create_authority as authority


INPUT = '7' * 64


def qualify(test):
    selected = patch.object(_bundle, 'QUALIFIED_GIT_INPUTS', frozenset({INPUT}))
    selected.start(); test.addCleanup(selected.stop)
    architecture = patch.object(_bundle, 'QUALIFIED_GIT_ARCHITECTURES', {INPUT: 'arm64'})
    architecture.start(); test.addCleanup(architecture.stop)


def runtime():
    return {**_bundle.GIT_CONTRACT, 'input_inventory_sha256': INPUT, 'payload_entries': 239,
            'payload_sha256': '1' * 64, 'descriptor_sha256': '2' * 64, 'executable_sha256': '3' * 64,
            'source_build_id': '4' * 64, 'publisher': _bundle.PUBLISHER_TEAM}


def writer(origin, stage):
    stage = Path(stage)
    spec = dict(protocol=request.PROTOCOL, workspace=origin['id'], transaction=origin['transaction'],
        seed=origin['seed'], seed_identity=[1, 2], commit=origin['commit'], name=origin['name'],
        branch=origin['branch'], capacity_gib=origin['capacity_gib'], jobs=1,
        budget=copy.deepcopy(request.DEFAULT_BUDGET), install=False, profile='production', host=str(_native.HOST),
        stage=str(stage), stage_identity=origin['native_image']['parent'], input_identity=[1, 3],
        object=origin['native_image']['object'], store_lock=[1, 4], seed_lock=[1, 5],
        lease={'file': [1, 6], 'generation': request.generation(None, origin['id'], origin['transaction'])},
        workspace_lock=[1, 7], method=request.METHOD, runtime=runtime(), parent=None)
    repo = stage / 'input/repo'
    prefix = ['--git-dir=' + str(repo / '.git'), '--work-tree=' + str(repo)]
    commands = [['config', '--file', str(repo / '.git/config'), '--no-includes', '--null', '--list'],
        [*prefix, 'for-each-ref', '--include-root-refs', '--format=%(refname)'],
        [*prefix, 'rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}'],
        [*prefix, 'symbolic-ref', '--quiet', 'HEAD'], [*prefix, 'checkout', '-b', spec['branch']]]
    def terminal(code=0):
        return dict(outcome='success' if code == 0 else 'error', child_pending=False, pid=123,
                    reaped=True, returncode=code, streams_eof=True, streams_durable=True, output_bytes=0)
    actors = []
    executable = '/Fixture.app/Contents/Resources/Runtime/Git/bin/git'
    for role, args, code in zip(('00-config', '01-refs', '02-head', '03-head-state', '04-checkout'), commands, (0, 0, 0, 1, 0)):
        log = stage / 'actors' / role
        actors.append(dict(terminal(code), role=role, cwd=str(stage / 'actors/environment/inspect'),
            environment=git.POLICY, runtime=spec['runtime'], input={'repository': [1, 8], 'git': [1, 9],
                'config': {'file': [1, 10], 'sha256': '8' * 64}},
            executable={'path': executable, 'sha256': spec['runtime']['executable_sha256']},
            argv=[executable, *git.PREFIX, *args], stdout=str(log / 'stdout'), stderr=str(log / 'stderr')))
    log = stage / 'discovery/00-verify-package'
    helper = dict(terminal(), label='verify-package', argv=_native.package_argv(spec['host']),
        cwd=str(stage / 'discovery'), environment='native-preflight-empty-environment-v3',
        stdout=str(log / 'stdout'), stderr=str(log / 'stderr'))
    record = {'spec_digest': request.digest(spec), 'actors': actors, 'helpers': [helper], 'child_pending': False}
    return authority.packet(spec, record)
