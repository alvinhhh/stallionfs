"""Positive writer evidence, separate from historical image inspection."""
import copy
import json
from pathlib import Path

from . import core, _native, _bundle
from ._native_create_recovery import require

MAX_PACKET = 65536


def current(spec):
    from . import _native_create_request as request
    request.schema(spec)
    require(spec['protocol'] == request.PROTOCOL and spec['method'] == request.METHOD,
            'unverified-writer')
    runtime = spec['runtime']
    try:
        _bundle.git_contract({key: runtime[key] for key in set(_bundle.GIT_CONTRACT) | {'input_inventory_sha256'}}, architecture='arm64')
    except (ValueError, KeyError):
        require(False, 'unverified-writer')


def packet(spec, record):
    value = {'schema': 1, 'spec_digest': record['spec_digest'], 'spec': copy.deepcopy(spec), 'actors': copy.deepcopy(record['actors']),
             'preflight': {key: copy.deepcopy(record[key]) for key in ('helpers', 'child_pending') if key in record}}
    if 'discovery' in record:
        value['preflight']['discovery'] = copy.deepcopy(record['discovery'])
    return value


def proof(origin, created):
    """Validate recorded semantics without reopening retired paths or streams."""
    from . import _native_create_request as request, _native_create_retry as retry, _native_create_git as git
    from ._native_create_recovery import origin_metadata
    require(type(created) is dict and ('format' not in created
            or type(created['format']) is int and created['format'] == 1), 'unverified-writer')
    origin_metadata(origin, {key: item for key, item in created.items() if key != 'format'})
    value = created.get('writer')
    require(type(value) is dict and set(value) == {'schema', 'spec_digest', 'spec', 'actors', 'preflight'}
            and type(value['schema']) is int and value['schema'] == 1, 'unverified-writer')
    require(len(json.dumps(value, sort_keys=True, allow_nan=False).encode()) <= MAX_PACKET, 'unverified-writer')
    spec = value['spec']; current(spec)
    require(value['spec_digest'] == request.digest(spec), 'unverified-writer')
    stage = Path(spec['stage'])
    require(stage.is_absolute() and stage.name == 'native-create-' + spec['transaction']
            and stage.parent.name == 'staging' and '..' not in stage.parts,
            'unverified-writer')
    require(all(spec[key] == origin[target] for key, target in
                (('workspace', 'id'), ('transaction', 'transaction'), ('seed', 'seed'), ('commit', 'commit'),
                 ('name', 'name'), ('branch', 'branch'), ('capacity_gib', 'capacity_gib')))
            and spec['stage_identity'] == origin['native_image']['parent']
            and spec['object'] == origin['native_image']['object'], 'unverified-writer')
    rows = value['actors']
    require(type(rows) is list and len(rows) == 5, 'unverified-writer')
    retry.actors({'stage': str(stage), 'actors': rows}, spec, pending=False)
    for row, code in zip(rows, (0, 0, 0, 1, 0)):
        require(row['returncode'] == code and row['outcome'] == ('success' if code == 0 else 'error'), 'unverified-writer')
    preflight = value['preflight']
    expected = {'helpers', 'child_pending'} | ({'discovery'} if spec['install'] else set())
    require(type(preflight) is dict and set(preflight) == expected, 'unverified-writer')
    helpers = preflight['helpers']
    commands = [('verify-package', _native.package_argv(spec['host']))]
    if spec['install']:
        commands.append(('discover', [spec['host'], '--discover-json']))
        discovery = preflight['discovery']
        require(type(discovery) is dict and discovery.get('protocol') == 1 and discovery.get('ok') is True
                and type(discovery.get('modules')) is list, 'unverified-writer')
    require(type(helpers) is list and len(helpers) == len(commands), 'unverified-writer')
    _native.check_helpers({'protocol': request.PROTOCOL, **preflight}, {label for label, _ in commands})
    for index, (row, (label, argv)) in enumerate(zip(helpers, commands)):
        directory = stage / 'discovery' / f'{index:02}-{label}'
        require(row['label'] == label and row['argv'] == argv and row['outcome'] == 'success'
                and row['returncode'] == 0 and row.get('cwd') == str(stage / 'discovery')
                and row.get('environment') == 'native-preflight-empty-environment-v3'
                and row['stdout'] == str(directory / 'stdout') and row['stderr'] == str(directory / 'stderr'),
                'unverified-writer')
    return value


def installed(path, metadata):
    origin = metadata.get('origin')
    require(type(origin) is dict, 'unverified-writer')
    created = core.read_json(Path(path) / 'native-create.json')
    proof(origin, created)
    value = {'origin': copy.deepcopy(origin), 'proof': copy.deepcopy(created)}
    from ._native_binding import NAME
    if (Path(path) / NAME).exists():
        from ._native_create_recovery import semantic
        value['hosting'] = {'binding': semantic(core.read_json(Path(path) / NAME)),
                            'installation': semantic(core.read_json(Path(path) / 'native-install.json'))}
    return value


def retained(value, target, workspace):
    require(type(value) is dict and set(value) in ({'origin', 'proof'}, {'origin', 'proof', 'hosting'}), 'unverified-writer')
    core.native_target({'ownership': 'external-reference', 'native_image': target})
    origin = value['origin']; proof(origin, value['proof'])
    if 'hosting' in value:
        from . import _native_binding as binding
        from ._native_create_recovery import semantic
        hosting = value['hosting']
        require(type(hosting) is dict and set(hosting) == {'binding', 'installation'}, 'unverified-writer')
        epoch = hosting['binding']
        require(type(epoch) is dict and type(epoch.get('origin_target')) is dict, 'unverified-writer')
        metadata = {'id': workspace, 'transaction': origin['transaction'], 'native_image': epoch['origin_target']}
        binding.validate(epoch, metadata, binding.fingerprint(origin, semantic(value['proof']), hosting['installation']))
        installation = hosting['installation']
        require(installation.get('operation') == 'native-install' and installation.get('complete') is True
                and installation.get('id') == workspace and installation.get('transaction') == origin['transaction']
                and installation.get('target') == epoch['origin_target']
                and _native._consumed(installation.get('guard'),
                    binding.historical_target(Path(epoch['admitted_target']['directory']), metadata),
                    origin['native_image']['anchor']), 'unverified-writer')
        # Hosting identity permits current read/write admission, but this packet
        # carries no descriptor-validated current destructive authority.
        # Retention therefore still requires the original exact object pairs.
    require(origin['id'] == workspace
            and all(origin['native_image'][key] == target[key] for key in ('component', 'object', 'file', 'uuid') if key in target),
            'unverified-writer')
    require(origin['native_image']['object'] == target['parent'], 'unverified-writer')
