"""Export explicitly path-redacted generated-fixture results; retain original reports."""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import zlib

import fileops
import native_correctness
import native_report
import native_suite

# This is an export-policy allowlist, not automatically expanded from new fixtures.
GENERATED_FIXTURES = frozenset({
    'tiny_4kib', 'large_64mib', 'flat_2000', 'nested_10000',
    'dependencies_100k', 'git_50k_2gb', 'cache_200k_10gb',
    'docs_5k_100mb', 'dataset_2k_50gb', 'huge_2x10gib', 'deep_20000', 'photo_library',
})
SCAN_FIXTURES = frozenset({'scan_flat_20k', 'scan_nested_20k', 'scan_deep40_20k'})
MAX_SCAN_BYTES = 4 * 1024 * 1024
MAX_SCAN_COMPRESSED = 1024 * 1024
JOURNAL_KINDS = ('rows', 'preparation', 'metadata_preparation', 'comparisons', 'unavailable')
SELECTION_FIELDS = frozenset({'binary', 'scratch', 'output', 'samples', 'runs',
                             'cache', 'fixtures', 'copy_tools', 'operations', 'timeout', 'jobs'})
DEPENDENCY_SELECTION_FIELDS = frozenset({'node', 'npm', 'npm_cache'})
LOCKED_DEPENDENCY_INPUTS = {
    'package.json': '6c0c343e91ab0689397ad98e0c52417f6f71024582856b376cec5b33f7afd160',
    'package-lock.json': '518e2a3693b5f2a51ac10dd2fb46d3d42436e6bacd50fc71ccc4ad0f5bcefd5e',
    'check.cjs': 'c0c31b1f975222e1fa3cbd0b90fc6e8fb0ab5e04c708b062e3fe5971a82e215e',
}
DEPENDENCY_POLICY = 'offline npm ci; lifecycle scripts, audit and funding disabled; no cache cleanup'
DEPENDENCY_PIN_SCOPE = 'Node executable, npm entrypoint and package manifest only; npm package tree is not fully pinned'


def require_locked_dependencies(report, preparations=None):
    """Permit receipts for the explicitly reviewed offline fixture, not user trees."""
    selection = report['selection']
    def path(value):
        return (isinstance(value, str) and value.startswith('/') and value != '/' and '\x00' not in value
                and str(Path(value)) == value and '..' not in Path(value).parts)
    def digest(value):
        return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)
    # Selection preserves the producer's input spelling, which may be relative.
    # Only preparation receipts contain resolved paths; never resolve at export time.
    if not all(isinstance(selection.get(key), str) and selection[key] and '\x00' not in selection[key]
               and str(Path(selection[key])) == selection[key] for key in DEPENDENCY_SELECTION_FIELDS):
        raise ValueError('Locked dependency export requires explicit runtime/cache paths')
    if any(report.get('source_sha256', {}).get('tests/perf/fixture/' + name) != value
           for name, value in LOCKED_DEPENDENCY_INPUTS.items()):
        raise ValueError('Dependency fixture inputs require a new export review')
    fields = {'run', 'fixture', 'status', 'root', 'cache', 'node_path', 'npm_cli_path', 'node_sha256',
              'npm_entrypoint_sha256', 'npm_package_manifest', 'npm_package_manifest_sha256',
              'npm_package_version', 'runtime_pin_scope', 'locked_inputs', 'commands', 'node_version',
              'node_platform', 'npm_version', 'typescript_platform', 'typescript_cli_version',
              'dependencies', 'source', 'installed_lock_sha256', 'policy', 'manifest_sha256',
              'regular_files', 'logical_bytes'}
    if preparations is None:
        preparations = report.get('preparation')
        if not isinstance(preparations, list):
            raise ValueError('Missing locked dependency preparation')
    runs = set()
    for receipt in preparations:
        if not isinstance(receipt, dict):
            raise ValueError('Invalid preparation receipt')
        if receipt.get('fixture') != 'installed_dependencies' or 'status' not in receipt:
            continue  # Existing measured-operand setup receipts retain their original policy.
        if set(receipt) != fields or receipt['status'] != 'prepared':
            raise ValueError('Unknown or incomplete locked dependency preparation')
        run = receipt['run']
        if type(run) is not int or run < 0 or run in runs:
            raise ValueError('Invalid dependency preparation run')
        runs.add(run)
        if (receipt['locked_inputs'] != LOCKED_DEPENDENCY_INPUTS or receipt['policy'] != DEPENDENCY_POLICY
                or receipt['runtime_pin_scope'] != DEPENDENCY_PIN_SCOPE
                or any(not digest(receipt[key]) for key in ('node_sha256', 'npm_entrypoint_sha256',
                    'npm_package_manifest_sha256', 'installed_lock_sha256', 'manifest_sha256'))
                or any(type(receipt[key]) is not int or receipt[key] < 0 for key in ('regular_files', 'logical_bytes'))):
            raise ValueError('Invalid dependency preparation evidence')
        if not all(path(receipt[key]) for key in ('root', 'cache', 'node_path', 'npm_cli_path', 'npm_package_manifest', 'source')):
            raise ValueError('Invalid dependency preparation path')
        root, node, npm, cache = (receipt[key] for key in ('root', 'node_path', 'npm_cli_path', 'cache'))
        source = root + '/node_modules'
        platform = receipt['node_platform']
        dependencies = receipt['dependencies']
        if (receipt['source'] != source or receipt['npm_package_manifest'] != str(Path(npm).parent.parent / 'package.json')
                or not isinstance(platform, dict) or set(platform) != {'platform', 'arch'}
                or platform['platform'] != 'darwin' or platform['arch'] not in ('arm64', 'x64')
                or not isinstance(dependencies, dict) or dependencies != {
                    'axios': '1.20.0', 'date-fns': '4.4.0', 'eslint': '10.12.0', 'lodash': '4.18.1',
                    'prettier': '3.9.9', 'react': '19.3.0', 'react-dom': '19.3.0', 'rxjs': '7.8.2',
                    'typescript': '7.0.2', 'zod': '4.6.5'}
                or receipt['typescript_platform'] != {'name': '@typescript/typescript-darwin-' + platform['arch'], 'version': '7.0.2'}
                or receipt['typescript_cli_version'] != 'Version 7.0.2'
                or not isinstance(receipt['node_version'], str) or not re.fullmatch(r'v\d+\.\d+\.\d+', receipt['node_version'])
                or int(receipt['node_version'][1:].split('.')[0]) < 24
                or not isinstance(receipt['npm_version'], str) or not re.fullmatch(r'\d+\.\d+\.\d+', receipt['npm_version'])
                or receipt['npm_version'] != receipt['npm_package_version']):
            raise ValueError('Unexpected installed dependency runtime or packages')
        common = [node, npm, '--prefix', root, '--userconfig', root + '/empty-user.npmrc',
                  '--globalconfig', root + '/empty-global.npmrc', '--cache', cache]
        expected = [[node, '--version'], [node, '-p', 'JSON.stringify({platform:process.platform,arch:process.arch})'],
                    [*common, '--version'], [*common, 'ci', '--offline', '--ignore-scripts', '--no-audit', '--no-fund'],
                    [node, root + '/check.cjs'], [node, source + '/typescript/bin/tsc', '--version']]
        commands = receipt['commands']
        if not isinstance(commands, list) or len(commands) != len(expected):
            raise ValueError('Incomplete dependency commands')
        for command, argv in zip(commands, expected):
            if (not isinstance(command, dict) or set(command) != {'argv', 'exit_code', 'stdout', 'stderr'}
                    or command['argv'] != argv or type(command['exit_code']) is not int or command['exit_code'] != 0
                    or not isinstance(command['stdout'], str) or not isinstance(command['stderr'], str)):
                raise ValueError('Unknown or unsuccessful dependency preparation command')
    if not runs:
        raise ValueError('Missing completed locked dependency preparation')
    require_dependency_rows(report, runs)
    return runs


def require_dependency_rows(report, runs):
    for field in ('rows', 'unavailable', 'comparisons'):
        for row in report.get(field, []):
            if row.get('fixture') == 'installed_dependencies' and 'run' in row and row['run'] not in runs:
                raise ValueError('Dependency row lacks its preparation receipt')
MAX_SHARING_BYTES = 256 * 1024 * 1024
MAX_SHARING_COMPRESSED = 64 * 1024 * 1024
SHARING_ENCODING = 'UTF-8 JSON Lines, gzip with mtime=0, then base64; digest and length describe uncompressed bytes.'
SHARING_SCOPE = 'Data-bearing regular-file streams only; empty and holes-only streams are not positive evidence. No resource-fork or disk-space savings claim.'
SHARING_EVIDENCE = 'Encoded records retain every pair, including positive raw attributes and returned masks. Sequential observations are not atomic.'
SHARING_REASONS = {
    'shared': {'Matching nonzero clone IDs and full-sharing flags'},
    'not_shared': {'Regular-file path mismatch', 'Pair requires independent identical files on one device',
                   'Full data-stream sharing not observed'},
    'unknown': {'Missing attributes or zero clone identifier'},
    'not_applicable': {'Empty or observed holes-only data stream'},
}


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate sharing record key')
        result[key] = value
    return result


def _decode_gzip_payload(encoded, length, digest, maximum, compressed_maximum):
    """Bound allocation and require one complete gzip member with the stated digest."""
    if (type(length) is not int or not 0 <= length <= maximum
            or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)
            or not isinstance(encoded, str) or len(encoded) > 4 * ((compressed_maximum + 2) // 3)):
        raise ValueError('Invalid or oversized encoded payload')
    try:
        compressed = base64.b64decode(encoded, validate=True)
        if len(compressed) > compressed_maximum:
            raise ValueError('Oversized compressed payload')
        decoder = zlib.decompressobj(31)
        raw = decoder.decompress(compressed, length + 1)
        if len(raw) != length or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError('Gzip length, EOF or trailing data mismatch')
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Payload digest mismatch')
    except (zlib.error, TypeError) as error:
        raise ValueError('Malformed encoded payload') from error
    return raw


def export_scan_stdout(row):
    """Keep numeric stdout bytes exact; discard optional gzip header metadata."""
    raw = _decode_gzip_payload(row['stdout_gzip_b64'], row['stdout_bytes'], row['stdout_sha256'],
                               MAX_SCAN_BYTES, MAX_SCAN_COMPRESSED)
    # Parsing proves stdout contains only six numeric counters or numeric stat rows.
    # Device zero is only for grammar validation; recorded outcomes are not recomputed.
    native_suite.parse_scan_output(row['method'], raw, 0)
    compressed = gzip.compress(raw, mtime=0)
    if len(compressed) > MAX_SCAN_COMPRESSED:
        raise ValueError('Oversized compressed scan output')
    return base64.b64encode(compressed).decode('ascii')


def _sharing_attributes(value):
    if value is None:
        return
    if not isinstance(value, dict):
        raise ValueError('Invalid sharing attributes')
    if set(value) == {'available', 'unavailable'}:
        if value['available'] is not False or value['unavailable'] != 'Requires little-endian Darwin':
            raise ValueError('Unknown unavailable sharing attributes')
    elif set(value) == {'available', 'error_number', 'raw_hex', 'unavailable'}:
        if (value['available'] is not False or type(value['error_number']) is not int
                or value['error_number'] <= 0 or value['unavailable'] != 'Clone attributes unsupported'
                or not isinstance(value['raw_hex'], str) or not re.fullmatch('[0-9a-f]{88}', value['raw_hex'])):
            raise ValueError('Invalid unsupported sharing attributes')
    else:
        try:
            raw = value['raw_hex']
            if not isinstance(raw, str) or not re.fullmatch('[0-9a-f]{88}', raw):
                raise ValueError('Invalid sharing attribute bytes')
            parsed = native_correctness._parse_clone_attributes(bytes.fromhex(raw))
            # JSON equality alone treats booleans as integers.
            if json.dumps(value, sort_keys=True) != json.dumps(parsed, sort_keys=True):
                raise ValueError('Sharing attributes disagree with raw bytes')
        except (KeyError, TypeError) as error:
            raise ValueError('Unknown sharing attribute schema') from error


def redact_sharing(value, replace):
    """Validate the current observation schema and redact only record paths."""
    def redact_path(path):
        # Filesystem names may contain surrogateescaped bytes; JSON escapes them.
        return replace(path.encode('utf-8', errors='surrogateescape')).decode('utf-8', errors='surrogateescape')

    required = {'full_data_stream_sharing', 'counts', 'exceptions', 'observations_gzip_b64',
                'observations_sha256', 'observations_bytes', 'observations_encoding', 'scope', 'evidence'}
    if not isinstance(value, dict) or set(value) not in (required, required | {'required'}):
        raise ValueError('Unknown clone-sharing schema')
    if ('required' in value and type(value['required']) is not bool
            or value['observations_encoding'] != SHARING_ENCODING or value['scope'] != SHARING_SCOPE
            or value['evidence'] != SHARING_EVIDENCE):
        raise ValueError('Unknown clone-sharing encoding or scope')
    length, digest, encoded = value['observations_bytes'], value['observations_sha256'], value['observations_gzip_b64']
    raw = _decode_gzip_payload(encoded, length, digest, MAX_SHARING_BYTES, MAX_SHARING_COMPRESSED)
    try:
        raw.decode('utf-8', errors='strict')
    except UnicodeError as error:
        raise ValueError('Malformed sharing payload') from error
    counts = dict.fromkeys(SHARING_REASONS, 0)
    exceptions, paths, new_digest, new_length = [], set(), hashlib.sha256(), 0
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode='wb', mtime=0) as stream:
        for line in io.BytesIO(raw):
            if not line.endswith(b'\n'):
                raise ValueError('Sharing record lacks newline')
            pair = json.loads(line, object_pairs_hook=_strict_object,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite sharing number')))
            if not isinstance(pair, dict) or set(pair) != {'path', 'source', 'destination', 'source_identity',
                                                          'destination_identity', 'status', 'reason'}:
                raise ValueError('Unknown sharing record schema')
            path, status = pair['path'], pair['status']
            if (not isinstance(path, str) or '\x00' in path or path in paths
                    or not isinstance(status, str) or status not in SHARING_REASONS
                    or not isinstance(pair['reason'], str) or pair['reason'] not in SHARING_REASONS[status]):
                raise ValueError('Invalid sharing path or status')
            paths.add(path)
            for side in ('source', 'destination'):
                _sharing_attributes(pair[side])
                identity = pair[side + '_identity']
                if identity is not None and (not isinstance(identity, list) or len(identity) != 2
                        or any(type(n) is not int or not -(1 << 63) <= n < 1 << 64 for n in identity)):
                    raise ValueError('Invalid sharing identity')
            if status == 'shared':
                left, right = pair['source'], pair['destination']
                left_identity, right_identity = pair['source_identity'], pair['destination_identity']
                if (not left or not right or left.get('available') is not True or right.get('available') is not True
                        or not left.get('clone_id') or left['clone_id'] != right.get('clone_id')
                        or not all(side['extended_flags'] & 0x40 for side in (left, right))
                        or left_identity is None or right_identity is None
                        or left_identity[0] != right_identity[0] or left_identity[1] == right_identity[1]):
                    raise ValueError('Shared status contradicts attributes or identities')
            counts[status] += 1
            if status != 'shared':
                exceptions.append({'path': path, 'status': status, 'reason': pair['reason']})
            pair['path'] = redact_path(path)
            line = json.dumps(pair, sort_keys=True, separators=(',', ':')).encode('utf-8') + b'\n'
            if new_length + len(line) > MAX_SHARING_BYTES:
                raise ValueError('Oversized redacted sharing payload')
            stream.write(line); new_digest.update(line); new_length += len(line)
    outcome = False if counts['not_shared'] else None if counts['unknown'] or not counts['shared'] else True
    if (json.dumps(value['counts'], sort_keys=True) != json.dumps(counts, sort_keys=True)
            or value['exceptions'] != exceptions or value['full_data_stream_sharing'] is not outcome):
        raise ValueError('Sharing summary disagrees with records')
    result = dict(value)
    if output.tell() > MAX_SHARING_COMPRESSED:
        raise ValueError('Oversized compressed redacted sharing payload')
    result['exceptions'] = [dict(item, path=redact_path(item['path'])) for item in exceptions]
    result.update(observations_gzip_b64=base64.b64encode(output.getvalue()).decode('ascii'),
                  observations_sha256=new_digest.hexdigest(), observations_bytes=new_length,
                  original_observations_sha256=digest, original_observations_bytes=length)
    return result


def require_generated(report, *, dependency_runs=None):
    """Reject other report families and future input policies until reviewed."""
    if not isinstance(report, dict) or report.get('schema') != 1 or 'export' in report:
        raise ValueError('Expected an unexported native-suite schema 1 report')
    selection = report.get('selection')
    if not isinstance(selection, dict):
        raise ValueError('Invalid selection')
    names = selection.get('fixtures')
    installed = isinstance(names, list) and 'installed_dependencies' in names
    allowed_selection = SELECTION_FIELDS | (DEPENDENCY_SELECTION_FIELDS if installed else set())
    if set(selection) - allowed_selection:
        raise ValueError('Unknown selection fields; input policy needs review')
    jobs = selection.get('jobs')
    if jobs is not None and (type(jobs) is not int or not 1 <= jobs <= 4):
        raise ValueError('Invalid jobs selection')
    allowed_fixtures = GENERATED_FIXTURES | SCAN_FIXTURES | {'installed_dependencies'}
    if not isinstance(names, list) or not names or any(name not in allowed_fixtures for name in names):
        raise ValueError('Only explicitly allowed generated fixtures may be exported')
    scans = any(name in SCAN_FIXTURES for name in names)
    if scans:
        if any(name not in SCAN_FIXTURES for name in names) or selection.get('operations') != ['scan']:
            raise ValueError('Scan export requires only existing scan fixtures and the scan operation')
    elif 'operations' in selection and (not isinstance(selection['operations'], list)
            or any(operation not in ('clone', 'copy', 'move', 'delete') for operation in selection['operations'])):
        raise ValueError('Unknown operation export policy')
    sources = report.get('source_sha256')
    if not isinstance(sources, dict) or not re.fullmatch('[0-9a-f]{64}', str(sources.get('native_suite.py', ''))):
        raise ValueError('Missing native-suite source provenance')
    for field in ('rows', 'unavailable', 'comparisons'):
        rows = report.get(field, [])
        if not isinstance(rows, list):
            raise ValueError('Invalid report rows')
        for row in rows:
            if not isinstance(row, dict) or row.get('fixture') not in names:
                raise ValueError('Row fixture outside generated selection')
            if 'data_stream_sharing' in row and (field != 'rows' or row.get('operation') != 'clone'):
                raise ValueError('Clone-sharing observations require a clone row')
            if not scans and row.get('operation') == 'scan':
                raise ValueError('Scan row requires an existing scan fixture selection')
            if scans:
                if row.get('operation') != 'scan':
                    raise ValueError('Scan row requires the scan operation')
                if field == 'rows':
                    if row.get('method') not in ('stallionfs', 'find-stat'):
                        raise ValueError('Unknown scan method export policy')
                    encoded = {'stdout_gzip_b64', 'stdout_bytes', 'stdout_sha256'} & row.keys()
                    if encoded:
                        if (len(encoded) != 3 or 'stdout' in row or 'stdout_b64' in row
                                or row.get('completion_uncertain')):
                            raise ValueError('Incomplete or ambiguous compressed scan stdout')
                    elif row.get('completion_uncertain') is not True:
                        raise ValueError('Missing compressed scan stdout')
    if not isinstance(report.get('rows'), list):
        raise ValueError('Missing native-suite rows')
    if installed:
        if dependency_runs is None:
            require_locked_dependencies(report)
        else:
            require_dependency_rows(report, dependency_runs)


def _redactor(aliases):
    """One replacement counter for exactly the values emitted by an export."""
    pairs = list(aliases)
    if not pairs:
        raise ValueError('Supply explicit path aliases')
    prefixes, tokens = [], []
    for prefix, name in pairs:
        if (not isinstance(prefix, str) or not prefix.startswith('/') or prefix == '/'
                or '\x00' in prefix or prefix.endswith('/') or str(Path(prefix)) != prefix
                or '..' in Path(prefix).parts):
            raise ValueError('Prefixes must be normalized non-root absolute paths')
        if not isinstance(name, str) or not re.fullmatch('[A-Z][A-Z0-9_]*', name):
            raise ValueError('Alias names must be uppercase identifiers')
        prefixes.append(prefix)
        tokens.append('${' + name + '}')
    if len(set(prefixes)) != len(prefixes) or len(set(tokens)) != len(tokens):
        raise ValueError('Duplicate prefix or alias')
    for a in prefixes:
        for b in prefixes:
            if a != b and a.startswith(b + '/'):
                raise ValueError('Overlapping prefixes are ambiguous')
    # Bytes keep arbitrary raw stdout/stderr intact except for selected prefixes.
    rules = []
    for prefix, token in zip(prefixes, tokens):
        pattern = rb'(?<![A-Za-z0-9_./~+%\x80-\xff-])' + re.escape(prefix.encode('utf-8')) + rb'(?=$|[/\s\x00\x22\x27,:;\)\]\}])'
        rules.append((re.compile(pattern), token.encode('ascii')))
    counts = [0] * len(rules)
    def replace(data):
        if any(token.encode('ascii') in data for token in tokens):
            raise ValueError('Alias token already exists in source')
        for index, (pattern, token) in enumerate(rules):
            data, count = pattern.subn(lambda _: token, data)
            counts[index] += count
        return data
    def visit(value, field=None, *, measured_row=False, report_root=False):
        # Raw Git diagnostics and ownership details remain in private reports.
        if field in ('git_commands', 'git_preparations') or (isinstance(value, dict)
                and value.get('kind') == 'git-preparation'):
            raise ValueError('Raw Git preparation receipts require separate export review; retain the private original')
        if field == 'data_stream_sharing':
            return redact_sharing(value, replace)
        if field is not None and field.endswith('gzip_b64'):
            raise ValueError('Unknown encoded-output export schema')
        if isinstance(value, str):
            if field is not None and (field.endswith('stdout_b64') or field.endswith('stderr_b64')):
                try:
                    raw = base64.b64decode(value, validate=True)
                except (ValueError, TypeError) as error:
                    raise ValueError('Malformed raw output base64') from error
                return base64.b64encode(replace(raw)).decode('ascii')
            return replace(value.encode('utf-8')).decode('utf-8')
        if isinstance(value, list):
            return [visit(item) for item in value]
        if isinstance(value, dict):
            result = {}
            scan_stdout = (export_scan_stdout(value) if measured_row and value.get('fixture') in SCAN_FIXTURES
                           and 'stdout_gzip_b64' in value else None)
            for key, item in value.items():
                new_key = visit(key)
                if new_key in result:
                    raise ValueError('Redaction collided with an existing object key')
                if key == 'stdout_gzip_b64' and scan_stdout is not None:
                    result[new_key] = scan_stdout
                elif report_root and key == 'rows':
                    result[new_key] = [visit(row, measured_row=True) for row in item]
                else:
                    result[new_key] = visit(item, key)
            return result
        return value
    def manifest():
        return [{'alias': token, 'replacement_count': count} for token, count in zip(tokens, counts)]
    return visit, manifest


def redact_report(report, aliases):
    """Replace only caller-selected absolute path prefixes, including raw output."""
    require_generated(report)
    visit, manifest = _redactor(aliases)
    result = visit(report, report_root=True)
    return result, manifest()


EXPORT_POLICY = 'Reviewed generated fixtures and pinned offline dependency fixture only; explicit path-prefix substitutions in text, keys, decoded stdout/stderr and validated clone-sharing record paths. Re-encoded sharing payloads retain original digests and lengths alongside exported digests and lengths. Validated numeric scan stdout bytes, digests and lengths are unchanged; gzip headers are regenerated without optional metadata. Numeric observations are unchanged.'
EXPORT_LIMITATIONS = 'This is redacted raw measurement data, not an untouched original. Unknown strings are not automatically scrubbed; publication still requires content review.'


def _export_receipt(provenance, manifest):
    return {'format': 'redacted-generated-native-suite-v1', **provenance,
            'redaction_manifest': manifest, 'policy': EXPORT_POLICY, 'limitations': EXPORT_LIMITATIONS}


def export_journal(source, output, aliases):
    """Stream the latest journal records; return only the small export receipt."""
    source, output = Path(source), Path(output)
    if native_report.KINDS != JOURNAL_KINDS:
        raise ValueError('Unknown journal record kinds; export policy needs review')
    if not source.name.endswith('.manifest') or source.name == '.manifest':
        raise ValueError('Expected a native-suite journal manifest')
    if os.path.lexists(output):
        raise FileExistsError(output)
    reader = native_report.ReportJournal.open_existing(source.with_name(source.name[:-len('.manifest')]))
    temporary = None
    try:
        state = reader.state
        provenance = dict(reader.provenance)
        installed = 'installed_dependencies' in state.get('selection', {}).get('fixtures', [])
        # Validate installation receipts one at a time; retain only completed run IDs.
        dependency_runs = (require_locked_dependencies(state, reader.iter_latest('preparation'))
                           if installed else None)
        require_generated(state | {'rows': []}, dependency_runs=dependency_runs)
        visit, manifest = _redactor(aliases)
        redacted_state = visit(state)
        encoder = json.JSONEncoder(ensure_ascii=True, allow_nan=False, separators=(',', ':'))
        reader.verify()
        fd, temporary = tempfile.mkstemp(prefix='.native-export-', dir=output.parent)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            def emit(value):
                for piece in encoder.iterencode(value):
                    stream.write(piece)
            stream.write('{')
            first = True
            for key, value in redacted_state.items():
                if not first: stream.write(',')
                first = False
                emit(key); stream.write(':'); emit(value)
            for kind in JOURNAL_KINDS:
                if not first: stream.write(',')
                first = False
                emit(kind); stream.write(':[')
                for index, payload in enumerate(reader.iter_latest(kind)):
                    # Policy validation uses the real state but never redacts synthetic wrappers.
                    require_generated(state | {'rows': [], kind: [payload]}, dependency_runs=dependency_runs)
                    redacted = visit(payload, measured_row=kind == 'rows')
                    if index: stream.write(',')
                    emit(redacted)
                    del redacted, payload
                stream.write(']')
            receipt = _export_receipt(provenance, manifest())
            stream.write(',"export":'); emit(receipt); stream.write('}\n')
            stream.flush(); os.fsync(stream.fileno())
        reader.verify()
        os.link(temporary, output)
        return receipt
    finally:
        try:
            if temporary is not None and os.path.lexists(temporary): os.unlink(temporary)
        finally:
            reader.close()


def export_report(source, output, aliases):
    if Path(source).name.endswith('.manifest'):
        return export_journal(source, output, aliases)
    raw = Path(source).read_bytes()
    report = json.loads(raw)
    result, manifest = redact_report(report, aliases)
    result['export'] = _export_receipt({'original_report_sha256': hashlib.sha256(raw).hexdigest()}, manifest)
    # Exclusive atomic publication; never modify the private original or replace an output.
    fileops.write_new_json(Path(output), result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--alias', nargs=2, metavar=('ABSOLUTE_PREFIX', 'NAME'), action='append', required=True)
    args = parser.parse_args()
    export_report(args.source, args.output, args.alias)


if __name__ == '__main__':
    main()
