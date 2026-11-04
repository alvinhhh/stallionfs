"""One nonprivileged hosted System Trace capability probe; no CPU attribution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shutil
import stat
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_.:-]{0,63}\Z', re.ASCII)
MAX_XML = 8 * 1024 * 1024
MAX_DISK = 512 * 1024 * 1024
MAX_EXPORTS = 4
TOTAL_SECONDS = 180


class ProbeError(Exception):
    """Internal fixed code; never include tool or exception text in publication."""


def require(condition, code):
    if not condition:
        raise ProbeError(code)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def write_private(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())


def publish(path, value):
    """Make only the complete, size-bounded sanitized object visible to upload."""
    require(len(json.dumps(value).encode()) <= 65536, 'publication_limit')
    fd, temporary = tempfile.mkstemp(prefix='.trace-status-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def read_private(path, limit=65536):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and info.st_mode & 0o777 == 0o600 and info.st_size <= limit, 'private_file_invalid')
    return json.loads(path.read_text())


def parse_xml(raw):
    require(isinstance(raw, bytes) and len(raw) <= MAX_XML, 'schema_unavailable')
    # Reject declarations before parsing; accept only UTF-8, without expansion.
    raw.decode('utf-8', errors='strict')
    require(not re.search(br'<!\s*(?:DOCTYPE|ENTITY)\b', raw, re.I)
            and b'\x00' not in raw, 'schema_unavailable')
    declaration = re.match(br'\s*<\?xml[^?]*\?>', raw)
    if declaration:
        encoding = re.search(br'encoding\s*=\s*[\'"]([^\'"]+)', declaration[0], re.I)
        require(encoding is None or encoding[1].lower() in (b'utf-8', b'utf8'), 'schema_unavailable')
    parser = ET.XMLPullParser(events=('start', 'end'))
    depth = nodes = 0
    root = None
    for offset in range(0, len(raw), 4096):
        parser.feed(raw[offset:offset + 4096])
        for event, element in parser.read_events():
            if event == 'start':
                depth += 1
                nodes += 1
                require(depth <= 32 and nodes <= 50000, 'schema_unavailable')
                if root is None:
                    root = element
            else:
                depth -= 1
    parser.close()
    require(root is not None and depth == 0, 'schema_unavailable')
    return root


def identifier(value):
    require(isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None, 'schema_unavailable')
    return value


def toc_selection(raw):
    """Private TOC selection only. No TOC attributes become public metadata."""
    root = parse_xml(raw)
    require(root.tag == 'trace-toc', 'schema_unavailable')
    runs = root.findall('run')
    require(len(runs) == 1 and runs[0].get('number') == '1', 'schema_unavailable')
    tables = runs[0].findall('./data/table')
    require(0 < len(tables) <= 128, 'schema_unavailable')
    names = sorted({identifier(table.get('schema')) for table in tables})
    return names[:MAX_EXPORTS], len(names) <= MAX_EXPORTS


def schema_metadata(raw, expected):
    """Project identifiers from recognized metadata nodes, never event rows."""
    root = parse_xml(raw)
    require(root.tag == 'trace-query-result' and not root.attrib, 'schema_unavailable')
    nodes = list(root)
    require(len(nodes) == 1 and nodes[0].tag == 'node'
            and set(nodes[0].attrib) <= {'xpath'}, 'schema_unavailable')
    node = nodes[0]
    require(all(child.tag in ('schema', 'row') for child in node), 'schema_unavailable')
    schemas = node.findall('schema')
    require(len(schemas) == 1, 'schema_unavailable')
    schema = schemas[0]
    require(set(schema.attrib) == {'name'} and schema.get('name') == expected, 'schema_unavailable')
    name = identifier(schema.get('name'))
    columns = []
    require(0 < len(schema) <= 64, 'schema_unavailable')
    for column in schema:
        require(column.tag == 'col' and not column.attrib, 'schema_unavailable')
        require(all(part.tag in ('mnemonic', 'name', 'type') for part in column), 'schema_unavailable')
        require(len(column.findall('mnemonic')) == len(column.findall('type')) == 1
                and len(column.findall('name')) <= 1, 'schema_unavailable')
        for part in column:
            require(not part.attrib and not len(part), 'schema_unavailable')
        columns.append({'identifier': identifier(column.findtext('mnemonic')),
                        'type': identifier(column.findtext('type'))})
    require(len({column['identifier'] for column in columns}) == len(columns), 'schema_unavailable')
    return {'identifier': name, 'columns': columns}


def clean_capture(receipt):
    return (receipt.get('completion_uncertain') is False and type(receipt.get('exit_code')) is int
            and not any(receipt.get(field) for field in ('error', 'cleanup_error', 'output_limit_exceeded',
                                                       'timed_out', 'discarded_output_bytes')))


def bound_disk(root):
    total = entries = 0
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in (*directories, *files):
            info = (Path(parent) / name).lstat()
            entries += 1
            total += info.st_size if stat.S_ISREG(info.st_mode) else 0
            require(entries <= 20000 and total <= MAX_DISK, 'disk_limit')


def launcher(config_path):
    """The existing capture helper exclusively owns and reaps the real clone."""
    from stallionfs._benchmark_budget import command
    config = read_private(config_path)
    require(set(config) == {'nonce', 'argv', 'cli_sha256', 'argv_sha256', 'receipt', 'deadline'}, 'launcher_invalid')
    argv = config['argv']
    require(isinstance(argv, list) and len(argv) == 6 and argv[1:4] == ['clone', '--jobs', '2'], 'launcher_invalid')
    require(canonical_hash(argv) == config['argv_sha256'] and digest(argv[0]) == config['cli_sha256'], 'launcher_invalid')
    require(time.monotonic() < config['deadline'], 'launcher_invalid')
    os.environ['STALLIONFS_BENCHMARK_DEADLINE'] = str(config['deadline'])
    receipt = {}
    started = time.monotonic()
    returned = False
    # Raw capture bytes and detailed failure receipts remain in the private root.
    try:
        command(argv, timeout=25, umask=0o077, receipt=receipt, output_limit=1048576)
        returned = True
    except BaseException:
        pass
    completed = {'nonce': config['nonce'], 'argv_sha256': config['argv_sha256'], 'config_sha256': digest(config_path),
                 'cli_sha256': config['cli_sha256'], 'started': started, 'ended': time.monotonic(),
                 'returned': returned, 'capture': receipt}
    write_private(Path(config['receipt']), completed)
    return 0 if returned and clean_capture(receipt) and receipt.get('exit_code') == 0 else 1


def completion(config, value, config_hash):
    require(isinstance(value, dict) and set(value) == {'nonce', 'argv_sha256', 'config_sha256', 'cli_sha256', 'started', 'ended', 'returned', 'capture'},
            'target_completion_unknown')
    require(all(value.get(key) == config[key] for key in ('nonce', 'argv_sha256', 'cli_sha256')),
            'target_completion_unknown')
    require(value['config_sha256'] == config_hash, 'target_completion_unknown')
    receipt = value['capture']
    require(value['returned'] is True and isinstance(receipt, dict) and clean_capture(receipt) and receipt.get('exit_code') == 0
            and receipt.get('argv') == config['argv'] and type(receipt.get('pid')) is int and receipt['pid'] > 1,
            'target_completion_unknown')
    require(type(value['started']) in (int, float) and type(value['ended']) in (int, float)
            and 0 <= value['started'] <= value['ended'] <= config['deadline'], 'target_completion_unknown')


def validate_copy(source, destination, expected, before, base, correct, preserved):
    after = correct.snapshot(destination, observe_sharing=True)
    clone = correct.verify_clone(before, after)
    source_after = correct.snapshot(source, observe_sharing=True)
    unchanged = correct.verify_source(expected, source_after)['unchanged']
    sharing = correct.clone_sharing(source_after, after)['full_data_stream_sharing']
    sentinel = (base / 'outside-sentinel').read_bytes() == b'keep outside linked trees\n'
    passed = preserved(clone) and unchanged is True and sharing is True and sentinel
    return {'destination_preserved': preserved(clone), 'source_unchanged': unchanged is True,
            'full_data_stream_sharing': sharing is True, 'outside_sentinel_unchanged': sentinel, 'passed': passed}


def probe(binary, scratch, output, revision):
    from stallionfs._benchmark_budget import command
    import stallionfs
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import fileops
    import native_correctness as correct
    import native_fixtures
    import native_suite

    result = {'schema': 1, 'scope': 'hosted-source-build capability diagnostic', 'status': 'incomplete',
              'capability': 'unavailable', 'target_completion': 'unknown', 'correctness': None,
              'schema_metadata_status': 'unavailable', 'cpu_attribution': 'unavailable',
              'benchmark_verdict': 'not_applicable', 'recording_attempts': 0, 'cleanup': 'not_started'}
    private = base = identity = None
    safe_to_clean = True
    deadline = time.monotonic() + TOTAL_SECONDS
    os.environ['STALLIONFS_BENCHMARK_DEADLINE'] = str(deadline)
    try:
        require(sys.platform == 'darwin' and re.fullmatch('[0-9a-f]{40}', revision) is not None, 'host_invalid')
        binary, scratch = binary.resolve(strict=True), scratch.resolve(strict=True)
        require(binary.is_file() and os.access(binary, os.X_OK) and not output.exists(), 'input_invalid')
        require(not Path(stallionfs.__file__).resolve().is_relative_to(Path(__file__).resolve().parents[2]), 'wheel_invalid')
        private = Path(tempfile.mkdtemp(prefix='system-trace-private-', dir=scratch))
        identity = private.stat()
        receipts = private / 'receipts'
        receipts.mkdir(mode=0o700)
        os.environ['STALLIONFS_BENCHMARK_RECEIPTS'] = str(receipts)
        # Per-file limit plus short recording and aggregate checks bound retained data.
        hard = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
        resource.setrlimit(resource.RLIMIT_FSIZE, (min(MAX_DISK, hard) if hard != resource.RLIM_INFINITY else MAX_DISK, hard))

        def run(argv, timeout=10, limit=1048576):
            nonlocal safe_to_clean
            bound_disk(private)
            receipt = {}
            try:
                child = command(argv, timeout=timeout, umask=0o077, receipt=receipt, output_limit=limit)
            except BaseException:
                safe_to_clean = False
                raise
            if not clean_capture(receipt):
                safe_to_clean = False
                raise ProbeError('capture_incomplete')
            bound_disk(private)
            return child

        help_record = run(['/usr/bin/xcrun', 'xctrace', 'help', 'record'])
        help_export = run(['/usr/bin/xcrun', 'xctrace', 'help', 'export'])
        templates = run(['/usr/bin/xcrun', 'xctrace', 'list', 'templates'])
        require(all(item.returncode == 0 for item in (help_record, help_export, templates)), 'preflight_failed')
        text = help_record.stdout + help_record.stderr
        require(all(flag in text for flag in (b'--template', b'--time-limit', b'--no-prompt', b'--output',
                                              b'--target-stdout', b'--launch')), 'flags_unavailable')
        text = help_export.stdout + help_export.stderr
        require(all(flag in text for flag in (b'--input', b'--toc', b'--xpath'))
                and b'System Trace' in templates.stdout + templates.stderr, 'template_unavailable')
        result['capability'] = 'preflight_passed'
        volume = fileops.scratch_volume(json.loads(run([str(binary), '--json', 'volumes']).stdout), scratch)
        require(volume['filesystem'] == 'apfs' and shutil.disk_usage(scratch).free >= fileops.HEADROOM, 'scratch_invalid')
        sources = fileops.fingerprint_sources()
        sources.update({path.name: fileops.digest(path) for path in Path(__file__).parent.glob('native_*.py')})
        sources[Path(__file__).name] = digest(__file__)
        cli_hash = digest(binary)
        result['source_sha256'] = sources
        result['cli_sha256'] = cli_hash
        result['revision'] = revision
        base = private / 'fixture'
        base.mkdir(mode=0o700)
        fileops.no_mounts_below(binary, base)
        (base / 'outside-sentinel').write_bytes(b'keep outside linked trees\n')
        source = fileops.large_fixture(base, 'docs_5k_100mb', fileops.LARGE_PROFILES['docs_5k_100mb'])
        metadata = {}
        native_fixtures.enrich_metadata(source, receipt=metadata)
        expected = correct.snapshot(source)
        require(native_fixtures.verify_metadata_coverage(expected, metadata)['populated'] is True, 'metadata_incomplete')
        destination = base / 'destination'
        require(not os.path.lexists(destination), 'destination_exists')
        before = correct.snapshot(source)
        require(native_suite.preserved(correct.compare(expected, before)), 'source_precheck_failed')
        native_suite.cache_prepare('warm', 10)
        argv = native_suite.arguments('stallionfs', 'clone', binary, source, destination, jobs=2)
        config = {'nonce': secrets.token_hex(16), 'argv': argv, 'argv_sha256': canonical_hash(argv),
                  'cli_sha256': cli_hash, 'receipt': str(private / 'target-completion.json'), 'deadline': deadline}
        config_path = private / 'target-config.json'
        write_private(config_path, config)
        config_hash = digest(config_path)
        trace = private / 'capture.trace'
        recorder = ['/usr/bin/xcrun', 'xctrace', 'record', '--template', 'System Trace', '--time-limit', '3s',
                    '--no-prompt', '--output', str(trace), '--target-stdout', str(private / 'target.stdout'),
                    '--launch', '--', sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                    '--target-launch', str(config_path)]
        result['recording_attempts'] = 1
        safe_to_clean = False
        recorded = run(recorder, timeout=60)
        require(digest(config_path) == config_hash, 'target_completion_unknown')
        completion(config, read_private(Path(config['receipt']), limit=2 * 1048576), config_hash)
        result['target_completion'] = 'complete'
        safe_to_clean = True
        require(recorded.returncode == 0, 'recording_failed')
        result['capability'] = 'recorded'
        result['correctness'] = validate_copy(source, destination, expected, before, base, correct, native_suite.preserved)
        if not result['correctness']['source_unchanged']:
            safe_to_clean = False
        require(result['correctness']['passed'], 'correctness_failed')
        current_sources = fileops.fingerprint_sources()
        current_sources.update({path.name: fileops.digest(path) for path in Path(__file__).parent.glob('native_*.py')})
        current_sources[Path(__file__).name] = digest(__file__)
        require(digest(binary) == cli_hash and current_sources == sources, 'source_changed')
        # Export errors affect schema capability, never create a benchmark result.
        try:
            toc = run(['/usr/bin/xcrun', 'xctrace', 'export', '--input', str(trace), '--toc'], limit=MAX_XML)
            require(toc.returncode == 0, 'schema_unavailable')
            selected, exhaustive = toc_selection(toc.stdout)
            projected = []
            for name in selected:
                xpath = "/trace-toc/run[@number='1']/data/table[@schema='" + name + "']"
                exported = run(['/usr/bin/xcrun', 'xctrace', 'export', '--input', str(trace), '--xpath', xpath], limit=MAX_XML)
                require(exported.returncode == 0, 'schema_unavailable')
                projected.append(schema_metadata(exported.stdout, name))
            require(len(json.dumps(projected).encode()) <= 65536, 'schema_unavailable')
            result['schema_metadata'] = projected
            result['schema_metadata_status'] = 'complete' if exhaustive else 'bounded_subset'
        except Exception:
            result.pop('schema_metadata', None)
            result['schema_metadata_status'] = 'unavailable'
        result['status'] = 'complete' if result['schema_metadata_status'] != 'unavailable' else 'incomplete'
    except BaseException as error:
        result['error'] = str(error) if isinstance(error, ProbeError) else 'diagnostic_incomplete'
    finally:
        if private is not None:
            result['cleanup'] = 'retained_ephemeral'
            if safe_to_clean:
                try:
                    current = private.lstat()
                    require(stat.S_ISDIR(current.st_mode) and current.st_uid == os.getuid()
                            and stat.S_IMODE(current.st_mode) == 0o700
                            and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino), 'cleanup_failed')
                    fileops.no_mounts_below(binary, private)
                    shutil.rmtree(private)
                    require(not private.exists(), 'cleanup_failed')
                    result['cleanup'] = 'complete'
                except BaseException:
                    result['status'] = 'incomplete'
                    result['error'] = 'cleanup_failed'
        output.parent.mkdir(parents=True, exist_ok=True)
        publish(output, result)
    return 0 if result['status'] == 'complete' and result['cleanup'] == 'complete' else 1


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target-launch', type=Path)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--scratch', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--revision')
    args = parser.parse_args()
    try:
        if args.target_launch:
            require(all(getattr(args, name) is None for name in ('binary', 'scratch', 'output', 'revision')), 'launcher_invalid')
            return launcher(args.target_launch)
        require(all(getattr(args, name) is not None for name in ('binary', 'scratch', 'output', 'revision')), 'input_invalid')
        return probe(args.binary, args.scratch, args.output, args.revision)
    except BaseException:
        # Never print paths, raw diagnostics, configuration or exception text.
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
