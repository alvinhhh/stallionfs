"""Hosted-only directory-clone feasibility; no performance or concurrency verdict."""
import argparse
import errno
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_phase_probe import ProbeError, clean_capture, digest, publish, require, unique_object

MARKER = 'directory-clone-feasibility-v1'
MAX_SMALL_CASES = 19
FIRST_RECIPE = 'metadata-hardlinks-symlinks-flags'
DETAIL_MAX_ENTRIES = 64
DETAIL_MAX_BYTES = 32768
DETAIL_ENTRY_FIELDS = frozenset(('entry_id', 'source_kind', 'destination_kind', 'source_flags',
    'destination_flags', 'mtime_equal', 'mtime_delta_ns', 'source_acl', 'destination_acl', 'acl_equal'))
DETAIL_FIELDS = frozenset(('schema', 'status', 'observation_phase', 'entry_count', 'entries',
    'hardlink_scope', 'source_hardlink_groups', 'destination_hardlink_groups', 'source_unchanged',
    'outside_sentinel_unchanged', 'destination_independent'))
COVERAGE = ('ownership', 'metadata', 'hardlink_classes', 'symlinks', 'flags', 'setid', 'inherited_acl')
PIN_PATHS = ('stallionfs/_tree.c', 'stallionfs/_tree.h', 'stallionfs/_benchmark_budget.py',
             'tests/perf/native_metrics.py', 'tests/native_directory_clone_probe.c',
             'tests/perf/native_directory_clone_probe.py', 'tests/perf/native_phase_probe.py',
             'tests/perf/fileops.py', 'tests/perf/native_fixtures.py', 'tests/perf/native_correctness.py',
             'tests/perf/native_suite.py', 'tests/test_fileops.py', 'tests/test_copy.py')
PIN_PATHS += ('tests/test_native_directory_clone_probe.py', '.github/workflows/checks.yml')
PIN_PATHS += ('tests/perf/native_directory_restore.py', 'tests/test_native_directory_restore.py')
SETUP_ERRORS = {'host_checks': 'host_check_failed', 'inputs': 'input_unavailable',
                'wheel_identity': 'wheel_unavailable', 'source_pins': 'pin_unavailable',
                'binary_pins': 'binary_pin_unavailable', 'private_fixture_setup': 'fixture_setup_failed',
                'volume': 'volume_probe_failed', 'host_metadata': 'host_metadata_unavailable',
                'scratch_checks': 'scratch_check_failed'}


def pins(checkout):
    try:
        return {path: digest(checkout / path) for path in PIN_PATHS}
    except OSError:
        raise ProbeError('pin_unavailable') from None


def protocol(raw):
    require(len(raw) <= 1024, 'protocol_invalid')
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, ProbeError):
        raise ProbeError('protocol_invalid') from None
    require(isinstance(value, dict) and set(value) == {'schema', 'marker', 'native_return',
            'native_errno', 'admission_errno', 'clone_calls', 'close_error'}, 'protocol_invalid')
    require(type(value['schema']) is int and value['schema'] == 1 and value['marker'] == MARKER,
            'protocol_invalid')
    require(all(type(value[key]) is int for key in ('admission_errno', 'clone_calls', 'close_error')),
            'protocol_invalid')
    require(value['clone_calls'] in (0, 1) and 0 <= value['close_error'] <= 65535, 'protocol_invalid')
    if value['clone_calls'] == 0:
        require(value['native_return'] is None and value['native_errno'] is None
                and 0 < value['admission_errno'] <= 65535, 'protocol_invalid')
    else:
        require(type(value['native_return']) is int and type(value['native_errno']) is int
                and value['admission_errno'] == 0 and ((value['native_return'] == 0 and value['native_errno'] == 0)
                or (value['native_return'] == -1 and 0 < value['native_errno'] <= 65535)), 'protocol_invalid')
    return value


def first_recipe_detail(source, destination, summary, independent):
    """Project captured snapshots onto a bounded, path-free metadata schema."""
    def unavailable(reason):
        return {'schema': 1, 'status': 'unavailable', 'reason': reason}

    if (type(summary) is not dict or summary.get('source_unchanged') is not True or summary.get('outside_sentinel_unchanged') is not True
            or independent is not True):
        return unavailable('identity_unverified')
    try:
        left, right = source['entries'], destination['entries']
        require(type(left) is dict and type(right) is dict and type(source['unavailable_fields']) is list
                and type(destination['unavailable_fields']) is list and not source['unavailable_fields']
                and not destination['unavailable_fields'] and all(type(entry) is dict for entry in left.values())
                and all(type(entry) is dict for entry in right.values()), 'detail_schema_invalid')
        require(0 < len(left) <= DETAIL_MAX_ENTRIES and 0 < len(right) <= DETAIL_MAX_ENTRIES,
                'detail_bounds_exceeded')
        names = left.keys() | right.keys()
        require(len(names) <= DETAIL_MAX_ENTRIES, 'detail_bounds_exceeded')
        require(all(type(name) is str for name in names), 'detail_schema_invalid')
        ids = {name: f'e{index:04}' for index, name in enumerate(sorted(names), 1)}

        def metadata(entry):
            if entry is None: return (None,) * 5
            require(type(entry) is dict and type(entry['kind']) is str
                    and entry['kind'] in ('file', 'directory', 'symlink'), 'detail_schema_invalid')
            flags, mtime, acl = entry['flags'], entry['mtime_ns'], entry['acl']
            require(type(flags) is int and 0 <= flags <= 0xffffffff and type(mtime) is int
                    and -(1 << 63) <= mtime < (1 << 63), 'detail_schema_invalid')
            require(type(acl) is dict and set(acl) == {'text_hex', 'unavailable'}
                    and acl['unavailable'] is None, 'detail_schema_invalid')
            encoded = acl['text_hex']
            require(encoded is None or (type(encoded) is str and len(encoded) <= 16384
                    and len(encoded) % 2 == 0 and re.fullmatch('[0-9a-f]*', encoded) is not None), 'detail_schema_invalid')
            text = bytes.fromhex(encoded) if encoded is not None else b''
            lines = [line.strip() for line in text.rstrip(b'\x00').splitlines() if line.strip()]
            require(not lines or lines[0].startswith(b'!#acl '), 'detail_schema_invalid')
            state = 'nonempty' if any(not line.startswith(b'!#') for line in lines) else 'empty'
            return entry['kind'], flags, mtime, state, encoded

        entries = []
        for name, entry_id in ids.items():
            a, b = metadata(left.get(name)), metadata(right.get(name))
            delta = b[2] - a[2] if a[0] is not None and b[0] is not None else None
            require(delta is None or -(1 << 63) <= delta < (1 << 63), 'detail_schema_invalid')
            entry = {'entry_id': entry_id, 'source_kind': a[0], 'destination_kind': b[0],
                     'source_flags': a[1], 'destination_flags': b[1],
                     'mtime_equal': delta == 0 if delta is not None else None, 'mtime_delta_ns': delta,
                     'source_acl': a[3], 'destination_acl': b[3],
                     'acl_equal': a[4] == b[4] if delta is not None else None}
            require(set(entry) == DETAIL_ENTRY_FIELDS, 'detail_schema_invalid')
            entries.append(entry)

        def groups(snapshot, observed):
            raw = snapshot['hardlink_groups']
            require(type(raw) is list and len(raw) <= DETAIL_MAX_ENTRIES // 2, 'detail_schema_invalid')
            seen, normalized = set(), []
            for group in raw:
                require(type(group) is list and 2 <= len(group) <= DETAIL_MAX_ENTRIES
                        and all(type(name) is str and name in observed for name in group), 'detail_schema_invalid')
                require(len(set(group)) == len(group) and not seen.intersection(group), 'detail_schema_invalid')
                kinds = {observed[name]['kind'] for name in group}
                require(len(kinds) == 1 and kinds <= {'file', 'symlink'}, 'detail_schema_invalid')
                seen.update(group); normalized.append(sorted(ids[name] for name in group))
            return sorted(normalized)

        detail = {'schema': 1, 'status': 'available', 'observation_phase': 'post_clone_pre_alias_write',
                  'entry_count': len(entries), 'entries': entries,
                  'hardlink_scope': 'within_fixture; omitted leaf IDs are singletons',
                  'source_hardlink_groups': groups(source, left),
                  'destination_hardlink_groups': groups(destination, right),
                  'source_unchanged': True, 'outside_sentinel_unchanged': True, 'destination_independent': True}
        require(set(detail) == DETAIL_FIELDS, 'detail_schema_invalid')
        require(len(json.dumps(detail).encode()) <= DETAIL_MAX_BYTES, 'detail_bounds_exceeded')
        return detail
    except ProbeError as error:
        return unavailable(str(error) if str(error) in ('detail_schema_invalid', 'detail_bounds_exceeded') else 'detail_schema_invalid')
    except (KeyError, TypeError, ValueError, OverflowError):
        return unavailable('detail_schema_invalid')


def verdict(expected, source_after, destination, outside_before, outside_after, correct, preserved, *, include_detail=False):
    source_ok = correct.verify_source(expected, source_after)['unchanged'] is True
    sentinel_ok = correct.verify_source(outside_before, outside_after)['unchanged'] is True
    checks = correct.verify_clone(expected, destination)
    sharing = correct.clone_sharing(source_after, destination)['full_data_stream_sharing'] is True
    fields = sorted({row['field'] for row in checks.get('candidate_losses', [])})
    require(set(fields) <= set(correct.FIELDS) | {'entry', 'hardlink_groups', 'metadata_capabilities'}, 'comparison_invalid')
    result = {'destination_preserved': preserved(checks), 'source_unchanged': source_ok,
            'outside_sentinel_unchanged': sentinel_ok, 'full_data_stream_sharing': sharing,
            'difference_counts': {field: sum(row['field'] == field for row in checks['candidate_losses']) for field in fields},
            'passed': preserved(checks) and source_ok and sentinel_ok and sharing}
    if include_detail:
        result['first_recipe_detail'] = first_recipe_detail(expected, destination, result, checks.get('independent_clone'))
    return result


def recipes():
    """One attempt per recipe; existing assertions remain strict, with no jobs sweep."""
    return [(FIRST_RECIPE, None), ('setid', None),
            *[('inherit-' + name, None) for name in ('clean', 'parent-read', 'owner', 'foreign-read', 'foreign-xattr')],
            *[('parent-' + name, None) for name in ('shared', 'sticky', 'deny', 'current-user', 'other-principal')],
            *[('existing-' + name, (errno.EEXIST,)) for name in ('file', 'directory', 'link', 'dangling')],
            ('inside-source', (errno.EINVAL,)), ('stale-source-pin', (errno.ESTALE,)), ('special', (errno.ENOTSUP,))]


def prepare(base, name, native_fixtures, correct, run):
    """Controlled adaptations of test_fileops.FileOperations and test_copy.OrdinaryCopy recipes."""
    source, parent, outside = base / 'source', base / 'parent', base / 'outside'
    source.mkdir(mode=0o750); parent.mkdir(mode=0o700); outside.mkdir(mode=0o700)
    (outside / 'sentinel').write_bytes(b'outside remains unchanged\n')
    (source / 'file').write_bytes(b'original')
    expected_error = dict(recipes()).get(name)
    protected = []
    coverage = {'ownership': True, 'metadata': False, 'hardlink_classes': False, 'symlinks': False,
                'flags': False, 'setid': False, 'inherited_acl': False}
    if name == 'metadata-hardlinks-symlinks-flags':
        (source / 'file').unlink()
        for directory in ('a', 'b', 'c'): (source / directory).mkdir(mode=0o750)
        leaf = source / 'a/file'; leaf.write_bytes(b'original')
        link = source / 'a/link'; link.symlink_to('absent-target')
        for directory in ('b', 'c'):
            for entry in ('file', 'link'): os.link(source / 'a' / entry, source / directory / entry, follow_symlinks=False)
        os.link(leaf, outside / 'external-file')
        os.link(link, outside / 'external-link', follow_symlinks=False)
        (source / 'outside').symlink_to(outside, target_is_directory=True)
        (source / 'space \n café 🐎').write_bytes(b'names are bytes')
        seed = {}; native_fixtures.enrich_metadata(source, receipt=seed)
        tracked = getattr(stat, 'UF_TRACKED', 0x40)
        for path in (source, source / 'a', leaf, link):
            os.chflags(path, path.lstat().st_flags | tracked, follow_symlinks=False)
        for entry, flag in (('immutable', stat.UF_IMMUTABLE), ('append', stat.UF_APPEND)):
            path = source / 'c' / entry; path.write_bytes(b'protected content')
            os.chflags(path, tracked | flag); protected.append(path.relative_to(source))
        (source / 'a').chmod(0o500); source.chmod(0o550)
        observed = correct.snapshot(source)
        require(native_fixtures.verify_metadata_coverage(observed, seed)['populated'] is True, 'coverage_incomplete')
        require(len(observed['hardlink_groups']) == 3 and all(
            observed['entries'][entry]['flags'] & tracked for entry in ('', 'a', 'a/file', 'a/link')),
            'coverage_incomplete')
        coverage.update(metadata=True, hardlink_classes=True, symlinks=True, flags=True)
    elif name == 'setid':
        os.chown(source / 'file', -1, os.getegid()); (source / 'file').chmod(0o6750)
        require(stat.S_IMODE((source / 'file').stat().st_mode) == 0o6750, 'coverage_incomplete')
        coverage['setid'] = True
    elif name.startswith('inherit-'):
        (source / 'file').chmod(0o600)
        run(['/usr/bin/xattr', '-w', 'com.apple.ResourceFork', 'private resource fork', str(source / 'file')])
        user = pwd.getpwuid(os.getuid()).pw_name
        values = {'clean': None, 'parent-read': 'everyone allow read,readextattr',
                  'owner': f'user:{user} allow read,readextattr,file_inherit',
                  'foreign-read': 'everyone allow read,file_inherit',
                  'foreign-xattr': 'everyone allow readextattr,file_inherit'}
        acl = values[name.removeprefix('inherit-')]
        if acl: run(['/bin/chmod', '+a', acl, str(parent)])
        if name in ('inherit-foreign-read', 'inherit-foreign-xattr'): expected_error = (errno.EPERM,)
        coverage['inherited_acl'] = True
    elif name.startswith('parent-'):
        user = pwd.getpwuid(os.getuid()).pw_name
        mutation = 'add_file,add_subdirectory,delete_child'
        mode, acl, allowed = {'shared': (0o777, None, False), 'sticky': (0o1777, None, True),
            'deny': (0o700, 'group:everyone deny delete_child', True),
            'current-user': (0o700, f'user:{user} allow {mutation}', True),
            'other-principal': (0o700, f'group:everyone allow {mutation}', False)}[name.removeprefix('parent-')]
        parent.chmod(mode)
        if acl: run(['/bin/chmod', '+a', acl, str(parent)])
        if not allowed: expected_error = (errno.EPERM,)
    elif name.startswith('existing-'):
        destination = parent / 'output'
        kind = name.removeprefix('existing-')
        if kind == 'file': destination.write_bytes(b'keep')
        elif kind == 'directory': destination.mkdir(); (destination / 'sentinel').write_bytes(b'keep')
        else: destination.symlink_to(outside if kind == 'link' else 'missing', target_is_directory=True)
    elif name == 'inside-source': parent = source
    elif name == 'special': os.mkfifo(source / 'unsupported')
    return source, parent, outside, expected_error, protected, coverage


def probe(binary, wheel, helper, scratch, output, revision, *, first_recipe_only=False, restore_first_recipe=False):
    from stallionfs._benchmark_budget import command
    import stallionfs
    import fileops
    import native_correctness as correct
    import native_fixtures
    import native_suite
    result = {'schema': 1, 'scope': 'hosted directory-clone feasibility only', 'status': 'incomplete',
              'stage': 'host_checks',
              'setup_completion': 'not_started', 'target_completion': 'not_started', 'helper_launch': 'not_started',
              'restoration_completion': 'not_started', 'cases': [], 'docs_attempted': False, 'clone_calls': 0,
              'helper_invocations': 0,
              'cleanup': 'not_started', 'benchmark_verdict': 'not_applicable',
              'concurrency_and_cancellation': 'unresolved'}
    if first_recipe_only:
        result.update(scope='hosted directory-clone first-recipe detail only', first_recipe_only=True, full_gate_qualified=False)
    if restore_first_recipe:
        result.update(scope='hosted first-recipe selective restoration only', restoration_only=True, full_gate_qualified=False)
    private = identity = None
    safe_to_clean = True
    protected_paths = []
    restoration_sessions = []
    os.environ['STALLIONFS_BENCHMARK_DEADLINE'] = str(time.monotonic() + 180)
    try:
        require(not restore_first_recipe or first_recipe_only, 'restoration_scope_invalid')
        require(sys.platform == 'darwin' and os.environ.get('GITHUB_ACTIONS') == 'true'
                and os.environ.get('STALLIONFS_DIRECTORY_FEASIBILITY_HOSTED') == '1'
                and re.fullmatch('[0-9a-f]{40}', revision) is not None, 'host_invalid')
        checkout = Path(__file__).resolve().parents[2]
        result['stage'] = 'inputs'
        binary, wheel, helper, scratch = [path.resolve(strict=True) for path in (binary, wheel, helper, scratch)]
        runner = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        os.environ['RUNNER_TEMP'] = str(runner)
        require(scratch.is_relative_to(runner) and scratch != runner and helper.is_file()
                and os.access(helper, os.X_OK) and binary.is_file() and os.access(binary, os.X_OK)
                and wheel.is_file() and not os.path.lexists(output), 'input_invalid')
        result['stage'] = 'wheel_identity'
        require(not Path(stallionfs.__file__).resolve().is_relative_to(checkout), 'wheel_invalid')
        result['stage'] = 'source_pins'
        pinned = pins(checkout)
        result['stage'] = 'binary_pins'
        binaries = {'helper_sha256': digest(helper), 'cli_sha256': digest(binary), 'wheel_sha256': digest(wheel)}
        result.update(revision=revision, source_sha256=pinned, **binaries)
        result['stage'] = 'private_fixture_setup'
        private = Path(tempfile.mkdtemp(prefix='directory-feasibility-private-', dir=scratch)); identity = private.stat()
        receipts = private / 'receipts'; receipts.mkdir(mode=0o700)
        os.environ['STALLIONFS_BENCHMARK_RECEIPTS'] = str(receipts)

        def check_pins():
            require(pins(checkout) == pinned and all(digest(path) == binaries[key] for path, key in
                    ((helper, 'helper_sha256'), (binary, 'cli_sha256'), (wheel, 'wheel_sha256'))), 'source_changed')

        def run(argv, timeout=10, *, target=False):
            nonlocal safe_to_clean
            receipt = {}
            safe_to_clean = False
            completion = 'target_completion' if target else 'setup_completion'
            result[completion] = 'unknown'
            if target: result['helper_launch'] = 'unknown'
            try:
                child = command(argv, timeout=timeout, umask=0o077, receipt=receipt, output_limit=65536)
            except BaseException:
                raise ProbeError(completion + '_unknown') from None
            finally:
                if target and type(receipt.get('pid')) is int and receipt['pid'] > 0:
                    result['helper_launch'] = 'observed'
            if not clean_capture(receipt):
                raise ProbeError(completion + '_unknown')
            # Transport is complete; case correctness and cleanup remain unproven.
            result[completion] = 'complete'
            return child

        result['stage'] = 'volume'
        inventory = json.loads(run([str(binary), '--json', 'volumes']).stdout)
        volume = fileops.scratch_volume(inventory, scratch)
        require(volume.get('ignore_ownership') is False, 'scratch_invalid')
        result['volume'] = {'filesystem': 'apfs', 'readonly': False, 'ignore_ownership': False}
        result['stage'] = 'host_metadata'
        build = run(['/usr/bin/sw_vers', '-buildVersion']).stdout.decode('ascii').strip()
        require(re.fullmatch(r'\d+[A-Z]\d+[a-z]?', build) is not None, 'host_invalid')
        result['host'] = {'os': platform.mac_ver()[0], 'build': build, 'arch': os.uname().machine}
        result['stage'] = 'scratch_checks'
        require(shutil.disk_usage(scratch).free >= fileops.HEADROOM, 'scratch_invalid')
        fileops.no_mounts_below(binary, private)

        def execute(base, name, docs=False):
            nonlocal safe_to_clean
            check_pins()
            if docs:
                source = fileops.large_fixture(base, 'docs_5k_100mb', fileops.LARGE_PROFILES['docs_5k_100mb'])
                parent = base / 'parent'; parent.mkdir(mode=0o700)
                outside = base / 'outside'; outside.mkdir(mode=0o700)
                (outside / 'sentinel').write_bytes(b'keep outside linked trees\n')
                seed = {}; native_fixtures.enrich_metadata(source, receipt=seed)
                expected_error, protected, coverage = None, [], {}
                require(native_fixtures.verify_metadata_coverage(correct.snapshot(source), seed)['populated'] is True,
                        'coverage_incomplete')
            else:
                source, parent, outside, expected_error, protected, coverage = prepare(base, name, native_fixtures, correct, run)
            destination = parent / 'output'
            expected = correct.snapshot(source, allow_special=name == 'special')
            outside_before = correct.snapshot(outside)
            existing = correct.snapshot(destination) if os.path.lexists(destination) else None
            source_info, parent_info, base_info = source.stat(), parent.stat(), base.stat()
            require(correct.verify_source(expected, correct.snapshot(source, allow_special=name == 'special'))['unchanged'] is True,
                    'source_precheck_failed')
            restoration = None
            if restore_first_recipe:
                require(first_recipe_only and name == FIRST_RECIPE and not docs, 'restoration_scope_invalid')
                result['stage'] = 'restoration_admission'
                import native_directory_restore as restore
                try:
                    restoration = restore.Session(base, source.name, parent.name, expected,
                        cancelled=lambda: time.monotonic() >= float(os.environ['STALLIONFS_BENCHMARK_DEADLINE']))
                except restore.AdmissionError as error:
                    result['restoration_admission'] = error.report
                    raise ProbeError('restoration_admission_failed') from None
                except BaseException as error:
                    result['restoration_admission'] = restore.refusal_report(error)
                    raise ProbeError('restoration_admission_failed') from None
                result['restoration_admission'] = restoration.admission_report()
                restoration_sessions.append(restoration)
                result['stage'] = 'small_recipes'
            protected_paths.extend(source / relative for relative in protected)
            source_inode = source_info.st_ino + (name == 'stale-source-pin')
            argv = [str(helper), str(base), str(base_info.st_dev), str(base_info.st_ino), source.name, parent.name, 'output',
                    str(source_info.st_dev), str(source_inode), str(parent_info.st_dev), str(parent_info.st_ino)]
            safe_to_clean = False
            row = {'case': name, 'passed': False, 'coverage': coverage}
            result['cases'].append(row)
            known_calls = result['clone_calls']
            result['clone_calls'] = None
            row['clone_calls'] = None
            result['helper_invocations'] += 1
            if docs: result['docs_attempted'] = True
            child = run(argv, timeout=60 if docs else 10, target=True)
            try:
                native = protocol(child.stdout)
                require(not child.stderr, 'protocol_invalid')
            except BaseException:
                result['target_completion'] = 'unknown'
                raise
            row.update({key: native[key] for key in ('native_return', 'native_errno', 'admission_errno', 'clone_calls', 'close_error')})
            result['clone_calls'] = known_calls + native['clone_calls']
            check_pins()
            require(native['close_error'] == 0, 'descriptor_close_failed')
            # An ordinary, completed refusal remains distinct from failed capture.
            if expected_error is not None:
                require((native['clone_calls'] == 0 or native['native_return'] == -1)
                        and (native['native_errno'] if native['clone_calls'] else native['admission_errno']) in expected_error,
                        'refusal_failed')
                source_ok = correct.verify_source(expected, correct.snapshot(source, allow_special=name == 'special'))['unchanged'] is True
                sentinel_ok = correct.verify_source(outside_before, correct.snapshot(outside))['unchanged'] is True
                destination_ok = (correct.verify_source(existing, correct.snapshot(destination))['unchanged'] is True
                                  if existing is not None else not os.path.lexists(destination))
                row.update(source_unchanged=source_ok, outside_sentinel_unchanged=sentinel_ok,
                           destination_unchanged=destination_ok, passed=source_ok and sentinel_ok and destination_ok)
            else:
                require(native['native_return'] == 0 and native['clone_calls'] == 1, 'clone_failed')
                after = correct.snapshot(destination, observe_sharing=True)
                source_after = correct.snapshot(source, observe_sharing=True)
                if restoration is not None:
                    raw = verdict(expected, source_after, after, outside_before, correct.snapshot(outside), correct,
                                  native_suite.preserved, include_detail=True)
                    row['raw_clone'] = raw
                    require(raw['source_unchanged'] and raw['outside_sentinel_unchanged']
                            and raw.get('first_recipe_detail', {}).get('destination_independent') is True
                            and raw['full_data_stream_sharing'], 'restoration_precheck_failed')
                    result['restoration_completion'] = 'incomplete'
                    row['restoration'] = restoration.restore(after)
                    result['restoration_completion'] = row['restoration']['status']
                    require(row['restoration']['status'] == 'restored_pending_final_verifiers', 'restoration_incomplete')
                    # Every existing strict verifier and alias-isolation assertion still runs.
                    after = correct.snapshot(destination, observe_sharing=True)
                    source_after = correct.snapshot(source, observe_sharing=True)
                row.update(verdict(expected, source_after, after, outside_before, correct.snapshot(outside), correct,
                                   native_suite.preserved, include_detail=first_recipe_only and name == FIRST_RECIPE))
                protected_paths.extend(destination / relative for relative in protected)
                if name == 'metadata-hardlinks-symlinks-flags' and row['passed']:
                    # Existing cross-directory alias isolation assertion, after the immutable snapshot comparison.
                    (destination / 'b/file').write_bytes(b'changed')
                    require((destination / 'c/file').read_bytes() == b'changed' and (source / 'a/file').read_bytes() == b'original',
                            'alias_isolation_failed')
                    require(correct.verify_source(expected, correct.snapshot(source))['unchanged'] is True
                            and correct.verify_source(outside_before, correct.snapshot(outside))['unchanged'] is True,
                            'alias_isolation_failed')
            require(row['passed'], 'correctness_failed')
            check_pins()
            safe_to_clean = True

        result['stage'] = 'small_recipes'
        cases = recipes()
        require(len(cases) == MAX_SMALL_CASES, 'case_plan_invalid')
        if first_recipe_only:
            require(cases[0] == (FIRST_RECIPE, None), 'case_plan_invalid')
        for index, (name, _) in enumerate(cases[:1] if first_recipe_only else cases):
            base = private / f'case-{index:02}'; base.mkdir(mode=0o700)
            safe_to_clean = False
            execute(base, name)
        if first_recipe_only:
            require(len(result['cases']) == 1 and result['helper_invocations'] == 1 and result['clone_calls'] == 1
                    and result['cases'][0].get('first_recipe_detail', {}).get('status') == 'available',
                    'first_recipe_detail_unavailable')
            result['status'] = 'first_recipe_restoration_complete' if restore_first_recipe else 'first_recipe_diagnostic_complete'
        else:
            require(len(result['cases']) == MAX_SMALL_CASES and all(row['passed'] for row in result['cases']), 'small_gate_failed')
            require(all(any(row['coverage'].get(field) is True for row in result['cases']) for field in COVERAGE),
                    'coverage_incomplete')
            result['stage'] = 'document_recipe'
            base = private / 'docs'; base.mkdir(mode=0o700)
            safe_to_clean = False
            execute(base, 'docs_5k_100mb', docs=True)
            result['status'] = 'feasible_controlled_fixture_only'
        result['stage'] = 'complete'
    except BaseException as error:
        result['error'] = str(error) if isinstance(error, ProbeError) else SETUP_ERRORS.get(result['stage'], 'probe_incomplete')
    finally:
        for restoration in restoration_sessions:
            closed = restoration.close()
            result['restoration_admission'] = restoration.admission_report()
            if not closed:
                safe_to_clean = False
                result.update(status='incomplete', error='restoration_close_failed')
                for row in result['cases']:
                    if 'restoration' in row: row['restoration'] = dict(restoration.summary)
        if private is not None:
            result['cleanup'] = 'retained_ephemeral'
            if safe_to_clean:
                try:
                    current = private.lstat()
                    require(stat.S_ISDIR(current.st_mode) and current.st_uid == os.getuid()
                            and stat.S_IMODE(current.st_mode) == 0o700 and
                            (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino), 'cleanup_failed')
                    fileops.no_mounts_below(binary, private)
                    for path in protected_paths:
                        entry = path.lstat()
                        require(stat.S_ISREG(entry.st_mode) and entry.st_uid == os.getuid(), 'cleanup_failed')
                        os.chflags(path, entry.st_flags & ~(stat.UF_IMMUTABLE | stat.UF_APPEND), follow_symlinks=False)
                    for parent, _, _ in os.walk(private, followlinks=False): os.chmod(parent, 0o700)
                    shutil.rmtree(private)
                    require(not private.exists(), 'cleanup_failed')
                    result['cleanup'] = 'complete'
                except BaseException:
                    result['status'] = 'incomplete'; result['stage'] = 'cleanup'; result['error'] = 'cleanup_failed'
        publish(output, result)
    complete = ('first_recipe_restoration_complete' if restore_first_recipe else
                'first_recipe_diagnostic_complete' if first_recipe_only else 'feasible_controlled_fixture_only')
    return 0 if result['status'] == complete and result['cleanup'] == 'complete' else 1


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'wheel', 'helper', 'scratch', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--first-recipe-only', action='store_true')
    parser.add_argument('--restore-first-recipe', action='store_true')
    args = parser.parse_args()
    try:
        return probe(args.binary, args.wheel, args.helper, args.scratch, args.output, args.revision,
                     first_recipe_only=args.first_recipe_only, restore_first_recipe=args.restore_first_recipe)
    except BaseException:
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
