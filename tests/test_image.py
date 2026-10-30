"""Owned, offline APFS image qualification; no mount or hardware power-cut claim."""
import json
import io
import os
from contextlib import redirect_stderr
from pathlib import Path
import shlex
import shutil
import subprocess
import selectors
import signal
import time
import sys
import tempfile
import unittest
from unittest import mock


_COMMAND_STREAM_CAP = 1024 * 1024
_command_state = {'failure': None, 'active': None, 'first_signal': None, 'signal_count': 0}


def _exclusive(path, value):
    data = value.encode() if isinstance(value, str) else value
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        stream.write(data)


def _latch_command(kind, detail):
    if _command_state['failure'] is None:
        _command_state['failure'] = {'kind': kind, 'detail': detail}


def _cancel_command(signum, _frame, *, state):
    if state.get('cancellation_closed', False):
        return
    if state['first_signal'] is None:
        state['first_signal'] = signum
    state['signal_count'] += 1
    if state['failure'] is None:
        state['failure'] = {'kind': 'cancelled', 'detail': f'signal {signum}'}


def _install_command_handlers():
    state = _command_state

    def cancel(signum, frame):
        _cancel_command(signum, frame, state=state)

    previous = {}
    for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        previous[number] = signal.signal(number, cancel)
    return previous


def _restore_command_handlers(previous):
    for number, handler in previous.items():
        signal.signal(number, handler)


def _owned_command(argv, *, cwd, timeout, stem):
    if _command_state['failure'] is not None:
        raise RuntimeError(f'Further image commands refused: {_command_state["failure"]}')
    assert _command_state['active'] is None
    stem = Path(stem)
    record = {'label': stem.name, 'argv': argv, 'cwd': str(cwd) if cwd else None,
              'timeout_seconds': timeout, 'stream_cap_bytes': _COMMAND_STREAM_CAP,
              'pid': None, 'pgid': None, 'phase': 'preparing', 'returncode': None,
              'timeout': False, 'cap_reached': [], 'cleanup_errors': [],
              'cleanup_uncertain': False, 'kill_attempts': 0, 'cleanup_started': False,
              'stdout_retained_bytes': 0, 'stderr_retained_bytes': 0,
              'stdout_discarded_bytes': 0, 'stderr_discarded_bytes': 0}
    _command_state['active'] = record
    proc = None
    selector = None
    outputs = {}
    primary = None
    started = time.monotonic()

    def capture(cleaning=False):
        for event, _ in selector.select(0.05):
            name = event.data
            try:
                chunk = os.read(event.fileobj.fileno(), 65536)
            except BlockingIOError:
                continue
            if not chunk:
                selector.unregister(event.fileobj)
                event.fileobj.close()
                continue
            key = name + '_retained_bytes'
            keep = min(len(chunk), _COMMAND_STREAM_CAP - record[key])
            written = outputs[name].write(chunk[:keep])
            valid_write = type(written) is int and 0 <= written <= keep
            retained = written if valid_write else 0
            record[key] += retained
            record[name + '_discarded_bytes'] += len(chunk) - retained
            if not valid_write or written != keep:
                raise OSError('Image command capture short write')
            if record[key] >= _COMMAND_STREAM_CAP:
                if name not in record['cap_reached']:
                    record['cap_reached'].append(name)
                _latch_command('capture_limit', stem.name)
                if not cleaning:
                    raise RuntimeError(f'Image command capture limit: {stem}')

    def cleanup_poll():
        try:
            return proc.poll()
        except BaseException as error:
            record['cleanup_errors'].append(repr(error))
            record['cleanup_uncertain'] = True
            return None

    try:
        selector = selectors.DefaultSelector()
        _exclusive(str(stem) + '.started.json', json.dumps(record, indent=2) + '\n')
        for name in ('stdout', 'stderr'):
            path = Path(str(stem) + '.' + name + '.bin')
            record[name + '_path'] = str(path)
            outputs[name] = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb', buffering=0)
        if _command_state['failure'] is not None:
            raise RuntimeError(f'Image command cancelled before launch: {_command_state["failure"]}')
        record['phase'] = 'spawning'
        proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
        record.update(pid=proc.pid, pgid=proc.pid, phase='running')
        for name, pipe in (('stdout', proc.stdout), ('stderr', proc.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while selector.get_map() or proc.poll() is None:
            if _command_state['first_signal'] is not None:
                raise RuntimeError(f'Image command cancelled by signal {_command_state["first_signal"]}')
            if time.monotonic() - started >= timeout:
                record['timeout'] = True
                raise subprocess.TimeoutExpired(argv, timeout)
            capture()
        if proc.returncode:
            _latch_command('exit', f'{stem.name}: {proc.returncode}')
        try:
            os.killpg(proc.pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise RuntimeError('Image command left an owned process group alive')
    except BaseException as error:
        primary = error
        if isinstance(error, subprocess.TimeoutExpired):
            record['timeout'] = True
            _latch_command('timeout', stem.name)
        else:
            _latch_command('command_error', repr(error))
    finally:
        if proc is not None and (_command_state['failure'] is not None or primary is not None):
            record['cleanup_started'] = True
            record['phase'] = 'cleaning'
            record['drain_deadline'] = time.monotonic() + 2
            record['reap_deadline'] = record['drain_deadline'] + 2
            leader_reaped = proc.returncode is not None
            if leader_reaped:
                # Reaping releases the PID; its numeric group no longer proves ownership.
                record['group_signal_skipped_reason'] = 'leader_already_reaped'
                record['group_ownership_after_cleanup'] = 'unknown_after_reap'
                record['group_alive_after_cleanup'] = None
                record['cleanup_uncertain'] = True
            else:
                record['kill_attempts'] += 1
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except BaseException as error:
                    record['cleanup_errors'].append(repr(error))
                    record['cleanup_uncertain'] = True
            while selector is not None and selector.get_map() and time.monotonic() < record['drain_deadline']:
                try:
                    capture(cleaning=True)
                except BaseException as error:
                    record['cleanup_errors'].append(repr(error))
                    record['cleanup_uncertain'] = True
                    break
            if selector is not None and selector.get_map():
                record['cleanup_uncertain'] = True
            if cleanup_poll() is None:
                try:
                    proc.wait(timeout=min(2, max(0, record['reap_deadline'] - time.monotonic())))
                except BaseException as error:
                    record['cleanup_errors'].append(repr(error))
                    record['cleanup_uncertain'] = True
            if cleanup_poll() is None:
                record['cleanup_uncertain'] = True
            if not leader_reaped:
                try:
                    os.killpg(proc.pid, 0)
                except ProcessLookupError:
                    record['group_alive_after_cleanup'] = False
                except BaseException as error:
                    record['cleanup_errors'].append(repr(error))
                    record['cleanup_uncertain'] = True
                else:
                    record['group_alive_after_cleanup'] = True
                    record['cleanup_uncertain'] = True
        if proc is not None:
            record['returncode'] = cleanup_poll()
            for pipe in (proc.stdout, proc.stderr):
                try:
                    pipe.close()
                except BaseException as error:
                    record['cleanup_errors'].append(repr(error))
                    record['cleanup_uncertain'] = True
        try:
            if selector is not None:
                selector.close()
        except BaseException as error:
            record['cleanup_errors'].append(repr(error))
            record['cleanup_uncertain'] = True
        for stream in outputs.values():
            try:
                stream.close()
            except BaseException as error:
                record['cleanup_errors'].append(repr(error))
                record['cleanup_uncertain'] = True
        record.update(phase='done', first_signal=_command_state['first_signal'],
                      signal_count=_command_state['signal_count'], elapsed_seconds=time.monotonic() - started)
        if record['cleanup_uncertain']:
            _latch_command('cleanup_uncertain', stem.name)
        record['first_failure'] = _command_state['failure']
        record['primary_exception'] = repr(primary) if primary is not None else None
        try:
            _exclusive(str(stem) + '.command.json', json.dumps(record, indent=2) + '\n')
        except BaseException as error:
            _latch_command('receipt_error', repr(error))
            if primary is None:
                primary = error
            elif hasattr(primary, 'add_note'):
                primary.add_note(f'Command receipt capture also failed: {error!r}')
        _command_state['active'] = None
    try:
        stdout = Path(record['stdout_path']).read_bytes() if 'stdout_path' in record and Path(record['stdout_path']).is_file() else b''
        stderr = Path(record['stderr_path']).read_bytes() if 'stderr_path' in record and Path(record['stderr_path']).is_file() else b''
    except BaseException as error:
        _latch_command('capture_read_error', repr(error))
        if primary is not None:
            raise primary from error
        raise
    if isinstance(primary, subprocess.TimeoutExpired):
        if primary.output is None:
            primary.output = stdout
        if primary.stderr is None:
            primary.stderr = stderr
    if primary is not None:
        raise primary
    if _command_state['failure'] is not None and not record['returncode']:
        raise RuntimeError(f'Image command failed or incomplete: {_command_state["failure"]}')
    try:
        return subprocess.CompletedProcess(argv, record['returncode'], stdout.decode(), stderr.decode())
    except BaseException as error:
        _latch_command('decode_error', repr(error))
        raise


@unittest.skipUnless(sys.platform == 'darwin', 'Offline image core requires macOS APFS')
class ImageCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = Path(tempfile.mkdtemp(prefix='stallionfs-image-tests-')).resolve()
        cls.failed = False
        cls.executables = {}
        cls.source = Path(__file__).resolve().parents[1]
        cls.common = [*shlex.split(os.environ.get('CC', 'cc')), '-std=c11', '-O2', '-g',
                      '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
                      '-I', str(cls.source / 'filesystem'), *shlex.split(os.environ.get('CFLAGS', ''))]
        try:
            cls.compile('normal')
        except BaseException as error:
            _latch_command('compile', repr(error))
            print(f'Image compilation evidence retained: {cls.base}', file=sys.stderr)
            raise

    @classmethod
    def compile(cls, name, *defines):
        if name in cls.executables:
            return cls.executables[name]
        obj, exe = cls.base / f'{name}.o', cls.base / name
        replacements = ('pread', 'pwrite', 'fcntl', 'fsync', 'flock', 'close',
                        'openat', 'fstat', 'fstatat', 'fstatfs', 'mkdirat', 'unlinkat',
                        'ftruncate', 'malloc', 'calloc', 'free', 'clock_gettime',
                        'CC_SHA256_Init', 'CC_SHA256_Update', 'CC_SHA256_Final')
        shim = cls.base / 'image-copy-hook.h'
        shim_bytes = ('#include <string.h>\n'
                        'void *sfs_test_memcpy(void *, const void *, size_t);\n'
                        '#undef memcpy\n#define memcpy sfs_test_memcpy\n').encode()
        if shim.exists():
            assert shim.read_bytes() == shim_bytes
        else:
            _exclusive(shim, shim_bytes)
        commands = [
            [*cls.common, *defines, *(f'-D{n}=sfs_test_{n}' for n in replacements),
             '-include', str(shim), '-c', str(cls.source / 'filesystem/image.c'), '-o', str(obj)],
            [*cls.common, *defines, str(cls.source / 'tests/image_driver.c'), str(obj), '-o', str(exe)],
        ]
        for index, command in enumerate(commands):
            result = _owned_command(command, cwd=None, timeout=60, stem=cls.base / f'command-{name}-compile-{index}')
            _exclusive(cls.base / f'{name}-compile-{index}.txt', result.stdout + result.stderr)
            if result.returncode:
                raise AssertionError(f'Image compilation failed; retained {cls.base}\n{result.stderr}')
            if index == 0:
                symbols = _owned_command(['/usr/bin/nm', '-u', str(obj)], cwd=None, timeout=60,
                                         stem=cls.base / f'command-{name}-symbols')
                _exclusive(cls.base / f'{name}-symbols.txt', symbols.stdout + symbols.stderr)
                if symbols.returncode or not {'_sfs_test_memcpy', '_sfs_test_clock_gettime'} <= set(symbols.stdout.split()):
                    _latch_command('symbols', name)
                    raise AssertionError(f'Image copy/clock hook absent; retained {cls.base}')
        cls.executables[name] = exe
        return exe

    @classmethod
    def tearDownClass(cls):
        if cls.failed:
            print(f'Failed image fixtures and receipts retained: {cls.base}', file=sys.stderr)
        else:
            shutil.rmtree(cls.base)

    def scenario(self, name, executable='normal', *, argument=None, timeout=90):
        receipt = self.base / f'{executable}-{name}.json'
        try:
            result = _owned_command([str(self.executables[executable]), name if argument is None else str(argument)], cwd=self.base,
                                    timeout=timeout, stem=self.base / f'command-{executable}-{name}')
            _exclusive(receipt, json.dumps({'scenario': name, 'returncode': result.returncode,
                                          'stdout': result.stdout, 'stderr': result.stderr}, indent=2))
            self.assertEqual(result.returncode, 0, f'{name}: {result.stderr}\n{result.stdout}\nRetained: {self.base}')
            self.assertIn(f'PASS {name}', result.stdout)
            print(result.stdout, end='', flush=True)
        except subprocess.TimeoutExpired as error:
            type(self).failed = True
            _latch_command('timeout', name)
            try:
                details = {'scenario': name, 'returncode': None, 'timeout': True,
                           'passed': False, 'timeout_seconds': error.timeout}
                for stream in ('stdout', 'stderr'):
                    value = getattr(error, stream)
                    raw = value if isinstance(value, bytes) else (value or '').encode()
                    path = receipt.with_suffix(f'.{stream}.bin')
                    _exclusive(path, raw)
                    details[stream] = raw.decode(errors='backslashreplace')
                    details[f'{stream}_path'] = str(path)
                    print(f'{name} {stream} before timeout:\n{details[stream]}', file=sys.stderr, flush=True)
                _exclusive(receipt, json.dumps(details, indent=2))
                print(f'Image timeout evidence retained: {receipt}', file=sys.stderr, flush=True)
            except BaseException as capture_error:
                if hasattr(error, 'add_note'):
                    error.add_note(f'Scenario timeout capture also failed: {capture_error!r}')
                try:
                    print(f'Scenario timeout capture also failed: {capture_error!r}', file=sys.stderr)
                except BaseException:
                    pass
            raise
        except BaseException as error:
            type(self).failed = True
            _latch_command('scenario', repr(error))
            raise

    def test_create_reopen_atomic_snapshot_ranges_and_iteration(self):
        self.scenario('basic')

    def test_live_inode_pins_detached_batches_replacement_and_faults(self):
        """Included by normal test_image unittest discovery; owns a fresh fixture."""
        try:
            executable = self.base / 'live-pins'
            command = [*self.common, str(self.source / 'tests/image_live_pins.c'),
                       str(self.source / 'tests/fskit_write_hooks.c'), '-o', str(executable)]
            result = _owned_command(command, cwd=None, timeout=60,
                                    stem=self.base / 'command-live-pins-compile')
            _exclusive(self.base / 'live-pins-compile.txt', result.stdout + result.stderr)
            self.assertEqual(result.returncode, 0,
                             f'Live pin compilation failed; retained {self.base}\n{result.stderr}')
            self.executables['live-pins'] = executable
            self.scenario('live-pins', 'live-pins', argument=self.base / 'live-pins-fixture', timeout=180)
        except BaseException as error:
            type(self).failed = True
            _latch_command('live-pins', repr(error))
            raise

    def test_creation_locks_fences_identity_and_retained_failures(self):
        self.scenario('creation')

    def test_exact_io_errors_poisoning_and_no_implicit_recovery(self):
        self.scenario('io')

    def test_process_cuts_and_separate_discard_unflushed_write_model(self):
        self.scenario('cuts')

    def test_review_newer_anchor_slot_errno_and_io_poisoning(self):
        self.scenario('review')

    def test_security_inode_counter_floors_and_per_pass_payload_verification(self):
        self.scenario('security')

    def test_parser_checksums_slot_pairs_and_read_only_recovery(self):
        self.scenario('parser')

    def test_admission_file_entry_snapshot_name_and_generation_limits(self):
        try:
            self.compile('limits', '-DSFS_FILE_MAX=UINT64_C(4194304)', '-DSFS_ENTRY_MAX=1024u')
            self.scenario('limits', 'limits')
        except BaseException:
            type(self).failed = True
            raise

    def test_recursive_indexes_split_borrow_merge_and_cookie_context(self):
        self.scenario('indexes')

    def test_streamed_partial_ranges_forced_seal_truncate_and_regrow(self):
        self.scenario('ranges')

    def test_full_budgets_cancellation_auxiliary_errors_and_cleanup(self):
        self.scenario('budgets')

    def test_exact_capacity_pre_seal_discard_and_abandoned_tail(self):
        self.scenario('capacity')

    def test_memory_only_cache_release_refill_authority_and_transactions(self):
        self.scenario('cache')

    def test_commit_cache_storage_reuse_invalidation_growth_and_integrity(self):
        self.scenario('cache-commit')

    def test_ordinary_readonly_admission_policy_poison_and_budgets(self):
        self.scenario('readonly')

    def test_stateless_resume_context_output_atomicity_and_bounded_seek(self):
        self.scenario('resume')

    def test_metadata_legacy_compatibility_times_parents_views_and_allocation(self):
        self.scenario('metadata')

    def test_metadata_codec_semantics_shared_counts_versions_and_eviction(self):
        self.scenario('metadata-codec')

    def test_metadata_atomic_admission_clock_failures_and_bounded_getter(self):
        self.scenario('metadata-atomic')

    def test_selected_information_constant_work_and_committed_receipt(self):
        self.scenario('metadata-information')

    def test_existing_file_diagnostic_receipts_and_transaction_failures(self):
        try:
            self.compile('diagnostic', '-DSFS_IMAGE_DIAGNOSTIC_TESTING=1')
            self.scenario('diagnostic-receipts', 'diagnostic')
        except BaseException:
            type(self).failed = True
            raise

    def test_symlink_explicit_versions_and_legacy_capability(self):
        self.scenario('symlink-versions')

    def test_symlink_opaque_bytes_canaries_and_independent_target_bound(self):
        try:
            self.compile('symlink-limits', '-DSFS_FILE_MAX=UINT64_C(64)')
            self.scenario('symlink-bytes', 'symlink-limits')
        except BaseException:
            type(self).failed = True
            raise

    def test_symlink_namespace_no_follow_and_canonical_resume(self):
        self.scenario('symlink-namespace')

    def test_symlink_metadata_committed_views_abort_and_recovery(self):
        self.scenario('symlink-views')

    def test_symlink_complete_reservation_faults_and_output_atomicity(self):
        self.scenario('symlink-failures')

    def test_symlink_full_semantics_shared_raw_budgets_and_eviction(self):
        self.scenario('symlink-verify')

    def test_xattr_versions_legacy_refusal_and_explicit_codec(self):
        self.scenario('xattr-versions')

    def test_xattr_exact_binary_values_names_ranges_and_enumeration(self):
        self.scenario('xattr-values')

    def test_xattr_namespace_metadata_no_follow_and_large_owner_prefix(self):
        self.scenario('xattr-namespace')

    def test_xattr_committed_snapshots_readonly_recovery_and_digest_binding(self):
        self.scenario('xattr-views')

    def test_xattr_atomic_capacity_faults_zero_seal_and_checked_prefix(self):
        try:
            self.compile('limits', '-DSFS_FILE_MAX=UINT64_C(4194304)', '-DSFS_ENTRY_MAX=1024u')
            self.scenario('xattr-failures', 'limits')
        except BaseException:
            type(self).failed = True
            raise

    def test_xattr_full_semantics_dense_contexts_budgets_and_target_memo(self):
        self.scenario('xattr-verify')

    def test_hardlink_versions_legacy_refusal_and_explicit_codec(self):
        self.scenario('hardlink-versions')

    def test_hardlink_shared_regular_symlink_identity_and_historical_views(self):
        self.scenario('hardlink-shared')

    def test_hardlink_representative_transitions_reverse_split_merge_and_counts(self):
        self.scenario('hardlink-transitions')

    def test_hardlink_exact_names_errors_cookie_binding_and_readonly_policy(self):
        self.scenario('hardlink-names')

    def test_hardlink_whole_reservation_faults_pending_batch_and_name_limit(self):
        try:
            self.compile('limits', '-DSFS_FILE_MAX=UINT64_C(4194304)', '-DSFS_ENTRY_MAX=1024u')
            self.scenario('hardlink-failures', 'limits')
        except BaseException:
            type(self).failed = True
            raise

    def test_hardlink_full_reverse_owner_global_semantics_and_budgets(self):
        self.scenario('hardlink-verify')


class ImageDiagnostics(unittest.TestCase):
    def test_reaped_child_failure_never_signals_numeric_group(self):
        for label, returncode in (('eperm', 0), ('live-group', 0), ('exit', 7)):
            with self.subTest(command=label), tempfile.TemporaryDirectory(prefix='stallionfs-image-reaped-') as temporary:
                state = {'failure': None, 'active': None, 'first_signal': None, 'signal_count': 0}
                stem = Path(temporary) / label
                output, error_output = b'complete output\n', b'complete error\n'
                denied = PermissionError(1, 'synthetic group probe denied')
                fake = mock.Mock(pid=987654, returncode=None)
                foreign_group_signals = []

                def launch(argv, **kwargs):
                    self.assertEqual(argv, ['owned', label])
                    self.assertIs(kwargs['start_new_session'], True)
                    for name, raw in (('stdout', output), ('stderr', error_output)):
                        reader, writer = os.pipe()
                        try:
                            os.write(writer, raw)
                        finally:
                            os.close(writer)
                        setattr(fake, name, os.fdopen(reader, 'rb', buffering=0))
                    return fake

                def poll():
                    self.assertTrue(fake.stdout.closed and fake.stderr.closed)
                    fake.returncode = returncode
                    return returncode

                def group(pgid, number):
                    self.assertEqual(pgid, fake.pid)
                    if number:
                        # A reused, signalable group would accept this destructive call.
                        foreign_group_signals.append(number)
                        return
                    if label == 'eperm':
                        raise denied
                    if label == 'exit':
                        raise ProcessLookupError()

                fake.poll.side_effect = poll
                with mock.patch(__name__ + '._command_state', state), \
                        mock.patch.object(subprocess, 'Popen', side_effect=launch) as popen, \
                        mock.patch.object(os, 'killpg', side_effect=group) as killpg:
                    if label == 'exit':
                        result = _owned_command(['owned', label], cwd=temporary, timeout=10, stem=stem)
                        self.assertEqual(result.returncode, returncode)
                        self.assertEqual((result.stdout, result.stderr), (output.decode(), error_output.decode()))
                    else:
                        with self.assertRaises(PermissionError if label == 'eperm' else RuntimeError) as caught:
                            _owned_command(['owned', label], cwd=temporary, timeout=10, stem=stem)
                        if label == 'eperm':
                            self.assertIs(caught.exception, denied)
                        else:
                            self.assertEqual(str(caught.exception), 'Image command left an owned process group alive')
                    self.assertEqual(killpg.call_args_list, [mock.call(fake.pid, 0)])
                    self.assertEqual(foreign_group_signals, [])
                    fake.wait.assert_not_called()
                    receipt = json.loads(Path(str(stem) + '.command.json').read_text())
                    self.assertEqual(receipt['returncode'], returncode)
                    self.assertEqual(receipt['kill_attempts'], 0)
                    self.assertEqual(receipt['group_signal_skipped_reason'], 'leader_already_reaped')
                    self.assertEqual(receipt['group_ownership_after_cleanup'], 'unknown_after_reap')
                    self.assertIsNone(receipt['group_alive_after_cleanup'])
                    self.assertTrue(receipt['cleanup_uncertain'])
                    self.assertEqual(receipt['first_failure']['kind'], 'exit' if label == 'exit' else 'command_error')
                    if label == 'eperm':
                        self.assertEqual(receipt['primary_exception'], repr(denied))
                        self.assertEqual(receipt['first_failure']['detail'], repr(denied))
                    for name, raw in (('stdout', output), ('stderr', error_output)):
                        self.assertEqual(Path(receipt[name + '_path']).read_bytes(), raw)
                        self.assertEqual(receipt[name + '_retained_bytes'], len(raw))
                    self.assertIsNone(state['active'])
                    next_stem = Path(temporary) / 'refused-next'
                    with self.assertRaises(RuntimeError):
                        _owned_command(['never'], cwd=temporary, timeout=10, stem=next_stem)
                    self.assertEqual(popen.call_count, 1)
                    self.assertFalse(list(Path(temporary).glob('refused-next*')))

    def test_timeout_preserves_partial_output_and_reraises(self):
        # Local pipes carry exact bytes; Popen, clocks and group signals are all synthetic.
        profiles = [('compile-0', 'deadline'), ('compile-1', 'existing-timeout'),
                    ('symbols', 'deadline'), ('scenario', 'deadline'), ('cap', 'cap'),
                    ('exit', 'exit'), ('cancel', 'cancel'), ('cleanup', 'cleanup'),
                    ('reap', 'reap'), ('launch', 'launch'),
                    ('short-write', 'short-write'), ('zero-write', 'zero-write'),
                    ('none-write', 'none-write')]
        for label, profile in profiles:
            with self.subTest(command=label), tempfile.TemporaryDirectory(prefix='stallionfs-image-owned-diagnostic-') as temporary:
                state = {'failure': None, 'active': None, 'first_signal': None, 'signal_count': 0}
                stem = Path(temporary) / label
                write_profile = profile in ('short-write', 'zero-write', 'none-write')
                output = b'prefix' if write_profile else b'partial output\n' if profile == 'exit' else b'partial \xff output\n'
                error_output = b'err' if write_profile else b'partial error\n'
                cleanup_output = b'cleanup!'
                sink_wrapped = [False]
                sink_written = [False]
                checked_prefix = [False]
                original_fdopen = os.fdopen
                tick = [0.0]
                killed = [False]
                requested = [False]
                writers = []
                registered = {}
                cleanup_deadlines = []
                existing = subprocess.TimeoutExpired(['owned', label], 1)
                fake = mock.Mock(pid=987654, returncode=None)
                real_selector = selectors.DefaultSelector()
                original_select = real_selector.select

                def now():
                    tick[0] += 0.25
                    return tick[0]

                def launch(argv, **kwargs):
                    self.assertEqual(argv, ['owned', label])
                    self.assertIs(kwargs['start_new_session'], True)
                    self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
                    if profile == 'launch':
                        raise OSError('synthetic launch failure')
                    for name, raw in (('stdout', output), ('stderr', error_output)):
                        reader, writer = os.pipe()
                        os.write(writer, raw)
                        setattr(fake, name, os.fdopen(reader, 'rb', buffering=0))
                        if profile == 'cleanup' or (write_profile and name == 'stdout'):
                            writers.append(writer)
                        else:
                            os.close(writer)
                    return fake

                def capture_open(fd, mode, *args, **kwargs):
                    stream = original_fdopen(fd, mode, *args, **kwargs)
                    if write_profile and mode == 'wb' and kwargs.get('buffering') == 0 and not sink_wrapped[0]:
                        sink_wrapped[0] = True
                        wrapped = mock.Mock(wraps=stream)

                        def write(data):
                            if not sink_written[0]:
                                sink_written[0] = True
                                self.assertEqual(data, output)
                                count = 3 if profile == 'short-write' else 0
                                if count:
                                    self.assertEqual(stream.write(data[:count]), count)
                                return None if profile == 'none-write' else count
                            return stream.write(data)

                        wrapped.write.side_effect = write
                        return wrapped
                    return stream

                def poll():
                    if profile == 'cancel' and not requested[0]:
                        requested[0] = True
                        registered[signal.SIGTERM](signal.SIGTERM, None)
                    if profile == 'reap':
                        return None
                    if profile == 'exit':
                        fake.returncode = 7
                    elif killed[0]:
                        fake.returncode = -signal.SIGKILL
                    return fake.returncode

                def group(pgid, number):
                    self.assertEqual(pgid, fake.pid)
                    if number == 0:
                        if profile == 'reap':
                            return
                        raise ProcessLookupError()
                    self.assertEqual(number, signal.SIGKILL)
                    killed[0] = True
                    self.assertEqual(state['active']['phase'], 'cleaning')
                    cleanup_deadlines.append((state['active']['drain_deadline'], state['active']['reap_deadline']))
                    if write_profile:
                        active = state['active']
                        count = 3 if profile == 'short-write' else 0
                        self.assertEqual(active['stdout_retained_bytes'], count)
                        self.assertEqual(active['stdout_discarded_bytes'], len(output) - count)
                        self.assertEqual(Path(active['stdout_path']).read_bytes(), output[:count])
                        checked_prefix[0] = True
                        writer = writers.pop()
                        self.assertEqual(os.write(writer, cleanup_output), len(cleanup_output))
                        os.close(writer)
                    if profile == 'cancel':
                        registered[signal.SIGHUP](signal.SIGHUP, None)
                        registered[signal.SIGINT](signal.SIGINT, None)
                        self.assertEqual(cleanup_deadlines[-1], (state['active']['drain_deadline'], state['active']['reap_deadline']))

                def select(timeout):
                    active = state['active']
                    if profile == 'cleanup' and active['phase'] == 'cleaning':
                        raise OSError('synthetic cleanup capture failure')
                    if profile == 'existing-timeout' and active['phase'] != 'cleaning' and active['stdout_retained_bytes'] and active['stderr_retained_bytes']:
                        raise existing
                    return original_select(timeout)

                def install(number, handler):
                    registered[number] = handler
                    return signal.SIG_DFL

                fake.poll.side_effect = poll
                fake.wait.side_effect = subprocess.TimeoutExpired(['owned', label], 2)
                cap = 8 if profile == 'cap' or write_profile else _COMMAND_STREAM_CAP
                try:
                    with mock.patch(__name__ + '._command_state', state), \
                            mock.patch(__name__ + '._COMMAND_STREAM_CAP', cap), \
                            mock.patch.object(subprocess, 'Popen', side_effect=launch) as popen, \
                            mock.patch.object(selectors, 'DefaultSelector', return_value=real_selector), \
                            mock.patch.object(real_selector, 'select', side_effect=select), \
                            mock.patch.object(time, 'monotonic', side_effect=now), \
                            mock.patch.object(os, 'killpg', side_effect=group) as killpg, \
                            mock.patch.object(os, 'fdopen', side_effect=capture_open), \
                            mock.patch.object(signal, 'signal', side_effect=install):
                        previous = _install_command_handlers()
                        self.assertEqual(set(previous), {signal.SIGTERM, signal.SIGHUP, signal.SIGINT})
                        if profile == 'exit':
                            result = _owned_command(['owned', label], cwd=temporary, timeout=1, stem=stem)
                            self.assertEqual(result.returncode, 7)
                        else:
                            with self.assertRaises((subprocess.TimeoutExpired, RuntimeError, OSError)) as caught:
                                _owned_command(['owned', label], cwd=temporary, timeout=1, stem=stem)
                            if profile == 'existing-timeout':
                                self.assertIs(caught.exception, existing)
                            if write_profile:
                                self.assertIsInstance(caught.exception, OSError)
                                self.assertEqual(str(caught.exception), 'Image command capture short write')
                            if isinstance(caught.exception, subprocess.TimeoutExpired):
                                self.assertEqual(caught.exception.output, output)
                                self.assertEqual(caught.exception.stderr, error_output)
                        self.assertEqual(popen.call_count, 1)
                        self.assertIsNone(state['active'])
                        self.assertIsNotNone(state['failure'])
                        next_stem = Path(temporary) / 'refused-next'
                        with self.assertRaises(RuntimeError):
                            _owned_command(['never'], cwd=temporary, timeout=1, stem=next_stem)
                        self.assertEqual(popen.call_count, 1)
                        self.assertFalse(list(Path(temporary).glob('refused-next*')))
                        receipt = json.loads(Path(str(stem) + '.command.json').read_text())
                        expected_output = b'' if profile == 'launch' else output[:cap]
                        if write_profile:
                            prefix = output[:3] if profile == 'short-write' else b''
                            expected_output = prefix + cleanup_output[:cap - len(prefix)]
                        self.assertEqual(Path(receipt['stdout_path']).read_bytes(), expected_output)
                        self.assertEqual(Path(receipt['stderr_path']).read_bytes(), b'' if profile == 'launch' else error_output[:cap])
                        self.assertEqual(receipt['first_failure'], state['failure'])
                        if write_profile:
                            self.assertTrue(sink_written[0] and checked_prefix[0])
                            self.assertEqual(receipt['first_failure']['kind'], 'command_error')
                            self.assertIn('Image command capture short write', receipt['primary_exception'])
                            self.assertFalse(receipt['timeout'] or receipt['cleanup_uncertain'])
                            self.assertIn('stdout', receipt['cap_reached'])
                            for name, supplied in (('stdout', len(output) + len(cleanup_output)), ('stderr', len(error_output))):
                                actual = len(Path(receipt[name + '_path']).read_bytes())
                                self.assertEqual(receipt[name + '_retained_bytes'], actual)
                                self.assertLessEqual(actual, cap)
                                self.assertEqual(receipt[name + '_discarded_bytes'], supplied - actual)
                        if profile == 'launch':
                            self.assertEqual(receipt['kill_attempts'], 0)
                            self.assertEqual(killpg.call_count, 0)
                        else:
                            self.assertEqual(receipt['pid'], fake.pid)
                            self.assertEqual(receipt['pgid'], fake.pid)
                            self.assertEqual(receipt['kill_attempts'], 0 if profile == 'exit' else 1)
                        if profile == 'cancel':
                            self.assertEqual(receipt['first_signal'], signal.SIGTERM)
                            self.assertEqual(receipt['signal_count'], 3)
                            self.assertEqual(receipt['first_failure']['kind'], 'cancelled')
                            self.assertEqual(len(cleanup_deadlines), 1)
                            self.assertFalse(receipt['timeout'])
                        if profile == 'cap':
                            self.assertIn('stdout', receipt['cap_reached'])
                            self.assertEqual(receipt['first_failure']['kind'], 'capture_limit')
                            self.assertFalse(receipt['timeout'])
                        if profile in ('cleanup', 'reap'):
                            self.assertTrue(receipt['cleanup_uncertain'])
                            self.assertTrue(receipt['cleanup_errors'])
                            self.assertEqual(receipt['first_failure']['kind'], 'timeout')
                        if profile == 'reap':
                            self.assertLessEqual(fake.wait.call_args.kwargs['timeout'], 2)
                        _restore_command_handlers(previous)
                finally:
                    real_selector.close()
                    for writer in writers:
                        os.close(writer)
        # An installed handler keeps its state even while diagnostics replace the global.
        qualification_state = _command_state
        for first_failure in (None, {'kind': 'timeout', 'detail': 'earlier failure'}):
            live = {'failure': first_failure, 'active': None, 'first_signal': None, 'signal_count': 0}
            synthetic = {'failure': None, 'active': None, 'first_signal': None, 'signal_count': 0}
            registered = {}

            def install(number, handler):
                registered[number] = handler
                return signal.SIG_DFL

            with mock.patch(__name__ + '._command_state', live), \
                    mock.patch.object(signal, 'signal', side_effect=install):
                previous = _install_command_handlers()
                installed = registered[signal.SIGTERM]
                with mock.patch(__name__ + '._command_state', synthetic):
                    self.assertIsNone(synthetic['failure'])
                    installed(signal.SIGTERM, None)
                    installed(signal.SIGHUP, None)
                self.assertEqual(live['first_signal'], signal.SIGTERM)
                self.assertEqual(live['signal_count'], 2)
                self.assertIsNone(synthetic['failure'])
                self.assertEqual(synthetic['signal_count'], 0)
                if first_failure is None:
                    self.assertEqual(live['failure']['kind'], 'cancelled')
                else:
                    self.assertIs(live['failure'], first_failure)
                _restore_command_handlers(previous)
            self.assertIs(_command_state, qualification_state)
        # A signal before admission creates neither a child nor new capture files.
        with tempfile.TemporaryDirectory(prefix='stallionfs-image-prelaunch-diagnostic-') as temporary:
            state = {'failure': None, 'active': None, 'first_signal': None, 'signal_count': 0}
            with mock.patch(__name__ + '._command_state', state), mock.patch.object(subprocess, 'Popen') as popen:
                _cancel_command(signal.SIGTERM, None, state=state)
                with self.assertRaises(RuntimeError):
                    _owned_command(['never'], cwd=temporary, timeout=1, stem=Path(temporary) / 'refused')
                popen.assert_not_called()
                self.assertEqual(list(Path(temporary).iterdir()), [])
        with tempfile.TemporaryDirectory(prefix='stallionfs-image-diagnostics-') as temporary:
            case = ImageCore('test_admission_file_entry_snapshot_name_and_generation_limits')
            case.base = Path(temporary)
            case.executables = {'normal': case.base / 'not-executed'}
            output = b'{"cap_phase":"entries","state":"before"}\n\xff'
            error = subprocess.TimeoutExpired(['normal', 'limits'], 90, output=output, stderr='partial error\n')
            diagnostic = io.StringIO()
            with mock.patch.object(ImageCore, 'failed', False, create=True), \
                    mock.patch(__name__ + '._command_state', {'failure': None, 'active': None, 'first_signal': None, 'signal_count': 0}), \
                    mock.patch(__name__ + '._owned_command', side_effect=error), redirect_stderr(diagnostic):
                with self.assertRaises(subprocess.TimeoutExpired) as caught:
                    case.scenario('limits')
                self.assertIs(caught.exception, error)
                self.assertTrue(ImageCore.failed)
            receipt = json.loads((case.base / 'normal-limits.json').read_text())
            self.assertTrue(receipt['timeout'])
            self.assertFalse(receipt['passed'])
            self.assertIsNone(receipt['returncode'])
            self.assertEqual(receipt['timeout_seconds'], 90)
            self.assertEqual(Path(receipt['stdout_path']).read_bytes(), output)
            self.assertEqual(Path(receipt['stderr_path']).read_bytes(), b'partial error\n')
            self.assertIn('cap_phase', diagnostic.getvalue())
            self.assertNotIn('PASS limits', diagnostic.getvalue())
