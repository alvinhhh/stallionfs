"""Controlled test eligibility preserves production architecture and receipt checks."""
import copy
from contextlib import contextmanager
import multiprocessing
import os
import signal
import sys
import unittest
from unittest.mock import patch

from stallionfs import _native_create_authority as authority, _native_create_git as git
from stallionfs import _native_create_request as request, _bundle, core
from qualified_git_fixture import native_creation
from native_writer_fixture import writer

ARM = '9b9401eaea9d2f2b3e88c8c87509b52414b5522016c505718c050cd562725700'
INTEL = '020c08613be10d2d21d46a4defd6c4c98724b0af61426a9a2096e1bee48d546a'
PRODUCTION_CURRENT = authority.current
PRODUCTION_RUNTIME = git.qualified_runtime
ORIGIN = dict(id='a' * 32, transaction='b' * 32, seed='c' * 64, commit='d' * 40,
              name='typed', branch=request.branch_name('typed', 'a' * 32), capacity_gib=1,
              native_image={'parent': [1, 2], 'object': [1, 3]})


def contract(inventory):
    return dict(_bundle.GIT_CONTRACT, input_inventory_sha256=inventory, payload_entries=239,
                payload_sha256='1' * 64, descriptor_sha256='2' * 64,
                executable_sha256='3' * 64, source_build_id='4' * 64,
                publisher=_bundle.PUBLISHER_TEAM)


def spec_for(inventory):
    value = writer(ORIGIN, '/typed/staging/native-create-' + ORIGIN['transaction'])['spec']
    value['runtime'] = contract(inventory)
    return value


class TypedAdmission:
    """Synthetic data only: no path is opened and no Git executable exists."""
    def __init__(self, inventory):
        self.contract = contract(inventory)
        architecture = _bundle.QUALIFIED_GIT_ARCHITECTURES[inventory]
        self.executable = '/typed/' + architecture + '/bin/git'
        self.exec_path = '/typed/' + architecture + '/libexec/git-core'
        self.calls = 0
        self.failure = None

    def runtime(self):
        value = dict(executable=self.executable, exec_path=self.exec_path, contract=copy.deepcopy(self.contract))
        def check():
            self.calls += 1
            if self.failure:
                raise self.failure
            if value['contract'] != self.contract or value['executable'] != self.executable or value['exec_path'] != self.exec_path:
                raise ValueError('Typed runtime changed')
        value['check'] = check
        check()
        return value


class TypedFeasibility(unittest.TestCase):
    def setUp(self):
        self.admission = TypedAdmission(INTEL)
        self.enterContext(patch.dict(sys.modules, ci_git_input=self.admission))
        self.enterContext(patch('qualified_git_fixture.platform.machine', return_value='x86_64'))
        self.actor = self.enterContext(patch('stallionfs._native.execute_owned', side_effect=AssertionError('typed actor effect')))
        self.clone = self.enterContext(patch('stallionfs.core.clone_tree', side_effect=AssertionError('typed clone effect')))
        self.addCleanup(self.assert_restored)

    def assert_restored(self):
        self.assertIs(authority.current, PRODUCTION_CURRENT)
        self.assertIs(git.qualified_runtime, PRODUCTION_RUNTIME)
        self.actor.assert_not_called()
        self.clone.assert_not_called()

    def refuses(self, call):
        with self.assertRaises((ValueError, core.StallionError)):
            call()

    def test_unmodified_production_arm_only_and_invalid_requests(self):
        authority.current(spec_for(ARM))
        self.refuses(lambda: authority.current(spec_for(INTEL)))
        for change in ('unknown', 'source', 'protocol', 'method', 'missing', 'schema', 'publisher'):
            spec = spec_for(ARM)
            if change == 'unknown': spec['runtime']['input_inventory_sha256'] = '0' * 64
            elif change == 'source': spec['runtime']['source_sha256'] = '0' * 64
            elif change == 'protocol': spec['protocol'] = 2
            elif change == 'method': spec['method'] = 'wrong'
            elif change == 'missing': spec.pop('runtime')
            elif change == 'schema': spec['runtime']['schema'] = True
            else: spec['runtime']['publisher'] = 'wrong'
            with self.subTest(change=change): self.refuses(lambda: authority.current(spec))

    def test_intel_exact_contract_inside_and_production_refusal_outside(self):
        spec = spec_for(INTEL)
        self.refuses(lambda: authority.current(spec))
        with native_creation() as value:
            self.assertEqual(value['contract']['input_inventory_sha256'], INTEL)
            self.assertEqual(value['executable'], '/typed/x86_64/bin/git')
            self.assertIs(git.qualified_runtime(), value)
            authority.current(spec)
            self.assertGreater(self.admission.calls, 3)
        self.refuses(lambda: authority.current(spec))

    def test_request_contract_mutations_and_missing_fields_refuse(self):
        with native_creation():
            for field in contract(INTEL):
                spec = spec_for(INTEL)
                value = spec['runtime'][field]
                spec['runtime'][field] = value + 1 if type(value) is int else '0' * 64 if len(value) == 64 else 'wrong'
                with self.subTest(field=field): self.refuses(lambda: authority.current(spec))
            for field in request.FIELDS:
                spec = spec_for(INTEL); spec.pop(field)
                with self.subTest(missing=field): self.refuses(lambda: authority.current(spec))
            for inventory in (ARM, '0' * 64):
                with self.subTest(inventory=inventory): self.refuses(lambda: authority.current(spec_for(inventory)))

    def test_scalar_equality_cannot_substitute_runtime_schema(self):
        for scalar in (True, 1.0):
            with self.subTest(scalar=scalar):
                value = self.admission.runtime()
                with native_creation(value):
                    spec = spec_for(INTEL); spec['runtime']['schema'] = scalar
                    self.refuses(lambda: authority.current(spec))
                    value['contract']['schema'] = scalar
                    self.refuses(git.qualified_runtime)

    def test_runtime_mutation_and_replaced_check_fail_before_getter_effect(self):
        for field in ('contract', 'executable', 'exec_path', 'check'):
            value = self.admission.runtime()
            with self.subTest(field=field), native_creation(value):
                if field == 'contract': value[field]['payload_sha256'] = '5' * 64
                elif field == 'check': value[field] = lambda: None
                else: value[field] += '-changed'
                self.refuses(git.qualified_runtime)
                self.refuses(lambda: authority.current(spec_for(INTEL)))

    def test_equal_numeric_contract_types_refuse_before_entry_and_inside(self):
        for field, original, changed in (('payload_entries', 239, 239.0), ('payload_entries', 1, True),
                                         ('schema', 1, 1.0), ('schema', 1, True)):
            self.admission.contract[field] = original
            for phase in ('before-entry', 'inside-context', 'fresh-admission'):
                with self.subTest(field=field, value=changed, phase=phase):
                    value = self.admission.runtime()
                    try:
                        if phase == 'before-entry':
                            value['contract'][field] = changed
                            self.refuses(lambda: native_creation(value).__enter__())
                        else:
                            with native_creation(value):
                                if phase == 'inside-context': value['contract'][field] = changed
                                else: self.admission.contract[field] = changed
                                self.refuses(git.qualified_runtime)
                    finally:
                        self.admission.contract[field] = original

    def test_initialized_contract_drift_and_host_mismatch_refuse(self):
        with native_creation():
            self.admission.executable += '-changed'
            self.refuses(git.qualified_runtime)
        self.admission = TypedAdmission(ARM)
        with patch.dict(sys.modules, ci_git_input=self.admission):
            self.refuses(lambda: native_creation().__enter__())
        for machine in ('aarch64', '', 'ARM64'):
            with self.subTest(machine=machine), patch('qualified_git_fixture.platform.machine', return_value=machine):
                self.admission = TypedAdmission(INTEL)
                with patch.dict(sys.modules, ci_git_input=self.admission):
                    self.refuses(lambda: native_creation().__enter__())

    def test_live_check_failure_at_entry_and_inside_preserves_exception(self):
        sentinel = OSError('typed identity failure')
        self.admission.failure = sentinel
        with self.assertRaises(OSError) as caught:
            with native_creation(): self.fail('entered after failed live check')
        self.assertIs(caught.exception, sentinel)
        self.admission.failure = None
        with self.assertRaises(OSError) as caught:
            with native_creation():
                self.admission.failure = sentinel
                git.qualified_runtime()
        self.assertIs(caught.exception, sentinel)

    def test_exception_restores_originals_and_revokes_saved_adapters(self):
        sentinel = RuntimeError('scope exit')
        with self.assertRaises(RuntimeError) as caught:
            with native_creation():
                current, getter = authority.current, git.qualified_runtime
                authority.current(spec_for(INTEL))
                raise sentinel
        self.assertIs(caught.exception, sentinel)
        self.assertIs(authority.current, PRODUCTION_CURRENT)
        self.assertIs(git.qualified_runtime, PRODUCTION_RUNTIME)
        self.refuses(lambda: current(spec_for(INTEL)))
        self.refuses(getter)

    def test_arm_calls_original_production_current_inside_context(self):
        self.admission = TypedAdmission(ARM)
        with patch.dict(sys.modules, ci_git_input=self.admission), \
             patch('qualified_git_fixture.platform.machine', return_value='arm64'), \
             patch.object(authority, 'current', wraps=PRODUCTION_CURRENT) as original:
            with native_creation(): authority.current(spec_for(ARM))
            original.assert_called_once()
        PRODUCTION_CURRENT(spec_for(ARM))

    def test_proof_installed_retained_keep_actor_and_packet_validation(self):
        import tempfile
        from test_native_create_recovery import CreateRecovery
        fixture = CreateRecovery('test_success_repeated_calls_and_guarded_rename_syncs')
        try:
            with patch('native_writer_fixture.qualify', lambda test: None):
                fixture.setUp()
            created = copy.deepcopy(fixture.proof)
            packet = created['writer']; packet['spec']['runtime'] = contract(INTEL)
            packet['spec_digest'] = request.digest(packet['spec'])
            for actor in packet['actors']: actor['runtime'] = contract(INTEL)
            with native_creation():
                authority.proof(fixture.meta, created)
                fixture.save(fixture.owned / 'native-create.json', created)
                authority.installed(fixture.owned, {'origin': fixture.meta})
                authority.retained({'origin': fixture.meta, 'proof': created},
                                   dict(fixture.target, directory=str(fixture.owned), parent=fixture.target['object']), fixture.workspace)
                for key in ('runtime', 'executable', 'argv', 'environment', 'reaped', 'streams_durable'):
                    bad = copy.deepcopy(created)
                    if key == 'runtime': bad['writer']['actors'][0][key]['input_inventory_sha256'] = ARM
                    elif key == 'executable': bad['writer']['actors'][0][key]['sha256'] = '0' * 64
                    elif key == 'argv': bad['writer']['actors'][0][key].append('--unsafe')
                    elif key == 'environment': bad['writer']['actors'][0][key] = 'wrong'
                    else: bad['writer']['actors'][0][key] = False
                    with self.subTest(key=key): self.refuses(lambda: authority.proof(fixture.meta, bad))
        finally: fixture.doCleanups()

    @contextmanager
    def owned_fork(self, action):
        context = multiprocessing.get_context('fork')
        reader, output = context.Pipe(duplex=False)
        process = context.Process(target=action, args=(output,))
        cleanup = {}
        try:
            process.start()
            output.close()
            yield process, reader, cleanup
        finally:
            try:
                try: reader.close()
                finally: output.close()
            finally:
                try:
                    if process.pid is not None:
                        try:
                            if process.is_alive(): process.kill()
                        finally:
                            process.join(5)
                        self.assertFalse(process.is_alive(), 'Owned child did not terminate')
                        cleanup.update(pid=process.pid, exitcode=process.exitcode,
                                       reader_closed=reader.closed, output_closed=output.closed)
                finally:
                    if process.pid is None or not process.is_alive(): process.close()

    def test_owned_fork_inherits_context_and_restores_locally(self):
        with native_creation():
            def child(output):
                try:
                    inherited = authority.current
                    inherited(spec_for(INTEL))
                    try:
                        with native_creation():
                            saved = authority.current
                            saved(spec_for(INTEL))
                            raise RuntimeError('child scope')
                    except RuntimeError: pass
                    assert authority.current is inherited
                    try: saved(spec_for(INTEL))
                    except core.StallionError: pass
                    else: raise AssertionError('child adapter not revoked')
                    output.send_bytes(b'PASS')
                except BaseException as error:
                    output.send_bytes(repr(error).encode()[:1024])
                    raise SystemExit(1)
            with self.owned_fork(child) as (process, reader, cleanup):
                self.assertTrue(reader.poll(5), 'Owned child did not respond')
                observed = reader.recv_bytes(2048)
                process.join(5)
                self.assertFalse(process.is_alive(), 'Owned child did not exit')
                self.assertEqual((process.exitcode, observed), (0, b'PASS'))
            self.assertEqual(cleanup['exitcode'], 0)
            self.assertTrue(cleanup['reader_closed'] and cleanup['output_closed'])
            authority.current(spec_for(INTEL))

    def test_owned_fork_failure_timeout_and_read_error_reap_before_scope_exit(self):
        for failure, error in (('child-exit', EOFError), ('timeout', TimeoutError), ('read-error', OSError)):
            with self.subTest(failure=failure), native_creation():
                read_failure = OSError('controlled pipe read failure')
                def child(output):
                    if failure == 'child-exit': os._exit(7)
                    signal.pause()
                with self.assertRaises(error) as caught:
                    with self.owned_fork(child) as (process, reader, cleanup):
                        if failure == 'child-exit':
                            self.assertTrue(reader.poll(5), 'Owned child did not close its pipe')
                            reader.recv_bytes(2048)
                        elif failure == 'timeout':
                            self.assertFalse(reader.poll(0.05))
                            raise TimeoutError('Owned child did not respond')
                        else:
                            with patch.object(reader, 'recv_bytes', side_effect=read_failure):
                                reader.recv_bytes(2048)
                if failure == 'read-error': self.assertIs(caught.exception, read_failure)
                self.assertEqual(cleanup['exitcode'], 7 if failure == 'child-exit' else -signal.SIGKILL)
                self.assertTrue(cleanup['reader_closed'] and cleanup['output_closed'])
                authority.current(spec_for(INTEL))


if __name__ == '__main__': unittest.main()
