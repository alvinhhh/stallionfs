"""Current activation producer/history and bounded mount diagnostics."""
import copy
import fcntl
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from stallionfs import _native_activation as activation, _native, core


class ActivationIntent(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sfs-activation-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / ('1' * 32)
        self.root.mkdir(mode=0o700)
        self.operation_id = '2' * 32
        self.directory = self.root / 'native-operations' / self.operation_id
        self.directory.mkdir(mode=0o700, parents=True)
        self.directory.parent.chmod(0o700)
        image = self.root / 'image.sfs'; image.write_bytes(b'inert backing'); image.chmod(0o600)
        pair = lambda p: [p.stat().st_dev, p.stat().st_ino]
        self.target = dict(directory=str(self.root), component='image.sfs', parent=pair(self.root), file=pair(image), uuid='3'*32)
        self.metadata = dict(id=self.root.name, transaction='4'*32)
        self.guard = dict(status=0, core_consumed=True, parent_close_errno=0, poisoned=False,
                          transaction_active=False, device=self.target['file'][0], inode=self.target['file'][1],
                          uuid=self.target['uuid'], generation=2, root_digest='5'*64, committed_end=16384, physical_end=16384)
        self.record = dict(id=self.operation_id, operation='native-mount', workspace=self.root.name, target=self.target)
        self.operation = SimpleNamespace(path=self.root, record=self.record)

    def test_real_producer_record_exact_command_and_history_bindings(self):
        self.record['activation_protocol'] = 1
        with activation.pending(self.operation, self.metadata, self.guard) as value:
            path = self.directory / ('activation-'+value['nonce'])
            self.assertEqual((path/'request').read_bytes(), activation.encode(value))
            lease = os.open(path/'lease', os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError): fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally: os.close(lease)
            helper = dict(activation_version=1, activation=value, argv=activation.argv(value,'stallionfs',self.root))
            activation.validate_helper(self.record,helper,'stallionfs',self.root,self.metadata['transaction'],self.guard)
            for field in ('transaction','generation','root_digest','committed_end','physical_end','operation','workspace','nonce','uuid','version'):
                with self.subTest(field=field):
                    changed = copy.deepcopy(helper)
                    old = changed['activation'][field]
                    changed['activation'][field] = old+1 if type(old) is int else 'f'*len(old)
                    with self.assertRaises(core.StallionError):
                        activation.validate_helper(self.record,changed,'stallionfs',self.root,self.metadata['transaction'],self.guard)
            for value_bad in (None, [], {}, {'version':True}):
                with self.subTest(malformed=value_bad):
                    changed = dict(helper,activation=value_bad)
                    with self.assertRaises(core.StallionError):
                        activation.validate_helper(self.record,changed,'stallionfs',self.root,self.metadata['transaction'],self.guard)
        lease = os.open(path/'lease',os.O_RDONLY)
        try: fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally: os.close(lease)
        self.assertEqual((path/'request').read_bytes(),activation.encode(value))

    def test_exact_historical_commands_and_no_arbitrary_extras(self):
        old=['/sbin/mount','-t','stallionfs',str(self.root),str(self.root/'volume')]
        for args in (old,old[:1]+['-F']+old[1:]):
            activation.validate_helper(self.record,{'argv':args},'stallionfs',self.root,None,None)
            for bad in (args+['-w'],args+['-o','rw'],args+['--rdonly']):
                with self.assertRaises(core.StallionError):
                    activation.validate_helper(self.record,{'argv':bad},'stallionfs',self.root,None,None)

    def test_versioned_attempt_cannot_downgrade_or_borrow_another_attempt(self):
        old = ['/sbin/mount', '-F', '-t', 'stallionfs', str(self.root), str(self.root/'volume')]
        def validate(helper, attempt):
            activation.validate_helper(self.record, helper, 'stallionfs', self.root,
                                       self.metadata['transaction'], self.guard, attempt=attempt)
        for evidence in ({'activation': None}, {'activation_version': None},
                         {'activation': None, 'activation_version': None}, {'activation_version': 1}):
            with self.subTest(null_or_partial=evidence), self.assertRaises(core.StallionError):
                validate(dict(argv=old, **evidence), {})
        with activation.pending(self.operation, self.metadata, self.guard) as value:
            helper = dict(activation=value, activation_version=1,
                          argv=activation.argv(value, 'stallionfs', self.root))
            historical, current = {}, {'activation_protocol': 1}
            # Mixed history keeps each attempt's contract; no journal rewriting.
            validate({'argv': old}, historical)
            validate(helper, current)
            for bad in ({'argv': old}, dict(argv=old, activation=None, activation_version=None)):
                with self.subTest(downgrade=bad), self.assertRaises(core.StallionError):
                    validate(bad, current)
            with self.assertRaises(core.StallionError): validate(helper, historical)
            for version in (None, True, 0, 2, '1'):
                with self.subTest(version=version), self.assertRaises(core.StallionError):
                    validate(helper, {'activation_protocol': version})

    def test_mount_failure_retains_original_and_later_rows_without_aliases(self):
        volume=self.root/'volume'
        def row(flags):
            return dict(path=str(volume),filesystem='stallionfs',owner=501,flags=flags,fsid=[7,-9],
                        readonly=True,ignore_ownership=True,source='unrelated private source')
        original=row(17); later=row(19)
        error=_native.failure('original conflict',{'mount_row':original})
        operation=SimpleNamespace(record={'operation':'native-mount'},persist=lambda:None)
        with patch.object(_native,'observe',side_effect=_native.failure('later conflict',{'mount_row':later})):
            _native._record_failure(error,operation,volume,'production')
        kept=operation.record['original_mount_failure']['mount_row']
        self.assertEqual(kept['flags'],17); self.assertEqual(kept['owner'],501); self.assertEqual(kept['fsid'],[7,-9])
        self.assertEqual(operation.record['later_mount_failure']['mount_row']['flags'],19)
        self.assertNotIn('source',kept)
        original['fsid'][0]=99; self.assertEqual(kept['fsid'],[7,-9])
        with patch.object(_native,'observe',return_value=None):
            _native._record_failure(error,operation,volume,'production')
        self.assertEqual(kept['flags'],17)
        self.assertIs(error.native_candidate_result,operation.record)
        self.assertNotIn('original_mount_failure',kept)


class ActivationAdapter(unittest.TestCase):
    """Real Python producer, native pending handle and actual activation callback."""
    def test_producer_consumer_and_terminal_callback_drain(self):
        import hashlib
        import json
        import uuid
        import time
        from concurrent.futures import ThreadPoolExecutor
        from native_activation_runner import run, owned_directory
        executable = os.environ.get('STALLIONFS_ACTIVATION_DRIVER')
        if not executable:
            self.skipTest('requires compiled offline activation driver')
        with owned_directory() as temporary:
            base = Path(temporary).resolve()
            run([executable, 'options', base], base)
            for mode in ('success', 'fail-after-promotion', 'fail-result', 'fail-result-cleanup', 'revoke-after-promotion', 'revoke-after-result', 'no-scope', 'revoked', 'stale',
                         'malformed', 'wrong-anchor', 'wrong-transaction-shape', 'replay', 'denied-rw', 'revoke-after-claim',
                         'cancel-before-transfer', 'close-after-transfer'):
                with self.subTest(mode=mode):
                    root = base / uuid.uuid4().hex; root.mkdir(mode=0o700)
                    anchor = json.loads(run([executable, 'prepare', root], base))
                    image = root/'image.sfs'
                    (root/'unrelated').mkdir(mode=0o700)
                    (root/'unrelated'/'sentinel').write_bytes(b'owned unrelated fixture bytes')
                    def fullmap():
                        return {str(p.relative_to(root)): (p.stat().st_mode & 0o777, hashlib.sha256(p.read_bytes()).hexdigest())
                                for p in root.rglob('*') if p.is_file()}
                    target = dict(directory=str(root), component='image.sfs', parent=[root.stat().st_dev, root.stat().st_ino],
                                  file=[image.stat().st_dev, image.stat().st_ino], uuid=anchor['uuid'])
                    guard = _native.guarded(target)
                    self.assertTrue(_native._consumed(guard, target))
                    metadata = dict(id=root.name, transaction=uuid.uuid4().hex)
                    operation_id = uuid.uuid4().hex
                    directory = root/'native-operations'/operation_id
                    directory.mkdir(mode=0o700, parents=True); directory.parent.chmod(0o700)
                    record = dict(id=operation_id, operation='native-mount', workspace=root.name,
                                  target=target, activation_protocol=1)
                    operation = SimpleNamespace(path=root, record=record)
                    before = hashlib.sha256(image.read_bytes()).hexdigest()
                    def command(label, arguments):
                        self.assertEqual(label, 'mount')
                        helper = dict(operation.command_context, argv=arguments)
                        activation.validate_helper(record, helper, 'stallionfs', root, metadata['transaction'], guard)
                        value = helper['activation']; attempt = directory/('activation-'+value['nonce'])
                        request = attempt/'request'
                        if mode == 'malformed': request.write_bytes(request.read_bytes()+b'extra\n')
                        if mode in ('wrong-anchor', 'wrong-transaction-shape'):
                            fields = request.read_text().splitlines()
                            fields[11 if mode == 'wrong-anchor' else 3] = '999' if mode == 'wrong-anchor' else 'invalid'
                            request.write_text('\n'.join(fields)+'\n')
                        if mode == 'replay':
                            (attempt/'claim').touch(mode=0o600)
                        if mode == 'stale': return dict(returncode=0, arguments=arguments, attempt=attempt)
                        before_map = fullmap()
                        result = run([executable, mode, root, *arguments[4:6]], base)
                        after_map = fullmap()
                        self.assertEqual({k:after_map[k] for k in before_map}, before_map)
                        self.assertLessEqual(set(after_map)-set(before_map), {str((attempt/'claim').relative_to(root))})
                        self.assertEqual(result, 'PASS activation '+mode+'\n')
                        expected_claim = mode in ('success','fail-after-promotion','fail-result','fail-result-cleanup','revoke-after-promotion','revoke-after-result','replay','denied-rw','revoke-after-claim')
                        self.assertEqual((attempt/'claim').exists(), expected_claim)
                        return dict(returncode=0)
                    operation.command = command
                    if mode in ('cancel-before-transfer', 'close-after-transfer'):
                        with ThreadPoolExecutor(max_workers=1) as executor:
                            def race_command(label, arguments):
                                task = executor.submit(run, [executable, mode, root, *arguments[4:6]], base)
                                deadline = time.monotonic()+5
                                while not (root/'transfer-waiting').exists():
                                    self.assertLess(time.monotonic(), deadline, 'consumer transfer boundary')
                                    time.sleep(.001)
                                return task
                            operation.command = race_command
                            task = activation.mount(operation, metadata, 'stallionfs', guard)
                            # The real producer has now closed its lease under
                            # the coordinated gate, with the consumer paused.
                            (root/'transfer-release').touch(mode=0o600)
                            self.assertEqual(task.result(timeout=10), 'PASS activation '+mode+'\n')
                            self.assertEqual(bool(list(directory.glob('activation-*/claim'))), mode == 'close-after-transfer')
                        self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(), before)
                        continue
                    result = activation.mount(operation, metadata, 'stallionfs', guard)
                    if mode == 'stale':
                        self.assertEqual(run([executable, mode, root, *result['arguments'][4:6]], base), 'PASS activation stale\n')
                        self.assertFalse((result['attempt']/'claim').exists())
                    self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(), before)


class ActivationRetention(unittest.TestCase):
    def test_owned_control_records_preserve_strict_purge_manifest(self):
        import test_stallionfs as fixtures
        case = fixtures.Workspaces(); case.setUp(); self.addCleanup(case.doCleanups)
        seed = case.prepare()
        with case.native_controller_fixture(), case.native_wall_clock() as now:
            workspace, root = case.native_purge_fixture(seed, now)
            control = next(root.glob('native-operations/*/activation-*'))
            request = control/'request'; original = request.read_bytes()
            def fullmap():
                return {str(p.relative_to(case.store.root)): p.read_bytes()
                        for p in case.store.root.rglob('*') if p.is_file()}
            for change in ('request', 'extra', 'claim-content'):
                with self.subTest(change=change):
                    extra = control/('claim' if change == 'claim-content' else 'unexpected')
                    if change == 'request': request.write_bytes(original.replace(b'owners', b'noownr'))
                    else: extra.write_bytes(b'unexpected'); extra.chmod(0o600)
                    before = fullmap()
                    with self.assertRaises(core.StallionError): case.store.purge('trash', workspace, yes=True)
                    self.assertEqual(fullmap(), before)
                    if change == 'request': request.write_bytes(original)
                    else: extra.unlink()
            archive = control.parent/'record.json'
            saved = archive.read_bytes()
            for change in ('operation', 'version', 'control-mode', 'control-link'):
                with self.subTest(change=change):
                    if change in ('operation', 'version'):
                        value = json.loads(saved)
                        if change == 'operation': value['helpers'][-1]['activation']['operation'] = '0'*32
                        else: value['activation_protocol'] = None
                        archive.write_text(json.dumps(value))
                    elif change == 'control-mode': request.chmod(0o644)
                    else: os.link(request, case.base/'control-alias')
                    before = fullmap()
                    with self.assertRaises(core.StallionError): case.store.purge('trash', workspace, yes=True)
                    self.assertEqual(fullmap(), before)
                    if change in ('operation', 'version'): archive.write_bytes(saved)
                    elif change == 'control-mode': request.chmod(0o600)
                    else: (case.base/'control-alias').unlink()
            for leaf in ('gate', 'lease'):
                fd = os.open(control/leaf, os.O_RDONLY)
                try:
                    fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    before = fullmap()
                    with self.assertRaisesRegex(core.StallionError, 'activation control is active'):
                        case.store.purge('trash', workspace, yes=True)
                    self.assertEqual(fullmap(), before)
                finally: os.close(fd)
            # An authentic empty consumption claim is eligible metadata, not an
            # authority source. The ordinary closed-image gates still run.
            (control/'claim').touch(mode=0o600)
            record = case.store.purge('trash', workspace, yes=True)['native_operation']
            self.assertTrue(record['data_absent'])
            self.assertFalse(root.exists())
            # A request the adapter never consumed is equally eligible only
            # after the enclosing ordinary closure and purge authority pass.
            workspace, root = case.native_purge_fixture(seed, now)
            self.assertFalse(list(root.glob('native-operations/*/activation-*/claim')))
            record = case.store.purge('trash', workspace, yes=True)['native_operation']
            self.assertTrue(record['data_absent'])
            self.assertFalse(root.exists())
