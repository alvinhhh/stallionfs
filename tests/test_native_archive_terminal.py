"""Terminal catalog failures and movement archives retain their original outcomes."""
import contextlib
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch


def load_modules():
    source = Path(__file__).resolve().parents[1] / 'stallionfs'
    package = ModuleType('_native_archive_terminal_' + str(id(source)))
    package.__path__ = [str(source)]
    sys.modules[package.__name__] = package

    def unavailable(*args, **kwargs):
        raise AssertionError('Native helpers are outside this test')

    for name in ('_scan', '_image'):
        module = ModuleType(package.__name__ + '.' + name)
        module.__path__ = []
        module.__getattr__ = unavailable
        for function in (('_private_directory', 'move') if name == '_scan' else ('snapshot', 'restore', 'snapshots')):
            setattr(module, function, unavailable)
        sys.modules[module.__name__] = module
        setattr(package, name, module)

    def load(name):
        qualified = package.__name__ + '.' + name
        if qualified in sys.modules:
            return sys.modules[qualified]
        spec = importlib.util.spec_from_file_location(qualified, source / (name + '.py'))
        module = importlib.util.module_from_spec(spec)
        sys.modules[qualified] = module
        setattr(package, name, module)
        spec.loader.exec_module(module)
        return module

    modules = {key: load(name) for key, name in (
        ('core', 'core'), ('native', '_native'), ('recovery', '_native_recovery'),
        ('interval', '_native_interval'), ('binding', '_native_binding'), ('life', 'lifecycle'))}
    modules.update(scan=package._scan, image=package._image)
    return package.__name__, modules


class SyntheticStore:
    def __init__(self, root, modules):
        for name, module in modules.items():
            setattr(self, name, module)
        self.root=root
        for d in ('workspaces','trash','journals','lifecycle','protected','locks'):(self.root/d).mkdir(mode=0o700)
        self.workspace='1'*32;self.path=self.root/'workspaces'/self.workspace;self.path.mkdir(mode=0o700)
        (self.path/'image.sfs').touch(mode=0o600)
        self.meta={'id':self.workspace,'backend':'native-image','ownership':'store-created','transaction':'2'*32,'controller_profile':'production',
            'native_image':{'parent':self.life.identity(self.path.parent),'object':self.life.identity(self.path),
                'file':self.life.identity(self.path/'image.sfs'),'uuid':'3'*32}}
        self.life.replace_json(self.path/'meta.json',self.meta)
        self.store=self.core.Store.__new__(self.core.Store);self.store.root=self.root
        self.store._payload=lambda p,m:p/'image.sfs'
        self.store._retention=lambda:contextlib.nullcontext()
        self.store.object=lambda c,w:(self.root/c/w,self.core.read_json(self.root/c/w/'meta.json'))
        self.store._no_mounts=lambda p:None
        self.calls=[];self.guard_error=None
        self.state=self.store._open(self.workspace,self.path,self.meta,enrolled=True)
        self.state.update(status='closed',closed_at=1,native_idle={'anchor':self.anchor()})
        self.life.replace_json(self.store._state(self.workspace),self.state)
        self.state=self.core.read_json(self.store._state(self.workspace))
    def anchor(self):return dict(generation=7,committed_end=8192,root_digest='a'*64)
    def target(self,p):return dict(directory=str(p),component='image.sfs',parent=self.life.identity(p),file=self.life.identity(p/'image.sfs'),uuid='3'*32)
    def c_receipt(self, target, *, status=0, phase=15, coverage=0, limit=0):
        return dict(self.anchor(), device=target['file'][0], inode=target['file'][1],
            uuid=target['uuid'], status=status, phase=phase, coverage=coverage, limit_reason=limit,
            physical_end=8192, system_errno=0, incomplete_reason=0, fence_attempted=0,
            fence_succeeded=0, transaction_active=False, poisoned=False)

    def receipt(self, target):
        return dict(self.c_receipt(target), core_consumed=True, parent_close_errno=0)

    def private(self,p):
        p=Path(p);assert p==self.root or p.is_relative_to(self.root)
        info=p.lstat();assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o700 and info.st_uid==os.getuid()
    def location(self,store,p,meta):
        saved=p/'native-location.json'
        if saved.exists():return self.core.read_json(saved)
        return dict(schema=1,workspace=p.name,transaction=meta['transaction'],origin_target=meta['native_image'],
            collection=p.parent.name,parent=self.life.identity(p.parent),object=self.life.identity(p),file=self.life.identity(p/'image.sfs'),
            uuid='3'*32,operation=meta['transaction'],complete=True,guard=self.receipt(self.target(p)))
    def guard(self,t,callback=None,**kwargs):
        self.calls.append({'guard':copy.deepcopy(t),'expected_anchor':kwargs.get('expected_anchor'),'callback':callback is not None})
        receipt=self.receipt(t)
        if self.guard_error:
            error=self.core.StallionError('synthetic anchor race');error.native_anchor_mismatch=True
            if self.guard_error=='bad-close':receipt['parent_close_errno']=errno.EIO
            error.native_current_guard=receipt;raise error
        class Token:
            def verify(token,target):
                assert self.target(Path(target['directory']))==target
        if callback:callback(Token())
        return receipt
    def move(self,a,b):
        assert a.is_relative_to(self.root) and b.is_relative_to(self.root)
        self.calls.append({'rename':[str(a),str(b)]});os.rename(a,b)
    @contextlib.contextmanager
    def seams(self):
        with contextlib.ExitStack() as s:
            for obj,name,value in ((self.core,'private_directory',self.private),(self.core,'lock',lambda *a,**k:contextlib.nullcontext()),
                (self.recovery,'ready',lambda st,p,m:self.target(p)),(self.recovery,'location',self.location),
                (self.native,'guarded',self.guard),(self.scan,'move',self.move)):
                s.enter_context(patch.object(obj,name,value,create=True))
            yield
    def records(self,p=None):
        p=p or self.path
        return {q.parent.name:self.core.read_json(q) for q in sorted((p/'native-operations').glob('*/record.json'))}

    def bridge(self, action, *names):
        target = self.target(self.path)
        opened = self.c_receipt(target, phase=5, coverage=2)
        failed = action != 'snapshots'
        receipt = self.c_receipt(target, status=5, phase=6, limit=3) if failed else self.c_receipt(target, phase=0, coverage=3)
        return dict(ok=not failed, operation=action, error_code=errno.EOVERFLOW if failed else 0,
            committed=False, commit_attempted=False, outcome='not_committed', deadline_expired=False,
            interrupted=False, path_errno=0, guard_close_errno=0, abort_attempted=False,
            close_attempted=True, receipt=receipt, opened_receipt=opened,
            staged_receipt=copy.deepcopy(receipt) if failed else None, abort_receipt=None,
            close_receipt=self.c_receipt(target), view=1 if action == 'restore' else 0, recovery_view=0,
            snapshot=names[0] if names else None, recovery=names[1] if len(names) > 1 else None,
            snapshots=[] if failed else [{'name': 'entry-' + str(i)} for i in range(32)],
            identity={'file': target['file'], 'uuid': target['uuid']})


class NativeArchiveTerminal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.package, cls.modules = load_modules()

    @classmethod
    def tearDownClass(cls):
        for name in list(sys.modules):
            if name == cls.package or name.startswith(cls.package + '.'):
                del sys.modules[name]

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='native-archive-terminal-')
        self.addCleanup(temporary.cleanup)
        self.fixture = SyntheticStore(Path(temporary.name).resolve(), self.modules)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(self.fixture.seams())
        for action in ('snapshot', 'restore', 'snapshots'):
            self.stack.enter_context(patch.object(self.fixture.image, action,
                lambda target, *names, action=action: self.fixture.bridge(action, *names)))

    def catalogs(self):
        f = self.fixture
        for action, name in (('snapshot', 'overflow'), ('restore', 'entry-0')):
            with self.assertRaises(f.core.StallionError) as caught:
                f.recovery.catalog_locked(f.store, f.path, f.meta, action, name)
            self.assertEqual(caught.exception.native_candidate_result['outcome'], 'incomplete')
        self.assertEqual(len(f.recovery.catalog_locked(f.store, f.path, f.meta, 'snapshots')), 32)
        self.assertFalse((f.root / 'journals' / (f.workspace + '.json')).exists())
        return f.records()

    def marker(self):
        f = self.fixture
        target = f.target(f.path)
        return {'state': 'absent', 'target': target, 'current_guard': f.receipt(target)}

    def consumers(self, records, *, accepted):
        f = self.fixture
        before = copy.deepcopy(records)
        for name, consume in (
            ('interval', lambda: f.interval.Index(records, f.path, f.meta)),
            ('archive', lambda: f.binding.archive_anchor(records, f.path, f.meta, self.marker())),
        ):
            with self.subTest(consumer=name):
                if accepted:
                    result = consume()
                    if name == 'interval':
                        self.assertFalse(result.origins)
                        self.assertFalse(result.closes)
                else:
                    with self.assertRaises(f.core.StallionError):
                        consume()
                self.assertEqual(records, before)

    def failed_catalog(self):
        return next(r for r in self.catalogs().values() if r['operation'] == 'native-snapshot')

    def test_catalog_producers_preserve_failure_and_allow_closed_history(self):
        f = self.fixture
        records = self.catalogs()
        paths = list((f.path / 'native-operations').glob('*/record.json'))
        before = {p: p.read_bytes() for p in paths}
        self.consumers(records, accepted=True)
        self.assertEqual({p: p.read_bytes() for p in paths}, before)
        failed = [r for r in records.values() if r['outcome'] == 'incomplete']
        self.assertEqual(len(failed), 2)
        self.assertTrue(all(r['error']['type'] == 'StallionError' and r['native_image_result']['ok'] is False for r in failed))

    def test_catalog_receipt_requires_every_c_field_and_rejects_coercion(self):
        record = self.failed_catalog()
        for receipt_name in ('opened_receipt', 'receipt', 'staged_receipt', 'close_receipt'):
            for field, value in record['native_image_result'][receipt_name].items():
                for changed in ('missing', 'wrong-type'):
                    with self.subTest(receipt=receipt_name, field=field, changed=changed):
                        row = copy.deepcopy(record)
                        receipt = row['native_image_result'][receipt_name]
                        if changed == 'missing':
                            del receipt[field]
                        else:
                            receipt[field] = bool(value) if type(value) is int else 0
                        self.consumers({row['id']: row}, accepted=False)

    def test_catalog_unknown_commit_close_and_partial_response_stay_blocked(self):
        record = self.failed_catalog()
        changes = (
            {'outcome': 'unknown'}, {'commit_attempted': True}, {'committed': True},
            {'guard_close_errno': errno.EIO}, {'path_errno': errno.ESTALE}, {'close_attempted': False},
            {'abort_attempted': True}, {'interrupted': True}, {'deadline_expired': True},
            {'response_complete': False}, {'response_complete': True}, {'error_code': True},
            {'view': True}, {'snapshots': [{}]}, {'identity': {'file': [0, 0], 'uuid': '3' * 32}},
        )
        for changeset in changes:
            with self.subTest(changes=changeset):
                row = copy.deepcopy(record)
                row['native_image_result'].update(changeset)
                self.consumers({row['id']: row}, accepted=False)

    def test_catalog_status_anchor_identity_and_resources_stay_bound(self):
        record = self.failed_catalog()
        changes = (
            ('receipt', 'status', 0), ('receipt', 'phase', 5), ('receipt', 'limit_reason', 1),
            ('receipt', 'transaction_active', True), ('receipt', 'poisoned', True),
            ('receipt', 'physical_end', 16384), ('opened_receipt', 'generation', 8),
            ('close_receipt', 'status', 2), ('close_receipt', 'inode', 0),
            ('close_receipt', 'root_digest', 'b' * 64), ('close_receipt', 'fence_attempted', 1),
        )
        for receipt, key, value in changes:
            with self.subTest(receipt=receipt, key=key):
                row = copy.deepcopy(record)
                row['native_image_result'][receipt][key] = value
                self.consumers({row['id']: row}, accepted=False)
        for changeset in ({'child_pending': True}, {'helpers': [{}]}, {'phase': 'complete'},
                          {'workspace': 'f' * 32}, {'error': {}}, {'bridge_attempted': False}):
            row = dict(record, **changeset)
            self.consumers({row['id']: row}, accepted=False)

    def test_catalog_does_not_supply_missing_ordinary_close_authority(self):
        f = self.fixture
        records = self.catalogs()
        with self.assertRaises(f.core.StallionError):
            f.binding.archive_anchor(records, f.path, f.meta, None, {'first_mount_attempted': True})

    def stale_reset(self, *, bad_close=False):
        f = self.fixture
        f.guard_error = 'bad-close' if bad_close else 'clean-close'
        if bad_close:
            with self.assertRaises(f.core.StallionError):
                f.recovery.move_locked(f.store, f.workspace, selected=(f.path, f.meta, f.state))
        else:
            self.assertIsNone(f.recovery.move_locked(f.store, f.workspace, selected=(f.path, f.meta, f.state)))
        return next(iter(f.records().values()))

    def round_trip(self):
        f = self.fixture
        f.recovery.move_locked(f.store, f.workspace, selected=(f.path, f.meta, f.state))
        f.recovery.move_locked(f.store, f.workspace, restore=True)
        self.assertEqual(len([c for c in f.calls if 'rename' in c]), 2)
        return f.records()

    def test_stale_reset_producer_is_terminal_without_an_interval(self):
        f = self.fixture
        row = self.stale_reset()
        self.assertTrue(row['stale_reset'])
        self.assertFalse(row['rename_attempted'])
        self.assertEqual(row['outcome'], 'complete')
        self.assertFalse((f.root / 'protected' / (f.workspace + '.json')).exists())
        self.assertFalse((f.root / 'journals' / (f.workspace + '.json')).exists())
        self.consumers({row['id']: row}, accepted=True)

    def test_failed_stale_close_keeps_protection_and_refuses(self):
        f = self.fixture
        row = self.stale_reset(bad_close=True)
        self.assertEqual(row['outcome'], 'incomplete')
        self.assertTrue((f.root / 'protected' / (f.workspace + '.json')).exists())
        self.assertTrue((f.root / 'journals' / (f.workspace + '.json')).exists())
        self.consumers({row['id']: row}, accepted=False)

    def test_completed_moves_keep_historical_targets_and_bytes(self):
        f = self.fixture
        records = self.round_trip()
        returned = next(r for r in records.values() if r['operation'] == 'native-return')
        self.assertEqual(returned['target']['directory'], str(f.root / 'trash' / f.workspace))
        paths = list((f.path / 'native-operations').glob('*/record.json'))
        before = {p: p.read_bytes() for p in paths}
        self.consumers(records, accepted=True)
        self.assertEqual({p: p.read_bytes() for p in paths}, before)
        self.assertFalse((f.root / 'protected' / (f.workspace + '.json')).exists())
        self.assertFalse((f.root / 'journals' / (f.workspace + '.json')).exists())

    def test_moves_reject_foreign_location_metadata_and_guards(self):
        records = self.round_trip()
        for record in records.values():
            mutations = (
                ('target', 'directory', '/foreign/trash/' + self.fixture.workspace),
                ('target', 'component', 'other.sfs'),
                ('metadata', 'transaction', 'b' * 32),
                ('source_location', 'collection', 'elsewhere'),
                ('source_location', 'object', [0, 0]),
                ('source_location', 'guard', {}),
                ('destination_location', 'operation', 'c' * 32),
                ('destination_location', 'complete', True),
                ('current_location', 'complete', False),
                ('current_location', 'file', [0, 0]),
                ('current_location', 'schema', True),
            )
            for section, field, value in mutations:
                with self.subTest(action=record['operation'], section=section, field=field):
                    row = copy.deepcopy(record)
                    row[section][field] = value
                    self.consumers({row['id']: row}, accepted=False)
            for field, value in (('core_consumed', False), ('parent_close_errno', errno.EIO),
                    ('status', True), ('phase', 5), ('uuid', '0' * 32), ('transaction_active', True),
                    ('poisoned', True), ('system_errno', errno.EIO)):
                row = copy.deepcopy(record)
                row['current_location']['guard'][field] = value
                self.consumers({row['id']: row}, accepted=False)

    def test_stale_reset_rejects_forged_disposition_and_close(self):
        record = self.stale_reset()
        for changeset in ({'rename_attempted': True}, {'stale_reset': False}, {'outcome': 'incomplete'},
                          {'helpers': [{}]}, {'current_location': {}}):
            row = dict(record, **changeset)
            self.consumers({row['id']: row}, accepted=False)
        for key, value in (('core_consumed', False), ('parent_close_errno', errno.EIO),
                           ('status', True), ('inode', 0), ('transaction_active', True)):
            row = copy.deepcopy(record)
            row['current_guard'][key] = value
            self.consumers({row['id']: row}, accepted=False)

    def test_moves_reject_incomplete_helper_and_unproduced_shapes(self):
        records = self.round_trip()
        for record in records.values():
            for changeset in ({'outcome': 'incomplete'}, {'child_pending': True}, {'helpers': [{}]},
                    {'rename_attempted': False}, {'stale_reset': True}, {'resolution': {}},
                    {'error': {'type': 'OSError', 'message': 'uncertain'}}, {'ordinary_interval': {}}):
                row = dict(record, **changeset)
                self.consumers({row['id']: row}, accepted=False)
        stale = copy.deepcopy(next(iter(records.values())))
        stale.update(stale_reset=True, rename_attempted=False, current_guard=stale['current_location']['guard'])
        del stale['current_location']
        stale['operation'] = 'native-return'
        self.consumers({stale['id']: stale}, accepted=False)


if __name__ == '__main__':
    unittest.main()
