"""Real normal-install publications with inert backing and helper evidence."""
from pathlib import Path
import copy
import os
import unittest
from unittest.mock import patch
from stallionfs import core, _native, _native_create_recovery as recovery, _native_binding as binding
from stallionfs import _native_create_request as request, _native_create_authority as authority
from native_writer_fixture import writer
import test_native_create_recovery as fixtures

class Cut(BaseException):
    pass


def interrupted(t, boundary):
    # Generate current protocol controls through the real request producer in a new store.
    root=t.base/'producer-store';store=core.Store(root)
    seedpath=root/'seeds'/t.seed;seedpath.mkdir(mode=0o700)
    with core.lock(root/'.lock') as sf,core.lock(root/'locks'/('seed-'+t.seed)) as seedfd:
        with request.prepare_controller(root,(sf,seedfd),seedpath,{'id':t.seed,'commit':t.meta['commit']},workspace=t.workspace,
                    transaction=t.transaction,name=t.meta['name'],jobs=1,capacity=1,budget=None,install_profile='production',host=None,
                    runtime=t.proof['writer']['spec']['runtime']) as (a,specification,intent):
            stage=Path(intent['stage']);owned=stage/'owned';final=root/'workspaces'/t.workspace;journal=root/'journals'/(t.workspace+'.json')
            image=owned/'image.sfs';image.write_bytes(b'opaque synthetic backing');image.chmod(0o600)
            target={**t.target,'parent':t.ident(stage),'object':t.ident(owned),'file':t.ident(image)}
            origin={**t.meta,'native_image':target}
            result=copy.deepcopy(t.record['result']);result['identity']['file']=target['file'];result['observed_file']=target['file']
            for key in ('creation','original','commit','verify','close','reopen','reopen_close'):
                result[key].update(device=target['file'][0],inode=target['file'][1])
            writer_packet=writer(origin,stage);writer_packet['spec']=copy.deepcopy(specification);writer_packet['spec_digest']=request.digest(specification)
            discover=copy.deepcopy(writer_packet['preflight']['helpers'][0]);discover.update(label='discover',argv=[specification['host'],'--discover-json'],stdout=str(stage/'discovery/01-discover/stdout'),stderr=str(stage/'discovery/01-discover/stderr'))
            writer_packet['preflight']['helpers'].append(discover);writer_packet['preflight']['discovery']={'protocol':1,'ok':True,'modules':[]}
            # Existing fixture creates terminal qualified helper/actor records; all surrounding persistence is real.
            intent.update(phase='preflight',helpers=writer_packet['preflight']['helpers'],child_pending=False,discovery=writer_packet['preflight']['discovery'])
            discovery=stage/'discovery';discovery.mkdir(mode=0o700)
            request.publish(a,journal,intent)
            recovery.Admission.publish(a,discovery/'record.json',copy.deepcopy(intent))
            intent.update(phase='install',actors=writer_packet['actors'],creation_attempted=True,outcome='candidate-created',result=result,
                    native_image={k:target[k] for k in ('component','file','uuid','anchor')})
            created={**t.proof,'native_image':target,'result':result,'writer':writer_packet}
            authority.proof(origin,created)
            recovery.Admission.publish(a,owned/'native-create.json',created);recovery.Admission.publish(a,owned/'meta.json',origin)
            request.publish(a,journal,intent)
            # Match caller's release of the owned descriptor before the real install producer renames it.
            a.bindings.pop(owned);os.close(a.fds.pop(owned))
            response={'candidate':str(owned),'journal':str(journal)}
            original_persist=_native._persist
            original_publish=recovery.Admission.publish
            original_fsync=os.fsync
            original_unlink=os.unlink
            original_replace=os.replace
            original_binding_publish=binding.publish
            def check(label):
                if boundary == label: raise Cut(label)
            def persist(path,value):
                if Path(path)==journal and 'lifecycle' in value.get('installation',{}): check('before-intent')
                original_persist(path,value)
                if Path(path)==journal and 'lifecycle' in value.get('installation',{}): check('after-intent')
                if Path(path)==final/'native-install.json': check('after-proof')
                if Path(path)==final/'meta.json' and value.get('state')=='installed': check('after-metadata')
            def publish(admission,path,value):
                original_publish(admission,path,value)
                if Path(path)==root/'lifecycle'/(t.workspace+'.json'): check('after-lifecycle')
            def fsync(fd):
                original_fsync(fd)
                ident=[os.fstat(fd).st_dev,os.fstat(fd).st_ino]
                if ident==t.ident(root/'lifecycle') and (root/'lifecycle'/(t.workspace+'.json')).exists(): check('after-lifecycle-fsync')
                if ident==t.ident(journal.parent) and not journal.exists(): check('after-unlink-fsync')
            def unlink(path,*args,**kwargs):
                original_unlink(path,*args,**kwargs)
                if Path(path)==journal: check('after-unlink')
            def replace(source, destination, *args, **kwargs):
                original_replace(source, destination, *args, **kwargs)
                parent = kwargs.get('dst_dir_fd')
                if parent is not None and [os.fstat(parent).st_dev, os.fstat(parent).st_ino] == t.ident(root/'lifecycle'):
                    check('after-lifecycle-replace')
            def binding_publish(*args):
                original_binding_publish(*args)
                check('after-binding-publication')
            original_enroll=_native._enroll_current
            def enroll(*args):
                check('before-enrollment')
                original_enroll(*args)
                check('after-enrollment')
            with patch.object(_native._scan,'mounts',return_value=[]),patch.object(_native,'_persist',side_effect=persist),patch.object(recovery.Admission,'publish',publish),patch.object(os,'fsync',side_effect=fsync),patch.object(os,'unlink',side_effect=unlink),patch.object(os,'replace',side_effect=replace),patch.object(binding,'publish',side_effect=binding_publish),patch.object(_native,'_enroll_current',side_effect=enroll):
                try:_native.install_candidate(store,response,intent,origin,'production',None)
                except Cut as e: assert str(e)==boundary
                else: raise AssertionError('cut not reached')
    return root, final, journal

class NormalInstallPublication(unittest.TestCase):
    def fixture(self, boundary):
        t = fixtures.CreateRecovery('runTest')
        t.setUp()
        self.addCleanup(t.doCleanups)
        root, final, journal = interrupted(t, boundary)
        return t, root, final, journal

    def test_durable_producer_boundaries_continue_same_generation(self):
        for boundary in ('before-intent', 'after-intent', 'after-proof', 'after-metadata',
                         'after-lifecycle', 'after-lifecycle-replace', 'after-lifecycle-fsync', 'after-unlink',
                         'after-unlink-fsync', 'before-enrollment', 'after-binding-publication', 'after-enrollment'):
            with self.subTest(boundary=boundary):
                t, root, final, journal = self.fixture(boundary)
                saved = t.read(journal).get('installation', {}).get('lifecycle') if journal.exists() else t.read(final/'native-install.json')['lifecycle']
                before = t.snapshot()
                with patch.object(_native._scan, 'mounts', return_value=[]):
                    # Only pre-rename cuts may perform the single original rename.
                    move = t.exclusive_move if boundary in ('before-intent', 'after-intent') else lambda *a: self.fail('rename replay')
                    with patch.object(_native._scan, 'move', side_effect=move):
                        result = recovery.continue_creation(root, t.workspace, t.transaction)
                        self.assertEqual(result['status'], 'installed-unmounted', result)
                        state = t.read(root/'lifecycle'/(t.workspace+'.json'))
                        if saved is not None: self.assertEqual(state, saved)
                        after = t.snapshot()
                        repeated = recovery.continue_creation(root, t.workspace, t.transaction)
                        self.assertEqual(repeated['status'], 'installed-unmounted', repeated)
                        self.assertEqual(after, t.snapshot())
                # Only installation metadata may change; the one rename maps
                # original directory and payload identities to their final names.
                changed = {'producer-store/journals/' + t.workspace + '.json',
                           'producer-store/lifecycle/' + t.workspace + '.json'}
                changed.update('producer-store/workspaces/' + t.workspace + '/' + name
                               for name in ('meta.json', 'native-install.json', 'native-binding.json'))
                source_prefix = 'producer-store/staging/native-create-' + t.transaction + '/owned'
                final_prefix = 'producer-store/workspaces/' + t.workspace
                after = t.snapshot()
                mapped = {}
                for name, value in before.items():
                    if name == source_prefix or name.startswith(source_prefix + '/'):
                        name = final_prefix + name[len(source_prefix):]
                    mapped[name] = value
                    if name not in changed: self.assertEqual(value, after[name], name)
                self.assertLessEqual(set(after) - set(mapped), changed)
                t.doCleanups()

    def test_normal_completion_retry_syncs_existing_lifecycle_before_unlink(self):
        for fail_sync in (False, True):
            with self.subTest(fail_sync=fail_sync):
                t, root, final, journal = self.fixture('after-lifecycle-replace')
                state_path = root/'lifecycle'/(t.workspace+'.json')
                saved = state_path.read_bytes(), t.ident(state_path)
                intent = t.read(journal)
                metadata = t.read(final/'meta.json')
                store = core.Store.__new__(core.Store)
                store.root = root
                events = []
                fsync, unlink = os.fsync, os.unlink

                def synced(fd):
                    if [os.fstat(fd).st_dev, os.fstat(fd).st_ino] == t.ident(root/'lifecycle'):
                        events.append('lifecycle-sync')
                        if fail_sync: raise OSError('injected lifecycle directory sync failure')
                    fsync(fd)

                def unlinked(path, *args, **kwargs):
                    if Path(path) == journal:
                        self.assertIn('lifecycle-sync', events)
                        events.append('journal-unlink')
                    unlink(path, *args, **kwargs)

                with patch.object(_native._scan, 'mounts', return_value=[]), \
                        patch.object(os, 'fsync', side_effect=synced), \
                        patch.object(os, 'unlink', side_effect=unlinked), \
                        patch.object(_native._scan, 'move', side_effect=AssertionError('rename replay')):
                    if fail_sync:
                        with self.assertRaisesRegex(OSError, 'injected lifecycle'):
                            _native._complete_install(store, final, metadata, intent, journal, intent['installation']['guard'])
                        self.assertTrue(journal.exists())
                        self.assertNotIn('journal-unlink', events)
                    else:
                        _native._complete_install(store, final, metadata, intent, journal, intent['installation']['guard'])
                        self.assertEqual(events, ['lifecycle-sync', 'journal-unlink'])
                self.assertEqual(saved, (state_path.read_bytes(), t.ident(state_path)))
                with patch.object(_native._scan, 'mounts', return_value=[]):
                    self.assertEqual(recovery.continue_creation(root, t.workspace, t.transaction)['status'], 'installed-unmounted')
                self.assertEqual(saved, (state_path.read_bytes(), t.ident(state_path)))
                t.doCleanups()

    def test_adjacent_lifecycle_and_authority_conflicts_are_read_only(self):
        for fault in ('generation', 'id', 'payload', 'object', 'owner', 'guard', 'pending', 'mount'):
            with self.subTest(fault=fault):
                t, root, final, journal = self.fixture('after-lifecycle')
                state_path = root/'lifecycle'/(t.workspace+'.json')
                state = t.read(state_path)
                if fault in ('generation', 'id', 'payload', 'object'):
                    state[fault] = 'f'*32 if fault in ('generation', 'id') else [1, 2]
                    t.save(state_path, state)
                elif fault == 'owner': state_path.chmod(0o644)
                elif fault == 'guard':
                    proof = t.read(final/'native-install.json')
                    proof['guard']['uuid'] = 'f'*32
                    t.save(final/'native-install.json', proof)
                else:
                    record = t.read(journal)
                    if fault == 'pending': record['child_pending'] = True
                    else: record['installation']['first_mount_attempted'] = True
                    t.save(journal, record)
                before = t.snapshot(); guards = len(t.guard_calls)
                with patch.object(_native._scan, 'mounts', return_value=[]):
                    result = recovery.continue_creation(root, t.workspace, t.transaction)
                self.assertEqual(result['status'], 'blocked', result)
                self.assertEqual(before, t.snapshot())
                self.assertEqual(guards, len(t.guard_calls))
                t.doCleanups()
