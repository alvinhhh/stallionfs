"""Owned inert fixtures for maintenance acquisition and software/STORE boundaries."""
import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import plistlib
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('maintenance_workflow',SOURCE/'filesystem/fskit/maintenance_observer.py')
o = importlib.util.module_from_spec(spec); spec.loader.exec_module(o)
INSTALLED_VALIDATORS = o.installed_validators
ACQUIRE_ATTACHMENTS = o.acquire_attachments


def authority(home):
    artifact = dict(id='a'*64, descriptor_sha256='b'*64, observer_sha256='c'*64,
                    native_sha256='d'*64, compatibility_sha256='e'*64)
    return dict(schema=1,artifact=artifact,archive=dict(path='/retained/exact.zip',sha256='f'*64),
        home=str(home),store_runtime=dict(o.GIT_CONTRACT,input_inventory_sha256='1'*64,payload_entries=1,
            payload_sha256='2'*64,descriptor_sha256=artifact['descriptor_sha256'],executable_sha256='3'*64,
            source_build_id='4'*64,publisher=o.PUBLISHER_TEAM),runtime=copy.deepcopy(o.RUNTIME_CONTRACT),roles=dict(o.RESOURCE_ROLES),publisher=o.PUBLISHER_TEAM,
        inventory=[dict(path='Contents',type='dir',size=0,mode='0o755')],last_installed=artifact['id'],
        executable_history=[artifact['id']],store_history=dict(runtime=artifact['id'],mutation='known-same-artifact'),
        cooperation=dict(scope='all-possible-users-cooperative',users=[os.getuid()],confirmed_ns=1,boot_id='boot'))


def idle():
    return dict(cooperative_downtime=True,mounts=[],helpers=[],descendants=[],uncertainties=[])


class Workflow(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='maintenance-workflow-',dir=SOURCE.parent)
        self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.base.chmod(0o700)
        self.authority=authority(self.base)

    def test_independent_authority_and_hostile_resource(self):
        data=o.json_bytes(self.authority)
        import hashlib
        pin=hashlib.sha256(data).hexdigest()
        self.assertEqual(o.validate_authorization(data,pin,o.PUBLISHER_TEAM),self.authority)
        for changed in (dict(publisher='BADTEAM000'),dict(roles={}),dict(runtime={}),dict(cooperation={}),
                        dict(artifact={}),dict(inventory=[]),dict(schema=True),dict(extra=True)):
            value={**self.authority,**changed};raw=o.json_bytes(value)
            with self.subTest(changed=changed),self.assertRaises(o.Refusal):
                o.validate_authorization(raw,hashlib.sha256(raw).hexdigest(),o.PUBLISHER_TEAM)
        with self.assertRaises(o.Refusal):o.validate_authorization(data,'0'*64,o.PUBLISHER_TEAM)
        with self.assertRaises(o.Refusal):o.validate_authorization(data,pin,'OTHERTEAM0')

    def test_real_request_acquisition_preserves_all_literal_denominators(self):
        fake=type('User',(),dict(pw_dir=str(self.base)))()
        with patch.object(pwd,'getpwuid',return_value=fake),patch.dict(os.environ,{'STALLIONFS_HOME':'relative/hostile'},clear=True):
            request=o.original_request('remove',['/custom/one','/custom/two'],self.authority)
        self.assertEqual(request['roots'],[dict(literal=str(self.base)+'/Library/Application Support/stallionfs',reason='default'),
            dict(literal='relative/hostile',reason='environment'),dict(literal='/custom/one',reason='explicit'),
            dict(literal='/custom/two',reason='explicit')])
        self.assertEqual(request['environment'],dict(STALLIONFS_HOME='relative/hostile'))
        self.assertNotIn('activity',request)
        with self.assertRaises(o.Refusal):o.original_request('restore',[],self.authority)

    def test_retention_exclusive_nofollow_modes_readback(self):
        directory=self.base/'controls';directory.mkdir(mode=0o700)
        retained=o.Retention(directory);self.addCleanup(retained.close)
        retained.write('request.json',b'original\n')
        self.assertEqual((directory/'request.json').stat().st_mode&0o777,0o600)
        with self.assertRaises(FileExistsError):retained.write('request.json',b'changed')
        (directory/'alias').symlink_to(directory/'request.json')
        with self.assertRaises(OSError):o.retained_read(directory/'alias',private=True)
        (directory/'request.json').chmod(0o644)
        with self.assertRaises(o.Refusal):o.retained_read(directory/'request.json',private=True)
        alias=self.base/'alias';alias.symlink_to(directory,target_is_directory=True)
        with self.assertRaises(OSError):o.retained_read(alias/'request.json')
        directory.chmod(0o755)
        with self.assertRaises(o.Refusal):retained.check()
        with self.assertRaises(o.Refusal):retained.close()
        self.assertEqual(retained.access.fds,{})

    def test_software_only_state_matrix_preserves_store_scope(self):
        for state in ('absent','partial','intact-wrong','intact-exact'):
            result=o.software_plan(self.authority,idle(),state,request_retained=True,leaf_available=True)
            self.assertTrue(result['software_only_eligible']);self.assertFalse(result['store_access_eligible'])
            for changes in (dict(last_installed=None),dict(last_installed='b'*64),dict(executable_history=None),
                            dict(executable_history=['a'*64,'b'*64])):
                self.assertFalse(o.software_plan({**self.authority,**changes},idle(),state,
                    request_retained=True,leaf_available=True)['software_only_eligible'])
            for key in ('mounts','helpers','descendants','uncertainties'):
                self.assertFalse(o.software_plan(self.authority,{**idle(),key:[{'unknown':True}]},state,
                    request_retained=True,leaf_available=True)['software_only_eligible'])
        result=o.software_plan({**self.authority,'store_history':None},idle(),'absent',request_retained=False,leaf_available=True)
        self.assertTrue(result['software_only_eligible'])
        self.assertEqual(result['store_blockers'],['unknown-or-mixed-store-history','original-root-request-unavailable-preserve-scope'])
        self.assertIn('separate-qualified-recovery',result['pending_requests'])
        self.assertFalse(o.software_plan(self.authority,idle(),'absent',request_retained=True,leaf_available=False)['software_only_eligible'])

    def test_native_binding_unknown_paths_pid_reuse_descendants_mounts_sessions(self):
        request=dict(acquisition=dict(acquired_ns=10),cooperation=self.authority['cooperation'])
        completion=dict(complete=True,reaped=True,streams_eof=True,output_durable=True,directory_bound=True,
                        output_bound=True,cleanup_complete=True,io_error=False,close_errors=False,worker_pid=9,
                        output_readback=True,returncode=0,outcome='success')
        native=dict(schema=1,scope='global-kernel-snapshot',complete=True,uncertainties=[],boot_id='boot',
                    started_ns=11,finished_ns=12,mounts=[],processes=[dict(pid=0,ppid=0,uid=0,start_sec=0,start_usec=0,
                        path=None,path_errno=2,stable=True,kernel=True)],sessions=[])
        def check(n=native,c=completion):return o.native_activity(n,c,request,leaf_path='/external/leaf',collector_pid=8)
        self.assertEqual(check()['uncertainties'],[])
        for changed in (dict(complete=False),dict(uncertainties=['denial']),dict(started_ns=9),dict(boot_id='')):
            with self.assertRaises(o.Refusal):check({**native,**changed})
        for key in ('complete','reaped','streams_eof','output_durable','directory_bound','output_bound','cleanup_complete'):
            with self.assertRaises(o.Refusal):check(c={**completion,key:False})
        with self.assertRaises(o.Refusal):check(c={**completion,'io_error':True})
        row=dict(pid=100,ppid=1,uid=os.getuid(),start_sec=1,start_usec=0,path='',path_errno=2,stable=True)
        self.assertEqual(check({**native,'processes':[row]})['uncertainties'],[row])
        with self.assertRaises(o.Refusal):check({**native,'processes':[{**row,'stable':False}]})
        known={**row,'path':o.APP+'/Contents/MacOS/StallionFS','path_errno':0}
        child={**known,'pid':101,'ppid':100,'path':'/bin/sleep'}
        result=check({**native,'processes':[known,child]})
        self.assertEqual(result['helpers'],[known]);self.assertEqual(result['descendants'],[child])
        self.assertTrue(check({**native,'mounts':[dict(source='x',target='/x',type='fskit')]})['uncertainties'])
        self.assertTrue(check({**native,'sessions':[dict(user='not-a-real-maintenance-user')]})['uncertainties'])

    def test_runtime_independent_search_path_and_flags(self):
        with self.assertRaises(o.Refusal):o.actual_runtime(o.RUNTIME_CONTRACT)
        with self.assertRaises(o.Refusal):o.actual_runtime({**o.RUNTIME_CONTRACT,'initial_paths':list(sys.path)})
        self.assertEqual(o.publisher_requirement('com.alvinhhh.stallionfs',o.PUBLISHER_TEAM),
            'anchor apple generic and identifier "com.alvinhhh.stallionfs" and certificate leaf[subject.OU] = "'+o.PUBLISHER_TEAM+'"')

    def test_packager_exec_remains_inert(self):
        source=(SOURCE/'filesystem/fskit/maintenance_observer.py').read_bytes()
        with patch.object(o.os,'open',side_effect=AssertionError('import opened path')):
            namespace={'__name__':'maintenance_observer_resource','__file__':'/unused/observer.py'}
            exec(compile(source,'observer.py','exec'),namespace)
        self.assertIn('main',namespace);self.assertNotIn('site',namespace)

    def test_app_inventory_no_follow_and_exact_rows(self):
        app=self.base/'fixture.app';app.mkdir(mode=0o755)
        (app/'Contents').mkdir(mode=0o755);path=app/'Contents/fixture';path.write_bytes(b'abc');path.chmod(0o644)
        (app/'Contents/alias').symlink_to('fixture')
        rows=o.app_inventory(app)
        self.assertEqual({r['path'] for r in rows},{'Contents','Contents/fixture','Contents/alias'})
        (app/'Contents/alias').unlink();(app/'Contents/alias').symlink_to('../../outside')
        with self.assertRaises(o.Refusal):o.app_inventory(app)


class Upgrade(unittest.TestCase):
    """Real retained controls and inert app/store bytes; no executable app input."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='maintenance-upgrade-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve(); self.base.chmod(0o700)
        self.home = self.base/'home'; self.home.mkdir(mode=0o700)
        (self.home/'Library').mkdir(mode=0o700)
        (self.home/'Library/Application Support').mkdir(mode=0o700)
        self.store = self.base/'store'; self.store.mkdir(mode=0o700)
        for name in o.COLLECTIONS: (self.store/name).mkdir(mode=0o700)
        for name, data in (('.lock', b''), ('store.json', b'{"format":1,"application":"stallionfs"}')):
            path = self.store/name; path.write_bytes(data); path.chmod(0o600)
        self.controller = self.base/'observer.py'
        self.controller.write_bytes((SOURCE/'filesystem/fskit/maintenance_observer.py').read_bytes())
        self.controller.chmod(0o600)
        self.old_path = self.base/'Old.app'; self.candidate_path = self.base/'Candidate.app'
        old = self.release(self.old_path, 'a', self.controller.read_bytes()+b'\n# inert predecessor\n')
        declaration = dict(predecessor_artifact_id=old['artifact']['id'],
                           predecessor_descriptor_sha256=old['artifact']['descriptor_sha256'])
        candidate = self.release(self.candidate_path, 'b', self.controller.read_bytes(), [declaration])
        self.installed = self.base/'Installed.app'; shutil.copytree(self.old_path, self.installed)
        self.controls = self.base/'controls'; self.controls.mkdir(mode=0o700)
        self.session = dict(schema=2, kind='upgrade-session', old=old, candidate=candidate,
            runtime_artifact_id=old['artifact']['id'],
            controller=dict(artifact_id=candidate['artifact']['id'], observer_sha256=candidate['artifact']['observer_sha256']),
            home=str(self.home), cooperation=dict(scope='single-user-controlled', users=[os.getuid()], confirmed_ns=1, boot_id='boot'),
            history=dict(request_sha256=None, previous_step_sha256=None, last_installed=old['artifact']['id'],
                         candidate_access='none', continuous_downtime=True))
        self.last = None
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        for context in (patch.object(o, 'APP', str(self.installed)), patch.object(o, '__file__', str(self.controller)),
                        patch.object(pwd, 'getpwuid', return_value=type('User', (), dict(pw_dir=str(self.home)))()),
                        patch.dict(os.environ, {}, clear=True),
                        patch('subprocess.Popen', side_effect=AssertionError('unexpected execution'))):
            self.stack.enter_context(context)
        self.signatures = self.stack.enter_context(patch.object(o, 'static_signature', side_effect=self.signature))
        self.runtime = self.stack.enter_context(patch.object(o, 'actual_runtime', return_value=o.RUNTIME_CONTRACT))
        self.native = self.stack.enter_context(patch.object(o, 'acquire_native', side_effect=self.activity))
        import contextlib
        self.validators = self.stack.enter_context(patch.object(o, 'installed_validators',
            side_effect=lambda release: contextlib.nullcontext(None)))

    def release(self, app, source, observer, predecessors=None):
        app.mkdir(mode=0o755)
        def write(name, data, mode=0o644):
            path = app/name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data); path.chmod(mode)
            for parent in path.parents:
                if parent == app: break
                parent.chmod(0o755)
            return path
        build = dict(bundle_id='com.alvinhhh.stallionfs', bundle_version='1' if source == 'a' else '2',
                     package_version='0.7.0', source_build_id=source*64)
        write('Contents/Info.plist', plistlib.dumps(dict(CFBundleIdentifier=build['bundle_id'], CFBundleVersion=build['bundle_version'])))
        write('Contents/Extensions/StallionFS.appex/Contents/Info.plist', b'inert extension')
        write('Contents/Resources/Runtime/CPython/bin/python3.13', b'inert python', 0o755)
        write('Contents/Resources/Runtime/Git/bin/git', b'inert git', 0o755)
        git = dict(o.GIT_CONTRACT, input_inventory_sha256='1'*64, payload_entries=1, payload_sha256='2'*64)
        write(o.DESCRIPTOR, o.json_bytes(dict(schema=2, git=git, source_build_id=build['source_build_id'],
             package_version=build['package_version'], bundle_version=build['bundle_version'])))
        write(o.RESOURCE_ROLES['observer'], observer)
        write(o.RESOURCE_ROLES['native'], b'inert native leaf', 0o755)
        compatibility = o.create_compatibility(observer, build, predecessors)
        write(o.RESOURCE_ROLES['compatibility'], compatibility)
        rows = o.app_inventory(app)
        sha = lambda data: hashlib.sha256(data).hexdigest()
        artifact = dict(id=sha(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()))
        for name, key in ((o.DESCRIPTOR, 'descriptor_sha256'), (o.RESOURCE_ROLES['observer'], 'observer_sha256'),
                          (o.RESOURCE_ROLES['native'], 'native_sha256'), (o.RESOURCE_ROLES['compatibility'], 'compatibility_sha256')):
            artifact[key] = sha((app/name).read_bytes())
        archive = self.base/(source+'.zip'); archive.write_bytes(b'inert retained archive '+source.encode()); archive.chmod(0o600)
        roles = {'.':'com.alvinhhh.stallionfs', 'Contents/Extensions/StallionFS.appex':'com.alvinhhh.stallionfs.module',
                 o.RESOURCE_ROLES['native']:'com.alvinhhh.stallionfs.maintenance'}
        return dict(schema=1, kind='final-maintenance-artifact-bindings', publisher=o.PUBLISHER_TEAM,
            artifact=artifact, inventory=rows, archive=dict(path=str(archive), sha256=sha(archive.read_bytes())),
            roles=dict(o.RESOURCE_ROLES), runtime=copy.deepcopy(o.RUNTIME_CONTRACT), build=build,
            store_runtime=dict(git, descriptor_sha256=artifact['descriptor_sha256'], executable_sha256=sha(b'inert git'),
                               source_build_id=build['source_build_id'], publisher=o.PUBLISHER_TEAM),
            public_upgrade_support=json.loads(compatibility)['public_upgrade_support'],
            signing_roles=[dict(path=name, requirement='='+o.publisher_requirement(identity,o.PUBLISHER_TEAM))
                           for name, identity in roles.items()])

    def signature(self, path, requirement, retention, label):
        self.assertTrue(requirement.startswith('anchor apple generic and '))
        retention.write(label+'.json', o.json_bytes(dict(inert=True)))
        return {}

    def activity(self, retention, leaf, authority, request):
        self.assertTrue((self.controls/'request.json').exists())
        self.assertEqual(leaf.read_bytes(), b'inert native leaf')
        return dict(idle(), boot_id='boot', observed_ns=request['acquisition']['acquired_ns'])

    def authority_now(self, **history):
        session = copy.deepcopy(self.session)
        if self.last:
            session['history'].update(request_sha256=self.last['request_sha256'], previous_step_sha256=self.last['step_sha256'])
        session['history'].update(history)
        return session

    def invoke(self, phase, session=None, roots=None):
        session = session or self.authority_now()
        raw = o.json_bytes(session)
        admitted = o.validate_upgrade_authorization(raw, hashlib.sha256(raw).hexdigest(), o.PUBLISHER_TEAM)
        retention = o.Retention(self.controls)
        primary = None
        try:
            result = o.upgrade_acquisition(phase, [str(self.store)] if roots is None else roots,
                                           str(self.candidate_path), admitted, retention)
        except BaseException as error:
            primary = error
            if hasattr(error, 'expected_stamp') or hasattr(error, 'observations'):
                print(json.dumps(o.diagnostic(error, 'inert-upgrade-fixture')))
            raise
        finally:
            try: retention.close()
            except BaseException as error:
                if primary is None: raise
                primary.cleanup_failures = o.merge_cleanup(getattr(primary,'cleanup_failures',[]),
                                                          getattr(error,'cleanup_failures',[]))
        self.last = result
        return result

    def install_candidate(self):
        shutil.rmtree(self.installed); shutil.copytree(self.candidate_path, self.installed)

    def test_prepare_publish_resume_verifies_actual_candidate_and_retains_scope(self):
        result = self.invoke('prepare')
        self.assertEqual(result['next_action'], 'prepared-request-publication')
        request = json.loads((self.controls/'request.json').read_bytes())
        self.assertEqual(request['roots'], [dict(literal=str(self.home)+'/Library/Application Support/stallionfs',reason='default'),
                                           dict(literal=str(self.store),reason='explicit')])
        before = (self.controls/'request.json').read_bytes()
        result = self.invoke('publish')
        self.assertEqual(result['candidate_access'], 'possible')
        step = json.loads((self.controls/'step-0001.json').read_bytes())
        self.assertEqual(o.retained_digest(step), result['step_sha256'])
        self.install_candidate()
        session = self.authority_now(last_installed=self.session['candidate']['artifact']['id'])
        session['runtime_artifact_id'] = self.session['candidate']['artifact']['id']
        result = self.invoke('verify', session)
        self.assertEqual(result['next_action'], 'verify-settings-discovery-and-command-link')
        self.assertFalse(result['store_access_eligible'])
        self.assertEqual((self.controls/'request.json').read_bytes(), before)
        self.assertEqual(o.app_inventory(self.old_path), self.session['old']['inventory'])

    def test_authority_pair_controller_source_runtime_and_publisher_refuse(self):
        paths = (('controller','observer_sha256'), ('controller','artifact_id'),
                 ('candidate','build','source_build_id'), ('candidate','publisher'),
                 ('old','artifact','id'), ('candidate','store_runtime','descriptor_sha256'))
        for path in paths:
            session = copy.deepcopy(self.session); row = session
            for key in path[:-1]: row = row[key]
            row[path[-1]] = 'f'*64
            with self.subTest(path=path), self.assertRaises(o.Refusal): self.invoke('prepare',session)
        session = copy.deepcopy(self.session); session['candidate']['runtime']['flags'] = ['-S']
        with self.assertRaises(o.Refusal): self.invoke('prepare',session)
        self.assertEqual(list(self.controls.iterdir()), [])
        self.native.assert_not_called(); self.signatures.assert_not_called(); self.runtime.assert_not_called()
        data = (self.candidate_path/o.RESOURCE_ROLES['compatibility']).read_bytes()
        wrong = copy.deepcopy(self.session); wrong['old']['artifact']['id'] = 'f'*64
        with self.assertRaisesRegex(o.Refusal, 'unsupported-predecessor'):
            o.upgrade_pair(wrong, data, self.controller.read_bytes())

    def test_controller_or_candidate_tamper_refuses_before_native_or_store_reads(self):
        self.controller.write_bytes(self.controller.read_bytes()+b'changed')
        with patch.object(o,'observe',side_effect=AssertionError('store read before admission')):
            with self.assertRaisesRegex(o.Refusal, 'controller-digest'): self.invoke('prepare')
        self.native.assert_not_called(); self.runtime.assert_not_called()
        self.assertFalse((self.controls/'step-0000.json').exists())

    def test_separate_candidate_controller_with_old_then_candidate_fixed_runtime(self):
        # The controller is the new admitted observer; its installed runtime starts old.
        self.assertNotEqual(self.session['controller']['observer_sha256'], self.session['old']['artifact']['observer_sha256'])
        wrong = self.authority_now(); wrong['runtime_artifact_id'] = wrong['candidate']['artifact']['id']
        with self.assertRaisesRegex(o.Refusal, 'runtime-pairing'):
            self.invoke('prepare', wrong)
        self.runtime.assert_not_called(); self.native.assert_not_called()
        # Retain the failed transaction; use a fresh explicitly owned output for a new request.
        self.controls = self.base/'second-controls'; self.controls.mkdir(mode=0o700)
        self.invoke('prepare'); self.invoke('publish'); self.install_candidate()
        self.runtime.reset_mock(); self.native.reset_mock()
        with self.assertRaisesRegex(o.Refusal, 'runtime-pairing'): self.invoke('verify')
        self.runtime.assert_not_called(); self.native.assert_not_called()
        session = self.authority_now(last_installed=self.session['candidate']['artifact']['id'])
        session['runtime_artifact_id'] = session['candidate']['artifact']['id']
        self.invoke('verify', session)
        self.runtime.assert_called_once_with(session['candidate']['runtime'])

    def test_scope_changes_and_original_baseline_identity_are_not_rebased(self):
        self.invoke('prepare')
        with self.assertRaisesRegex(o.Refusal, 'root-scope-changed'): self.invoke('publish', roots=[])
        with patch.dict(os.environ, {'STALLIONFS_HOME':str(self.store)}):
            with self.assertRaisesRegex(o.Refusal, 'root-scope-changed'): self.invoke('resume')
        old = self.base/'preserved-store'; self.store.rename(old)
        shutil.copytree(old, self.store)
        with self.assertRaisesRegex(o.Refusal, 'root-identity-changed'): self.invoke('publish')
        self.assertFalse((self.controls/'step-0001.json').exists())

    def test_unknown_activity_and_pending_state_do_not_issue_publication(self):
        self.invoke('prepare')
        self.native.side_effect = lambda *a, **k: dict(idle(), uncertainties=[{'unresolved':True}])
        with self.assertRaisesRegex(o.Refusal, 'root-coverage'): self.invoke('publish')
        self.native.side_effect = self.activity
        pending = self.store/'journals'/('.'+'1'*32+'.json.'+'2'*32)
        pending.write_bytes(b'inert unresolved publication'); pending.chmod(0o600)
        with self.assertRaises(o.Refusal): self.invoke('publish')
        self.assertFalse((self.controls/'step-0001.json').exists())

    def test_rollback_requires_positive_unbroken_history_and_no_handoff(self):
        self.invoke('prepare')
        result = self.invoke('rollback')
        self.assertEqual(result['next_action'], 'keep-exact-predecessor')
        for history in (dict(candidate_access='unknown'), dict(continuous_downtime=False)):
            with self.subTest(history=history), self.assertRaisesRegex(o.Refusal, 'rollback-refused'):
                self.invoke('rollback', self.authority_now(**history))
        session = self.authority_now(); session['cooperation']['boot_id'] = 'new-boot'
        with self.assertRaisesRegex(o.Refusal, 'rollback-refused'): self.invoke('rollback',session)
        # Failed attempts remain preserved and invalidate continuity in that transaction.
        self.controls = self.base/'new-window'; self.controls.mkdir(mode=0o700); self.last = None
        self.invoke('prepare')
        self.invoke('publish')
        with self.assertRaisesRegex(o.Refusal, 'rollback-refused'): self.invoke('rollback')
        result = self.invoke('resume')
        self.assertEqual(result['next_action'], 'finder-repair-exact-candidate-at-fixed-path')

    def test_journal_truncation_and_baseline_change_refuse(self):
        self.invoke('prepare'); self.invoke('publish')
        preserved = (self.controls/'step-0001.json').read_bytes()
        (self.controls/'step-0001.json').unlink()
        with self.assertRaisesRegex(o.Refusal, 'journal-history-binding'): self.invoke('resume')
        (self.controls/'step-0001.json').write_bytes(preserved); (self.controls/'step-0001.json').chmod(0o600)
        baseline = json.loads((self.controls/'baseline.json').read_bytes())
        baseline['roots'][1]['physical_identity'] = [99,99]
        (self.controls/'baseline.json').write_bytes(o.json_bytes(baseline))
        with self.assertRaisesRegex(o.Refusal, 'baseline-binding'): self.invoke('resume')

    def test_intent_failure_before_and_after_durable_write_cannot_grant_rollback(self):
        self.invoke('prepare')
        real = o.Retention.write
        def fail_before(retention, name, *args, **kwargs):
            if name == 'step-0001.json': raise OSError('disk full before intent')
            return real(retention,name,*args,**kwargs)
        with patch.object(o.Retention,'write',fail_before), self.assertRaises(OSError): self.invoke('publish')
        self.assertFalse((self.controls/'step-0001.json').exists())
        with self.assertRaisesRegex(o.Refusal,'rollback-refused'): self.invoke('rollback')
        result = self.invoke('resume')
        self.assertEqual(result['candidate_access'],'unknown')
        self.assertEqual(result['next_action'],'finder-repair-exact-candidate-at-fixed-path')
        self.controls = self.base/'after-intent'; self.controls.mkdir(mode=0o700); self.last = None
        self.invoke('prepare')
        def fail_after(retention, name, *args, **kwargs):
            result = real(retention,name,*args,**kwargs)
            if name == 'step-0001.json': raise KeyboardInterrupt('controller stopped after durable intent')
            return result
        with patch.object(o.Retention,'write',fail_after), self.assertRaises(KeyboardInterrupt): self.invoke('publish')
        step = json.loads((self.controls/'step-0001.json').read_bytes())
        self.assertEqual(step['candidate_access'], 'possible')
        # A stale external continuation pin must stop rather than discard the unreported step.
        with self.assertRaisesRegex(o.Refusal, 'journal-history-binding'): self.invoke('rollback')
        session = self.authority_now(previous_step_sha256=o.retained_digest(step))
        with self.assertRaisesRegex(o.Refusal, 'rollback-refused'): self.invoke('rollback',session)
        result = self.invoke('resume',session)
        self.assertEqual(result['next_action'], 'finder-repair-exact-candidate-at-fixed-path')

    def test_partial_intent_is_retained_and_never_skipped(self):
        self.invoke('prepare')
        path = self.controls/'step-0001.json'; path.write_bytes(b'{'); path.chmod(0o600)
        with self.assertRaises(ValueError): self.invoke('resume')
        self.assertEqual(path.read_bytes(),b'{')

    def test_real_intent_write_fsync_readback_and_close_failures_return_no_action(self, faults=None):
        for fault in faults or ('write', 'file-fsync', 'directory-fsync', 'readback', 'close'):
            with self.subTest(fault=fault):
                self.controls = self.base/('controls-'+fault); self.controls.mkdir(mode=0o700)
                self.last = None; self.invoke('prepare')
                state = dict(fd=None, created=False, hits=0)
                real_open, real_write, real_sync, real_close, real_read = os.open, os.write, os.fsync, os.close, o.retained_read
                def opened(name, flags, *args, **kwargs):
                    fd = real_open(name, flags, *args, **kwargs)
                    if name == 'step-0001.json' and flags & os.O_CREAT:
                        state.update(fd=fd, created=True)
                    return fd
                def written(fd, data):
                    if fault == 'write' and fd == state['fd']:
                        state['hits'] += 1
                        return 0
                    return real_write(fd,data)
                def synced(fd):
                    if state['created'] and ((fault == 'file-fsync' and fd == state['fd'])
                            or (fault == 'directory-fsync' and fd != state['fd'])):
                        state['hits'] += 1
                        raise OSError('injected intent durability failure:'+fault)
                    return real_sync(fd)
                def read(path, *args, **kwargs):
                    if fault == 'readback' and Path(path) == self.controls/'step-0001.json':
                        state['hits'] += 1
                        return b'wrong readback'
                    return real_read(path,*args,**kwargs)
                def closed(fd):
                    real_close(fd)
                    if fault == 'close' and fd == state['fd']:
                        state['fd'] = None
                        state['hits'] += 1
                        raise OSError('injected consumed intent close')
                with patch.object(os,'open',side_effect=opened), patch.object(os,'write',side_effect=written), \
                     patch.object(os,'fsync',side_effect=synced), patch.object(os,'close',side_effect=closed), \
                     patch.object(o,'retained_read',side_effect=read), self.assertRaises((OSError,o.Refusal)) as caught:
                    self.invoke('publish')
                self.assertEqual(state['hits'],1, 'Selected fault must be exercised exactly once')
                error = caught.exception
                if fault in ('file-fsync','directory-fsync'):
                    self.assertIs(type(error),OSError)
                    self.assertEqual(str(error),'injected intent durability failure:'+fault)
                else:
                    self.assertIs(type(error),o.Refusal)
                    self.assertEqual(error.code, {'write':'retention-short-write',
                        'readback':'retention-readback','close':'close-failed'}[fault])
                    if fault == 'close':
                        self.assertTrue(any(row['detail']=='injected consumed intent close'
                                            for row in error.cleanup_failures))
                path = self.controls/'step-0001.json'
                self.assertTrue(path.exists())
                if fault == 'write': self.assertEqual(path.read_bytes(),b'')
                else: self.assertEqual(json.loads(path.read_bytes())['candidate_access'],'possible')
                self.assertEqual(o.app_inventory(self.installed),self.session['old']['inventory'])

    def test_failed_final_control_close_does_not_print_manual_action(self):
        import contextlib
        import io
        raw = o.json_bytes(self.session)
        auth = self.base/'session.json'; auth.write_bytes(raw); auth.chmod(0o600)
        close = o.Retention.close
        def uncertain(retention):
            close(retention)
            if retention.path == self.controls: raise OSError('injected final close uncertainty')
        output = io.StringIO()
        args = ['upgrade','--phase','prepare','--candidate-app',str(self.candidate_path),
                '--authorization',str(auth),'--authorization-sha256',hashlib.sha256(raw).hexdigest(),
                '--publisher',o.PUBLISHER_TEAM,'--retain',str(self.controls),'--root',str(self.store)]
        with patch.object(o.Retention,'close',uncertain),contextlib.redirect_stdout(output):
            self.assertEqual(o.main(args),1)
        result = json.loads(output.getvalue())
        self.assertEqual(result['status'],'blocked'); self.assertNotIn('next_action',result)
        self.assertTrue((self.controls/'step-0000.json').exists())

    def test_candidate_signature_and_archive_failure_preserve_apps_and_store(self):
        before = (self.store/'store.json').read_bytes()
        self.signatures.side_effect = o.Refusal('publisher-or-signature-refused')
        with patch.object(o,'observe',side_effect=AssertionError('store read before signature admission')):
            with self.assertRaisesRegex(o.Refusal,'publisher-or-signature-refused'): self.invoke('prepare')
        self.native.assert_not_called(); self.runtime.assert_not_called()
        self.assertEqual((self.store/'store.json').read_bytes(),before)
        self.assertEqual(o.app_inventory(self.installed),self.session['old']['inventory'])
        self.controls = self.base/'archive-controls'; self.controls.mkdir(mode=0o700)
        self.signatures.side_effect = self.signature
        Path(self.session['candidate']['archive']['path']).write_bytes(b'wrong archive')
        with patch.object(o,'observe',side_effect=AssertionError('store read before archive admission')):
            with self.assertRaisesRegex(o.Refusal,'archive-digest'): self.invoke('prepare')
        self.native.assert_not_called(); self.runtime.assert_not_called()

    def test_actual_installed_state_and_missing_runtime_do_not_launch_fallback(self):
        self.assertEqual(o.upgrade_installed_state(self.session),'old')
        self.install_candidate(); self.assertEqual(o.upgrade_installed_state(self.session),'candidate')
        (self.installed/'Contents/extra').write_bytes(b'foreign')
        self.assertEqual(o.upgrade_installed_state(self.session),'foreign')
        shutil.rmtree(self.installed); self.assertEqual(o.upgrade_installed_state(self.session),'absent')
        for state in ('absent','partial','old','candidate'):
            policy = o.upgrade_recovery(self.session,state,[],runtime_available=False)
            self.assertEqual(policy['next_action'],'native-static-exact-candidate-repair-only')
            self.assertFalse(policy['store_access_eligible'])
        for state in ('foreign','unresolved'):
            self.assertEqual(o.upgrade_recovery(self.session,state,[],runtime_available=False)['next_action'], 'stop-preserve-all')
        with self.assertRaisesRegex(o.Refusal, 'fixed-runtime-unavailable'): self.invoke('prepare')
        self.runtime.assert_not_called(); self.native.assert_not_called()

    def test_unknown_last_installed_never_publishes_or_regains_normal_verification(self):
        self.invoke('prepare')
        session = self.authority_now(last_installed=None)
        with self.assertRaisesRegex(o.Refusal,'publication-already-exposed-or-uncertain'):
            self.invoke('publish',session)
        self.assertFalse((self.controls/'step-0001.json').exists())
        result = self.invoke('resume',session)
        self.assertEqual(result['next_action'],'finder-repair-exact-candidate-at-fixed-path')
        self.assertEqual(result['candidate_access'],'unknown')
        self.assertFalse(result['store_access_eligible'])
        self.install_candidate()
        session = self.authority_now(last_installed=None)
        session['runtime_artifact_id'] = session['candidate']['artifact']['id']
        result = self.invoke('verify',session)
        self.assertEqual(result['next_action'],'verify-exact-candidate-software-only')
        self.assertFalse(result['store_access_eligible'])

    def test_historical_candidate_with_actual_old_cannot_restore_unexposed_state(self):
        self.invoke('prepare')
        result = self.invoke('resume',self.authority_now(last_installed=self.session['candidate']['artifact']['id']))
        self.assertEqual(result['candidate_access'],'possible')
        self.assertEqual(result['next_action'],'finder-repair-exact-candidate-at-fixed-path')
        with self.assertRaisesRegex(o.Refusal,'rollback-refused'): self.invoke('rollback')

    def test_terminal_recovery_stop_cannot_be_overwritten_by_phase(self):
        self.invoke('prepare')
        with patch.object(o,'upgrade_recovery',return_value=dict(candidate_access='none',next_action='stop-preserve-all')) as policy:
            with self.assertRaisesRegex(o.Refusal,'history-unresolved'): self.invoke('publish')
        policy.assert_called_once()
        self.assertFalse((self.controls/'step-0001.json').exists())

    def test_unreferenced_attempt_after_controller_death_blocks_rollback_before_intent(self):
        self.invoke('prepare')
        original = o.Retention.__init__; hits = []
        def interrupted(retention, directory):
            if Path(directory).name.startswith('attempt-'):
                hits.append(str(directory))
                raise KeyboardInterrupt('injected death after durable attempt directory')
            return original(retention,directory)
        with patch.object(o.Retention,'__init__',interrupted):
            with self.assertRaisesRegex(KeyboardInterrupt,'death after durable attempt'): self.invoke('publish')
        self.assertEqual(len(hits),1); self.assertTrue(Path(hits[0]).is_dir())
        self.assertFalse((self.controls/'step-0001.json').exists())
        with self.assertRaisesRegex(o.Refusal,'rollback-refused'): self.invoke('rollback')
        result = self.invoke('resume')
        self.assertEqual(result['candidate_access'],'unknown')
        self.assertEqual(result['next_action'],'finder-repair-exact-candidate-at-fixed-path')
        self.assertTrue(Path(hits[0]).is_dir())

    def test_actual_legacy_predecessor_mapping_derives_build_without_changing_mapping(self):
        expected_build = self.session['old'].pop('build')
        original = copy.deepcopy(self.session['old'])
        self.invoke('prepare')
        self.assertEqual(self.session['old'],original)
        request = json.loads((self.controls/'request.json').read_bytes())
        self.assertEqual(request['authority']['old'],original)
        admitted_builds = list(self.controls.glob('attempt-*/installed-build.json'))
        self.assertEqual(len(admitted_builds),1)
        self.assertEqual(json.loads(admitted_builds[0].read_bytes()),
                         dict(artifact_id=original['artifact']['id'],build=expected_build))
        self.invoke('publish'); self.install_candidate()
        session = self.authority_now(last_installed=self.session['candidate']['artifact']['id'])
        session['runtime_artifact_id'] = session['candidate']['artifact']['id']
        result = self.invoke('verify',session)
        self.assertEqual(result['next_action'],'verify-settings-discovery-and-command-link')
        self.assertEqual(o.app_inventory(self.old_path),original['inventory'])

    def test_legacy_build_requires_bound_old_metadata_and_candidate_build_stays_required(self):
        for fault in ('bundle-version','source','malformed-plist'):
            with self.subTest(fault=fault):
                app = self.base/('bad-'+fault+'.app'); shutil.copytree(self.old_path,app)
                release = copy.deepcopy(self.session['old']); release.pop('build')
                if fault == 'source':
                    path = app/o.DESCRIPTOR; metadata = json.loads(path.read_bytes())
                    metadata['source_build_id'] = 'c'*64; path.write_bytes(o.json_bytes(metadata))
                else:
                    path = app/'Contents/Info.plist'
                    if fault == 'malformed-plist': path.write_bytes(b'invalid plist')
                    else:
                        info = plistlib.loads(path.read_bytes()); info['CFBundleVersion'] = '999'
                        path.write_bytes(plistlib.dumps(info))
                release['inventory'] = o.app_inventory(app)
                release['artifact']['id'] = hashlib.sha256(json.dumps(release['inventory'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
                release['artifact']['descriptor_sha256'] = hashlib.sha256((app/o.DESCRIPTOR).read_bytes()).hexdigest()
                release['store_runtime']['descriptor_sha256'] = release['artifact']['descriptor_sha256']
                controls = self.base/('bad-controls-'+fault); controls.mkdir(mode=0o700)
                retained = o.Retention(controls)
                try:
                    with self.assertRaises((o.Refusal,ValueError)):
                        o.admit_upgrade_app(app,release,retained,'old',allow_legacy_build=True)
                finally: retained.close()
        session = copy.deepcopy(self.session); session['candidate'].pop('build')
        raw = o.json_bytes(session)
        with self.assertRaisesRegex(o.Refusal,'release-schema'):
            o.validate_upgrade_authorization(raw,hashlib.sha256(raw).hexdigest(),o.PUBLISHER_TEAM)
        self.runtime.assert_not_called(); self.native.assert_not_called()

    def test_final_inventory_refusal_retains_original_path_stamps_and_classification(self):
        original_state, original_inventory = o.upgrade_installed_state, o.app_inventory
        capture = dict(state_calls=0,in_state=False,hits=0)
        failure = o.Refusal('app-directory-changed','Contents')
        failure.expected_stamp = [1,2,3,4,5,6,7,8,9]
        failure.observed_stamp = [1,2,3,4,5,6,7,8,10]
        def inventory(path):
            if capture['in_state'] and capture['state_calls'] == 2:
                capture['hits'] += 1
                raise failure
            return original_inventory(path)
        def state(session,errors=None):
            capture['state_calls'] += 1; capture['in_state'] = True
            try: return original_state(session,errors)
            finally: capture['in_state'] = False
        with patch.object(o,'app_inventory',side_effect=inventory),patch.object(o,'upgrade_installed_state',side_effect=state):
            with self.assertRaisesRegex(o.Refusal,'upgrade-installed-state-changed') as caught: self.invoke('prepare')
        self.assertEqual(capture['hits'],1); self.assertEqual(capture['state_calls'],2)
        observed = caught.exception.observations
        self.assertEqual(observed['expected_state'],'old'); self.assertEqual(observed['observed_state'],'unresolved')
        self.assertEqual(observed['errors'],[dict(code='app-directory-changed',path='Contents',detail='app-directory-changed',
                         expected_stamp=failure.expected_stamp,observed_stamp=failure.observed_stamp)])
        self.assertEqual(o.diagnostic(caught.exception,'controller')['observations'],observed)
        self.assertFalse((self.controls/'step-0000.json').exists())


class AcquisitionIntegration(unittest.TestCase):
    setUp = Workflow.setUp
    def test_actual_retained_request_precedes_store_reads_and_denominator_survives(self):
        import hashlib
        home=self.base/'home';home.mkdir(mode=0o700)
        store=home/'Library/Application Support/stallionfs';store.mkdir(parents=True,mode=0o700)
        for parent in (home/'Library',home/'Library/Application Support'):parent.chmod(0o700)
        for name in o.COLLECTIONS:(store/name).mkdir(mode=0o700)
        for name,data in (('.lock',b''),('store.json',b'{"format":1,"application":"stallionfs"}')):
            (store/name).write_bytes(data);(store/name).chmod(0o600)
        controls=self.base/'controls';controls.mkdir(mode=0o700)
        external=self.base/'observer.py';external.write_bytes(b'inert external observation fixture');external.chmod(0o600)
        authorization=authority(home)
        payload={o.DESCRIPTOR:b'descriptor',o.RESOURCE_ROLES['observer']:b'observer',
                 o.RESOURCE_ROLES['compatibility']:b'compatibility',o.RESOURCE_ROLES['native']:b'native'}
        for name,key in ((o.DESCRIPTOR,'descriptor_sha256'),(o.RESOURCE_ROLES['compatibility'],'compatibility_sha256'),
                         (o.RESOURCE_ROLES['native'],'native_sha256')):
            authorization['artifact'][key]=hashlib.sha256(payload[name]).hexdigest()
        authorization['artifact']['observer_sha256']=hashlib.sha256(external.read_bytes()).hexdigest()
        authorization['store_runtime']['descriptor_sha256']=authorization['artifact']['descriptor_sha256']
        payload[o.RESOURCE_ROLES['observer']]=external.read_bytes()
        original_read=o.retained_read
        def read(path,*args,**kwargs):
            if str(path).startswith(o.APP+'/'):return payload[str(path)[len(o.APP)+1:]]
            return original_read(path,*args,**kwargs)
        def native(retention,leaf,auth,request):
            self.assertTrue((controls/'request.json').exists())
            self.assertEqual(leaf.read_bytes(),b'native');self.assertEqual(leaf.stat().st_mode&0o777,0o700)
            self.assertNotIn('activity',json.loads((controls/'request.json').read_bytes()))
            self.assertEqual(request['runtime'],auth['store_runtime'])
            self.assertNotEqual(request['runtime'],auth['runtime'])
            return idle()
        original_observe=o.observe
        def observe(request):
            self.assertTrue((controls/'request.json').exists())
            return original_observe(request)
        retention=o.Retention(controls)
        try:
            with patch.object(pwd,'getpwuid',return_value=type('User',(),dict(pw_dir=str(home)))()), \
                patch.dict(os.environ,{},clear=True),patch.object(o,'__file__',str(external)), \
                patch.object(o,'retained_read',side_effect=read),patch.object(o,'actual_runtime',return_value=o.RUNTIME_CONTRACT), \
                patch.object(o,'app_inventory',return_value=authorization['inventory']), \
                patch.object(o,'static_signature',return_value={}),patch.object(o,'acquire_native',side_effect=native), \
                patch.object(o,'observe',side_effect=observe):
                report=o.acquisition('remove',[str(self.base/'missing-explicit')],authorization,retention)
            self.assertEqual(report['exit_code'],1);self.assertFalse(report['maintenance_clearance'])
            retained=json.loads((controls/'request.json').read_bytes())
            self.assertEqual(report['declared_roots'],retained['roots'])
            self.assertEqual(len(report['roots']),2);self.assertEqual(report['roots'][0]['blockers'],[])
            self.assertTrue(report['roots'][1]['blockers'])
            self.assertEqual(json.loads((controls/'observation.json').read_bytes()),report)
        finally:retention.close()

    def test_signature_timeout_retains_uncertain_child_without_signalling(self):
        directory=self.base/'controls';directory.mkdir(mode=0o700);retention=o.Retention(directory)
        self.addCleanup(retention.close)
        from unittest.mock import Mock
        process=Mock(pid=987654321);process.poll.return_value=None
        with patch('subprocess.Popen',return_value=process),patch.object(o.os,'set_blocking'), \
            patch.object(o.time,'monotonic',side_effect=[0,31]):
            with self.assertRaisesRegex(o.Refusal,'signature-helper-lifetime'):
                o.static_signature(self.base/'fixture','anchor apple generic and identifier "fixture"',retention,'signature')
        process.kill.assert_not_called();process.terminate.assert_not_called();process.stdout.close.assert_not_called()
        self.assertFalse(json.loads((directory/'signature.json').read_bytes())['complete'])
        o._UNRESOLVED_TOOLS.remove(process)


class OutputBoundary(unittest.TestCase):
    setUp = Workflow.setUp
    def test_app_or_requested_store_retention_rejected_before_writes(self):
        controls=self.base/'controls';controls.mkdir(mode=0o700);retention=o.Retention(controls)
        self.addCleanup(retention.close)
        fake=type('User',(),dict(pw_dir=str(self.base)))()
        with patch.object(pwd,'getpwuid',return_value=fake),patch.dict(os.environ,{},clear=True):
            with self.assertRaisesRegex(o.Refusal,'overlaps'):
                o.acquisition('remove',[str(controls)],self.authority,retention)
            self.assertEqual(list(controls.iterdir()),[])
            with patch.object(o,'APP',str(controls.parent)):
                with self.assertRaisesRegex(o.Refusal,'overlaps'):
                    o.acquisition('remove',[],self.authority,retention)
            self.assertEqual(list(controls.iterdir()),[])

    def test_oversized_denominator_retained_without_reading_stores(self):
        controls=self.base/'controls';controls.mkdir(mode=0o700);retention=o.Retention(controls)
        self.addCleanup(retention.close)
        fake=type('User',(),dict(pw_dir=str(self.base)))()
        with patch.object(pwd,'getpwuid',return_value=fake),patch.dict(os.environ,{},clear=True), \
             patch.object(o,'observe',side_effect=AssertionError('store read before request limit')):
            with self.assertRaisesRegex(o.Refusal,'request-root-budget'):
                o.acquisition('remove',['/explicit/'+str(i) for i in range(65)],self.authority,retention)
        request=json.loads((controls/'request.json').read_bytes())
        self.assertEqual(len(request['roots']),66)

    def test_app_inventory_closes_each_member(self):
        app=self.base/'fixture.app';app.mkdir(mode=0o755)
        for i in range(300):(app/str(i)).write_bytes(b'x')
        opened=set();peak=[0];realopen=os.open;realclose=os.close
        def track(*args,**kwargs):
            fd=realopen(*args,**kwargs);opened.add(fd);peak[0]=max(peak[0],len(opened));return fd
        def close(fd):opened.discard(fd);return realclose(fd)
        with patch.object(o.os,'open',side_effect=track),patch.object(o.os,'close',side_effect=close):
            self.assertEqual(len(o.app_inventory(app)),300)
        self.assertLess(peak[0],20);self.assertEqual(opened,set())


    def test_full_cli_rejected_output_never_receives_failure_json(self):
        import contextlib
        import io
        controls=self.base/'controls';controls.mkdir(mode=0o700)
        auth=self.base/'authorization.json';auth.write_bytes(b'{}');auth.chmod(0o600)
        fake=type('User',(),dict(pw_dir=str(self.base)))()
        args=['remove','--authorization',str(auth),'--authorization-sha256','a'*64,
              '--publisher',o.PUBLISHER_TEAM,'--retain',str(controls)]
        aliases=[str(controls),str(self.base/'not-present/../controls'),
                 '/system/volumes/data'+str(controls)]
        for literal in aliases:
            output=io.StringIO()
            with patch.object(o,'validate_authorization',return_value=self.authority), \
                 patch.object(pwd,'getpwuid',return_value=fake),patch.dict(os.environ,{},clear=True), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(o.main([*args,'--root',literal]),1)
            self.assertEqual(list(controls.iterdir()),[])
            self.assertIn('overlap',json.loads(output.getvalue())['error']['code'])
        with patch.object(o,'APP',str(self.base)),patch.object(o,'validate_authorization',return_value=self.authority), \
             patch.object(pwd,'getpwuid',return_value=fake),patch.dict(os.environ,{},clear=True), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(o.main(args),1)
        self.assertEqual(list(controls.iterdir()),[])

    def test_main_reports_close_uncertainty_after_attempting_every_descriptor(self):
        import contextlib
        import io
        controls=self.base/'controls';controls.mkdir(mode=0o700)
        auth=self.base/'authorization.json';auth.write_bytes(b'{}');auth.chmod(0o600)
        args=['remove','--authorization',str(auth),'--authorization-sha256','a'*64,
              '--publisher',o.PUBLISHER_TEAM,'--retain',str(controls)]
        realclose=os.close;calls=[]
        def close(fd):
            realclose(fd);calls.append(fd)
            if len(calls)==1:raise OSError('injected close uncertainty')
        output=io.StringIO()
        with patch.object(o,'validate_authorization',return_value=self.authority), \
             patch.object(o,'acquisition',return_value=dict(status='no-known-blockers-at-observation',exit_code=0)), \
             patch.object(o.os,'close',side_effect=close),patch.object(o,'retained_read',return_value=b'{}'), \
             contextlib.redirect_stdout(output):
            self.assertEqual(o.main(args),1)
        result=json.loads(output.getvalue())
        self.assertEqual(result['exit_code'],1);self.assertFalse(result['cleanup_complete'])
        self.assertEqual(result['error']['code'],'retention-close-uncertainty')
        self.assertGreater(len(calls),1)


class CollectorFailures(unittest.TestCase):
    setUp = Workflow.setUp
    def test_verifier_collection_and_stream_close_uncertainty_retained(self):
        from unittest.mock import Mock
        for mode in ('collector','stream-close'):
            directory=self.base/mode;directory.mkdir(mode=0o700);retention=o.Retention(directory)
            process=Mock(pid=987654321);process.poll.return_value=0
            process.stdout.fileno.return_value=123
            if mode=='stream-close':process.stdout.close.side_effect=OSError('close uncertainty')
            try:
                with patch('subprocess.Popen',return_value=process), \
                     patch.object(o.os,'set_blocking',side_effect=OSError('collector uncertainty') if mode=='collector' else None), \
                     patch('select.select',return_value=([process.stdout],[],[])),patch.object(o.os,'read',return_value=b''):
                    with self.assertRaisesRegex(o.Refusal,'signature-helper-lifetime'):
                        o.static_signature(self.base/'fixture','anchor apple generic and identifier "fixture"',retention,'verify')
                receipt=json.loads((directory/'verify.json').read_bytes())
                self.assertEqual(receipt['pid'],process.pid);self.assertFalse(receipt['complete'])
                self.assertFalse(receipt['cleanup_complete']);self.assertIsNotNone(receipt['collector_error'])
            finally:
                if process in o._UNRESOLVED_TOOLS:o._UNRESOLVED_TOOLS.remove(process)
                retention.close()


class BoundNativeConsumer(unittest.TestCase):
    setUp = Workflow.setUp
    def test_raw_native_output_count_digest_and_outcome_are_bound(self):
        import hashlib
        from unittest.mock import Mock
        authorization=authority(self.base)
        native=dict(schema=1,scope='global-kernel-snapshot',complete=True,uncertainties=[],boot_id='boot',
                    started_ns=11,finished_ns=12,mounts=[],processes=[dict(pid=0,ppid=0,uid=0,start_sec=0,start_usec=0,
                        path=None,path_errno=2,stable=True,kernel=True)],sessions=[])
        raw=o.json_bytes(native)
        receipt=dict(schema=1,worker_pid=9,complete=True,reaped=True,returncode=0,outcome='success',
            streams_eof=True,output_durable=True,output_readback=True,directory_bound=True,
            output_bound=True,cleanup_complete=True,io_error=False,close_errors=False,
            output_bytes=len(raw),output_sha256=hashlib.sha256(raw).hexdigest())
        request=dict(acquisition=dict(acquired_ns=10),cooperation=authorization['cooperation'])
        authorization['artifact']['native_sha256']=hashlib.sha256(b'leaf').hexdigest()
        for index,changed in enumerate(({},dict(output_bytes=1),dict(output_sha256='0'*64),
                                       dict(returncode=1),dict(outcome='error'),dict(output_readback=False))):
            directory=self.base/str(index);directory.mkdir(mode=0o700);retention=o.Retention(directory)
            leaf=directory/'leaf';leaf.write_bytes(b'leaf');leaf.chmod(0o700)
            process=Mock(pid=8);process.wait.return_value=0
            def launch(*args,**kwargs):
                for name,data in (('native.json',raw),('native-completion.json',o.json_bytes({**receipt,**changed}))):
                    path=directory/'native'/name;path.write_bytes(data);path.chmod(0o600)
                return process
            try:
                with patch.object(o,'static_signature',return_value={}),patch('subprocess.Popen',side_effect=launch):
                    if changed:
                        with self.assertRaises(o.Refusal):o.acquire_native(retention,leaf,authorization,request)
                    else:self.assertEqual(o.acquire_native(retention,leaf,authorization,request)['uncertainties'],[])
            finally:retention.close()

    def test_acquired_store_runtime_matches_exact_dormant_pending_request(self):
        pending_spec=importlib.util.spec_from_file_location('pending_fixture',SOURCE/'tests/test_maintenance_observer.py')
        module=importlib.util.module_from_spec(pending_spec);pending_spec.loader.exec_module(module)
        fixture=module.Inert(methodName='test_O1_empty_actual_store');fixture.setUp()
        try:
            fields,record,journal,stage=fixture.creation()
            authorization=authority(fixture.base);authorization['store_runtime']=fields['runtime']
            home=fixture.base
            (home/'Library/Application Support').mkdir(parents=True,mode=0o700)
            (home/'Library').chmod(0o700)
            fake=type('User',(),dict(pw_dir=str(home)))()
            with patch.object(pwd,'getpwuid',return_value=fake),patch.dict(os.environ,{},clear=True):
                request=o.original_request('reinstall',[str(fixture.root)],authorization)
            request['activity']=idle()
            report=o.observe(request)
            entry=next(row for root in report['roots'] for row in root['entries'] if row.get('operation')=='native-create')
            self.assertTrue(entry['runtime_matches']);self.assertEqual(entry['status'],'pending')
            self.assertTrue(entry['blocking']);self.assertFalse(report['maintenance_clearance'])
        finally:fixture.doCleanups()


class PopulatedUpgrade(Upgrade):
    """Real parser sources and controls; extension loading/hosting identity are inert doubles."""
    volume_uuid = '12345678-1234-1234-1234-123456789abc'

    def release(self, app, source, observer, predecessors=None):
        import importlib.machinery
        result = super().release(app, source, observer, predecessors)
        package = app/'Contents/Resources/Runtime/CLI/lib/python3.13/site-packages/stallionfs'
        package.mkdir(parents=True)
        for name in o.VALIDATOR_SOURCES:
            (package/(name+'.py')).write_bytes((SOURCE/'stallionfs'/(name+'.py')).read_bytes())
        for name in ('_scan', '_image'):
            (package/(name+importlib.machinery.EXTENSION_SUFFIXES[0])).write_bytes(b'inert extension input')
        result['inventory'] = o.app_inventory(app)
        result['artifact']['id'] = hashlib.sha256(json.dumps(result['inventory'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        return result

    def setUp(self):
        super().setUp()
        self.hosting_calls = []
        self.validators.side_effect = self.loaded
        def attachments(retention,request):
            data=plistlib.dumps({'images':[]})
            receipt=dict(argv=['/usr/bin/hdiutil','info','-plist'],complete=True,cleanup_complete=True,
                reaped=True,streams_eof=True,returncode=0,collector_error=None,started_ns=request['acquisition']['acquired_ns'],
                finished_ns=request['acquisition']['acquired_ns']+1,output_bytes=len(data),output_sha256=hashlib.sha256(data).hexdigest())
            return o.attachment_inventory(data,receipt,request)
        self.attachments=self.stack.enter_context(patch.object(o,'acquire_attachments',side_effect=attachments))

    @__import__('contextlib').contextmanager
    def loaded(self, release):
        real_spec = importlib.util.spec_from_file_location
        owner = self
        class InertExtension:
            def create_module(self, spec): return None
            def exec_module(self, module):
                module.__file__ = module.__spec__.origin
                if module.__name__.endswith('._scan'):
                    module._private_directory = lambda *args: (_ for _ in ()).throw(AssertionError('native directory action'))
                    def hosting(fd):
                        owner.hosting_calls.append(fd)
                        return dict(volume_uuid=owner.volume_uuid,file_id=os.fstat(fd).st_ino)
                    module.hosting_identity = hosting
        def spec(name, location, *args, **kwargs):
            if name in ('stallionfs._scan','stallionfs._image'):
                return importlib.util.spec_from_loader(name,InertExtension(),origin=str(location))
            return real_spec(name,location,*args,**kwargs)
        site = str(self.installed/'Contents/Resources/Runtime/CLI/lib/python3.13/site-packages')
        with patch.dict(o.RUNTIME_CONTRACT, {'site_packages':site}), patch.object(importlib.util,'spec_from_file_location',side_effect=spec):
            with INSTALLED_VALIDATORS(release) as validators:
                yield validators

    def save(self, path, value):
        path.write_bytes(o.json_bytes(dict(format=1, **value))); path.chmod(0o600)

    def ident(self, path): return o.pair(path.stat())

    def lifecycle(self, path, payload):
        self.save(self.store/'lifecycle'/(path.name+'.json'),dict(id=path.name,generation='f'*32,
            status='open',enrolled=False,object=self.ident(path),payload=self.ident(payload)))

    def ordinary(self, backend):
        spec = dict(source='/inert/source',commit='6'*40,origin='/inert/origin',key='inert',command=[],
                    system='Darwin',release='inert',machine='arm64')
        if backend == 'image': spec.update(backend='image',capacity_gib=1)
        seed = hashlib.sha256(json.dumps(dict(format=1,**spec),sort_keys=True).encode()).hexdigest()
        spath = self.store/'seeds'/seed; spath.mkdir(mode=0o700)
        self.save(spath/'meta.json',dict(id=seed,created=123.0,**spec))
        workspace = ('a' if backend == 'folder' else 'b')*32
        path = self.store/'workspaces'/workspace; path.mkdir(mode=0o700)
        meta = dict(id=workspace,seed=seed,name='',branch='stallionfs/'+workspace,commit=spec['commit'],created=124.0)
        for directory in (spath,path):
            if backend == 'folder':
                payload = directory/'repo'; payload.mkdir(mode=0o755)
                (payload/'payload.txt').write_bytes(b'preserved contents\n'); (payload/'payload.txt').chmod(0o640)
            else:
                payload = directory/'workspace.sparseimage'; payload.write_bytes(b'opaque image payload\x00'); payload.chmod(0o600)
        if backend == 'image':
            meta.update(backend='image',capacity_gib=1); (path/'volume').mkdir(mode=0o700)
            self.save(path/'ready.json',dict(id=workspace))
        self.save(path/'meta.json',meta); self.lifecycle(path,path/('repo' if backend == 'folder' else 'workspace.sparseimage'))
        return path, seed

    def native_object(self, seed, *, modern=True):
        path = self.store/'workspaces'/('1'*32); path.mkdir(mode=0o700)
        (path/'volume').mkdir(mode=0o700)
        image = path/'image.sfs'; image.write_bytes(b'opaque native contents\x00preserved'); image.chmod(0o600)
        anchor = dict(generation=2,root_digest='4'*64,committed_end=16384)
        target = dict(component='image.sfs',parent=[1,2],object=self.ident(path),file=self.ident(image),uuid='5'*32,anchor=anchor)
        receipt = dict(status=0,uuid=target['uuid'],device=target['file'][0],inode=target['file'][1],
            poisoned=False,transaction_active=False,phase=0,system_errno=0,coverage=0,incomplete_reason=0,
            limit_reason=0,fence_attempted=0,fence_succeeded=0,physical_end=16384,**anchor)
        budget_keys = ('raw_cells','metadata_read_bytes','metadata_hash_bytes','checks','auxiliary_bytes','auxiliary_io_bytes')
        result = dict(identity=dict(file=target['file'],uuid=target['uuid']),anchor=anchor,candidate_complete=True,
            import_committed=True,verified=True,creation_disposition='known_created',outcome='candidate-created',ok=True,
            creation_attempted=True,reason='none',error_code=0,local_error=0,descriptor_close_error=0,
            failed_record=(1<<64)-1,observed_file=target['file'],resources=dict(entries=1,scratch_bytes=4096,
            xattr_memory_high_water=0,policy='finite-traversal-v2',budget={k:4096 for k in budget_keys}),
            budget_explicit=False,budget_saturated=False,parent_steps=0,abort=None,failure_path_error=0,
            xattr_names_scratch_high_water=0,failure_path=None)
        for key in ('creation','original','commit','verify','close','reopen','reopen_close'): result[key]=dict(receipt)
        result['creation']['generation']=1; result['commit'].update(fence_attempted=3,fence_succeeded=3);result['verify']['coverage']=1
        origin = dict(id=path.name,seed=seed,transaction='2'*32,name='',branch='stallionfs/'+path.name,commit='6'*40,
            created=123.5,backend='native-image',ownership='store-created',state='candidate',capacity_gib=1,
            native_image=target,creation_proof='native-create.json')
        created = dict(operation='native-create',id=path.name,transaction=origin['transaction'],seed=seed,
                       native_image=target,import_contract='prepared-tree-v1',result=result)
        with self.loaded(self.session['old']) as validators:
            from stallionfs import _native_create_recovery as recovery, _native, _native_interval as interval
            metadata = dict(recovery.installed_metadata(origin,self.ident(path.parent),'production',str(_native.HOST)),state='installed')
            live = validators.binding.historical_target(path,metadata)
            guard = dict(receipt,core_consumed=True,parent_close_errno=0)
            proof = dict(operation='native-install',id=path.name,transaction=origin['transaction'],target=metadata['native_image'],
                complete=True,guard=guard,previous_installation=dict(metadata=dict(metadata,state='installed-unconfirmed'),
                first_mount_attempted=False,rename_attempted=True),first_mount_attempted=True,
                first_use=dict(accepted=True,operation='7'*32,write_probe=dict(complete=True,path=str(path/'volume/repo'/('.stallionfs-write-'+'9'*32)))))
            self.save(path/'meta.json',metadata);self.save(path/'native-create.json',created);self.save(path/'native-install.json',proof)
            operations=path/'native-operations';operations.mkdir(mode=0o700)
            mount=dict(path=str(path/'volume'),filesystem='stallionfs',owner=os.getuid(),flags=0,fsid=[11,22],readonly=False,ignore_ownership=False)
            token=interval.token('7'*32,path,metadata,live,mount)
            for name,action,labels,argv in (('7'*32,'native-mount',('verify-package','discover','mount'),
                    (_native.package_argv(_native.HOST),[str(_native.HOST),'--discover-json'],['/sbin/mount','-F','-t','stallionfs',str(path),str(path/'volume')])),
                    ('8'*32,'native-unmount',('unmount',),(['/sbin/umount',str(path/'volume')],))):
                directory=operations/name;directory.mkdir(mode=0o700);helpers=[]
                for index,(label,arguments) in enumerate(zip(labels,argv)):
                    output=directory/(str(index).zfill(2)+'-'+label);output.mkdir(mode=0o700)
                    for stream in ('stdout','stderr'):(output/stream).touch(mode=0o600)
                    helpers.append(dict(label=label,argv=arguments,child_pending=False,pid=123,reaped=True,returncode=0,
                        outcome='success',stdout=str(output/'stdout'),stderr=str(output/'stderr')))
                record=dict(operation=action,workspace=path.name,id=name,target=live,outcome='complete',child_pending=False,
                    helpers=helpers,previous_unresolved=None,current_guard=guard,lifecycle_version=1,ordinary_interval=token)
                if action=='native-mount':record.update(mount_attempted=True,observed_mount=mount,interval_seed=interval.seed(name,path,live),write_probe=proof['first_use']['write_probe'])
                else:record.update(before_mount=mount,observed_mount=None)
                if modern and action=='native-mount':
                    activation=dict(version=1,operation=name,action=action,transaction=origin['transaction'],workspace=path.name,
                        nonce='d'*32,parent=live['parent'],file=live['file'],uuid=live['uuid'],physical_end=16384,**anchor)
                    record['activation_protocol']=1
                    helpers[-1].update(activation_version=1,activation=activation,
                        argv=validators.activation.argv(activation,'stallionfs',path))
                    attempt=directory/('activation-'+activation['nonce']);attempt.mkdir(mode=0o700)
                    for control in ('gate','lease','claim'):(attempt/control).touch(mode=0o600)
                    (attempt/'request').write_bytes(validators.activation.encode(activation));(attempt/'request').chmod(0o600)
                self.save(directory/'record.json',record)
            self.save(path/'native-mount.json',dict(state='absent',target=live,operation='8'*32,current_guard=guard,lifecycle_version=1,ordinary_interval=token))
            binding_path=path/'native-binding.json';binding_path.touch(mode=0o600)
            binding=dict(schema=1,epoch='9'*32,authority='installation',workspace=path.name,transaction=origin['transaction'],
                historical=validators.binding.fingerprint(origin,created,proof),origin_target=metadata['native_image'],
                stable=dict(volume_uuid=self.volume_uuid,collection=path.parent.stat().st_ino,object=path.stat().st_ino,file=image.stat().st_ino),
                admitted_target=live,anchor=anchor,guard=guard,complete=True,publication_file_id=binding_path.stat().st_ino)
            self.save(binding_path,binding)
        self.lifecycle(path,image)
        return path

    def snapshot_store(self):
        return {str(p.relative_to(self.store)):(p.stat().st_mode,p.stat().st_ino,p.stat().st_mtime_ns,
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None) for p in self.store.rglob('*')}

    def test_populated_folder_image_and_native_history_upgrade_preserves_data(self):
        _,seed=self.ordinary('folder');self.ordinary('image');self.native_object(seed)
        before=self.snapshot_store()
        self.invoke('prepare');self.invoke('publish');self.install_candidate()
        session=self.authority_now(last_installed=self.session['candidate']['artifact']['id'])
        session['runtime_artifact_id']=session['candidate']['artifact']['id']
        result=self.invoke('verify',session)
        self.assertEqual(result['next_action'],'verify-settings-discovery-and-command-link')
        self.assertEqual(before,self.snapshot_store());self.assertGreaterEqual(len(self.hosting_calls),18)

    def test_populated_unknown_lineage_activity_and_substitution_refuse(self):
        _,seed=self.ordinary('folder');path=self.native_object(seed)
        cases=('origin','pending','marker','backing','lifecycle','volume-uuid')
        for fault in cases:
            with self.subTest(fault=fault):
                target={'origin':path/'meta.json','pending':path/'native-operations'/('8'*32)/'record.json',
                    'marker':path/'native-mount.json','lifecycle':self.store/'lifecycle'/(path.name+'.json')}.get(fault)
                saved=target.read_bytes() if target else None
                if target:
                    value=json.loads(saved)
                    if fault=='origin':value['origin']['transaction']='0'*32
                    elif fault=='pending':value['outcome']='prepared';value['child_pending']=True
                    elif fault=='marker':value['operation']='0'*32
                    else:value['payload']=[1,2]
                    target.write_bytes(o.json_bytes(value))
                elif fault=='backing':
                    (path/'image.sfs').rename(self.base/'saved-image');(path/'image.sfs').write_bytes(b'foreign');(path/'image.sfs').chmod(0o600)
                else:self.volume_uuid='98765432-1234-1234-1234-123456789abc'
                before=self.snapshot_store()
                with self.assertRaisesRegex(o.Refusal,'root-coverage'):self.invoke('prepare')
                self.assertEqual(before,self.snapshot_store());self.assertFalse((self.controls/'step-0000.json').exists())
                if target:target.write_bytes(saved)
                elif fault=='backing':(path/'image.sfs').unlink();(self.base/'saved-image').rename(path/'image.sfs')
                else:self.volume_uuid=type(self).volume_uuid
                self.controls=self.base/('controls-'+fault);self.controls.mkdir(mode=0o700)

    def test_admitted_loader_rejects_changed_missing_ambient_and_outside_closure(self):
        import types
        package=self.installed/'Contents/Resources/Runtime/CLI/lib/python3.13/site-packages/stallionfs'
        path=package/'_native_binding.py';original=path.read_bytes()
        for fault in ('changed','missing','ambient','outside'):
            with self.subTest(fault=fault):
                release=copy.deepcopy(self.session['old'])
                if fault=='changed':path.write_bytes(original+b'\n')
                elif fault=='missing':release['inventory']=[row for row in release['inventory'] if row['path']!=str(path.relative_to(self.installed))]
                elif fault=='ambient':sys.modules['stallionfs']=types.ModuleType('stallionfs')
                else:
                    path.write_bytes(original+b'\nimport stallionfs.images\n')
                    row=next(row for row in release['inventory'] if row['path']==str(path.relative_to(self.installed)))
                    row['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
                try:
                    with self.assertRaisesRegex(o.Refusal,{'changed':'module-digest','missing':'module-missing',
                            'ambient':'import-origin','outside':'outside-closure'}[fault]):
                        with self.loaded(release):self.fail('invalid loader reached consumer')
                finally:
                    path.write_bytes(original)
                    if fault=='ambient':sys.modules.pop('stallionfs',None)
                self.assertFalse(any(n=='stallionfs' or n.startswith('stallionfs.') for n in sys.modules))

    def test_orphan_lifecycle_and_live_hosting_change_refuse_without_action(self):
        _,seed=self.ordinary('folder');path=self.native_object(seed)
        orphan=self.store/'lifecycle'/('d'*32+'.json')
        self.save(orphan,dict(id='d'*32))
        with self.assertRaisesRegex(o.Refusal,'root-coverage'):self.invoke('prepare')
        orphan.unlink();self.controls=self.base/'hosting-controls';self.controls.mkdir(mode=0o700)
        real=self.loaded
        @__import__('contextlib').contextmanager
        def changing(release):
            with real(release) as validators:
                original=validators.scan.hosting_identity;calls=[]
                def hosting(fd):
                    calls.append(fd);result=original(fd)
                    if len(calls)>3:result['volume_uuid']='98765432-1234-1234-1234-123456789abc'
                    return result
                validators.scan.hosting_identity=hosting
                yield validators
                self.assertGreater(len(calls),3)
        self.validators.side_effect=changing
        with self.assertRaisesRegex(o.Refusal,'root-coverage'):self.invoke('prepare')
        self.assertFalse((self.controls/'step-0000.json').exists())

    def test_attachment_capture_and_global_refusal_contract(self):
        import time
        request=dict(acquisition=dict(acquired_ns=1),cooperation=dict(boot_id='boot'))
        for images in ([],[{'image-path':'/unrelated/image.dmg','system-entities':[{'dev-entry':'/dev/disk42'}]}],
                       [{'image-path':'/unfollowed/alias.sparseimage','system-entities':[{'dev-entry':'/dev/disk43'}]}]):
            data=plistlib.dumps(dict(images=images))
            receipt=dict(argv=['/usr/bin/hdiutil','info','-plist'],complete=True,cleanup_complete=True,
                reaped=True,streams_eof=True,returncode=0,collector_error=None,started_ns=2,finished_ns=3,
                output_bytes=len(data),output_sha256=hashlib.sha256(data).hexdigest())
            result=o.attachment_inventory(data,receipt,request)
            self.assertEqual(result['detached'],not images);self.assertEqual(result['boot_id'],'boot')
            for field,value in (('started_ns',0),('complete',False),('reaped',False),('streams_eof',False),
                                ('cleanup_complete',False),('returncode',1),('output_sha256','0'*64)):
                with self.subTest(field=field),self.assertRaisesRegex(o.Refusal,'image-inventory-capture'):
                    o.attachment_inventory(data,dict(receipt,**{field:value}),request)
        data=plistlib.dumps({'images':[]})
        for fault in ('none','timeout','readback'):
            directory=self.base/('capture-'+fault);directory.mkdir(mode=0o700);retained=o.Retention(directory)
            readfd,writefd=os.pipe();os.write(writefd,data);os.close(writefd)
            stream=os.fdopen(readfd,'rb',buffering=0)
            process=type('InertProcess',(),dict(pid=4242,stdout=stream,poll=lambda _self:None if fault=='timeout' else 0))()
            original=o.retained_read
            hits=[]
            def readback(path,*args,**kwargs):
                if fault=='readback' and Path(path).name=='image-attachments.output':
                    hits.append(str(path));return b'wrong'
                return original(path,*args,**kwargs)
            ticks=iter((0,1,31))
            try:
                with ExitStack() as stack:
                    launch=stack.enter_context(patch('subprocess.Popen',return_value=process))
                    stack.enter_context(patch.object(o,'retained_read',side_effect=readback))
                    if fault=='timeout':stack.enter_context(patch.object(time,'monotonic',side_effect=lambda:next(ticks,31)))
                    if fault=='none':
                        captured=ACQUIRE_ATTACHMENTS(retained,request);self.assertTrue(captured['detached'])
                    else:
                        with self.assertRaisesRegex(o.Refusal,'signature-helper-lifetime-or-output-unresolved'):
                            ACQUIRE_ATTACHMENTS(retained,request)
                    launch.assert_called_once()
                    self.assertEqual(launch.call_args.args[0],['/usr/bin/hdiutil','info','-plist'])
                    self.assertEqual(len(hits),int(fault=='readback'))
                record=json.loads((directory/'image-attachments.json').read_bytes())
                self.assertEqual(record['complete'],fault=='none')
                self.assertEqual(record['reaped'],fault!='timeout')
                self.assertTrue((directory/'image-attachments.output').exists())
            finally:
                stream.close()
                if process in o._UNRESOLVED_TOOLS:o._UNRESOLVED_TOOLS.remove(process)
                retained.close()
        self.ordinary('image')
        self.attachments.side_effect=lambda *a:dict(detached=False)
        with self.assertRaisesRegex(o.Refusal,'root-coverage'):self.invoke('prepare')
        self.assertFalse((self.controls/'step-0000.json').exists())

    def test_schema2_reconciliation_basis_is_required_and_bound(self):
        _,seed=self.ordinary('folder');path=self.native_object(seed,modern=False)
        records={}
        for location in (path/'native-operations').glob('*/record.json'):
            row=json.loads(location.read_bytes());row.pop('format')
            for key in ('lifecycle_version','interval_seed','ordinary_interval'):row.pop(key,None)
            self.save(location,row);records[location.parent.name]=row
        failed=copy.deepcopy(records['7'*32]);failed.update(id='6'*32,outcome='incomplete',observed_mount=None)
        failed.pop('write_probe',None)
        failure_path=path/'native-operations'/('6'*32)
        shutil.copytree(path/'native-operations'/('7'*32),failure_path)
        for helper in failed['helpers']:
            for stream in ('stdout','stderr'):
                helper[stream]=str(failure_path/Path(helper[stream]).parent.name/stream)
        failed['helpers'][-1].update(outcome='error',returncode=1)
        self.save(failure_path/'record.json',failed);records['6'*32]=failed
        records['7'*32]['previous_unresolved']=dict(operation='native-mount',id='6'*32,
            record=str(failure_path/'record.json'),outcome='incomplete')
        self.save(path/'native-operations'/('7'*32)/'record.json',records['7'*32])
        marker=json.loads((path/'native-mount.json').read_bytes());marker.pop('format')
        for key in ('lifecycle_version','ordinary_interval'):marker.pop(key,None)
        self.save(path/'native-mount.json',marker)
        metadata=json.loads((path/'meta.json').read_bytes());metadata.pop('format')
        binding=json.loads((path/'native-binding.json').read_bytes());binding.pop('format')
        with self.loaded(self.session['old']) as validators:
            access=o.Existing(str(self.store),o.LIMITS);access.admit()
            try:
                access.read(path/'meta.json')
                for name in records:access.read(path/'native-operations'/name/'record.json')
                scope=validators.reconcile.scope(access,path,metadata,records,binding['stable'],binding['admitted_target'])
                receipt=dict(schema=1,id='c'*32,authority='legacy-offline-reconciliation',scope=scope,
                    scope_digest=validators.reconcile.digest(scope),marker=marker,
                    marker_hash=hashlib.sha256((path/'native-mount.json').read_bytes()).hexdigest(),guard=binding['guard'],complete=True)
            finally:self.assertEqual(access.finish(),[])
        directory=path/'native-reconciliations';directory.mkdir(mode=0o700)
        location=directory/(receipt['id']+'.json');self.save(location,receipt)
        binding.update(schema=2,authority='legacy-offline-reconciliation',basis=dict(version=1,reconciliation=receipt['id'],
            sha256=hashlib.sha256(location.read_bytes()).hexdigest(),scope_digest=receipt['scope_digest']))
        self.save(path/'native-binding.json',binding)
        before=self.snapshot_store();self.invoke('prepare');self.assertEqual(before,self.snapshot_store())
        changed=copy.deepcopy(receipt);changed['scope']['endpoints']=[];self.save(location,changed)
        with self.assertRaisesRegex(o.Refusal,'root-coverage'):self.invoke('publish')
        self.assertFalse((self.controls/'step-0001.json').exists())

    def test_activation_controls_require_bound_request_claim_and_idle_leases(self):
        import fcntl
        _,seed=self.ordinary('folder');path=self.native_object(seed)
        activation=path/'native-operations'/('7'*32)/('activation-'+'d'*32)
        request=(activation/'request').read_bytes()
        for fault in ('request','claim','missing-claim','lease'):
            held=None
            with self.subTest(fault=fault):
                if fault=='request':(activation/'request').write_bytes(request+b'changed')
                elif fault=='claim':(activation/'claim').write_bytes(b'changed')
                elif fault=='missing-claim':(activation/'claim').rename(self.base/'saved-claim')
                else:
                    held=os.open(activation/'lease',os.O_RDONLY);fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
                try:
                    before=self.snapshot_store()
                    with self.assertRaisesRegex(o.Refusal,'root-coverage'):self.invoke('prepare')
                    self.assertEqual(before,self.snapshot_store())
                    self.assertFalse((self.controls/'step-0000.json').exists())
                finally:
                    if held is not None:os.close(held)
                    if fault=='request':(activation/'request').write_bytes(request)
                    elif fault=='claim':(activation/'claim').write_bytes(b'')
                    elif fault=='missing-claim':(self.base/'saved-claim').rename(activation/'claim')
                self.controls=self.base/('activation-'+fault);self.controls.mkdir(mode=0o700)

    def idle_state(self, path, status):
        state=json.loads((self.store/'lifecycle'/(path.name+'.json')).read_bytes());state.pop('format')
        metadata=json.loads((path/'meta.json').read_bytes());metadata.pop('format')
        binding=json.loads((path/'native-binding.json').read_bytes())
        with self.loaded(self.session['old']) as validators:
            target=validators.binding.historical_target(path,metadata)
            guard=copy.deepcopy(binding['guard'])
            anchor=validators.recovery.anchor(guard)
            self.assertTrue(validators.recovery._valid_anchor(anchor))
            self.assertTrue(validators.native._consumed(guard,target,anchor))
        state.update(status=status,native_idle=dict(generation=state['generation'],target=target,
            anchor=anchor,observed_at=123.5,guard=guard))
        if status=='closed':state['closed_at']=123.0
        else:state.pop('closed_at',None)
        return state

    def test_native_idle_open_closed_and_historical_baselines_preserve_data(self):
        _,seed=self.ordinary('folder');path=self.native_object(seed)
        # Later terminal unmount evidence need not equal a valid historical idle baseline.
        for location in (path/'native-operations'/('8'*32)/'record.json',path/'native-mount.json'):
            row=json.loads(location.read_bytes());row.pop('format')
            row['current_guard'].update(generation=3,root_digest='a'*64)
            self.save(location,row)
        for status in ('open','closed'):
            with self.subTest(status=status):
                self.save(self.store/'lifecycle'/(path.name+'.json'),self.idle_state(path,status))
                before=self.snapshot_store()
                self.invoke('prepare');self.invoke('publish')
                self.assertEqual(before,self.snapshot_store())
                self.controls=self.base/('idle-'+status);self.controls.mkdir(mode=0o700);self.last=None

    def test_native_idle_malformed_or_nonnative_never_grants_offline_admission(self):
        folder,seed=self.ordinary('folder');path=self.native_object(seed)
        location=self.store/'lifecycle'/(path.name+'.json')
        original=self.idle_state(path,'closed')
        for fault in ('generation','target','time-negative','time-future','anchor','guard','extra','nonnative','active'):
            with self.subTest(fault=fault):
                value=copy.deepcopy(original);idle=value['native_idle'];other=None
                if fault=='generation':idle['generation']='0'*32
                elif fault=='target':idle['target']['file']=[1,2]
                elif fault=='time-negative':idle['observed_at']=-1
                elif fault=='time-future':idle['observed_at']=10**30
                elif fault=='anchor':idle['anchor']['root_digest']='invalid'
                elif fault=='guard':idle['guard']['core_consumed']=False
                elif fault=='extra':idle['extra']=True
                elif fault=='nonnative':
                    other=self.store/'lifecycle'/(folder.name+'.json');saved=other.read_bytes()
                    row=json.loads(saved);row.pop('format');row['native_idle']=idle;self.save(other,row)
                else:
                    other=path/'native-mount.json';saved=other.read_bytes()
                    row=json.loads(saved);row.pop('format');row['state']='mounted';self.save(other,row)
                self.save(location,value);before=self.snapshot_store()
                with self.assertRaisesRegex(o.Refusal,'root-coverage') as caught:self.invoke('prepare')
                codes=[row['code'] for root in caught.exception.observations['roots'] for row in root.get('blockers',[])]
                self.assertIn('binding-resolution-marker' if fault=='active' else 'native-idle-schema',codes)
                self.assertEqual(before,self.snapshot_store());self.assertFalse((self.controls/'step-0000.json').exists())
                if other is not None:other.write_bytes(saved)
                self.controls=self.base/('idle-fault-'+fault);self.controls.mkdir(mode=0o700)


if __name__=='__main__':unittest.main()
