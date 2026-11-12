"""Owned inert fixtures for maintenance acquisition and software/STORE boundaries."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import pwd
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('maintenance_workflow',SOURCE/'filesystem/fskit/maintenance_observer.py')
o = importlib.util.module_from_spec(spec); spec.loader.exec_module(o)


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


if __name__=='__main__':unittest.main()
