"""Inert synthetic fixtures in archived format=1 layouts; no installed execution."""
import builtins
import ast
import contextlib
import copy
import ctypes
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import types
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
OBSERVER = HERE.parent/'filesystem/fskit/maintenance_observer.py'
spec = importlib.util.spec_from_file_location('maintenance_observer', OBSERVER)
o = importlib.util.module_from_spec(spec); spec.loader.exec_module(o)

def save(path, value):
    path.write_text(json.dumps({'format':1, **value}, sort_keys=True)+'\n'); path.chmod(0o600)

def touch(path, data=''):
    path.write_text(data); path.chmod(0o600)

def native_metadata(path):
    c=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
    c.listxattr.argtypes=[ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
    c.listxattr.restype=ctypes.c_ssize_t
    c.getxattr.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint32,ctypes.c_int]
    c.getxattr.restype=ctypes.c_ssize_t
    encoded=os.fsencode(path); size=c.listxattr(encoded,None,0,1)
    if size<0: raise OSError(ctypes.get_errno(),'snapshot listxattr')
    names=ctypes.create_string_buffer(size);actual=c.listxattr(encoded,names,size,1)
    if actual!=size: raise OSError('snapshot xattr names changed')
    attrs={}
    for name in names.raw[:size].split(b'\0'):
        if not name:continue
        n=c.getxattr(encoded,name,None,0,0,1)
        if n<0:raise OSError(ctypes.get_errno(),'snapshot getxattr')
        data=ctypes.create_string_buffer(n)
        if c.getxattr(encoded,name,data,n,0,1)!=n:raise OSError('snapshot xattr changed')
        attrs[os.fsdecode(name)]=data.raw.hex()
    c.acl_get_link_np.argtypes=[ctypes.c_char_p,ctypes.c_int];c.acl_get_link_np.restype=ctypes.c_void_p
    c.acl_to_text.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ssize_t)];c.acl_to_text.restype=ctypes.c_void_p
    c.acl_free.argtypes=[ctypes.c_void_p]
    acl=c.acl_get_link_np(encoded,0x100);text=''
    if acl:
        count=ctypes.c_ssize_t();ptr=c.acl_to_text(acl,ctypes.byref(count))
        if not ptr:raise OSError('snapshot acl unreadable')
        text=ctypes.string_at(ptr,count.value).decode();c.acl_free(ptr);c.acl_free(acl)
    elif ctypes.get_errno()!=2:raise OSError(ctypes.get_errno(),'snapshot acl')
    return dict(xattrs=attrs,acl=text)

def tree(root):
    result = {}
    for path in [root, *sorted(root.rglob('*'))]:
        info = path.lstat()
        try:metadata=native_metadata(path)
        except PermissionError as error:metadata=dict(metadata_unreadable_errno=error.errno)
        record = dict(identity=o.stamp(info), **metadata, kind=stat.S_IFMT(info.st_mode))
        if stat.S_ISREG(info.st_mode): record['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        if stat.S_ISLNK(info.st_mode): record['link'] = os.readlink(path)
        result[str(path.relative_to(root))] = record
    return result

def policy_state(report, retained_request):
    """Expected roots/identities come from the retained request, never the report."""
    binding=o.digest(retained_request)
    return dict(candidate_access='provably-none',downtime=True,observation=report,
        required_roots=copy.deepcopy(retained_request['roots']),request_binding=binding,
        old_runtime=copy.deepcopy(retained_request['runtime']),old_identity=copy.deepcopy(retained_request['old']),
        root_access=[dict(input=row['input'],candidate_access='provably-none',
            old_runtime=copy.deepcopy(retained_request['runtime']),old_identity=copy.deepcopy(retained_request['old']),
            physical_identity=row.get('physical_identity'),request_binding=binding) for row in report['roots']])

@contextlib.contextmanager
def write_guard():
    """Python call traps only. Native direct syscalls are not intercepted."""
    real_open, real_builtin = os.open, builtins.open
    def guarded_open(path, flags, *args, **kwargs):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError('write-capable-open')
        return real_open(path, flags, *args, **kwargs)
    def guarded_builtin(path, mode='r', *args, **kwargs):
        if any(c in mode for c in 'wax+'):
            raise AssertionError('write-capable-builtin-open')
        return real_builtin(path, mode, *args, **kwargs)
    def forbidden(*args, **kwargs):
        raise AssertionError('forbidden-call')
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(os, 'open', guarded_open))
        stack.enter_context(patch.object(builtins, 'open', guarded_builtin))
        stack.enter_context(patch.object(io, 'open', guarded_builtin))
        for name in ('write','pwrite','mkdir','makedirs','unlink','remove','rmdir','rename','replace',
                     'chmod','chown','fchmod','fchown','truncate','ftruncate','symlink','link','setxattr','removexattr'):
            if hasattr(os,name):stack.enter_context(patch.object(os, name, forbidden))
        stack.enter_context(patch.object(subprocess, 'Popen', forbidden))
        yield

class Inert(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='maintenance-observer-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.base.chmod(0o700)
        self.root = self.base/'store'; self.root.mkdir(mode=0o700)
        for name in o.COLLECTIONS: (self.root/name).mkdir(mode=0o700)
        touch(self.root/'.lock')
        save(self.root/'store.json', {'application':'stallionfs'})
        self.activity = dict(cooperative_downtime=True, mounts=[], helpers=[], descendants=[], uncertainties=[])
        self.request = dict(operation='upgrade', roots=[dict(literal=str(self.root), reason='default')],
                            root_contract=dict(default=str(self.root),environment=None),
                            old={'fixture':'original-build'}, candidate=None,
                            archives={'old':'retained-fixture','new':None}, activity=self.activity)

    def check(self, request=None, **kwargs):
        before = tree(self.base)
        with write_guard(): result = o.observe(request or self.request, **kwargs)
        after = tree(self.base)
        self.assertEqual(before, after)
        self.assertFalse(any(self.base.rglob('*.pyc')))
        return result

    def codes(self, result):
        return [b['code'] for b in result['blockers']] + [b['code'] for row in result['roots'] for b in row['blockers']]

    def restore_state(self):
        self.request['runtime']={'fixture':'original-runtime'}
        retained_request=copy.deepcopy(self.request)
        report=self.check(retained_request)
        return policy_state(report,retained_request),retained_request

    def creation(self):
        workspace, transaction, seed = '1'*32, '2'*32, '3'*64
        stage = self.root/'staging'/('native-create-'+transaction); stage.mkdir(mode=0o700)
        for name in ('input','owned'): (stage/name).mkdir(mode=0o700)
        for name in ('seed-'+seed, 'use-'+workspace, 'workspace-'+workspace): touch(self.root/'locks'/name)
        runtime = {**o.GIT_CONTRACT, 'input_inventory_sha256': '4'*64,
                   'payload_entries': 1, 'payload_sha256': '5'*64,
                   'descriptor_sha256': '6'*64, 'executable_sha256': '7'*64,
                   'source_build_id': '8'*64, 'publisher': o.PUBLISHER_TEAM}
        generation = o.generation(None, workspace, transaction)
        touch(self.root/'locks'/('use-'+workspace), generation+'\n')
        identity = lambda p:o.pair(p.stat())
        fields = dict(protocol=3, workspace=workspace, transaction=transaction, seed=seed,
            seed_identity=[0,0], commit='6'*40, name='fixture', branch=o.branch_name('fixture',workspace),
            capacity_gib=1, jobs=1, budget=o.DEFAULT_BUDGET, install=True, profile='production',
            host='/Applications/StallionFS.app/Contents/MacOS/StallionFS', stage=str(stage),
            stage_identity=identity(stage), input_identity=identity(stage/'input'), object=identity(stage/'owned'),
            store_lock=identity(self.root/'.lock'), seed_lock=identity(self.root/'locks'/('seed-'+seed)),
            lease=dict(file=identity(self.root/'locks'/('use-'+workspace)), generation=generation),
            workspace_lock=identity(self.root/'locks'/('workspace-'+workspace)), method=o.METHOD, runtime=runtime, parent=None)
        o.schema(fields)
        record = {key:fields[key] for key in ('workspace','transaction','seed','stage','stage_identity','object')}
        record.update(operation='native-create', candidate=str(stage/'owned'), final=str(self.root/'workspaces'/workspace),
                      protocol=3, spec_digest=o.digest(fields), phase='specified', actors=[], creation_attempted=False,
                      outcome='preparing', helpers=[], child_pending=False)
        save(stage/'create-spec.json',fields); save(stage/'native-create',o.marker(record))
        journal = self.root/'journals'/(workspace+'.json'); save(journal,record)
        self.request['runtime'] = runtime
        return fields, record, journal, stage

    def test_O1_empty_actual_store(self):
        result = self.check()
        self.assertEqual(result['status'],'no-known-blockers-at-observation')
        self.assertEqual(set(result['roots'][0]['coverage']),set(o.COLLECTIONS)|{'store.json','.lock','cleanup.json:absent'})

    def test_O2_absence_and_unavailable_parent(self):
        self.request['roots']=[dict(literal=str(self.base/'absent'),reason='default')]
        self.request['root_contract']['default']=str(self.base/'absent')
        result=self.check(); self.assertEqual(result['exit_code'],0)
        self.request['roots']=[dict(literal=str(self.base/'offline'/'absent'),reason='default')]
        self.request['root_contract']['default']=str(self.base/'offline'/'absent')
        result=self.check(); self.assertEqual(result['exit_code'],1)
        self.assertFalse(result['complete'])
        parent=self.base/'unreadable';parent.mkdir(mode=0)
        self.request['roots']=[dict(literal=str(parent/'absent'),reason='default')]
        self.request['root_contract']['default']=str(parent/'absent')
        self.assertEqual(self.check()['exit_code'],1)

    def test_O3_denominator_and_duplicates(self):
        self.request['roots'] += [dict(literal=str(self.root),reason='environment'),
            dict(literal=str(self.root)+'/',reason='explicit'),dict(literal=str(self.base/'missing'),reason='explicit')]
        self.request['root_contract']['environment']=str(self.root)
        result=self.check(); self.assertEqual(len(result['roots']),4)
        self.assertEqual(result['roots'][1]['duplicate_of'],str(self.root))
        self.assertFalse(result['complete']);self.assertEqual(result['exit_code'],1)
        self.request['roots'].reverse()
        self.assertEqual(len(self.check()['roots']),4)

    def test_O4_alias_mode_hardlink_acl_volume(self):
        alias=self.base/'alias';alias.symlink_to(self.root, target_is_directory=True)
        for literal in (str(alias),str(alias/'nested')):
            request={**self.request,'roots':[dict(literal=literal,reason='explicit'),*self.request['roots']]}
            self.assertEqual(self.check(request)['exit_code'],1)
        marker=self.root/'store.json';marker.chmod(0o644)
        self.assertIn('unsafe-owner-mode',self.codes(self.check()));marker.chmod(0o600)
        os.link(marker,self.base/'linked-control')
        self.assertIn('unsafe-type-or-hardlink',self.codes(self.check()));(self.base/'linked-control').unlink()
        original=o.empty_acl
        def acl(fd,**kwargs):
            if o.pair(os.fstat(fd))==o.pair(marker.stat()):raise o.Refusal('unsupported-acl')
            return original(fd,**kwargs)
        with patch.object(o,'empty_acl',acl): self.assertIn('unsupported-acl',self.codes(self.check()))
        realstat=os.stat
        def foreign(path,*args,**kwargs):
            info=realstat(path,*args,**kwargs)
            if str(path)=='store.json':
                values={key:getattr(info,key) for key in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
                values['st_dev']+=1;return types.SimpleNamespace(**values)
            return info
        with patch.object(os,'stat',foreign):self.assertIn('foreign-volume',self.codes(self.check()))
        def foreign_owner(path,*args,**kwargs):
            info=realstat(path,*args,**kwargs)
            if str(path)=='store.json':
                values={key:getattr(info,key) for key in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
                values['st_uid']+=1;return types.SimpleNamespace(**values)
            return info
        with patch.object(os,'stat',foreign_owner):self.assertIn('unsafe-owner-mode',self.codes(self.check()))

    def test_O4_replacement_detected(self):
        marker=self.root/'store.json'; replacement=self.base/'replacement';save(replacement,{'application':'stallionfs'})
        a=o.Existing(str(self.root),o.LIMITS);a.admit();a.read(marker)
        os.replace(replacement,marker)
        self.assertTrue(a.finish())

    def test_O5_missing_and_busy_locks(self):
        (self.root/'.lock').unlink()
        self.assertEqual(self.check()['exit_code'],1);touch(self.root/'.lock')
        for prefix,length in (('seed-',64),('use-',32),('workspace-',32)):
            path=self.root/'locks'/(prefix+'a'*length);touch(path)
            with path.open('rb') as stream:
                fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
                self.assertIn('busy-lock',self.codes(self.check()))
            path.unlink()
        self.assertEqual(self.check()['exit_code'],0)

    def test_O6_terminal_pending_unknown_and_cleanup(self):
        touch(self.root/'journals'/('.'+'a'*32+'.json.'+'b'*32),'interrupted publication bytes')
        save(self.root/'cleanup.json',{'enabled':False})
        retained_result=self.check();self.assertEqual(retained_result['exit_code'],1)
        retained=retained_result['roots'][0]['entries'][0]
        self.assertEqual(retained['status'],'retained-publication-remnant');self.assertTrue(retained['blocking'])
        fields,record,journal,stage=self.creation()
        result=self.check();self.assertTrue(result['complete']);self.assertEqual(result['exit_code'],1)
        entry=next(e for e in result['roots'][0]['entries'] if e.get('operation')=='native-create')
        self.assertEqual(entry['helper_activity'],'terminal-retained')
        for altered in (dict(child_pending=True),dict(actors=[{'role':'00-config','child_pending':True}])):
            save(journal,{**record,**altered})
            result=self.check();self.assertEqual(result['exit_code'],1)
            entry=next(e for e in result['roots'][0]['entries'] if e.get('operation')=='native-create')
            if 'child_pending' in altered:self.assertEqual(entry['helper_activity'],'unresolved')
            else:self.assertEqual(entry['actor_activity'],'requires-exact-actor-and-OS-attribution')
        for operation in ('native-mount','native-unmount','snapshot','rollback','retire','native-purge','unknown'):
            save(journal,{**record,'operation':operation})
            self.assertIn('unsupported-journal-operation',self.codes(self.check()))

    def test_O7_limits_and_partial_findings(self):
        touch(self.root/'journals'/('.'+'a'*32+'.json.'+'b'*32),'retained')
        for limits,code in ((dict(entries=3),'entry-budget'),(dict(document=4),'document-budget'),
                            (dict(control_bytes=4),'control-byte-budget'),(dict(roots=0),'request-root-budget'),
                            (dict(output=10),'output-budget')):
            result=self.check(limits=limits);self.assertIn(code,self.codes(result));self.assertEqual(result['exit_code'],1)
            if code=='output-budget':
                with self.assertRaises(o.Refusal):o.serialize(result)
        save(self.root/'journals'/'bad.json',{'format':99})
        result=self.check();self.assertTrue(result['roots'][0]['entries']);self.assertTrue(result['roots'][0]['omitted'])

    def test_O7_close_failure(self):
        original=os.close; failed=[]
        def close(fd):
            original(fd)
            if not failed:failed.append(fd);raise OSError('injected close result uncertainty')
        with patch.object(os,'close',close):self.assertIn('close-failed',self.codes(self.check()))

    def test_O8_call_traps_and_import_boundary(self):
        with write_guard():
            for call in (lambda:os.open(str(self.root/'forbidden'),os.O_CREAT|os.O_WRONLY,0o600),
                         lambda:(self.root/'forbidden').write_text('bad'),lambda:os.mkdir(self.root/'forbidden'),
                         lambda:subprocess.Popen(['/usr/bin/true'])):
                with self.assertRaises(AssertionError):call()
        self.assertFalse((self.root/'forbidden').exists())
        # Observer has no product import/dispatch path at all.
        for node in ast.walk(ast.parse(OBSERVER.read_text())):
            if isinstance(node,ast.Import):self.assertTrue(all(not a.name.startswith('stallionfs') for a in node.names))
            if isinstance(node,ast.ImportFrom):self.assertEqual(node.level,0)
        for prohibited in ('Store','reconcile','lease','git','mount','unmount','native_engine'):
            with self.assertRaises(AttributeError):getattr(o,prohibited)
        self.assertEqual(self.check()['exit_code'],0)

    def test_O9_exact_runtime_bound_pending(self):
        fields,record,journal,stage=self.creation()
        result=self.check();entry=next(e for e in result['roots'][0]['entries'] if e.get('operation')=='native-create')
        self.assertTrue(entry['runtime_matches']); self.assertEqual(entry['runtime'],fields['runtime'])
        for key in ('descriptor_sha256','source_build_id','payload_sha256'):
            runtime=copy.deepcopy(fields['runtime']);runtime[key]='0'*64;self.request['runtime']=runtime
            result=self.check();entry=next(e for e in result['roots'][0]['entries'] if e.get('operation')=='native-create')
            self.assertFalse(entry['runtime_matches']);self.assertEqual(entry['runtime'],fields['runtime'])
        for phase in ('complete','install','unknown'):
            save(journal,{**record,'phase':phase})
            self.assertEqual(self.check()['exit_code'],1)
        for key,value in (('profile','private-sfsro27'),('host','/fixture/Contents/MacOS/StallionFS')):
            changed={**fields,key:value};changed_record={**record,'spec_digest':o.digest(changed)}
            save(stage/'create-spec.json',changed);save(stage/'native-create',o.marker(changed_record));save(journal,changed_record)
            result=self.check();entry=next(e for e in result['roots'][0]['entries'] if e.get('operation')=='native-create')
            self.assertFalse(entry['configuration_matches'])
            self.assertEqual(entry[key],value)
        save(stage/'create-spec.json',fields);save(stage/'native-create',o.marker(record))
        for update in (dict(installation={}),dict(first_mount_attempted=False),dict(first_use={'accepted':False})):
            save(journal,{**record,**update});self.assertEqual(self.check()['exit_code'],1)

    def test_B2_runtime_contract(self):
        runtime=dict(flags=['-I','-B','-S'], version=[3,13,18], initial_paths=['/original/stdlib'],
            cache_tag='cpython-313', gil=True,
            executable='/Applications/StallionFS.app/Contents/Resources/Runtime/CPython/bin/python3.13')
        self.assertTrue(o.runtime_contract(runtime,runtime))
        for key,value in (('version',[3,13,3]),('flags',['-I','-S']),('initial_paths',['/hostile']),
                          ('cache_tag','cpython-314'),('gil',False),('executable','/candidate/python')):
            with self.assertRaises(o.Refusal):o.runtime_contract({**runtime,key:value},runtime)

    def test_O10_activity_and_snapshot_only(self):
        for key in ('mounts','helpers','descendants','uncertainties'):
            self.activity[key]=[{'identity':'fixture-known-or-uncertain','lifetime':'unresolved'}]
            self.assertIn('activity-busy-or-unresolved',self.codes(self.check()));self.activity[key]=[]
        self.assertEqual(self.check()['exit_code'],0)
        touch(self.root/'journals'/'later.json','new work after observation')
        self.assertEqual(self.check()['exit_code'],1)

    def test_R4_R5_policy_and_missing_app(self):
        for access in ('potentially-mutating','unknown'):
            self.assertEqual(o.recovery_policy(dict(candidate_access=access,downtime=True),self.request),'same-candidate-repair-only-after-downtime')
            self.assertEqual(o.recovery_policy(dict(candidate_access=access,downtime=True,old_pending=True),self.request),
                             'stop-mixed-runtime-preserve-all')
        state,retained_request=self.restore_state()
        self.assertEqual(o.recovery_policy({**state,'missing_or_broken':True},retained_request),
                         'stop-missing-app-uncertainty')
        self.assertEqual(o.recovery_policy({**state,'missing_or_broken':True,
            'missing_app_route_qualified':True,'last_exact_version_known':True},retained_request),'restore-exact-same-version-then-observe')

    def test_R7_link_states(self):
        link=self.base/'link';target=self.base/'target'
        self.assertEqual(o.inspect_link(link,target),'no-link')
        link.symlink_to(target);self.assertEqual(o.inspect_link(link,target),'owned-dangling')
        touch(target);self.assertEqual(o.inspect_link(link,target),'owned-link')
        self.assertEqual(o.inspect_link(link,self.base/'other'),'foreign-entry-preserve')
        link.unlink();touch(link);self.assertEqual(o.inspect_link(link,target),'foreign-entry-preserve')

    def test_regression_temporary_native_intent_is_not_terminal(self):
        path=self.root/'journals'/('.'+'a'*32+'.json.'+'b'*32)
        for contents in ('arbitrary partial bytes',json.dumps({'format':1,'operation':'native-create',
                         'child_pending':True,'helpers':[{'pid':123,'reaped':False}]})):
            touch(path,contents)
            report=self.check();self.assertEqual(report['exit_code'],1);self.assertTrue(report['complete'])
            entry=report['roots'][0]['entries'][0]
            self.assertEqual(entry['status'],'retained-publication-remnant')
            self.assertFalse(entry['authoritative']);self.assertTrue(entry['blocking'])

    def test_regression_empty_default_environment_contract(self):
        for roots in ([],None,{},'not-a-list'):
            report=self.check({**self.request,'roots':roots})
            self.assertIn('empty-or-invalid-root-request',self.codes(report))
            self.assertFalse(report['complete']);self.assertEqual(report['exit_code'],1)
        report=self.check({**self.request,'root_contract':None})
        self.assertIn('invalid-root-contract',self.codes(report));self.assertEqual(len(report['roots']),1)
        report=self.check({**self.request,'roots':[dict(literal=str(self.root),reason='explicit')]})
        self.assertIn('default-root-not-accounted',self.codes(report))
        report=self.check({**self.request,'root_contract':dict(default=str(self.root),environment=str(self.base/'env'))})
        self.assertIn('environment-root-not-accounted',self.codes(report))
        environment=dict(literal=str(self.base/'env'),reason='environment')
        report=self.check({**self.request,'roots':[*self.request['roots'],environment],
            'root_contract':dict(default=str(self.root),environment=environment['literal'])})
        self.assertFalse(report['complete']);self.assertEqual(len(report['roots']),2)

    def test_regression_double_slash_preserves_later_root(self):
        bad=dict(literal='/'+str(self.root),reason='explicit')
        report=self.check({**self.request,'roots':[bad,*self.request['roots']]})
        self.assertEqual(report['exit_code'],1);self.assertEqual(len(report['roots']),2)
        self.assertEqual(report['roots'][0]['input'],bad)
        self.assertIn('unsupported-root-spelling',[b['code'] for b in report['roots'][0]['blockers']])
        self.assertTrue(report['roots'][1]['complete']);self.assertEqual(report['roots'][1]['blockers'],[])

    def test_regression_restore_requires_complete_bound_denominator(self):
        state,retained_request=self.restore_state()
        self.assertEqual(o.recovery_policy(state,retained_request),'old-samepath-restore-eligible-for-qualified-manual-procedure')
        for update in (dict(complete=False),dict(requested_roots_unavailable=True),dict(root_access=[]),
                       dict(required_roots=[]),dict(request_binding='different'),dict(old_runtime={'different':True}),
                       dict(old_identity={'different':True}),dict(observation=None)):
            self.assertEqual(o.recovery_policy({**state,**update},retained_request),'stop-incomplete-required-root-evidence')
        for field,value in (('candidate_access','unknown'),('old_runtime',{'different':True}),
                            ('old_identity',{'different':True}),('physical_identity',[0,0]),
                            ('request_binding','different'),('input',{'different':True})):
            changed=copy.deepcopy(state);changed['root_access'][0][field]=value
            self.assertEqual(o.recovery_policy(changed,retained_request),'stop-incomplete-required-root-evidence')
        for key,value in (('complete',False),('omitted',['uninspected']),('blockers',[{'code':'unknown'}])):
            changed=copy.deepcopy(state);changed['observation']['roots'][0][key]=value
            self.assertEqual(o.recovery_policy(changed,retained_request),'stop-incomplete-required-root-evidence')
        # Exact independent raw reproduction cannot supply optimistic flags instead of evidence.
        self.assertEqual(o.recovery_policy(dict(candidate_access='provably-none',downtime=True,old_pending=True,
            complete=False,requested_roots_unavailable=True),retained_request),'stop-incomplete-required-root-evidence')

    def test_regression_actual_missing_root_blocks_restore(self):
        state,unused_request=self.restore_state()
        request={**self.request,'roots':[*self.request['roots'],dict(literal=str(self.base/'missing'),reason='explicit')]}
        retained_request=copy.deepcopy(request)
        report=self.check(retained_request)
        changed={**policy_state(report,retained_request),'old_pending':True}
        self.assertEqual(o.recovery_policy(changed,retained_request),'stop-incomplete-required-root-evidence')
        changed.update(missing_or_broken=True,missing_app_route_qualified=True,last_exact_version_known=True)
        self.assertEqual(o.recovery_policy(changed,retained_request),'stop-incomplete-required-root-evidence')

    def test_r3_dropped_root_with_original_request_unchanged(self):
        self.request['runtime']={'fixture':'original-runtime'}
        self.request['roots'].append(dict(literal=str(self.base/'missing'),reason='explicit'))
        retained_request=copy.deepcopy(self.request);before=copy.deepcopy(retained_request)
        report=self.check(retained_request);filtered=copy.deepcopy(report)
        filtered['declared_roots']=filtered['declared_roots'][:1];filtered['roots']=filtered['roots'][:1]
        filtered.update(complete=True,status='no-known-blockers-at-observation',exit_code=0)
        self.assertEqual(filtered['request_binding'],o.digest(retained_request))
        state=policy_state(filtered,retained_request)
        self.assertEqual(o.recovery_policy(state,retained_request),'stop-incomplete-required-root-evidence')
        state['required_roots']=copy.deepcopy(filtered['declared_roots'])
        self.assertEqual(o.recovery_policy(state,retained_request),'stop-incomplete-required-root-evidence')
        self.assertEqual(retained_request,before)

    def test_r3_changed_report_context_with_original_request_unchanged(self):
        state,retained_request=self.restore_state();report=state['observation'];before=copy.deepcopy(retained_request)
        self.assertEqual(o.recovery_policy(state,retained_request),'old-samepath-restore-eligible-for-qualified-manual-procedure')
        for key,value in (('runtime',{'fixture':'replacement-runtime'}),('old',{'fixture':'replacement-artifact'}),
            ('candidate',{'fixture':'replacement-candidate'}),('archives',{'fixture':'replacement-archives'}),
            ('root_contract',{'default':str(self.root),'environment':str(self.root)}),
            ('operation','removal'),('activity',{'cooperative_downtime':False})):
            changed=copy.deepcopy(report);changed[key]=value
            self.assertEqual(changed['request_binding'],o.digest(retained_request))
            changed_state=policy_state(changed,retained_request)
            self.assertEqual(o.recovery_policy(changed_state,retained_request),'stop-incomplete-required-root-evidence')
        changed=copy.deepcopy(report);changed['request_binding']='0'*64
        self.assertEqual(o.recovery_policy(policy_state(changed,retained_request),retained_request),'stop-incomplete-required-root-evidence')
        reordered=dict(reversed(list(retained_request.items())))
        self.assertEqual(o.digest(reordered),o.digest(retained_request))
        self.assertEqual(o.recovery_policy(state,reordered),'old-samepath-restore-eligible-for-qualified-manual-procedure')
        self.assertEqual(o.recovery_policy(state,None),'stop-incomplete-required-root-evidence')
        with self.assertRaises(TypeError):o.recovery_policy(state)
        self.assertEqual(retained_request,before)

class Compatibility(unittest.TestCase):
    def setUp(self):
        self.observer = OBSERVER.read_bytes()
        self.build = dict(bundle_id='com.alvinhhh.stallionfs', bundle_version='9',
                          package_version='0.7.0', source_build_id='a'*64)
        self.data = o.create_compatibility(self.observer, self.build)
        self.value = json.loads(self.data)
        self.pair = dict(predecessor_descriptor_sha256='b'*64, candidate_build=self.build,
            runtime_contract=o.RUNTIME_CONTRACT, parser_contract=o.PARSER_CONTRACT,
            observer_sha256=hashlib.sha256(self.observer).hexdigest())

    def encode(self, value):
        return json.dumps(value).encode()

    def test_empty_support_refuses_and_synthetic_exact_tuple_is_only_structural(self):
        self.assertEqual(o.validate_compatibility(self.data, self.observer, self.build), self.value)
        with self.assertRaises(o.Refusal):
            o.compatible_predecessor(self.data, self.observer, self.build, self.pair)
        self.value['public_upgrade_support'] = [self.pair]
        data = self.encode(self.value)
        self.assertEqual(o.compatible_predecessor(data, self.observer, self.build, self.pair),
                         dict(structurally_consistent=True, authenticated=False))
        for key, value in (('predecessor_descriptor_sha256', 'c'*64), ('observer_sha256','d'*64),
                           ('candidate_build',dict(self.build,bundle_version='10')),
                           ('runtime_contract',dict(o.RUNTIME_CONTRACT,architecture='x86_64')),
                           ('parser_contract',dict(o.PARSER_CONTRACT,store_format=2))):
            with self.subTest(key=key), self.assertRaises(o.Refusal):
                o.compatible_predecessor(data,self.observer,self.build,dict(self.pair,**{key:value}))
        for pair in (None, {}, {k:v for k,v in self.pair.items() if k!='observer_sha256'}):
            with self.assertRaises(o.Refusal): o.compatible_predecessor(data,self.observer,self.build,pair)

    def test_resource_refuses_malformed_unknown_aliases_and_authority(self):
        updates = [dict(schema=True), dict(schema=2), dict(verified=True), dict(publisher='candidate'),
            dict(roles=dict(o.RESOURCE_ROLES, observer='../observer.py')),
            dict(roles=dict(o.RESOURCE_ROLES, observer=o.RESOURCE_ROLES['compatibility'])),
            dict(roles=dict(o.RESOURCE_ROLES, observer='Contents/Resources/Maintenance/./observer.py')),
            dict(roles={'observer':o.RESOURCE_ROLES['observer']}),
            dict(build=dict(self.build,source_build_id='b'*64)),
            dict(observer=dict(self.value['observer'],size=True)),
            dict(observer=dict(self.value['observer'],sha256='0'*64)),
            dict(runtime_contract=dict(o.RUNTIME_CONTRACT,soabi='cpython-314-darwin')),
            dict(runtime_contract=dict(o.RUNTIME_CONTRACT,gil=1)),
            dict(runtime_contract=dict(o.RUNTIME_CONTRACT,flags=['-I','-S'])),
            dict(runtime_contract=dict(o.RUNTIME_CONTRACT,initial_paths=['/candidate'])),
            dict(parser_contract=dict(o.PARSER_CONTRACT,store_format=True)),
            dict(public_upgrade_support=[self.pair]*2), dict(public_upgrade_support=[self.pair]*17)]
        for update in updates:
            with self.subTest(update=update), self.assertRaises(o.Refusal):
                o.validate_compatibility(self.encode(dict(self.value,**update)), self.observer,self.build)
        for data in (b'', b'{', b'{"schema":1,"schema":1}', b'{"x":NaN}', b'\xff', b' '*32769,
                     b'['*2000+b']'*2000):
            with self.subTest(data=data[:30]), self.assertRaises(o.Refusal):
                o.validate_compatibility(data,self.observer,self.build)
        for observer in (b'',self.observer+b'\n',b'x'*(o.OBSERVER_LIMIT+1)):
            with self.assertRaises(o.Refusal):o.validate_compatibility(self.data,observer,self.build)
        with self.assertRaises(o.Refusal):
            o.validate_compatibility(self.data,self.observer,dict(self.build,package_version='0.8.0'))


if __name__ == '__main__':
    unittest.main()
