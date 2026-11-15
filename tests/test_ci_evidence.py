"""Adversarial records from real, exclusively owned subprocesses."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('entry', ROOT / 'tools/ci_test_entry.py')
entry = importlib.util.module_from_spec(spec); spec.loader.exec_module(entry)
spec = importlib.util.spec_from_file_location('budget', ROOT / 'tools/ci_job_budget.py')
budget = importlib.util.module_from_spec(spec); spec.loader.exec_module(budget)
NS = 10**9
EPOCH_NS = 10000 * NS


def allocation_record(start_ns, minutes, environment):
    return dict(schema=1, clock='darwin-CLOCK_MONOTONIC_RAW-ns-v1',
                start_ns=start_ns, minutes=minutes,
                identity={key: environment[key] for key in budget.IDENTITY}, token='a'*32)

WRITER = """
import json,os,sys,time
from pathlib import Path
rows=[]
for phase in ('setup','suite','close','admission','accounting','exit'):
 for state in ('start','end'):
  r=dict(kind='phase',phase=phase,state=state,time=time.monotonic(),pid=os.getpid(),
         invocation=os.environ['CI_INVOCATION'],mode=os.environ['CI_MODE'],job=os.environ['CI_JOB_BINDING'])
  if (phase,state) in (('suite','end'),('exit','start')):
   r.update(tests=1,failures=0,errors=0,skips=0)
  if (phase,state)==('exit','start'): r['code']=0
  rows.append(r)
case=sys.argv[2]
exec(case)
Path(sys.argv[1]).write_text(raw if 'raw' in globals() else ''.join(json.dumps(r)+'\\n' for r in rows))
"""


# Fault only the owned capture receipt sink after real child collection.
PERSISTENCE_FAULT = r"""
import json,os
root=Path(os.environ['RUNNER_TEMP'])
original_open=Path.open
original_validate=e.validate_receipt
original_fsync=e.os.fsync
capture_fd=None
faulted=False
def fail():
 global faulted
 faulted=True
 raise OSError('SECRET_SENTINEL_4821')
class Sink:
 def __init__(self,stream):self.stream=stream
 def __enter__(self):return self
 def __getattr__(self,name):return getattr(self.stream,name)
 def __exit__(self,*args):
  result=self.stream.__exit__(*args)
  if stage=='close':fail()
  return result
 def write(self,data):
  if stage=='write':fail()
  return self.stream.write(data)
 def flush(self):
  if stage=='flush':fail()
  return self.stream.flush()
def opened(path,*args,**kwargs):
 global capture_fd
 stream=original_open(path,*args,**kwargs)
 if str(path).endswith('/events.jsonl.receipt.json'):
  capture_fd=stream.fileno()
  return Sink(stream)
 if block_refusal and path.name.startswith('suite-closure-refusal-'):
  stream.close()
  raise PermissionError('different secondary failure')
 return stream
def validate(data):
 r=original_validate(data)
 if 'pid' in r and not faulted:
  with original_open(root/'observed-child-capture.json','x') as observer:observer.write(data)
  if stage=='validate':fail()
 return r
def fsync(fd):
 if fd==capture_fd and stage=='fsync' and not faulted:fail()
 return original_fsync(fd)
Path.open=opened
e.validate_receipt=validate
e.os.fsync=fsync
"""

class EvidenceTests(unittest.TestCase):
    def run_record(self, case, mode='pass'):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events'
            r = entry.supervise([sys.executable, '-I', '-B', '-c', WRITER, str(path), case],
                                path, 3, echo=False, mode=mode)
            saved = entry.strict_json(path.with_suffix('.receipt.json').read_bytes())
            self.assertEqual(saved, r)
            self.assertTrue(r['reaped'])
            return r

    def test_live_contradictory_and_unsupported_counts(self):
        for field in ('tests', 'failures', 'errors', 'skips'):
            for value in (True, -1, 1.5, 1000001, [], {}, None):
                with self.subTest(field=field, value=value):
                    r = self.run_record("rows[3][%r]=%r; rows[-2][%r]=%r" % (field, value, field, value))
                    self.assertFalse(r['success'])
                    self.assertFalse(r['valid'])
        for case in ("rows[3]['failures']=7; rows[-2]['failures']=7",
                     "rows[-2]['tests']=0", "rows[3]['tests']=2",
                     "rows[-2]['code']=True", "rows[-2]['code']=2",
                     "rows[3].update(tests=2); rows[-2].update(tests=2)"):
            self.assertFalse(self.run_record(case)['success'])

    def test_live_duplicate_nested_nonobject_and_deep_json(self):
        for case in (
            "raw='null\\n'", "raw='[]\\n'", "raw='[{}]\\n'",
            "raw='['*2000+'0'+']'*2000+'\\n'",
            """raw=''.join(json.dumps(r).replace('"code": 0','"code": 1, "code": 0')+'\\n' for r in rows)""",
            "rows[4]=dict(rows[4],kind='stack',threads={})",
            "rows[4].update(state='error',error='print')",
            "rows[4].update(state='error',error=[])",
        ):
            with self.subTest(case=case):
                r=self.run_record(case)
                self.assertFalse(r['valid'])
                self.assertFalse(r['success'])

    def test_binding_replay_cross_mode_child_job_and_time(self):
        for case in ("rows[2]['pid']+=1", "rows[2]['mode']='suite'",
                     "rows[2]['job']='1'*64", "rows[2]['invocation']='1'*32",
                     "rows[2]['time']=1", "rows[2]['time']=float('inf')",
                     "rows[2]['time']=True"):
            self.assertFalse(self.run_record(case)['valid'])
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'events';path.write_text('null\n')
            r=entry.supervise([sys.executable,'-I','-B','-c','pass'],path,1,echo=False)
            self.assertFalse(r['success']);self.assertIsNone(r['pid'])
            self.assertEqual(path.read_text(),'null\n')
            self.assertTrue(path.with_suffix('.receipt.json').exists())

    def test_exact_nested_stack_containers(self):
        stack = dict(kind='stack', threads=[], truncated=False, child_ownership='unavailable')
        for change in ("stack['threads']={}",
                       "stack['threads']=[None]",
                       "stack['threads']=[dict(id=1,native_id=1,alive=True,daemon=False,frames={},truncated=False)]",
                       "stack['threads']=[dict(id=True,native_id=1,alive=True,daemon=False,frames=[],truncated=False)]",
                       "stack['threads']=[dict(id=1,native_id=1,alive=True,daemon=False,frames=[[]],truncated=False)]"):
            case = "stack=%r; stack.update({k:rows[4][k] for k in ('time','pid','mode','job','invocation')}); " % stack
            case += change + "; rows.insert(4,stack)"
            self.assertFalse(self.run_record(case)['valid'])

    def test_exact_probe_count_and_exit(self):
        self.assertTrue(self.run_record('pass')['success'])
        self.assertFalse(self.run_record('pass',mode='fail')['success'])
        self.assertFalse(self.run_record("rows[-2]['code']=1")['valid'])

    def test_collection_exception_retains_cleanup_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'events'
            def cancel(): raise ValueError('SECRET_SENTINEL_4821')
            r=entry.supervise([sys.executable,'-I','-B','-c','import time; time.sleep(10)'],
                              path,3,echo=False,cancelled=cancel)
            self.assertTrue(r['reaped']);self.assertFalse(r['success'])
            self.assertEqual(r['reason'],'collection_error')
            self.assertNotIn('SECRET_SENTINEL',path.with_suffix('.receipt.json').read_text())

    def test_collection_binding_checks_each_current_field(self):
        original=entry._supervise
        for field,other in (('invocation','b'*32),('mode','pass'),('job','b'*64)):
            for value in (other,None,True,'missing'):
                with self.subTest(field=field,value=value),tempfile.TemporaryDirectory() as d:
                    path=Path(d)/'events';result=entry.CaptureResult();observed=[]
                    def wrong(*args,**kwargs):
                        actual=original(*args,**kwargs);observed.append(actual)
                        returned=dict(actual)
                        if value=='missing':del returned[field]
                        else:returned[field]=value
                        return returned
                    with patch.object(entry,'_supervise',side_effect=wrong), self.assertRaisesRegex(ValueError,'Collection capture binding'):
                        entry.supervise([sys.executable,'-I','-B','-c','pass'],path,2,
                                        echo=False,job='a'*64,result=result)
                    self.assertEqual(len(observed),1)
                    self.assertEqual(observed[0]['returncode'],0)
                    self.assertTrue(observed[0]['reaped'] and all(observed[0]['eof'].values()))
                    self.assertFalse(observed[0]['cleanup_uncertainty'])
                    self.assertEqual(result.capture,dict(success=False,reason='capture_unavailable',
                                                        job='a'*64,cleanup_uncertainty=True))
                    self.assertEqual(path.with_suffix('.receipt.json').read_bytes(),b'')

    def test_stale_self_consistent_transcript_refused_in_every_entry_mode(self):
        original=entry._supervise
        for mode in ('pass','fail','suite'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as d:
                root=Path(d);prior_path=root/'prior';path=root/'current'
                case="rows[3]['failures']=1;rows[-2].update(failures=1,code=1)" if mode=='fail' else 'pass'
                script=WRITER+('\nraise SystemExit(1)\n' if mode=='fail' else '')
                prior=entry.supervise([sys.executable,'-I','-B','-c',script,str(prior_path),case],
                                      prior_path,2,echo=False,mode=mode,job='a'*64)
                self.assertTrue(prior['valid'] and prior['complete'])
                self.assertEqual(entry.validate_receipt(json.dumps(prior)),prior)
                old=prior_path.with_suffix('.receipt.json').read_bytes()
                observed=[];result=entry.CaptureResult()
                def stale(*args,**kwargs):
                    observed.append(original(*args,**kwargs))
                    return prior
                with patch.object(entry,'_supervise',side_effect=stale), self.assertRaisesRegex(ValueError,'Collection capture binding'):
                    entry.supervise([sys.executable,'-I','-B','-c','raise SystemExit(7)'],path,2,
                                    echo=False,mode=mode,job='a'*64,result=result)
                self.assertEqual(len(observed),1)
                actual=observed[0]
                self.assertEqual(actual['returncode'],7)
                self.assertTrue(actual['reaped'] and all(actual['eof'].values()))
                self.assertFalse(actual['cleanup_uncertainty'])
                self.assertNotEqual(actual['invocation'],prior['invocation'])
                self.assertNotEqual(actual['pid'],prior['pid'])
                self.assertLessEqual(prior['collected'],actual['launched'])
                self.assertEqual(result.capture,dict(success=False,reason='capture_unavailable',
                                                    job='a'*64,cleanup_uncertainty=True))
                self.assertEqual(path.with_suffix('.receipt.json').read_bytes(),b'')
                self.assertEqual(prior_path.with_suffix('.receipt.json').read_bytes(),old)
                self.assertEqual(entry.strict_json(old),prior)

    def test_spawn_failure_retains_current_binding_without_child(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'events';result=entry.CaptureResult()
            r=entry.supervise([str(Path(d)/'absent-executable')],path,2,
                              echo=False,mode='pass',job='a'*64,result=result)
            self.assertEqual(r,result.capture)
            self.assertEqual(entry.validate_receipt(path.with_suffix('.receipt.json').read_bytes()),r)
            self.assertEqual((r['mode'],r['job'],r['reason']),('pass','a'*64,'spawn_error'))
            self.assertEqual(len(r['invocation']),32)
            self.assertIsNone(r['pid'])
            self.assertIsNone(r['returncode'])
            self.assertFalse(r['success'] or r['reaped'] or any(r['eof'].values()))
            self.assertNotIn('launched',r)

    def test_receipts_reject_wrong_types_and_duplicates(self):
        r=self.run_record('pass')
        import copy
        for field, value in (('success',1),('valid',[]),('eof',[]),('pid',True),
                             ('bytes',1.5),('timeout',True),('events',{}),
                             ('last_phase',[]),('returncode',False),('mode',[]),('job',{}),('invocation',None)):
            mutated=copy.deepcopy(r);mutated[field]=value
            with self.subTest(field=field), self.assertRaises((ValueError,TypeError)):
                entry.validate_receipt(json.dumps(mutated))
        with self.assertRaises(ValueError):
            entry.validate_receipt(json.dumps(r).replace('"success": true','"success": false, "success": true'))

    def test_missing_anchor_produces_durable_main_refusal(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            env=dict(os.environ,RUNNER_TEMP=d)
            env.pop('CI_ALLOCATION_SHA256',None)
            p=subprocess.run([sys.executable,'-I','-B',str(ROOT/'tools/ci_test_entry.py')],
                             env=env,capture_output=True,timeout=5)
            self.assertEqual(p.returncode,1)
            receipt=entry.validate_receipt(next(Path(d).glob('suite-closure-refusal-*.json')).read_bytes())
            self.assertEqual(receipt['reason'],'entry_refusal')
            self.assertEqual(receipt['mode'],'pass')
            self.assertIsNone(receipt['capture'])
            self.assertIsNone(receipt['job'])
            self.assertFalse(receipt['success'] or receipt['qualification'])

    def test_preexisting_main_root_is_preserved_with_refusal(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'suite-closure';root.mkdir()
            sentinel=root/'keep';sentinel.write_text('untouched')
            child=subprocess.run([sys.executable,'-I','-B',str(ROOT/'tools/ci_test_entry.py')],
                                 env=dict(os.environ,RUNNER_TEMP=d),capture_output=True,timeout=5)
            self.assertEqual(child.returncode,1)
            self.assertEqual(sentinel.read_text(),'untouched')
            paths=list(Path(d).glob('suite-closure-refusal-*.json'))
            self.assertEqual(len(paths),1)
            self.assertFalse(json.loads(paths[0].read_text())['success'])

    def test_anchor_state_and_phase_order(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {
            'RUNNER_TEMP':d,'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1',
            'GITHUB_JOB':'test','CI_WORKER':'macos-15-3.12-0-installed','CI_SPARSE_REQUIRED':'1'}), \
                patch.object(entry.time, 'clock_gettime_ns', return_value=EPOCH_NS):
            path=Path(d)/'ci-allocation.json'
            record=allocation_record(EPOCH_NS-25*NS,20,os.environ)
            def save(r):
                data=json.dumps(r).encode();path.write_bytes(data)
                os.environ['CI_ALLOCATION_SHA256']=budget.digest(data)
            with self.assertRaises((KeyError,FileNotFoundError)):budget.load()
            save(record)
            self.assertGreater(budget.load()[2],1044)
            with self.assertRaises(FileNotFoundError):budget.claim('suite')
            job,_=budget.claim('sparse')
            with self.assertRaises(ValueError):budget.claim('pass')
            budget.finish('sparse',job)
            for phase in ('pass','fail','suite'):
                j,_=budget.claim(phase);budget.finish(phase,j)
            with self.assertRaises(FileExistsError):budget.claim('suite')
            path.write_text(json.dumps(dict(record,start_ns=EPOCH_NS)))
            with self.assertRaises(ValueError):budget.load()
            for changes in (dict(start_ns=EPOCH_NS+100*NS),dict(start_ns=1),
                            dict(start_ns=float('nan')),dict(start_ns=True),dict(start_ns=-1),
                            dict(start_ns=1.0),dict(start_ns=float('inf')),dict(minutes=True),
                            dict(schema=True),dict(schema=2),dict(clock='time.monotonic'),
                            dict(identity=dict(record['identity'],GITHUB_RUN_ATTEMPT='2')),
                            dict(identity=[])):
                save(dict(record,**changes))
                with self.assertRaises(ValueError):budget.load()

    def test_workflow_anchor_keeps_setup_time_across_generic_clock_origins(self):
        import textwrap
        text=(ROOT/'.github/workflows/checks.yml').read_text()
        anchor=text.split("          /usr/bin/python3 -I -B - <<'PYTHON'\n",1)[1].split('          PYTHON\n',1)[0]
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {
            'RUNNER_TEMP':d,'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1',
            'GITHUB_JOB':'test','CI_WORKER':'worker','CI_JOB_MINUTES':'20',
            'GITHUB_ENV':str(Path(d)/'environment')}):
            with patch.object(entry.time,'clock_gettime_ns',return_value=EPOCH_NS), \
                    patch.object(entry.time,'monotonic',return_value=.01), \
                    patch.object(entry.time,'perf_counter',return_value=.01):
                exec(compile(textwrap.dedent(anchor),'<allocation-anchor>','exec'),{})
            path=Path(d)/'ci-allocation.json';original=path.read_bytes()
            marker=Path(os.environ['GITHUB_ENV']).read_text().strip()
            os.environ['CI_ALLOCATION_SHA256']=marker.split('=',1)[1]
            with patch.object(entry.time,'clock_gettime_ns',return_value=EPOCH_NS+25*NS), \
                    patch.object(entry.time,'monotonic',return_value=999999), \
                    patch.object(entry.time,'perf_counter',return_value=999999):
                record,job,remaining=budget.load()
                self.assertEqual(remaining,1045)
                self.assertEqual(budget.load(tail=True)[2],1165)
            self.assertEqual(record['start_ns'],EPOCH_NS)
            self.assertEqual(job,budget.digest(original))
            self.assertEqual(path.read_bytes(),original)

    def test_tail_uses_absolute_deadline_and_retains_refusal(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {
            'RUNNER_TEMP':d,'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1',
            'GITHUB_JOB':'test','CI_WORKER':'worker','GITHUB_OUTPUT':str(Path(d)/'outputs')}), \
                patch.object(entry.time, 'clock_gettime_ns', return_value=EPOCH_NS):
            record=allocation_record(EPOCH_NS-800*NS,15,os.environ)
            data=json.dumps(record).encode()
            (Path(d)/'ci-allocation.json').write_bytes(data)
            os.environ['CI_ALLOCATION_SHA256']=budget.digest(data)
            self.assertEqual(budget.tail('suite-upload'),0)
            with patch.object(entry.time,'clock_gettime_ns',return_value=record['start_ns']+850*NS):
                self.assertEqual(budget.tail('image-upload'),1)
            paths=list(Path(d).glob('suite-closure-refusal-*.json'))
            self.assertEqual(len(paths),1)
            refusal=entry.validate_receipt(paths[0].read_bytes())
            self.assertFalse(refusal['success'])
            self.assertEqual(refusal['phase'],'image-upload')
            self.assertEqual(budget.tail('suite-upload'),1)
            self.assertEqual(len(list(Path(d).glob('suite-closure-refusal-*.json'))),2)

    def test_sparse_synthetic_child_closes_under_shared_allocation(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {
            'RUNNER_TEMP':d,'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1',
            'GITHUB_JOB':'test','CI_WORKER':'worker','CI_SPARSE_REQUIRED':'1'}):
            record=allocation_record(entry.allocation_clock_ns(),15,os.environ)
            data=json.dumps(record).encode()
            (Path(d)/'ci-allocation.json').write_bytes(data)
            os.environ['CI_ALLOCATION_SHA256']=budget.digest(data)
            child=subprocess.run([sys.executable,'-I','-B',str(ROOT/'tools/ci_job_budget.py'),'sparse'],
                                 input='print("owned synthetic workload")',text=True,
                                 capture_output=True,timeout=5)
            self.assertEqual(child.returncode,0,child.stderr)
            receipt=json.loads((Path(d)/'sparse-closure/receipt.json').read_text())
            self.assertTrue(receipt['success'])
            self.assertFalse(receipt['qualification'])
            self.assertTrue(receipt['capture']['reaped'])
            self.assertTrue(all(receipt['capture']['eof'].values()))
            entry.validate_receipt(json.dumps(receipt['capture']))

    def test_workflow_all_required_work_precedes_suite(self):
        text=(ROOT/'.github/workflows/checks.yml').read_text().split('\n  test:',1)[0]
        suite=text.index('      - name: Test installed wheel')
        for name in ('Check large sparse-seek metadata',):
            self.assertLess(text.index('      - name: '+name),suite)
        self.assertIn('ci_job_budget.py" sparse',text)
        self.assertIn('timeout-minutes: 9',text)
        for phase in ('validation','suite-upload','image-upload','interface-upload'):
            self.assertIn('ci_job_budget.py" tail '+phase,text)
            self.assertIn('steps.tail-'+phase+".outputs.admitted == 'true'",text)
        for name in ('image-failure-${{ matrix.os }}-${{ matrix.python }}',
                     'fskit-interface-failure-${{ matrix.os }}-${{ matrix.python }}'):
            self.assertIn('name: '+name,text)
        admission=(ROOT/'tools/ci_test_entry.py').read_text().split('    def final_admission():',1)[1]
        self.assertIn("'doctor'], check=True)",admission)
        self.assertIn("'check', str(container)], check=True)",admission)
        self.assertIn('resource.RLIMIT_CPU, (300, 300)',text)
        self.assertEqual(entry.remainder(100*NS,20,200*NS),970)
        self.assertGreater(entry.remainder(100*NS,20,200*NS),686)
        self.assertGreater(entry.remainder(100*NS,45,125*NS),1792)



class PublicBudgetTests(unittest.TestCase):
    def anchor(self, root):
        env=dict(os.environ,RUNNER_TEMP=str(root),GITHUB_RUN_ID='42',GITHUB_RUN_ATTEMPT='1',
                 GITHUB_JOB='test',CI_WORKER='owned',CI_SPARSE_REQUIRED='1',GITHUB_OUTPUT=str(root/'output'))
        data=json.dumps(allocation_record(entry.allocation_clock_ns(),15,env)).encode()
        (root/'ci-allocation.json').write_bytes(data)
        env['CI_ALLOCATION_SHA256']=budget.digest(data)
        return env

    def invoke(self, env, mode, injection=None, exit_code=0):
        import subprocess
        args=[sys.executable,'-I','-B',str(ROOT/'tools/ci_job_budget.py'),mode]
        if mode=='tail':args.append('suite-upload')
        if injection is not None:
            wrapper="""import importlib.util,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('budget',sys.argv[1])
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
e=b.entry_module_load();b.entry_module_load=lambda:e
exec(sys.argv[3])
sys.exit(b.sparse() if sys.argv[2]=='sparse' else b.tail('suite-upload'))
"""
            args=[sys.executable,'-I','-B','-c',wrapper,str(ROOT/'tools/ci_job_budget.py'),mode,injection]
        workload="from pathlib import Path\np=Path(%r)\nwith p.open('a') as f:f.write('launch\\n')\n" % str(Path(env['RUNNER_TEMP'])/'launches')
        if exit_code:workload+='raise SystemExit(%d)\n' % exit_code
        return subprocess.run(args,input=workload,text=True,capture_output=True,env=env,timeout=6)

    def read_refusal(self, root, mode):
        paths=list(root.glob('suite-closure-refusal-*.json'))
        self.assertEqual(len(paths),1)
        r=entry.validate_receipt(paths[0].read_bytes())
        self.assertEqual((r['kind'],r['phase']),(mode,'sparse' if mode=='sparse' else 'suite-upload'))
        self.assertFalse(r['success'] or r['qualification'])
        return r

    def test_public_sparse_and_tail_replay_preserve_receipts_without_work(self):
        for mode in ('sparse','tail'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as d:
                root=Path(d);env=self.anchor(root)
                self.assertEqual(self.invoke(env,mode).returncode,0)
                old={p:p.read_bytes() for p in root.rglob('*') if p.is_file() and p.name!='output'}
                self.assertEqual(self.invoke(env,mode).returncode,1)
                for p,data in old.items():self.assertEqual(p.read_bytes(),data)
                r=self.read_refusal(root,mode)
                self.assertEqual(r['job'],env['CI_ALLOCATION_SHA256'])
                self.assertIsNone(r['capture'])
                if mode=='sparse':self.assertEqual((root/'launches').read_text(),'launch\n')

    def test_public_stale_capture_cannot_complete_current_phase(self):
        for case in ('same-job','cross-mode','cross-job'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as d:
                root=Path(d);env=self.anchor(root);prior_path=root/'prior.jsonl'
                prior=entry.supervise([sys.executable,'-I','-B','-c',WRITER,str(prior_path),'pass'],
                    prior_path,2,echo=False,mode='pass' if case=='cross-mode' else 'synthetic',
                    job='b'*64 if case=='cross-job' else env['CI_ALLOCATION_SHA256'])
                self.assertTrue(prior['valid'] and prior['complete'] and prior['success'])
                self.assertEqual(entry.validate_receipt(json.dumps(prior)),prior)
                (root/'prior-capture.json').write_text(json.dumps(prior))
                injection="""original=e._supervise
root=Path(b.os.environ['RUNNER_TEMP'])
def collect(*args,**kwargs):
 actual=original(*args,**kwargs)
 (root/'actual-capture.json').write_text(e.json.dumps(actual))
 return e.strict_json((root/'prior-capture.json').read_bytes())
e._supervise=collect
"""
                p=self.invoke(env,'sparse',injection,exit_code=7)
                self.assertEqual(p.returncode,1,p.stderr)
                r=self.read_refusal(root,'sparse')
                actual=entry.validate_receipt((root/'actual-capture.json').read_bytes())
                self.assertEqual(actual['returncode'],7)
                self.assertNotEqual(actual['invocation'],prior['invocation'])
                self.assertNotEqual(actual['pid'],prior['pid'])
                self.assertLessEqual(prior['collected'],actual['launched'])
                self.assertTrue(actual['reaped'] and all(actual['eof'].values()))
                self.assertFalse(actual['cleanup_uncertainty'])
                self.assertEqual(r['job'],env['CI_ALLOCATION_SHA256'])
                self.assertEqual(r['capture'],dict(success=False,reason='capture_unavailable',
                                                  job=r['job'],cleanup_uncertainty=True))
                self.assertEqual(r['error'],'ValueError')
                self.assertFalse(entry.strict_json((root/'ci-phase-sparse.json').read_bytes())['complete'])
                self.assertEqual((root/'launches').read_text(),'launch\n')
                self.assertEqual(entry.strict_json((root/'prior-capture.json').read_bytes()),prior)
                old={path:path.read_bytes() for path in root.rglob('*.json')}
                self.assertEqual(self.invoke(env,'sparse').returncode,1)
                for path,data in old.items():self.assertEqual(path.read_bytes(),data)
                self.assertEqual((root/'launches').read_text(),'launch\n')

    def test_public_fresh_capture_uses_actual_success_or_failure(self):
        for code in (0,7):
            with self.subTest(code=code),tempfile.TemporaryDirectory() as d:
                root=Path(d);env=self.anchor(root)
                p=self.invoke(env,'sparse',exit_code=code)
                self.assertEqual(p.returncode,int(code!=0),p.stderr)
                r=entry.validate_receipt((root/'sparse-closure/receipt.json').read_bytes())
                capture=entry.validate_receipt((root/'sparse-closure/events.jsonl.receipt.json').read_bytes())
                self.assertEqual(r['capture'],capture)
                self.assertEqual(r['job'],env['CI_ALLOCATION_SHA256'])
                self.assertEqual(r['success'],code==0)
                self.assertFalse(r['qualification'])
                self.assertEqual(capture['returncode'],code)
                self.assertTrue(capture['reaped'] and all(capture['eof'].values()))
                self.assertFalse(capture['cleanup_uncertainty'])
                self.assertEqual(entry.strict_json((root/'ci-phase-sparse.json').read_bytes())['complete'],code==0)
                self.assertEqual((root/'launches').read_text(),'launch\n')

    def test_public_missing_malformed_anchor_and_setup_path_failure(self):
        for mode in ('sparse','tail'):
            for case in ('missing','malformed','root-file','output-directory'):
                if mode=='sparse' and case=='output-directory':continue
                with self.subTest(mode=mode,case=case),tempfile.TemporaryDirectory() as d:
                    root=Path(d);env=self.anchor(root)
                    if case=='missing':(root/'ci-allocation.json').unlink()
                    if case=='malformed':
                        data=b'null';(root/'ci-allocation.json').write_bytes(data)
                        env['CI_ALLOCATION_SHA256']=budget.digest(data)
                    if case=='root-file':(root/('sparse-closure' if mode=='sparse' else 'suite-closure')).write_text('keep')
                    if case=='output-directory':env['GITHUB_OUTPUT']=d
                    p=self.invoke(env,mode);self.assertEqual(p.returncode,1,p.stderr)
                    r=self.read_refusal(root,mode)
                    self.assertEqual(r['job'],None if case in ('missing','malformed') else env['CI_ALLOCATION_SHA256'])
                    self.assertIsNone(r['capture'])
                    self.assertFalse((root/'launches').exists())
                    if case=='root-file':self.assertEqual((root/('sparse-closure' if mode=='sparse' else 'suite-closure')).read_text(),'keep')

    def test_public_collection_and_finish_failures_retain_actual_child(self):
        for case in ('collection','finish'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as d:
                root=Path(d);env=self.anchor(root)
                injection=("def broken(*a,**k): raise ValueError('SECRET_SENTINEL_4821')\n"
                           + ("e.selectors.DefaultSelector.select=broken" if case=='collection' else 'b.finish=broken'))
                p=self.invoke(env,'sparse',injection);self.assertEqual(p.returncode,1,p.stderr)
                if case=='collection':
                    r=entry.validate_receipt((root/'sparse-closure/receipt.json').read_bytes());capture=r['capture']
                    self.assertEqual(capture['reason'],'collection_error')
                else:
                    r=self.read_refusal(root,'sparse');capture=r['capture']
                    self.assertEqual((root/'launches').read_text(),'launch\n')
                    self.assertEqual(capture['returncode'],0)
                    self.assertTrue(all(capture['eof'].values()))
                self.assertIsInstance(capture['pid'],int)
                self.assertTrue(capture['reaped'])
                self.assertFalse(r['success'])
                for path in root.rglob('*.json'):
                    self.assertNotIn('SECRET_SENTINEL',path.read_text())

    def test_public_capture_persistence_failures_retain_exact_observations(self):
        for stage in ('validate', 'write', 'flush', 'fsync', 'close'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as d:
                root=Path(d);env=self.anchor(root)
                injection="stage=%r;block_refusal=False\n" % stage + PERSISTENCE_FAULT
                p=self.invoke(env,'sparse',injection)
                self.assertEqual(p.returncode,1,p.stderr)
                r=self.read_refusal(root,'sparse')
                actual=entry.validate_receipt((root/'observed-child-capture.json').read_bytes())
                self.assertEqual(r['capture'],actual)
                self.assertEqual(r['job'],env['CI_ALLOCATION_SHA256'])
                self.assertEqual(actual['job'],r['job'])
                self.assertEqual(actual['returncode'],0)
                self.assertTrue(actual['reaped'] and all(actual['eof'].values()))
                self.assertFalse(actual['cleanup_uncertainty'])
                self.assertEqual((root/'launches').read_text(),'launch\n')
                self.assertEqual(r['error'],'OSError')
                old={path:path.read_bytes() for path in root.rglob('*.json')}
                self.assertEqual(self.invoke(env,'sparse').returncode,1)
                for path,data in old.items():self.assertEqual(path.read_bytes(),data)
                self.assertEqual((root/'launches').read_text(),'launch\n')
                for path in root.rglob('*.json'):
                    self.assertNotIn('SECRET_SENTINEL',path.read_text())

    def test_public_unavailable_capture_does_not_claim_no_launch(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);env=self.anchor(root)
            injection="""original=e._supervise
def collect(*args,**kwargs):
 r=original(*args,**kwargs)
 (Path(b.os.environ['RUNNER_TEMP'])/'observed.json').write_text(e.json.dumps(r))
 raise RuntimeError('SECRET_SENTINEL_4821')
e._supervise=collect
"""
            p=self.invoke(env,'sparse',injection)
            self.assertEqual(p.returncode,1,p.stderr)
            r=self.read_refusal(root,'sparse')
            self.assertEqual(r['capture'],dict(success=False,reason='capture_unavailable',
                             job=env['CI_ALLOCATION_SHA256'],cleanup_uncertainty=True))
            self.assertEqual(r['error'],'RuntimeError')
            actual=entry.validate_receipt((root/'observed.json').read_bytes())
            self.assertTrue(actual['reaped'] and all(actual['eof'].values()))
            self.assertEqual((root/'launches').read_text(),'launch\n')

    def check_unavailable_collection_return(self, expression):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);env=self.anchor(root)
            injection="""original=e._supervise
def collect(*args,**kwargs):
 r=original(*args,**kwargs)
 (Path(b.os.environ['RUNNER_TEMP'])/'observed-child-capture.json').write_text(e.json.dumps(r))
 return %s
e._supervise=collect
""" % expression
            p=self.invoke(env,'sparse',injection)
            self.assertEqual(p.returncode,1,p.stderr)
            r=self.read_refusal(root,'sparse')
            self.assertEqual(r['job'],env['CI_ALLOCATION_SHA256'])
            self.assertEqual(r['capture'],dict(success=False,reason='capture_unavailable',
                             job=r['job'],cleanup_uncertainty=True))
            self.assertEqual(r['error'],'ValueError')
            actual=entry.validate_receipt((root/'observed-child-capture.json').read_bytes())
            self.assertEqual(actual['job'],r['job'])
            self.assertIsInstance(actual['pid'],int)
            self.assertEqual(actual['returncode'],0)
            self.assertTrue(actual['reaped'] and all(actual['eof'].values()))
            self.assertFalse(actual['cleanup_uncertainty'])
            self.assertEqual((root/'launches').read_text(),'launch\n')
            old={path:path.read_bytes() for path in root.rglob('*.json')}
            self.assertEqual(self.invoke(env,'sparse').returncode,1)
            for path,data in old.items():self.assertEqual(path.read_bytes(),data)
            fresh=[path for path in root.glob('*-refusal-*') if path not in old]
            self.assertEqual(len(fresh),1)
            replay=entry.validate_receipt(fresh[0].read_bytes())
            self.assertIsNone(replay['capture'])
            self.assertEqual(replay['job'],r['job'])
            self.assertEqual((root/'launches').read_text(),'launch\n')

    def test_public_null_collection_return_retains_unavailable(self):
        self.check_unavailable_collection_return('None')

    def test_public_nonobject_collection_returns_retain_unavailable(self):
        for expression in ('False', 'True', '0', '1.5', 'float("nan")', "''",
                           '[]', '[r]', '()', "b''", 'object()',
                           '__import__("collections").UserDict(r)',
                           '__import__("types").MappingProxyType(r)',
                           'type("Capture", (dict,), {})(r)'):
            with self.subTest(expression=expression):
                self.check_unavailable_collection_return(expression)

    def test_public_unpersistable_refusal_keeps_primary_error(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);env=self.anchor(root)
            p=self.invoke(env,'sparse',"stage='write';block_refusal=True\n"+PERSISTENCE_FAULT)
            self.assertEqual(p.returncode,1)
            self.assertIn('sparse refusal: OSError; receipt unavailable',p.stderr)
            self.assertNotIn('SECRET_SENTINEL',p.stderr)
            actual=entry.validate_receipt((root/'observed-child-capture.json').read_bytes())
            self.assertTrue(actual['reaped'] and all(actual['eof'].values()))
            self.assertEqual((root/'launches').read_text(),'launch\n')
            # A failed sink is not a durable refusal, even if open created a file.
            self.assertTrue(all(path.stat().st_size==0 for path in root.glob('*-refusal-*')))

    def test_public_refusal_collisions_are_exclusive_and_finite(self):
        for mode in ('sparse','tail'):
            for count in (1,4):
                with self.subTest(mode=mode,count=count),tempfile.TemporaryDirectory() as d:
                    root=Path(d);env=self.anchor(root)
                    (root/('sparse-closure' if mode=='sparse' else 'suite-closure')).write_text('keep')
                    prefix='suite'
                    old={root/(prefix+'-closure-refusal-'+('b'*32)+'-'+str(i)+'.json'):b'keep' for i in range(count)}
                    for path,data in old.items():path.write_bytes(data)
                    injection="from types import SimpleNamespace\nb.uuid.uuid4=lambda:SimpleNamespace(hex='b'*32)"
                    p=self.invoke(env,mode,injection);self.assertEqual(p.returncode,1)
                    for path,data in old.items():self.assertEqual(path.read_bytes(),data)
                    if count==1:
                        r=entry.validate_receipt((root/(prefix+'-closure-refusal-'+('b'*32)+'-1.json')).read_bytes())
                        self.assertIsNone(r['capture'])
                    else:
                        self.assertIn(mode+' refusal: OSError; receipt unavailable',p.stderr)
                        self.assertEqual(len(list(root.glob('*-refusal-*'))),4)
                    self.assertFalse((root/'launches').exists())


PARENT_INTERVAL_FAULT = r'''
original=e._supervise
root=Path(b.os.environ['RUNNER_TEMP'])
def collected(*args,**kwargs):
 actual=original(*args,**kwargs)
 (root/'actual.json').write_text(e.json.dumps(actual))
 returned=dict(actual)
 if mutation=='reversed':returned['collected']=actual['launched']-1
 elif mutation=='missing':returned.pop('collected')
 elif mutation=='missing-launch':returned.pop('launched')
 elif mutation=='equal':returned['collected']=actual['launched']
 (root/'returned.json').write_text(e.json.dumps(returned))
 return returned
e._supervise=collected
'''


class ParentIntervalTests(unittest.TestCase):
    def test_public_sparse_parent_interval_is_independent_of_events(self):
        helper=PublicBudgetTests()
        for mutation in ('control','equal','reversed','missing','missing-launch'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as d:
                root=Path(d);env=helper.anchor(root)
                p=helper.invoke(env,'sparse','mutation=%r\n' % mutation+PARENT_INTERVAL_FAULT)
                actual=entry.validate_receipt((root/'actual.json').read_bytes())
                returned=entry.strict_json((root/'returned.json').read_bytes())
                self.assertFalse(actual['valid'])
                self.assertEqual(actual['diagnostic_error'],'invalid_or_unavailable')
                self.assertGreaterEqual(actual['collected'],actual['launched'])
                self.assertEqual(actual['returncode'],0)
                self.assertTrue(actual['reaped'] and all(actual['eof'].values()))
                self.assertFalse(actual['cleanup_uncertainty'])
                self.assertEqual((root/'launches').read_text(),'launch\n')
                for key in actual.keys()-{'launched','collected'}:
                    self.assertEqual(actual[key],returned[key])
                ledger=entry.strict_json((root/'ci-phase-sparse.json').read_bytes())
                if mutation in ('control','equal'):
                    self.assertEqual(p.returncode,0,p.stderr)
                    receipt=entry.validate_receipt((root/'sparse-closure/receipt.json').read_bytes())
                    self.assertEqual(receipt['capture'],returned)
                    self.assertTrue(receipt['success'] and ledger['complete'])
                    self.assertFalse(receipt['qualification'])
                else:
                    self.assertEqual(p.returncode,1,p.stderr)
                    self.assertFalse(ledger['complete'])
                    with self.assertRaises(ValueError):entry.validate_receipt(json.dumps(returned))
                    self.assertEqual((root/'sparse-closure/events.jsonl.receipt.json').read_bytes(),b'')
                    self.assertEqual((root/'sparse-closure/receipt.json').read_bytes(),b'')
                    self.assertIn('ValueError; receipt unavailable',p.stderr)
                old={path:path.read_bytes() for path in root.rglob('*.json')}
                self.assertEqual(helper.invoke(env,'sparse').returncode,1)
                for path,data in old.items():self.assertEqual(path.read_bytes(),data)
                self.assertEqual((root/'launches').read_text(),'launch\n')

    def test_parent_timestamp_types_and_order_for_both_transcript_states(self):
        helper=EvidenceTests()
        with tempfile.TemporaryDirectory() as d:
            no_events=entry.supervise([sys.executable,'-I','-B','-c','pass'],Path(d)/'events',2,echo=False)
        for actual in (no_events,helper.run_record('pass')):
            self.assertEqual(entry.validate_receipt(json.dumps(actual)),actual)
            for field in ('launched','collected'):
                for value in (-1,float('inf'),float('-inf'),float('nan'),True,'0',None):
                    invalid=dict(actual);invalid[field]=value
                    with self.subTest(valid=actual['valid'],field=field,value=value),self.assertRaises(ValueError):
                        entry.validate_receipt(json.dumps(invalid))
                invalid=dict(actual);del invalid[field]
                with self.assertRaises(ValueError):entry.validate_receipt(json.dumps(invalid))
            invalid=dict(actual,collected=actual['launched']-1)
            with self.assertRaises(ValueError):entry.validate_receipt(json.dumps(invalid))
        equal=dict(no_events,collected=no_events['launched'])
        self.assertEqual(entry.validate_receipt(json.dumps(equal)),equal)

if __name__=='__main__':unittest.main()
