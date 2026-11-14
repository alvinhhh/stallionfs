"""One retained raw-input exact-command campaign; no authority registration."""
import copy, hashlib, importlib.util, json, os, shutil, stat, subprocess, sys, tempfile, traceback
from pathlib import Path
from unittest.mock import patch

import argparse, time
parser=argparse.ArgumentParser()
parser.add_argument('--checkout',type=Path,required=True)
parser.add_argument('--packet',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--registered-input',action='store_true')
parser.add_argument('--wheel-output',type=Path)
args=parser.parse_args()
PACKET=args.packet.resolve(strict=True)
SOURCE=args.checkout.resolve(strict=True)
CAMPAIGN=args.output.parent.resolve(strict=True)/args.output.name
PRODUCER=args.wheel_output.resolve(strict=True) if args.wheel_output else PACKET
SOURCE_PINS=PRODUCER/'source-pins.json'
ORIGIN_MANIFEST=PACKET/('package-manifest.json' if args.registered_input else 'origin-package-manifest.json')
import stallionfs
SITE=Path(stallionfs.__file__).resolve().parent.parent
assert not SITE.is_relative_to(SOURCE)
from stallionfs import core, _bundle, _native, _native_create_git as git
STARTED=time.monotonic()
DEADLINE=STARTED+900
RETAINED=0
RETAINED_LIMIT=64*1024**2
def sha(data): return hashlib.sha256(data).hexdigest()
def durable(path,value,exclusive=False):
    global RETAINED
    data=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    assert time.monotonic()<DEADLINE, 'campaign deadline'
    assert RETAINED+len(data)<=RETAINED_LIMIT, 'campaign retained byte limit'
    RETAINED+=len(data)
    flags=os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|(os.O_EXCL if exclusive else os.O_TRUNC)
    fd=os.open(path,flags,0o600)
    with os.fdopen(fd,'wb') as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
    core.sync_directory(path.parent)
    return sha(data)
CAMPAIGN.mkdir(mode=0o700)
for name in ('owned-commands','fixtures','tmp','home','xdg'): (CAMPAIGN/name).mkdir(mode=0o700)
tempfile.tempdir=str(CAMPAIGN/'tmp')
SPEC=importlib.util.spec_from_file_location('package_fskit',SOURCE/'tools/package_fskit.py')
package=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(package)
admission_spec=importlib.util.spec_from_file_location('raw_installed_bindings',SOURCE/'tools/ci_git_input.py')
admission_module=importlib.util.module_from_spec(admission_spec); admission_spec.loader.exec_module(admission_module)
installed_bindings=admission_module._Bindings(_bundle)
installed_bindings.reader=package._runtime_read
package._runtime_read=installed_bindings.read
installed_bindings.tree(SITE/'stallionfs')
build_result=json.loads(installed_bindings.read(PRODUCER/'build-result.json'))
wheel=(PRODUCER if args.wheel_output else PACKET/'wheels')/build_result['wheel']
assert sha(installed_bindings.read(SOURCE_PINS))==build_result['source_pins_sha256']
assert sha(installed_bindings.read(wheel))==build_result['wheel_sha256']
import zipfile, io
with zipfile.ZipFile(io.BytesIO(installed_bindings.read(wheel))) as opened:
    wheel_files,wheel_modes=admission_module._wheel_files(opened)
installed_names=set()
for name,data in wheel_files.items():
    if name.startswith('stallionfs/'):
        path=SITE/name
        assert installed_bindings.read(path)==data
        assert oct(stat.S_IMODE(path.lstat().st_mode))==wheel_modes[name]
        installed_names.add(name)
assert {'stallionfs/'+p.relative_to(SITE/'stallionfs').as_posix() for p in (SITE/'stallionfs').rglob('*') if p.is_file()}==installed_names
installed_bindings.check()
inventory_bytes=installed_bindings.read(PACKET/'input-inventory.json')
inventory=json.loads(inventory_bytes)
inventory_sha=sha(inventory_bytes)
GIT=PACKET/'Git'
installed_bindings.tree(GIT)
payload=_bundle.git_payload(GIT)
assert package._runtime_inventory(GIT)==inventory
assert (inventory_sha in _bundle.QUALIFIED_GIT_INPUTS)==args.registered_input
source_manifest=json.loads(installed_bindings.read(ORIGIN_MANIFEST))
if not args.registered_input:
    assert sha(installed_bindings.read(ORIGIN_MANIFEST))==build_result['original_package_manifest_sha256']
    assert inventory_sha==build_result['input_inventory_sha256']
assert source_manifest['source']=={key:_bundle.GIT_CONTRACT[key] for key in _bundle.GIT_SOURCE_KEYS}
contract={**_bundle.GIT_CONTRACT,'input_inventory_sha256':inventory_sha,
          'payload_entries':payload['entries'],'payload_sha256':payload['sha256'],
          'executable_sha256':payload['executable_sha256']}
_bundle.git_contract({**_bundle.GIT_CONTRACT,'input_inventory_sha256':inventory_sha},qualified=args.registered_input)
source_paths=[str(SOURCE/row['path']) for row in json.loads(installed_bindings.read(SOURCE_PINS))]
source_paths += [str(PACKET/'input-inventory.json'),str(ORIGIN_MANIFEST),str(SOURCE_PINS),str(PRODUCER/'build-result.json')]
source_paths += [str(SOURCE/'tools/ci_native_campaign.py'),str(SOURCE/'tools/ci_native_qualify.py')]
# Bind installed Python modules to the same current wheel-producing source.
modules=[]
for path in sorted((SOURCE/'stallionfs').glob('*.py')):
    installed=SITE/'stallionfs'/path.name
    assert installed.read_bytes()==path.read_bytes(),path.name
    modules.append({'source':str(path),'installed':str(installed),'sha256':sha(path.read_bytes())})
    source_paths += [str(path),str(installed)]
source_paths=sorted(set(source_paths))
bound={}
for name in source_paths:
    identity=_bundle._identity(Path(name).lstat())
    bound[name]={'sha256':sha(installed_bindings.read(Path(name))),'identity':identity}
    assert _bundle._identity(Path(name).lstat())==identity
for row in json.loads(installed_bindings.read(SOURCE_PINS)):
    assert bound[str(SOURCE/row['path'])]['sha256']==row['sha256']

checks=[]
def check():
    installed_bindings.check()
    fd=_bundle._directory(GIT)
    try: assert _bundle._identity(os.fstat(fd))==payload['root_identity'],'runtime-root-substitution'
    finally: os.close(fd)
    for relative,expected in payload['identities'].items():
        assert _bundle._identity((GIT/relative).lstat())==expected,'runtime-member-substitution'
    for name,row in bound.items(): assert _bundle._identity(Path(name).lstat())==row['identity'],'source-input-substitution'
    checks.append(len(checks)+1)
runtime={'executable':str(GIT/'bin/git'),'exec_path':str(GIT/'libexec/git-core'),'contract':contract,'check':check}
check()
durable(CAMPAIGN/'before.json',{'contract':contract,'payload':payload,'inventory_sha256':inventory_sha,'bound':bound,'installed_modules':modules},True)

guards=[]
def refuses(label,action):
    try: action()
    except (ValueError,core.StallionError,AssertionError,OSError) as error:
        guards.append({'label':label,'refused':True,'error':str(error),'exception':type(error).__name__})
    else: raise AssertionError('missing refusal: '+label)
if args.registered_input:
    _bundle.git_contract({**_bundle.GIT_CONTRACT,'input_inventory_sha256':inventory_sha})
    guards.append({'label':'actual-registered-input-contract','accepted':True})
else:
    refuses('actual-input-not-registered',lambda:_bundle.git_contract({**_bundle.GIT_CONTRACT,'input_inventory_sha256':inventory_sha}))
refuses('legacy-v2',lambda:_bundle.git_contract(dict(_bundle.LEGACY_GIT_CONTRACT),qualified=False))
refuses('missing-current-source-field',lambda:_bundle.git_contract({k:v for k,v in {**_bundle.GIT_CONTRACT,'input_inventory_sha256':inventory_sha}.items() if k!='notice_patch_sha256'},qualified=False))
refuses('changed-source-constant',lambda:_bundle.git_contract({**_bundle.GIT_CONTRACT,'combined_patch_sha256':sha(b'changed'),'input_inventory_sha256':inventory_sha},qualified=False))
refuses('changed-input-still-unregistered',lambda:_bundle.git_contract({**_bundle.GIT_CONTRACT,'input_inventory_sha256':sha(b'changed')}))
# Preflight substitution refusal in the exact unchanged launch-check slot.
pre=CAMPAIGN/'fixtures/preflight'; (pre/'repo/.git').mkdir(mode=0o700,parents=True)
(pre/'repo/.git/config').write_text('[core]\nrepositoryformatversion=0\nbare=false\n')
with patch.object(_native,'execute_owned',side_effect=AssertionError('actor before runtime guard')):
    refuses('runtime-check-before-inspector',lambda:git.inspect_standalone(pre/'repo',runtime={**runtime,'check':lambda:(_ for _ in ()).throw(core.StallionError('frozen-runtime-guard'))}))
assert guards[-1]['exception']=='StallionError' and guards[-1]['error']=='frozen-runtime-guard'
durable(CAMPAIGN/'inert-guards.json',guards,True)

actual_execute=_native.execute_owned
command_rows=[]; current_phase='fixture-preparation'; strict_env=[]
def tracked_execute(argv,record,persist,directory,**options):
    global RETAINED
    assert time.monotonic()+15<DEADLINE, 'campaign deadline reserve'
    assert RETAINED+git.OUTPUT_CAP<=RETAINED_LIMIT, 'campaign output reserve'
    argv=[str(item) for item in argv]
    number=len(command_rows); log=CAMPAIGN/'owned-commands'/f'{number:04d}'; log.mkdir(mode=0o700)
    is_native=current_phase.startswith('native-') and argv[1:1+len(git.PREFIX)]==git.PREFIX
    row={'number':number,'phase':current_phase,'native_prefix':is_native,'argv':argv,
         'cwd':str(options.get('cwd')),'environment':dict(options.get('env',{})),'snapshots':[]}
    command_rows.append(row)
    check()
    if is_native:
        env=options['env']; cwd=Path(options['cwd']); base=cwd.parent
        expected=git.environment(base,runtime)
        for k,v in expected.items(): assert env[k]==v,(k,env.get(k),v)
        assert set(env)-set(expected)<={'GIT_COMMITTER_NAME','GIT_COMMITTER_EMAIL','GIT_TRACE2','GIT_TRACE2_EVENT','GIT_TRACE2_PERF'}
        assert options['output_limit']==git.OUTPUT_CAP
        assert cwd.name=='inspect' and cwd.is_dir()
        for name in ('home','xdg','tmp'): assert stat.S_IMODE((base/name).stat().st_mode)==0o700
        assert (base/'empty-config').read_bytes()==b''
        assert not any(k.startswith(('DYLD_','GIT_STALLIONFS_')) for k in env)
        assert not any(k in env for k in ('GIT_DIR','GIT_WORK_TREE','GIT_CONFIG_COUNT','GIT_CONFIG_PARAMETERS'))
        strict_env.append(number)
    def save():
        persist()
        snap=copy.deepcopy(record); index=len(row['snapshots'])
        digest=durable(log/f'{index:02d}-receipt.json',snap,True)
        row['snapshots'].append({'file':f'{index:02d}-receipt.json','sha256':digest,'outcome':snap.get('outcome'),'pid':snap.get('pid')})
    durable(log/'request.json',row,True)
    try: result=actual_execute(argv,record,save,directory,**options)
    finally:
        row['receipt']=copy.deepcopy(record)
        for name in ('stdout','stderr'):
            path=Path(directory)/name
            if path.exists():
                data=path.read_bytes(); target=log/name
                assert RETAINED+len(data)<=RETAINED_LIMIT, 'campaign retained stream limit'
                RETAINED+=len(data)
                fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'wb') as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
                row[name]={'sha256':sha(data),'size':len(data),'original':str(path)}
        durable(log/'result.json',row,True)
    assert record['child_pending'] is False and type(record['pid']) is int and record['pid']>0
    assert all(record[k] is True for k in ('reaped','streams_eof','streams_durable'))
    assert 0<=record['output_bytes']<=options['output_limit']
    first=json.loads((log/row['snapshots'][0]['file']).read_text())
    assert first['outcome']=='launch-pending' and first['pid'] is None and first['child_pending'] is True
    assert any(s['outcome']=='running' and type(s['pid']) is int and s['pid']>0 for s in row['snapshots'])
    try: os.waitpid(record['pid'],os.WNOHANG)
    except ChildProcessError: row['independent_reap_check']='not-a-waitable-child'
    else: raise AssertionError('owned actor was not already reaped')
    return result

def command(repo,*args,code=0):
    global current_phase
    previous_phase=current_phase; current_phase='fixture-command'
    log=CAMPAIGN/'tmp'/f'fixture-{len(command_rows):04d}'; log.mkdir(mode=0o700)
    record={}
    try:
        tracked_execute([runtime['executable'],*git.PREFIX,'-C',str(repo),*args],record,lambda:None,log,
                        cwd=repo,env=fixture_env,output_limit=git.OUTPUT_CAP,deadline=15)
    finally: current_phase=previous_phase
    assert record['returncode']==code,record
    return (log/'stdout').read_text().strip()

def owned_subprocess_run(args,**options):
    assert options.get('stdout')==subprocess.PIPE and options.get('stderr')==subprocess.PIPE
    log=CAMPAIGN/'tmp'/f'prepare-{len(command_rows):04d}'; log.mkdir(mode=0o700)
    receipt={}
    tracked_execute(args,receipt,lambda:None,log,cwd=options.get('cwd'),env=options.get('env'),output_limit=git.OUTPUT_CAP,deadline=15)
    output=(log/'stdout').read_bytes(); error=(log/'stderr').read_bytes()
    if options.get('text'): output=output.decode(); error=error.decode()
    return subprocess.CompletedProcess(args,receipt['returncode'],output,error)

# Preparation alone permits the owned local file transport. Native environments are generated afresh.
fixture_env={'PATH':str(GIT/'bin')+':/usr/bin:/bin','HOME':str(CAMPAIGN/'home'),'XDG_CONFIG_HOME':str(CAMPAIGN/'xdg'),
             'TMPDIR':str(CAMPAIGN/'tmp'),'LC_ALL':'C','LANG':'C','TZ':'UTC','GIT_EXEC_PATH':runtime['exec_path'],
             'GIT_CONFIG_NOSYSTEM':'1','GIT_ATTR_NOSYSTEM':'1','GIT_CONFIG_SYSTEM':'/dev/null','GIT_CONFIG_GLOBAL':str(CAMPAIGN/'home/.gitconfig'),
             'GIT_TERMINAL_PROMPT':'0','GIT_ALLOW_PROTOCOL':'file','GIT_PROTOCOL_FROM_USER':'0',
             'GIT_TRACE2':'0','GIT_TRACE2_EVENT':'0','GIT_TRACE2_PERF':'0'}
(CAMPAIGN/'home/.gitconfig').write_text('[user]\n name = Fixture\n email = fixture@example.invalid\n')
fixture_env['GIT_CONFIG_GLOBAL']=str(CAMPAIGN/'home/.gitconfig')
store=core.Store(CAMPAIGN/'store')
successes=[]; refusals=[]

def prepared(name,object_format='sha1',ref_format='files',detached=False):
    global current_phase
    current_phase='fixture-preparation-'+name
    source=CAMPAIGN/'fixtures'/('source-'+name); source.mkdir(mode=0o700)
    command(source,'init','-b','main','--object-format='+object_format,'--ref-format='+ref_format,'--template=')
    (source/'file').write_text('prepared bytes '+name+'\n')
    command(source,'add','file'); command(source,'commit','-m','Fixture')
    if detached: command(source,'checkout','--detach')
    # Explicit owned fixture global default drives actual Store.prepare's clone format.
    (CAMPAIGN/'home/.gitconfig').write_text('[user]\n name = Fixture\n email = fixture@example.invalid\n[init]\n defaultRefFormat = '+ref_format+'\n')
    # core.run strips routing env by design, while preserving this owned HOME/PATH.
    with patch.dict(os.environ,fixture_env,clear=True): seed=store.prepare(source,key='native-qualification-'+name)
    repo=store.root/'seeds'/seed['id']/'repo'
    assert (repo/'.git/reftable/tables.list').exists()==(ref_format=='reftable')
    assert len(seed['commit'])==(64 if object_format=='sha256' else 40)
    assert 'branch.main.remote' in command(repo,'config','--local','--name-only','--list')
    return repo,seed['commit']

def checkout(name,seed,commit):
    global current_phase
    current_phase='native-checkout-'+name
    stage=CAMPAIGN/'fixtures'/('stage-'+name); stage.mkdir(mode=0o700)
    repo=stage/'repo'; shutil.copytree(seed,repo,symlinks=True)
    before=[(repo/relative).read_bytes() for relative in ('.git/config','.git/index','file')]
    record={}; receipts=stage/'record.json'
    def persist(): durable(receipts,record)
    branch='stallionfs/'+hashlib.sha256(name.encode()).hexdigest()[:32]
    start=len(command_rows)
    # Hostile parent state must not flow into the native empty-origin actor environment.
    hostile={'GIT_DIR':'/ambient','GIT_WORK_TREE':'/ambient','GIT_CONFIG_COUNT':'9','GIT_STALLIONFS_CONFIG_PROVIDER':'/ambient',
             'GIT_STALLIONFS_ATTR_PROVIDER':'/ambient','DYLD_INSERT_LIBRARIES':'/ambient','GIT_TRACE2':str(CAMPAIGN/'unexpected-trace')}
    with patch.dict(os.environ,hostile): git.checkout(repo,commit,branch,stage,record,persist,runtime)
    assert before==[(repo/relative).read_bytes() for relative in ('.git/config','.git/index','file')]
    actors=record['actors']; assert len(actors)==5
    assert [actor['returncode'] for actor in actors]==[0,0,0,1,0]
    assert [actor['role'] for actor in actors]==['00-config','01-refs','02-head','03-head-state','04-checkout']
    assert all(actor['runtime']==contract for actor in actors)
    current_phase='native-inspector-'+name
    inspected=git.inspect_standalone(repo,branch=branch,runtime=runtime)
    current_phase='native-readiness-'+name
    with patch.object(git,'qualified_runtime',return_value=runtime) as seam:
        result=git.readiness(repo,{'native_host':'raw-input-resolver-seam'})
        assert result==(commit,branch); seam.assert_called_once_with('raw-input-resolver-seam')
    successes.append({'name':name,'commit':commit,'branch':branch,'command_start':start,'command_end':len(command_rows),
                      'record':str(receipts),'inspected_config':inspected,'readiness':list(result)})
    return repo

def refuse_before_actor(name,seed,commit,mutation):
    stage=CAMPAIGN/'fixtures'/('refusal-'+name); stage.mkdir(mode=0o700)
    repo=stage/'repo'; shutil.copytree(seed,repo,symlinks=True); mutation(repo)
    with patch.object(_native,'execute_owned',side_effect=AssertionError('actor before structural refusal')):
        try: git.checkout(repo,commit,'stallionfs/'+'f'*32,stage,{},lambda:None,runtime)
        except core.StallionError as error: refusals.append({'name':name,'error':str(error)})
        else: raise AssertionError('unsafe fixture admitted: '+name)
    assert not (stage/'actors').exists()

failure=None
try:
    with patch.object(_native,'execute_owned',side_effect=tracked_execute),patch.object(core.subprocess,'run',side_effect=owned_subprocess_run):
        seeds={}
        for obj,refs,detach in [('sha1','files',False),('sha1','reftable',False),('sha256','files',False),('sha256','files',True),('sha256','reftable',False),('sha256','reftable',True)]:
            name=obj+'-'+refs+('-detached' if detach else '-branch')
            seed,commit=prepared(name,obj,refs,detach); seeds[name]=(seed,commit)
            checkout(name,seed,commit)
        seed,commit=seeds['sha1-files-branch']
        for setting in ('false','always','true'):
            name='identity-log-'+setting
            command(seed,'config','core.logAllRefUpdates',setting)
            command(seed,'config','committer.name','Local Committer'); command(seed,'config','committer.email','local@example.invalid')
            command(seed,'config','core.hooksPath','.hooks'); command(seed,'config','core.preferSymlinkRefs','true')
            repo=checkout(name,seed,commit)
            assert (repo/'.git/HEAD').is_symlink()
            assert 'Local Committer' in (repo/'.git/logs/HEAD').read_text()
        # Corrected early /dev/null gate must defeat configured AND traditional descendant hooks.
        sentinel=CAMPAIGN/'outside-hook-writer'
        for event in ('post-checkout','reference-transaction'):
            command(seed,'config','--add','hook.fixture-'+event+'.event',event)
            command(seed,'config','hook.fixture-'+event+'.command','(for x in 1 2 3; do echo BAD >> '+str(sentinel)+'; sleep .02; done) &')
        hooks=seed/'.hooks'; hooks.mkdir(mode=0o700)
        for event in ('post-checkout','reference-transaction'):
            script=hooks/event; script.write_text('#!/bin/sh\n(for x in 1 2 3; do echo BAD >> '+str(sentinel)+'; sleep .02; done) &\n'); script.chmod(0o700)
        checkout('hostile-configured-and-traditional-descendants',seed,commit)
        assert not sentinel.exists() and not (CAMPAIGN/'unexpected-trace').exists()
        # Inspector lifecycle path checks actual optional worktree config with no whole-tree admission.
        current_phase='native-inspector-config-worktree'
        work=CAMPAIGN/'fixtures/inspect-worktree'; shutil.copytree(seed,work,symlinks=True)
        (work/'.git/config.worktree').write_text('[user]\n name = Worktree Fixture\n')
        git.inspect_standalone(work,structure_required=False,runtime=runtime)
        for number,name in enumerate(sorted(git.TRANSIENT)):
            refuse_before_actor('transient-'+str(number),seed,commit,lambda repo,n=name:(repo/'.git'/n).write_text(commit))
        for kind in ('symlink','hardlink','fifo'):
            outside=CAMPAIGN/('outside-'+kind)
            original=(seed/'.git/config').read_bytes(); outside.write_bytes(original)
            def mutation(repo,kind=kind,outside=outside):
                config=repo/'.git/config'; config.unlink()
                if kind=='symlink': config.symlink_to(outside)
                elif kind=='hardlink': os.link(outside,config)
                else: os.mkfifo(config)
            refuse_before_actor(kind,seed,commit,mutation)
            assert outside.read_bytes()==original
        check()
except BaseException as error:
    failure={'exception':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()}
finally:
    after_inventory=package._runtime_inventory(GIT)
    after_payload=_bundle.git_payload(GIT)
    after_bound={name:sha(Path(name).read_bytes()) for name in bound}
    unchanged=after_inventory==inventory and sha((PACKET/'input-inventory.json').read_bytes())==inventory_sha and after_payload==payload and all(after_bound[name]==row['sha256'] for name,row in bound.items())
    durable(CAMPAIGN/'after.json',{'inventory':after_inventory,'payload':after_payload,'bound_sha256':after_bound,'unchanged':unchanged,'input_unregistered':inventory_sha not in _bundle.QUALIFIED_GIT_INPUTS},True)
    durable(CAMPAIGN/'commands.json',command_rows,True)
    result={'scope':'registered raw-input reproducibility recheck' if args.registered_input else 'raw-input exact-command prequalification; no app descriptor or authority','passed':failure is None and unchanged and len(successes)==10 and len(refusals)==27 and len(strict_env)==92 and len(command_rows)==581 and (inventory_sha in _bundle.QUALIFIED_GIT_INPUTS)==args.registered_input,'failure':failure,'successes':successes,'structural_refusals':refusals,'inert_guards':guards,'owned_commands':len(command_rows),'strict_native_environment_commands':strict_env,'runtime_check_count':len(checks),'input_unchanged':unchanged,'input_unregistered':inventory_sha not in _bundle.QUALIFIED_GIT_INPUTS,'contract':contract}
    durable(CAMPAIGN/'result.json',result,True)
    print(json.dumps({k:v for k,v in result.items() if k not in ('successes','strict_native_environment_commands','inert_guards','structural_refusals','contract')}))
if not result['passed']:
    raise RuntimeError('Native campaign failed its complete retained result')
