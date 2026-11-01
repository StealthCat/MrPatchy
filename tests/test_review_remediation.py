"""Regressions for the complete security/reliability review."""
import concurrent.futures
import copy
import hashlib
import json
import os
from pathlib import Path
import time
from types import SimpleNamespace
import uuid

import pytest
from fastapi.testclient import TestClient
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from app import apt,advisories,worker,releases
from app.db import Session,Host,Job,Package,Setting,Observation
from app.main import app,login_attempts
from target import agent,bridge

SOURCE='Types: deb\nURIs: https://example.test/debian\nSuites: stable\nComponents: main\n'

@pytest.mark.parametrize('field',['Trusted : yes','Trusted\t: yes','Check-Valid-Until : no',
    'Check-Date\t: no','Allow-Insecure : yes','Signed-By : /etc/apt/keyrings/test.gpg',
    'Trusted: no\nTrusted : yes','Signed-By: /one.gpg\nSigned-By\t: /two.gpg'])
def test_noncanonical_deb822_fields_cannot_reach_apt(tmp_path,monkeypatch,field):
    monkeypatch.setattr(apt,'DATA',tmp_path)
    with pytest.raises(ValueError,match='Deb822 field'):
        apt.prepare('test',{'files':{'/etc/apt/sources.list.d/test.sources':SOURCE+field+'\n'},'keys':{},'status':'','architecture':'amd64'})

@pytest.mark.parametrize('args',[['-u'],['-I'],['-IB'],['-X','dev'],['-Wignore'],['--']])
def test_python_options_preserve_script_provenance(tmp_path,monkeypatch,args):
    proc=tmp_path/'proc';proc.mkdir();(proc/'root').mkdir()
    (proc/'maps').write_text('');(proc/'root/script.py').write_text('print(1)')
    (proc/'cmdline').write_bytes(b'\0'.join(os.fsencode(x) for x in ['python3',*args,'/script.py','secret-value'])+b'\0')
    monkeypatch.setattr(agent.os,'readlink',lambda p:'/usr/bin/python3.12')
    evidence=agent.provenance(proc,{})
    assert evidence==[{'kind':'script','path':'/script.py','identity_verified':True,
        'sha256':hashlib.sha256(b'print(1)').hexdigest(),'source':'script-file'}]
    assert 'secret-value' not in json.dumps(evidence)

@pytest.mark.parametrize(('exe','args'),[('python3',['-c','secret-inline-code']),('python3',['-m','secret.module']),
    ('node',['--require','secret-library','/script.js']),('bash',['-c','secret-shell-code']),
    ('perl',['-e','secret-code']),('ruby',['--unknown','secret']),('python3',['-'])])
def test_unresolved_interpreters_are_explicit_without_argument_leaks(tmp_path,monkeypatch,exe,args):
    (tmp_path/'maps').write_text('')
    (tmp_path/'cmdline').write_bytes(b'\0'.join(os.fsencode(x) for x in [exe,*args])+b'\0')
    monkeypatch.setattr(agent.os,'readlink',lambda p:'/usr/bin/'+exe)
    evidence=agent.provenance(tmp_path,{})
    assert evidence and evidence[0]['kind']=='script' and evidence[0]['identity_verified'] is False
    assert 'secret' not in json.dumps(evidence)

@pytest.mark.parametrize(('exe','args','expected'),[('bash',['bash','-eux','--','x.sh'],'x.sh'),
    ('dash',['sh','-e','x.sh'],'x.sh'),('node',['node','--no-warnings','x.js'],'x.js'),
    ('ruby3.1',['ruby','-w','x.rb'],'x.rb'),('perl',['perl','-w','x.pl'],'x.pl'),
    ('node_exporter',['node_exporter','arg'],None),('sha256sum',['sha256sum','arg'],None)])
def test_supported_interpreter_options(exe,args,expected):
    assert agent.script_operand(exe,[os.fsencode(x) for x in args])==expected


def test_hash_rejects_sparse_oversize_and_fifo_without_reading(tmp_path):
    large=tmp_path/'large'
    with large.open('wb') as stream:stream.truncate(129*1024*1024)
    fifo=tmp_path/'fifo';os.mkfifo(fifo)
    for path in (large,fifo):
        with pytest.raises(ValueError,match='128 MiB'):agent.hash_artifact(path,{})


def test_hash_rejects_inode_change_and_elapsed_budget(tmp_path,monkeypatch):
    path=tmp_path/'file';path.write_bytes(b'a'*1024*1024)
    real=agent.os.fstat;calls=0
    def changed(fd):
        nonlocal calls
        info=real(fd);calls+=1
        if calls==2:
            values={name:getattr(info,name) for name in dir(info) if name.startswith('st_')}
            values['st_ctime_ns']+=1
            return SimpleNamespace(**values)
        return info
    monkeypatch.setattr(agent.os,'fstat',changed)
    cache={}
    with pytest.raises(ValueError,match='changed'):agent.hash_artifact(path,cache)
    assert cache=={}
    monkeypatch.setattr(agent.os,'fstat',real)
    times=iter([0,3]);monkeypatch.setattr(agent.time,'monotonic',lambda:next(times))
    with pytest.raises(ValueError,match='time budget'):agent.hash_artifact(path,cache)
    assert cache=={}


def test_collect_keeps_unverified_executables_and_continues(tmp_path,monkeypatch):
    for number,size in ((1,129*1024*1024),(2,10)):
        proc=tmp_path/str(number);proc.mkdir();(proc/'ns').mkdir();(proc/'ns/net').touch();(proc/'fd').mkdir()
        exe=tmp_path/('binary'+str(number))
        with exe.open('wb') as stream:stream.truncate(size)
        (proc/'exe').symlink_to(exe);(proc/'status').write_text('Uid:\t0\t0\t0\t0\n')
    real=Path.iterdir
    monkeypatch.setattr(Path,'iterdir',lambda p:real(tmp_path) if str(p)=='/proc' else real(p))
    monkeypatch.setattr(agent,'sockets',lambda p:({},[]));monkeypatch.setattr(agent,'provenance',lambda *a,**kw:[])
    identity={'pid':1,'start_ticks':0,'pid_namespace':3,'boot_id':'11111111-1111-1111-1111-111111111111','proc_device':4,'proc_inode':5}
    monkeypatch.setattr(agent,'observe_process_identity',lambda p,pid,boot=None:{**identity,'pid':pid})
    processes,errors=agent.collect({});processes.sort(key=lambda p:p['pid'])
    assert [p['identity_verified'] for p in processes]==[False,True]
    assert processes[0]['sha256']=='unavailable' and errors
    assert processes[0]['process_identity']==identity
    assert processes[1]['process_identity']=={**identity,'pid':2}
    assert not [error for error in errors if error.get('error','').startswith('Process identity unverified:')]
    assert worker.behavior_evidence(processes[0])['identity_verified'] is False
    assert worker.behavior_evidence(processes[0])['process_identity']==identity


def patch_fixture(tmp_path,monkeypatch):
    etc=tmp_path/'etc';etc.mkdir();config=etc/'service.conf';config.write_text('original')
    monkeypatch.setattr(bridge,'ROOT',tmp_path);monkeypatch.setattr(bridge,'PATCH_CONFIG_ROOT',etc)
    monkeypatch.setattr(agent,'MANAGED',[])
    inv={'os':'ID=debian\nVERSION_ID=12','architecture':'amd64','foreign_architectures':[],
         'machine_id':'a'*32,'files':{},'keys':{},'status':'Package: demo\nVersion: 1\n'}
    active=['demo.service'];real_handle=bridge.handle
    def handle(req):
        if req['action']=='inventory':return inv
        if req['action']=='health':return {'failed_units':'','collector_active':True}
        return real_handle(req)
    monkeypatch.setattr(bridge,'handle',handle)
    monkeypatch.setattr(bridge,'run',lambda cmd,**kw:'\n'.join(active) if cmd[0]=='systemctl' else '')
    return config,inv,active

@pytest.mark.parametrize('change',['package','repository','trust','content','permissions','service','extra-file','symlink'])
def test_rollback_verification_rejects_unrestored_state(tmp_path,monkeypatch,change):
    config,inv,active=patch_fixture(tmp_path,monkeypatch)
    original=bridge.patch_evidence()
    assert bridge.verify_patch_original(original)['original_state_verified']
    if change=='package':inv['status']=inv['status'].replace('Version: 1','Version: 2')
    if change=='repository':inv['files']['/etc/apt/sources.list']='deb https://other.test stable main'
    if change=='trust':inv['keys']['/key.gpg']='changed'
    if change=='content':config.write_text('new configuration')
    if change=='permissions':config.chmod(0o777)
    if change=='service':active.clear()
    if change=='extra-file':(config.parent/'new.conf').write_text('left behind')
    if change=='symlink':config.unlink();config.symlink_to('/tmp/elsewhere')
    with pytest.raises(ValueError,match='not restored'):bridge.verify_patch_original(original)


def test_noop_rollback_is_not_verified_after_patch_mutation(tmp_path,monkeypatch):
    config,inv,active=patch_fixture(tmp_path,monkeypatch);original=bridge.patch_evidence()
    handle=bridge.handle;calls=[]
    def patch(req):
        if req['action']=='patch':
            inv['status']=inv['status'].replace('Version: 1','Version: 2')
            raise RuntimeError('Maintainer script failed after unpack')
        return handle(req)
    monkeypatch.setattr(bridge,'handle',patch)
    def hook(action,identifier):
        calls.append(action)
        return {'ready':True,'snapshot':'fixture','reboot_required':False}
    monkeypatch.setattr(bridge,'recovery_hook',hook)
    with pytest.raises(ValueError,match='not restored'):
        bridge.protected_patch({'job_id':str(uuid.uuid4()),'packages':['demo=2'],'policy':{'rollback':True},'original':original})
    assert calls==['probe','snapshot','rollback']


def test_patch_original_receipt_is_durable_before_target_mutation(admin,monkeypatch):
    original={'version':1,'configs':{'/etc/demo':{'sha256':'a'*64}},'inventory_hash':'b'*64,'services':[]}
    policy={'reboot':False,'rollback':True};identifier=str(uuid.uuid4())
    with Session() as s:
        s.add(Host(id='patch',name='patch',address='192.0.2.1',fingerprint='test'))
        s.add(Setting(key='recovery:patch',value=policy))
        s.add(Job(id=identifier,host_id='patch',action='patch',payload={'packages':['demo=2'],'_recovery_policy':policy}));s.commit()
    monkeypatch.setattr(worker,'save_inventory',lambda *a:None);monkeypatch.setattr(worker,'validate_patch',lambda *a:None)
    def call(host,req,**kwargs):
        if req['action']=='health':return {'failed_units':'','collector_active':True}
        if req['action']=='patch-inspect':return original
        if req['action']=='protected-patch':
            with Session() as other:assert other.get(Job,identifier).payload['_patch_original']==original
            assert req['original']==original
            raise OSError('SSH disconnected during patch')
        return {}
    monkeypatch.setattr(worker.ssh,'call',call)
    worker.execute(identifier)
    with Session() as s:
        job=s.get(Job,identifier)
        assert job.state=='recovery_required' and job.payload['_patch_original']==original


def test_missing_or_unverified_central_recovery_receipt_fails_closed(monkeypatch):
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**kw:{'outcome':'rolled_back'})
    with pytest.raises(ValueError,match='missing'):worker.verify_patch_recovery(None,None)
    with pytest.raises(ValueError,match='not been verified'):worker.verify_patch_recovery(None,{'version':1})
    with pytest.raises(ValueError,match='missing'):
        worker.wait_for_reboot(None,{'outcome':'rollback_pending','boot_before':'old'},'job')


def test_busy_remote_release_jobs_do_not_consume_dispatch_capacity(admin,monkeypatch):
    from app.coordination import Lock
    locks={name:Lock('review-dispatch-'+name) for name in ('one','two','free')}
    remote=[Lock('review-dispatch-'+name) for name in ('one','two')]
    for lock in remote:assert lock.acquire(False)
    monkeypatch.setattr(worker,'host_lock',lambda name:locks[name])
    ran=[];monkeypatch.setattr(worker,'execute_locked',lambda identifier:ran.append(identifier))
    active={};busy=set()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            for name in ('one','two','free'):
                worker.submit_job(pool,SimpleNamespace(id=name,host_id=name),active,busy)
            assert set(active)=={'free'}
            active['free'][0].result(timeout=5)
        assert ran==['free']
        assert locks['free'].acquire(False);locks['free'].release()
    finally:
        for lock in remote:lock.release()


def test_submission_failure_releases_reserved_host_lock(monkeypatch):
    from app.coordination import Lock
    lock=Lock('review-submit-failure');monkeypatch.setattr(worker,'host_lock',lambda _:lock)
    def fail(*a):raise RuntimeError('executor stopped')
    with pytest.raises(RuntimeError):worker.submit_job(SimpleNamespace(submit=fail),SimpleNamespace(id='j',host_id='h'),{},set())
    assert lock.acquire(False);lock.release()


def test_trusted_proxy_separates_login_limits_and_untrusted_cannot_spoof(client):
    proxy=ProxyHeadersMiddleware(app,trusted_hosts=['172.30.254.2'])
    with TestClient(proxy,client=('172.30.254.2',50000)) as proxied:
        for n in range(50):
            assert proxied.post('/api/login',headers={'x-forwarded-for':'198.51.100.1'},json={'username':'unknown'+str(n),'password':'bad'}).status_code==401
        assert proxied.post('/api/login',headers={'x-forwarded-for':'198.51.100.1'},json={'password':'bad'}).status_code==429
        response=proxied.post('/api/login',headers={'x-forwarded-for':'198.51.100.2'},json={'password':os.environ['ADMIN_PASSWORD']})
        assert response.status_code==200
    login_attempts.clear()
    with TestClient(proxy,client=('192.0.2.9',50000)) as untrusted:
        for n in range(10):
            assert untrusted.post('/api/login',headers={'x-forwarded-for':'198.51.100.'+str(n)},json={'username':'unknown','password':'bad'}).status_code==401
        assert untrusted.post('/api/login',headers={'x-forwarded-for':'198.51.100.99'},json={'username':'unknown','password':'bad'}).status_code==429
    assert '192.0.2.9:unknown' in login_attempts


def test_event_drain_keeps_up_with_sustained_exec_traffic_and_retries(admin,tmp_path,monkeypatch):
    monkeypatch.setattr(agent,'ROOT',tmp_path)
    host=SimpleNamespace(id='event-host');fail_ack=True
    def call(h,req,**kw):
        nonlocal fail_ack
        if req['action']=='events':return agent.pending_events()
        if req['action']=='ack':
            if fail_ack:fail_ack=False;raise OSError('ack transport lost')
            return agent.acknowledge(req['ids'])
        raise AssertionError(req)
    monkeypatch.setattr(worker.ssh,'call',call)
    process={'executable':'/bin/demo','sha256':'a'*64,'uid':'0','connections':[],'capture':'ebpf'}
    with Session() as s:
        for cycle in range(3):
            # 1 exec/second plus the regular 30-second process snapshot.
            for _ in range(31):agent.spool([process],time.time())
            snapshot=agent.pending_events()
            if cycle==0:
                with pytest.raises(OSError):worker.drain_events(s,host,snapshot)
                assert agent.pending_events()['spool']['pending']==31
            worker.drain_events(s,host,agent.pending_events())
            assert agent.pending_events()['spool']['pending']==0
        assert len(s.query(Observation).all())==93


def test_event_drain_has_a_finite_batch_budget(admin,tmp_path,monkeypatch):
    monkeypatch.setattr(agent,'ROOT',tmp_path)
    for _ in range(25):agent.spool([],time.time())
    monkeypatch.setattr(worker.ssh,'call',lambda h,r,**kw:agent.acknowledge(r['ids']) if r['action']=='ack' else agent.pending_events())
    with Session() as s:worker.drain_events(s,SimpleNamespace(id='bounded'),agent.pending_events(),max_batches=2)
    assert agent.pending_events()['spool']['pending']==9

@pytest.mark.parametrize('action',['release-plan','release-upgrade'])
def test_cancellation_is_terminal_for_linked_release_plan(admin,action):
    host_id='cancel-host';plan_id=str(uuid.uuid4());job_id=str(uuid.uuid4())
    with Session() as s:
        s.add(Host(id=host_id,name='cancel',address='192.0.2.1',fingerprint='test'))
        row=releases.ReleasePlan(id=plan_id,host_id=host_id,state='planning' if action=='release-plan' else 'approved',job_id=job_id)
        releases.store(row,{'blockers':[],'expires':time.time()+600})
        s.add_all([row,Job(id=job_id,host_id=host_id,action=action,payload={'plan_id':plan_id})]);s.commit();digest=row.digest
    assert admin.post('/api/operations/jobs/'+job_id+'/cancel').status_code==200
    assert admin.get(f'/api/hosts/{host_id}/releases/{plan_id}').json()['state']=='cancelled'
    assert admin.post(f'/api/hosts/{host_id}/releases/{plan_id}/decision',json={'decision':'go','digest':digest}).status_code==409
    with Session() as s:assert s.get(Job,job_id).state=='cancelled'

@pytest.mark.parametrize('marker',['package','repository','os'])
def test_pi_os_is_rejected_before_advisory_network_query(monkeypatch,marker):
    inv={'os':'ID=debian\nVERSION_ID=12','status':'','files':{}}
    if marker=='package':inv['status']='Package: raspberrypi-sys-mods\n'
    if marker=='repository':inv['files']['/etc/apt/sources.list.d/raspi.list']='deb https://archive.raspberrypi.com/debian bookworm main'
    if marker=='os':inv['os']='ID=raspbian\nVERSION_ID=12'
    def forbidden(*a,**kw):raise AssertionError('Must not query Debian advisories for Pi OS')
    monkeypatch.setattr(advisories.httpx,'post',forbidden)
    with pytest.raises(ValueError,match='ecosystem'):advisories.scan(inv,[])
    assert advisories.ecosystem('ID=debian\nVERSION_ID=12',{'status':'','files':{}})=='Debian:12'
    assert advisories.ecosystem('ID=ubuntu\nVERSION_ID="24.04"')=='Ubuntu:24.04:LTS'


def test_dispatch_resumes_free_release_while_remote_releases_are_owned(admin,monkeypatch):
    """Exercise the scheduler's running-job/quarantine filtering, not only submission."""
    import threading
    from app.coordination import Lock
    with Session() as s:
        for name in ('owned-one','owned-two','orphan','queued'):
            s.add(Host(id=name,name=name,address='192.0.2.1',fingerprint='test'))
            s.add(Job(id=name,host_id=name,action='release-upgrade' if name!='queued' else 'refresh',state='running' if name!='queued' else 'queued'))
        s.commit()
    leader=Lock('scheduler');assert leader.acquire(False)
    owned=[Lock('host:'+name) for name in ('owned-one','owned-two')]
    for lock in owned:assert lock.acquire(False)
    ran=[];done=threading.Event()
    def execute(identifier):
        ran.append(identifier)
        if len(ran)==2:done.set()
    monkeypatch.setattr(worker,'execute_locked',execute)
    class Stop:
        def __init__(self):self.ticks=0
        def wait(self,seconds):
            self.ticks+=1
            return self.ticks>1
    monkeypatch.setattr(worker,'stop',Stop())
    try:worker.loop()
    finally:
        leader.release()
        for lock in owned:lock.release()
    assert set(ran)=={'orphan','queued'} and done.is_set()


def test_stale_approved_plan_does_not_reuse_cancelled_job(admin):
    host='stale-host';plan_id=str(uuid.uuid4());job_id=str(uuid.uuid4())
    with Session() as s:
        s.add(Host(id=host,name=host,address='192.0.2.1',fingerprint='test'))
        row=releases.ReleasePlan(id=plan_id,host_id=host,state='approved',job_id=job_id)
        releases.store(row,{'blockers':[],'expires':time.time()+600})
        s.add_all([row,Job(id=job_id,host_id=host,action='release-upgrade',state='cancelled',payload={'plan_id':plan_id})]);s.commit();digest=row.digest
    assert admin.post(f'/api/hosts/{host}/releases/{plan_id}/decision',json={'decision':'go','digest':digest}).status_code==409


def test_cached_hash_is_returned_after_deadline(tmp_path):
    path=tmp_path/'bin';path.write_bytes(b'cached')
    cache={}
    digest=agent.hash_artifact(path,cache)
    assert agent.hash_artifact(path,cache,deadline=agent.time.monotonic()-1)==digest
    for name,data in (('full',b'x'*10),('empty',b'')):
        target=tmp_path/name;target.write_bytes(data)
        reads=[]
        real=agent.os.fdopen
        def spy(fd,*a,**k):
            stream=real(fd,*a,**k)
            class S:
                def __getattr__(self,n):return getattr(stream,n)
                def __enter__(self):return self
                def __exit__(self,*e):return stream.__exit__(*e)
                def read(self,*x):reads.append(x);return stream.read(*x)
            return S()
        agent.os.fdopen=spy
        try:
            with pytest.raises(ValueError,match='time budget'):
                agent.hash_artifact(target,{},deadline=agent.time.monotonic()-1)
        finally:agent.os.fdopen=real
        assert reads==[]
