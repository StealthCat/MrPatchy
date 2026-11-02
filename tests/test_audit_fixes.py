"""Regression coverage for the post-merge requirements/security review."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
import pytest
from sqlalchemy import select
from app import worker,operations,sso
from app.db import Session,Host,Package,Job,Setting,Audit
from target import agent,bridge


def host(s):
    h=Host(id='audit-host',name='Fixture',address='192.0.2.1',fingerprint='fixture',state='offline',inventory={'fixture':True},last_repo=time.time())
    s.add(h);s.flush();return h


def recovery_module():
    spec=importlib.util.spec_from_file_location('recovery',Path(__file__).parents[1]/'scripts/recovery.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def test_backup_refuses_missing_and_non_application_databases(tmp_path,monkeypatch):
    import sqlite3
    recovery=recovery_module();calls=[]
    monkeypatch.setattr(recovery,'remote',lambda:None)
    monkeypatch.setattr(recovery,'run',lambda *a,**kw:calls.append(a))
    source=tmp_path/'missing.db'
    monkeypatch.setenv('DATABASE_URL','sqlite:///'+str(source))
    with pytest.raises(ValueError,match='Existing SQLite'):recovery.backup(tmp_path,tmp_path,tmp_path,tmp_path)
    assert not source.exists() and not calls
    with sqlite3.connect(source) as db:db.execute('CREATE TABLE unrelated (id INT)')
    with pytest.raises(ValueError,match='application tables'):recovery.backup(tmp_path,tmp_path,tmp_path,tmp_path)
    assert not calls


def test_oidc_preserves_exact_configured_issuer(monkeypatch):
    env={**os.environ,'OIDC_ISSUER':'https://issuer.example/','OIDC_CLIENT_ID':'test','OIDC_CLIENT_SECRET':'test'}
    result=subprocess.check_output([sys.executable,'-c','from app.sso import issuer; print(issuer)'],env=env,text=True)
    assert result.strip()=='https://issuer.example/'
    monkeypatch.setattr(sso,'issuer','https://issuer.example/')
    async def metadata():return {'issuer':sso.issuer,'authorization_endpoint':sso.issuer+'authorize','token_endpoint':sso.issuer+'token','jwks_uri':sso.issuer+'jwks'}
    monkeypatch.setattr(sso,'oauth',SimpleNamespace(provider=SimpleNamespace(load_server_metadata=metadata)))
    assert asyncio.run(sso.validate_provider())['issuer']==sso.issuer


def test_candidate_supersession_preserves_original_deadline(admin,monkeypatch):
    with Session() as s:
        h=host(s)
        p=Package(id=h.id+':demo:amd64',host_id=h.id,name='demo:amd64',installed='1',candidate='2',available_since=100,priority='high')
        s.add(p);s.commit()
        candidate={'name':p.name,'candidate':'3','origin':'security','priority':'high'}
        monkeypatch.setattr(worker.apt,'refresh',lambda *a:([candidate],'fixture'))
        worker.update_repos(s,h);assert p.available_since==100
        candidate['candidate']='';worker.update_repos(s,h);assert p.available_since==0
        candidate['candidate']='4';worker.update_repos(s,h);assert p.available_since>100


@pytest.mark.parametrize('state',['running','recovery_required'])
def test_orphan_quarantines_queue_until_verified_reconciliation(admin,monkeypatch,state):
    with Session() as s:
        h=host(s);s.add_all([Job(id='orphan',host_id=h.id,action='repair',state=state),Job(id='next',host_id=h.id,action='repair',state='queued')]);s.commit()
    calls=[]
    def call(h,request,**kwargs):calls.append(request['action']);return {'busy':False}
    monkeypatch.setattr(worker.ssh,'call',call);monkeypatch.setattr(worker,'save_inventory',lambda *a:None)
    worker.execute('next');assert not calls
    assert admin.put('/api/operations/audit-host/observability',json={'ebpf':True}).status_code==409
    assert admin.post('/api/operations/jobs/orphan/reconcile',json={'verified_target_state':False}).status_code==400
    assert admin.post('/api/operations/jobs/orphan/reconcile',json={'verified_target_state':True}).status_code==200
    worker.execute('next')
    with Session() as s:assert s.get(Job,'next').state=='complete'
    assert calls==['operation-status','repair','inventory']


def test_busy_worker_does_not_occupy_another_worker_slot(admin):
    with Session() as s:
        h=host(s);s.add(Job(id='next',host_id=h.id,action='repair'));s.commit()
    with worker.host_lock('audit-host'):worker.execute('next')
    with Session() as s:assert s.get(Job,'next').state=='queued'


def healthy():return {'failed_units':'','collector_active':True,'reboot_required':True}


def test_reboot_intent_survives_crash_before_submission(tmp_path,monkeypatch):
    monkeypatch.setattr(bridge,'ROOT',tmp_path)
    monkeypatch.setattr(bridge,'boot_id',lambda:'original-boot')
    monkeypatch.setattr(bridge,'handle',lambda req: {} if req['action']=='patch' else healthy())
    def crash(*a,**k):raise SystemExit('simulated process loss')
    monkeypatch.setattr(bridge,'run',crash)
    req={'job_id':'a'*36,'packages':['demo=2'],'policy':{'reboot':True}}
    with pytest.raises(SystemExit):bridge.protected_patch(req)
    state=json.loads((tmp_path/'transactions'/('a'*36+'.json')).read_text())
    assert state['state']=='reboot_pending'
    with pytest.raises(RuntimeError,match='incomplete'):bridge.protected_patch(req)
    with pytest.raises(RuntimeError,match='not rebooted'):bridge.complete_recovery(req)
    monkeypatch.setattr(bridge,'boot_id',lambda:'new-boot')
    assert bridge.complete_recovery(req)['outcome']=='complete'


def test_health_retries_and_then_completes_reboot(monkeypatch):
    calls=[];attempts=0
    def call(h,request,**kwargs):
        nonlocal attempts
        action=request['action'];calls.append(action)
        if action=='recovery-status':return {'boot_id':'new'}
        if action=='health':
            attempts+=1
            if attempts==1:raise RuntimeError('collector activating')
            return healthy()
        return {'outcome':'complete','reboot_verified':True}
    monkeypatch.setattr(worker.ssh,'call',call);monkeypatch.setattr(worker.time,'sleep',lambda _:None)
    result=worker.wait_for_reboot(None,{'boot_before':'old'},'a'*36,timeout=10)
    assert result['reboot_verified'] and attempts==2 and calls[-1]=='complete-recovery'


def test_failed_postboot_health_requests_one_rollback(admin,monkeypatch):
    with Session() as s:
        h=host(s);j=Job(id='b'*36,host_id=h.id,action='patch',state='running');s.add(j);s.commit()
        waits=[];calls=[]
        def wait(h,result,job_id,**kwargs):
            waits.append(result)
            if len(waits)==1:raise worker.RecoveryTimeout('unhealthy')
            return {'outcome':'rolled_back','reboot_verified':True}
        def call(h,request,**kw):
            calls.append(request);return {'outcome':'rollback_pending','reboot_scheduled':True,'boot_before':'new'}
        monkeypatch.setattr(worker,'wait_for_reboot',wait);monkeypatch.setattr(worker.ssh,'call',call)
        result=worker.finish_recovery(s,h,j,{'reboot_scheduled':True,'boot_before':'old'},{'rollback':True})
        assert result['outcome']=='rolled_back' and len(waits)==2
        assert calls==[{'action':'rollback-patch','job_id':j.id}]
        assert 'rollback_pending' in s.get(Job,j.id).output


def test_rollback_verification_survives_reverted_target_journal(monkeypatch):
    calls=[]
    def call(h,req,**kw):
        calls.append(req['action'])
        if req['action']=='patch-restored':
            assert req['original']=={'version':1}
            return {'outcome':'rolled_back','original_state_verified':True}
        return {'boot_id':'restored-boot'} if req['action']=='recovery-status' else healthy()
    monkeypatch.setattr(worker.ssh,'call',call);monkeypatch.setattr(worker.time,'sleep',lambda _:None)
    result=worker.wait_for_reboot(None,{'outcome':'rollback_pending','boot_before':'failed-boot'},'a'*36,original={'version':1})
    assert result['outcome']=='rolled_back' and result['reboot_verified']
    assert calls==['recovery-status','health','patch-restored']


def test_postboot_rollback_requires_changed_boot_and_never_repeats(tmp_path,monkeypatch):
    monkeypatch.setattr(bridge,'ROOT',tmp_path);monkeypatch.setattr(bridge,'boot_id',lambda:'old')
    journal=bridge.transaction_path('a'*36)
    state={'state':'reboot_scheduled','boot_before':'old','job':'a'*36,'policy':{'rollback':True,'reboot':False},'snapshot':'42'}
    journal.write_text(json.dumps(state));calls=[]
    monkeypatch.setattr(bridge,'recovery_hook',lambda *a:calls.append(a) or {'reboot_required':False})
    monkeypatch.setattr(bridge,'handle',lambda req:healthy())
    monkeypatch.setattr(bridge,'verify_patch_original',lambda original: {'outcome':'rolled_back','original_state_verified':True})
    with pytest.raises(RuntimeError,match='observed reboot'):bridge.rollback_after_reboot({'job_id':'a'*36})
    assert not calls
    monkeypatch.setattr(bridge,'boot_id',lambda:'new')
    assert bridge.rollback_after_reboot({'job_id':'a'*36})['outcome']=='rolled_back'
    assert bridge.rollback_after_reboot({'job_id':'a'*36})['outcome']=='rolled_back'
    assert calls==[('rollback','42')]


def test_patch_requires_reviewed_policy_and_rejects_later_changes(admin,monkeypatch):
    with Session() as s:
        h=host(s);s.add(Package(id=h.id+':demo:amd64',host_id=h.id,name='demo:amd64',installed='1',candidate='2'))
        s.add(Setting(key='recovery:'+h.id,value={'reboot':True,'rollback':False}));s.commit()
    url='/api/hosts/audit-host/patch';body={'packages':['demo:amd64']}
    assert admin.post(url,json=body).status_code==409
    policy=admin.get('/api/hosts/audit-host/patch-policy').json();assert policy['reboot']
    queued=admin.post(url,json={**body,'expected_recovery_policy':policy}).json()['job_id']
    with Session() as s:
        assert s.get(Job,queued).payload['_recovery_policy']==policy
        s.get(Setting,'recovery:audit-host').value={'reboot':False,'rollback':False};s.commit()
    calls=[]
    monkeypatch.setattr(worker,'save_inventory',lambda *a:None);monkeypatch.setattr(worker,'validate_patch',lambda *a:None)
    monkeypatch.setattr(worker.ssh,'call',lambda h,p,**kw:calls.append(p['action']) or {})
    worker.execute(queued)
    assert calls==['inventory']
    with Session() as s:assert s.get(Job,queued).state=='failed'


def test_deleted_and_replaced_library_mappings_are_not_silently_trusted(tmp_path,monkeypatch):
    proc=tmp_path/'proc';proc.mkdir();(proc/'root').mkdir()
    (proc/'maps').write_text('1000-2000 r-xp 0000 08:01 42 /lib/gone.so (deleted)\n2000-3000 r-xp 0000 08:01 43 /changed.so\n')
    (proc/'root/changed.so').write_text('replacement')
    monkeypatch.setattr(agent.os,'readlink',lambda _: '/usr/bin/demo')
    result=agent.provenance(proc,{})
    assert len(result)==2 and all(not x['identity_verified'] for x in result)
    assert all('sha256' not in x for x in result)


def test_mapped_inode_can_be_hashed_after_unlink(tmp_path,monkeypatch):
    proc=tmp_path/'proc';proc.mkdir();(proc/'map_files').mkdir()
    mapped=proc/'map_files/1000-2000';mapped.write_text('mapped content');info=mapped.stat()
    (proc/'maps').write_text(f'1000-2000 r-xp 0000 {os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x} {info.st_ino} /lib/deleted.so (deleted)\n')
    monkeypatch.setattr(agent.os,'readlink',lambda _: '/usr/bin/demo')
    result=agent.provenance(proc,{})
    assert result[0]['identity_verified'] and len(result[0]['sha256'])==64


def test_unverified_bpf_identity_is_preserved():
    event={'executable':'/tmp/exited','sha256':'unavailable','uid':'1000','capture':'ebpf','identity_verified':False}
    assert worker.behavior_evidence(event)['identity_verified'] is False


def test_protected_failure_quarantines_host_and_preserves_receipt(admin,monkeypatch):
    with Session() as s:
        h=host(s)
        s.add(Setting(key='recovery:'+h.id,value={'reboot':True,'rollback':False}))
        s.add(Job(id='protected',host_id=h.id,action='patch',payload={'packages':['demo:amd64=2'],'_recovery_policy':{'reboot':True,'rollback':False}}))
        s.add(Job(id='later',host_id=h.id,action='repair'));s.commit()
    calls=[]
    def call(h,req,**kw):
        calls.append(req['action'])
        if req['action']=='health':return healthy()
        return {'outcome':'reboot_pending','reboot_scheduled':True,'boot_before':'old'} if req['action']=='protected-patch' else {}
    def fail(*args):raise worker.RecoveryTimeout('target did not return')
    monkeypatch.setattr(worker.ssh,'call',call)
    monkeypatch.setattr(worker,'save_inventory',lambda *a:None)
    monkeypatch.setattr(worker,'validate_patch',lambda *a:None)
    monkeypatch.setattr(worker,'wait_for_reboot',fail)
    worker.execute('protected');worker.execute('later')
    with Session() as s:
        job=s.get(Job,'protected')
        assert job.state=='recovery_required' and 'boot_before' in job.output
        assert s.get(Job,'later').state=='queued'
    assert calls==['inventory','health','protected-patch']


def test_rollout_requires_each_hosts_reviewed_policy(admin):
    with Session() as s:
        a=host(s);b=Host(id='audit-second',name='Second',address='192.0.2.2',fingerprint='fixture',last_repo=time.time())
        s.add(b)
        for h in (a,b):s.add(Package(id=h.id+':demo:amd64',host_id=h.id,name='demo:amd64',installed='1',candidate='2'))
        s.add(Setting(key='recovery:'+b.id,value={'reboot':True,'rollback':False}));s.commit()
    body={'hosts':['audit-host','audit-second'],'packages':['demo:amd64']}
    assert admin.post('/api/operations/rollouts',json=body).status_code==409
    policies={'audit-host':{'reboot':False,'rollback':False},'audit-second':{'reboot':True,'rollback':False}}
    result=admin.post('/api/operations/rollouts',json={**body,'expected_recovery_policies':policies})
    assert result.status_code==200
    with Session() as s:
        for job_id in result.json()['jobs']:
            job=s.get(Job,job_id);assert job.payload['_recovery_policy']==policies[job.host_id]


def test_rollout_audits_each_queued_patch_job(admin):
    with Session() as s:
        a=host(s);b=Host(id='audit-third',name='Third',address='192.0.2.3',fingerprint='fixture',last_repo=time.time())
        s.add(b)
        for h in (a,b):s.add(Package(id=h.id+':demo:amd64',host_id=h.id,name='demo:amd64',installed='1',candidate='2'))
        s.commit()
    body={'hosts':['audit-host','audit-third'],'packages':['demo:amd64']}
    policies={h:{'reboot':False,'rollback':False} for h in body['hosts']}
    result=admin.post('/api/operations/rollouts',json={**body,'expected_recovery_policies':policies})
    assert result.status_code==200
    with Session() as s:
        queued=[r.detail for r in s.scalars(select(Audit).where(Audit.action=='queue patch'))]
    assert sorted(queued)==['audit-host','audit-third']


def test_rollout_rejects_full_server_queue(admin):
    with Session() as s:
        a=host(s);s.add(Package(id=a.id+':demo:amd64',host_id=a.id,name='demo:amd64',installed='1',candidate='2'))
        b=Host(id='audit-fourth',name='Fourth',address='192.0.2.4',fingerprint='fixture',last_repo=time.time());s.add(b)
        s.add(Package(id=b.id+':demo:amd64',host_id=b.id,name='demo:amd64',installed='1',candidate='2'))
        for i in range(50):s.add(Job(id='full-%d'%i,host_id=b.id,action='inventory',payload={}))
        s.commit()
    body={'hosts':['audit-host','audit-fourth'],'packages':['demo:amd64'],'expected_recovery_policies':{h:{'reboot':False,'rollback':False} for h in ('audit-host','audit-fourth')}}
    assert admin.post('/api/operations/rollouts',json=body).status_code==429
