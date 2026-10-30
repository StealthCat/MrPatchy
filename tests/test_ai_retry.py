import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from email.utils import formatdate
import httpx
import pytest
from sqlalchemy import select
from app import ai, ai_retry, ai_runs, worker
from app.db import Session, Setting, Behavior, Host, Audit
from app.identity import User
from app.security import seal


def setup():
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture','ai_hourly_limit':20}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        s.add(Host(id='host',name='Fixture',address='192.0.2.1',fingerprint=''))
        s.add(Behavior(id='subject',host_id='host',evidence={'executable':'/srv/fixture','sha256':'a'*64,'identity_verified':True}))
        s.commit()


def response(status=503,code='server_error',headers=None):
    return httpx.Response(status,json={'error':{'code':code,'message':'private-key raw-evidence'}},headers=headers,request=httpx.Request('POST',ai.URL))


def success(checks=None):
    result={'risk':'low','explanation':'Fixture assessment','recommended_checks':'Review uncertainty','requested_checks':checks or []}
    return httpx.Response(200,json={'status':'completed','output':[{'content':[{'type':'output_text','text':json.dumps(result)}]}]},request=httpx.Request('POST',ai.URL))


@pytest.mark.parametrize('status,code,transient',[(429,'rate_limit_exceeded',True),(429,'slow_down',True),(429,'insufficient_quota',False),(429,'private-code',False),(503,'server_error',True),(502,None,True),(500,'invalid_api_key',False),(401,'invalid_api_key',False),(400,'invalid_json_schema',False),(408,None,True),(404,'model_not_found',False)])
def test_http_classification_is_conservative(status,code,transient):
    error=ai.http_error(response(status,code,{'retry-after':'120','x-private':'raw-secret'}))
    assert error.transient is transient
    assert error.retry_after==(120 if transient else 0)
    assert 'raw-secret' not in str(error) and 'private-key' not in str(error)


@pytest.mark.parametrize('header,expected',[('60',60),('-1',0),('1.5',0),('nan',0),('infinity',0),('private-key',0),('x'*129,0)])
def test_retry_after_parsing(header,expected):
    assert ai.retry_after(response(headers={'retry-after':header}))==expected


def test_http_date_and_past_retry_after(monkeypatch):
    now=1793380000
    monkeypatch.setattr(ai.time,'time',lambda:now)
    assert ai.retry_after(response(headers={'retry-after':formatdate(now+100,usegmt=True)}))==100
    assert ai.retry_after(response(headers={'retry-after':formatdate(now-100,usegmt=True)}))==0


def test_durable_deferral_restart_manual_floor_receipts_and_success(admin,monkeypatch):
    setup();calls=[]
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:calls.append(1) or response(headers={'retry-after':'120'}))
    worker.investigate_one();worker.investigate_one()
    assert len(calls)==1
    with Session() as s:
        retry=s.get(ai_retry.TriageRetry,'subject');assert retry.state=='deferred' and retry.attempts==1
        assert 119<retry.next_at-time.time()<=120
        assert list(s.scalars(select(ai_runs.AICall)))[0].status=='unavailable'
        assert s.get(Behavior,'subject').approved is False
    # A fresh session / worker entry point reads the durable delay, not memory.
    persisted=json.loads(subprocess.check_output([sys.executable,'-c',"import json;from app.db import Session;from app.ai_retry import TriageRetry; s=Session();r=s.get(TriageRetry,'subject');print(json.dumps({'state':r.state,'next_at':r.next_at}));s.close()"],text=True,timeout=20))
    assert persisted['state']=='deferred' and persisted['next_at']>time.time()
    assert admin.post('/api/investigations/subject/retry').status_code==409
    with Session() as s:
        s.get(Setting,'config').value={**s.get(Setting,'config').value,'ai_model':'changed-model'};s.commit()
    worker.investigate_one();assert len(calls)==1  # Configuration changes cannot skip a provider floor.
    item=admin.get('/api/investigations').json()[0]
    assert item['retry']['state']=='deferred' and 'configuration' not in item['retry']
    ai_runs.heartbeat();status=admin.get('/api/investigation-status').json()
    assert status['ready']==0 and status['retry_at']>time.time() and status['reason']=='backoff'
    with Session() as s:
        r=s.get(ai_retry.TriageRetry,'subject');r.next_at=0;r.provider_until=0;s.commit()
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:calls.append(1) or success())
    worker.investigate_one()
    assert len(calls)==2
    with Session() as s:
        assert s.get(Behavior,'subject').verdict=='low' and not s.get(Behavior,'subject').approved
        assert s.get(ai_retry.TriageRetry,'subject') is None
        assert len(list(s.scalars(select(ai_runs.AICall))))==2


def test_configuration_block_does_not_starve_other_work_and_key_change_recovers(admin,monkeypatch):
    setup();calls=[]
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:calls.append(1) or response(429,'insufficient_quota'))
    worker.investigate_one();worker.investigate_one();assert len(calls)==1
    with Session() as s:
        r=s.get(ai_retry.TriageRetry,'subject');assert r.state=='blocked'
        s.add(Behavior(id='other',host_id='host',evidence={}));s.commit()
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:calls.append(1) or success())
    worker.investigate_one();assert len(calls)==2
    with Session() as s:
        assert s.get(Behavior,'subject').verdict=='error'
        s.get(Setting,'openai_key').value={'encrypted':seal('replacement-key')};s.commit()
    worker.investigate_one();assert len(calls)==3
    with Session() as s:assert s.get(Behavior,'subject').verdict=='low'


def test_bounded_retries_and_manual_reset_is_audited(admin,monkeypatch):
    setup();calls=[];bounds=[]
    monkeypatch.setattr(ai_retry.random,'uniform',lambda low,high:bounds.append((low,high)) or high)
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:calls.append(1) or response())
    for i in range(5):
        worker.investigate_one()
        with Session() as s:
            r=s.get(ai_retry.TriageRetry,'subject');assert r.attempts==i+1
            if i<4:r.next_at=0;s.commit()
    worker.investigate_one();assert len(calls)==5 and bounds==[(30,60),(30,120),(30,240),(30,480)]
    with Session() as s:assert s.get(ai_retry.TriageRetry,'subject').state=='blocked'
    assert admin.post('/api/investigations/subject/retry').status_code==200
    with Session() as s:
        assert s.get(ai_retry.TriageRetry,'subject') is None
        assert s.scalar(select(Audit).where(Audit.action=='retry AI investigation'))
    worker.investigate_one();assert len(calls)==6


def test_pause_lifecycle_and_follow_up_remain_gated(admin,monkeypatch):
    setup();calls=[]
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:calls.append(k['json']) or success(['executable']))
    def evidence(*a,**k):
        with Session() as s:s.merge(Setting(key='server-ai:host',value={'paused':True}));s.commit()
        return {'identity_verified':True,'sha256':'a'*64}
    monkeypatch.setattr(worker.ssh,'call',evidence)
    worker.investigate_one();assert len(calls)==1
    with Session() as s:
        assert s.get(Behavior,'subject').verdict=='error' and not s.get(Behavior,'subject').approved
        assert 'investigation' in s.get(Behavior,'subject').evidence
    ai_runs.heartbeat();status=admin.get('/api/investigation-status').json();assert status['paused']==1 and status['ready']==0
    assert admin.get('/api/investigations').json()[0]['retry']['state']=='paused'
    worker.investigate_one();assert len(calls)==1
    with Session() as s:
        s.get(Setting,'server-ai:host').value={'paused':False};s.get(Host,'host').enabled=False;s.commit()
    worker.investigate_one();assert len(calls)==1
    with Session() as s:s.get(Host,'host').enabled=True;s.commit()
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:calls.append(k['json']) or success())
    worker.investigate_one();assert len(calls)==2
    with Session() as s:assert s.get(Behavior,'subject').verdict=='low'


def test_oversized_delay_blocks_without_early_automatic_retry():
    error=ai.http_error(response(headers={'retry-after':'999999999999999999999999999999999'}))
    assert not error.transient and 'outside supported bounds' in str(error)


def test_interrupted_attempts_have_durable_recovery_and_finite_limit(admin,monkeypatch):
    setup();calls=[]
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:calls.append(1) or success())
    with Session() as s:
        row=s.get(Behavior,'subject');signature=ai_retry.configuration(s)
        ai_retry.begin(s,row,signature,time.time());s.commit()
    worker.investigate_one();assert calls==[]
    with Session() as s:
        retry=s.get(ai_retry.TriageRetry,'subject');retry.attempts=5;retry.next_at=0;s.commit()
    worker.investigate_one();assert calls==[]
    assert admin.get('/api/investigations').json()[0]['retry']['state']=='blocked'
    assert admin.post('/api/investigations/subject/retry').status_code==200
    worker.investigate_one();assert len(calls)==1


def test_failed_follow_up_retains_evidence_receipts_and_repeats_required_checks(admin,monkeypatch):
    setup();calls=[];ssh_calls=[]
    def post(*a,**k):
        calls.append(k['json'])
        if len(calls)==2:raise httpx.ReadTimeout('private-key lost response')
        return success(['executable'] if len(calls) in (1,3) else [])
    monkeypatch.setattr(ai.transport,'post',post)
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:ssh_calls.append(1) or {'identity_verified':True,'sha256':'a'*64})
    worker.investigate_one()
    with Session() as s:
        assert s.get(Behavior,'subject').verdict=='error'
        assert 'investigation' in s.get(Behavior,'subject').evidence
        assert len(list(s.scalars(select(ai_runs.AICall))))==2
        assert all(r.status=='unavailable' for r in s.scalars(select(ai_runs.AICall)))
        s.get(ai_retry.TriageRetry,'subject').next_at=0;s.commit()
    worker.investigate_one();assert len(calls)==4 and len(ssh_calls)==2
    assert all(c['model']=='fixture' and c['max_output_tokens']==1600 and c['text']['format']['schema']==ai.SCHEMA for c in calls)
    with Session() as s:
        row=s.get(Behavior,'subject');assert row.verdict=='low' and not row.approved
        assert len(list(s.scalars(select(ai_runs.AICall))))==4
def test_same_host_independent_subject_not_blocked_by_retry_and_duplicate_workers(admin,monkeypatch):
    setup();calls=[]
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:calls.append(1) or response(headers={'retry-after':'120'}))
    worker.investigate_one()
    with Session() as s:s.add(Behavior(id='other',host_id='host',evidence={}));s.commit()
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:calls.append(1) or success())
    with ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(lambda _:worker.investigate_one(),range(2)))
    assert len(calls)==2
    with Session() as s:assert s.get(Behavior,'other').verdict=='low' and s.get(Behavior,'subject').verdict=='error'


def test_manual_retry_roles_and_csrf(admin):
    setup()
    for role in ('viewer','operator'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.post('/api/investigations/subject/retry').status_code==403
    with Session() as s:s.get(User,'admin').role='admin';s.commit()
    admin.headers.pop('X-CSRF-Token')
    assert admin.post('/api/investigations/subject/retry').status_code==403
