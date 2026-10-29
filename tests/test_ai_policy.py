import pytest
from app import ai_policy,ai,ai_runs
from app.db import Session,Host,Setting,Audit,Job,Behavior
from app.coordination import Lock
from app.identity import User
from sqlalchemy import select

BASE='/api/hosts/one/security/ai-policy'
@pytest.fixture
def managed(admin):
    with Session() as s:
        s.add_all([Host(id=x,name=x,address='192.0.2.1',fingerprint='') for x in ('one','two')]);s.add(Setting(key='config',value={'ai_enabled':True}));s.commit()
    return admin

def pause(client,**changes):
    current=client.get(BASE).json()
    return client.put(BASE,json={'paused':True,'expected_revision':current['revision'],'reason':'Pause provider processing for review',**changes})

def test_persistence_isolation_revision_audit_and_global_precedence(managed):
    assert pause(managed).status_code==200
    with Session() as s:
        assert ai_policy.status(s,'one')['paused']
        assert not ai_policy.status(s,'two')['paused']
        assert 'one admin' in s.scalar(select(Audit).where(Audit.action=='server AI paused')).detail
        assert list(s.scalars(ai_policy.paused_ids()))==['one']
        s.get(Setting,'config').value={'ai_enabled':False};s.commit()
    assert pause(managed,expected_revision='').status_code==400
    assert pause(managed,paused=False).json()['state']=='globally_disabled'
    with pytest.raises(ai.AIError,match='globally disabled'):ai_policy.require(['one'])

def test_actual_provider_boundary_blocks_queued_shared_and_followup_calls(managed,monkeypatch):
    calls=[];monkeypatch.setattr(ai,'_request',lambda *a,**k:calls.append(1) or {})
    with ai_runs.track('triage','fixture',host_id='one'):
        ai.request({'model':'fixture'},'key')
        assert pause(managed).status_code==200
        with pytest.raises(ai.AIError,match='paused'):ai.request({'model':'fixture'},'key')
    with ai_runs.track('update_scoring','fixture',host_ids=['two','one']):
        with pytest.raises(ai.AIError,match='paused'):ai.request({'model':'fixture'},'key')
    with ai_runs.track('security_plan','fixture',host_id='one'):
        with pytest.raises(ai.AIError,match='paused'):ai.request({'model':'fixture'},'key')
    with ai_runs.track('triage','fixture',host_id='two'):ai.request({'model':'fixture'},'key')
    assert len(calls)==2 and ai_policy.scope.get()==()

def test_inflight_conflict_permissions_csrf_deleted_and_non_ai(managed):
    with Lock('ai-provider:one'):assert pause(managed).status_code==409
    assert not managed.get(BASE).json()['paused']
    pause(managed)
    with Session() as s:
        assert s.get(Host,'one').enabled
        s.add(Job(id='scan',host_id='one',action='security-scan'));s.commit()
    assert managed.get('/api/hosts/one/summary').status_code==200
    csrf=managed.headers.pop('X-CSRF-Token')
    assert pause(managed).status_code==403
    managed.headers['X-CSRF-Token']=csrf
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert managed.get(BASE).status_code==403
        assert managed.put(BASE,json={'paused':False,'reason':'A meaningful reason'}).status_code==403

def test_manual_entry_points_reject_before_mocked_provider(managed,monkeypatch):
    from app import incidents,releases,worker,startup_ai
    from types import SimpleNamespace
    pause(managed)
    monkeypatch.setattr(ai,'request',lambda *a,**k:pytest.fail('provider bypass'))
    with Session() as s:
        for fn in (lambda:incidents.generate(s,SimpleNamespace(host_id='one')),lambda:startup_ai.generate(s,SimpleNamespace(host_id='one',updated=0),0),lambda:releases.ai_review(s,'','','','','',host_id='one'),lambda:worker._assess_behavior(s,SimpleNamespace(host_id='one'),{},None)):
            with pytest.raises(ai.AIError,match='paused'):fn()


def test_automatic_scoring_and_triage_skip_paused_host_without_starvation(managed,monkeypatch):
    from app import worker,update_scores
    from app.db import Package
    from app.security import seal
    with Session() as s:
        s.get(Setting,'config').value={'ai_enabled':True,'ai_model':'fixture'}
        s.add(Setting(key='openai_key',value={'encrypted':seal('fixture-key')}))
        for host in ('one','two'):
            s.add(Behavior(id=host,host_id=host,evidence={'executable':'/srv/test','sha256':'a'*64}))
            s.add(Package(id=host+':pkg',host_id=host,name='pkg',installed='1',candidate='2'))
        s.commit()
    pause(managed)
    seen=[]
    monkeypatch.setattr(worker,'_assess_behavior',lambda s,row,*args:seen.append(row.host_id))
    worker.investigate_one();assert seen==['two']
    def provider(payload,*args,**kwargs):
        import json
        batch=json.loads(payload['input']);assert len(batch)==1
        with Session() as s:assert s.get(update_scores.UpdateScore,batch[0]['id']).host_id=='two'
        return {'assessments':[{'id':batch[0]['id'],'score':40,'confidence':'low','explanation':'fixture assessment','limitations':'No advisory evidence'}]}
    monkeypatch.setattr(ai,'request',provider);update_scores.run_one()
    with Session() as s:
        assert list(s.scalars(select(update_scores.UpdateScore.host_id)))==['two']
        assert s.get(Behavior,'one').attempted==0


def test_deleted_state_is_read_only(managed):
    import time
    with Session() as s:s.get(Host,'one').deleted_at=time.time();s.commit()
    assert managed.get(BASE).status_code==200
    assert pause(managed).status_code==409


def test_pause_can_be_preconfigured_while_management_disabled(managed):
    with Session() as s:s.get(Host,'one').enabled=False;s.commit()
    assert pause(managed).status_code==200
    with Session() as s:assert s.get(Host,'one').enabled is False


def test_queued_security_plan_rechecks_pause_at_worker_execution(managed,monkeypatch):
    from app import incidents,worker
    with Session() as s:
        s.add(incidents.Incident(id='queued-incident',host_id='one',scan_id='scan',evidence={'path':'/srv/test','sha256':'a'*64}));s.commit()
        job_id=worker.enqueue(s,'one','security-plan',{'incident_id':'queued-incident'})
    assert pause(managed).status_code==200
    monkeypatch.setattr(ai,'request',lambda *a,**k:pytest.fail('Paused queued work reached provider'))
    worker.execute(job_id)
    with Session() as s:
        job=s.get(Job,job_id)
        assert job.state=='failed',job.output
        assert 'paused' in job.output
        assert not list(s.scalars(select(incidents.Plan)))
