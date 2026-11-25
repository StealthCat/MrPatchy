import time
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_admission, ai_runs, incidents, startup_ai, worker
from app.db import Host, Job, Session, Setting
from app.security import seal


def plan(identifier):
    return {'summary': 'Review the retained scanner evidence', 'severity': 'unknown',
        'uncertainty': 'The finding may be a false positive.',
        'steps': [{'action': 'preserve_evidence', 'reason': 'Retain the artifact receipt.',
            'impact': 'Uses protected storage.', 'verification': 'Compare the retained digest.',
            'evidence_ids': [identifier, 'scan-plan']}]}


def seed_security_plan():
    with Session() as session:
        session.add(Host(id='plan-host', name='Plan host', address='192.0.2.1',
            fingerprint='', state='online'))
        report={'state':'completed_with_findings','findings':[{
            'path':'/srv/fixture','sha256':'a'*64,'evidence':'fixture rule'}]}
        incidents.record(session, 'plan-host', 'scan-plan', report)
        incident=session.scalar(select(incidents.Incident))
        session.merge(Setting(key='config', value={'ai_enabled':True,
            'ai_model':'fixture-model','ai_control_mode':'rate','ai_rate_per_hour':20}))
        session.merge(Setting(key='openai_key', value={'encrypted':seal('fixture-key')}))
        session.commit()
        return worker.enqueue(session, 'plan-host', 'security-plan', {'incident_id':incident.id}),incident.id


def test_security_plan_rate_refusal_stays_queued_and_resumes(admin, monkeypatch):
    job_id,incident_id=seed_security_plan();floor=time.time()+120
    with Session() as session:
        session.add(ai_admission.Admission(id='global', next_at=floor, admitted=1,
            updated=time.time(), model='fixture-model'))
        session.commit()
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: pytest.fail('deferred plan reached provider transport'))
    worker.execute(job_id)
    with Session() as session:
        job=session.get(Job, job_id)
        assert job.state=='queued' and job.next_at==pytest.approx(floor, abs=1)
        assert job.payload['_ai_deferred'] is True and 'queued' in job.output.lower()
        run=session.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.purpose=='security_plan'))
        assert run.state=='deferred' and run.calls==0
        status=ai_runs.status(session)
        assert status['plan_deferred']==1
        assert status['plan_next_at']==pytest.approx(floor,abs=1)
    for path in ('/api/jobs?host_id=plan-host','/api/jobs/'+job_id+'?host_id=plan-host'):
        result=admin.get(path).json();result=result[0] if isinstance(result,list) else result
        assert result['ai_deferred'] is True and 'payload' not in result
    worker.execute(job_id)
    with Session() as session:
        assert session.get(Job, job_id).state=='queued'
        session.get(Job, job_id).next_at=0
        session.get(ai_admission.Admission, 'global').next_at=0
        session.commit()
    monkeypatch.setattr(ai, 'request', lambda *a, **k: plan(incident_id))
    worker.execute(job_id)
    with Session() as session:
        job=session.get(Job, job_id)
        assert job.state=='complete' and job.next_at==0
        assert '_ai_deferred' not in job.payload
        assert session.scalar(select(incidents.Plan)).incident_id==incident_id


def test_startup_plan_shared_wait_is_retained_by_the_job(admin, monkeypatch):
    now=time.time()
    with Session() as session:
        session.add(Host(id='startup-plan-host',name='Startup plan host',address='192.0.2.2',
            fingerprint='',state='online'))
        session.add(incidents.PersistenceIncident(id='startup-incident',host_id='startup-plan-host',
            baseline_id='baseline',updated=now,evidence={'changes':[]}))
        job_id=worker.enqueue(session,'startup-plan-host','startup-plan',
            {'incident_id':'startup-incident','expected_updated':repr(now)})
    monkeypatch.setattr(startup_ai, 'generate', lambda *a, **k: (_ for _ in ()).throw(
        ai.AIError('Shared provider wait.', policy_wait=True, retry_after=90)))
    worker.execute(job_id)
    with Session() as session:
        job=session.get(Job,job_id)
        assert job.state=='queued' and 89<=job.next_at-time.time()<=90
        assert job.payload['_ai_deferred'] is True
    monkeypatch.setattr(startup_ai, 'generate', lambda *a, **k: SimpleNamespace(id='startup-plan'))
    with Session() as session:
        session.get(Job,job_id).next_at=0;session.commit()
    worker.execute(job_id)
    with Session() as session:
        assert session.get(Job,job_id).state=='complete'


def test_uncontrolled_plan_error_remains_terminal(admin, monkeypatch):
    job_id,_=seed_security_plan()
    monkeypatch.setattr(incidents,'generate',lambda *a,**k: (_ for _ in ()).throw(
        ai.AIError('Saved AI configuration requires review.')))
    worker.execute(job_id)
    with Session() as session:
        job=session.get(Job,job_id)
        assert job.state=='failed' and job.next_at==0
        assert '_ai_deferred' not in job.payload


@pytest.mark.parametrize('plan_kind', ['incident', 'startup'])
@pytest.mark.parametrize('response_kind', ['refusal', 'token_limit', 'other_incomplete'])
def test_plan_provider_failures_keep_accurate_redacted_diagnostics(admin, monkeypatch, plan_kind, response_kind):
    if plan_kind == 'incident':
        job_id, incident_id = seed_security_plan()
    else:
        from test_startup_ai import BASE, setup_incident

        incident_id = setup_incident(admin)
        with Session() as session:
            updated = session.get(incidents.PersistenceIncident, incident_id).updated
        queued = admin.post(f'{BASE}/persistence-incidents/{incident_id}/plan',
                            json={'expected_updated': updated})
        assert queued.status_code == 200
        job_id = queued.json()['job_id']

    raw_provider_text = 'private refusal /srv/provider-only-marker'
    if response_kind == 'refusal':
        response = {'status': 'completed', 'output': [
            {'content': [{'type': 'refusal', 'refusal': raw_provider_text}]}]}
    else:
        reason = 'max_output_tokens' if response_kind == 'token_limit' else 'other'
        response = {'status': 'incomplete', 'incomplete_details': {'reason': reason}}

    def provider(*args, **kwargs):
        return httpx.Response(200, json=response, request=httpx.Request('POST', ai.URL))

    monkeypatch.setattr(ai.transport, 'post', provider)
    worker.execute(job_id)

    with Session() as session:
        job = session.get(Job, job_id)
        run = session.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.subject == incident_id))
        receipt = session.scalar(select(ai_runs.AICall).where(ai_runs.AICall.run_id == run.id))
        events = list(session.scalars(select(ai_runs.AIEvent).where(ai_runs.AIEvent.run_id == run.id)))
        assert job.state == 'failed' and job.next_at == 0 and '_ai_deferred' not in job.payload
        assert run.state == 'error' and run.calls == 1 and receipt is not None
        assert not session.scalar(select(incidents.Plan).where(incidents.Plan.incident_id == incident_id))
        assert job.output.strip() == run.message
        assert [event.message for event in events if event.stage == 'failed'] == [run.message]
        assert all(raw_provider_text not in text for text in [job.output, run.message, *(e.message for e in events)])
        if response_kind == 'other_incomplete':
            assert run.message == ('OpenAI did not complete the structured response. '
                                   'No partial assessment was accepted; retry or review the model configuration.')
        else:
            assert 'No advisory plan was accepted.' in run.message
            assert 'may be billed' in run.message and 'review' in run.message.lower()
            reason = 'model refused' if response_kind == 'refusal' else 'response token budget'
            assert reason in run.message


def test_ready_plan_precedes_future_plan_backoff(admin):
    from app.identity import User

    now=time.time()
    with Session() as session:
        for identifier in ('ready-plan-host','future-plan-host','paused-plan-host'):
            session.add(Host(id=identifier,name=identifier,address='192.0.2.10',fingerprint='',state='online'))
        session.add_all([
            Job(id='ready-plan',host_id='ready-plan-host',action='security-plan',payload={'_ai_deferred':True},next_at=0),
            Job(id='future-plan',host_id='future-plan-host',action='startup-plan',payload={'_ai_deferred':True},next_at=now+300),
            Job(id='paused-plan',host_id='paused-plan-host',action='security-plan',payload={'_ai_deferred':True},next_at=0),
            Setting(key='server-ai:paused-plan-host',value={'paused':True}),
            Setting(key='worker:heartbeat',value={'seen':now}),
        ])
        session.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture-model'}))
        session.merge(Setting(key='openai_key',value={'encrypted':seal('fixture-key')}))
        session.commit();status=ai_runs.status(session)
        assert status['reason']=='ready' and status['plan_ready']==1
        assert status['plan_deferred']==3 and status['plan_next_at']==pytest.approx(now+300)
    response=admin.get('/api/investigation-status')
    assert response.status_code==200
    assert response.json()['plan_deferred_by_action']=={
        'release-plan':{'deferred':0,'ready':0,'next_at':None},
        'security-plan':{'deferred':2,'ready':1,'next_at':None},
        'startup-plan':{'deferred':1,'ready':0,'next_at':pytest.approx(now+300)},
    }
    assert 'paused-plan-host' not in response.text
    with Session() as session:
        session.get(User,'admin').role='viewer'
        session.commit()
    viewer=admin.get('/api/investigation-status')
    assert viewer.status_code==200
    assert set(viewer.json())=={'pending','oldest','enabled'}


@pytest.mark.parametrize('include_resumed_server', (False, True))
def test_paused_plan_retry_is_recorded_without_becoming_next_eligible(admin,include_resumed_server):
    now=time.time()
    with Session() as session:
        for host_id in ('paused-plan-host','resumed-plan-host'):
            session.add(Host(id=host_id,name=host_id,address='192.0.2.10',fingerprint='',state='online'))
        session.add(Job(id='paused-plan',host_id='paused-plan-host',action='security-plan',
            payload={'_ai_deferred':True},next_at=now+120))
        if include_resumed_server:
            session.add(Job(id='resumed-plan',host_id='resumed-plan-host',action='startup-plan',
                payload={'_ai_deferred':True},next_at=now+300))
        session.add(Setting(key='server-ai:paused-plan-host',value={'paused':True}))
        session.add(Setting(key='worker:heartbeat',value={'seen':now}))
        session.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture-model'}))
        session.merge(Setting(key='openai_key',value={'encrypted':seal('fixture-key')}))
        session.commit()

    response=admin.get('/api/investigation-status')
    assert response.status_code==200
    status=response.json()
    assert status['plan_next_at']==pytest.approx(now+120)
    assert status['plan_deferred_by_action']['security-plan']['next_at']==pytest.approx(now+120)
    if include_resumed_server:
        assert status['reason']=='backoff'
        assert status['retry_at']==pytest.approx(now+300)
        assert status['plan_next_eligible_at']==pytest.approx(now+300)
    else:
        assert status['reason']=='blocked' and 'resumed' in status['message']
        assert status['retry_at'] is None and status['plan_next_eligible_at'] is None
    assert 'paused-plan-host' not in response.text

    with Session() as session:
        session.get(Setting,'server-ai:paused-plan-host').value={'paused':False}
        session.commit()
    status=admin.get('/api/investigation-status').json()
    assert status['plan_next_eligible_at']==pytest.approx(now+120)
    assert status['retry_at']==pytest.approx(now+120)

    with Session() as session:
        session.get(Setting,'config').value={'ai_enabled':False,'ai_model':'fixture-model'}
        session.commit()
    status=admin.get('/api/investigation-status').json()
    assert status['reason']=='disabled'
    assert status['plan_next_eligible_at'] is None and status['retry_at'] is None
    assert status['plan_next_at']==pytest.approx(now+120)


def test_indefinite_policy_wait_records_deferred_run(admin, monkeypatch):
    job_id,_=seed_security_plan()
    monkeypatch.setattr(ai,'request',lambda *a,**k: (_ for _ in ()).throw(
        ai.AIError('Administrator pause.',policy_wait=True,retry_after=0)))
    worker.execute(job_id)
    with Session() as session:
        job=session.get(Job,job_id)
        run=session.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.purpose=='security_plan'))
        assert job.state=='queued' and job.next_at==0 and job.payload['_ai_deferred'] is True
        assert run.state=='deferred' and run.stage=='deferred' and 'resume' in run.message


@pytest.mark.parametrize('action',['release-plan','security-plan','startup-plan'])
def test_scheduler_skips_ai_plans_while_paused_or_disabled(admin,action):
    from app import ai_policy
    with Session() as session:
        session.add(Host(id='skip-host',name='skip',address='192.0.2.11',fingerprint='',state='online'))
        session.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture-model'}))
        job=Job(id='skip-job',host_id='skip-host',action=action,payload={'_ai_deferred':True},next_at=0)
        session.add(job);session.commit()
        assert worker.ai_plan_waiting(session,job) is False
        session.merge(Setting(key='config',value={'ai_enabled':False,'ai_model':'fixture-model'}));session.commit()
        assert worker.ai_plan_waiting(session,job) is True
        session.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture-model'}));session.commit()
        session.merge(Setting(key=ai_policy.PREFIX+'skip-host',value={'paused':True}));session.commit()
        assert worker.ai_plan_waiting(session,job) is True
    with Session() as session:
        patch=Job(id='patch-job',host_id='skip-host',action='patch',payload={},next_at=0)
        assert worker.ai_plan_waiting(session,patch) is False
