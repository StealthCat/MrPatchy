import time
from types import SimpleNamespace

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


def test_ready_plan_precedes_future_plan_backoff(admin):
    now=time.time()
    with Session() as session:
        for identifier in ('ready-plan-host','future-plan-host'):
            session.add(Host(id=identifier,name=identifier,address='192.0.2.10',fingerprint='',state='online'))
        session.add_all([
            Job(id='ready-plan',host_id='ready-plan-host',action='security-plan',payload={'_ai_deferred':True},next_at=0),
            Job(id='future-plan',host_id='future-plan-host',action='startup-plan',payload={'_ai_deferred':True},next_at=now+300),
            Setting(key='worker:heartbeat',value={'seen':now}),
        ])
        session.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture-model'}))
        session.merge(Setting(key='openai_key',value={'encrypted':seal('fixture-key')}))
        session.commit();status=ai_runs.status(session)
        assert status['reason']=='ready' and status['plan_ready']==1
        assert status['plan_deferred']==2 and status['plan_next_at']==pytest.approx(now+300)


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
