"""Advisory AI plan jobs left running by a lost worker (issue #104)."""
import time

import pytest
from sqlalchemy import select

from app import ai, ai_budget, ai_runs, incidents, operations, worker
from app.coordination import Lock
from app.db import Audit, Host, Job, Session, Setting
from app.security import seal


class WorkerKilled(BaseException):
    """Stands in for process death: no Exception handler or commit runs."""


def seed(host_id='recovery-host'):
    with Session() as session:
        session.add(Host(id=host_id, name='Recovery host', address='192.0.2.40', fingerprint='', state='online'))
        report={'state':'completed_with_findings','findings':[{'path':'/srv/fixture','sha256':'b'*64,'evidence':'fixture rule'}]}
        incidents.record(session, host_id, 'scan-recovery', report)
        incident=session.scalar(select(incidents.Incident).where(incidents.Incident.host_id==host_id))
        session.merge(Setting(key='config', value={'ai_enabled':True,'ai_model':'gpt-6-luna',
            'ai_control_mode':'daily_cap','ai_daily_cap_usd':5.0,'ai_budget_timezone':'UTC'}))
        session.merge(Setting(key='openai_key', value={'encrypted':seal('fixture-key')}))
        session.commit()
        return worker.enqueue(session, host_id, 'security-plan', {'incident_id':incident.id}),incident.id


def crashed(job_id):
    with pytest.raises(WorkerKilled):worker.execute(job_id)
    with Session() as session:
        job=session.get(Job, job_id)
        assert job.state=='running'
        # A stale running job holds the whole server's operation queue.
        assert operations.host_quarantined(session, job.host_id)


def assert_fenced(job_id, incident_id):
    with Session() as session:
        job=session.get(Job, job_id)
        assert job.state=='interrupted' and job.next_at==0 and 'not replayed' in job.output
        assert not operations.host_quarantined(session, job.host_id)
        run=session.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.purpose=='security_plan',ai_runs.AIRun.subject==incident_id))
        assert run.state=='interrupted' and run.finished>0 and 'not replayed' in run.message
        assert session.scalar(select(Audit).where(Audit.action=='interrupted security-plan'))
        assert not session.scalar(select(incidents.Plan).where(incidents.Plan.incident_id==incident_id))


def test_crash_before_provider_transmission_is_fenced_without_replay(admin, monkeypatch):
    job_id,incident_id=seed()
    sent=[]
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: sent.append(True))
    monkeypatch.setattr(ai, 'request', lambda *a, **k: (_ for _ in ()).throw(WorkerKilled()))
    crashed(job_id)
    assert worker.reconcile_advisory_plans()==[job_id]
    assert_fenced(job_id, incident_id)
    with Session() as session:
        assert session.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.subject==incident_id)).calls==0
    # Terminal: neither the scheduler nor a second reconciliation resends it.
    worker.execute(job_id)
    assert worker.reconcile_advisory_plans()==[] and sent==[]


def test_crash_after_provider_transmission_keeps_uncertain_spend(admin, monkeypatch):
    job_id,incident_id=seed()
    sent=[]
    def transmitted(*args, **kwargs):
        sent.append(True);raise WorkerKilled()
    monkeypatch.setattr(ai.transport, 'post', transmitted)
    crashed(job_id)
    assert len(sent)==1
    assert worker.reconcile_advisory_plans()==[job_id]
    assert_fenced(job_id, incident_id)
    with Session() as session:
        entry=session.scalar(select(ai_budget.BudgetEntry))
        assert entry.status=='sent' and entry.call_id
        status=ai_budget.status(session)
        assert float(status['uncertain_usd'])>0
        assert session.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.subject==incident_id)).calls==1
    worker.execute(job_id)
    assert worker.reconcile_advisory_plans()==[] and len(sent)==1


@pytest.mark.parametrize('owner', ['other-process', 'this-process'])
def test_live_owner_keeps_its_running_plan(admin, monkeypatch, owner):
    job_id,incident_id=seed()
    monkeypatch.setattr(ai, 'request', lambda *a, **k: (_ for _ in ()).throw(WorkerKilled()))
    crashed(job_id)
    # The executing worker holds the host lock until its final commit.
    lock=Lock('host:recovery-host') if owner=='other-process' else worker.host_lock('recovery-host')
    assert lock.acquire(False)
    try:assert worker.reconcile_advisory_plans()==[]
    finally:lock.release()
    with Session() as session:
        assert session.get(Job, job_id).state=='running'
        assert session.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.subject==incident_id)).state=='running'
    assert worker.reconcile_advisory_plans()==[job_id]


def test_only_stale_advisory_plans_are_reconciled(admin):
    now=time.time()
    with Session() as session:
        session.add(Host(id='mixed-host', name='Mixed host', address='192.0.2.41', fingerprint='', state='online'))
        session.add_all([
            Job(id='stale-startup', host_id='mixed-host', action='startup-plan', state='running',
                payload={'incident_id':'startup-incident','_ai_deferred':True}),
            Job(id='upgrade', host_id='mixed-host', action='release-upgrade', state='running', payload={'plan_id':'p'}),
            Job(id='release-plan', host_id='mixed-host', action='release-plan', state='running', payload={'plan_id':'p'}),
            Job(id='queued-plan', host_id='mixed-host', action='security-plan', state='queued', payload={'incident_id':'x'}),
            Job(id='done-plan', host_id='mixed-host', action='security-plan', state='complete', payload={'incident_id':'y'}),
            ai_runs.AIRun(id='other-run', purpose='security_plan', host_id='mixed-host', subject='unrelated', started=now),
        ])
        session.commit()
    assert worker.reconcile_advisory_plans()==['stale-startup']
    with Session() as session:
        stale=session.get(Job, 'stale-startup')
        assert stale.state=='interrupted' and '_ai_deferred' not in stale.payload
        # Target-side release work keeps its existing resume/manual reconciliation paths.
        assert {identifier:session.get(Job, identifier).state for identifier in ('upgrade','release-plan','queued-plan','done-plan')}=={
            'upgrade':'running','release-plan':'running','queued-plan':'queued','done-plan':'complete'}
        assert session.get(ai_runs.AIRun, 'other-run').state=='running'
