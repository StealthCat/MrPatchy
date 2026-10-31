import time
from decimal import Decimal

import pytest
from sqlalchemy import select

from app import ai_runs, worker
from app.ai_budget import BudgetEntry
from app.db import Audit, Host, Job, Session


def seed(action='security-plan', suffix=''):
    host_id='advisory-host'+suffix;job_id='advisory-job'+suffix;run_id='advisory-run'+suffix
    now=time.time()
    with Session() as s:
        s.add(Host(id=host_id,name='Advisory fixture',address='192.0.2.1',fingerprint='pin',state='online'))
        s.add(Job(id=job_id,host_id=host_id,action=action,state='running',next_at=now+300,
            payload={'incident_id':'incident'+suffix,'_ai_deferred':True}))
        s.add(ai_runs.AIRun(id=run_id,purpose='security_plan',host_id=host_id,subject='incident'+suffix,
            state='running',stage='provider',message='private evidence must not be copied'))
        s.add(ai_runs.AICall(id='advisory-call'+suffix,run_id=run_id,number=1,requested_model='fixture-model',
            status='unavailable',reason='No usage receipt was received.'))
        s.add(BudgetEntry(id='advisory-budget'+suffix,run_id=run_id,call_id='advisory-call'+suffix,
            created=now,updated=now,reset_at=now+3600,timezone='UTC',model='fixture-model',status='uncertain',
            reservation_usd=Decimal('0.25'),pricing_version='fixture',pricing_source='fixture'))
        s.commit()
    return host_id,job_id,run_id


@pytest.mark.parametrize('action',['security-plan','startup-plan'])
def test_orphaned_advisory_plan_requires_receipt_review_without_replay(admin,action):
    host_id,job_id,run_id=seed(action,'-'+action)
    assert worker.reconcile_interrupted_advisory_jobs()==1
    assert worker.reconcile_interrupted_advisory_jobs()==0
    worker.execute(job_id)
    with Session() as s:
        job=s.get(Job,job_id);run=s.get(ai_runs.AIRun,run_id)
        call=s.get(ai_runs.AICall,'advisory-call-'+action)
        budget=s.get(BudgetEntry,'advisory-budget-'+action)
        events=list(s.scalars(select(ai_runs.AIEvent).where(ai_runs.AIEvent.run_id==run_id)))
        assert job.state=='recovery_required' and job.next_at==0 and '_ai_deferred' not in job.payload
        assert 'No AI call was replayed' in job.output and 'private evidence' not in job.output
        assert run.state=='interrupted' and run.stage=='interrupted' and run.finished>0
        assert len(events)==1 and events[0].stage=='interrupted'
        assert call.status=='unavailable' and budget.status=='uncertain' and Decimal(budget.reservation_usd)==Decimal('0.25')
        assert s.scalar(select(Audit).where(Audit.action=='recover interrupted '+action))


def test_live_advisory_worker_is_not_reclassified(admin):
    _,job_id,run_id=seed(suffix='-owned')
    with worker.host_lock('advisory-host-owned'):
        assert worker.reconcile_interrupted_advisory_jobs()==0
    with Session() as s:
        assert s.get(Job,job_id).state=='running'
        assert s.get(ai_runs.AIRun,run_id).state=='running'


def test_advisory_reconciliation_reviews_central_receipts_without_target_access(admin,monkeypatch):
    _,job_id,_=seed(suffix='-review')
    worker.reconcile_interrupted_advisory_jobs()
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:pytest.fail('advisory reconciliation must not query or mutate the target'))
    response=admin.post('/api/operations/jobs/'+job_id+'/reconcile',json={'verified_ai_receipts':False})
    assert response.status_code==400 and 'spend reservation' in response.json()['detail']
    assert admin.post('/api/operations/jobs/'+job_id+'/reconcile',json={'verified_target_state':True}).status_code==400
    assert admin.post('/api/operations/jobs/'+job_id+'/reconcile',json={'verified_ai_receipts':True}).status_code==200
    with Session() as s:
        job=s.get(Job,job_id)
        assert job.state=='interrupted' and 'was not replayed' in job.output


def test_recovery_failure_keeps_scheduler_admitting_work_and_waits_five_seconds(admin,monkeypatch,caplog):
    from concurrent.futures import Future
    from app import execution_scans,persistence,response_monitor,service_monitor,worker_registry

    with Session() as s:
        s.add(Host(id='scheduler-host',name='Scheduler fixture',address='192.0.2.2',fingerprint='',state='online'))
        s.add(Job(id='scheduler-job',host_id='scheduler-host',action='refresh'))
        s.commit()
    for module in (worker.incidents,persistence,response_monitor,service_monitor,execution_scans):
        monkeypatch.setattr(module,'schedule_tick',lambda *a:None)
    monkeypatch.setattr(worker.incidents,'auto_plan_tick',lambda *a:None)
    monkeypatch.setattr(worker.operations,'collect_alerts',lambda:None)
    scheduled=[];admitted=[];recoveries=[];tick=[0];now=time.time()
    monkeypatch.setattr(worker.scheduling,'tick',lambda *a:scheduled.append(tick[0]))
    monkeypatch.setattr(worker,'submit_job',lambda *a:admitted.append(tick[0]) or False)
    def unavailable():
        recoveries.append(tick[0])
        raise OSError('Fixture recovery database unavailable')
    monkeypatch.setattr(worker,'reconcile_interrupted_advisory_jobs',unavailable)

    class Pool:
        def __init__(self,**kwargs):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def submit(self,*args):
            future=Future();future.set_result(None);return future
    monkeypatch.setattr(worker.concurrent.futures,'ThreadPoolExecutor',Pool)
    offsets={1:0,2:1,3:5,4:6,5:7}
    monkeypatch.setattr(worker.time,'time',lambda:now+offsets.get(tick[0],0))
    with worker_registry.Registration() as node:
        def wait(_):
            tick[0]+=1
            if tick[0]==4:
                worker_registry.request_control(node.id,node.boot,0,'drain','End fixture scheduler','admin')
            return tick[0]>=4
        monkeypatch.setattr(worker.stop,'wait',wait)
        worker._loop(node)

    assert recoveries==[1,3]
    assert scheduled==[1] and admitted==[1,2,3]
    assert caplog.text.count('Advisory plan recovery failed')==2
