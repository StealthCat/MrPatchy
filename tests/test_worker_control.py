import concurrent.futures
import json
import time
import pytest
from sqlalchemy import select
from app import worker_registry as registry
from app.db import Session,Setting,Audit,Host,Job
from app.identity import User


def send(admin,node,action='drain',revision=0,**changes):
    body={'worker_id':node.id,'boot_id':node.boot,'revision':revision,'action':action,'reason':'Planned worker maintenance',**changes}
    return admin.post('/api/operations/workers/control',json=body)


def test_control_acknowledgement_work_completion_resume_and_audit(admin):
    with registry.Registration() as node:
        assert send(admin,node).json()['revision']==1
        before=registry.page()['items'][0]
        assert before['state']=='reporting' and before['control']=={'action':'drain','revision':1}
        assert before['control_revision']==0 and before['controllable']
        assert node.heartbeat(True,['assigned-job'],1,True,2,True)
        row=registry.page()['items'][0]
        assert row['state']=='draining' and not row['coordinator'] and row['control_revision']==1
        assert row['pending_polls']==2 and row['notification_active']
        node.last-=16;assert node.heartbeat(False,[],0,False,1)
        assert registry.page()['items'][0]['state']=='draining','Queued polls prevent a drained claim'
        node.last-=16;node.heartbeat(False,[],0,False)
        assert registry.page()['items'][0]['state']=='drained'
        assert send(admin,node,'resume',1).status_code==200
        assert not node.heartbeat(False,[],0,False)
        assert registry.page()['items'][0]['state']=='reporting'
    with Session() as s:
        rows=list(s.scalars(select(Audit).where(Audit.action.in_(['worker drain requested','worker resume requested']))))
        assert len(rows)==2 and all('admin' in row.detail and 'Planned worker maintenance' in row.detail for row in rows)
        observed=list(s.scalars(select(Audit.action).where(Audit.action.in_(['worker drain observed','worker resume observed','worker drained']))))
        assert observed.count('worker drain observed')==1 and observed.count('worker resume observed')==1 and observed.count('worker drained')==1


def test_control_revisions_restart_and_legacy_state(admin,monkeypatch):
    monkeypatch.setenv('MRPATCHY_WORKER_ID','stable-control')
    with registry.Registration() as first:
        assert send(admin,first).status_code==200
        assert send(admin,first).status_code==409
        assert send(admin,first,boot_id='f'*32).status_code==409
        old=first.boot
    assert send(admin,first,'resume',1).status_code==409
    with registry.Registration() as second:
        assert second.boot!=old and not second.heartbeat(False,[],0,False)
        assert send(admin,first,'resume',1).status_code==409
        assert send(admin,second).status_code==200
        assert second.heartbeat(False,[],0,False)


@pytest.mark.parametrize('change',[{'heartbeat':0},{'heartbeat':'future'},{'version':'0.0.1'},{'state':'unknown'}])
def test_unavailable_or_incompatible_worker_not_controllable(admin,change):
    change=dict(change)
    if change.get('heartbeat')=='future':change['heartbeat']=time.time()+300
    with registry.Registration() as node:
        with Session() as s:
            row=s.get(Setting,registry.record_key(node.id));row.value={**row.value,**change};s.commit()
        assert send(admin,node).status_code==409
        assert not registry.page()['items'][0]['controllable']


def test_control_roles_csrf_validation_and_no_remote_calls(admin,monkeypatch):
    from app import ai,ssh
    monkeypatch.setattr(ai,'request',lambda *a,**k:pytest.fail('AI must not run'))
    monkeypatch.setattr(ssh,'call',lambda *a,**k:pytest.fail('SSH must not run'))
    with registry.Registration() as node:
        assert send(admin,node,reason='   short  ').status_code==400
        assert send(admin,node,revision=True).status_code==422
        assert send(admin,node,action='shell').status_code==422
        csrf=admin.headers.pop('X-CSRF-Token');assert send(admin,node).status_code==403
        admin.headers['X-CSRF-Token']=csrf
        for role in ('viewer','operator'):
            with Session() as s:s.get(User,'admin').role=role;s.commit()
            assert send(admin,node).status_code==403
        with Session() as s:s.get(User,'admin').role='admin';s.commit()
        assert send(admin,node).status_code==200


def test_invalid_control_blocks_admission_without_forging_ack(admin):
    with registry.Registration() as node:
        with Session() as s:
            s.add(Setting(key=registry.control_key(node.id),value={'boot_id':node.boot,'revision':True,'action':'drain'}));s.commit()
        with pytest.raises(ValueError,match='admission blocked'):node.heartbeat(False,[],0,False)
        row=registry.page()['items'][0]
        assert row['control']['action']=='invalid' and not row['controllable']
        assert row['control_revision']==0


@pytest.mark.parametrize('jobs,polls',[('1','1'),('8','32')])
def test_configured_capacities_report_actual_pool_limits(admin,monkeypatch,jobs,polls):
    monkeypatch.setenv('MRPATCHY_JOB_CONCURRENCY',jobs);monkeypatch.setenv('MRPATCHY_POLL_CONCURRENCY',polls)
    with registry.Registration() as node:
        assert node.capacity=={'jobs':int(jobs),'polls':int(polls),'ai':4}
        row=registry.page()['items'][0];assert row['job_capacity']==int(jobs) and row['poll_capacity']==int(polls)


@pytest.mark.parametrize('env,value',[('MRPATCHY_JOB_CONCURRENCY','0'),('MRPATCHY_JOB_CONCURRENCY','9'),('MRPATCHY_POLL_CONCURRENCY','33'),('MRPATCHY_POLL_CONCURRENCY','-1'),('MRPATCHY_JOB_CONCURRENCY','2.0'),('MRPATCHY_POLL_CONCURRENCY','nan'),('MRPATCHY_AI_CONCURRENCY','0'),('MRPATCHY_AI_CONCURRENCY','9'),('MRPATCHY_AI_CONCURRENCY','1.5')])
def test_invalid_concurrency_refuses_start(env,value,monkeypatch):
    monkeypatch.setenv(env,value)
    with pytest.raises(ValueError,match=env):registry.Registration()


def test_scheduler_drain_releases_coordinator_finishes_assigned_and_resumes(admin,monkeypatch):
    from app import worker,persistence,response_monitor,service_monitor,execution_scans
    for module in (worker.scheduling,worker.incidents,persistence,response_monitor,service_monitor,execution_scans):
        monkeypatch.setattr(module,'schedule_tick' if module is not worker.scheduling else 'tick',lambda *a:None)
    monkeypatch.setattr(worker.incidents,'auto_plan_tick',lambda *a:None)
    monkeypatch.setattr(worker.operations,'collect_alerts',lambda:None)
    monkeypatch.setattr(worker.operations,'deliver_one',lambda:None)
    monkeypatch.setattr(worker,'poll_host',lambda *a:None)
    with Session() as s:
        for n in range(3):
            host=Host(id='control-host-'+str(n),name='Control fixture',address='192.0.2.1',fingerprint='');s.add(host)
            s.add(Job(id='control-job-'+str(n),host_id=host.id,action='refresh'))
        s.commit()
    pending=[];admissions=[];tick=[0]
    def submit(pool,job,active,busy):
        future=concurrent.futures.Future();future.set_running_or_notify_cancel()
        active[job.id]=(future,job.host_id);busy.add(job.host_id)
        pending.append(future);admissions.append(tick[0]);return True
    monkeypatch.setattr(worker,'submit_job',submit)
    monkeypatch.setenv('MRPATCHY_JOB_CONCURRENCY','1')
    with registry.Registration() as node:
        def wait(_):
            tick[0]+=1
            if tick[0]==2:
                assert send(admin,node).status_code==200
            if tick[0]==3:
                # Drain released leadership while the assigned job is still running.
                other=worker.Lock('scheduler');assert other.acquire(False);other.release()
                assert pending[0].running()
                pending[0].set_result(None);node.last-=16
            if tick[0]==4:
                assert registry.page()['items'][0]['state']=='drained'
                assert admissions==[1]
                assert send(admin,node,'resume',1).status_code==200
            if tick[0]==5:
                for future in pending:
                    if not future.done():future.set_result(None)
                return True
            return False
        monkeypatch.setattr(worker.stop,'wait',wait)
        worker._loop(node)
        assert admissions==[1,4], 'No new claims while drained; configured one-job limit on resume'


def test_competing_control_requests_are_serialized(admin):
    from fastapi import HTTPException
    with registry.Registration() as node:
        def request():
            try:return registry.request_control(node.id,node.boot,0,'drain','Concurrent maintenance request','admin')['revision']
            except HTTPException as error:return error.status_code
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(lambda _:request(),range(2)))==[1,409]


def test_unreadable_control_skips_every_admission_phase(admin,monkeypatch):
    from app import worker
    calls=[0]
    def wait(_):calls[0]+=1;return calls[0]>1
    def unavailable(*args):raise OSError('Database temporarily unavailable')
    monkeypatch.setattr(worker.stop,'wait',wait)
    monkeypatch.setattr(worker.scheduling,'tick',lambda *a:pytest.fail('No scheduling after control read failure'))
    monkeypatch.setattr(worker,'submit_job',lambda *a:pytest.fail('No job claims after control read failure'))
    with registry.Registration() as node:
        monkeypatch.setattr(registry,'control_value',unavailable)
        worker._loop(node)


def test_failed_ack_write_retries_without_admitting_work(admin,monkeypatch):
    with registry.Registration() as node:
        assert send(admin,node).status_code==200
        original=node.write
        monkeypatch.setattr(node,'write',lambda *a,**k:(_ for _ in ()).throw(OSError('Write unavailable')))
        with pytest.raises(OSError):node.heartbeat(False,[],0,False)
        assert node.control_revision==0
        monkeypatch.setattr(node,'write',original)
        assert node.heartbeat(False,[],0,False)
        assert registry.page()['items'][0]['state']=='drained' and node.control_revision==1


@pytest.mark.parametrize('identity',['.','..','Worker-A','worker-a'])
def test_body_identity_preserves_dot_and_case_identities(admin,monkeypatch,identity):
    monkeypatch.setenv('MRPATCHY_WORKER_ID',identity)
    with registry.Registration() as node:
        assert send(admin,node).status_code==200
        assert node.heartbeat(False,[],0,False)
        assert registry.page()['items'][0]['id']==identity
        assert send(admin,node,'resume',1).status_code==200
        assert not node.heartbeat(False,[],0,False)
        assert send(admin,node,worker_id='../other').status_code==422
