"""Exercise handler and worker-backstop failure paths through actual status jobs."""
import pytest
from sqlalchemy import select
from app import quarantine,process_response,worker
from app.db import Session,Job
from test_quarantine import scenario  # noqa: F401 -- pytest fixture
from test_process_response import prepared  # noqa: F401 -- pytest fixture
import test_quarantine as files
import test_process_response as processes


@pytest.mark.parametrize('kind,fixture', [('file','scenario'),('process','prepared')])
@pytest.mark.parametrize('layer,rollback', [('handler',False),('worker',False),('worker',True)])
def test_failed_status_preserves_actor_hold_and_single_backstop_event(admin,request,monkeypatch,kind,fixture,layer,rollback):
    request.getfixturevalue(fixture)
    api=files if kind=='file' else processes
    module=quarantine if kind=='file' else process_response
    record=api.row(admin)
    approved=api.approve(admin,record);assert approved.status_code==200
    worker.execute(approved.json()['job_id']);record=api.row(admin)
    assert record['receipt']
    action='quarantine-status' if kind=='file' else 'process-status'
    endpoint=files.BASE+('/quarantines/' if kind=='file' else '/process-responses/')+record['id']+('/status' if kind=='file' else '/verify')
    if layer=='handler':
        original=module.ssh.call
        def fail_status(host,payload,**kwargs):
            if payload['action']==action:raise TimeoutError('Fixture status reply lost')
            return original(host,payload,**kwargs)
        monkeypatch.setattr(module.ssh,'call',fail_status)
    else:
        def fail_before_handler(*args):raise ValueError('Fixture failure before status handler')
        monkeypatch.setattr(module,'execute',fail_before_handler)
    if rollback:
        original_audit=worker.audit
        def fail_final_audit(session,action,detail):
            if action=='failed '+action_name:raise RuntimeError('Fixture final audit failure')
            return original_audit(session,action,detail)
        action_name=action
        monkeypatch.setattr(worker,'audit',fail_final_audit)
    identifiers=[]
    for attempt in range(1 if rollback else 2):
        queued=admin.post(endpoint,json={});assert queued.status_code==200,queued.text
        identifier=queued.json()['job_id']
        identifiers.append(identifier)
        with Session() as session:
            job=session.get(Job,identifier);job.payload={**job.payload,'_actor':'status-reviewer'};session.commit()
        if rollback:
            with pytest.raises(RuntimeError,match='Fixture final audit failure'):worker.execute(identifier)
            current=api.row(admin)
            assert {key:current[key] for key in ('state','hold','receipt')}=={key:record[key] for key in ('state','hold','receipt')}
            with Session() as session:
                assert not list(session.scalars(select(module.Event).where(module.Event.kind=='observation_failed')))
                assert session.get(Job,identifier).state=='running'
            continue
        worker.execute(identifier)
        current=api.row(admin)
        assert current['state']=='uncertain' and current['hold'] and current['receipt']=={}
        with Session() as session:
            events=list(session.scalars(select(module.Event).where(module.Event.kind=='observation_failed')))
            assert len(events)==(attempt+1 if layer=='handler' else 1)
            assert all(event.actor=='status-reviewer' for event in events)
            assert sorted(event.details['job_id'] for event in events)==sorted(identifiers if layer=='handler' else identifiers[:1])
            assert session.get(Job,identifier).state=='failed'
