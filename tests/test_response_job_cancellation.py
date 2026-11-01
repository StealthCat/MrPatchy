"""Cancel unstarted response approvals locally without weakening retained holds."""
import time
import pytest
from sqlalchemy import select
from app import quarantine,process_response,worker
from app.db import Session,Host,Job,Audit
from app.identity import User

HOST='cancel-response-host'
CASES=[('quarantine-apply','queued','prepared','rejected'),
       ('quarantine-restore','restore_queued','quarantined','quarantined'),
       ('process-suspend','queued','prepared','rejected'),
       ('process-resume','resume_queued','suspended','suspended')]


def seed(action,state,before_state,before_hold,*,job_state='queued',row_host=HOST,approval=True):
    module=process_response if action.startswith('process-') else quarantine
    Model=module.ProcessResponse if module is process_response else module.Quarantine
    with Session() as s:
        for host in {HOST,row_host}:
            s.add(Host(id=host,name=host,address='192.0.2.1',fingerprint='fixture'))
        fields={'id':'response','host_id':row_host,'state':state,'hold':True,'fingerprint':'fixture',
                'plan':{},'approval_id':'approval' if approval else 'missing','receipt':{'retained':'fixture'},'observed':123}
        fields.update({'quarantine_id':'file','observation_id':'observation'} if module is process_response else
                      {'incident_id':'incident','archive_id':'archive','evidence_digest':'a'*64})
        s.add(Model(**fields))
        if approval:
            attrs={'id':'approval','action':{'quarantine-apply':'quarantine','quarantine-restore':'restore','process-suspend':'suspend','process-resume':'resume'}[action],
                   'expires':time.time()+300,'plan_digest':'b'*64,'actor':'original-approver','reason':'Reviewed fixture response.',
                   'before_state':before_state,'before_hold':before_hold}
            attrs['process_id' if module is process_response else 'quarantine_id']='response'
            s.add(module.Approval(**attrs))
        s.add(Job(id='cancel-me',host_id=HOST,action=action,state=job_state,
                  payload={'process_id' if module is process_response else 'quarantine_id':'response','_actor':'original-approver'}))
        s.commit()
    return module,Model


@pytest.mark.parametrize('action,state,before,after',CASES)
@pytest.mark.parametrize('before_hold',[False,True])
def test_cancel_response_restores_approval_hold_and_status_without_ssh(admin,monkeypatch,action,state,before,after,before_hold):
    module,Model=seed(action,state,before,before_hold)
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**kw:pytest.fail('Cancellation must remain controller-local'))
    result=admin.post('/api/operations/jobs/cancel-me/cancel')
    assert result.status_code==200,result.text
    with Session() as s:
        row=s.get(Model,'response');job=s.get(Job,'cancel-me')
        assert job.state=='cancelled' and row.state==after and row.hold is before_hold
        assert row.receipt=={'retained':'fixture'} and row.observed==123
        assert s.get(module.Approval,'approval') is not None
        assert s.scalar(select(Audit).where(Audit.action=='cancel job',Audit.detail.contains('cancel-me')))
        assert s.scalar(select(module.Event).where(module.Event.kind=='rejected'))
    # Activity obtains this authoritative state on its normal list/detail refresh.
    rows=admin.get('/api/jobs',params={'host_id':HOST}).json()
    assert next(j for j in rows if j['id']=='cancel-me')['state']=='cancelled'
    assert admin.post('/api/operations/jobs/cancel-me/cancel').status_code==409


@pytest.mark.parametrize('action,state,before,after',CASES)
def test_cancellation_preserves_uncertain_response_and_unrelated_hold(admin,action,state,before,after):
    module,Model=seed(action,'uncertain',before,False)
    with Session() as s:
        s.add(quarantine.Quarantine(id='unrelated',host_id=HOST,incident_id='other',archive_id='other',
              state='quarantined',hold=True,fingerprint='fixture',evidence_digest='a'*64,plan={}))
        s.add(Job(id='held-operation',host_id=HOST,action='repair',state='recovery_required'))
        s.commit()
    assert admin.post('/api/operations/jobs/cancel-me/cancel').status_code==200
    with Session() as s:
        row=s.get(Model,'response')
        assert row.state=='uncertain' and row.hold and row.receipt=={'retained':'fixture'}
        assert s.get(quarantine.Quarantine,'unrelated').hold
        assert s.get(Job,'held-operation').state=='recovery_required'
        assert s.scalar(select(module.Event).where(module.Event.kind=='rejected')) is None


@pytest.mark.parametrize('action,state,before,after',CASES)
@pytest.mark.parametrize('job_state',['running','recovery_required','complete'])
def test_nonqueued_job_never_cancels_or_changes_response(admin,action,state,before,after,job_state):
    module,Model=seed(action,state,before,False,job_state=job_state)
    assert admin.post('/api/operations/jobs/cancel-me/cancel').status_code==409
    with Session() as s:
        assert s.get(Job,'cancel-me').state==job_state
        assert s.get(Model,'response').state==state and s.get(Model,'response').hold
        assert not s.scalar(select(Audit).where(Audit.action=='cancel job'))


@pytest.mark.parametrize('action,state,before,after',CASES)
def test_missing_approval_never_releases_a_hold(admin,action,state,before,after):
    module,Model=seed(action,state,before,False,approval=False)
    assert admin.post('/api/operations/jobs/cancel-me/cancel').status_code==200
    with Session() as s:
        row=s.get(Model,'response')
        assert row.hold and row.state==('rejected' if state=='queued' else 'uncertain')


@pytest.mark.parametrize('role',['viewer','operator'])
def test_cancel_response_stays_admin_only(admin,role):
    seed(*CASES[0][:3],False)
    with Session() as s:s.get(User,'admin').role=role;s.commit()
    assert admin.post('/api/operations/jobs/cancel-me/cancel').status_code==403
    with Session() as s:assert s.get(Job,'cancel-me').state=='queued'


@pytest.mark.parametrize('action,state,before,after',CASES)
def test_foreign_host_reference_is_not_reconciled(admin,action,state,before,after):
    module,Model=seed(action,state,before,False,row_host='foreign-host')
    assert admin.post('/api/operations/jobs/cancel-me/cancel').status_code==200
    with Session() as s:
        row=s.get(Model,'response')
        assert row.state==state and row.hold
        assert s.scalar(select(module.Event).where(module.Event.kind=='rejected')) is None


def test_busy_host_mutex_refuses_cancel_without_cleanup(admin,monkeypatch):
    seed(*CASES[0][:3],False)
    class Busy:
        def acquire(self,*args):return False
        def release(self):pytest.fail('Never release a lock not acquired')
    monkeypatch.setattr(worker,'host_lock',lambda *args:Busy())
    assert admin.post('/api/operations/jobs/cancel-me/cancel').status_code==409
    with Session() as s:
        assert s.get(Job,'cancel-me').state=='queued'
        assert s.get(quarantine.Quarantine,'response').state=='queued'


def test_cleanup_failure_rolls_back_job_hold_events_and_audit(admin,monkeypatch):
    from app import host_lifecycle
    seed(*CASES[0][:3],False)
    original=host_lifecycle.reject_pending_records
    def fail(*args):
        original(*args)
        raise RuntimeError('Fixture cleanup failed')
    monkeypatch.setattr(host_lifecycle,'reject_pending_records',fail)
    response=admin.post('/api/operations/jobs/cancel-me/cancel')
    assert response.status_code==500 and 'Fixture cleanup failed' not in response.text
    with Session() as s:
        assert s.get(Job,'cancel-me').state=='queued'
        row=s.get(quarantine.Quarantine,'response')
        assert row.state=='queued' and row.hold
        assert not s.scalar(select(quarantine.Event))
        assert not s.scalar(select(Audit).where(Audit.action=='cancel job'))


@pytest.mark.parametrize('action',['trusted-repair-stage','trusted-repair-prepare','trusted-repair-publish',
                                   'evidence-preserve','evidence-acquire','execution-scan'])
def test_linked_unstarted_security_records_cancel_locally_and_keep_other_holds(admin,monkeypatch,action):
    from app import repair_staging,repair_preparation,repair_publication,execution_scans
    from app.evidence_vault import EvidenceCopy,EvidenceArchive,ArchiveObservation
    now=time.time()
    with Session() as s:
        s.add(Host(id=HOST,name=HOST,address='192.0.2.1',fingerprint='fixture'))
        s.add(quarantine.Quarantine(id='original',host_id=HOST,incident_id='incident',archive_id='archive',
              state='quarantined',hold=True,fingerprint='fixture',evidence_digest='a'*64,plan={}))
        if action=='trusted-repair-stage':
            Model=repair_staging.Stage;key='stage_id';expected='rejected'
            row=Model(id='linked',host_id=HOST,quarantine_id='original',preparation_id='preparation',preparation_digest='a'*64,
                      expires=now+300,actor='admin',reason='Fixture approved staging.',fingerprint='fixture',plan={})
        elif action=='trusted-repair-prepare':
            Model=repair_preparation.Preparation;key='preparation_id';expected='cancelled'
            row=Model(id='linked',host_id=HOST,quarantine_id='original',bundle_id='bundle',path='/srv/file',actor='admin',
                      fingerprint='fixture',response_plan_digest='a'*64)
        elif action=='trusted-repair-publish':
            Model=repair_publication.Publication;key='publication_id';expected='rejected'
            row=Model(id='linked',host_id=HOST,quarantine_id='original',stage_id='stage',expires=now+300,actor='admin',
                      reason='Fixture approved publication.',fingerprint='fixture',stage_report_digest='a'*64,plan={},before_state='quarantined',before_hold=True)
        elif action=='evidence-preserve':
            Model=EvidenceCopy;key='copy_id';expected='rejected'
            row=Model(id='linked',host_id=HOST,incident_id='incident',evidence_digest='a'*64,state='queued',expires=now+300)
        elif action=='evidence-acquire':
            Model=EvidenceArchive;key='archive_id';expected='rejected'
            row=Model(id='linked',host_id=HOST,copy_id='copy',snapshot={},fingerprint='fixture',actor='admin',reason='Fixture acquisition.',expires=now+300)
        else:
            Model=execution_scans.Trigger;key='trigger_id';expected='skipped'
            row=Model(id='linked',host_id=HOST,revision='revision',host_revision='',observed=now,expires=now+300,
                      state='queued',evidence={},job_id='cancel-me')
        s.add(row);s.add(Job(id='cancel-me',host_id=HOST,action=action,payload={key:'linked','quarantine_id':'original'}));s.commit()
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**kw:pytest.fail('Cancellation must not contact target'))
    assert admin.post('/api/operations/jobs/cancel-me/cancel').status_code==200
    with Session() as s:
        row=s.get(Model,'linked')
        assert row.state==expected and s.get(Job,'cancel-me').state=='cancelled'
        assert s.get(quarantine.Quarantine,'original').hold
        if action=='evidence-preserve':assert row.expires==0
        if action=='evidence-acquire':assert s.scalar(select(ArchiveObservation).where(ArchiveObservation.archive_id=='linked',ArchiveObservation.state=='rejected'))
        if action=='trusted-repair-prepare':assert row.finished
        if action=='trusted-repair-publish':assert not row.hold and row.report['not_requested']
