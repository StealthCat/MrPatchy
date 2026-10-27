import copy
import time
import uuid
import pytest
from app import quarantine,incidents,worker,operations,persistence,agent_maintenance
from app.db import Session,Host,Job,Setting
from app.evidence_vault import EvidenceCopy,EvidenceArchive
from app.identity import User

BASE='/api/hosts/response-host/security'

@pytest.fixture
def scenario(admin,monkeypatch):
    snapshot={'path':'/srv/suspect','sha256':'a'*64,'identity':{'dev':1,'ino':2,'size':4,'uid':0,'gid':0,'mode':0o100640,'mtime_ns':1,'ctime_ns':1,'nlink':1},'parent':{'dev':1,'ino':3}}
    plan={'file':snapshot,'ancestors':[{'dev':1,'ino':1,'uid':0,'gid':0,'mode':0o40755},{'dev':1,'ino':3,'uid':0,'gid':0,'mode':0o40755}],'xattrs':{},'vault_device':1}
    with Session() as s:
        s.add(Host(id='response-host',name='Response',address='192.0.2.1',fingerprint='pin',state='online',last_seen=time.time(),baseline={'fixture':'reviewed'}))
        incidents.record(s,'response-host','scan',{'findings':[{'path':snapshot['path'],'sha256':snapshot['sha256'],'device':1,'inode':2}]})
        finding=s.query(incidents.Incident).one()
        s.add(EvidenceCopy(id='copy',host_id='response-host',incident_id=finding.id,state='preserved',snapshot=snapshot,evidence_digest=incidents.digest(finding.evidence)))
        s.add(EvidenceArchive(id='archive',host_id='response-host',copy_id='copy',created=time.time(),state='verified',snapshot=snapshot,fingerprint='pin',actor='admin',reason='Independent retained evidence.',expires=time.time()+300));s.commit()
    monkeypatch.setattr(quarantine.evidence_archive,'verify',lambda row:'verified')
    monkeypatch.setattr(agent_maintenance,'inspect',lambda *a,**k:{'state':'current'})
    calls=[];state={'value':'quarantined','timeout':False}
    def remote(host,request,**kwargs):
        calls.append(copy.deepcopy(request))
        if request['action']=='quarantine-prepare':return copy.deepcopy(plan)
        if request['action']=='operation-status':return {'busy':False}
        if state['timeout']:raise TimeoutError('Lost response')
        restored=request['action']=='quarantine-restore'
        value='restored' if restored else state['value']
        return {'id':request['id'],'plan':copy.deepcopy(plan),'state':value,'restore_ready':value=='quarantined','restore_attempted':restored}
    monkeypatch.setattr(worker.ssh,'call',remote)
    response=admin.post(BASE+'/evidence-archives/archive/quarantine',json={});assert response.status_code==200,response.text
    worker.execute(response.json()['job_id'])
    return {'plan':plan,'calls':calls,'state':state}


def row(admin):return admin.get(BASE+'/quarantines').json()['items'][0]

def approve(admin,record,restore=False,**changes):
    body={'plan_digest':record['plan_digest'],'receipt_digest':record['receipt_digest'],'reason':'Reviewed the file and service impact for this response.','confirmation':'RESTORE' if restore else 'QUARANTINE',**changes}
    return admin.post(BASE+'/quarantines/'+record['id']+('/restore' if restore else '/execute'),json=body)

def status(admin,record):
    response=admin.post(BASE+'/quarantines/'+record['id']+'/status',json={});assert response.status_code==200,response.text
    worker.execute(response.json()['job_id']);return row(admin)

def history(admin,record):return admin.get(BASE+'/quarantines/'+record['id']+'/history').json()


def test_separate_approvals_hold_other_jobs_and_allow_verified_restore(admin,scenario):
    record=row(admin);assert record['state']=='prepared' and not record['hold']
    assert approve(admin,record,confirmation='PRESERVE').status_code==400
    assert approve(admin,record,plan_digest='b'*64).status_code==409
    response=approve(admin,record);assert response.status_code==200,response.text
    assert row(admin)['hold'] and approve(admin,record).status_code==409
    with Session() as s:
        assert operations.host_quarantined(s,'response-host')
        ordinary=worker.enqueue(s,'response-host','refresh')
    before=len(scenario['calls']);worker.execute(ordinary)
    assert len(scenario['calls'])==before
    with Session() as s:assert s.get(Job,ordinary).state=='queued'
    worker.execute(response.json()['job_id']);record=row(admin)
    assert record['state']=='quarantined' and record['hold']
    local=admin.post(BASE+'/evidence-archives/archive/status',json={});assert local.status_code==200
    before=len(scenario['calls']);worker.execute(local.json()['job_id']);assert len(scenario['calls'])==before
    with Session() as s:assert s.get(Job,local.json()['job_id']).state=='complete'
    assert admin.post(BASE+'/evidence-archives/archive/quarantine',json={}).status_code==409
    restore=approve(admin,record,restore=True);assert restore.status_code==200,restore.text
    worker.execute(restore.json()['job_id']);record=row(admin)
    assert record['state']=='restored' and not record['hold']
    reviews=history(admin,record)
    assert {a['action'] for a in reviews['approvals']}=={'quarantine','restore'}
    assert all(a['actor']=='admin' for a in reviews['approvals'])
    with Session() as s:assert s.query(incidents.Incident).one().state=='open'


def test_timeout_holds_and_status_does_not_repeat_mutation(admin,scenario):
    record=row(admin);response=approve(admin,record);scenario['state']['timeout']=True
    worker.execute(response.json()['job_id']);record=row(admin)
    assert record['state']=='uncertain' and record['hold']
    scenario['state']['timeout']=False;record=status(admin,record)
    assert record['state']=='quarantined' and record['hold']
    assert len([r for r in scenario['calls'] if r['action']=='quarantine-apply'])==1
    release=admin.post(BASE+'/quarantines/'+record['id']+'/release',json={'plan_digest':record['plan_digest'],'receipt_digest':record['receipt_digest'],'reason':'Verified the application and accepted the quarantined file removal.','confirmation':'KEEP QUARANTINED'})
    assert release.status_code==200 and not row(admin)['hold']
    scenario['state']['value']='uncertain';record=status(admin,row(admin))
    assert record['hold'] and record['state']=='uncertain'


def test_incomplete_move_receipt_does_not_mark_action_successful(admin,scenario):
    record=row(admin);response=approve(admin,record);scenario['state']['value']='not_moved'
    worker.execute(response.json()['job_id']);record=row(admin)
    assert record['state']=='not_moved' and not record['hold']
    with Session() as s:assert s.get(Job,response.json()['job_id']).state=='failed'


def test_failed_observation_invalidates_previous_restoration_readiness(admin,scenario):
    response=approve(admin,row(admin));worker.execute(response.json()['job_id']);record=row(admin)
    assert record['receipt']['restore_ready']
    scenario['state']['timeout']=True;record=status(admin,record)
    assert record['state']=='uncertain' and record['hold'] and not record['receipt']
    assert approve(admin,record,True).status_code==409


@pytest.mark.parametrize('change',['agent','fresh_agent','pin','expiry','incident','archive'])
def test_rejected_before_remote_access_releases_only_its_new_hold(admin,scenario,monkeypatch,change):
    record=row(admin);response=approve(admin,record)
    with Session() as s:
        current=s.get(quarantine.Quarantine,record['id'])
        if change=='agent':s.add(Setting(key='agent-status:response-host',value={'state':'blocked'}))
        if change=='pin':s.get(Host,'response-host').fingerprint='changed'
        if change=='expiry':s.get(quarantine.Approval,current.approval_id).expires=time.time()-1
        if change=='incident':s.query(incidents.Incident).one().state='resolved'
        s.commit()
    if change=='archive':monkeypatch.setattr(quarantine.evidence_archive,'verify',lambda row:'unavailable')
    if change=='agent':monkeypatch.setattr(agent_maintenance,'inspect',lambda *a,**k:{'state':'blocked'})
    if change=='fresh_agent':monkeypatch.setattr(agent_maintenance,'inspect',lambda *a,**k:{'state':'drifted'})
    before=len(scenario['calls']);worker.execute(response.json()['job_id'])
    assert len(scenario['calls'])==before
    record=row(admin);assert record['state']=='rejected' and not record['hold']
    assert any(e['kind']=='rejected' for e in history(admin,record)['events'])


def test_readonly_reconciliation_can_recheck_a_cached_connection_outage(admin,scenario,monkeypatch):
    response=approve(admin,row(admin));worker.execute(response.json()['job_id']);record=row(admin)
    with Session() as s:s.add(Setting(key='agent-status:response-host',value={'state':'unavailable'}));s.commit()
    checked=[]
    def refreshed(s,host,**kwargs):
        checked.append(host.id);s.get(Setting,'agent-status:'+host.id).value={'state':'current'};s.commit()
        return {'state':'current'}
    monkeypatch.setattr(agent_maintenance,'inspect',refreshed)
    assert status(admin,record)['state']=='quarantined' and checked==['response-host']
    assert len([r for r in scenario['calls'] if r['action']=='quarantine-apply'])==1


def test_approval_expiry_during_local_preflight_never_requests_mutation(admin,scenario,monkeypatch):
    record=row(admin);response=approve(admin,record);now=time.time()
    def expired(archive):
        monkeypatch.setattr(quarantine.time,'time',lambda:now+600)
        return 'verified'
    monkeypatch.setattr(quarantine.evidence_archive,'verify',expired)
    worker.execute(response.json()['job_id'])
    assert row(admin)['state']=='rejected' and not row(admin)['hold']
    assert not any(r['action']=='quarantine-apply' for r in scenario['calls'])


def test_running_job_after_restart_requires_existing_activity_reconciliation(admin,scenario):
    record=row(admin);response=approve(admin,record)
    with Session() as s:
        s.get(Job,response.json()['job_id']).state='running'
        current=s.get(quarantine.Quarantine,record['id']);current.state='uncertain';s.commit()
    assert admin.post(BASE+'/quarantines/'+record['id']+'/status',json={}).status_code==409
    reconciled=admin.post('/api/operations/jobs/'+response.json()['job_id']+'/reconcile',json={'verified_target_state':True})
    assert reconciled.status_code==200,reconciled.text
    assert row(admin)['hold']
    assert status(admin,record)['state']=='quarantined'
    assert not any(r['action']=='quarantine-apply' for r in scenario['calls'])


def test_stale_or_changed_readiness_cannot_authorize_restore_or_release(admin,scenario):
    response=approve(admin,row(admin));worker.execute(response.json()['job_id']);record=row(admin)
    assert approve(admin,record,True,receipt_digest='b'*64).status_code==409
    with Session() as s:s.get(quarantine.Quarantine,record['id']).observed=time.time()-301;s.commit()
    assert approve(admin,record,True).status_code==409
    assert admin.post(BASE+'/quarantines/'+record['id']+'/release',json={'plan_digest':record['plan_digest'],'receipt_digest':record['receipt_digest'],'reason':'Accepting this operational change after review.','confirmation':'KEEP QUARANTINED'}).status_code==409
    assert row(admin)['hold']


def test_console_recovery_is_explicit_audited_and_does_not_resolve_incident(admin,scenario):
    response=approve(admin,row(admin));scenario['state']['timeout']=True;worker.execute(response.json()['job_id']);record=row(admin)
    body={'plan_digest':record['plan_digest'],'receipt_digest':record['receipt_digest'],'reason':'Reviewed target console and repaired the interrupted file operation.','confirmation':'wrong'}
    endpoint=BASE+'/quarantines/'+record['id']+'/release'
    assert admin.post(endpoint,json=body).status_code==400
    body['confirmation']='CONSOLE RECOVERED';assert admin.post(endpoint,json=body).status_code==200
    assert row(admin)['state']=='console_recovered' and not row(admin)['hold']
    assert any(e['kind']=='hold_released' and e['details']['reason']==body['reason'] for e in history(admin,record)['events'])
    with Session() as s:assert s.query(incidents.Incident).one().state=='open'


def test_security_schedules_and_maintenance_defer_while_response_is_held(admin,scenario):
    record=row(admin);approve(admin,record)
    with Session() as s:
        s.add(Setting(key='security-policy:response-host',value={'enabled':True,'interval_hours':1,'paths':['/srv']}))
        s.add(Setting(key='persistence-monitor:response-host',value={'enabled':True,'interval_hours':1,'link_incidents':True,'revision':'rev'}));s.commit()
    incidents.schedule_tick(time.time()+10000);persistence.schedule_tick(time.time()+10000);operations.collect_alerts()
    with Session() as s:
        assert s.query(Job).filter(Job.action.in_(['security-scan','security-inspect'])).count()==0
        assert s.query(operations.Alert).filter_by(kind='file response hold').one().state=='open'


def test_scope_prerequisite_host_and_role_boundaries(admin,scenario):
    record=row(admin);path=BASE+'/quarantines/'+record['id']
    assert admin.get(path.replace('response-host','other')+'/history').status_code==404
    assert admin.post(path.replace('response-host','other')+'/status',json={}).status_code==404
    assert admin.get(BASE+'/quarantines?offset=-1').status_code==400
    assert admin.get(path+'/history?offset=-1').status_code==400
    with Session() as s:s.get(EvidenceArchive,'archive').state='uncertain';s.commit()
    assert admin.post(BASE+'/evidence-archives/archive/quarantine',json={}).status_code==409
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get(BASE+'/quarantines').status_code==403
        for action in ('execute','restore','status','release'):
            response=admin.post(path+'/'+action,json={'plan_digest':record['plan_digest'],'reason':'A sufficiently long review reason.','confirmation':'QUARANTINE'})
            assert response.status_code==403,response.text


@pytest.mark.parametrize('change',['capability','ancestor','filesystem'])
def test_untrusted_preflight_metadata_is_rejected(admin,scenario,change):
    plan=copy.deepcopy(scenario['plan'])
    if change=='capability':plan['xattrs']={'security.capability':'b'*64}
    if change=='ancestor':plan['ancestors'][-1]['mode']=0o40777
    if change=='filesystem':plan['vault_device']=2
    with pytest.raises(ValueError):quarantine.validate_plan(plan,scenario['plan']['file'])
    with Session() as s:assert s.query(quarantine.Approval).count()==0
