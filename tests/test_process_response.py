import copy
import time
import pytest
from app import process_response as response,response_processes,quarantine,worker,incidents,operations,agent_maintenance,response_monitor
from app.db import Session,Host,Job,Setting
from app.identity import User
from test_quarantine import scenario,row as file_row,approve as approve_file,BASE


@pytest.fixture
def prepared(admin,scenario,monkeypatch):
    worker.execute(approve_file(admin,file_row(admin)).json()['job_id']);file=file_row(admin)
    observed={'scope':'helper_visible_process_leaders','boot_id':'12345678-1234-1234-1234-123456789abc','pid_namespace':123,'observer_pid':999,'processes_examined':1,'entries_examined':5,'matches':[{'pid':41,'start_ticks':100,'pid_namespace':123,'references':{'executable':1}}],'gaps':{}}
    with Session() as s:
        s.add(response_processes.Observation(id='observation',host_id='response-host',quarantine_id=file['id'],actor='admin',state='references_found',report={'held_verified':True,'scope_current':True,'fingerprint':'pin','plan_digest':file['plan_digest'],'observation':observed}));s.commit()
    original=worker.ssh.call;calls=[];state={'value':'suspended','fail':False,'during':lambda:None}
    def call(host,request,**kwargs):
        if not request['action'].startswith('process-'):return original(host,request,**kwargs)
        calls.append(copy.deepcopy(request));state['during']()
        if state['fail']:raise TimeoutError('Lost process reply')
        if request['action']=='process-prepare':return {'version':1,'quarantine_id':request['quarantine_id'],'quarantine_plan':request['quarantine_plan'],'process':{**request['expected'],'proc_device':7,'proc_inode':8},'boot_id':request['boot_id'],'pid_namespace':request['pid_namespace']}
        value='resumed' if request['action']=='process-resume' else state['value']
        return {'id':request['id'],'plan_digest':incidents.digest(request['plan']),'state':value,'resume_ready':value=='suspended','resume_attempted':value=='resumed','threads':1 if value in ('suspended','resumed') else 0}
    monkeypatch.setattr(worker.ssh,'call',call)
    result=admin.post(BASE+'/quarantines/'+file['id']+'/process-preparations',json={'observation_id':'observation','pid':41,'plan_digest':file['plan_digest']})
    assert result.status_code==200,result.text
    worker.execute(result.json()['job_id'])
    with Session() as s:assert s.get(Job,result.json()['job_id']).state=='complete',s.get(Job,result.json()['job_id']).output
    return {'file':file,'calls':calls,'state':state,'observed':observed}


def row(admin):return admin.get(BASE+'/process-responses').json()['items'][0]
def approve(admin,record,resume=False,**changes):
    return admin.post(BASE+'/process-responses/'+record['id']+'/actions/'+('resume' if resume else 'suspend'),json={'plan_digest':record['plan_digest'],'receipt_digest':record['receipt_digest'],'reason':'Reviewed process identity, service impact and recovery.','confirmation':'RESUME' if resume else 'SUSPEND',**changes})
def verify(admin,record):
    result=admin.post(BASE+'/process-responses/'+record['id']+'/verify',json={});assert result.status_code==200,result.text
    worker.execute(result.json()['job_id']);return row(admin)
def history(admin,record):return admin.get(BASE+'/process-responses/'+record['id']+'/history').json()


def test_separate_typed_approvals_and_independent_holds(admin,prepared):
    record=row(admin);assert record['state']=='prepared' and not record['hold']
    assert approve(admin,record,confirmation='QUARANTINE').status_code==400
    assert approve(admin,record,plan_digest='b'*64).status_code==409
    assert approve(admin,record,True).status_code==409
    result=approve(admin,record);assert result.status_code==200,result.text
    assert row(admin)['hold']
    with Session() as s:
        ordinary=worker.enqueue(s,'response-host','refresh')
    worker.execute(ordinary)
    with Session() as s:assert s.get(Job,ordinary).state=='queued'
    worker.execute(result.json()['job_id']);record=row(admin)
    assert record['state']=='suspended' and record['hold'] and record['receipt']['resume_ready']
    assert admin.post(BASE+'/quarantines/'+prepared['file']['id']+'/restore',json={'plan_digest':prepared['file']['plan_digest'],'receipt_digest':prepared['file']['receipt_digest'],'reason':'Reviewing original file restoration while process held.','confirmation':'RESTORE'}).status_code==409
    assert admin.post(BASE+'/quarantines/'+prepared['file']['id']+'/release',json={'plan_digest':prepared['file']['plan_digest'],'receipt_digest':prepared['file']['receipt_digest'],'reason':'Reviewing file pause while process still held.','confirmation':'KEEP QUARANTINED'}).status_code==409
    result=approve(admin,record,True);assert result.status_code==200,result.text
    worker.execute(result.json()['job_id']);record=row(admin)
    assert record['state']=='resumed' and not record['hold']
    assert file_row(admin)['hold'],'Process recovery must not release the independent file hold'
    assert {r['action'] for r in history(admin,record)['approvals']}=={'suspend','resume'}
    with Session() as s:assert s.query(incidents.Incident).one().state=='open'


def test_lost_reply_preserves_hold_and_read_only_verification_does_not_replay(admin,prepared):
    record=row(admin);result=approve(admin,record);prepared['state']['fail']=True
    worker.execute(result.json()['job_id']);record=row(admin)
    assert record['state']=='uncertain' and record['hold'] and not record['receipt']
    assert approve(admin,record,True).status_code==409
    prepared['state']['fail']=False;record=verify(admin,record)
    assert record['state']=='suspended' and record['hold']
    assert len([r for r in prepared['calls'] if r['action']=='process-suspend'])==1
    prepared['state']['fail']=True;record=verify(admin,record)
    assert record['state']=='uncertain' and not record['receipt'] and record['hold']


@pytest.mark.parametrize('change',['expiry','pin','plan','agent'])
def test_preflight_refusal_releases_only_new_process_hold(admin,prepared,monkeypatch,change):
    record=row(admin);result=approve(admin,record)
    with Session() as s:
        current=s.get(response.ProcessResponse,record['id'])
        if change=='expiry':s.get(response.Approval,current.approval_id).expires=time.time()-1
        if change=='pin':s.get(Host,'response-host').fingerprint='new-pin'
        if change=='plan':current.plan={**current.plan,'boot_id':'changed'}
        s.commit()
    if change=='agent':monkeypatch.setattr(agent_maintenance,'inspect',lambda *a,**k:{'state':'blocked'})
    worker.execute(result.json()['job_id']);record=row(admin)
    assert record['state']=='rejected' and not record['hold'] and file_row(admin)['hold']
    assert not [r for r in prepared['calls'] if r['action']=='process-suspend']


def test_approval_expiry_is_rechecked_after_slow_health(admin,prepared,monkeypatch):
    record=row(admin);result=approve(admin,record);now=time.time()
    def expired(*a,**k):monkeypatch.setattr(response.time,'time',lambda:now+600);return {'state':'current'}
    monkeypatch.setattr(agent_maintenance,'inspect',expired)
    worker.execute(result.json()['job_id'])
    assert row(admin)['state']=='rejected' and not [r for r in prepared['calls'] if r['action']=='process-suspend']


def test_monitoring_defers_and_alert_remains_until_reviewed_exit(admin,prepared):
    record=row(admin);worker.execute(approve(admin,record).json()['job_id']);record=row(admin)
    with Session() as s:s.add(Setting(key='response-monitor:response-host',value={'enabled':True,'interval_minutes':5,'revision':'v1'}));s.commit()
    response_monitor.schedule_tick(time.time()+10000);operations.collect_alerts()
    with Session() as s:
        assert not s.query(Job).filter_by(action='quarantine-audit').count()
        assert s.query(operations.Alert).filter_by(kind='process response hold').one().state=='open'
    prepared['state']['value']='exited';record=verify(admin,record)
    assert record['hold'] and record['state']=='exited'
    result=admin.post(BASE+'/process-responses/'+record['id']+'/actions/release',json={'plan_digest':record['plan_digest'],'receipt_digest':record['receipt_digest'],'reason':'Reviewed process exit and affected application health.','confirmation':'ACCEPT PROCESS EXIT'})
    assert result.status_code==200 and not row(admin)['hold'] and file_row(admin)['hold']


@pytest.mark.parametrize('change',['stale','descriptor_only','pin','scope','file_state'])
def test_preparation_requires_fresh_executable_evidence(admin,prepared,change):
    with Session() as s:
        observation=s.get(response_processes.Observation,'observation');record=s.get(quarantine.Quarantine,prepared['file']['id'])
        if change=='stale':observation.created=time.time()-301
        if change=='descriptor_only':observation.report={**observation.report,'observation':{**prepared['observed'],'matches':[{**prepared['observed']['matches'][0],'references':{'descriptor':1}}]}}
        if change=='pin':s.get(Host,'response-host').fingerprint='new-pin'
        if change=='scope':observation.report={**observation.report,'scope_current':False}
        if change=='file_state':record.state='restored'
        s.commit()
    result=admin.post(BASE+'/quarantines/'+prepared['file']['id']+'/process-preparations',json={'observation_id':'observation','pid':41,'plan_digest':prepared['file']['plan_digest']})
    assert result.status_code==400,result.text


def test_host_roles_pagination_and_console_review_are_separate(admin,prepared):
    record=row(admin);base=BASE+'/process-responses/'+record['id']
    assert admin.get(base.replace('response-host','other')+'/history').status_code==404
    assert admin.get(BASE+'/process-responses?offset=-1').status_code==400
    assert admin.get(base+'/history?offset=-1').status_code==400
    worker.execute(approve(admin,record).json()['job_id']);record=row(admin)
    result=admin.post(base+'/actions/release',json={'plan_digest':record['plan_digest'],'receipt_digest':record['receipt_digest'],'reason':'Recovered through a trusted console and reviewed services.','confirmation':'CONSOLE RECOVERED'})
    assert result.status_code==200 and row(admin)['state']=='console_recovered' and not row(admin)['hold']
    assert any(e['kind']=='hold_released' for e in history(admin,record)['events'])
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get(BASE+'/process-responses').status_code==403
        assert admin.get(base+'/history').status_code==403
        assert admin.post(base+'/verify',json={}).status_code==403
        assert admin.post(base+'/actions/suspend',json={'plan_digest':record['plan_digest'],'reason':'A sufficient review reason.','confirmation':'SUSPEND'}).status_code==403


@pytest.mark.parametrize('change',['id','digest','extra','ready','attempted','threads','state'])
def test_protocol_rejects_contradictory_receipts(admin,prepared,change):
    record=row(admin)
    value={'id':record['id'],'plan_digest':record['plan_digest'],'state':'suspended','resume_ready':True,'resume_attempted':False,'threads':1}
    if change=='id':value['id']='another-response'
    if change=='digest':value['plan_digest']='a'*64
    if change=='extra':value['environment']='must not be retained'
    if change=='ready':value['resume_ready']=False
    if change=='attempted':value['resume_attempted']=True
    if change=='threads':value['threads']=True
    if change=='state':value['state']='resumed'
    with Session() as s:
        with pytest.raises(ValueError):response.validate_receipt(value,s.get(response.ProcessResponse,record['id']))


def test_scope_is_rechecked_after_remote_io_without_releasing_a_hold(admin,prepared):
    record=row(admin)
    def changed():
        with Session() as s:s.get(Host,'response-host').fingerprint='changed-during-rpc';s.commit()
    prepared['state']['during']=changed
    result=approve(admin,record);worker.execute(result.json()['job_id'])
    assert row(admin)['state']=='uncertain' and row(admin)['hold'] and not row(admin)['receipt']
    with Session() as s:assert s.get(Job,result.json()['job_id']).state=='failed'


def test_deferred_automatic_read_cannot_deadlock_explicit_process_recovery(admin,prepared):
    record=row(admin);worker.execute(approve(admin,record).json()['job_id']);record=row(admin)
    with Session() as s:
        audit_job=worker.enqueue(s,'response-host','quarantine-audit',{'quarantine_id':prepared['file']['id']})
    worker.execute(audit_job)
    with Session() as s:assert s.get(Job,audit_job).state=='queued'
    assert verify(admin,record)['state']=='suspended'
    result=approve(admin,row(admin),True);assert result.status_code==200,result.text
    worker.execute(result.json()['job_id'])
    assert row(admin)['state']=='resumed' and not row(admin)['hold']
