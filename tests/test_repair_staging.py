import base64
import copy
import json
import time
import uuid
import pytest
from app import repair_staging as staging,repair_preparation,quarantine,process_response,vendor,worker,agent_maintenance,incidents
from app.db import Session,Host,Job
from app.identity import User
from test_repair_preparation import retained,scenario,queue as prepare,history as preparations
from test_quarantine import row as file_row,BASE


@pytest.fixture
def transfer(admin,retained,monkeypatch):
    data=b'BINARY_STAGING_SECRET_'+b'x'*staging.CHUNK_SIZE
    retained['manifest']['entries'][0].update(size=len(data),sha256=vendor.sha(data))
    worker.execute(prepare(admin,retained['record'])['job_id'])
    prepared=preparations(admin)[0];assert prepared['state']=='ready'
    def payload(bundle,path):
        manifest,proof=vendor.replacement(bundle,path)
        return manifest,proof,data
    monkeypatch.setattr(vendor,'replacement_payload',payload)
    original=worker.ssh.call;calls=[]
    state={'received':0,'staged':False,'failure':None,'during':lambda action:None,'bad':None,'capacity':False}
    def call(host,request,**kwargs):
        action=request['action']
        if not action.startswith('repair-stage-'):return original(host,request,**kwargs)
        calls.append({'action':action,'offset':request.get('offset'),'length':len(json.dumps(request))})
        if state['failure']==action:raise TimeoutError('BINARY_STAGING_SECRET_ must not be retained')
        if action=='repair-stage-chunk':
            block=base64.b64decode(request['data']);assert block==data[request['offset']:request['offset']+len(block)]
            state['received']+=len(block)
        if action=='repair-stage-finish':state['staged']=True
        state['during'](action)
        if state['failure']==action+'-after':raise TimeoutError('BINARY_STAGING_SECRET_ must not be retained')
        entry=request['plan']['manifest']['entries'][0]
        result={'version':1,'id':request['id'],'plan_digest':incidents.digest(request['plan']),'state':'staged' if state['staged'] else 'receiving',
                'received':state['received'],'payload':{'sha256':entry['sha256'],'size':entry['size'],'identity':{'dev':1,'ino':999,'size':entry['size'],'uid':0,'gid':0,'mode':0o100600,'mtime_ns':10,'nlink':1}} if state['staged'] else None,
                'facts':{'intent_verified':True,'payload_verified':state['staged'],'completion_recorded':state['staged']},'readiness':None}
        if state['capacity']:
            result.update(state='capacity_reached',received=0,payload=None,facts={'intent_verified':False,'payload_verified':False,'completion_recorded':False},readiness=copy.deepcopy(prepared['report']['target']))
        if state['bad']:state['bad'](result)
        return result
    monkeypatch.setattr(worker.ssh,'call',call)
    return {'prepared':prepared,'calls':calls,'state':state,'retained':retained,'data':data}


def approve(admin,f,**change):
    return admin.post(BASE+'/repair-preparations/'+f['prepared']['id']+'/stage',json={'report_digest':f['prepared']['report_digest'],'confirmation':'STAGE','reason':'Reviewed authenticated private staging and storage limits.',**change})
def stages(admin):return admin.get(BASE+'/repair-stages').json()['items']
def verify(admin,identifier):
    result=admin.post(BASE+'/repair-stages/'+identifier+'/status',json={});assert result.status_code==200,result.text
    worker.execute(result.json()['job_id']);return stages(admin)[0]


def test_separate_approval_chunk_budget_history_and_unchanged_response(admin,transfer):
    f=transfer;assert not stages(admin) and not f['calls']
    for changes in ({'confirmation':'PUBLISH'},{'reason':' '*20},{'report_digest':'f'*64}):assert approve(admin,f,**changes).status_code==400
    before=file_row(admin);approved=approve(admin,f);assert approved.status_code==200,approved.text
    identifier=approved.json()['stage_id'];assert not f['calls']
    assert approve(admin,f).status_code==409
    worker.execute(approved.json()['job_id']);result=stages(admin)[0]
    assert result['state']=='staged' and result['report']['scope_current'] and result['report']['trust_current']
    assert result['report']['publication']=='not_authorized' and result['actor']=='admin'
    assert [c['action'] for c in f['calls']]==['repair-stage-begin','repair-stage-chunk','repair-stage-chunk','repair-stage-finish']
    assert max(c['length'] for c in f['calls'])<4_000_000
    assert file_row(admin)['state']==before['state'] and file_row(admin)['hold']==before['hold'] and file_row(admin)['observed']==before['observed']
    events=admin.get(BASE+'/repair-stages/'+identifier+'/history').json()['items']
    assert {e['kind'] for e in events}=={'approved','started','observed_staged'}
    assert 'BINARY_STAGING_SECRET_' not in json.dumps(result) and 'BINARY_STAGING_SECRET_' not in json.dumps(events)
    assert preparations(admin)[0]['stage_id']==identifier
    with Session() as s:
        job=s.get(Job,approved.json()['job_id']);assert job.state=='complete'
        count=len(f['calls']);assert not staging.execute(s,s.get(Host,'response-host'),job)['replayed']
        assert len(f['calls'])==count and s.query(incidents.Incident).one().state=='open'


@pytest.mark.parametrize('failure',['authentication','helper','bytes'])
def test_preflight_failures_send_no_payload_and_redact_errors(admin,transfer,monkeypatch,failure):
    f=transfer
    if failure=='authentication':f['retained']['state']['failure']='authentication'
    if failure=='helper':monkeypatch.setattr(agent_maintenance,'inspect',lambda *a,**k:{'state':'blocked'})
    if failure=='bytes':monkeypatch.setattr(vendor,'replacement_payload',lambda *a:(f['retained']['manifest'],f['retained']['proof'],b'wrong bytes'))
    approved=approve(admin,f);worker.execute(approved.json()['job_id']);result=stages(admin)[0]
    assert result['state']=='rejected' and not f['calls'] and 'BINARY_STAGING_SECRET_' not in json.dumps(result)
    with Session() as s:assert s.get(Job,approved.json()['job_id']).state=='failed'


def test_capacity_refusal_is_classified_and_does_not_send_chunks(admin,transfer):
    transfer['state']['capacity']=True;approved=approve(admin,transfer);worker.execute(approved.json()['job_id'])
    assert stages(admin)[0]['state']=='capacity_reached'
    assert [call['action'] for call in transfer['calls']]==['repair-stage-begin']
    assert file_row(admin)['hold']
    with Session() as s:assert s.get(Job,approved.json()['job_id']).state=='failed'


@pytest.mark.parametrize('phase',['queued','health','chunk'])
def test_expired_approvals_never_start_or_continue_the_transfer(admin,transfer,monkeypatch,phase):
    f=transfer;approved=approve(admin,f);identifier=approved.json()['stage_id']
    def expire(*args):
        with Session() as s:s.get(staging.Stage,identifier).expires=time.time()-1;s.commit()
        return {'state':'current'}
    if phase=='queued':expire()
    if phase=='health':monkeypatch.setattr(agent_maintenance,'inspect',expire)
    if phase=='chunk':f['state']['during']=lambda action:expire() if action=='repair-stage-chunk' else None
    worker.execute(approved.json()['job_id']);result=stages(admin)[0]
    assert result['state']==('uncertain' if phase=='chunk' else 'rejected')
    assert all(c['action']!='repair-stage-finish' for c in f['calls'])
    if phase!='chunk':assert not f['calls']


@pytest.mark.parametrize('change',['pin','plan','restored'])
def test_scope_changes_during_transfer_stop_later_chunks_with_fresh_db_reads(admin,transfer,change):
    f=transfer
    def changed(action):
        if action!='repair-stage-chunk':return
        with Session() as s:
            original=s.get(quarantine.Quarantine,f['retained']['record']['id'])
            if change=='pin':s.get(Host,'response-host').fingerprint='changed-pin'
            if change=='plan':original.plan={**original.plan,'xattrs':{'user.changed':'e'*64}}
            if change=='restored':original.state='restored'
            s.commit()
    f['state']['during']=changed;approved=approve(admin,f);worker.execute(approved.json()['job_id'])
    assert stages(admin)[0]['state']=='uncertain'
    assert [c['action'] for c in f['calls']]==['repair-stage-begin','repair-stage-chunk']


@pytest.mark.parametrize('phase',['before','during','after'])
def test_changed_authentication_prevents_positive_staging_and_never_publishes(admin,transfer,phase):
    f=transfer
    def changed(action):
        if action==('repair-stage-finish' if phase=='after' else 'repair-stage-chunk'):f['retained']['state']['changed_trust']=True
    if phase=='before':f['retained']['state']['changed_trust']=True
    else:f['state']['during']=changed
    approved=approve(admin,f);worker.execute(approved.json()['job_id']);result=stages(admin)[0]
    assert result['state']==('rejected' if phase=='before' else 'uncertain')
    assert not result['report']['scope_current']
    if phase=='before':assert not f['calls']
    if phase=='during':assert not any(c['action']=='repair-stage-finish' for c in f['calls'])
    if phase=='after':assert result['report']['target']['state']=='staged'


@pytest.mark.parametrize('phase',['chunk','finish'])
def test_lost_replies_are_reconciled_read_only_without_upload_retry(admin,transfer,phase):
    f=transfer;f['state']['failure']='repair-stage-'+phase+'-after';approved=approve(admin,f)
    worker.execute(approved.json()['job_id']);result=stages(admin)[0]
    assert result['state']=='uncertain' and 'BINARY_STAGING_SECRET_' not in json.dumps(result)
    previous=list(f['calls']);f['state']['failure']=None;result=verify(admin,result['id'])
    assert result['state']==('incomplete' if phase=='chunk' else 'staged')
    assert f['calls'][:-1]==previous and f['calls'][-1]['action']=='repair-stage-status'
    assert file_row(admin)['hold']


def test_related_process_holds_are_preserved_and_other_holds_block_staging(admin,transfer):
    f=transfer;qid=f['retained']['record']['id']
    with Session() as s:
        s.add(process_response.ProcessResponse(id='related',host_id='response-host',quarantine_id=qid,observation_id='old',state='suspended',hold=True,fingerprint='pin',plan={}))
        normal=worker.enqueue(s,'response-host','refresh');deferred=worker.enqueue(s,'response-host','quarantine-audit',{'quarantine_id':qid})
    approved=approve(admin,f);assert approved.status_code==200,approved.text
    worker.execute(approved.json()['job_id']);assert stages(admin)[0]['state']=='staged'
    worker.execute(normal);worker.execute(deferred)
    with Session() as s:
        assert s.get(process_response.ProcessResponse,'related').hold and s.get(quarantine.Quarantine,qid).hold
        assert s.get(Job,normal).state=='queued' and s.get(Job,deferred).state=='queued'
        s.get(process_response.ProcessResponse,'related').quarantine_id='other';s.commit()
    assert admin.post(BASE+'/repair-stages/'+stages(admin)[0]['id']+'/status',json={}).status_code==409


def test_unrelated_hold_appearing_between_chunks_prevents_continuation(admin,transfer):
    f=transfer
    def hold(action):
        if action=='repair-stage-chunk':
            with Session() as s:s.add(process_response.ProcessResponse(id='unrelated',host_id='response-host',quarantine_id='other',observation_id='old',state='uncertain',hold=True,fingerprint='pin',plan={}));s.commit()
    f['state']['during']=hold;approved=approve(admin,f);worker.execute(approved.json()['job_id'])
    assert stages(admin)[0]['state']=='uncertain' and len(f['calls'])==2


def test_status_keeps_approval_history_when_bundle_is_removed_and_failed_health_clears_old_proof(admin,transfer,monkeypatch):
    f=transfer;approved=approve(admin,f);worker.execute(approved.json()['job_id']);record=stages(admin)[0]
    first=admin.get(BASE+'/repair-stages/'+record['id']+'/history').json()['items']
    f['retained']['state']['failure']='authentication';result=verify(admin,record['id'])
    assert result['state']=='staged' and not result['report']['trust_current']
    monkeypatch.setattr(agent_maintenance,'inspect',lambda *a,**k:{'state':'blocked'})
    result=verify(admin,record['id']);assert result['state']=='uncertain' and 'target' not in result['report']
    events=admin.get(BASE+'/repair-stages/'+record['id']+'/history').json()['items']
    assert all(e in events for e in first) and len(events)==len(first)+2


@pytest.mark.parametrize('change',['id','plan','version','extra','received','payload','mode'])
def test_bad_receipts_are_never_positive(admin,transfer,change):
    f=transfer
    def bad(value):
        if change=='id':value['id']='wrong'
        if change=='plan':value['plan_digest']='f'*64
        if change=='version':value['version']=True
        if change=='extra':value['content']='BINARY_STAGING_SECRET_'
        if change=='received':value['received']=True
        if change=='payload':value['facts']['payload_verified']=True
        if change=='mode' and value['payload']:value['payload']['identity']['mode']=0o100755
    f['state']['bad']=bad;approved=approve(admin,f);worker.execute(approved.json()['job_id'])
    assert stages(admin)[0]['state']=='uncertain' and 'BINARY_STAGING_SECRET_' not in json.dumps(stages(admin)[0])


def test_roles_host_scope_pagination_and_publication_requires_its_own_approval(admin,transfer):
    f=transfer;approved=approve(admin,f);worker.execute(approved.json()['job_id']);row=stages(admin)[0]
    assert admin.get(BASE.replace('response-host','other')+'/repair-stages/'+row['id']+'/history').status_code==404
    assert admin.post(BASE.replace('response-host','other')+'/repair-preparations/'+f['prepared']['id']+'/stage',json={'report_digest':f['prepared']['report_digest'],'confirmation':'STAGE','reason':'Reviewed staging only.'}).status_code==404
    assert admin.get(BASE+'/repair-stages?offset=-1').status_code==400
    assert admin.get(BASE+'/repair-stages/'+row['id']+'/history?offset=-1').status_code==400
    assert admin.post(BASE+'/repair-stages/'+row['id']+'/publish',json={}).status_code==422
    with Session() as s:
        for i in range(21):s.add(staging.Event(stage_id=row['id'],host_id='response-host',kind='fixture',actor='admin'))
        s.commit()
    assert len(admin.get(BASE+'/repair-stages/'+row['id']+'/history').json()['items'])==20
    assert admin.get(BASE+'/repair-stages/'+row['id']+'/history').json()['more']
    assert len(admin.get(BASE+'/repair-stages/'+row['id']+'/history?offset=20').json()['items'])==4
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get(BASE+'/repair-stages').status_code==403
        assert admin.post(BASE+'/repair-stages/'+row['id']+'/status',json={}).status_code==403


def test_staging_approval_and_events_survive_verified_offline_database_copy(admin,transfer,tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session as DatabaseSession
    from app import database_migrate
    from app.db import engine
    approved=approve(admin,transfer);worker.execute(approved.json()['job_id']);identifier=approved.json()['stage_id']
    destination='sqlite:///'+str(tmp_path/'staging-copy.db')
    result=database_migrate.migrate(engine.url.render_as_string(hide_password=False),destination)
    assert result['security_repair_stages']['rows']==1 and result['security_repair_stage_events']['rows']==3
    copied=create_engine(destination)
    try:
        with DatabaseSession(copied) as s:
            row=s.get(staging.Stage,identifier)
            assert row.state=='staged' and row.reason=='Reviewed authenticated private staging and storage limits.'
            assert row.report['target']['payload']['sha256']==vendor.sha(transfer['data'])
            assert s.query(staging.Event).filter_by(stage_id=identifier).count()==3
    finally:copied.dispose()
