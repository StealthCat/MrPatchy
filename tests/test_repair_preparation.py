import copy
import json
import time
import uuid
import pytest
from app import repair_preparation as repair,quarantine,process_response,worker,incidents,vendor,agent_maintenance
from app.db import Session,Host,Job,Setting
from app.identity import User
from test_quarantine import scenario,row as file_row,approve,BASE
from test_vendor import bundle,signing


@pytest.fixture
def retained(admin,scenario,monkeypatch):
    worker.execute(approve(admin,file_row(admin)).json()['job_id']);record=file_row(admin)
    manifest={'package':'fixture','version':'1.0-1','architecture':'all','entries':[{'path':record['plan']['file']['path'],'sha256':'b'*64,'size':10}]}
    proof={'bundle_id':'fixture','artifact_sha256':'c'*64,'keyring_sha256':'d'*64,'signers':['e'*40],'authenticated_at':time.time()}
    state={'failure':None,'blocked':False,'during':lambda:None,'changed_trust':False};auth=[];calls=[];original=worker.ssh.call
    def authenticate(bundle_id,path):
        auth.append((bundle_id,path))
        if state['failure']=='authentication':raise ValueError('replacement secret must not be retained')
        result=copy.deepcopy(proof);result['authenticated_at']=time.time()
        if state['changed_trust'] and len(auth)>1:result['keyring_sha256']='f'*64
        return copy.deepcopy(manifest),result
    monkeypatch.setattr(vendor,'replacement',authenticate)
    def call(host,request,**kwargs):
        if request['action']!='repair-readiness':return original(host,request,**kwargs)
        calls.append(copy.deepcopy(request));state['during']()
        if state['failure']=='remote':raise TimeoutError('replacement secret must not be retained')
        facts={k:True for k in repair.FACTS};gaps=[]
        if state['blocked']:facts['destination_empty']=False;gaps=['destination_occupied']
        result={'version':1,'quarantine_id':request['id'],'response_plan_digest':incidents.digest(request['plan']),'manifest_digest':incidents.digest(request['manifest']),
                'state':'blocked' if gaps else 'ready','facts':facts,'gaps':gaps,'replacement_mode':0o640}
        if state['failure']=='protocol':result['content']='replacement secret must not be retained'
        return result
    monkeypatch.setattr(worker.ssh,'call',call)
    return {'record':record,'calls':calls,'auth':auth,'state':state,'manifest':manifest,'proof':proof}


def queue(admin,record):
    result=admin.post(BASE+'/quarantines/'+record['id']+'/repair-preparations',json={'bundle_id':'fixture','plan_digest':record['plan_digest']})
    assert result.status_code==200,result.text
    assert result.json()['read_only'] and result.json()['publication']=='not_implemented'
    return result.json()

def history(admin):return admin.get(BASE+'/repair-preparations').json()['items']


def test_immutable_preparation_authenticates_twice_and_never_changes_holds(admin,retained):
    before=file_row(admin);job=queue(admin,before);worker.execute(job['job_id'])
    result=history(admin)[0]
    assert result['state']=='ready' and result['actor']=='admin' and result['report']['scope_current']
    assert result['report']['publication']=='not_implemented' and result['report']['manifest']==retained['manifest']
    assert len(retained['auth'])==2 and len(retained['calls'])==1
    assert 'replacement secret' not in json.dumps(result)
    assert file_row(admin)['state']==before['state'] and file_row(admin)['hold']==before['hold'] and file_row(admin)['observed']==before['observed']
    with Session() as s:
        assert s.get(Job,job['job_id']).state=='complete'
        repair.execute(s,s.get(Host,'response-host'),s.get(Job,job['job_id']));s.commit()
        assert s.query(repair.Preparation).count()==1
        assert s.query(incidents.Incident).one().state=='open'
    assert len(retained['calls'])==1 and history(admin)[0]['finished']==result['finished']


@pytest.mark.parametrize('failure',['authentication','helper','remote','protocol','authentication_recheck'])
def test_unavailable_receipts_are_sanitized_and_cannot_be_ready(admin,retained,monkeypatch,failure):
    if failure=='helper':monkeypatch.setattr(agent_maintenance,'inspect',lambda *a,**k:{'state':'blocked'})
    elif failure=='authentication_recheck':retained['state']['changed_trust']=True
    else:retained['state']['failure']=failure
    job=queue(admin,retained['record']);worker.execute(job['job_id'])
    result=history(admin)[0]
    assert result['state']=='unavailable' and result['report']['failure']['stage']==failure
    assert not result['report']['scope_current'] and 'replacement secret' not in json.dumps(result)
    if failure in ('authentication','helper'):assert not retained['calls']
    with Session() as s:assert s.get(Job,job['job_id']).state=='failed'
    assert file_row(admin)['hold']


def test_blocked_preparation_is_a_recorded_observation_not_action_success(admin,retained):
    retained['state']['blocked']=True;job=queue(admin,retained['record']);worker.execute(job['job_id'])
    result=history(admin)[0]
    assert result['state']=='blocked' and result['report']['target']['gaps']==['destination_occupied']
    with Session() as s:assert s.get(Job,job['job_id']).state=='complete'
    assert file_row(admin)['hold']


@pytest.mark.parametrize('change',['pin','plan','restored'])
def test_changed_queued_scope_is_skipped_before_authentication_or_access(admin,retained,change):
    job=queue(admin,retained['record'])
    with Session() as s:
        if change=='pin':s.get(Host,'response-host').fingerprint='new-pin'
        if change=='plan':s.get(quarantine.Quarantine,retained['record']['id']).plan={**retained['record']['plan'],'xattrs':{'user.new':'b'*64}}
        if change=='restored':s.get(quarantine.Quarantine,retained['record']['id']).state='restored'
        s.commit()
    worker.execute(job['job_id'])
    assert history(admin)[0]['state']=='skipped' and not retained['calls'] and not retained['auth']


@pytest.mark.parametrize('phase',['health','remote'])
def test_scope_rechecked_after_health_and_remote_io(admin,retained,monkeypatch,phase):
    def changed(*args,**kwargs):
        with Session() as s:s.get(Host,'response-host').fingerprint='changed';s.commit()
        return {'state':'current'}
    if phase=='health':monkeypatch.setattr(agent_maintenance,'inspect',changed)
    else:retained['state']['during']=changed
    worker.execute(queue(admin,retained['record'])['job_id'])
    result=history(admin)[0]
    assert result['state']=='skipped' and not result['report']['scope_current']
    if phase=='health':assert not retained['calls']
    else:assert result['report']['target']['state']=='ready'


def test_same_response_process_holds_allow_only_this_read_and_remain_active(admin,retained):
    record=retained['record']
    with Session() as s:
        s.add(process_response.ProcessResponse(id='process-hold',host_id='response-host',quarantine_id=record['id'],observation_id='old',state='suspended',hold=True,fingerprint='pin',plan={}));s.commit()
        deferred=worker.enqueue(s,'response-host','quarantine-audit',{'quarantine_id':record['id']})
        ordinary=worker.enqueue(s,'response-host','refresh')
    worker.execute(ordinary);worker.execute(deferred)
    job=queue(admin,record);worker.execute(job['job_id'])
    assert history(admin)[0]['state']=='ready'
    with Session() as s:
        assert s.get(process_response.ProcessResponse,'process-hold').hold and s.get(quarantine.Quarantine,record['id']).hold
        assert s.get(Job,ordinary).state=='queued' and s.get(Job,deferred).state=='queued'
        s.get(process_response.ProcessResponse,'process-hold').quarantine_id='unrelated';s.commit()
    assert admin.post(BASE+'/quarantines/'+record['id']+'/repair-preparations',json={'bundle_id':'fixture','plan_digest':record['plan_digest']}).status_code==409


def test_role_host_pagination_and_pending_boundaries(admin,retained):
    record=retained['record'];url=BASE+'/quarantines/'+record['id']+'/repair-preparations';body={'bundle_id':'fixture','plan_digest':record['plan_digest']}
    assert admin.post(url.replace('response-host','other'),json=body).status_code==404
    assert admin.post(url,json={**body,'plan_digest':'f'*64}).status_code==400
    first=queue(admin,record)
    assert admin.post(url,json=body).status_code==409
    worker.execute(first['job_id'])
    with Session() as s:
        for index in range(21):s.add(repair.Preparation(id=str(index),host_id='response-host',quarantine_id=record['id'],bundle_id='old',path='/srv/old',actor='admin',state='blocked',fingerprint='pin',response_plan_digest='a'*64))
        s.commit()
    assert len(admin.get(BASE+'/repair-preparations').json()['items'])==20 and admin.get(BASE+'/repair-preparations').json()['more']
    assert len(admin.get(BASE+'/repair-preparations?offset=20').json()['items'])==2
    assert admin.get(BASE+'/repair-preparations?offset=-1').status_code==400
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get(BASE+'/repair-preparations').status_code==403
        assert admin.post(url,json=body).status_code==403


@pytest.mark.parametrize('change',['id','manifest','plan','extra','facts','state','mode','gap'])
def test_unbound_or_contradictory_protocol_is_rejected(admin,retained,change):
    record=retained['record'];value={'version':1,'quarantine_id':record['id'],'response_plan_digest':record['plan_digest'],'manifest_digest':incidents.digest(retained['manifest']),
        'state':'ready','facts':{k:True for k in repair.FACTS},'gaps':[],'replacement_mode':0o640}
    if change=='id':value['quarantine_id']='other'
    if change=='manifest':value['manifest_digest']='f'*64
    if change=='plan':value['response_plan_digest']='f'*64
    if change=='extra':value['content']='not metadata'
    if change=='facts':value['facts']['owner_matches']=1
    if change=='state':value['state']='blocked'
    if change=='mode':value['replacement_mode']=0o755
    if change=='gap':value['gaps']=['untrusted exception body']
    with Session() as s:
        with pytest.raises(ValueError):repair.validate(value,s.get(quarantine.Quarantine,record['id']),retained['manifest'])


def test_real_authenticated_replacement_hash_and_path_binding(bundle):
    directory,_=bundle;(directory/'replacement').write_bytes(b'known bytes')
    manifest,proof=vendor.replacement('fixture','/usr/share/patchy-test')
    assert manifest['entries'][0]['sha256']==vendor.sha(b'known bytes') and proof['signers']
    assert 'known bytes' not in json.dumps((manifest,proof))
    assert vendor.authentication_digest(manifest,proof)==vendor.authentication_digest(manifest,{**proof,'authenticated_at':time.time()+1})
    with pytest.raises(ValueError):vendor.replacement('fixture','/srv/not-listed')
    (directory/'replacement').write_bytes(b'tampered')
    with pytest.raises(ValueError):vendor.replacement('fixture','/usr/share/patchy-test')
    (directory/'replacement').unlink();(directory/'replacement').symlink_to(directory/'package.deb')
    with pytest.raises(OSError):vendor.replacement('fixture','/usr/share/patchy-test')
