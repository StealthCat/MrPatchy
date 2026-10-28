import copy
import time
import pytest
from app import response_processes as processes,quarantine,worker,incidents,agent_maintenance
from app.db import Session,Host,Job,Setting
from app.identity import User
from test_quarantine import scenario,row,approve,BASE


def report(record,**changes):
    return {'version':1,'id':record['id'],'plan_digest':record['plan_digest'],'state':'references_found','held_verified':True,
            'observation':{'scope':'helper_visible_process_leaders','boot_id':'12345678-1234-1234-1234-123456789abc','pid_namespace':123,'observer_pid':99,
            'processes_examined':2,'entries_examined':10,'matches':[{'pid':41,'start_ticks':100,'pid_namespace':123,'references':{'descriptor':1,'memory_map':1}}],'gaps':{}},**changes}


@pytest.fixture
def retained(admin,scenario,monkeypatch):
    worker.execute(approve(admin,row(admin)).json()['job_id']);record=row(admin)
    remote=worker.ssh.call;calls=[];data={'report':report(record),'failure':False,'during':lambda:None}
    def call(host,request,**kwargs):
        if request['action']!='quarantine-processes':return remote(host,request,**kwargs)
        calls.append(copy.deepcopy(request));data['during']()
        if data['failure']:raise TimeoutError('sensitive exception must not be retained')
        return copy.deepcopy(data['report'])
    monkeypatch.setattr(worker.ssh,'call',call)
    return data|{'data':data,'calls':calls,'record':record}


def queue(admin,record):
    result=admin.post(BASE+'/quarantines/'+record['id']+'/processes',json={'plan_digest':record['plan_digest']})
    assert result.status_code==200,result.text
    return result.json()['job_id']


def history(admin,record):return admin.get(BASE+'/quarantines/'+record['id']+'/processes').json()['items']


def test_observations_work_through_own_hold_and_never_change_response(admin,retained):
    record=retained['record'];before=row(admin)
    identifier=queue(admin,record)
    assert admin.post(BASE+'/quarantines/'+record['id']+'/processes',json={'plan_digest':record['plan_digest']}).status_code==409
    worker.execute(identifier)
    assert row(admin)['state']==before['state'] and row(admin)['receipt']==before['receipt'] and row(admin)['observed']==before['observed'] and row(admin)['hold']
    first=history(admin,record)[0]
    assert first['state']=='references_found' and first['actor']=='admin' and first['report']['held_verified']
    assert first['report']['observation']['matches'][0]['references']=={'descriptor':1,'memory_map':1}
    assert row(admin)['process_observation']['id']==identifier
    with Session() as s:
        assert s.get(Job,identifier).state=='complete'
        assert s.query(incidents.Incident).one().state=='open'
    retained['data']['report']['state']='none_observed';retained['data']['report']['observation']['matches']=[]
    second=queue(admin,record);worker.execute(second)
    assert len(history(admin,record))==2 and history(admin,record)[0]['state']=='none_observed'
    assert row(admin)['hold']
    with Session() as s:
        processes.execute(s,s.get(Host,'response-host'),s.get(Job,identifier));s.commit()
        assert s.query(processes.Observation).count()==2


@pytest.mark.parametrize('phase',['helper','remote','protocol'])
def test_failures_retain_explicit_sanitized_observations(admin,retained,monkeypatch,phase):
    if phase=='helper':monkeypatch.setattr(agent_maintenance,'inspect',lambda *a,**k:{'state':'blocked'})
    if phase=='remote':retained['data']['failure']=True
    if phase=='protocol':retained['data']['report']['unexpected']='secret unvalidated field'
    worker.execute(queue(admin,retained['record']))
    item=history(admin,retained['record'])[0]
    assert item['state']=='unavailable' and item['report']['failure']['stage']==phase
    assert item['report']['observation'] is None and 'sensitive' not in str(item) and 'secret' not in str(item)
    assert row(admin)['hold'] and row(admin)['state']=='quarantined'
    if phase=='helper':assert not retained['calls']


@pytest.mark.parametrize('change',['pin','plan','restored'])
def test_queued_work_does_not_follow_changed_scope(admin,retained,change):
    identifier=queue(admin,retained['record'])
    with Session() as s:
        if change=='pin':s.get(Host,'response-host').fingerprint='new-pin'
        if change=='plan':s.get(quarantine.Quarantine,retained['record']['id']).plan={**retained['record']['plan'],'xattrs':{'user.new':'a'*64}}
        if change=='restored':s.get(quarantine.Quarantine,retained['record']['id']).state='restored'
        s.commit()
    worker.execute(identifier)
    assert not retained['calls'] and history(admin,retained['record'])[0]['state']=='skipped'


def test_scope_is_rechecked_after_independent_health_and_remote_io(admin,retained,monkeypatch):
    record=retained['record']
    def changed_health(*a,**k):
        with Session() as s:s.get(Host,'response-host').fingerprint='new-pin';s.commit()
        return {'state':'current'}
    identifier=queue(admin,record);monkeypatch.setattr(agent_maintenance,'inspect',changed_health)
    worker.execute(identifier)
    assert not retained['calls'] and history(admin,record)[0]['state']=='skipped'
    with Session() as s:s.get(Host,'response-host').fingerprint='pin';s.commit()
    monkeypatch.setattr(agent_maintenance,'inspect',lambda *a,**k:{'state':'current'})
    def change_scope():
        with Session() as s:s.get(quarantine.Quarantine,record['id']).state='restored';s.commit()
    retained['data']['during']=change_scope
    worker.execute(queue(admin,record))
    assert history(admin,record)[0]['state']=='references_found' and not history(admin,record)[0]['report']['scope_current']
    assert row(admin)['state']=='restored' and row(admin)['hold']


def test_read_only_action_rechecks_a_cached_agent_outage(admin,retained):
    with Session() as s:s.add(Setting(key='agent-status:response-host',value={'state':'unavailable'}));s.commit()
    worker.execute(queue(admin,retained['record']))
    assert retained['calls'] and history(admin,retained['record'])[0]['state']=='references_found'


def test_pagination_host_roles_plan_and_state_boundaries(admin,retained):
    record=retained['record'];url=BASE+'/quarantines/'+record['id']+'/processes'
    assert admin.post(url,json={'plan_digest':'b'*64}).status_code==409
    assert admin.post(url,json={'plan_digest':'invalid'}).status_code==422
    assert admin.get(url+'?offset=-1').status_code==400
    assert admin.get(url.replace('response-host','another-host')).status_code==404
    assert admin.post(url.replace('response-host','another-host'),json={'plan_digest':record['plan_digest']}).status_code==404
    for n in range(22):
        with Session() as s:s.add(processes.Observation(id=str(n),host_id='response-host',quarantine_id=record['id'],actor='admin',created=n+1,state='unavailable',report={'scope_current':True}));s.commit()
    assert len(admin.get(url).json()['items'])==20 and admin.get(url).json()['more']
    assert len(admin.get(url+'?offset=20').json()['items'])==2 and not admin.get(url+'?offset=20').json()['more']
    assert row(admin)['process_observation']['id']=='21'
    with Session() as s:s.get(quarantine.Quarantine,record['id']).state='restored';s.commit()
    assert admin.post(url,json={'plan_digest':record['plan_digest']}).status_code==409
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get(url).status_code==403
        assert admin.post(url,json={'plan_digest':record['plan_digest']}).status_code==403


@pytest.mark.parametrize('change',['extra','binding','bool_count','unknown_gap','duplicate_pid','bad_state','no_binding','negative_ticks','bad_kind','too_many','no_namespace'])
def test_protocol_rejects_unbound_or_contradictory_results(admin,retained,change):
    value=copy.deepcopy(retained['data']['report']);obs=value['observation']
    if change=='extra':obs['cmdline']='must not be retained'
    if change=='binding':value['plan_digest']='b'*64
    if change=='bool_count':obs['entries_examined']=True
    if change=='unknown_gap':obs['gaps']['secret exception']=1
    if change=='duplicate_pid':obs['matches']*=2
    if change=='bad_state':value['state']='none_observed'
    if change=='no_binding':value['held_verified']=False
    if change=='negative_ticks':obs['matches'][0]['start_ticks']=-1
    if change=='bad_kind':obs['matches'][0]['references']={'arbitrary':1}
    if change=='too_many':obs['processes_examined']=4097
    if change=='no_namespace':obs['pid_namespace']=None
    with Session() as s:
        with pytest.raises(ValueError):processes.validate(value,s.get(quarantine.Quarantine,retained['record']['id']))
