import copy
import json
import time
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session as DatabaseSession
from app import response_health as health,quarantine,worker,incidents,agent_maintenance,process_response,repair_publication
from app.db import Session,Host,Job,engine
from app.identity import User
from target import agent
from test_quarantine import scenario,row,BASE
from test_repair_preparation import retained
from test_repair_staging import transfer
from test_repair_publication import staged,publish
from test_response_health_target import properties,BOOT


@pytest.fixture
def remote(admin,scenario,monkeypatch):
    original=worker.ssh.call;calls=[];state={'properties':{},'during':lambda:None,'failure':False,'bad':lambda value:None}
    monkeypatch.setattr(agent,'response_service_boot',lambda:BOOT)
    monkeypatch.setattr(agent,'response_service_query',lambda unit,timeout:properties(unit,**state['properties']))
    def call(host,request,**kwargs):
        if request['action']!=health.ACTION:return original(host,request,**kwargs)
        assert kwargs['timeout']==120;calls.append(copy.deepcopy(request));state['during']()
        if state['failure']:raise TimeoutError('PRIVATE_DIAGNOSTIC')
        result=agent.response_service_health(request['id'],request['plan_digest'],request['units']);state['bad'](result)
        return result
    monkeypatch.setattr(worker.ssh,'call',call)
    return {'state':state,'calls':calls}


def queue(admin,record=None,**changes):
    record=record or row(admin)
    return admin.post(BASE+'/quarantines/'+record['id']+'/service-health',json={
        'plan_digest':record['plan_digest'],'units':['example.service'],'reason':'Review explicitly selected services after file remediation.','baseline_id':'',**changes})


def history(admin,record=None,offset=0):
    record=record or row(admin)
    return admin.get(BASE+'/quarantines/'+record['id']+'/service-health?offset='+str(offset)).json()


def observe(admin,**changes):
    response=queue(admin,**changes);assert response.status_code==200,response.text
    worker.execute(response.json()['job_id']);return history(admin)['items'][0]


def test_explicit_service_checks_are_immutable_do_not_change_response_or_pauses(admin,remote):
    before=row(admin);first=observe(admin)
    assert first['state']=='healthy' and first['actor']=='admin' and first['reason'].startswith('Review explicitly')
    assert first['report']['scope_current'] and first['report']['target']['boot_rechecked']
    assert row(admin)['service_observation']['id']==first['id']
    assert first['report']['comparison']['state']=='not_requested'
    assert all(row(admin)[key]==before[key] for key in ('state','hold','receipt','observed'))
    with Session() as s:
        job=s.get(Job,first['id']);assert job.state=='complete'
        health.execute(s,s.get(Host,'response-host'),job);s.commit()
        assert s.query(health.Observation).count()==1 and s.query(incidents.Incident).one().state=='open'
        assert s.query(quarantine.Event).filter_by(kind='service_health_observed').one().details['observation_id']==first['id']
    assert len(remote['calls'])==1
    remote['state']['properties']={'ActiveState':'failed','Result':'exit-code','MainPID':0}
    second=observe(admin,baseline_id=first['id'])
    assert second['state']=='problem' and second['report']['comparison']['state']=='compared'
    changes=second['report']['comparison']['changes'][0]
    assert changes['unit']=='example.service' and changes['fields']['ActiveState']=={'before':'active','after':'failed'}
    assert history(admin)['items'][1]==first
    with Session() as s:assert s.get(Job,second['id']).state=='complete'


@pytest.mark.parametrize('phase',['helper','remote','protocol'])
def test_failures_are_sanitized_and_never_become_positive(admin,remote,monkeypatch,phase):
    if phase=='helper':monkeypatch.setattr(agent_maintenance,'inspect',lambda *a,**k:{'state':'blocked'})
    if phase=='remote':remote['state']['failure']=True
    if phase=='protocol':remote['state']['bad']=lambda result:result.update(SECRET_UNVALIDATED=True)
    result=observe(admin)
    assert result['state']=='unavailable' and result['report']['target'] is None and result['report']['failure']['stage']==phase
    assert 'PRIVATE_DIAGNOSTIC' not in json.dumps(result) and 'SECRET_UNVALIDATED' not in json.dumps(result)
    if phase=='helper':assert not remote['calls']
    with Session() as s:assert s.get(Job,result['id']).state=='failed'


@pytest.mark.parametrize('change',['outcome','unit','boot','properties','counter','failure','gap','sample'])
def test_contradictory_or_unbound_target_receipts_are_rejected(admin,remote,change):
    def corrupt(result):
        service=result['services'][0]
        if change=='outcome':result['state']='problem'
        if change=='unit':service['unit']='other.service'
        if change=='boot':result['boot_id']=None
        if change=='properties':service['after']['ExecStart']='PRIVATE_COMMAND'
        if change=='counter':service['after']['NRestarts']=True
        if change=='failure':service['failure']='query_failed'
        if change=='gap':result['gaps']=['unit_unavailable']
        if change=='sample':service['after']['MainPID']=43
    remote['state']['bad']=corrupt
    result=observe(admin)
    assert result['state']=='unavailable' and result['report']['failure']['stage']=='protocol'
    assert result['report']['target'] is None and 'PRIVATE_COMMAND' not in json.dumps(result)


@pytest.mark.parametrize('change',['pin','plan','state','publication'])
@pytest.mark.parametrize('phase',['queued','helper','remote'])
def test_scope_is_revalidated_before_and_after_io(admin,remote,monkeypatch,change,phase):
    file=row(admin);response=queue(admin);assert response.status_code==200
    def mutate():
        with Session() as s:
            q=s.get(quarantine.Quarantine,file['id'])
            if change=='pin':s.get(Host,'response-host').fingerprint='new-pin'
            if change=='plan':q.plan={**q.plan,'xattrs':{'user.changed':'a'*64}}
            if change=='state':q.state='console_recovered'
            if change=='publication':s.add(repair_publication.Publication(id='new-pub',host_id=q.host_id,quarantine_id=q.id,stage_id='different',expires=time.time()+300,actor='admin',reason='Different publication',fingerprint='pin',stage_report_digest='a'*64,plan={'different':True},before_state=q.state,before_hold=q.hold,state='published',hold=False))
            s.commit()
    if phase=='queued':mutate()
    if phase=='helper':
        def verified(*a,**k):mutate();return {'state':'current'}
        monkeypatch.setattr(agent_maintenance,'inspect',verified)
    if phase=='remote':remote['state']['during']=mutate
    worker.execute(response.json()['job_id']);result=history(admin,file)['items'][0]
    assert result['state']=='skipped' and not result['report']['scope_current']
    assert bool(remote['calls'])==(phase=='remote')


def test_own_file_process_publication_pauses_allow_read_only_checks_but_remain_active(admin,staged,monkeypatch):
    published=publish(admin,staged);file=row(admin)
    with Session() as s:
        s.add(process_response.ProcessResponse(id='related',host_id='response-host',quarantine_id=file['id'],observation_id='old',state='suspended',hold=True,fingerprint='pin',plan={}));s.commit()
    monkeypatch.setattr(agent,'response_service_boot',lambda:BOOT)
    monkeypatch.setattr(agent,'response_service_query',lambda unit,timeout:properties(unit))
    original=worker.ssh.call
    monkeypatch.setattr(worker.ssh,'call',lambda host,request,**kwargs:agent.response_service_health(request['id'],request['plan_digest'],request['units']) if request['action']==health.ACTION else original(host,request,**kwargs))
    result=observe(admin);assert result['state']=='healthy'
    assert result['report']['publication_id']==published['id'] and result['report']['response_state']=='replaced'
    waiting=queue(admin);assert waiting.status_code==200
    with Session() as s:
        assert s.get(quarantine.Quarantine,file['id']).hold
        assert s.get(repair_publication.Publication,published['id']).hold
        assert s.get(process_response.ProcessResponse,'related').hold
        s.add(process_response.ProcessResponse(id='unrelated',host_id='response-host',quarantine_id='another',observation_id='old',state='suspended',hold=True,fingerprint='pin',plan={}));s.commit()
    assert queue(admin).status_code==409
    worker.execute(waiting.json()['job_id'])
    with Session() as s:assert s.get(Job,waiting.json()['job_id']).state=='queued'


def test_pending_work_and_other_operations_are_not_bypassed(admin,remote):
    first=queue(admin);assert first.status_code==200
    assert queue(admin).status_code==409
    with Session() as s:
        s.get(Job,first.json()['job_id']).state='cancelled'
        s.add(Job(id='recovery',host_id='response-host',action='patch',state='recovery_required'));s.commit()
    assert queue(admin).status_code==409 and not remote['calls']


def test_baseline_units_identity_and_digest_are_bound_and_rechecked(admin,remote):
    first=observe(admin)
    assert queue(admin,baseline_id=first['id'],units=['other.service']).status_code==400
    response=queue(admin,baseline_id=first['id']);assert response.status_code==200
    with Session() as s:
        previous=s.get(health.Observation,first['id']);previous.report={**previous.report,'started':0};s.commit()
    worker.execute(response.json()['job_id']);result=history(admin)['items'][0]
    assert result['state']=='skipped' and result['report']['comparison']['state']=='unavailable'
    assert len(remote['calls'])==1


def test_baseline_changes_during_remote_io_cannot_make_positive_comparison(admin,remote):
    first=observe(admin)
    def changed():
        with Session() as s:
            item=s.get(health.Observation,first['id']);item.report={**item.report,'started':0};s.commit()
    remote['state']['during']=changed
    result=observe(admin,baseline_id=first['id'])
    assert result['state']=='skipped' and not result['report']['scope_current']


def test_baseline_is_rechecked_after_independent_helper_verification(admin,remote,monkeypatch):
    first=observe(admin)
    def changed(*a,**k):
        with Session() as s:
            item=s.get(health.Observation,first['id']);item.report={**item.report,'started':0};s.commit()
        return {'state':'current'}
    monkeypatch.setattr(agent_maintenance,'inspect',changed)
    result=observe(admin,baseline_id=first['id'])
    assert result['state']=='skipped' and len(remote['calls'])==1


@pytest.mark.parametrize('units',[[],['*.service'],['../example.service'],['a.service','a.service'],['a.timer']])
def test_unit_selection_is_explicit_and_bounded(admin,remote,units):
    assert queue(admin,units=units).status_code in (400,422)
    assert not remote['calls'] and not history(admin)['items']


def test_history_host_role_reason_plan_csrf_and_pagination(admin,remote):
    first=observe(admin);file=row(admin);url=BASE+'/quarantines/'+file['id']+'/service-health'
    assert queue(admin,reason=' '*20).status_code==400
    assert queue(admin,plan_digest='f'*64).status_code==409
    assert admin.post(url,json={'plan_digest':file['plan_digest'],'units':['example.service'],'reason':'A meaningful service check reason.'},headers={'X-CSRF-Token':'bad'}).status_code==403
    assert admin.get(url.replace('response-host','other-host')).status_code==404
    assert admin.get(url+'?offset=-1').status_code==400
    with Session() as s:
        for i in range(21):s.add(health.Observation(id='history-%02d'%i,host_id='response-host',quarantine_id=file['id'],created=1+i,actor='admin',reason='Historical selected service review.',state='healthy',report=first['report']))
        s.add(health.Observation(id='foreign',host_id='foreign-host',quarantine_id=file['id'],actor='private',reason='PRIVATE_FOREIGN',state='healthy',report={}));s.commit()
    assert history(admin)['more'] and len(history(admin)['items'])==20
    assert len(history(admin,offset=20)['items'])==2 and 'PRIVATE_FOREIGN' not in json.dumps(history(admin))
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get(url).status_code==403 and queue(admin,file).status_code==403


def test_new_health_records_are_exported_and_survive_verified_offline_migration(admin,remote,tmp_path):
    from app import database_migrate
    first=observe(admin);file=row(admin)
    result=admin.post(BASE+'/quarantines/'+file['id']+'/export',json={'plan_digest':file['plan_digest'],'reason':'Independently retain service observations.'})
    assert result.status_code==200,result.text
    assert result.json()['record']['version']==2 and result.json()['record']['sections']['service_observations'][0]['id']==first['id']
    destination='sqlite:///'+str(tmp_path/'services.db')
    copied=database_migrate.migrate(engine.url.render_as_string(hide_password=False),destination)
    assert copied['security_response_service_observations']['rows']==1
    db=create_engine(destination)
    try:
        with DatabaseSession(db) as s:assert s.get(health.Observation,first['id']).report==first['report']
    finally:db.dispose()
