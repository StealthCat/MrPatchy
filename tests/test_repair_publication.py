import copy
import json
import time
import pytest
from app import repair_publication as publication,repair_staging,quarantine,worker,incidents,agent_maintenance,process_response,operations,response_monitor
from app.db import Session,Host,Job
from app.identity import User
from test_repair_staging import transfer,retained,scenario,approve as approve_stage,stages
from test_quarantine import BASE,row as file_row
from test_response_monitor import configure,queue as queue_monitor,checks


@pytest.fixture
def staged(admin,transfer,monkeypatch):
    worker.execute(approve_stage(admin,transfer).json()['job_id']);record=stages(admin)[0]
    calls=[];state={'published':False,'attempted':False,'uncertain':False,'failure':None,'bad':None,'during':lambda action:None}
    original=worker.ssh.call
    def remote(host,request,**kwargs):
        action=request['action']
        if action not in ('repair-publish','repair-publish-status'):return original(host,request,**kwargs)
        calls.append(copy.deepcopy(request))
        if state['failure']==action:raise TimeoutError('PRIVATE_CONTENT must not be retained')
        if action=='repair-publish':state['attempted']=True;state['published']=not state['uncertain']
        state['during'](action)
        if state['failure']==action+'-after':raise TimeoutError('PRIVATE_CONTENT must not be retained')
        plan=request['plan'];positive=state['published'] and not state['uncertain']
        facts={key:positive for key in publication.FACTS};facts['private_present']=not state['published'];facts['intent_verified']=state['attempted']
        value={'version':1,'id':request['id'],'stage_id':plan['stage_id'],'quarantine_id':plan['stage_plan']['quarantine_id'],
            'plan_digest':incidents.digest(plan),'response_plan_digest':incidents.digest(plan['stage_plan']['quarantine_plan']),
            'state':'published' if positive else ('uncertain' if state['attempted'] else 'not_started'),
            'payload':{**plan['payload'],'identity':{**plan['payload']['identity'],'mode':0o100000|plan['stage_plan']['replacement_mode']}} if positive else None,
            'facts':facts,'gaps':[] if positive or not state['attempted'] else ['destination_changed'],'readiness':None}
        if state['bad']:state['bad'](value)
        return value
    monkeypatch.setattr(worker.ssh,'call',remote)
    return {'record':record,'transfer':transfer,'calls':calls,'state':state}


def approve(admin,f,**changes):
    return admin.post(BASE+'/repair-stages/'+f['record']['id']+'/publish',json={'report_digest':f['record']['report_digest'],'confirmation':'PUBLISH','reason':'Reviewed live replacement, permission policy and service impact.',**changes})
def rows(admin):return admin.get(BASE+'/repair-publications').json()['items']
def verify(admin,identifier):
    result=admin.post(BASE+'/repair-publications/'+identifier+'/status',json={});assert result.status_code==200,result.text
    worker.execute(result.json()['job_id']);return rows(admin)[0]
def release(admin,row,confirmation='KEEP REPLACEMENT',**changes):
    return admin.post(BASE+'/repair-publications/'+row['id']+'/release',json={'plan_digest':row['plan_digest'],'receipt_digest':row['receipt_digest'],'reason':'Reviewed service health, original evidence and recovery impact.','confirmation':confirmation,**changes})
def publish(admin,f):
    result=approve(admin,f);assert result.status_code==200,result.text
    worker.execute(result.json()['job_id']);row=rows(admin)[0];assert row['state']=='published',row
    return row


def test_separate_approval_holds_live_changes_and_preserves_original_and_history(admin,staged):
    f=staged;assert not rows(admin) and not f['calls']
    for change in ({'confirmation':'STAGE'},{'reason':' '*20},{'report_digest':'f'*64}):assert approve(admin,f,**change).status_code==400
    approved=approve(admin,f);assert approved.status_code==200,approved.text
    assert not f['calls'] and rows(admin)[0]['hold']
    assert approve(admin,f).status_code==409
    with Session() as s:
        normal=worker.enqueue(s,'response-host','refresh');assert operations.host_quarantined(s,'response-host')
    worker.execute(normal)
    with Session() as s:assert s.get(Job,normal).state=='queued'
    worker.execute(approved.json()['job_id']);result=rows(admin)[0]
    assert result['state']=='published' and result['hold'] and result['report']['trust_current'] and result['receipt']['facts']['held_verified']
    assert file_row(admin)['state']=='replaced' and file_row(admin)['hold'] and stages(admin)[0]['state']=='published'
    assert stages(admin)[0]['publication_id']==result['id'] and file_row(admin)['publication_id']==result['id']
    with Session() as s:
        job=s.get(Job,approved.json()['job_id']);assert job.state=='complete'
        before=len(f['calls']);assert publication.execute(s,s.get(Host,'response-host'),job)['replayed'] is False
        assert len(f['calls'])==before and s.query(incidents.Incident).one().state=='open'
    history=admin.get(BASE+'/repair-publications/'+result['id']+'/history').json()['items']
    assert {e['kind'] for e in history}=={'approved','started','observed_published'}
    assert all(e['actor']=='admin' for e in history) and 'PRIVATE_CONTENT' not in json.dumps((result,history))
    assert admin.post(BASE+'/quarantines/'+file_row(admin)['id']+'/restore',json={'plan_digest':file_row(admin)['plan_digest'],'receipt_digest':file_row(admin)['receipt_digest'],'reason':'Do not overwrite the approved replacement.','confirmation':'RESTORE'}).status_code==409
    assert admin.post(BASE+'/quarantines/'+file_row(admin)['id']+'/release',json={'plan_digest':file_row(admin)['plan_digest'],'receipt_digest':file_row(admin)['receipt_digest'],'reason':'File pause cannot bypass publication review.','confirmation':'CONSOLE RECOVERED'}).status_code==409
    operations.collect_alerts()
    with Session() as s:assert s.query(operations.Alert).filter_by(kind='publication hold',state='open').one()
    reviewed=release(admin,result);assert reviewed.status_code==200,reviewed.text
    assert not reviewed.json()['publication_hold'] and not reviewed.json()['file_hold'] and not reviewed.json()['server_changes_paused']
    assert file_row(admin)['state']=='replaced' and not rows(admin)[0]['hold']


def test_old_stage_and_file_verification_redirect_to_publication_protocol(admin,staged):
    row=publish(admin,staged)
    for url in ('/repair-stages/'+staged['record']['id']+'/status','/quarantines/'+row['quarantine_id']+'/status'):
        result=admin.post(BASE+url,json={});assert result.status_code==200,result.text
        with Session() as s:assert s.get(Job,result.json()['job_id']).action=='trusted-repair-publish-status'
        worker.execute(result.json()['job_id'])
        assert rows(admin)[0]['state']=='published' and file_row(admin)['state']=='replaced'
    assert [request['action'] for request in staged['calls']]==['repair-publish','repair-publish-status','repair-publish-status']


def test_related_process_pause_stays_suspended_after_publication_and_file_pause_review(admin,staged):
    qid=staged['record']['quarantine_id']
    with Session() as s:
        s.add(process_response.ProcessResponse(id='related',host_id='response-host',quarantine_id=qid,observation_id='old',state='suspended',hold=True,fingerprint='pin',plan={}));s.commit()
    row=publish(admin,staged);row=verify(admin,row['id']);reviewed=release(admin,row)
    assert reviewed.status_code==200 and reviewed.json()['server_changes_paused'] and not reviewed.json()['file_hold']
    with Session() as s:assert s.get(process_response.ProcessResponse,'related').state=='suspended' and s.get(process_response.ProcessResponse,'related').hold
    assert all(r['action'] in ('repair-publish','repair-publish-status') for r in staged['calls'])


@pytest.mark.parametrize('failure',['authentication','helper','expired','staging'])
def test_unstarted_failure_releases_only_its_new_hold_and_allows_a_new_explicit_approval(admin,staged,monkeypatch,failure):
    f=staged;approved=approve(admin,f);before=file_row(admin)
    if failure=='authentication':f['transfer']['retained']['state']['failure']='authentication'
    if failure=='helper':monkeypatch.setattr(agent_maintenance,'inspect',lambda *a,**k:{'state':'blocked'})
    if failure in ('expired','staging'):
        with Session() as s:
            if failure=='expired':s.get(publication.Publication,approved.json()['publication_id']).expires=time.time()-1
            else:
                stage=s.get(repair_staging.Stage,f['record']['id']);stage.report={**stage.report,'unexpected':True}
            s.commit()
    worker.execute(approved.json()['job_id']);result=rows(admin)[0]
    assert result['state']=='rejected' and not result['hold'] and not f['calls']
    assert file_row(admin)['state']==before['state'] and file_row(admin)['hold']==before['hold']
    assert 'PRIVATE_CONTENT' not in json.dumps(result)
    if failure=='expired':assert approve(admin,f).status_code==200


@pytest.mark.parametrize('change',['pin','plan','restored'])
def test_scope_changes_during_mutation_do_not_overwrite_new_evidence_or_state(admin,staged,change):
    f=staged
    def changed(action):
        with Session() as s:
            q=s.get(quarantine.Quarantine,f['record']['quarantine_id'])
            if change=='pin':s.get(Host,'response-host').fingerprint='changed-pin'
            if change=='plan':q.plan={**q.plan,'xattrs':{'user.changed':'f'*64}}
            if change=='restored':q.state='restored'
            s.commit()
    f['state']['during']=changed;approved=approve(admin,f);worker.execute(approved.json()['job_id'])
    result=rows(admin)[0];assert result['state']=='uncertain' and result['hold'] and not result['report']['scope_current'] and result['receipt']=={}
    if change=='plan':assert file_row(admin)['plan']['xattrs']=={'user.changed':'f'*64}
    if change=='restored':assert file_row(admin)['state']=='restored'


def test_lost_reply_is_observed_without_replaying_the_publication(admin,staged):
    f=staged;f['state']['failure']='repair-publish-after';approved=approve(admin,f);worker.execute(approved.json()['job_id'])
    row=rows(admin)[0];assert row['state']=='uncertain' and row['hold'] and file_row(admin)['state']=='replacement_uncertain'
    f['state']['failure']=None;result=verify(admin,row['id'])
    assert result['state']=='published' and result['hold'] and file_row(admin)['hold']
    assert [r['action'] for r in f['calls']]==['repair-publish','repair-publish-status']
    assert release(admin,result,receipt_digest='f'*64).status_code==409
    assert release(admin,result).status_code==200


def test_changed_trust_after_mutation_retains_uncertainty_and_requires_console_review(admin,staged):
    f=staged;f['state']['during']=lambda action:f['transfer']['retained']['state'].update(changed_trust=True)
    approved=approve(admin,f);worker.execute(approved.json()['job_id']);row=rows(admin)[0]
    assert row['state']=='uncertain' and row['hold'] and row['receipt']=={}
    row=verify(admin,row['id']);assert row['state']=='published' and not row['report']['trust_current']
    assert release(admin,row).status_code==409
    reviewed=release(admin,row,'CONSOLE RECOVERED');assert reviewed.status_code==200
    assert reviewed.json()['file_hold'] and not reviewed.json()['publication_hold'] and file_row(admin)['state']=='console_recovered'
    assert admin.post(BASE+'/repair-publications/'+row['id']+'/status',json={}).status_code==409


def test_expiry_during_health_never_requests_a_mutation(admin,staged,monkeypatch):
    f=staged;approved=approve(admin,f)
    def expired(*args,**kwargs):
        with Session() as s:s.get(publication.Publication,approved.json()['publication_id']).expires=time.time()-1;s.commit()
        return {'state':'current'}
    monkeypatch.setattr(agent_maintenance,'inspect',expired);worker.execute(approved.json()['job_id'])
    assert rows(admin)[0]['state']=='rejected' and not staged['calls']


def test_unrelated_hold_during_health_prevents_publication(admin,staged,monkeypatch):
    f=staged;approved=approve(admin,f)
    def paused(*args,**kwargs):
        with Session() as s:s.add(process_response.ProcessResponse(id='other',host_id='response-host',quarantine_id='other',observation_id='old',state='uncertain',hold=True,fingerprint='pin',plan={}));s.commit()
        return {'state':'current'}
    monkeypatch.setattr(agent_maintenance,'inspect',paused);worker.execute(approved.json()['job_id'])
    assert not f['calls'] and rows(admin)[0]['state']=='rejected' and not rows(admin)[0]['hold']
    with Session() as s:assert s.get(process_response.ProcessResponse,'other').hold and operations.host_quarantined(s,'response-host')


@pytest.mark.parametrize('change',['id','plan','version','content','held','private','inode','mode','size'])
def test_unbound_or_contradictory_receipts_never_become_current_positive_proof(admin,staged,change):
    f=staged
    def bad(value):
        if change=='id':value['id']='wrong'
        if change=='plan':value['plan_digest']='f'*64
        if change=='version':value['version']=True
        if change=='content':value['content']='PRIVATE_CONTENT'
        if change=='held':value['facts']['held_verified']=False
        if change=='private':value['facts']['private_present']=True
        if change=='inode':value['payload']['identity']['ino']+=1
        if change=='mode':value['payload']['identity']['mode']=0o100755
        if change=='size':value['payload']['size']=True
    f['state']['bad']=bad;approved=approve(admin,f);worker.execute(approved.json()['job_id'])
    row=rows(admin)[0];assert row['state']=='uncertain' and row['hold'] and row['receipt']=={}
    assert 'PRIVATE_CONTENT' not in json.dumps(row)


@pytest.mark.parametrize('pause',[False,True])
def test_monitoring_verifies_both_original_and_approved_replacement_and_respects_pause_policy(admin,staged,pause):
    row=publish(admin,staged);assert release(admin,row).status_code==200
    assert configure(admin,pause_on_problem=pause).status_code==200
    identifier=queue_monitor(admin)
    with Session() as s:
        job=s.get(Job,identifier);assert job.payload['publication_id']==row['id'] and job.payload['publication_plan_digest']==row['plan_digest']
    worker.execute(identifier);record=file_row(admin)
    assert record['state']=='replaced' and checks(admin,record)[0]['state']=='replacement_verified'
    assert admin.get(BASE+'/response-monitor').json()['problem_count']==0
    staged['state']['uncertain']=True;identifier=queue_monitor(admin,1201);worker.execute(identifier)
    record=file_row(admin);result=rows(admin)[0]
    assert record['state']=='replacement_uncertain' and record['hold']==pause and result['hold']==pause
    assert admin.get(BASE+'/response-monitor').json()['problem_count']==1
    old=checks(admin,record)
    staged['state']['uncertain']=False;result=verify(admin,result['id'])
    assert result['state']=='published' and result['hold']==pause and file_row(admin)['hold']==pause
    assert admin.get(BASE+'/response-monitor').json()['problem_count']==0 and checks(admin,file_row(admin))==old


def test_monitoring_rechecks_policy_after_io_and_does_not_reintroduce_a_disabled_pause(admin,staged):
    row=publish(admin,staged);release(admin,row);configure(admin,pause_on_problem=True)
    identifier=queue_monitor(admin);staged['state']['uncertain']=True
    def disabled(action):
        from app.db import Setting
        with Session() as s:
            cfg=s.get(Setting,'response-monitor:response-host');cfg.value={**cfg.value,'enabled':False,'pause_on_problem':False,'revision':'changed-during-read'};s.commit()
    staged['state']['during']=disabled
    worker.execute(identifier)
    assert rows(admin)[0]['state']=='uncertain' and not rows(admin)[0]['hold'] and not file_row(admin)['hold']
    assert not checks(admin,file_row(admin))[0]['report']['pause_on_problem']


@pytest.mark.parametrize('change',['digest','legacy'])
def test_stale_publication_queue_binding_skips_without_using_original_quarantine_audit(admin,staged,change):
    row=publish(admin,staged);release(admin,row);configure(admin)
    identifier=queue_monitor(admin);before=len(staged['calls'])
    with Session() as s:
        job=s.get(Job,identifier)
        job.payload={**job.payload,'publication_plan_digest':'f'*64} if change=='digest' else {k:v for k,v in job.payload.items() if k not in ('publication_id','publication_plan_digest')}
        s.commit()
    worker.execute(identifier)
    assert len(staged['calls'])==before and checks(admin,file_row(admin))[0]['state']=='skipped'


def test_cancelling_queued_publication_releases_only_its_new_hold_and_never_calls_target(admin,staged):
    approved=approve(admin,staged);assert approved.status_code==200
    result=admin.post('/api/operations/jobs/'+approved.json()['job_id']+'/cancel',json={})
    assert result.status_code==200,result.text
    assert rows(admin)[0]['state']=='rejected' and not rows(admin)[0]['hold'] and file_row(admin)['hold']
    worker.execute(approved.json()['job_id']);assert not staged['calls']
    history=admin.get(BASE+'/repair-publications/'+approved.json()['publication_id']+'/history').json()['items']
    assert {item['kind'] for item in history}=={'approved','cancelled'}
    assert approve(admin,staged).status_code==200


def test_publication_metadata_and_append_only_events_survive_offline_copy(admin,staged,tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session as DatabaseSession
    from app import database_migrate
    from app.db import engine
    row=publish(admin,staged);destination='sqlite:///'+str(tmp_path/'publication-copy.db')
    result=database_migrate.migrate(engine.url.render_as_string(hide_password=False),destination)
    assert result['security_repair_publications']['rows']==1 and result['security_repair_publication_events']['rows']==3
    copied=create_engine(destination)
    try:
        with DatabaseSession(copied) as s:
            record=s.get(publication.Publication,row['id']);assert record.hold and record.receipt==row['receipt']
            assert s.query(publication.Event).filter_by(publication_id=row['id']).count()==3
    finally:copied.dispose()


def test_role_host_pagination_and_historical_approval_boundaries(admin,staged):
    row=publish(admin,staged);url=BASE+'/repair-publications/'+row['id']
    assert admin.get(url.replace('response-host','other')+'/history').status_code==404
    assert admin.post(url.replace('response-host','other')+'/status',json={}).status_code==404
    assert admin.get(BASE+'/repair-publications?offset=-1').status_code==400
    assert admin.get(url+'/history?offset=-1').status_code==400
    history=admin.get(url+'/history').json()['items']
    with Session() as s:
        for _ in range(21):publication.event(s,s.get(publication.Publication,row['id']),'fixture','admin')
        s.commit()
    page=admin.get(url+'/history').json();assert len(page['items'])==20 and page['more']
    assert len(admin.get(url+'/history?offset=20').json()['items'])==4
    assert all(item in admin.get(url+'/history?offset=20').json()['items']+page['items'] for item in history)
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get(BASE+'/repair-publications').status_code==403
        assert admin.post(url+'/status',json={}).status_code==403
