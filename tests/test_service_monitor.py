import copy
import json
import time
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session as DatabaseSession
from app import service_monitor as monitor,response_health as health,worker,quarantine,incidents,operations,agent_maintenance
from app.db import Session,Host,Job,engine
from app.identity import User
from test_quarantine import scenario,row,BASE
from test_repair_preparation import retained
from test_repair_staging import transfer
from test_repair_publication import staged,publish
from test_response_health import remote,observe,queue as manual_queue


def url(record):return BASE+'/quarantines/'+record['id']+'/service-watch'

def view(admin,record=None):return admin.get(url(record or row(admin))).json()

def configure(admin,observation=None,record=None,**changes):
    record=record or row(admin);watch=view(admin,record)
    observation=observation or observe(admin)
    return admin.put(url(record),json={'expected_revision':watch['revision'],'plan_digest':record['plan_digest'],'enabled':True,'interval_minutes':5,'pause_on_problem':False,
        'baseline_id':observation['id'],'report_digest':observation['report_digest'],'reason':'Enable recurring checks of the explicitly reviewed service selection.',**changes})


def scheduled(advance=301):
    monitor.schedule_tick(time.time()+advance)
    with Session() as s:
        job=s.query(Job).filter(Job.action==health.ACTION,Job.state=='queued').one_or_none()
        return job.id if job else None


def automatic(admin,advance=301):
    identifier=scheduled(advance);assert identifier
    worker.execute(identifier)
    with Session() as s:
        observed=s.get(health.Observation,identifier);assert observed
        return {'id':observed.id,'state':observed.state,'report':copy.deepcopy(observed.report)}


def release(admin,record=None,observation=None,confirmation='ACCEPT HEALTHY SERVICES',**changes):
    record=record or row(admin);watch=view(admin,record)
    return admin.post(url(record)+'/release',json={'expected_revision':watch['revision'],'confirmation':confirmation,
        'observation_id':observation['id'] if observation else '', 'report_digest':observation['report_digest'] if observation else '',
        'reason':'Reviewed selected services and any independent response pauses.',**changes})


def status(admin):return admin.get(BASE+'/service-monitor').json()


def test_opt_in_revision_bound_recurring_checks_and_coverage(admin,remote):
    assert not scheduled() and not status(admin)['watched']
    baseline=observe(admin);response=configure(admin,baseline);assert response.status_code==200,response.text
    watch=response.json();assert watch['enabled'] and watch['units']==['example.service'] and watch['revision']
    assert not scheduled(1)
    result=automatic(admin)
    assert result['state']=='healthy' and result['report']['scheduled'] and result['report']['service_watch_revision']==watch['revision']
    assert result['report']['policy_current'] and not result['report']['service_pause_added']
    assert result['report']['comparison']['state']=='compared'
    assert view(admin)['last_observation_id']==result['id'] and not view(admin)['hold']
    assert status(admin)['watched']==1 and not status(admin)['problem_count'] and not status(admin)['overdue_count']
    assert row(admin)['state']=='prepared' and not row(admin)['hold']
    assert not scheduled(302)
    with Session() as s:
        before=len(remote['calls']);health.execute(s,s.get(Host,'response-host'),s.get(Job,result['id']));s.commit()
        assert len(remote['calls'])==before
    with Session() as s:assert monitor.assessment(s,'response-host',time.time()+10000)['overdue_count']==1


@pytest.mark.parametrize('pause',[False,True])
@pytest.mark.parametrize('failure',['problem','remote','helper','protocol'])
def test_only_explicit_pause_policy_adds_its_own_independent_hold(admin,remote,monkeypatch,pause,failure):
    assert configure(admin,pause_on_problem=pause).status_code==200
    if failure=='problem':remote['state']['properties']={'ActiveState':'failed','Result':'exit-code'}
    if failure=='remote':remote['state']['failure']=True
    if failure=='helper':monkeypatch.setattr(agent_maintenance,'inspect',lambda *a,**k:{'state':'blocked'})
    if failure=='protocol':remote['state']['bad']=lambda result:result.update(private='SECRET')
    result=automatic(admin)
    assert result['state']==('problem' if failure=='problem' else 'unavailable')
    assert view(admin)['hold']==pause and result['report']['service_pause_added']==pause
    assert not row(admin)['hold'] and row(admin)['state']=='prepared'
    with Session() as s:assert operations.host_quarantined(s,'response-host')==pause
    assert status(admin)['problem_count']==1 and status(admin)['overdue_count']==1
    assert 'SECRET' not in json.dumps(result) and 'PRIVATE_DIAGNOSTIC' not in json.dumps(result)


@pytest.mark.parametrize('phase',['queued','helper','remote'])
@pytest.mark.parametrize('change',['disabled','revision','baseline','pin','plan','state'])
def test_policy_and_scope_changes_never_follow_old_work_or_add_pauses(admin,remote,monkeypatch,phase,change):
    configured=configure(admin,pause_on_problem=True);assert configured.status_code==200
    identifier=scheduled();assert identifier;file=row(admin)
    def mutate():
        with Session() as s:
            watch=s.get(monitor.Watch,file['id'])
            if change=='disabled':watch.enabled=False
            if change=='revision':watch.revision='another-policy'
            if change=='baseline':
                baseline=s.get(health.Observation,watch.baseline_id);baseline.report={**baseline.report,'started':0}
            if change=='pin':s.get(Host,'response-host').fingerprint='another-pin'
            if change=='plan':q=s.get(quarantine.Quarantine,file['id']);q.plan={**q.plan,'xattrs':{'user.changed':'a'*64}}
            if change=='state':s.get(quarantine.Quarantine,file['id']).state='console_recovered'
            s.commit()
    before=len(remote['calls'])
    if phase=='queued':mutate()
    if phase=='helper':
        def check(*a,**k):mutate();return {'state':'current'}
        monkeypatch.setattr(agent_maintenance,'inspect',check)
    if phase=='remote':remote['state']['during']=mutate
    remote['state']['properties']={'ActiveState':'failed','Result':'exit-code'}
    worker.execute(identifier)
    with Session() as s:
        result=s.get(health.Observation,identifier);assert result.state=='skipped'
        assert not s.get(monitor.Watch,file['id']).hold
    assert len(remote['calls'])-before==(1 if phase=='remote' else 0)


def test_automatic_reads_defer_while_manual_reads_can_review_an_existing_hold(admin,remote):
    configured=configure(admin,pause_on_problem=True);assert configured.status_code==200
    remote['state']['properties']={'ActiveState':'failed','Result':'exit-code'}
    result=automatic(admin);assert view(admin)['hold']
    assert not scheduled(601)
    remote['state']['properties']={};manual=observe(admin)
    assert manual['state']=='healthy' and view(admin)['hold']
    assert not status(admin)['problem_count'] # A newer manual positive supersedes the old alert, not the pause.
    assert release(admin,observation=manual).status_code==200
    assert not view(admin)['hold']
    with Session() as s:
        assert not operations.host_quarantined(s,'response-host')
        assert s.query(quarantine.Event).filter_by(kind='service_pause_reviewed').one().details['observation_id']==manual['id']
    assert result['report']['service_pause_added']


def test_disabling_and_reconfiguring_never_release_a_pause_and_console_review_is_separate(admin,remote):
    baseline=observe(admin);assert configure(admin,baseline,pause_on_problem=True).status_code==200
    remote['state']['properties']={'ActiveState':'failed','Result':'exit-code'};automatic(admin)
    response=configure(admin,baseline,enabled=False);assert response.status_code==200 and response.json()['hold']
    assert not scheduled(601) and not status(admin)['watched']
    assert release(admin).status_code==400
    assert release(admin,confirmation='CONSOLE REVIEWED').status_code==200
    assert not view(admin)['hold'] and not view(admin)['enabled']


def test_pause_review_retains_file_and_publication_holds(admin,remote):
    assert configure(admin,pause_on_problem=True).status_code==200
    remote['state']['properties']={'ActiveState':'failed','Result':'exit-code'};automatic(admin)
    file=row(admin)
    with Session() as s:
        q=s.get(quarantine.Quarantine,file['id']);q.hold=True;s.commit()
    remote['state']['properties']={};manual=observe(admin)
    response=release(admin,observation=manual);assert response.status_code==200,response.text
    assert response.json()['server_changes_paused'] and row(admin)['hold'] and not view(admin)['hold']


def test_automatic_worker_does_not_inherit_manual_hold_exemptions(admin,remote):
    assert configure(admin).status_code==200
    identifier=scheduled();assert identifier;before=len(remote['calls']);file=row(admin)
    with Session() as s:s.get(quarantine.Quarantine,file['id']).hold=True;s.commit()
    worker.execute(identifier)
    with Session() as s:assert s.get(Job,identifier).state=='queued' and not s.get(health.Observation,identifier)
    assert len(remote['calls'])==before


def test_scope_changes_raise_alerts_without_silently_rebinding_services(admin,remote):
    assert configure(admin).status_code==200;file=row(admin)
    with Session() as s:s.get(quarantine.Quarantine,file['id']).state='console_recovered';s.commit()
    assert not scheduled() and status(admin)['problems'][0]['state']=='scope_changed'
    operations.collect_alerts()
    with Session() as s:
        assert s.query(operations.Alert).filter_by(host_id='response-host',kind='service health',state='open').one()
        assert s.query(operations.Alert).filter_by(host_id='response-host',kind='service coverage',state='open').one()


def test_configuration_requires_fresh_healthy_manual_current_selection(admin,remote):
    baseline=observe(admin);file=row(admin)
    assert configure(admin,baseline,report_digest='f'*64).status_code==400
    with Session() as s:s.get(health.Observation,baseline['id']).created=time.time()-301;s.commit()
    assert configure(admin,baseline).status_code==400
    remote['state']['properties']={'ActiveState':'failed','Result':'exit-code'};bad=observe(admin)
    assert configure(admin,bad).status_code==400
    remote['state']['properties']={};fresh=observe(admin);assert configure(admin,fresh).status_code==200
    result=automatic(admin)
    with Session() as s:record=s.get(health.Observation,result['id']);auto={'id':record.id,'report_digest':incidents.digest(record.report)}
    assert configure(admin,auto).status_code==400
    assert configure(admin,fresh,expected_revision='stale').status_code==400
    assert configure(admin,fresh,reason=' '*20).status_code==400


def test_service_watch_export_offline_copy_and_stale_pause_review_boundaries(admin,remote,tmp_path):
    from app import database_migrate
    assert configure(admin,pause_on_problem=True).status_code==200
    remote['state']['properties']={'ActiveState':'failed','Result':'exit-code'};automatic(admin)
    file=row(admin);watch=view(admin)
    assert release(admin,confirmation='CONSOLE REVIEWED',expected_revision='stale').status_code==400
    exported=admin.post(BASE+'/quarantines/'+file['id']+'/export',json={'plan_digest':file['plan_digest'],'reason':'Retain independent service policy and pause evidence.'})
    assert exported.status_code==200 and exported.json()['record']['version']==3
    assert exported.json()['record']['sections']['service_watch'][0]['hold']
    destination='sqlite:///'+str(tmp_path/'service-watches.db')
    result=database_migrate.migrate(engine.url.render_as_string(hide_password=False),destination)
    assert result['security_service_watches']['rows']==1
    copied=create_engine(destination)
    try:
        with DatabaseSession(copied) as s:
            stored=s.get(monitor.Watch,file['id']);assert stored.hold and stored.revision==watch['revision'] and stored.binding==watch['binding']
    finally:copied.dispose()


def test_roles_hosts_csrf_bounds_and_overdue_policy_are_enforced(admin,remote):
    baseline=observe(admin);file=row(admin);endpoint=url(file)
    assert configure(admin,baseline,interval_minutes=4).status_code==422
    assert admin.get(endpoint.replace('response-host','foreign-host')).status_code==404
    assert admin.put(endpoint,json={},headers={'X-CSRF-Token':'bad'}).status_code==403
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get(endpoint).status_code==403 and admin.get(BASE+'/service-monitor').status_code==403
        assert admin.put(endpoint,json={}).status_code==403 and admin.post(endpoint+'/release',json={}).status_code==403


def test_paused_watch_cannot_be_rebound_to_different_healthy_services(admin,remote):
    assert configure(admin,pause_on_problem=True).status_code==200
    remote['state']['properties']={'ActiveState':'failed','Result':'exit-code'};automatic(admin)
    remote['state']['properties']={};other=observe(admin,units=['other.service'])
    result=configure(admin,other)
    assert result.status_code==400 and view(admin)['units']==['example.service'] and view(admin)['hold']
    assert release(admin,observation=other).status_code==400


@pytest.mark.parametrize('hold',['file','service'])
def test_scheduled_worker_has_no_own_pause_exemption(admin,remote,hold):
    assert configure(admin).status_code==200;identifier=scheduled();file=row(admin)
    with Session() as s:
        if hold=='file':s.get(quarantine.Quarantine,file['id']).hold=True
        else:s.get(monitor.Watch,file['id']).hold=True
        s.commit()
    worker.execute(identifier)
    with Session() as s:assert s.get(Job,identifier).state=='queued' and not s.get(health.Observation,identifier)


def test_pending_jobs_and_existing_file_pauses_defer_scheduler(admin,remote):
    assert configure(admin).status_code==200;file=row(admin)
    with Session() as s:
        s.add(Job(id='ordinary',host_id='response-host',action='refresh',state='queued'));s.commit()
    assert not scheduled()
    with Session() as s:
        s.get(Job,'ordinary').state='cancelled';s.get(quarantine.Quarantine,file['id']).hold=True;s.commit()
    assert not scheduled()


def test_watch_cap_and_existing_enabled_watch_reconfiguration(admin,remote,monkeypatch):
    first=observe(admin);assert configure(admin,first).status_code==200
    monkeypatch.setattr(monitor,'LIMIT',1)
    assert configure(admin,first,interval_minutes=10).status_code==200
    with Session() as s:
        original=s.get(quarantine.Quarantine,row(admin)['id'])
        s.add(quarantine.Quarantine(id='second-response',host_id='response-host',incident_id=original.incident_id,archive_id=original.archive_id,fingerprint=original.fingerprint,evidence_digest=original.evidence_digest,plan=original.plan,state='prepared'))
        report=copy.deepcopy(first['report'])
        report['target']['id']='second-response'
        s.add(health.Observation(id='second-manual',host_id='response-host',quarantine_id='second-response',actor='admin',reason='Review another service watch.',state='healthy',report=report));s.commit()
    record={'id':'second-response','plan_digest':row(admin)['plan_digest']}
    with Session() as s:second=s.get(health.Observation,'second-manual');observation={'id':second.id,'report_digest':incidents.digest(second.report)}
    assert configure(admin,observation,record=record).status_code==400


def test_server_cadence_and_fair_rotation_between_due_watches(admin,remote):
    import uuid
    first=observe(admin);assert configure(admin,first).status_code==200;original_id=row(admin)['id'];second_id=str(uuid.uuid4());baseline_id=str(uuid.uuid4())
    with Session() as s:
        original=s.get(quarantine.Quarantine,original_id)
        s.add(quarantine.Quarantine(id=second_id,host_id=original.host_id,incident_id=original.incident_id,archive_id=original.archive_id,fingerprint=original.fingerprint,evidence_digest=original.evidence_digest,plan=original.plan,state=original.state))
        report=copy.deepcopy(first['report']);report['target']['id']=second_id
        s.add(health.Observation(id=baseline_id,host_id='response-host',quarantine_id=second_id,actor='admin',reason='Review a second response service baseline.',state='healthy',report=report));s.commit()
    second_record={'id':second_id,'plan_digest':row(admin)['plan_digest']}
    assert configure(admin,{'id':baseline_id,'report_digest':incidents.digest(report)},record=second_record).status_code==200
    identifier=scheduled(301);assert identifier
    with Session() as s:assert s.get(Job,identifier).payload['quarantine_id']==original_id
    worker.execute(identifier)
    assert not scheduled(302)
    identifier=scheduled(602);assert identifier
    with Session() as s:assert s.get(Job,identifier).payload['quarantine_id']==second_id
    worker.execute(identifier)
    assert status(admin)['watched']==2 and not status(admin)['problem_count']


def test_manual_recovery_reads_can_run_past_a_deferred_automatic_read(admin,remote):
    assert configure(admin).status_code==200;identifier=scheduled();file=row(admin)
    with Session() as s:s.get(monitor.Watch,file['id']).hold=True;s.commit()
    worker.execute(identifier)
    response=manual_queue(admin);assert response.status_code==200,response.text
    # Ordinary manual work still serializes; only queued automatic reads defer.
    assert manual_queue(admin).status_code==409
    worker.execute(response.json()['job_id'])
    with Session() as s:
        assert s.get(Job,identifier).state=='queued'
        assert s.get(health.Observation,response.json()['job_id']).state=='healthy'
        assert s.get(monitor.Watch,file['id']).hold


def test_old_healthy_proof_cannot_bypass_a_newer_known_negative(admin,remote):
    baseline=observe(admin);assert configure(admin,baseline,pause_on_problem=True).status_code==200
    remote['state']['properties']={'ActiveState':'failed','Result':'exit-code'};automatic(admin)
    assert release(admin,observation=baseline).status_code==400 and view(admin)['hold']
    remote['state']['properties']={};current=observe(admin)
    assert release(admin,observation=current).status_code==200
