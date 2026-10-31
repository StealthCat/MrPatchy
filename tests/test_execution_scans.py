import copy
import time
import uuid
from types import SimpleNamespace
import pytest
from sqlalchemy import select,create_engine
from sqlalchemy.orm import Session as DatabaseSession
from app import execution_scans as scans,worker,quarantine,ssh,incidents,operations,host_lifecycle
from app.db import Session,Host,Job,Setting,Observation,engine
from app.identity import User
from target import agent

BASE='/api/hosts/exec-host/security/execution-scans'

@pytest.fixture
def managed(admin):
    with Session() as s:s.add(Host(id='exec-host',name='Execution fixture',address='192.0.2.19',fingerprint='pin',state='online',last_seen=time.time(),baseline={'fixture':'a'*64}));s.commit()
    return admin


def configure(admin,**changes):
    policy=admin.get(BASE).json()['policy']
    return admin.put(BASE,json={'enabled':True,'paths':['/srv/app'],'debounce_seconds':15,'cooldown_minutes':5,'max_per_hour':4,'expected_revision':policy['revision'],'reason':'Review scoped scans prompted by verified execution metadata.',**changes})


def process(**changes):
    return {'capture':'ebpf','identity_verified':True,'executable':'/srv/app/fixture','sha256':'a'*64,'uid':0,'connections':[],'provenance':[],**changes}


def emit(items=None,observed=None,event_id=None):
    event={'id':event_id or str(uuid.uuid4()),'observed':time.time() if observed is None else observed,'processes':[process()] if items is None else items}
    with Session() as s:worker.ingest_events(s,s.get(Host,'exec-host'),{'events':[event]});s.commit()
    return event


def rows():
    with Session() as s:return list(s.scalars(select(scans.Trigger).order_by(scans.Trigger.created,scans.Trigger.id)))


def queue():
    with Session() as s:
        for row in s.scalars(select(scans.Trigger).where(scans.Trigger.state=='pending')):row.created=time.time()-31
        s.commit()
    scans.schedule_tick()
    with Session() as s:return s.scalar(select(Job).where(Job.action=='execution-scan').order_by(Job.created.desc()))


def scanner(monkeypatch,during=None,**changes):
    calls=[]
    monkeypatch.setattr(quarantine,'healthy',lambda *a:None)
    def call(host,request,**kwargs):
        calls.append(copy.deepcopy(request))
        if during:during()
        return {'version':2,'engine':'ClamAV','roots':request['paths'],'state':'no_detections','available':True,'scanned':1,'findings':[],'gaps':[],'signatures':{'state':'recent'},**changes}
    monkeypatch.setattr(ssh,'call',call)
    return calls


def test_opt_in_future_verified_spool_events_only_no_backfill(managed):
    old=emit();assert not rows()
    assert configure(managed).status_code==200
    emit(event_id=old['id']);assert not rows()
    for item in [process(capture='sample'),process(identity_verified=False),process(executable='/elsewhere/file'),process(sha256='invalid')]:emit([item])
    emit(observed=time.time()-121);emit(observed=time.time()+6)
    assert not rows()
    event=emit();assert len(rows())==1
    assert rows()[0].evidence['observation_id']==worker.hashlib.sha256(('exec-host'+event['id']).encode()).hexdigest()
    emit();emit([process(connections=[{'protocol':'tcp','remote':'192.0.2.99','remote_port':443,'local_port':12345,'local':'192.0.2.19','state':'01'}])])
    assert len(rows())==1
    emit([process(sha256='b'*64)]);assert len(rows())==2


def test_native_collector_uid_survives_spool_ingestion_and_queue(managed,tmp_path,monkeypatch):
    assert configure(managed).status_code==200
    monkeypatch.setattr(agent,'ROOT',tmp_path)
    monkeypatch.setattr(agent.os,'readlink',lambda path:'/srv/app/fixture')
    monkeypatch.setattr(agent,'hash_artifact',lambda *args,**kwargs:'a'*64)
    monkeypatch.setattr(agent,'observe_process_identity',lambda *args,**kwargs:(_ for _ in ()).throw(OSError('exited')))
    produced=agent.ebpf_process('321\t0\t/srv/app/fixture\n')
    assert produced['uid']==0 and type(produced['uid']) is int and produced['identity_verified']
    agent.spool([produced],time.time())
    snapshot=agent.pending_events()
    assert snapshot['events'][0]['processes'][0]['uid']==0
    with Session() as s:
        worker.ingest_events(s,s.get(Host,'exec-host'),snapshot);s.commit()
        trigger=s.query(scans.Trigger).one();trigger.created=time.time()-31;s.commit()
    scans.schedule_tick()
    with Session() as s:
        job=s.query(Job).filter_by(action='execution-scan').one()
        assert job.payload['trigger_ids']==[s.query(scans.Trigger).one().id]


@pytest.mark.parametrize('record',[
    '0\t0\t/srv/app/fixture\n','01\t0\t/srv/app/fixture\n',
    '321\t-1\t/srv/app/fixture\n','321\t00\t/srv/app/fixture\n',
    '321\t4294967296\t/srv/app/fixture\n',
])
def test_native_collector_rejects_noncanonical_process_identity(record):
    with pytest.raises(ValueError,match='bpftrace process identity'):agent.ebpf_process(record)


def test_legacy_decimal_uid_is_normalized_and_invalid_uid_is_accounted(managed):
    assert configure(managed).status_code==200
    emit([process(uid='0')])
    assert rows()[0].evidence['uid']==0 and type(rows()[0].evidence['uid']) is int
    emit([process(uid='not-a-uid',sha256='b'*64)])
    status=managed.get(BASE).json()
    assert status['limited'] and status['coverage']['dropped_observations']==1


@pytest.mark.parametrize('paths',[['relative'],['/'],['/srv/../etc'],['/srv/app/'],['/srv//app'],['/proc'],['/var/lib/mrpatchy-quarantine'],['/srv\napp'],['/srv','/srv/app'],['/srv','/srv']])
def test_policy_refuses_unsafe_or_overlapping_scope(managed,paths):
    assert configure(managed,paths=paths).status_code==400


def test_batched_scoped_scan_retains_hint_and_incident_context(managed,monkeypatch):
    configure(managed);emit();emit([process(executable='/srv/app/second',sha256='b'*64)])
    scans.schedule_tick();assert all(row.state=='pending' for row in rows())
    job=queue();assert job and all(row.state=='queued' and row.job_id==job.id for row in rows())
    calls=scanner(monkeypatch,findings=[{'path':'/srv/app/third','sha256':'c'*64,'evidence':'Fixture.Signature FOUND'}],state='completed_with_findings')
    worker.execute(job.id)
    assert calls==[{'action':'security-scan','paths':['/srv/app']}]
    with Session() as s:
        assert s.get(Job,job.id).state=='complete'
        report=s.get(incidents.Scan,job.id).report
        assert report['automation']['binding']=='scheduling_hint_only' and len(report['automation']['executions'])==2
        assert report['automation']['scope_current'] and len(report['automation']['trigger_ids'])==2
        detection=s.query(incidents.Incident).one()
        assert detection.evidence['path']=='/srv/app/third'
        assert 'scan_context' in detection.evidence and 'origin' in detection.evidence['scan_context']
    assert all(row.state=='completed' for row in rows())
    worker.execute(job.id);assert len(calls)==1


def test_policy_replacement_cancels_old_work_without_replaying_observations(managed,monkeypatch):
    configure(managed);event=emit();job=queue();calls=scanner(monkeypatch)
    old=managed.get(BASE).json()['policy']['revision']
    response=configure(managed,enabled=False);assert response.status_code==200 and response.json()['revision']!=old
    assert all(row.state=='skipped' for row in rows())
    worker.execute(job.id);assert calls==[]
    assert configure(managed,expected_revision=old).status_code==400
    configure(managed);emit(event_id=event['id']);assert len(rows())==1
    emit();assert len(rows())==2


def test_lifecycle_disable_revokes_pending_and_queued_triggers(managed,monkeypatch):
    configure(managed);emit();job=queue();emit([process(sha256='b'*64)])
    state=managed.get('/api/hosts/exec-host/summary').json()['host']
    response=managed.put('/api/hosts/exec-host/lifecycle',json={'enabled':False,'expected_revision':state['lifecycle_revision'],'reason':'Suspend server management and cancel execution scans.'})
    assert response.status_code==200 and response.json()['cancelled_jobs']==1
    assert all(row.state=='skipped' for row in rows())
    calls=scanner(monkeypatch);worker.execute(job.id);scans.schedule_tick();assert not calls
    assert managed.get(BASE).json()['state']=='suspended'


def test_holds_busy_hosts_stale_telemetry_and_queue_lock_defer(managed):
    configure(managed);emit()
    with Session() as s:
        for row in s.scalars(select(scans.Trigger)):row.created-=31
        s.add(Job(id='busy',host_id='exec-host',action='patch',state='queued'));s.commit()
    scans.schedule_tick();assert rows()[0].state=='pending'
    with Session() as s:s.get(Job,'busy').state='recovery_required';s.commit()
    scans.schedule_tick();assert rows()[0].state=='pending'
    with Session() as s:s.get(Job,'busy').state='complete';s.get(Host,'exec-host').last_seen=time.time()-121;s.commit()
    scans.schedule_tick();assert rows()[0].state=='pending'
    with Session() as s:s.get(Host,'exec-host').last_seen=time.time();s.commit()
    with worker.host_lock('exec-host'):scans.schedule_tick()
    assert rows()[0].state=='pending'
    scans.schedule_tick();assert rows()[0].state=='queued'


def test_expired_triggers_are_not_scanned_and_raise_coverage_alert(managed,monkeypatch):
    configure(managed);emit();job=queue();calls=scanner(monkeypatch)
    with Session() as s:
        for row in s.scalars(select(scans.Trigger)):row.expires=time.time()-1
        s.commit()
    worker.execute(job.id);assert not calls and rows()[0].state=='skipped'
    operations.collect_alerts()
    with Session() as s:assert s.query(operations.Alert).filter_by(host_id='exec-host',kind='execution scan coverage',state='open').one()


def test_intake_budget_is_bounded_and_drop_coverage_is_explicit(managed,monkeypatch):
    configure(managed);monkeypatch.setattr(scans,'MAX_PENDING',2)
    emit([process(sha256=str(index)*64) for index in range(5)])
    assert len(rows())==2
    status=managed.get(BASE).json();assert status['limited'] and status['coverage']['dropped_observations']==3
    for row in rows():assert row.expires-row.created==scans.MAX_AGE


def test_scan_rate_limits_survive_policy_revisions_and_failures(managed,monkeypatch):
    configure(managed,max_per_hour=1);emit();job=queue();calls=scanner(monkeypatch)
    worker.execute(job.id);emit([process(sha256='b'*64)])
    assert queue().id==job.id and rows()[1].state=='pending'
    configure(managed,max_per_hour=1);emit([process(sha256='c'*64)])
    scans.schedule_tick(time.time()+60)
    with Session() as s:assert s.query(Job).filter_by(action='execution-scan').count()==1
    assert len(calls)==1


def test_scope_rechecked_after_helper_and_remote_io(managed,monkeypatch):
    configure(managed);emit();job=queue();calls=scanner(monkeypatch)
    def change_during_health(*a):
        with Session() as s:
            setting=s.get(Setting,'execution-scan-policy:exec-host');setting.value={**setting.value,'revision':str(uuid.uuid4())};s.commit()
    monkeypatch.setattr(quarantine,'healthy',change_during_health)
    worker.execute(job.id);assert not calls and rows()[0].state=='skipped'
    with Session() as s:s.get(Job,job.id).created-=301;s.commit()
    configure(managed);emit();job=queue()
    calls=scanner(monkeypatch,during=change_during_health)
    worker.execute(job.id);assert len(calls)==1 and rows()[-1].state=='incomplete'
    with Session() as s:
        report=s.get(incidents.Scan,job.id).report
        assert report['state']=='incomplete' and not report['automation']['scope_current']


def test_wrong_scope_receipt_and_transport_failure_fail_closed(managed,monkeypatch):
    configure(managed);emit();job=queue();scanner(monkeypatch,roots=['/other'])
    worker.execute(job.id)
    assert rows()[0].state=='failed'
    with Session() as s:assert not s.get(incidents.Scan,job.id)
    with Session() as s:s.get(Job,job.id).created-=301;s.commit()
    configure(managed);emit();job=queue();scanner(monkeypatch)
    monkeypatch.setattr(ssh,'call',lambda *a,**k:(_ for _ in ()).throw(TimeoutError('fixture')))
    worker.execute(job.id);assert rows()[-1].state=='failed'


def test_roles_csrf_host_boundaries_and_active_work_guard(managed):
    assert managed.put(BASE,headers={'X-CSRF-Token':'bad'},json={}).status_code==403
    with worker.host_lock('exec-host'):assert configure(managed).status_code==409
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert managed.get(BASE).status_code==403
        assert managed.put(BASE,json={}).status_code==403


def test_offline_migration_keeps_execution_trigger_policy_and_links(managed,tmp_path):
    from app import database_migrate
    configure(managed);emit();job=queue()
    destination='sqlite:///'+str(tmp_path/'execution.db')
    database_migrate.migrate(engine.url.render_as_string(hide_password=False),destination)
    copied=create_engine(destination)
    try:
        with DatabaseSession(copied) as s:
            trigger=s.query(scans.Trigger).one();assert trigger.job_id==job.id and trigger.evidence['identity_verified']
            assert scans.policy(s,'exec-host')['revision']==trigger.revision
    finally:copied.dispose()


def test_unexamined_process_tail_has_explicit_coverage_gap(managed):
    configure(managed)
    emit([process(capture='sample') for _ in range(128)]+[process()])
    assert not rows()
    assert managed.get(BASE).json()['coverage']['dropped_observations']==1


def test_quarantine_hold_defers_scans_without_exemptions(managed):
    configure(managed);emit()
    with Session() as s:
        s.add(quarantine.Quarantine(id='held',host_id='exec-host',incident_id='incident',archive_id='archive',fingerprint='pin',evidence_digest='a'*64,plan={},state='quarantined',hold=True));s.commit()
    assert queue() is None and rows()[0].state=='pending'


def test_job_and_trigger_intent_commit_atomically_under_storage_failure(managed,monkeypatch):
    configure(managed);emit()
    from sqlalchemy.orm import Session as ORMSession
    original=ORMSession.commit
    def commit(session):
        if any(isinstance(row,Job) and row.action=='execution-scan' for row in session.new):raise OSError('Injected storage failure before durable queue commit')
        return original(session)
    monkeypatch.setattr(ORMSession,'commit',commit)
    with pytest.raises(OSError):queue()
    with Session() as s:assert s.query(Job).filter_by(action='execution-scan').count()==0
    assert rows()[0].state=='pending' and not rows()[0].job_id
    monkeypatch.setattr(ORMSession,'commit',original)
    assert queue() and rows()[0].state=='queued'


def test_changed_host_pin_prevents_even_helper_contact(managed,monkeypatch):
    configure(managed);emit();job=queue()
    with Session() as s:s.get(Host,'exec-host').fingerprint='different-pin';s.commit()
    monkeypatch.setattr(quarantine,'healthy',lambda *a:pytest.fail('Stale pin must be rejected before helper contact'))
    worker.execute(job.id);assert rows()[0].state=='skipped'


def test_batch_budget_does_not_consume_unqueued_intents(managed,monkeypatch):
    configure(managed);emit([process(executable='/srv/app/'+str(i),sha256=f'{i:064x}') for i in range(33)])
    job=queue();assert len(job.payload['trigger_ids'])==32
    assert sum(row.state=='pending' for row in rows())==1
    calls=scanner(monkeypatch);worker.execute(job.id)
    assert len(calls)==1 and sum(row.state=='completed' for row in rows())==32
    queue();assert sum(row.state=='pending' for row in rows())==1


@pytest.mark.parametrize('changes',[{'engine':'YARA'},{'roots':['/etc']},{'state':'clean'}, {'available':False}, {'signatures':{'state':'unknown'}}, {'scanned':-1}, {'version':2.0}, {'state':'completed_with_findings'}])
def test_invalid_or_contradictory_scanner_receipts_are_rejected(changes):
    report={'version':2,'engine':'ClamAV','roots':['/srv/app'],'state':'no_detections','available':True,'scanned':1,'findings':[],'gaps':[],'signatures':{'state':'recent'}}
    with pytest.raises(ValueError):scans.validate_receipt({**report,**changes},['/srv/app'])


def test_unusual_real_filename_detection_is_preserved(managed,monkeypatch):
    configure(managed);emit();job=queue();path='/srv/app/suspicious\nname'
    scanner(monkeypatch,findings=[{'path':path,'sha256':'b'*64}],state='completed_with_findings')
    worker.execute(job.id)
    with Session() as s:
        assert s.get(Job,job.id).state=='complete' and s.query(incidents.Incident).one().evidence['path']==path
