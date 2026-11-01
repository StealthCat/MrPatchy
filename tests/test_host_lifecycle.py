import copy
import json
import time
import uuid
from types import SimpleNamespace
import pytest
from sqlalchemy import select,create_engine,text
from sqlalchemy.orm import Session as DatabaseSession
from app import host_lifecycle as lifecycle,worker,ssh,incidents,persistence,response_monitor,service_monitor,scheduling,operations,ai,update_scores,coordination
from app.db import Session,Host,Job,Setting,Package,Behavior,Audit,engine
from app.identity import User
from app.security import token_hash,seal


def create(admin,name='Lifecycle fixture'):
    response=admin.post('/api/hosts',json={'name':name,'address':'192.0.2.17'});assert response.status_code==200,response.text
    return response.json()['id']


def host(admin,identifier):return admin.get('/api/hosts/'+identifier+'/summary').json()['host']


def change(admin,identifier,enabled,**changes):
    record=host(admin,identifier)
    return admin.put('/api/hosts/'+identifier+'/lifecycle',json={'enabled':enabled,'expected_revision':record['lifecycle_revision'],'reason':'Review server management and pending work before changing lifecycle.',**changes})


def remove(admin,identifier,**changes):
    record=host(admin,identifier)
    return admin.request('DELETE','/api/hosts/'+identifier,json={'confirmation':record['name'],'expected_revision':record['lifecycle_revision'],'reason':'Remove management after reviewing operations and retained records.',**changes})


def test_disable_enable_cancelled_work_and_enrollment_are_explicit(admin,monkeypatch):
    identifier=create(admin)
    with Session() as s:
        job_id=worker.enqueue(s,identifier,'agent-check')
        s.add(Setting(key='enroll:'+token_hash('pending-token'),value={'host_id':identifier,'expires':time.time()+300}))
        s.add(scheduling.PatchRun(id='waiting-run',host_id=identifier,schedule_id='old',revision=1,trigger='regular',due=time.time(),expires=time.time()+3600));s.commit()
    initial=host(admin,identifier);response=change(admin,identifier,False)
    assert response.status_code==200,response.text
    assert response.json()['cancelled_jobs']==1 and not host(admin,identifier)['enabled']
    assert host(admin,identifier)['state']=='disabled' and initial['lifecycle_revision']!=host(admin,identifier)['lifecycle_revision']
    assert admin.get('/enroll/pending-token').status_code==404
    assert admin.get('/api/hosts/'+identifier+'/installer').status_code==409
    assert admin.post('/api/hosts/'+identifier+'/actions/refresh',json={}).status_code==409
    with Session() as s:
        assert s.get(Job,job_id).state=='cancelled' and s.get(scheduling.PatchRun,'waiting-run').state=='cancelled'
        with pytest.raises(lifecycle.Inactive):worker.enqueue(s,identifier,'refresh')
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:pytest.fail('Inactive host must not be contacted'))
    worker.poll_host(identifier);worker.execute(job_id)
    assert change(admin,identifier,True).status_code==200
    with Session() as s:assert s.get(Job,job_id).state=='cancelled'
    assert admin.get('/api/hosts/'+identifier+'/installer').status_code==200


def test_delete_removes_management_and_local_credentials_preserves_records(admin):
    identifier=create(admin);key=ssh.key_path(identifier)
    for suffix in ('.next.key','.rotation.json','.rotation.tmp'):(key.parent/(identifier+suffix)).write_text('private fixture')
    auth=ssh.DATA/'apt'/identifier/'etc/apt/auth.conf';auth.parent.mkdir(parents=True);auth.write_text('SECRET_CACHED_AUTH')
    with Session() as s:
        h=s.get(Host,identifier);h.inventory={'architecture':'amd64','historical':'retained'}
        s.add(Package(id=identifier+':fixture',host_id=identifier,name='fixture',installed='1',candidate='2'))
        s.add(Job(id='historical',host_id=identifier,action='patch',state='complete',output='retained operation'))
        s.add(Setting(key='repository-access:'+identifier,value={'encrypted':seal('private repository configuration')}))
        s.add(Setting(key='connection:'+identifier,value={'transport':'direct'}))
        s.add(Setting(key='enroll:'+token_hash('delete-token'),value={'host_id':identifier,'expires':time.time()+300}));s.commit()
    response=remove(admin,identifier);assert response.status_code==200,response.text
    assert response.json()['history_retained'] and not response.json()['remote_agent_removed']
    assert not key.exists() and not auth.exists()
    assert not any((key.parent/(identifier+suffix)).exists() for suffix in ('.next.key','.rotation.json','.rotation.tmp'))
    assert identifier not in [h['id'] for h in admin.get('/api/hosts').json()]
    assert identifier in [h['id'] for h in admin.get('/api/hosts?deleted=true').json()]
    record=host(admin,identifier);assert record['deleted_at']>0 and not record['enabled'] and record['state']=='deleted'
    assert change(admin,identifier,True).status_code==400
    assert admin.get('/api/hosts/'+identifier+'/snapshot').json()['inventory']['historical']=='retained'
    with Session() as s:
        assert s.get(Job,'historical').output=='retained operation'
        assert s.get(Package,identifier+':fixture')
        assert not s.get(Setting,'repository-access:'+identifier) and not s.get(Setting,'connection:'+identifier)
        assert s.query(Audit).filter_by(action='delete server').one()
    assert remove(admin,identifier).status_code==200


@pytest.mark.parametrize('kind',['queue','polling','telemetry','control','ai'])
def test_lifecycle_change_refuses_inflight_activity_without_changing_state(admin,kind):
    identifier=create(admin);before=host(admin,identifier)
    with lifecycle.activity([identifier],kind):
        assert change(admin,identifier,False).status_code==409
        assert remove(admin,identifier).status_code==409
    assert host(admin,identifier)['enabled'] and host(admin,identifier)['lifecycle_revision']==before['lifecycle_revision']
    assert change(admin,identifier,False).status_code==200


def test_activity_refuses_failed_lock_without_entering_or_releasing(admin,monkeypatch):
    identifier=create(admin)
    events=[]
    class RefusedLock:
        def __init__(self,name):events.append(('created',name))
        def acquire(self,blocking=True):events.append(('acquire',blocking));return False
        def release(self):events.append(('release',))
    monkeypatch.setattr(lifecycle,'Lock',RefusedLock)
    with pytest.raises(lifecycle.Busy,match='active'):
        with lifecycle.activity([identifier],'control'):
            events.append(('entered',))
    assert events==[('created','server-control:'+identifier),('acquire',True)]


def test_interactive_ssh_refuses_busy_lifecycle_lock_as_conflict(admin,monkeypatch):
    identifier=create(admin)
    class RefusedLock:
        def __init__(self,name):pass
        def acquire(self,blocking=True):return False
        def release(self):pytest.fail('An unowned lifecycle lock must not be released')
    monkeypatch.setattr(lifecycle,'Lock',RefusedLock)
    monkeypatch.setattr(ssh,'_call',lambda *a,**k:pytest.fail('Busy request must not start SSH'))
    response=admin.get('/api/hosts/'+identifier+'/backups')
    assert response.status_code==409
    assert 'active' in response.json()['detail'].lower()


def test_activity_fails_closed_when_mysql_named_lock_times_out(admin,monkeypatch):
    identifier=create(admin);closed=[];created=[]
    connection=SimpleNamespace(
        execute=lambda *a,**k:SimpleNamespace(scalar=lambda:0),
        close=lambda:closed.append(True),
    )
    engine=SimpleNamespace(url=SimpleNamespace(database='fixture'),dialect=SimpleNamespace(name='mysql'),connect=lambda:connection)
    monkeypatch.setattr(coordination,'lock_engine',engine)
    class CapturedLock(coordination.Lock):
        def __init__(self,name):super().__init__(name);created.append(self)
    monkeypatch.setattr(lifecycle,'Lock',CapturedLock)
    with pytest.raises(lifecycle.Busy,match='active'):
        with lifecycle.activity([identifier],'control'):
            pytest.fail('A timed-out MySQL lock must not protect work')
    assert closed==[True] and created[0].resource is None
    assert created[0].local.acquire(False);created[0].local.release()


def test_interactive_activity_uses_nonblocking_sqlite_lock(admin,monkeypatch):
    identifier=create(admin);created=[];original=coordination.fcntl.flock
    monkeypatch.setattr(coordination,'lock_engine',SimpleNamespace(url=SimpleNamespace(database='fixture'),dialect=SimpleNamespace(name='sqlite')))
    def busy(stream,operation):
        if operation & coordination.fcntl.LOCK_NB:raise BlockingIOError
        return original(stream,operation)
    monkeypatch.setattr(coordination.fcntl,'flock',busy)
    class CapturedLock(coordination.Lock):
        def __init__(self,name):super().__init__(name);created.append(self)
    monkeypatch.setattr(lifecycle,'Lock',CapturedLock)
    with pytest.raises(lifecycle.Busy,match='active'):
        with lifecycle.activity([identifier],'control',blocking=False):
            pytest.fail('A busy SQLite lock must not protect work')
    assert created[0].resource is None
    assert created[0].local.acquire(False);created[0].local.release()


def test_running_jobs_and_response_holds_are_not_discarded(admin):
    from app.quarantine import Quarantine
    identifier=create(admin)
    with Session() as s:s.add(Job(id='running',host_id=identifier,action='patch',state='running'));s.commit()
    assert change(admin,identifier,False).status_code==409 and remove(admin,identifier).status_code==409
    with Session() as s:
        s.get(Job,'running').state='recovery_required'
        s.add(Quarantine(id='held',host_id=identifier,incident_id='retained',archive_id='archive',fingerprint='',evidence_digest='a'*64,plan={},state='quarantined',hold=True));s.commit()
    assert change(admin,identifier,False).status_code==200
    assert remove(admin,identifier).status_code==409
    with Session() as s:assert s.get(Quarantine,'held').hold and s.get(Job,'running').state=='recovery_required'


def test_credential_cleanup_failure_is_durably_disabled_and_retryable(admin,monkeypatch):
    identifier=create(admin);original=lifecycle.remove_credentials
    monkeypatch.setattr(lifecycle,'remove_credentials',lambda *a:(_ for _ in ()).throw(OSError('SECRET_STORAGE_ERROR')))
    response=remove(admin,identifier);assert response.status_code==400 and 'SECRET_STORAGE_ERROR' not in response.text
    assert not host(admin,identifier)['enabled'] and not host(admin,identifier)['deleted_at']
    monkeypatch.setattr(lifecycle,'remove_credentials',original)
    assert remove(admin,identifier).status_code==200


def test_stale_host_objects_and_old_jobs_cannot_cross_disable_enable(admin,monkeypatch):
    identifier=create(admin)
    with Session() as s:
        stale=s.get(Host,identifier);s.expunge(stale)
        job_id=worker.enqueue(s,identifier,'agent-check')
        old_payload=copy.deepcopy(s.get(Job,job_id).payload)
    assert change(admin,identifier,False).status_code==200
    monkeypatch.setattr(ssh,'_call',lambda *a,**k:pytest.fail('A stale host object must not contact a disabled target'))
    with pytest.raises(lifecycle.Inactive):ssh.call(stale,{'action':'snapshot'})
    assert change(admin,identifier,True).status_code==200
    with Session() as s:s.add(Job(id='late-old-job',host_id=identifier,action='agent-check',payload=old_payload));s.commit()
    worker.execute('late-old-job')
    with Session() as s:assert s.get(Job,'late-old-job').state=='cancelled'


def test_disabled_connection_can_be_fixed_locally_without_contact(admin):
    identifier=create(admin);assert change(admin,identifier,False).status_code==200
    current=admin.get('/api/hosts/'+identifier+'/connection').json()
    updated={**current,'address':'192.0.2.99'}
    response=admin.put('/api/hosts/'+identifier+'/connection',json={'connection':updated,'expected':current})
    assert response.status_code==200 and host(admin,identifier)['state']=='disabled'
    assert admin.post('/api/hosts/'+identifier+'/connection/test',json={}).status_code==409


def test_disabled_hosts_do_not_schedule_scans_monitors_or_patch_windows(admin):
    identifier=create(admin)
    with Session() as s:
        h=s.get(Host,identifier);h.state='online';h.last_seen=time.time();h.fingerprint='pin';h.inventory={'status':'','architecture':'amd64'}
        for key,value in [('security-policy:',{'enabled':True,'interval_hours':1,'paths':['/tmp']}),('persistence-monitor:',{'enabled':True,'interval_hours':1,'revision':'policy'}),('response-monitor:',{'enabled':True,'interval_minutes':5})]:s.add(Setting(key=key+identifier,value=value))
        s.commit()
    assert change(admin,identifier,False).status_code==200
    incidents.schedule_tick();persistence.schedule_tick();response_monitor.schedule_tick();service_monitor.schedule_tick();scheduling.tick()
    with Session() as s:
        assert not list(s.scalars(select(Job).where(Job.host_id==identifier,Job.state.in_(['queued','running']))))
        assert not scheduling.hosts_for(s,{'all_hosts':True})
    operations.collect_alerts()
    with Session() as s:
        assert s.query(operations.Alert).filter_by(host_id=identifier,kind='server disabled',state='open').one()
        assert not s.query(operations.Alert).filter_by(host_id=identifier,kind='stale',state='open').count()


def test_ai_skips_inactive_servers_without_starving_active_work(admin,monkeypatch):
    inactive=create(admin,'Inactive');active=create(admin,'Active')
    assert change(admin,inactive,False).status_code==200
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture','ai_hourly_limit':20}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('test-secret')}))
        s.add(Behavior(id='inactive',host_id=inactive,first_seen=1,evidence={'executable':'/inactive'}))
        s.add(Behavior(id='active',host_id=active,first_seen=2,evidence={'executable':'/active'}));s.commit()
    calls=[]
    monkeypatch.setattr(ai,'investigate',lambda evidence,*a:(calls.append(evidence['executable']) or {'risk':'low','explanation':'fixture','recommended_checks':'none','requested_checks':[]}))
    worker.investigate_one()
    assert calls==['/active']
    with Session() as s:assert s.get(Behavior,'inactive').verdict=='pending' and not s.get(Behavior,'inactive').attempted


def test_roles_csrf_confirmation_revision_and_unknown_hosts(admin):
    identifier=create(admin)
    assert change(admin,identifier,False,expected_revision='stale').status_code==400
    assert change(admin,identifier,False,reason=' '*20).status_code==400
    assert remove(admin,identifier,confirmation='another server').status_code==400
    assert admin.put('/api/hosts/'+identifier+'/lifecycle',headers={'X-CSRF-Token':'bad'},json={}).status_code==403
    assert admin.request('DELETE','/api/hosts/unknown',json={'confirmation':'unknown','reason':'Review unknown server removal.'}).status_code==404
    assert remove(admin,identifier).status_code==200
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.put('/api/hosts/'+identifier+'/lifecycle',json={}).status_code==403
        assert admin.request('DELETE','/api/hosts/'+identifier,json={}).status_code==403
        assert admin.get('/api/hosts?deleted=true').status_code==403
        assert admin.get('/api/hosts/'+identifier+'/summary').status_code==403


def test_lifecycle_fields_survive_verified_offline_migration(admin,tmp_path):
    from app import database_migrate
    disabled=create(admin,'Disabled');deleted=create(admin,'Deleted')
    assert change(admin,disabled,False).status_code==200 and remove(admin,deleted).status_code==200
    destination='sqlite:///'+str(tmp_path/'lifecycle.db')
    database_migrate.migrate(engine.url.render_as_string(hide_password=False),destination)
    copied=create_engine(destination)
    try:
        with DatabaseSession(copied) as s:
            assert not s.get(Host,disabled).enabled and not s.get(Host,disabled).deleted_at
            assert s.get(Host,deleted).deleted_at and not s.get(Host,deleted).enabled
    finally:copied.dispose()


def test_existing_host_schema_is_upgraded_idempotently(tmp_path,monkeypatch):
    from app import db
    legacy=create_engine('sqlite:///'+str(tmp_path/'legacy.db'))
    db.Base.metadata.create_all(legacy)
    with DatabaseSession(legacy) as s:s.add(Host(id='legacy',name='Legacy',address='192.0.2.1',fingerprint=''));s.commit()
    with legacy.begin() as connection:
        for column in ('enabled','deleted_at','lifecycle_revision'):connection.execute(text('ALTER TABLE hosts DROP COLUMN '+column))
    monkeypatch.setattr(db,'engine',legacy)
    db.init();db.init()
    with legacy.connect() as connection:
        row=connection.execute(text('SELECT enabled,deleted_at,lifecycle_revision FROM hosts WHERE id=\'legacy\'')).one()
        assert row==(1,0,'')
    legacy.dispose()


def test_disable_closes_unstarted_evidence_and_repair_records(admin):
    from app.evidence_vault import EvidenceCopy,EvidenceArchive,ArchiveObservation
    from app.repair_preparation import Preparation
    identifier=create(admin)
    with Session() as s:
        s.add(EvidenceCopy(id='pending-copy',host_id=identifier,incident_id='incident',evidence_digest='a'*64,state='queued',expires=time.time()+300))
        s.add(EvidenceArchive(id='pending-archive',host_id=identifier,copy_id='preserved-copy',state='queued',snapshot={},fingerprint='pin',actor='admin',reason='Preserve approved evidence.',expires=time.time()+300))
        s.add(Preparation(id='pending-preparation',host_id=identifier,quarantine_id='response',bundle_id='bundle',path='/srv/fixture',actor='admin',fingerprint='pin',response_plan_digest='a'*64))
        for action,payload in [('evidence-preserve',{'copy_id':'pending-copy'}),('evidence-acquire',{'archive_id':'pending-archive'}),('trusted-repair-prepare',{'preparation_id':'pending-preparation'})]:
            s.add(Job(id=action,host_id=identifier,action=action,payload=payload))
        s.commit()
    assert change(admin,identifier,False).json()['cancelled_jobs']==3
    with Session() as s:
        assert s.get(EvidenceCopy,'pending-copy').state=='rejected' and not s.get(EvidenceCopy,'pending-copy').expires
        assert s.get(EvidenceArchive,'pending-archive').state=='rejected'
        assert s.query(ArchiveObservation).filter_by(archive_id='pending-archive',state='rejected').one()
        assert s.get(Preparation,'pending-preparation').state=='cancelled' and s.get(Preparation,'pending-preparation').finished


def test_inactive_investigation_actions_and_update_provider_are_blocked(admin,monkeypatch):
    identifier=create(admin)
    with Session() as s:
        s.add(Behavior(id='inactive-behavior',host_id=identifier,evidence={'executable':'/srv/fixture'}))
        s.add(Package(id=identifier+':fixture',host_id=identifier,name='fixture',installed='1',candidate='2'))
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_updates_enabled':True,'ai_model':'fixture'}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('test-secret')}));s.commit()
    assert change(admin,identifier,False).status_code==200
    assert admin.put('/api/investigations/inactive-behavior',json={'approved':True}).status_code==400
    assert admin.post('/api/investigations/inactive-behavior/retry',json={}).status_code==400
    monkeypatch.setattr(ai,'request',lambda *a,**k:pytest.fail('Disabled/deleted packages must not be sent for AI scoring'))
    update_scores.run_one()
    assert remove(admin,identifier).status_code==200
    update_scores.run_one()
    with Session() as s:assert not s.get(Behavior,'inactive-behavior').approved
