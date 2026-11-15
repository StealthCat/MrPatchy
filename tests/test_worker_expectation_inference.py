"""Issue #755: infer expected workers from retained registrations and remove obsolete ones."""
import time
import pytest
from sqlalchemy import select
from app import worker_registry as registry
from app.db import Session,Setting,Audit as AuditLog
from app.main import APP_VERSION
from app.identity import User

BOOT='a'*32


def report(identity,heartbeat,state='reporting',boot=BOOT,version=APP_VERSION):
    with Session() as s:
        s.merge(Setting(key=registry.record_key(identity),value={'id':identity,'boot_id':boot,'heartbeat':heartbeat,'version':version,'state':state}))
        s.commit()


def test_no_registrations_expects_zero(admin,monkeypatch):
    monkeypatch.delenv('MRPATCHY_EXPECTED_WORKER_IDS',raising=False)
    data=admin.get('/api/operations/workers').json()
    assert data['expected']==[] and data['expected_count']==0
    assert data['expectation_source']=='registrations' and data['expectation_error'] is None


def test_inferred_from_registrations_keeps_stale_and_counts_once(admin,monkeypatch):
    monkeypatch.delenv('MRPATCHY_EXPECTED_WORKER_IDS',raising=False)
    now=time.time()
    report('live',now);report('old',now-600);report('retired',now-900,state='stopped')
    with Session() as s:
        # Unidentifiable or mismatched rows are not expectations.
        s.add(Setting(key=registry.PREFIX+'garbage',value={'id':'live'}));s.add(Setting(key=registry.PREFIX+'broken',value='x'));s.commit()
    data=admin.get('/api/operations/workers').json()
    rows={row['id']:row for row in data['expected']}
    assert sorted(rows)==['live','old','retired'] and data['expected_count']==3
    assert rows['live']['state']=='reporting' and rows['old']['state']=='stale' and rows['retired']['state']=='stopped'
    assert all(row['registered'] for row in rows.values())
    # Heartbeat updates do not duplicate the worker.
    report('live',time.time())
    assert admin.get('/api/operations/workers').json()['expected_count']==3


def test_explicit_configuration_takes_precedence(admin,monkeypatch):
    now=time.time()
    report('registered-only',now-600)
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS','configured')
    data=admin.get('/api/operations/workers').json()
    assert data['expectation_source']=='configuration' and [row['id'] for row in data['expected']]==['configured']
    assert data['expected'][0]['state']=='missing'


def test_remove_stale_registration_updates_inferred_count_and_audits(admin,monkeypatch):
    monkeypatch.delenv('MRPATCHY_EXPECTED_WORKER_IDS',raising=False)
    now=time.time()
    report('keep',now);report('gone',now-600)
    with Session() as s:s.add(Setting(key=registry.control_key('gone'),value={'boot_id':BOOT,'revision':1,'action':'drain','requested':now}));s.commit()
    rows={row['id']:row for row in admin.get('/api/operations/workers').json()['items']}
    assert rows['gone']['removable'] is True and rows['keep']['removable'] is False
    result=admin.post('/api/operations/workers/remove',json={'worker_id':'gone','boot_id':BOOT})
    assert result.status_code==200 and result.json()['state']=='stale'
    data=admin.get('/api/operations/workers').json()
    assert [row['id'] for row in data['expected']]==['keep'] and [row['id'] for row in data['items']]==['keep']
    with Session() as s:
        # Stale is not proof of exit: the boot-bound drain is retained (only a graceful stop clears it).
        assert registry.control_value(s,'gone',BOOT)=={'revision':1,'action':'drain'}
        assert any(row.action=='worker registration removed' and 'gone' in row.detail for row in s.scalars(select(AuditLog)))


def test_remove_configured_registration_shows_missing_without_editing_configuration(admin,monkeypatch):
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS','one')
    report('one',time.time()-900,state='stopped')
    assert admin.get('/api/operations/workers').json()['expected'][0]['state']=='stopped'
    assert admin.post('/api/operations/workers/remove',json={'worker_id':'one','boot_id':BOOT}).status_code==200
    data=admin.get('/api/operations/workers').json()
    assert data['expected'][0]['state']=='missing' and data['expected_count']==1
    import os
    assert os.environ['MRPATCHY_EXPECTED_WORKER_IDS']=='one'


@pytest.mark.parametrize('state,version',[('reporting',APP_VERSION),('draining',APP_VERSION),('drained',APP_VERSION),('reporting','0.0.1')])
def test_live_registration_cannot_be_removed(admin,state,version):
    report('live',time.time(),state=state,version=version)
    response=admin.post('/api/operations/workers/remove',json={'worker_id':'live','boot_id':BOOT})
    assert response.status_code==409
    with Session() as s:assert s.get(Setting,registry.record_key('live')) is not None


@pytest.mark.parametrize('offset,state,version',[(60,'reporting',APP_VERSION),(0,'reporting','9.9'),(0,'paused',APP_VERSION)])
def test_fresh_unknown_registration_is_not_removable(admin,offset,state,version):
    # Review finding on #756: a heartbeating worker whose clock runs ahead, or whose report state/version is
    # unrecognized, reports `unknown` but is live; removing it would drop its pending control record.
    now=time.time()
    report('live',now+offset,state=state,version=version)
    with Session() as s:s.add(Setting(key=registry.control_key('live'),value={'boot_id':BOOT,'revision':1,'action':'drain','requested':now}));s.commit()
    row=[row for row in admin.get('/api/operations/workers').json()['items'] if row['id']=='live'][0]
    assert row['state']=='unknown' and row['removable'] is False
    assert admin.post('/api/operations/workers/remove',json={'worker_id':'live','boot_id':BOOT}).status_code==409
    with Session() as s:
        assert s.get(Setting,registry.record_key('live')) is not None and s.get(Setting,registry.control_key('live')) is not None


def test_unknown_registration_without_heartbeat_is_removable(admin):
    with Session() as s:s.add(Setting(key=registry.record_key('nobeat'),value={'id':'nobeat','boot_id':BOOT}));s.commit()
    row=[row for row in admin.get('/api/operations/workers').json()['items'] if row['id']=='nobeat'][0]
    assert row['state']=='unknown' and row['removable'] is True
    assert admin.post('/api/operations/workers/remove',json={'worker_id':'nobeat','boot_id':BOOT}).status_code==200


def test_remove_requires_matching_boot_and_existing_registration(admin):
    report('old',time.time()-600)
    assert admin.post('/api/operations/workers/remove',json={'worker_id':'old','boot_id':'b'*32}).status_code==409
    assert admin.post('/api/operations/workers/remove',json={'worker_id':'absent','boot_id':BOOT}).status_code==409
    assert admin.post('/api/operations/workers/remove',json={'worker_id':'bad id','boot_id':BOOT}).status_code==422
    with Session() as s:assert s.get(Setting,registry.record_key('old')) is not None


def test_registration_without_boot_is_removable(admin):
    with Session() as s:s.add(Setting(key=registry.record_key('legacy'),value={'id':'legacy','heartbeat':1}));s.commit()
    row=[row for row in admin.get('/api/operations/workers').json()['items'] if row['id']=='legacy'][0]
    assert row['state']=='stale' and row['removable'] is True
    assert admin.post('/api/operations/workers/remove',json={'worker_id':'legacy','boot_id':''}).status_code==200


@pytest.mark.parametrize('role',['viewer','operator'])
def test_removal_requires_administrator(admin,role):
    report('old',time.time()-600)
    with Session() as s:s.get(User,'admin').role=role;s.commit()
    assert admin.post('/api/operations/workers/remove',json={'worker_id':'old','boot_id':BOOT}).status_code==403
    with Session() as s:assert s.get(Setting,registry.record_key('old')) is not None


def test_inferred_expectations_do_not_publish_notifications(admin,monkeypatch):
    from app import notifications
    monkeypatch.delenv('MRPATCHY_EXPECTED_WORKER_IDS',raising=False)
    report('retired',time.time()-900,state='stopped')
    assert registry.publish_notifications(now=time.time(),started=0)==0
    with Session() as s:assert not list(s.scalars(select(notifications.NotificationEvent)))


def test_too_many_registrations_reports_inference_error(admin,monkeypatch):
    monkeypatch.delenv('MRPATCHY_EXPECTED_WORKER_IDS',raising=False)
    monkeypatch.setattr(registry,'INFERRED_LIMIT',2)
    for name in ('a','b','c'):report(name,1)
    data=registry.page(now=1000)
    assert data['expected']==[] and 'More than 2' in data['expectation_error']


def test_removing_stale_drained_registration_keeps_its_drain(admin,monkeypatch):
    # A stale heartbeat does not prove the process is gone: a hung-but-alive boot must stay drained on recovery.
    monkeypatch.delenv('MRPATCHY_EXPECTED_WORKER_IDS',raising=False)
    now=time.time()
    report('hung',now-600,state='drained')
    with Session() as s:s.add(Setting(key=registry.control_key('hung'),value={'boot_id':BOOT,'revision':1,'action':'drain','requested':now}));s.commit()
    assert admin.post('/api/operations/workers/remove',json={'worker_id':'hung','boot_id':BOOT}).status_code==200
    with Session() as s:
        assert s.get(Setting,registry.record_key('hung')) is None
        assert registry.control_value(s,'hung',BOOT)=={'revision':1,'action':'drain'}


def test_remove_refuses_registration_whose_identity_is_still_held(admin,monkeypatch):
    # The worker holds worker-identity:<id> for its lifetime; a held lock proves a live process owns it.
    monkeypatch.delenv('MRPATCHY_EXPECTED_WORKER_IDS',raising=False)
    report('alive',time.time()-600)
    from app.coordination import Lock
    held=Lock('worker-identity:alive')
    assert held.acquire(False)
    try:
        result=admin.post('/api/operations/workers/remove',json={'worker_id':'alive','boot_id':BOOT})
        assert result.status_code==409 and 'running' in result.json()['detail']
        with Session() as s:assert s.get(Setting,registry.record_key('alive')) is not None
    finally:held.release()
    assert admin.post('/api/operations/workers/remove',json={'worker_id':'alive','boot_id':BOOT}).status_code==200


def test_removing_gracefully_stopped_registration_clears_its_control(admin,monkeypatch):
    monkeypatch.delenv('MRPATCHY_EXPECTED_WORKER_IDS',raising=False)
    now=time.time()
    report('done',now-900,state='stopped')
    with Session() as s:s.add(Setting(key=registry.control_key('done'),value={'boot_id':BOOT,'revision':2,'action':'drain','requested':now}));s.commit()
    assert admin.post('/api/operations/workers/remove',json={'worker_id':'done','boot_id':BOOT}).status_code==200
    with Session() as s:assert s.get(Setting,registry.control_key('done')) is None
