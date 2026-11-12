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
        assert s.get(Setting,registry.control_key('gone')) is None
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
