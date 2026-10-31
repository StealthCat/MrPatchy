import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import select

from app import ai, ai_admission, ai_runs
from app.db import Session, Setting


def configure(mode='rate', rate=20):
    with Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': True, 'ai_model': 'fixture-model',
            'ai_control_mode': mode, 'ai_rate_per_hour': rate,
        }))
        session.commit()


def test_shared_rate_is_smooth_durable_and_blocks_before_a_call(admin,monkeypatch):
    configure(rate=20)
    clock=[1000.0]
    monkeypatch.setattr(ai_admission.time, 'time', lambda: clock[0])
    first=ai_admission.admit('fixture-model')
    assert first['mode']=='rate' and first['next_at']==pytest.approx(1180)
    with pytest.raises(ai.AIError) as blocked:
        ai_admission.admit('fixture-model')
    assert blocked.value.policy_wait and blocked.value.retry_after==pytest.approx(180)
    with Session() as session:
        row=session.get(ai_admission.Admission, 'global')
        assert row and row.next_at==pytest.approx(1180) and row.admitted==1
        assert not list(session.scalars(select(ai_runs.AICall)))
    clock[0]=1180
    assert ai_admission.admit('fixture-model')['next_at']==pytest.approx(1360)


def test_provider_boundary_blocks_every_request_before_transport(admin,monkeypatch):
    configure(rate=20);clock=[3000.0]
    monkeypatch.setattr(ai_admission.time,'time',lambda:clock[0])
    ai_admission.admit('fixture-model');sent=[]
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:sent.append(k) or pytest.fail('provider must not be called'))
    with pytest.raises(ai.AIError) as blocked:ai.request({'model':'fixture-model','input':'{}'},'fixture-key')
    assert blocked.value.retry_after==pytest.approx(180) and sent==[]


def test_one_logical_work_scope_preserves_multi_stage_capability(admin,monkeypatch):
    configure(rate=20);clock=[3500.0]
    monkeypatch.setattr(ai_admission.time,'time',lambda:clock[0])
    token=ai_admission.begin_scope()
    try:
        first=ai_admission.admit('fixture-model')
        second=ai_admission.admit('fixture-model')
    finally:ai_admission.end_scope(token)
    assert first['mode']=='rate' and second['mode']=='continuation'
    with Session() as session:
        row=session.get(ai_admission.Admission,'global')
        assert row.admitted==1 and row.next_at==pytest.approx(3680)


def test_tracked_run_scopes_two_provider_stages_to_one_start(admin,monkeypatch):
    configure(rate=20);monkeypatch.setattr(ai_admission.time,'time',lambda:3600.0)
    calls=[];monkeypatch.setattr(ai,'_request',lambda payload,key,timeout=60,reservation=None:calls.append(payload) or {'ok':True})
    with ai_runs.track('triage','fixture-model',subject='fixture'):
        ai.request({'model':'fixture-model','input':'first'},'fixture-key')
        ai.request({'model':'fixture-model','input':'follow-up'},'fixture-key')
    assert [call['input'] for call in calls]==['first','follow-up']
    with Session() as session:assert session.get(ai_admission.Admission,'global').admitted==1


def test_invalid_local_configuration_does_not_consume_rate(admin):
    configure(rate=20)
    with pytest.raises(ai.AIError):ai.request({'model':'fixture-model'},'bad key')
    with Session() as session:assert session.get(ai_admission.Admission,'global') is None


def test_shared_rate_race_admits_only_one(admin,monkeypatch):
    configure(rate=60)
    monkeypatch.setattr(ai_admission.time, 'time', lambda: 2000.0)
    barrier=threading.Barrier(8)
    def attempt(_):
        barrier.wait(timeout=10)
        try:return ai_admission.admit('fixture-model')['admitted']
        except ai.AIError:return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(attempt, range(8)))
    assert results.count(True)==1
    with Session() as session:assert session.get(ai_admission.Admission, 'global').admitted==1


def test_unthrottled_and_legacy_do_not_create_shared_reservations(admin):
    for mode in ('unthrottled','legacy'):
        configure(mode)
        assert ai_admission.admit('fixture-model')['mode']==mode
    with Session() as session:assert session.get(ai_admission.Admission, 'global') is None


def test_existing_configuration_requires_explicit_migration(admin):
    with Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': False, 'ai_model': '',
            'ai_hourly_limit': 12, 'ai_update_hourly_limit': 7,
        }))
        session.commit()
    state=admin.get('/api/settings').json()
    assert state['ai_control_mode']=='legacy'
    assert state['ai_control_migration']=={
        'required': True, 'suggested_rate_per_hour': 7,
        'legacy_investigations_per_hour': 12,
        'legacy_scoring_batches_per_hour': 7,
    }
    saved=admin.put('/api/settings/ai', json={
        'ai_model': '', 'ai_enabled': False, 'ai_updates_enabled': True,
        'ai_hourly_limit': 12, 'ai_update_hourly_limit': 7,
        'ai_control_mode': 'rate', 'ai_rate_per_hour': 7,
    })
    assert saved.status_code==200 and saved.json()['ai_control_mode']=='rate'
    assert admin.get('/api/settings').json()['ai_control_migration']['required'] is False


def test_status_explains_shared_next_eligibility(admin,monkeypatch):
    configure(rate=20);clock=[4000.0]
    monkeypatch.setattr(ai_admission.time,'time',lambda:clock[0])
    ai_admission.admit('fixture-model')
    state=admin.get('/api/investigation-status').json()
    assert state['admission']['mode']=='rate'
    assert state['admission']['next_at']==pytest.approx(4180)
    assert state['retry_at']==pytest.approx(4180)
