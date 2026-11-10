import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

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
    calls=[];monkeypatch.setattr(ai,'_request',lambda payload,*args:calls.append(payload) or {'ok':True})
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


@pytest.mark.parametrize('mode', ['legacy', 'daily_cap', 'unthrottled'])
def test_modes_without_shared_pacing_skip_the_rate_lock(admin, monkeypatch, mode):
    configure(mode)
    lock = ai_admission.Lock
    lock_names = []

    def record_lock(name):
        lock_names.append(name)
        return lock(name)

    monkeypatch.setattr(ai_admission, 'Lock', record_lock)
    token = ai_admission.begin_scope()
    try:
        assert ai_admission.admit('fixture-model') == {
            'mode': mode, 'admitted': True, 'next_at': None,
        }
        assert ai_admission.admit('fixture-model')['mode'] == 'continuation'
    finally:
        ai_admission.end_scope(token)
    assert lock_names == []
    with Session() as session:
        assert session.get(ai_admission.Admission, 'global') is None


@pytest.mark.parametrize('mode,expected_mode,next_at', [
    ('daily_cap', 'daily_cap', None),
    ('rate_and_daily', 'rate', 5060.0),
])
def test_shared_rate_rereads_settings_after_lock(admin, monkeypatch, mode, expected_mode, next_at):
    configure('rate', rate=20)
    lock = ai_admission.Lock

    @contextmanager
    def change_settings_while_entering(name):
        assert name == 'ai-shared-admission'
        configure(mode, rate=60)
        with lock(name):
            yield

    monkeypatch.setattr(ai_admission, 'Lock', change_settings_while_entering)
    monkeypatch.setattr(ai_admission.time, 'time', lambda: 5000.0)
    assert ai_admission.admit('fixture-model') == {
        'mode': expected_mode, 'admitted': True, 'next_at': next_at,
    }
    with Session() as session:
        row = session.get(ai_admission.Admission, 'global')
        if next_at is None:
            assert row is None
        else:
            assert row.admitted == 1 and row.next_at == next_at


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
