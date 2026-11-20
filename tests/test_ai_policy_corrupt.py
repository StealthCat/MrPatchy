"""A non-object stored server AI policy fails closed without crashing (#1233)."""
import pytest
from sqlalchemy import select
from test_auto_plan_status import seed

from app import ai_policy, incidents, worker
from app.db import Audit, Host, Job, Session, Setting

BASE = '/api/hosts/web/security/ai-policy'
CORRUPT = [['corrupt'], 'paused', 0, None]


def corrupt(value, host='web'):
    with Session() as s:
        s.merge(Setting(key=ai_policy.PREFIX + host, value=value))
        s.commit()


@pytest.mark.parametrize('value', CORRUPT)
def test_status_reports_a_non_object_policy_as_paused(admin, value):
    seed()
    corrupt(value)
    with Session() as s:
        result = ai_policy.status(s, 'web')
    # Same reading as the provider gate and the display helper.
    assert result['paused'] is True and result['state'] == 'paused'
    assert result['revision'] == ''
    assert result['concurrency_limit'] == ai_policy.MIN_CONCURRENCY
    with Session() as s:
        assert ai_policy.stored_paused(s.get(Setting, ai_policy.PREFIX + 'web').value) is True


@pytest.mark.parametrize('value', [['corrupt'], 'x', 3])
def test_investigation_limit_value_narrows_a_non_object_policy(value):
    assert ai_policy.investigation_limit_value(value) == ai_policy.MIN_CONCURRENCY


def test_one_corrupt_policy_does_not_stop_automatic_plans_for_other_servers(admin, monkeypatch):
    now = seed()
    with Session() as s:
        s.add(Host(id='db', name='db', address='192.0.2.2', fingerprint=''))
        s.add(Setting(key='security-policy:db', value={'auto_ai_plan': True, 'enabled': True}))
        s.add(incidents.Incident(id='db-owed', host_id='db', scan_id='s9', evidence={}, updated=now - 30))
        s.commit()
    corrupt(['corrupt'], 'db')
    queued = []
    monkeypatch.setattr('app.worker.enqueue', lambda s, host, action, payload: queued.append((host, payload['incident_id'])))
    incidents.auto_plan_tick(now)
    # The corrupt server is treated as paused; the healthy server is still planned.
    assert queued == [('web', 'owed-old')]


def test_queued_plan_waits_on_a_corrupt_policy(admin):
    seed()
    corrupt(['corrupt'])
    with Session() as s:
        job = s.get(Job, 'auto-old')
        assert worker.ai_plan_waiting(s, job) is True


def test_administrator_can_read_and_repair_a_corrupt_policy(admin):
    seed()
    corrupt(['corrupt'])
    current = admin.get(BASE)
    assert current.status_code == 200, current.text
    assert current.json()['paused'] is True and current.json()['revision'] == ''
    saved = admin.put(BASE, json={'paused': False, 'expected_revision': '',
                                  'reason': 'Repair the corrupt stored AI policy'})
    assert saved.status_code == 200, saved.text
    body = saved.json()
    assert body['paused'] is False and body['revision']
    assert body['concurrency_limit'] == ai_policy.MIN_CONCURRENCY
    with Session() as s:
        value = s.get(Setting, ai_policy.PREFIX + 'web').value
        assert isinstance(value, dict) and value['paused'] is False
        actions = list(s.scalars(select(Audit.action).where(Audit.action.like('server AI %'))))
    assert 'server AI resumed' in actions
