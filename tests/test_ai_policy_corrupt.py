"""A non-object stored server AI policy fails closed without crashing (#1233)."""
import pytest
from sqlalchemy import select
from test_auto_plan_status import seed

from app import ai, ai_policy, ai_runs, incidents, worker
from app.db import Audit, Behavior, Host, Job, Session, Setting
from tests.test_ai_claims import result as triage_result, seed as seed_triage

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


def test_administrator_can_repair_a_bad_revision_without_resuming_ai(admin):
    seed()
    corrupt({'paused': 'fixture-private-value', 'revision': ['not a revision']})
    current = admin.get(BASE)
    assert current.status_code == 200
    policy = current.json()
    assert policy['paused'] and policy['needs_repair']
    assert len(policy['revision']) == 36
    assert 'fixture-private-value' not in current.text and 'not a revision' not in current.text
    corrupt({'paused': 0, 'revision': 1234})
    body = {'paused': True, 'expected_revision': policy['revision'],
            'reason': 'Repair the malformed policy and keep server AI paused'}
    rejected = admin.put(BASE, json=body)
    assert rejected.status_code == 400 and 'AI state changed' in rejected.json()['detail']
    body['expected_revision'] = admin.get(BASE).json()['revision']
    repaired = admin.put(BASE, json=body)
    assert repaired.status_code == 200
    assert repaired.json()['paused'] is True
    assert repaired.json()['needs_repair'] is False
    with Session() as s:
        assert s.get(Setting, ai_policy.PREFIX + 'web').value['paused'] is True
        assert s.scalar(select(Audit.id).where(Audit.action == 'server AI policy repaired'))


def test_api_save_with_resume_on_a_repair_revision_is_audited_as_resume(admin):
    # The panel always repairs to paused; the API still accepts an audited
    # resume against a repair revision, as documented in SECURITY_IMPLEMENTATION.
    seed()
    corrupt({'paused': 'fixture-private-value', 'revision': ['not a revision']})
    policy = admin.get(BASE).json()
    assert policy['needs_repair']
    resumed = admin.put(BASE, json={'paused': False, 'expected_revision': policy['revision'],
                                    'reason': 'Replace the malformed policy and resume server AI'})
    assert resumed.status_code == 200
    assert resumed.json()['paused'] is False and resumed.json()['needs_repair'] is False
    with Session() as s:
        assert s.scalar(select(Audit.id).where(Audit.action == 'server AI resumed'))
        assert not s.scalar(select(Audit.id).where(Audit.action == 'server AI policy repaired'))


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


def test_sql_pause_matches_the_provider_guard_for_json_policy_values(admin):
    seed_triage(count=1)
    cases = {
        'missing-field': ({'concurrency_limit': 2}, False),
        'resumed': ({'paused': False}, False),
        'paused': ({'paused': True}, True),
        'null-field': ({'paused': None}, True),
        'string-false': ({'paused': 'false'}, True),
        'number-zero': ({'paused': 0}, True),
        'empty-array': ({'paused': []}, True),
        'object-field': ({'paused': {}}, True),
        'null-policy': (None, True),
        'array-policy': ([False], True),
        'string-policy': ('false', True),
        'boolean-policy': (False, True),
        'numeric-policy': (0, True),
    }
    with Session() as s:
        for host, (value, _paused) in cases.items():
            s.add(Host(id=host, name=host, address='192.0.2.1', fingerprint=''))
            s.add(Setting(key=ai_policy.PREFIX + host, value=value))
        s.commit()
        assert set(s.scalars(ai_policy.paused_ids())) == {
            host for host, (_value, paused) in cases.items() if paused
        }

    ai_policy.require(['host-0'])  # No saved policy row.
    for host, (_value, paused) in cases.items():
        if paused:
            with pytest.raises(ai.AIError, match='paused for this server'):
                ai_policy.require([host])
        else:
            ai_policy.require([host])


def test_corrupt_policy_leaves_triage_queued_and_the_healthy_server_claims_first(admin, monkeypatch):
    seed_triage(count=2)
    corrupt({'paused': 'false'}, 'host-0')
    with Session() as s:
        s.get(Behavior, 'subject-0').first_seen = 1
        s.get(Behavior, 'subject-1').first_seen = 2
        s.commit()

    sent = []

    def provider(*args, **kwargs):
        sent.append(kwargs['json'])
        return triage_result()

    monkeypatch.setattr(ai.transport, 'post', provider)
    worker.investigate_one()
    assert len(sent) == 1
    with Session() as s:
        assert list(s.scalars(select(ai_runs.AIRun.subject))) == ['subject-1']
        assert s.get(Behavior, 'subject-0').attempted == 0
        status = ai_runs.status(s)
        assert status['pending'] == status['paused'] == 1
        assert status['eligible_unclaimed'] == 0
    response = admin.get('/api/investigation-status/servers')
    assert response.status_code == 200
    queue = response.json()
    [server] = queue['servers']
    assert server['host_id'] == 'host-0' and server['paused'] is True
    assert (
        'A server with an invalid saved AI policy stays paused until an administrator repairs it.'
        in queue['limitations']
    )
    saved = admin.put('/api/hosts/host-0/security/ai-policy', json={
        'paused': False, 'expected_revision': '', 'reason': 'Repair the malformed stored server AI policy',
    })
    assert saved.status_code == 200 and saved.json()['paused'] is False
    worker.investigate_one()
    assert len(sent) == 2
    with Session() as s:
        assert s.get(Behavior, 'subject-0').verdict == 'low'
