"""Read-only automatic AI plan status and pacing for one server (#922)."""
import json
import time

import pytest
from sqlalchemy import select
from test_operations import login_as

from app import ai, auto_plan_status, incidents
from app.db import Host, Job, Session, Setting, config

URL = '/api/hosts/{}/security/auto-plan-status'


def seed(mode='rate', policy=True, now=None):
    now = time.time() if now is None else now
    with Session() as s:
        s.merge(Setting(key='config', value={**config(s), 'ai_enabled': True, 'ai_model': 'fixture-model',
                                              'ai_control_mode': mode}))
        s.merge(Setting(key='openai_key', value={'encrypted': 'fixture-key-material'}))
        s.add(Host(id='web', name='web', address='192.0.2.1', fingerprint=''))
        s.add(Setting(key='security-policy:web', value={'auto_ai_plan': policy, 'enabled': True,
                                                       'interval_hours': 24, 'paths': ['/srv/private-path']}))
        evidence = {'findings': [{'path': '/srv/private-path/secret-finding'}]}
        # Owed an attempt: two ordinary incidents. YARA, resolved, planned and attempted ones are not.
        s.add(incidents.Incident(id='owed-old', host_id='web', scan_id='s1', evidence=evidence, updated=now - 900))
        s.add(incidents.Incident(id='owed-new', host_id='web', scan_id='s1', evidence=evidence, updated=now - 60))
        s.add(incidents.Incident(id='yara', host_id='web', scan_id='s1', updated=now - 1200,
                                 evidence={'scan_context': {'engine': 'YARA'}}))
        s.add(incidents.Incident(id='closed', host_id='web', scan_id='s1', state='resolved', evidence={}))
        s.add(incidents.Incident(id='planned', host_id='web', scan_id='s1', evidence={}))
        s.add(incidents.Plan(id='plan-1', incident_id='planned', state='draft', content={}, evidence_digest='d'))
        s.add(incidents.Incident(id='tried', host_id='web', scan_id='s2', evidence={}))
        s.add(Job(id='auto-old', host_id='web', action='security-plan', state='failed', created=now - 7200,
                  output='private provider text',
                  payload={'incident_id': 'tried', 'scan_id': 's2', 'automatic': True}))
        s.commit()
    return now


def status(now):
    with Session() as s:
        return auto_plan_status.status(s, 'web', now)


def test_awaiting_matches_the_incidents_the_tick_would_plan(admin, monkeypatch):
    now = seed()
    result = status(now)
    assert result['state'] == 'ready' and result['enabled'] is True
    assert result['awaiting'] == 2 and result['awaiting_truncated'] is False
    assert result['oldest_awaiting_since'] == pytest.approx(now - 900)
    assert result['latest_automatic'] == {'state': 'failed', 'created': pytest.approx(now - 7200)}
    assert result['active_plan'] is None

    queued = []
    monkeypatch.setattr('app.worker.enqueue', lambda s, host, action, payload: queued.append(payload['incident_id']))
    incidents.auto_plan_tick(now)
    # The tick plans exactly the oldest owed incident first, from the same predicate.
    assert queued == ['owed-old']


def test_active_plan_and_latest_attempt_are_reported_without_payload(admin):
    now = seed()
    with Session() as s:
        s.add(Job(id='auto-new', host_id='web', action='security-plan', state='queued', created=now - 30,
                  payload={'incident_id': 'owed-old', 'scan_id': 's1', 'automatic': True}))
        s.commit()
    result = status(now)
    assert result['active_plan'] == {'state': 'queued', 'created': pytest.approx(now - 30)}
    assert result['latest_automatic'] == {'state': 'queued', 'created': pytest.approx(now - 30)}
    # The attempted incident is no longer owed.
    assert result['awaiting'] == 1


@pytest.mark.parametrize('mode', ['rate', 'daily_cap', 'rate_and_daily', 'unthrottled'])
def test_non_legacy_modes_claim_no_plan_hourly_cap(admin, mode):
    now = seed(mode)
    with Session() as s:
        s.add_all(Job(id=f'recent-{n}', host_id='other', action='security-plan', state='failed', created=now - 60)
                  for n in range(12))
        s.commit()
    assert status(now)['pacing'] == {'mode': mode, 'limit': None, 'used': None, 'remaining': None, 'next_at': None}


def test_legacy_mode_reports_the_fleet_allowance_and_when_it_frees(admin):
    now = seed('legacy')
    with Session() as s:
        s.add_all(Job(id=f'recent-{n}', host_id='other', action='startup-plan' if n % 2 else 'security-plan',
                      state='failed', created=now - 3000 + n) for n in range(10))
        s.commit()
    pacing = status(now)['pacing']
    assert pacing['mode'] == 'legacy' and pacing['limit'] == 10 and pacing['used'] == 10
    assert pacing['remaining'] == 0 and pacing['next_at'] == pytest.approx(now - 3000 + 3600)
    with Session() as s:
        for job in s.scalars(select(Job).where(Job.id.in_(['recent-0', 'recent-1']))):
            job.created = now - 4000
        s.commit()
    pacing = status(now)['pacing']
    assert pacing['used'] == 8 and pacing['remaining'] == 2 and pacing['next_at'] is None


def test_state_precedence_explains_why_nothing_is_enqueued(admin):
    now = seed(policy=False)
    assert status(now)['state'] == 'off'
    with Session() as s:
        s.merge(Setting(key='security-policy:web', value={'auto_ai_plan': True}))
        s.merge(Setting(key='config', value={**config(s), 'ai_enabled': False}))
        s.commit()
    assert status(now)['state'] == 'ai_disabled'
    with Session() as s:
        s.merge(Setting(key='config', value={**config(s), 'ai_enabled': True, 'ai_model': ''}))
        s.commit()
    assert status(now)['state'] == 'not_configured'
    with Session() as s:
        s.merge(Setting(key='config', value={**config(s), 'ai_model': 'fixture-model'}))
        s.merge(Setting(key='server-ai:web', value={'paused': True}))
        s.commit()
    assert status(now)['state'] == 'paused'
    with Session() as s:
        s.merge(Setting(key='server-ai:web', value={'paused': False}))
        s.get(Host, 'web').enabled = False
        s.commit()
    assert status(now)['state'] == 'inactive'


def test_held_server_reports_held(admin):
    from app.service_monitor import Watch

    now = seed()
    with Session() as s:
        s.add(Watch(id='fixture-watch', host_id='web', actor='admin',
                    reason='Fixture service watch', revision='fixture-revision', hold=True))
        s.commit()
    assert status(now)['state'] == 'held'


def test_awaiting_is_bounded_and_reports_truncation(admin, monkeypatch):
    now = seed()
    # Only the oldest AWAITING_LIMIT owed candidates are read, so a truncated count is a lower bound and says so.
    monkeypatch.setattr(auto_plan_status, 'AWAITING_LIMIT', 1)
    result = status(now)
    assert result['awaiting'] == 1 and result['awaiting_truncated'] is True
    assert result['oldest_awaiting_since'] == pytest.approx(now - 900)
    monkeypatch.setattr(auto_plan_status, 'AWAITING_LIMIT', 2)
    assert status(now)['awaiting'] == 2 and status(now)['awaiting_truncated'] is False


def test_leading_yara_incidents_do_not_hide_owed_incidents(admin, monkeypatch):
    # Review finding on #923: YARA rows older than every owed incident used to fill the bounded
    # window, reporting "0 or more" with no oldest time while the tick still planned owed-old.
    now = seed()
    with Session() as s:
        s.add_all(incidents.Incident(id=f'y{n}', host_id='web', scan_id='s1', updated=now - 5000 + n,
                                     evidence={'scan_context': {'engine': 'YARA'}})
                  for n in range(auto_plan_status.AWAITING_LIMIT + 1))
        # Missing or other engines stay candidates, exactly as automatic_candidate() treats them.
        s.add(incidents.Incident(id='clamav', host_id='web', scan_id='s1', updated=now - 30,
                                 evidence={'scan_context': {'engine': 'ClamAV'}}))
        s.add(incidents.Incident(id='no-engine', host_id='web', scan_id='s1', updated=now - 20,
                                 evidence={'scan_context': {}}))
        s.commit()
    result = status(now)
    assert result['awaiting'] == 4 and result['awaiting_truncated'] is False
    assert result['oldest_awaiting_since'] == pytest.approx(now - 900)
    with Session() as s:
        owed = list(s.scalars(select(incidents.Incident).where(*incidents.awaiting_auto_plan())))
    assert sum(map(incidents.automatic_candidate, owed)) == result['awaiting']
    queued = []
    monkeypatch.setattr('app.worker.enqueue', lambda s, host, action, payload: queued.append(payload['incident_id']))
    incidents.auto_plan_tick(now)
    assert queued == ['owed-old']


def test_endpoint_is_admin_only_and_redacted(client, admin, monkeypatch):
    def no_provider(*args, **kwargs):
        raise AssertionError('the status must not call a provider')
    monkeypatch.setattr(ai.transport, 'post', no_provider)
    seed()
    reply = admin.get(URL.format('web'))
    assert reply.status_code == 200
    text = json.dumps(reply.json())
    for private in ('secret-finding', 'private-path', 'private provider text', 'fixture-key-material',
                    'fixture-model', 'owed-old', 'tried'):
        assert private not in text
    assert admin.get(URL.format('missing')).status_code == 404
    with Session() as s:
        jobs = s.scalar(select(Job.id).where(Job.id != 'auto-old').limit(1))
    assert jobs is None
    admin.post('/api/logout')
    login_as(client, 'reader', 'viewer')
    assert client.get(URL.format('web')).status_code == 403
    client.post('/api/logout')
    login_as(client, 'ops', 'operator')
    assert client.get(URL.format('web')).status_code == 403
