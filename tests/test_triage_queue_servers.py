"""Read-only per-server process-triage queue breakdown (#975)."""
import json
import time

import pytest
from sqlalchemy import func, select
from test_operations import login_as

from app import ai, ai_claims, ai_retry, ai_runs, triage_queue_servers
from app.db import Behavior, Host, Session, Setting
from app.security import seal

SERVERS = '/api/investigation-status/servers'


def seed():
    """Three active servers with a backlog, one paused, plus servers that must stay out."""
    now = time.time()
    with Session() as s:
        for name in ('busy', 'quiet', 'paused', 'disabled', 'deleted', 'clean'):
            s.add(Host(id=name, name='srv-' + name, address='192.0.2.1', fingerprint='', state='online',
                       enabled=name != 'disabled', deleted_at=now if name == 'deleted' else 0))
        s.merge(Setting(key='server-ai:paused', value={'paused': True}))
        s.merge(Setting(key='server-ai:busy', value={'paused': False, 'concurrency_limit': 1}))
        s.merge(Setting(key='config', value={'ai_enabled': True, 'ai_model': 'fixture-model',
                                              'ai_control_mode': 'unthrottled'}))
        s.merge(Setting(key='openai_key', value={'encrypted': seal('private-key')}))
        s.commit()
        signature = ai_retry.configuration(s)

        def behavior(host, key, age, verdict='pending', approved=False, attempted=0):
            identifier = host + '-' + key
            s.add(Behavior(id=identifier, host_id=host, evidence={'exe': '/opt/secret-tool', 'cmd': 'secret-cmd'},
                           verdict=verdict, analysis='private analysis text', approved=approved,
                           first_seen=now - age, last_seen=now, attempted=attempted))
            return identifier

        def retry(subject, state, configuration=signature, attempts=1, next_at=0, provider_until=0):
            s.add(ai_retry.TriageRetry(subject=subject, configuration=configuration, attempts=attempts, state=state,
                                       next_at=next_at, provider_until=provider_until, reason='private provider text'))

        behavior('busy', 'new', 900)                                    # never attempted: eligible
        retry(behavior('busy', 'due', 800, 'error'), 'deferred', next_at=now - 5)    # wait elapsed: eligible
        retry(behavior('busy', 'later', 700, 'error'), 'deferred', next_at=now + 600)    # retry wait
        retry(behavior('busy', 'provider', 650, 'error'), 'deferred', next_at=now + 1200, provider_until=now + 1200)
        behavior('busy', 'recent', 600, attempted=now - 60)             # legacy hourly retry wait
        retry(behavior('busy', 'blocked', 500, 'error'), 'blocked')     # blocked under the saved configuration
        retry(behavior('busy', 'spent', 450, 'error'), 'interrupted', attempts=ai_retry.MAX_ATTEMPTS)
        retry(behavior('busy', 'old-block', 400, 'error'), 'blocked', configuration='earlier')    # eligible again
        running = behavior('busy', 'running', 300)
        retry(running, 'interrupted', attempts=ai_retry.MAX_ATTEMPTS, next_at=now + 3600)    # running last attempt
        lapsed = behavior('busy', 'lapsed', 200)                        # expired claim: eligible, not active
        behavior('busy', 'approved', 100, approved=True)
        behavior('busy', 'done', 100, verdict='safe')
        for subject, expires in ((running, now + 120), (lapsed, now - 1)):
            s.add(ai_claims.Claim(subject=subject, host_id='busy', token='t', worker_id='w', boot_id='b',
                                  run_id='r-' + subject, revision='', configuration=signature, created=now - 30, renewed=now - 30,
                                  expires=expires))
        behavior('quiet', 'new', 5000)
        behavior('paused', 'one', 50)
        behavior('paused', 'two', 40)
        behavior('disabled', 'one', 10)
        behavior('deleted', 'one', 10)
        behavior('clean', 'done', 10, verdict='safe')
        s.commit()
    return now


def breakdown(now, **options):
    with Session() as s:
        return triage_queue_servers.status(s, now, **options)


def no_provider(*args, **kwargs):
    raise AssertionError('the per-server queue breakdown must not call a provider')


def test_each_pending_investigation_is_classified_once_per_server(admin, monkeypatch):
    monkeypatch.setattr(ai.transport, 'post', no_provider)
    now = seed()
    result = breakdown(now)
    assert [row['host_id'] for row in result['servers']] == ['busy', 'paused', 'quiet']
    assert result['servers_with_backlog'] == 3 and result['truncated'] is False
    busy, paused, quiet = result['servers']
    assert {key: busy[key] for key in ('pending', 'active', 'eligible', 'blocked', 'retry_wait')} == {
        'pending': 10, 'active': 1, 'eligible': 4, 'blocked': 2, 'retry_wait': 3}
    assert busy['name'] == 'srv-busy' and busy['paused'] is False
    assert busy['investigation_limit'] == 1 and busy['at_investigation_limit'] is True
    assert busy['active_leases'] == 1 and paused['active_leases'] == quiet['active_leases'] == 0
    assert busy['oldest_pending_observation_at'] == pytest.approx(now - 900)
    assert busy['next_retry_at'] == pytest.approx(now + 600)
    assert paused['paused'] is True and paused['pending'] == 2 and paused['eligible'] == 2
    assert quiet['pending'] == quiet['eligible'] == 1 and quiet['next_retry_at'] is None
    assert quiet['investigation_limit'] == 2 and quiet['at_investigation_limit'] is False
    for row in result['servers']:
        assert row['pending'] == row['active'] + row['eligible'] + row['blocked'] + row['retry_wait']


def test_rows_add_up_to_the_fleet_status_totals(admin):
    now = seed()
    with Session() as s:
        fleet = ai_runs.status(s)
    servers = breakdown(now)['servers']
    assert sum(row['pending'] for row in servers) == fleet['pending']
    assert sum(row['pending'] for row in servers if row['paused']) == fleet['paused']
    assert sum(row['eligible'] for row in servers if not row['paused']) == fleet['eligible_unclaimed']
    assert sum(row['active'] for row in servers) == fleet['active']
    # The fleet total still counts the running last attempt as blocked; here it is active.
    assert sum(row['blocked'] for row in servers if not row['paused']) == fleet['blocked'] - 1


def test_limit_uses_the_admission_lease_count_when_a_claimed_behavior_leaves_the_pending_scope(admin):
    now = seed()
    with Session() as s:
        s.get(Behavior, 'busy-running').approved = True    # approved while its investigation still runs
        s.commit()
        admission = ai_claims.occupancy(s, 'busy', now)['active_lease_count']
    busy = breakdown(now)['servers'][0]
    assert busy['host_id'] == 'busy' and busy['pending'] == 9 and busy['active'] == 0
    assert busy['active_leases'] == admission == 1 and busy['at_investigation_limit'] is True


def test_a_corrupt_per_server_limit_is_reported_as_the_fail_closed_minimum(admin):
    now = seed()
    with Session() as s:
        s.merge(Setting(key='server-ai:quiet', value={'paused': False, 'concurrency_limit': 99}))
        s.commit()
    quiet = breakdown(now)['servers'][2]
    assert quiet['host_id'] == 'quiet' and quiet['investigation_limit'] == 1


def test_list_is_bounded_and_reports_truncation(admin):
    now = seed()
    result = breakdown(now, limit=2)
    assert [row['host_id'] for row in result['servers']] == ['busy', 'paused']
    assert result['servers_with_backlog'] == 3 and result['truncated'] is True and result['max_servers'] == 2
    assert breakdown(now, limit=10_000)['max_servers'] == triage_queue_servers.MAX_SERVERS


def test_no_backlog_reports_an_empty_list(admin):
    result = breakdown(time.time())
    assert result['servers'] == [] and result['servers_with_backlog'] == 0 and result['truncated'] is False


def test_breakdown_writes_nothing(admin):
    now = seed()

    def state():
        with Session() as s:
            return ([(row.id, row.verdict, row.attempted) for row in s.scalars(select(Behavior).order_by(Behavior.id))],
                    [(row.subject, row.state, row.attempts, row.next_at) for row in s.scalars(
                        select(ai_retry.TriageRetry).order_by(ai_retry.TriageRetry.subject))],
                    [(row.subject, row.expires) for row in s.scalars(
                        select(ai_claims.Claim).order_by(ai_claims.Claim.subject))],
                    s.scalar(select(func.count()).select_from(ai_runs.AIRun)))

    before = state()
    breakdown(now)
    assert state() == before


def test_endpoint_is_admin_only(client):
    seed()
    login_as(client, 'reader', 'viewer')
    assert client.get(SERVERS).status_code == 403
    client.post('/api/logout')
    login_as(client, 'ops', 'operator')
    assert client.get(SERVERS).status_code == 403


def test_admin_endpoint_reports_counts_without_private_data(admin, monkeypatch):
    monkeypatch.setattr(ai.transport, 'post', no_provider)
    seed()
    reply = admin.get(SERVERS)
    assert reply.status_code == 200
    body = reply.json()
    assert [row['host_id'] for row in body['servers']] == ['busy', 'paused', 'quiet']
    assert set(body['servers'][0]) == {
        'host_id', 'name', 'pending', 'active', 'eligible', 'blocked', 'retry_wait', 'paused',
        'active_leases', 'investigation_limit', 'at_investigation_limit', 'oldest_pending_observation_at', 'next_retry_at'}
    text = json.dumps(body)
    for private in ('secret-tool', 'secret-cmd', 'private analysis text', 'private provider text', 'private-key',
                    'fixture-model', 'busy-new', 'srv-disabled', 'srv-deleted', 'srv-clean'):
        assert private not in text
