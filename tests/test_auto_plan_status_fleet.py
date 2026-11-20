"""Read-only fleet-wide automatic AI plan status (#936)."""
import json

import pytest
from sqlalchemy import event, func, select
from test_auto_plan_status import seed
from test_operations import login_as

from app import ai, auto_plan_status
from app.db import Host, Job, Session, Setting, engine

URL = '/api/security/auto-plan-status'


def add_host(host_id, name, policy=None, deleted=False):
    with Session() as s:
        s.add(Host(id=host_id, name=name, address='192.0.2.9', fingerprint='', deleted_at=100.0 if deleted else 0))
        if policy is not None:
            s.add(Setting(key='security-policy:' + host_id, value=policy))
        s.commit()


def fleet(now):
    with Session() as s:
        return auto_plan_status.fleet(s, now)


def test_rows_match_the_per_server_status_and_skip_opted_out_and_deleted(admin):
    now = seed()
    add_host('alpha', 'alpha', {'auto_ai_plan': True, 'enabled': True})
    add_host('off', 'off', {'auto_ai_plan': False, 'enabled': True})
    add_host('none', 'none')
    add_host('gone', 'gone', {'auto_ai_plan': True}, deleted=True)
    add_host('junk', 'junk', ['not', 'a', 'dict'])
    result = fleet(now)
    assert [item['host_id'] for item in result['items']] == ['alpha', 'web']
    with Session() as s:
        for item in result['items']:
            single = auto_plan_status.status(s, item['host_id'], now)
            assert item == {'host_id': item['host_id'], 'host_name': item['host_id'],
                            **{k: v for k, v in single.items() if k not in ('generated_at', 'pacing')}}
            assert result['pacing'] == single['pacing']
    assert result['truncated'] is False
    assert result['totals'] == {'servers': 2, 'ready': 2, 'awaiting': 2, 'awaiting_truncated': False,
                                'active_plans': 0}


def test_disabled_server_is_listed_as_inactive_and_active_plans_are_counted(admin):
    now = seed()
    add_host('beta', 'beta', {'auto_ai_plan': True})
    with Session() as s:
        s.get(Host, 'beta').enabled = False
        s.add(Job(id='live', host_id='web', action='security-plan', state='queued', created=now - 10,
                  payload={'incident_id': 'owed-old', 'automatic': True}))
        s.commit()
    result = fleet(now)
    states = {item['host_id']: item['state'] for item in result['items']}
    assert states == {'beta': 'inactive', 'web': 'ready'}
    assert result['totals']['ready'] == 1 and result['totals']['active_plans'] == 1


def test_fleet_reads_both_job_summaries_in_one_query(admin, monkeypatch):
    now = seed()
    host_ids = [f'fleet-{index:02d}' for index in range(11)]
    for host_id in host_ids + ['zz-over-limit']:
        add_host(host_id, host_id, {'auto_ai_plan': True})
    monkeypatch.setattr(auto_plan_status, 'FLEET_LIMIT', 12)
    with Session() as s:
        for host_id in host_ids:
            s.add_all([
                Job(id=f'{host_id}-newer-active', host_id=host_id,
                    action='security-plan', state='queued', created=now - 30),
                Job(id=f'{host_id}-b-active', host_id=host_id,
                    action='startup-plan', state='running', created=now - 40),
                Job(id=f'{host_id}-a-active', host_id=host_id,
                    action='security-plan', state='queued', created=now - 40),
                Job(id=f'{host_id}-a-auto', host_id=host_id,
                    action='security-plan', payload={'automatic': True}, state='failed', created=now - 20),
                Job(id=f'{host_id}-z-auto', host_id=host_id,
                    action='security-plan', payload={'automatic': True}, state='complete', created=now - 20),
                Job(id=f'{host_id}-manual', host_id=host_id,
                    action='security-plan', state='complete', created=now - 10),
                Job(id=f'{host_id}-startup', host_id=host_id,
                    action='startup-plan', payload={'automatic': True}, state='failed', created=now - 5),
            ])
        s.commit()

    job_reads = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        if 'order by jobs.created' in ' '.join(statement.lower().split()):
            job_reads.append(statement)

    event.listen(engine, 'before_cursor_execute', capture)
    try:
        result = fleet(now)
    finally:
        event.remove(engine, 'before_cursor_execute', capture)

    assert len(job_reads) == 1
    assert result['truncated'] is True
    assert [item['host_id'] for item in result['items']] == host_ids + ['web']
    with Session() as s:
        for item in result['items'][:-1]:
            assert item['active_plan'] == {'state': 'running', 'created': pytest.approx(now - 40)}
            assert item['latest_automatic'] == {'state': 'complete', 'created': pytest.approx(now - 20)}
            single = auto_plan_status.status(s, item['host_id'], now)
            assert item['active_plan'] == single['active_plan']
            assert item['latest_automatic'] == single['latest_automatic']
    assert result['items'][-1]['active_plan'] is None
    assert result['items'][-1]['latest_automatic']['state'] == 'failed'


def test_listing_is_bounded_and_reports_truncation(admin, monkeypatch):
    now = seed()
    for n in range(3):
        add_host(f'h{n}', f'host-{n}', {'auto_ai_plan': True})
    monkeypatch.setattr(auto_plan_status, 'FLEET_LIMIT', 2)
    result = fleet(now)
    assert [item['host_name'] for item in result['items']] == ['host-0', 'host-1']
    assert result['truncated'] is True and result['totals']['servers'] == 2


def test_awaiting_truncation_is_carried_into_the_totals(admin, monkeypatch):
    now = seed()
    monkeypatch.setattr(auto_plan_status, 'AWAITING_LIMIT', 1)
    totals = fleet(now)['totals']
    assert totals['awaiting'] == 1 and totals['awaiting_truncated'] is True


def test_legacy_pacing_is_reported_once(admin):
    now = seed('legacy')
    result = fleet(now)
    assert result['pacing']['mode'] == 'legacy' and result['pacing']['limit'] == 10
    assert all('pacing' not in item for item in result['items'])


@pytest.mark.parametrize('mode', ['rate', 'unthrottled'])
def test_endpoint_is_admin_only_read_only_and_redacted(client, admin, monkeypatch, mode):
    def no_provider(*args, **kwargs):
        raise AssertionError('the status must not call a provider')
    monkeypatch.setattr(ai.transport, 'post', no_provider)
    seed(mode)
    with Session() as s:
        jobs, settings = s.scalar(select(func.count()).select_from(Job)), s.scalar(select(func.count()).select_from(Setting))
    reply = admin.get(URL)
    assert reply.status_code == 200 and reply.json()['items'][0]['host_id'] == 'web'
    text = json.dumps(reply.json())
    for private in ('secret-finding', 'private-path', 'private provider text', 'fixture-key-material',
                    'fixture-model', 'owed-old', 'tried'):
        assert private not in text
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(Job)) == jobs
        assert s.scalar(select(func.count()).select_from(Setting)) == settings
    admin.post('/api/logout')
    for user, role in (('reader', 'viewer'), ('ops', 'operator')):
        login_as(client, user, role)
        assert client.get(URL).status_code == 403
        client.post('/api/logout')
