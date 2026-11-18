"""Read-only fleet-wide automatic AI plan status (#936)."""
import json

import pytest
from sqlalchemy import func, select
from test_auto_plan_status import seed
from test_operations import login_as

from app import ai, auto_plan_status
from app.db import Host, Job, Session, Setting

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
