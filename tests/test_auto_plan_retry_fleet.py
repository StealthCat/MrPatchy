"""Fleet-wide release of failed automatic AI plan attempts (#1251)."""
import json

import pytest
from sqlalchemy import func, select
from test_auto_plan_retry import add_job
from test_auto_plan_status import seed
from test_operations import login_as

from app import ai, auto_plan_retry, incidents
from app.db import Audit, Host, Job, Session

COUNT = '/api/security/auto-plan-failed'
RETRY = '/api/security/auto-plan-failed/retry'
ACTION = 'automatic AI plan retry released'


def add_server(host_id, *, enabled=True, deleted_at=0, failures=1, scan='f1'):
    with Session() as s:
        s.add(Host(id=host_id, name=host_id, address='192.0.2.9', fingerprint='',
                   enabled=enabled, deleted_at=deleted_at))
        for n in range(failures):
            s.add(incidents.Incident(id=f'{host_id}-{n}', host_id=host_id, scan_id=scan, evidence={}))
        s.commit()
    for n in range(failures):
        add_job(f'{host_id}-job-{n}', f'{host_id}-{n}', scan, host=host_id)


def fleet_failed():
    with Session() as s:
        return auto_plan_retry.fleet_failed_count(s)


def release_fleet(now, user='admin'):
    with Session() as s:
        result = auto_plan_retry.release_fleet(s, user, now)
        s.commit()
        return result


def released_jobs():
    with Session() as s:
        return {job.id for job in s.scalars(select(Job)) if (job.payload or {}).get('retry_released')}


def audits():
    with Session() as s:
        return [row.detail for row in s.scalars(select(Audit).where(Audit.action == ACTION))]


def test_fleet_counts_and_releases_every_active_server(admin):
    now = seed()
    add_server('db', failures=2)
    assert fleet_failed() == 3
    assert release_fleet(now) == {'released': 3, 'remaining': 0}
    assert released_jobs() == {'auto-old', 'db-job-0', 'db-job-1'}
    with Session() as s:
        assert auto_plan_retry.failed_count(s, 'web') == 0 and auto_plan_retry.failed_count(s, 'db') == 0
        job = s.get(Job, 'db-job-0')
        assert job.state == 'failed' and job.payload['retry_released_by'] == 'admin'
    assert audits() == ['fleet admin incidents=3 servers=2']


@pytest.mark.parametrize('change', ['disabled', 'deleted'])
def test_inactive_servers_are_neither_counted_nor_released(admin, change):
    now = seed()
    add_server('gone', enabled=change != 'disabled', deleted_at=now if change == 'deleted' else 0)
    assert fleet_failed() == 1
    assert release_fleet(now) == {'released': 1, 'remaining': 0}
    assert released_jobs() == {'auto-old'}
    with Session() as s:
        # The per-server count still reports the inactive server's failure as before (#1036).
        assert auto_plan_retry.failed_count(s, 'gone') == 1


def test_fleet_exclusions_match_the_per_server_predicate(admin):
    now = seed()
    with Session() as s:
        s.add(incidents.Incident(id='stale', host_id='web', scan_id='s3', evidence={}))
        s.add(incidents.Incident(id='manual', host_id='web', scan_id='s3', evidence={}))
        s.add(incidents.Incident(id='yara2', host_id='web', scan_id='s3',
                                 evidence={'scan_context': {'engine': 'YARA'}}))
        s.add(incidents.Incident(id='live', host_id='web', scan_id='s3', evidence={}))
        s.commit()
    add_job('job-stale', 'stale', 's3', output=auto_plan_retry.STALE_OUTPUT + '\n')
    add_job('job-manual', 'manual', 's3', automatic=False)
    add_job('job-yara', 'yara2', 's3')
    add_job('job-live-failed', 'live', 's3')
    add_job('job-live-queued', 'live', 's3', state='queued')
    with Session() as s:
        assert auto_plan_retry.failed_count(s, 'web') == fleet_failed() == 1
    assert release_fleet(now)['released'] == 1
    assert released_jobs() == {'auto-old'}


def test_a_job_recorded_under_another_server_is_not_marked(admin):
    now = seed()
    add_server('db', failures=0)
    # A failed job naming web's incident but filed under db must not be released.
    add_job('cross', 'tried', 's2', host='db')
    assert release_fleet(now)['released'] == 1
    assert released_jobs() == {'auto-old'}


def test_fleet_release_is_bounded_across_servers(admin, monkeypatch):
    now = seed()
    add_server('db', failures=2)
    monkeypatch.setattr(auto_plan_retry, 'BATCH_LIMIT', 2)
    assert release_fleet(now) == {'released': 2, 'remaining': 1}
    assert release_fleet(now) == {'released': 1, 'remaining': 0}
    assert release_fleet(now) == {'released': 0, 'remaining': 0}
    assert len(audits()) == 2  # nothing released, nothing audited


def test_released_fleet_attempts_are_replanned_by_the_ordinary_tick(admin, monkeypatch):
    now = seed()
    with Session() as s:
        for n, incident in enumerate(('owed-old', 'owed-new')):
            s.add(incidents.Plan(id=f'p{n}', incident_id=incident, state='draft', content={}, evidence_digest='d'))
        s.commit()
    queued = []
    monkeypatch.setattr('app.worker.enqueue', lambda s, host, action, payload: queued.append(payload))
    incidents.auto_plan_tick(now)
    assert queued == []
    release_fleet(now)
    incidents.auto_plan_tick(now)
    assert queued == [{'incident_id': 'tried', 'scan_id': 's2', 'automatic': True}]


def test_fleet_routes_are_admin_only_send_nothing_and_return_no_private_text(client, admin, monkeypatch):
    def no_provider(*args, **kwargs):
        raise AssertionError('releasing must not call a provider')
    monkeypatch.setattr(ai.transport, 'post', no_provider)
    seed()
    add_server('db')
    reply = admin.get(COUNT)
    assert reply.status_code == 200 and reply.json() == {'failed': 2}
    with Session() as s:
        jobs = s.scalar(select(func.count()).select_from(Job))
    reply = admin.post(RETRY)
    assert reply.status_code == 200 and reply.json() == {'released': 2, 'remaining': 0}
    text = json.dumps(reply.json())
    for private in ('private provider text', 'secret-finding', 'fixture-key-material', 'tried', 'db'):
        assert private not in text
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(Job)) == jobs  # nothing enqueued
    admin.post('/api/logout')
    for user, role in (('reader', 'viewer'), ('ops', 'operator')):
        login_as(client, user, role)
        assert client.get(COUNT).status_code == 403
        assert client.post(RETRY).status_code == 403
        client.post('/api/logout')
    assert len(audits()) == 1

