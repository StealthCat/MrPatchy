"""Release a server's failed automatic AI plan attempts for retry (#1036)."""
import json

import pytest
from sqlalchemy import func, select
from test_auto_plan_status import seed
from test_operations import login_as

from app import ai, auto_plan_retry, auto_plan_status, incidents
from app.db import Audit, Host, Job, Session

COUNT = '/api/hosts/{}/security/auto-plan-failed'
RETRY = '/api/hosts/{}/security/auto-plan-failed/retry'


def failed():
    with Session() as s:
        return auto_plan_retry.failed_count(s, 'web')


def awaiting(now):
    with Session() as s:
        return auto_plan_status.status(s, 'web', now)['awaiting']


def release(now, user='admin'):
    with Session() as s:
        result = auto_plan_retry.release(s, 'web', user, now)
        s.commit()
        return result


def tick(now, monkeypatch):
    queued = []
    monkeypatch.setattr('app.worker.enqueue', lambda s, host, action, payload: queued.append(payload))
    incidents.auto_plan_tick(now)
    return queued


def add_job(job_id, incident, scan, state='failed', automatic=True, output='', host='web', created=0.0):
    payload = {'incident_id': incident, 'scan_id': scan}
    if automatic:
        payload['automatic'] = True
    with Session() as s:
        s.add(Job(id=job_id, host_id=host, action='security-plan', state=state, output=output,
                  payload=payload, created=created))
        s.commit()


def test_failed_attempt_is_counted_released_and_replanned_by_the_tick(admin, monkeypatch):
    now = seed()
    # Plan the two owed incidents so only the failed one is left for the tick.
    with Session() as s:
        for n, incident in enumerate(('owed-old', 'owed-new')):
            s.add(incidents.Plan(id=f'p{n}', incident_id=incident, state='draft', content={}, evidence_digest='d'))
        s.commit()
    assert failed() == 1 and awaiting(now) == 0
    assert tick(now, monkeypatch) == []

    assert release(now) == {'released': 1, 'remaining': 0}
    assert failed() == 0 and awaiting(now) == 1
    with Session() as s:
        job = s.get(Job, 'auto-old')
        # The historical attempt is kept, failed, with its output untouched.
        assert job.state == 'failed' and job.output == 'private provider text'
        assert job.payload['retry_released'] is True and job.payload['retry_released_by'] == 'admin'
        assert s.scalar(select(func.count()).select_from(Audit).where(
            Audit.action == 'automatic AI plan retry released')) == 1
    # The ordinary tick re-plans it as a fresh automatic attempt for the same scan.
    assert tick(now, monkeypatch) == [{'incident_id': 'tried', 'scan_id': 's2', 'automatic': True}]


def test_a_new_failure_blocks_again_until_released_again(admin):
    now = seed()
    release(now)
    add_job('auto-second', 'tried', 's2', created=now)
    assert failed() == 1
    assert release(now) == {'released': 1, 'remaining': 0}
    assert failed() == 0


@pytest.mark.parametrize('state', ['queued', 'running', 'complete'])
def test_unreleased_live_or_complete_attempt_is_not_counted_or_released(admin, state):
    now = seed()
    add_job('auto-live', 'tried', 's2', state=state, created=now)
    assert failed() == 0
    assert release(now) == {'released': 0, 'remaining': 0}
    with Session() as s:
        assert 'retry_released' not in s.get(Job, 'auto-old').payload


def test_excluded_incidents_are_never_counted(admin):
    now = seed()
    with Session() as s:
        # Planned, resolved, YARA, an older scan, a stale skip, a manual failure and another server.
        s.add(incidents.Incident(id='planned2', host_id='web', scan_id='s3', evidence={}))
        s.add(incidents.Plan(id='plan-2', incident_id='planned2', state='draft', content={}, evidence_digest='d'))
        s.add(incidents.Incident(id='resolved2', host_id='web', scan_id='s3', state='resolved', evidence={}))
        s.add(incidents.Incident(id='yara2', host_id='web', scan_id='s3', evidence={'scan_context': {'engine': 'YARA'}}))
        s.add(incidents.Incident(id='rescanned', host_id='web', scan_id='s4', evidence={}))
        s.add(incidents.Incident(id='stale', host_id='web', scan_id='s3', evidence={}))
        s.add(incidents.Incident(id='manual', host_id='web', scan_id='s3', evidence={}))
        s.add(Host(id='other', name='other', address='192.0.2.2', fingerprint=''))
        s.add(incidents.Incident(id='elsewhere', host_id='other', scan_id='s3', evidence={}))
        s.commit()
    for incident in ('planned2', 'resolved2', 'yara2', 'elsewhere'):
        add_job('job-' + incident, incident, 's3', host='other' if incident == 'elsewhere' else 'web')
    add_job('job-rescanned', 'rescanned', 'old-scan')
    add_job('job-stale', 'stale', 's3', output=auto_plan_retry.STALE_OUTPUT + '\n')
    add_job('job-manual', 'manual', 's3', automatic=False)
    assert failed() == 1  # only the seeded 'tried' incident
    assert release(now)['released'] == 1
    with Session() as s:
        released = {job.id for job in s.scalars(select(Job)) if (job.payload or {}).get('retry_released')}
    assert released == {'auto-old'}


def test_release_is_bounded(admin, monkeypatch):
    now = seed()
    with Session() as s:
        for n in range(3):
            s.add(incidents.Incident(id=f'many-{n}', host_id='web', scan_id='m', evidence={}, updated=now + n))
        s.commit()
    for n in range(3):
        add_job(f'many-job-{n}', f'many-{n}', 'm')
    assert failed() == 4
    monkeypatch.setattr(auto_plan_retry, 'BATCH_LIMIT', 3)
    assert release(now) == {'released': 3, 'remaining': 1}
    assert release(now) == {'released': 1, 'remaining': 0}
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(Audit).where(
            Audit.action == 'automatic AI plan retry released')) == 2


@pytest.mark.parametrize('change', ['disabled', 'deleted'])
def test_inactive_server_releases_nothing(admin, change):
    now = seed()
    with Session() as s:
        host = s.get(Host, 'web')
        if change == 'disabled':
            host.enabled = False
        else:
            host.deleted_at = now
        s.commit()
    assert release(now) == {'released': 0, 'remaining': 1}
    with Session() as s:
        assert 'retry_released' not in s.get(Job, 'auto-old').payload
        assert s.scalar(select(func.count()).select_from(Audit).where(
            Audit.action == 'automatic AI plan retry released')) == 0


def test_paused_server_releases_but_the_tick_still_waits(admin, monkeypatch):
    now = seed()
    from app import ai_policy
    monkeypatch.setattr(ai_policy, 'status', lambda s, host: {'paused': True})
    assert release(now)['released'] == 1
    assert tick(now, monkeypatch) == []


def test_routes_are_admin_only_send_nothing_and_return_no_private_text(client, admin, monkeypatch):
    def no_provider(*args, **kwargs):
        raise AssertionError('releasing must not call a provider')
    monkeypatch.setattr(ai.transport, 'post', no_provider)
    seed()
    reply = admin.get(COUNT.format('web'))
    assert reply.status_code == 200 and reply.json() == {'failed': 1}
    assert admin.get(COUNT.format('missing')).status_code == 404
    assert admin.post(RETRY.format('missing')).status_code == 404
    with Session() as s:
        jobs = s.scalar(select(func.count()).select_from(Job))
    reply = admin.post(RETRY.format('web'))
    assert reply.status_code == 200 and reply.json() == {'released': 1, 'remaining': 0}
    text = json.dumps(reply.json())
    for private in ('private provider text', 'secret-finding', 'fixture-key-material', 'tried'):
        assert private not in text
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(Job)) == jobs  # nothing enqueued
    admin.post('/api/logout')
    for user, role in (('reader', 'viewer'), ('ops', 'operator')):
        login_as(client, user, role)
        assert client.get(COUNT.format('web')).status_code == 403
        assert client.post(RETRY.format('web')).status_code == 403
        client.post('/api/logout')
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(Audit).where(
            Audit.action == 'automatic AI plan retry released')) == 1
