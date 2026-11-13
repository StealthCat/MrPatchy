"""Failed server-changing operations reach the in-app notification bell (#731)."""
import pytest
from sqlalchemy import func, select

from app import job_notifications, notifications, worker
from app.db import Host, Job, Session
from app.identity import User

SECRET = 'endpoint said <script>alert(1)</script> token=hunter2'


def seed():
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.add(Host(id='two', name='two', address='192.0.2.2', fingerprint='test'))
        s.add(User(username='viewer', password='x', role='viewer'))
        s.add(User(username='operator', password='x', role='operator'))
        s.commit()


def finish(job_id, action='patch', state='failed', host='one', payload=None):
    with Session() as s:
        job = Job(id=job_id, host_id=host, action=action, state=state, output=SECRET,
                  payload={'packages': ['demo=2'], '_actor': 'operator'} if payload is None else payload)
        s.add(job)
        s.flush()
        created = job_notifications.publish_outcome(s, job, now=1000.0)
        s.commit()
        return created


def items(username='operator'):
    with Session() as s:
        return notifications.list_for_user(s, username, include_dismissed=True)


def revisions():
    with Session() as s:
        return s.scalar(select(func.count()).select_from(notifications.NotificationRevision))


def test_failed_operation_publishes_safe_operator_event_without_job_output(admin):
    seed()
    assert finish('job-a') is True
    [item] = items()
    assert item['source'] == 'operations' and item['kind'] == 'patch'
    assert item['host_id'] == 'one' and item['severity'] == 'medium' and item['lifecycle'] == 'active'
    assert item['deep_link'] == '#activity/jobs/job-a'
    assert 'Package update failed' in item['reason']
    assert 'hunter2' not in item['reason'] and '<script>' not in item['reason']
    assert items('viewer') == []


def test_repeated_failure_resurfaces_and_later_success_resolves(admin):
    seed()
    finish('job-a')
    with Session() as s:
        [item] = notifications.list_for_user(s, 'operator')
        notifications.mark_read(s, 'operator', item['id'], item['revision'])
        s.commit()
    assert finish('job-b') is True
    [item] = items()
    assert item['revision'] == 2 and item['deep_link'] == '#activity/jobs/job-b'
    with Session() as s:
        assert notifications.unread_count(s, 'operator') == 1
    assert finish('job-c', state='complete') is True
    [item] = items()
    assert item['lifecycle'] == 'resolved' and item['severity'] == 'info'
    assert item['deep_link'] == '#activity/jobs/job-c'
    # A further success is unchanged state: no new revision.
    count = revisions()
    assert finish('job-d', state='complete') is False and revisions() == count


def test_success_without_prior_failure_and_other_servers_or_actions_publish_nothing(admin):
    seed()
    assert finish('ok', state='complete') is False
    finish('fail-one')
    assert finish('ok-two', state='complete', host='two') is False
    assert finish('ok-key', action='key', state='complete', payload={}) is False
    [item] = items()
    assert item['host_id'] == 'one' and item['lifecycle'] == 'active'


@pytest.mark.parametrize('action,state,payload', [
    ('patch', 'failed', {'packages': ['demo=2'], '_schedule': {'id': 'schedule-a'}}),
    ('patch', 'recovery_required', {'packages': ['demo=2']}),
    ('patch', 'cancelled', {'packages': ['demo=2']}),
    ('refresh', 'failed', {}),
    ('security-scan', 'failed', {}),
    ('release-plan', 'failed', {}),
])
def test_covered_or_read_only_outcomes_publish_nothing(admin, action, state, payload):
    seed()
    assert finish('job', action=action, state=state, payload=payload) is False
    assert revisions() == 0


@pytest.mark.parametrize('action', sorted(job_notifications.ACTIONS))
def test_every_server_changing_action_has_its_own_event(admin, action):
    seed()
    assert finish('job-' + action, action=action, payload={}) is True
    [item] = items()
    assert item['kind'] == action and job_notifications.ACTIONS[action] in item['reason']


def test_deleted_server_publishes_nothing(admin):
    seed()
    assert finish('job', host='missing') is False and revisions() == 0


def test_worker_publishes_failure_with_the_job_state_and_resolves_on_success(admin, monkeypatch):
    seed()
    with Session() as s:
        s.add(Job(id='patch-fail', host_id='one', action='patch',
                  payload={'packages': ['demo=2'], '_actor': 'operator'}))
        s.commit()
    monkeypatch.setattr(worker.ssh, 'call', lambda *a, **k: {})
    monkeypatch.setattr(worker, 'save_inventory', lambda *a: None)

    def refuse(*args):
        raise ValueError(SECRET)
    monkeypatch.setattr(worker, 'validate_patch', refuse)
    worker.execute('patch-fail')
    with Session() as s:
        job = s.get(Job, 'patch-fail')
        assert job.state == 'failed' and 'hunter2' in job.output
    [item] = items()
    assert item['lifecycle'] == 'active' and item['deep_link'] == '#activity/jobs/patch-fail'
    assert 'hunter2' not in item['reason']

    with Session() as s:
        s.add(Job(id='patch-ok', host_id='one', action='patch',
                  payload={'packages': ['demo=2'], '_actor': 'operator'}))
        s.commit()
    monkeypatch.setattr(worker, 'validate_patch', lambda *a: None)
    worker.execute('patch-ok')
    with Session() as s:
        assert s.get(Job, 'patch-ok').state == 'complete'
    [item] = items()
    assert item['lifecycle'] == 'resolved' and item['deep_link'] == '#activity/jobs/patch-ok'


def test_notification_failure_never_changes_the_recorded_job_state(admin, monkeypatch):
    seed()
    with Session() as s:
        s.add(Job(id='patch-fail', host_id='one', action='patch',
                  payload={'packages': ['demo=2'], '_actor': 'operator'}))
        s.commit()
    monkeypatch.setattr(worker.ssh, 'call', lambda *a, **k: {})
    monkeypatch.setattr(worker, 'save_inventory', lambda *a: None)

    def refuse(*args):
        raise ValueError('refused')

    def broken(*args, **kwargs):
        raise RuntimeError('notification store unavailable')
    monkeypatch.setattr(worker, 'validate_patch', refuse)
    monkeypatch.setattr(notifications, 'publish', broken)
    worker.execute('patch-fail')
    with Session() as s:
        job = s.get(Job, 'patch-fail')
        assert job.state == 'failed' and 'refused' in job.output
    assert revisions() == 0
