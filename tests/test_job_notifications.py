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


# AI response-plan failures (#806): admin-only, fixed text, resolved by a later plan.

def admins_and_operators():
    with Session() as s:
        s.add(User(username='planner', password='x', role='admin'))
        s.commit()


@pytest.mark.parametrize('action', sorted(job_notifications.PLAN_ACTIONS))
def test_failed_plan_job_publishes_admin_only_fixed_event_and_success_resolves(admin, action):
    seed()
    admins_and_operators()
    assert finish('plan-a', action=action, payload={'incident_id': 'i'}) is True
    [item] = items('planner')
    assert item['source'] == 'operations' and item['kind'] == action
    assert item['severity'] == 'medium' and item['lifecycle'] == 'active'
    assert item['deep_link'] == '#activity/jobs/plan-a'
    assert job_notifications.PLAN_ACTIONS[action] in item['reason']
    assert 'no response plan was proposed' in item['reason'] and 'Nothing ran' in item['reason']
    assert 'hunter2' not in item['reason'] and '<script>' not in item['reason']
    assert items('operator') == [] and items('viewer') == []
    assert finish('plan-b', action=action, state='complete', payload={'incident_id': 'i'}) is True
    [item] = items('planner')
    assert item['lifecycle'] == 'resolved' and item['deep_link'] == '#activity/jobs/plan-b'


def test_plan_actions_have_separate_events_and_do_not_resolve_each_other(admin):
    seed()
    admins_and_operators()
    finish('security', action='security-plan', payload={})
    assert finish('startup-ok', action='startup-plan', state='complete', payload={}) is False
    [item] = items('planner')
    assert item['kind'] == 'security-plan' and item['lifecycle'] == 'active'


@pytest.mark.parametrize('message', [job_notifications.AUTOMATIC_PLAN_DISABLED,
                                     job_notifications.AUTOMATIC_PLAN_STALE])
def test_skipped_automatic_plan_is_not_a_failure_but_the_same_text_on_a_manual_plan_is(admin, message):
    seed()
    with Session() as s:
        job = Job(id='auto', host_id='one', action='security-plan', state='failed',
                  output=message + '\n', payload={'incident_id': 'i', 'automatic': True})
        s.add(job)
        s.flush()
        assert job_notifications.publish_outcome(s, job, now=1000.0) is False
        manual = Job(id='manual', host_id='one', action='security-plan', state='failed',
                     output=message + '\n', payload={'incident_id': 'i'})
        s.add(manual)
        s.flush()
        assert job_notifications.publish_outcome(s, manual, now=1000.0) is True
        s.commit()


def seed_plan_job(automatic=False):
    from app.db import Setting
    from app.security import seal
    from app import incidents
    with Session() as s:
        s.add(Host(id='plan-host', name='Plan host', address='192.0.2.9', fingerprint='', state='online'))
        s.add(User(username='planner', password='x', role='admin'))
        report = {'state': 'completed_with_findings', 'findings': [{
            'path': '/srv/fixture', 'sha256': 'a' * 64, 'evidence': 'fixture rule'}]}
        incidents.record(s, 'plan-host', 'scan-plan', report)
        incident = s.scalar(select(incidents.Incident))
        s.merge(Setting(key='config', value={'ai_enabled': True, 'ai_model': 'fixture-model',
                                             'ai_control_mode': 'unthrottled'}))
        s.merge(Setting(key='openai_key', value={'encrypted': seal('fixture-key')}))
        payload = {'incident_id': incident.id}
        if automatic:
            payload.update(automatic=True, scan_id='stale-scan')
        s.commit()
        return worker.enqueue(s, 'plan-host', 'security-plan', payload)


def test_worker_notifies_terminal_plan_failure_but_not_a_controlled_wait(admin, monkeypatch):
    from app import ai, incidents
    job_id = seed_plan_job()
    before = revisions()  # incident recording may publish its own notification

    def wait(*args, **kwargs):
        raise ai.AIError('Shared provider wait.', policy_wait=True, retry_after=90)
    monkeypatch.setattr(incidents, 'generate', wait)
    worker.execute(job_id)
    with Session() as s:
        assert s.get(Job, job_id).state == 'queued'
    assert revisions() == before

    def rejected(*args, **kwargs):
        raise ai.AIError('OpenAI rejected the saved key ' + SECRET)
    monkeypatch.setattr(incidents, 'generate', rejected)
    with Session() as s:
        s.get(Job, job_id).next_at = 0
        s.commit()
    worker.execute(job_id)
    with Session() as s:
        job = s.get(Job, job_id)
        assert job.state == 'failed' and 'hunter2' in job.output
    assert revisions() == before + 1
    [item] = [i for i in items('planner') if i['source'] == 'operations']
    assert item['kind'] == 'security-plan' and item['deep_link'] == '#activity/jobs/' + job_id
    assert 'hunter2' not in item['reason'] and 'rejected' not in item['reason']


def test_worker_skipped_automatic_plan_publishes_nothing(admin, monkeypatch):
    from app import incidents
    from app.db import Setting
    job_id = seed_plan_job(automatic=True)
    before = revisions()
    with Session() as s:
        s.merge(Setting(key='security-policy:plan-host', value={'auto_ai_plan': True}))
        s.commit()
    monkeypatch.setattr(incidents, 'generate', lambda *a, **k: pytest.fail('stale automatic plan reached AI'))
    worker.execute(job_id)
    with Session() as s:
        job = s.get(Job, job_id)
        assert job.state == 'failed' and job.output.startswith(job_notifications.AUTOMATIC_PLAN_STALE)
    assert revisions() == before
