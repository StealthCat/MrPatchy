"""Administrator retry for update scores blocked on AI configuration (#815)."""
import time

import pytest
from sqlalchemy import select

from app import ai, notifications, operations, scoring_block_notifications, update_scores
from app.db import Audit, Host, Package, Session, Setting, config
from test_operations import login_as
from test_scoring_block_notifications import rejected_key, seed, success, states

BLOCKED = '/api/update-scores/blocked'
RETRY = BLOCKED + '/retry'


def scoring_revisions():
    with Session() as s:
        return [r.lifecycle for r in s.scalars(
            select(notifications.NotificationRevision)
            .join(notifications.NotificationEvent,
                  notifications.NotificationEvent.id == notifications.NotificationRevision.event_id)
            .where(notifications.NotificationEvent.source == 'ai-scoring')
            .order_by(notifications.NotificationRevision.revision))]


@pytest.fixture
def blocked(admin, monkeypatch):
    seed(('one', 'two'))
    rejected_key.calls = 0
    monkeypatch.setattr(ai.transport, 'post', rejected_key)
    update_scores.run_one()
    assert rejected_key.calls == 1 and states() == {'one': 'blocked', 'two': 'blocked'}
    return admin


def test_settings_report_the_notification_predicate_count(blocked):
    assert blocked.get('/api/settings').json()['ai_scoring_blocked'] == 2
    with Session() as s:
        s.merge(Setting(key='server-ai:two', value={'paused': True}))
        s.commit()
    assert blocked.get('/api/settings').json()['ai_scoring_blocked'] == 1


def test_blocked_endpoint_matches_the_notification_predicate(blocked):
    def predicate():
        with Session() as s:
            return scoring_block_notifications.blocked_count(s, config(s))[0]
    assert blocked.get(BLOCKED).json() == {'blocked': 2} and predicate() == 2
    with Session() as s:
        s.merge(Setting(key='server-ai:two', value={'paused': True}))
        s.commit()
    assert blocked.get(BLOCKED).json() == {'blocked': 1} and predicate() == 1
    assert blocked.post(RETRY).json()['retried'] == 1
    assert blocked.get(BLOCKED).json() == {'blocked': 0} and predicate() == 0


def test_retry_requeues_without_a_provider_call_and_scheduler_scores_them(blocked, monkeypatch):
    operations.collect_alerts(time.time())
    assert scoring_revisions() == ['active']
    reply = blocked.post(RETRY)
    assert reply.status_code == 200 and reply.json()['retried'] == 2
    # The retry itself sends nothing; the scores wait for the normal scheduler.
    assert rejected_key.calls == 1 and states() == {'one': 'pending', 'two': 'pending'}
    with Session() as s:
        rows = list(s.scalars(select(update_scores.UpdateScore)))
        assert all(r.configuration == '' and r.attempted == 0 and 'administrator' in r.explanation for r in rows)
        entry = s.scalar(select(Audit).where(Audit.action == 'retry blocked AI update scores'))
        assert entry is not None and '2 blocked update score' in entry.detail
    assert blocked.get('/api/settings').json()['ai_scoring_blocked'] == 0
    operations.collect_alerts(time.time() + 60)
    assert scoring_revisions() == ['active', 'resolved']
    # No one-hour wait: the next pass is eligible immediately under the same model and key.
    monkeypatch.setattr(ai.transport, 'post', success)
    update_scores.run_one()
    assert states() == {'one': 'complete', 'two': 'complete'}


def test_repeat_failure_blocks_again_and_resurfaces(blocked):
    operations.collect_alerts(time.time())
    assert blocked.post(RETRY).json()['retried'] == 2
    operations.collect_alerts(time.time() + 60)
    update_scores.run_one()  # the provider still rejects the same model and key
    assert rejected_key.calls == 2 and states() == {'one': 'blocked', 'two': 'blocked'}
    operations.collect_alerts(time.time() + 120)
    assert scoring_revisions() == ['active', 'resolved', 'active']


@pytest.mark.parametrize('change', ['paused', 'server_disabled', 'superseded', 'old_signature', 'ai_disabled'])
def test_retry_leaves_out_of_scope_blocked_scores_unchanged(blocked, change):
    with Session() as s:
        if change == 'paused':
            s.merge(Setting(key='server-ai:two', value={'paused': True}))
        elif change == 'server_disabled':
            s.get(Host, 'two').enabled = False
        elif change == 'superseded':
            s.get(Package, 'two:fixture').candidate = '3'
        elif change == 'old_signature':
            s.scalar(select(update_scores.UpdateScore).where(
                update_scores.UpdateScore.host_id == 'two')).configuration = 'earlier-signature'
        else:
            row = s.get(Setting, 'config')
            row.value = {**row.value, 'ai_enabled': False}
        s.commit()
    reply = blocked.post(RETRY).json()
    if change == 'ai_disabled':
        assert reply['retried'] == 0 and states() == {'one': 'blocked', 'two': 'blocked'}
        assert 'No update scores are blocked' in reply['detail']
        with Session() as s:
            assert s.scalar(select(Audit).where(Audit.action == 'retry blocked AI update scores')) is None
    else:
        assert reply['retried'] == 1 and states() == {'one': 'pending', 'two': 'blocked'}


@pytest.mark.parametrize('role', ['viewer', 'operator'])
def test_retry_requires_an_administrator(blocked, role):
    blocked.post('/api/logout')
    login_as(blocked, 'reader-' + role, role)
    assert blocked.post(RETRY).status_code == 403
    assert blocked.get(BLOCKED).status_code == 403
    assert blocked.get('/api/settings').status_code == 403
    assert states() == {'one': 'blocked', 'two': 'blocked'}


def test_retry_requires_csrf(blocked):
    token = blocked.headers.pop('X-CSRF-Token')
    try:
        assert blocked.post(RETRY).status_code == 403
    finally:
        blocked.headers['X-CSRF-Token'] = token
    assert states() == {'one': 'blocked', 'two': 'blocked'}
