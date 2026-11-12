import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_retry, notifications, operations, triage_block_notifications, worker
from app.db import Behavior, Host, Session, Setting
from app.identity import User
from app.security import seal

NOW = 2_000_000_000.0


def seed(hosts=('one',)):
    with Session() as s:
        for host in hosts:
            s.add(Host(id=host, name=host, address='192.0.2.1', fingerprint=''))
            s.add(Behavior(id='subject-' + host, host_id=host, verdict='pending', analysis='Awaiting',
                           evidence={'executable': '/srv/<script>' + host, 'sha256': 'a' * 64,
                                     'uid': '1000', 'identity_verified': True}))
        s.add(User(username='viewer', password='x', role='viewer'))
        s.merge(Setting(key='config', value={'ai_enabled': True, 'ai_model': 'fixture-model'}))
        s.merge(Setting(key='openai_key', value={'encrypted': seal('private-key')}))
        s.commit()


def rejected_key(*args, **kwargs):
    return httpx.Response(401, json={'error': {'code': 'invalid_api_key', 'message': 'sk-leaked-secret'}},
                          request=httpx.Request('POST', ai.URL))


def block_all(monkeypatch, count=1):
    monkeypatch.setattr(ai.transport, 'post', rejected_key)
    for _ in range(count):
        worker.investigate_one()
    with Session() as s:
        states = {row.subject: row.state for row in s.scalars(select(ai_retry.TriageRetry))}
    assert states and set(states.values()) == {'blocked'}


def event(session):
    return session.scalar(select(notifications.NotificationEvent).where(
        notifications.NotificationEvent.kind == 'configuration-blocked'))


def revisions():
    with Session() as s:
        return [(r.revision, r.lifecycle, r.severity, r.subject_revision)
                for r in s.scalars(select(notifications.NotificationRevision)
                                   .join(notifications.NotificationEvent,
                                         notifications.NotificationEvent.id == notifications.NotificationRevision.event_id)
                                   .where(notifications.NotificationEvent.kind == 'configuration-blocked')
                                   .order_by(notifications.NotificationRevision.revision))]


def set_config(**changes):
    with Session() as s:
        row = s.get(Setting, 'config')
        row.value = {**row.value, **changes}
        s.commit()


def test_blocked_triage_publishes_one_safe_admin_event_and_more_blocks_do_not_flood(admin, monkeypatch):
    seed(('one', 'two'))
    block_all(monkeypatch)
    operations.collect_alerts(NOW)
    with Session() as s:
        items = notifications.list_for_user(s, 'admin')
        assert notifications.list_for_user(s, 'viewer') == []
    blocked = [item for item in items if item['kind'] == 'configuration-blocked']
    assert len(blocked) == 1
    item = blocked[0]
    assert item['source'] == 'ai-triage' and item['severity'] == 'medium' and item['lifecycle'] == 'active'
    assert item['deep_link'] == '#investigations' and item['host_id'] == ''
    # Fixed text only: no provider message, key material, path or retry signature.
    assert 'sk-leaked' not in item['reason'] and 'private-key' not in item['reason'] and '<script>' not in item['reason']
    with Session() as s:
        signature = ai_retry.configuration(s)
        assert signature not in revisions()[0][3]
        assert notifications.mark_read(s, 'admin', item['id'], item['revision'])
        s.commit()

    block_all(monkeypatch, 2)  # the second server blocks under the same configuration
    operations.collect_alerts(NOW + 60)
    assert len(revisions()) == 1
    with Session() as s:
        assert notifications.unread_count(s, 'admin') == 0


def test_configuration_change_resolves_and_a_new_block_reopens(admin, monkeypatch):
    seed()
    block_all(monkeypatch)
    operations.collect_alerts(NOW)
    first = revisions()[0][3]
    set_config(ai_model='replacement-model')  # blocked rows become eligible again
    operations.collect_alerts(NOW + 60)
    operations.collect_alerts(NOW + 120)  # resolution is published once
    assert [r[1] for r in revisions()] == ['active', 'resolved']

    block_all(monkeypatch)  # the new configuration is rejected too
    operations.collect_alerts(NOW + 180)
    history = revisions()
    assert [r[1] for r in history] == ['active', 'resolved', 'active']
    assert history[2][3] != first  # bound to the new configuration


@pytest.mark.parametrize('change', ['ai_disabled', 'paused', 'server_disabled', 'approved'])
def test_blocked_items_that_no_longer_matter_resolve_the_event(admin, monkeypatch, change):
    seed()
    block_all(monkeypatch)
    operations.collect_alerts(NOW)
    with Session() as s:
        if change == 'ai_disabled':
            row = s.get(Setting, 'config')
            row.value = {**row.value, 'ai_enabled': False}
        elif change == 'paused':
            s.merge(Setting(key='server-ai:one', value={'paused': True}))
        elif change == 'server_disabled':
            s.get(Host, 'one').enabled = False
        else:
            s.get(Behavior, 'subject-one').approved = True
        s.commit()
    operations.collect_alerts(NOW + 60)
    assert [r[1] for r in revisions()] == ['active', 'resolved']


def test_transient_deferral_and_unblocked_queue_publish_nothing(admin, monkeypatch):
    seed()
    operations.collect_alerts(NOW)  # pending but never attempted
    with Session() as s:
        s.add(ai_retry.TriageRetry(subject='subject-one', configuration=ai_retry.configuration(s),
                                   attempts=1, state='deferred', next_at=NOW + 600))
        s.commit()
    operations.collect_alerts(NOW + 60)
    with Session() as s:
        assert event(s) is None
        assert triage_block_notifications.publish(s, {'ai_enabled': True}, NOW + 60) is False


def test_exhausted_interrupted_attempts_count_as_blocked(admin):
    seed()
    with Session() as s:
        s.add(ai_retry.TriageRetry(subject='subject-one', configuration=ai_retry.configuration(s),
                                   attempts=ai_retry.MAX_ATTEMPTS, state='interrupted', next_at=NOW - 1))
        s.commit()
    operations.collect_alerts(NOW)
    assert [r[1] for r in revisions()] == ['active']
