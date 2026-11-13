"""In-app notice while external SMTP/webhook alert delivery keeps failing (#792)."""
import json
import time

import httpx
import pytest
from sqlalchemy import select

from app import alert_delivery_notifications, notifications, operations
from app.db import Host, Session, Setting
from app.identity import User
from app.security import seal

HOST = '6f1c2a54-0d1e-4b4e-9e43-5a7d2f0c9b11'
SECRET_URL = 'https://hooks.example.test/secret-path'
SECRET_TOKEN = 'tok-leaked-secret'


def configure(enabled=True, channel='webhook'):
    value = {'enabled': enabled, 'channel': channel, 'url': SECRET_URL, 'token': SECRET_TOKEN,
             'recipients': 'ops@example.test'}
    with Session() as s:
        s.merge(Setting(key='notifications', value={'encrypted': seal(json.dumps(value))}))
        s.commit()


def stale_host():
    """A server whose telemetry is stale produces one open SMTP/webhook-only alert."""
    with Session() as s:
        s.add(Host(id=HOST, name='stale <b>server</b>', address='example', fingerprint='pinned',
                   state='online', last_seen=1))
        s.add(User(username='viewer', password='x', role='viewer'))
        s.add(User(username='operator', password='x', role='operator'))
        s.commit()


def failing_post(*args, **kwargs):
    raise httpx.ConnectError('refused ' + SECRET_URL)


def attempt_delivery(monkeypatch, times, post=failing_post):
    monkeypatch.setattr(operations.httpx, 'post', post)
    for _ in range(times):
        with Session() as s:  # bypass backoff timing; the attempt count is what matters
            for alert in s.scalars(select(operations.Alert)):
                alert.attempted = 0
            s.commit()
        operations.deliver_one()


def revisions():
    with Session() as s:
        return [(r.lifecycle, r.severity, r.subject_revision)
                for r in s.scalars(select(notifications.NotificationRevision)
                                   .join(notifications.NotificationEvent,
                                         notifications.NotificationEvent.id == notifications.NotificationRevision.event_id)
                                   .where(notifications.NotificationEvent.kind == 'delivery-failing')
                                   .order_by(notifications.NotificationRevision.revision))]


def test_repeated_webhook_failures_publish_one_safe_admin_event(admin, monkeypatch):
    configure()
    stale_host()
    now = time.time()
    operations.collect_alerts(now)
    attempt_delivery(monkeypatch, 2)
    operations.collect_alerts(now + 60)
    assert revisions() == []  # two failures are not yet a pattern

    attempt_delivery(monkeypatch, 1)
    operations.collect_alerts(now + 120)
    assert revisions() == [('active', 'high', 'failing:webhook')]
    with Session() as s:
        assert notifications.list_for_user(s, 'viewer') == []
        assert notifications.list_for_user(s, 'operator') == []
        items = [i for i in notifications.list_for_user(s, 'admin') if i['kind'] == 'delivery-failing']
        alert = s.scalar(select(operations.Alert))
        assert alert.notified == 0 and alert.attempts == 3 and alert.error.startswith('ConnectError')
    assert len(items) == 1
    item = items[0]
    assert item['source'] == 'alert-delivery' and item['host_id'] == '' and item['deep_link'] == ''
    assert 'webhook' in item['reason']
    for leaked in (SECRET_URL, SECRET_TOKEN, 'ConnectError', 'refused', 'stale', '<b>', 'ops@example.test'):
        assert leaked not in item['reason']

    # More failures and a changing error class do not create new unread revisions.
    attempt_delivery(monkeypatch, 2, post=lambda *a, **k: (_ for _ in ()).throw(httpx.ReadTimeout('slow')))
    operations.collect_alerts(now + 180)
    assert len(revisions()) == 1


def test_successful_delivery_resolves_once_and_a_new_failure_reopens(admin, monkeypatch):
    configure()
    stale_host()
    now = time.time()
    operations.collect_alerts(now)
    attempt_delivery(monkeypatch, 3)
    operations.collect_alerts(now + 60)
    ok = httpx.Response(204, request=httpx.Request('POST', SECRET_URL))
    attempt_delivery(monkeypatch, 1, post=lambda *a, **k: ok)
    operations.collect_alerts(now + 120)
    operations.collect_alerts(now + 180)  # resolution is published once
    assert [r[0] for r in revisions()] == ['active', 'resolved']

    with Session() as s:  # telemetry resumes, then goes stale again: a new undelivered alert episode
        s.get(Host, HOST).last_seen = now + 3600
        s.commit()
    operations.collect_alerts(now + 240)
    with Session() as s:
        s.get(Host, HOST).last_seen = 1
        s.commit()
    operations.collect_alerts(now + 300)
    with Session() as s:
        alert = s.scalar(select(operations.Alert))
        assert alert.state == 'open' and alert.notified == 0 and alert.attempts == 0
    attempt_delivery(monkeypatch, 3)
    operations.collect_alerts(now + 360)
    assert [r[0] for r in revisions()] == ['active', 'resolved', 'active']


@pytest.mark.parametrize('change', ['acknowledged', 'delivery_disabled', 'delivery_removed', 'condition_cleared'])
def test_failing_condition_that_no_longer_applies_resolves(admin, monkeypatch, change):
    configure()
    stale_host()
    now = time.time()
    operations.collect_alerts(now)
    attempt_delivery(monkeypatch, 3)
    operations.collect_alerts(now + 60)
    with Session() as s:
        if change == 'acknowledged':
            s.scalar(select(operations.Alert)).state = 'acknowledged'
        elif change == 'delivery_disabled':
            s.commit()
            configure(enabled=False)
        elif change == 'delivery_removed':
            s.delete(s.get(Setting, 'notifications'))
        else:
            s.get(Host, HOST).last_seen = now + 3600  # telemetry resumes, the alert resolves
        s.commit()
    operations.collect_alerts(now + 120)
    assert [r[0] for r in revisions()] == ['active', 'resolved']


def test_smtp_channel_is_named_and_bound_separately(admin):
    configure(channel='smtp')
    with Session() as s:
        s.add(operations.Alert(id='a' * 64, host_id=HOST, kind='stale', message='x', attempts=5,
                               error='SMTPAuthenticationError (SMTP 535)'))
        assert alert_delivery_notifications.publish(s, time.time()) is True
        s.commit()
    assert revisions() == [('active', 'high', 'failing:smtp')]
    with Session() as s:
        reason = [i for i in notifications.list_for_user(s, 'admin') if i['kind'] == 'delivery-failing'][0]['reason']
    assert 'SMTP email' in reason and 'SMTPAuthentication' not in reason and '535' not in reason


def test_unreadable_configuration_never_raises(admin):
    with Session() as s:
        s.merge(Setting(key='notifications', value={'encrypted': 'not-a-fernet-token'}))
        s.add(operations.Alert(id='b' * 64, host_id=HOST, kind='stale', message='x', attempts=4, error='ValueError'))
        assert alert_delivery_notifications.delivery_channel(s) == 'unknown'
        assert alert_delivery_notifications.publish(s, time.time()) is True
        s.commit()
    assert revisions() == [('active', 'high', 'failing:unknown')]


def test_nothing_is_published_without_repeated_recorded_failures(admin):
    configure()
    with Session() as s:
        # Never attempted, delivered after retries, and attempts without a recorded error.
        s.add(operations.Alert(id='c' * 64, host_id=HOST, kind='stale', message='x'))
        s.add(operations.Alert(id='d' * 64, host_id=HOST, kind='stale', message='x', attempts=6, notified=1.0))
        s.add(operations.Alert(id='e' * 64, host_id=HOST, kind='stale', message='x', attempts=6, error=''))
        assert alert_delivery_notifications.publish(s, time.time()) is False
        s.commit()
        assert s.scalar(select(notifications.NotificationEvent)) is None


def test_producer_is_read_only(admin, monkeypatch):
    configure()
    stale_host()
    now = time.time()
    operations.collect_alerts(now)
    attempt_delivery(monkeypatch, 3)
    with Session() as s:
        before = [(a.id, a.state, a.attempts, a.attempted, a.notified, a.error) for a in s.scalars(select(operations.Alert))]
    monkeypatch.setattr(operations.httpx, 'post', lambda *a, **k: pytest.fail('producer must not send'))
    with Session() as s:
        alert_delivery_notifications.publish(s, now + 60)
        s.commit()
    with Session() as s:
        after = [(a.id, a.state, a.attempts, a.attempted, a.notified, a.error) for a in s.scalars(select(operations.Alert))]
    assert before == after
    assert len(before) == 1  # no alert row of its own
