"""Recovery from an unreadable SMTP/webhook alert-delivery configuration.

When the saved ``notifications`` setting can no longer be decrypted (for example after the
encryption key changed), ``deliver_one()`` stops before counting an attempt. The #792
producer therefore never saw a failing attempt, and the Operations routes raised instead of
letting an administrator replace the configuration.
"""
import json
import time

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import alert_delivery_notifications, notifications, operations
from app.db import Session, Setting
from app.main import app
from app.security import unseal

HOST = '6f1c2a54-0d1e-4b4e-9e43-5a7d2f0c9b11'
UNREADABLE = {'encrypted': 'not-a-fernet-token'}


def make_unreadable():
    with Session() as s:
        s.merge(Setting(key='notifications', value=dict(UNREADABLE)))
        s.commit()


def add_alert(alert_id='a' * 64, **fields):
    with Session() as s:
        s.add(operations.Alert(id=alert_id, host_id=HOST, kind='stale', message='server <b>secret</b>', **fields))
        s.commit()


def revisions():
    with Session() as s:
        return [(r.lifecycle, r.severity, r.subject_revision)
                for r in s.scalars(select(notifications.NotificationRevision)
                                   .join(notifications.NotificationEvent,
                                         notifications.NotificationEvent.id == notifications.NotificationRevision.event_id)
                                   .where(notifications.NotificationEvent.kind == 'delivery-failing')
                                   .order_by(notifications.NotificationRevision.revision))]


def saved_config():
    with Session() as s:
        return json.loads(unseal(s.get(Setting, 'notifications').value['encrypted']))


def test_unreadable_configuration_with_undelivered_alert_notifies_admins_without_attempts(admin):
    make_unreadable()
    add_alert()
    operations.deliver_one()  # cannot start: the configuration is unreadable
    with Session() as s:
        assert alert_delivery_notifications.publish(s, time.time()) is True
        s.commit()
    assert revisions() == [('active', 'high', 'unreadable')]
    with Session() as s:
        assert s.scalar(select(operations.Alert)).attempts == 0  # nothing was ever attempted
        items = [i for i in notifications.list_for_user(s, 'admin') if i['kind'] == 'delivery-failing']
    assert len(items) == 1
    reason = items[0]['reason']
    assert 'cannot be read' in reason and 'Activity → Alert delivery' in reason
    for leaked in ('not-a-fernet-token', 'secret', '<b>', 'InvalidToken'):
        assert leaked not in reason


def test_unreadable_configuration_without_undelivered_alerts_stays_quiet(admin):
    make_unreadable()
    add_alert('b' * 64, notified=1.0)
    add_alert('c' * 64, state='acknowledged')
    with Session() as s:
        assert alert_delivery_notifications.publish(s, time.time()) is False
        s.commit()
    assert revisions() == []


def test_unreadable_notice_is_stable_and_resolves_after_replacement(admin):
    make_unreadable()
    add_alert()
    now = time.time()
    with Session() as s:
        alert_delivery_notifications.publish(s, now)
        alert_delivery_notifications.publish(s, now + 30)  # unchanged: no new unread revision
        s.commit()
    assert revisions() == [('active', 'high', 'unreadable')]
    assert admin.put('/api/operations/notifications', json={'url': '', 'enabled': False}).status_code == 200
    with Session() as s:
        assert alert_delivery_notifications.publish(s, now + 60) is False
        s.commit()
    assert [r[0] for r in revisions()] == ['active', 'resolved']


def test_operations_panel_reports_unreadable_configuration_without_values(admin):
    make_unreadable()
    response = admin.get('/api/operations/notifications')
    assert response.status_code == 200
    body = response.json()
    assert body['unreadable'] is True and body['channel'] == 'webhook'
    assert body['token_configured'] is False and body['password_configured'] is False
    assert 'not-a-fernet-token' not in response.text


def test_readable_configuration_is_not_marked_unreadable(admin):
    assert admin.put('/api/operations/notifications',
                     json={'url': 'https://alerts.example.test/e', 'token': 'tok', 'enabled': True}).status_code == 200
    body = admin.get('/api/operations/notifications').json()
    assert body['unreadable'] is False and body['token_configured'] is True and 'token' not in body


def test_webhook_save_replaces_unreadable_configuration_without_retaining_secrets(admin):
    make_unreadable()
    response = admin.put('/api/operations/notifications',
                         json={'url': 'https://alerts.example.test/e', 'enabled': True})
    assert response.status_code == 200
    assert saved_config() == {'enabled': True, 'url': 'https://alerts.example.test/e', 'token': '', 'channel': 'webhook'}


def test_smtp_save_replaces_unreadable_configuration(admin):
    make_unreadable()
    response = admin.put('/api/operations/smtp', json={
        'enabled': True, 'host': 'smtp.example.test', 'port': 587, 'mode': 'starttls',
        'sender': 'patchy@example.test', 'recipients': ['ops@example.test'], 'username': 'u'})
    assert response.status_code == 200, response.text
    value = saved_config()
    assert value['channel'] == 'smtp' and value['password'] == '' and value['host'] == 'smtp.example.test'


def test_deliver_one_skips_unreadable_configuration_without_counting_attempts(admin, monkeypatch):
    make_unreadable()
    add_alert()
    monkeypatch.setattr(operations.httpx, 'post', lambda *a, **k: (_ for _ in ()).throw(AssertionError('no send')))
    operations.deliver_one()  # must not raise into the worker's poll executor
    with Session() as s:
        alert = s.scalar(select(operations.Alert))
        assert alert.attempts == 0 and alert.notified == 0 and alert.error == ''


def test_unreadable_routes_remain_admin_only(client):
    make_unreadable()
    assert client.get('/api/operations/notifications').status_code == 401
    assert TestClient(app).put('/api/operations/notifications', json={'enabled': False}).status_code in (401, 403)

