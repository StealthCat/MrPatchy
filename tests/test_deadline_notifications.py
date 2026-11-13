"""In-app notifications for pending package updates past their patch deadline (#775)."""
import time

from sqlalchemy import select

from app import deadline_notifications, notifications, operations
from app.db import Host, Package, Session, Setting
from app.identity import User

HOST = '5b0e2c1d-7a3f-4c9e-8d21-0f6e4a3b2c19'
OTHER = '9c8d7e6f-5a4b-4c3d-9e2f-1a0b9c8d7e6f'
HOUR = 3600


def add_host(host_id=HOST, **values):
    with Session() as s:
        s.add(Host(id=host_id, name='Deadline ' + host_id[:4], address='example', fingerprint='pinned',
                   state='online', **{'last_seen': time.time() + HOUR, **values}))
        s.commit()


def add_package(name, priority, age_hours, host_id=HOST, candidate='2.0'):
    with Session() as s:
        s.add(Package(id=host_id + ':' + name, host_id=host_id, name=name, installed='1.0', candidate=candidate,
                      priority=priority, available_since=time.time() - age_hours * HOUR))
        s.commit()


def events(s):
    return s.scalars(select(notifications.NotificationEvent).where(
        notifications.NotificationEvent.kind == 'patch-deadline').order_by(notifications.NotificationEvent.host_id)).all()


def current(s, event):
    return s.get(notifications.NotificationRevision, (event.id, event.revision))


def test_overdue_update_publishes_one_fixed_admin_notification_without_count_revisions(admin):
    add_host()
    add_package('openssl', 'normal', 200)
    with Session() as s:
        s.add(User(username='viewer', password='x', role='viewer'))
        s.add(User(username='operator', password='x', role='operator'))
        s.commit()
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        revision = current(s, event)
        assert (event.source, event.subject_type, event.subject_id, event.host_id, event.minimum_role) == (
            'operations', 'server', HOST, HOST, 'admin')
        assert (revision.severity, revision.lifecycle) == ('medium', 'active')
        assert revision.deep_link == '#servers/' + HOST + '/patching'
        assert revision.reason == deadline_notifications.message('normal')
        assert 'openssl' not in revision.reason and '1' not in revision.reason
        assert notifications.unread_count(s, 'admin') == 1
        assert notifications.unread_count(s, 'operator') == notifications.unread_count(s, 'viewer') == 0
        # The SMTP/webhook outbox alert keeps its existing count text.
        alert = s.query(operations.Alert).filter_by(kind='overdue').one()
        assert alert.message == '1 packages passed their deadline'
        assert not s.query(operations.Alert).filter_by(kind='patch deadline').count()

    # More overdue packages of the same or lower priority are not a new revision.
    add_package('curl', 'normal', 300)
    add_package('vim', 'low', 900)
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        assert event.revision == 1
        assert s.query(operations.Alert).filter_by(kind='overdue').one().message == '3 packages passed their deadline'


def test_priority_escalation_and_deescalation_each_append_one_revision(admin):
    add_host()
    add_package('vim', 'low', 900)
    operations.collect_alerts()
    add_package('openssh-server', 'critical', 30)
    operations.collect_alerts()
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        revision = current(s, event)
        assert event.revision == 2 and revision.severity == 'critical'
        assert revision.reason == deadline_notifications.message('critical')
        s.delete(s.get(Package, HOST + ':openssh-server'))
        s.commit()
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        revision = current(s, event)
        assert event.revision == 3 and (revision.severity, revision.lifecycle) == ('low', 'active')


def test_not_yet_due_installed_unknown_age_or_unknown_priority_updates_do_not_publish(admin):
    add_host()
    add_package('due-later', 'critical', 10)
    add_package('installed', 'critical', 100, candidate='')
    with Session() as s:
        s.add(Package(id=HOST + ':unknown-age', host_id=HOST, name='unknown-age', installed='1', candidate='2',
                      priority='high', available_since=0))
        s.commit()
    operations.collect_alerts()
    with Session() as s:
        assert events(s) == []


def test_resolves_when_installed_or_deadline_extended(admin):
    add_host()
    add_package('openssl', 'high', 100)
    operations.collect_alerts()
    with Session() as s:
        s.get(Package, HOST + ':openssl').candidate = ''
        s.commit()
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        assert event.revision == 2 and current(s, event).lifecycle == 'resolved'
        assert current(s, event).severity == 'info'
        # A new overdue update reopens the same event as unread.
        s.get(Package, HOST + ':openssl').candidate = '3.0'
        s.commit()
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        assert event.revision == 3 and current(s, event).lifecycle == 'active'
        s.add(Setting(key='config', value={'deadlines': {'critical': 24, 'high': 200, 'normal': 168, 'low': 720},
                                           'ai_control_mode': 'rate'}))
        s.commit()
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        assert event.revision == 4 and current(s, event).lifecycle == 'resolved'


def test_disabled_deleted_and_enrolling_servers_are_excluded_and_resolved(admin):
    add_host()
    add_host(OTHER)
    add_package('openssl', 'high', 100)
    add_package('openssl', 'high', 100, host_id=OTHER)
    operations.collect_alerts()
    with Session() as s:
        assert [event.host_id for event in events(s)] == sorted([HOST, OTHER])
        s.get(Host, HOST).enabled = False
        s.get(Host, OTHER).state = 'enrolling'
        s.commit()
    operations.collect_alerts()
    with Session() as s:
        assert [current(s, event).lifecycle for event in events(s)] == ['resolved', 'resolved']
        s.get(Host, HOST).enabled = True
        s.get(Host, OTHER).state = 'online'
        s.get(Host, OTHER).deleted_at = time.time()
        s.commit()
    operations.collect_alerts()
    with Session() as s:
        states = {event.host_id: current(s, event).lifecycle for event in events(s)}
        assert states == {HOST: 'active', OTHER: 'resolved'}


def test_rejected_publish_keeps_existing_event_active(admin, monkeypatch):
    add_host()
    add_package('openssl', 'high', 100)
    operations.collect_alerts()
    monkeypatch.setattr(deadline_notifications, 'message', lambda priority: '')
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        assert event.revision == 1 and current(s, event).lifecycle == 'active'


def test_highest_overdue_uses_one_grouped_read_per_chunk(admin, monkeypatch):
    add_host()
    add_host(OTHER)
    add_package('a', 'low', 900)
    add_package('b', 'high', 100)
    add_package('c', 'normal', 200, host_id=OTHER)
    monkeypatch.setattr(deadline_notifications, 'CHUNK', 1)
    with Session() as s:
        calls = []
        original = s.execute
        monkeypatch.setattr(s, 'execute', lambda *a, **k: calls.append(a) or original(*a, **k))
        found = deadline_notifications.highest_overdue(
            s, [HOST, OTHER], {'critical': 24, 'high': 72, 'normal': 168, 'low': 720}, time.time())
    assert found == {HOST: 'high', OTHER: 'normal'}
    assert len(calls) == 2
