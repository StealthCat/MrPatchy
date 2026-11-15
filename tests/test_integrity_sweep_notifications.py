"""In-app notifications when a server's file-integrity hash sweep stalls while telemetry is fresh (#794)."""
import time

from sqlalchemy import func, select

from app import integrity_sweep_notifications as sweep, notifications, operations
from app.db import Host, Session

HOST = 'hs'


def seed(hashed_age=0.0, seen_age=0.0, now=None, **fields):
    now = time.time() if now is None else now
    with Session() as s:
        host = s.get(Host, HOST)
        if not host:
            host = Host(id=HOST, name='sweep target', address='192.0.2.40', fingerprint='test', state='online')
            s.add(host)
        host.last_seen = now - seen_age
        host.telemetry = {'collected': now - seen_age, 'hashed_at': now - hashed_age, 'processes': [], 'errors': []}
        for key, value in fields.items():
            setattr(host, key, value)
        s.commit()
    return now


def collect(now):
    operations.collect_alerts(now=now)


def items(client):
    response = client.get('/api/notifications', params={'source': sweep.SOURCE, 'include_dismissed': True})
    assert response.status_code == 200, response.text
    return response.json()['items']


def revisions():
    with Session() as s:
        return s.scalar(select(func.count()).select_from(notifications.NotificationRevision).join(
            notifications.NotificationEvent, notifications.NotificationEvent.id == notifications.NotificationRevision.event_id).where(
            notifications.NotificationEvent.source == sweep.SOURCE))


def test_recent_sweep_and_short_gaps_publish_nothing(admin):
    now = seed(hashed_age=30)
    collect(now)
    now = seed(hashed_age=600)  # past the 360 s ingest check but short of the sustained threshold
    collect(now)
    assert items(admin) == []


def test_stalled_sweep_opens_one_admin_notification_without_endpoint_text(admin):
    now = seed(hashed_age=sweep.STALLED_SECONDS + 60)
    with Session() as s:
        s.get(Host, HOST).integrity = [{'path': '/etc/<script>secret', 'issue': 'endpoint supplied text'}]
        s.commit()
    collect(now)
    [item] = items(admin)
    assert item['kind'] == sweep.KIND and item['subject_type'] == 'server' and item['subject_id'] == HOST
    assert item['host_id'] == HOST and item['severity'] == 'medium' and item['lifecycle'] == 'active'
    assert item['deep_link'] == '#servers/hs/overview'
    assert item['reason'] == sweep.MESSAGES['overdue'] and 'not a clean-host' in item['reason']
    assert '<script>' not in item['reason'] and 'endpoint supplied' not in item['reason']
    with Session() as s:
        assert s.get(notifications.NotificationEvent, item['id']).minimum_role == 'admin'
    collect(now + 30)  # unchanged category: no flood
    collect(now + 60)
    assert revisions() == 1


def test_category_change_appends_revision_and_recovery_resolves_then_reopens(admin):
    now = seed(hashed_age=sweep.STALLED_SECONDS + 1)
    collect(now)
    now = seed(hashed_age=-(sweep.FUTURE_SECONDS + 60))
    collect(now)
    [item] = items(admin)
    assert item['revision'] == 2 and item['reason'] == sweep.MESSAGES['future'] and item['lifecycle'] == 'active'
    now = seed(hashed_age=10)
    collect(now)
    [item] = items(admin)
    assert item['lifecycle'] == 'resolved' and item['severity'] == 'info' and item['revision'] == 3
    collect(now + 1)
    assert revisions() == 3
    now = seed(hashed_age=sweep.STALLED_SECONDS + 5)
    collect(now)
    [item] = items(admin)
    assert item['lifecycle'] == 'active' and item['revision'] == 4 and not item['read']


def test_stale_telemetry_is_left_to_the_telemetry_loss_producer(admin):
    now = seed(hashed_age=sweep.STALLED_SECONDS * 3, seen_age=sweep.FRESH_SECONDS + 1)
    collect(now)
    assert items(admin) == []
    now = seed(hashed_age=sweep.STALLED_SECONDS + 1)
    collect(now)
    assert items(admin)[0]['lifecycle'] == 'active'
    now = seed(hashed_age=sweep.STALLED_SECONDS * 3, seen_age=sweep.FRESH_SECONDS + 1)
    collect(now)
    assert items(admin)[0]['lifecycle'] == 'resolved'


def test_disabled_enrolling_and_deleted_servers_resolve(admin):
    for change in ({'enabled': False}, {'state': 'enrolling'}, {'deleted_at': 1.0}):
        reset = {'enabled': True, 'state': 'online', 'deleted_at': 0.0}
        now = seed(hashed_age=sweep.STALLED_SECONDS + 1, **reset)
        collect(now)
        assert items(admin)[0]['lifecycle'] == 'active', change
        now = seed(hashed_age=sweep.STALLED_SECONDS + 1, **change)
        collect(now)
        assert items(admin)[0]['lifecycle'] == 'resolved', change


def test_notifications_are_hidden_from_viewers_and_operators(admin):
    from app.identity import User
    now = seed(hashed_age=sweep.STALLED_SECONDS + 1)
    collect(now)
    with Session() as s:
        s.add_all([User(username='sweep-viewer', password='x', role='viewer'),
                   User(username='sweep-operator', password='x', role='operator')])
        s.commit()
        assert notifications.unread_count(s, 'sweep-viewer') == 0
        assert notifications.unread_count(s, 'sweep-operator') == 0
        assert notifications.unread_count(s, 'admin') >= 1


def test_existing_integrity_alert_and_patching_state_are_unchanged(admin, monkeypatch):
    now = seed(hashed_age=sweep.STALLED_SECONDS + 1, integrity=[{'path': 'integrity', 'issue': 'Hash sweep is overdue'}])
    collect(now)
    with Session() as s:
        alerts = {alert.kind for alert in s.scalars(select(operations.Alert).where(operations.Alert.host_id == HOST))}
        assert 'integrity' in alerts and sweep.KIND not in alerts
        assert s.get(Host, HOST).integrity == [{'path': 'integrity', 'issue': 'Hash sweep is overdue'}]

    def reject(*args, **kwargs):
        raise ValueError('rejected')
    monkeypatch.setattr(sweep.notifications, 'publish', reject)
    with Session() as s:
        s.get(Host, HOST).integrity = [{'path': 'integrity', 'issue': 'Hash sweep is overdue'}, {'path': 'x', 'issue': 'y'}]
        s.commit()
    collect(now + 1)  # a rejected payload never blocks SMTP/webhook alert collection
    with Session() as s:
        alert = s.scalar(select(operations.Alert).where(operations.Alert.host_id == HOST, operations.Alert.kind == 'integrity'))
        assert alert.state == 'open' and '"x"' in alert.message


def test_classify_handles_missing_and_invalid_timestamps():
    now = 10_000.0
    host = Host(id='c', name='c', address='192.0.2.41', fingerprint='t', state='online', enabled=True, deleted_at=0.0,
                last_seen=now, telemetry={'collected': now})
    assert sweep.classify(host, now) == 'overdue'  # no sweep ever reported
    host.telemetry = {'collected': now, 'hashed_at': float('nan')}
    assert sweep.classify(host, now) == 'overdue'
    host.telemetry = {}
    assert sweep.classify(host, now) is None  # no snapshot yet: nothing to classify
    host.telemetry = {'collected': now, 'hashed_at': now - sweep.STALLED_SECONDS}
    assert sweep.classify(host, now) is None  # boundary is exclusive
