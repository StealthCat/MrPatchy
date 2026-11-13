"""In-app notifications for agent event-spool pressure and newly lost observations (#108)."""
import time

import pytest
from sqlalchemy import func, select

from app import agent_spool_health, notifications, worker
from app.db import Host, Session

CAPACITY = 1000


def spool(queued=0, dropped=0, observations=0):
    return {'pending': 1, 'queued_bytes': queued, 'capacity_bytes': CAPACITY, 'batch_limit_bytes': 100,
            'dropped': dropped, 'dropped_observations': observations,
            'drop_reasons': {'capacity': {'batches': dropped, 'observations': observations}}}


def seed():
    with Session() as s:
        if not s.get(Host, 'sp'):
            s.add(Host(id='sp', name='spool target', address='192.0.2.9', fingerprint='test', state='online'))
            s.commit()


def poll(queued=0, dropped=0, observations=0):
    with Session() as s:
        host = s.get(Host, 'sp')
        now = time.time()
        worker.ingest(s, host, {'telemetry': {'collected': now, 'hashed_at': now, 'processes': [], 'errors': []},
                                'spool': spool(queued, dropped, observations)})


def items(client):
    response = client.get('/api/notifications', params={'source': 'agent-spool', 'include_dismissed': True})
    assert response.status_code == 200, response.text
    return response.json()['items']


def revisions():
    with Session() as s:
        return s.scalar(select(func.count()).select_from(notifications.NotificationRevision).join(
            notifications.NotificationEvent, notifications.NotificationEvent.id == notifications.NotificationRevision.event_id).where(
            notifications.NotificationEvent.source == 'agent-spool'))


@pytest.mark.parametrize('active,pressure,loss,expected', [
    ('', 'ok', False, ('none', '')),
    ('', 'warning', False, ('none', '')),
    ('', 'unavailable', False, ('none', '')),
    ('', 'critical', False, ('publish', 'critical')),
    ('', 'ok', True, ('publish', 'loss')),
    ('', 'critical', True, ('publish', 'critical+loss')),
    ('critical', 'critical', False, ('hold', 'critical')),
    ('critical', 'warning', False, ('hold', 'critical')),
    ('critical', 'unavailable', False, ('hold', 'critical')),
    ('critical', 'ok', False, ('resolve', '')),
    ('critical', 'warning', True, ('publish', 'critical+loss')),
    ('loss', 'ok', True, ('hold', 'loss')),
    ('loss', 'critical', False, ('publish', 'critical+loss')),
    ('critical+loss', 'critical', True, ('hold', 'critical+loss')),
    ('critical+loss', 'ok', False, ('resolve', '')),
])
def test_episode_transitions_open_escalate_hold_and_resolve(active, pressure, loss, expected):
    assert agent_spool_health.notification_transition(active, pressure, loss) == expected


def test_quiet_spool_publishes_nothing(admin):
    seed()
    poll(queued=100)
    poll(queued=750)
    assert items(admin) == []


def test_critical_pressure_opens_one_admin_notification_and_resolves_below_warning(admin):
    seed()
    poll(queued=950)
    [item] = items(admin)
    assert item['kind'] == 'spool-health' and item['subject_type'] == 'server' and item['subject_id'] == 'sp'
    assert item['host_id'] == 'sp' and item['severity'] == 'medium' and item['lifecycle'] == 'active'
    assert item['deep_link'] == '#servers/sp/summary' and '90%' in item['reason']
    with Session() as s:
        assert s.get(notifications.NotificationEvent, item['id']).minimum_role == 'admin'
    poll(queued=960)
    poll(queued=800)  # still at warning: held, not resolved or republished
    assert revisions() == 1
    poll(queued=100)
    [item] = items(admin)
    assert item['lifecycle'] == 'resolved' and item['severity'] == 'info' and item['revision'] == 2
    poll(queued=100)
    assert revisions() == 2
    poll(queued=990)  # a later episode reopens the same event as unread
    [item] = items(admin)
    assert item['lifecycle'] == 'active' and item['revision'] == 3 and not item['read']


def test_new_loss_is_high_severity_escalates_once_and_does_not_flood(admin):
    seed()
    poll(dropped=0)
    poll(dropped=2, observations=40)
    [item] = items(admin)
    assert item['severity'] == 'high' and 'lost observation batches' in item['reason']
    poll(dropped=5, observations=90)  # continuing loss in the same episode
    assert revisions() == 1
    poll(queued=950, dropped=6, observations=95)
    [item] = items(admin)
    assert item['revision'] == 2 and item['severity'] == 'high'
    assert '90%' in item['reason'] and 'lost observation batches' in item['reason']
    poll(queued=950, dropped=6, observations=95)
    assert revisions() == 2
    poll(queued=0, dropped=6, observations=95)  # cumulative counters retained, no new loss
    [item] = items(admin)
    assert item['lifecycle'] == 'resolved' and item['revision'] == 3


def test_retained_cumulative_loss_alone_does_not_notify(admin):
    seed()
    poll(dropped=3, observations=10)  # first sample after enrollment: counted as new loss
    poll(dropped=3, observations=10)
    poll(dropped=3, observations=10)
    [item] = items(admin)
    assert item['lifecycle'] == 'resolved' and revisions() == 2


def test_notifications_are_hidden_from_viewers_and_operators(admin):
    from app.identity import User
    seed()
    poll(queued=999)
    with Session() as s:
        s.add_all([User(username='spool-viewer', password='x', role='viewer'),
                   User(username='spool-operator', password='x', role='operator')])
        s.commit()
        assert notifications.unread_count(s, 'spool-viewer') == 0
        assert notifications.unread_count(s, 'spool-operator') == 0
        assert notifications.unread_count(s, 'admin') >= 1


def test_server_deletion_resolves_active_spool_notification(admin):
    seed()
    poll(queued=999)
    record = admin.get('/api/hosts/sp/summary').json()['host']
    response = admin.request('DELETE', '/api/hosts/sp', json={
        'confirmation': record['name'], 'expected_revision': record['lifecycle_revision'],
        'reason': 'Remove management after reviewing operations and retained records.'})
    assert response.status_code == 200, response.text
    [item] = items(admin)
    assert item['lifecycle'] == 'resolved' and item['revision'] == 2 and 'deleted' in item['reason']


def test_deleting_a_server_without_an_active_episode_publishes_nothing(admin):
    seed()
    poll(queued=999)
    poll(queued=0)
    with Session() as s:
        assert agent_spool_health.resolve_host_notification(s, 'sp') is False
    assert revisions() == 2
