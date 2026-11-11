"""In-app notifications for the malware-scan incident lifecycle (#700)."""
from sqlalchemy import func, select

from app import incidents, notifications
from app.db import Host, Session

SECRET_PATH = '/srv/payload-SECRET-PATH.bin'
SECRET_RULE = 'Rule SECRET_RULE_NAME matched'


def report(sha='a'):
    return {'state': 'completed_with_findings', 'engine': 'ClamAV',
            'findings': [{'path': SECRET_PATH, 'sha256': sha * 64, 'evidence': SECRET_RULE}]}


def seed(scan='scan-1', sha='a'):
    with Session() as s:
        if not s.get(Host, 'a'):
            s.add(Host(id='a', name='alpha', address='192.0.2.1', fingerprint='test'))
            s.add(Host(id='b', name='beta', address='192.0.2.2', fingerprint='test'))
            s.commit()
        incidents.record(s, 'a', scan, report(sha))
        s.commit()
        return incidents.digest({'host': 'a', 'path': SECRET_PATH, 'sha256': sha * 64})


def items(client, **params):
    response = client.get('/api/notifications', params={'source': 'security-scan', 'include_dismissed': True, **params})
    assert response.status_code == 200, response.text
    return response.json()['items']


def revisions():
    with Session() as s:
        return s.scalar(select(func.count()).select_from(notifications.NotificationRevision))


def review(client, incident_id, state, host='a'):
    current = next(row for row in client.get('/api/hosts/' + host + '/security/incidents').json()['items'] if row['id'] == incident_id)
    response = client.put('/api/hosts/' + host + '/security/incidents/' + incident_id,
                          json={'state': state, 'reason': 'Reviewed the retained scan evidence.', 'expected_updated': current['updated']})
    assert response.status_code == 200, response.text


def test_new_detection_publishes_one_safe_admin_notification(admin):
    incident_id = seed()
    [item] = items(admin)
    assert item['kind'] == 'malware-detection' and item['subject_type'] == 'incident'
    assert item['subject_id'] == incident_id and item['host_id'] == 'a'
    assert item['severity'] == 'high' and item['lifecycle'] == 'active' and not item['read']
    assert item['deep_link'] == '#servers/a/security'
    text = repr(item)
    assert 'SECRET' not in text and 'ClamAV' not in text
    with Session() as s:
        event = s.get(notifications.NotificationEvent, item['id'])
        assert event.minimum_role == 'admin'


def test_repeat_detection_of_open_or_acknowledged_incident_does_not_flood(admin):
    incident_id = seed('scan-1')
    before = revisions()
    seed('scan-2')
    assert revisions() == before
    review(admin, incident_id, 'acknowledged')
    seed('scan-3')
    assert revisions() == before
    [item] = items(admin)
    assert item['revision'] == 1 and item['lifecycle'] == 'active'


def test_close_resolves_and_recurrence_reopens_as_unread(admin):
    incident_id = seed('scan-1')
    [item] = items(admin)
    assert admin.post('/api/notifications/' + item['id'] + '/read', json={'revision': item['revision']}).status_code == 200
    review(admin, incident_id, 'false_positive')
    [item] = items(admin)
    assert item['lifecycle'] == 'resolved' and item['severity'] == 'info' and item['revision'] == 2
    # Switching between closed states is not a new attention event.
    review(admin, incident_id, 'resolved')
    assert items(admin)[0]['revision'] == 2
    seed('scan-2')
    [item] = items(admin)
    assert item['lifecycle'] == 'active' and item['severity'] == 'high' and item['revision'] == 3
    assert not item['read'] and 'matched again' in item['reason']


def test_administrator_reopen_republishes_and_acknowledge_changes_nothing(admin):
    incident_id = seed()
    review(admin, incident_id, 'acknowledged')
    assert items(admin)[0]['revision'] == 1
    review(admin, incident_id, 'resolved')
    review(admin, incident_id, 'open')
    [item] = items(admin)
    assert item['lifecycle'] == 'active' and item['revision'] == 3 and 'reopened' in item['reason']


def test_closing_legacy_incident_without_notification_adds_nothing(admin):
    incident_id = seed()
    with Session() as s:
        s.query(notifications.NotificationRevision).delete()
        s.query(notifications.NotificationArrival).delete()
        s.query(notifications.NotificationEvent).delete()
        s.commit()
    review(admin, incident_id, 'resolved')
    assert items(admin) == [] and revisions() == 0


def test_distinct_incidents_publish_distinct_events_scoped_to_their_server(admin):
    seed('scan-1', 'a')
    seed('scan-2', 'b')
    assert len(items(admin)) == 2
    assert items(admin, host_id='b') == []


def test_viewer_and_operator_do_not_see_incident_notifications(admin, client):
    from app.identity import User
    seed()
    with Session() as s:
        s.add(User(username='viewer', password='x', role='viewer'))
        s.add(User(username='operator', password='x', role='operator'))
        s.commit()
        for username in ('viewer', 'operator'):
            assert notifications.list_for_user(s, username) == []
            assert notifications.unread_count(s, username) == 0


def test_server_deletion_resolves_active_incident_notifications(admin):
    seed()
    record = admin.get('/api/hosts/a/summary').json()['host']
    response = admin.request('DELETE', '/api/hosts/a', json={
        'confirmation': record['name'], 'expected_revision': record['lifecycle_revision'],
        'reason': 'Remove management after reviewing operations and retained records.'})
    assert response.status_code == 200, response.text
    [item] = items(admin)
    assert item['lifecycle'] == 'resolved' and item['revision'] == 2 and 'deleted' in item['reason']
    with Session() as s:
        assert s.get(incidents.Incident, item['subject_id']).state == 'open'
