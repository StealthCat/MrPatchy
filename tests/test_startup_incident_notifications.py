"""In-app notifications for the startup-change incident lifecycle (#704)."""
from sqlalchemy import func, select

from app import incidents, notifications, persistence
from app.db import Session
from test_persistence_baseline import setup_host, payload, URL
from test_persistence_comparison import inventory

BASE = '/api/hosts/baseline-host/security'
SECRET_PATH = '/etc/cron.d/SECRET-PERSISTENCE-PATH'


def enable(admin, link=True):
    policy = {'enabled': False, 'interval_hours': 2, 'link_incidents': link, 'expected_revision': ''}
    response = admin.put(BASE + '/persistence-monitor', json=policy)
    assert response.status_code == 200, response.text


def changed(variant='a'):
    entry = {'path': SECRET_PATH, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644,
             'size': 9, 'mtime_ns': 1, 'sha256': variant * 64}
    return {**inventory(), 'entries': inventory()['entries'] + [entry]}


def receipt(inv):
    return {'version': 1, 'trust_basis': 'target_local_package_database', 'state': inv['state'],
            'packages': [], 'persistence': inv}


def prepare(admin, link=True):
    setup_host()
    response = admin.post(URL, json=payload(admin))
    assert response.status_code == 200, response.text
    enable(admin, link)


def observe(inspection, variant='a'):
    with Session() as s:
        incidents.record_inspection(s, 'baseline-host', inspection, receipt(changed(variant)))
        s.commit()


def items(client, **params):
    response = client.get('/api/notifications', params={'source': 'file-integrity', 'include_dismissed': True, **params})
    assert response.status_code == 200, response.text
    return response.json()['items']


def revisions():
    with Session() as s:
        return s.scalar(select(func.count()).select_from(notifications.NotificationRevision))


def incident(admin):
    rows = admin.get(BASE + '/persistence-incidents').json()['items']
    assert len(rows) == 1
    return rows[0]


def review(admin, state):
    row = incident(admin)
    response = admin.put(BASE + '/persistence-incidents/' + row['id'], json={
        'state': state, 'reason': 'Reviewed the changed startup entries.', 'expected_updated': row['updated']})
    assert response.status_code == 200, response.text


def test_new_startup_change_publishes_one_safe_admin_notification(admin):
    prepare(admin)
    observe('change-1')
    row = incident(admin)
    [item] = items(admin)
    assert item['kind'] == 'startup-change' and item['subject_type'] == 'startup-incident'
    assert item['subject_id'] == row['id'] and item['host_id'] == 'baseline-host'
    assert item['severity'] == 'medium' and item['lifecycle'] == 'active' and not item['read']
    assert item['deep_link'] == '#servers/baseline-host/integrity'
    assert 'not a malware verdict' in item['reason']
    text = repr(item)
    assert 'SECRET' not in text and 'cron.d' not in text and 'aaaa' not in text
    with Session() as s:
        assert s.get(notifications.NotificationEvent, item['id']).minimum_role == 'admin'


def test_no_incident_recording_means_no_notification(admin):
    prepare(admin, link=False)
    observe('change-1')
    assert items(admin) == [] and revisions() == 0


def test_repeat_detection_of_open_or_acknowledged_incident_does_not_flood(admin):
    prepare(admin)
    observe('change-1')
    before = revisions()
    observe('change-2')
    assert revisions() == before
    review(admin, 'acknowledged')
    assert revisions() == before
    observe('change-3')
    assert revisions() == before
    [item] = items(admin)
    assert item['revision'] == 1 and item['lifecycle'] == 'active'


def test_close_resolves_and_recurrence_reopens_as_unread(admin):
    prepare(admin)
    observe('change-1')
    [item] = items(admin)
    assert admin.post('/api/notifications/' + item['id'] + '/read', json={'revision': item['revision']}).status_code == 200
    review(admin, 'false_positive')
    [item] = items(admin)
    assert item['lifecycle'] == 'resolved' and item['severity'] == 'info' and item['revision'] == 2
    # Moving between closed states is not a new attention event.
    review(admin, 'resolved')
    assert items(admin)[0]['revision'] == 2
    observe('change-2')
    [item] = items(admin)
    assert item['lifecycle'] == 'active' and item['severity'] == 'medium' and item['revision'] == 3
    assert not item['read'] and 'observed again' in item['reason']
    assert incident(admin)['state'] == 'open'


def test_administrator_reopen_republishes_including_straight_to_acknowledged(admin):
    prepare(admin)
    observe('change-1')
    review(admin, 'resolved')
    review(admin, 'acknowledged')
    [item] = items(admin)
    assert item['lifecycle'] == 'active' and item['revision'] == 3 and 'reopened' in item['reason']
    # Acknowledged -> open is not a new attention event.
    review(admin, 'open')
    assert items(admin)[0]['revision'] == 3


def test_distinct_change_sets_publish_distinct_events(admin):
    prepare(admin)
    observe('change-1', 'a')
    observe('change-2', 'b')
    assert len(items(admin)) == 2
    assert items(admin, host_id='other-host') == []


def test_closing_legacy_incident_without_notification_adds_nothing(admin):
    prepare(admin)
    observe('change-1')
    with Session() as s:
        s.query(notifications.NotificationRevision).delete()
        s.query(notifications.NotificationArrival).delete()
        s.query(notifications.NotificationEvent).delete()
        s.commit()
    review(admin, 'resolved')
    assert items(admin) == [] and revisions() == 0


def test_rolled_back_detection_announces_nothing(admin):
    prepare(admin)
    with Session() as s:
        incidents.record_inspection(s, 'baseline-host', 'change-1', receipt(changed()))
        s.rollback()
    assert items(admin) == [] and revisions() == 0


def test_viewer_and_operator_do_not_see_startup_notifications(admin):
    from app.identity import User
    prepare(admin)
    observe('change-1')
    with Session() as s:
        s.add(User(username='viewer', password='x', role='viewer'))
        s.add(User(username='operator', password='x', role='operator'))
        s.commit()
        for username in ('viewer', 'operator'):
            assert notifications.list_for_user(s, username) == []
            assert notifications.unread_count(s, username) == 0


def test_server_deletion_resolves_active_startup_notifications(admin):
    prepare(admin)
    observe('change-1')
    record = admin.get('/api/hosts/baseline-host/summary').json()['host']
    response = admin.request('DELETE', '/api/hosts/baseline-host', json={
        'confirmation': record['name'], 'expected_revision': record['lifecycle_revision'],
        'reason': 'Remove management after reviewing operations and retained records.'})
    assert response.status_code == 200, response.text
    [item] = items(admin)
    assert item['lifecycle'] == 'resolved' and item['revision'] == 2 and 'deleted' in item['reason']
    with Session() as s:
        assert s.get(incidents.PersistenceIncident, item['subject_id']).state == 'open'
    # Re-running the resolution is idempotent.
    with Session() as s:
        persistence.resolve_host_notifications(s, 'baseline-host')
        s.commit()
    assert revisions() == 2
