from sqlalchemy import select
from fastapi.testclient import TestClient

from app import notifications
from app.db import Audit, Session, Setting
from app.identity import User
from app.security import password_hash
from app.security import token_hash
from app.main import (_notification_sse, _notification_stream_session,
                      notification_streams)


PASSWORD = 'notification-test-password'


def add_user(username, role):
    with Session() as session:
        session.add(User(username=username, password=password_hash(PASSWORD), role=role))
        session.commit()


def login(client, username):
    result = client.post('/api/login', json={'username': username, 'password': PASSWORD})
    assert result.status_code == 200
    client.headers['X-CSRF-Token'] = result.json()['csrf']


def publish(session, subject_id, minimum_role='viewer', now=100, **changes):
    values = {
        'source': 'operations', 'kind': 'attention', 'subject_type': 'job',
        'subject_id': subject_id, 'subject_revision': 'revision-1',
        'severity': 'high', 'reason': 'A bounded fixture needs human attention.',
        'deep_link': '#/operations?job=' + subject_id,
        'minimum_role': minimum_role, 'now': now,
    }
    values.update(changes)
    event, _ = notifications.publish(
        session, **values)
    return event


def seed_events():
    with Session() as session:
        first = publish(session, 'viewer-first', now=300)
        second = publish(session, 'viewer-second', now=200)
        operator = publish(session, 'operator-only', 'operator', now=100)
        session.commit()
        return first.id, second.id, operator.id


def test_list_count_role_filter_and_pagination_use_authenticated_identity(admin):
    add_user('reader', 'viewer')
    first, second, operator = seed_events()
    login(admin, 'reader')

    count = admin.get('/api/notifications/unread-count')
    assert count.status_code == 200 and count.json() == {'unread': 2}
    page = admin.get('/api/notifications?limit=1&offset=0').json()
    assert page['total'] == 2 and page['more'] is True
    assert page['offset'] == 0 and page['limit'] == 1
    assert [item['id'] for item in page['items']] == [first]
    assert set(page['items'][0]) == {
        'id', 'revision', 'source', 'kind', 'subject_type', 'subject_id',
        'host_id', 'severity', 'reason', 'deep_link', 'lifecycle', 'created',
        'read', 'dismissed'}
    last = admin.get('/api/notifications?limit=1&offset=1').json()
    assert [item['id'] for item in last['items']] == [second]
    assert last['more'] is False and operator not in {item['id'] for item in page['items'] + last['items']}

    assert admin.get('/api/notifications?limit=0').status_code == 400
    assert admin.get('/api/notifications?limit=101').status_code == 400
    assert admin.get('/api/notifications?offset=-1').status_code == 400


def test_list_filters_are_authoritative_and_keep_role_boundaries(admin):
    add_user('reader', 'viewer')
    with Session() as session:
        match = publish(session, 'matching', source='scanner', severity='critical',
                        host_id='host-1', now=400)
        publish(session, 'wrong-source', source='operations', severity='critical',
                host_id='host-1', now=300)
        publish(session, 'wrong-severity', source='scanner', severity='info',
                host_id='host-1', now=200)
        publish(session, 'higher-role', 'operator', source='scanner',
                severity='critical', host_id='host-1', now=100)
        session.commit()
    login(admin, 'reader')

    page = admin.get('/api/notifications?severity=critical&source=scanner&host_id=host-1').json()
    assert page['total'] == 1 and [item['id'] for item in page['items']] == [match.id]
    assert admin.post(f'/api/notifications/{match.id}/read', json={'revision': 1}).status_code == 200
    assert admin.get('/api/notifications?severity=critical&source=scanner&host_id=host-1&unread_only=true').json()['total'] == 0

    for query in ('severity=urgent', 'source=Scanner', 'source=' + 'x' * 41,
                  'host_id=' + 'x' * 37):
        assert admin.get('/api/notifications?' + query).status_code == 400


def test_read_and_dismiss_are_csrf_protected_isolated_and_revision_bound(admin):
    add_user('reader', 'viewer')
    add_user('other-reader', 'viewer')
    first, _, operator = seed_events()
    login(admin, 'reader')
    csrf = admin.headers.pop('X-CSRF-Token')
    assert admin.post(f'/api/notifications/{first}/read', json={'revision': 1}).status_code == 403
    admin.headers['X-CSRF-Token'] = csrf

    read = admin.post(f'/api/notifications/{first}/read', json={'revision': 1})
    assert read.status_code == 200
    assert read.json()['read_revision'] == 1 and read.json()['dismissed_revision'] == 0
    assert admin.get('/api/notifications/unread-count').json() == {'unread': 1}

    dismissed = admin.post(f'/api/notifications/{first}/dismiss', json={'revision': 1})
    assert dismissed.status_code == 200
    assert dismissed.json()['read_revision'] == dismissed.json()['dismissed_revision'] == 1
    assert first not in {item['id'] for item in admin.get('/api/notifications').json()['items']}
    included = admin.get('/api/notifications?include_dismissed=true').json()['items']
    assert next(item for item in included if item['id'] == first)['dismissed'] is True

    # A lower-role account cannot infer that a higher-role event exists.
    assert admin.post(f'/api/notifications/{operator}/read', json={'revision': 1}).status_code == 404
    assert admin.post('/api/notifications/not-an-id/read', json={'revision': 1}).status_code == 404
    assert admin.post(f'/api/notifications/{first}/read', json={'revision': 2}).status_code == 400
    assert admin.post(f'/api/notifications/{first}/read', json={'revision': True}).status_code == 422

    login(admin, 'other-reader')
    assert admin.get('/api/notifications/unread-count').json() == {'unread': 2}
    other = admin.get('/api/notifications?include_dismissed=true').json()['items']
    assert next(item for item in other if item['id'] == first)['dismissed'] is False

    with Session() as session:
        actions = list(session.scalars(select(Audit.action).where(
            Audit.action.in_(['read notification', 'dismiss notification']))
            .order_by(Audit.id)))
        assert actions == ['read notification', 'dismiss notification']


def test_old_tab_revision_does_not_mark_changed_notification_read(admin):
    add_user('reader', 'viewer')
    first, _, _ = seed_events()
    login(admin, 'reader')
    with Session() as session:
        notifications.publish(
            session, source='operations', kind='attention', subject_type='job',
            subject_id='viewer-first', subject_revision='revision-2',
            severity='critical', reason='The condition escalated.',
            deep_link='#/operations?job=viewer-first', minimum_role='viewer', now=400)
        session.commit()

    stale = admin.post(f'/api/notifications/{first}/read', json={'revision': 1})
    assert stale.status_code == 200 and stale.json()['read_revision'] == 1
    rows = admin.get('/api/notifications?unread_only=true').json()['items']
    changed = next(item for item in rows if item['id'] == first)
    assert changed['revision'] == 2 and changed['read'] is False


def test_stream_requires_authentication_and_reports_capacity(admin, monkeypatch):
    with TestClient(admin.app) as anonymous:
        assert anonymous.get('/api/notifications/stream').status_code == 401
    add_user('reader', 'viewer')
    login(admin, 'reader')
    monkeypatch.setattr(notification_streams, 'acquire', lambda: False)
    result = admin.get('/api/notifications/stream')
    assert result.status_code == 429
    assert result.headers['retry-after'] == '3'


def test_stream_session_rechecks_generation_enablement_and_expiry(admin):
    add_user('reader', 'viewer')
    login(admin, 'reader')
    token = admin.cookies.get('mrpatchy')
    key = 'session:' + token_hash(token)
    with Session() as session:
        row = session.get(Setting, key)
        generation = row.value['generation']
        assert _notification_stream_session(session, key, 'reader', generation, 'viewer')
        user = session.get(User, 'reader')
        user.role = 'operator'
        session.commit()
        assert not _notification_stream_session(session, key, 'reader', generation, 'viewer')
        user.role = 'viewer'
        user.generation += 1
        session.commit()
        assert not _notification_stream_session(session, key, 'reader', generation, 'viewer')


def test_stream_frame_contains_only_valid_cursor_and_reconnect_metadata():
    cursor = 'a' * 64
    assert _notification_sse(cursor) == (
        'id: ' + cursor + '\nretry: 3000\nevent: notifications\n'
        'data: {"cursor":"' + cursor + '"}\n\n')
