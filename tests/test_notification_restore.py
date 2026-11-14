"""Per-account restore of a dismissed notification (issue #833)."""
from sqlalchemy import func, select

from app import notifications
from app.db import Audit, Session
from app.identity import User
from app.security import password_hash


PASSWORD = 'notification-restore-password'


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
        'severity': 'critical', 'reason': 'A bounded fixture needs human attention.',
        'deep_link': '#/operations?job=' + subject_id,
        'minimum_role': minimum_role, 'now': now,
    }
    values.update(changes)
    event, _ = notifications.publish(session, **values)
    return event


def restore_audits():
    with Session() as session:
        return session.scalar(select(func.count()).select_from(Audit).where(
            Audit.action == 'restore notification'))


def test_restore_returns_dismissed_item_to_default_history_and_keeps_it_read(admin):
    add_user('reader', 'viewer')
    with Session() as session:
        event = publish(session, 'restore-me')
        notifications.dismiss(session, 'reader', event.id, 1, now=110)
        assert notifications.list_for_user(session, 'reader') == []
        before = notifications.stream_cursor(session, 'reader')

        state = notifications.restore(session, 'reader', event.id, 1, now=120)
        assert state.dismissed_revision == 0 and state.read_revision == 1
        rows = notifications.list_for_user(session, 'reader')
        assert [row['id'] for row in rows] == [event.id]
        assert rows[0]['dismissed'] is False and rows[0]['read'] is True
        # A restored item stays read, so the unread badge does not grow.
        assert notifications.unread_count(session, 'reader') == 0
        # Other tabs of this account see a new cursor and refresh.
        assert notifications.stream_cursor(session, 'reader') != before
        session.commit()
    assert restore_audits() == 1


def test_restore_is_idempotent_and_ignores_stale_or_undismissed_revisions(admin):
    add_user('reader', 'viewer')
    with Session() as session:
        event = publish(session, 'stale')
        # Never dismissed and never touched: no state row is created.
        state = notifications.restore(session, 'reader', event.id, 1)
        assert state.dismissed_revision == 0
        assert session.get(notifications.NotificationUserState, (event.id, 'reader')) is None

        notifications.dismiss(session, 'reader', event.id, 1)
        revised = publish(session, 'stale', subject_revision='revision-2', now=200)
        assert revised.revision == 2
        # The new revision already resurfaced; restoring the old one is a no-op.
        state = notifications.restore(session, 'reader', event.id, 1)
        assert state.dismissed_revision == 1
        notifications.dismiss(session, 'reader', event.id, 2)
        notifications.restore(session, 'reader', event.id, 2)
        again = notifications.restore(session, 'reader', event.id, 2)
        assert again.dismissed_revision == 0
        session.commit()
    assert restore_audits() == 1


def test_restore_only_changes_the_calling_account(admin):
    add_user('reader', 'viewer')
    add_user('other-reader', 'viewer')
    with Session() as session:
        event = publish(session, 'shared')
        notifications.dismiss(session, 'reader', event.id, 1)
        notifications.dismiss(session, 'other-reader', event.id, 1)
        notifications.restore(session, 'reader', event.id, 1)
        assert notifications.list_for_user(session, 'reader')[0]['dismissed'] is False
        assert notifications.list_for_user(session, 'other-reader') == []
        # Global event lifecycle is untouched: restore never acknowledges or resolves.
        assert session.get(notifications.NotificationEvent, event.id).revision == 1
        assert notifications.list_for_user(
            session, 'reader')[0]['lifecycle'] == 'active'


def test_restore_api_is_csrf_protected_role_filtered_and_revision_bound(admin):
    add_user('reader', 'viewer')
    with Session() as session:
        first = publish(session, 'viewer-event').id
        operator = publish(session, 'operator-event', 'operator').id
        session.commit()
    login(admin, 'reader')
    assert admin.post(f'/api/notifications/{first}/dismiss',
                      json={'revision': 1}).status_code == 200
    assert admin.get('/api/notifications').json()['total'] == 0

    csrf = admin.headers.pop('X-CSRF-Token')
    assert admin.post(f'/api/notifications/{first}/restore',
                      json={'revision': 1}).status_code == 403
    admin.headers['X-CSRF-Token'] = csrf

    restored = admin.post(f'/api/notifications/{first}/restore', json={'revision': 1})
    assert restored.status_code == 200
    assert restored.json() == {'id': first, 'revision': 1,
                               'read_revision': 1, 'dismissed_revision': 0}
    page = admin.get('/api/notifications').json()
    assert [item['id'] for item in page['items']] == [first]
    assert admin.get('/api/notifications/unread-count').json() == {'unread': 0}

    # Hidden higher-role events and malformed identifiers stay indistinguishable.
    assert admin.post(f'/api/notifications/{operator}/restore',
                      json={'revision': 1}).status_code == 404
    assert admin.post('/api/notifications/not-an-id/restore',
                      json={'revision': 1}).status_code == 404
    assert admin.post(f'/api/notifications/{first}/restore',
                      json={'revision': 2}).status_code == 400
    assert admin.post(f'/api/notifications/{first}/restore',
                      json={'revision': True}).status_code == 422
    assert restore_audits() == 1
