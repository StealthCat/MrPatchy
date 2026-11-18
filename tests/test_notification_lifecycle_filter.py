"""Notification-center status (current-revision lifecycle) filter — issue #835."""
from app import notifications
from app.db import Session

from tests.test_notification_api import add_user, login, publish


def seed():
    with Session() as session:
        active = publish(session, 'still-open', now=400)
        resolved = publish(session, 'recovered', now=300)
        reopened = publish(session, 'reopened', now=200)
        hidden = publish(session, 'operator-resolved', 'operator', now=100)
        session.flush()
        publish(session, 'recovered', now=310, lifecycle='resolved',
                subject_revision='revision-2', reason='The fixture recovered.')
        publish(session, 'reopened', now=210, lifecycle='resolved',
                subject_revision='revision-2', reason='The fixture recovered.')
        publish(session, 'reopened', now=220, lifecycle='active',
                subject_revision='revision-3', reason='The fixture needs attention again.')
        publish(session, 'operator-resolved', 'operator', now=110, lifecycle='resolved',
                subject_revision='revision-2', reason='The fixture recovered.')
        session.commit()
        return active.id, resolved.id, reopened.id, hidden.id


def ids(page):
    return [item['id'] for item in page['items']]


def test_status_filter_uses_current_revision_and_total(admin):
    add_user('reader', 'viewer')
    active, resolved, reopened, hidden = seed()
    login(admin, 'reader')

    everything = admin.get('/api/notifications').json()
    assert set(ids(everything)) == {active, resolved, reopened} and everything['total'] == 3

    only_active = admin.get('/api/notifications?lifecycle=active').json()
    # A reopened event is filtered by its newest revision, not its history.
    assert ids(only_active) == [active, reopened]
    assert only_active['total'] == 2 and only_active['more'] is False
    assert {item['lifecycle'] for item in only_active['items']} == {'active'}

    only_resolved = admin.get('/api/notifications?lifecycle=resolved').json()
    assert ids(only_resolved) == [resolved] and only_resolved['total'] == 1
    # The operator-only resolved event stays invisible to a viewer.
    assert hidden not in ids(only_resolved)

    paged = admin.get('/api/notifications?lifecycle=active&limit=1&offset=0').json()
    assert ids(paged) == [active] and paged['total'] == 2 and paged['more'] is True

    # The unread badge is not affected by the center filter.
    assert admin.get('/api/notifications/unread-count').json() == {'unread': 3}


def test_status_filter_rejects_unknown_values_with_fixed_text(admin):
    add_user('reader', 'viewer')
    seed()
    login(admin, 'reader')
    for value in ('open', 'RESOLVED', '<b>x</b>', 'active%20'):
        response = admin.get('/api/notifications?lifecycle=' + value)
        assert response.status_code == 400
        assert response.json()['detail'] == 'Invalid notification status filter'


def test_status_filter_combines_with_existing_filters_and_dismissal(admin):
    add_user('operator1', 'operator')
    active, resolved, reopened, hidden = seed()
    login(admin, 'operator1')
    page = admin.get('/api/notifications?lifecycle=resolved').json()
    assert set(ids(page)) == {resolved, hidden}

    with Session() as session:
        event = session.get(notifications.NotificationEvent, hidden)
        notifications.dismiss(session, 'operator1', hidden, event.revision)
        session.commit()
    assert ids(admin.get('/api/notifications?lifecycle=resolved').json()) == [resolved]
    both = admin.get('/api/notifications?lifecycle=resolved&include_dismissed=true').json()
    assert set(ids(both)) == {resolved, hidden}
    assert ids(admin.get('/api/notifications?lifecycle=resolved&severity=critical').json()) == []
    assert admin.get('/api/notifications?lifecycle=resolved&unread_only=true').json()['total'] == 1


def test_module_helpers_validate_status_directly():
    assert notifications.validate_filters(lifecycle='resolved')[3] == 'resolved'
    assert notifications.validate_filters()[3] == ''
    try:
        notifications.validate_filters(lifecycle='closed')
    except ValueError as error:
        assert str(error) == 'Invalid notification status filter'
    else:
        raise AssertionError('invalid lifecycle accepted')
