"""Durable notification arrival cursor (#668)."""
import time

import pytest
from sqlalchemy import select

from app import notifications
from app.db import Session
from app.identity import User
from app.security import password_hash


PASSWORD = 'notification-arrival-password'


def add_user(username, role):
    with Session() as session:
        session.add(User(username=username, password=password_hash(PASSWORD), role=role))
        session.commit()


def login(client, username):
    result = client.post('/api/login', json={'username': username, 'password': PASSWORD})
    assert result.status_code == 200
    client.headers['X-CSRF-Token'] = result.json()['csrf']


def publish(session, subject_id, minimum_role='viewer', now=1000, **changes):
    values = {
        'source': 'operations', 'kind': 'attention', 'subject_type': 'job',
        'subject_id': subject_id, 'subject_revision': 'revision-1',
        'severity': 'critical', 'reason': 'A bounded fixture needs human attention.',
        'deep_link': '#/operations?job=' + subject_id,
        'minimum_role': minimum_role, 'now': now,
    }
    values.update(changes)
    event, created = notifications.publish(session, **values)
    return event


def baseline(client):
    result = client.get('/api/notifications/arrivals')
    assert result.status_code == 200
    body = result.json()
    assert body['items'] == [] and body['more'] is False and body['reset'] is False
    return body['cursor']


def test_publish_appends_one_arrival_per_created_revision(admin):
    with Session() as session:
        event = publish(session, 'job-1')
        publish(session, 'job-1')  # identical observation: no new revision
        publish(session, 'job-1', subject_revision='revision-2')
        session.commit()
        rows = session.execute(select(
            notifications.NotificationArrival.event_id,
            notifications.NotificationArrival.revision)
            .order_by(notifications.NotificationArrival.seq)).all()
    assert rows == [(event.id, 1), (event.id, 2)]


def test_new_arrival_is_found_despite_lagging_timestamp_and_large_backlog(admin):
    """Both failures reproduced on #662: >100 newer unread items and a lagging producer."""
    add_user('reader', 'viewer')
    with Session() as session:
        for index in range(105):
            publish(session, f'old-{index}', now=5000 + index)
        session.commit()
    login(admin, 'reader')
    cursor = baseline(admin)
    with Session() as session:
        late = publish(session, 'late-critical', now=1)  # oldest timestamp of all
        session.commit()
        late_id = late.id
    # The ordinary list cannot surface it: it sorts below 105 newer unread items.
    page = admin.get('/api/notifications?unread_only=true&severity=critical&limit=100').json()
    assert late_id not in {item['id'] for item in page['items']}
    body = admin.get(f'/api/notifications/arrivals?after={cursor}').json()
    assert [item['id'] for item in body['items']] == [late_id]
    item = body['items'][0]
    assert item['revision'] == 1 and item['severity'] == 'critical'
    assert item['read'] is False and item['arrival'] == body['cursor'] > cursor
    again = admin.get(f"/api/notifications/arrivals?after={body['cursor']}").json()
    assert again == {'items': [], 'cursor': body['cursor'], 'more': False, 'reset': False}


def test_current_role_filter_and_superseded_revisions_still_advance_cursor(admin):
    add_user('reader', 'viewer')
    login(admin, 'reader')
    cursor = baseline(admin)
    with Session() as session:
        publish(session, 'operator-only', 'operator')
        changed = publish(session, 'changed')
        publish(session, 'changed', subject_revision='revision-2', severity='high')
        session.commit()
        changed_id = changed.id
        latest = session.scalar(select(notifications.NotificationArrival.seq)
                                .order_by(notifications.NotificationArrival.seq.desc()).limit(1))
    body = admin.get(f'/api/notifications/arrivals?after={cursor}').json()
    assert [(item['id'], item['revision'], item['severity']) for item in body['items']] == [
        (changed_id, 2, 'high')]
    assert body['cursor'] == latest and body['more'] is False

    # Role changes take effect immediately; the operator-only arrival becomes visible.
    with Session() as session:
        session.get(User, 'reader').role = 'operator'
        session.commit()
    login(admin, 'reader')
    visible = admin.get(f'/api/notifications/arrivals?after={cursor}').json()
    assert {item['subject_id'] for item in visible['items']} == {'operator-only', 'changed'}


def test_pagination_returns_more_and_resumes_without_loss(admin):
    add_user('reader', 'viewer')
    login(admin, 'reader')
    cursor = baseline(admin)
    with Session() as session:
        ids = [publish(session, f'job-{index}').id for index in range(7)]
        session.commit()
    seen = []
    for _ in range(4):
        body = admin.get(f'/api/notifications/arrivals?after={cursor}&limit=3').json()
        seen += [item['id'] for item in body['items']]
        cursor = body['cursor']
        if not body['more']:
            break
    assert seen == ids


def test_read_and_dismissed_state_is_reported_not_filtered(admin):
    add_user('reader', 'viewer')
    login(admin, 'reader')
    cursor = baseline(admin)
    with Session() as session:
        event = publish(session, 'job-read')
        session.commit()
        notifications.dismiss(session, 'reader', event.id, 1)
        session.commit()
    item = admin.get(f'/api/notifications/arrivals?after={cursor}').json()['items'][0]
    assert item['read'] is True and item['dismissed'] is True


def test_gap_is_held_until_settled(admin):
    """A lower in-flight (or rolled-back) sequence must not be skipped immediately."""
    with Session() as session:
        session.add(User(username='reader', password='x', role='viewer'))
        first = publish(session, 'first')
        session.commit()
        cursor = session.scalar(select(notifications.NotificationArrival.seq))
        # Simulate a committed later arrival while cursor+1 is still uncommitted.
        later = publish(session, 'later')
        session.flush()
        row = session.scalar(select(notifications.NotificationArrival)
                             .where(notifications.NotificationArrival.event_id == later.id))
        row.seq = cursor + 2
        session.commit()
        now = row.created + 1
        held = notifications.arrivals_for_user(session, 'reader', after=cursor, now=now)
        assert held == {'items': [], 'cursor': cursor, 'more': False, 'reset': False}
        # A fresh baseline also stays before the unsettled gap.
        assert notifications.arrivals_for_user(session, 'reader', now=now)['cursor'] == cursor

        # The missing sequence commits late: it is returned before the later one.
        missing = publish(session, 'missing')
        session.flush()
        row_missing = session.scalar(select(notifications.NotificationArrival)
                                     .where(notifications.NotificationArrival.event_id == missing.id))
        row_missing.seq = cursor + 1
        session.commit()
        filled = notifications.arrivals_for_user(session, 'reader', after=cursor, now=now)
        assert [item['subject_id'] for item in filled['items']] == ['missing', 'later']
        assert filled['cursor'] == cursor + 2
        assert first.id not in {item['id'] for item in filled['items']}


def test_rolled_back_gap_is_skipped_after_hold(admin):
    with Session() as session:
        session.add(User(username='reader', password='x', role='viewer'))
        publish(session, 'first')
        session.commit()
        cursor = session.scalar(select(notifications.NotificationArrival.seq))
        later = publish(session, 'later')
        session.flush()
        row = session.scalar(select(notifications.NotificationArrival)
                             .where(notifications.NotificationArrival.event_id == later.id))
        row.seq = cursor + 5
        session.commit()
        now = row.created + notifications.ARRIVAL_GAP_HOLD_SECONDS + 1
        settled = notifications.arrivals_for_user(session, 'reader', after=cursor, now=now)
        assert [item['subject_id'] for item in settled['items']] == ['later']
        assert settled['cursor'] == cursor + 5


def test_cursor_beyond_retained_sequence_resets_to_baseline(admin):
    add_user('reader', 'viewer')
    login(admin, 'reader')
    current = baseline(admin)
    body = admin.get(f'/api/notifications/arrivals?after={current + 1000}').json()
    assert body == {'items': [], 'cursor': current, 'more': False, 'reset': True}


@pytest.mark.parametrize('query', ['after=-1', 'after=x', 'limit=0', 'limit=101'])
def test_invalid_cursor_or_limit_is_rejected(admin, query):
    assert admin.get('/api/notifications/arrivals?' + query).status_code in (400, 422)


def test_arrivals_require_sign_in(client):
    assert client.get('/api/notifications/arrivals').status_code == 401


def test_arrival_time_does_not_trust_producer_timestamp(admin):
    with Session() as session:
        publish(session, 'skewed', now=1)
        session.commit()
        row = session.scalar(select(notifications.NotificationArrival))
    assert abs(row.created - time.time()) < 60
