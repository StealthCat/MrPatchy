"""Durable notification arrival cursor (#668)."""
import os
import threading
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
            .order_by(notifications.NotificationArrival.id)).all()
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
    body = admin.get(f'/api/notifications/arrivals?after={cursor}').json()
    with Session() as session:
        latest = session.scalar(select(notifications.NotificationArrival.seq)
                                .order_by(notifications.NotificationArrival.seq.desc()).limit(1))
    assert latest == cursor + 3
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


def test_baseline_covers_every_committed_revision_beyond_one_scan_batch(admin):
    """Review finding on 84e860f: 501 recent arrivals left one beyond the baseline."""
    add_user('reader', 'viewer')
    with Session() as session:
        for index in range(notifications.ARRIVAL_SEQUENCE_BATCH + 1):
            publish(session, f'recent-{index}')
        session.commit()
    login(admin, 'reader')
    cursor = baseline(admin)
    assert cursor >= notifications.ARRIVAL_SEQUENCE_BATCH + 1
    again = admin.get(f'/api/notifications/arrivals?after={cursor}').json()
    assert again == {'items': [], 'cursor': cursor, 'more': False, 'reset': False}


def test_unsequenced_arrival_committed_late_is_returned_after_cursor(admin):
    """A producer that commits after a reader advanced is sequenced above it."""
    add_user('reader', 'viewer')
    login(admin, 'reader')
    cursor = baseline(admin)
    with Session() as session:
        first = publish(session, 'first')
        session.commit()
        first_id = first.id
    body = admin.get(f'/api/notifications/arrivals?after={cursor}').json()
    assert [item['id'] for item in body['items']] == [first_id]
    with Session() as session:
        # A lower allocation id than anything sequenced later still cannot be
        # skipped: sequence numbers are assigned at sequencing time.
        late = publish(session, 'late')
        session.commit()
        late_id = late.id
    next_body = admin.get(f"/api/notifications/arrivals?after={body['cursor']}").json()
    assert [item['id'] for item in next_body['items']] == [late_id]
    assert next_body['items'][0]['arrival'] == body['cursor'] + 1


def test_rolled_back_publish_never_appears_and_leaves_no_gap(admin):
    add_user('reader', 'viewer')
    login(admin, 'reader')
    cursor = baseline(admin)
    with Session() as session:
        publish(session, 'rolled-back')
        session.flush()
        session.rollback()
    with Session() as session:
        kept = publish(session, 'kept')
        session.commit()
        kept_id = kept.id
    body = admin.get(f'/api/notifications/arrivals?after={cursor}').json()
    assert [item['id'] for item in body['items']] == [kept_id]
    assert body['items'][0]['arrival'] == cursor + 1 == body['cursor']


def test_concurrent_sequencers_assign_dense_unique_sequence(admin):
    with Session() as session:
        for index in range(40):
            publish(session, f'concurrent-{index}')
        session.commit()
    errors = []

    def run():
        try:
            notifications.sequence_arrivals()
        except Exception as error:  # pragma: no cover - reported below
            errors.append(error)

    workers = [threading.Thread(target=run) for _ in range(6)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert errors == []
    with Session() as session:
        rows = session.execute(select(notifications.NotificationArrival.id,
                                      notifications.NotificationArrival.seq)
                               .order_by(notifications.NotificationArrival.id)).all()
        head = session.get(notifications.NotificationArrivalHead, 1).head
    assert [seq for _, seq in rows] == list(range(1, len(rows) + 1))
    assert head == len(rows) == 40


def test_simultaneous_first_requests_initialize_head_without_error(admin, monkeypatch):
    """Review finding on 7c2740e: two first-use requests deadlocked on MySQL.

    Both requests are held until each has observed the missing head row, then
    both seed it at once.  The old locking-UPDATE-then-INSERT path took gap
    locks and failed one request with MySQL 1213; now the loser re-reads.
    """
    add_user('reader', 'viewer')
    with Session() as session:
        publish(session, 'before-first-use')
        session.commit()
    with Session() as session:
        assert session.get(notifications.NotificationArrivalHead, 1) is None
    both_missing = threading.Barrier(2, timeout=10)
    original_seed = notifications._seed_arrival_head

    def synchronized_seed(session):
        both_missing.wait()
        return original_seed(session)

    monkeypatch.setattr(notifications, '_seed_arrival_head', synchronized_seed)
    results, errors = [], []

    def first_request():
        try:
            with Session() as session:
                results.append(notifications.arrivals_for_user(session, 'reader'))
        except Exception as error:  # pragma: no cover - reported below
            errors.append(error)

    workers = [threading.Thread(target=first_request) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(30)
    assert errors == []
    assert results == [{'items': [], 'cursor': 1, 'more': False, 'reset': False}] * 2
    with Session() as session:
        assert session.get(notifications.NotificationArrivalHead, 1).head == 1
    login(admin, 'reader')
    assert baseline(admin) == 1


@pytest.mark.skipif(not os.getenv('TEST_DATABASE_URL', '').startswith('mysql'),
                    reason='SQLite serializes writers, so commits cannot reorder')
def test_slow_lower_transaction_is_not_skipped_by_faster_higher_commit(admin):
    """Review finding on 84e860f, reproduced on MySQL 8.4 with two writers."""
    add_user('reader', 'viewer')
    login(admin, 'reader')
    cursor = baseline(admin)
    slow_session = Session()
    try:
        slow = publish(slow_session, 'slow')
        slow_session.flush()  # allocated first, still uncommitted
        slow_id = slow.id
        with Session() as session:
            fast = publish(session, 'fast')
            session.commit()
            fast_id = fast.id
        first = admin.get(f'/api/notifications/arrivals?after={cursor}').json()
        assert [item['id'] for item in first['items']] == [fast_id]
        slow_session.commit()
    finally:
        slow_session.close()
    second = admin.get(f"/api/notifications/arrivals?after={first['cursor']}").json()
    assert [item['id'] for item in second['items']] == [slow_id]
    assert second['cursor'] > first['cursor']


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
