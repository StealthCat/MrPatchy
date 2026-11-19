"""Every open undelivered alert is listed and counted on Activity → Alert delivery (#1180)."""
from sqlalchemy import select

from app import alert_delivery_notifications, operations
from app.db import Session, Setting

ROUTE = '/api/operations/alert-delivery/pending'


def add_alerts():
    """One old open alert failing delivery, buried under 250 newer alerts of other states."""
    with Session() as s:
        s.add(operations.Alert(id='old-failing', host_id='h', kind='stale', message='private <b>message</b>',
                               state='open', created=1, notified=0, attempts=4, error='ConnectError'))
        s.add(operations.Alert(id='old-trying', host_id='h', kind='repository', message='m',
                               state='open', created=2, notified=0, attempts=1, error='ReadTimeout'))
        for i in range(250):
            state, notified = (('acknowledged', 0) if i % 2 else ('open', 100 + i))
            s.add(operations.Alert(id=f'new-{i:03}', host_id='h', kind='stale', message='m',
                                   state=state, created=1000 + i, notified=notified, attempts=1, error=''))
        s.commit()


def test_old_failing_alert_beyond_the_newest_200_is_listed_and_counted(admin):
    add_alerts()
    recent = admin.get('/api/operations/alerts').json()
    assert 'old-failing' not in {a['id'] for a in recent}  # the legacy list the page used to filter

    data = admin.get(ROUTE).json()
    assert [a['id'] for a in data['items']] == ['old-trying', 'old-failing']  # newest first
    assert (data['total'], data['failing'], data['failed_attempts'], data['offset'], data['limit']) == (2, 1, 3, 0, 50)
    assert all('message' not in a for a in data['items'])
    assert admin.get(ROUTE, params={'offset': 1}).json()['items'][0]['id'] == 'old-failing'


def test_pages_are_bounded_counts_follow_the_saved_threshold_and_nothing_changes(admin):
    with Session() as s:
        for i in range(120):
            s.add(operations.Alert(id=f'p-{i:03}', host_id='h', kind='stale', message='m', state='open',
                                   created=i, notified=0, attempts=i % 6, error='E' if i % 3 else ''))
        s.merge(Setting(key=alert_delivery_notifications.THRESHOLD_KEY, value={'failed_attempts': 5}))
        s.commit()
        before = sorted((a.id, a.state, a.notified, a.attempts, a.attempted) for a in s.scalars(select(operations.Alert)))
    seen = []
    for offset in (0, 50, 100):
        data = admin.get(ROUTE, params={'offset': offset}).json()
        seen += [a['id'] for a in data['items']]
        assert data['total'] == 120 and data['failed_attempts'] == 5
        assert data['failing'] == sum(1 for i in range(120) if i % 6 >= 5 and i % 3)
    assert seen == [f'p-{i:03}' for i in reversed(range(120))]
    assert admin.get(ROUTE, params={'offset': 500}).json()['items'] == []
    assert admin.get(ROUTE, params={'offset': -1}).status_code == 422
    with Session() as s:  # read-only: nothing sent, retried or acknowledged
        assert sorted((a.id, a.state, a.notified, a.attempts, a.attempted) for a in s.scalars(select(operations.Alert))) == before
