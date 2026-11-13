"""Admin-only notifications for release plans awaiting a GO/no-go decision (#743)."""
import pytest
from sqlalchemy import select

from app import notifications, plan_notifications, release_notifications, releases
from app.db import Host, Job, Session


NOW = 1_000_000.0


def seed(session, *, host='rel-host', plan_id='rel-1', state='ready', blockers=(), expires=NOW + 3600,
         created=NOW - 600, configs='secret-config-text /etc/ssh/sshd_config'):
    if not session.get(Host, host):
        session.add(Host(id=host, name=host, address='192.0.2.20', fingerprint='test'))
    row = releases.ReleasePlan(id=plan_id, host_id=host, state=state, created=created)
    releases.store(row, {'format': 1, 'host_id': host, 'expires': expires, 'blockers': list(blockers),
                         'configs': [configs], 'reviews': ['AI says GO now']})
    session.add(row)
    session.commit()
    return row


def update(session, plan_id='rel-1', **body):
    row = session.get(releases.ReleasePlan, plan_id)
    state = body.pop('state', None)
    if body:
        plan = releases.body(row)
        plan.update(body)
        releases.store(row, plan)
    if state:
        row.state = state
    session.commit()
    return row


@pytest.fixture(autouse=True)
def fresh_rotation(monkeypatch):
    monkeypatch.setattr(plan_notifications, '_cursors', {})


def revisions(session, plan_id='rel-1'):
    event = session.scalar(select(notifications.NotificationEvent).where(
        notifications.NotificationEvent.source == 'release-plans',
        notifications.NotificationEvent.subject_id == plan_id))
    if event is None:
        return None, []
    rows = list(session.scalars(select(notifications.NotificationRevision).where(
        notifications.NotificationRevision.event_id == event.id).order_by(
        notifications.NotificationRevision.revision)))
    return event, rows


def sync(session, now=NOW):
    result = release_notifications.sync(session, now)
    session.commit()
    return result


def test_ready_plan_publishes_fixed_admin_only_decision_notification(admin):
    with Session() as s:
        row = seed(s)
        assert sync(s) == (1, 0)
        event, rows = revisions(s)
        assert (event.kind, event.subject_type, event.host_id, event.minimum_role) == (
            'release-plan', 'release-plan', 'rel-host', 'admin')
        assert [(r.lifecycle, r.severity, r.subject_revision) for r in rows] == [('active', 'medium', row.digest)]
        assert rows[0].deep_link == '#servers/rel-host/maintenance'
        assert rows[0].reason == release_notifications.PENDING_REASON
        # Plan content, AI review text and configuration paths never reach the payload.
        for text in ('secret-config-text', 'sshd_config', 'AI says'):
            assert text not in rows[0].reason
        # Unchanged plans publish nothing on later passes.
        assert sync(s, NOW + 30) == (0, 0)
        assert len(revisions(s)[1]) == 1


@pytest.mark.parametrize('kwargs', [
    {'state': 'blocked'}, {'state': 'planning'}, {'state': 'declined'}, {'state': 'approved'},
    {'blockers': ['Review/remove APT pinning']}, {'expires': NOW - 1},
])
def test_undecidable_plans_are_never_announced(admin, kwargs):
    with Session() as s:
        seed(s, **kwargs)
        assert sync(s) == (0, 0)
        assert revisions(s) == (None, [])


@pytest.mark.parametrize('field', ['enabled', 'deleted_at'])
def test_inactive_server_plans_are_never_announced(admin, field):
    with Session() as s:
        seed(s)
        host = s.get(Host, 'rel-host')
        setattr(host, field, False if field == 'enabled' else NOW - 5)
        s.commit()
        assert sync(s) == (0, 0)
        assert revisions(s) == (None, [])


@pytest.mark.parametrize('change,outcome', [
    ({'state': 'approved'}, 'approved'),
    ({'state': 'running'}, 'approved'),
    ({'state': 'complete'}, 'approved'),
    ({'state': 'declined'}, 'declined'),
    ({'state': 'planning'}, 'regenerating'),
    ({'state': 'blocked'}, 'blocked'),
    ({'blockers': ['New blocker']}, 'blocked'),
    ({'expires': NOW + 10}, 'expired'),
])
def test_decision_and_lifecycle_changes_resolve_once(admin, change, outcome):
    with Session() as s:
        seed(s)
        assert sync(s) == (1, 0)
        update(s, **change)
        assert sync(s, NOW + 60) == (0, 1)
        _, rows = revisions(s)
        assert [r.lifecycle for r in rows] == ['active', 'resolved']
        assert rows[-1].reason == release_notifications.RESOLVED_REASON[outcome]
        assert rows[-1].severity == 'info' and rows[-1].deep_link == '#servers/rel-host/maintenance'
        assert sync(s, NOW + 90) == (0, 0)


def test_deleted_plan_and_inactive_server_resolve_unavailable(admin):
    with Session() as s:
        seed(s, plan_id='rel-1')
        seed(s, plan_id='rel-2', host='rel-other')
        assert sync(s) == (2, 0)
        s.delete(s.get(releases.ReleasePlan, 'rel-1'))
        s.get(Host, 'rel-other').enabled = False
        s.commit()
        assert sync(s, NOW + 60) == (0, 2)
        for plan_id in ('rel-1', 'rel-2'):
            rows = revisions(s, plan_id)[1]
            assert rows[-1].reason == release_notifications.RESOLVED_REASON['unavailable']


def test_regenerated_plan_resurfaces_with_new_digest(admin):
    with Session() as s:
        first = seed(s).digest
        assert sync(s) == (1, 0)
        # Regenerated in one pass interval: still ready, but a different frozen plan.
        second = update(s, configs=['different proposed config']).digest
        assert second != first
        assert sync(s, NOW + 60) == (1, 0)
        _, rows = revisions(s)
        assert [(r.lifecycle, r.subject_revision) for r in rows] == [('active', first), ('active', second)]
        # Regeneration through planning and back to ready also resurfaces.
        update(s, state='planning')
        assert sync(s, NOW + 90) == (0, 1)
        update(s, state='ready', configs=['third'])
        assert sync(s, NOW + 120) == (1, 0)
        assert revisions(s)[1][-1].lifecycle == 'active'


def test_reconciler_changes_no_plan_or_job_state(admin):
    with Session() as s:
        seed(s)
        sync(s)
        row = update(s, expires=NOW + 10)
        before = (row.state, row.digest, row.encrypted, row.job_id)
        assert sync(s, NOW + 60) == (0, 1)
        s.expire_all()
        row = s.get(releases.ReleasePlan, 'rel-1')
        assert (row.state, row.digest, row.encrypted, row.job_id) == before
        assert s.scalar(select(Job.id)) is None


def test_pending_scan_is_bounded_and_active_scan_rotates(admin, monkeypatch):
    monkeypatch.setattr(release_notifications, 'BATCH', 1)
    monkeypatch.setattr(plan_notifications, 'BATCH', 1)
    with Session() as s:
        for index in range(3):
            seed(s, plan_id='rel-' + str(index), created=NOW - 600 + index)
        # One new plan per pass; announced plans never hold the pending page.
        assert [sync(s, NOW + step)[0] for step in range(3)] == [1, 1, 1]
        for index in range(3):
            update(s, plan_id='rel-' + str(index), state='declined')
        # The active scan rotates, so every event resolves within a bounded number of passes.
        resolved = sum(sync(s, NOW + 10 + step)[1] for step in range(6))
        assert resolved == 3


def test_tick_commits_and_old_plans_beyond_lookback_are_ignored(admin):
    with Session() as s:
        seed(s, plan_id='old', created=NOW - release_notifications.LOOKBACK - 1, expires=NOW + 3600)
    release_notifications.tick(NOW)
    with Session() as s:
        assert revisions(s, 'old') == (None, [])
        seed(s, plan_id='new')
    release_notifications.tick(NOW)
    with Session() as s:
        assert revisions(s, 'new')[1][0].lifecycle == 'active'


def test_admin_notification_api_lists_release_event(admin, client):
    with Session() as s:
        seed(s)
        sync(s)
    data = client.get('/api/notifications').json()
    items = data.get('items', data) if isinstance(data, dict) else data
    assert any(item.get('source') == 'release-plans' for item in items)
