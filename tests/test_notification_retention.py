"""Retention of resolved in-app notification history (#787)."""
import pytest
from sqlalchemy import func, select

from app import notifications
from app.db import Session
from app.identity import User
from app.security import password_hash

N = notifications
CUTOFF = 10_000


def publish(session, subject_id, now, lifecycle='active', subject_revision='r1'):
    event, _ = N.publish(
        session, source='operations', kind='attention', subject_type='job',
        subject_id=subject_id, subject_revision=subject_revision,
        severity='info' if lifecycle == 'resolved' else 'high',
        reason='Fixture ' + lifecycle + ' notification.', deep_link='#activity',
        minimum_role='viewer', lifecycle=lifecycle, now=now)
    return event.id


def add_viewer(name='retention-viewer'):
    with Session() as session:
        session.add(User(username=name, password=password_hash('retention-password'), role='viewer'))
        session.commit()
    return name


def revisions(event_id):
    with Session() as session:
        return session.scalars(select(N.NotificationRevision.revision)
                               .where(N.NotificationRevision.event_id == event_id)
                               .order_by(N.NotificationRevision.revision)).all()


def states(event_id):
    with Session() as session:
        return session.scalar(select(func.count()).select_from(N.NotificationUserState)
                              .where(N.NotificationUserState.event_id == event_id))


def test_old_resolved_history_is_pruned_but_active_and_recent_are_kept(admin):
    viewer = add_viewer()
    with Session() as session:
        old_resolved = publish(session, 'old-resolved', 1000)
        publish(session, 'old-resolved', 2000, lifecycle='resolved')
        old_active = publish(session, 'old-active', 1000)
        publish(session, 'old-active', 2000, subject_revision='r2')
        recent_resolved = publish(session, 'recent-resolved', 1000)
        publish(session, 'recent-resolved', CUTOFF + 5, lifecycle='resolved')
        session.commit()
    with Session() as session:
        for event_id in (old_resolved, old_active, recent_resolved):
            N.mark_read(session, viewer, event_id, 1, now=1500)
        session.commit()

    assert N.prune_resolved(CUTOFF) == (1, 2)

    assert revisions(old_resolved) == [] and states(old_resolved) == 0
    assert revisions(old_active) == [1, 2] and states(old_active) == 1
    assert revisions(recent_resolved) == [1, 2] and states(recent_resolved) == 1
    with Session() as session:
        assert session.get(N.NotificationEvent, old_resolved).revision == 2
        listed = {item['id'] for item in N.list_for_user(session, viewer, include_dismissed=True)}
        assert listed == {old_active, recent_resolved}
        assert N.count_for_user(session, viewer, include_dismissed=True) == 2
    # Idempotent: nothing further qualifies.
    assert N.prune_resolved(CUTOFF) == (0, 0)


def test_recurring_subject_continues_revisions_and_is_unread(admin):
    viewer = add_viewer()
    with Session() as session:
        event_id = publish(session, 'recurring', 1000)
        publish(session, 'recurring', 2000, lifecycle='resolved')
        session.commit()
    with Session() as session:
        N.mark_read(session, viewer, event_id, 2, now=2500)
        session.commit()
    N.prune_resolved(CUTOFF)
    with Session() as session:
        cursor = N.arrivals_for_user(session, viewer)['cursor']
    with Session() as session:
        publish(session, 'recurring', CUTOFF + 100)
        session.commit()
    assert revisions(event_id) == [3]
    with Session() as session:
        items = N.list_for_user(session, viewer, unread_only=True)
        assert [(item['id'], item['revision'], item['lifecycle']) for item in items] == [(event_id, 3, 'active')]
        assert N.unread_count(session, viewer) == 1
    with Session() as session:
        arrived = N.arrivals_for_user(session, viewer, after=cursor)['items']
        assert [(item['id'], item['revision']) for item in arrived] == [(event_id, 3)]


def test_rows_written_at_or_after_cutoff_survive_a_racing_prune(admin):
    viewer = add_viewer()
    with Session() as session:
        event_id = publish(session, 'racing', 1000)
        publish(session, 'racing', 2000, lifecycle='resolved')
        session.commit()
    with Session() as session:
        # Read state written after the cutoff, before the prune transaction.
        N.mark_read(session, viewer, event_id, 2, now=CUTOFF + 1)
        session.commit()
    N.prune_resolved(CUTOFF)
    assert revisions(event_id) == [] and states(event_id) == 1


def test_bounded_batches_cover_every_qualifying_event(admin):
    with Session() as session:
        ids = []
        for index in range(7):
            ids.append(publish(session, 'batch-%d' % index, 1000))
            publish(session, 'batch-%d' % index, 2000, lifecycle='resolved')
        session.commit()
    assert N.prune_resolved(CUTOFF, batch=3) == (7, 14)
    assert all(revisions(event_id) == [] for event_id in ids)


def test_invalid_batch_is_rejected():
    with pytest.raises(ValueError):
        N.prune_resolved(CUTOFF, batch=0)


class _ReopenAfterSelection:
    """Session wrapper that commits a reopen from a second session after the
    prune's first (candidate) selection, before it deletes anything."""

    def __init__(self, reopen):
        self.reopen = reopen
        self.selections = 0

    def __call__(self):
        wrapper = self

        class Wrapped:
            def __init__(self):
                self.session = Session()

            def __enter__(self):
                self.session.__enter__()
                return self

            def __exit__(self, *exc):
                return self.session.__exit__(*exc)

            def scalars(self, *args, **kwargs):
                result = self.session.scalars(*args, **kwargs)
                wrapper.selections += 1
                if wrapper.selections == 1:
                    rows = result.all()
                    wrapper.reopen()
                    return _Rows(rows)
                return result

            def __getattr__(self, name):
                return getattr(self.session, name)

        return Wrapped()


class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return self.rows


def test_event_reopened_after_candidate_selection_keeps_its_history(admin):
    with Session() as session:
        event_id = publish(session, 'reopened', 1000)
        publish(session, 'reopened', 2000, lifecycle='resolved')
        stays_resolved = publish(session, 'stays-resolved', 1000)
        publish(session, 'stays-resolved', 2000, lifecycle='resolved')
        session.commit()

    def reopen():
        # A second session reopens the candidate and commits mid-prune.
        with Session() as other:
            publish(other, 'reopened', CUTOFF + 50, subject_revision='r2')
            other.commit()

    factory = _ReopenAfterSelection(reopen)
    assert N.prune_resolved(CUTOFF, factory=factory) == (1, 2)
    assert factory.selections >= 2
    # The now-active event keeps its prior history and the new revision.
    assert revisions(event_id) == [1, 2, 3]
    with Session() as session:
        assert session.get(N.NotificationEvent, event_id).revision == 3
    assert revisions(stays_resolved) == []
