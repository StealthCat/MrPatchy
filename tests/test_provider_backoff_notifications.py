"""In-app notification for a sustained or capped shared AI provider backoff (#696)."""
from types import SimpleNamespace

import pytest

from app import ai_provider_backoff, notifications, operations
from app.db import Session, Setting, config
from app.identity import User

T0 = 1_900_000_000.0
LINK = '#settings/ai'


def configure(enabled=True):
    with Session() as session:
        session.merge(Setting(key='config', value={**config(session), 'ai_enabled': enabled,
                                                    'ai_model': 'gpt-6-luna'}))
        if not session.get(User, 'viewer'):
            session.add(User(username='viewer', password='x', role='viewer'))
        session.commit()


def fail(now, retry_after=0):
    error = SimpleNamespace(transient=True, provider_retry_after=retry_after,
                            body='PROVIDER-SECRET-DETAIL sk-test-1234')
    return ai_provider_backoff.failed(error, now=now)


def event_and_revision():
    with Session() as session:
        events = session.query(notifications.NotificationEvent).filter_by(
            source='ai-provider', kind='provider-backoff').all()
        if not events:
            return None, None
        assert len(events) == 1
        event = events[0]
        revision = session.get(notifications.NotificationRevision, (event.id, event.revision))
        session.expunge_all()
        return event, revision


def test_single_short_backoff_publishes_nothing(admin):
    configure()
    fail(T0)
    operations.collect_alerts(T0 + 1)
    assert event_and_revision() == (None, None)
    ai_provider_backoff.succeeded(now=T0 + 2)
    operations.collect_alerts(T0 + 3)
    assert event_and_revision() == (None, None)


def test_sustained_failures_publish_once_resolve_and_reopen(admin):
    configure()
    for index in range(ai_provider_backoff.SUSTAINED_FAILURES - 1):
        fail(T0 + index)
    operations.collect_alerts(T0 + 10)
    assert event_and_revision() == (None, None)

    fail(T0 + 20)
    operations.collect_alerts(T0 + 21)
    event, revision = event_and_revision()
    assert event.revision == 1 and event.minimum_role == 'admin' and event.host_id == ''
    assert revision.severity == 'medium' and revision.lifecycle == 'active'
    assert revision.deep_link == LINK and revision.subject_revision == 'sustained'
    assert 'PROVIDER-SECRET' not in revision.reason and 'sk-test' not in revision.reason

    # Further failures and passes inside the same episode add no revision.
    fail(T0 + 600)
    fail(T0 + 1800)
    operations.collect_alerts(T0 + 1801)
    operations.collect_alerts(T0 + 1900)
    event, _ = event_and_revision()
    assert event.revision == 1
    with Session() as session:
        assert notifications.unread_count(session, 'admin') == 1
        assert notifications.unread_count(session, 'viewer') == 0
        assert notifications.list_for_user(session, 'viewer') == []
        notifications.mark_read(session, 'admin', event.id, 1, now=T0 + 1901)
        session.commit()

    # A successful provider response resolves it once.
    ai_provider_backoff.succeeded(now=T0 + 2000)
    operations.collect_alerts(T0 + 2001)
    operations.collect_alerts(T0 + 2100)
    event, revision = event_and_revision()
    assert event.revision == 2
    assert revision.lifecycle == 'resolved' and revision.severity == 'info'

    # A later episode reopens it as unread.
    for index in range(ai_provider_backoff.SUSTAINED_FAILURES):
        fail(T0 + 5000 + index)
    operations.collect_alerts(T0 + 5100)
    event, revision = event_and_revision()
    assert event.revision == 3 and revision.lifecycle == 'active' and revision.severity == 'medium'
    with Session() as session:
        assert notifications.unread_count(session, 'admin') == 1


def test_capped_retry_after_is_high_and_escalates_a_sustained_event(admin):
    configure()
    for index in range(ai_provider_backoff.SUSTAINED_FAILURES):
        fail(T0 + index)
    operations.collect_alerts(T0 + 10)
    event, revision = event_and_revision()
    assert event.revision == 1 and revision.severity == 'medium'

    fail(T0 + 20, retry_after=200_000)
    operations.collect_alerts(T0 + 21)
    operations.collect_alerts(T0 + 3600)
    event, revision = event_and_revision()
    assert event.revision == 2
    assert revision.severity == 'high' and revision.subject_revision == 'capped'
    assert revision.lifecycle == 'active' and 'AI Settings' in revision.reason


def test_capped_first_failure_publishes_and_administrator_clear_resolves(admin):
    configure()
    fail(T0, retry_after=200_000)
    operations.collect_alerts(T0 + 1)
    event, revision = event_and_revision()
    assert revision.severity == 'high' and revision.lifecycle == 'active'

    with Session() as session:
        expected = ai_provider_backoff.status(session, T0 + 2)['revision']
    assert ai_provider_backoff.clear(now=T0 + 2, expected_revision=expected)
    operations.collect_alerts(T0 + 3)
    event, revision = event_and_revision()
    assert event.revision == 2 and revision.lifecycle == 'resolved'


def test_idle_episode_and_disabled_ai_resolve(admin):
    configure()
    for index in range(ai_provider_backoff.SUSTAINED_FAILURES):
        fail(T0 + index)
    operations.collect_alerts(T0 + 10)
    assert event_and_revision()[1].lifecycle == 'active'

    # No further attempts within the failure-reset window: the episode ended.
    operations.collect_alerts(T0 + 4 + ai_provider_backoff.FAILURE_WINDOW + 1)
    event, revision = event_and_revision()
    assert event.revision == 2 and revision.lifecycle == 'resolved'

    for index in range(ai_provider_backoff.SUSTAINED_FAILURES):
        fail(T0 + 10_000 + index)
    operations.collect_alerts(T0 + 10_010)
    assert event_and_revision()[1].lifecycle == 'active'
    configure(enabled=False)
    operations.collect_alerts(T0 + 10_020)
    event, revision = event_and_revision()
    assert event.revision == 4 and revision.lifecycle == 'resolved'


@pytest.mark.parametrize('retry_after', [0, 200_000])
def test_disabled_ai_never_publishes(admin, retry_after):
    configure(enabled=False)
    for index in range(ai_provider_backoff.SUSTAINED_FAILURES):
        fail(T0 + index, retry_after=retry_after)
    operations.collect_alerts(T0 + 10)
    assert event_and_revision() == (None, None)


def test_backoff_adds_no_smtp_alert(admin):
    configure()
    fail(T0, retry_after=200_000)
    operations.collect_alerts(T0 + 1)
    with Session() as session:
        assert session.query(operations.Alert).count() == 0
