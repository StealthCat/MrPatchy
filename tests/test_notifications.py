import subprocess
import sys

import pytest
from sqlalchemy import func, select

from app.db import Audit, Session
from app.identity import User
from app import notifications


def users():
    with Session() as session:
        session.add_all([
            User(username='viewer', password='x', role='viewer'),
            User(username='operator', password='x', role='operator'),
            User(username='other', password='x', role='operator'),
        ])
        session.commit()


def publish(session, **changes):
    values = {
        'source': 'operations',
        'kind': 'service-health',
        'subject_type': 'service-watch',
        'subject_id': 'watch-1',
        'subject_revision': 'subject-revision-1',
        'severity': 'high',
        'reason': 'A selected service stopped unexpectedly.',
        'deep_link': '#/servers/host-1/security?watch=watch-1',
        'host_id': 'host-1',
        'minimum_role': 'operator',
        'now': 100,
    }
    values.update(changes)
    return notifications.publish(session, **values)


def test_exact_publication_is_idempotent_and_identity_excludes_display_text(admin):
    users()
    with Session() as session:
        event, created = publish(session)
        event_id = event.id
        assert created and event.revision == 1
        same, created = publish(session)
        assert same.id == event_id and not created and same.revision == 1
        assert session.scalar(select(func.count()).select_from(notifications.NotificationRevision)) == 1

        changed, created = publish(
            session, subject_revision='subject-revision-2', severity='critical',
            reason='The service remains stopped and dependent checks now fail.', now=200)
        assert created and changed.id == event_id and changed.revision == 2
        assert session.scalar(select(func.count()).select_from(notifications.NotificationRevision)) == 2
        history = list(session.scalars(select(notifications.NotificationRevision)
                                       .order_by(notifications.NotificationRevision.revision)))
        assert [item.subject_revision for item in history] == ['subject-revision-1', 'subject-revision-2']
        assert [item.severity for item in history] == ['high', 'critical']
        other_host, created = publish(session, host_id='host-2')
        assert created and other_host.id != event_id


def test_current_role_filters_and_per_user_read_dismiss_are_isolated(admin):
    users()
    with Session() as session:
        event, _ = publish(session)
        session.commit()
        assert notifications.list_for_user(session, 'viewer') == []
        assert notifications.unread_count(session, 'viewer') == 0
        assert notifications.unread_count(session, 'operator') == 1
        assert notifications.unread_count(session, 'other') == 1
        with pytest.raises(PermissionError):
            notifications.mark_read(session, 'viewer', event.id, 1)

        notifications.mark_read(session, 'operator', event.id, 1, now=110)
        session.commit()
        assert notifications.unread_count(session, 'operator') == 0
        assert notifications.unread_count(session, 'other') == 1
        assert notifications.list_for_user(session, 'operator')[0]['read'] is True

        notifications.dismiss(session, 'operator', event.id, 1, now=120)
        session.commit()
        assert notifications.list_for_user(session, 'operator') == []
        assert notifications.list_for_user(session, 'operator', include_dismissed=True)[0]['dismissed'] is True
        assert notifications.list_for_user(session, 'other')[0]['dismissed'] is False
        actions = list(session.scalars(select(Audit.action).order_by(Audit.id)))
        assert actions[-2:] == ['read notification', 'dismiss notification']


def test_filtered_counts_and_pages_share_the_same_permission_boundary(admin):
    users()
    with Session() as session:
        matched, _ = publish(session, source='scanner', severity='critical', host_id='host-1')
        publish(session, source='scanner', severity='info', host_id='host-1', subject_id='other')
        publish(session, source='operations', severity='critical', host_id='host-1', subject_id='source')
        publish(session, source='scanner', severity='critical', host_id='host-2', subject_id='host')
        publish(session, source='scanner', severity='critical', host_id='host-1', subject_id='admin', minimum_role='admin')
        session.commit()
        filters = {'severity': 'critical', 'source': 'scanner', 'host_id': 'host-1'}
        rows = notifications.list_for_user(session, 'operator', **filters)
        assert [row['id'] for row in rows] == [matched.id]
        assert notifications.count_for_user(session, 'operator', **filters) == 1


def test_change_resolve_and_reopen_resurface_after_read_or_dismiss(admin):
    users()
    with Session() as session:
        event, _ = publish(session)
        notifications.dismiss(session, 'operator', event.id, 1)
        resolved, created = publish(
            session, subject_revision='subject-revision-2', lifecycle='resolved',
            severity='info', reason='The service recovered and was verified.', now=200)
        assert created and resolved.revision == 2
        row = notifications.list_for_user(session, 'operator')[0]
        assert row['revision'] == 2 and row['lifecycle'] == 'resolved'
        assert not row['read'] and not row['dismissed']
        notifications.mark_read(session, 'operator', event.id, 2)

        reopened, created = publish(
            session, subject_revision='subject-revision-3', lifecycle='active',
            severity='critical', reason='The selected service failed again.', now=300)
        assert created and reopened.revision == 3
        row = notifications.list_for_user(session, 'operator')[0]
        assert row['revision'] == 3 and row['lifecycle'] == 'active' and not row['read']
        assert notifications.unread_count(session, 'operator') == 1


def test_stale_tab_cannot_mark_a_new_revision_read(admin):
    users()
    with Session() as session:
        event, _ = publish(session)
        publish(session, subject_revision='subject-revision-2', reason='Changed reason.', now=200)
        notifications.mark_read(session, 'operator', event.id, 1)
        session.commit()
        assert notifications.unread_count(session, 'operator') == 1
        notifications.mark_read(session, 'operator', event.id, 2)
        session.commit()
        assert notifications.unread_count(session, 'operator') == 0


def test_role_change_disable_and_future_revision_fail_closed(admin):
    users()
    with Session() as session:
        event, _ = publish(session)
        operator = session.get(User, 'operator')
        operator.role = 'viewer'
        session.commit()
        assert notifications.list_for_user(session, 'operator') == []
        with pytest.raises(PermissionError):
            notifications.dismiss(session, 'operator', event.id, 1)
        operator.role = 'admin'
        operator.enabled = False
        session.commit()
        assert notifications.unread_count(session, 'operator') == 0
        with pytest.raises(PermissionError):
            notifications.mark_read(session, 'operator', event.id, 1)
        operator.enabled = True
        session.commit()
        with pytest.raises(ValueError):
            notifications.mark_read(session, 'operator', event.id, 2)
        with pytest.raises(ValueError):
            notifications.mark_read(session, 'operator', event.id, True)
        session.commit()
        assert session.get(
            notifications.NotificationUserState, (event.id, 'operator')) is None


@pytest.mark.parametrize('change', [
    {'source': 'Operations'},
    {'severity': 'urgent'},
    {'minimum_role': 'owner'},
    {'lifecycle': 'acknowledged'},
    {'deep_link': 'https://example.test/secret'},
    {'deep_link': '//example.test/secret'},
    {'deep_link': '/\\example.test/secret'},
    {'reason': 'x' * 2001},
    {'reason': 'hidden\x00value'},
    {'subject_id': 'x' * 201},
])
def test_public_metadata_is_bounded_and_same_origin(admin, change):
    with Session() as session, pytest.raises(ValueError):
        publish(session, **change)


def test_model_registration_creates_all_notification_tables(admin):
    from sqlalchemy import inspect
    from app.db import engine
    names = set(inspect(engine).get_table_names())
    assert {'notification_events', 'notification_revisions', 'notification_user_state'} <= names


def test_clean_process_model_registration_includes_notifications():
    code = ("from app.db import Base,register_models; register_models(); "
            "assert {'notification_events','notification_revisions',"
            "'notification_user_state'} <= set(Base.metadata.tables)")
    subprocess.run([sys.executable, '-c', code], check=True)
