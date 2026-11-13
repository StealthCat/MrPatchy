"""In-app notifications for changed, missing or unbaselined managed agent files (#777)."""
import time

from sqlalchemy import select

from app import agent_integrity_notifications as producer, notifications, operations
from app.db import Host, Session
from app.identity import User

HOST = '3c2b1a09-8f7e-4d6c-9b5a-4f3e2d1c0b9a'
OTHER = '9a8b7c6d-5e4f-4a3b-9c2d-1e0f2a3b4c5d'
AGENT = '/usr/local/libexec/mrpatchy-agent.py'
SUDOERS = '/etc/sudoers.d/mrpatchy'
BASELINE = {AGENT: 'a' * 64, SUDOERS: 'b' * 64}


def changed(path):
    return {'path': path, 'issue': producer.CHANGED}


def metadata(path):
    return {'path': path, 'issue': producer.METADATA}


def add_host(host_id=HOST, integrity=(), baseline=None, **values):
    with Session() as s:
        s.add(Host(id=host_id, name='Agent ' + host_id[:4], address='example', fingerprint='pinned',
                   state='attention', last_seen=time.time() + 3600,
                   baseline=BASELINE if baseline is None else baseline, integrity=list(integrity), **values))
        s.commit()


def set_integrity(integrity, host_id=HOST):
    with Session() as s:
        s.get(Host, host_id).integrity = list(integrity)
        s.commit()


def events(s, kind='agent-integrity'):
    return s.scalars(select(notifications.NotificationEvent).where(
        notifications.NotificationEvent.source == operations.OPERATIONAL_NOTIFICATION_SOURCE,
        notifications.NotificationEvent.kind == kind).order_by(notifications.NotificationEvent.host_id)).all()


def current(s, event):
    return s.get(notifications.NotificationRevision, (event.id, event.revision))


def test_changed_managed_file_publishes_deduplicates_revises_and_resolves(admin):
    add_host(integrity=[changed(AGENT)])
    operations.collect_alerts()
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        revision = current(s, event)
        assert (event.subject_type, event.subject_id, event.host_id, event.revision) == ('server', HOST, HOST, 1)
        assert event.minimum_role == 'admin'
        assert revision.severity == 'high' and revision.lifecycle == 'active'
        assert revision.deep_link == '#servers/' + HOST + '/overview'
        assert '1 managed agent file(s) differ from the enrolled SHA-256' in revision.reason
        assert 'does not repair files or authorize any response' in revision.reason
        # The raw outbox alert is unchanged and still SMTP/webhook-only.
        assert s.query(operations.Alert).filter_by(kind='integrity', host_id=HOST).one().state == 'open'
        assert notifications.unread_count(s, 'admin') == 1

    set_integrity([changed(AGENT), metadata(SUDOERS), metadata(SUDOERS)])
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        revision = current(s, event)
        assert event.revision == 2 and revision.lifecycle == 'active'
        assert '1 managed agent file(s) have changed ownership or permissions' in revision.reason

    set_integrity([])
    operations.collect_alerts()
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        assert event.revision == 3 and current(s, event).lifecycle == 'resolved'

    set_integrity([changed(AGENT)])
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        assert event.revision == 4 and current(s, event).lifecycle == 'active'


def test_missing_baseline_publishes(admin):
    add_host(baseline={}, integrity=[{'path': 'baseline', 'issue': producer.BASELINE}])
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        assert 'baseline recorded at enrollment is missing' in current(s, event).reason


def test_endpoint_text_and_unrelated_findings_never_publish(admin):
    secret = 'endpoint secret text'
    add_host(integrity=[
        # Endpoint-supplied collector text that copies a controller finding string.
        {'path': 'collector', 'issue': producer.CHANGED},
        {'path': '/tmp/' + secret, 'issue': producer.CHANGED},
        {'path': 'collector', 'issue': secret},
        {'path': 'integrity', 'issue': 'Hash sweep is overdue'},
        {'path': 'eBPF', 'issue': secret},
        {'path': 'event spool', 'issue': secret},
        {'path': 'baseline', 'issue': producer.BASELINE},  # Baseline exists, so this is not a controller finding.
        'not a dict', {'path': 7, 'issue': producer.CHANGED},
    ])
    add_host(OTHER, integrity={'path': AGENT, 'issue': producer.CHANGED})  # Malformed non-list value.
    operations.collect_alerts()
    with Session() as s:
        assert events(s) == []
        reasons = ' '.join(r.reason for r in s.scalars(select(notifications.NotificationRevision)))
        assert secret not in reasons


def test_reason_never_contains_paths(admin):
    add_host(integrity=[changed(AGENT), metadata(SUDOERS)])
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        reason = current(s, event).reason
        assert AGENT not in reason and SUDOERS not in reason


def test_viewers_cannot_see_it(admin):
    add_host(integrity=[changed(AGENT)])
    with Session() as s:
        s.add(User(username='viewer', password='x', role='viewer'))
        s.commit()
    operations.collect_alerts()
    with Session() as s:
        assert notifications.unread_count(s, 'viewer') == 0
        assert notifications.unread_count(s, 'admin') == 1


def test_disabled_deleted_and_reenrolling_servers_resolve(admin):
    add_host(integrity=[changed(AGENT)])
    add_host(OTHER, integrity=[changed(AGENT)])
    operations.collect_alerts()
    with Session() as s:
        assert len(events(s)) == 2
        s.get(Host, HOST).enabled = False
        s.get(Host, OTHER).state = 'enrolling'
        s.commit()
    operations.collect_alerts()
    with Session() as s:
        assert {e.host_id: current(s, e).lifecycle for e in events(s)} == {HOST: 'resolved', OTHER: 'resolved'}
        s.get(Host, HOST).enabled = True
        s.get(Host, OTHER).state = 'attention'
        s.commit()
    operations.collect_alerts()
    with Session() as s:
        assert {e.host_id: current(s, e).lifecycle for e in events(s)} == {HOST: 'active', OTHER: 'active'}
        s.get(Host, OTHER).deleted_at = time.time()
        s.commit()
    operations.collect_alerts()
    with Session() as s:
        assert {e.host_id: current(s, e).lifecycle for e in events(s)} == {HOST: 'active', OTHER: 'resolved'}


def test_rejected_payload_keeps_event_active_and_never_blocks_alerts(admin, monkeypatch):
    add_host(integrity=[changed(AGENT)])
    operations.collect_alerts()
    original = operations._operational_notification

    def reject(s, host_id, kind, *args):
        if kind == producer.ALERT_KIND:
            raise ValueError('Invalid notification reason')
        return original(s, host_id, kind, *args)
    monkeypatch.setattr(operations, '_operational_notification', reject)
    set_integrity([changed(AGENT), metadata(SUDOERS)])
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        assert event.revision == 1 and current(s, event).lifecycle == 'active'
        assert s.query(operations.Alert).filter_by(kind='integrity', host_id=HOST).one().state == 'open'
