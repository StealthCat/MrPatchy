"""In-app notifications published from human-attention operational alerts."""
import re
import time
from pathlib import Path
from sqlalchemy import select
from app import notifications, operations
from app.db import Host, Job, Session, Setting
from app.identity import User

HOST = '6f1c2a54-0d1e-4b4e-9e43-5a7d2f0c9b11'
OTHER = '0a9b8c7d-6e5f-4a3b-8c2d-1e0f9a8b7c6d'


def add_host(host_id=HOST, **values):
    with Session() as s:
        values = {'last_seen': time.time() + 3600, **values}
        s.add(Host(id=host_id, name='Notify ' + host_id[:4], address='example', fingerprint='pinned',
                   state='online', **values))
        s.commit()


def add_job(job_id, host_id=HOST, state='recovery_required'):
    with Session() as s:
        s.add(Job(id=job_id, host_id=host_id, action='patch', state=state))
        s.commit()


def operational_events(s):
    return s.scalars(select(notifications.NotificationEvent).where(
        notifications.NotificationEvent.source == operations.OPERATIONAL_NOTIFICATION_SOURCE)
        .order_by(notifications.NotificationEvent.kind)).all()


def current(s, event):
    return s.get(notifications.NotificationRevision, (event.id, event.revision))


def test_recovery_alert_publishes_deduplicates_changes_resolves_and_reopens(admin):
    add_host()
    add_job('job-1')
    operations.collect_alerts()
    operations.collect_alerts()
    with Session() as s:
        [event] = operational_events(s)
        revision = current(s, event)
        assert (event.kind, event.subject_type, event.subject_id, event.host_id) == (
            'recovery-required', 'server', HOST, HOST)
        assert event.minimum_role == 'admin' and event.revision == 1
        assert revision.severity == 'high' and revision.lifecycle == 'active'
        assert revision.deep_link == '#servers/' + HOST + '/history'
        alert = s.query(operations.Alert).filter_by(kind='recovery').one()
        assert revision.reason == alert.message and 'job-1' in revision.reason
        assert notifications.unread_count(s, 'admin') == 1
        # Read/dismiss and global acknowledgement stay independent of the producer.
        notifications.mark_read(s, 'admin', event.id, event.revision)
        alert.state = 'acknowledged'
        s.commit()

    operations.collect_alerts()
    with Session() as s:
        [event] = operational_events(s)
        assert event.revision == 1 and notifications.unread_count(s, 'admin') == 0
        assert s.query(operations.Alert).filter_by(kind='recovery').one().state == 'acknowledged'

    add_job('job-2')
    operations.collect_alerts()
    with Session() as s:
        [event] = operational_events(s)
        revision = current(s, event)
        assert event.revision == 2 and revision.lifecycle == 'active' and 'job-2' in revision.reason
        assert notifications.unread_count(s, 'admin') == 1
        for job in s.scalars(select(Job)):
            job.state = 'complete'
        s.commit()

    operations.collect_alerts()
    operations.collect_alerts()
    with Session() as s:
        [event] = operational_events(s)
        revision = current(s, event)
        assert event.revision == 3 and revision.lifecycle == 'resolved' and revision.severity == 'info'
        assert revision.deep_link == '#servers/' + HOST + '/history'
        assert s.query(operations.Alert).filter_by(kind='recovery').one().state == 'resolved'
        s.get(Job, 'job-1').state = 'recovery_required'
        s.commit()

    operations.collect_alerts()
    with Session() as s:
        [event] = operational_events(s)
        revision = current(s, event)
        assert event.revision == 4 and revision.lifecycle == 'active' and revision.severity == 'high'


def test_only_allowlisted_kinds_publish_and_viewers_cannot_see_them(admin):
    # Stale telemetry, raw integrity JSON and repository errors stay outbox-only.
    add_host(last_seen=1, integrity={'path': '/etc/passwd', 'raw': 'endpoint text'},
             repo_error='E: repository https://user:secret@example invalid')
    add_job('job-r')
    with Session() as s:
        s.add(User(username='viewer', password='x', role='viewer'))
        s.commit()
    operations.collect_alerts()
    with Session() as s:
        kinds = {alert.kind for alert in s.query(operations.Alert)}
        assert {'stale', 'integrity', 'repository', 'recovery'} <= kinds
        # Long telemetry silence is reported in-app with fixed text, never as the raw stale alert.
        assert [event.kind for event in operational_events(s)] == ['recovery-required', 'telemetry-lost']
        reasons = ' '.join(row.reason for row in s.scalars(select(notifications.NotificationRevision)))
        assert 'secret' not in reasons and 'endpoint text' not in reasons
        assert notifications.unread_count(s, 'viewer') == 0
        assert notifications.unread_count(s, 'admin') == 2


def test_disabled_and_deleted_servers_resolve_their_notifications(admin):
    add_host()
    add_host(OTHER)
    add_job('job-a', HOST)
    add_job('job-b', OTHER)
    operations.collect_alerts()
    with Session() as s:
        assert {(e.host_id, e.kind) for e in operational_events(s)} == {
            (HOST, 'recovery-required'), (OTHER, 'recovery-required')}
        s.get(Host, HOST).enabled = False
        s.get(Host, OTHER).deleted_at = time.time()
        s.commit()

    operations.collect_alerts()
    with Session() as s:
        states = {(e.host_id, e.kind): current(s, e).lifecycle for e in operational_events(s)}
        # The disabled server keeps a recovery hold, which is reported under its own kind.
        assert states == {
            (HOST, 'recovery-required'): 'resolved',
            (HOST, 'disabled-server-recovery'): 'active',
            (OTHER, 'recovery-required'): 'resolved',
        }
        held = next(e for e in operational_events(s) if e.kind == 'disabled-server-recovery')
        assert current(s, held).deep_link == '#servers/' + HOST + '/security'


def test_invalid_notification_payload_never_blocks_alert_collection(admin, monkeypatch):
    add_host()
    add_job('job-x')

    def reject(*args, **kwargs):
        raise ValueError('Invalid notification reason')
    monkeypatch.setattr(operations, '_operational_notification', reject)
    operations.collect_alerts()
    with Session() as s:
        assert s.query(operations.Alert).filter_by(kind='recovery').one().state == 'open'
        assert operational_events(s) == []


def test_startup_baseline_links_to_the_file_integrity_review_panel(admin):
    # Review finding on #690: the reviewed-baseline panel is rendered by the File integrity
    # tab (serverIntegrity), not File status, so the deep link must open `integrity`.
    add_host()
    with Session() as s:
        # A configured but unverifiable baseline assesses as `unavailable`, which raises the alert.
        s.add(Setting(key='persistence-baseline:' + HOST, value={'id': 'missing'}))
        s.commit()
    operations.collect_alerts()
    with Session() as s:
        [event] = operational_events(s)
        revision = current(s, event)
        assert event.kind == 'startup-baseline' and revision.lifecycle == 'active'
        assert revision.deep_link == '#servers/' + HOST + '/integrity'
        alert = s.query(operations.Alert).filter_by(kind='startup baseline').one()
        assert revision.reason == alert.message and 'File integrity' in alert.message


def test_allowlist_is_well_formed():
    tabs = {'history', 'security', 'patching', 'agent', 'integrity'}
    kinds = [value[0] for value in operations.OPERATIONAL_NOTIFICATIONS.values()]
    assert len(kinds) == len(set(kinds))
    for notification_kind, severity, tab in operations.OPERATIONAL_NOTIFICATIONS.values():
        assert notifications.IDENTIFIER.fullmatch(notification_kind)
        assert severity in notifications.SEVERITIES and tab in tabs
    for excluded in ('stale', 'integrity', 'repository', 'overdue', 'server disabled'):
        assert excluded not in operations.OPERATIONAL_NOTIFICATIONS


def test_allowlisted_tabs_exist_and_baseline_review_lives_on_integrity():
    # Deep links must name a real server tab; the startup-baseline review panel is rendered by the
    # `integrity` view, so its notification must land there and not on `files` (File status).
    source = (Path(__file__).resolve().parents[1] / 'app' / 'static' / 'server.js').read_text()
    server_tabs = set(re.findall(r"\['([a-z]+)','[^']+'(?:,true)?\]", re.search(r'const SERVER_TABS=\[(.*?)\];', source).group(1)))
    assert {'integrity', 'files', 'security', 'history', 'patching', 'agent'} <= server_tabs
    for _, _, tab in operations.OPERATIONAL_NOTIFICATIONS.values():
        assert tab in server_tabs
    views = re.search(r'const views=\{(.*?)\};', source).group(1)
    assert 'integrity:serverIntegrity' in views
    integrity = source[source.index('async function serverIntegrity('):]
    integrity = integrity[:integrity.index('\n}\n')]
    assert 'renderPersistenceBaseline(' in integrity
    assert operations.OPERATIONAL_NOTIFICATIONS['startup baseline'][2] == 'integrity'


def telemetry_events(s):
    return [event for event in operational_events(s) if event.kind == 'telemetry-lost']


def test_telemetry_loss_notifies_once_resolves_and_reopens_without_outbox_alert(admin):
    now = time.time()
    add_host(last_seen=now - operations.TELEMETRY_LOST_SECONDS - 60)
    with Session() as s:
        s.add(User(username='viewer', password='x', role='viewer'))
        s.commit()
    operations.collect_alerts(now)
    operations.collect_alerts(now + 300)
    with Session() as s:
        [event] = telemetry_events(s)
        revision = current(s, event)
        assert (event.subject_type, event.subject_id, event.host_id, event.minimum_role) == (
            'server', HOST, HOST, 'admin')
        assert event.revision == 1 and revision.lifecycle == 'active' and revision.severity == 'high'
        assert revision.deep_link == '#servers/' + HOST + '/agent'
        assert revision.reason == operations.TELEMETRY_LOST_MESSAGE
        assert notifications.unread_count(s, 'viewer') == 0
        # The outbox keeps only the existing stale alert; no new SMTP/webhook kind is introduced.
        kinds = {alert.kind for alert in s.query(operations.Alert)}
        assert 'stale' in kinds and 'telemetry lost' not in kinds
        s.get(Host, HOST).last_seen = now + 400
        s.commit()

    operations.collect_alerts(now + 400)
    with Session() as s:
        [event] = telemetry_events(s)
        assert event.revision == 2 and current(s, event).lifecycle == 'resolved'

    operations.collect_alerts(now + 400 + operations.TELEMETRY_LOST_SECONDS + 60)
    with Session() as s:
        [event] = telemetry_events(s)
        assert event.revision == 3 and current(s, event).lifecycle == 'active'


def test_short_stale_enrolling_and_disabled_servers_do_not_report_telemetry_loss(admin):
    now = time.time()
    add_host(last_seen=now - 300)  # stale for SMTP/webhook, below the in-app threshold
    add_host(OTHER, last_seen=1)
    with Session() as s:
        s.get(Host, OTHER).state = 'enrolling'
        s.commit()
    operations.collect_alerts(now)
    with Session() as s:
        assert telemetry_events(s) == []
        assert s.query(operations.Alert).filter_by(kind='stale', host_id=HOST).count() == 1
        s.get(Host, HOST).last_seen = 1
        s.commit()
    operations.collect_alerts(now)
    with Session() as s:
        [event] = telemetry_events(s)
        assert current(s, event).lifecycle == 'active'
        s.get(Host, HOST).enabled = False
        s.commit()
    operations.collect_alerts(now)
    with Session() as s:
        [event] = telemetry_events(s)
        assert current(s, event).lifecycle == 'resolved'


def test_coordinator_outage_does_not_flood_telemetry_loss_until_observed_for_threshold(admin):
    # After a controller/coordinator outage every server's last_seen is old; the first leader
    # tick runs before asynchronous polls land, so the silence is the coordinator's own gap.
    now = time.time()
    add_host(last_seen=now - 3600)
    add_host(OTHER, last_seen=now - 3600)
    operations.collect_alerts(now, observing_since=now)
    operations.collect_alerts(now + operations.TELEMETRY_LOST_SECONDS, observing_since=now)
    with Session() as s:
        assert telemetry_events(s) == []
        # Polls landed for one server; the other stays silent.
        s.get(Host, OTHER).last_seen = now + operations.TELEMETRY_LOST_SECONDS + 30
        s.commit()
    operations.collect_alerts(now + operations.TELEMETRY_LOST_SECONDS + 60, observing_since=now)
    with Session() as s:
        [event] = telemetry_events(s)
        assert event.subject_id == HOST and current(s, event).lifecycle == 'active'
        assert event.revision == 1


def test_leader_change_keeps_existing_telemetry_loss_active_without_new_revision(admin):
    now = time.time()
    add_host(last_seen=now - 3600)
    operations.collect_alerts(now)
    # A new leader starts observing: the genuine outage stays active rather than resolving and reopening.
    operations.collect_alerts(now + 30, observing_since=now + 30)
    with Session() as s:
        [event] = telemetry_events(s)
        assert event.revision == 1 and current(s, event).lifecycle == 'active'
        s.get(Host, HOST).last_seen = now + 60
        s.commit()
    operations.collect_alerts(now + 60, observing_since=now + 30)
    with Session() as s:
        [event] = telemetry_events(s)
        assert event.revision == 2 and current(s, event).lifecycle == 'resolved'


def test_worker_passes_leadership_start_to_alert_collection():
    source = (Path(__file__).resolve().parents[1] / 'app' / 'worker.py').read_text()
    assert 'if is_leader:leader_since=now' in source
    assert 'operations.collect_alerts(observing_since=leader_since)' in source
