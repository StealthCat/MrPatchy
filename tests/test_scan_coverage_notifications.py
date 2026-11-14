"""In-app notifications when scheduled malware scanning has no current conclusion (#816)."""
import time

from sqlalchemy import func, select

from app import notifications, operations
from app import scan_coverage_notifications as coverage
from app.db import Host, Job, Session, Setting
from app.incidents import Scan

HOST = 'sc'
HOUR = 3600


def report(**changes):
    now = time.time()
    return {'engine': 'ClamAV', 'state': 'no_detections', 'available': True, 'scanned': 3, 'findings': [],
            'roots': ['/srv'], 'gaps': [], 'signatures': {'state': 'recent', 'built_at': now, 'expires': now + HOUR},
            **changes}


def seed(*, enabled=True, interval=24, **fields):
    with Session() as s:
        host = s.get(Host, HOST)
        if not host:
            host = Host(id=HOST, name='scan target', address='192.0.2.50', fingerprint='test', state='online')
            s.add(host)
        host.last_seen = time.time()
        for key, value in fields.items():
            setattr(host, key, value)
        setting = s.get(Setting, 'security-policy:' + HOST)
        value = {'enabled': enabled, 'interval_hours': interval, 'paths': ['/srv']}
        if setting:
            setting.value = value
        else:
            s.add(Setting(key='security-policy:' + HOST, value=value))
        s.commit()


def scan(job_id, state='complete', age=60.0, receipt=True, **changes):
    now = time.time()
    with Session() as s:
        s.add(Job(id=job_id, host_id=HOST, action='security-scan', state=state, created=now - age,
                  payload={'paths': ['/srv'], 'scheduled': True}))
        if receipt and state == 'complete':
            s.add(Scan(id=job_id, host_id=HOST, created=now - age, report=report(**changes)))
        s.commit()


def collect(now=None):
    operations.collect_alerts(now=time.time() if now is None else now)


def items(client):
    response = client.get('/api/notifications', params={'source': coverage.SOURCE, 'include_dismissed': True})
    assert response.status_code == 200, response.text
    return [item for item in response.json()['items'] if item['kind'] == coverage.KIND]


def revisions():
    with Session() as s:
        return s.scalar(select(func.count()).select_from(notifications.NotificationRevision).join(
            notifications.NotificationEvent,
            notifications.NotificationEvent.id == notifications.NotificationRevision.event_id).where(
            notifications.NotificationEvent.source == coverage.SOURCE,
            notifications.NotificationEvent.kind == coverage.KIND))


def test_recorded_pending_and_never_scanned_publish_nothing(admin):
    seed()
    collect()  # policy enabled, scheduler has not started yet
    scan('ok')
    collect()
    scan('next', state='running', age=1)
    collect()
    assert items(admin) == []


def test_failed_scheduled_scan_opens_one_admin_notification_without_endpoint_text(admin):
    seed()
    scan('ok', age=2 * HOUR)
    with Session() as s:
        s.add(Job(id='bad', host_id=HOST, action='security-scan', state='failed', created=time.time() - 60,
                  payload={'paths': ['/srv/<script>'], 'scheduled': True}, output='clamd: /srv/<script>secret'))
        s.commit()
    collect()
    [item] = items(admin)
    assert item['subject_type'] == 'server' and item['subject_id'] == HOST and item['host_id'] == HOST
    assert item['severity'] == 'medium' and item['lifecycle'] == 'active'
    assert item['deep_link'] == '#servers/sc/security'
    assert item['reason'] == coverage.MESSAGES['failed'] and 'not a clean-host' in item['reason']
    assert '<script>' not in item['reason'] and 'clamd' not in item['reason']
    with Session() as s:
        assert s.get(notifications.NotificationEvent, item['id']).minimum_role == 'admin'
    collect(time.time() + 30)  # unchanged category: no flood
    collect(time.time() + 60)
    assert revisions() == 1


def test_incomplete_receipts_publish_incomplete():
    for changes in ({'gaps': ['/srv/huge skipped']}, {'available': False},
                    {'signatures': {'state': 'recent', 'built_at': 0}}):
        s = type('Scan', (), {'id': 'j', 'created': time.time(), 'report': report(**changes)})()
        attempt = type('Job', (), {'id': 'j', 'state': 'complete', 'created': s.created})()
        assert coverage.classify(s, attempt, {'interval_hours': 24}, time.time()) == 'incomplete', changes
    attempt = type('Job', (), {'id': 'lost', 'state': 'complete', 'created': time.time()})()
    assert coverage.classify(None, attempt, {}, time.time()) == 'incomplete'  # receipt missing


def test_overdue_uses_interval_plus_grace(admin):
    seed(interval=1)
    scan('old', age=HOUR + coverage.GRACE_SECONDS - 120)
    collect()
    assert items(admin) == []  # overdue on the coverage page, but within the grace period
    collect(time.time() + 300)
    [item] = items(admin)
    assert item['reason'] == coverage.MESSAGES['overdue'] and item['lifecycle'] == 'active'


def test_category_change_revision_pending_hold_recovery_and_reopen(admin):
    seed()
    scan('bad', state='failed', age=3 * HOUR)
    collect()
    scan('partial', age=2 * HOUR, gaps=['limit'])
    collect()
    [item] = items(admin)
    assert item['revision'] == 2 and item['reason'] == coverage.MESSAGES['incomplete']
    scan('retry', state='queued', age=HOUR)
    collect()
    [item] = items(admin)
    assert item['revision'] == 2 and item['lifecycle'] == 'active'  # pending keeps the event unchanged
    with Session() as s:
        s.get(Job, 'retry').state = 'complete'
        s.add(Scan(id='retry', host_id=HOST, created=time.time() - HOUR, report=report()))
        s.commit()
    collect()
    [item] = items(admin)
    assert item['revision'] == 3 and item['lifecycle'] == 'resolved' and item['reason'] == coverage.RESOLVED
    scan('again', state='failed', age=60)
    collect()
    [item] = items(admin)
    assert item['revision'] == 4 and item['lifecycle'] == 'active' and item['read'] is False


def test_findings_are_left_to_the_incident_producer(admin):
    seed()
    scan('bad', state='failed', age=HOUR)
    collect()
    with Session() as s:
        s.add(Job(id='found', host_id=HOST, action='security-scan', state='complete', created=time.time() - 60))
        s.add(Scan(id='found', host_id=HOST, created=time.time() - 60, report=report(
            state='completed_with_findings', findings=[{'path': '/srv/x', 'sha256': 'a' * 64}])))
        s.commit()
    collect()
    [item] = items(admin)
    assert item['lifecycle'] == 'resolved'


def test_policy_disabled_server_disabled_enrolling_and_deleted_resolve(admin):
    for change in ({'policy': False}, {'enabled': False}, {'state': 'enrolling'}, {'deleted_at': 1.0}):
        seed(enabled=True)
        with Session() as s:
            host = s.get(Host, HOST)
            host.enabled, host.state, host.deleted_at = True, 'online', 0.0
            s.query(Job).delete()
            s.commit()
        scan('bad', state='failed', age=60)
        collect()
        assert items(admin)[0]['lifecycle'] == 'active', change
        if 'policy' in change:
            seed(enabled=False)
        else:
            with Session() as s:
                for key, value in change.items():
                    setattr(s.get(Host, HOST), key, value)
                s.commit()
        collect()
        assert items(admin)[0]['lifecycle'] == 'resolved', change


def test_hidden_from_viewers_and_operators(admin):
    from app.identity import User
    seed()
    scan('bad', state='failed', age=60)
    collect()
    with Session() as s:
        s.add_all([User(username='scan-viewer', password='x', role='viewer'),
                   User(username='scan-operator', password='x', role='operator')])
        s.commit()
        assert notifications.unread_count(s, 'scan-viewer') == 0
        assert notifications.unread_count(s, 'scan-operator') == 0
        assert notifications.unread_count(s, 'admin') >= 1


def test_read_only_and_rejected_payload_never_blocks_alert_collection(admin, monkeypatch):
    seed()
    scan('bad', state='failed', age=60)
    with Session() as s:
        jobs_before = s.scalar(select(func.count()).select_from(Job))
    collect()
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(Job)) == jobs_before  # never enqueues or retries scans
        assert s.get(Job, 'bad').state == 'failed'
        alerts = {alert.kind for alert in s.scalars(select(operations.Alert).where(operations.Alert.host_id == HOST))}
        assert coverage.KIND not in alerts  # in-app only

    def reject(*args, **kwargs):
        raise ValueError('rejected')
    monkeypatch.setattr(coverage.notifications, 'publish', reject)
    with Session() as s:
        s.get(Host, HOST).last_seen = 0.0
        s.commit()
    collect()
    with Session() as s:
        alert = s.scalar(select(operations.Alert).where(operations.Alert.host_id == HOST,
                                                        operations.Alert.kind == 'stale'))
        assert alert is not None and alert.state == 'open'


def test_scheduler_still_queues_scans_as_before(admin):
    from app import incidents
    seed(interval=1)
    scan('old', age=2 * HOUR)
    collect()
    incidents.schedule_tick()
    with Session() as s:
        queued = s.scalars(select(Job).where(Job.host_id == HOST, Job.state == 'queued')).all()
        assert [job.action for job in queued] == ['security-scan']


def test_stuck_pending_scan_past_interval_plus_grace_publishes_stalled(admin):
    seed(interval=1)
    scan('stuck', state='queued', age=HOUR + coverage.GRACE_SECONDS - 120)
    collect()
    assert items(admin) == []  # a young pending attempt still publishes nothing
    collect(time.time() + 300)
    [item] = items(admin)
    assert item['reason'] == coverage.MESSAGES['stalled'] and item['lifecycle'] == 'active'
    assert item['severity'] == 'medium' and item['deep_link'] == '#servers/' + HOST + '/security'
    for word in ('/srv', 'stuck', 'queued since'):
        assert word not in item['reason']
    collect(time.time() + 600)
    [item] = items(admin)
    assert item['revision'] == 1  # unchanged stalled state adds no revision
    with Session() as s:
        job = s.get(Job, 'stuck')
        assert job.state == 'queued'  # the producer never cancels, retries or recovers the job
        job.state = 'complete'
        s.add(Scan(id='stuck', host_id=HOST, created=time.time(), report=report()))
        s.commit()
    collect()
    [item] = items(admin)
    assert item['revision'] == 2 and item['lifecycle'] == 'resolved' and item['reason'] == coverage.RESOLVED


def test_stuck_running_scan_replaces_overdue_with_one_revision(admin):
    seed()
    scan('old', age=72 * HOUR)
    collect()
    [item] = items(admin)
    assert item['reason'] == coverage.MESSAGES['overdue'] and item['revision'] == 1
    scan('hung', state='running', age=24 * HOUR + coverage.GRACE_SECONDS + 60)
    collect()
    [item] = items(admin)
    assert item['reason'] == coverage.MESSAGES['stalled'] and item['revision'] == 2
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(Job).where(Job.host_id == HOST)) == 2  # nothing enqueued


def test_classify_stalled_boundary_uses_attempt_age():
    now = time.time()
    limit = 24 * HOUR + coverage.GRACE_SECONDS
    for state in ('queued', 'running'):
        young = type('Job', (), {'id': 'p', 'state': state, 'created': now - limit})()
        old = type('Job', (), {'id': 'p', 'state': state, 'created': now - limit - 1})()
        assert coverage.classify(None, young, {'interval_hours': 24}, now) == 'pending'
        assert coverage.classify(None, old, {'interval_hours': 24}, now) == 'stalled'


def policy_value():
    with Session() as s:
        return dict(s.get(Setting, 'security-policy:' + HOST).value)


def put_policy(client, **changes):
    body = {'enabled': True, 'interval_hours': 1, 'paths': ['/srv'], **changes}
    response = client.put('/api/hosts/' + HOST + '/security/policy', json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_policy_save_records_server_managed_enabled_since(admin):
    seed(enabled=False)  # legacy-style stored policy without enabled_since
    before = time.time()
    saved = put_policy(admin, enabled_since=1.0)  # clients cannot choose the clock
    since = saved['enabled_since']
    assert before <= since <= time.time() and policy_value()['enabled_since'] == since
    assert admin.get('/api/hosts/' + HOST + '/security/policy').json()['enabled_since'] == since
    assert put_policy(admin, interval_hours=2)['enabled_since'] == since  # kept while scanning stays enabled
    assert 'enabled_since' not in put_policy(admin, enabled=False)  # removed when disabled
    assert 'enabled_since' not in policy_value()
    assert put_policy(admin)['enabled_since'] > since  # a disabled-to-enabled transition restarts the clock
    seed(enabled=True)  # legacy enabled policy without enabled_since
    assert put_policy(admin)['enabled_since'] >= before  # re-saving starts the clock


def test_never_enqueued_first_scan_publishes_overdue_after_interval_plus_grace(admin):
    from app import incidents
    seed(enabled=False)
    put_policy(admin)  # enabled now, interval 1 hour
    with Session() as s:
        # A recovery-required operation blocks the scheduler from the moment scanning is enabled.
        s.add(Job(id='stuck-op', host_id=HOST, action='install', state='recovery_required', created=time.time(),
                  payload={}))
        s.commit()
    incidents.schedule_tick()
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(Job).where(Job.action == 'security-scan')) == 0
    collect()
    collect(time.time() + HOUR + coverage.GRACE_SECONDS - 60)
    assert items(admin) == []  # within the interval plus grace a new policy publishes nothing
    collect(time.time() + HOUR + coverage.GRACE_SECONDS + 60)
    [item] = items(admin)
    assert item['reason'] == coverage.MESSAGES['overdue'] and item['lifecycle'] == 'active'
    assert item['severity'] == 'medium' and item['deep_link'] == '#servers/' + HOST + '/security'
    collect(time.time() + 3 * HOUR)
    assert items(admin)[0]['revision'] == 1  # unchanged category adds no revision
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(Job).where(Job.action == 'security-scan')) == 0
        assert s.get(Job, 'stuck-op').state == 'recovery_required'  # read-only producer
    scan('first')
    collect()
    [item] = items(admin)
    assert item['lifecycle'] == 'resolved' and item['revision'] == 2


def test_classify_never_scanned_uses_enabled_since_and_ignores_invalid_values():
    now = time.time()
    limit = 24 * HOUR + coverage.GRACE_SECONDS
    assert coverage.classify(None, None, {'interval_hours': 24, 'enabled_since': now - limit}, now) is None
    assert coverage.classify(None, None, {'interval_hours': 24, 'enabled_since': now - limit - 1}, now) == 'overdue'
    for invalid in (None, 'old', True, float('nan'), float('-inf'), now + HOUR, [now - limit - 1]):
        assert coverage.classify(None, None, {'interval_hours': 24, 'enabled_since': invalid}, now) is None
    assert coverage.classify(None, None, {'interval_hours': 24}, now) is None  # legacy policy
