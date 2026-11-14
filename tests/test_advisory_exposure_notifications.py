"""In-app notifications when a stored advisory scan shows version-affected advisories (#822)."""
import time

from sqlalchemy import func, select

from app import advisory_exposure_notifications as exposure, notifications, operations
from app.db import Host, Session, Setting

HOST = 'ax'
STATUS = ('Package: openssl\nArchitecture: amd64\nVersion: {openssl}\nStatus: install ok installed\n\n'
          'Package: libssl3\nArchitecture: amd64\nSource: openssl ({openssl})\nVersion: {openssl}\n'
          'Status: install ok installed\n\n'
          'Package: curl\nArchitecture: amd64\nVersion: 7.88.1-10\nStatus: install ok installed\n')


def row(advisory, status='affected', fix=True, reason='Installed version is inside a vendor range'):
    return {'advisory_id': advisory, 'cve_ids': [], 'status': status, 'reason': reason,
            'fixed_version': '3.0.12-1' if fix else None, 'fix_available': fix}


def item(binary, source, version, *rows):
    return {'binary': binary, 'package': {'ecosystem': 'Debian:12', 'name': source}, 'version': version,
            'vulnerabilities': [{'id': r.get('advisory_id')} for r in rows if isinstance(r, dict)], 'applicability': list(rows)}


def seed(results=None, openssl='3.0.11-1', now=None, **fields):
    now = time.time() if now is None else now
    with Session() as s:
        host = s.get(Host, HOST)
        if not host:
            host = Host(id=HOST, name='advisory target', address='192.0.2.50', fingerprint='test', state='online')
            s.add(host)
        host.last_seen = now
        host.inventory = {'status': STATUS.format(openssl=openssl), 'package_manager': 'apt'}
        for key, value in fields.items():
            setattr(host, key, value)
        if results is not None:
            s.merge(Setting(key='advisories:' + HOST, value={'checked': now, 'ecosystem': 'Debian:12',
                                                             'results': results, 'summary': {}}))
        s.commit()
    return now


def collect(now):
    operations.collect_alerts(now=now)


def items(client):
    response = client.get('/api/notifications', params={'source': exposure.SOURCE, 'include_dismissed': True})
    assert response.status_code == 200, response.text
    return response.json()['items']


def revisions():
    with Session() as s:
        return s.scalar(select(func.count()).select_from(notifications.NotificationRevision).join(
            notifications.NotificationEvent,
            notifications.NotificationEvent.id == notifications.NotificationRevision.event_id).where(
            notifications.NotificationEvent.source == exposure.SOURCE))


AFFECTED = [item('libssl3:amd64', 'openssl', '3.0.11-1', row('DSA-1'), row('CVE-2024-0002', fix=False)),
            item('openssl:amd64', 'openssl', '3.0.11-1', row('DSA-1'))]


def test_no_scan_or_no_affected_rows_publish_nothing(admin):
    now = seed()
    collect(now)
    now = seed([item('curl:amd64', 'curl', '7.88.1-10', row('DSA-9', status='fixed'),
                     row('DSA-8', status='unaffected'), row('DSA-7', status='uncertain'))])
    collect(now)
    assert items(admin) == []


def test_affected_scan_opens_one_admin_notification_with_counts_only(admin):
    hostile = item('openssl:amd64', 'openssl', '3.0.11-1',
                   row('DSA-3', reason='<script>alert(1)</script> endpoint text'), row('bad id <b>'))
    now = seed(AFFECTED + [hostile, item('curl:amd64', 'curl', '7.88.1-10', row('DSA-7', status='uncertain'))])
    collect(now)
    [entry] = items(admin)
    assert entry['kind'] == exposure.KIND and entry['subject_type'] == 'server' and entry['subject_id'] == HOST
    assert entry['severity'] == 'medium' and entry['lifecycle'] == 'active'
    assert entry['deep_link'] == '#servers/ax/patching'
    text = entry['reason']
    assert '4 advisory matches' in text and '2 packages' in text and '3 of these name a vendor fix' in text
    assert '1 uncertain result ' in text and 'not evidence of exploitation' in text
    for leaked in ('<script>', 'DSA-', 'CVE-', 'openssl', 'libssl3', 'endpoint text', 'bad id'):
        assert leaked not in text
    with Session() as s:
        assert s.get(notifications.NotificationEvent, entry['id']).minimum_role == 'admin'
    collect(now + 30)
    seed(AFFECTED + [hostile, item('curl:amd64', 'curl', '7.88.1-10', row('DSA-7', status='uncertain'))])
    collect(now + 60)  # identical rescan: no flood
    assert revisions() == 1


def test_new_affected_advisory_resurfaces_and_patching_resolves(admin):
    now = seed(AFFECTED)
    collect(now)
    [entry] = items(admin)
    assert admin.post('/api/notifications/' + entry['id'] + '/read', json={'revision': entry['revision']}
                      ).status_code == 200
    now = seed(AFFECTED + [item('openssl:amd64', 'openssl', '3.0.11-1', row('DSA-4'))])
    collect(now)
    [entry] = items(admin)
    assert entry['revision'] == 2 and not entry['read'] and '4 advisory matches' in entry['reason']
    now = seed(openssl='3.0.12-1')  # patched: stored rows describe a version no longer installed
    collect(now)
    [entry] = items(admin)
    assert entry['lifecycle'] == 'resolved' and entry['severity'] == 'info' and entry['revision'] == 3
    assert entry['reason'] == exposure.RESOLVED and 'not a clean-host verdict' in entry['reason']
    collect(now + 1)
    assert revisions() == 3
    now = seed(openssl='3.0.11-1')  # downgraded back to the scanned version
    collect(now)
    [entry] = items(admin)
    assert entry['lifecycle'] == 'active' and entry['revision'] == 4


def test_clean_rescan_resolves_and_unreadable_inventory_does_not(admin):
    now = seed(AFFECTED)
    collect(now)
    with Session() as s:
        s.get(Host, HOST).inventory = {}
        s.commit()
    collect(now + 1)
    assert items(admin)[0]['lifecycle'] == 'active'  # cannot tell whether it was patched: keep it
    now = seed([item('openssl:amd64', 'openssl', '3.0.11-1', row('DSA-1', status='fixed'))])
    collect(now)
    assert items(admin)[0]['lifecycle'] == 'resolved'


def test_disabled_enrolling_and_deleted_servers_resolve(admin):
    for change in ({'enabled': False}, {'state': 'enrolling'}, {'deleted_at': 1.0}):
        now = seed(AFFECTED, enabled=True, state='online', deleted_at=0.0)
        collect(now)
        assert items(admin)[0]['lifecycle'] == 'active', change
        now = seed(**change)
        collect(now)
        assert items(admin)[0]['lifecycle'] == 'resolved', change


def test_notifications_are_hidden_from_viewers_and_operators(admin):
    from app.identity import User
    collect(seed(AFFECTED))
    with Session() as s:
        s.add_all([User(username='adv-viewer', password='x', role='viewer'),
                   User(username='adv-operator', password='x', role='operator')])
        s.commit()
        assert notifications.unread_count(s, 'adv-viewer') == 0
        assert notifications.unread_count(s, 'adv-operator') == 0
        assert notifications.unread_count(s, 'admin') >= 1


def test_producer_is_read_only_and_a_rejected_payload_never_blocks_alerts(admin, monkeypatch):
    now = seed(AFFECTED)
    with Session() as s:
        before = s.get(Setting, 'advisories:' + HOST).value
    collect(now)
    with Session() as s:
        assert s.get(Setting, 'advisories:' + HOST).value == before
        assert not any(alert.kind == exposure.KIND for alert in s.scalars(select(operations.Alert)))

    def reject(*args, **kwargs):
        raise ValueError('rejected')
    monkeypatch.setattr(exposure.notifications, 'publish', reject)
    with Session() as s:
        s.get(Host, HOST).repo_error = 'mirror unreachable'
        s.commit()
    collect(now + 1)
    with Session() as s:
        assert s.scalar(select(operations.Alert).where(operations.Alert.host_id == HOST,
                                                       operations.Alert.kind == 'repository')).state == 'open'


def test_exposure_ignores_malformed_rows_and_keeps_rows_without_inventory():
    assert exposure.exposure(None, {}) == (set(), 0)
    assert exposure.exposure({'results': 'x'}, {}) == (set(), 0)
    malformed = {'results': [1, {'binary': 'a:amd64'}, {'binary': 'a:amd64', 'package': 'x', 'version': '1',
                                                        'applicability': [row('DSA-1')]},
                             item('a:amd64', 'a', '1', 'not-a-row', row(None), row('x' * 200))]}
    assert exposure.exposure(malformed, {'a:amd64': ('a', '1')}) == (set(), 0)
    current = {'results': [item('a:amd64', 'a', '1', row('DSA-1'))]}
    assert len(exposure.exposure(current, None)[0]) == 1
    assert exposure.exposure(current, {})[0] == set()
    assert exposure.installed_sources({'package_manager': 'rpm', 'status': ''}) is None
    assert exposure.installed_sources({'status': STATUS.format(openssl='1-1')})['libssl3:amd64'] == (
        'openssl', '1-1')
