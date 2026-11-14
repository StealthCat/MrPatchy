"""In-app notifications when a server's verified OS release is past standard support (#341, roadmap J)."""
from datetime import datetime, timezone

from sqlalchemy import func, select

from app import notifications, operations, os_lifecycle_notifications as lifecycle
from app.db import Host, Session

HOST = 'ol'


def ts(value):
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc).timestamp()


NOW = ts('2026-11-04T13:00:00')


def seed(os_release, architecture='amd64', now=NOW, collected_age=60.0, **fields):
    with Session() as s:
        host = s.get(Host, HOST)
        if not host:
            host = Host(id=HOST, name='lifecycle target', address='192.0.2.50', fingerprint='test', state='online')
            s.add(host)
        host.last_seen = now
        host.inventory = {'os': os_release, 'architecture': architecture, 'collected': now - collected_age}
        for key, value in fields.items():
            setattr(host, key, value)
        s.commit()
    return now


def collect(now):
    operations.collect_alerts(now=now)


def items(client):
    response = client.get('/api/notifications', params={'source': lifecycle.SOURCE, 'include_dismissed': True})
    assert response.status_code == 200, response.text
    return response.json()['items']


def revisions():
    with Session() as s:
        return s.scalar(select(func.count()).select_from(notifications.NotificationRevision).join(
            notifications.NotificationEvent, notifications.NotificationEvent.id == notifications.NotificationRevision.event_id).where(
            notifications.NotificationEvent.source == lifecycle.SOURCE))


UBUNTU_2004 = 'ID=ubuntu\nVERSION_ID="20.04"'
UBUNTU_2404 = 'ID=ubuntu\nVERSION_ID="24.04"'
UBUNTU_2610 = 'ID=ubuntu\nVERSION_ID="26.10"'
DEBIAN_12 = 'ID=debian\nVERSION_ID="12"'


def test_supported_releases_publish_nothing(admin):
    collect(seed(UBUNTU_2404))
    collect(seed(DEBIAN_12, 'arm64'))  # verified Debian LTS coverage needs no attention
    assert items(admin) == []


def test_ubuntu_pro_gap_opens_one_admin_notification_from_catalog_text(admin):
    now = seed(UBUNTU_2004 + '\nPRETTY_NAME="<script>endpoint</script>"')
    collect(now)
    [item] = items(admin)
    assert item['kind'] == lifecycle.KIND and item['subject_type'] == 'server' and item['subject_id'] == HOST
    assert item['host_id'] == HOST and item['severity'] == 'medium' and item['lifecycle'] == 'active'
    assert item['deep_link'] == '#servers/ol/overview'
    assert item['reason'].startswith('Ubuntu 20.04 LTS standard support ended on 2025-05-31.')
    assert 'Ubuntu Pro' in item['reason'] and '2030-05-31' in item['reason']
    assert 'not a compromise verdict' in item['reason'] and '<script>' not in item['reason']
    with Session() as s:
        assert s.get(notifications.NotificationEvent, item['id']).minimum_role == 'admin'
    collect(now + 60)  # unchanged observation: no flood
    collect(now + 3600)
    assert revisions() == 1


def test_debian_lts_unverified_architecture_is_medium(admin):
    collect(seed(DEBIAN_12, 's390x'))
    [item] = items(admin)
    assert item['severity'] == 'medium' and 'Debian 12 (bookworm) standard support ended on 2026-07-11' in item['reason']
    assert 'not verified as eligible for Debian LTS' in item['reason'] and '2028-06-30' in item['reason']


def test_crossing_end_date_opens_high_event_and_upgrade_resolves(admin):
    collect(seed(UBUNTU_2610))  # 2026-11-04: standard support
    assert items(admin) == []
    now = seed(UBUNTU_2610, now=ts('2027-08-01T00:00:00'))
    collect(now)
    [item] = items(admin)
    assert item['severity'] == 'high' and item['lifecycle'] == 'active'
    assert item['reason'].startswith('Ubuntu 26.10 reached the end of its reviewed vendor support lifecycle on 2027-07-31.')
    now = seed(UBUNTU_2404, now=now + 60)  # upgraded to a supported release
    collect(now)
    [item] = items(admin)
    assert item['lifecycle'] == 'resolved' and item['severity'] == 'info' and item['revision'] == 2
    collect(now + 1)
    assert revisions() == 2


def test_category_change_appends_revision_and_reopens_unread(admin):
    collect(seed(UBUNTU_2004))
    collect(seed(UBUNTU_2004, now=ts('2030-06-01T00:00:00')))  # Ubuntu Pro window ended as well
    [item] = items(admin)
    assert item['revision'] == 2 and item['severity'] == 'high' and '2030-05-31' in item['reason']
    assert not item['read']


def test_stale_or_missing_inventory_holds_state_without_false_resolution(admin):
    now = seed(UBUNTU_2004)
    collect(now)
    stale = seed(UBUNTU_2004, collected_age=10 ** 7)
    collect(stale)
    [item] = items(admin)
    assert item['lifecycle'] == 'active' and revisions() == 1
    with Session() as s:
        s.get(Host, HOST).inventory = {}
        s.commit()
    collect(now + 10)
    assert items(admin)[0]['lifecycle'] == 'active' and revisions() == 1
    # A stale snapshot never opens a new event either.
    with Session() as s:
        s.add(Host(id='ol2', name='stale', address='192.0.2.51', fingerprint='t', state='online', last_seen=now,
                   inventory={'os': UBUNTU_2004, 'architecture': 'amd64', 'collected': now - 10 ** 7}))
        s.commit()
    collect(now + 20)
    assert [i['subject_id'] for i in items(admin)] == [HOST]


def test_unknown_or_derivative_release_resolves(admin):
    for release in ('ID=ubuntu\nVERSION_ID="19.10"', 'ID=linuxmint\nVERSION_ID="21"'):
        collect(seed(UBUNTU_2004))
        assert items(admin)[0]['lifecycle'] == 'active', release
        collect(seed(release))
        assert items(admin)[0]['lifecycle'] == 'resolved', release


def test_disabled_enrolling_and_deleted_servers_resolve(admin):
    for change in ({'enabled': False}, {'state': 'enrolling'}, {'deleted_at': 1.0}):
        reset = {'enabled': True, 'state': 'online', 'deleted_at': 0.0}
        collect(seed(UBUNTU_2004, **reset))
        assert items(admin)[0]['lifecycle'] == 'active', change
        collect(seed(UBUNTU_2004, **change))
        assert items(admin)[0]['lifecycle'] == 'resolved', change


def test_notifications_are_hidden_from_viewers_and_operators(admin):
    from app.identity import User
    collect(seed(UBUNTU_2004))
    with Session() as s:
        s.add_all([User(username='life-viewer', password='x', role='viewer'),
                   User(username='life-operator', password='x', role='operator')])
        s.commit()
        assert notifications.unread_count(s, 'life-viewer') == 0
        assert notifications.unread_count(s, 'life-operator') == 0
        assert notifications.unread_count(s, 'admin') >= 1


def test_rejected_payload_never_blocks_alert_collection(admin, monkeypatch):
    def reject(*args, **kwargs):
        raise ValueError('rejected')
    monkeypatch.setattr(lifecycle.notifications, 'publish', reject)
    now = seed(UBUNTU_2004, integrity=[{'path': 'x', 'issue': 'y'}])
    collect(now)
    with Session() as s:
        alert = s.scalar(select(operations.Alert).where(operations.Alert.host_id == HOST, operations.Alert.kind == 'integrity'))
        assert alert.state == 'open'
        # Lifecycle status changes no patching, upgrade or host state.
        host = s.get(Host, HOST)
        assert host.state == 'online' and host.enabled
