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


# Advance warning before a covered release reaches its next support boundary.

def set_window(days):
    from app.db import Setting
    with Session() as s:
        item = s.get(Setting, 'config')
        s.merge(Setting(key='config', value={**(item.value if item else {}), 'os_lifecycle_warning_days': days}))
        s.commit()


def test_standard_support_ending_within_default_window_warns_low(admin):
    now = seed(UBUNTU_2610, now=ts('2027-05-03T00:00:00'))  # 89 days before 2027-07-31
    collect(now)
    [item] = items(admin)
    assert item['severity'] == 'low' and item['lifecycle'] == 'active' and item['deep_link'] == '#servers/ol/overview'
    assert item['reason'].startswith('Ubuntu 26.10 standard support ends on 2027-07-31.')
    assert 'No further reviewed vendor support phase follows.' in item['reason']
    with Session() as s:
        assert s.get(notifications.NotificationEvent, item['id']).minimum_role == 'admin'
    collect(now + 86400)  # the next day is the same boundary: no new revision
    assert revisions() == 1
    # Crossing the boundary moves the same event to the high "ended" revision, unread.
    collect(seed(UBUNTU_2610, now=ts('2027-08-01T00:00:00')))
    [item] = items(admin)
    assert item['revision'] == 2 and item['severity'] == 'high' and not item['read']


def test_outside_window_or_disabled_window_publishes_nothing(admin):
    collect(seed(UBUNTU_2610, now=ts('2027-05-01T00:00:00')))  # 91 days before
    assert items(admin) == []
    set_window(0)
    collect(seed(UBUNTU_2610, now=ts('2027-07-30T00:00:00')))
    assert items(admin) == []


def test_ubuntu_lts_warning_names_pro_requirement_and_moves_to_subscription(admin):
    set_window(30)
    collect(seed('ID=ubuntu\nVERSION_ID="22.04"', now=ts('2027-05-10T00:00:00')))
    [item] = items(admin)
    assert item['severity'] == 'low' and 'Ubuntu 22.04 LTS standard support ends on 2027-05-31.' in item['reason']
    assert 'Ubuntu Pro' in item['reason'] and '2032-05-31' in item['reason']
    collect(seed('ID=ubuntu\nVERSION_ID="22.04"', now=ts('2027-06-01T00:00:00')))
    [item] = items(admin)
    assert item['revision'] == 2 and item['severity'] == 'medium' and 'standard support ended' in item['reason']


def test_verified_debian_lts_end_warns_then_resolves_into_lts_between(admin):
    collect(seed(DEBIAN_12, 'arm64', now=ts('2026-06-01T00:00:00')))  # standard ends 2026-07-11
    [item] = items(admin)
    assert 'Debian LTS may cover it until 2028-06-30' in item['reason']
    # Verified LTS coverage after the standard end needs no attention: the warning resolves.
    collect(seed(DEBIAN_12, 'arm64', now=ts('2026-07-12T00:00:00')))
    assert items(admin)[0]['lifecycle'] == 'resolved'
    # Approaching the end of verified LTS reopens the same event with a new boundary.
    collect(seed(DEBIAN_12, 'arm64', now=ts('2028-05-01T00:00:00')))
    [item] = items(admin)
    assert item['lifecycle'] == 'active' and item['severity'] == 'low' and not item['read']
    assert item['reason'].startswith('Debian 12 (bookworm) Debian LTS coverage ends on 2028-06-30.')


def test_stale_inventory_never_opens_an_advance_warning(admin):
    collect(seed(UBUNTU_2610, now=ts('2027-07-01T00:00:00'), collected_age=10 ** 7))
    assert items(admin) == []


def test_invalid_stored_window_disables_warning():
    assert lifecycle.warning_days(90) == 90 and lifecycle.warning_days(0) == 0
    for value in (-1, 731, True, '30', 3.5, None):
        assert lifecycle.warning_days(value) == 0


def test_patch_settings_save_window_audits_and_keeps_it_when_omitted(admin):
    from app.db import Audit, config
    deadlines = {'critical': 24, 'high': 72, 'normal': 168, 'low': 720}
    assert admin.get('/api/settings').json()['os_lifecycle_warning_days'] == 90
    r = admin.put('/api/settings/patching', json={'repo_minutes': 60, 'deadlines': deadlines, 'os_lifecycle_warning_days': 30})
    assert r.status_code == 200, r.text
    assert admin.put('/api/settings/patching', json={'repo_minutes': 45, 'deadlines': deadlines}).status_code == 200
    with Session() as s:
        cfg = config(s)
        assert cfg['os_lifecycle_warning_days'] == 30 and cfg['repo_minutes'] == 45
        details = [a.detail for a in s.query(Audit).filter_by(action='update patching settings')]
        assert any('OS lifecycle advance warning changed from 90 to 30 days' in d for d in details)
        assert sum('OS lifecycle advance warning' in d for d in details) == 1
    for bad in (-1, 731, 'x'):
        assert admin.put('/api/settings/patching', json={'repo_minutes': 60, 'deadlines': deadlines,
                                                          'os_lifecycle_warning_days': bad}).status_code == 422
