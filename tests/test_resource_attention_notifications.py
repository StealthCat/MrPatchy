"""In-app notifications for low disk, inodes, memory or an unsynchronized agent clock (#1257)."""
import time

import pytest
from sqlalchemy import select

from app import notifications, operations
from app import resource_attention_notifications as producer
from app.db import Host, Session

HOST = '5d4c3b2a-1f0e-4d9c-8b7a-6f5e4d3c2b1a'
OTHER = '6e5d4c3b-2a1f-4e0d-9c8b-7a6f5e4d3c2b'
KIND = 'resource-attention'


def device(disk=50.0, inodes=50.0):
    def capacity(unit, percent):
        total = 1000
        available = int(percent * 10)
        return {'state': 'collected', 'unit': unit, 'total': total, 'available': available, 'used': total - available}
    return {'version': 1, 'bytes': capacity('bytes', disk), 'inodes': capacity('inodes', inodes)}


def pressure(memory=50.0):
    total = 1000
    return {'version': 1, 'memory_capacity': {'state': 'collected', 'unit': 'bytes', 'total': total,
                                              'available': int(memory * 10)}}


def clock(synchronized=True):
    max_error = 1000 if synchronized else 16_000_000
    return {'version': 1, 'state': 'synchronized' if synchronized else 'unsynchronized', 'unit': 'microseconds',
            'kernel_unsync': not synchronized, 'max_error': max_error, 'estimated_error': 10, 'offset': -5}


def telemetry(disk=50.0, inodes=50.0, memory=50.0, synchronized=True, collected=None):
    return {'collected': time.time() if collected is None else collected,
            'device_health': device(disk, inodes), 'resource_pressure': pressure(memory),
            'clock_sync': clock(synchronized)}


def add_host(host_id=HOST, data=None, **values):
    values.setdefault('state', 'online')
    with Session() as s:
        s.add(Host(id=host_id, name='Res ' + host_id[:4], address='example', fingerprint='pinned',
                   last_seen=time.time() + 3600, telemetry=telemetry() if data is None else data, **values))
        s.commit()


def set_telemetry(data, host_id=HOST):
    with Session() as s:
        s.get(Host, host_id).telemetry = data
        s.commit()


def events(s):
    return s.scalars(select(notifications.NotificationEvent).where(
        notifications.NotificationEvent.source == operations.OPERATIONAL_NOTIFICATION_SOURCE,
        notifications.NotificationEvent.kind == KIND).order_by(notifications.NotificationEvent.host_id)).all()


def current(s, event):
    return s.get(notifications.NotificationRevision, (event.id, event.revision))


def state(host_id=HOST):
    """Return (revision, lifecycle, reason) of the server's event, or None."""
    with Session() as s:
        found = [event for event in events(s) if event.host_id == host_id]
        if not found:
            return None
        revision = current(s, found[0])
        return found[0].revision, revision.lifecycle, revision.reason


def test_healthy_resources_publish_nothing(admin):
    add_host()
    operations.collect_alerts()
    assert state() is None


def test_low_disk_publishes_once_with_fixed_text_and_resolves(admin):
    add_host(data=telemetry(disk=8.0))
    operations.collect_alerts()
    set_telemetry(telemetry(disk=7.0))  # a changed percentage is not a new revision
    operations.collect_alerts()
    with Session() as s:
        [event] = events(s)
        revision = current(s, event)
        assert (event.subject_type, event.subject_id, event.host_id, event.revision) == ('server', HOST, HOST, 1)
        assert event.minimum_role == 'admin'
        assert revision.severity == 'medium' and revision.lifecycle == 'active'
        assert revision.deep_link == '#servers/' + HOST + '/agent'
        assert revision.reason == producer.message({'disk-space-low'})
        assert 'free disk space on the root file system' in revision.reason
        assert 'authorize any response' in revision.reason
        assert '7' not in revision.reason.replace('10%', '')  # no live numbers
        # Notification-only: no SMTP/webhook outbox alert.
        assert not s.query(operations.Alert).filter_by(kind=producer.ALERT_KIND).all()

    set_telemetry(telemetry(disk=60.0))
    operations.collect_alerts()
    operations.collect_alerts()
    assert state()[:2] == (2, 'resolved')


def test_changed_categories_add_one_revision_each(admin):
    add_host(data=telemetry(disk=5.0))
    operations.collect_alerts()
    set_telemetry(telemetry(disk=5.0, memory=3.0, synchronized=False))
    operations.collect_alerts()
    operations.collect_alerts()
    revision, lifecycle, reason = state()
    assert (revision, lifecycle) == (2, 'active')
    assert reason == producer.message({'disk-space-low', 'memory-low', 'clock-unsynchronized'})
    assert 'kernel clock is not synchronized' in reason
    set_telemetry(telemetry(disk=60.0, memory=60.0, synchronized=False))
    operations.collect_alerts()
    assert state() == (3, 'active', producer.message({'clock-unsynchronized'}))


def test_hysteresis_keeps_an_active_category_until_above_the_clear_threshold(admin):
    add_host(data=telemetry(inodes=9.0))
    operations.collect_alerts()
    assert state()[:2] == (1, 'active')
    set_telemetry(telemetry(inodes=12.0))  # above trigger, within the clear band
    operations.collect_alerts()
    assert state()[:2] == (1, 'active')
    set_telemetry(telemetry(inodes=15.0))
    operations.collect_alerts()
    assert state()[:2] == (1, 'active')
    set_telemetry(telemetry(inodes=15.1))
    operations.collect_alerts()
    assert state()[:2] == (2, 'resolved')
    set_telemetry(telemetry(inodes=12.0))  # the band does not trigger a new event
    operations.collect_alerts()
    assert state()[:2] == (2, 'resolved')


def test_band_value_of_another_category_is_not_added(admin):
    add_host(data=telemetry(disk=9.0, memory=12.0))
    operations.collect_alerts()
    assert state()[2] == producer.message({'disk-space-low'})


@pytest.mark.parametrize('unknown', [
    lambda: telemetry(disk=60.0, collected=time.time() - 3600),          # stale
    lambda: telemetry(disk=60.0, collected=time.time() + 3600),          # future-dated
    lambda: {},                                                          # missing
    lambda: {'collected': time.time(), 'device_health': 'garbage'},      # malformed record
    lambda: {**telemetry(), 'device_health': {'version': 1, 'bytes': {'state': 'unknown', 'unit': 'bytes'},
                                              'inodes': {'state': 'unknown', 'unit': 'inodes'}}},
])
def test_unknown_telemetry_is_not_recovery(admin, unknown):
    add_host(data=telemetry(disk=5.0))
    operations.collect_alerts()
    set_telemetry(unknown())
    operations.collect_alerts()
    assert state() == (1, 'active', producer.message({'disk-space-low'}))


def test_unknown_clock_keeps_previous_clock_state(admin):
    add_host(data=telemetry(synchronized=False))
    operations.collect_alerts()
    data = telemetry()
    del data['clock_sync']
    set_telemetry(data)
    operations.collect_alerts()
    assert state() == (1, 'active', producer.message({'clock-unsynchronized'}))
    set_telemetry(telemetry())
    operations.collect_alerts()
    assert state()[:2] == (2, 'resolved')


def test_enrolling_disabled_and_deleted_servers(admin):
    add_host(data=telemetry(disk=5.0), state='enrolling')
    add_host(OTHER, data=telemetry(disk=5.0))
    operations.collect_alerts()
    assert state() is None and state(OTHER)[:2] == (1, 'active')
    with Session() as s:
        s.get(Host, OTHER).enabled = False
        s.commit()
    operations.collect_alerts()
    assert state(OTHER)[:2] == (2, 'resolved')
    with Session() as s:
        host = s.get(Host, OTHER)
        host.enabled, host.deleted_at = True, time.time()
        s.commit()
    operations.collect_alerts()
    assert state(OTHER)[:2] == (2, 'resolved')


def test_unrecognised_active_text_is_kept_on_unknown_and_replaced_on_fresh_values(admin):
    add_host(data=telemetry(collected=time.time() - 3600))
    with Session() as s:
        operations._operational_notification(s, HOST, producer.ALERT_KIND, 'Older wording.', time.time())
        s.commit()
    operations.collect_alerts()
    assert state() == (1, 'active', 'Older wording.')
    set_telemetry(telemetry(memory=4.0))
    operations.collect_alerts()
    assert state() == (2, 'active', producer.message({'memory-low'}))
    set_telemetry(telemetry())
    operations.collect_alerts()
    assert state()[:2] == (3, 'resolved')


def test_every_message_is_fixed_bounded_and_recoverable():
    assert len(producer._BY_MESSAGE) == 2 ** len(producer.CODES) - 1
    for reason, codes in producer._BY_MESSAGE.items():
        assert len(reason) <= 2000
        assert producer.message(set(codes)) == reason
    with pytest.raises(ValueError):
        producer.message(set())


def test_evaluate_is_pure_and_ignores_resource_health_classification():
    fresh = {'disk': {'available_percent': 10.0}, 'inodes': {'available_percent': 10.1}, 'memory': None,
             'clock': {'synchronized': True}}
    assert producer.evaluate(fresh, frozenset()) == {'disk-space-low'}
    assert producer.evaluate(fresh, frozenset({'inodes-x'})) == {'disk-space-low'}
    assert producer.evaluate(fresh, frozenset({'memory-low', 'disk-inodes-low'})) == {
        'disk-space-low', 'disk-inodes-low', 'memory-low'}
