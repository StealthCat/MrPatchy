"""Administrator-configured telemetry-loss notification threshold (#948)."""
import time

from sqlalchemy import select

from app import notifications, operations
from app.db import Audit, Host, Session, Setting, config

HOST = '3d2c1b0a-9f8e-4d7c-8b6a-5f4e3d2c1b0a'
DEADLINES = {'critical': 24, 'high': 72, 'normal': 168, 'low': 720}


def add_host(last_seen):
    with Session() as s:
        s.add(Host(id=HOST, name='Threshold host', address='example', fingerprint='pinned',
                   state='online', last_seen=last_seen))
        s.commit()


def set_minutes(value):
    with Session() as s:
        item = s.get(Setting, 'config')
        s.merge(Setting(key='config', value={**(item.value if item else {}), 'telemetry_lost_minutes': value}))
        s.commit()


def telemetry_events(s):
    return list(s.scalars(select(notifications.NotificationEvent).where(
        notifications.NotificationEvent.source == operations.OPERATIONAL_NOTIFICATION_SOURCE,
        notifications.NotificationEvent.kind == 'telemetry-lost')))


def current(s, event):
    return s.get(notifications.NotificationRevision, (event.id, event.revision))


def test_default_threshold_and_message_are_unchanged():
    assert operations.TELEMETRY_LOST_SECONDS == 900
    assert operations.telemetry_lost_minutes({}) == 15
    # Existing active events keep their revision: the default text is the pre-#948 wording.
    assert operations.TELEMETRY_LOST_MESSAGE.startswith(
        'No telemetry has arrived from this server for at least 15 minutes. It may be powered off, ')
    assert operations.telemetry_lost_message(15) == operations.TELEMETRY_LOST_MESSAGE


def test_invalid_stored_threshold_falls_back_to_default():
    for value in (4, 1441, 0, -5, True, '30', 30.0, None, [30]):
        assert operations.telemetry_lost_minutes({'telemetry_lost_minutes': value}) == 15
    for value in (5, 30, 1440):
        assert operations.telemetry_lost_minutes({'telemetry_lost_minutes': value}) == value


def test_shorter_threshold_notifies_sooner_and_names_the_configured_minutes(admin):
    now = time.time()
    add_host(now - 6 * 60)  # silent for six minutes: below the 15-minute default
    operations.collect_alerts(now)
    with Session() as s:
        assert telemetry_events(s) == []
    set_minutes(5)
    operations.collect_alerts(now)
    operations.collect_alerts(now + 30)
    with Session() as s:
        [event] = telemetry_events(s)
        revision = current(s, event)
        assert event.revision == 1 and revision.lifecycle == 'active'
        assert revision.reason == operations.telemetry_lost_message(5)
        assert 'at least 5 minutes' in revision.reason


def test_raising_threshold_resolves_and_later_reopens(admin):
    now = time.time()
    add_host(now - 20 * 60)
    operations.collect_alerts(now)
    with Session() as s:
        [event] = telemetry_events(s)
        assert current(s, event).lifecycle == 'active'
        assert current(s, event).reason == operations.TELEMETRY_LOST_MESSAGE
    set_minutes(60)
    operations.collect_alerts(now + 30)
    with Session() as s:
        [event] = telemetry_events(s)
        assert event.revision == 2 and current(s, event).lifecycle == 'resolved'
    operations.collect_alerts(now + 41 * 60)  # silent for 61 minutes
    with Session() as s:
        [event] = telemetry_events(s)
        assert event.revision == 3 and current(s, event).lifecycle == 'active'
        assert 'at least 60 minutes' in current(s, event).reason


def test_observation_guard_uses_the_configured_threshold(admin):
    now = time.time()
    add_host(now - 3600)
    set_minutes(30)
    # A new coordinator must observe for the configured threshold, not the 15-minute default.
    operations.collect_alerts(now + 20 * 60, observing_since=now)
    with Session() as s:
        assert telemetry_events(s) == []
    operations.collect_alerts(now + 31 * 60, observing_since=now)
    with Session() as s:
        [event] = telemetry_events(s)
        assert current(s, event).lifecycle == 'active'


def test_patch_settings_save_validates_audits_and_keeps_threshold_when_omitted(admin):
    assert admin.get('/api/settings').json()['telemetry_lost_minutes'] == 15
    r = admin.put('/api/settings/patching', json={'repo_minutes': 60, 'deadlines': DEADLINES,
                                                  'telemetry_lost_minutes': 45})
    assert r.status_code == 200, r.text
    # Older clients omit the field and keep the stored threshold.
    assert admin.put('/api/settings/patching', json={'repo_minutes': 50, 'deadlines': DEADLINES}).status_code == 200
    # Saving the same value again records no change.
    assert admin.put('/api/settings/patching', json={'repo_minutes': 50, 'deadlines': DEADLINES,
                                                     'telemetry_lost_minutes': 45}).status_code == 200
    assert admin.get('/api/settings').json()['telemetry_lost_minutes'] == 45
    with Session() as s:
        cfg = config(s)
        assert cfg['telemetry_lost_minutes'] == 45 and cfg['repo_minutes'] == 50
        details = [a.detail for a in s.query(Audit).filter_by(action='update patching settings')]
        assert sum('telemetry-loss notification threshold changed from 15 to 45 minutes' in d for d in details) == 1
        assert sum('telemetry-loss' in d for d in details) == 1
    for bad in (4, 1441, '30', 30.5, True, None):
        body = {'repo_minutes': 60, 'deadlines': DEADLINES, 'telemetry_lost_minutes': bad}
        status = admin.put('/api/settings/patching', json=body).status_code
        # None is treated as omitted, like the other optional patching fields.
        assert status == (200 if bad is None else 422), bad
    assert admin.get('/api/settings').json()['telemetry_lost_minutes'] == 45


def test_corrupt_stored_threshold_is_reported_as_default(admin):
    set_minutes('soon')
    assert admin.get('/api/settings').json()['telemetry_lost_minutes'] == 15
