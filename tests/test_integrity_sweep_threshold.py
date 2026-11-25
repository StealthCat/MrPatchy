"""Administrator-configured hash-sweep stall threshold for the integrity-sweep notification (#1265)."""
from sqlalchemy import select

from app import integrity_sweep_notifications as sweep, notifications
from app.db import Audit, Session, Setting, config
from tests.test_integrity_sweep_notifications import collect, items, revisions, seed

DEADLINES = {'critical': 24, 'high': 72, 'normal': 168, 'low': 720}
PATCHING = {'repo_minutes': 60, 'deadlines': DEADLINES}


def set_minutes(value):
    with Session() as s:
        item = s.get(Setting, 'config')
        s.merge(Setting(key='config', value={**(item.value if item else {}), sweep.CONFIG_KEY: value}))
        s.commit()


def test_default_threshold_and_message_are_unchanged():
    assert sweep.STALLED_SECONDS == 1800 and sweep.stalled_minutes({}) == 30
    # Active events keep their revision on upgrade: the default text is the pre-#1265 wording.
    assert sweep.MESSAGES['overdue'] == sweep.overdue_message(30)
    assert sweep.MESSAGES['overdue'].startswith(
        'File-integrity monitoring has not completed a hash sweep on this server for at least 30 minutes, '
        'although telemetry is still arriving.')


def test_invalid_stored_values_fall_back_to_the_default():
    for value in (9, 1441, 0, -5, '45', 45.0, True, None, [45], {'minutes': 45}):
        assert sweep.stalled_minutes({sweep.CONFIG_KEY: value}) == 30, value
    for value in (10, 45, 1440):
        assert sweep.stalled_minutes({sweep.CONFIG_KEY: value}) == value
    assert sweep.stalled_minutes(None) == 30


def test_shorter_threshold_opens_the_notice_sooner_and_names_its_minutes(admin):
    set_minutes(10)
    now = seed(hashed_age=11 * 60)
    collect(now)
    [item] = items(admin)
    assert item['lifecycle'] == 'active' and item['severity'] == 'medium'
    assert item['reason'] == sweep.overdue_message(10) and 'at least 10 minutes' in item['reason']
    collect(now + 30)  # unchanged category and threshold: no new revision
    assert revisions() == 1


def test_longer_threshold_holds_a_stall_the_default_would_report(admin):
    set_minutes(120)
    now = seed(hashed_age=sweep.STALLED_SECONDS + 60)
    collect(now)
    assert items(admin) == []
    now = seed(hashed_age=121 * 60)
    collect(now)
    [item] = items(admin)
    assert item['lifecycle'] == 'active' and 'at least 120 minutes' in item['reason']


def test_threshold_change_rewrites_active_text_once_then_raise_resolves_and_reopens(admin):
    now = seed(hashed_age=45 * 60)
    collect(now)
    [item] = items(admin)
    assert item['revision'] == 1 and item['reason'] == sweep.MESSAGES['overdue']
    set_minutes(40)  # still qualifies: one rewrite naming the new minutes
    collect(now + 30)
    collect(now + 60)
    [item] = items(admin)
    assert item['revision'] == 2 and item['lifecycle'] == 'active' and 'at least 40 minutes' in item['reason']
    set_minutes(60)  # raised above the current stall: resolved
    collect(now + 90)
    [item] = items(admin)
    assert item['revision'] == 3 and item['lifecycle'] == 'resolved' and item['reason'] == sweep.RESOLVED
    now = seed(hashed_age=61 * 60)  # the stall passes the new threshold: the same event reopens
    collect(now)
    [item] = items(admin)
    assert item['revision'] == 4 and item['lifecycle'] == 'active' and 'at least 60 minutes' in item['reason']
    with Session() as s:
        assert len(list(s.scalars(select(notifications.NotificationEvent).where(
            notifications.NotificationEvent.source == sweep.SOURCE)))) == 1


def test_future_category_is_unaffected_by_the_threshold(admin):
    set_minutes(1440)
    now = seed(hashed_age=-(sweep.FUTURE_SECONDS + 60))
    collect(now)
    [item] = items(admin)
    assert item['reason'] == sweep.MESSAGES['future']


def test_patch_settings_save_validates_audits_and_keeps_threshold_when_omitted(admin):
    assert admin.get('/api/settings').json()[sweep.CONFIG_KEY] == 30
    r = admin.put('/api/settings/patching', json={**PATCHING, sweep.CONFIG_KEY: 90})
    assert r.status_code == 200, r.text
    # Older clients omit the field and keep the stored threshold.
    assert admin.put('/api/settings/patching', json={**PATCHING, 'repo_minutes': 50}).status_code == 200
    # Saving the same value again records no change.
    assert admin.put('/api/settings/patching', json={**PATCHING, sweep.CONFIG_KEY: 90}).status_code == 200
    assert admin.get('/api/settings').json()[sweep.CONFIG_KEY] == 90
    with Session() as s:
        assert config(s)[sweep.CONFIG_KEY] == 90
        details = [a.detail for a in s.query(Audit).filter_by(action='update patching settings')]
        assert sum('hash-sweep stall notification threshold changed from 30 to 90 minutes' in d for d in details) == 1
        assert sum('hash-sweep' in d for d in details) == 1
    for bad in (9, 1441, '30', 30.5, True, None):
        status = admin.put('/api/settings/patching', json={**PATCHING, sweep.CONFIG_KEY: bad}).status_code
        # None is treated as omitted, like the other optional patching fields.
        assert status == (200 if bad is None else 422), bad
    assert admin.get('/api/settings').json()[sweep.CONFIG_KEY] == 90


def test_corrupt_stored_threshold_is_reported_and_applied_as_default(admin):
    set_minutes('soon')
    assert admin.get('/api/settings').json()[sweep.CONFIG_KEY] == 30
    now = seed(hashed_age=sweep.STALLED_SECONDS + 60)
    collect(now)
    [item] = items(admin)
    assert item['reason'] == sweep.MESSAGES['overdue']

