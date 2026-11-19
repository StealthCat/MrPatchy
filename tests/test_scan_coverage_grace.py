"""Configurable grace before scheduled-scan coverage notifications (#1182)."""
import time

from app import scan_coverage_notifications as coverage
from app.db import Session, Setting

from tests.test_scan_coverage_notifications import (
    HOST, HOUR, collect, hold_scheduler, items, put_policy, report, scan, seed, set_host,
)


def stored_policy():
    with Session() as s:
        return dict(s.get(Setting, 'security-policy:' + HOST).value)


def test_policy_save_accepts_and_validates_notify_grace_hours(admin):
    seed(enabled=False)
    assert put_policy(admin, notify_grace_hours=12)['notify_grace_hours'] == 12
    assert stored_policy()['notify_grace_hours'] == 12
    assert put_policy(admin)['notify_grace_hours'] == 1  # omitted: one hour, as before
    for bad in (0, 169, -1, 'soon', 1.5, True, 1.0, '12', None):
        body = {'enabled': True, 'interval_hours': 1, 'paths': ['/srv'], 'notify_grace_hours': bad}
        response = admin.put('/api/hosts/' + HOST + '/security/policy', json=body)
        assert response.status_code == 422, (bad, response.text)
    assert stored_policy()['notify_grace_hours'] == 1  # rejected saves change nothing


def test_policy_default_includes_one_hour_grace(admin):
    seed(enabled=False)
    with Session() as s:
        s.delete(s.get(Setting, 'security-policy:' + HOST))
        s.commit()
    response = admin.get('/api/hosts/' + HOST + '/security/policy')
    assert response.status_code == 200 and response.json()['notify_grace_hours'] == 1


def test_classify_uses_configured_grace_for_overdue_stalled_and_never_scanned():
    now = time.time()
    policy = {'interval_hours': 1, 'notify_grace_hours': 6}
    limit = 7 * HOUR
    old = type('Scan', (), {'id': 'o', 'created': now - limit + 60, 'report': report()})()
    done = type('Job', (), {'id': 'o', 'state': 'complete', 'created': old.created})()
    assert coverage.classify(old, done, policy, now) is None
    assert coverage.classify(old, done, policy, now + 120) == 'overdue'
    for state in ('queued', 'running'):
        pending = type('Job', (), {'id': 'p', 'state': state, 'created': now - limit})()
        assert coverage.classify(None, pending, policy, now) == 'pending'
        assert coverage.classify(None, pending, policy, now + 1) == 'stalled'
    fresh = {**policy, 'enabled_since': now - limit + 60}
    assert coverage.classify(None, None, fresh, now) is None
    assert coverage.classify(None, None, fresh, now + 120) == 'overdue'


def test_invalid_stored_grace_keeps_one_hour():
    now = time.time()
    old = type('Scan', (), {'id': 'o', 'created': now - HOUR - coverage.GRACE_SECONDS - 60, 'report': report()})()
    done = type('Job', (), {'id': 'o', 'state': 'complete', 'created': old.created})()
    for invalid in (None, 0, 169, '6', 6.0, True, -3):
        policy = {'interval_hours': 1, 'notify_grace_hours': invalid}
        assert coverage.classify(old, done, policy, now) == 'overdue', invalid
        assert coverage.message('overdue', policy) == coverage.MESSAGES['overdue']


def test_default_grace_reason_is_unchanged_and_custom_grace_names_hours():
    for category, text in coverage.MESSAGES.items():
        assert coverage.message(category, {}) == text
        assert coverage.message(category, {'notify_grace_hours': 1}) == text
    custom = coverage.message('overdue', {'notify_grace_hours': 12})
    assert 'plus its 12-hour notification grace period' in custom and 'one hour' not in custom
    assert 'plus its 12-hour notification grace period' in coverage.message('stalled', {'notify_grace_hours': 12})
    assert coverage.message('failed', {'notify_grace_hours': 12}) == coverage.MESSAGES['failed']


def test_saved_grace_delays_overdue_notification_end_to_end(admin):
    seed(enabled=False)
    scan('old', age=2 * HOUR)
    put_policy(admin, notify_grace_hours=6)  # enabled now; one-hour interval plus six hours of grace
    hold_scheduler()
    start = time.time()
    collect(start + HOUR + coverage.GRACE_SECONDS + 60)
    assert items(admin) == []  # the one-hour default would already have published
    collect(start + 7 * HOUR - 60)
    assert items(admin) == []
    collect(start + 7 * HOUR + 60)
    [item] = items(admin)
    assert item['lifecycle'] == 'active'
    assert item['reason'] == coverage.message('overdue', {'notify_grace_hours': 6})


def test_resume_clock_uses_configured_grace(admin):
    seed(enabled=False)
    now = time.time()
    scan('old', age=2 * HOUR, signatures={'state': 'recent', 'built_at': now, 'expires': now + 60 * 24 * HOUR})
    put_policy(admin, notify_grace_hours=4)
    set_host(enabled=False)
    collect()
    set_host(enabled=True)
    hold_scheduler()
    later = time.time() + 3 * 24 * HOUR
    collect(later)
    collect(later + HOUR + coverage.GRACE_SECONDS + 60)
    assert items(admin) == []  # the resume clock is not retired after only one hour of grace
    collect(later + 5 * HOUR + 60)
    assert items(admin)[0]['lifecycle'] == 'active'
