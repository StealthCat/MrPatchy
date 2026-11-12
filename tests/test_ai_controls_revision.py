"""Revision-checked AI admission/spend controls (#709) and partial AI saves (#708)."""
from sqlalchemy import func, select

from app.db import Audit, Session

FULL = {'ai_model': 'm1', 'ai_enabled': False, 'ai_hourly_limit': 7, 'ai_updates_enabled': False,
        'ai_update_hourly_limit': 9, 'ai_control_mode': 'daily_cap', 'ai_rate_per_hour': 33,
        'ai_daily_cap_usd': 2.5, 'ai_budget_timezone': 'America/New_York'}
CONTROLS = {k: v for k, v in FULL.items() if k not in ('ai_model', 'ai_enabled')}


def audits():
    with Session() as s:
        # Every request has a generic 'request' audit row; count settings-change entries only.
        return s.scalar(select(func.count()).select_from(Audit).where(Audit.action.like('update%settings')))


def saved(admin):
    return admin.get('/api/settings').json()


def test_partial_ai_section_save_keeps_stored_controls(admin):
    admin.put('/api/settings/ai-key', json={'api_key': 'fixture-key'})
    assert admin.put('/api/settings/ai', json=FULL).status_code == 200
    r = admin.put('/api/settings/ai', json={'ai_model': '  m2  '})
    assert r.status_code == 200 and r.json()['ai_model'] == 'm2'
    state = saved(admin)
    assert state['ai_model'] == 'm2'
    assert {k: state[k] for k in CONTROLS} == CONTROLS
    assert r.json()['ai_controls_revision'] == state['ai_controls_revision']


def test_partial_save_validates_enable_against_stored_model(admin):
    admin.put('/api/settings/ai-key', json={'api_key': 'fixture-key'})
    assert admin.put('/api/settings/ai', json=FULL).status_code == 200
    assert admin.put('/api/settings/ai', json={'ai_enabled': True}).status_code == 200
    assert saved(admin)['ai_model'] == 'm1' and saved(admin)['ai_enabled']


def test_revision_is_stable_and_tracks_control_values_only(admin):
    first = saved(admin)['ai_controls_revision']
    assert len(first) == 64 and first == saved(admin)['ai_controls_revision']
    assert admin.put('/api/settings/ai', json={'ai_model': 'other'}).status_code == 200
    assert saved(admin)['ai_controls_revision'] == first
    assert admin.put('/api/settings/ai', json={'ai_daily_cap_usd': 3.0}).status_code == 200
    assert saved(admin)['ai_controls_revision'] != first


def test_stale_section_revision_is_rejected_without_write_or_audit(admin):
    stale = saved(admin)['ai_controls_revision']
    assert admin.put('/api/settings/ai', json=FULL | {'expected_ai_controls_revision': stale}).status_code == 200
    before, count = saved(admin), audits()
    r = admin.put('/api/settings/ai', json=FULL | {'ai_control_mode': 'unthrottled', 'ai_model': 'm9',
                                                   'expected_ai_controls_revision': stale})
    assert r.status_code == 409 and 'Reload' in r.json()['detail']
    after = saved(admin)
    assert after == before and after['ai_control_mode'] == 'daily_cap' and after['ai_model'] == 'm1'
    assert audits() == count


def test_current_section_revision_is_accepted_and_returns_next(admin):
    current = saved(admin)['ai_controls_revision']
    r = admin.put('/api/settings/ai', json=FULL | {'expected_ai_controls_revision': current})
    assert r.status_code == 200
    assert r.json()['ai_controls_revision'] == saved(admin)['ai_controls_revision'] != current
    assert 'expected_ai_controls_revision' not in admin.get('/api/settings').json()


def test_legacy_settings_endpoint_checks_revision(admin):
    base = {'repo_minutes': 60, 'deadlines': {'critical': 24, 'high': 72, 'normal': 168, 'low': 720}}
    stale = saved(admin)['ai_controls_revision']
    assert admin.put('/api/settings', json=base | CONTROLS).status_code == 200
    count = audits()
    r = admin.put('/api/settings', json=base | {'ai_control_mode': 'unthrottled', 'expected_ai_controls_revision': stale})
    assert r.status_code == 409 and saved(admin)['ai_control_mode'] == 'daily_cap' and audits() == count
    current = saved(admin)['ai_controls_revision']
    ok = admin.put('/api/settings', json=base | {'ai_control_mode': 'rate', 'expected_ai_controls_revision': current})
    assert ok.status_code == 200 and saved(admin)['ai_control_mode'] == 'rate'
    assert ok.json()['ai_controls_revision'] == saved(admin)['ai_controls_revision']


def test_malformed_revision_is_rejected(admin):
    assert admin.put('/api/settings/ai', json={'expected_ai_controls_revision': 'abc'}).status_code == 422
