"""Preview AI admission/spend changes before save and audit any expansion (#871)."""
from sqlalchemy import func, select

from app import ai_control_preview as preview
from app.db import Audit, Session, Setting, config
from app.identity import User

BASE = {'ai_control_mode': 'rate', 'ai_rate_per_hour': 20, 'ai_daily_cap_usd': 10.0,
        'ai_budget_timezone': 'UTC', 'ai_hourly_limit': 20, 'ai_update_hourly_limit': 20,
        'ai_updates_enabled': True}


def effects(stored, proposed):
    return preview.compare(BASE | stored, proposed)


def test_no_change_reports_nothing():
    result = effects({}, dict(BASE))
    assert result['effects'] == [] and not result['changed'] and not result['expands']


def test_lowering_rate_is_a_restriction_not_an_expansion():
    result = effects({}, {'ai_rate_per_hour': 5})
    assert result['changed'] and not result['expands']
    assert result['after']['hourly_starts'] == {'triage': 5, 'update_scoring': 5, 'automatic_plans': 5}
    assert result['after']['combined_hourly_starts'] == 5


def test_raising_rate_expands():
    result = effects({}, {'ai_rate_per_hour': 60})
    assert result['expands']
    assert any('Combined AI work start ceiling changes from 20/hour to 60/hour' in t for t in result['expansions'])


def test_leaving_legacy_compares_each_hidden_allowance_with_new_shared_rate():
    stored = {'ai_control_mode': 'legacy', 'ai_hourly_limit': 4, 'ai_update_hourly_limit': 30}
    result = effects(stored, {'ai_control_mode': 'rate', 'ai_rate_per_hour': 12})
    assert result['before']['hourly_starts'] == {'triage': 4, 'update_scoring': 30, 'automatic_plans': 10}
    assert result['before']['combined_hourly_starts'] == 44
    text = ' '.join(result['expansions'])
    assert 'Process triage start ceiling changes from 4/hour to 12/hour' in text
    assert 'Automatic incident/startup plans start ceiling changes from 10/hour to 12/hour' in text
    # Scoring falls from 30 to 12: a reduction, reported but not flagged.
    scoring = [e for e in result['effects'] if e['text'].startswith('Update scoring')]
    assert scoring and not scoring[0]['expands']
    assert not any('Combined' in t for t in result['expansions'])


def test_unthrottled_and_cap_removal_expand():
    result = effects({'ai_control_mode': 'rate_and_daily'}, {'ai_control_mode': 'unthrottled'})
    text = ' '.join(result['expansions'])
    assert 'Mr Patchy rate and spend controls are removed' in text
    assert 'Daily spend ceiling changes from $10.00/day to no daily cap' in text
    assert 'to no Mr Patchy limit' in text


def test_cap_changes():
    capped = {'ai_control_mode': 'daily_cap', 'ai_daily_cap_usd': 5}
    assert effects(capped, {'ai_daily_cap_usd': 8})['expands']
    lowered = effects(capped, {'ai_daily_cap_usd': 2})
    assert lowered['changed'] and not lowered['expands']
    added = effects({}, {'ai_control_mode': 'rate_and_daily'})
    assert added['changed'] and not added['expands']


def test_enabling_scoring_expands_and_disabling_restricts():
    on = effects({'ai_updates_enabled': False}, {'ai_updates_enabled': True})
    assert on['expansions'] == ['Automatic update scoring is enabled and starts making paid provider calls.']
    off = effects({}, {'ai_updates_enabled': False})
    assert off['changed'] and not off['expands']


def test_timezone_change_expands_only_while_capped():
    capped = {'ai_control_mode': 'daily_cap'}
    assert effects(capped, {'ai_budget_timezone': 'Asia/Tokyo'})['expands']
    uncapped = effects({}, {'ai_budget_timezone': 'Asia/Tokyo'})
    assert not uncapped['changed']


def test_legacy_only_limits_are_inert_outside_legacy():
    assert not effects({}, {'ai_hourly_limit': 999})['changed']


def test_audit_suffix():
    assert preview.audit_suffix(BASE, {'ai_rate_per_hour': 5}) == ''
    assert preview.audit_suffix(BASE, {'ai_rate_per_hour': 50}).startswith('; expands AI admission or spend: ')


def _audit_count(session):
    return session.scalar(select(func.count()).select_from(Audit).where(Audit.action.like('update%settings')))


def test_preview_route_is_read_only(admin):
    with Session() as s:
        before, audits = config(s), _audit_count(s)
        raw = s.get(Setting, 'config')
        raw_before = dict(raw.value) if raw else None
    r = admin.post('/api/settings/ai/preview', json={'ai_control_mode': 'unthrottled'})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body['expands'] and body['after']['mode'] == 'unthrottled'
    assert len(body['ai_controls_revision']) == 64
    with Session() as s:
        assert config(s) == before and _audit_count(s) == audits
        raw = s.get(Setting, 'config')
        assert (dict(raw.value) if raw else None) == raw_before


def test_preview_route_validates_and_requires_admin(admin):
    assert admin.post('/api/settings/ai/preview', json={'ai_budget_timezone': 'Not/AZone'}).status_code == 400
    assert admin.post('/api/settings/ai/preview', json={'unknown': 1}).status_code == 422
    csrf = admin.headers.pop('X-CSRF-Token')
    assert admin.post('/api/settings/ai/preview', json={}).status_code == 403
    admin.headers['X-CSRF-Token'] = csrf
    with Session() as s:
        s.get(User, 'admin').role = 'viewer'
        s.commit()
    assert admin.post('/api/settings/ai/preview', json={}).status_code == 403


def _last_settings_audit():
    with Session() as s:
        return s.scalars(select(Audit).where(Audit.action.like('update%settings'))
                         .order_by(Audit.id.desc())).first().detail


def test_both_save_paths_audit_expansions(admin):
    assert admin.put('/api/settings/ai', json={'ai_control_mode': 'rate', 'ai_rate_per_hour': 10}).status_code == 200
    assert admin.put('/api/settings/ai', json={'ai_rate_per_hour': 40}).status_code == 200
    detail = _last_settings_audit()
    assert '; expands AI admission or spend: ' in detail and 'from 10/hour to 40/hour' in detail
    assert admin.put('/api/settings/ai', json={'ai_rate_per_hour': 5}).status_code == 200
    assert 'expands AI admission' not in _last_settings_audit()
    current = admin.get('/api/settings').json()
    body = {k: current[k] for k in ('repo_minutes', 'deadlines', 'history_days')} | {'ai_control_mode': 'unthrottled'}
    assert admin.put('/api/settings', json=body).status_code == 200
    assert 'Mr Patchy rate and spend controls are removed' in _last_settings_audit()
