"""Preview AI admission/spend changes before save, audit any expansion (#871) and refuse unconfirmed ones (#881)."""
from sqlalchemy import func, select

from app import ai_control_preview as preview
from app.db import Audit, Session, Setting, config
from app.identity import User
from tests.ai_settings_helpers import confirmed_put

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


def test_enabling_ai_expands_and_other_enable_states_do_not():
    enabling = 'AI is enabled and Mr Patchy starts making paid provider calls within the ceilings below.'
    on = effects({'ai_enabled': False}, {'ai_enabled': True})
    assert on['expands'] and on['expansions'] == [enabling]
    for stored, proposed in (({'ai_enabled': True}, {'ai_enabled': True}), ({'ai_enabled': True}, {'ai_enabled': False}),
                             ({'ai_enabled': False}, {'ai_enabled': False}), ({'ai_enabled': False}, {}),
                             ({}, {'ai_enabled': True})):  # controls-only callers (no stored switch) are unaffected
        assert not effects(stored, proposed)['expands'], (stored, proposed)
    # Enabling AI and raising a ceiling in one save lists both expansions.
    both = effects({'ai_enabled': False}, {'ai_enabled': True, 'ai_rate_per_hour': 40})
    assert both['expansions'][0] == enabling and len(both['expansions']) > 1
    assert 'ai_enabled' in preview.PREVIEW_FIELDS and 'ai_enabled' not in preview.FIELDS


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
    assert confirmed_put(admin, '/api/settings/ai', {'ai_control_mode': 'rate', 'ai_rate_per_hour': 10}).status_code == 200
    assert confirmed_put(admin, '/api/settings/ai', {'ai_rate_per_hour': 40}).status_code == 200
    detail = _last_settings_audit()
    assert '; expands AI admission or spend: ' in detail and 'from 10/hour to 40/hour' in detail
    assert admin.put('/api/settings/ai', json={'ai_rate_per_hour': 5}).status_code == 200
    assert 'expands AI admission' not in _last_settings_audit()
    current = admin.get('/api/settings').json()
    body = {k: current[k] for k in ('repo_minutes', 'deadlines', 'history_days')} | {'ai_control_mode': 'unthrottled'}
    assert confirmed_put(admin, '/api/settings', body).status_code == 200
    assert 'Mr Patchy rate and spend controls are removed' in _last_settings_audit()


# --- No silent spend expansion (#881) -------------------------------------------------


def _stored_controls():
    with Session() as s:
        cfg = config(s)
        return {key: cfg[key] for key in preview.FIELDS}, _audit_count(s)


def test_confirmation_digest_binds_revision_and_expansions():
    assert preview.expansion_confirmation('a' * 64, []) is None
    one = preview.expansion_confirmation('a' * 64, ['x'])
    assert len(one) == 64 and one == preview.expansion_confirmation('a' * 64, ['x'])
    assert one != preview.expansion_confirmation('b' * 64, ['x'])
    assert one != preview.expansion_confirmation('a' * 64, ['x', 'y'])


def test_unconfirmed_expansion_is_refused_on_both_save_paths(admin):
    assert admin.put('/api/settings/ai', json={'ai_control_mode': 'unthrottled'}).status_code == 409
    assert confirmed_put(admin, '/api/settings/ai', {'ai_control_mode': 'rate', 'ai_rate_per_hour': 10}).status_code == 200
    before, audits = _stored_controls()
    r = admin.put('/api/settings/ai', json={'ai_rate_per_hour': 40})
    assert r.status_code == 409 and 'from 10/hour to 40/hour' in r.json()['detail'] and 'Nothing was saved' in r.json()['detail']
    current = admin.get('/api/settings').json()
    full = {k: current[k] for k in ('repo_minutes', 'deadlines', 'history_days')} | {'ai_control_mode': 'unthrottled'}
    r = admin.put('/api/settings', json=full)
    assert r.status_code == 409 and 'Mr Patchy rate and spend controls are removed' in r.json()['detail']
    assert admin.put('/api/settings/ai', json={'ai_rate_per_hour': 40, 'confirm_ai_expansion': 'f' * 64}).status_code == 409
    assert _stored_controls() == (before, audits)  # refusals write no settings and no audit entry
    assert confirmed_put(admin, '/api/settings', full).status_code == 200
    assert admin.get('/api/settings').json()['ai_control_mode'] == 'unthrottled'


def test_confirmation_cannot_authorize_a_larger_or_later_expansion(admin):
    assert confirmed_put(admin, '/api/settings/ai', {'ai_control_mode': 'rate', 'ai_rate_per_hour': 10}).status_code == 200
    token = admin.post('/api/settings/ai/preview', json={'ai_rate_per_hour': 20}).json()['expansion_confirmation']
    assert token
    # A different, larger expansion is refused with the confirmation for the smaller one.
    assert admin.put('/api/settings/ai', json={'ai_rate_per_hour': 30, 'confirm_ai_expansion': token}).status_code == 409
    assert admin.put('/api/settings/ai', json={'ai_rate_per_hour': 20, 'confirm_ai_expansion': token}).status_code == 200
    # Lower to a different value, then replay the old confirmation for the same target: the stored revision changed.
    assert admin.put('/api/settings/ai', json={'ai_rate_per_hour': 5}).status_code == 200
    assert admin.put('/api/settings/ai', json={'ai_rate_per_hour': 20, 'confirm_ai_expansion': token}).status_code == 409
    assert admin.get('/api/settings').json()['ai_rate_per_hour'] == 5


def test_non_expanding_saves_need_no_confirmation(admin):
    assert confirmed_put(admin, '/api/settings/ai', {'ai_control_mode': 'rate', 'ai_rate_per_hour': 30}).status_code == 200
    preview_body = admin.post('/api/settings/ai/preview', json={'ai_rate_per_hour': 5}).json()
    assert preview_body['expands'] is False and preview_body['expansion_confirmation'] is None
    for body in ({'ai_rate_per_hour': 5}, {'ai_updates_enabled': False}, {'ai_model': 'other-model'}, {}):
        assert admin.put('/api/settings/ai', json=body).status_code == 200, body
    current = admin.get('/api/settings').json()
    assert admin.put('/api/settings', json={k: current[k] for k in ('repo_minutes', 'deadlines', 'history_days')}).status_code == 200


def test_confirmation_field_is_validated(admin):
    assert admin.put('/api/settings/ai', json={'confirm_ai_expansion': 'not-a-digest'}).status_code == 422


def _enable_prerequisites(admin):
    assert admin.put('/api/settings/ai-key', json={'api_key': 'fixture-key'}).status_code == 200
    assert admin.put('/api/settings/ai', json={'ai_model': 'fixture-model'}).status_code == 200
    assert admin.get('/api/settings').json()['ai_enabled'] is False


def test_enabling_ai_requires_confirmation_on_both_save_paths(admin):
    _enable_prerequisites(admin)
    shown = admin.post('/api/settings/ai/preview', json={'ai_enabled': True}).json()
    assert shown['expands'] and shown['expansion_confirmation']
    assert shown['expansions'][0].startswith('AI is enabled and Mr Patchy starts making paid provider calls')
    before, audits = _stored_controls()
    r = admin.put('/api/settings/ai', json={'ai_enabled': True})
    assert r.status_code == 409 and 'AI is enabled' in r.json()['detail'] and 'Nothing was saved' in r.json()['detail']
    current = admin.get('/api/settings').json()
    full = {k: current[k] for k in ('repo_minutes', 'deadlines', 'history_days')} | {'ai_enabled': True}
    assert admin.put('/api/settings', json=full).status_code == 409
    assert admin.put('/api/settings', json=full | {'confirm_ai_expansion': 'f' * 64}).status_code == 409
    assert _stored_controls() == (before, audits) and admin.get('/api/settings').json()['ai_enabled'] is False
    assert admin.put('/api/settings/ai', json={'ai_enabled': True, 'confirm_ai_expansion': shown['expansion_confirmation']}).status_code == 200
    assert admin.get('/api/settings').json()['ai_enabled'] is True
    assert 'AI is enabled' in _last_settings_audit()
    # Keeping AI on, or turning it off, needs no confirmation.
    assert admin.put('/api/settings/ai', json={'ai_enabled': True}).status_code == 200
    assert admin.put('/api/settings', json=full | {'ai_enabled': False}).status_code == 200
    # Turning it back on through the full settings route also needs the preview's confirmation.
    assert admin.put('/api/settings', json=full).status_code == 409
    assert confirmed_put(admin, '/api/settings', full).status_code == 200
    assert admin.get('/api/settings').json()['ai_enabled'] is True


# Concrete budget-window disclosure before and after a capped change (#1267).
from datetime import datetime, timezone as _tz  # noqa: E402

CAPPED = BASE | {'ai_control_mode': 'daily_cap'}


def _ts(*args):
    return datetime(*args, tzinfo=_tz.utc).timestamp()


def test_budget_reset_is_absent_without_a_capped_window_change():
    now = _ts(2026, 11, 21, 7, 0)
    assert preview.budget_reset(BASE, {'ai_rate_per_hour': 5}, now) is None
    assert preview.budget_reset(BASE, {'ai_budget_timezone': 'Asia/Tokyo'}, now) is None  # rate mode: no window
    assert preview.budget_reset(CAPPED, {'ai_daily_cap_usd': 20}, now) is None
    assert preview.budget_reset(CAPPED, {'ai_control_mode': 'rate_and_daily'}, now) is None
    assert preview.budget_reset(CAPPED, {'ai_control_mode': 'unthrottled', 'ai_budget_timezone': 'Asia/Tokyo'}, now) is None


def test_budget_reset_names_both_windows_when_the_timezone_changes():
    now = _ts(2026, 11, 21, 7, 0)
    result = preview.budget_reset(CAPPED, {'ai_budget_timezone': 'Pacific/Kiritimati'}, now)
    assert result['current'] == {'timezone': 'UTC', 'window_start': _ts(2026, 11, 21), 'next_reset': _ts(2026, 11, 22)}
    # UTC+14: local 2026-11-21 21:00, so the window started 2026-11-20 10:00 UTC and resets 10:00 UTC.
    assert result['proposed'] == {'timezone': 'Pacific/Kiritimati', 'window_start': _ts(2026, 11, 20, 10),
                                  'next_reset': _ts(2026, 11, 21, 10)}
    assert result['resets_sooner'] is True and result['seconds_until_proposed_reset'] == 3 * 3600
    assert 'keeps counting while the budget window it was admitted under is still open' in result['carryover']
    assert 'while it was made inside the active window' in result['carryover']
    # An earlier proposed boundary is not a refill: retained spend can still count after it (#1269 review).
    assert 'fresh daily cap' not in result['carryover']
    assert 'can still count after it' in result['carryover']
    assert result['starts_earlier'] is True and result['resets_later'] is False
    later = preview.budget_reset(CAPPED, {'ai_budget_timezone': 'America/Los_Angeles'}, now)
    # PST (UTC-8): local 2026-11-20 23:00, resets at 08:00 UTC, still sooner than UTC midnight.
    assert later['proposed']['next_reset'] == _ts(2026, 11, 21, 8) and later['resets_sooner']
    evening = preview.budget_reset(CAPPED, {'ai_budget_timezone': 'America/Los_Angeles'}, _ts(2026, 11, 21, 9))
    assert evening['proposed']['next_reset'] == _ts(2026, 11, 22, 8) and not evening['resets_sooner']


def test_budget_reset_follows_daylight_saving_days():
    # 2026-11-01 is the US fall-back day: a 25-hour budget day in America/New_York.
    now = _ts(2026, 11, 1, 12)
    window = preview.budget_reset(CAPPED, {'ai_budget_timezone': 'America/New_York'}, now)['proposed']
    assert window['window_start'] == _ts(2026, 11, 1, 4) and window['next_reset'] == _ts(2026, 11, 2, 5)


def test_budget_reset_on_entering_a_capped_mode_has_no_current_window():
    now = _ts(2026, 11, 21, 7, 30)
    result = preview.budget_reset(BASE, {'ai_control_mode': 'rate_and_daily'}, now)
    assert result['current'] is None and result['resets_sooner'] is False
    assert result['starts_earlier'] is False and result['resets_later'] is False
    assert result['proposed']['timezone'] == 'UTC' and result['proposed']['next_reset'] == _ts(2026, 11, 22)
    assert result['seconds_until_proposed_reset'] == 16 * 3600 + 30 * 60
    assert 'not recorded against a daily cap' in result['carryover']


def test_budget_reset_keeps_the_expansion_confirmation_clock_independent():
    proposed = {'ai_budget_timezone': 'Asia/Tokyo'}
    first = preview.compare(CAPPED, proposed)
    assert preview.budget_reset(CAPPED, proposed, _ts(2026, 11, 21, 1)) != \
        preview.budget_reset(CAPPED, proposed, _ts(2026, 11, 21, 23))
    assert '2026' not in ' '.join(first['expansions'])
    assert preview.compare(CAPPED, proposed)['expansions'] == first['expansions']


def test_preview_route_returns_the_budget_reset_read_only(admin):
    put = confirmed_put(admin, '/api/settings/ai', {'ai_control_mode': 'daily_cap', 'ai_budget_timezone': 'UTC'})
    assert put.status_code == 200, put.text
    with Session() as s:
        before, audits = config(s), _audit_count(s)
    body = admin.post('/api/settings/ai/preview', json={'ai_budget_timezone': 'Asia/Tokyo'}).json()
    reset = body['budget_reset']
    assert reset['current']['timezone'] == 'UTC' and reset['proposed']['timezone'] == 'Asia/Tokyo'
    assert reset['current']['next_reset'] > reset['generated_at'] and reset['proposed']['next_reset'] > reset['generated_at']
    assert body['expands'] and body['expansion_confirmation']
    assert admin.post('/api/settings/ai/preview', json={'ai_daily_cap_usd': 5}).json()['budget_reset'] is None
    with Session() as s:
        assert config(s) == before and _audit_count(s) == audits


def _counted_after_timezone_change(created, first, second, now):
    """Ledger amount ``ai_budget.status`` counts at ``now`` for one sent $0.004 row, before and after a change."""
    from decimal import Decimal
    from app import ai_budget
    from app.security import seal

    def configure(name):
        with Session() as session:
            session.merge(Setting(key='config', value={
                'ai_enabled': True, 'ai_model': 'gpt-6-luna', 'ai_control_mode': 'daily_cap',
                'ai_rate_per_hour': 20, 'ai_daily_cap_usd': 0.01, 'ai_budget_timezone': name}))
            session.merge(Setting(key='openai_key', value={'encrypted': seal('fixture')}))
            session.commit()

    _start, reset = ai_budget._window(created, first)
    configure(first)
    with Session() as session:
        session.add(ai_budget.BudgetEntry(id='00000000-0000-0000-0000-000000001269', created=created, updated=created,
            reset_at=reset, timezone=first, model='gpt-6-luna', status='sent', reservation_usd=Decimal('0.004'),
            pricing_version='t', pricing_source='t'))
        session.commit()
    with Session() as session:
        before = Decimal(ai_budget.status(session, now)['counted_usd'])
    configure(second)
    with Session() as session:
        after = Decimal(ai_budget.status(session, now)['counted_usd'])
    return before, after


def test_budget_reset_discloses_spend_counted_past_its_own_reset(admin):
    # UTC -> Los Angeles moves the reset west: a row made at 10:00 UTC reset at midnight UTC under the
    # stored zone, but it lies inside the proposed 08:00-08:00 UTC window, so it keeps counting (#1269 review).
    created = _ts(2026, 11, 24, 10)
    result = preview.budget_reset(CAPPED, {'ai_budget_timezone': 'America/Los_Angeles'}, created)
    assert result['resets_later'] is True and result['starts_earlier'] is False and not result['resets_sooner']
    assert 'a proposed reset that is later keeps current spend counted until that reset' in result['carryover']
    before, after = _counted_after_timezone_change(created, 'UTC', 'America/Los_Angeles', _ts(2026, 11, 25, 1))
    assert before == 0 and after > 0


def test_budget_reset_discloses_recounted_spend_from_an_already_reset_window(admin):
    # Tokyo -> Los Angeles at 16:00 UTC: a 14:00 UTC row already reset at 15:00 UTC under Tokyo and counts
    # nothing, but the proposed window started at 08:00 UTC, so saving counts it again at once (#1269 review).
    now = _ts(2026, 11, 24, 16)
    stored = CAPPED | {'ai_budget_timezone': 'Asia/Tokyo'}
    result = preview.budget_reset(stored, {'ai_budget_timezone': 'America/Los_Angeles'}, now)
    assert result['starts_earlier'] is True and result['resets_sooner'] is True and not result['resets_later']
    assert 'can count again spend from a window that has already reset' in result['carryover']
    before, after = _counted_after_timezone_change(_ts(2026, 11, 24, 14), 'Asia/Tokyo', 'America/Los_Angeles', now)
    assert before == 0 and after > 0
