"""Non-expanding legacy-to-shared-rate migration proposal (#879, fixes #878)."""
import pytest

from app import ai_control_preview as preview
from app.db import Session, Setting

LEGACY = {'ai_control_mode': 'legacy', 'ai_rate_per_hour': 20, 'ai_daily_cap_usd': 10.0,
          'ai_budget_timezone': 'UTC', 'ai_hourly_limit': 20, 'ai_update_hourly_limit': 20,
          'ai_updates_enabled': True}


@pytest.mark.parametrize('overrides,expected', [
    ({}, 10),  # defaults: the fixed 10/hour automatic-plan allowance is the lowest (#878)
    ({'ai_hourly_limit': 4}, 4),
    ({'ai_update_hourly_limit': 3}, 3),
    # Disabled scoring stays off after the change, so its limit does not lower the rate.
    ({'ai_updates_enabled': False, 'ai_update_hourly_limit': 2, 'ai_hourly_limit': 30}, 10),
    ({'ai_updates_enabled': False, 'ai_hourly_limit': 6}, 6),
    ({'ai_hourly_limit': 1000, 'ai_update_hourly_limit': 1000}, 10),
])
def test_proposal_is_lowest_enabled_allowance_and_never_expands(overrides, expected):
    values = LEGACY | overrides
    result = preview.legacy_migration(values)
    assert result['required'] is True
    assert result['suggested_rate_per_hour'] == expected
    assert result['proposal'] == {'ai_control_mode': 'rate', 'ai_rate_per_hour': expected}
    assert result['proposal_expands'] is False and result['proposal_expansions'] == []
    # Independent check through the public comparison used by Settings and the audit.
    compared = preview.compare(values, result['proposal'])
    assert compared['changed'] and not compared['expands']
    for key, before in compared['before']['hourly_starts'].items():
        after = compared['after']['hourly_starts'][key]
        assert after <= before, key


def test_reports_hidden_allowances_with_disabled_scoring_off():
    result = preview.legacy_migration(LEGACY | {'ai_updates_enabled': False, 'ai_hourly_limit': 12})
    assert result['legacy_hourly_starts'] == {'triage': 12, 'update_scoring': 0, 'automatic_plans': 10}
    assert result['legacy_investigations_per_hour'] == 12
    assert result['legacy_scoring_batches_per_hour'] == 20


def test_explicit_modes_do_not_require_migration_but_still_report_safely():
    result = preview.legacy_migration(LEGACY | {'ai_control_mode': 'rate_and_daily'})
    assert result['required'] is False
    # The proposal is computed against the stored legacy fields only for display.
    assert result['suggested_rate_per_hour'] == 10


def test_previous_default_suggestion_expanded_automatic_plans():
    # Regression evidence for #878: the old min(triage, scoring) suggestion of 20/hour
    # raised the automatic-plan ceiling from 10/hour to 20/hour.
    old = preview.compare(LEGACY, {'ai_control_mode': 'rate', 'ai_rate_per_hour': 20})
    assert old['expands']
    assert any('Automatic incident/startup plans start ceiling changes from 10/hour to 20/hour' in text
               for text in old['expansions'])


def test_settings_route_returns_non_expanding_proposal_without_saving(admin):
    with Session() as session:
        session.merge(Setting(key='config', value={'ai_enabled': False, 'ai_model': '',
                                                   'ai_hourly_limit': 20, 'ai_update_hourly_limit': 20}))
        session.commit()
    state = admin.get('/api/settings').json()
    migration = state['ai_control_migration']
    assert state['ai_control_mode'] == 'legacy'
    assert migration['required'] is True and migration['suggested_rate_per_hour'] == 10
    assert migration['proposal'] == {'ai_control_mode': 'rate', 'ai_rate_per_hour': 10}
    assert migration['proposal_expands'] is False
    previewed = admin.post('/api/settings/ai/preview', json=migration['proposal']).json()
    assert previewed['changed'] and not previewed['expands']
    # Reading the proposal never switches the mode.
    assert admin.get('/api/settings').json()['ai_control_mode'] == 'legacy'
