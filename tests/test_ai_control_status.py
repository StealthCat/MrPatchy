from decimal import Decimal

from app import ai_admission, ai_budget, ai_control_status, ai_provider_backoff
from app.db import Session, Setting


def configure(*, enabled=True, model='fixture-model', mode='unthrottled', rate=20, cap=10):
    with Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': enabled,
            'ai_model': model,
            'ai_control_mode': mode,
            'ai_rate_per_hour': rate,
            'ai_daily_cap_usd': cap,
            'ai_budget_timezone': 'UTC',
        }))
        session.merge(Setting(key='openai_key', value={'encrypted': 'fixture'}))
        session.commit()


def test_snapshot_uses_latest_simultaneous_gate_without_exposing_records(admin):
    now = 2_000_000_000.0
    budget_reset = ai_budget._window(now, 'UTC')[1]
    configure(mode='rate_and_daily', cap=0.01)
    with Session() as session:
        session.add_all([
            ai_admission.Admission(id='global', next_at=now + 60, admitted=7, updated=now, model='private-model'),
            ai_provider_backoff.ProviderBackoff(id='global', blocked_until=now + 120, failures=2,
                updated=now, reason='private provider detail'),
            ai_budget.BudgetEntry(id='private-call-id', run_id='private-run-id', call_id='private-receipt-id',
                created=now - 10, updated=now - 5, reset_at=budget_reset, timezone='UTC', model='private-model',
                status='reserved', reservation_usd=Decimal('0.01'), pricing_version='private-version',
                pricing_source='https://private.example.test'),
        ])
        session.commit()
        result = ai_control_status.snapshot(session, now)

    assert not result['can_start_now']
    assert result['next_start_at'] == budget_reset
    assert [(item['code'], item['next_at']) for item in result['blockers']] == [
        ('provider_backoff', now + 120),
        ('rate_throttle', now + 60),
        ('daily_cap', budget_reset),
    ]
    rendered = str(result)
    for private in ('private-call-id', 'private-run-id', 'private-receipt-id', 'private-model',
                    'private-version', 'private.example.test', 'private provider detail'):
        assert private not in rendered


def test_indefinite_policy_or_configuration_blocker_refuses_a_claimed_time(admin):
    configure(enabled=False, model='', mode='rate')
    with Session() as session:
        session.delete(session.get(Setting, 'openai_key'))
        session.add(ai_admission.Admission(id='global', next_at=1300, admitted=1, updated=1000, model='m'))
        session.commit()
        result = ai_control_status.snapshot(session, 1000)
    assert not result['can_start_now'] and result['next_start_at'] is None
    assert [item['code'] for item in result['blockers']] == ['disabled', 'configuration', 'rate_throttle']


def test_unthrottled_configured_snapshot_is_read_only_and_explains_remaining_gates(admin):
    configure()
    response = admin.get('/api/settings/ai-control-status')
    assert response.status_code == 200
    result = response.json()
    assert result['mode'] == 'unthrottled' and result['can_start_now']
    assert result['next_start_at'] is None and result['blockers'] == []
    assert 'call-specific conservative price quote' in result['limitations'][0]
    with Session() as session:
        assert session.get(ai_admission.Admission, 'global') is None
        assert session.get(ai_provider_backoff.ProviderBackoff, 'global') is None
        assert not list(session.query(ai_budget.BudgetEntry))


def test_control_snapshot_requires_admin(client):
    assert client.get('/api/settings/ai-control-status').status_code in (401, 403)
