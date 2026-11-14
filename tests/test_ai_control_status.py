from decimal import Decimal
from datetime import datetime, timezone

from app import ai_admission, ai_budget, ai_control_status, ai_pricing, ai_provider_backoff
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


def priced_catalog(monkeypatch):
    # These cases exercise other gates; keep the #735 pricing gate open for them.
    monkeypatch.setattr(ai_pricing, 'VERIFIED_AT', 0)
    monkeypatch.setattr(ai_pricing, 'EXPIRES_AT', 4_000_000_000)


def test_snapshot_uses_latest_simultaneous_gate_without_exposing_records(admin, monkeypatch):
    priced_catalog(monkeypatch)
    now = 2_000_000_000.0
    budget_reset = ai_budget._window(now, 'UTC')[1]
    configure(model='gpt-6-luna', mode='rate_and_daily', cap=0.01)
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


def test_timezone_overlap_exposes_recheck_without_promising_headroom(admin, monkeypatch):
    priced_catalog(monkeypatch)
    now = datetime(2026, 3, 8, 8, 0, tzinfo=timezone.utc).timestamp()
    created = datetime(2026, 3, 7, 22, 0, tzinfo=timezone.utc).timestamp()
    configure(model='gpt-6-luna', mode='daily_cap', cap=1)
    old_reset = ai_budget._window(created, 'Pacific/Pago_Pago')[1]
    configured_reset = ai_budget._window(now, 'Pacific/Kiritimati')[1]
    with Session() as session:
        settings = session.get(Setting, 'config').value
        settings['ai_budget_timezone'] = 'Pacific/Kiritimati'
        session.merge(Setting(key='config', value=settings))
        session.add(ai_budget.BudgetEntry(id='old-window', created=created, updated=created,
            reset_at=old_reset, timezone='Pacific/Pago_Pago', model='fixture-model', status='sent',
            reservation_usd=Decimal('1'), pricing_version='fixture', pricing_source='fixture'))
        session.commit()
        result = ai_control_status.snapshot(session, now)
        assert ai_budget.status(session, configured_reset)['remaining_usd'] == '0'
        assert ai_budget.status(session, old_reset)['remaining_usd'] == '1'

    blocker = result['blockers'][0]
    assert blocker['code'] == 'daily_cap'
    assert blocker['next_at'] is None
    assert blocker['recheck_at'] == configured_reset
    assert result['next_start_at'] is None
    assert 'recheck boundary only' in blocker['message']


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


def test_legacy_mode_discloses_unreflected_per_purpose_hourly_limits(admin):
    configure(mode='legacy')
    with Session() as session:
        result = ai_control_status.snapshot(session, 1000)
    assert result['mode'] == 'legacy'
    assert result['limitations'][:len(ai_control_status.LIMITATIONS)] == ai_control_status.LIMITATIONS
    assert result['limitations'][-1] == ai_control_status.LEGACY_LIMITATION
    assert 'per-purpose hourly allowances' in result['limitations'][-1]
    for mode in ('rate', 'daily_cap', 'rate_and_daily', 'unthrottled'):
        configure(mode=mode)
        with Session() as session:
            assert ai_control_status.snapshot(session, 1000)['limitations'] == ai_control_status.LIMITATIONS
            assert ai_control_status.snapshot(session, 1000)['purpose_limits'] == []


def legacy_config(**values):
    configure(mode='legacy')
    with Session() as session:
        settings = dict(session.get(Setting, 'config').value)
        settings.update(values)
        session.merge(Setting(key='config', value=settings))
        session.commit()


def add_history(*, attempts=(), triage=(), scoring=(), plans=(), other_jobs=()):
    from app.ai_runs import AIRun
    from app.db import Behavior, Job
    with Session() as session:
        for index, at in enumerate(attempts):
            session.add(Behavior(id=f'private-behavior-{index}', host_id='private-host', evidence={'cmd': 'private'},
                                 attempted=at))
        for purpose, times in (('triage', triage), ('update_scoring', scoring)):
            for index, at in enumerate(times):
                session.add(AIRun(id=f'private-{purpose}-{index}', purpose=purpose, host_id='private-host',
                                  model='private-model', subject='private-subject', started=at))
        for index, (action, at) in enumerate([*plans, *other_jobs]):
            session.add(Job(id=f'private-job-{index}', host_id='private-host', action=action,
                            payload={'private': True}, created=at))
        session.commit()


def limits_by_purpose(now):
    with Session() as session:
        result = ai_control_status.snapshot(session, now)
    return result, {item['purpose']: item for item in result['purpose_limits']}


def test_legacy_allowances_report_exact_sliding_window_opening(admin):
    now = 2_000_000_000.0
    legacy_config(ai_hourly_limit=3, ai_update_hourly_limit=2)
    # Five scoring runs in the window with a limit of two: the gate reopens
    # when only one remains, i.e. after the fourth-oldest entry expires.
    add_history(scoring=(now - 3000, now - 2500, now - 2000, now - 1500, now - 10),
                plans=[('security-plan', now - 3500 + i) for i in range(6)] +
                      [('startup-plan', now - 1000 + i) for i in range(4)],
                other_jobs=[('refresh', now - 100), ('security-plan', now - 3600)])
    result, limits = limits_by_purpose(now)

    assert [item['purpose'] for item in result['purpose_limits']] == ['triage', 'update_scoring', 'automatic_plans']
    assert limits['triage'] == {'purpose': 'triage', 'limit': 3, 'used': 0, 'state': 'available', 'next_at': None}
    assert limits['update_scoring'] == {'purpose': 'update_scoring', 'limit': 2, 'used': 5,
                                        'state': 'exhausted', 'next_at': now - 1500 + 3600}
    # Ten plans counted (the run exactly an hour old is outside the window);
    # with the fixed limit of ten the oldest must leave first.
    assert limits['automatic_plans'] == {'purpose': 'automatic_plans', 'limit': 10, 'used': 10,
                                         'state': 'exhausted', 'next_at': now - 3500 + 3600}
    # Per-purpose holds do not change the shared global gates.
    assert result['can_start_now'] and result['blockers'] == [] and result['next_start_at'] is None
    rendered = str(result)
    for private in ('private-behavior', 'private-host', 'private-model', 'private-subject', 'private-job',
                    'private-triage', 'private-update'):
        assert private not in rendered

    # At the opening instant the window has dropped below the limit.
    _, limits = limits_by_purpose(now - 1500 + 3600)
    assert limits['update_scoring']['state'] == 'available' and limits['update_scoring']['used'] == 1
    assert limits['update_scoring']['next_at'] is None


def test_legacy_triage_allowance_waits_for_both_admission_counters(admin):
    now = 2_000_000_000.0
    legacy_config(ai_hourly_limit=2)
    add_history(attempts=(now - 3000, now - 2900, now - 100), triage=(now - 2000, now - 1000, now - 50, now - 40))
    _, limits = limits_by_purpose(now)
    # Attempts reopen at (now-2900)+3600; runs reopen at (now-50)+3600. Admission
    # needs both counters below the limit, so the later time applies.
    assert limits['triage'] == {'purpose': 'triage', 'limit': 2, 'used': 4, 'state': 'exhausted',
                                'next_at': now - 50 + 3600}

    # Exhausting only one counter still holds triage.
    with Session() as session:
        from app.ai_runs import AIRun
        session.query(AIRun).delete()
        session.commit()
    _, limits = limits_by_purpose(now)
    assert limits['triage'] == {'purpose': 'triage', 'limit': 2, 'used': 3, 'state': 'exhausted',
                                'next_at': now - 2900 + 3600}


def test_disabled_update_scoring_is_not_reported_as_exhausted(admin):
    now = 2_000_000_000.0
    legacy_config(ai_update_hourly_limit=1, ai_updates_enabled=False)
    add_history(scoring=(now - 30, now - 20))
    _, limits = limits_by_purpose(now)
    assert limits['update_scoring'] == {'purpose': 'update_scoring', 'limit': 1, 'used': 2,
                                        'state': 'disabled', 'next_at': None}


def test_legacy_allowances_match_actual_admission_refusals(admin, monkeypatch):
    # The reported counters use the same predicates admission enforces.
    from app import ai_claims
    now = 2_000_000_000.0
    legacy_config(ai_hourly_limit=2)
    add_history(attempts=(now - 30, now - 20))
    monkeypatch.setattr(ai_claims.time, 'time', lambda: now)
    assert ai_claims.acquire() is None
    _, limits = limits_by_purpose(now)
    assert limits['triage']['state'] == 'exhausted' and limits['triage']['next_at'] == now - 30 + 3600


def test_control_snapshot_requires_admin(client):
    assert client.get('/api/settings/ai-control-status').status_code in (401, 403)
