from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
import threading

import pytest

from app import ai, ai_admission, ai_budget, ai_pricing
from app.db import Session, Setting


def configure(mode='daily_cap', cap=Decimal('0.01'), timezone='UTC', rate=20):
    with Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': True, 'ai_model': 'gpt-6-luna',
            'ai_control_mode': mode, 'ai_rate_per_hour': rate,
            'ai_daily_cap_usd': float(cap), 'ai_budget_timezone': timezone,
        }))
        session.commit()


def payload(model='gpt-6-luna', output=1000):
    return {'model': model, 'input': 'bounded evidence', 'max_output_tokens': output,
            'store': False, 'service_tier': 'default'}


def test_capped_unknown_pricing_fails_before_rate_or_provider(admin, monkeypatch):
    configure(mode='rate_and_daily')
    sent=[]
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: sent.append(True))
    with pytest.raises(ai.AIError, match='safe reservation'):
        ai.request(payload('private-model'), 'fixture-key')
    with Session() as session:
        assert session.get(ai_admission.Admission, 'global') is None
        assert not session.query(ai_budget.BudgetEntry).count()
    assert sent == []


def test_daily_cap_reservation_is_atomic_and_reports_reset(admin, monkeypatch):
    quote=ai_pricing.reservation(payload())['amount_usd']
    configure(cap=quote+Decimal('0.000001'))
    monkeypatch.setattr(ai_budget.time, 'time', lambda: 1793404800.0)  # 2026-10-31 UTC
    barrier=threading.Barrier(8)
    def attempt(_):
        barrier.wait(timeout=10)
        try:return ai_budget.reserve(payload())
        except ai.AIError:return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        values=list(pool.map(attempt, range(8)))
    assert sum(value is not None for value in values)==1
    with Session() as session:
        state=ai_budget.status(session)
        assert state['mode']=='daily_cap'
        assert Decimal(state['reserved_usd'])==quote
        assert Decimal(state['remaining_usd'])==Decimal('0.000001')
        assert state['next_reset']==pytest.approx(1793491200)


def test_actual_usage_reconciles_but_sent_failure_retains_uncertain_charge(admin, monkeypatch):
    configure(cap=Decimal('1'))
    monkeypatch.setattr(ai_budget.time, 'time', lambda: 1793404800.0)
    first=ai_budget.reserve(payload())
    ai_budget.mark_sent(first, 'call-one')
    ai_budget.reconcile(first, {
        'status':'estimated', 'pricing':{'estimated_usd':'0.000123'},
        'reason':'Public token-rate estimate; actual billing may differ.',
    })
    second=ai_budget.reserve(payload())
    ai_budget.mark_sent(second, 'call-two')
    ai_budget.mark_uncertain(second, 'Provider outcome is unknown after a timeout.')
    with Session() as session:
        state=ai_budget.status(session)
        assert state['settled_usd']=='0.000123'
        assert Decimal(state['uncertain_usd'])==ai_pricing.reservation(payload())['amount_usd']
        assert Decimal(state['counted_usd'])==Decimal('0.000123')+ai_pricing.reservation(payload())['amount_usd']
        assert session.get(ai_budget.BudgetEntry, second).status=='uncertain'


def test_unsent_failure_releases_reservation(admin, monkeypatch):
    configure(cap=Decimal('1'))
    monkeypatch.setattr(ai_budget.time, 'time', lambda: 1793404800.0)
    identifier=ai_budget.reserve(payload())
    ai_budget.release_unsent(identifier, 'No provider request was sent.')
    with Session() as session:
        assert ai_budget.status(session)['counted_usd']=='0'
        assert session.get(ai_budget.BudgetEntry, identifier).status=='released'


def test_settings_expose_combined_cap_and_validate_timezone(admin):
    body={'ai_model':'gpt-6-luna','ai_enabled':False,'ai_updates_enabled':True,
          'ai_hourly_limit':20,'ai_update_hourly_limit':20,
          'ai_control_mode':'rate_and_daily','ai_rate_per_hour':30,
          'ai_daily_cap_usd':12.5,'ai_budget_timezone':'America/New_York'}
    result=admin.put('/api/settings/ai',json=body)
    assert result.status_code==200
    state=admin.get('/api/settings').json()
    assert state['ai_control_mode']=='rate_and_daily'
    assert state['ai_budget']['cap_usd']=='12.5'
    assert state['ai_budget']['timezone']=='America/New_York'
    body['ai_budget_timezone']='Not/A_Zone'
    assert admin.put('/api/settings/ai',json=body).status_code==400
