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


@pytest.mark.parametrize('value,expected', [
    ('0', '0'), ('-0.000', '0'), ('1', '1'), ('10', '10'),
    ('100', '100'), ('1000000', '1000000'), ('1E+6', '1000000'),
    ('10.000000', '10'), ('100.000000000', '100'),
    ('12.500000', '12.5'), ('0.000000010', '0.00000001'),
    ('0E-9', '0'), ('-10', '-10'),
])
def test_money_preserves_integral_zeros(value, expected):
    assert ai_budget._money(Decimal(value)) == expected


@pytest.mark.parametrize('endpoint', ['/api/settings/ai', '/api/settings'])
def test_default_cap_is_normalized_and_matches_budget_summary(admin, endpoint):
    from app.main import AISettingsInput, ConfigInput
    body={'ai_control_mode':'daily_cap'}
    if endpoint == '/api/settings':
        body.update(repo_minutes=60, deadlines={'critical':24,'high':72,'normal':168,'low':720})
    model=AISettingsInput if endpoint.endswith('/ai') else ConfigInput
    assert type(model(**body).ai_daily_cap_usd) is float
    assert admin.put(endpoint, json=body).status_code == 200
    state=admin.get('/api/settings').json()
    assert state['ai_daily_cap_usd'] == 10
    assert state['ai_budget']['cap_usd'] == '10'
    assert state['ai_budget']['remaining_usd'] == '10'


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


def test_pricing_catalog_status_has_exact_freshness_boundaries():
    before=ai_pricing.catalog_status(ai_pricing.VERIFIED_AT-1)
    fresh=ai_pricing.catalog_status(ai_pricing.VERIFIED_AT)
    final=ai_pricing.catalog_status(ai_pricing.EXPIRES_AT-1)
    expired=ai_pricing.catalog_status(ai_pricing.EXPIRES_AT)
    assert before['state']=='not_yet_valid' and not before['fresh']
    assert fresh['state']=='fresh' and fresh['fresh']
    assert final['state']=='fresh' and final['fresh']
    assert expired['state']=='expired' and not expired['fresh']
    assert expired['version']==ai_pricing.VERSION
    assert expired['source']==ai_pricing.SOURCE
    assert expired['verified_at']<expired['expires_at']


def test_expired_catalog_blocks_capped_call_before_rate_or_provider(admin, monkeypatch):
    configure(mode='rate_and_daily')
    sent=[]
    monkeypatch.setattr(ai_pricing.time, 'time', lambda: ai_pricing.EXPIRES_AT)
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: sent.append(True))
    with pytest.raises(ai.AIError, match='catalog has expired'):
        ai.request(payload(), 'fixture-key')
    with Session() as session:
        assert session.get(ai_admission.Admission, 'global') is None
        assert not session.query(ai_budget.BudgetEntry).count()
        catalog=ai_budget.status(session)['pricing_catalog']
    assert catalog['state']=='expired' and not catalog['fresh']
    assert sent == []


@pytest.mark.parametrize('mode', ['rate', 'unthrottled'])
def test_expired_catalog_does_not_add_a_spend_guard_without_a_cap(admin, monkeypatch, mode):
    configure(mode=mode)
    monkeypatch.setattr(ai_pricing.time, 'time', lambda: ai_pricing.EXPIRES_AT)
    # Budget admission remains disabled in modes that do not promise a daily cap.
    assert ai_budget.reserve(payload()) is None


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
    assert state['ai_budget']['pricing_catalog']['state']=='fresh'
    assert state['ai_budget']['pricing_catalog']['expires_at']==ai_pricing.EXPIRES_AT
    body['ai_budget_timezone']='Not/A_Zone'
    assert admin.put('/api/settings/ai',json=body).status_code==400


@pytest.mark.parametrize('first,second', [
    ('UTC', 'Pacific/Kiritimati'), ('Pacific/Kiritimati', 'UTC'),
    ('UTC', 'Pacific/Pago_Pago'), ('America/New_York', 'Asia/Tokyo'),
])
def test_timezone_change_does_not_regrant_spent_budget(admin, first, second):
    from datetime import datetime, timezone
    now = datetime(2026, 3, 8, 23, 0, tzinfo=timezone.utc).timestamp()  # US DST change day
    created = now - 18 * 3600
    configure(mode='daily_cap', cap=Decimal('1'), timezone=first)
    start, reset = ai_budget._window(created, first)
    with Session() as session:
        session.add(ai_budget.BudgetEntry(id='e1', created=created, updated=created, reset_at=reset, timezone=first,
            model='gpt-6-luna', status='settled', reservation_usd=Decimal('1'), actual_usd=Decimal('1'),
            pricing_version='t', pricing_source='t'))
        session.commit()
    with Session() as session:
        before = ai_budget.status(session, created + 60)
        assert before['remaining_usd'] == '0'
    configure(mode='daily_cap', cap=Decimal('1'), timezone=second)
    with Session() as session:
        assert ai_budget.status(session, now)["remaining_usd"] == "0"
        # Once the original window has ended and the new one holds nothing, spend is released.
        late = reset + 2 * 86400
        assert ai_budget.status(session, late)['remaining_usd'] == '1'


def test_status_totals_use_sql_aggregates_without_loading_ledger(admin):
    import time
    from sqlalchemy import event
    configure(mode='daily_cap', cap=Decimal('100'))
    now=time.time()
    def entry(i,status,reserve,actual=None):
        return ai_budget.BudgetEntry(id=f'00000000-0000-0000-0000-{i:012d}',created=now,updated=now,reset_at=now+3600,
            timezone='UTC',model='m',status=status,reservation_usd=Decimal(reserve),actual_usd=actual,
            pricing_version='v',pricing_source='s')
    rows=[entry(i,'settled','0.1',Decimal('0.000000003')) for i in range(300)]
    rows+=[entry(1000+i,'reserved','0.002') for i in range(200)]
    rows+=[entry(2000+i,'sent','0.003') for i in range(50)]
    rows+=[entry(3000+i,'uncertain','0.004') for i in range(50)]
    rows+=[entry(4000+i,'released','5') for i in range(100)]
    with Session() as session:
        session.add_all(rows);session.commit()
    loaded=[]
    def on_load(*args):loaded.append(1)
    event.listen(ai_budget.BudgetEntry,'load',on_load)
    try:
        with Session() as session:
            result=ai_budget.status(session,now)
    finally:
        event.remove(ai_budget.BudgetEntry,'load',on_load)
    assert not loaded
    assert result['settled_usd']=='0.0000009'
    assert result['reserved_usd']=='0.4'
    assert result['uncertain_usd']=='0.35'
    assert result['counted_usd']=='0.7500009'
    assert result['remaining_usd']=='99.2499991'


def test_unrecognized_status_rows_stay_counted_and_block_admission(admin):
    import time
    configure(mode='daily_cap', cap=Decimal('1'))
    now=time.time()
    with Session() as session:
        session.add(ai_budget.BudgetEntry(id='00000000-0000-0000-0000-000000000001',created=now,updated=now,reset_at=now+3600,
            timezone='UTC',model='m',status='legacy_pending',reservation_usd=Decimal('1'),pricing_version='v',pricing_source='s'))
        session.commit()
        result=ai_budget.status(session,now)
    assert result['counted_usd']=='1' and result['remaining_usd']=='0'
    with pytest.raises(ai.AIError, match='safe reservation'):
        ai_budget.reserve(payload())
    with Session() as session:
        assert session.query(ai_budget.BudgetEntry).count()==1


def test_spend_history_aggregates_exact_persisted_windows_without_loading_ledger(admin):
    from sqlalchemy import event
    import time
    now=time.time()
    def entry(identifier,timezone,reset,status,reserve,actual=None):
        created=min(reset-3600,now-60)
        return ai_budget.BudgetEntry(id=identifier,created=created,updated=created+30,reset_at=reset,
            timezone=timezone,model='private-model-name',status=status,reservation_usd=Decimal(reserve),actual_usd=actual,
            pricing_version='catalog-test',pricing_source='https://pricing.example.test/private')
    current=ai_budget._window(now,'UTC')[1]
    older=now-2*86400
    rows=[
        entry('history-settled','UTC',current,'settled','9',Decimal('0.125')),
        entry('history-reserved','UTC',current,'reserved','0.2'),
        entry('history-sent','UTC',current,'sent','0.3'),
        entry('history-uncertain','UTC',current,'uncertain','0.4'),
        entry('history-other','UTC',current,'legacy_pending','0.5'),
        entry('history-released','UTC',current,'released','99'),
        entry('history-old','America/New_York',older,'settled','1',Decimal('0.75')),
    ]
    with Session() as session:session.add_all(rows);session.commit()
    loaded=[]
    def on_load(*args):loaded.append(1)
    event.listen(ai_budget.BudgetEntry,'load',on_load)
    try:response=admin.get('/api/settings/ai-spend-history?days=30')
    finally:event.remove(ai_budget.BudgetEntry,'load',on_load)
    assert response.status_code==200 and not loaded
    data=response.json();assert data['days']==30 and not data['truncated']
    assert len(data['windows'])==2
    current_window=next(row for row in data['windows'] if row['timezone']=='UTC')
    assert current_window=={
        'timezone':'UTC','window_start':pytest.approx(current-86400),'reset_at':current,'call_count':5,
        'settled_usd':'0.125','reserved_usd':'0.2','sent_usd':'0.3','uncertain_usd':'0.4',
        'other_usd':'0.5','counted_usd':'1.525',
    }
    assert 'private-model-name' not in response.text
    assert 'pricing.example.test' not in response.text


def test_spend_history_validates_range_role_and_bounds_group_rows(admin):
    from app.identity import User
    import time
    now=time.time()
    with Session() as session:
        session.add_all([ai_budget.BudgetEntry(id=f'history-{i}',created=now-60,updated=now-30,reset_at=now+i+1,
            timezone='UTC',model='m',status='reserved',reservation_usd=Decimal('0.01'),
            pricing_version='v',pricing_source='s') for i in range(12)])
        session.commit()
    assert admin.get('/api/settings/ai-spend-history?days=0').status_code==400
    assert admin.get('/api/settings/ai-spend-history?days=91').status_code==400
    result=admin.get('/api/settings/ai-spend-history?days=1').json()
    assert result['max_windows']==4 and result['truncated'] and len(result['windows'])==4
    with Session() as session:session.get(User,'admin').role='viewer';session.commit()
    assert admin.get('/api/settings/ai-spend-history').status_code==403
