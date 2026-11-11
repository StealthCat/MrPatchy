from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from decimal import Decimal
import threading

import httpx
import pytest

from app import ai, ai_admission, ai_budget, ai_pricing, ai_provider_backoff, notifications, operations
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


@pytest.mark.parametrize('mode', ['legacy', 'rate', 'unthrottled'])
def test_uncapped_reservation_skips_shared_lock_and_quote(admin, monkeypatch, mode):
    configure(mode=mode)
    actions = []
    lock = ai_budget.Lock
    quote = ai_pricing.reservation

    def record_lock(name):
        actions.append(name)
        return lock(name)

    def record_quote(request):
        actions.append('quote')
        return quote(request)

    monkeypatch.setattr(ai_budget, 'Lock', record_lock)
    monkeypatch.setattr(ai_pricing, 'reservation', record_quote)
    assert ai_budget.reserve(payload()) is None
    assert actions == []
    with Session() as session:
        assert session.query(ai_budget.BudgetEntry).count() == 0


@pytest.mark.parametrize('new_mode,new_cap', [
    ('rate', Decimal('1')),
    ('daily_cap', Decimal('0.000001')),
])
def test_capped_reservation_rereads_settings_after_lock(admin, monkeypatch, new_mode, new_cap):
    configure(cap=Decimal('1'))
    lock = ai_budget.Lock
    quote = ai_pricing.reservation
    actions = []

    @contextmanager
    def change_settings_while_entering(name):
        assert name == 'ai-shared-budget'
        configure(mode=new_mode, cap=new_cap)
        with lock(name):
            actions.append('lock')
            yield

    def record_quote(request):
        actions.append('quote')
        return quote(request)

    monkeypatch.setattr(ai_budget, 'Lock', change_settings_while_entering)
    monkeypatch.setattr(ai_pricing, 'reservation', record_quote)
    if new_mode == 'rate':
        assert ai_budget.reserve(payload('unknown-model')) is None
        assert actions == ['lock']
    else:
        with pytest.raises(ai.AIError, match='no remaining safe reservation'):
            ai_budget.reserve(payload())
        assert actions == ['lock', 'quote']
    with Session() as session:
        assert session.query(ai_budget.BudgetEntry).count() == 0


def test_capped_catalog_warning_escalates_deduplicates_and_resolves(admin):
    configure(mode='daily_cap')
    warning_at=ai_pricing.EXPIRES_AT-operations.AI_PRICING_CATALOG_WARNING_SECONDS
    operations.collect_alerts(warning_at-1)
    with Session() as session:
        assert not session.query(operations.Alert).filter_by(kind='AI pricing catalog').count()
        assert not session.query(notifications.NotificationEvent).filter_by(kind='pricing-catalog').count()

    operations.collect_alerts(warning_at)
    operations.collect_alerts(warning_at+60)
    with Session() as session:
        alert=session.query(operations.Alert).filter_by(kind='AI pricing catalog').one()
        event=session.query(notifications.NotificationEvent).filter_by(kind='pricing-catalog').one()
        revision=session.get(notifications.NotificationRevision,(event.id,event.revision))
        assert alert.host_id=='controller' and alert.state=='open'
        assert event.minimum_role=='admin' and event.revision==1
        assert revision.severity=='medium' and revision.lifecycle=='active'
        assert revision.deep_link=='#settings/ai'
        alert.state='acknowledged';alert.notified=warning_at;alert.attempts=2
        notifications.mark_read(session,'admin',event.id,event.revision,now=warning_at)
        notifications.dismiss(session,'admin',event.id,event.revision,now=warning_at)
        session.commit()

    operations.collect_alerts(ai_pricing.EXPIRES_AT)
    with Session() as session:
        alert=session.query(operations.Alert).filter_by(kind='AI pricing catalog').one()
        event=session.query(notifications.NotificationEvent).filter_by(kind='pricing-catalog').one()
        revision=session.get(notifications.NotificationRevision,(event.id,event.revision))
        assert alert.state=='open' and alert.notified==0 and alert.attempts==0
        assert 'is expired' in alert.message
        assert event.revision==2 and revision.severity=='high' and revision.lifecycle=='active'
        assert notifications.unread_count(session,'admin')==1

    configure(mode='rate')
    operations.collect_alerts(ai_pricing.EXPIRES_AT+60)
    with Session() as session:
        alert=session.query(operations.Alert).filter_by(kind='AI pricing catalog').one()
        event=session.query(notifications.NotificationEvent).filter_by(kind='pricing-catalog').one()
        revision=session.get(notifications.NotificationRevision,(event.id,event.revision))
        assert alert.state=='resolved'
        assert event.revision==3 and revision.severity=='info' and revision.lifecycle=='resolved'


@pytest.mark.parametrize('mode,enabled', [
    ('rate',True),('unthrottled',True),('legacy',True),('daily_cap',False),('rate_and_daily',False),
])
def test_catalog_lifecycle_alert_only_applies_to_enabled_cap_modes(admin,mode,enabled):
    configure(mode=mode)
    with Session() as session:
        row=session.get(Setting,'config');row.value={**row.value,'ai_enabled':enabled};session.commit()
    operations.collect_alerts(ai_pricing.EXPIRES_AT)
    with Session() as session:
        assert not session.query(operations.Alert).filter_by(kind='AI pricing catalog').count()
        assert not session.query(notifications.NotificationEvent).filter_by(kind='pricing-catalog').count()


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


@pytest.mark.parametrize('status,retry_after,transient',[(200,None,False),(503,'90',True)])
def test_oversized_response_retains_charge_and_preserves_status_backoff(admin,monkeypatch,status,retry_after,transient):
    configure(cap=Decimal('1'))
    sent=[]
    headers={'x-private':'secret-provider-value'}
    if retry_after:headers['retry-after']=retry_after
    response=httpx.Response(status,headers=headers,content=b'',request=httpx.Request('POST',ai.URL))
    def oversized(*args,**kwargs):
        sent.append(1);raise ai.transport.ResponseTooLarge(response)
    monkeypatch.setattr(ai.transport,'post',oversized)
    with pytest.raises(ai.AIError) as raised:ai.request(payload(),'fixture-key')
    assert len(sent)==1 and raised.value.transient is transient
    assert 'secret-provider-value' not in raised.value.diagnostic
    with Session() as session:
        row=session.query(ai_budget.BudgetEntry).one()
        assert row.status=='uncertain' and 'oversized response' in row.reason
        assert ai_budget.status(session)['uncertain_usd']!='0'
        backoff=ai_provider_backoff.status(session)
        assert backoff['blocked'] is transient


@pytest.mark.parametrize('status,retry_after,transient',[(200,None,False),(503,'75',True)])
def test_invalid_response_encoding_retains_charge_and_preserves_status_backoff(admin,monkeypatch,status,retry_after,transient):
    configure(cap=Decimal('1'))
    headers={'x-private':'secret-provider-value'}
    if retry_after:headers['retry-after']=retry_after
    response=httpx.Response(status,headers=headers,content=b'',request=httpx.Request('POST',ai.URL))
    monkeypatch.setattr(ai.transport,'post',lambda *args,**kwargs:(_ for _ in ()).throw(ai.transport.ResponseDecodeError(response)))
    with pytest.raises(ai.AIError) as raised:ai.request(payload(),'fixture-key')
    assert raised.value.transient is transient
    assert 'secret-provider-value' not in raised.value.diagnostic
    with Session() as session:
        row=session.query(ai_budget.BudgetEntry).one()
        assert row.status=='uncertain' and 'content encoding' in row.reason
        assert ai_budget.status(session)['uncertain_usd']!='0'
        backoff=ai_provider_backoff.status(session)
        assert backoff['blocked'] is transient


@pytest.mark.parametrize('failure', [httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.ReadError])
def test_transport_failures_with_uncertain_outcomes_remain_counted(admin, monkeypatch, failure):
    configure(cap=Decimal('1'))
    monkeypatch.setattr(ai_pricing.time, 'time', lambda: 1793404800.0)

    def fail(*args, **kwargs):
        raise failure('fixture transport detail')

    monkeypatch.setattr(ai.transport, 'post', fail)
    with pytest.raises(ai.AIError) as error:
        ai.request(payload(), 'fixture-key')
    assert 'fixture transport detail' not in str(error.value)
    with Session() as session:
        assert session.query(ai_budget.BudgetEntry).one().status == 'uncertain'
        assert Decimal(ai_budget.status(session)['uncertain_usd']) == ai_pricing.reservation(payload())['amount_usd']


@pytest.mark.parametrize('call_id', ['', 'call-one'])
def test_pool_timeout_release_requires_matching_sent_call(admin, monkeypatch, call_id):
    configure(cap=Decimal('1'))
    monkeypatch.setattr(ai_pricing.time, 'time', lambda: 1793404800.0)
    identifier = ai_budget.reserve(payload())
    ai_budget.mark_sent(identifier, call_id)
    ai_budget.release_unsent(identifier, 'Wrong receipt.', pool_timeout_call_id='call-two')
    ai_budget.release_unsent(identifier, 'No receipt was supplied.')
    with Session() as session:
        assert session.get(ai_budget.BudgetEntry, identifier).status == 'sent'
    ai_budget.release_unsent(identifier, 'Pool timeout.', pool_timeout_call_id=call_id)
    with Session() as session:
        assert session.get(ai_budget.BudgetEntry, identifier).status == 'released'


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
        session.add_all([
            ai_budget.BudgetEntry(id=identifier,created=now-3600,updated=now-30,reset_at=now-60,
                timezone=zone,model='m',status='reserved',reservation_usd=Decimal(amount),
                pricing_version='v',pricing_source='s')
            for identifier,zone,amount in [
                ('history-match','America/New_York','0.25'),
                ('history-other-case','america/new_york','9.00'),
            ]
        ])
        session.commit()
    assert admin.get('/api/settings/ai-spend-history?days=0').status_code==400
    assert admin.get('/api/settings/ai-spend-history?days=91').status_code==400
    result=admin.get('/api/settings/ai-spend-history?days=1').json()
    assert result['max_windows']==4 and result['truncated'] and len(result['windows'])==4
    assert all(row['timezone']=='UTC' for row in result['windows'])
    base='/api/settings/ai-spend-history?days=1'
    filtered=admin.get(base+'&timezone=America%2FNew_York')
    assert filtered.status_code==200
    data=filtered.json()
    assert not data['truncated'] and len(data['windows'])==1
    row=data['windows'][0]
    assert row['timezone']=='America/New_York' and row['call_count']==1
    assert row['reserved_usd']=='0.25' and row['counted_usd']=='0.25'
    assert admin.get(base+'&timezone=Europe%2FLondon').json()['windows']==[]
    assert admin.get(base+'&timezone=Invalid%2FTimezone').status_code==400
    with Session() as session:session.get(User,'admin').role='viewer';session.commit()
    assert admin.get(base+'&timezone=America%2FNew_York').status_code==403


DAY=1793404800.0  # 2026-10-31T00:00:00Z


def ledger(amount, *, created=DAY+60, status='reserved', reset=DAY+86400):
    import uuid
    with Session() as session:
        session.add(ai_budget.BudgetEntry(id=str(uuid.uuid4()), created=created, updated=created,
            reset_at=reset, timezone='UTC', model='gpt-6-luna', status=status,
            reservation_usd=Decimal(amount), pricing_version='fixture', pricing_source='fixture'))
        session.commit()


def cap_event(session):
    return session.query(notifications.NotificationEvent).filter_by(source='ai-budget', kind='daily-cap').one_or_none()


def cap_revision(session, event):
    return session.get(notifications.NotificationRevision, (event.id, event.revision))


def test_exhausted_daily_cap_notifies_once_per_window_and_resolves_at_reset(admin):
    configure(mode='rate_and_daily', cap=Decimal('1'))
    ledger('0.4')
    operations.collect_alerts(DAY+120)
    with Session() as session:
        assert cap_event(session) is None
    ledger('0.35', status='sent')
    ledger('0.25', status='uncertain')
    operations.collect_alerts(DAY+180)
    with Session() as session:
        event=cap_event(session);revision=cap_revision(session, event)
        assert event.revision==1 and event.minimum_role=='admin' and event.host_id==''
        assert revision.lifecycle=='active' and revision.severity=='medium'
        assert revision.deep_link=='#settings/ai'
        assert '$1 (UTC day)' in revision.reason and '2026-11-01T00:00:00Z' in revision.reason
        assert 'deferred, not discarded' in revision.reason
        notifications.mark_read(session, 'admin', event.id, event.revision, now=DAY+200)
        session.commit()
    # Further spend in the same window is not a new observation.
    ledger('0.5', status='sent')
    operations.collect_alerts(DAY+240)
    with Session() as session:
        assert cap_event(session).revision==1
        assert notifications.unread_count(session, 'admin')==0
        assert not session.query(operations.Alert).filter(operations.Alert.kind.like('%cap%')).count()
    # The reset opens a new window with headroom: one resolved revision, then no churn.
    operations.collect_alerts(DAY+86400+10)
    operations.collect_alerts(DAY+86400+70)
    with Session() as session:
        event=cap_event(session);revision=cap_revision(session, event)
        assert event.revision==2 and revision.lifecycle=='resolved' and revision.severity=='info'
    # Exhaustion in the next window resurfaces as unread.
    ledger('1', created=DAY+86400+100, reset=DAY+2*86400)
    operations.collect_alerts(DAY+86400+130)
    with Session() as session:
        event=cap_event(session);revision=cap_revision(session, event)
        assert event.revision==3 and revision.lifecycle=='active'
        assert '2026-11-02T00:00:00Z' in revision.reason
        assert notifications.unread_count(session, 'admin')==1


@pytest.mark.parametrize('change', ['raise_cap', 'rate_mode', 'unthrottled', 'disabled'])
def test_cap_notification_resolves_when_cap_no_longer_blocks(admin, change):
    configure(mode='daily_cap', cap=Decimal('1'))
    ledger('1')
    operations.collect_alerts(DAY+120)
    if change=='raise_cap':configure(mode='daily_cap', cap=Decimal('2'))
    elif change=='rate_mode':configure(mode='rate')
    elif change=='unthrottled':configure(mode='unthrottled')
    else:
        with Session() as session:
            row=session.get(Setting, 'config');row.value={**row.value, 'ai_enabled': False};session.commit()
    operations.collect_alerts(DAY+180)
    with Session() as session:
        event=cap_event(session)
        assert event.revision==2 and cap_revision(session, event).lifecycle=='resolved'


@pytest.mark.parametrize('mode,enabled', [
    ('rate',True),('unthrottled',True),('legacy',True),('daily_cap',False),('rate_and_daily',False),
])
def test_uncapped_or_disabled_modes_never_create_cap_notification(admin, mode, enabled):
    configure(mode=mode, cap=Decimal('1'))
    with Session() as session:
        row=session.get(Setting, 'config');row.value={**row.value, 'ai_enabled': enabled};session.commit()
    ledger('5', status='settled')
    operations.collect_alerts(DAY+120)
    with Session() as session:
        assert cap_event(session) is None


def test_released_rows_and_headroom_do_not_notify_and_viewers_cannot_see_it(admin):
    from app.identity import User
    with Session() as session:
        session.add(User(username='viewer', password='x', role='viewer'));session.commit()
    configure(mode='daily_cap', cap=Decimal('1'))
    ledger('3', status='released')
    ledger('0.999999')
    operations.collect_alerts(DAY+120)
    with Session() as session:
        assert cap_event(session) is None
    ledger('0.000001')
    operations.collect_alerts(DAY+180)
    with Session() as session:
        event=cap_event(session)
        assert event.minimum_role=='admin'
        assert event.id in {item['id'] for item in notifications.list_for_user(session, 'admin')}
        assert notifications.list_for_user(session, 'viewer')==[]
        assert notifications.unread_count(session, 'viewer')==0
