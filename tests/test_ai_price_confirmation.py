"""Administrator-confirmed AI price catalog (#1487).

An administrator can reverify the catalogued public token rates in Settings and
start a new bounded validity window without a release. The newer of the bundled
and confirmed catalogs applies, an expired confirmation fails closed, and the
confirmed catalog can never add models or change rate structure.
"""
from decimal import Decimal
import time

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_budget, ai_pricing, main
from app.db import Audit, Session, Setting
from app.security import seal

URL = '/api/settings/ai-price-catalog'
PAYLOAD = {'model': 'gpt-6-astra', 'max_output_tokens': 100_000, 'input': 'fixture'}


def current(admin):
    response = admin.get(URL)
    assert response.status_code == 200
    return response.json()


def confirm_body(catalog, *, rates=None, days=30, **extra):
    table = {model: [values[field] for field in ai_pricing.RATE_FIELDS]
             for model, values in catalog['rates'].items()} if rates is None else rates
    return {'expected_revision': catalog['revision'], 'rates': table, 'days': days,
            'checked_source': True, 'confirmation': 'CONFIRM PRICES', **extra}


def doubled(catalog):
    return {model: [None if value is None else format(Decimal(value) * 2, 'f') for value in
                    (values[field] for field in ai_pricing.RATE_FIELDS)]
            for model, values in catalog['rates'].items()}


def stored():
    with Session() as s:
        row = s.get(Setting, ai_pricing.STORED_KEY)
        return row.value if row else None


def audits():
    with Session() as s:
        return [row.detail for row in s.scalars(select(Audit).where(Audit.action == 'confirm AI price catalog'))]


def test_settings_view_starts_from_the_bundled_catalog(admin):
    catalog = current(admin)
    assert catalog['origin'] == 'bundled' and catalog['version'] == ai_pricing.VERSION
    assert catalog['rates'] == catalog['bundled_rates']
    assert set(catalog['rates']) == set(ai_pricing.RATES)
    assert catalog['rates']['gpt-4.1']['cache_write'] is None
    assert catalog['max_confirmation_days'] == 30 and len(catalog['revision']) == 64


def test_confirmed_rates_start_a_new_window_and_price_reservations_and_estimates(admin):
    before = current(admin)
    now = time.time()
    bundled_quote = ai_pricing.reservation(PAYLOAD, max(now, ai_pricing.VERIFIED_AT + 1))
    response = admin.post(URL, json=confirm_body(before, rates=doubled(before), days=7))
    assert response.status_code == 200, response.text
    after = response.json()
    assert after['origin'] == 'administrator' and after['confirmed_by'] == 'admin'
    assert after['version'].startswith('admin-') and len(after['version']) <= 30
    assert after['expires_at'] - after['verified_at'] == 7 * 86400
    assert after['fresh'] and after['revision'] != before['revision']
    assert after['rates']['gpt-6-astra']['input'] == '20'
    assert after['bundled_rates'] == before['bundled_rates']

    now = time.time() + 1
    quote = ai_pricing.reservation(PAYLOAD, now)
    assert quote['ok'] and quote['pricing_version'] == after['version']
    if bundled_quote['ok']:
        assert abs(quote['amount_usd'] - 2 * bundled_quote['amount_usd']) <= Decimal('0.000002')
    usage = {'input_tokens': 100_000, 'output_tokens': 0, 'total_tokens': 100_000,
             'input_tokens_details': {'cached_tokens': 0, 'cache_write_tokens': 0}}
    estimate = ai_pricing.estimate({'model': 'gpt-6-astra', 'service_tier': 'default', 'usage': usage}, {})
    assert estimate['status'] == 'estimated'
    assert Decimal(estimate['pricing']['estimated_usd']) == 2
    assert estimate['pricing']['version'] == after['version']
    assert ai_pricing.model_status('gpt-6-astra', now)['version'] == after['version']

    [detail] = audits()
    assert 'admin confirmed AI price catalog ' + after['version'] in detail
    assert 'replacing ' + before['version'] in detail and '(7 days)' in detail
    assert 'gpt-6-astra input 10 -> 20' in detail and 'gpt-4.1 cache_write' not in detail


def scaled(catalog, factor):
    return {model: [None if value is None else format(Decimal(value) * factor, 'f') for value in
                    (values[field] for field in ai_pricing.RATE_FIELDS)]
            for model, values in catalog['rates'].items()}


@pytest.mark.parametrize('bundled_expires_in_flight', [False, True], ids=['increase', 'old-catalog-expires'])
def test_in_flight_confirmation_settles_at_the_admission_catalog(admin, monkeypatch, bundled_expires_in_flight):
    """A capped call settles with the rates its reservation was quoted from (#1488 review).

    Confirming 100x rates while the request is in flight must not settle the
    reply at the new rates (5x the cap in this fixture) or label the charge
    with the admission version; the next call uses the confirmed catalog.
    """
    monkeypatch.setattr(ai_pricing, 'EXPIRES_AT', int(time.time()) + 86400)
    with Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': True, 'ai_model': 'gpt-6-luna', 'ai_control_mode': 'daily_cap', 'ai_rate_per_hour': 20,
            'ai_daily_cap_usd': 0.001, 'ai_budget_timezone': 'UTC'}))
        session.merge(Setting(key='openai_key', value={'encrypted': seal('fixture')}))
        session.commit()
    request = {'model': 'gpt-6-luna', 'input': 'bounded evidence', 'max_output_tokens': 100,
               'store': False, 'service_tier': 'default'}
    admitted = ai_pricing.reservation(request)
    assert admitted['ok'] and admitted['pricing_version'] == ai_pricing.VERSION
    confirmed = {}

    def respond(*args, **kwargs):
        catalog = current(admin)
        response = admin.post(URL, json=confirm_body(catalog, rates=scaled(catalog, 100), days=7))
        assert response.status_code == 200, response.text
        confirmed.update(response.json())
        if bundled_expires_in_flight:
            monkeypatch.setattr(ai_pricing, 'EXPIRES_AT', int(time.time()) - 1)
        return httpx.Response(200, request=httpx.Request('POST', ai.URL), json={
            'status': 'completed', 'model': 'gpt-6-luna', 'service_tier': 'default',
            'usage': {'input_tokens': 100, 'output_tokens': 80, 'total_tokens': 180,
                      'input_tokens_details': {'cached_tokens': 0, 'cache_write_tokens': 0}},
            'output': [{'content': [{'type': 'output_text', 'text': '{"accepted":true}'}]}],
        })

    monkeypatch.setattr(ai.transport, 'post', respond)
    ai.request(request, 'fixture-key')
    assert confirmed['version'].startswith('admin-')
    with Session() as session:
        entry = session.query(ai_budget.BudgetEntry).one()
        assert entry.status == 'settled'
        assert entry.reservation_usd == admitted['amount_usd']
        # 100 input tokens at $0.1/M plus 80 output tokens at $0.5/M, from the admission catalog.
        assert entry.actual_usd == Decimal('0.00005')
        assert entry.pricing_version == ai_pricing.VERSION
        assert entry.actual_usd <= Decimal('0.001')

    # Calls admitted after the confirmation use the confirmed catalog.
    later = ai_pricing.reservation(request)
    assert later['ok'] and later['pricing_version'] == confirmed['version']
    assert later['amount_usd'] >= 99 * admitted['amount_usd']
    with ai_pricing.call_snapshot():
        estimate = ai_pricing.estimate({'model': 'gpt-6-luna', 'service_tier': 'default', 'usage': {
            'input_tokens': 100, 'output_tokens': 80, 'total_tokens': 180,
            'input_tokens_details': {'cached_tokens': 0, 'cache_write_tokens': 0}}}, request)
    assert estimate['pricing']['version'] == confirmed['version']
    assert Decimal(estimate['pricing']['estimated_usd']) == Decimal('0.005')


def test_unchanged_reconfirmation_is_audited_as_unchanged(admin):
    response = admin.post(URL, json=confirm_body(current(admin)))
    assert response.status_code == 200
    assert response.json()['rates'] == response.json()['bundled_rates']
    assert audits()[0].endswith('rates unchanged')


def test_stale_revision_is_refused_without_writing(admin):
    catalog = current(admin)
    assert admin.post(URL, json=confirm_body(catalog)).status_code == 200
    saved = stored()
    response = admin.post(URL, json=confirm_body(catalog, rates=doubled(catalog)))
    assert response.status_code == 409
    assert stored() == saved and len(audits()) == 1


@pytest.mark.parametrize(('change', 'status'), [
    ({'days': 0}, 422), ({'days': 31}, 422), ({'days': '7'}, 422),
    ({'checked_source': False}, 400), ({'confirmation': 'confirm prices'}, 422),
    ({'unexpected': 1}, 422),
])
def test_invalid_requests_change_nothing(admin, change, status):
    response = admin.post(URL, json=confirm_body(current(admin)) | change)
    assert response.status_code == status
    assert stored() is None and audits() == []


@pytest.mark.parametrize('mutate', [
    lambda rates: rates.pop('gpt-4.1'),
    lambda rates: rates.update({'gpt-7-fixture': ['1', '0.1', '2', '1.25']}),
    lambda rates: rates.update({'gpt-6-luna': ['0', '0.01', '0.5', '0.125']}),
    lambda rates: rates.update({'gpt-6-luna': ['-1', '0.01', '0.5', '0.125']}),
    lambda rates: rates.update({'gpt-6-luna': ['0.1234567', '0.01', '0.5', '0.125']}),
    lambda rates: rates.update({'gpt-6-luna': ['10001', '0.01', '0.5', '0.125']}),
    lambda rates: rates.update({'gpt-6-luna': ['1e2', '0.01', '0.5', '0.125']}),
    lambda rates: rates.update({'gpt-6-luna': ['0.1', '0.01', '0.5']}),
    lambda rates: rates.update({'gpt-6-luna': ['0.1', '0.01', '0.5', None]}),
    lambda rates: rates.update({'gpt-4.1': ['2', '0.5', '8', '2.5']}),
], ids=['missing-model', 'new-model', 'zero', 'negative', 'precision', 'too-large', 'exponent',
        'short', 'drops-cache-write', 'adds-cache-write'])
def test_confirmed_rates_cannot_widen_or_corrupt_the_catalog(admin, mutate):
    catalog = current(admin)
    rates = confirm_body(catalog)['rates']
    mutate(rates)
    response = admin.post(URL, json=confirm_body(catalog, rates=rates))
    assert response.status_code == 400, response.text
    assert stored() is None and audits() == []


def test_missing_csrf_token_is_refused(admin):
    body = confirm_body(current(admin))
    token = admin.headers.pop('X-CSRF-Token')
    try:
        assert admin.post(URL, json=body).status_code == 403
    finally:
        admin.headers['X-CSRF-Token'] = token
    assert stored() is None


def test_clock_before_bundled_verification_is_refused(admin, monkeypatch):
    catalog = current(admin)
    monkeypatch.setattr(main.time, 'time', lambda: float(ai_pricing.VERIFIED_AT - 60))
    response = admin.post(URL, json=confirm_body(catalog))
    assert response.status_code == 400 and 'clock' in response.json()['detail']
    assert stored() is None


def test_expired_confirmation_fails_closed_instead_of_using_older_bundled_rates(admin, monkeypatch):
    response = admin.post(URL, json=confirm_body(current(admin), days=1))
    confirmed = response.json()
    # Keep the older bundled catalog fresh: the expired confirmation must still win.
    monkeypatch.setattr(ai_pricing, 'EXPIRES_AT', confirmed['expires_at'] + 30 * 86400)
    later = confirmed['expires_at'] + 1
    status = ai_pricing.catalog_status(later)
    assert status['origin'] == 'administrator' and status['state'] == 'expired'
    assert 'Re-confirm current prices in Settings' in status['reason']
    quote = ai_pricing.reservation(PAYLOAD, later)
    assert not quote['ok'] and quote['catalog']['state'] == 'expired'
    assert ai_pricing.model_status('gpt-6-astra', later)['code'] == 'catalog'


def test_newer_bundled_release_supersedes_an_older_confirmation(admin, monkeypatch):
    confirmed = admin.post(URL, json=confirm_body(current(admin), rates=doubled(current(admin)))).json()
    monkeypatch.setattr(ai_pricing, 'VERIFIED_AT', confirmed['verified_at'] + 1)
    monkeypatch.setattr(ai_pricing, 'EXPIRES_AT', confirmed['verified_at'] + 30 * 86400)
    catalog = current(admin)
    assert catalog['origin'] == 'bundled' and catalog['version'] == ai_pricing.VERSION
    assert catalog['rates']['gpt-6-astra']['input'] == '10'


def test_model_added_by_a_later_release_stays_unpriced_until_reconfirmed(admin, monkeypatch):
    confirmed = admin.post(URL, json=confirm_body(current(admin))).json()
    monkeypatch.setitem(ai_pricing.RATES, 'gpt-7-fixture', ('1', '0.1', '2', '1.25'))
    now = confirmed['verified_at'] + 60
    assert ai_pricing.model_status('gpt-7-fixture', now)['code'] == 'model'
    assert not ai_pricing.reservation({**PAYLOAD, 'model': 'gpt-7-fixture'}, now)['ok']
    # The settings view offers the new model for confirmation from the bundled rates.
    catalog = current(admin)
    assert 'gpt-7-fixture' not in catalog['rates'] and 'gpt-7-fixture' in catalog['bundled_rates']


@pytest.mark.parametrize('value', [
    None, [], {'version': '2026-11-16'},
    {'version': 'admin-20991231T000000Z', 'verified_at': 4_000_000_000, 'expires_at': 4_000_000_000 + 31 * 86400,
     'rates': {}},
    {'version': 'admin-20991231T000000Z', 'verified_at': 4_000_000_000.0, 'expires_at': 4_000_086_400, 'rates': {}},
    {'version': 'admin-20991231T000000Z', 'verified_at': 4_000_000_000, 'expires_at': 4_000_000_000, 'rates': {}},
])
def test_malformed_stored_catalog_is_ignored(value):
    assert ai_pricing.stored_catalog(value) is None
    assert ai_pricing.active_catalog(stored=value if value is not None else {})['origin'] == 'bundled'


def test_stored_catalog_drops_models_whose_rates_no_longer_match():
    value = {'version': 'admin-20991231T000000Z', 'verified_at': 4_000_000_000, 'expires_at': 4_000_086_400,
             'rates': {'gpt-6-luna': ['0.2', '0.02', '1', '0.25'], 'gpt-4.1': ['2', '0.5', '8', '9'],
                       'gpt-unknown': ['1', '1', '1', '1']}}
    catalog = ai_pricing.stored_catalog(value)
    assert catalog['rates'] == {'gpt-6-luna': ('0.2', '0.02', '1', '0.25')}
    assert ai_pricing.active_catalog(stored=value)['origin'] == 'administrator'
