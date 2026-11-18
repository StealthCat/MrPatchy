"""Roadmap A milestone 4: unknown pricing and usage under a daily spend cap (#994).

Each provider response that the bundled catalog cannot price is driven through the
real ``ai.investigate()`` -> ``ai.request()`` path. Under a cap, the full conservative
reservation must stay counted as ``uncertain`` and must block a later call that would
overrun the cap before anything is sent. Unknown request-side pricing must refuse
capped admission before transmission. Uncapped modes add no spend guard.
"""
from decimal import Decimal
import json

import httpx
import pytest

from app import ai, ai_admission, ai_budget, ai_pricing, ai_provider_backoff, ai_runs
from app.db import Session, Setting
from tests.test_ai_budget import configure, payload

MODEL = 'gpt-6-luna'
FIXED_NOW = 1793448000.0  # 2026-10-31 12:00 UTC, inside the fresh catalog window


def body(**changes):
    """A completed, schema-valid triage response with priced default usage."""
    result = {'model': MODEL, 'service_tier': 'default', 'status': 'completed',
              'usage': {'input_tokens': 120, 'output_tokens': 20, 'total_tokens': 140,
                        'input_tokens_details': {'cached_tokens': 0, 'cache_write_tokens': 0},
                        'output_tokens_details': {'reasoning_tokens': 5}},
              'output': [{'content': [{'type': 'output_text', 'text': json.dumps({
                  'risk': 'low', 'explanation': 'Fixture', 'recommended_checks': '',
                  'requested_checks': []})}]}]}
    result.update(changes)
    return result


def usage_without(*path):
    usage = json.loads(json.dumps(body()['usage']))
    target = usage
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]
    return usage


UNKNOWN_RESPONSES = {
    'usage-missing': (200, body(usage=None)),
    'usage-malformed-total': (200, body(usage={**body()['usage'], 'total_tokens': 999})),
    'usage-negative': (200, body(usage={**body()['usage'], 'output_tokens': -1})),
    'reasoning-exceeds-output': (200, body(usage={**body()['usage'],
        'output_tokens_details': {'reasoning_tokens': 21}})),
    'unpriced-returned-model': (200, body(model='gpt-6-luna-private')),
    'invalid-returned-model': (200, body(model='<script>x</script>')),
    'tier-missing': (200, body(service_tier=None)),
    'tier-unpriced': (200, body(service_tier='scale')),
    'cache-write-missing': (200, body(usage=usage_without('input_tokens_details', 'cache_write_tokens'))),
    'cached-input-missing': (200, body(usage=usage_without('input_tokens_details', 'cached_tokens'))),
    'server-error-without-usage': (500, {'error': {'code': 'server_error', 'message': 'fixture'}}),
    'bad-request-without-usage': (400, {'error': {'code': 'invalid_request', 'message': 'fixture'}}),
}


@pytest.fixture
def provider(monkeypatch):
    """Record every transmission and every rate admission; serve a queued response."""
    state = type('Provider', (), {})()
    state.sent, state.admitted, state.responses = [], [], []
    state.now = FIXED_NOW

    def post(*args, **kwargs):
        status, content = state.responses.pop(0)
        state.sent.append(status)
        return httpx.Response(status, json=content, request=httpx.Request('POST', ai.URL))

    original_admit = ai_admission.admit

    def admit(model):
        state.admitted.append(model)
        return original_admit(model)

    monkeypatch.setattr(ai.transport, 'post', post)
    monkeypatch.setattr(ai_admission, 'admit', admit)
    # One shared clock (the modules share the ``time`` module) inside the fresh catalog window.
    monkeypatch.setattr(ai_budget.time, 'time', lambda: state.now)
    return state


def investigate(provider, status, content):
    # Ten minutes apart: past the 20/hour rate spacing, still inside one UTC day.
    provider.now += 600
    provider.responses.append((status, content))
    with ai_runs.track('triage', MODEL) as run_id:
        try:
            return run_id, ai.investigate({'process': 'fixture'}, MODEL, 'fixture-key'), None
        except ai.AIError as error:
            return run_id, None, error


def set_cap(cap):
    with Session() as session:
        row = session.get(Setting, 'config')
        row.value = {**row.value, 'ai_daily_cap_usd': float(cap)}
        session.commit()


def rows():
    with Session() as session:
        return [(row.status, row.reservation_usd, row.actual_usd)
                for row in session.query(ai_budget.BudgetEntry).order_by(ai_budget.BudgetEntry.created)]


def receipt(run_id):
    with Session() as session:
        run = session.get(ai_runs.AIRun, run_id)
        calls = ai_runs.call_receipts(session, [run_id])[run_id]
        return ai_runs.cost_summary(run, calls), calls


def quote():
    return ai_pricing.reservation(ai.investigation_payload({'process': 'fixture'}, MODEL))['amount_usd']


@pytest.mark.parametrize('mode', ['daily_cap', 'rate_and_daily'])
@pytest.mark.parametrize('case', sorted(UNKNOWN_RESPONSES))
def test_unpriced_response_keeps_full_reservation_and_blocks_overrun(admin, provider, mode, case):
    configure(mode=mode, cap=Decimal('1'))
    amount = quote()
    assert Decimal(0) < amount < Decimal('0.5')

    run_id, _result, _error = investigate(provider, *UNKNOWN_RESPONSES[case])
    assert provider.sent == [UNKNOWN_RESPONSES[case][0]] and len(provider.admitted) == 1
    [(status, reservation, actual)] = rows()
    assert (status, reservation, actual) == ('uncertain', amount, None)
    cost, [call] = receipt(run_id)
    assert call.status == 'unavailable' and call.pricing == {}
    assert cost['status'] == 'unavailable' and cost['estimated_usd'] is None
    with Session() as session:
        state = ai_budget.status(session)
    assert Decimal(state['uncertain_usd']) == amount
    assert Decimal(state['counted_usd']) == amount and state['settled_usd'] == '0'
    assert state['unreconciled_call_count'] == 1

    # A transient error also opens the shared provider backoff; clear it so the
    # daily cap is the only gate left for the next call.
    ai_provider_backoff.clear()
    # Room for one more full reservation only if the unknown charge were treated as free.
    set_cap(amount + amount / 2)
    _run, result, error = investigate(provider, 200, body())
    assert result is None and error is not None and error.policy_wait
    assert 'no remaining safe reservation' in str(error)
    assert error.retry_after > 0
    assert len(provider.sent) == 1 and len(provider.admitted) == 1
    assert rows() == [('uncertain', amount, None)]
    with Session() as session:
        assert Decimal(ai_budget.status(session)['counted_usd']) == amount


@pytest.mark.parametrize('mode', ['daily_cap', 'rate_and_daily'])
def test_priced_response_settles_and_frees_headroom_for_the_same_later_call(admin, provider, mode):
    configure(mode=mode, cap=Decimal('1'))
    amount = quote()
    run_id, result, error = investigate(provider, 200, body())
    assert error is None and result['risk'] == 'low'
    [(status, reservation, actual)] = rows()
    assert status == 'settled' and reservation == amount and Decimal(0) < actual < amount / 2
    cost, [call] = receipt(run_id)
    assert call.status == 'estimated' and cost['status'] == 'estimated'
    assert Decimal(cost['estimated_usd']) == actual

    set_cap(amount + amount / 2)
    _run, result, error = investigate(provider, 200, body())
    assert error is None and result['risk'] == 'low'
    assert len(provider.sent) == 2 and len(provider.admitted) == 2
    assert [row[0] for row in rows()] == ['settled', 'settled']


REQUEST_SIDE = {
    'unpriced-saved-model': (lambda p: {**p, 'model': 'private-model'}, 'no verified price'),
    'tool-fees': (lambda p: {**p, 'tools': [{'type': 'web_search'}]}, 'Tool fees'),
    'unbounded-output': (lambda p: {k: v for k, v in p.items() if k != 'max_output_tokens'}, 'output-token maximum'),
    'unpriced-tier': (lambda p: {**p, 'service_tier': 'scale'}, 'processing tier'),
    'unpriced-cache-ttl': (lambda p: {**p, 'prompt_cache_options': {'ttl': '7d'}}, 'Prompt-cache pricing'),
    'expired-catalog': (None, 'catalog has expired'),
}


@pytest.mark.parametrize('mode', ['daily_cap', 'rate_and_daily'])
@pytest.mark.parametrize('case', sorted(REQUEST_SIDE))
def test_unknown_request_pricing_refuses_capped_admission_before_sending(admin, provider, monkeypatch, mode, case):
    configure(mode=mode, cap=Decimal('1000'))
    change, reason = REQUEST_SIDE[case]
    request = payload()
    if change is None:
        provider.now = ai_pricing.EXPIRES_AT
    else:
        request = change(request)
    with pytest.raises(ai.AIError) as raised:
        ai.request(request, 'fixture-key')
    assert reason in str(raised.value)
    assert 'no provider request was sent' in str(raised.value)
    assert provider.sent == [] and provider.admitted == []
    assert rows() == []
    with Session() as session:
        assert session.get(ai_admission.Admission, 'global') is None
        assert ai_budget.status(session)['counted_usd'] == '0'


@pytest.mark.parametrize('mode', ['rate', 'unthrottled'])
@pytest.mark.parametrize('case', ['usage-missing', 'unpriced-returned-model', 'server-error-without-usage'])
def test_uncapped_modes_add_no_spend_guard_for_unknown_usage(admin, provider, mode, case):
    configure(mode=mode, cap=Decimal('0.000001'))
    run_id, _result, _error = investigate(provider, *UNKNOWN_RESPONSES[case])
    cost, [call] = receipt(run_id)
    assert call.status == 'unavailable' and cost['estimated_usd'] is None
    ai_provider_backoff.clear()
    _run, result, error = investigate(provider, 200, body())
    assert error is None and result['risk'] == 'low'
    assert len(provider.sent) == 2
    assert rows() == []
