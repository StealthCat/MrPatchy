"""Roadmap B: explicit known-good Re-triage respects the shared AI controls (#1029).

An administrator's Re-triage bypasses the fleet exact-match known-good lookup.
It must still respect per-server pause, global AI disable, data sharing and the
shared daily spend cap. While a control holds the request back, the worker must
not call the provider and must not fall back to the cached verdict. It must also
keep the request. These tests drive the real ``worker.investigate_one()`` path.
Only the provider transport is a fixture.
"""
import json
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_assessments, ai_budget, ai_pricing, ai_runs, known_good, worker
from app.db import Audit, Behavior, Host, Session, Setting
from app.security import seal
from tests.test_known_good import complete, retained

MODEL = 'gpt-6-astra'
ADDRESS = '203.0.113.88'
HOST_KEY = 'SHA256:retriage-fixture-host-key'
IDENTITY = {'pid': 4242, 'start_ticks': 99, 'boot_id': 'b' * 32}
USAGE = {'input_tokens': 1000, 'output_tokens': 200, 'total_tokens': 1200,
         'input_tokens_details': {'cached_tokens': 0, 'cache_write_tokens': 0},
         'output_tokens_details': {'reasoning_tokens': 100}}


class Provider:
    """Record every transmitted request body and answer with a valid low verdict."""

    def __init__(self):
        self.bodies = []

    def __call__(self, *args, **kwargs):
        body = kwargs['json']
        self.bodies.append(body)
        data = {'risk': 'low', 'explanation': 'Fresh provider result',
                'recommended_checks': 'Continue deterministic monitoring', 'requested_checks': []}
        response = {'model': MODEL, 'service_tier': 'default', 'status': 'completed', 'usage': USAGE,
                    'output': [{'content': [{'type': 'output_text', 'text': json.dumps(data)}]}]}
        return httpx.Response(200, json=response, request=httpx.Request('POST', ai.URL))


def configure(**changes):
    with Session() as s:
        row = s.get(Setting, 'config')
        base = row.value if row else {
            'ai_enabled': True, 'ai_model': MODEL, 'ai_control_mode': 'daily_cap',
            'ai_daily_cap_usd': 5.0, 'ai_budget_timezone': 'UTC', 'ai_updates_enabled': False}
        s.merge(Setting(key='config', value={**base, **changes}))
        s.merge(Setting(key='openai_key', value={'encrypted': seal('private-key')}))
        s.commit()


def pause(paused):
    with Session() as s:
        s.merge(Setting(key='server-ai:host-two', value={'paused': paused}))
        s.commit()


def seed(refresh=True):
    """One active exact candidate from host-one; host-two observes the same artifact."""
    current = complete()
    current['host_id'] = 'host-two'
    current['investigation']['details']['known_good_context']['observation']['host_id'] = 'host-two'
    current['process_identity'] = dict(IDENTITY)
    source = retained(snapshot=complete())
    source.model = MODEL
    source.policy_hash = ai_assessments.digest([ai.investigation_policy()])
    with Session() as s:
        s.add_all([
            Host(id='host-one', name='Source', address='192.0.2.1', fingerprint=''),
            Host(id='host-two', name='Current', address=ADDRESS, fingerprint=HOST_KEY),
            source,
            Behavior(id='behavior-two', host_id='host-two', evidence=current, verdict='pending')])
        if refresh:
            s.add(ai_assessments.Refresh(subject='behavior-two', id='refresh-two', actor='admin',
                reason='Explicitly request a fresh provider assessment', previous=source.id,
                withdrew_approval=False))
        published = known_good.publish(s, source)
        s.commit()
    return published


def state():
    with Session() as s:
        behavior = s.get(Behavior, 'behavior-two')
        return {
            'verdict': behavior.verdict,
            'refresh': s.get(ai_assessments.Refresh, 'behavior-two') is not None,
            'assessments': [(row.source, (row.refresh or {}).get('id')) for row in s.scalars(
                select(ai_assessments.Assessment).where(
                    ai_assessments.Assessment.subject == 'behavior-two'))],
            'reused': s.scalar(select(Audit).where(Audit.action == 'reuse known-good candidate')) is not None,
            'active': [row.active for row in s.scalars(select(known_good.Entry))],
            'ledger': [(row.status, row.reservation_usd) for row in s.scalars(
                select(ai_budget.BudgetEntry).order_by(ai_budget.BudgetEntry.created))],
            'runs': [(row.state, row.calls) for row in s.scalars(
                select(ai_runs.AIRun).where(ai_runs.AIRun.subject == 'behavior-two'))],
        }


def assert_held_back(provider):
    """Nothing was sent, reserved or reused, and the explicit request survived."""
    held = state()
    assert provider.bodies == []
    assert held['verdict'] == 'pending' and held['refresh'] is True
    assert held['assessments'] == [] and held['reused'] is False
    assert held['active'] == [True] and held['ledger'] == []


def assert_consumed_by_one_call(provider):
    done = state()
    assert len(provider.bodies) == 1
    assert done['verdict'] == 'low' and done['refresh'] is False and done['reused'] is False
    assert done['assessments'] == [('ai', 'refresh-two')]
    assert [status for status, _ in done['ledger']] == ['settled']


@pytest.fixture
def provider(monkeypatch):
    sent = Provider()
    monkeypatch.setattr(ai.transport, 'post', sent)
    return sent


def test_without_retriage_an_exact_hit_reuses_with_zero_calls_and_zero_reservations(client, provider):
    configure()
    seed(refresh=False)
    worker.investigate_one()
    done = state()
    assert provider.bodies == []
    assert done['verdict'] == 'low' and done['reused'] is True
    assert done['assessments'] == [('known_good', None)]
    assert done['ledger'] == [] and done['runs'] == [('complete', 0)]


def test_server_pause_holds_retriage_without_cache_fallback_until_resume(client, provider):
    configure()
    seed()
    pause(True)
    for _ in range(2):
        worker.investigate_one()
    assert_held_back(provider)
    pause(False)
    worker.investigate_one()
    assert_consumed_by_one_call(provider)


def test_global_disable_holds_retriage_without_cache_fallback_until_enabled(client, provider):
    configure(ai_enabled=False)
    seed()
    for _ in range(2):
        worker.investigate_one()
    assert_held_back(provider)
    configure(ai_enabled=True)
    worker.investigate_one()
    assert_consumed_by_one_call(provider)


@pytest.mark.parametrize('mode', ['daily_cap', 'rate_and_daily'])
def test_daily_cap_without_headroom_defers_retriage_without_charge_or_cache_fallback(client, provider, mode):
    # Far below one call's conservative reservation, so the claim-time quote refuses.
    configure(ai_control_mode=mode, ai_daily_cap_usd=0.000001, ai_rate_per_hour=60)
    seed()
    for _ in range(2):
        worker.investigate_one()
    assert_held_back(provider)
    configure(ai_daily_cap_usd=5.0)
    worker.investigate_one()
    assert_consumed_by_one_call(provider)


def test_retriage_shares_the_same_bounded_request_and_reserves_on_it(client, provider):
    configure()
    seed()
    worker.investigate_one()
    assert_consumed_by_one_call(provider)
    body = provider.bodies[0]
    sent = json.loads(body['input'])
    # Re-triage widens nothing: the stored-evidence contract of an ordinary call applies.
    assert body['store'] is False
    assert 'process_identity' not in sent
    assert ADDRESS not in body['input'] and HOST_KEY not in body['input']
    contract = sent['investigation']['details']['known_good_context']
    assert 'observation' not in contract
    # Byte-for-byte the input an ordinary investigation of this evidence sends.
    assert body['input'] == ai.investigation_payload(state_evidence(), MODEL)['input']
    with Session() as s:
        entry = s.scalar(select(ai_budget.BudgetEntry))
        assert entry.reservation_usd == Decimal(str(ai_pricing.reservation(body)['amount_usd']))
        # The identity stays local for follow-up selection.
        assert s.get(Behavior, 'behavior-two').evidence['process_identity'] == IDENTITY


def state_evidence():
    with Session() as s:
        return s.get(Behavior, 'behavior-two').evidence
