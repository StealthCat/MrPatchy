"""#1003: a subject whose own reservation exceeds the whole daily cap must not stall the fleet.

The tests drive the real worker path (``worker.investigate_one``) in both capped
modes. Only the provider transport and SSH are fixtures.
"""
import json
import time
from contextlib import contextmanager

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_budget, ai_claims, ai_pricing, ai_retry, host_lifecycle, triage_block_notifications, worker
from app.db import Behavior, Host, Session, Setting
from app.security import seal

MODEL = 'gpt-6-astra'
SMALL_MODEL = 'gpt-6-luna'
ADDRESS = '203.0.113.78'
FINGERPRINT = 'SHA256:fixture-host-key'
BIG = {'executable': '/srv/big', 'sha256': 'a' * 64, 'uid': '1000', 'identity_verified': True, 'service': 'x' * 40000}
SMALL = {'executable': '/srv/small', 'sha256': 'b' * 64, 'uid': '1000', 'identity_verified': True}
USAGE = {'input_tokens': 1000, 'output_tokens': 200, 'total_tokens': 1200,
         'input_tokens_details': {'cached_tokens': 0, 'cache_write_tokens': 0},
         'output_tokens_details': {'reasoning_tokens': 100}}


def configure(**changes):
    with Session() as s:
        row = s.get(Setting, 'config')
        base = row.value if row else {'ai_enabled': True, 'ai_model': MODEL, 'ai_control_mode': 'daily_cap',
                                      'ai_daily_cap_usd': 5.0, 'ai_budget_timezone': 'UTC',
                                      'ai_updates_enabled': False}
        s.merge(Setting(key='config', value={**base, **changes}))
        if not s.get(Setting, 'openai_key'):
            s.merge(Setting(key='openai_key', value={'encrypted': seal('private-key')}))
        s.commit()


def add_host(host, evidence):
    with Session() as s:
        s.add(Host(id=host, name=host, address=ADDRESS, fingerprint=FINGERPRINT, state='online',
                   inventory={'os': 'ID=debian\nVERSION_ID=12'}))
        s.add(Behavior(id='subject-' + host, host_id=host, evidence=json.loads(json.dumps(evidence))))
        s.commit()


class Provider:
    def __init__(self):
        self.bodies = []

    def kinds(self):
        return [body['text']['format']['name'] for body in self.bodies]

    def __call__(self, *args, **kwargs):
        body = kwargs['json']
        self.bodies.append(body)
        data = {'risk': 'low', 'explanation': 'Advisory fixture', 'recommended_checks': 'Review limitations',
                'requested_checks': []}
        response = {'model': body['model'], 'service_tier': 'default', 'status': 'completed', 'usage': USAGE,
                    'output': [{'content': [{'type': 'output_text', 'text': json.dumps(data)}]}]}
        return httpx.Response(200, json=response, request=httpx.Request('POST', ai.URL))


@pytest.fixture
def ssh(monkeypatch):
    monkeypatch.setattr(worker.ssh, 'call', lambda host, request, **kwargs: {'identity_verified': True,
                                                                             'sha256': 'a' * 64})


def quote(evidence, model=MODEL):
    return ai_pricing.reservation(ai.investigation_payload(evidence, model))['amount_usd']


def state(subject):
    with Session() as s:
        row = s.get(Behavior, subject)
        retry = s.get(ai_retry.TriageRetry, subject)
        return row.verdict, retry


def ledger_count():
    with Session() as s:
        return len(list(s.scalars(select(ai_budget.BudgetEntry))))


@pytest.mark.parametrize('mode', ['daily_cap', 'rate_and_daily'])
def test_claim_quotes_once_and_provider_still_reserves_its_exact_payload(admin, monkeypatch, ssh, mode):
    configure(ai_control_mode=mode, ai_rate_per_hour=3600)
    add_host('host-a', BIG)
    provider = Provider()
    monkeypatch.setattr(ai.transport, 'post', provider)
    reservation = ai_pricing.reservation
    quoted = []

    def observe(payload, *args, **kwargs):
        quoted.append((ai_claims.current.get() is not None, payload))
        return reservation(payload, *args, **kwargs)

    monkeypatch.setattr(ai_pricing, 'reservation', observe)
    worker.investigate_one()

    assert [inside_run for inside_run, _ in quoted] == [False, True]
    assert [quoted[-1][1]] == provider.bodies
    assert state('subject-host-a')[0] == 'low'
    with Session() as s:
        row = s.scalars(select(ai_budget.BudgetEntry)).one()
        assert row.status == 'settled'
        assert row.reservation_usd == reservation(provider.bodies[0])['amount_usd']


@pytest.mark.parametrize('mode', ['daily_cap', 'rate_and_daily'])
def test_subject_quote_above_whole_cap_does_not_stall_other_hosts(admin, monkeypatch, ssh, mode):
    big, small = quote(BIG), quote(SMALL)
    assert small < big
    cap = (big + small) / 2
    configure(ai_control_mode=mode, ai_daily_cap_usd=float(cap), ai_rate_per_hour=3600)
    add_host('host-big', BIG)
    time.sleep(0.01)
    add_host('host-ok', SMALL)
    provider = Provider()
    monkeypatch.setattr(ai.transport, 'post', provider)
    for _ in range(3):
        worker.investigate_one()
    # The small subject on the other host is triaged; the oversized one is never sent.
    assert provider.kinds() == ['process_investigation']
    assert state('subject-host-ok')[0] == 'low'
    verdict, retry = state('subject-host-big')
    assert verdict == 'pending'
    assert retry.state == 'blocked' and retry.attempts == 0 and retry.next_at == 0
    assert 'daily spend cap' in retry.reason and 'Nothing was reserved or sent' in retry.reason
    # Only the admitted call reserved spend.
    assert ledger_count() == 1
    with Session() as s:
        # Existing blocked surfaces count it, and the queue moves on.
        assert triage_block_notifications.blocked_count(s, time.time())[0] == 1
        summary = ai_retry.summary(s.get(ai_retry.TriageRetry, 'subject-host-big'),
                                   ai_retry.configuration(s), time.time())
        assert summary['state'] == 'blocked' and 'daily spend cap' in summary['reason']
    # Further passes neither re-elect nor send the blocked subject.
    worker.investigate_one()
    assert provider.kinds() == ['process_investigation']


def test_ordinary_exhaustion_still_defers_the_fleet_without_blocking(admin, monkeypatch, ssh):
    # The quote fits the cap on its own, but not on top of spend already counted:
    # nothing is blocked and the subject stays queued for the reset.
    small = quote(SMALL)
    configure(ai_daily_cap_usd=float(small * 3 / 2))
    add_host('host-a', SMALL)
    provider = Provider()
    monkeypatch.setattr(ai.transport, 'post', provider)
    with Session() as s:
        s.add(ai_budget.BudgetEntry(id='prior', run_id='prior-run', status='uncertain', created=time.time(),
                                    reset_at=time.time() + 3600, reservation_usd=small, timezone='UTC',
                                    model=MODEL, pricing_version='fixture', pricing_source='fixture'))
        s.commit()
    for _ in range(2):
        assert ai_claims.acquire() is None
    assert provider.kinds() == []
    verdict, retry = state('subject-host-a')
    assert verdict == 'pending' and retry is None


def test_host_queue_gate_rereads_headroom_after_the_fleet_preflight(admin, monkeypatch):
    small = quote(SMALL)
    configure(ai_daily_cap_usd=float(small * 3 / 2))
    add_host('host-a', SMALL)
    activity = host_lifecycle.activity

    @contextmanager
    def commit_after_initial_preflight(hosts, kind):
        with activity(hosts, kind):
            assert kind == 'queue'
            with Session() as s:
                s.add(ai_budget.BudgetEntry(
                    id='competing-call', status='uncertain', created=time.time(),
                    reset_at=time.time() + 3600, reservation_usd=small, timezone='UTC',
                    model=MODEL, pricing_version='fixture', pricing_source='fixture',
                ))
                s.commit()
            yield

    monkeypatch.setattr(host_lifecycle, 'activity', commit_after_initial_preflight)
    assert ai_claims.acquire() is None
    assert state('subject-host-a') == ('pending', None)
    assert ledger_count() == 1


def test_model_change_or_explicit_retry_readmits_an_over_cap_subject(admin, monkeypatch, ssh):
    big = quote(BIG)
    configure(ai_daily_cap_usd=float(big / 2))
    add_host('host-big', BIG)
    provider = Provider()
    monkeypatch.setattr(ai.transport, 'post', provider)
    worker.investigate_one()
    assert state('subject-host-big')[1].state == 'blocked'
    # A larger cap alone does not change the model/key signature: an administrator retries explicitly.
    configure(ai_daily_cap_usd=float(big * 2))
    worker.investigate_one()
    assert provider.kinds() == []
    with Session() as s:
        ai_retry.manual(s, s.get(Behavior, 'subject-host-big'))
        s.commit()
    worker.investigate_one()
    assert provider.kinds() == ['process_investigation']
    assert state('subject-host-big')[0] == 'low'
    # A model change also makes a cap-blocked subject eligible again.
    add_host('host-big-2', {**BIG, 'executable': '/srv/big2'})
    configure(ai_daily_cap_usd=float(big / 2))
    worker.investigate_one()
    assert state('subject-host-big-2')[1].state == 'blocked'
    # The cap stays below the original model's quote; only the model changes.
    assert quote({**BIG, 'executable': '/srv/big2'}, SMALL_MODEL) < quote(BIG) / 10
    configure(ai_model=SMALL_MODEL)
    worker.investigate_one()
    assert provider.kinds()[-1] == 'process_investigation' and len(provider.kinds()) == 2

