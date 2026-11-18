"""Triage policy waits preserve reason, attempt refunds and independent deadlines."""
import time
from decimal import Decimal

import pytest

from app import ai, ai_admission, ai_budget, ai_retry
from app.db import Behavior, Host, Session
from tests.test_ai_budget import configure, payload

SUBJECT='subject-one'


def seed():
    with Session() as s:
        s.add(Host(id='host-one',name='host-one',address='192.0.2.10',fingerprint=''))
        s.add(Behavior(id=SUBJECT,host_id='host-one',evidence={}))
        s.add(ai_retry.TriageRetry(subject=SUBJECT,configuration=ai_retry.configuration(s),
                                   attempts=1,state='interrupted'))
        s.commit()


def defer(error,now):
    with Session() as s:
        retry=ai_retry.failed(s,s.get(Behavior,SUBJECT),error,now);s.commit()
        return retry.state,retry.attempts,retry.next_at,retry.reason


def cap_refusal():
    with pytest.raises(ai.AIError) as refused:ai_budget.reserve(payload())
    return refused.value


def test_daily_cap_deferral_names_the_cap_and_its_reset(admin):
    configure(mode='daily_cap',cap=Decimal('0.000001'))
    seed();now=time.time()
    error=cap_refusal()
    assert error.policy_wait and error.retry_after>0
    state,attempts,next_at,reason=defer(error,now)
    assert (state,attempts)==('deferred',0)
    assert next_at>=now+error.retry_after
    assert 'daily AI spend cap' in reason and 'reset' in reason
    assert 'no provider request was sent' in reason
    assert 'rate' not in reason


def test_rate_and_daily_cap_refusal_also_names_the_cap(admin):
    configure(mode='rate_and_daily',cap=Decimal('0.000001'))
    seed()
    reason=defer(cap_refusal(),time.time())[3]
    assert 'daily AI spend cap' in reason and 'rate' not in reason


@pytest.mark.parametrize('error,expected',[
    (ai.AIError('Shared AI rate throttle is waiting for the next start.',policy_wait=True,retry_after=60),
     'Waiting for shared AI rate eligibility; no provider request was sent.'),
    (ai.AIError('AI integration is paused for this server.',policy_wait=True),
     'Waiting for AI policy resume; eligibility is rechecked before every provider call.'),
],ids=['rate-throttle','pause'])
def test_other_policy_waits_keep_their_reasons(admin,error,expected):
    configure(mode='rate_and_daily')
    seed()
    assert defer(error,time.time())[3]==expected


def test_provider_backoff_keeps_its_reason(admin):
    configure(mode='daily_cap')
    seed();now=time.time()
    error=ai.AIError('Provider backoff.',policy_wait=True,retry_after=60)
    error.provider_wait_until=now+60
    assert defer(error,now)[3]=='Waiting for shared provider backoff; no provider request was sent.'


RATE_REASON = 'Waiting for shared AI rate eligibility; no provider request was sent.'
CAP_REASON = 'Waiting for the daily AI spend cap to reset; no provider request was sent.'


def add_waiter(subject, next_at, reason, provider_until=0):
    with Session() as s:
        s.add(ai_retry.TriageRetry(subject=subject, configuration=ai_retry.configuration(s),
                                   state='deferred', next_at=next_at, provider_until=provider_until,
                                   reason=reason))
        s.commit()


@pytest.mark.parametrize('mode', ['daily_cap', 'rate_and_daily'])
@pytest.mark.parametrize('after_reset', [False, True])
def test_budget_retry_uses_its_reset_even_when_another_wait_runs_later(admin, mode, after_reset):
    configure(mode=mode, cap=Decimal('0.000001'))
    seed()
    refusal = cap_refusal()
    with Session() as s:
        reset = ai_budget.status(s)['next_reset']
    add_waiter('rate-waiter', reset + 120, RATE_REASON)
    recorded_at = reset + 1 if after_reset else reset - 1

    assert defer(refusal, recorded_at) == ('deferred', 0, max(reset, recorded_at), CAP_REASON)


@pytest.mark.parametrize('existing_rate_waiter', [False, True])
def test_rate_retry_spacing_only_follows_other_rate_waiters(admin, existing_rate_waiter):
    configure(mode='rate_and_daily', rate=20)
    seed()
    refill = ai_admission.admit('gpt-6-luna')['next_at']
    with pytest.raises(ai.AIError) as refused:
        ai_admission.admit('gpt-6-luna')
    now = time.time()
    add_waiter('cap-waiter', refill + 7200, CAP_REASON)
    add_waiter('provider-waiter', refill + 3600, 'Provider wait', provider_until=refill + 3600)
    if existing_rate_waiter:
        add_waiter('rate-waiter', refill + 60, RATE_REASON)

    state, attempts, next_at, reason = defer(refused.value, now)
    assert (state, attempts, reason) == ('deferred', 0, RATE_REASON)
    expected = refill + 60 + 3600 / 20 if existing_rate_waiter else refill
    assert next_at == pytest.approx(expected, abs=1, rel=0)
