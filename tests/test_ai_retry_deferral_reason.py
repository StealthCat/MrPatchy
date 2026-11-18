"""#1015: a daily-cap deferral names the cap, not the rate throttle.

Each kind of policy wait keeps its own reason text. Only the text changes: the
deferral state, attempt refund and next eligibility stay exactly as before.
"""
import time
from decimal import Decimal

import pytest

from app import ai, ai_budget, ai_retry
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
