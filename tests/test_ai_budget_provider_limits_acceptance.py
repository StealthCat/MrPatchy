"""Roadmap A milestone 4: provider limits and bounded retries under a daily spend cap.

These tests drive the real worker path (``worker.investigate_one``), replacing only
the provider transport and the SSH call with fixtures. They check four things. A
provider rate limit or transient failure keeps any possibly incurred charge counted.
Waiting for a provider floor costs nothing. Automatic retries stop at the attempt
limit. A retry is admitted only once both provider eligibility and cap headroom allow
it.
"""
import json
import time
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import select

from app import (
    ai,
    ai_assessments,
    ai_budget,
    ai_pricing,
    ai_provider_backoff,
    ai_retry,
    ai_runs,
    worker,
)
from app.db import Behavior, Host, Session, Setting
from app.security import seal

MODEL='gpt-6-astra'
SUBJECT='subject-0'
OTHER='subject-1'
EVIDENCE={'executable':'/srv/fixture','sha256':'a'*64,'uid':'1000','identity_verified':True}
USAGE={'input_tokens':1000,'output_tokens':200,'total_tokens':1200,
       'input_tokens_details':{'cached_tokens':0,'cache_write_tokens':0},
       'output_tokens_details':{'reasoning_tokens':100}}


def quote():
    return ai_pricing.reservation(ai.investigation_payload(EVIDENCE,MODEL))['amount_usd']


def seed(*,cap):
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':MODEL,'ai_control_mode':'daily_cap',
            'ai_daily_cap_usd':float(cap),'ai_budget_timezone':'UTC'}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        s.add(Host(id='host-0',name='Fixture',address='192.0.2.1',fingerprint=''))
        s.add(Behavior(id=SUBJECT,host_id='host-0',evidence=dict(EVIDENCE)))
        s.commit()


class Clock:
    """A controllable wall clock shared by the worker, retry, backoff and budget code."""
    def __init__(self,monkeypatch):
        self.real=time.time;self.shift=0.0
        monkeypatch.setattr(time,'time',self.now)
    def now(self):
        return self.real()+self.shift
    def advance_to(self,instant):
        self.shift+=max(0.0,instant-self.now())+1


class Provider:
    """Answers each transmission from a script of responses, then succeeds."""
    def __init__(self,*failures):
        self.failures=list(failures);self.sent=[]
    def __call__(self,*args,**kwargs):
        self.sent.append(ai_runs.active.get())
        request=httpx.Request('POST',ai.URL)
        if self.failures:
            status,headers,code=self.failures.pop(0)
            body={'error':{'code':code,'message':'fixture provider detail'}} if code else {}
            return httpx.Response(status,headers=headers,json=body,request=request)
        data={'risk':'low','explanation':'Advisory fixture','recommended_checks':'Review limitations',
              'requested_checks':[]}
        body={'model':MODEL,'service_tier':'default','status':'completed','usage':USAGE,
              'output':[{'content':[{'type':'output_text','text':json.dumps(data)}]}]}
        return httpx.Response(200,json=body,request=request)


@pytest.fixture
def ssh(monkeypatch):
    calls=[]
    def call(host,request,**kwargs):
        calls.append(request['checks'])
        return {'identity_verified':True,'sha256':'a'*64,'context':host.id}
    monkeypatch.setattr(worker.ssh,'call',call)
    return calls


def queue_fresh_subject():
    """Queue a second, never-attempted subject that only the shared gates can hold back."""
    with Session() as s:
        s.add(Behavior(id=OTHER,host_id='host-0',evidence=dict(EVIDENCE)));s.commit()


def ledger(s):
    return list(s.scalars(select(ai_budget.BudgetEntry).order_by(ai_budget.BudgetEntry.created)))


def runs(s):
    return list(s.scalars(select(ai_runs.AIRun).order_by(ai_runs.AIRun.started)))


def counted(s):
    return Decimal(ai_budget.status(s)['counted_usd'])


RATE_LIMIT=(429,{'retry-after':'120'},'rate_limit_exceeded')
UNAVAILABLE=(503,{'retry-after':'1'},'')


def test_rate_limit_keeps_the_charge_and_waiting_for_the_floor_costs_nothing(admin,monkeypatch,ssh):
    seed(cap=quote()*4);clock=Clock(monkeypatch)
    provider=Provider(RATE_LIMIT);monkeypatch.setattr(ai.transport,'post',provider)
    started=clock.now()
    worker.investigate_one()
    assert len(provider.sent)==1
    with Session() as s:
        rows=ledger(s);limited=rows[0]
        # The 429 carried no usage, so the full reservation stays counted as uncertain.
        assert [row.status for row in rows]==['uncertain']
        assert counted(s)==limited.reservation_usd==Decimal(ai_budget.status(s)['uncertain_usd'])
        floor=ai_provider_backoff.status(s)
        assert floor['blocked'] and floor['next_at']>=started+120
        retry=s.get(ai_retry.TriageRetry,SUBJECT)
        assert retry.state=='deferred' and retry.attempts==1 and retry.provider_until>=started+120
        assert retry.next_at>=retry.provider_until
        assert not list(s.scalars(select(ai_assessments.Assessment)))
        behavior=s.get(Behavior,SUBJECT);assert behavior.verdict=='error' and not behavior.approved
        runs_before=[run.id for run in runs(s)]
    # While the floor is active, worker passes send nothing and record nothing, for
    # the deferred subject and for a fresh subject that has no retry delay of its own.
    queue_fresh_subject()
    for _ in range(3):worker.investigate_one()
    assert len(provider.sent)==1
    with Session() as s:
        assert [row.id for row in ledger(s)]==[limited.id]
        assert counted(s)==limited.reservation_usd
        assert [run.id for run in runs(s)]==runs_before
        assert s.get(ai_retry.TriageRetry,SUBJECT).attempts==1
    # A direct call is refused before any reservation, so it is never charged.
    with pytest.raises(ai.AIError) as refused:
        ai.request(ai.investigation_payload(EVIDENCE,MODEL),'private-key')
    assert refused.value.policy_wait and len(provider.sent)==1
    with Session() as s:assert [row.status for row in ledger(s)]==['uncertain']
    with Session() as s:assert s.get(Behavior,OTHER).verdict=='pending'
    # After the floor and the subject's retry delay pass, both run with fresh reservations.
    with Session() as s:clock.advance_to(s.get(ai_retry.TriageRetry,SUBJECT).next_at)
    worker.investigate_one();worker.investigate_one()
    assert len(provider.sent)==3
    with Session() as s:
        rows=ledger(s)
        assert [row.status for row in rows]==['uncertain','settled','settled'] and rows[0].id==limited.id
        assert counted(s)==limited.reservation_usd+rows[1].actual_usd+rows[2].actual_usd
        assert not ai_provider_backoff.status(s)['blocked']
        assert s.get(ai_retry.TriageRetry,SUBJECT) is None
        assessments=list(s.scalars(select(ai_assessments.Assessment)))
        assert sorted(a.run_id for a in assessments)==sorted(provider.sent[1:])
        for subject in (SUBJECT,OTHER):
            behavior=s.get(Behavior,subject);assert behavior.verdict=='low' and not behavior.approved


def test_transient_failures_stop_at_the_attempt_limit_with_every_attempt_counted(admin,monkeypatch,ssh):
    seed(cap=quote()*(ai_retry.MAX_ATTEMPTS+3));clock=Clock(monkeypatch)
    provider=Provider(*[UNAVAILABLE]*(ai_retry.MAX_ATTEMPTS+2))
    monkeypatch.setattr(ai.transport,'post',provider)
    for attempt in range(1,ai_retry.MAX_ATTEMPTS+1):
        worker.investigate_one()
        assert len(provider.sent)==attempt
        with Session() as s:
            retry=s.get(ai_retry.TriageRetry,SUBJECT);assert retry.attempts==attempt
            rows=ledger(s);assert [row.status for row in rows]==['uncertain']*attempt
            assert counted(s)==sum(row.reservation_usd for row in rows)
            wake=max(retry.next_at,ai_provider_backoff.waiting(s,clock.now()))
        clock.advance_to(wake)
    with Session() as s:
        retry=s.get(ai_retry.TriageRetry,SUBJECT)
        assert retry.state=='blocked' and 'limit reached' in retry.reason
        summary=ai_retry.summary(retry,ai_retry.configuration(s),clock.now())
        assert summary['state']=='blocked'
        before=[row.id for row in ledger(s)];runs_before=[run.id for run in runs(s)]
    # No further automatic attempt: nothing is reserved, sent or recorded.
    for _ in range(3):
        clock.advance_to(clock.now()+3600)
        worker.investigate_one()
    assert len(provider.sent)==ai_retry.MAX_ATTEMPTS
    with Session() as s:
        assert [row.id for row in ledger(s)]==before
        assert [run.id for run in runs(s)]==runs_before
        assert not list(s.scalars(select(ai_assessments.Assessment)))
        # Every sent attempt stays counted against the cap.
        rows=ledger(s);assert all(row.status=='uncertain' for row in rows)
        assert counted(s)==sum(row.reservation_usd for row in rows)>=quote()*ai_retry.MAX_ATTEMPTS
    # An explicit administrator retry re-admits the subject with a fresh reservation.
    with Session() as s:
        ai_retry.manual(s,s.get(Behavior,SUBJECT),clock.now());s.commit()
    worker.investigate_one()
    assert len(provider.sent)==ai_retry.MAX_ATTEMPTS+1
    with Session() as s:assert len(ledger(s))==ai_retry.MAX_ATTEMPTS+1


@pytest.mark.parametrize('code',['project_spend_limit_exceeded','insufficient_quota'])
def test_provider_spend_limit_blocks_without_automatic_retry_and_stays_counted(admin,monkeypatch,ssh,code):
    seed(cap=quote()*4);clock=Clock(monkeypatch)
    provider=Provider((429,{'retry-after':'5'},code));monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    with Session() as s:
        rows=ledger(s);assert [row.status for row in rows]==['uncertain']
        assert counted(s)==rows[0].reservation_usd
        retry=s.get(ai_retry.TriageRetry,SUBJECT)
        assert retry.state=='blocked' and retry.next_at==0 and retry.provider_until==0
        # A billing limit is not a transient rate limit: no shared provider floor is set.
        assert not ai_provider_backoff.status(s)['blocked']
        run=runs(s)[0];assert run.state=='error' and code in run.message
        behavior=s.get(Behavior,SUBJECT);assert behavior.verdict=='error' and code in behavior.analysis
    for _ in range(3):
        clock.advance_to(clock.now()+7200)
        worker.investigate_one()
    assert len(provider.sent)==1
    with Session() as s:
        assert len(ledger(s))==1 and len(runs(s))==1
        assert not list(s.scalars(select(ai_assessments.Assessment)))


def test_retry_waits_for_both_provider_eligibility_and_the_cap_reset(admin,monkeypatch,ssh):
    # Room for one reservation only: the rate-limited attempt's counted charge fills the cap.
    seed(cap=quote()*Decimal('1.5'));clock=Clock(monkeypatch)
    provider=Provider(RATE_LIMIT);monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    with Session() as s:
        retry=s.get(ai_retry.TriageRetry,SUBJECT);provider_ready=retry.next_at
        reset=ai_budget.status(s)['next_reset']
        assert provider_ready<reset
        assert ai_budget.waiting(s,clock.now(),ai.investigation_payload(EVIDENCE,MODEL))==reset
        runs_before=[run.id for run in runs(s)]
    # Provider eligibility alone is not enough: the cap still has no headroom, for the
    # retried subject and for a fresh subject alike.
    queue_fresh_subject()
    clock.advance_to(provider_ready)
    with Session() as s:assert not ai_provider_backoff.status(s)['blocked']
    for _ in range(2):worker.investigate_one()
    assert len(provider.sent)==1
    with Session() as s:
        assert [row.status for row in ledger(s)]==['uncertain']
        assert [run.id for run in runs(s)]==runs_before
        assert s.get(ai_retry.TriageRetry,SUBJECT).attempts==1
        assert s.get(Behavior,OTHER).verdict=='pending'
    # After the reset the retry is admitted with a fresh reservation in the new window.
    clock.advance_to(reset)
    worker.investigate_one()
    assert len(provider.sent)==2
    with Session() as s:
        rows=ledger(s);assert [row.status for row in rows]==['uncertain','settled']
        assert rows[1].reset_at>reset and rows[0].reset_at<=reset
        assert sorted(s.get(Behavior,subject).verdict for subject in (SUBJECT,OTHER)).count('low')==1
