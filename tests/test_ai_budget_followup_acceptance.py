"""Roadmap A milestone 4: two-call (follow-up) triage reservations under a daily cap.

A process investigation whose first model call requests follow-up checks makes a
second provider call after SSH evidence collection. These tests drive the real
worker path (``worker.investigate_one``) with only the provider transport and the
SSH call replaced by disposable fixtures, and check the shared spend ledger.
"""
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_assessments, ai_budget, ai_claims, ai_pricing, ai_retry, ai_runs, worker
from app.db import Behavior, Host, Session, Setting
from app.security import seal

MODEL='gpt-6-astra'
EVIDENCE={'executable':'/srv/fixture','sha256':'a'*64,'uid':'1000','identity_verified':True}
# Reconciled usage is far below any reservation, so a settled call leaves headroom.
USAGE={'input_tokens':1000,'output_tokens':200,'total_tokens':1200,
       'input_tokens_details':{'cached_tokens':0,'cache_write_tokens':0},
       'output_tokens_details':{'reasoning_tokens':100}}


def first_quote():
    """The first call's reservation; the follow-up call carries more input, so it costs more."""
    return ai_pricing.reservation(ai.investigation_payload(EVIDENCE,MODEL))['amount_usd']


def seed(count=1,*,cap):
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':MODEL,'ai_control_mode':'daily_cap',
            'ai_daily_cap_usd':float(cap),'ai_budget_timezone':'UTC'}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        for n in range(count):
            s.add(Host(id='host-'+str(n),name='Fixture',address='192.0.2.1',fingerprint=''))
            s.add(Behavior(id='subject-'+str(n),host_id='host-'+str(n),evidence=dict(EVIDENCE,executable='/srv/fixture')))
        s.commit()


class Provider:
    """Records every provider transmission; first calls request follow-up checks."""
    def __init__(self,*,usage=True,barrier=None):
        self.sent=[];self.guard=threading.Lock();self.usage=usage;self.barrier=barrier
    def __call__(self,*args,**kwargs):
        payload=kwargs['json'];first='investigation' not in json.loads(payload['input'])
        if first and self.barrier:self.barrier.wait(timeout=15)
        with self.guard:self.sent.append((ai_runs.active.get(),first,payload))
        data={'risk':'low','explanation':'Advisory fixture','recommended_checks':'Review limitations',
              'requested_checks':['executable','service'] if first else []}
        body={'model':MODEL,'service_tier':'default','status':'completed',
              'output':[{'content':[{'type':'output_text','text':json.dumps(data)}]}]}
        if self.usage:body['usage']=USAGE
        return httpx.Response(200,json=body,request=httpx.Request('POST',ai.URL))


class Calls(list):
    barrier=None


@pytest.fixture
def ssh(monkeypatch):
    calls=Calls();guard=threading.Lock()
    def call(host,request,**kwargs):
        with guard:calls.append((host.id,request['checks']))
        # Release every follow-up reservation together when a test asks for it.
        if calls.barrier:calls.barrier.wait(timeout=15)
        return {'identity_verified':True,'sha256':'a'*64,'context':host.id}
    monkeypatch.setattr(worker.ssh,'call',call)
    return calls


def ledger(s):
    return list(s.scalars(select(ai_budget.BudgetEntry).order_by(ai_budget.BudgetEntry.created)))


def calls(s):
    return list(s.scalars(select(ai_runs.AICall)))


def test_followup_call_reserves_and_reconciles_its_own_ledger_row(admin,monkeypatch,ssh):
    seed(cap=first_quote()*4)
    provider=Provider();monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    assert [first for _,first,_ in provider.sent]==[True,False] and len(ssh)==1
    with Session() as s:
        rows=ledger(s);receipts={row.id:row for row in calls(s)}
        assert len(rows)==2 and all(row.status=='settled' for row in rows)
        # Each reservation covers its own request: the follow-up carries the collected evidence.
        assert rows[0].reservation_usd<rows[1].reservation_usd
        assert [row.reservation_usd for row in rows]==[ai_pricing.reservation(p)['amount_usd'] for _,_,p in provider.sent]
        assert {row.call_id for row in rows}==set(receipts) and len({row.run_id for row in rows})==1
        for row in rows:assert row.actual_usd==Decimal(receipts[row.call_id].pricing['estimated_usd'])
        state=ai_budget.status(s)
        assert Decimal(state['counted_usd'])==sum(row.actual_usd for row in rows)
        assert Decimal(state['reserved_usd'])==0 and Decimal(state['uncertain_usd'])==0
        behavior=s.get(Behavior,'subject-0');assert behavior.verdict=='low' and not behavior.approved
        assert s.get(ai_retry.TriageRetry,'subject-0') is None


def test_cap_exhausted_between_calls_defers_without_a_second_transmission(admin,monkeypatch,ssh):
    # Room for the first call's reservation only; without returned usage it stays fully counted.
    cap=first_quote()*Decimal('1.5')
    seed(cap=cap)
    provider=Provider(usage=False);monkeypatch.setattr(ai.transport,'post',provider)
    started=time.time()
    worker.investigate_one()
    assert [first for _,first,_ in provider.sent]==[True] and len(ssh)==1
    with Session() as s:
        rows=ledger(s)
        assert len(rows)==1 and rows[0].status=='uncertain'
        assert rows[0].reservation_usd==ai_pricing.reservation(provider.sent[0][2])['amount_usd']
        state=ai_budget.status(s);reset=state['next_reset']
        assert Decimal(state['counted_usd'])==rows[0].reservation_usd<=cap
        assert reset>started
        # The follow-up evidence stays bound to the subject for the retry.
        behavior=s.get(Behavior,'subject-0')
        assert behavior.verdict!='low' and not behavior.approved
        assert behavior.evidence['investigation']['details']['context']=='host-0'
        assert not list(s.scalars(select(ai_assessments.Assessment)))
        retry=s.get(ai_retry.TriageRetry,'subject-0')
        assert retry.state=='deferred' and retry.next_at==pytest.approx(reset,abs=1)
        assert retry.attempts==0  # a controlled wait is not a failed attempt
        run=s.scalars(select(ai_runs.AIRun)).one()
        assert run.state=='deferred' and run.calls==1 and len(calls(s))==1


def test_cap_deferred_followup_says_the_earlier_call_was_sent(admin,monkeypatch,ssh):
    # #1286: only the follow-up was withheld; the first-stage call was transmitted and still counts.
    seed(cap=first_quote()*Decimal('1.5'))
    provider=Provider(usage=False);monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    assert [first for _,first,_ in provider.sent]==[True]
    with Session() as s:
        retry=s.get(ai_retry.TriageRetry,'subject-0')
        assert retry.reason==ai_retry.FOLLOW_UP_BUDGET_WAIT_REASON and retry.state=='deferred' and retry.attempts==0
        analysis=s.get(Behavior,'subject-0').analysis
        run=s.scalars(select(ai_runs.AIRun)).one()
        failed=[e.message for e in s.scalars(select(ai_runs.AIEvent).where(ai_runs.AIEvent.run_id==run.id,ai_runs.AIEvent.stage=='failed'))]
    assert ai.FOLLOW_UP_BUDGET_DIAGNOSTIC in analysis and ai_retry.FOLLOW_UP_BUDGET_WAIT_REASON in analysis
    assert failed==[ai.FOLLOW_UP_BUDGET_DIAGNOSTIC]
    listed=[row for row in admin.get('/api/investigations').json() if row['id']=='subject-0'][0]
    assert listed['retry']['reason']==ai_retry.FOLLOW_UP_BUDGET_WAIT_REASON
    for text in (analysis,listed['retry']['reason'],failed[0]):
        assert 'no provider request was sent' not in text.lower()
        assert 'first-stage provider call was sent' in text


def test_cap_refusal_before_any_transmission_keeps_its_wording(admin,monkeypatch,ssh):
    # The first subject's sent call uses the headroom; the second subject's first call
    # then does not fit, so nothing was sent for it and the existing explanation stays.
    seed(count=2,cap=first_quote()*Decimal('1.5'))
    provider=Provider(usage=False);monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    # Simulate headroom used between claim preflight and the atomic reservation, so
    # the final reservation (not the preflight) refuses the second subject's first call.
    monkeypatch.setattr(ai_budget,'waiting',lambda *args,**kwargs:0)
    worker.investigate_one()
    assert [first for _,first,_ in provider.sent]==[True] and len(ssh)==1
    deferred=provider.sent[0][0]
    with Session() as s:
        sent_subject=s.get(ai_runs.AIRun,deferred).subject
        retry=s.get(ai_retry.TriageRetry,({'subject-0','subject-1'}-{sent_subject}).pop())
        assert retry.reason==ai_retry.BUDGET_WAIT_REASON and retry.state=='deferred' and retry.attempts==0
        analysis=s.get(Behavior,retry.subject).analysis
    assert 'No provider request was sent' in analysis and ai.FOLLOW_UP_BUDGET_DIAGNOSTIC not in analysis


def test_deferred_followup_completes_in_the_next_window(admin,monkeypatch,ssh):
    cap=first_quote()*Decimal('1.5')
    seed(cap=cap)
    provider=Provider(usage=False);monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    with Session() as s:
        reset=ai_budget.status(s)['next_reset'];first_window=[row.id for row in ledger(s)]
    assert len(provider.sent)==1 and len(first_window)==1
    # Still inside the window: the retry is not claimed and nothing is sent.
    worker.investigate_one()
    assert len(provider.sent)==1
    real=time.time;shift=reset-real()+5
    monkeypatch.setattr(time,'time',lambda:real()+shift)
    worker.investigate_one()
    with Session() as s:
        behavior=s.get(Behavior,'subject-0');assert behavior.verdict=='low' and not behavior.approved
        assert s.get(ai_retry.TriageRetry,'subject-0') is None
        assessment=s.scalars(select(ai_assessments.Assessment)).one()
        new_rows=[row for row in ledger(s) if row.id not in first_window]
        assert new_rows and all(row.reset_at>reset for row in new_rows)
        assert {row.run_id for row in new_rows}=={assessment.run_id}
        # The retry's own calls are all reserved in the new window; the old row keeps its window.
        assert len(new_rows)==len(provider.sent)-1
        # Observed behaviour: the retry's single call carries the follow-up evidence
        # persisted before the deferral, so no new SSH collection is requested.
        assert [first for _,first,_ in provider.sent]==[True,False] and len(ssh)==1
        assert s.get(ai_budget.BudgetEntry,first_window[0]).reset_at==reset
        state=ai_budget.status(s)
        assert Decimal(state['counted_usd'])==sum((row.reservation_usd for row in new_rows),Decimal(0))<=cap


def test_concurrent_followups_never_count_more_than_the_cap(admin,monkeypatch,ssh):
    # Four two-stage investigations would need eight calls; the cap fits at most five reservations.
    quote=first_quote();cap=quote*Decimal('5.5')
    seed(count=4,cap=cap)
    provider=Provider(usage=False,barrier=threading.Barrier(4));monkeypatch.setattr(ai.transport,'post',provider)
    ssh.barrier=threading.Barrier(4)
    with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda _:worker.investigate_one(),range(4)))
    firsts=[run for run,first,_ in provider.sent if first]
    seconds=[run for run,first,_ in provider.sent if not first]
    # Four first reservations fit; one follow-up fits after them, three are refused.
    assert len(firsts)==4 and len(seconds)==1 and len(ssh)==4
    with Session() as s:
        rows=ledger(s)
        # Every transmission has exactly one counted ledger row; refusals leave none.
        assert len(rows)==len(provider.sent) and all(row.status=='uncertain' for row in rows)
        assert {row.call_id for row in rows}=={row.id for row in calls(s)}
        assert sum((row.reservation_usd for row in rows),Decimal(0))<=cap
        assert Decimal(ai_budget.status(s)['counted_usd'])<=cap
        assert not list(s.scalars(select(ai_claims.Claim)))
        runs={run.id:run for run in s.scalars(select(ai_runs.AIRun))}
        for behavior in s.scalars(select(Behavior)):
            retry=s.get(ai_retry.TriageRetry,behavior.id)
            record=s.scalars(select(ai_assessments.Assessment).where(ai_assessments.Assessment.subject==behavior.id)).one_or_none()
            if record:
                assert retry is None and behavior.verdict=='low' and runs[record.run_id].state=='complete'
                assert record.run_id in seconds
            else:
                assert retry.state=='deferred' and retry.attempts==0 and behavior.verdict!='low'
                assert behavior.evidence['investigation']['details']['context']==behavior.host_id
        assert sum(run.state=='complete' for run in runs.values())==len(seconds)
        assert sum(run.state=='deferred' for run in runs.values())==4-len(seconds)
