"""Roadmap A milestone 4: lost or crashed triage leases under a daily spend cap.

A worker can lose its lease, hang or die after a provider call was sent. These tests
drive the real worker path (``worker.investigate_one``) with only the provider
transport and the SSH call replaced by disposable fixtures. They check that charges
that may have been incurred stay counted in the shared ledger, that a successor
reserves its own spend or defers at the cap, and that no stale result is accepted.
"""
import json
import os
import subprocess
import sys
import threading
import time
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from sqlalchemy import select

from app import (
    ai,
    ai_assessments,
    ai_budget,
    ai_claims,
    ai_policy,

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
EVIDENCE={'executable':'/srv/fixture','sha256':'a'*64,'uid':'1000','identity_verified':True}
USAGE={'input_tokens':1000,'output_tokens':200,'total_tokens':1200,
       'input_tokens_details':{'cached_tokens':0,'cache_write_tokens':0},
       'output_tokens_details':{'reasoning_tokens':100}}
WAIT=15


def first_quote():
    return ai_pricing.reservation(ai.investigation_payload(EVIDENCE,MODEL))['amount_usd']


def seed(*,cap):
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':MODEL,'ai_control_mode':'daily_cap',
            'ai_daily_cap_usd':float(cap),'ai_budget_timezone':'UTC'}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        s.add(Host(id='host-0',name='Fixture',address='192.0.2.1',fingerprint=''))
        s.add(Behavior(id=SUBJECT,host_id='host-0',evidence=dict(EVIDENCE)))
        s.commit()


class Provider:
    """Records each transmission. The first transmission can be held open to model a
    worker that lost its lease or hung mid-call; it then returns or fails."""
    def __init__(self,*,hold_first=False,followup=False,failure=None):
        self.sent=[];self.guard=threading.Lock();self.followup=followup;self.failure=failure
        self.hold=threading.Event() if hold_first else None
        self.in_flight=threading.Event();self.release=threading.Event()
    def __call__(self,*args,**kwargs):
        payload=kwargs['json'];first='investigation' not in json.loads(payload['input'])
        with self.guard:
            held=self.hold is not None and not self.hold.is_set()
            if held:self.hold.set()
            self.sent.append((ai_runs.active.get(),first))
        if held:
            self.in_flight.set()
            assert self.release.wait(timeout=WAIT)
            if self.failure:raise self.failure
        data={'risk':'low','explanation':'Advisory fixture','recommended_checks':'Review limitations',
              'requested_checks':['executable','service'] if first and self.followup else []}
        body={'model':MODEL,'service_tier':'default','status':'completed','usage':USAGE,
              'output':[{'content':[{'type':'output_text','text':json.dumps(data)}]}]}
        return httpx.Response(200,json=body,request=httpx.Request('POST',ai.URL))


@pytest.fixture
def ssh(monkeypatch):
    calls=[]
    def call(host,request,**kwargs):
        calls.append(request['checks'])
        return {'identity_verified':True,'sha256':'a'*64,'context':host.id}
    monkeypatch.setattr(worker.ssh,'call',call)
    return calls


def ledger(s):
    return list(s.scalars(select(ai_budget.BudgetEntry).order_by(ai_budget.BudgetEntry.created)))


def expire_lease():
    """Model a lost heartbeat: the lease is past expiry and the retry is due again."""
    with Session() as s:
        claim=s.get(ai_claims.Claim,SUBJECT);run_id=claim.run_id
        claim.expires=0;s.get(ai_retry.TriageRetry,SUBJECT).next_at=0;s.commit()
    return run_id


def start(target):
    thread=threading.Thread(target=target,daemon=True);thread.start();return thread


def test_late_result_after_lease_loss_stays_counted_but_is_never_accepted(admin,monkeypatch,ssh):
    seed(cap=first_quote()*4)
    provider=Provider(hold_first=True);monkeypatch.setattr(ai.transport,'post',provider)
    lost=start(worker.investigate_one)
    assert provider.in_flight.wait(timeout=WAIT)
    with Session() as s:assert [row.status for row in ledger(s)]==['sent']
    lost_run=expire_lease()
    # The successor recovers the subject and completes with its own reservation.
    worker.investigate_one()
    with Session() as s:
        successor=s.scalars(select(ai_assessments.Assessment)).one().run_id
        assert successor!=lost_run and s.get(ai_runs.AIRun,lost_run).state=='interrupted'
    provider.release.set();lost.join(timeout=WAIT);assert not lost.is_alive()
    assert [run for run,_ in provider.sent]==[lost_run,successor]
    with Session() as s:
        rows=ledger(s)
        # The late response is reconciled into the lost call's own row and stays counted.
        assert [(row.run_id,row.status) for row in rows]==[(lost_run,'settled'),(successor,'settled')]
        state=ai_budget.status(s)
        assert Decimal(state['counted_usd'])==sum(row.actual_usd for row in rows)
        assert Decimal(state['reserved_usd'])==0 and Decimal(state['uncertain_usd'])==0
        # Only the successor's result is accepted; the stale one changes nothing.
        assessment=s.scalars(select(ai_assessments.Assessment)).one()
        assert assessment.run_id==successor
        assert s.get(ai_runs.AIRun,lost_run).state=='interrupted'
        assert s.get(ai_runs.AIRun,successor).state=='complete'
        behavior=s.get(Behavior,SUBJECT);assert behavior.verdict=='low' and not behavior.approved
        assert not list(s.scalars(select(ai_claims.Claim)))


def test_hung_worker_charge_blocks_a_successor_at_the_cap_until_reset(admin,monkeypatch,ssh):
    # Start just before UTC reset so the provider backoff crosses it.
    real_time = time.time
    started = real_time()
    offset = (int(started) // 86400 + 1) * 86400 - 15 - started
    monkeypatch.setattr(time, 'time', lambda: real_time() + offset)
    # Room for the hung call's reservation only.
    cap=first_quote()*Decimal('1.5')
    seed(cap=cap)
    provider=Provider(hold_first=True,failure=httpx.ReadError('connection lost'))
    monkeypatch.setattr(ai.transport,'post',provider)
    hung=start(worker.investigate_one)
    assert provider.in_flight.wait(timeout=WAIT)
    hung_run=expire_lease()
    with Session() as s:
        before=ledger(s);reset=ai_budget.status(s)['next_reset']
        runs_before={run.id for run in s.scalars(select(ai_runs.AIRun))}
    assert [row.status for row in before]==['sent']
    # The successor finds no safe headroom: nothing is claimed, reserved or sent.
    assert ai_claims.acquire() is None
    worker.investigate_one()
    assert len(provider.sent)==1
    with Session() as s:
        assert [(row.id,row.status) for row in ledger(s)]==[(before[0].id,'sent')]
        assert Decimal(ai_budget.status(s)['counted_usd'])==before[0].reservation_usd<=cap
        assert {run.id for run in s.scalars(select(ai_runs.AIRun))}==runs_before
        assert s.get(ai_runs.AIRun,hung_run).state=='interrupted'
        # Still queued, not failed: the subject keeps its pending verdict.
        behavior=s.get(Behavior,SUBJECT);assert behavior.verdict=='pending' and not behavior.approved
        assert ai_budget.waiting(s,time.time(),ai.investigation_payload(EVIDENCE,MODEL))==reset
    # The hung call finally fails with an unknown outcome; its charge stays counted.
    provider.release.set();hung.join(timeout=WAIT);assert not hung.is_alive()
    with Session() as s:
        rows=ledger(s);assert [row.status for row in rows]==['uncertain']
        state=ai_budget.status(s)
        assert Decimal(state['counted_usd'])==rows[0].reservation_usd==Decimal(state['uncertain_usd'])
        assert s.get(ai_runs.AIRun,hung_run).state=='interrupted'
        assert not list(s.scalars(select(ai_assessments.Assessment)))
        assert s.get(Behavior,SUBJECT).verdict!='low'
    # The reset releases budget headroom, but the independent provider floor still applies.
    with Session() as s:
        provider_until = ai_provider_backoff.waiting(s, time.time())
    assert provider_until > reset + 5
    offset = reset + 5 - real_time()
    worker.investigate_one()
    assert len(provider.sent) == 1
    with Session() as s:
        assert [row.status for row in ledger(s)] == ['uncertain']
        assert Decimal(ai_budget.status(s)['counted_usd']) == 0

    # Once both gates are open, the successor takes a fresh reservation.
    offset = provider_until + 5 - real_time()
    worker.investigate_one()
    with Session() as s:
        rows=ledger(s);assert len(rows)==2 and rows[1].reset_at>reset
        assert s.get(Behavior,SUBJECT).verdict=='low'


CRASH_WORKER = """
import sys

import pytest

from app import ai, worker
from tests.pricing_catalog import pin_fresh_pricing_catalog

ai.URL = sys.argv[1]
with pytest.MonkeyPatch.context() as patch:
    pin_fresh_pricing_catalog(patch)
    worker.investigate_one()
"""


def test_process_killed_after_provider_receives_request_preserves_the_cap(admin, monkeypatch, ssh):
    cap = first_quote() * Decimal('1.5')
    seed(cap=cap)
    received = threading.Event()
    release = threading.Event()

    class ProviderRequest(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            received.set()
            # Keep the request in flight until the parent has killed the worker.
            release.wait(timeout=45)

        def log_message(self, *args):
            pass

    environment = {name: value for name, value in os.environ.items()
                   if not name.lower().endswith('_proxy')}
    with ThreadingHTTPServer(('127.0.0.1', 0), ProviderRequest) as server:
        listener = start(server.serve_forever)
        url = f'http://127.0.0.1:{server.server_port}/v1/responses'
        try:
            with subprocess.Popen([sys.executable, '-c', CRASH_WORKER, url], env=environment,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True) as child:
                arrived = received.wait(timeout=30)
                running = child.poll() is None
                if running:
                    child.kill()
                _, errors = child.communicate(timeout=WAIT)
                assert arrived and running, errors
                assert child.returncode != 0
        finally:
            release.set()
            server.shutdown()
            listener.join(timeout=WAIT)

    with Session() as s:
        receipt, = ledger(s)
        assert receipt.status == 'sent' and receipt.call_id
        assert s.get(ai_claims.Claim, SUBJECT).run_id == receipt.run_id
        assert s.get(ai_runs.AIRun, receipt.run_id).state == 'running'
        reset = ai_budget.status(s)['next_reset']
    assert expire_lease() == receipt.run_id

    # The successor has only the shared durable state after process death.
    provider = Provider()
    monkeypatch.setattr(ai.transport, 'post', provider)
    worker.investigate_one()
    assert provider.sent == []
    with Session() as s:
        state = ai_budget.status(s)
        assert [row.id for row in ledger(s)] == [receipt.id]
        assert Decimal(state['counted_usd']) == Decimal(state['uncertain_usd']) == receipt.reservation_usd
        assert state['unreconciled_call_count'] == 1
        assert s.get(ai_runs.AIRun, receipt.run_id).state == 'interrupted'
        assert s.get(ai_claims.Claim, SUBJECT) is None
        assert not list(s.scalars(select(ai_assessments.Assessment)))
        behavior = s.get(Behavior, SUBJECT)
        assert behavior.verdict == 'pending' and not behavior.approved

    clock = time.time
    shift = reset - clock() + 5
    monkeypatch.setattr(time, 'time', lambda: clock() + shift)
    worker.investigate_one()
    successor, = [run_id for run_id, _ in provider.sent]
    with Session() as s:
        before, after = ledger(s)
        assert (before.id, before.status) == (receipt.id, 'sent')
        assert after.status == 'settled' and after.run_id == successor and after.reset_at > reset
        assert s.scalars(select(ai_assessments.Assessment)).one().run_id == successor
        assert s.get(ai_runs.AIRun, successor).state == 'complete'
        behavior = s.get(Behavior, SUBJECT)
        assert behavior.verdict == 'low' and not behavior.approved


def test_lease_lost_during_followup_collection_never_sends_the_second_call(admin,monkeypatch):
    seed(cap=first_quote()*4)
    provider=Provider(followup=True);monkeypatch.setattr(ai.transport,'post',provider)
    collected=[]
    def call(host,request,**kwargs):
        # The heartbeat is lost while follow-up evidence is being collected.
        collected.append(request['checks']);expire_lease()
        return {'identity_verified':True,'sha256':'a'*64,'context':host.id}
    monkeypatch.setattr(worker.ssh,'call',call)
    worker.investigate_one()
    assert [first for _,first in provider.sent]==[True] and len(collected)==1
    with Session() as s:
        rows=ledger(s)
        # Only the first call was reserved; it was answered, so it settles and stays counted.
        assert [row.status for row in rows]==['settled']
        assert Decimal(ai_budget.status(s)['counted_usd'])==rows[0].actual_usd
        run=s.scalars(select(ai_runs.AIRun)).one()
        # The owner detects its own lost lease and records the run as failed (no successor
        # has reconciled it yet); the run discloses that the sent call may still be billable.
        assert run.state=='error' and 'billable' in run.message and rows[0].run_id==run.id
        assert not list(s.scalars(select(ai_assessments.Assessment)))
        assert s.get(Behavior,SUBJECT).verdict!='low'
        assert not list(s.scalars(select(ai_claims.Claim)))


def test_lease_lost_after_evidence_persistence_never_sends_the_second_call(admin,monkeypatch,ssh):
    """The lease is lost after follow-up evidence is stored but before the second call
    is sent. Only the provider gate's pre-send lease recheck can stop that call."""
    seed(cap=first_quote()*4)
    provider=Provider(followup=True);monkeypatch.setattr(ai.transport,'post',provider)
    real=ai_policy.require
    def require(identifiers):
        if len(provider.sent)==1:expire_lease()
        return real(identifiers)
    monkeypatch.setattr(ai_policy,'require',require)
    worker.investigate_one()
    assert [first for _,first in provider.sent]==[True] and len(ssh)==1
    with Session() as s:
        rows=ledger(s)
        assert [row.status for row in rows]==['settled']
        assert Decimal(ai_budget.status(s)['counted_usd'])==rows[0].actual_usd
        run=s.scalars(select(ai_runs.AIRun)).one();assert run.state in ('error','interrupted')
        assert not list(s.scalars(select(ai_assessments.Assessment)))
        assert s.get(Behavior,SUBJECT).verdict!='low'
