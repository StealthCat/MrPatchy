"""Roadmap A milestone 4: worker drain and resume under a daily spend cap (#1008).

An administrator can drain a worker while a capped triage call is in flight on it.
These tests drive the real worker path (``worker.investigate_one``) with registered
workers. Only the provider transport and the SSH call are disposable fixtures. They
check four things. Admitted work finishes with full capability and settled spend. A
draining worker claims, reserves and sends nothing new. Another worker admits queued
work with its own reservation. Resume restores admission on the same worker.
"""
import json
import threading
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_assessments, ai_budget, ai_claims, ai_pricing, ai_retry, ai_runs, worker, worker_registry
from app.db import Behavior, Host, Session, Setting
from app.security import seal

MODEL='gpt-6-astra'
EVIDENCE={'executable':'/srv/fixture','sha256':'a'*64,'uid':'1000','identity_verified':True}
USAGE={'input_tokens':1000,'output_tokens':200,'total_tokens':1200,
       'input_tokens_details':{'cached_tokens':0,'cache_write_tokens':0},
       'output_tokens_details':{'reasoning_tokens':100}}
WAIT=15


def first_quote():
    return ai_pricing.reservation(ai.investigation_payload(EVIDENCE,MODEL))['amount_usd']


def seed(*,subjects=2):
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':MODEL,'ai_control_mode':'daily_cap',
            'ai_daily_cap_usd':float(first_quote()*20),'ai_budget_timezone':'UTC'}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        for n in range(subjects):
            s.add(Host(id='host-'+str(n),name='Fixture',address='192.0.2.1',fingerprint=''))
            s.add(Behavior(id='subject-'+str(n),host_id='host-'+str(n),evidence=dict(EVIDENCE)))
        s.commit()


class Provider:
    """Records each transmission. A chosen call (first or follow-up) is held open so a
    drain can be requested while it is in flight."""
    def __init__(self,*,hold='first',followup=False):
        self.sent=[];self.guard=threading.Lock();self.followup=followup;self.hold=hold
        self.in_flight=threading.Event();self.release=threading.Event();self.held=False
    def __call__(self,*args,**kwargs):
        payload=kwargs['json'];first='investigation' not in json.loads(payload['input'])
        with self.guard:
            held=not self.held and self.hold==('first' if first else 'followup')
            if held:self.held=True
            self.sent.append((ai_runs.active.get(),first))
        if held:
            self.in_flight.set()
            assert self.release.wait(timeout=WAIT)
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


def drain(node,action='drain'):
    with Session() as s:revision=worker_registry.control_value(s,node.id,node.boot)['revision']
    worker_registry.request_control(node.id,node.boot,revision,action,'Planned fixture maintenance window','admin')


def reported(node):
    with Session() as s:return s.get(Setting,worker_registry.record_key(node.id)).value['state']


def start(target,*args):
    thread=threading.Thread(target=target,args=args,daemon=True);thread.start();return thread


def assert_spend_matches(s,rows):
    state=ai_budget.status(s)
    assert Decimal(state['counted_usd'])==sum(row.actual_usd for row in rows)
    assert Decimal(state['reserved_usd'])==0 and Decimal(state['uncertain_usd'])==0


@pytest.mark.parametrize('hold,followup',[('first',False),('first',True),('followup',True)])
def test_drain_finishes_admitted_capped_work_and_admits_nothing_new(admin,monkeypatch,ssh,hold,followup):
    seed()
    provider=Provider(hold=hold,followup=followup);monkeypatch.setattr(ai.transport,'post',provider)
    with worker_registry.Registration() as node:
        owner=(node.id,node.boot)
        running=start(worker.investigate_one,owner)
        assert provider.in_flight.wait(timeout=WAIT)
        drain(node)
        assert node.heartbeat(False,[],0,1) is True and reported(node)=='draining'
        with Session() as s:
            busy=s.scalars(select(ai_claims.Claim)).one().subject
            before=[(row.id,row.status) for row in ledger(s)]
            # The held call is sent; an answered first call has already settled.
            assert [status for _,status in before]==(['settled','sent'] if hold=='followup' else ['sent'])
        # The draining worker claims, reserves and sends nothing for the other subject.
        assert ai_claims.acquire(owner) is None
        worker.investigate_one(owner)
        with Session() as s:
            assert [(row.id,row.status) for row in ledger(s)]==before
            assert [claim.subject for claim in s.scalars(select(ai_claims.Claim))]==[busy]
            assert len(list(s.scalars(select(ai_runs.AIRun))))==1
        provider.release.set();running.join(timeout=WAIT);assert not running.is_alive()
        # The admitted investigation completed with every check, including its follow-up.
        assert [first for _,first in provider.sent]==[True,False][:1+followup]
        assert len(ssh)==int(followup)
        with Session() as s:
            rows=ledger(s);run=s.scalars(select(ai_runs.AIRun)).one()
            assert run.state=='complete' and [row.status for row in rows]==['settled']*(1+followup)
            assert {row.run_id for row in rows}=={run.id}
            assert_spend_matches(s,rows)
            assessment=s.scalars(select(ai_assessments.Assessment)).one()
            assert assessment.subject==busy and assessment.run_id==run.id
            assert s.get(Behavior,busy).verdict=='low'
            other=next(row for row in s.scalars(select(Behavior)) if row.id!=busy)
            # Queued, not failed or blocked: no retry state and no claim.
            assert other.verdict=='pending' and s.get(ai_retry.TriageRetry,other.id) is None
            assert not list(s.scalars(select(ai_claims.Claim)))
        assert node.heartbeat(False,[],0,0) is True and reported(node)=='drained'
        assert ai_claims.acquire(owner) is None


def test_another_worker_takes_queued_work_and_resume_restores_admission(admin,monkeypatch,ssh):
    seed(subjects=3)
    provider=Provider(hold=None);monkeypatch.setattr(ai.transport,'post',provider)
    with worker_registry.Registration() as drained,worker_registry.Registration() as serving:
        assert drained.id!=serving.id
        drained_owner=(drained.id,drained.boot);serving_owner=(serving.id,serving.boot)
        drain(drained);assert drained.heartbeat(False,[],0,0) is True and reported(drained)=='drained'
        worker.investigate_one(drained_owner)
        with Session() as s:assert not ledger(s) and not list(s.scalars(select(ai_runs.AIRun)))
        assert provider.sent==[]
        # A reporting worker admits queued work with its own reservation.
        worker.investigate_one(serving_owner)
        with Session() as s:
            rows=ledger(s);assert [row.status for row in rows]==['settled']
            assert s.get(ai_runs.AIRun,rows[0].run_id).state=='complete'
            assert len([row for row in s.scalars(select(Behavior)) if row.verdict=='low'])==1
        # Resume records a new control revision; the next heartbeat reports again.
        drain(drained,'resume')
        # Until that heartbeat the worker still reports ``drained``, so the
        # reported-state half of the admission gate refuses capped work.
        assert reported(drained)=='drained'
        assert ai_claims.acquire(drained_owner) is None
        worker.investigate_one(drained_owner)
        assert len(provider.sent)==1
        with Session() as s:assert len(ledger(s))==1
        assert drained.heartbeat(False,[],0,0) is False and reported(drained)=='reporting'
        worker.investigate_one(drained_owner)
        with Session() as s:
            rows=ledger(s);assert [row.status for row in rows]==['settled','settled']
            assert len({row.run_id for row in rows})==2
            assert_spend_matches(s,rows)
            assert len([row for row in s.scalars(select(Behavior)) if row.verdict=='low'])==2
        assert len(provider.sent)==2 and all(first for _,first in provider.sent)


def test_drain_not_yet_observed_by_heartbeat_still_blocks_admission(admin,monkeypatch,ssh):
    """Admission reads the drain control record itself. It does not wait for the
    worker's next heartbeat to report ``draining``. A drain that commits while an
    admission transaction is already open may let that one admission proceed. That
    work then finishes like any other in-flight work."""
    seed(subjects=1)
    provider=Provider(hold=None);monkeypatch.setattr(ai.transport,'post',provider)
    with worker_registry.Registration() as node:
        owner=(node.id,node.boot)
        drain(node)
        assert reported(node)=='reporting' and not node.draining
        assert ai_claims.acquire(owner) is None
        worker.investigate_one(owner)
        assert provider.sent==[]
        with Session() as s:
            assert not ledger(s) and not list(s.scalars(select(ai_claims.Claim)))
            assert not list(s.scalars(select(ai_runs.AIRun)))
            assert s.get(Behavior,'subject-0').verdict=='pending'
