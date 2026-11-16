"""Roadmap A milestone 4: per-server AI pause and global AI disable under a daily cap.

These tests drive the real worker path (``worker.investigate_one``) and the real
administrator route, with only the provider transport and the SSH call replaced by
disposable fixtures. They check that a paused server takes no cap headroom, that a
pause cannot land while a capped call is in flight, and that disabling AI between a
first call and its follow-up stops the second call while the first stays counted.
"""
import json
import threading
from decimal import Decimal

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
    ai_retry,
    ai_runs,
    worker,
)
from app.db import Audit, Behavior, Host, Session, Setting
from app.identity import User
from app.security import seal

MODEL='gpt-6-astra'
EVIDENCE={'executable':'/srv/fixture','sha256':'a'*64,'uid':'1000','identity_verified':True}
USAGE={'input_tokens':1000,'output_tokens':200,'total_tokens':1200,
       'input_tokens_details':{'cached_tokens':0,'cache_write_tokens':0},
       'output_tokens_details':{'reasoning_tokens':100}}
WAIT=15


def policy_url(host):
    return f'/api/hosts/{host}/security/ai-policy'


def first_quote():
    return ai_pricing.reservation(ai.investigation_payload(EVIDENCE,MODEL))['amount_usd']


def seed(*,cap,hosts=('host-a',)):
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':MODEL,'ai_control_mode':'daily_cap',
            'ai_daily_cap_usd':float(cap),'ai_budget_timezone':'UTC'}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        for host in hosts:
            s.add(Host(id=host,name=host,address='192.0.2.1',fingerprint=''))
            s.add(Behavior(id='subject-'+host,host_id=host,evidence=dict(EVIDENCE)))
        s.commit()


def set_pause(client,host,paused,**changes):
    current=client.get(policy_url(host)).json()
    return client.put(policy_url(host),json={'paused':paused,'expected_revision':current['revision'],
        'reason':'Pause provider processing for budget review',**changes})


def set_ai_enabled(enabled):
    with Session() as s:
        row=s.get(Setting,'config');row.value={**row.value,'ai_enabled':enabled};s.commit()


class Provider:
    """Records each transmission with its run and host. The first transmission can be
    held open; ``on_first`` runs after the first call is answered."""
    def __init__(self,*,hold_first=False,followup=False,on_first=None):
        self.sent=[];self.inputs=[];self.guard=threading.Lock();self.followup=followup;self.on_first=on_first
        self.hold=hold_first;self.in_flight=threading.Event();self.release=threading.Event()
    def __call__(self,*args,**kwargs):
        payload=kwargs['json'];sent_input=json.loads(payload['input'])
        first='investigation' not in sent_input
        with self.guard:
            self.inputs.append(sent_input)
            held=self.hold and not self.sent
            self.sent.append((ai_runs.active.get(),first))
        if held:
            self.in_flight.set()
            assert self.release.wait(timeout=WAIT)
        data={'risk':'low','explanation':'Advisory fixture','recommended_checks':'Review limitations',
              'requested_checks':['executable','service'] if first and self.followup else []}
        if first and self.on_first:self.on_first()
        body={'model':MODEL,'service_tier':'default','status':'completed','usage':USAGE,
              'output':[{'content':[{'type':'output_text','text':json.dumps(data)}]}]}
        return httpx.Response(200,json=body,request=httpx.Request('POST',ai.URL))


@pytest.fixture
def ssh(monkeypatch):
    calls=[]
    def call(host,request,**kwargs):
        calls.append((host.id,request['checks']))
        return {'identity_verified':True,'sha256':'a'*64,'context':host.id}
    monkeypatch.setattr(worker.ssh,'call',call)
    return calls


def ledger(s):
    return list(s.scalars(select(ai_budget.BudgetEntry).order_by(ai_budget.BudgetEntry.created)))


def run_host(s,run_id):
    return s.get(ai_runs.AIRun,run_id).host_id


def test_paused_server_takes_no_cap_headroom_and_runs_with_its_own_reservation_after_resume(admin,monkeypatch,ssh):
    # Room for one first call only: whichever subject is admitted uses it all.
    seed(cap=first_quote()*Decimal('1.5'),hosts=('host-a','host-b'))
    assert set_pause(admin,'host-a',True).status_code==200
    provider=Provider();monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    with Session() as s:
        # Only the unpaused server was claimed, reserved and sent.
        assert [run_host(s,run) for run,_ in provider.sent]==['host-b']
        rows=ledger(s);assert [(run_host(s,row.run_id),row.status) for row in rows]==[('host-b','settled')]
        assert {ssh_host for ssh_host,_ in ssh}<={'host-b'}
        assert s.get(Behavior,'subject-host-b').verdict=='low'
        paused=s.get(Behavior,'subject-host-a')
        assert paused.verdict=='pending' and paused.attempted==0 and not paused.approved
        assert not list(s.scalars(select(ai_runs.AIRun).where(ai_runs.AIRun.host_id=='host-a')))
    # Repeated passes neither claim nor reserve anything for the paused server.
    worker.investigate_one();worker.investigate_one()
    assert len(provider.sent)==1
    with Session() as s:assert len(ledger(s))==1
    # After resume the paused subject is eligible again, but must reserve its own spend:
    # the cap has no room left today, so it waits rather than borrowing headroom.
    def set_cap(cap):
        with Session() as s:
            cfg=s.get(Setting,'config');cfg.value={**cfg.value,'ai_daily_cap_usd':float(cap)};s.commit()
    with Session() as s:spent=Decimal(ai_budget.status(s)['counted_usd'])
    set_cap(spent+first_quote()/2)
    assert set_pause(admin,'host-a',False).status_code==200
    assert ai_claims.acquire() is None
    worker.investigate_one();assert len(provider.sent)==1
    with Session() as s:
        assert len(ledger(s))==1 and s.get(Behavior,'subject-host-a').verdict=='pending'
    set_cap(first_quote()*4)
    worker.investigate_one()
    with Session() as s:
        assert [run_host(s,run) for run,_ in provider.sent]==['host-b','host-a']
        rows=ledger(s)
        assert [(run_host(s,row.run_id),row.status) for row in rows]==[('host-b','settled'),('host-a','settled')]
        assert rows[0].run_id!=rows[1].run_id
        assert Decimal(ai_budget.status(s)['counted_usd'])==sum(row.actual_usd for row in rows)
        assert s.get(Behavior,'subject-host-a').verdict=='low'


def test_pause_is_refused_while_a_capped_call_is_in_flight_then_accepted(admin,monkeypatch,ssh):
    seed(cap=first_quote()*4)
    provider=Provider(hold_first=True);monkeypatch.setattr(ai.transport,'post',provider)
    thread=threading.Thread(target=worker.investigate_one,daemon=True);thread.start()
    try:
        assert provider.in_flight.wait(timeout=WAIT)
        before=admin.get(policy_url('host-a')).json()
        refused=set_pause(admin,'host-a',True)
        assert refused.status_code==409 and 'State has not changed' in refused.json()['detail']
        after=admin.get(policy_url('host-a')).json()
        assert not after['paused'] and after['revision']==before['revision']
        with Session() as s:
            rows=ledger(s);assert [row.status for row in rows]==['sent']
            assert Decimal(ai_budget.status(s)['counted_usd'])==rows[0].reservation_usd
            assert not list(s.scalars(select(Audit).where(Audit.action=='server AI paused')))
    finally:
        provider.release.set();thread.join(timeout=WAIT)
    assert not thread.is_alive()
    with Session() as s:
        rows=ledger(s);assert [row.status for row in rows]==['settled']
        assert s.scalars(select(ai_assessments.Assessment)).one().run_id==rows[0].run_id
        assert not list(s.scalars(select(ai_claims.Claim)))
    # With nothing in flight the same pause is accepted and audited.
    accepted=set_pause(admin,'host-a',True)
    assert accepted.status_code==200 and accepted.json()['paused']
    with Session() as s:
        assert list(s.scalars(select(Audit).where(Audit.action=='server AI paused')))
        # New work on the paused server is not admitted and reserves nothing.
        s.add(Behavior(id='subject-new',host_id='host-a',evidence=dict(EVIDENCE)));s.commit()
    assert ai_claims.acquire() is None
    worker.investigate_one()
    assert len(provider.sent)==1
    with Session() as s:
        assert len(ledger(s))==1 and s.get(Behavior,'subject-new').verdict=='pending'


def test_global_disable_between_first_and_followup_never_sends_or_reserves_the_second_call(admin,monkeypatch,ssh):
    seed(cap=first_quote()*4)
    provider=Provider(followup=True,on_first=lambda:set_ai_enabled(False))
    monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    # The first call was sent; the follow-up was refused at the provider gate.
    assert [first for _,first in provider.sent]==[True]
    with Session() as s:
        rows=ledger(s)
        # Only the first call was reserved; it was answered, so it settles and stays counted.
        assert [row.status for row in rows]==['settled']
        state=ai_budget.status(s)
        assert Decimal(state['counted_usd'])==rows[0].actual_usd
        assert Decimal(state['reserved_usd'])==0 and Decimal(state['uncertain_usd'])==0
        assert not list(s.scalars(select(ai_assessments.Assessment)))
        behavior=s.get(Behavior,'subject-host-a')
        assert behavior.verdict!='low' and not behavior.approved
        assert not list(s.scalars(select(ai_claims.Claim)))
        # A policy wait is queued work, not a failed run: the run is deferred and the
        # subject keeps a policy-wait retry instead of a provider-failure backoff.
        assert s.get(ai_runs.AIRun,rows[0].run_id).state=='deferred'
        retry=s.get(ai_retry.TriageRetry,'subject-host-a')
        assert retry and 'Waiting for AI policy resume' in retry.reason
    # While disabled, nothing more is claimed, reserved or sent.
    worker.investigate_one()
    assert len(provider.sent)==1
    with Session() as s:assert len(ledger(s))==1
    # Re-enabling admits the subject again with fresh reservations for both calls.
    provider.on_first=None;set_ai_enabled(True)
    with Session() as s:s.get(ai_retry.TriageRetry,'subject-host-a').next_at=0;s.commit()
    worker.investigate_one()
    # The retry starts with a new first call. It carries the follow-up evidence that
    # was collected and retained before the disable, so no further follow-up is needed.
    assert len(provider.sent)==2 and provider.sent[1][0]!=provider.sent[0][0]
    assert 'investigation' in provider.inputs[1] and 'investigation' not in provider.inputs[0]
    with Session() as s:
        rows=ledger(s);assert [row.status for row in rows]==['settled']*2
        assert rows[1].run_id!=rows[0].run_id
        assert Decimal(ai_budget.status(s)['counted_usd'])==sum(row.actual_usd for row in rows)
        assert s.scalars(select(ai_assessments.Assessment)).one().run_id==rows[1].run_id
        assert s.get(Behavior,'subject-host-a').verdict=='low'


def test_pause_route_keeps_csrf_and_role_checks_with_a_capped_ledger(admin,monkeypatch,ssh):
    seed(cap=first_quote()*4)
    provider=Provider();monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    with Session() as s:before=[(row.id,row.status,row.actual_usd) for row in ledger(s)]
    assert len(before)==1
    csrf=admin.headers.pop('X-CSRF-Token')
    assert set_pause(admin,'host-a',True).status_code==403
    admin.headers['X-CSRF-Token']=csrf
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get(policy_url('host-a')).status_code==403
        assert admin.put(policy_url('host-a'),json={'paused':True,'reason':'A meaningful reason'}).status_code==403
    with Session() as s:
        s.get(User,'admin').role='admin';s.commit()
        assert not ai_policy.status(s,'host-a')['paused']
        assert [(row.id,row.status,row.actual_usd) for row in ledger(s)]==before
        assert not list(s.scalars(select(Audit).where(Audit.action=='server AI paused')))
