"""Roadmap A milestone 4: Unthrottled mode keeps every control except Mr Patchy's own pacing and spend cap (#1018).

Roadmap A states that Unthrottled removes only Mr Patchy's rate and spend
controls; concurrency, provider limits, pause, authorization and data-sharing
controls still apply. These tests drive the real worker path
(``worker.investigate_one``: claim -> admission -> provider -> acceptance) and the
real administrator pause route in ``unthrottled`` mode. Only the provider
transport and SSH are fixtures.

Role/CSRF refusal of a switch to Unthrottled is covered by
``tests/test_ai_budget_role_csrf_acceptance.py`` (#1010), and identical,
bounded data sharing in Unthrottled mode by
``tests/test_ai_budget_data_sharing_acceptance.py`` (#1000).
"""
import json
import threading
import time

import httpx
import pytest
from sqlalchemy import select

from app import (
    ai,
    ai_admission,
    ai_budget,
    ai_claims,
    ai_policy,
    ai_provider_backoff,
    ai_runs,
    worker,
)
from app.db import Behavior, Host, Session, Setting
from app.security import seal

PRICED='gpt-6-astra'
UNPRICED='fixture-unpriced-model'
EVIDENCE={'executable':'/srv/fixture','sha256':'a'*64,'uid':'1000','identity_verified':True}
USAGE={'input_tokens':1000,'output_tokens':200,'total_tokens':1200,
       'input_tokens_details':{'cached_tokens':0,'cache_write_tokens':0},
       'output_tokens_details':{'reasoning_tokens':100}}
WAIT=15


def configure(**changes):
    """Unthrottled with deliberately restrictive *stale* rate and cap values saved."""
    with Session() as s:
        row=s.get(Setting,'config')
        base=row.value if row else {'ai_enabled':True,'ai_model':PRICED,'ai_control_mode':'unthrottled',
            'ai_rate_per_hour':1,'ai_daily_cap_usd':0.01,'ai_budget_timezone':'UTC','ai_updates_enabled':False}
        s.merge(Setting(key='config',value={**base,**changes}))
        if not s.get(Setting,'openai_key'):s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        s.commit()


def add_subject(host,subject=None):
    with Session() as s:
        if not s.get(Host,host):s.add(Host(id=host,name=host,address='192.0.2.1',fingerprint=''))
        s.add(Behavior(id=subject or 'subject-'+host,host_id=host,evidence=dict(EVIDENCE)))
        s.commit()


class Provider:
    """Records each transmission's host. Optionally holds the first open, or fails
    with a scripted provider response before succeeding."""
    def __init__(self,*failures,hold_first=False):
        self.sent=[];self.guard=threading.Lock();self.failures=list(failures)
        self.hold=hold_first;self.in_flight=threading.Event();self.release=threading.Event()
    def hosts(self):
        with Session() as s:return [s.get(ai_runs.AIRun,run).host_id for run in self.sent]
    def __call__(self,*args,**kwargs):
        request=httpx.Request('POST',ai.URL)
        with self.guard:
            held=self.hold and not self.sent
            self.sent.append(ai_runs.active.get())
            failure=self.failures.pop(0) if self.failures else None
        if held:
            self.in_flight.set()
            assert self.release.wait(timeout=WAIT)
        if failure:
            status,headers,code=failure
            return httpx.Response(status,headers=headers,json={'error':{'code':code,'message':'fixture'}},request=request)
        data={'risk':'low','explanation':'Advisory fixture','recommended_checks':'Review limitations','requested_checks':[]}
        body={'model':PRICED,'service_tier':'default','status':'completed','usage':USAGE,
              'output':[{'content':[{'type':'output_text','text':json.dumps(data)}]}]}
        return httpx.Response(200,json=body,request=request)


@pytest.fixture
def ssh(monkeypatch):
    calls=[]
    def call(host,request,**kwargs):
        calls.append(host.id)
        return {'identity_verified':True,'sha256':'a'*64,'context':host.id}
    monkeypatch.setattr(worker.ssh,'call',call)
    return calls


def ledger_count():
    with Session() as s:return len(list(s.scalars(select(ai_budget.BudgetEntry))))


def verdict(subject):
    with Session() as s:return s.get(Behavior,subject).verdict


def set_pause(client,host,paused):
    url=f'/api/hosts/{host}/security/ai-policy'
    current=client.get(url).json()
    return client.put(url,json={'paused':paused,'expected_revision':current['revision'],
        'reason':'Pause provider processing for review'})


def test_unthrottled_ignores_stale_rate_and_cap_values_that_rate_and_cap_modes_enforce(admin,monkeypatch,ssh):
    # A one-per-hour rate, a one-cent cap and an unpriced model are all saved.
    configure(ai_model=UNPRICED)
    for host in ('host-a','host-b','host-c'):add_subject(host)
    provider=Provider();monkeypatch.setattr(ai.transport,'post',provider)
    for _ in range(3):worker.investigate_one()
    # Three back-to-back starts: no pacing wait, no reservation, and no pricing needed.
    assert sorted(provider.hosts())==['host-a','host-b','host-c']
    assert ledger_count()==0
    with Session() as s:
        assert ai_admission.waiting(s,time.time())==0
        assert ai_budget.waiting(s,time.time())==0
        assert s.get(ai_admission.Admission,'global') is None
    assert {verdict('subject-'+host) for host in ('host-a','host-b','host-c')}=={'low'}

    # Control: the same saved values in daily_cap mode refuse the unpriced model
    # before sending anything, so the Unthrottled result above is not a fixture artifact.
    configure(ai_control_mode='daily_cap');add_subject('host-d')
    worker.investigate_one()
    assert len(provider.sent)==3 and ledger_count()==0 and verdict('subject-host-d')=='pending'

    # Control: rate mode admits one start and then waits for the next hourly slot.
    configure(ai_control_mode='rate');add_subject('host-e')
    worker.investigate_one();worker.investigate_one()
    assert len(provider.sent)==4
    with Session() as s:assert ai_admission.waiting(s,time.time())>time.time()+3000
    assert sorted(verdict('subject-'+host) for host in ('host-d','host-e')).count('pending')==1

    # Back to Unthrottled: the outstanding rate slot no longer holds work back.
    configure(ai_control_mode='unthrottled')
    worker.investigate_one()
    assert len(provider.sent)==5 and ledger_count()==0
    assert {verdict('subject-'+host) for host in ('host-d','host-e')}=={'low'}


@pytest.mark.parametrize('limit,expected_while_held',[(1,['host-a','host-b']),(2,['host-a','host-b','host-a'])])
def test_unthrottled_keeps_the_per_server_investigation_concurrency_limit(admin,monkeypatch,ssh,limit,expected_while_held):
    configure()
    with Session() as s:
        s.merge(Setting(key=ai_policy.PREFIX+'host-a',value={'concurrency_limit':limit}));s.commit()
    add_subject('host-a','subject-a1');add_subject('host-a','subject-a2');add_subject('host-b')
    with Session() as s:
        # Make host-a's subjects the oldest so it is elected first.
        s.get(Behavior,'subject-a1').first_seen=1;s.get(Behavior,'subject-a2').first_seen=2;s.commit()
    provider=Provider(hold_first=True);monkeypatch.setattr(ai.transport,'post',provider)
    thread=threading.Thread(target=worker.investigate_one,daemon=True);thread.start()
    try:
        assert provider.in_flight.wait(timeout=WAIT)
        # While host-a's first call is in flight, further passes may start other work,
        # but never more concurrent host-a investigations than its configured limit.
        for _ in range(3):worker.investigate_one()
        assert provider.hosts()==expected_while_held
        with Session() as s:assert ai_claims.occupancy(s,'host-a')['active_lease_count']==1
    finally:
        provider.release.set();thread.join(timeout=WAIT)
    assert not thread.is_alive()
    worker.investigate_one()
    assert sorted(provider.hosts())==['host-a','host-a','host-b']
    assert {verdict(subject) for subject in ('subject-a1','subject-a2','subject-host-b')}=={'low'}
    assert ledger_count()==0


def test_unthrottled_honours_provider_retry_after_for_every_subject(admin,monkeypatch,ssh):
    configure();add_subject('host-a')
    real=time.time;shift=[0.0]
    monkeypatch.setattr(time,'time',lambda:real()+shift[0])
    provider=Provider((429,{'retry-after':'120'},'rate_limit_exceeded'))
    monkeypatch.setattr(ai.transport,'post',provider)
    started=time.time()
    worker.investigate_one()
    assert len(provider.sent)==1
    with Session() as s:
        floor=ai_provider_backoff.status(s)
        assert floor['blocked'] and floor['next_at']>=started+120
    # A fresh subject on another server has no retry delay of its own; the shared
    # provider floor still holds it, and nothing is claimed, sent or reserved.
    add_subject('host-b')
    for _ in range(3):worker.investigate_one()
    assert len(provider.sent)==1 and verdict('subject-host-b')=='pending'
    with Session() as s:
        assert not list(s.scalars(select(ai_claims.Claim)))
        assert len(list(s.scalars(select(ai_runs.AIRun))))==1
    assert ledger_count()==0
    # After the floor passes, work resumes without any Mr Patchy pacing between starts.
    shift[0]+=floor['next_at']-time.time()+1
    worker.investigate_one();worker.investigate_one()
    assert len(provider.sent)==3
    assert verdict('subject-host-b')=='low'


def test_unthrottled_keeps_server_pause_and_global_disable(admin,monkeypatch,ssh):
    configure();add_subject('host-a');add_subject('host-b')
    assert set_pause(admin,'host-a',True).status_code==200
    provider=Provider();monkeypatch.setattr(ai.transport,'post',provider)
    for _ in range(3):worker.investigate_one()
    # The paused server's subject is not claimed or sent, and opens no run.
    assert provider.hosts()==['host-b']
    assert verdict('subject-host-a')=='pending'
    with Session() as s:
        assert not list(s.scalars(select(ai_runs.AIRun).where(ai_runs.AIRun.host_id=='host-a')))
    # Global disable stops every server, including an unpaused one with new work.
    configure(ai_enabled=False);add_subject('host-b','subject-b2')
    assert set_pause(admin,'host-a',False).status_code==200
    for _ in range(3):worker.investigate_one()
    assert len(provider.sent)==1
    assert verdict('subject-host-a')=='pending' and verdict('subject-b2')=='pending'
    # Re-enabling resumes both without any pacing wait or reservation.
    configure(ai_enabled=True)
    worker.investigate_one();worker.investigate_one()
    assert sorted(provider.hosts())==['host-a','host-b','host-b']
    assert verdict('subject-host-a')=='low' and verdict('subject-b2')=='low'
    assert ledger_count()==0
