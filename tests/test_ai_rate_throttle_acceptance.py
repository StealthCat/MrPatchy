"""Roadmap A milestone 4: Rate throttle paces smoothly, defers durably and resumes without a charged attempt (#1021).

Roadmap A replaces burst-then-stop hourly allowances with a smooth configurable
Rate throttle. Deferral must be durable and its next eligibility visible, and
deferred work must resume at refill without charging a failed attempt. The rate is
shared by every billable path. These tests drive the real worker path
(``worker.investigate_one``: claim -> admission -> provider -> acceptance), the
administrator start-gates status route and the administrator connection-test
route in ``rate`` and ``rate_and_daily`` modes. Only the provider transport, SSH
and the wall clock are fixtures.

Unit coverage of the admission row itself is in ``tests/test_ai_admission.py``.
The Unthrottled control comparison is in ``tests/test_ai_unthrottled_acceptance.py`` (#1018).
"""
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from sqlalchemy import func, select

from app import ai, ai_admission, ai_budget, ai_retry, ai_runs, update_scores, worker
from app.db import Behavior, Host, Package, Session, Setting
from app.security import seal
from tests.test_ai_scoring_deferral import success as scored_response

PRICED='gpt-6-astra'
RATE=6
INTERVAL=3600.0/RATE
EVIDENCE={'executable':'/srv/fixture','sha256':'a'*64,'uid':'1000','identity_verified':True}
USAGE={'input_tokens':1000,'output_tokens':200,'total_tokens':1200,
       'input_tokens_details':{'cached_tokens':0,'cache_write_tokens':0},
       'output_tokens_details':{'reasoning_tokens':100}}
MODES=('rate','rate_and_daily')


@pytest.fixture
def clock(monkeypatch):
    """Real wall clock plus a test-controlled offset, so leases and windows stay coherent."""
    real=time.time;offset=[0.0]
    monkeypatch.setattr(time,'time',lambda:real()+offset[0])
    class Clock:
        def advance(self,seconds):offset[0]+=seconds
    return Clock()


def configure(mode,**changes):
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':PRICED,'ai_control_mode':mode,
            'ai_rate_per_hour':RATE,'ai_daily_cap_usd':50.0,'ai_budget_timezone':'UTC',
            'ai_updates_enabled':False,**changes}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        s.commit()


def add_subject(host,subject=None):
    subject=subject or 'subject-'+host
    with Session() as s:
        if not s.get(Host,host):s.add(Host(id=host,name=host,address='192.0.2.1',fingerprint=''))
        s.add(Behavior(id=subject,host_id=host,evidence=dict(EVIDENCE)))
        s.commit()
    return subject


class Provider:
    """Records the AI run of each transmission and answers with a low-risk verdict."""
    def __init__(self):self.sent=[]
    def purposes(self):
        with Session() as s:return [s.get(ai_runs.AIRun,run).purpose for run in self.sent]
    def __call__(self,*args,**kwargs):
        request=httpx.Request('POST',ai.URL)
        self.sent.append(ai_runs.active.get())
        data={'risk':'low','explanation':'Advisory fixture','recommended_checks':'Review limitations','requested_checks':[]}
        body={'model':PRICED,'service_tier':'default','status':'completed','usage':USAGE,
              'output':[{'content':[{'type':'output_text','text':json.dumps(data)}]}]}
        return httpx.Response(200,json=body,request=request)


@pytest.fixture
def provider(monkeypatch):
    sent=Provider();monkeypatch.setattr(ai.transport,'post',sent)
    monkeypatch.setattr(worker.ssh,'call',lambda host,request,**kwargs:{'identity_verified':True,'sha256':'a'*64})
    return sent


def verdicts(*subjects):
    with Session() as s:return [s.get(Behavior,subject).verdict for subject in subjects]


def counts():
    """Durable side effects: (triage runs by state, retry rows, unreleased ledger entries)."""
    with Session() as s:
        runs=dict(s.execute(select(ai_runs.AIRun.state,func.count()).where(
            ai_runs.AIRun.purpose=='triage').group_by(ai_runs.AIRun.state)).all())
        retries=s.scalar(select(func.count()).select_from(ai_retry.TriageRetry))
        ledger=s.scalar(select(func.count()).select_from(ai_budget.BudgetEntry).where(
            ai_budget.BudgetEntry.status!='released'))
    return runs,retries,ledger


def ledger_statuses():
    with Session() as s:return sorted(s.scalars(select(ai_budget.BudgetEntry.status)))


def admitted_next_at():
    with Session() as s:return s.get(ai_admission.Admission,'global').next_at


def gates(client):
    response=client.get('/api/settings/ai-control-status')
    assert response.status_code==200
    return response.json()


def rate_gate(snapshot):
    return [item for item in snapshot['blockers'] if item['code']=='rate_throttle']


def drain(times=4):
    for _ in range(times):worker.investigate_one()


@pytest.mark.parametrize('mode',MODES)
def test_rate_throttle_paces_one_start_per_interval_with_visible_next_eligibility(admin,clock,provider,mode):
    configure(mode)
    subjects=[add_subject(host) for host in ('host-a','host-b','host-c')]

    # Three eligible servers, repeated worker passes: exactly one start.
    started=time.time();drain()
    assert len(provider.sent)==1
    assert sorted(verdicts(*subjects))==['low','pending','pending']
    next_at=admitted_next_at()
    assert next_at==pytest.approx(started+INTERVAL,abs=5)

    # Waiting work stays queued: no failed or deferred run, no retry attempt and
    # no spend reservation was created for the subjects that did not start.
    runs,retries,ledger=counts()
    assert runs=={'complete':1} and retries==0
    assert ledger==(1 if mode=='rate_and_daily' else 0)

    # The administrator status names the throttle and the exact next start.
    snapshot=gates(admin)
    assert snapshot['mode']==mode and snapshot['can_start_now'] is False
    assert [item['next_at'] for item in rate_gate(snapshot)]==[pytest.approx(next_at)]
    assert snapshot['next_start_at']==pytest.approx(next_at)

    # Just before the interval nothing starts; at the interval exactly one more does.
    clock.advance(next_at-time.time()-5);drain()
    assert len(provider.sent)==1 and admitted_next_at()==next_at
    clock.advance(10);drain()
    assert len(provider.sent)==2
    assert sorted(verdicts(*subjects))==['low','low','pending']
    assert admitted_next_at()>next_at

    # Starts are spread across servers, not taken twice from one host.
    with Session() as s:
        hosts={s.get(ai_runs.AIRun,run).host_id for run in provider.sent}
    assert len(hosts)==2

    # At the last refill the throttle gate clears and the remaining subject starts.
    clock.advance(INTERVAL+1)
    assert rate_gate(gates(admin))==[] and gates(admin)['can_start_now'] is True
    drain()
    assert len(provider.sent)==3 and verdicts(*subjects)==['low']*3
    runs,retries,ledger=counts()
    assert runs=={'complete':3} and retries==0
    assert ledger==(3 if mode=='rate_and_daily' else 0)


@pytest.mark.parametrize('mode',MODES)
def test_rate_throttle_does_not_accumulate_a_burst_after_idle_time(admin,clock,provider,mode):
    configure(mode)
    add_subject('host-a');drain()
    assert len(provider.sent)==1

    # Five idle hours would be thirty starts of saved-up hourly allowance.
    clock.advance(5*3600)
    subjects=[add_subject(host) for host in ('host-b','host-c','host-d','host-e')]
    started=time.time();drain(6)
    assert len(provider.sent)==2
    assert sorted(verdicts(*subjects))==['low','pending','pending','pending']
    assert admitted_next_at()==pytest.approx(started+INTERVAL,abs=5)
    assert counts()[1]==0


@pytest.mark.parametrize('mode',MODES)
def test_a_start_lost_to_another_caller_after_the_claim_is_durable_uncharged_and_resumes(admin,clock,provider,monkeypatch,mode):
    """The claim's read-only gate is open, but another billable caller takes the slot
    before this subject's provider admission. The refusal is queued work, not a
    failed attempt, and the subject resumes at the next refill."""
    configure(mode)
    subject=add_subject('host-a')
    real_waiting=ai_admission.waiting;raced=[]
    def waiting(session,now,**kwargs):
        result=real_waiting(session,now,**kwargs)
        if not raced:
            # Another worker or billable path is admitted between the claim's read and this call's admission.
            raced.append(ai_admission.admit('other-caller'))
        return result
    monkeypatch.setattr(ai_admission,'waiting',waiting)
    worker.investigate_one()
    monkeypatch.setattr(ai_admission,'waiting',real_waiting)

    assert raced and provider.sent==[]
    taken=admitted_next_at()
    with Session() as s:
        retry=s.get(ai_retry.TriageRetry,subject)
        assert retry.state=='deferred' and retry.attempts==0
        assert retry.next_at==pytest.approx(taken,abs=1)
        assert 'shared AI rate eligibility' in retry.reason
        run=s.scalars(select(ai_runs.AIRun).where(ai_runs.AIRun.subject==subject)).one()
        assert run.state=='deferred'
        assert s.get(ai_admission.Admission,'global').admitted==1
        counted=ai_budget.status(s,time.time())
    # Under a daily cap the pre-admission reservation is released, not retained as spend.
    assert ledger_statuses()==(['released'] if mode=='rate_and_daily' else [])
    if mode=='rate_and_daily':assert float(counted['counted_usd'])==0 and float(counted['reserved_usd'])==0

    # Still deferred until the refill; the snapshot shows that start time.
    drain()
    assert provider.sent==[]
    assert [item['next_at'] for item in rate_gate(gates(admin))]==[pytest.approx(taken)]

    clock.advance(taken-time.time()+1);drain()
    assert len(provider.sent)==1 and verdicts(subject)==['low']
    with Session() as s:
        assert s.get(ai_retry.TriageRetry,subject) is None
        states=sorted(run.state for run in s.scalars(select(ai_runs.AIRun).where(ai_runs.AIRun.subject==subject)))
        assert states==['complete','deferred']
    assert counts()[2]==(1 if mode=='rate_and_daily' else 0)


@pytest.mark.parametrize('mode',MODES)
def test_connection_tests_and_triage_share_one_rate_slot(admin,clock,provider,mode):
    configure(mode)
    subject=add_subject('host-a')

    # An administrator connection test takes the slot, so triage waits for it.
    assert admin.post('/api/settings/ai-test').status_code==200
    assert provider.purposes()==['connection_test']
    drain()
    assert len(provider.sent)==1 and verdicts(subject)==['pending'] and counts()[1]==0
    assert len(rate_gate(gates(admin)))==1

    # After the refill triage takes the slot, and the next connection test is
    # refused before transport with the shared-throttle reason.
    clock.advance(INTERVAL+1);drain()
    assert provider.purposes()==['connection_test','triage'] and verdicts(subject)==['low']
    refused=admin.post('/api/settings/ai-test')
    assert refused.status_code==502
    assert 'Shared AI rate throttle' in refused.json()['detail']
    assert len(provider.sent)==2
    with Session() as s:
        assert s.get(ai_admission.Admission,'global').admitted==2


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('winner', ['triage', 'update_scoring'])
def test_scoring_and_triage_contend_for_one_shared_slot(admin, clock, provider, monkeypatch, mode, winner):
    configure(mode, ai_updates_enabled=True)
    subject = add_subject('triage-host')
    with Session() as session:
        session.add(Host(id='score-host', name='Score host', address='192.0.2.2', fingerprint='',
                         state='online', inventory={'os': 'ID=debian'}))
        session.add(Package(id='score-host:fixture', host_id='score-host', name='fixture',
                            installed='1', candidate='2', available_since=time.time() - 30))
        session.commit()

    def post(*args, **kwargs):
        schema = kwargs['json']['text']['format']['name']
        if schema != 'update_importance':
            return provider(*args, **kwargs)
        provider.sent.append(ai_runs.active.get())
        response = scored_response(*args, **kwargs)
        return httpx.Response(200, request=response.request, json={
            **response.json(), 'model': PRICED, 'service_tier': 'default', 'usage': USAGE,
        })

    monkeypatch.setattr(ai.transport, 'post', post)
    real_admit = ai_admission.admit
    arrived = threading.Barrier(2)
    winner_admitted = threading.Event()

    def contend(model):
        with Session() as session:
            purpose = session.get(ai_runs.AIRun, ai_runs.active.get()).purpose
        # Both real paths are past their own preflight. Select which reaches the
        # shared gate first so both deferral paths are tested deterministically.
        arrived.wait(timeout=15)
        if purpose == winner:
            try:
                return real_admit(model)
            finally:
                winner_admitted.set()
        assert winner_admitted.wait(timeout=15)
        return real_admit(model)

    dispatch = {'triage': worker.investigate_one, 'update_scoring': update_scores.run_one}
    with monkeypatch.context() as collision:
        collision.setattr(ai_admission, 'admit', contend)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(run) for run in dispatch.values()]
            for future in futures:
                future.result(timeout=30)

    loser = next(purpose for purpose in dispatch if purpose != winner)
    assert provider.purposes() == [winner]
    with Session() as session:
        admission = session.get(ai_admission.Admission, 'global')
        assert admission.admitted == 1
        refill = admission.next_at
        runs = {run.purpose: run for run in session.scalars(select(ai_runs.AIRun))}
        assert runs[winner].state == 'complete' and runs[winner].calls == 1
        assert runs[loser].state == 'deferred' and runs[loser].calls == 0
        if loser == 'triage':
            retry = session.get(ai_retry.TriageRetry, subject)
            assert retry.state == 'deferred' and retry.attempts == 0
            assert retry.next_at == pytest.approx(refill, abs=1)
        else:
            score = session.scalars(select(update_scores.UpdateScore)).one()
            assert score.state == 'deferred' and score.score is None
            assert score.next_at == pytest.approx(refill, abs=1)
    assert ledger_statuses() == (['released', 'settled'] if mode == 'rate_and_daily' else [])

    dispatch[loser]()
    assert provider.purposes() == [winner]
    clock.advance(refill - time.time() + 2)
    dispatch[loser]()
    assert provider.purposes() == [winner, loser]
    assert verdicts(subject) == ['low']
    with Session() as session:
        assert session.get(ai_admission.Admission, 'global').admitted == 2
        assert session.get(ai_retry.TriageRetry, subject) is None
        score = session.scalars(select(update_scores.UpdateScore)).one()
        assert (score.state, score.score, score.installed, score.candidate) == ('complete', 50, '1', '2')
    assert ledger_statuses() == (['released', 'settled', 'settled'] if mode == 'rate_and_daily' else [])
