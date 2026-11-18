"""Roadmap A milestone 4: stale and replayed triage results under a daily spend cap (#1005).

These tests drive the real worker path (``worker.investigate_one``) in ``daily_cap``
mode. Only the provider transport and SSH are fixtures. While the provider call is
in flight, a fixture changes the subject's evidence, approval or AI key, or takes
over its lease. The late answer must never be accepted, yet the money the sent call
cost must still count against today's cap.
"""
import json
import time
import uuid
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_assessments, ai_budget, ai_claims, ai_retry, ai_runs, worker
from app.db import Behavior, Host, Session, Setting
from app.security import seal

MODEL='gpt-6-astra'
EVIDENCE={'executable':'/srv/fixture','sha256':'a'*64,'uid':'1000','identity_verified':True}
USAGE={'input_tokens':1000,'output_tokens':200,'total_tokens':1200,
       'input_tokens_details':{'cached_tokens':0,'cache_write_tokens':0},
       'output_tokens_details':{'reasoning_tokens':100}}
SUBJECT='subject-host-a'


def configure(**changes):
    with Session() as s:
        row=s.get(Setting,'config')
        base=row.value if row else {'ai_enabled':True,'ai_model':MODEL,'ai_control_mode':'daily_cap',
            'ai_daily_cap_usd':5.0,'ai_budget_timezone':'UTC','ai_updates_enabled':False}
        s.merge(Setting(key='config',value={**base,**changes}))
        if not s.get(Setting,'openai_key'):s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        s.commit()


def add_host(host='host-a'):
    with Session() as s:
        s.add(Host(id=host,name=host,address='203.0.113.5',fingerprint='SHA256:fixture',state='online',
                   inventory={'os':'ID=debian\nVERSION_ID=12'}))
        s.add(Behavior(id='subject-'+host,host_id=host,evidence=json.loads(json.dumps(EVIDENCE))))
        s.commit()


class Provider:
    """Answers every investigation 'low'; runs ``during`` inside the first call only."""
    def __init__(self,during=None):self.bodies=[];self.during=during
    def __call__(self,*args,**kwargs):
        body=kwargs['json'];self.bodies.append(body)
        if self.during and len(self.bodies)==1:self.during()
        data={'risk':'low','explanation':'Advisory fixture','recommended_checks':'Review limitations','requested_checks':[]}
        response={'model':MODEL,'service_tier':'default','status':'completed','usage':USAGE,
                  'output':[{'content':[{'type':'output_text','text':json.dumps(data)}]}]}
        return httpx.Response(200,json=response,request=httpx.Request('POST',ai.URL))
    def evidence(self,index):return json.loads(self.bodies[index]['input'])


@pytest.fixture
def ssh(monkeypatch):
    calls=[]
    def call(host,request,**kwargs):
        calls.append(host.id);return {'identity_verified':True,'sha256':'a'*64}
    monkeypatch.setattr(worker.ssh,'call',call)
    return calls


def ledger(s):
    return list(s.scalars(select(ai_budget.BudgetEntry).order_by(ai_budget.BudgetEntry.created)))


def assessments(s):
    return list(s.scalars(select(ai_assessments.Assessment).where(ai_assessments.Assessment.subject==SUBJECT)))


def runs(s):
    return list(s.scalars(select(ai_runs.AIRun).where(ai_runs.AIRun.subject==SUBJECT).order_by(ai_runs.AIRun.started)))


def counted(s,at=None):
    # Read at a ledger row's own time so a real-clock run across the UTC
    # reset cannot move the window between a charge and its check.
    return ai_budget.status(s,at)['counted_usd']


def assert_rejected_but_charged(s):
    """The late answer left no result, and its receipt still counts against the cap."""
    row=s.get(Behavior,SUBJECT)
    assert row.verdict=='pending' and 'Advisory fixture' not in (row.analysis or '')
    assert assessments(s)==[]
    first=runs(s)[0]
    assert first.state=='error' and 'no stale result was accepted' in first.message,(first.state,first.message)
    entry=[e for e in ledger(s) if e.run_id==first.id]
    assert [e.status for e in entry]==['settled']
    # The sent call is charged at its receipt, never released back to the cap.
    assert entry[0].actual_usd is not None and entry[0].actual_usd>0
    assert Decimal(str(counted(s,entry[0].created)))>=entry[0].actual_usd
    assert s.get(ai_claims.Claim,SUBJECT) is None or s.get(ai_claims.Claim,SUBJECT).run_id!=first.id


def recovery_interval_passes():
    """Stand in for the one-hour interrupted-attempt recovery interval elapsing."""
    with Session() as s:
        retry=s.get(ai_retry.TriageRetry,SUBJECT)
        assert retry.state=='interrupted' and retry.next_at>time.time()+3000
        retry.next_at=time.time()-1;s.commit()


def test_unchanged_subject_is_accepted_with_one_settled_charge(admin,monkeypatch,ssh):
    configure();add_host()
    provider=Provider();monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    assert len(provider.bodies)==1
    with Session() as s:
        assert s.get(Behavior,SUBJECT).verdict=='low'
        assert len(assessments(s))==1
        assert [e.status for e in ledger(s)]==['settled']
        assert [r.state for r in runs(s)]==['complete']


def test_evidence_change_in_flight_is_rejected_charged_and_retriaged_on_the_new_evidence(admin,monkeypatch,ssh):
    configure();add_host()
    def change():
        with Session() as s:
            row=s.get(Behavior,SUBJECT);row.evidence={**row.evidence,'sha256':'b'*64};s.commit()
    provider=Provider(change);monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    assert len(provider.bodies)==1
    with Session() as s:
        assert_rejected_but_charged(s)
    # A subject whose evidence keeps changing cannot re-bill in a loop: it waits
    # the interrupted-attempt recovery interval before another paid call.
    for _ in range(3):worker.investigate_one()
    assert len(provider.bodies)==1
    recovery_interval_passes()
    # The next eligible pass sends a new, separately reserved request bound to
    # the new evidence, and only that answer is accepted.
    worker.investigate_one()
    assert len(provider.bodies)==2
    assert provider.evidence(0)['sha256']=='a'*64 and provider.evidence(1)['sha256']=='b'*64
    with Session() as s:
        rows=ledger(s);assert [e.status for e in rows]==['settled','settled']
        assert rows[0].run_id!=rows[1].run_id
        assert all(e.actual_usd is not None and e.actual_usd>0 for e in rows)
        assert s.get(Behavior,SUBJECT).verdict=='low'
        saved=assessments(s);assert len(saved)==1 and saved[0].run_id==rows[1].run_id
        assert [r.state for r in runs(s)]==['error','complete']


def test_approval_in_flight_is_rejected_charged_and_never_retriaged(admin,monkeypatch,ssh):
    configure();add_host()
    def approve():
        with Session() as s:revision=ai_assessments.revision(s.get(Behavior,SUBJECT))
        response=admin.put('/api/investigations/'+SUBJECT,json={'approved':True,'expected_revision':revision})
        assert response.status_code==200,response.text
    provider=Provider(approve);monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    with Session() as s:
        assert s.get(Behavior,SUBJECT).approved is True
        assert_rejected_but_charged(s)
        charge=ledger(s)[0]
    for _ in range(3):worker.investigate_one()
    assert len(provider.bodies)==1
    with Session() as s:
        assert [(e.id,e.status,e.actual_usd) for e in ledger(s)]==[(charge.id,'settled',charge.actual_usd)]


def test_key_rotation_in_flight_is_rejected_and_charged(admin,monkeypatch,ssh):
    configure();add_host()
    def rotate():
        with Session() as s:s.merge(Setting(key='openai_key',value={'encrypted':seal('rotated-key')}));s.commit()
    provider=Provider(rotate);monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    with Session() as s:assert_rejected_but_charged(s)
    worker.investigate_one();assert len(provider.bodies)==1
    # After the recovery interval, the rotated key gets a fresh, separately charged investigation.
    recovery_interval_passes()
    worker.investigate_one()
    assert len(provider.bodies)==2
    with Session() as s:
        assert [e.status for e in ledger(s)]==['settled','settled']
        assert s.get(Behavior,SUBJECT).verdict=='low'


@pytest.mark.parametrize('takeover',['new_owner','expired'])
def test_replayed_answer_after_lease_takeover_writes_nothing_and_is_charged(admin,monkeypatch,ssh,takeover):
    configure();add_host()
    state={}
    def take():
        with Session() as s:
            claim=s.get(ai_claims.Claim,SUBJECT)
            if takeover=='new_owner':
                # Another worker re-claimed the subject after this lease expired.
                state['token']=claim.token=str(uuid.uuid4());claim.run_id=state['run']=str(uuid.uuid4())
            else:claim.expires=0
            s.commit()
    provider=Provider(take);monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    assert len(provider.bodies)==1
    with Session() as s:
        assert_rejected_but_charged(s)
        claim=s.get(ai_claims.Claim,SUBJECT)
        if takeover=='new_owner':
            # The stale worker must not release the new owner's lease.
            assert claim is not None and claim.token==state['token'] and claim.run_id==state['run']
        else:assert claim is None
