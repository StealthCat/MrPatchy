"""Roadmap A milestone 4: representative triage outcomes under a daily spend cap (#1013).

These tests drive the real worker path (``worker.investigate_one``) in ``daily_cap``
mode. Only the provider transport and SSH are fixtures. Each verdict must be stored
and charged exactly as it would be without a cap, and the cap must not change any
evidence check, structured validation or response gate: no verdict approves the
subject or creates a job, incident or response plan, and only a complete low-risk
result can become a known-good candidate.
"""
import json
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import func, select

from app import (
    ai,
    ai_assessments,
    ai_budget,
    ai_runs,
    known_good,
    notifications,
    worker,
)
from app.db import Audit, Behavior, Host, Job, Session, Setting
from app.incidents import Incident, Plan
from app.security import seal

MODEL='gpt-6-astra'
SUBJECT='subject-host-a'
USAGE={'input_tokens':1000,'output_tokens':200,'total_tokens':1200,
       'input_tokens_details':{'cached_tokens':0,'cache_write_tokens':0},
       'output_tokens_details':{'reasoning_tokens':100}}


def evidence(**changes):
    return {'executable':'/srv/fixture','sha256':'a'*64,'uid':'1000','identity_verified':True,**changes}


def configure():
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':MODEL,'ai_control_mode':'daily_cap',
            'ai_daily_cap_usd':5.0,'ai_budget_timezone':'UTC','ai_updates_enabled':False}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        s.commit()


def add_host(observed=None):
    with Session() as s:
        s.add(Host(id='host-a',name='host-a',address='203.0.113.5',fingerprint='SHA256:fixture',state='online',
                   inventory={'os':'ID=debian\nVERSION_ID=12'}))
        s.add(Behavior(id=SUBJECT,host_id='host-a',evidence=observed or evidence()))
        s.commit()


class Provider:
    """Returns one scripted answer per call; the last answer repeats."""
    def __init__(self,*answers):self.answers=list(answers);self.bodies=[]
    def __call__(self,*args,**kwargs):
        self.bodies.append(kwargs['json'])
        answer=self.answers[min(len(self.bodies),len(self.answers))-1]
        response={'model':MODEL,'service_tier':'default','status':'completed','usage':USAGE,
                  'output':[{'content':[{'type':'output_text','text':json.dumps(answer)}]}]}
        return httpx.Response(200,json=response,request=httpx.Request('POST',ai.URL))
    def evidence(self,index):return json.loads(self.bodies[index]['input'])


def answer(risk,checks=()):
    return {'risk':risk,'explanation':'Fixture rated '+risk,'recommended_checks':'Review the evidence',
            'requested_checks':list(checks)}


@pytest.fixture
def ssh(monkeypatch):
    calls=[]
    def call(host,request,**kwargs):
        calls.append(request);return {'identity_verified':True,'sha256':'a'*64,'package':{'name':'fixture'}}
    monkeypatch.setattr(worker.ssh,'call',call)
    return calls


def ledger(s):
    return list(s.scalars(select(ai_budget.BudgetEntry).order_by(ai_budget.BudgetEntry.created)))


def assessments(s):
    return list(s.scalars(select(ai_assessments.Assessment).where(ai_assessments.Assessment.subject==SUBJECT)))


def runs(s):
    return list(s.scalars(select(ai_runs.AIRun).where(ai_runs.AIRun.subject==SUBJECT)))


def count(s,model):
    return s.scalar(select(func.count()).select_from(model))


def triage_notices(s):
    return list(s.scalars(select(notifications.NotificationRevision).join(
        notifications.NotificationEvent,
        notifications.NotificationEvent.id==notifications.NotificationRevision.event_id).where(
        notifications.NotificationEvent.subject_id==SUBJECT)))


def assert_settled_and_counted(s,calls):
    rows=ledger(s)
    assert [e.status for e in rows]==['settled']*calls,[(e.status,e.actual_usd) for e in rows]
    assert all(e.actual_usd is not None and e.actual_usd>0 for e in rows)
    # Read at the last row's own time so a run across the UTC reset cannot move the window.
    counted=Decimal(str(ai_budget.status(s,rows[-1].created)['counted_usd']))
    assert counted>=sum(e.actual_usd for e in rows)


def assert_no_response(s):
    """The verdict is advisory: nothing approves the subject or starts a response."""
    assert s.get(Behavior,SUBJECT).approved is False
    assert count(s,Job)==0 and count(s,Incident)==0 and count(s,Plan)==0
    assert not s.scalars(select(Audit).where(Audit.action.like('%approv%'))).first()


@pytest.mark.parametrize('risk',['low','medium','high','unknown'])
def test_each_verdict_is_stored_charged_once_and_authorizes_nothing(admin,monkeypatch,ssh,risk):
    configure();add_host()
    provider=Provider(answer(risk));monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    assert len(provider.bodies)==1 and ssh==[]
    with Session() as s:
        row=s.get(Behavior,SUBJECT)
        assert row.verdict==risk and 'Fixture rated '+risk in row.analysis
        saved=assessments(s);assert len(saved)==1 and saved[0].result['risk']==risk
        assert [r.state for r in runs(s)]==['complete']
        assert_settled_and_counted(s,1)
        assert ledger(s)[0].run_id==runs(s)[0].id==saved[0].run_id
        assert_no_response(s)
        notices=triage_notices(s)
        if risk in ('medium','high'):
            assert [(n.severity,n.lifecycle) for n in notices]==[(risk,'active')]
            assert 'authorize any response' in notices[0].reason
        else:assert notices==[]
        # Only a complete low-risk result may ever become a known-good candidate.
        status=known_good.assessment(saved[0])
        codes={reason['code'] for reason in status['reasons']}
        if risk!='low':
            assert status['eligible'] is False and 'result_not_safe' in codes
            assert count(s,known_good.Entry)==0
        else:assert 'result_not_safe' not in codes
    # A completed verdict is never re-sent or re-billed on later passes.
    for _ in range(3):worker.investigate_one()
    assert len(provider.bodies)==1
    with Session() as s:assert_settled_and_counted(s,1)


def test_follow_up_collects_verified_evidence_once_and_charges_both_calls(admin,monkeypatch,ssh):
    configure();add_host()
    provider=Provider(answer('unknown',['package','executable']),answer('medium'))
    monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    assert len(provider.bodies)==2
    assert len(ssh)==1 and ssh[0]['action']=='evidence' and ssh[0]['sha256']=='a'*64
    assert sorted(ssh[0]['checks'])==['executable','package']
    # The second call carries the collected evidence; the first did not.
    assert 'investigation' not in provider.evidence(0)
    assert provider.evidence(1)['investigation']['details']['package']=={'name':'fixture'}
    with Session() as s:
        assert s.get(Behavior,SUBJECT).verdict=='medium'
        saved=assessments(s);assert len(saved)==1 and saved[0].result['risk']=='medium'
        assert_settled_and_counted(s,2)
        assert len({e.run_id for e in ledger(s)})==1
        assert_no_response(s)
    for _ in range(3):worker.investigate_one()
    assert len(provider.bodies)==2 and len(ssh)==1


@pytest.mark.parametrize('observed',[evidence(identity_verified=False),evidence(sha256='')],
                         ids=['unverified-identity','missing-checksum'])
def test_unverified_subject_never_triggers_ssh_even_when_checks_are_requested(admin,monkeypatch,ssh,observed):
    configure();add_host(observed)
    provider=Provider(answer('unknown',['service']),answer('unknown'))
    monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    assert ssh==[] and len(provider.bodies)==2
    details=provider.evidence(1)['investigation']['details']
    assert details['identity_verified'] is False and 'no remote evidence request was sent' in details['reason']
    with Session() as s:
        assert s.get(Behavior,SUBJECT).verdict=='unknown'
        assert_settled_and_counted(s,2)
        assert_no_response(s)


@pytest.mark.parametrize('invalid',[
    {'risk':'safe','explanation':'x','recommended_checks':'y','requested_checks':[]},
    {'risk':'low','explanation':'x','recommended_checks':'y','requested_checks':['shell']},
],ids=['out-of-schema-risk','unsupported-check'])
def test_invalid_structured_answer_is_rejected_and_still_charged(admin,monkeypatch,ssh,invalid):
    configure();add_host()
    provider=Provider(invalid);monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    assert len(provider.bodies)==1 and ssh==[]
    with Session() as s:
        row=s.get(Behavior,SUBJECT)
        assert row.verdict=='error'
        assert 'no result was accepted' in row.analysis or 'no remote check was executed' in row.analysis
        assert 'Fixture' not in row.analysis
        assert assessments(s)==[] and count(s,known_good.Entry)==0
        assert [r.state for r in runs(s)]==['error']
        # The sent call cost money: it counts against the cap rather than being released.
        assert_settled_and_counted(s,1)
        assert_no_response(s)
        assert triage_notices(s)==[]
