"""Roadmap A milestone 4: AI data-sharing controls under a daily spend cap (#1000).

These tests drive the real worker path (``worker.investigate_one``) and the real
update-scoring pass (``update_scores.run_one``) in ``daily_cap`` mode. Only the
provider transport and SSH are fixtures. They check that a cap neither widens nor
narrows what is sent, that refused evidence costs nothing, and that the scoring
opt-in decides whether package metadata is sent and charged.
"""
import json
import time
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_budget, ai_pricing, ai_retry, ai_runs, update_scores, worker
from app.db import Behavior, Host, Package, Session, Setting
from app.security import seal

MODEL='gpt-6-astra'
ADDRESS='203.0.113.77'
FINGERPRINT='SHA256:fixture-host-key'
CONNECTIONS=[{'remote':f'198.51.100.{i%250}:{1000+i}','state':'ESTABLISHED'} for i in range(ai.INVESTIGATION_CONNECTIONS+50)]
IDENTITY={'pid':4242,'start_ticks':99,'pid_namespace':'4026531836','boot_id':'b'*32,'proc_device':'0:5','proc_inode':'7'}
EVIDENCE={'executable':'/srv/fixture','sha256':'a'*64,'uid':'1000','identity_verified':True,
          'connections':CONNECTIONS,'process_identity':IDENTITY}
USAGE={'input_tokens':1000,'output_tokens':200,'total_tokens':1200,
       'input_tokens_details':{'cached_tokens':0,'cache_write_tokens':0},
       'output_tokens_details':{'reasoning_tokens':100}}


def configure(**changes):
    with Session() as s:
        row=s.get(Setting,'config')
        base=row.value if row else {'ai_enabled':True,'ai_model':MODEL,'ai_control_mode':'daily_cap',
            'ai_daily_cap_usd':5.0,'ai_budget_timezone':'UTC','ai_updates_enabled':False}
        s.merge(Setting(key='config',value={**base,**changes}))
        if not s.get(Setting,'openai_key'):s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        s.commit()


def add_host(host,evidence=EVIDENCE,package=False):
    with Session() as s:
        s.add(Host(id=host,name=host,address=ADDRESS,fingerprint=FINGERPRINT,state='online',
                   inventory={'os':'ID=debian\nVERSION_ID=12'}))
        s.add(Behavior(id='subject-'+host,host_id=host,evidence=json.loads(json.dumps(evidence))))
        if package:
            s.add(Package(id=host+':fixture-pkg',host_id=host,name='fixture-pkg',installed='1',candidate='2',
                          available_since=time.time()-3600))
        s.commit()


class Provider:
    """Records every transmitted request body and answers by request kind."""
    def __init__(self):self.bodies=[]
    def kinds(self):return [body['text']['format']['name'] for body in self.bodies]
    def __call__(self,*args,**kwargs):
        body=kwargs['json'];self.bodies.append(body)
        if body['text']['format']['name']=='update_importance':
            data={'assessments':[{'id':item['id'],'score':40,'confidence':'low','explanation':'Fixture score.',
                                  'limitations':'No advisory evidence.'} for item in json.loads(body['input'])]}
        else:
            data={'risk':'low','explanation':'Advisory fixture','recommended_checks':'Review limitations','requested_checks':[]}
        response={'model':MODEL,'service_tier':'default','status':'completed','usage':USAGE,
                  'output':[{'content':[{'type':'output_text','text':json.dumps(data)}]}]}
        return httpx.Response(200,json=response,request=httpx.Request('POST',ai.URL))


@pytest.fixture
def ssh(monkeypatch):
    calls=[]
    def call(host,request,**kwargs):
        calls.append(host.id)
        return {'identity_verified':True,'sha256':'a'*64}
    monkeypatch.setattr(worker.ssh,'call',call)
    return calls


def ledger(s):
    return list(s.scalars(select(ai_budget.BudgetEntry).order_by(ai_budget.BudgetEntry.created)))


def purpose(s,entry):
    return s.get(ai_runs.AIRun,entry.run_id).purpose


def test_capped_investigation_sends_the_same_bounded_request_as_unthrottled_and_reserves_on_it(admin,monkeypatch,ssh):
    configure();add_host('host-capped')
    provider=Provider();monkeypatch.setattr(ai.transport,'post',provider)
    worker.investigate_one()
    assert provider.kinds()==['process_investigation']
    capped=provider.bodies[0];sent=json.loads(capped['input'])
    # Bounded and stripped exactly as the sharing contract states, with the cap active.
    assert capped['store'] is False
    assert 'process_identity' not in sent
    assert len(sent['connections'])==ai.INVESTIGATION_CONNECTIONS and sent['omitted_connections']==50
    assert ADDRESS not in capped['input'] and FINGERPRINT not in capped['input']
    with Session() as s:
        rows=ledger(s);assert [(purpose(s,r),r.status) for r in rows]==[('triage','settled')]
        # The reservation was quoted from the same bounded request that was transmitted.
        assert rows[0].reservation_usd==Decimal(str(ai_pricing.reservation(capped)['amount_usd']))
        # The process identity is retained locally for follow-up selection, not shared.
        assert s.get(Behavior,'subject-host-capped').evidence['process_identity']==IDENTITY
    # The same evidence under unthrottled mode sends an identical request:
    # the cap neither widens nor narrows what is shared.
    configure(ai_control_mode='unthrottled');add_host('host-free')
    worker.investigate_one()
    assert provider.kinds()==['process_investigation']*2
    free=provider.bodies[1]
    assert {k:v for k,v in free.items()}=={k:v for k,v in capped.items()}
    with Session() as s:assert len(ledger(s))==1


@pytest.mark.parametrize('mode',['daily_cap','rate_and_daily','unthrottled'])
def test_evidence_over_the_sharing_limit_costs_nothing_and_does_not_stall_other_hosts(admin,monkeypatch,ssh,mode):
    # #1001: in capped modes the claim-time quote refused the oldest subject and
    # left it pending, so no other subject in the fleet was ever claimed.
    configure(ai_control_mode=mode)
    add_host('host-big',evidence={**EVIDENCE,'service':'x'*(ai.INVESTIGATION_BYTES+1000)})
    time.sleep(0.01);add_host('host-ok')
    provider=Provider();monkeypatch.setattr(ai.transport,'post',provider)
    for _ in range(3):worker.investigate_one()
    # The oversized evidence was never transmitted; the other host was triaged.
    assert provider.kinds()==['process_investigation']
    assert 'x'*1000 not in provider.bodies[0]['input']
    with Session() as s:
        assert s.get(Behavior,'subject-host-ok').verdict=='low'
        big=s.get(Behavior,'subject-host-big')
        assert big.verdict=='error' and '64 KB' in big.analysis and not big.approved
        retry=s.get(ai_retry.TriageRetry,'subject-host-big')
        assert retry.state=='blocked' and retry.next_at==0
        # Only the admitted call reserved spend; the refused subject reserved nothing.
        rows=ledger(s)
        assert all(s.get(ai_runs.AIRun,r.run_id).host_id=='host-ok' for r in rows)
        assert len(rows)==(0 if mode=='unthrottled' else 1)
    # A blocked subject stays out of the queue until reviewed: later passes send nothing.
    worker.investigate_one()
    assert len(provider.bodies)==1


def test_update_scoring_opt_in_decides_whether_package_metadata_is_sent_and_charged(admin,monkeypatch,ssh):
    configure(ai_updates_enabled=False);add_host('host-pkg',package=True)
    provider=Provider();monkeypatch.setattr(ai.transport,'post',provider)
    # Opted out: scoring sends nothing, reserves nothing and records no score row.
    update_scores.run_one()
    assert provider.bodies==[]
    with Session() as s:
        assert ledger(s)==[] and s.scalar(select(update_scores.UpdateScore)) is None
    # Investigations are still admitted under the same cap, and carry no package metadata.
    worker.investigate_one()
    assert provider.kinds()==['process_investigation']
    assert 'fixture-pkg' not in provider.bodies[0]['input']
    with Session() as s:assert [(purpose(s,r),r.status) for r in ledger(s)]==[('triage','settled')]
    # Opted in: the scoring batch reserves its own spend and shares only package metadata.
    configure(ai_updates_enabled=True)
    update_scores.run_one()
    assert provider.kinds()==['process_investigation','update_importance']
    scoring=provider.bodies[1];items=json.loads(scoring['input'])
    assert scoring['store'] is False and [item['package'] for item in items]==['fixture-pkg']
    for leaked in (ADDRESS,FINGERPRINT,'/srv/fixture','a'*64,'process_identity','connections'):
        assert leaked not in scoring['input']
    with Session() as s:
        rows=ledger(s)
        assert [(purpose(s,r),r.status) for r in rows]==[('triage','settled'),('update_scoring','settled')]
        assert rows[1].reservation_usd==Decimal(str(ai_pricing.reservation(scoring)['amount_usd']))
        assert s.scalar(select(update_scores.UpdateScore)).state=='complete'
