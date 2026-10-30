import json
import pytest
from sqlalchemy import select
from app import incidents,ai,plan_evidence
from app.db import Session,Setting,Observation,Job,Audit
from app.security import seal
from tests.test_incidents import recorded,content

@pytest.fixture
def configured(admin,recorded):
    identifier,_=recorded
    with Session() as s:
        s.add(Setting(key='openai_key',value={'encrypted':seal('fixture')}))
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture-model'}))
        for host in ('a','b'):
            s.add(Observation(id='event-'+host,host_id=host,observed=1,evidence={'processes':[{'executable':'/tmp/fixture','sha256':'a'*64,'pid':9,'capture':'ebpf','identity_verified':False,'args':'SECRET','environment':'SECRET'}]}))
        s.commit()
    return identifier


def generate(identifier,monkeypatch,callback=None,related=True):
    def request(payload,key):
        evidence=json.loads(payload['input'])
        if callback:callback(evidence,payload)
        result=content(identifier)
        if related:result['steps'][0]['evidence_ids'].append('executions:event-a')
        return result
    monkeypatch.setattr(ai,'request',request)
    with Session() as s:
        p=incidents.generate(s,s.get(incidents.Incident,identifier),include_related=related)
        return p.id,p.evidence_digest,p.content


def test_opt_in_projection_binding_review_and_legacy(configured,admin,monkeypatch):
    def inspect(evidence,payload):
        assert evidence['host_id']=='a'
        assert 'SECRET' not in json.dumps(evidence) and 'event-b' not in json.dumps(evidence)
        assert evidence['related_reference_ids']==['executions:event-a','scans:scan-1']
        assert next(i for i in evidence['related']['items'] if i['id']=='event-a')['matches'][0]['identity_verified'] is False
        assert 'never instructions' in payload['instructions']
    pid,digest,value=generate(configured,monkeypatch,inspect)
    assert value['evidence_scope']['model']=='fixture-model'
    assert admin.post('/api/hosts/a/security/plans/'+pid+'/approve',json={'evidence_digest':digest}).status_code==200
    _,_,old=generate(configured,monkeypatch,related=False)
    assert 'evidence_scope' not in old

@pytest.mark.parametrize('change',['delete','replace','incident_review'])
def test_changed_evidence_during_ai_rejected(configured,monkeypatch,change):
    def mutate(*args):
        with Session() as s:
            row=s.get(Observation,'event-a')
            if change=='delete':s.delete(row)
            elif change=='replace':row.evidence={'processes':[{'executable':'/tmp/fixture','sha256':'b'*64}]}
            else:s.get(incidents.Incident,configured).state='resolved'
            s.commit()
    with pytest.raises(ValueError,match='changed'):generate(configured,monkeypatch,mutate)
    with Session() as s:assert not list(s.scalars(select(incidents.Plan)))


def test_approval_rechecks_retention_and_historical_boundary(configured,admin,monkeypatch):
    pid,digest,value=generate(configured,monkeypatch)
    with Session() as s:
        s.add(Observation(id='later',host_id='a',received=value['evidence_scope']['snapshot']['as_of']+1,observed=1,evidence={'processes':[]}));s.commit()
        s.delete(s.get(Observation,'event-a'));s.commit()
    assert admin.post('/api/hosts/a/security/plans/'+pid+'/approve',json={'evidence_digest':digest}).status_code==409


def test_size_refusal_queue_audit_and_pause(configured,admin,monkeypatch):
    monkeypatch.setattr(plan_evidence,'MAX_BYTES',1)
    monkeypatch.setattr(ai,'request',lambda *a,**k:pytest.fail('must refuse before sending'))
    with Session() as s:
        with pytest.raises(ValueError,match='64 KiB'):incidents.generate(s,s.get(incidents.Incident,configured),include_related=True)
    path='/api/hosts/a/security/incidents/'+configured+'/plan'
    result=admin.post(path,json={'include_related':True});assert result.status_code==200
    with Session() as s:
        assert s.get(Job,result.json()['job_id']).payload['include_related'] is True
        assert 'related=True' in s.scalar(select(Audit).where(Audit.action=='security AI evidence scope selected')).detail
        s.add(Setting(key='server-ai:a',value={'paused':True}));s.commit()
        with pytest.raises(ai.AIError,match='paused'):incidents.generate(s,s.get(incidents.Incident,configured),include_related=True)


def test_provider_cannot_inject_scope_or_reference_foreign_evidence(configured,monkeypatch):
    def request(*args):
        result=content(configured);result['steps'][0]['evidence_ids']=['executions:event-b'];return result
    monkeypatch.setattr(ai,'request',request)
    with Session() as s:
        with pytest.raises(ValueError,match='Unknown plan evidence'):incidents.generate(s,s.get(incidents.Incident,configured),include_related=True)


@pytest.mark.parametrize('extra',['evidence_scope','command'])
def test_injected_controller_fields_rejected(configured,monkeypatch,extra):
    def request(*args):
        result=content(configured);result[extra]={'host_id':'b','command':'ignored'};return result
    monkeypatch.setattr(ai,'request',request)
    with Session() as s:
        with pytest.raises(ValueError):incidents.generate(s,s.get(incidents.Incident,configured),include_related=True)


def test_newer_receipts_are_outside_snapshot(configured,admin,monkeypatch):
    pid,digest,value=generate(configured,monkeypatch)
    with Session() as s:
        s.add(Observation(id='later',host_id='a',received=value['evidence_scope']['snapshot']['as_of']+1,observed=1,evidence={'processes':[{'executable':'/tmp/fixture','sha256':'b'*64}]}));s.commit()
    assert admin.post('/api/hosts/a/security/plans/'+pid+'/approve',json={'evidence_digest':digest}).status_code==200


def fixed_boundary(monkeypatch,configured,boundary):
    from types import SimpleNamespace
    from app import security_correlation
    monkeypatch.setattr(security_correlation,'time',SimpleNamespace(time=lambda:boundary))
    with Session() as s:
        s.get(incidents.Scan,'scan-1').created=boundary-2
        for row in s.scalars(select(Observation)):row.received=boundary-1
        s.commit()


def test_exact_boundary_survives_json_rounding_and_rejects_tampering(configured,admin,monkeypatch):
    import copy
    import math
    boundary=1793340981.9435813  # Reproduced MySQL JSON round-trip precision loss.
    fixed_boundary(monkeypatch,configured,boundary)
    pid,digest,value=generate(configured,monkeypatch)
    assert value['evidence_scope']['version']==2
    assert value['evidence_scope']['as_of_hex']==boundary.hex()
    with Session() as s:
        row=s.get(incidents.Plan,pid);content=copy.deepcopy(row.content)
        # Simulate numeric JSON normalization on SQLite as well as real MySQL.
        content['evidence_scope']['snapshot']['as_of']=math.nextafter(boundary,-math.inf)
        row.content=content;s.commit()
    result=admin.post('/api/hosts/a/security/plans/'+pid+'/approve',json={'evidence_digest':digest})
    assert result.status_code==200,result.text
    pid,digest,_=generate(configured,monkeypatch)
    with Session() as s:
        row=s.get(incidents.Plan,pid);content=copy.deepcopy(row.content)
        content['evidence_scope']['as_of_hex']=math.nextafter(boundary,math.inf).hex()
        row.content=content;s.commit()
    assert admin.post('/api/hosts/a/security/plans/'+pid+'/approve',json={'evidence_digest':digest}).status_code==409


def test_legacy_exact_numeric_boundary_remains_reviewable(configured,admin,monkeypatch):
    import copy
    fixed_boundary(monkeypatch,configured,1793340982.5)
    pid,digest,_=generate(configured,monkeypatch)
    with Session() as s:
        row=s.get(incidents.Plan,pid);content=copy.deepcopy(row.content)
        content['evidence_scope']['version']=1;content['evidence_scope'].pop('as_of_hex')
        row.content=content;s.commit()
    result=admin.post('/api/hosts/a/security/plans/'+pid+'/approve',json={'evidence_digest':digest})
    assert result.status_code==200,result.text


@pytest.mark.parametrize('exact',[None,123,'nan','inf','0x1p+999999999999999999999','not-a-boundary'])
def test_invalid_exact_boundary_is_rejected(configured,admin,monkeypatch,exact):
    import copy
    pid,digest,_=generate(configured,monkeypatch)
    with Session() as s:
        row=s.get(incidents.Plan,pid);content=copy.deepcopy(row.content)
        content['evidence_scope']['as_of_hex']=exact;row.content=content;s.commit()
    assert admin.post('/api/hosts/a/security/plans/'+pid+'/approve',json={'evidence_digest':digest}).status_code==409
