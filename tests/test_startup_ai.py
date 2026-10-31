import json
import math
import pytest
from app import startup_ai,incidents,worker,ai
from app.db import Session,Setting,Job,config
from app.security import seal
from app.identity import User
from test_persistence_baseline import setup_host,payload,URL
from test_persistence_monitoring import enable,receipt,BASE
from test_persistence_comparison import inventory


def setup_incident(admin):
    setup_host();assert admin.post(URL,json=payload(admin)).status_code==200;enable(admin)
    with Session() as s:
        incidents.record_inspection(s,'baseline-host','changed',receipt({**inventory(),'entries':[]}))
        cfg=config(s);cfg.update(ai_enabled=True,ai_model='test-model')
        s.merge(Setting(key='config',value=cfg));s.merge(Setting(key='openai_key',value={'encrypted':seal('fixture-key')}));s.commit()
        return s.query(incidents.PersistenceIncident).one().id


def response(identifier):
    return {'summary':'Review this startup change','severity':'unknown','uncertainty':'May be legitimate administration',
            'steps':[{'action':'preserve_evidence','reason':'Retain receipts','impact':'Storage','verification':'Compare metadata','evidence_ids':[identifier]}]}


def test_startup_plan_worker_usage_binding_and_manual_approval(admin,monkeypatch):
    identifier=setup_incident(admin);path=BASE+'/persistence-incidents/'+identifier
    calls=[]
    def request(payload,key):
        calls.append(payload)
        data=json.loads(payload['input']);assert len(payload['input'].encode())<=64000
        assert data['baseline_digest'] and data['current_observation']['state']=='drifted'
        assert payload['store'] is False and key=='fixture-key'
        return response(identifier)
    monkeypatch.setattr(ai,'request',request)
    row=admin.get(BASE+'/persistence-incidents').json()['items'][0]
    queued=admin.post(path+'/plan',json={'expected_updated':row['updated']});assert queued.status_code==200
    assert admin.post(path+'/plan',json={'expected_updated':row['updated']}).status_code==409
    with Session() as s:
        revision=s.get(Job,queued.json()['job_id']).payload['expected_updated']
        assert isinstance(revision,str) and float(revision)==row['updated']
    worker.execute(queued.json()['job_id'])
    with Session() as s:
        job=s.get(Job,queued.json()['job_id'])
        assert job.state=='complete',job.output
        plan=s.query(incidents.Plan).one();plan_id=plan.id;digest=plan.evidence_digest
        from app.ai_runs import AIRun
        assert s.get(AIRun,plan.run_id).purpose=='security_plan'
    assert len(calls)==1
    assert admin.post(path+'/plans/'+plan_id+'/approve',json={'evidence_digest':digest}).json()['execution']=='manual_only'
    with Session() as s:
        incidents.record_inspection(s,'baseline-host','gap',receipt({**inventory(),'state':'incomplete','gaps':['unreadable']}));s.commit()
    assert admin.get(BASE+'/persistence-incidents').json()['items'][0]['plans'][0]['state']=='stale'
    assert admin.post(path+'/plans/'+plan_id+'/approve',json={'evidence_digest':digest}).status_code==409


def test_changed_during_call_and_invalid_references_rejected(admin,monkeypatch):
    identifier=setup_incident(admin)
    with Session() as s:
        row=s.get(incidents.PersistenceIncident,identifier)
        monkeypatch.setattr(ai,'request',lambda *a:response('invented'))
        with pytest.raises(ValueError,match='Unknown plan evidence'):startup_ai.generate(s,row,row.updated)
        def changed(*a):
            with Session() as other:
                incident=other.get(incidents.PersistenceIncident,identifier);incident.updated+=1;other.commit()
            return response(identifier)
        monkeypatch.setattr(ai,'request',changed)
        with pytest.raises(ValueError,match='changed during'):startup_ai.generate(s,row,row.updated)
        assert s.query(incidents.Plan).count()==0


def test_shared_budget_roles_and_changed_job_prevent_provider_call(admin,monkeypatch):
    identifier=setup_incident(admin);path=BASE+'/persistence-incidents/'+identifier+'/plan'
    with Session() as s:
        row=s.get(incidents.PersistenceIncident,identifier);updated=row.updated
        cfg=s.get(Setting,'config');cfg.value={**cfg.value,'ai_control_mode':'legacy'}
        for n in range(10):s.add(Job(id='limit'+str(n),host_id='other',action='security-plan',state='complete'))
        s.commit()
    assert admin.post(path,json={'expected_updated':updated}).status_code==429
    monkeypatch.setattr(ai,'request',lambda *a:pytest.fail('No provider call'))
    with Session() as s:
        row=s.get(incidents.PersistenceIncident,identifier)
        with pytest.raises(ValueError,match='changed'):startup_ai.generate(s,row,math.nextafter(updated,math.inf))
        for role in ('viewer','operator'):
            s.get(User,'admin').role=role;s.commit()
            assert admin.post(path,json={'expected_updated':updated}).status_code==403
