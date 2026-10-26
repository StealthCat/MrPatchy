import copy
import time
import pytest
from sqlalchemy import select
from app import incidents,ai
from app.db import Session,Host,Setting
from app.security import seal
from app.identity import User

@pytest.fixture
def recorded(admin):
    with Session() as s:
        for host in ('a','b'):s.add(Host(id=host,name=host,address='192.0.2.1',fingerprint='test'))
        s.commit()
        report={'state':'completed_with_findings','findings':[{'path':'/tmp/fixture','sha256':'a'*64,'evidence':'fixture rule'}]}
        incidents.record(s,'a','scan-1',report);s.commit()
        row=s.scalar(select(incidents.Incident));return row.id,report

def content(identifier,scan='scan-1'):
    return {'summary':'Review a scanner alert','severity':'unknown','uncertainty':'A signature can be a false positive','steps':[{'action':'preserve_evidence','reason':'Retain artifact','impact':'Storage use','verification':'Compare digest','evidence_ids':[identifier,scan]}]}

def test_scan_receipts_are_immutable_and_recurrence_reopens(admin,recorded):
    identifier,report=recorded
    with Session() as s:
        row=s.get(incidents.Incident,identifier);row.state='closed'
        incidents.record(s,'a','scan-1',{'findings':[]});s.commit()
        assert s.get(incidents.Scan,'scan-1').report==report
        incidents.record(s,'a','scan-2',report);s.commit()
        assert row.state=='open' and row.scan_id=='scan-2'
    assert len(admin.get('/api/hosts/a/security/history').json()['items'])==2
    assert admin.get('/api/hosts/b/security/history').json()['items']==[]
    assert admin.get('/api/hosts/b/security/incidents').json()['items']==[]

@pytest.mark.parametrize('alteration', ['unknown_evidence','command','empty','bad_type'])
def test_ai_plan_validation_rejects_unbound_output(alteration):
    value=content('incident')
    if alteration=='unknown_evidence':value['steps'][0]['evidence_ids']=['invented']
    if alteration=='command':value['steps'][0]['action']='execute_shell'
    if alteration=='empty':value['steps']=[]
    if alteration=='bad_type':value['steps'][0]['impact']=None
    with pytest.raises(ValueError):incidents.validate_plan(value,{'incident','scan-1'})

def test_generation_and_approval_bind_to_current_evidence(admin,recorded,monkeypatch):
    identifier,report=recorded
    with Session() as s:
        s.add(Setting(key='openai_key',value={'encrypted':seal('fixture-key')}))
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture'}));s.commit()
        monkeypatch.setattr(ai,'request',lambda payload,key:content(identifier))
        plan=incidents.generate(s,s.get(incidents.Incident,identifier));pid=plan.id;checksum=plan.evidence_digest
    assert admin.post('/api/hosts/b/security/plans/'+pid+'/approve',json={'evidence_digest':checksum}).status_code==404
    assert admin.post('/api/hosts/a/security/plans/'+pid+'/approve',json={'evidence_digest':'wrong'}).status_code==409
    result=admin.post('/api/hosts/a/security/plans/'+pid+'/approve',json={'evidence_digest':checksum})
    assert result.status_code==200 and result.json()['execution']=='manual_only'
    assert admin.post('/api/hosts/a/security/plans/'+pid+'/approve',json={'evidence_digest':checksum}).status_code==409
    with Session() as s:
        incidents.record(s,'a','scan-2',report);s.commit()
        assert s.get(incidents.Plan,pid).state=='superseded'
    runs=admin.get('/api/ai/runs?host_id=a&purpose=security_plan').json()['items']
    assert len(runs)==1 and runs[0]['subject']==identifier

@pytest.mark.parametrize('role',['viewer','operator'])
def test_security_subresources_admin_only(admin,recorded,role):
    identifier,_=recorded
    with Session() as s:s.get(User,'admin').role=role;s.commit()
    for path in ['history','incidents']:
        assert admin.get('/api/hosts/a/security/'+path).status_code==403
    assert admin.post('/api/hosts/a/security/incidents/'+identifier+'/plan').status_code==403

def test_plan_queue_duplicate_and_cross_host_rejection(admin,recorded):
    identifier,_=recorded
    path='/api/hosts/a/security/incidents/'+identifier+'/plan'
    assert admin.post('/api/hosts/b/security/incidents/'+identifier+'/plan').status_code==404
    assert admin.post(path).status_code==200
    assert admin.post(path).status_code==409

def test_schedule_policy_queues_once_and_preserves_host_scope(admin,recorded):
    from app.db import Job
    assert admin.put('/api/hosts/a/security/policy',json={'paths':['/tmp'],'enabled':True,'interval_hours':0}).status_code==422
    assert admin.put('/api/hosts/a/security/policy',json={'paths':['/tmp/../etc'],'enabled':True,'interval_hours':1}).status_code==400
    assert admin.put('/api/hosts/a/security/policy',json={'paths':['/tmp'],'enabled':True,'interval_hours':1}).status_code==200
    incidents.schedule_tick();incidents.schedule_tick()
    with Session() as s:
        rows=list(s.scalars(select(Job).where(Job.action=='security-scan')))
        assert len(rows)==1 and rows[0].host_id=='a' and rows[0].payload['scheduled']
