import hashlib,json,runpy,time
from pathlib import Path
import pytest
from sqlalchemy import select
from app import scanner_records,response_records,worker,ssh,ai
from app.db import Session,Host,Audit,Setting
from app.incidents import Scan,Incident,IncidentEvent,Plan
from app.identity import User
verify=runpy.run_path(str(Path(__file__).resolve().parents[1]/'tools/verify_response_record.py'))['verify']
BASE='/api/hosts/one/security/export'

@pytest.fixture
def seeded(admin):
    with Session() as s:
        for id in ('one','two'):s.add(Host(id=id,name=id,address='192.0.2.1',fingerprint='pin'))
        s.add(Setting(key='openai_key',value={'encrypted':'SECRET_CONFIG'}))
        for host in ('one','two'):
            s.add(Scan(id=host+'-scan',host_id=host,report={'engine':'ClamAV','state':'incomplete','scanned':1,'gaps':['Signature unknown'],'findings':[{'path':'/srv/test','sha256':'a'*64,'inode':2**63+1,'evidence':'RAW_SECRET','unknown':'SECRET_EXTRA'}],'unknown':'SECRET_EXTRA'}))
            s.add(Incident(id=host,host_id=host,scan_id=host+'-scan',evidence={'path':'/srv/test','sha256':'a'*64,'evidence':'RAW_SECRET'}))
            s.add(IncidentEvent(id=host+'-event',incident_id=host,kind='review',actor='admin',details={'reason':'Operator reviewed receipt','scan_id':host+'-scan'}))
            s.add(Plan(id=host+'-plan',incident_id=host,evidence_digest='d'*64,content={'summary':'Review','steps':[{'action':'rescan','evidence_ids':[host,host+'-scan']}]}))
        s.commit()
    return admin

def export(c,**changes):return c.post(BASE,json={'reason':'Retain scanner records for independent review',**changes})

def test_portable_projection_scope_integrity_audit_and_no_io(seeded,monkeypatch):
    monkeypatch.setattr(ssh,'call',lambda *a,**k:pytest.fail('No target I/O'))
    monkeypatch.setattr(ai,'request',lambda *a,**k:pytest.fail('No provider call'))
    r=export(seeded);assert r.status_code==200,r.text
    digest=hashlib.sha256(r.content).hexdigest();assert verify(r.content,digest)==r.headers['x-scanner-record-sha256']
    data=r.json()['record'];sections=data['sections'];assert data['scope']['primary_references_complete']
    assert {row['id'] for rows in sections.values() for row in rows}=={'one-scan','one','one-event','one-plan'}
    assert sections['scans'][0]['report']['findings'][0]['inode']==2**63+1
    assert 'SECRET' not in r.text and 'RAW_SECRET' not in r.text
    assert r.headers['cache-control']=='no-store'
    with Session() as s:
        assert digest in s.scalar(select(Audit).where(Audit.action=='scanner record exported')).detail
        assert s.get(Incident,'one').state=='open'
    bad=json.loads(r.content);bad['record']['sections']['scans'][0]['report']['scanned']=99
    with pytest.raises(ValueError):verify(json.dumps(bad).encode())
    with pytest.raises(ValueError):verify(r.content,'0'*64)
    with pytest.raises(ValueError):verify(b'{"record":{},"record":{}}')

@pytest.mark.parametrize('state',['disabled','deleted'])
def test_inactive_history_export_preserves_lifecycle(seeded,state):
    with Session() as s:
        host=s.get(Host,'one');host.enabled=False;host.deleted_at=time.time() if state=='deleted' else 0;s.commit()
    assert export(seeded).status_code==200
    with Session() as s:assert not s.get(Host,'one').enabled

@pytest.mark.parametrize('limit,value',[('MAX_SECTION_ROWS',0),('MAX_ROWS',0),('MAX_BYTES',100),('MAX_SECONDS',-1)])
def test_whole_export_refused_at_limits_without_success_audit(seeded,monkeypatch,limit,value):
    monkeypatch.setattr(response_records,limit,value)
    assert export(seeded).status_code==413
    with Session() as s:assert not list(s.scalars(select(Audit).where(Audit.action=='scanner record exported')))

def test_missing_references_roles_csrf_reason_and_host_lock(seeded):
    with Session() as s:s.get(Incident,'one').scan_id='missing';s.commit()
    data=export(seeded).json()['record'];assert data['scope']['missing_scan_references']==['missing'] and not data['scope']['primary_references_complete']
    assert export(seeded,reason=' '*20).status_code==400
    with worker.host_lock('one'):assert export(seeded).status_code==409
    csrf=seeded.headers.pop('X-CSRF-Token');assert export(seeded).status_code==403;seeded.headers['X-CSRF-Token']=csrf
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert export(seeded).status_code==403



def test_related_evidence_citations_resolve_or_are_out_of_scope(seeded):
    with Session() as s:
        row=s.get(Plan,'one-plan');row.content={'steps':[{'evidence_ids':['one','scans:one-scan','executions:x1','inspections:i1','scans:gone']}]};s.commit()
    scope=export(seeded).json()['record']['scope']
    assert scope['missing_evidence_references']==['scans:gone'] and not scope['primary_references_complete']
    assert scope['out_of_scope_evidence_references']==['executions:x1','inspections:i1']
    with Session() as s:
        row=s.get(Plan,'one-plan');row.content={'steps':[{'evidence_ids':['one','scans:one-scan','executions:x1']}]};s.commit()
    scope=export(seeded).json()['record']['scope']
    assert scope['missing_evidence_references']==[] and scope['primary_references_complete']


def test_unresolved_plan_references_and_oversize_findings_are_explicit(seeded):
    with Session() as s:
        row=s.get(Plan,'one-plan');row.content={'steps':[{'evidence_ids':['missing-evidence']}]};s.commit()
    scope=export(seeded).json()['record']['scope']
    assert scope['missing_evidence_references']==['missing-evidence'] and not scope['primary_references_complete']
    with Session() as s:
        s.get(Scan,'one-scan').report={'findings':[{'path':'/srv/a'}]*101};s.commit()
    assert export(seeded).status_code==413
