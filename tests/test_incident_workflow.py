import time
from sqlalchemy import select
from app import incidents
from app.db import Session,Host
from app.identity import User
from tests.test_incidents import recorded


def test_review_conflicts_scope_history_and_reopening(admin,recorded):
    identifier,report=recorded
    url='/api/hosts/a/security/incidents/'+identifier
    with Session() as s:stamp=s.get(incidents.Incident,identifier).updated
    body={'state':'resolved','reason':'Manually restored trusted package and verified service health','expected_updated':stamp}
    assert admin.put(url.replace('/hosts/a/','/hosts/b/'),json=body).status_code==404
    assert admin.put(url,json={**body,'reason':'          '}).status_code==400
    result=admin.put(url,json=body);assert result.status_code==200
    assert result.json()['state']=='resolved'
    assert admin.put(url,json=body).status_code==409
    events=admin.get(url+'/timeline').json()['items']
    assert events[0]['kind']=='review' and events[0]['actor']=='admin'
    assert events[0]['details']['verification']=='manual_review'
    assert events[-1]['kind']=='detection'
    with Session() as s:
        incidents.record(s,'a','repeat',report);s.commit()
        assert s.get(incidents.Incident,identifier).state=='open'
    assert admin.get(url+'/timeline').json()['items'][0]['details']['previous_state']=='resolved'
    assert admin.get(url.replace('/hosts/a/','/hosts/b/')+'/timeline').status_code==404


def test_review_invalidates_plans_and_does_not_modify_evidence(admin,recorded):
    identifier,report=recorded
    with Session() as s:
        row=s.get(incidents.Incident,identifier);stamp=row.updated
        s.add(incidents.Plan(id='plan',incident_id=row.id,evidence_digest='a'*64,content={},state='approved'));s.commit()
    result=admin.put('/api/hosts/a/security/incidents/'+identifier,json={'state':'false_positive','reason':'Confirmed approved testing fixture with owner','expected_updated':stamp})
    assert result.status_code==200
    with Session() as s:
        assert s.get(incidents.Plan,'plan').state=='superseded'
        assert s.get(incidents.Scan,'scan-1').report==report


def test_indicator_search_exact_hash_and_permissions(admin,recorded):
    identifier,report=recorded
    with Session() as s:
        incidents.record(s,'b','scan-b',report)
        other={'findings':[{'path':'/different','sha256':'b'*64}]}
        incidents.record(s,'b','scan-other',other);s.commit()
    result=admin.get('/api/security/indicators/'+'a'*64).json()
    assert {r['host_id'] for r in result['items']}=={'a','b'} and len(result['items'])==2
    assert admin.get('/api/security/indicators/not-a-hash').status_code==400
    for role in ['operator','viewer']:
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get('/api/security/indicators/'+'a'*64).status_code==403
        assert admin.get('/api/hosts/a/security/incidents/'+identifier+'/timeline').status_code==403
        assert admin.put('/api/hosts/a/security/incidents/'+identifier,json={'state':'resolved','reason':'A sufficiently long review reason','expected_updated':1}).status_code==403
