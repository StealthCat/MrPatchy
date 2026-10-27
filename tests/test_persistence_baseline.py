import time
import pytest
from app import incidents,persistence,operations,worker
from app.db import Session,Host,Setting
from app.identity import User
from test_persistence_comparison import inventory


def setup_host():
    with Session() as s:
        s.add(Host(id='baseline-host',name='Baseline',address='example',fingerprint='pinned',state='online',last_seen=time.time()))
        s.add(incidents.Inspection(id='first',host_id='baseline-host',report={'persistence':inventory()}));s.commit()

URL='/api/hosts/baseline-host/security/baseline'

def payload(admin):
    state=admin.get(URL).json()
    return {'inspection_id':state['latest']['id'],'evidence_digest':state['latest']['digest'],
            'expected':state['baseline']['id'] if state['baseline'] else '', 'reason':'Reviewed startup inventory against approved configuration.'}


def test_approval_conflicts_history_and_drift_alerts(admin):
    setup_host();body=payload(admin)
    assert admin.post(URL,json=body).status_code==200
    assert admin.post(URL,json=body).status_code==409
    assert admin.get(URL).json()['state']=='matches'
    with Session() as s:
        s.add(incidents.Inspection(id='second',host_id='baseline-host',created=time.time()+.001,report={'persistence':{**inventory(),'entries':[]}}));s.commit()
    time.sleep(.01)
    assert admin.get(URL).json()['state']=='drifted'
    operations.collect_alerts()
    with Session() as s:assert s.query(operations.Alert).filter_by(kind='startup baseline').one().state=='open'
    assert admin.post(URL,json=payload(admin)).status_code==200
    assert len(admin.get(URL+'/history').json()['items'])==2
    operations.collect_alerts()
    with Session() as s:assert s.query(operations.Alert).filter_by(kind='startup baseline').one().state=='resolved'


@pytest.mark.parametrize('change',['incomplete','old','changed','digest','host'])
def test_stale_or_incomplete_review_is_rejected(admin,change):
    setup_host();body=payload(admin)
    with Session() as s:
        row=s.get(incidents.Inspection,'first')
        if change=='incomplete':row.report={'persistence':{**inventory(),'state':'incomplete','gaps':['missing access']}}
        elif change=='old':row.created=time.time()-86401
        elif change=='changed':s.add(incidents.Inspection(id='new',host_id='baseline-host',created=time.time(),report={'persistence':inventory()}))
        elif change=='host':row.host_id='another'
        elif change=='digest':body['evidence_digest']='0'*64
        s.commit()
    assert admin.post(URL,json=body).status_code==409
    with Session() as s:assert s.query(incidents.PersistenceBaseline).count()==0


def test_gaps_and_staleness_never_resolve_as_matches(admin):
    setup_host();assert admin.post(URL,json=payload(admin)).status_code==200
    with Session() as s:
        s.add(incidents.Inspection(id='gap',host_id='baseline-host',report={'persistence':{**inventory(),'state':'incomplete','entries':[],'gaps':['unreadable']}}));s.commit()
    assert admin.get(URL).json()['state']=='unavailable'
    with Session() as s:
        for row in s.query(incidents.Inspection):row.created=time.time()-86401
        s.commit()
    assert admin.get(URL).json()['state']=='stale'


def test_roles_host_lock_and_receipt_binding(admin):
    setup_host();body=payload(admin)
    with worker.host_lock('baseline-host'):assert admin.post(URL,json=body).status_code==409
    assert admin.post(URL,json=body).status_code==200
    with Session() as s:
        s.get(incidents.Inspection,'first').report={'persistence':{**inventory(),'entries':[]}};s.commit()
    assert admin.get(URL).json()['state']=='unavailable'
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get(URL).status_code==403
        assert admin.get(URL+'/history').status_code==403
        assert admin.post(URL,json=body).status_code==403
