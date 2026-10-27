import time
from app import persistence,incidents,worker
from app.db import Session,Setting,Host,Job
from app.identity import User
from test_persistence_baseline import setup_host,payload,URL
from test_persistence_comparison import inventory

BASE='/api/hosts/baseline-host/security'

def enable(admin):
    policy={'enabled':True,'interval_hours':2,'link_incidents':True,'expected_revision':''}
    result=admin.put(BASE+'/persistence-monitor',json=policy)
    assert result.status_code==200
    return result.json()


def test_scheduler_duplicate_cooldown_disable_and_roles(admin,monkeypatch):
    setup_host();policy=enable(admin)
    persistence.schedule_tick();persistence.schedule_tick()
    with Session() as s:
        job=s.query(Job).one();identifier=job.id
        assert job.payload['persistence'] and not job.payload['packages']
    assert admin.put(BASE+'/persistence-monitor',json={**policy,'enabled':False,'expected_revision':policy['revision']}).status_code==200
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:(_ for _ in ()).throw(AssertionError('No remote call')))
    worker.execute(identifier)
    with Session() as s:
        assert s.get(Job,identifier).state=='failed'
        assert 'policy changed' in s.get(Job,identifier).output
    policy=admin.get(BASE+'/persistence-monitor').json()
    assert admin.put(BASE+'/persistence-monitor',json={**policy,'enabled':True,'expected_revision':policy['revision']}).status_code==200
    persistence.schedule_tick()
    with Session() as s:assert s.query(Job).count()==1
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get(BASE+'/persistence-monitor').status_code==403
        assert admin.get(BASE+'/persistence-incidents').status_code==403


def receipt(inv):
    return {'version':1,'trust_basis':'target_local_package_database','state':inv['state'],'packages':[],'persistence':inv}


def test_drift_links_receipts_reviews_reopens_and_gaps_do_not_clear(admin):
    setup_host();assert admin.post(URL,json=payload(admin)).status_code==200;enable(admin)
    changed={**inventory(),'entries':[]}
    with Session() as s:
        incidents.record_inspection(s,'baseline-host','change-one',receipt(changed));s.commit()
        incidents.record_inspection(s,'baseline-host','change-one',receipt(changed));s.commit()
    rows=admin.get(BASE+'/persistence-incidents').json()['items'];assert len(rows)==1
    row=rows[0];path=BASE+'/persistence-incidents/'+row['id']
    body={'state':'resolved','reason':'Reviewed and handled change manually.','expected_updated':row['updated']}
    assert admin.put(path,json=body).status_code==200
    assert admin.put(path,json=body).status_code==409
    with Session() as s:
        incidents.record_inspection(s,'baseline-host','change-two',receipt(changed));s.commit()
        incidents.record_inspection(s,'baseline-host','gap',receipt({**changed,'state':'incomplete','gaps':['unreadable']}));s.commit()
    rows=admin.get(BASE+'/persistence-incidents').json()['items'];assert len(rows)==1 and rows[0]['state']=='open'
    history=admin.get(path+'/history').json()
    assert {r['inspection_id'] for r in history['detections']}=={'change-one','change-two'}
    assert history['reviews'][0]['state']=='resolved'
    assert admin.get(path.replace('baseline-host','other')+'/history').status_code==404


def test_no_incident_without_opt_in_and_recovery_defers_schedule(admin):
    setup_host();assert admin.post(URL,json=payload(admin)).status_code==200
    with Session() as s:
        incidents.record_inspection(s,'baseline-host','no-opt-in',receipt({**inventory(),'entries':[]}));s.commit()
        assert s.query(incidents.PersistenceIncident).count()==0
    enable(admin)
    with Session() as s:
        s.add(Job(id='blocked',host_id='baseline-host',action='patch',state='recovery_required'));s.commit()
    persistence.schedule_tick(time.time()+10000)
    with Session() as s:assert s.query(Job).count()==1
