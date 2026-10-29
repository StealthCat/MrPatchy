import copy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import time
import pytest
from app import response_records as records, quarantine, incidents, worker, response_monitor
from app import response_processes, process_response, repair_staging, repair_publication
from app.db import Session, Host, Job, Setting, Audit
from app.evidence_vault import EvidenceCopy, EvidenceArchive, ArchiveObservation
from app.identity import User
from test_quarantine import scenario, row, BASE
from test_repair_preparation import retained
from test_repair_staging import transfer
from test_repair_publication import staged, publish

VERIFIER = Path(__file__).resolve().parents[1] / 'tools' / 'verify_response_record.py'
verify = runpy.run_path(str(VERIFIER))['verify']


def export(admin, record=None, **changes):
    record = record or row(admin)
    return admin.post(BASE+'/quarantines/'+record['id']+'/export', json={
        'plan_digest': record['plan_digest'], 'reason': 'Retain response records in independent protected storage.', **changes})


def test_export_published_lineage_integrity_and_independent_audit(admin, staged, monkeypatch, tmp_path):
    published = publish(admin, staged)
    file = row(admin)
    with Session() as s:
        s.add(ArchiveObservation(id='custody',archive_id='archive',host_id='response-host',state='verified',actor='custodian'))
        q=s.get(quarantine.Quarantine,file['id'])
        s.add(response_monitor.Check(id='monitor',host_id=q.host_id,quarantine_id=q.id,state='replacement_verified',report={'publication_id':published['id']}))
        s.add(response_processes.Observation(id='references',host_id=q.host_id,quarantine_id=q.id,actor='investigator',state='references_found',report={'pid':41}))
        s.add(process_response.ProcessResponse(id='process',host_id=q.host_id,quarantine_id=q.id,observation_id='references',fingerprint='pin',plan={'pid':41}))
        s.add(process_response.Approval(id='process-approval',process_id='process',action='suspend',expires=time.time()+300,plan_digest='a'*64,actor='admin',reason='Reviewed independent process suspension.',before_state='prepared',before_hold=False))
        s.add(process_response.Event(id='process-event',process_id='process',actor='admin',kind='suspend_approved',details={'approval':'process-approval'}))
        s.add(incidents.Plan(id='advisory',incident_id=q.incident_id,evidence_digest=q.evidence_digest,content={'summary':'Advisory only'}))
        s.add(Setting(key='response-monitor:'+q.host_id,value={'enabled':True,'interval_minutes':5,'pause_on_problem':True,'revision':'r','private_extra':'SECRET_SETTING'}))
        s.get(Host,q.host_id).telemetry={'secret':'HOST_SECRET'}
        s.get(Host,q.host_id).inventory={'secret':'INVENTORY_SECRET'}
        s.add(Job(id='secret-job',host_id=q.host_id,action='refresh',payload={'password':'PAYLOAD_SECRET'},output='JOB_OUTPUT_SECRET'))
        s.commit()
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:pytest.fail('Export must not contact a target'))
    monkeypatch.setattr(quarantine.evidence_archive,'verify',lambda *a,**k:pytest.fail('Export must not read preserved file bytes'))
    result=export(admin,file)
    assert result.status_code==200,result.text
    value=result.json();record=value['record'];sections=record['sections']
    digest=hashlib.sha256(result.content).hexdigest()
    assert verify(result.content,digest)==digest==result.headers['x-response-record-sha256']
    assert result.headers['cache-control']=='no-store' and result.headers['x-content-type-options']=='nosniff'
    assert result.headers['content-disposition'].endswith(record['export']['id']+'.json"')
    assert record['export']['actor']=='admin' and record['scope']['missing_references']==[]
    assert record['host']=={'id':'response-host','name':'Response','fingerprint':'pin'}
    assert set(sections)==set(records.FIELDS)
    for name, rows in sections.items():
        assert rows, name
        assert all(set(r)==set(records.FIELDS[name].split()) for r in rows)
    assert sections['repair_publications'][0]['id']==published['id']
    assert sections['response'][0]['state']=='replaced' and sections['response'][0]['hold']
    assert len(sections['stage_events'])==3 and len(sections['publication_events'])==3
    assert 'record_exported' not in [r['kind'] for r in sections['file_events']]
    for secret in ('SECRET_SETTING','HOST_SECRET','INVENTORY_SECRET','PAYLOAD_SECRET','JOB_OUTPUT_SECRET','BINARY_STAGING_SECRET_'):
        assert secret not in result.text
    with Session() as s:
        q=s.get(quarantine.Quarantine,file['id']);p=s.get(repair_publication.Publication,published['id'])
        assert q.state=='replaced' and q.hold and p.hold and p.state=='published'
        event=s.query(quarantine.Event).filter_by(kind='record_exported').one()
        assert event.details['sha256']==digest and event.details['export_id']==record['export']['id']
        assert any(digest in item.detail for item in s.query(Audit).filter_by(action='response record exported'))
    path=tmp_path/'record.json';path.write_bytes(result.content)
    cli=subprocess.run([sys.executable,str(VERIFIER),str(path),'--sha256',digest],capture_output=True,text=True)
    assert cli.returncode==0 and 'Integrity verified' in cli.stdout
    again=export(admin,file).json()['record']
    assert again['export']['id']!=record['export']['id']
    assert any(r['kind']=='record_exported' for r in again['sections']['file_events'])


@pytest.mark.parametrize('state',['prepared','uncertain','restored','console_recovered','replacement_uncertain'])
def test_historical_and_uncertain_responses_are_exportable_without_changing_state(admin,scenario,state):
    file=row(admin)
    with Session() as s:
        q=s.get(quarantine.Quarantine,file['id']);q.state=state;q.hold=True
        q.receipt={'integer':9223372036854775807,'mtime_ns':1793245000123456789}
        s.commit()
    result=export(admin,file)
    assert result.status_code==200,result.text
    assert b'9223372036854775807' in result.content
    assert result.json()['record']['sections']['response'][0]['state']==state
    assert row(admin)['hold'] and row(admin)['state']==state
    assert verify(result.content)==result.headers['x-response-record-sha256']


@pytest.mark.parametrize('relation',['incident','acquisition','preservation'])
def test_missing_or_cross_host_primary_links_are_reported_without_foreign_data(admin,scenario,relation):
    file=row(admin)
    with Session() as s:
        q=s.get(quarantine.Quarantine,file['id'])
        model,identifier={'incident':(incidents.Incident,q.incident_id),'acquisition':(EvidenceArchive,'archive'),'preservation':(EvidenceCopy,'copy')}[relation]
        item=s.get(model,identifier);item.host_id='foreign-host'
        if relation=='incident':item.evidence={'private':'FOREIGN_RECORD'}
        elif relation=='acquisition':item.reason='FOREIGN_RECORD'
        else:item.reason='FOREIGN_RECORD'
        s.commit()
    result=export(admin,file)
    assert result.status_code==200,result.text
    record=result.json()['record']
    assert relation in record['scope']['missing_references']
    assert record['sections'][relation]==[] and 'FOREIGN_RECORD' not in result.text


def test_child_history_is_scoped_by_host_and_response_and_sorted_beyond_ui_page(admin,scenario):
    file=row(admin)
    with Session() as s:
        for i in range(25):
            s.add(quarantine.Event(id='event-%02d'%i,quarantine_id=file['id'],created=10+i,kind='historical',actor='admin',details={'sequence':i}))
        s.add(quarantine.Event(id='other',quarantine_id='unrelated',kind='FOREIGN_RECORD',actor='admin'))
        s.add(response_monitor.Check(id='foreign',host_id='foreign-host',quarantine_id=file['id'],state='unavailable',report={'private':'FOREIGN_RECORD'}))
        s.add(repair_staging.Event(id='foreign-stage-event',host_id='response-host',stage_id='unrelated-stage',actor='admin',kind='FOREIGN_RECORD'))
        s.add(process_response.ProcessResponse(id='foreign-process',host_id='foreign-host',quarantine_id=file['id'],observation_id='x',fingerprint='x',plan={'private':'FOREIGN_RECORD'}))
        s.add(process_response.Event(id='foreign-process-event',process_id='foreign-process',actor='admin',kind='FOREIGN_RECORD'))
        s.commit()
    result=export(admin,file)
    assert result.status_code==200 and 'FOREIGN_RECORD' not in result.text
    events=result.json()['record']['sections']['file_events']
    assert [e['details']['sequence'] for e in events if e['kind']=='historical']==list(range(25))


@pytest.mark.parametrize('limit,value',[('MAX_SECTION_ROWS',1),('MAX_ROWS',1),('MAX_BYTES',64),('MAX_SECONDS',-1)])
def test_limits_refuse_whole_export_without_partial_download_or_success_event(admin,scenario,monkeypatch,limit,value):
    file=row(admin)
    with Session() as s:
        quarantine.event(s,s.get(quarantine.Quarantine,file['id']),'observed','admin');s.commit()
    monkeypatch.setattr(records,limit,value)
    result=export(admin,file)
    assert result.status_code==413,result.text
    assert 'content-disposition' not in result.headers
    with Session() as s:
        assert s.query(quarantine.Event).filter_by(kind='record_exported').count()==0
        assert s.query(Audit).filter_by(action='response record exported').count()==0


def test_export_enforces_role_host_csrf_plan_reason_and_host_operation_lock(admin,scenario):
    file=row(admin);url=BASE+'/quarantines/'+file['id']+'/export'
    assert export(admin,file,plan_digest='f'*64).status_code==409
    assert export(admin,file,reason=' '*20).status_code==400
    assert export(admin,file,reason='short').status_code==422
    body={'plan_digest':file['plan_digest'],'reason':'Retain independently reviewed record.'}
    assert admin.post(url,json=body,headers={'X-CSRF-Token':'wrong'}).status_code==403
    assert admin.post(url.replace('response-host','wrong-host'),json=body).status_code==404
    lock=worker.host_lock('response-host');assert lock.acquire(False)
    try:assert export(admin,file).status_code==409
    finally:lock.release()
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert export(admin,file).status_code==403


@pytest.mark.parametrize('fault',['record','section','manifest','duplicate','version','wrong_external_hash','nan','missing_section'])
def test_offline_verifier_rejects_tampering_and_malformed_records(admin,scenario,fault):
    result=export(admin);value=result.json();expected=None
    if fault=='record':value['record']['export']['actor']='someone-else'
    if fault=='section':
        value['record']['sections']['response'][0]['state']='tampered'
        value['integrity']['record_sha256']=records.sha256(value['record'])
    if fault=='manifest':value['integrity']['sections']['response']['records']=True
    if fault=='version':value['record']['version']=True
    if fault=='wrong_external_hash':expected='0'*64
    if fault=='nan':value['record']['export']['created']=float('nan')
    if fault=='missing_section':
        del value['record']['sections']['file_events'];del value['integrity']['sections']['file_events']
        value['integrity']['record_sha256']=records.sha256(value['record'])
    data=json.dumps(value).encode()
    if fault=='duplicate':data=data.replace(b'"version": 1',b'"version": 1, "version": 1')
    with pytest.raises(ValueError):verify(data,expected)
