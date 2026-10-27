import base64
import copy
import hashlib
import json
import os
import stat
import time
import uuid
import pytest
from app import evidence_archive as archive,incidents,worker
from app.db import Session,Host,Job,Setting,Audit
from app.evidence_vault import EvidenceCopy,EvidenceArchive,ArchiveObservation
from app.identity import User

CONTENT=b'forensic fixture\x00\xff never execute'

@pytest.fixture
def storage(tmp_path,monkeypatch):
    monkeypatch.setattr(archive,'DATA',tmp_path)
    return tmp_path/'evidence-archive'

def seed():
    snapshot={'path':'/srv/suspect','sha256':hashlib.sha256(CONTENT).hexdigest(),'identity':{'dev':1,'ino':2,'size':len(CONTENT),'uid':0,'gid':0,'mode':0o100644,'mtime_ns':1,'ctime_ns':1,'nlink':1},'parent':{'dev':1,'ino':3}}
    with Session() as s:
        s.add(Host(id='archive-host',name='archive',address='192.0.2.1',fingerprint='pin'))
        s.add(EvidenceCopy(id='copy',host_id='archive-host',incident_id='resolved-is-allowed',state='preserved',snapshot=snapshot,evidence_digest='a'*64))
        s.commit()
    return snapshot

def approve(admin,snapshot):
    return admin.post('/api/hosts/archive-host/security/evidence-copies/copy/acquire',json={'snapshot_digest':incidents.digest(snapshot),'reason':'Retain independent evidence for the investigation.','confirmation':'ACQUIRE'})

def export(snapshot):return {'id':'copy','snapshot':copy.deepcopy(snapshot),'content_base64':base64.b64encode(CONTENT).decode()}

def row(admin):return admin.get('/api/hosts/archive-host/security/evidence-archives').json()['items'][0]

def status(admin,identifier):
    response=admin.post('/api/hosts/archive-host/security/evidence-archives/'+identifier+'/status',json={})
    assert response.status_code==200,response.text
    worker.execute(response.json()['job_id'])

def history(admin,identifier):return admin.get('/api/hosts/archive-host/security/evidence-archives/'+identifier+'/history').json()['items']


def test_separate_approval_private_acquisition_and_independent_custody(admin,storage,monkeypatch):
    snapshot=seed();url='/api/hosts/archive-host/security/evidence-copies/copy/acquire'
    body={'snapshot_digest':incidents.digest(snapshot),'reason':'Preserve independently for investigation.','confirmation':'PRESERVE'}
    assert admin.post(url,json=body).status_code==400
    body['confirmation']='ACQUIRE';body['snapshot_digest']='a'*64
    assert admin.post(url,json=body).status_code==409
    response=approve(admin,snapshot);assert response.status_code==200,response.text
    assert approve(admin,snapshot).status_code==409
    def remote(host,request,**kwargs):
        assert request['action']=='evidence-export' and request['snapshot']==snapshot and time.time()<request['approved_until']<=time.time()+300
        return export(snapshot)
    monkeypatch.setattr(worker.ssh,'call',remote)
    worker.execute(response.json()['job_id']);result=row(admin)
    assert result['state']=='verified' and result['actor']=='admin'
    folder=storage/result['id'];assert (folder/'content').read_bytes()==CONTENT
    assert stat.S_IMODE(folder.stat().st_mode)==0o700
    for file in folder.iterdir():assert stat.S_IMODE(file.stat().st_mode)==0o600
    # Local verification works with a blocked target and never accesses SSH.
    with Session() as s:
        s.add(Setting(key='agent-status:archive-host',value={'state':'blocked'}));s.commit()
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:pytest.fail('Local verification must not connect'))
    status(admin,result['id']);assert row(admin)['state']=='verified'
    states=[r['state'] for r in history(admin,result['id'])]
    assert sorted(states)==sorted(['approved','started','verified','verified'])
    (folder/'content').write_bytes(b'changed')
    status(admin,result['id']);assert row(admin)['state']=='unavailable'
    assert any(r['state']=='verified' for r in history(admin,result['id']))
    with Session() as s:
        job=s.get(Job,response.json()['job_id'])
        assert job.state=='complete' and 'content_base64' not in job.output and 'never execute' not in job.output
        assert all('never execute' not in r.detail for r in s.query(Audit))
    assert 'never execute' not in json.dumps(result)


@pytest.mark.parametrize('failure',['timeout','wrong_hash','wrong_snapshot','bad_encoding','expired_during_transfer'])
def test_transfer_failure_is_uncertain_and_never_publishes_content(admin,storage,monkeypatch,failure):
    snapshot=seed();response=approve(admin,snapshot)
    def remote(*args,**kwargs):
        if failure=='timeout':raise TimeoutError('Connection lost')
        result=export(snapshot)
        if failure=='wrong_hash':result['content_base64']=base64.b64encode(b'x'*len(CONTENT)).decode()
        if failure=='wrong_snapshot':result['snapshot']['path']='/etc/another'
        if failure=='bad_encoding':result['content_base64']='!!!!'
        return result
    if failure=='expired_during_transfer':
        now=time.time()
        def remote(*args,**kwargs):
            monkeypatch.setattr(archive.time,'time',lambda:now+600)
            return export(snapshot)
    monkeypatch.setattr(worker.ssh,'call',remote)
    worker.execute(response.json()['job_id']);result=row(admin)
    assert result['state']=='uncertain'
    assert not (storage/result['id']/'content').exists()
    assert (storage/result['id']/'intent.json').is_file()
    assert {r['state'] for r in history(admin,result['id'])}=={'approved','started','interrupted'}
    status(admin,result['id']);assert row(admin)['state']=='incomplete'


@pytest.mark.parametrize('fault',['after_content','after_receipt'])
def test_crash_reconciliation_retains_partial_or_recovers_completed_copy(admin,storage,monkeypatch,fault):
    snapshot=seed();response=approve(admin,snapshot)
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:export(snapshot))
    original=archive.write_json
    def fail(fd,name,value):
        if name=='receipt.json':
            if fault=='after_receipt':original(fd,name,value)
            raise OSError('Simulated interrupted publication')
        original(fd,name,value)
    monkeypatch.setattr(archive,'write_json',fail)
    worker.execute(response.json()['job_id']);result=row(admin)
    assert result['state']=='uncertain' and (storage/result['id']/'content').read_bytes()==CONTENT
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:pytest.fail('No automatic retry'))
    status(admin,result['id'])
    assert row(admin)['state']==('verified' if fault=='after_receipt' else 'incomplete')
    with Session() as s:
        host=s.get(Host,'archive-host');record=s.get(EvidenceArchive,result['id'])
        record.state='queued';record.expires=time.time()+300;s.commit()
        with pytest.raises(ValueError,match='read-only reconciliation'):
            archive.execute(s,host,Job(id=str(uuid.uuid4()),action='evidence-acquire',payload={'archive_id':record.id}))
    assert (storage/result['id']/'content').read_bytes()==CONTENT


@pytest.mark.parametrize('change',['pin','snapshot','expired'])
def test_queue_approval_is_rechecked_before_access(admin,storage,monkeypatch,change):
    snapshot=seed();response=approve(admin,snapshot)
    with Session() as s:
        record=s.get(EvidenceArchive,response.json()['archive_id'])
        if change=='pin':s.get(Host,'archive-host').fingerprint='different-pin'
        if change=='snapshot':s.get(EvidenceCopy,'copy').snapshot={**snapshot,'sha256':'a'*64}
        if change=='expired':record.expires=time.time()-1
        s.commit()
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:pytest.fail('Invalid approval accessed target'))
    worker.execute(response.json()['job_id'])
    assert not storage.exists()
    with Session() as s:assert s.get(Job,response.json()['job_id']).state=='failed'


@pytest.mark.parametrize('change',['symlink','hardlink','mode','receipt'])
def test_unsafe_or_mismatched_controller_files_cannot_verify(admin,storage,monkeypatch,change):
    snapshot=seed();response=approve(admin,snapshot);monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:export(snapshot))
    worker.execute(response.json()['job_id']);result=row(admin);folder=storage/result['id'];content=folder/'content'
    if change=='symlink':
        content.rename(folder/'other');content.symlink_to(folder/'other')
    if change=='hardlink':os.link(content,folder/'other')
    if change=='mode':content.chmod(0o644)
    if change=='receipt':
        receipt=json.loads((folder/'receipt.json').read_text());receipt['host_id']='different';(folder/'receipt.json').write_text(json.dumps(receipt))
    status(admin,result['id']);assert row(admin)['state']=='unavailable'


def test_archive_endpoints_enforce_host_and_role(admin,storage):
    snapshot=seed();response=approve(admin,snapshot);identifier=response.json()['archive_id']
    wrong='/api/hosts/another/security/evidence-archives/'+identifier
    assert admin.get(wrong+'/history').status_code==404
    assert admin.post(wrong+'/status',json={}).status_code==404
    assert admin.get('/api/hosts/archive-host/security/evidence-archives?offset=-1').status_code==400
    assert admin.get('/api/hosts/archive-host/security/evidence-archives/'+identifier+'/history?offset=-1').status_code==400
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get('/api/hosts/archive-host/security/evidence-archives').status_code==403
        assert admin.post('/api/hosts/archive-host/security/evidence-archives/'+identifier+'/status',json={}).status_code==403
        assert approve(admin,snapshot).status_code==403


def test_storage_anchor_rejects_symlinks_and_writable_data_directory(tmp_path,monkeypatch):
    actual=tmp_path/'actual';actual.mkdir(mode=0o700);alias=tmp_path/'alias';alias.symlink_to(actual,target_is_directory=True)
    monkeypatch.setattr(archive,'DATA',alias)
    with pytest.raises(OSError):
        with archive.directory(str(uuid.uuid4()),create=True):pass
    monkeypatch.setattr(archive,'DATA',actual);actual.chmod(0o777)
    with pytest.raises(ValueError):
        with archive.directory(str(uuid.uuid4()),create=True):pass
