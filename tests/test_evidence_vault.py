import base64
import copy
import hashlib
import os
import stat
import uuid
from contextlib import contextmanager
import pytest
from app import evidence_vault,incidents,worker
from app.db import Session,Host,Job
from target import agent


def detection(path):
    info=path.stat();return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'device':info.st_dev,'inode':info.st_ino}

@pytest.fixture
def vault(tmp_path,monkeypatch):
    if os.geteuid()!=0:pytest.skip('Root-owned vault fixtures require root; native SSH container tests exercise production ownership checks')
    root=tmp_path/'vault';monkeypatch.setattr(agent,'EVIDENCE_ROOT',root)
    # /tmp is deliberately world-writable. Unit tests anchor an isolated fixture;
    # native SSH integration separately exercises the production ancestor guard.
    @contextmanager
    def directory(path,create=False):
        if create:path.mkdir(parents=True,mode=0o700,exist_ok=True)
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:yield fd
        finally:os.close(fd)
    monkeypatch.setattr(agent,'evidence_directory',directory)
    return root


def test_prepare_preserve_status_idempotence_and_source_unchanged(tmp_path,vault):
    source=tmp_path/'source';source.write_bytes(b'forensic fixture')
    expected=detection(source);snapshot=agent.evidence_prepare(expected);identifier=str(uuid.uuid4())
    receipt=agent.evidence_preserve(identifier,snapshot)
    assert receipt['state']=='preserved' and source.read_bytes()==b'forensic fixture'
    assert (vault/identifier/'content').read_bytes()==source.read_bytes()
    assert stat.S_IMODE((vault/identifier/'content').stat().st_mode)==0o600
    assert agent.evidence_preserve(identifier,snapshot)==receipt
    assert agent.evidence_preserve(identifier,status_only=True)==receipt
    assert agent.evidence_preserve(str(uuid.uuid4()),status_only=True)['state']=='not_found'
    with pytest.raises(ValueError):agent.evidence_preserve(identifier,{**snapshot,'sha256':'0'*64})
    (vault/identifier/'content').write_bytes(b'tampered')
    with pytest.raises(ValueError):agent.evidence_preserve(identifier,status_only=True)


def test_changed_replaced_symlink_and_oversize_source_rejected(tmp_path,vault):
    path=tmp_path/'file';path.write_bytes(b'known');expected=detection(path);snapshot=agent.evidence_prepare(expected)
    path.write_bytes(b'changed')
    with pytest.raises(ValueError):agent.evidence_preserve(str(uuid.uuid4()),snapshot)
    path.unlink();path.symlink_to(tmp_path/'other')
    with pytest.raises((ValueError,OSError)):agent.evidence_prepare(expected)
    path.unlink();path.write_bytes(b'x'*(32*1024*1024+1))
    with pytest.raises(ValueError):agent.evidence_prepare(detection(path))


def test_vault_ancestor_guard_rejects_world_writable_and_symlink(tmp_path):
    with pytest.raises(ValueError):
        with agent.evidence_directory(tmp_path,create=False):pass
    alias=tmp_path/'alias';alias.symlink_to(tmp_path,target_is_directory=True)
    with pytest.raises((ValueError,OSError)):
        with agent.evidence_directory(alias):pass


def test_partial_copy_is_retained_and_never_retried(tmp_path,vault,monkeypatch):
    path=tmp_path/'file';path.write_bytes(b'known');snapshot=agent.evidence_prepare(detection(path));identifier=str(uuid.uuid4())
    original=agent.evidence_prepare;calls=0
    def changed(expected):
        nonlocal calls
        calls+=1
        if calls==2:raise ValueError('Simulated source change after copying')
        return original(expected)
    monkeypatch.setattr(agent,'evidence_prepare',changed)
    with pytest.raises(ValueError):agent.evidence_preserve(identifier,snapshot)
    assert (vault/identifier/'partial').read_bytes()==b'known' and path.read_bytes()==b'known'
    assert agent.evidence_preserve(identifier,status_only=True)['state']=='incomplete'
    assert agent.evidence_preserve(identifier,snapshot)['state']=='incomplete'


def test_export_only_completed_preservation_and_rechecks_content(tmp_path,vault):
    source=tmp_path/'source';source.write_bytes(b'private forensic fixture\x00\xff')
    snapshot=agent.evidence_prepare(detection(source));identifier=str(uuid.uuid4())
    agent.evidence_preserve(identifier,snapshot)
    source.unlink() # Acquisition reads the vault, never the original path.
    result=agent.evidence_export(identifier,snapshot)
    assert result['snapshot']==snapshot and base64.b64decode(result['content_base64'])==b'private forensic fixture\x00\xff'
    with pytest.raises(ValueError):agent.evidence_export('../'+'a'*33,snapshot)
    with pytest.raises(ValueError):agent.evidence_export(identifier,{**snapshot,'path':'/etc/shadow'})
    (vault/identifier/'content').write_bytes(b'tampered')
    with pytest.raises(ValueError):agent.evidence_export(identifier,snapshot)


def test_incomplete_vault_cannot_be_exported(tmp_path,vault):
    identifier=str(uuid.uuid4());folder=vault/identifier;folder.mkdir(parents=True,mode=0o700)
    fd=os.open(folder,os.O_DIRECTORY)
    try:agent.evidence_write(fd,'receipt.json',{'id':identifier,'state':'incomplete','snapshot':{}})
    finally:os.close(fd)
    with pytest.raises(ValueError):agent.evidence_export(identifier,{})


def seed():
    with Session() as s:
        s.add(Host(id='vault-host',name='vault',address='192.0.2.1',fingerprint='pin'))
        incidents.record(s,'vault-host','detected',{'findings':[{'path':'/tmp/fixture','sha256':'a'*64,'device':1,'inode':2}]});s.commit()
        return s.query(incidents.Incident).one().id


def test_approval_is_separate_from_ai_and_connection_loss_reconciles(admin,monkeypatch):
    incident_id=seed();base='/api/hosts/vault-host/security';snapshot={'path':'/tmp/fixture','sha256':'a'*64,'identity':{'dev':1,'ino':2,'size':5,'uid':0,'gid':0,'mode':0o100644,'mtime_ns':1,'ctime_ns':1,'nlink':1},'parent':{'dev':1,'ino':3}}
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:copy.deepcopy(snapshot))
    response=admin.post(base+'/incidents/'+incident_id+'/preservation',json={});assert response.status_code==200
    worker.execute(response.json()['job_id'])
    row=admin.get(base+'/evidence-copies').json()['items'][0]
    assert row['state']=='prepared'
    body={'snapshot_digest':row['snapshot_digest'],'reason':'Preserve this file for manual investigation.','confirmation':'no'}
    url=base+'/evidence-copies/'+row['id']
    assert admin.post(url+'/execute',json=body).status_code==400
    body['confirmation']='PRESERVE';response=admin.post(url+'/execute',json=body);assert response.status_code==200
    assert admin.post(url+'/execute',json=body).status_code==409
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:(_ for _ in ()).throw(TimeoutError('Lost reply')))
    worker.execute(response.json()['job_id'])
    assert admin.get(base+'/evidence-copies').json()['items'][0]['state']=='uncertain'
    monkeypatch.setattr(worker.ssh,'call',lambda host,req,**k:{'id':row['id'],'state':'preserved','snapshot':snapshot,'original_unchanged':True})
    status=admin.post(url+'/status',json={});worker.execute(status.json()['job_id'])
    result=admin.get(base+'/evidence-copies').json()['items'][0]
    assert result['state']=='preserved' and result['actor']=='admin' and result['reason']==body['reason']
    assert admin.get(base.replace('vault-host','missing')+'/evidence-copies').status_code==404
