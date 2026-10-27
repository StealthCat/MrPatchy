"""Explicitly approved evidence preservation. Never removes the source file."""
import time
import uuid
from sqlalchemy import String,Double,JSON,Text,select
from sqlalchemy.orm import Mapped,mapped_column
from .db import Base,audit
from . import incidents,ssh

class EvidenceCopy(Base):
    __tablename__='security_evidence_copies'
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    incident_id:Mapped[str]=mapped_column(String(64),index=True)
    created:Mapped[float]=mapped_column(Double,default=time.time)
    state:Mapped[str]=mapped_column(String(30),default='prepared')
    evidence_digest:Mapped[str]=mapped_column(String(64))
    snapshot:Mapped[dict]=mapped_column(JSON,default=dict)
    receipt:Mapped[dict]=mapped_column(JSON,default=dict)
    actor:Mapped[str]=mapped_column(String(120),default='')
    reason:Mapped[str]=mapped_column(Text,default='')
    expires:Mapped[float]=mapped_column(Double,default=0)

class EvidenceArchive(Base):
    __tablename__='security_evidence_archives'
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    copy_id:Mapped[str]=mapped_column(String(36),index=True)
    created:Mapped[float]=mapped_column(Double,default=time.time)
    state:Mapped[str]=mapped_column(String(30),default='queued')
    snapshot:Mapped[dict]=mapped_column(JSON)
    fingerprint:Mapped[str]=mapped_column(String(100))
    actor:Mapped[str]=mapped_column(String(120))
    reason:Mapped[str]=mapped_column(Text)
    expires:Mapped[float]=mapped_column(Double)

class ArchiveObservation(Base):
    __tablename__='security_evidence_archive_observations'
    id:Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid.uuid4()))
    archive_id:Mapped[str]=mapped_column(String(36),index=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    created:Mapped[float]=mapped_column(Double,default=time.time)
    job_id:Mapped[str]=mapped_column(String(36),default='')
    state:Mapped[str]=mapped_column(String(30))
    actor:Mapped[str]=mapped_column(String(120))


def validate_snapshot(snapshot,expected):
    import stat
    if not isinstance(snapshot,dict):raise ValueError('Invalid evidence snapshot')
    identity=snapshot.get('identity')
    keys={'dev','ino','size','uid','gid','mode','mtime_ns','ctime_ns','nlink'}
    if set(snapshot)!={'path','sha256','identity','parent'} or not isinstance(identity,dict) or set(identity)!=keys or any(type(v) is not int or v<0 for v in identity.values()):raise ValueError('Invalid evidence identity snapshot')
    parent=snapshot['parent']
    if not isinstance(parent,dict) or set(parent)!={'dev','ino'} or any(type(v) is not int or v<0 for v in parent.values()):raise ValueError('Invalid evidence parent snapshot')
    if not stat.S_ISREG(identity['mode']) or identity['size']>32*1024*1024 or identity['nlink']<1:raise ValueError('Evidence file outside preservation limits')
    if snapshot['path']!=expected['path'] or snapshot['sha256']!=expected['sha256'] or identity['dev']!=expected['device'] or identity['ino']!=expected['inode']:raise ValueError('Preparation does not bind detected identity')


def incident(s,host_id,identifier):
    row=s.get(incidents.Incident,identifier)
    if not row or row.host_id!=host_id or row.state not in ('open','acknowledged'):raise ValueError('An open or acknowledged scanner incident is required')
    return row


def execute(s,host,job):
    payload=job.payload
    if job.action=='evidence-prepare':
        row=incident(s,host.id,payload['incident_id'])
        fingerprint=incidents.digest(row.evidence)
        if fingerprint!=payload['evidence_digest']:raise ValueError('Incident evidence changed before preparation')
        expected={k:row.evidence.get(k) for k in ('path','sha256','device','inode')}
        snapshot=ssh.call(host,{'action':'evidence-prepare','expected':expected},timeout=45)
        validate_snapshot(snapshot,expected)
        identifier=str(uuid.uuid4());s.add(EvidenceCopy(id=identifier,host_id=host.id,incident_id=row.id,evidence_digest=fingerprint,snapshot=snapshot))
        audit(s,'evidence preservation prepared',host.id+' '+identifier)
        return {'id':identifier,'state':'prepared','execution':'explicit_preservation_approval_required'}
    copy=s.get(EvidenceCopy,payload['copy_id'])
    if not copy or copy.host_id!=host.id:raise ValueError('Evidence operation not found')
    if job.action=='evidence-preserve':
        row=incident(s,host.id,copy.incident_id)
        if copy.state!='queued' or time.time()>copy.expires or incidents.digest(row.evidence)!=copy.evidence_digest:raise ValueError('Evidence approval expired, superseded or changed')
    request={'action':'evidence-status' if job.action=='evidence-status' else 'evidence-preserve','id':copy.id}
    if job.action!='evidence-status':request.update(snapshot=copy.snapshot,approved_until=copy.expires)
    # Preserve uncertainty across connection loss or a controller restart.
    copy.state='uncertain';s.commit()
    try:
        receipt=ssh.call(host,request,timeout=180)
        if not isinstance(receipt,dict) or receipt.get('id')!=copy.id or receipt.get('state') not in ('preserved','incomplete','not_found'):raise ValueError('Unsupported evidence receipt')
        if receipt['state']=='preserved' and (receipt.get('snapshot')!=copy.snapshot or receipt.get('original_unchanged') is not True):raise ValueError('Vault receipt does not bind approved evidence')
        copy.state=receipt['state'];copy.receipt=receipt
        audit(s,'evidence preservation '+copy.state,host.id+' '+copy.id+' '+copy.actor)
        return {'id':copy.id,'state':copy.state,'original_not_removed':True}
    except Exception:
        s.rollback();raise
