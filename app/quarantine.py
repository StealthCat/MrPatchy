"""Reviewed, narrowly scoped file moves with durable uncertainty and host holds."""
import re
import json
import stat
import time
import uuid
from pathlib import PurePosixPath
from sqlalchemy import String,Double,Boolean,JSON,Text,select
from sqlalchemy.orm import Mapped,mapped_column
from .db import Base,audit
from . import incidents,ssh,evidence_archive
from .evidence_vault import EvidenceCopy,EvidenceArchive,validate_snapshot,incident

ACTIONS=('quarantine-prepare','quarantine-apply','quarantine-status','quarantine-restore','quarantine-audit','quarantine-processes')
RECOVERY_ACTIONS=('quarantine-apply','quarantine-status','quarantine-restore','quarantine-audit','quarantine-processes')
ACTIONS+=('process-prepare','process-suspend','process-status','process-resume')
RECOVERY_ACTIONS+=('process-prepare','process-suspend','process-status','process-resume')

class Quarantine(Base):
    __tablename__='security_quarantines'
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    incident_id:Mapped[str]=mapped_column(String(64),index=True)
    archive_id:Mapped[str]=mapped_column(String(36))
    created:Mapped[float]=mapped_column(Double,default=time.time)
    state:Mapped[str]=mapped_column(String(30),default='prepared')
    hold:Mapped[bool]=mapped_column(Boolean,default=False)
    fingerprint:Mapped[str]=mapped_column(String(100))
    evidence_digest:Mapped[str]=mapped_column(String(64))
    plan:Mapped[dict]=mapped_column(JSON)
    receipt:Mapped[dict]=mapped_column(JSON,default=dict)
    observed:Mapped[float]=mapped_column(Double,default=0)
    approval_id:Mapped[str]=mapped_column(String(36),default='')

class Approval(Base):
    __tablename__='security_quarantine_approvals'
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    quarantine_id:Mapped[str]=mapped_column(String(36),index=True)
    action:Mapped[str]=mapped_column(String(30))
    created:Mapped[float]=mapped_column(Double,default=time.time)
    expires:Mapped[float]=mapped_column(Double)
    plan_digest:Mapped[str]=mapped_column(String(64))
    actor:Mapped[str]=mapped_column(String(120))
    reason:Mapped[str]=mapped_column(Text)
    before_state:Mapped[str]=mapped_column(String(30))
    before_hold:Mapped[bool]=mapped_column(Boolean)

class Event(Base):
    __tablename__='security_quarantine_events'
    id:Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid.uuid4()))
    quarantine_id:Mapped[str]=mapped_column(String(36),index=True)
    created:Mapped[float]=mapped_column(Double,default=time.time)
    kind:Mapped[str]=mapped_column(String(40))
    actor:Mapped[str]=mapped_column(String(120))
    details:Mapped[dict]=mapped_column(JSON,default=dict)


def event(s,row,kind,actor='system',details=None):
    s.add(Event(quarantine_id=row.id,kind=kind,actor=actor,details=details or {}))
    audit(s,'file response '+kind,row.host_id+' '+row.id+' '+actor)


def validate_plan(plan,snapshot):
    if not isinstance(plan,dict) or set(plan)!={'file','ancestors','xattrs','vault_device'} or plan['file']!=snapshot:raise ValueError('Response plan does not bind acquired evidence')
    if len(json.dumps(plan).encode())>48000:raise ValueError('Response metadata exceeds budget')
    validate_snapshot(snapshot,{'path':snapshot['path'],'sha256':snapshot['sha256'],'device':snapshot['identity']['dev'],'inode':snapshot['identity']['ino']})
    path=snapshot['path'];identity=snapshot['identity']
    if not path.startswith(('/srv/','/opt/')) or path.startswith('/opt/drpatch/') or path=='/opt/drpatch' or identity['uid']!=0 or identity['nlink']!=1 or identity['mode']&0o7022:raise ValueError('File is outside the protected quarantine scope')
    chain=plan['ancestors']
    if not isinstance(chain,list) or not 1<=len(chain)<=32 or len(chain)!=len(PurePosixPath(path).parent.parts):raise ValueError('Invalid response ancestor chain')
    for info in chain:
        if not isinstance(info,dict) or set(info)!={'dev','ino','uid','gid','mode'} or any(type(v) is not int or v<0 for v in info.values()) or info['uid']!=0 or info['mode']&0o022 or not stat.S_ISDIR(info['mode']):raise ValueError('Unsafe response ancestor metadata')
    if {k:chain[-1][k] for k in ('dev','ino')}!=snapshot['parent']:raise ValueError('Response parent identity mismatch')
    attrs=plan['xattrs']
    if not isinstance(attrs,dict) or len(attrs)>32 or any(not isinstance(k,str) or len(k)>255 or k in ('security.capability','system.posix_acl_access') or not isinstance(v,str) or not re.fullmatch('[a-f0-9]{64}',v) for k,v in attrs.items()):raise ValueError('Unsafe response extended attributes')
    if type(plan['vault_device']) is not int or plan['vault_device']!=identity['dev']:raise ValueError('Response requires a matching vault filesystem')


def acquired(s,host,archive_id):
    archive=s.get(EvidenceArchive,archive_id)
    if not archive or archive.host_id!=host.id or archive.fingerprint!=host.fingerprint:raise ValueError('Same-host pinned evidence acquisition is required')
    copy=s.get(EvidenceCopy,archive.copy_id)
    if not copy or copy.host_id!=host.id or copy.snapshot!=archive.snapshot:raise ValueError('Preservation evidence changed')
    if evidence_archive.verify(archive)!='verified':raise ValueError('Verify an intact controller evidence archive before quarantine')
    return archive,copy


def healthy(s,host):
    from . import agent_maintenance
    if not host.baseline:raise ValueError('Finish and verify the reviewed agent installation before file response')
    if agent_maintenance.inspect(s,host,queue=False)['state']!='current':raise ValueError('Fresh independent agent verification failed; review Agent health and target console')


def reject_unstarted(s,job):
    row=s.get(Quarantine,job.payload.get('quarantine_id'))
    if row and row.host_id==job.host_id and row.state in ('queued','restore_queued'):
        approval=s.get(Approval,row.approval_id)
        row.state='rejected' if row.state=='queued' else (approval.before_state if approval else 'uncertain')
        row.hold=approval.before_hold if approval else True
        event(s,row,'rejected',approval.actor if approval else 'system',{'job_id':job.id})


def execute(s,host,job):
    if job.action=='quarantine-prepare':
        archive,copy=acquired(s,host,job.payload['archive_id'])
        current=incident(s,host.id,copy.incident_id)
        if incidents.digest(current.evidence)!=job.payload['evidence_digest'] or copy.evidence_digest!=job.payload['evidence_digest']:raise ValueError('Incident evidence changed before response preparation')
        healthy(s,host)
        plan=ssh.call(host,{'action':'quarantine-prepare','snapshot':archive.snapshot},timeout=90)
        validate_plan(plan,archive.snapshot)
        row=Quarantine(id=str(uuid.uuid4()),host_id=host.id,incident_id=current.id,archive_id=archive.id,fingerprint=host.fingerprint,evidence_digest=copy.evidence_digest,plan=plan)
        s.add(row);event(s,row,'prepared',job.payload['_actor'])
        return {'id':row.id,'state':'prepared','execution':'separate_quarantine_approval_required'}
    row=s.get(Quarantine,job.payload['quarantine_id'])
    if not row or row.host_id!=host.id or row.fingerprint!=host.fingerprint:raise ValueError('Response identity or pinned host changed; review target console')
    request={'action':job.action,'id':row.id,'plan':row.plan}
    actor=job.payload.get('_actor','system')
    if job.action!='quarantine-status':
        approval=s.get(Approval,row.approval_id)
        action='restore' if job.action=='quarantine-restore' else 'quarantine'
        if not approval or approval.quarantine_id!=row.id or approval.action!=action or approval.plan_digest!=incidents.digest(row.plan) or time.time()>=approval.expires or row.state!=('restore_queued' if action=='restore' else 'queued'):raise ValueError('Typed response approval expired or changed')
        healthy(s,host)
        if action=='quarantine':
            archive,copy=acquired(s,host,row.archive_id)
            current=incident(s,host.id,row.incident_id)
            if archive.snapshot!=row.plan['file'] or incidents.digest(current.evidence)!=row.evidence_digest:raise ValueError('Acquired evidence or incident changed before quarantine')
        if time.time()>=approval.expires:raise ValueError('Response approval expired during preflight; no mutation requested')
        request['approval']={'id':approval.id,'action':action,'expires':approval.expires,'actor':approval.actor,'reason':approval.reason}
        actor=approval.actor;row.state='uncertain';row.hold=True
        event(s,row,'restore_started' if action=='restore' else 'quarantine_started',actor,{'job_id':job.id});s.commit()
    try:
        if job.action=='quarantine-status':healthy(s,host)
        receipt=ssh.call(host,request,timeout=300)
        states=('quarantined','restored','not_moved','uncertain','not_found')
        if not isinstance(receipt,dict) or set(receipt)!={'id','plan','state','restore_ready','restore_attempted'} or receipt['id']!=row.id or receipt['plan']!=row.plan or receipt['state'] not in states or type(receipt['restore_ready']) is not bool or type(receipt['restore_attempted']) is not bool:raise ValueError('Unsupported or mismatched response receipt')
        if receipt['restore_ready'] and (receipt['restore_attempted'] or receipt['state'] not in ('quarantined','uncertain')):raise ValueError('Contradictory restoration receipt')
        if (receipt['state']=='quarantined' and not receipt['restore_ready']) or (receipt['state']=='restored' and not receipt['restore_attempted']) or (receipt['state'] in ('not_moved','not_found') and (receipt['restore_ready'] or receipt['restore_attempted'])):raise ValueError('Contradictory response completion receipt')
        row.state=receipt['state'];row.receipt=receipt;row.observed=time.time()
        if row.state in ('restored','not_moved'):row.hold=False
        elif row.state in ('uncertain','not_found'):row.hold=True
        event(s,row,'observed_'+row.state,actor,{'job_id':job.id,'receipt':receipt})
        expected='restored' if job.action=='quarantine-restore' else 'quarantined'
        incomplete=job.action!='quarantine-status' and row.state!=expected
        return {'id':row.id,'state':row.state,'server_changes_paused':row.hold,'outcome':'response_incomplete' if incomplete else 'observed'}
    except Exception:
        s.rollback();row=s.get(Quarantine,row.id)
        row.state='uncertain';row.hold=True;row.receipt={};row.observed=time.time()
        event(s,row,'observation_failed',actor,{'job_id':job.id});s.commit()
        raise
