"""Separately approved process suspension/recovery with durable host holds."""
import time
import uuid
from sqlalchemy import String,Double,Boolean,JSON,Text
from sqlalchemy.orm import Mapped,mapped_column
from .db import Base,audit
from . import quarantine,response_processes,incidents,ssh,response_rejection,response_status

ACTIONS=('process-prepare','process-suspend','process-status','process-resume')
RECOVERY_ACTIONS=('process-suspend','process-status','process-resume')


class ProcessResponse(Base):
    __tablename__='security_process_responses'
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    quarantine_id:Mapped[str]=mapped_column(String(36),index=True)
    observation_id:Mapped[str]=mapped_column(String(36))
    created:Mapped[float]=mapped_column(Double,default=time.time)
    state:Mapped[str]=mapped_column(String(30),default='prepared')
    hold:Mapped[bool]=mapped_column(Boolean,default=False)
    fingerprint:Mapped[str]=mapped_column(String(100))
    plan:Mapped[dict]=mapped_column(JSON)
    receipt:Mapped[dict]=mapped_column(JSON,default=dict)
    observed:Mapped[float]=mapped_column(Double,default=0)
    approval_id:Mapped[str]=mapped_column(String(36),default='')


class Approval(Base):
    __tablename__='security_process_approvals'
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    process_id:Mapped[str]=mapped_column(String(36),index=True)
    action:Mapped[str]=mapped_column(String(30))
    created:Mapped[float]=mapped_column(Double,default=time.time)
    expires:Mapped[float]=mapped_column(Double)
    plan_digest:Mapped[str]=mapped_column(String(64))
    actor:Mapped[str]=mapped_column(String(120))
    reason:Mapped[str]=mapped_column(Text)
    before_state:Mapped[str]=mapped_column(String(30))
    before_hold:Mapped[bool]=mapped_column(Boolean)


class Event(Base):
    __tablename__='security_process_events'
    id:Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid.uuid4()))
    process_id:Mapped[str]=mapped_column(String(36),index=True)
    created:Mapped[float]=mapped_column(Double,default=time.time)
    kind:Mapped[str]=mapped_column(String(40))
    actor:Mapped[str]=mapped_column(String(120))
    details:Mapped[dict]=mapped_column(JSON,default=dict)


def event(s,row,kind,actor,details=None):
    s.add(Event(process_id=row.id,kind=kind,actor=actor,details=details or {}))
    audit(s,'process response '+kind,row.host_id+' '+row.id+' '+actor)


def source(s,host,payload):
    row=s.get(quarantine.Quarantine,payload['quarantine_id'])
    observation=s.get(response_processes.Observation,payload['observation_id'])
    if not row or row.host_id!=host.id or row.state not in ('quarantined','replaced') or row.fingerprint!=host.fingerprint or host.fingerprint!=payload['fingerprint'] or incidents.digest(row.plan)!=payload['plan_digest']:raise ValueError('Retained file response or pinned host changed')
    if not observation or observation.host_id!=host.id or observation.quarantine_id!=row.id or observation.state!='references_found' or not 0<=time.time()-observation.created<=300:raise ValueError('Fresh same-host process reference evidence is required')
    report=observation.report;observed=report.get('observation') or {}
    if not report.get('held_verified') or not report.get('scope_current') or report.get('fingerprint')!=host.fingerprint or report.get('plan_digest')!=payload['plan_digest']:raise ValueError('Process evidence binding changed')
    match=next((m for m in observed.get('matches',[]) if m.get('pid')==payload['pid'] and m.get('references',{}).get('executable')==1),None)
    if not match:raise ValueError('Select a process whose executable references the retained original')
    return row,observed,{k:match[k] for k in ('pid','start_ticks','pid_namespace')}


def validate_plan(plan,row,observed,expected):
    if not isinstance(plan,dict) or set(plan)!={'version','quarantine_id','quarantine_plan','process','boot_id','pid_namespace'} or type(plan['version']) is not int or plan['version']!=1 or plan['quarantine_id']!=row.id or plan['quarantine_plan']!=row.plan or plan['boot_id']!=observed['boot_id'] or plan['pid_namespace']!=observed['pid_namespace']:raise ValueError('Unbound process response preparation')
    process=plan['process']
    if not isinstance(process,dict) or set(process)!={*expected,'proc_device','proc_inode'} or any(process[k]!=v for k,v in expected.items()) or any(not response_processes.integer(v,1) for v in process.values()) or process['pid']<=1:raise ValueError('Invalid prepared process identity')


def bound(s,host,row):
    response=s.get(quarantine.Quarantine,row.quarantine_id)
    return bool(row.host_id==host.id and row.fingerprint==host.fingerprint and response and response.host_id==host.id and response.fingerprint==host.fingerprint and row.plan.get('quarantine_id')==response.id and row.plan.get('quarantine_plan')==response.plan)


def validate_receipt(receipt,row):
    if not isinstance(receipt,dict) or set(receipt)!={'id','plan_digest','state','resume_ready','resume_attempted','threads'} or receipt['id']!=row.id or receipt['plan_digest']!=incidents.digest(row.plan) or receipt['state'] not in ('suspended','resumed','exited','identity_changed','uncertain','not_started') or any(type(receipt[k]) is not bool for k in ('resume_ready','resume_attempted')) or not response_processes.integer(receipt['threads'],0,256):raise ValueError('Unsupported process response receipt')
    state=receipt['state']
    if receipt['resume_ready']!=(state=='suspended') or (state=='suspended' and (receipt['resume_attempted'] or not receipt['threads'])) or (state=='resumed' and (not receipt['resume_attempted'] or not receipt['threads'])) or (state=='not_started' and (receipt['resume_attempted'] or receipt['threads'])):raise ValueError('Contradictory process response receipt')


def reject_unstarted(s,job):
    response_rejection.reject_unstarted(s,job,model=ProcessResponse,approval_model=Approval,
        payload_key='process_id',recovery_state='resume_queued',event=event,actor_from_approval=False)


def execute(s,host,job):
    payload=job.payload;actor=payload.get('_actor','system')
    if job.action=='process-prepare':
        response,observation,expected=source(s,host,payload)
        quarantine.healthy(s,host)
        s.rollback();s.expire_all();response,observation,expected=source(s,host,payload)
        plan=ssh.call(host,{'action':'process-prepare','quarantine_id':response.id,'quarantine_plan':response.plan,'expected':expected,'boot_id':observation['boot_id'],'pid_namespace':observation['pid_namespace']},timeout=120)
        s.rollback();s.expire_all();response,observation,expected=source(s,host,payload)
        validate_plan(plan,response,observation,expected)
        row=ProcessResponse(id=str(uuid.uuid4()),host_id=host.id,quarantine_id=response.id,observation_id=payload['observation_id'],fingerprint=host.fingerprint,plan=plan)
        s.add(row);event(s,row,'prepared',actor)
        return {'id':row.id,'state':'prepared','execution':'separate_suspend_approval_required'}
    row=s.get(ProcessResponse,payload['process_id'])
    if not row or row.host_id!=host.id:raise ValueError('Process response not found')
    started=False;status=job.action=='process-status';action='resume' if job.action=='process-resume' else 'suspend'
    try:
        if not bound(s,host,row):raise ValueError('Process response or pinned host changed; review console')
        quarantine.healthy(s,host)
        s.rollback();s.expire_all();row=s.get(ProcessResponse,payload['process_id'])
        if not row or not bound(s,host,row):raise ValueError('Process response changed during helper verification')
        request={'action':job.action,'id':row.id,'plan':row.plan};digest=incidents.digest(row.plan)
        if not status:
            approval=s.get(Approval,row.approval_id)
            if not approval or approval.process_id!=row.id or approval.action!=action or approval.plan_digest!=digest or row.state!=('resume_queued' if action=='resume' else 'queued') or time.time()>=approval.expires:raise ValueError('Process approval expired or changed')
            request['approval']={'id':approval.id,'action':action,'expires':approval.expires,'actor':approval.actor,'reason':approval.reason}
            row.state='uncertain';row.hold=True;event(s,row,action+'_started',actor,{'job_id':job.id});s.commit();started=True
        receipt=ssh.call(host,request,timeout=150);validate_receipt(receipt,row)
        s.rollback();s.expire_all();row=s.get(ProcessResponse,payload['process_id'])
        if not row or not bound(s,host,row) or incidents.digest(row.plan)!=digest:raise ValueError('Process scope changed during remote response; review console')
        row.receipt=receipt;row.observed=time.time();row.state=receipt['state'];row.hold=row.state!='resumed'
        if receipt['state']=='not_started':
            approval=s.get(Approval,row.approval_id)
            if approval and approval.process_id==row.id and approval.plan_digest==digest:row.state=approval.before_state;row.hold=approval.before_hold
        event(s,row,'observed_'+receipt['state'],actor,{'job_id':job.id,'receipt':receipt})
        incomplete=not status and row.state!=('resumed' if action=='resume' else 'suspended')
        return {'id':row.id,'state':row.state,'process_hold':row.hold,'outcome':'response_incomplete' if incomplete else 'observed'}
    except Exception:
        if started or status:
            s.rollback();row=s.get(ProcessResponse,payload['process_id'])
            if row and row.host_id==host.id:
                response_status.mark_status_failed(s,row,actor,job.id,event=event,clock=time.time);s.commit()
        raise
