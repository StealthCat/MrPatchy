"""Append-only, metadata-only observations of references to a retained inode."""
import time
from sqlalchemy import String,Double,JSON,Index
from sqlalchemy.orm import Mapped,mapped_column
from .db import Base
from . import incidents,quarantine,ssh,latest_records

STATES=('quarantined','uncertain','not_found','console_recovered','replaced','replacement_uncertain')
GAPS=('entry_limit','process_limit','match_limit','time_limit','procfs_unavailable',
      'executable_unavailable','descriptor_unavailable','memory_map_unavailable',
      'reference_disappeared','unexpected_entry','process_changed','process_unavailable')


class Observation(Base):
    __tablename__='security_response_process_observations'
    __table_args__=(Index('ix_response_process_q_created','quarantine_id','created'),)
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    quarantine_id:Mapped[str]=mapped_column(String(36),index=True)
    created:Mapped[float]=mapped_column(Double,default=time.time)
    actor:Mapped[str]=mapped_column(String(120))
    state:Mapped[str]=mapped_column(String(30))
    report:Mapped[dict]=mapped_column(JSON)


def latest(s,rows):
    if not rows:return {}
    host_id=rows[0].host_id;ids=[r.id for r in rows]
    return latest_records.latest_by(s,Observation,'quarantine_id',ids,Observation.host_id==host_id)


def valid(host,row,payload):
    return bool(row and row.host_id==host.id and row.state in STATES
        and row.fingerprint==host.fingerprint==payload.get('fingerprint')
        and incidents.digest(row.plan)==payload.get('plan_digest'))


def integer(value,minimum=0,maximum=2**64-1):
    return type(value) is int and minimum<=value<=maximum


def validate(report,row):
    import re
    if not isinstance(report,dict) or set(report)!={'version','id','plan_digest','state','held_verified','observation'} or type(report['version']) is not int or report['version']!=1 or report['id']!=row.id or report['plan_digest']!=incidents.digest(row.plan) or report['state'] not in ('references_found','none_observed','unavailable') or type(report['held_verified']) is not bool:
        raise ValueError('Unsupported process reference report')
    observation=report['observation']
    if observation is None:
        if report['state']!='unavailable' or report['held_verified']:raise ValueError('Unbound process reference observation')
        return
    if not report['held_verified'] or not isinstance(observation,dict) or set(observation)!={'scope','boot_id','pid_namespace','observer_pid','processes_examined','entries_examined','matches','gaps'} or observation['scope']!='helper_visible_process_leaders':raise ValueError('Invalid process observation scope')
    boot=observation['boot_id'];namespace=observation['pid_namespace']
    if boot is not None and (not isinstance(boot,str) or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',boot)):raise ValueError('Invalid boot identity')
    observer=observation['observer_pid']
    if observer is not None and not integer(observer,1):raise ValueError('Invalid observer PID')
    if namespace is not None and not integer(namespace,1):raise ValueError('Invalid PID namespace')
    if not integer(observation['processes_examined'],0,4096) or not integer(observation['entries_examined'],0,50000):raise ValueError('Invalid process observation counts')
    gaps=observation['gaps'];matches=observation['matches']
    if not isinstance(gaps,dict) or any(k not in GAPS or not integer(v,1,100000) for k,v in gaps.items()):raise ValueError('Invalid process observation gaps')
    if not isinstance(matches,list) or len(matches)>min(128,observation['processes_examined']):raise ValueError('Invalid process observation matches')
    seen=set()
    for match in matches:
        if not isinstance(match,dict) or set(match)!={'pid','start_ticks','pid_namespace','references'} or not integer(match['pid'],1) or not integer(match['start_ticks'],0) or not integer(match['pid_namespace'],1) or match['pid'] in seen or match['pid']==observer:raise ValueError('Invalid process reference identity')
        seen.add(match['pid']);refs=match['references']
        if not isinstance(refs,dict) or not refs or any(k not in ('executable','descriptor','memory_map') or not integer(v,1,50000) for k,v in refs.items()) or refs.get('executable',1)!=1:raise ValueError('Invalid process reference kinds')
    expected=('references_found' if matches else 'none_observed') if boot and namespace and observer and (matches or 'procfs_unavailable' not in gaps) else 'unavailable'
    if report['state']!=expected or (expected=='unavailable' and not gaps):raise ValueError('Contradictory process reference outcome')


def execute(s,host,job):
    existing=s.get(Observation,job.id)
    if existing:return {'observation_id':existing.id,'state':existing.state}
    payload=job.payload;row=s.get(quarantine.Quarantine,payload['quarantine_id']);stage='helper'
    report=None;failure=None
    if valid(host,row,payload):
        try:
            quarantine.healthy(s,host)
            # Independent verification may be slow. End MySQL snapshots before
            # rechecking pins/scope and before retaining the final observation.
            s.rollback();s.expire_all();row=s.get(quarantine.Quarantine,payload['quarantine_id'])
            if valid(host,row,payload):
                stage='remote'
                report=ssh.call(host,{'action':'quarantine-processes','id':row.id,'plan':row.plan},timeout=120)
                stage='protocol';validate(report,row)
        except Exception as error:
            report=None;failure={'stage':stage,'type':type(error).__name__}
    s.rollback();s.expire_all();row=s.get(quarantine.Quarantine,payload['quarantine_id'])
    if not row or row.host_id!=host.id:raise ValueError('Response removed during process observation')
    current=valid(host,row,payload)
    state=report['state'] if report else ('unavailable' if failure else 'skipped')
    summary={'version':1,'plan_digest':payload['plan_digest'],'fingerprint':payload['fingerprint'],
             'scope_current':current,'held_verified':report['held_verified'] if report else False,
             'observation':report['observation'] if report else None,'failure':failure}
    s.add(Observation(id=job.id,host_id=host.id,quarantine_id=row.id,actor=payload.get('_actor','system'),state=state,report=summary))
    quarantine.event(s,row,'process_references_observed',payload.get('_actor','system'),{'observation_id':job.id,'state':state})
    # An observation never changes the hold, restoration readiness or incident.
    return {'observation_id':job.id,'state':state,'outcome':'response_incomplete' if state=='unavailable' else 'observed'}
