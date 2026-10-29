"""Immutable, explicitly requested service observations. No service mutations."""
import re
import time
from sqlalchemy import String,Double,JSON,Text,Index,select,func
from sqlalchemy.orm import Mapped,mapped_column
from .db import Base,Host
from . import incidents,quarantine,repair_publication,ssh
from target.agent import response_service_units,response_service_properties,response_service_state

ACTION='response-service-health'
GAPS=('boot_unavailable','boot_changed','time_limit','unit_unavailable','unit_changing')


class Observation(Base):
    __tablename__='security_response_service_observations'
    __table_args__=(Index('ix_response_service_q_created','quarantine_id','created'),)
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    quarantine_id:Mapped[str]=mapped_column(String(36),index=True)
    created:Mapped[float]=mapped_column(Double,default=time.time)
    actor:Mapped[str]=mapped_column(String(120))
    reason:Mapped[str]=mapped_column(Text)
    state:Mapped[str]=mapped_column(String(30))
    report:Mapped[dict]=mapped_column(JSON)


def latest(s,rows):
    if not rows:return {}
    ids=[row.id for row in rows];host_id=rows[0].host_id
    rank=select(Observation.id,func.row_number().over(partition_by=Observation.quarantine_id,order_by=(Observation.created.desc(),Observation.id)).label('rank')).where(Observation.host_id==host_id,Observation.quarantine_id.in_(ids)).subquery()
    return {row.quarantine_id:row for row in s.scalars(select(Observation).where(Observation.id.in_(select(rank.c.id).where(rank.c.rank==1))))}


def binding(s,host,row):
    current=repair_publication.active(s,row.id)
    return {'fingerprint':host.fingerprint,'plan_digest':incidents.digest(row.plan),'response_state':row.state,
            'publication_id':current.id if current else '',
            'publication_plan_digest':incidents.digest(current.plan) if current else ''}


def valid(s,host,row,payload):
    return bool(host and row and row.host_id==host.id and row.fingerprint==host.fingerprint
        and row.state not in ('queued','restore_queued')
        and all(payload.get(key)==value for key,value in binding(s,host,row).items()))


def validate(report,row,units,plan_digest):
    if (not isinstance(report,dict) or set(report)!={'version','id','plan_digest','units','boot_id','boot_rechecked','services','gaps','state'}
        or type(report['version']) is not int or report['version']!=1 or report['id']!=row.id or report['plan_digest']!=plan_digest or report['units']!=units
        or type(report['boot_rechecked']) is not bool or report['state'] not in ('healthy','problem','unavailable')):raise ValueError('Unbound service health report')
    response_service_units(report['units']);boot=report['boot_id'];gaps=report['gaps'];services=report['services']
    if boot is not None and (not isinstance(boot,str) or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',boot)):raise ValueError('Invalid service boot identity')
    if (not isinstance(gaps,list) or any(not isinstance(gap,str) or gap not in GAPS for gap in gaps) or len(gaps)!=len(set(gaps))
        or not isinstance(services,list) or len(services)!=len(units)):raise ValueError('Invalid service health coverage')
    expected_gaps=set()
    if boot is None:
        if report['boot_rechecked']:raise ValueError('Missing boot proof')
        expected_gaps.add('boot_unavailable')
    elif not report['boot_rechecked']:
        if not set(gaps).intersection(('boot_changed','boot_unavailable')):raise ValueError('Missing boot recheck gap')
        expected_gaps.update(set(gaps).intersection(('boot_changed','boot_unavailable')))
    for unit,item in zip(units,services):
        if not isinstance(item,dict) or set(item)!={'unit','before','after','state','failure'} or item['unit']!=unit:raise ValueError('Unbound service observation')
        before,after,failure=item['before'],item['after'],item['failure']
        for value in (before,after):
            if value is not None:response_service_properties(value)
        if failure is not None:
            if failure not in ('time_limit','invalid_properties','query_failed') or after is not None or item['state']!='unavailable':raise ValueError('Invalid service failure')
            expected_gaps.add('unit_unavailable')
            if failure=='time_limit':expected_gaps.add('time_limit')
        else:
            if before is None or after is None:raise ValueError('Missing service samples')
            expected='changing' if before!=after else response_service_state(after)
            if item['state']!=expected:raise ValueError('Contradictory service state')
            if expected=='changing':expected_gaps.add('unit_changing')
    if set(gaps)!=expected_gaps:raise ValueError('Contradictory service gaps')
    expected='unavailable' if gaps or not report['boot_rechecked'] else ('problem' if any(item['state']=='problem' for item in services) else 'healthy')
    if report['state']!=expected:raise ValueError('Contradictory service health outcome')


def baseline(s,host,row,identifier,units):
    previous=s.get(Observation,identifier) if identifier else None
    if not host or not previous or previous.host_id!=host.id or previous.quarantine_id!=row.id or previous.state not in ('healthy','problem'):
        raise ValueError('Select a complete same-response service observation as the comparison baseline')
    report=previous.report
    if not report.get('scope_current') or report.get('fingerprint')!=host.fingerprint or report.get('plan_digest')!=incidents.digest(row.plan) or report.get('units')!=units or not report.get('target'):
        raise ValueError('Baseline units, response scope or pinned host changed')
    validate(report['target'],row,units,report['plan_digest'])
    if previous.state!=report['target']['state']:raise ValueError('Baseline outcome changed')
    return previous


def comparison(previous,target):
    if not previous:return {'state':'not_requested','baseline_id':'','boot_changed':None,'changes':[]}
    if not target or target['state']=='unavailable':return {'state':'unavailable','baseline_id':previous.id,'boot_changed':None,'changes':[]}
    before={item['unit']:item['after'] for item in previous.report['target']['services']}
    changes=[]
    for item in target['services']:
        fields={key:{'before':before[item['unit']][key],'after':value} for key,value in item['after'].items() if before[item['unit']][key]!=value}
        if fields:changes.append({'unit':item['unit'],'fields':fields})
    return {'state':'compared','baseline_id':previous.id,'boot_changed':previous.report['target']['boot_id']!=target['boot_id'],'changes':changes}


def execute(s,host,job):
    existing=s.get(Observation,job.id)
    if existing:return {'observation_id':existing.id,'state':existing.state,'replayed':False}
    payload=job.payload;host_id=host.id;response_id=payload['quarantine_id'];target=None;failure=None;previous=None;phase='scope';started=time.time()
    scheduled=payload.get('_service_watch') is True
    from . import service_monitor
    try:
        response_service_units(payload['units'])
        row=s.get(quarantine.Quarantine,response_id)
        if not valid(s,host,row,payload):raise ValueError('Service observation scope changed')
        if scheduled and not service_monitor.valid(s,host,row,payload):raise ValueError('Scheduled service policy changed')
        if payload.get('baseline_id'):
            previous=baseline(s,host,row,payload['baseline_id'],payload['units'])
            if incidents.digest(previous.report)!=payload.get('baseline_digest'):raise ValueError('Selected baseline changed')
        phase='helper';quarantine.healthy(s,host)
        s.rollback();s.expire_all();host=s.get(Host,host_id);row=s.get(quarantine.Quarantine,response_id);phase='scope'
        if not valid(s,host,row,payload):raise ValueError('Service observation scope changed during helper verification')
        if scheduled and not service_monitor.valid(s,host,row,payload):raise ValueError('Scheduled service policy changed during helper verification')
        if payload.get('baseline_id'):
            previous=baseline(s,host,row,payload['baseline_id'],payload['units'])
            if incidents.digest(previous.report)!=payload.get('baseline_digest'):raise ValueError('Selected baseline changed during helper verification')
        phase='remote';target=ssh.call(host,{'action':ACTION,'id':row.id,'plan_digest':payload['plan_digest'],'units':payload['units']},timeout=120)
        phase='protocol';validate(target,row,payload['units'],payload['plan_digest'])
    except Exception as error:
        target=None;failure={'stage':phase,'type':type(error).__name__}
    s.rollback();s.expire_all();host=s.get(Host,host_id);row=s.get(quarantine.Quarantine,response_id)
    if not row or row.host_id!=host_id:raise ValueError('Response removed during service observation')
    policy_current=not scheduled or service_monitor.valid(s,host,row,payload)
    current=valid(s,host,row,payload) and policy_current
    # Recheck the baseline after I/O as well. A historical association must not
    # follow changed controller records into a new positive comparison.
    if payload.get('baseline_id'):
        try:
            previous=baseline(s,host,row,payload['baseline_id'],payload['units'])
            if incidents.digest(previous.report)!=payload.get('baseline_digest'):raise ValueError('Selected baseline changed')
        except ValueError:previous=None;current=False
    state=target['state'] if target and current else ('skipped' if not current or phase=='scope' else 'unavailable')
    compared=comparison(previous,target) if current else {'state':'unavailable','baseline_id':payload.get('baseline_id',''),'boot_changed':None,'changes':[]}
    report={'version':1,**{key:payload.get(key,'') for key in ('plan_digest','fingerprint','response_state','publication_id','publication_plan_digest')},
            'units':payload['units'],'scope_current':current,'target':target,'failure':failure,'comparison':compared,
            'started':started,'finished':time.time(),'baseline_digest':payload.get('baseline_digest',''),
            'scheduled':scheduled,'service_watch_revision':payload.get('service_watch_revision',''),'policy_current':policy_current}
    actor=payload.get('_actor','system')
    observation=Observation(id=job.id,host_id=host_id,quarantine_id=row.id,actor=actor,reason=payload['reason'],state=state,report=report)
    s.add(observation)
    if scheduled and current:observation.report={**report,'service_pause_added':service_monitor.applied(s,host,row,job,observation)}
    quarantine.event(s,row,'service_health_observed',actor,{'observation_id':job.id,'state':state,'scope_current':current,'reason':payload['reason']})
    return {'observation_id':job.id,'state':state,'outcome':'response_incomplete' if state=='unavailable' else 'observed'}
