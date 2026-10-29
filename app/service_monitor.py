"""Opt-in service observations with revision-bound policy and independent pauses."""
from . import host_lifecycle
import time
import uuid
from sqlalchemy import String,Double,JSON,Text,Boolean,Integer,select,func
from sqlalchemy.orm import Mapped,mapped_column
from .db import Base,Session,Host,Job
from . import incidents,quarantine,response_health,repair_publication

LIMIT=500
DEFAULT={'enabled':False,'interval_minutes':15,'pause_on_problem':False,'revision':'','baseline_id':'','baseline_digest':'','units':[],'binding':{},'hold':False,'last_attempt':0,'last_observation_id':'','last_state':'not_checked','last_observed':0}


class Watch(Base):
    __tablename__='security_service_watches'
    id:Mapped[str]=mapped_column(String(36),primary_key=True) # Owning quarantine ID
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    created:Mapped[float]=mapped_column(Double,default=time.time)
    updated:Mapped[float]=mapped_column(Double,default=time.time)
    actor:Mapped[str]=mapped_column(String(120))
    reason:Mapped[str]=mapped_column(Text)
    revision:Mapped[str]=mapped_column(String(36))
    enabled:Mapped[bool]=mapped_column(Boolean,default=False)
    interval_minutes:Mapped[int]=mapped_column(Integer,default=15)
    pause_on_problem:Mapped[bool]=mapped_column(Boolean,default=False)
    baseline_id:Mapped[str]=mapped_column(String(36),default='')
    baseline_digest:Mapped[str]=mapped_column(String(64),default='')
    units:Mapped[list]=mapped_column(JSON,default=list)
    binding:Mapped[dict]=mapped_column(JSON,default=dict)
    hold:Mapped[bool]=mapped_column(Boolean,default=False)
    last_attempt:Mapped[float]=mapped_column(Double,default=0)
    last_observation_id:Mapped[str]=mapped_column(String(36),default='')
    last_state:Mapped[str]=mapped_column(String(30),default='not_checked')
    last_observed:Mapped[float]=mapped_column(Double,default=0)


def view(watch):
    return {column.name:getattr(watch,column.name) for column in Watch.__table__.columns} if watch else dict(DEFAULT)


def baseline_matches(watch,observation):
    try:
        report=observation.report
        return bool(observation.host_id==watch.host_id and observation.quarantine_id==watch.id and observation.state=='healthy'
            and report.get('scope_current') and not report.get('scheduled') and report.get('units')==watch.units
            and incidents.digest(report)==watch.baseline_digest
            and all(report.get(key)==value for key,value in watch.binding.items())
            and report['target']['state']=='healthy')
    except (AttributeError,KeyError,TypeError):return False


def scope(host,row,publication=None):
    return {'fingerprint':host.fingerprint,'plan_digest':incidents.digest(row.plan),'response_state':row.state,
            'publication_id':publication.id if publication else '',
            'publication_plan_digest':incidents.digest(publication.plan) if publication else ''}


def current(s,host,row,watch):
    if not host or not row or not watch or row.host_id!=host.id or watch.host_id!=host.id or watch.id!=row.id or row.fingerprint!=host.fingerprint:return False
    return watch.binding==response_health.binding(s,host,row) and row.state not in ('queued','restore_queued') and baseline_matches(watch,s.get(response_health.Observation,watch.baseline_id))


def valid(s,host,row,payload):
    watch=s.get(Watch,payload.get('quarantine_id'))
    return bool(watch and watch.enabled and watch.revision==payload.get('service_watch_revision') and current(s,host,row,watch)
        and watch.units==payload.get('units') and watch.baseline_id==payload.get('baseline_id') and watch.baseline_digest==payload.get('baseline_digest')
        and all(payload.get(key)==value for key,value in watch.binding.items()))


def save(s,host,row,body,actor):
    watch=s.get(Watch,row.id)
    if watch and watch.host_id!=host.id:raise ValueError('Service watch host mismatch')
    if (watch.revision if watch else '')!=body.expected_revision:raise ValueError('Service watch changed; refresh before saving')
    reason=body.reason.strip()
    if len(reason)<10:raise ValueError('Provide a meaningful service watch reason')
    previous=None
    if body.enabled:
        previous=s.get(response_health.Observation,body.baseline_id)
        if not previous or not 0<=time.time()-previous.created<=300:raise ValueError('Select a manual healthy service observation no more than five minutes old')
        response_health.baseline(s,host,row,previous.id,previous.report['units'])
        if previous.state!='healthy' or previous.report.get('scheduled') or incidents.digest(previous.report)!=body.report_digest or not response_health.valid(s,host,row,previous.report):raise ValueError('A fresh healthy manual observation with unchanged response/publication scope is required')
        if watch and watch.hold and (watch.units!=previous.report['units'] or watch.binding!=response_health.binding(s,host,row)):raise ValueError('Review the existing service pause before changing its service selection or scope')
        if not watch or not watch.enabled:
            count=s.scalar(select(func.count()).select_from(Watch).where(Watch.host_id==host.id,Watch.enabled==True))
            if count>=LIMIT:raise ValueError('At most 500 service watches can be enabled per server')
    if not watch:
        watch=Watch(id=row.id,host_id=host.id,actor=actor,reason=reason,revision='',enabled=False,hold=False)
        s.add(watch);s.flush()
    if previous:
        watch.baseline_id=previous.id;watch.baseline_digest=incidents.digest(previous.report)
        watch.units=list(previous.report['units']);watch.binding=response_health.binding(s,host,row)
    watch.enabled=body.enabled;watch.interval_minutes=body.interval_minutes;watch.pause_on_problem=body.pause_on_problem
    watch.revision=str(uuid.uuid4());watch.updated=time.time();watch.actor=actor;watch.reason=reason
    watch.last_attempt=watch.updated;watch.last_observation_id='';watch.last_state='not_checked';watch.last_observed=0
    # Disabling/reconfiguring a policy never releases an existing service pause.
    quarantine.event(s,row,'service_watch_saved',actor,view(watch))
    return watch


def applied(s,host,row,job,observation):
    payload=job.payload
    if not valid(s,host,row,payload):return False
    watch=s.get(Watch,row.id)
    watch.last_observation_id=observation.id;watch.last_state=observation.state;watch.last_observed=time.time()
    watch.last_attempt=max(watch.last_attempt,job.created)
    pause=watch.pause_on_problem and observation.state in ('problem','unavailable')
    if pause:watch.hold=True
    quarantine.event(s,row,'service_watch_observed','system',{'observation_id':observation.id,'state':observation.state,'revision':watch.revision,'pause_on_problem':watch.pause_on_problem,'service_hold':watch.hold})
    return pause


def release(s,host,row,body,actor):
    watch=s.get(Watch,row.id);reason=body.reason.strip()
    if not watch or watch.host_id!=host.id or not watch.hold or watch.revision!=body.expected_revision:raise ValueError('Service pause or policy changed; refresh before reviewing')
    if len(reason)<10:raise ValueError('Provide a meaningful service pause review reason')
    if body.confirmation=='ACCEPT HEALTHY SERVICES':
        observed=s.get(response_health.Observation,body.observation_id)
        if not observed or observed.host_id!=host.id or observed.quarantine_id!=row.id or observed.state!='healthy' or not 0<=time.time()-observed.created<=300:raise ValueError('A healthy manual service check no more than five minutes old is required')
        report=observed.report
        if report.get('scheduled') or not report.get('scope_current') or report.get('units')!=watch.units or incidents.digest(report)!=body.report_digest or not response_health.valid(s,host,row,report):raise ValueError('Manual service observation, selected units or current scope changed')
        response_health.validate(report['target'],row,watch.units,report['plan_digest'])
        # Immutable history must not let an old positive bypass a newer known
        # negative. Different unit selections/scopes do not supersede this proof.
        negatives=list(s.scalars(select(response_health.Observation).where(response_health.Observation.host_id==host.id,
            response_health.Observation.quarantine_id==row.id,response_health.Observation.created>=observed.created,
            response_health.Observation.id!=observed.id,response_health.Observation.state.in_(('problem','unavailable')))
            .order_by(response_health.Observation.created.desc()).limit(1001)))
        if len(negatives)>1000:raise ValueError('Recent service history exceeds review limits; collect a new manual check')
        current_binding=response_health.binding(s,host,row)
        if any(item.report.get('scope_current') and item.report.get('units')==watch.units and all(item.report.get(key)==value for key,value in current_binding.items()) for item in negatives):raise ValueError('A newer negative service observation requires a new healthy manual check')
    elif body.confirmation!='CONSOLE REVIEWED':raise ValueError('Type ACCEPT HEALTHY SERVICES or CONSOLE REVIEWED after service review')
    watch.hold=False
    quarantine.event(s,row,'service_pause_reviewed',actor,{'revision':watch.revision,'reason':reason,'confirmation':body.confirmation,'observation_id':body.observation_id,'report_digest':body.report_digest})
    return watch


def assessment(s,host_id,now=None):
    now=time.time() if now is None else now
    watches=list(s.scalars(select(Watch).where(Watch.host_id==host_id,Watch.enabled==True).order_by(Watch.id).limit(LIMIT+1)))
    limited=len(watches)>LIMIT;watches=watches[:LIMIT];host=s.get(Host,host_id)
    ids=[watch.id for watch in watches]
    rows={row.id:row for row in s.scalars(select(quarantine.Quarantine).where(quarantine.Quarantine.host_id==host_id,quarantine.Quarantine.id.in_(ids)))} if ids else {}
    publications=repair_publication.latest(s,list(rows.values()))
    observations={item.id:item for item in s.scalars(select(response_health.Observation).where(response_health.Observation.host_id==host_id,response_health.Observation.id.in_([value for watch in watches for value in (watch.baseline_id,watch.last_observation_id)])))} if watches else {}
    latest=response_health.latest(s,list(rows.values()))
    problems=[];overdue=[];eligible=[];rotation=len(watches)*5
    for watch in watches:
        row=rows.get(watch.id)
        bound=bool(host and row and row.fingerprint==host.fingerprint and row.state not in ('queued','restore_queued') and watch.binding==scope(host,row,publications.get(row.id)) and baseline_matches(watch,observations.get(watch.baseline_id)))
        if not bound:
            problems.append({'id':watch.id,'state':'scope_changed'});overdue.append(watch.id);continue
        eligible.append(watch)
        candidates=[observations.get(watch.baseline_id),observations.get(watch.last_observation_id),latest.get(watch.id)]
        matching=[item for item in candidates if item and item.state in ('healthy','problem','unavailable') and item.report.get('scope_current') and item.report.get('units')==watch.units and all(item.report.get(key)==value for key,value in watch.binding.items()) and (not item.report.get('scheduled') or item.report.get('service_watch_revision')==watch.revision)]
        observed=max(matching,key=lambda item:(item.created,item.id)) if matching else None
        budget=(max(watch.interval_minutes,rotation)+5)*60
        if observed and observed.state!='healthy':problems.append({'id':watch.id,'state':observed.state})
        if not observed or observed.state!='healthy' or not 0<=now-observed.created<=budget:overdue.append(watch.id)
    return {'watched':len(watches),'rotation_minutes':rotation,'problem_count':len(problems),'problems':problems[:20],
            'overdue_count':len(overdue),'overdue':overdue[:20],'scope_limited':limited,'eligible':eligible}


def schedule_tick(now=None):
    from .coordination import Lock
    from .worker import enqueue,host_lock
    from . import operations
    now=time.time() if now is None else now
    with Lock('service-watch-queue'),Session() as s:
        host_ids=list(s.scalars(select(Watch.host_id).where(Watch.enabled==True).distinct()))
        for host_id in host_ids:
            lock=host_lock(host_id)
            if not lock.acquire(False):continue
            try:
                s.rollback();host=s.get(Host,host_id)
                if not host_lifecycle.active(host) or host.state=='enrolling' or not host.fingerprint or operations.host_quarantined(s,host_id):continue
                # Other queued work takes precedence. Automatic reads never get
                # the manual response-hold exemptions used for console review.
                if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.state=='queued').limit(1)):continue
                last=s.scalar(select(Job).where(Job.host_id==host_id,Job.action==response_health.ACTION,Job.payload['_service_watch'].as_boolean()==True).order_by(Job.created.desc()).limit(1))
                if last and now-last.payload.get('_service_scheduled_at',last.created)<300:continue
                status=assessment(s,host_id,now)
                candidates=[watch for watch in status['eligible'] if now-max(watch.updated,watch.last_attempt)>=watch.interval_minutes*60]
                if not candidates:continue
                watch=min(candidates,key=lambda value:(value.last_attempt,value.created,value.id))
                payload={'quarantine_id':watch.id,**watch.binding,'units':watch.units,'baseline_id':watch.baseline_id,'baseline_digest':watch.baseline_digest,
                         '_service_watch':True,'_service_scheduled_at':now,'service_watch_revision':watch.revision,'_actor':'system','reason':'Scheduled read-only service watch approved by '+watch.actor}
                try:enqueue(s,host_id,response_health.ACTION,payload)
                except ValueError:continue
                watch.last_attempt=now;s.commit()
            finally:lock.release()
