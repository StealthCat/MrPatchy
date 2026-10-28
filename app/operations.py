"""Durable alert outbox, maintenance windows and operator exports."""
import datetime
import hashlib
import json
import time
import uuid
import httpx
from sqlalchemy import String,Text,Double,JSON,select,func
from sqlalchemy.orm import Mapped,mapped_column
from .db import Base,Session,Setting,Host,Package,Job,Audit,config
from .security import unseal

class Alert(Base):
    __tablename__='alerts'
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    kind:Mapped[str]=mapped_column(String(40))
    message:Mapped[str]=mapped_column(Text)
    state:Mapped[str]=mapped_column(String(20),default='open')
    created:Mapped[float]=mapped_column(Double,default=time.time)
    notified:Mapped[float]=mapped_column(Double,default=0)
    attempted:Mapped[float]=mapped_column(Double,default=0)
    attempts:Mapped[int]=mapped_column(default=0)
    error:Mapped[str]=mapped_column(Text,default='')

def in_window(windows,now=None):
    if not windows:return True
    date=datetime.datetime.fromtimestamp(time.time() if now is None else now,datetime.timezone.utc)
    minute=date.hour*60+date.minute
    return any(date.weekday() in w['days'] and w['start']<=minute<w['end'] for w in windows)

QUARANTINE_STATES=('running','recovery_required')

def host_quarantined(s,host_id,exclude=None,response_id=None,local_observation=False,process_id=None,read_only_response_id=None):
    query=select(Job.id).where(Job.host_id==host_id,Job.state.in_(QUARANTINE_STATES))
    if exclude:query=query.where(Job.id!=exclude)
    if s.scalar(query.limit(1)) is not None:return True
    if local_observation:return False
    from .quarantine import Quarantine
    holds=select(Quarantine.id).where(Quarantine.host_id==host_id,Quarantine.hold==True)
    if response_id:holds=holds.where(Quarantine.id!=response_id)
    if s.scalar(holds.limit(1)) is not None:return True
    from .process_response import ProcessResponse
    processes=select(ProcessResponse.id).where(ProcessResponse.host_id==host_id,ProcessResponse.hold==True)
    if process_id:processes=processes.where(ProcessResponse.id!=process_id)
    # Only the repair-preparation read uses this scope: related process holds
    # remain active and no mutation/recovery job inherits this exemption.
    if read_only_response_id:processes=processes.where(ProcessResponse.quarantine_id!=read_only_response_id)
    return s.scalar(processes.limit(1)) is not None

def recovery_policy(s,host_id):
    row=s.get(Setting,'recovery:'+host_id)
    return {name:bool(row and row.value.get(name)) for name in ('reboot','rollback')}

def eligible(s,job):
    if job.payload.get('_schedule'):
        from .scheduling import job_guard
        return job_guard(s,job)
    if job.action not in ('patch','repair','release-upgrade'): return True
    dependencies=job.payload.get('_depends_on',[])
    for dep in dependencies:
        previous=s.get(Job,dep)
        if not previous or previous.state in ('failed','blocked','interrupted','cancelled'):
            job.state='blocked';job.output='Canary/dependency did not complete successfully';s.commit();return False
        if previous.state=='recovery_required':
            job.state='blocked';job.output='Canary requires recovery reconciliation';s.commit();return False
        if previous.state!='complete':return False
    row=s.get(Setting,'window:'+job.host_id)
    return in_window(row.value['windows'] if row else [])

def collect_alerts():
    with Session() as s:
        now=time.time();cfg=config(s);active=set()
        def record(host,kind,message):
            key=hashlib.sha256((host.id+kind).encode()).hexdigest();active.add(key)
            alert=s.get(Alert,key)
            if not alert:s.add(Alert(id=key,host_id=host.id,kind=kind,message=message))
            else:
                alert.message=message
                if alert.state=='resolved':alert.state='open';alert.notified=0;alert.attempts=0;alert.attempted=0;alert.created=now
        from .scheduling import PatchRun
        for host in s.scalars(select(Host)):
            from . import response_monitor
            monitored=response_monitor.assessment(s,host.id)
            if monitored['problem_count']:
                record(host,'response integrity',str(monitored['problem_count'])+' retained response(s) have unresolved verification problems. Review Security: '+', '.join(r['id']+' '+r['state'] for r in monitored['problems']))
            if monitored['policy']['enabled'] and (monitored['overdue_count'] or monitored['scope_limited']):
                record(host,'response verification',str(monitored['overdue_count'])+' retained response(s) lack timely positive verification. '+('The 500-response monitoring scope limit was reached. ' if monitored['scope_limited'] else '')+'Review Security monitoring, pending jobs and agent health; missing verification is not a clean-host verdict.')
            from .quarantine import Quarantine
            response=s.scalar(select(Quarantine.id).where(Quarantine.host_id==host.id,Quarantine.hold==True).limit(1))
            if response:record(host,'file response hold','Server changes paused for reviewed file response '+response+'. Reconcile quarantine state or record reviewed console recovery in Security.')
            from .process_response import ProcessResponse
            process=s.scalar(select(ProcessResponse.id).where(ProcessResponse.host_id==host.id,ProcessResponse.hold==True).limit(1))
            if process:record(host,'process response hold','Server changes paused for process response '+process+'. Review suspension, recovery and affected services in Security.')
            failed_runs=s.scalar(select(func.count()).select_from(PatchRun).where(PatchRun.host_id==host.id,PatchRun.state.in_(('failed','blocked','skipped')),PatchRun.due>now-86400))
            if failed_runs:record(host,'scheduled patching',str(failed_runs)+' scheduled run(s) failed, were blocked, or missed their start window in the last 24 hours. Review Patch schedules and Activity.')
            recovery=list(s.scalars(select(Job.id).where(Job.host_id==host.id,Job.state=='recovery_required')))
            if recovery:record(host,'recovery',str(len(recovery))+' operation(s) require console recovery/reconciliation. See Activity: '+', '.join(recovery[:10]))
            if host.state=='enrolling':continue
            if now-host.last_seen>120:record(host,'stale','Telemetry has not arrived within 120 seconds')
            if host.integrity:record(host,'integrity',json.dumps(host.integrity)[:8000])
            agent=s.get(Setting,'agent-status:'+host.id)
            if agent and agent.value.get('state') not in ('current','outdated'):
                record(host,'agent health','Independent agent verification '+str(agent.value.get('state'))+'. Review Agent health; telemetry ingestion may be paused.')
            if s.get(Setting,'persistence-baseline:'+host.id):
                from . import persistence
                assessment=persistence.status(s,host.id)
                if assessment['state']!='matches':
                    record(host,'startup baseline','Startup inventory '+assessment['state']+' against the reviewed baseline. Review File integrity; differences are not a malware verdict.')
            if host.repo_error:record(host,'repository',host.repo_error[:8000])
            overdue=s.scalar(select(func.count()).select_from(Package).where(Package.host_id==host.id,Package.candidate!='',Package.available_since>0,
                Package.available_since<now- min(cfg['deadlines'].values())*3600))
            if overdue:
                count=sum(now>p.available_since+cfg['deadlines'][p.priority]*3600 for p in s.scalars(select(Package).where(Package.host_id==host.id,Package.candidate!='')))
                if count:record(host,'overdue',str(count)+' packages passed their deadline')
        for alert in s.scalars(select(Alert).where(Alert.state!='resolved')):
            if alert.id not in active:alert.state='resolved'
        s.commit()

def deliver_one():
    # Administrators explicitly configure/enable delivery. Never send in tests.
    with Session() as s:
        setting=s.get(Setting,'notifications')
        if not setting:return
        cfg=json.loads(unseal(setting.value['encrypted']))
        if not cfg.get('enabled'):return
        alert=next((row for row in s.scalars(select(Alert).where(Alert.state=='open',Alert.notified==0).order_by(Alert.attempted).limit(200)) if time.time()-row.attempted>=min(3600,30*2**min(row.attempts,7))),None)
        if not alert:return
        alert.attempted=time.time();alert.attempts+=1;s.commit()
        try:
            if cfg.get('channel')=='smtp':
                from .mail import send
                send(cfg,alert)
            else:
                response=httpx.post(cfg['url'],headers={'Authorization':'Bearer '+cfg['token']} if cfg.get('token') else {},
                json={'id':alert.id,'event_id':hashlib.sha256((alert.id+str(alert.created)).encode()).hexdigest(),'host_id':alert.host_id,'kind':alert.kind,'message':alert.message,'created':alert.created},timeout=10,follow_redirects=False)
                response.raise_for_status()
            alert.notified=time.time();alert.error=''
        except Exception as e:alert.error=type(e).__name__
        s.commit()


def failed_unit_names(health):
    """Normalize legacy systemctl tables and structured lists; reject uncertain data."""
    import re
    if not isinstance(health,dict) or type(health.get('collector_active')) is not bool:
        raise ValueError('Unable to verify collector health')
    raw=health.get('failed_units')
    if isinstance(raw,str):rows=raw.splitlines()
    elif isinstance(raw,list):rows=raw
    else:raise ValueError('Unable to verify failed-unit health')
    if len(rows)>4096:raise ValueError('Failed-unit health exceeds limit')
    names=set()
    for row in rows:
        if not isinstance(row,str):raise ValueError('Invalid failed-unit health entry')
        if not row.strip():continue
        parts=row.split()
        if len(parts)!=1 and (len(parts)<4 or parts[2]!='failed'):
            raise ValueError('Unrecognized failed-unit health output')
        name=parts[0]
        if len(name)>255 or not re.fullmatch(r'[A-Za-z0-9_.:@\\-]+\.(?:service|socket|target|device|mount|automount|swap|timer|path|slice|scope)',name):
            raise ValueError('Invalid failed-unit name')
        names.add(name)
    return names


def patch_health_comparison(before,after):
    previous=failed_unit_names(before);current=failed_unit_names(after)
    if before['collector_active'] is not True:raise ValueError('Collector was inactive before patching')
    return {'new_failed_units':sorted(current-previous),'pre_existing_failed_units':sorted(previous),
            'remaining_failed_units':sorted(current),'recovered_units':sorted(previous-current),
            'collector_active':after['collector_active'],
            'passed':not (current-previous) and after['collector_active'] is True}
