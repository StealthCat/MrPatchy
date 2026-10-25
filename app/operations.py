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

def host_quarantined(s,host_id,exclude=None):
    query=select(Job.id).where(Job.host_id==host_id,Job.state.in_(QUARANTINE_STATES))
    if exclude:query=query.where(Job.id!=exclude)
    return s.scalar(query.limit(1)) is not None

def recovery_policy(s,host_id):
    row=s.get(Setting,'recovery:'+host_id)
    return {name:bool(row and row.value.get(name)) for name in ('reboot','rollback')}

def eligible(s,job):
    if job.action not in ('patch','repair'): return True
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
        for host in s.scalars(select(Host)):
            if host.state=='enrolling':continue
            if now-host.last_seen>120:record(host,'stale','Telemetry has not arrived within 120 seconds')
            if host.integrity:record(host,'integrity',json.dumps(host.integrity)[:8000])
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
