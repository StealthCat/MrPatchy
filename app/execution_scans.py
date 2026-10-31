"""Opt-in scoped scans prompted by new verified execution identities.

An execution is a scheduling hint, never proof that the scanner read those bytes.
"""
import json
import math
import re
import time
import uuid
from pathlib import PurePosixPath
from sqlalchemy import String,Double,JSON,Text,Index,select,func
from sqlalchemy.orm import Mapped,mapped_column
from .db import Base,Session,Host,Job,Setting,audit
from . import host_lifecycle,incidents,operations
from .coordination import Lock
from target.agent import scan_excluded

DEFAULT={'enabled':False,'paths':['/usr/local/bin','/tmp'],'debounce_seconds':30,'cooldown_minutes':15,'max_per_hour':4,'revision':'','activated':0}
MAX_PENDING=128
MAX_INTAKE_HOURLY=128
MAX_BATCH=32
MAX_AGE=900


class Trigger(Base):
    __tablename__='security_execution_scan_triggers'
    __table_args__=(Index('ix_execution_scan_host_state_created','host_id','state','created'),)
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    revision:Mapped[str]=mapped_column(String(36))
    host_revision:Mapped[str]=mapped_column(String(36))
    created:Mapped[float]=mapped_column(Double,default=time.time)
    observed:Mapped[float]=mapped_column(Double)
    expires:Mapped[float]=mapped_column(Double)
    state:Mapped[str]=mapped_column(String(30),default='pending')
    evidence:Mapped[dict]=mapped_column(JSON)
    job_id:Mapped[str]=mapped_column(String(36),default='',index=True)
    detail:Mapped[str]=mapped_column(Text,default='')


def policy(s,host_id):
    row=s.get(Setting,'execution-scan-policy:'+host_id)
    return {**DEFAULT,**(row.value if row else {})}


def canonical(path):
    return (isinstance(path,str) and 1<len(path)<=4096 and path.startswith('/') and not path.startswith('//')
        and str(PurePosixPath(path))==path and '..' not in PurePosixPath(path).parts
        and not any(ord(c)<32 or ord(c)==127 for c in path) and not scan_excluded(PurePosixPath(path)))


def paths_valid(paths):
    if not isinstance(paths,list) or not 1<=len(paths)<=16 or any(not canonical(p) for p in paths):raise ValueError('Choose 1–16 canonical real absolute scan directories outside excluded filesystems')
    if any(a==b or a.startswith(b+'/') or b.startswith(a+'/') for i,a in enumerate(paths) for b in paths[i+1:]):raise ValueError('Scan directories must not overlap')


def cancel(s,host_id,detail):
    for row in s.scalars(select(Trigger).where(Trigger.host_id==host_id,Trigger.state.in_(('pending','queued')))):
        row.state='skipped';row.detail=detail
    for job in s.scalars(select(Job).where(Job.host_id==host_id,Job.action=='execution-scan',Job.state=='queued')):
        job.state='cancelled';job.output=detail


def save(s,host,body,actor):
    old=policy(s,host.id)
    if old['revision']!=body.expected_revision:raise ValueError('Execution scan policy changed; refresh before saving')
    paths_valid(body.paths);reason=body.reason.strip()
    if len(reason)<10:raise ValueError('Provide a meaningful execution scan policy reason')
    cancel(s,host.id,'Execution scan policy changed; old work will not resume')
    value=body.model_dump(exclude={'expected_revision','reason'})|{'revision':str(uuid.uuid4()),'activated':time.time()}
    s.merge(Setting(key='execution-scan-policy:'+host.id,value=value))
    audit(s,'execution scan policy saved',json.dumps({'host_id':host.id,'actor':actor,'reason':reason,'before':old,'after':value},sort_keys=True))
    return value


def dropped(s,host_id,count,now):
    if not count:return
    row=s.get(Setting,'execution-scan-coverage:'+host_id)
    previous=row.value if row else {}
    s.merge(Setting(key='execution-scan-coverage:'+host_id,value={'dropped_observations':previous.get('dropped_observations',0)+count,'last_dropped':now}))


def normalized_uid(value):
    """Accept the integer wire protocol and legacy decimal strings from stored events."""
    if type(value) is int:uid=value
    elif isinstance(value,str) and re.fullmatch(r'(?:0|[1-9][0-9]{0,9})',value):uid=int(value)
    else:return None
    return uid if 0<=uid<=2**32-1 else None


def observe(s,host,observation_id,processes,observed,cfg=None):
    """Called only for newly persisted spool events, in their ingestion transaction."""
    cfg=policy(s,host.id) if cfg is None else cfg;now=time.time()
    if not cfg['enabled'] or not host_lifecycle.active(host) or not host.fingerprint or not host.baseline:return
    if type(observed) not in (int,float) or not math.isfinite(observed) or not cfg['activated']<=observed<=now+5 or now-observed>120:return
    if not isinstance(processes,list):return
    candidates={};omitted=max(0,len(processes)-128)
    for item in processes[:128]:
        if not isinstance(item,dict) or item.get('capture')!='ebpf' or item.get('identity_verified') is not True:continue
        path=item.get('executable');digest=item.get('sha256');uid=normalized_uid(item.get('uid'))
        if not canonical(path) or not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest) or uid is None:
            omitted+=1;continue
        if not any(path.startswith(root+'/') for root in cfg['paths']):continue
        identifier=incidents.digest({'host_id':host.id,'revision':cfg['revision'],'path':path,'sha256':digest})
        candidates[identifier]={'observation_id':observation_id,'executable':path,'sha256':digest,'uid':uid,'capture':'ebpf','identity_verified':True}
    if not candidates:
        dropped(s,host.id,omitted,now);return
    existing=set(s.scalars(select(Trigger.id).where(Trigger.id.in_(candidates))))
    pending=s.scalar(select(func.count()).select_from(Trigger).where(Trigger.host_id==host.id,Trigger.state.in_(('pending','queued'))))
    intake=s.scalar(select(func.count()).select_from(Trigger).where(Trigger.host_id==host.id,Trigger.created>now-3600))
    capacity=max(0,min(MAX_PENDING-pending,MAX_INTAKE_HOURLY-intake))
    for identifier,evidence in candidates.items():
        if identifier in existing:continue
        if not capacity:omitted+=1;continue
        s.add(Trigger(id=identifier,host_id=host.id,revision=cfg['revision'],host_revision=host.lifecycle_revision,created=now,observed=observed,expires=now+MAX_AGE,evidence=evidence));capacity-=1
    dropped(s,host.id,omitted,now)


def scope_current(s,host,job,now=None):
    now=time.time() if now is None else now
    cfg=policy(s,host.id);payload=job.payload;ids=payload.get('trigger_ids',[])
    if (job.state not in ('queued','running') or not host_lifecycle.active(host) or not cfg['enabled'] or cfg['revision']!=payload.get('revision') or cfg['paths']!=payload.get('paths')
        or host.fingerprint!=payload.get('fingerprint') or host.lifecycle_revision!=payload.get('_host_revision')
        or not isinstance(ids,list) or not 1<=len(ids)<=MAX_BATCH or len(set(ids))!=len(ids)):return False
    rows=list(s.scalars(select(Trigger).where(Trigger.id.in_(ids))))
    return len(rows)==len(ids) and all(r.host_id==host.id and r.job_id==job.id and r.state=='queued' and r.revision==cfg['revision'] and r.host_revision==host.lifecycle_revision and now<r.expires for r in rows)


def finish(s,job,state,detail):
    for row in s.scalars(select(Trigger).where(Trigger.host_id==job.host_id,Trigger.job_id==job.id,Trigger.state=='queued')):
        row.state=state;row.detail=detail


def validate_receipt(report,paths):
    if (not isinstance(report,dict) or type(report.get('version')) is not int or report['version']!=2 or report.get('roots')!=paths or report.get('engine')!='ClamAV'
        or report.get('state') not in ('incomplete','no_detections','completed_with_findings') or type(report.get('available')) is not bool
        or type(report.get('scanned')) is not int or not 0<=report['scanned']<=2000):raise ValueError('Unbound execution scan scope, engine or coverage')
    findings=report.get('findings');gaps=report.get('gaps');signatures=report.get('signatures')
    if (not isinstance(findings,list) or len(findings)>min(100,report['scanned']) or not isinstance(gaps,list) or len(gaps)>104
        or any(not isinstance(g,str) or len(g)>10000 for g in gaps) or not isinstance(signatures,dict)
        or signatures.get('state') not in ('recent','stale','future','unknown','changed')):raise ValueError('Invalid execution scan coverage receipt')
    if ((not report['available'] or signatures['state']!='recent' or gaps) and report['state']!='incomplete'
        or not report['available'] and (report['scanned'] or findings)
        or report['state']=='no_detections' and findings or report['state']=='completed_with_findings' and not findings
        or report['state']=='incomplete' and not gaps):raise ValueError('Contradictory execution scan coverage')
    for item in findings:
        path=item.get('path') if isinstance(item,dict) else None
        # Real file names may contain control characters. Preserve their finding
        # metadata rather than discarding a detection; JSON/UI escaping applies.
        if (not isinstance(path,str) or len(path)>4096 or '\x00' in path or str(PurePosixPath(path))!=path or '..' in PurePosixPath(path).parts
            or not any(path.startswith(root+'/') for root in paths) or scan_excluded(PurePosixPath(path))):raise ValueError('Execution scan finding outside approved directories')


def schedule_tick(now=None):
    from .worker import host_lock
    now=time.time() if now is None else now
    with Lock('security-scan-queue'),Session() as s:
        host_ids=list(s.scalars(select(Trigger.host_id).where(Trigger.state.in_(('pending','queued'))).distinct().order_by(Trigger.host_id)))
        for host_id in host_ids:
            lock=host_lock(host_id)
            if not lock.acquire(False):continue
            try:
                s.rollback();host=s.get(Host,host_id);cfg=policy(s,host_id)
                for row in s.scalars(select(Trigger).where(Trigger.host_id==host_id,Trigger.state=='queued')):
                    job=s.get(Job,row.job_id)
                    if not job or job.state in ('cancelled','failed','blocked','interrupted'):
                        row.state='skipped' if job and job.state=='cancelled' else 'failed';row.detail='Owning operation did not complete; no automatic retry'
                for row in s.scalars(select(Trigger).where(Trigger.host_id==host_id,Trigger.state=='pending')):
                    if not host or not host_lifecycle.active(host) or not cfg['enabled'] or row.revision!=cfg['revision'] or row.host_revision!=host.lifecycle_revision or now>=row.expires:
                        row.state='skipped';row.detail='Trigger expired or management/policy changed; queue a manual scan if required'
                s.commit()
                if not host or not host_lifecycle.active(host) or not cfg['enabled'] or host.state=='enrolling' or not host.fingerprint or not host.baseline or not 0<=now-host.last_seen<=120:continue
                if operations.host_quarantined(s,host_id) or s.scalar(select(Job.id).where(Job.host_id==host_id,Job.state.in_(('queued','running','recovery_required'))).limit(1)):continue
                rows=list(s.scalars(select(Trigger).where(Trigger.host_id==host_id,Trigger.state=='pending',Trigger.created<=now-cfg['debounce_seconds']).order_by(Trigger.created,Trigger.id).limit(MAX_BATCH)))
                if not rows:continue
                recent=list(s.scalars(select(Job).where(Job.host_id==host_id,Job.action=='execution-scan',Job.created>now-3600).order_by(Job.created.desc())))
                if len(recent)>=cfg['max_per_hour'] or recent and now-recent[0].created<cfg['cooldown_minutes']*60:continue
                # The intent rows and owning job commit atomically. A restart
                # cannot expose an executable job whose intent is still pending.
                with host_lifecycle.activity([host_id],'queue') as revisions:
                    job_id=str(uuid.uuid4())
                    payload={'paths':cfg['paths'],'revision':cfg['revision'],'fingerprint':host.fingerprint,'trigger_ids':[r.id for r in rows],'_actor':'execution-scan','_host_revision':revisions[host_id]}
                    s.add(Job(id=job_id,host_id=host_id,action='execution-scan',payload=payload))
                    for row in rows:row.state='queued';row.job_id=job_id
                    audit(s,'queue execution-scan',host_id+' '+job_id);s.commit()
            finally:lock.release()


def execute(s,host,job):
    from . import quarantine,ssh
    if not scope_current(s,host,job):
        finish(s,job,'skipped','Execution scan authorization expired or changed before use')
        return {'state':'skipped','reason':'Authorization expired or changed; no scanner request sent'}
    quarantine.healthy(s,host)
    host_id=host.id;s.rollback();s.expire_all();host=s.get(Host,host_id)
    if not scope_current(s,host,job):
        finish(s,job,'skipped','Execution scan scope changed during helper verification')
        return {'state':'skipped','reason':'Scope changed during verification; no scanner request sent'}
    triggers=list(s.scalars(select(Trigger).where(Trigger.id.in_(job.payload['trigger_ids'])).order_by(Trigger.id)))
    context={'kind':'verified_execution','revision':job.payload['revision'],'trigger_ids':[r.id for r in triggers],
        'executions':[{'observed':r.observed,**r.evidence} for r in triggers],
        'binding':'scheduling_hint_only','limit':'Configured directories are scanned within normal scanner budgets. This does not attest that the observed executable or its earlier bytes were scanned.'}
    result=ssh.call(host,{'action':'security-scan','paths':job.payload['paths']},timeout=300)
    s.rollback();s.expire_all();host=s.get(Host,host_id)
    current=bool(host and scope_current(s,host,job));validate_receipt(result,job.payload['paths'])
    result={**result,'automation':{**context,'scope_current':current}}
    if not current:
        result['state']='incomplete';result['gaps']=[*result.get('gaps',[]),'Execution scan policy or identity changed during scanning']
    incidents.record(s,host_id,job.id,result)
    finish(s,job,'completed' if current and result.get('state')!='incomplete' else 'incomplete','Scoped scan receipt retained; executable-specific coverage is not asserted')
    return {'state':result.get('state'),'findings':len(result.get('findings',[])),'trigger_count':len(context['trigger_ids'])}


def coverage(s,host_id,cfg,now):
    coverage=s.get(Setting,'execution-scan-coverage:'+host_id)
    coverage=coverage.value if coverage else {'dropped_observations':0,'last_dropped':0}
    latest=s.scalar(select(Trigger.id).where(Trigger.host_id==host_id,Trigger.revision==cfg['revision'],Trigger.created>now-3600,Trigger.state.in_(('failed','incomplete','skipped'))).limit(1))
    expired=s.scalar(select(Trigger.id).where(Trigger.host_id==host_id,Trigger.state.in_(('pending','queued')),Trigger.expires<=now).limit(1))
    limited=bool(coverage.get('last_dropped',0)>now-3600 or latest or expired)
    return {'limited':limited,'coverage':coverage}


def status(s,host_id,now=None):
    now=time.time() if now is None else now
    cfg=policy(s,host_id);host=s.get(Host,host_id)
    counts=dict(s.execute(select(Trigger.state,func.count()).where(Trigger.host_id==host_id).group_by(Trigger.state)).all())
    limits=coverage(s,host_id,cfg,now);limited=limits['limited']
    state='disabled' if not cfg['enabled'] else ('suspended' if not host_lifecycle.active(host) else ('limited' if limited else 'enabled'))
    return {'policy':cfg,'state':state,'counts':counts,**limits,'last_seen':host.last_seen if host else 0,'collector_issues':host.integrity[:20] if host else []}
