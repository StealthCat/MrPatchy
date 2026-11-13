"""Bounded worker self-reports; not independent deployment/readiness attestation."""
import ast
import logging
import hashlib
import math
import os
from pathlib import Path
import re
import time
import uuid
from functools import lru_cache
from fastapi import HTTPException
from sqlalchemy import select
from .coordination import Lock
from .db import Session,Setting,audit
from . import ai_transport

log=logging.getLogger(__name__)
PREFIX='worker-registry:'
FRESH_SECONDS=120
POOL_CAPACITY={'jobs':2,'polls':8,'ai':4}
CONTROL_PREFIX='worker-control:'
GAPS=[
    'Self-reported scheduler-loop liveness; storage, secrets, target access and operational readiness are not independently assessed.',
    'Expected worker identities come from MRPATCHY_EXPECTED_WORKER_IDS when configured; otherwise they are inferred from retained registrations, so a worker that never registered is not expected. Endpoint agents and GCP integration nodes are not inventoried here. Controller web instances are listed separately below.',
    'Drain is boot-specific and cooperative: assigned work finishes; it does not stop a process or certify safe maintenance. Remote shared state and cross-host maintenance acceptance remain planned.',
]

def capacities():
    result=dict(POOL_CAPACITY)
    for key,env,maximum in [('jobs','MRPATCHY_JOB_CONCURRENCY',8),('polls','MRPATCHY_POLL_CONCURRENCY',32),('ai','MRPATCHY_AI_CONCURRENCY',8)]:
        value=os.getenv(env,str(result[key]))
        if not re.fullmatch(r'[0-9]{1,2}',value) or not 1<=int(value)<=maximum:raise ValueError(env+' must be an integer from 1 to '+str(maximum))
        result[key]=int(value)
    return result

def control_key(identity):return CONTROL_PREFIX+hashlib.sha256(identity.encode()).hexdigest()

def control_value(s,identity,boot):
    row=s.get(Setting,control_key(identity))
    if not row:return {'revision':0,'action':'resume'}
    data=row.value
    if not isinstance(data,dict):raise ValueError('Worker control record is invalid; admission blocked')
    if data.get('boot_id')!=boot:return {'revision':0,'action':'resume'}
    if data.get('action') not in ('drain','resume') or type(data.get('revision')) is not int or not 1<=data['revision']<=1_000_000_000:raise ValueError('Worker control record is invalid; admission blocked')
    return {'revision':data['revision'],'action':data['action']}

def request_control(identity,boot,revision,action,reason,username):
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,48}',identity):raise ValueError('Invalid worker identity')
    if action not in ('drain','resume'):raise ValueError('Invalid worker control')
    reason=reason.strip()
    if not 10<=len(reason)<=1000:raise ValueError('Give a reason of 10–1,000 characters')
    with Lock('worker-control:'+identity),Session() as s:
        row=s.get(Setting,record_key(identity));data=row.value if row and isinstance(row.value,dict) else {}
        heartbeat=data.get('heartbeat');now=time.time()
        if data.get('id')!=identity or data.get('boot_id')!=boot:raise HTTPException(409,'Worker boot changed or is unavailable; refresh before controlling it')
        if data.get('version')!=source_version() or data.get('state') not in ('reporting','draining','drained') or not isinstance(heartbeat,(int,float)) or isinstance(heartbeat,bool) or not math.isfinite(heartbeat) or not -5<=now-heartbeat<=FRESH_SECONDS:raise HTTPException(409,'Worker is stale, stopped, unknown or a different version; refresh and inspect it')
        previous=control_value(s,identity,boot)
        if revision!=previous['revision']:raise HTTPException(409,'Worker control changed; refresh before trying again')
        if revision>=1_000_000_000:raise HTTPException(409,'Worker control revision exhausted; restart the worker')
        value={'boot_id':boot,'revision':revision+1,'action':action,'requested':now}
        s.merge(Setting(key=control_key(identity),value=value))
        audit(s,'worker '+action+' requested',username+' '+identity+' '+boot+' '+str(revision+1)+' '+reason)
        s.commit()
    return {'ok':True,'boot_id':boot,'revision':revision+1,'action':action}

@lru_cache(maxsize=1)
def source_version():
    # Read the single authority without importing the web application or TLS/session setup.
    tree=ast.parse(Path(__file__).with_name('main.py').read_text())
    for node in tree.body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='APP_VERSION' for t in node.targets):
            value=ast.literal_eval(node.value)
            if isinstance(value,str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',value):return value
    raise ValueError('Application source version unavailable')

def record_key(identity):
    # ASCII hex avoids case/punctuation collation aliases in MySQL settings keys.
    return PREFIX+hashlib.sha256(identity.encode()).hexdigest()

class IdentityLost(RuntimeError):pass

class Registration:
    def __init__(self,role='worker'):
        self.id=os.getenv('MRPATCHY_WORKER_ID') or uuid.uuid4().hex
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,48}',self.id):raise ValueError('MRPATCHY_WORKER_ID must use 1-48 letters, numbers, dot, underscore, colon or hyphen')
        if role not in ('worker','embedded'):raise ValueError('Unsupported worker role')
        self.role=role;self.boot=uuid.uuid4().hex;self.started=time.time();self.monotonic=time.monotonic();self.last=0
        self.deployment=os.getenv('MRPATCHY_DEPLOYMENT_TYPE','process')
        if self.deployment not in ('docker','process'):raise ValueError('Unsupported reported deployment type')
        self.version=source_version();self.capacity=capacities();self.ai_http_capacity=ai_transport.connection_limit();self.draining=False;self.control_revision=0;self.last_state=None;self.lock=Lock('worker-identity:'+self.id)
    def __enter__(self):
        if not self.lock.acquire(False):raise ValueError('Worker identity is already in use; choose a unique MRPATCHY_WORKER_ID')
        try:self.write('reporting',False,[],0,False,True)
        except Exception:self.lock.release();raise
        return self
    def check_identity(self):
        try:owned=self.lock.owned()
        except Exception as error:raise IdentityLost('Unable to verify worker identity lock; refusing scheduler tick') from error
        if not owned:raise IdentityLost('Worker identity lock lost; refusing scheduler tick')
    def write(self,state,coordinator,jobs,polls,ai_active,initial=False,pending_polls=0,notification_active=False,observed_action=None):
        self.check_identity()
        from .worker_preflight import RESULT,STRUCTURE_RESULT
        value={'schema_structure':STRUCTURE_RESULT,'controller_state':RESULT,'id':self.id,'boot_id':self.boot,'role':self.role,'deployment_type':self.deployment,'version':self.version,
               'started':self.started,'heartbeat':time.time(),'uptime_seconds':max(0,time.monotonic()-self.monotonic),
               'state':state,'coordinator':bool(coordinator),'active_jobs':list(jobs)[:16],
               'active_polls':polls,'pending_polls':pending_polls,'notification_active':bool(notification_active),'ai_active':bool(ai_active),'active_ai_tasks':int(ai_active),'job_capacity':self.capacity['jobs'],'poll_capacity':self.capacity['polls'],'ai_capacity':self.capacity['ai'],
               'ai_http_capacity':self.ai_http_capacity,'control_revision':self.control_revision,
               'readiness':'not_assessed'}
        with Session() as s:
            s.merge(Setting(key=record_key(self.id),value=value))
            if initial:audit(s,'worker registered',self.id+' '+self.boot+' '+self.role)
            if state=='stopped':audit(s,'worker stopped',self.id+' '+self.boot)
            if observed_action:audit(s,'worker '+observed_action+' observed',self.id+' '+self.boot+' '+str(self.control_revision))
            if state=='drained' and self.last_state!='drained':audit(s,'worker drained',self.id+' '+self.boot+' '+str(self.control_revision))
            s.commit()
        self.last=time.monotonic();self.last_state=state
    def heartbeat(self,coordinator,jobs,polls,ai_active,pending_polls=0,notification_active=False):
        # The ownership check is on every tick; periodic writes are every 15 seconds, with immediate state/control changes.
        self.check_identity()
        with Session() as s:control=control_value(s,self.id,self.boot)
        previous_revision=self.control_revision;changed=control['revision']!=previous_revision
        self.control_revision=control['revision'];self.draining=control['action']=='drain' or getattr(self,'stopping',False)
        state=('draining' if jobs or polls or pending_polls or ai_active or notification_active else 'drained') if self.draining else 'reporting'
        if changed or state!=self.last_state or time.monotonic()-self.last>=15:
            try:self.write(state,coordinator and not self.draining,jobs,polls,ai_active,pending_polls=pending_polls,notification_active=notification_active,observed_action=control['action'] if changed else None)
            except Exception:self.control_revision=previous_revision;raise
        return self.draining
    def __exit__(self,*args):
        try:self.write('stopped',False,[],0,False)
        except Exception:log.warning('Unable to record worker shutdown')
        finally:
            try:self.lock.release()
            except Exception:log.warning('Unable to release worker identity lock')

def report_state(data,now):
    heartbeat=data.get("heartbeat")
    age=now-heartbeat if isinstance(heartbeat,(int,float)) and not isinstance(heartbeat,bool) and math.isfinite(heartbeat) and heartbeat>=0 else None
    if age is None or age < -5:state,reason='unknown','Heartbeat is missing, invalid or in the future; check clocks and runtime logs.'
    elif data.get('state')=='stopped':state,reason='stopped','Worker reported a graceful stop; this is retained registration history.'
    elif age>FRESH_SECONDS:state,reason='stale','Heartbeat expired; worker liveness and in-flight outcomes are unknown. Review operations before recovery.'
    elif data.get('state') not in ('reporting','draining','drained'):state,reason='unknown','Worker report state is not recognized.'
    elif not isinstance(data.get('version'),str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',data['version']):state,reason='unknown','Reported worker version is missing or unrecognized.'
    elif data.get('version')!=source_version():state,reason='version_mismatch','Reported worker version differs from this controller; compatibility is not certified.'
    elif data.get('state')=='draining':state,reason='draining','Worker observed drain; assigned work is finishing. New assignments are blocked.'
    elif data.get('state')=='drained':state,reason='drained','Worker reports no assigned work and admission paused. Process remains running; readiness is not assessed.'
    else:state,reason='reporting','Scheduler loop reported recently; operational readiness is not independently assessed.'
    return state,reason,age


def page(offset=0,now=None):
    if offset<0 or offset>100000:raise ValueError('Invalid worker page')
    now=time.time() if now is None else now
    with Session() as s:
        rows=list(s.scalars(select(Setting).where(Setting.key.startswith(PREFIX)).order_by(Setting.key).offset(offset).limit(51)))
        items=[]
        for row in rows[:50]:
            data=row.value if isinstance(row.value,dict) else {}
            fields=('id','boot_id','role','deployment_type','version','started','heartbeat','uptime_seconds','coordinator','active_jobs','active_polls','pending_polls','notification_active','ai_active','active_ai_tasks','job_capacity','poll_capacity','ai_capacity','ai_http_capacity','control_revision')
            item={k:data.get(k) for k in fields}
            for key in ('started','heartbeat','uptime_seconds','active_polls','pending_polls','active_ai_tasks','job_capacity','poll_capacity','ai_capacity','ai_http_capacity','control_revision'):
                value=item[key]
                if not isinstance(value,(int,float)) or isinstance(value,bool) or not math.isfinite(value) or value<0:item[key]=None
            item['id']=data.get('id') if isinstance(data.get('id'),str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,48}',data['id']) else row.key[len(PREFIX):]
            item['active_jobs']=[value for value in data.get('active_jobs',[])[:16] if isinstance(value,str) and len(value)<=64] if isinstance(data.get('active_jobs'),list) else []
            state,reason,age=report_state(data,now)
            try:control=control_value(s,item['id'],data.get('boot_id'))
            except ValueError:control={'revision':None,'action':'invalid'}
            item['schema_structure']=data.get('schema_structure') if data.get('schema_structure') in ('verified','not_checked') else 'unknown'
            item['controller_state']=data.get('controller_state') if data.get('controller_state') in ('verified','not_checked') else 'unknown'
            item['control']=control
            item['controllable']=state in ('reporting','draining','drained') and bool(re.fullmatch(r'[0-9a-f]{32}',str(data.get('boot_id','')))) and row.key==record_key(item['id']) and control['revision'] is not None
            item['removable']=removable(row,data,state,age)
            item.update(state=state,reason=reason,age_seconds=max(0,age) if age is not None else None,readiness='not_assessed')
            items.append(item)
    expected,error=expected_workers(now)
    source='configuration' if configured() else 'registrations'
    return {'items':items,'more':len(rows)>50,'fresh_seconds':FRESH_SECONDS,'gaps':GAPS,'expected':expected,'expectation_error':error,
            'expectation_source':source,'expected_count':len(expected),'inferred_limit':INFERRED_LIMIT}


INFERRED_LIMIT=500
BOOT_PATTERN=r'([0-9a-f]{32})?'


def configured():
    return bool(os.getenv('MRPATCHY_EXPECTED_WORKER_IDS','').strip())


def obsolete(state,age):
    # Removability is positive: only stale or stopped registrations, or unknown ones with no usable heartbeat.
    # A fresh `unknown` report (worker clock ahead, unrecognized state or version) is a live worker and is kept.
    return state in ('stale','stopped') or (state=='unknown' and age is None)


def removable(row,data,state,age):
    # Only an identifiable registration with no fresh heartbeat may be removed; live workers would re-register.
    identity=data.get('id')
    return (obsolete(state,age) and isinstance(identity,str) and bool(re.fullmatch(r'[A-Za-z0-9_.:-]{1,48}',identity))
            and row.key==record_key(identity) and bool(re.fullmatch(BOOT_PATTERN,str(data.get('boot_id') or ''))))


def inferred_workers(now):
    # Every retained, identifiable registration stays expected (including stale and stopped ones) until an
    # administrator removes it. Keys are hashes of the identity, so each worker ID is counted once.
    items=[]
    with Session() as s:
        rows=list(s.scalars(select(Setting).where(Setting.key.startswith(PREFIX)).order_by(Setting.key).limit(INFERRED_LIMIT+1)))
    if len(rows)>INFERRED_LIMIT:
        return [],'More than '+str(INFERRED_LIMIT)+' worker registrations are retained, so expected workers cannot be inferred. Remove obsolete registrations or configure MRPATCHY_EXPECTED_WORKER_IDS on the controller.'
    seen=set()
    for row in rows:
        data=row.value if isinstance(row.value,dict) else {}
        identity=data.get('id')
        if not isinstance(identity,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,48}',identity) or row.key!=record_key(identity) or identity in seen:continue
        seen.add(identity)
        state,reason,age=report_state(data,now)
        items.append({'id':identity,'registered':True,'state':state,'reason':reason,'age_seconds':max(0,age) if age is not None else None,'readiness':'not_assessed'})
    items.sort(key=lambda item:item['id'])
    return items,None


def expected_workers(now,infer=True):
    # An explicit controller configuration is authoritative. Otherwise infer from retained registrations
    # (infer=False returns no expectations). Never infer that an absent process is stopped.
    raw=os.getenv('MRPATCHY_EXPECTED_WORKER_IDS','')
    if not raw.strip():return inferred_workers(now) if infer else ([],None)
    identities=[value.strip() for value in raw.split(',')]
    if len(raw)>5000 or len(identities)>100 or any(not re.fullmatch(r'[A-Za-z0-9_.:-]{1,48}',value) for value in identities) or len(set(identities))!=len(identities):
        return [],'Expected-worker configuration is invalid. Use at most 100 unique, case-sensitive worker IDs (1–48 letters, numbers, dot, underscore, colon or hyphen), separated by commas.'
    items=[]
    with Session() as s:
        for identity in identities:
            row=s.get(Setting,record_key(identity))
            data=row.value if row and isinstance(row.value,dict) else {}
            registered=data.get('id')==identity
            if registered:state,reason,age=report_state(data,now)
            else:state,reason,age='missing','No matching registration is available. The process may be absent, misconfigured or unable to reach this database; inspect the deployment.',None
            items.append({'id':identity,'registered':registered,'state':state,'reason':reason,'age_seconds':max(0,age) if age is not None else None,'readiness':'not_assessed'})
    return items,None


def remove_registration(identity,boot,username):
    """Delete one obsolete registration. Does not edit configuration, stop a process or alter claims."""
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,48}',identity):raise HTTPException(400,'Invalid worker identity')
    if not re.fullmatch(BOOT_PATTERN,boot):raise HTTPException(400,'Invalid worker boot')
    with Lock('worker-control:'+identity),Session() as s:
        row=s.get(Setting,record_key(identity));data=row.value if row and isinstance(row.value,dict) else {}
        if not row or data.get('id')!=identity or str(data.get('boot_id') or '')!=boot:raise HTTPException(409,'Worker registration changed or is unavailable; refresh before removing it')
        state,_,age=report_state(data,time.time())
        if not removable(row,data,state,age):raise HTTPException(409,'Worker is reporting recently; it would register again. Stop or retire it before removing its registration')
        # A stale heartbeat does not prove the process exited. A live worker holds its identity lock for its
        # whole lifetime, so a held lock means a running (possibly hung) process still owns this registration.
        identity_lock=Lock('worker-identity:'+identity)
        if not identity_lock.acquire(False):raise HTTPException(409,'A worker process is still running with this identity; its heartbeat is late, not absent. Stop or retire it before removing its registration')
        try:
            s.delete(row)
            # Keep a drain request unless the boot reported a graceful stop: control is bound to boot_id, so a
            # retained row is inert for new boots but keeps a recovering boot drained instead of silently resuming it.
            control=s.get(Setting,control_key(identity))
            if control and state=='stopped':s.delete(control)
            audit(s,'worker registration removed',username+' '+identity+' '+(boot or 'no-boot')+' '+state)
            s.commit()
        finally:identity_lock.release()
    return {'ok':True,'id':identity,'state':state}


# Expected-worker attention notifications (roadmap H/J). Admin-only, advisory text;
# delivery/read state never drains, recovers or authorizes anything.
NOTIFY_SOURCE='deployment'
NOTIFY_KIND='worker-health'
NOTIFY_CONFIG_KIND='worker-expectation'
NOTIFY_LINK='#activity/workers'
NOTIFY_SEVERITY={'missing':'high','stale':'high','stopped':'high','unknown':'medium','version_mismatch':'medium'}
NOTIFY_TEXT={
    'missing':'has no matching registration. The process may be absent, misconfigured or unable to reach the database.',
    'stale':'stopped sending heartbeats. Its liveness and in-flight outcomes are unknown; review operations before recovery.',
    'stopped':'reported a graceful stop and is not running scheduled work.',
    'unknown':'has a missing, invalid, future-dated or unrecognized report. Check clocks and runtime logs.',
    'version_mismatch':'reports a different version from the controller; compatibility is not certified.',
}
PROCESS_STARTED=time.time()


def _active_worker_events(s):
    # Filter on the current revision's lifecycle so retained resolved history never crowds out active events.
    from . import notifications
    Event,Revision=notifications.NotificationEvent,notifications.NotificationRevision
    rows=s.execute(select(Event.kind,Event.subject_id).join(Revision,(Revision.event_id==Event.id)&(Revision.revision==Event.revision)).where(
        Event.source==NOTIFY_SOURCE,Event.kind.in_((NOTIFY_KIND,NOTIFY_CONFIG_KIND)),Revision.lifecycle=='active').limit(500))
    return {(kind,subject) for kind,subject in rows}


def publish_notifications(now=None,started=None):
    """Publish/resolve in-app events for configured expected workers.

    Runs from the elected coordinator's tick in its own transaction. A startup
    grace of one freshness window suppresses new attention while co-started
    workers register; resolutions always apply. Returns published revisions.
    """
    from . import notifications
    now=time.time() if now is None else now
    started=PROCESS_STARTED if started is None else started
    grace=now-started<FRESH_SECONDS
    # Inferred expectations are page-only: until worker IDs survive restarts (#754), each restart leaves a
    # stopped registration, and notifying on those would flood administrators.
    expected,error=expected_workers(now,infer=False)
    published=0
    with Session() as s:
        active=_active_worker_events(s)
        def emit(kind,subject_type,subject_id,revision,severity,reason,lifecycle='active'):
            nonlocal published
            _,created=notifications.publish(s,source=NOTIFY_SOURCE,kind=kind,subject_type=subject_type,subject_id=subject_id,
                subject_revision=revision,severity=severity,reason=reason,deep_link=NOTIFY_LINK,minimum_role='admin',lifecycle=lifecycle,now=now)
            published+=created
        config=(NOTIFY_CONFIG_KIND,'MRPATCHY_EXPECTED_WORKER_IDS')
        if error:
            if not grace or config in active:
                emit(NOTIFY_CONFIG_KIND,'deployment-config',config[1],'invalid','medium',
                     'The expected-worker configuration (MRPATCHY_EXPECTED_WORKER_IDS) is invalid, so expected workers cannot be checked. Correct it in the controller deployment.')
        else:
            if config in active:
                emit(NOTIFY_CONFIG_KIND,'deployment-config',config[1],'resolved','info',
                     'The expected-worker configuration is valid or cleared.',lifecycle='resolved')
            seen=set()
            for item in expected:
                identity=item['id'];state=item['state'];seen.add(identity)
                key=(NOTIFY_KIND,identity)
                if state in NOTIFY_SEVERITY:
                    if grace and key not in active:continue
                    emit(NOTIFY_KIND,'worker',identity,state,NOTIFY_SEVERITY[state],'Expected worker '+identity+' '+NOTIFY_TEXT[state])
                elif key in active:
                    emit(NOTIFY_KIND,'worker',identity,'resolved:'+state,'info',
                         'Expected worker '+identity+' is now '+state.replace('_',' ')+'; it no longer needs attention.',lifecycle='resolved')
            # An invalid configuration leaves earlier events untouched: removal is unknown.
            for kind,identity in active:
                if kind==NOTIFY_KIND and identity not in seen:
                    emit(NOTIFY_KIND,'worker',identity,'resolved:not-expected','info',
                         'Worker '+identity+' is no longer in the expected-worker configuration.',lifecycle='resolved')
        s.commit()
    return published
