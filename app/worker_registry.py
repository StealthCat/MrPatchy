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
from sqlalchemy import select
from .coordination import Lock
from .db import Session,Setting,audit

log=logging.getLogger(__name__)
PREFIX='worker-registry:'
FRESH_SECONDS=120
POOL_CAPACITY={'jobs':2,'polls':8,'ai':1}
GAPS=[
    'Self-reported scheduler-loop liveness; storage, secrets, target access and operational readiness are not independently assessed.',
    'Only registered workers are listed. Expected but never registered nodes, controllers, endpoint agents and GCP integration nodes are not inventoried here.',
    'Drain, configurable concurrency, remote-worker shared state and cross-host maintenance acceptance remain planned.',
]

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
        self.version=source_version();self.lock=Lock('worker-identity:'+self.id)
    def __enter__(self):
        if not self.lock.acquire(False):raise ValueError('Worker identity is already in use; choose a unique MRPATCHY_WORKER_ID')
        try:self.write('reporting',False,[],0,False,True)
        except Exception:self.lock.release();raise
        return self
    def check_identity(self):
        try:owned=self.lock.owned()
        except Exception as error:raise IdentityLost('Unable to verify worker identity lock; refusing scheduler tick') from error
        if not owned:raise IdentityLost('Worker identity lock lost; refusing scheduler tick')
    def write(self,state,coordinator,jobs,polls,ai_active,initial=False):
        self.check_identity()
        value={'id':self.id,'boot_id':self.boot,'role':self.role,'deployment_type':self.deployment,'version':self.version,
               'started':self.started,'heartbeat':time.time(),'uptime_seconds':max(0,time.monotonic()-self.monotonic),
               'state':state,'coordinator':bool(coordinator),'active_jobs':list(jobs)[:16],
               'active_polls':polls,'ai_active':bool(ai_active),'job_capacity':POOL_CAPACITY['jobs'],'poll_capacity':POOL_CAPACITY['polls'],'ai_capacity':POOL_CAPACITY['ai'],
               'readiness':'not_assessed'}
        with Session() as s:
            s.merge(Setting(key=record_key(self.id),value=value))
            if initial:audit(s,'worker registered',self.id+' '+self.boot+' '+self.role)
            if state=='stopped':audit(s,'worker stopped',self.id+' '+self.boot)
            s.commit()
        self.last=time.monotonic()
    def heartbeat(self,coordinator,jobs,polls,ai_active):
        # The ownership check is on every tick; storage writes are bounded to 15 seconds.
        self.check_identity()
        if time.monotonic()-self.last>=15:self.write('reporting',coordinator,jobs,polls,ai_active)
    def __exit__(self,*args):
        try:self.write('stopped',False,[],0,False)
        except Exception:log.warning('Unable to record worker shutdown')
        finally:
            try:self.lock.release()
            except Exception:log.warning('Unable to release worker identity lock')

def page(offset=0,now=None):
    if offset<0 or offset>100000:raise ValueError('Invalid worker page')
    now=time.time() if now is None else now
    with Session() as s:
        rows=list(s.scalars(select(Setting).where(Setting.key.startswith(PREFIX)).order_by(Setting.key).offset(offset).limit(51)))
        items=[]
        for row in rows[:50]:
            data=row.value if isinstance(row.value,dict) else {}
            fields=('id','boot_id','role','deployment_type','version','started','heartbeat','uptime_seconds','coordinator','active_jobs','active_polls','ai_active','job_capacity','poll_capacity','ai_capacity')
            item={k:data.get(k) for k in fields};heartbeat=data.get('heartbeat')
            for key in ('started','heartbeat','uptime_seconds','active_polls','job_capacity','poll_capacity','ai_capacity'):
                value=item[key]
                if not isinstance(value,(int,float)) or isinstance(value,bool) or not math.isfinite(value) or value<0:item[key]=None
            item['id']=data.get('id') if isinstance(data.get('id'),str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,48}',data['id']) else row.key[len(PREFIX):]
            item['active_jobs']=[value for value in data.get('active_jobs',[])[:16] if isinstance(value,str) and len(value)<=64] if isinstance(data.get('active_jobs'),list) else []
            age=now-heartbeat if isinstance(heartbeat,(int,float)) and not isinstance(heartbeat,bool) and math.isfinite(heartbeat) and heartbeat>=0 else None
            if age is None or age < -5:state,reason='unknown','Heartbeat is missing, invalid or in the future; check clocks and runtime logs.'
            elif data.get('state')=='stopped':state,reason='stopped','Worker reported a graceful stop; this is retained registration history.'
            elif age>FRESH_SECONDS:state,reason='stale','Heartbeat expired; worker liveness and in-flight outcomes are unknown. Review operations before recovery.'
            elif data.get('state')!='reporting':state,reason='unknown','Worker report state is not recognized.'
            elif not isinstance(data.get('version'),str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',data['version']):state,reason='unknown','Reported worker version is missing or unrecognized.'
            elif data.get('version')!=source_version():state,reason='version_mismatch','Reported worker version differs from this controller; compatibility is not certified.'
            else:state,reason='reporting','Scheduler loop reported recently; operational readiness is not independently assessed.'
            item.update(state=state,reason=reason,age_seconds=max(0,age) if age is not None else None,readiness='not_assessed')
            items.append(item)
    return {'items':items,'more':len(rows)>50,'fresh_seconds':FRESH_SECONDS,'gaps':GAPS}
