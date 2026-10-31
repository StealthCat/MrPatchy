import base64
import json
from contextlib import asynccontextmanager, contextmanager
import hashlib
import os
from pathlib import Path
import re
import secrets
import shlex
import threading
import time
import uuid
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.responses import FileResponse, PlainTextResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from .db import Session, Host, Package, Behavior, Job, Setting, Audit, InventoryRevision, Observation, init, config, audit
from .security import password_hash, verify, token_hash, seal
from . import ssh, apt, worker, tls, scheduling, ai, ai_runs, update_scores, install_times, package_history, packages as package_backend
from .http_security import RequestSizeLimit
from . import operations, incidents, connections,host_lifecycle
from .identity import User,actor,consume_otp,new_secret
from .security import unseal

@asynccontextmanager
async def lifespan(app):
    from .database_config import runtime_guard
    with runtime_guard():
        init()
        from .worker_preflight import publish
        publish(APP_VERSION)
        with Session() as s:
            if not s.get(Setting,'admin'):
                password=os.getenv('ADMIN_PASSWORD','')
                if len(password)<12 or password=='replace-with-a-long-unique-password': raise RuntimeError('Set ADMIN_PASSWORD to at least 12 characters before first start')
                s.add(Setting(key='admin',value={'hash':password_hash(password)})); s.commit()
        with Session() as s:
            if not s.get(User,'admin'):
                s.add(User(username='admin',password=s.get(Setting,'admin').value['hash'],role='admin'));s.commit()
        background=worker.start() if os.getenv('DISABLE_SCHEDULER')!='1' else None
        try:
            yield
        finally:
            worker.stop.set()
            if background: background.join()
            ai.transport.close()
APP_VERSION='1.35.17'
app=FastAPI(title='Mr Patchy',version=APP_VERSION,lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
app.add_middleware(RequestSizeLimit)
from starlette.middleware.sessions import SessionMiddleware
from .security import cipher
from . import sso
app.add_middleware(SessionMiddleware,secret_key=hashlib.sha256(cipher()._signing_key).hexdigest(),session_cookie='oidc_flow',https_only=True,same_site='lax',max_age=300)
app.include_router(sso.router)
@app.exception_handler(ValueError)
async def invalid_input(request,exc): return JSONResponse({'detail':str(exc)[:1000]},status_code=400)
static=Path(__file__).parent/'static'
app.mount('/static',StaticFiles(directory=static),name='static')

@app.middleware('http')
async def guard(request,call_next):
    response=await call_next(request)
    if request.method not in ('GET','HEAD') and getattr(request.state,'actor',None):
        with Session() as s:
            audit(s,'request',request.state.actor+' '+request.method+' '+request.url.path+' '+str(response.status_code));s.commit()
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if request.url.path.startswith(('/api','/enroll','/auth')): response.headers['Cache-Control']='no-store'
    return response

def auth(request:Request):
    token=request.cookies.get('mrpatchy','')
    with Session() as s:
        row=s.get(Setting,'session:'+token_hash(token))
        if not row or row.value['expires']<time.time(): raise HTTPException(401,'Sign in required')
        username=row.value.get('username')
        identity=s.get(User,username) if username else None
        if not identity or not identity.enabled or row.value.get('generation')!=identity.generation:
            raise HTTPException(401,'Session revoked; sign in again')
        if request.method not in ['GET','HEAD'] and not secrets.compare_digest(request.headers.get('x-csrf-token',''),row.value['csrf']): raise HTTPException(403,'Invalid CSRF token')
        path=request.url.path
        self_service=path in ('/api/logout','/api/identity','/api/identity/mfa','/api/identity/mfa/confirm','/api/identity/password','/api/identity/sessions')
        operator_action=(path.endswith('/patch') or path.endswith('/actions/refresh') or path.endswith('/preview'))
        sensitive_read=('/security' in path or '/release' in path or '/history' in path or path.endswith(('/installer','/enrollment-endpoints','/backups','/repository-access','/connection','/repositories','/snapshot','/security'))) or path.startswith(('/api/ai','/api/users','/api/settings','/api/audit','/api/operations','/api/tls','/api/schedules'))
        if not self_service:
            if sensitive_read and identity.role!='admin': raise HTTPException(403,'Administrator access required')
            if request.method not in ('GET','HEAD') and identity.role!='admin':
                if identity.role!='operator' or not operator_action: raise HTTPException(403,'This role cannot perform that operation')
        host_path=re.match(r'^/api/(?:hosts|operations)/([^/]+)',path)
        if host_path:
            host=s.get(Host,host_path.group(1))
            if host and host.deleted_at and identity.role!='admin':raise HTTPException(403,'Deleted server records require administrator access')
            lifecycle_action=path=='/api/hosts/'+host_path.group(1) or path=='/api/hosts/'+host_path.group(1)+'/lifecycle'
            metadata_export=bool(re.fullmatch(r'/api/hosts/[^/]+/security/(?:quarantines/[^/]+/export|export)',path))
            installer_read=path.endswith('/installer')
            local_connection=bool(host and not host.deleted_at and request.method=='PUT' and path in ('/api/hosts/'+host.id+'/connection','/api/hosts/'+host.id+'/fingerprint','/api/hosts/'+host.id+'/security/ai-policy'))
            if host and not host_lifecycle.active(host) and (request.method not in ('GET','HEAD') or installer_read) and not lifecycle_action and not metadata_export and not local_connection:
                raise HTTPException(409,'Server management is disabled or deleted')
        request.state.actor=identity.username
        return {**row.value,'username':identity.username,'role':identity.role,'mfa':bool(identity.otp_secret)}

@contextmanager
def host_change(host_id,allow_quarantined=False,allow_inactive=False):
    lock=worker.host_lock(host_id)
    if not lock.acquire(False): raise HTTPException(409,'Server has an active operation. Retry this configuration change when it finishes.')
    try:
        with Session() as s:
            host=s.get(Host,host_id)
            if host and not allow_inactive and not host_lifecycle.active(host):raise HTTPException(409,'Server management is disabled or deleted')
        if not allow_quarantined:
            with Session() as s:
                if operations.host_quarantined(s,host_id):raise HTTPException(409,'Reconcile the host operation before making further changes')
        yield
    finally: lock.release()

def host_or_404(s,host_id):
    h=s.get(Host,host_id)
    if not h: raise HTTPException(404,'Server not found')
    return h

def object_dict(obj,exclude=()): return {c.name:getattr(obj,c.name) for c in obj.__table__.columns if c.name not in exclude}
def public_job(job):
    """Return operation metadata without exposing its internal execution payload."""
    result=object_dict(job,('payload',))
    result['ai_deferred']=isinstance(job.payload,dict) and job.payload.get('_ai_deferred') is True
    return result
@app.get('/')
def index(): return FileResponse(static/'index.html')
@app.get('/healthz')
def health(): return {'status':'ok','version':APP_VERSION}
class Login(BaseModel):
    username:str=Field(default='admin',pattern=r'^[A-Za-z0-9_.-]{1,64}$')
    password:str=Field(max_length=1024)
    otp:str=Field(default='',max_length=6)
login_attempts={}; login_lock=threading.Lock(); login_throttle_logged={}
def audit_login_event(action,username,ip,reason):
    # Usernames are pattern-restricted by Login; never record the submitted password or OTP.
    with Session() as s:
        audit(s,action,username+' '+ip+' '+reason); s.commit()
@app.post('/api/login')
def login(body:Login,request:Request,response:Response):
    ip=request.client.host; now=time.time()
    # Reserve an attempt before expensive password hashing; remove it only on success.
    bucket=ip+':'+body.username
    throttled=None
    with login_lock:
        for key in list(login_attempts):
            login_attempts[key]=[x for x in login_attempts[key] if now-x<300]
            if not login_attempts[key]: del login_attempts[key]
        for key in list(login_throttle_logged):
            if now-login_throttle_logged[key]>=300: del login_throttle_logged[key]
        recent=login_attempts.get(bucket,[])
        ip_attempts=sum(len(v) for k,v in login_attempts.items() if k.startswith(ip+':'))
        if len(recent)>=10 or ip_attempts>=50 or len(login_attempts)>=10000:
            scope,reason=(bucket,'account limit') if len(recent)>=10 else (ip,'address limit') if ip_attempts>=50 else ('global','global limit')
            # One audit entry per limit and window, so rejected requests cannot flood the log.
            throttled=reason if scope not in login_throttle_logged else ''
            login_throttle_logged.setdefault(scope,now)
        else: login_attempts[bucket]=recent+[now]
    if throttled is not None:
        if throttled: audit_login_event('login throttled',body.username,ip,throttled)
        raise HTTPException(429,'Too many attempts. Try again in five minutes.')
    failure=None
    with login_lock, Session() as s:
        identity=s.get(User,body.username)
        if not identity or not identity.enabled: failure='unknown or disabled account'
        elif not verify(body.password,identity.password): failure='bad password'
        elif identity.otp_secret and not consume_otp(identity,body.otp): failure='bad MFA code'
        else:
            token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32)
            s.add(Setting(key='session:'+token_hash(token),value={'csrf':csrf,'expires':now+43200,'username':identity.username,'generation':identity.generation}))
            audit(s,'login',identity.username+' '+ip); s.commit()
            login_attempts[bucket]=[x for x in login_attempts.get(bucket,[]) if x!=now]
    if failure:
        audit_login_event('login failed',body.username,ip,failure)
        raise HTTPException(401,'Invalid credentials or MFA code' if failure=='bad MFA code' else 'Invalid credentials')
    response.set_cookie('mrpatchy',token,httponly=True,secure=os.getenv('COOKIE_SECURE','true').lower()=='true',samesite='strict',max_age=43200)
    return {'csrf':csrf,'username':identity.username,'role':identity.role}
@app.get('/api/session')
def session(user=Depends(auth)): return {'csrf':user['csrf']}
@app.post('/api/logout')
def logout(request:Request,response:Response,user=Depends(auth)):
    with Session() as s:
        row=s.get(Setting,'session:'+token_hash(request.cookies['mrpatchy'])); s.delete(row); s.commit()
    response.delete_cookie('mrpatchy'); return {'ok':True}
@app.get('/api/dashboard')
def dashboard(user=Depends(auth)):
    with Session() as s:
        cfg=config(s); hosts=list(s.scalars(select(Host).where(Host.enabled==True,Host.deleted_at==0))); packages=list(s.scalars(select(Package).where(Package.host_id.in_(host_lifecycle.active_ids())))); now=time.time()
        updates=[p for p in packages if p.candidate]
        return {'servers':len(hosts),'online':sum(h.state=='online' and now-h.last_seen<120 for h in hosts),'packages':len(packages),'updates':len(updates),'overdue':sum(now>p.available_since+cfg['deadlines'][p.priority]*3600 for p in updates),'integrity_alerts':sum(len(h.integrity) for h in hosts),'investigations':s.scalar(select(func.count()).select_from(Behavior).where(Behavior.approved==False,Behavior.host_id.not_in(host_lifecycle.inactive_ids()))),'repo_minutes':cfg['repo_minutes']}
@app.get('/api/hosts')
def hosts(deleted:bool=False,user=Depends(auth)):
    if deleted and user['role']!='admin':raise HTTPException(403,'Administrator access required')
    with Session() as s: return [object_dict(h,('inventory','telemetry','baseline'))|{'architecture':h.inventory.get('architecture',''),'os':h.inventory.get('os',''),'package_manager':h.inventory.get('package_manager','apt')} for h in s.scalars(select(Host).where(Host.deleted_at>0 if deleted else Host.deleted_at==0).order_by(Host.name))]

class HostLifecycleInput(BaseModel):
    enabled:bool
    expected_revision:str=Field(default='',max_length=36)
    reason:str=Field(min_length=10,max_length=4000)

class HostDeletionInput(BaseModel):
    expected_revision:str=Field(default='',max_length=36)
    confirmation:str=Field(max_length=120)
    reason:str=Field(min_length=10,max_length=4000)

@app.put('/api/hosts/{host_id}/lifecycle')
def change_host_lifecycle(host_id:str,body:HostLifecycleInput,user=Depends(auth)):
    with host_change(host_id,allow_quarantined=True,allow_inactive=True):
        try:
            with host_lifecycle.changing(host_id),Session() as s:
                host=host_or_404(s,host_id)
                cancelled=host_lifecycle.set_enabled(s,host,body.enabled,body.expected_revision,user['username'],body.reason);s.commit()
                return {'host':object_dict(host,('inventory','telemetry','baseline')),'cancelled_jobs':cancelled}
        except host_lifecycle.Busy as error:raise HTTPException(409,str(error)) from None

@app.delete('/api/hosts/{host_id}')
def delete_host(host_id:str,body:HostDeletionInput,user=Depends(auth)):
    with host_change(host_id,allow_quarantined=True,allow_inactive=True):
        try:
            with host_lifecycle.changing(host_id),Session() as s:
                host=host_or_404(s,host_id)
                host_lifecycle.remove(s,host,body.expected_revision,body.confirmation,user['username'],body.reason)
                return {'deleted':True,'history_retained':True,'remote_agent_removed':False,'deleted_at':host.deleted_at}
        except host_lifecycle.Busy as error:raise HTTPException(409,str(error)) from None

class ServerAIInput(BaseModel):
    paused:bool
    expected_revision:str=Field(default='',max_length=36)
    reason:str=Field(min_length=10,max_length=4000)

@app.get('/api/hosts/{host_id}/security/ai-policy')
def server_ai_policy(host_id:str,user=Depends(auth)):
    from . import ai_policy
    with Session() as s:
        host_or_404(s,host_id);return ai_policy.status(s,host_id)

@app.put('/api/hosts/{host_id}/security/ai-policy')
def save_server_ai_policy(host_id:str,body:ServerAIInput,user=Depends(auth)):
    from . import ai_policy
    with worker.Lock('ai-policy-change:'+host_id):
        lock=worker.Lock('ai-provider:'+host_id)
        if not lock.acquire(False):raise HTTPException(409,'AI request is in flight; retry after it finishes. State has not changed.')
        try:
            with Session() as s:return ai_policy.save(s,host_or_404(s,host_id),body.paused,body.expected_revision,body.reason,user['username'])
        finally:lock.release()

@app.get('/api/hosts/{host_id}/summary')
def host_summary(host_id:str,user=Depends(auth)):
    with Session() as s:
        h=host_or_404(s,host_id); cfg=config(s); now=time.time()
        packages=list(s.scalars(select(Package).where(Package.host_id==host_id)))
        updates=[p for p in packages if p.candidate]
        behaviors=list(s.execute(select(Behavior.verdict,Behavior.approved).where(Behavior.host_id==host_id)))
        jobs=dict(s.execute(select(Job.state,func.count()).where(Job.host_id==host_id).group_by(Job.state)).all())
        last=s.scalar(select(Job).where(Job.host_id==host_id,Job.action=='patch').order_by(Job.created.desc(),Job.id).limit(1))
        return {'host':object_dict(h,('inventory','telemetry','baseline')),
                'system':{k:h.inventory.get(k) for k in ('os','architecture','foreign_architectures','package_manager','machine_id','collected')},
                'collector':{'collected':h.telemetry.get('collected'), 'hashed_at':h.telemetry.get('hashed_at'),
                             'processes':len(h.telemetry.get('processes',[])), 'managed_files':len(h.telemetry.get('managed',{}))},
                'counts':{'packages':len(packages),'updates':len(updates),'held':sum(p.held for p in packages),
                          'overdue':sum(now>p.available_since+cfg['deadlines'][p.priority]*3600 for p in updates),
                          'investigations':len(behaviors),'unapproved':sum(not r.approved for r in behaviors),
                          'pending_ai':sum(not r.approved and r.verdict in ('pending','error') for r in behaviors)},
                'jobs':jobs,'last_patch':object_dict(last,('payload',)) if last else None}

@app.get('/api/hosts/{host_id}/snapshot')
def host_snapshot(host_id:str,user=Depends(auth)):
    with Session() as s:
        h=host_or_404(s,host_id)
        return {'inventory':h.inventory,'telemetry':h.telemetry,'baseline':h.baseline}

@app.get('/api/hosts/{host_id}/patching')
def host_patching(host_id:str,start:float,end:float,user=Depends(auth)):
    with Session() as s:
        host_or_404(s,host_id)
        events=scheduling.calendar(s,start,end,host_id)
        policies=[scheduling.serialize(r) for r in s.scalars(select(scheduling.PatchSchedule))
                  if r.policy['all_hosts'] or host_id in r.policy['host_ids']]
        # Display this host's policy without exposing other schedule members.
        policies=[{k:v for k,v in p.items() if k not in ('host_ids','all_hosts')} for p in policies]
        window=s.get(Setting,'window:'+host_id)
        return {'events':events,'schedules':policies,'windows':window.value['windows'] if window else [],
                'recovery':operations.recovery_policy(s,host_id)}
class HostInput(BaseModel):
    name:str=Field(min_length=1,max_length=120)
    address:str=Field(min_length=1,max_length=253,pattern=r'^[A-Za-z0-9:.\-]+$')
    port:int=Field(default=22,ge=1,le=65535)
    fingerprint:str=Field(default='',max_length=100)
@app.post('/api/hosts')
def add_host(body:HostInput,user=Depends(auth)):
    if body.fingerprint and not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',body.fingerprint): raise HTTPException(400,'Invalid SHA256 SSH fingerprint')
    with Session() as s:
        h=Host(id=str(uuid.uuid4()),**body.model_dump()); ssh.create_key(h.id); s.add(h); audit(s,'add server',h.name); s.commit(); return {'id':h.id}
class ConnectionUpdate(BaseModel):
    connection: connections.Connection
    expected: connections.Connection

@app.get('/api/hosts/{host_id}/connection')
def get_connection(host_id:str,user=Depends(auth)):
    with Session() as s:
        h=host_or_404(s,host_id)
        return connections.saved(s,h).model_dump()

@app.put('/api/hosts/{host_id}/connection')
def save_connection(host_id:str,body:ConnectionUpdate,user=Depends(auth)):
    with host_change(host_id,allow_quarantined=True,allow_inactive=True), Session() as s:
        h=host_or_404(s,host_id)
        if h.deleted_at:raise HTTPException(409,'Deleted server connection is read-only')
        if connections.saved(s,h)!=body.expected:
            raise HTTPException(409,'Connection changed since this page loaded. Reload before saving.')
        h.address=body.connection.address; h.port=body.connection.port
        s.merge(Setting(key='connection:'+host_id,value=body.connection.model_dump(exclude={'address','port'})))
        if host_lifecycle.active(h) and h.state!='enrolling':
            h.state='offline'; h.error='Connection updated; awaiting a successful check'
        audit(s,'update server connection',host_id+' '+body.connection.transport)
        s.commit()
        return body.connection.model_dump()

@app.post('/api/hosts/{host_id}/connection/test')
def test_connection(host_id:str,user=Depends(auth)):
    with host_change(host_id,allow_quarantined=True), Session() as s:
        h=host_or_404(s,host_id)
        if not h.fingerprint: raise HTTPException(400,'Pin the verified SSH fingerprint before testing')
        try: ssh.call(h,{'action':'snapshot'},timeout=30)
        except Exception as error: raise HTTPException(502,str(error)[:2000]) from error
        return {'ok':True,'message':'Pinned SSH identity and bridge response verified. Normal polling checks collector freshness and integrity.'}

class Fingerprint(BaseModel): fingerprint:str=Field(pattern=r'^SHA256:[A-Za-z0-9+/]{43}$')
@app.put('/api/hosts/{host_id}/fingerprint')
def set_fingerprint(host_id:str,body:Fingerprint,user=Depends(auth)):
    with host_change(host_id,allow_quarantined=True,allow_inactive=True), Session() as s:
        h=host_or_404(s,host_id)
        if h.deleted_at:raise HTTPException(409,'Deleted server identity is read-only')
        h.fingerprint=body.fingerprint; audit(s,'pin SSH host key',h.id+' '+h.fingerprint); s.commit(); return {'ok':True}
@app.get('/api/hosts/{host_id}/installer')
def installer(host_id:str,user=Depends(auth)):
    with host_change(host_id,allow_quarantined=True),Session() as s:
        h=host_or_404(s,host_id)
        return PlainTextResponse(ssh.bootstrap(h),headers={'Content-Disposition':'attachment; filename="mrpatchy-enroll.sh"'})
def enrollment_endpoints(request:Request):
    endpoints=[{'id':'default','label':'Default (PUBLIC_URL)',
                'url':os.getenv('PUBLIC_URL',str(request.base_url)).rstrip('/')}]
    for name, item in tls.public_state()['profiles'].items():
        if not item['enabled']:
            continue
        port=item['effective_https_port']
        origin='https://'+tls.address(tls.hostname(item['domain']))+(f':{port}' if port!=443 else '')
        endpoints.append({'id':name,'label':name.capitalize()+' HTTPS','url':origin})
    return endpoints

@app.get('/api/hosts/{host_id}/enrollment-endpoints')
def get_enrollment_endpoints(host_id:str,request:Request,user=Depends(auth)):
    with Session() as s:
        host_or_404(s,host_id)
    return {'endpoints':enrollment_endpoints(request)}

class EnrollmentLinkInput(BaseModel):
    endpoint:str=Field(default='default',max_length=32)

@app.post('/api/hosts/{host_id}/enrollment-link')
def enrollment_link(host_id:str,request:Request,body:EnrollmentLinkInput|None=None,user=Depends(auth)):
    with host_change(host_id,allow_quarantined=True),Session() as s:
        host_or_404(s,host_id)
        endpoint=body.endpoint if body else 'default'
        selected=next((item for item in enrollment_endpoints(request) if item['id']==endpoint),None)
        if selected is None:
            raise HTTPException(400,'HTTPS endpoint is unavailable. Select an enabled profile in Settings → HTTPS.')
        token=secrets.token_urlsafe(32)
        s.add(Setting(key='enroll:'+token_hash(token),value={'host_id':host_id,'expires':time.time()+3600})); s.commit()
        url=selected['url']+'/enroll/'+token
        return {'url':url,'endpoint':endpoint,'expires_in':3600,
                'command':f'f=$(mktemp) && curl -fsSL {shlex.quote(url)} -o "$f" && sudo bash "$f"; rm -f "$f"'}
@app.get('/enroll/{token}')
def enroll(token:str):
    with Session() as s:
        row=s.get(Setting,'enroll:'+token_hash(token))
        if not row or row.value['expires']<time.time(): raise HTTPException(404,'Enrollment link expired')
        h=host_or_404(s,row.value['host_id'])
        if not host_lifecycle.active(h):raise HTTPException(410,'Server management is disabled or deleted')
        with host_lifecycle.activity([h.id],'control'):return PlainTextResponse(ssh.bootstrap(h))
@app.post('/api/hosts/{host_id}/actions/{action}')
def host_action(host_id:str,action:str,user=Depends(auth)):
    if action not in ['deploy','refresh','repair','rotate-key']: raise HTTPException(404,'Unknown action')
    with Session() as s:
        h=host_or_404(s,host_id)
        if not h.fingerprint: raise HTTPException(400,'Pin the host fingerprint first')
        return {'job_id':worker.enqueue(s,host_id,action)}
@app.get('/api/hosts/{host_id}/packages')
def packages(host_id:str,q:str='',updates:bool=False,user=Depends(auth)):
    with Session() as s:
        h=host_or_404(s,host_id); cfg=config(s)
        versions={}
        for item in h.inventory.get("rpm_packages",[]):versions.setdefault(item["name"]+":"+item["arch"],[]).append(item["evr"])
        stmt=select(Package).where(Package.host_id==host_id).order_by(Package.name)
        if q: stmt=stmt.where(Package.name.contains(q[:200],autoescape=True))
        if updates: stmt=stmt.where(Package.candidate!='')
        planner=install_times.Planner(s,h)
        rows=list(s.scalars(stmt))
        historical_scores=update_scores.historical_cache(s,[(host_id,p.name,v) for p in rows for v in versions.get(p.name,[p.installed])])
        identities={p.id:update_scores.identity(h,p) for p in rows if p.candidate}
        keys=list(identities.values());scores={}
        # Saved assessments outlive candidates; fetch only this view's current identities.
        for start in range(0,len(keys),400):
            scores.update({r.id:r for r in s.scalars(select(update_scores.UpdateScore).where(update_scores.UpdateScore.id.in_(keys[start:start+400])))})
        return [object_dict(p)|{'installed_versions':versions.get(p.name,[p.installed]),'due':p.available_since+cfg['deadlines'][p.priority]*3600 if p.candidate else None,
            'installed_assessment':update_scores.historical(s,host_id,p.name,versions.get(p.name,[p.installed]),observed=h.inventory.get('collected'),cache=historical_scores) if p.candidate else None,
            'installation':planner.for_package(p),'assessment':update_scores.public(scores.get(identities[p.id]),cfg['ai_enabled'] and cfg['ai_updates_enabled']) if p.candidate else update_scores.historical(s,host_id,p.name,versions.get(p.name,[p.installed]),observed=h.inventory.get('collected'),cache=historical_scores)} for p in rows]
class PatchInput(BaseModel):
    packages:list[str]=Field(min_length=1,max_length=500)
    expected_versions:dict[str,str]|None=None
    expected_recovery_policy:dict[str,bool]|None=None

def reviewed_policy(s,host_id,expected):
    policy=operations.recovery_policy(s,host_id)
    if expected is None:
        if any(policy.values()):raise HTTPException(409,'Review the current reboot and rollback policy before submitting')
    elif expected!=policy:raise HTTPException(409,'Recovery policy changed; reopen the patch confirmation')
    if operations.host_quarantined(s,host_id):raise HTTPException(409,'Host has a running or unreconciled operation')
    return policy

@app.get('/api/hosts/{host_id}/patch-policy')
def patch_policy(host_id:str,user=Depends(auth)):
    with Session() as s:
        host_or_404(s,host_id)
        return operations.recovery_policy(s,host_id)

@app.post('/api/hosts/{host_id}/patch')
def patch(host_id:str,body:PatchInput,user=Depends(auth)):
    with Session() as s:
        h=host_or_404(s,host_id)
        policy=reviewed_policy(s,host_id,body.expected_recovery_policy)
        if h.repo_error or not h.last_repo or time.time()-h.last_repo>config(s)['repo_minutes']*120: raise HTTPException(409,'Refresh repositories before patching; candidate data is stale')
        specs=[]
        if len(set(body.packages))!=len(body.packages): raise HTTPException(400,'Duplicate package selections')
        if body.expected_versions is not None and set(body.expected_versions)!=set(body.packages): raise HTTPException(400,'Expected versions must match selected packages')
        for name in body.packages:
            p=s.get(Package,host_id+':'+name)
            if not p or not p.candidate or p.held or p.dpkg_state.split()[-1]!='installed': raise HTTPException(400,'Package missing, held, broken, or has no available update: '+name)
            if body.expected_versions is not None and body.expected_versions[name]!=p.candidate: raise HTTPException(409,'Candidate changed; reload and review '+name)
            specs.append(p.name+'='+p.candidate)
        return {'job_id':worker.enqueue(s,host_id,'patch',{'packages':specs,'_recovery_policy':policy,'_actor':user['username']})}
@app.get('/api/hosts/{host_id}/repositories')
def repositories(host_id:str,user=Depends(auth)):
    with Session() as s:
        h=host_or_404(s,host_id)
        access=worker.repository_access(s,host_id);health=[]
        for path,content in h.inventory.get('files',{}).items():
            if not package_backend.source_path(path,h.inventory): continue
            try:
                active=package_backend.sources(content,path,h.inventory,access)
                state='disabled' if not active else ('check_failed' if h.repo_error else ('checked' if h.last_repo else 'unverified'))
                detail='Central package metadata check includes this source' if active else 'No active repositories'
            except ValueError as e: state='blocked';detail=str(e)
            health.append({'path':path,'state':state,'detail':detail})
        return {'package_manager':h.inventory.get('package_manager','apt'),'editable_paths':[path for path in h.inventory.get('files',{}) if package_backend.source_path(path,h.inventory)],'files':h.inventory.get('files',{}),'keys':list(h.inventory.get('keys',{})),'last_checked':h.last_repo,'error':h.repo_error,'health':health}
class RepoInput(BaseModel):
    path:str=Field(max_length=300)
    content:str=Field(max_length=1_000_000)
@app.put('/api/hosts/{host_id}/repositories')
def repository(host_id:str,body:RepoInput,user=Depends(auth)):
    with Session() as s:
        h=host_or_404(s,host_id)
        if not package_backend.source_path(body.path,h.inventory): raise HTTPException(400,'Unsupported repository path for this target')
        package_backend.sources(body.content,body.path,h.inventory,worker.repository_access(s,host_id))
        return {'job_id':worker.enqueue(s,host_id,'repository',body.model_dump())}
class KeyInput(BaseModel): name:str; data:str=Field(max_length=3_000_000)
@app.put('/api/hosts/{host_id}/keys')
def key_upload(host_id:str,body:KeyInput,user=Depends(auth)):
    if not re.fullmatch(r'[A-Za-z0-9_-]+\.(gpg|asc)',body.name): raise HTTPException(400,'Use a .gpg or .asc filename')
    try: base64.b64decode(body.data,validate=True)
    except ValueError: raise HTTPException(400,'Invalid base64 key data')
    with Session() as s:
        host_or_404(s,host_id); return {'job_id':worker.enqueue(s,host_id,'key',body.model_dump())}
@app.get('/api/investigations')
def investigations(host_id:str='',offset:int=0,limit:int=500,user=Depends(auth)):
    if offset<0 or not 1<=limit<=500:raise HTTPException(400,'Invalid investigation pagination')
    with Session() as s:
        stmt=select(Behavior).order_by(Behavior.approved,Behavior.last_seen.desc(),Behavior.id).offset(offset).limit(limit)
        if host_id: host_or_404(s,host_id);stmt=stmt.where(Behavior.host_id==host_id)
        else:stmt=stmt.where(Behavior.host_id.not_in(host_lifecycle.inactive_ids()))
        from . import ai_retry,ai_policy,ai_claims
        rows=list(s.scalars(stmt));signature=ai_retry.configuration(s);paused=set(s.scalars(ai_policy.paused_ids()))
        retries={r.subject:r for r in s.scalars(select(ai_retry.TriageRetry).where(ai_retry.TriageRetry.subject.in_([x.id for x in rows])))}
        claimed=set(s.scalars(select(ai_claims.Claim.subject).where(ai_claims.Claim.subject.in_([x.id for x in rows]),ai_claims.Claim.expires>time.time())))
        result=[];now=time.time()
        for row in rows:
            retry=None
            if not row.approved and row.verdict in ('error','pending'):
                retry=ai_retry.summary(retries.get(row.id),signature,now,row.attempted)
                if row.id in claimed:retry={**retry,'state':'running','next_at':0,'reason':'A worker owns this investigation. Its result must still pass ownership and evidence checks.'}
                if row.host_id in paused:retry={**retry,'state':'paused','next_at':0,'reason':'AI integration is paused for this server. Historical results remain available.'}
            result.append(object_dict(row)|{'retry':retry})
        return result
class ApproveInput(BaseModel): approved:bool
@app.put('/api/investigations/{behavior_id}')
def approve(behavior_id:str,body:ApproveInput,user=Depends(auth)):
    with Session() as s:
        row=s.get(Behavior,behavior_id)
        if not row: raise HTTPException(404,'Behavior not found')
        with host_lifecycle.activity([row.host_id],'queue'):
            row.approved=body.approved; audit(s,'approve behavior' if body.approved else 'revoke behavior',behavior_id); s.commit(); return {'ok':True}

class RetriageInput(BaseModel):
    expected_revision:str=Field(pattern=r'^[a-f0-9]{64}$')
    reason:str=Field(min_length=10,max_length=4000)
    withdraw_approval:bool=False


class RevokeKnownGoodInput(BaseModel):
    expected_version:int=Field(ge=1,le=1_000_000,strict=True)
    reason:str=Field(min_length=10,max_length=1000)


@app.post('/api/investigations/{behavior_id}/retriage')
def retriage_investigation(behavior_id:str,body:RetriageInput,user=Depends(auth)):
    from . import ai_assessments,ai_claims
    reason=body.reason.strip()
    if len(reason)<10:raise HTTPException(400,'Provide a meaningful re-triage reason')
    lock=worker.Lock('ai-triage')
    if not lock.acquire(False):raise HTTPException(409,'An investigation is running. Reopen Re-triage when it finishes.')
    try:
        with Session() as s:
            claim=s.get(ai_claims.Claim,behavior_id)
            if claim and claim.expires>time.time():raise HTTPException(409,'This investigation is running. Reopen Re-triage when it finishes.')
            row=s.get(Behavior,behavior_id)
            if not row:raise HTTPException(404,'Investigation not found')
            if not host_lifecycle.active(s.get(Host,row.host_id)):raise HTTPException(409,'Server management is unavailable; retained assessments are read-only')
            host_id=row.host_id
            with host_lifecycle.activity([host_id],'queue'):
                # Approval mutations use this host lock. Drop the pre-lock read
                # transaction so MySQL repeatable-read cannot hide a new approval.
                s.rollback();row=s.get(Behavior,behavior_id)
                if not row or row.host_id!=host_id:raise HTTPException(409,'Investigation identity changed; reopen Re-triage')
                try:refresh=ai_assessments.queue(s,row,body.expected_revision,reason,user['username'],body.withdraw_approval)
                except ValueError as error:raise HTTPException(409,str(error)) from None
                s.commit()
                return {'ok':True,'request_id':refresh.id,'detail':'Fresh triage queued. Prior assessment retained; AI pause, model settings and admission limits still apply.'}
    finally:lock.release()


@app.post('/api/ai/known-good/{fingerprint}/revoke')
def revoke_known_good(fingerprint:str,body:RevokeKnownGoodInput,user=Depends(auth)):
    from . import known_good
    if not re.fullmatch(r'[a-f0-9]{64}',fingerprint):
        raise HTTPException(400,'Invalid known-good fingerprint')
    reason=body.reason.strip()
    if len(reason)<10:raise HTTPException(400,'Provide a meaningful revocation reason')
    lock=worker.Lock('ai-triage')
    if not lock.acquire(False):
        raise HTTPException(409,'An investigation is updating known-good state. Reopen the assessment when it finishes.')
    try:
        with Session() as s:
            try:result=known_good.revoke(s,fingerprint,body.expected_version,user['username'],reason)
            except LookupError as error:raise HTTPException(404,str(error)) from None
            except ValueError as error:raise HTTPException(409,str(error)) from None
            s.commit()
            return {**result,'detail':f'Candidate revoked across the fleet. {result["linked_assessments"]} linked assessment(s) require review.'}
    finally:lock.release()


@app.get('/api/investigations/{behavior_id}/history')
def investigation_history(behavior_id:str,host_id:str='',offset:int=0,limit:int=20,user=Depends(auth)):
    from . import ai_assessments
    if offset<0 or not 1<=limit<=50:raise HTTPException(400,'Invalid assessment pagination')
    with Session() as s:
        row=s.get(Behavior,behavior_id)
        if host_id:host_or_404(s,host_id)
        if not row or (host_id and row.host_id!=host_id):raise HTTPException(404,'Investigation not found in this scope')
        rows=list(s.scalars(select(ai_assessments.Assessment).where(ai_assessments.Assessment.subject==row.id,ai_assessments.Assessment.host_id==row.host_id).order_by(ai_assessments.Assessment.created.desc(),ai_assessments.Assessment.id.desc()).offset(offset).limit(limit+1)))
        return {'current':{'id':row.id,'host_id':row.host_id,'executable':row.evidence.get('executable',''),'verdict':row.verdict,'analysis':row.analysis,'approved':row.approved,'revision':ai_assessments.revision(row),'can_retriage':host_lifecycle.active(s.get(Host,row.host_id)) and row.verdict in ai_assessments.COMPLETE and not s.get(ai_assessments.Refresh,row.id),
            'refresh':ai_assessments.refresh_info(s.get(ai_assessments.Refresh,row.id))},
            'items':[{'id':r.id,'source':r.source,'created':r.created,'risk':r.result.get('risk','unknown'),'model':r.model,'run_id':r.run_id} for r in rows[:limit]],'more':len(rows)>limit}


@app.get('/api/investigations/{behavior_id}/history/{assessment_id}')
def investigation_assessment(behavior_id:str,assessment_id:str,host_id:str='',user=Depends(auth)):
    from . import ai_assessments, known_good
    with Session() as s:
        behavior=s.get(Behavior,behavior_id);row=s.get(ai_assessments.Assessment,assessment_id)
        if host_id:host_or_404(s,host_id)
        if not behavior or not row or row.subject!=behavior.id or row.host_id!=behavior.host_id or (host_id and row.host_id!=host_id):raise HTTPException(404,'Assessment not found in this scope')
        result=object_dict(row);result['known_good']=known_good.assessment(row,s)
        return result
@app.get('/api/operations/workers')
def registered_workers(offset:int=0,user=Depends(auth)):
    from .worker_registry import page
    return page(offset)

class WorkerControlInput(BaseModel):
    worker_id:str=Field(pattern=r'^[A-Za-z0-9_.:-]{1,48}$')
    boot_id:str=Field(pattern=r'^[0-9a-f]{32}$')
    revision:int=Field(ge=0,le=1_000_000_000,strict=True)
    action:str=Field(pattern=r'^(drain|resume)$')
    reason:str=Field(min_length=10,max_length=1000)

@app.post('/api/operations/workers/control')
def control_worker(body:WorkerControlInput,user=Depends(auth)):
    from .worker_registry import request_control
    return request_control(body.worker_id,body.boot_id,body.revision,body.action,body.reason,user['username'])

@app.get('/api/jobs')
def jobs(host_id:str='',offset:int=0,limit:int=100,user=Depends(auth)):
    if offset<0 or not 1<=limit<=100:raise HTTPException(400,'Invalid operation pagination')
    with Session() as s:
        query=select(Job)
        if host_id:host_or_404(s,host_id);query=query.where(Job.host_id==host_id)
        return [public_job(x) for x in s.scalars(query.order_by(Job.created.desc(),Job.id).offset(offset).limit(limit))]
@app.get('/api/audit')
def audit_log(offset:int=0,limit:int=200,user=Depends(auth)):
    if offset<0 or not 1<=limit<=200:raise HTTPException(400,'Invalid audit pagination')
    with Session() as s:return [object_dict(x) for x in s.scalars(select(Audit).order_by(Audit.created.desc(),Audit.id.desc()).offset(offset).limit(limit))]

@app.get('/api/audit/entries/{entry_id}')
def audit_detail(entry_id:int,user=Depends(auth)):
    with Session() as s:
        row=s.get(Audit,entry_id)
        if not row:raise HTTPException(404,'Audit entry not found')
        return object_dict(row)
@app.get('/api/settings')
def settings(user=Depends(auth)):
    from . import ai_budget,ai_provider_backoff
    with Session() as s:
        cfg=config(s);legacy=cfg['ai_control_mode']=='legacy'
        return cfg|{'api_key_configured':s.get(Setting,'openai_key') is not None,'api_key_revision':ai_key_revision(s.get(Setting,'openai_key')),'tls':tls.public_state(),
            'ai_budget':ai_budget.status(s),'ai_provider_backoff':ai_provider_backoff.status(s),
            'ai_control_migration':{'required':legacy,'suggested_rate_per_hour':min(cfg['ai_hourly_limit'],cfg['ai_update_hourly_limit']),
                'legacy_investigations_per_hour':cfg['ai_hourly_limit'],'legacy_scoring_batches_per_hour':cfg['ai_update_hourly_limit']}}
class ConfigInput(BaseModel):
    repo_minutes:int=Field(ge=5,le=10080)
    deadlines:dict[str,int]
    ai_enabled:bool=False
    ai_model:str=Field(default='',max_length=100)
    ai_hourly_limit:int=Field(default=20,ge=1,le=1000)
    ai_updates_enabled:bool=True
    ai_update_hourly_limit:int=Field(default=20,ge=1,le=1000)
    ai_control_mode:str=Field(default='rate',pattern='^(legacy|rate|daily_cap|rate_and_daily|unthrottled)$')
    ai_rate_per_hour:int=Field(default=20,ge=1,le=1000)
    ai_daily_cap_usd:float=Field(default=10,gt=0,le=1_000_000)
    ai_budget_timezone:str=Field(default='UTC',min_length=1,max_length=64)
    history_days:int=Field(default=30,ge=1,le=3650)
    api_key:str=Field(default='',max_length=1000)
@app.put('/api/settings')
def settings_save(body:ConfigInput,user=Depends(auth)):
    from . import ai_budget
    if set(body.deadlines)!={'critical','high','normal','low'} or any(v<1 or v>8760 for v in body.deadlines.values()): raise HTTPException(400,'Provide four priority deadlines, 1–8760 hours')
    body.ai_model=body.ai_model.strip();body.api_key=body.api_key.strip()
    if body.ai_model and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}',body.ai_model):raise HTTPException(400,'Enter an API model ID without whitespace, not a ChatGPT display label')
    if body.api_key and not re.fullmatch(r'[!-~]+',body.api_key):raise HTTPException(400,'The API key contains whitespace or unsupported characters')
    if not ai_budget.valid_timezone(body.ai_budget_timezone):raise HTTPException(400,'Enter a valid IANA timezone for the daily AI budget reset')
    with Session() as s:
        if body.ai_enabled and (not body.ai_model or not (body.api_key or s.get(Setting,'openai_key'))): raise HTTPException(400,'AI requires a model and an API key')
        s.merge(Setting(key='config',value=body.model_dump(exclude={'api_key'})))
        if body.api_key: s.merge(Setting(key='openai_key',value={'encrypted':seal(body.api_key)}))
        audit(s,'update settings','Patch policy, cadence or AI configuration changed'); s.commit(); return {'ok':True}

def ai_key_revision(secret):
    # An opaque version of randomized ciphertext, not a fingerprint of the key.
    return hashlib.sha256(secret.value['encrypted'].encode()).hexdigest()[:32] if secret else ''

class AISettingsInput(BaseModel):
    model_config={'extra':'forbid'}
    ai_enabled:bool=False
    ai_model:str=Field(default='',max_length=100)
    ai_hourly_limit:int=Field(default=20,ge=1,le=1000)
    ai_updates_enabled:bool=True
    ai_update_hourly_limit:int=Field(default=20,ge=1,le=1000)
    ai_control_mode:str=Field(default='legacy',pattern='^(legacy|rate|daily_cap|rate_and_daily|unthrottled)$')
    ai_rate_per_hour:int=Field(default=20,ge=1,le=1000)
    ai_daily_cap_usd:float=Field(default=10,gt=0,le=1_000_000)
    ai_budget_timezone:str=Field(default='UTC',min_length=1,max_length=64)

class AIKeyInput(BaseModel):
    model_config={'extra':'forbid'}
    api_key:str=Field(min_length=1,max_length=1000)

class PatchSettingsInput(BaseModel):
    model_config={'extra':'forbid'}
    repo_minutes:int=Field(ge=5,le=10080)
    deadlines:dict[str,int]

class HistorySettingsInput(BaseModel):
    model_config={'extra':'forbid'}
    history_days:int=Field(ge=1,le=3650)

def save_settings_section(values,section):
    with worker.Lock('settings-config'):
        with Session() as s:
            if section=='ai' and values['ai_enabled'] and (not values['ai_model'] or not s.get(Setting,'openai_key')):
                raise HTTPException(400,'Save an API key and select a model before enabling AI. You can save a key independently above.')
            previous=config(s);s.merge(Setting(key='config',value=previous|values))
            detail='Saved '+section+' configuration; no provider test was performed'
            if section=='ai' and previous['ai_control_mode']!=values['ai_control_mode']:
                detail+='; AI admission changed from '+previous['ai_control_mode']+' to '+values['ai_control_mode']
            if section=='ai' and previous['ai_daily_cap_usd']!=values['ai_daily_cap_usd']:
                detail+='; daily AI cap changed from $'+str(previous['ai_daily_cap_usd'])+' to $'+str(values['ai_daily_cap_usd'])
            if section=='ai' and previous['ai_budget_timezone']!=values['ai_budget_timezone']:
                detail+='; daily AI reset timezone changed from '+previous['ai_budget_timezone']+' to '+values['ai_budget_timezone']
            audit(s,'update '+section+' settings',detail)
            s.commit()
            return {'ok':True,**values,'api_key_revision':ai_key_revision(s.get(Setting,'openai_key'))}

@app.put('/api/settings/ai-key')
def ai_key_save(body:AIKeyInput,user=Depends(auth)):
    key=body.api_key.strip()
    if not re.fullmatch(r'[!-~]{1,1000}',key):raise HTTPException(400,'Enter an API key without whitespace or unsupported characters')
    with worker.Lock('settings-config'):
        with Session() as s:
            secret=Setting(key='openai_key',value={'encrypted':seal(key)})
            s.merge(secret)
            audit(s,'update AI API key',user['username']+' saved an API key; model unchanged; no provider test was performed')
            s.commit()
            return {'ok':True,'api_key_configured':True,'api_key_revision':ai_key_revision(secret)}

@app.put('/api/settings/ai')
def ai_settings_save(body:AISettingsInput,user=Depends(auth)):
    from . import ai_budget
    body.ai_model=body.ai_model.strip()
    if body.ai_model and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}',body.ai_model):
        raise HTTPException(400,'Enter an API model ID without whitespace, not a ChatGPT display label')
    if not ai_budget.valid_timezone(body.ai_budget_timezone):raise HTTPException(400,'Enter a valid IANA timezone for the daily AI budget reset')
    return save_settings_section(body.model_dump(),'ai')

@app.put('/api/settings/patching')
def patch_settings_save(body:PatchSettingsInput,user=Depends(auth)):
    if set(body.deadlines)!={'critical','high','normal','low'} or any(v<1 or v>8760 for v in body.deadlines.values()):
        raise HTTPException(400,'Provide four priority deadlines, 1–8760 hours')
    return save_settings_section(body.model_dump(),'patching')

@app.put('/api/settings/history')
def history_settings_save(body:HistorySettingsInput,user=Depends(auth)):
    return save_settings_section(body.model_dump(),'history')

class AITestInput(BaseModel):
    model_config={'extra':'forbid'}
    expected_model:str|None=Field(default=None,max_length=100)
    expected_key_revision:str|None=Field(default=None,max_length=64)

@app.post('/api/settings/ai-test')
def ai_test(body:AITestInput|None=None,user=Depends(auth)):
    lock=worker.Lock('ai-connection-test')
    if not lock.acquire(False):raise HTTPException(409,'An AI connection test is already running')
    try:
        with Session() as s:
            cfg=config(s);secret=s.get(Setting,'openai_key');last=s.get(Setting,'ai-test:last')
            if body and ((body.expected_model is not None and body.expected_model!=cfg['ai_model']) or (body.expected_key_revision is not None and body.expected_key_revision!=ai_key_revision(secret))):
                raise HTTPException(409,'Saved AI configuration changed. Reload the AI section before testing; no provider request was sent.')
            if not cfg['ai_model'] or not secret:raise HTTPException(400,'Save a model ID and API key before testing')
            if last and time.time()-last.value['attempted']<60:raise HTTPException(429,'Wait one minute between AI connection tests')
            encrypted=secret.value['encrypted']
            s.merge(Setting(key='ai-test:last',value={'attempted':time.time()}));s.commit()
        run_id=None
        try:
            with ai_runs.track('connection_test',cfg['ai_model'],subject=user['username']) as run_id:
                key=unseal(encrypted)
                ai.investigate({'diagnostic':'Connection and JSON-schema compatibility test only. No process or server evidence was supplied. Return unknown risk and request no checks.'},cfg['ai_model'],key)
        except Exception as error:
            return JSONResponse({'detail':'Test failed for model '+cfg['ai_model']+'. '+ai_runs.safe_error(error)+' Your saved model was not changed.', 'model':cfg['ai_model'],'run_id':run_id},status_code=502)
        return {'ok':True,'model':cfg['ai_model'],'run_id':run_id,'detail':'OpenAI connection and structured-output test passed for model '+cfg['ai_model']+'. No server evidence was sent.'}
    finally:lock.release()

@app.get('/api/settings/ai-models')
def ai_models(user=Depends(auth)):
    with Session() as s:
        secret=s.get(Setting,'openai_key')
        if not secret:raise HTTPException(400,'Save your API key in Settings → AI & models, then refresh models.')
        encrypted=secret.value['encrypted']
        selected=config(s)['ai_model']
    try:models=ai.list_models(unseal(encrypted))
    except Exception as error:return JSONResponse({'detail':'Model discovery failed. '+ai_runs.safe_error(error)+' You can still enter and save an exact model ID manually; saving does not call OpenAI.'},status_code=502)
    return {'models':models,'selected':selected,'selected_available':selected in models}

from . import database_config

@app.get('/api/settings/database')
def database_settings(user=Depends(auth)):
    return database_config.public_state()

@app.put('/api/settings/database')
def database_settings_save(body:database_config.DatabaseInput,user=Depends(auth)):
    result=database_config.stage(body)
    with Session() as s:
        audit(s,'stage database migration',user['username']+' staged '+body.backend+' destination; active database unchanged')
        s.commit()
    return {'ok':True,'target':result}

class TLSInput(BaseModel):
    domain:str=Field(default='',max_length=253)
    aliases:list[str]=Field(default_factory=list,max_length=20)
    enabled:bool=True
    mode:str=Field(pattern=r'^(internal|uploaded|acme)$')
    acme_url:str=Field(default='',max_length=2000)
    email:str=Field(default='',max_length=320)
    https_port:int|None=Field(default=None,ge=1,le=65535)
    redirect_http:bool=True
    challenge:str=Field(default='auto',pattern=r'^(auto|http|tlsalpn)$')
    certificate:str=Field(default='',max_length=100000)
    private_key:str=Field(default='',max_length=100000)
    ca:str=Field(default='',max_length=100000)
    clear_ca:bool=False
    eab_id:str=Field(default='',max_length=512)
    eab_key:str=Field(default='',max_length=2000)
    clear_eab:bool=False

@app.get('/api/tls')
def tls_settings(user=Depends(auth)):
    return tls.public_state()

@app.put('/api/tls')
def tls_save(body:TLSInput,user=Depends(auth)):
    return tls_profile_save('internal',body,user)

@app.put('/api/tls/{profile}')
def tls_profile_save(profile:str,body:TLSInput,user=Depends(auth)):
    try: result=tls.apply(body.model_dump(),profile)
    except Exception as e: raise HTTPException(400,'TLS configuration rejected: '+str(e)[:1000])
    with Session() as s:
        s.merge(Setting(key='tls',value=result));audit(s,'update TLS',profile+' '+body.domain+' '+body.mode);s.commit()
    return result

class PriorityInput(BaseModel):
    name:str
    priority:str
@app.put('/api/hosts/{host_id}/priority')
def set_priority(host_id:str,body:PriorityInput,user=Depends(auth)):
    if body.priority not in ['critical','high','normal','low','auto']: raise HTTPException(400,'Invalid priority')
    with host_change(host_id), Session() as s:
        p=s.get(Package,host_id+':'+body.name)
        if not p: raise HTTPException(404,'Package not found')
        p.priority_manual=body.priority!='auto'
        p.priority=body.priority if p.priority_manual else ('high' if '-security' in p.origin or '/security' in p.origin else 'normal')
        audit(s,'set package priority',host_id+' '+body.name+' '+body.priority);s.commit();return {'ok':True}

@app.get('/api/jobs/{job_id}')
def job_detail(job_id:str,host_id:str="",user=Depends(auth)):
    with Session() as s:
        job=s.get(Job,job_id)
        if not job or (host_id and job.host_id!=host_id): raise HTTPException(404,'Operation not found')
        return public_job(job)

@app.get('/api/hosts/{host_id}/history')
def history(host_id:str,kind:str='inventory',offset:int=0,limit:int=50,user=Depends(auth)):
    if kind not in ('inventory','observations') or offset<0 or not 1<=limit<=100: raise HTTPException(400,'Invalid history query')
    model=InventoryRevision if kind=='inventory' else Observation
    timestamp=model.created if kind=='inventory' else model.observed
    with Session() as s:
        host_or_404(s,host_id)
        return [object_dict(row,('inventory','evidence')) for row in s.scalars(select(model).where(model.host_id==host_id).order_by(timestamp.desc()).offset(offset).limit(limit))]

@app.get('/api/hosts/{host_id}/backups')
def repository_backups(host_id:str,user=Depends(auth)):
    with Session() as s:
        h=host_or_404(s,host_id)
        try: return ssh.call(h,{'action':'backups'})
        except Exception as e: raise HTTPException(502,str(e)[:1000])

class RepositoryAccess(BaseModel):
    credentials:list[dict[str,str]]=Field(default_factory=list,max_length=50)
    proxy:str=Field(default='',max_length=2000)
    ca:str=Field(default='',max_length=100000)
    default_release:str=Field(default='',max_length=120)
    mirrors:dict[str,str]=Field(default_factory=dict)
    replace_credentials:bool=False

@app.get('/api/hosts/{host_id}/repository-access')
def get_repository_access(host_id:str,user=Depends(auth)):
    with Session() as s:
        host_or_404(s,host_id);access=worker.repository_access(s,host_id)
        return {k:v for k,v in access.items() if k!='credentials'}|{'credential_scopes':[c['machine'] for c in access.get('credentials',[])]}

@app.put('/api/hosts/{host_id}/repository-access')
def save_repository_access(host_id:str,body:RepositoryAccess,user=Depends(auth)):
    from .repository_access import validate
    with host_change(host_id), Session() as s:
        h=host_or_404(s,host_id);value=body.model_dump(exclude={'replace_credentials'})
        if not body.replace_credentials: value['credentials']=worker.repository_access(s,host_id).get('credentials',[])
        try: validate(value)
        except Exception as e: raise HTTPException(400,str(e)[:1000])
        s.merge(Setting(key='repository-access:'+host_id,value={'encrypted':seal(json.dumps(value))}))
        h.last_repo=0;audit(s,'update repository access',host_id);s.commit();return {'ok':True}

@app.get('/api/investigation-status')
def investigation_status(user=Depends(auth)):
    with Session() as s:
        return ai_runs.status(s)

@app.get('/api/hosts/{host_id}/history/{record_id}')
def history_detail(host_id:str,record_id:str,kind:str='inventory',user=Depends(auth)):
    if kind not in ('inventory','observations'): raise HTTPException(400,'Invalid history kind')
    model=InventoryRevision if kind=='inventory' else Observation
    with Session() as s:
        record=s.get(model,record_id)
        if not record or record.host_id!=host_id: raise HTTPException(404,'History record not found')
        return object_dict(record)

@app.get('/api/identity')
def identity_info(user=Depends(auth)): return {**{k:user[k] for k in ('username','role','mfa')},'version':APP_VERSION}

class UserInput(BaseModel):
    username:str=Field(pattern=r'^[A-Za-z0-9_.-]{1,64}$')
    password:str=Field(default='',max_length=1024)
    role:str=Field(pattern=r'^(admin|operator|viewer)$')
    enabled:bool=True

@app.get('/api/users')
def users(user=Depends(auth)):
    with Session() as s: return [{'username':u.username,'role':u.role,'enabled':u.enabled,'mfa':bool(u.otp_secret)} for u in s.scalars(select(User))]

@app.put('/api/users')
def save_user(body:UserInput,user=Depends(auth)):
    if body.username=='admin' and (body.role!='admin' or not body.enabled): raise HTTPException(400,'The bootstrap administrator must remain enabled')
    if body.username==user['username'] and (not body.enabled or body.role!='admin'): raise HTTPException(400,'Cannot revoke your own administrator access')
    if body.password and len(body.password)<12: raise HTTPException(400,'Password must have at least 12 characters')
    with Session() as s:
        row=s.get(User,body.username)
        if not row:
            if not body.password: raise HTTPException(400,'New users require a password')
            row=User(username=body.username,password=password_hash(body.password));s.add(row);s.flush()
        elif body.password: row.password=password_hash(body.password)
        row.role=body.role;row.enabled=body.enabled;row.generation+=1
        audit(s,'manage user',user['username']+' → '+body.username);s.commit()
    return {'ok':True}

class Reauthenticate(BaseModel):
    password:str=Field(max_length=1024)
    otp:str=Field(default='',max_length=6)
    new_password:str=Field(default='',max_length=1024)

def reserve_account_attempt(username):
    # Account-wide across password, MFA setup/confirmation and session revocation.
    # Called under login_lock; these endpoints must not bypass login throttling.
    key='account:'+username;now=time.time()
    attempts=[t for t in login_attempts.get(key,[]) if now-t<300]
    if len(attempts)>=10:raise HTTPException(429,'Too many account verification attempts. Try again in five minutes.')
    login_attempts[key]=attempts+[now]

def check_password(row,body):
    reserve_account_attempt(row.username)
    if not verify(body.password,row.password): raise HTTPException(403,'Invalid credentials')
    if row.otp_secret and not consume_otp(row,body.otp): raise HTTPException(403,'Invalid MFA code')

@app.post('/api/identity/mfa')
def begin_mfa(body:Reauthenticate,user=Depends(auth)):
    from urllib.parse import quote
    with login_lock, Session() as s:
        row=s.get(User,user['username']);check_password(row,body)
        secret=new_secret();row.otp_pending=seal(secret);s.commit()
        return {'secret':secret,'uri':'otpauth://totp/MrPatchy:'+quote(row.username)+'?secret='+secret+'&issuer=MrPatchy&algorithm=SHA1&digits=6&period=30'}

class OTPInput(BaseModel): otp:str=Field(max_length=6)
@app.post('/api/identity/mfa/confirm')
def confirm_mfa(body:OTPInput,user=Depends(auth)):
    with login_lock, Session() as s:
        row=s.get(User,user['username'])
        reserve_account_attempt(row.username)
        if not consume_otp(row,body.otp,pending=True): raise HTTPException(400,'Invalid confirmation code')
        row.otp_secret=row.otp_pending;row.otp_pending='';row.generation+=1
        audit(s,'enable MFA',row.username);s.commit()
    return {'ok':True,'sign_in_again':True}

@app.put('/api/identity/password')
def change_password(body:Reauthenticate,user=Depends(auth)):
    if len(body.new_password)<12: raise HTTPException(400,'Password must have at least 12 characters')
    with login_lock, Session() as s:
        row=s.get(User,user['username']);check_password(row,body)
        row.password=password_hash(body.new_password);row.generation+=1
        audit(s,'change password',row.username);s.commit()
    return {'ok':True,'sign_in_again':True}

@app.delete('/api/identity/sessions')
def revoke_sessions(body:Reauthenticate,user=Depends(auth)):
    with login_lock, Session() as s:
        row=s.get(User,user['username']);check_password(row,body)
        row.generation+=1;audit(s,'revoke sessions',row.username);s.commit()
    return {'ok':True,'sign_in_again':True}

class WindowInput(BaseModel): windows:list[dict]=Field(default_factory=list,max_length=20)
@app.put('/api/operations/{host_id}/window')
def save_window(host_id:str,body:WindowInput,user=Depends(auth)):
    for w in body.windows:
        if set(w)!={'days','start','end'} or not isinstance(w['days'],list) or not w['days'] or any(type(d)!=int or d not in range(7) for d in w['days']) or type(w['start'])!=int or type(w['end'])!=int or not 0<=w['start']<w['end']<=1440:
            raise HTTPException(400,'Windows require days 0–6 (Monday first) and start/end UTC minutes within one day')
    with host_change(host_id),Session() as s:
        host_or_404(s,host_id);s.merge(Setting(key='window:'+host_id,value=body.model_dump()));s.commit()
    return {'ok':True}
@app.get('/api/operations/{host_id}/window')
def get_window(host_id:str,user=Depends(auth)):
    with Session() as s:
        host_or_404(s,host_id);row=s.get(Setting,'window:'+host_id)
        return row.value if row else {'windows':[]}

class NotificationInput(BaseModel):
    enabled:bool=False
    url:str=Field(default='',max_length=2000)
    token:str=Field(default='',max_length=2000)
    clear_token:bool=False

def notification_config(s):
    row=s.get(Setting,'notifications')
    return json.loads(unseal(row.value['encrypted'])) if row else {}

def retain_notification_secret(previous,value,secret,clear,identity):
    if clear:value[secret]=''
    elif not value.get(secret) and previous.get(secret):
        if any(previous.get(key,'')!=value.get(key,'') for key in identity):
            raise HTTPException(400,'Enter or explicitly clear the '+secret+' when changing the notification destination/account')
        value[secret]=previous[secret]
    return value

@app.get('/api/operations/notifications')
def notification_settings(user=Depends(auth)):
    with Session() as s:
        value=notification_config(s)
        return {k:v for k,v in value.items() if k not in ('password','token')}|{
            'channel':value.get('channel','webhook'),'password_configured':bool(value.get('password')),
            'token_configured':bool(value.get('token'))}

@app.put('/api/operations/notifications')
def notifications(body:NotificationInput,user=Depends(auth)):
    from urllib.parse import urlsplit
    url=urlsplit(body.url)
    if body.enabled and (url.scheme!='https' or not url.hostname or url.username or url.password or url.fragment):raise HTTPException(400,'Use an HTTPS webhook URL without embedded credentials')
    if any(c in body.token for c in '\r\n'):raise HTTPException(400,'Invalid token')
    with Session() as s:
        previous=notification_config(s)
        value=body.model_dump(exclude={'clear_token'});value['channel']='webhook'
        retain_notification_secret(previous if previous.get('channel','webhook')=='webhook' else {},value,'token',body.clear_token,('url',))
        s.merge(Setting(key='notifications',value={'encrypted':seal(json.dumps(value))}));s.commit()
    return {'ok':True}
@app.get('/api/operations/alerts')
def alerts(user=Depends(auth)):
    with Session() as s:return [object_dict(a) for a in s.scalars(select(operations.Alert).order_by(operations.Alert.created.desc()).limit(200))]
@app.post('/api/operations/alerts/{alert_id}/ack')
def acknowledge_alert(alert_id:str,user=Depends(auth)):
    with Session() as s:
        alert=s.get(operations.Alert,alert_id)
        if not alert:raise HTTPException(404,'Alert not found')
        alert.state='acknowledged';audit(s,'acknowledge alert',user['username']+' '+alert_id);s.commit()
    return {'ok':True}

@app.post('/api/hosts/{host_id}/preview')
def preview_patch(host_id:str,body:PatchInput,user=Depends(auth)):
    with host_change(host_id),Session() as s:
        h=host_or_404(s,host_id);specs=[]
        for name in body.packages:
            p=s.get(Package,host_id+':'+name)
            if not p or not p.candidate:raise HTTPException(400,'Package has no candidate')
            specs.append(name+'='+p.candidate)
        worker.validate_patch(s,h,specs)
        if package_backend.is_rpm(h.inventory):
            return {'plan':'Reviewed RPM candidates:\n'+'\n'.join(specs),'packages':specs,'warning':'Candidate review only. Native DNF resolves dependencies and verifies signatures on the target before installation; removals and downgrades are prohibited.'}
        cfgfile=apt.DATA/'apt'/host_id/'apt.conf'
        if not cfgfile.exists():raise HTTPException(409,'Refresh repositories first')
        result=apt.run(cfgfile,['apt-get','--simulate','--no-remove','--only-upgrade','install','--',*specs])
        return {'plan':result[-48000:],'packages':specs,'warning':'Central simulation; target and repositories are revalidated at execution.'}

@app.post('/api/operations/jobs/{job_id}/cancel')
def cancel_job(job_id:str,user=Depends(auth)):
    with Session() as s:
        job=s.get(Job,job_id)
        if not job:raise HTTPException(404,'Job not found')
        host_id=job.host_id
        publication_cancel=job.action=='trusted-repair-publish'
    with host_change(host_id,allow_quarantined=publication_cancel),Session() as s:
        job=s.get(Job,job_id)
        if job.state!='queued':raise HTTPException(409,'Only queued operations can be cancelled')
        job.state='cancelled'
        if job.action=='trusted-repair-publish':
            from . import repair_publication
            repair_publication.reject_unstarted(s,job,user['username'],'cancelled')
        if job.action in ('release-plan','release-upgrade'):
            plan=s.get(releases.ReleasePlan,job.payload.get('plan_id'))
            if plan and plan.host_id==host_id and plan.job_id==job.id:
                plan.state='cancelled';plan.error='Operation cancelled; prepare a new release plan'
        audit(s,'cancel job',user['username']+' '+job_id);s.commit()
    return {'ok':True}

@app.get('/api/hosts/{host_id}/sbom')
def sbom(host_id:str,user=Depends(auth)):
    from urllib.parse import quote
    with Session() as s:
        h=host_or_404(s,host_id)
        return {'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'serialNumber':'urn:uuid:'+str(uuid.uuid4()),
            'components':[{'type':'library','name':p.name,'version':p.installed,'purl':('pkg:rpm/' if package_backend.is_rpm(h.inventory) else 'pkg:deb/')+quote(p.name.split(':')[0],safe='')+'@'+quote(p.installed,safe='')+'?arch='+p.name.split(':')[-1]} for p in s.scalars(select(Package).where(Package.host_id==host_id))]}

@app.get('/api/audit/export')
def export_audit(after:int=0,limit:int=1000,user=Depends(auth)):
    if after<0 or not 1<=limit<=10000:raise HTTPException(400,'Invalid export bounds')
    with Session() as s:
        rows=[object_dict(row) for row in s.scalars(select(Audit).where(Audit.id>after).order_by(Audit.id).limit(limit))]
        return PlainTextResponse(''.join(json.dumps(row)+'\n' for row in rows),media_type='application/x-ndjson',headers={'Content-Disposition':'attachment; filename="mrpatchy-audit.jsonl"'})

@app.get('/api/metrics')
def metrics(user=Depends(auth)):
    with Session() as s:
        counts={'hosts':s.scalar(select(func.count()).select_from(Host)),'queued_jobs':s.scalar(select(func.count()).select_from(Job).where(Job.state=='queued')),'open_alerts':s.scalar(select(func.count()).select_from(operations.Alert).where(operations.Alert.state=='open'))}
        return PlainTextResponse(''.join('mrpatchy_'+name+' '+str(value)+'\n' for name,value in counts.items()))

class RolloutInput(BaseModel):
    hosts:list[str]=Field(min_length=2,max_length=50)
    packages:list[str]=Field(min_length=1,max_length=500)
    expected_recovery_policies:dict[str,dict[str,bool]]|None=None
@app.post('/api/operations/rollouts')
def rollout(body:RolloutInput,user=Depends(auth)):
    if len(set(body.hosts))!=len(body.hosts):raise HTTPException(400,'Duplicate servers')
    if body.expected_recovery_policies is not None and set(body.expected_recovery_policies)!=set(body.hosts):raise HTTPException(400,'Review recovery policies for every server')
    with host_lifecycle.activity(body.hosts,'queue'),Session() as s:
        prepared=[]
        for host_id in body.hosts:
            h=host_or_404(s,host_id);specs=[]
            if not host_lifecycle.active(h):raise HTTPException(409,'A selected server is disabled or deleted')
            policy=reviewed_policy(s,host_id,(body.expected_recovery_policies or {}).get(host_id))
            if s.scalar(select(func.count()).select_from(Job).where(Job.host_id==host_id,Job.state.in_(['queued','running'])))>=50:raise HTTPException(429,'Server queue is full')
            for name in body.packages:
                p=s.get(Package,host_id+':'+name)
                if not p or not p.candidate:raise HTTPException(400,'Missing candidate on '+h.name+': '+name)
                specs.append(name+'='+p.candidate)
            worker.validate_patch(s,h,specs);prepared.append((h.id,specs,policy,h.lifecycle_revision))
        # One transaction: no partial rollout submission. The first server is the canary.
        ids=[]
        for host_id,specs,policy,revision in prepared:
            job=Job(id=str(uuid.uuid4()),host_id=host_id,action='patch',payload={'packages':specs,'_host_revision':revision,'_depends_on':ids[-1:],'_recovery_policy':policy,'_actor':user['username']})
            s.add(job);ids.append(job.id)
        audit(s,'create staged rollout',user['username']+' '+','.join(ids));s.commit()
        return {'jobs':ids,'canary':ids[0]}

class AdvisoryInput(BaseModel): packages:list[str]=Field(min_length=1,max_length=100)
@app.post('/api/operations/{host_id}/advisories')
def scan_advisories(host_id:str,body:AdvisoryInput,user=Depends(auth)):
    from .advisories import scan
    with host_change(host_id),Session() as s:
        h=host_or_404(s,host_id)
        result=scan(h.inventory,body.packages)
        if len(json.dumps(result).encode())>2000000:raise HTTPException(413,'Advisory result too large')
        s.merge(Setting(key='advisories:'+host_id,value=result));s.commit()
        return result
@app.get('/api/operations/{host_id}/advisories')
def get_advisories(host_id:str,user=Depends(auth)):
    with Session() as s:
        host_or_404(s,host_id);row=s.get(Setting,'advisories:'+host_id)
        return row.value if row else {'results':[],'coverage':'Not checked'}

class SSOBinding(BaseModel):
    subject:str=Field(min_length=1,max_length=500)
    username:str=Field(min_length=1,max_length=64)
@app.put('/api/operations/sso-binding')
def bind_sso(body:SSOBinding,user=Depends(auth)):
    if not sso.issuer:raise HTTPException(409,'Configure OIDC deployment variables first')
    with Session() as s:
        if not s.get(User,body.username):raise HTTPException(404,'Create the local account/role first')
        s.merge(Setting(key=sso.binding_key(body.subject),value={'username':body.username}))
        audit(s,'bind SSO identity',user['username']+' → '+body.username);s.commit()
    return {'ok':True}

class SMTPInput(BaseModel):
    enabled:bool=False
    host:str=Field(max_length=253)
    port:int=Field(default=587,ge=1,le=65535)
    mode:str='starttls'
    sender:str=Field(max_length=320)
    recipients:list[str]=Field(min_length=1,max_length=50)
    username:str=Field(default='',max_length=320)
    password:str=Field(default='',max_length=2000)
    ca:str=Field(default='',max_length=100000)
    clear_password:bool=False
@app.put('/api/operations/smtp')
def smtp_save(body:SMTPInput,user=Depends(auth)):
    from .mail import validate
    value=validate(body.model_dump(exclude={'clear_password'}));value['channel']='smtp'
    with Session() as s:
        previous=notification_config(s)
        retain_notification_secret(previous if previous.get('channel')=='smtp' else {},value,'password',body.clear_password,('host','port','mode','username'))
        s.merge(Setting(key='notifications',value={'encrypted':seal(json.dumps(value))}));s.commit()
    return {'ok':True}

class RecoveryPolicy(BaseModel):
    reboot:bool=False
    rollback:bool=False
@app.put('/api/operations/{host_id}/recovery')
def recovery_policy(host_id:str,body:RecoveryPolicy,user=Depends(auth)):
    with host_change(host_id),Session() as s:
        h=host_or_404(s,host_id)
        status=ssh.call(h,{'action':'recovery-status'})
        if body.rollback and not status['rollback_adapter']:raise HTTPException(409,'Install and validate a root-owned rollback adapter on this target first')
        if body.reboot and not status['systemd']:raise HTTPException(409,'Automatic reboot requires systemd')
        s.merge(Setting(key='recovery:'+host_id,value=body.model_dump()));audit(s,'set recovery policy',host_id);s.commit()
    return {'ok':True,'capabilities':status}

class ObservabilityInput(BaseModel): ebpf:bool=False
@app.put('/api/operations/{host_id}/observability')
def observability(host_id:str,body:ObservabilityInput,user=Depends(auth)):
    with host_change(host_id),Session() as s:
        h=host_or_404(s,host_id);result=ssh.call(h,{'action':'observability','ebpf':body.ebpf})
        path='/etc/systemd/system/mrpatchy-agent.service.d/observability.conf'
        baseline=dict(h.baseline)
        if body.ebpf:baseline[path]=hashlib.sha256(b'[Service]\nProtectSystem=false\nNoNewPrivileges=false\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\n').hexdigest()
        else:baseline.pop(path,None)
        h.baseline=baseline
        audit(s,'configure eBPF',host_id+' '+str(body.ebpf));s.commit()
    return result

class ReconcileInput(BaseModel):
    verified_target_state:bool=False
    verified_ai_receipts:bool=False
@app.post('/api/operations/jobs/{job_id}/reconcile')
def reconcile_job(job_id:str,body:ReconcileInput,user=Depends(auth)):
    with Session() as s:
        job=s.get(Job,job_id)
        if not job:raise HTTPException(404,'Job not found')
        host_id=job.host_id;advisory=job.action in worker.ADVISORY_PLAN_ACTIONS
    if advisory:
        if not body.verified_ai_receipts:raise HTTPException(400,'Review the retained AI run, call usage, and spend reservation before reconciling an interrupted advisory plan')
    elif not body.verified_target_state:raise HTTPException(400,'Review the target state before reconciling an interrupted worker')
    with host_change(host_id,allow_quarantined=True),Session() as s:
        job=s.get(Job,job_id);h=host_or_404(s,host_id)
        if job.state not in operations.QUARANTINE_STATES:raise HTTPException(409,'Only running or recovery-required jobs require reconciliation')
        if not advisory and ssh.call(h,{'action':'operation-status'}).get('busy'):raise HTTPException(409,'Target operation is still running')
        if job.action in ('release-plan','release-upgrade'):
            plan=s.get(worker.releases.ReleasePlan,job.payload.get('plan_id'))
            if plan:plan.state='interrupted'
        job.state='interrupted'
        job.output=('Operator reviewed retained AI run, call usage, and spend reservation after worker interruption; the advisory request was not replayed'
            if advisory else 'Operator reviewed target after worker interruption; operation was not automatically replayed')
        audit(s,'reconcile job',user['username']+' '+job_id);s.commit()
    return {'ok':True}


# Administrator-only release plans expose configuration diffs and authorize reboots.
from . import releases

@app.get('/api/hosts/{host_id}/releases')
def release_plans(host_id:str,user=Depends(auth)):
    with Session() as s:
        host_or_404(s,host_id)
        rows=s.scalars(select(releases.ReleasePlan).where(releases.ReleasePlan.host_id==host_id).order_by(releases.ReleasePlan.created.desc()).limit(20))
        return [{'id':r.id,'state':r.state,'created':r.created,'job_id':r.job_id,'error':r.error} for r in rows]

@app.post('/api/hosts/{host_id}/releases')
def plan_release(host_id:str,user=Depends(auth)):
    with host_change(host_id),Session() as s:
        h=host_or_404(s,host_id)
        if package_backend.is_rpm(h.inventory):raise HTTPException(409,'RPM major release upgrades require a distribution-specific migration plan; regular RPM patching is supported')
        required='/usr/local/lib/mrpatchy/release.py'
        if h.baseline.get(required)!=hashlib.sha256((ssh.TARGET/'release.py').read_bytes()).hexdigest():
            raise HTTPException(409,'Finish / verify installation to install the current release runner first')
        if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.state.in_(['queued','running'])).limit(1)):
            raise HTTPException(409,'Wait for existing host operations before preparing a release plan')
        row=releases.ReleasePlan(id=str(uuid.uuid4()),host_id=host_id)
        job=Job(id=str(uuid.uuid4()),host_id=host_id,action='release-plan',payload={'plan_id':row.id,'_host_revision':h.lifecycle_revision})
        row.job_id=job.id;s.add_all([row,job]);audit(s,'plan distribution upgrade',user['username']+' '+host_id);s.commit()
        return {'plan_id':row.id,'job_id':job.id}

@app.get('/api/hosts/{host_id}/releases/{plan_id}')
def release_plan(host_id:str,plan_id:str,user=Depends(auth)):
    with Session() as s:
        row=s.get(releases.ReleasePlan,plan_id)
        if not row or row.host_id!=host_id:raise HTTPException(404,'Release plan not found')
        return releases.public(row)

class ReleaseDecision(BaseModel):
    decision:str=Field(pattern='^(go|no-go)$')
    digest:str=Field(pattern='^[a-f0-9]{64}$')

@app.post('/api/hosts/{host_id}/releases/{plan_id}/decision')
def decide_release(host_id:str,plan_id:str,body:ReleaseDecision,user=Depends(auth)):
    with host_change(host_id),Session() as s:
        host_or_404(s,host_id);row=s.get(releases.ReleasePlan,plan_id)
        if not row or row.host_id!=host_id:raise HTTPException(404,'Release plan not found')
        plan=releases.body(row)
        if body.digest!=row.digest or releases.digest(releases.canonical(plan))!=row.digest:raise HTTPException(409,'Plan changed; review it again')
        if body.decision=='no-go':
            if row.state not in ('ready','blocked'):raise HTTPException(409,'Only an unapproved completed plan can be declined')
            row.state='declined';audit(s,'decline distribution upgrade',user['username']+' '+row.id);s.commit();return {'state':row.state}
        if row.state=='approved':
            job=s.get(Job,row.job_id)
            if not job or job.state not in ('queued','running'):
                raise HTTPException(409,'Approved operation is no longer pending; prepare a new release plan')
            return {'state':row.state,'job_id':row.job_id}
        if row.state!='ready' or plan.get('blockers'):raise HTTPException(409,'Resolve every blocker and regenerate the plan before GO')
        if plan['expires']<time.time():raise HTTPException(409,'Plan expired; regenerate it')
        if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.state.in_(['queued','running'])).limit(1)):raise HTTPException(409,'Wait for existing host operations before GO')
        job=Job(id=str(uuid.uuid4()),host_id=host_id,action='release-upgrade',payload={'_host_revision':s.get(Host,host_id).lifecycle_revision,'plan_id':row.id,'digest':row.digest,'_actor':user['username']})
        row.job_id=job.id;row.state='approved';s.add(job);audit(s,'approve distribution upgrade',user['username']+' '+row.id+' '+row.digest);s.commit()
        return {'state':row.state,'job_id':job.id}


@app.get('/api/schedules')
def patch_schedules(user=Depends(auth)):
    with Session() as s:
        return {'host_policies':{h.id:operations.recovery_policy(s,h.id) for h in s.scalars(select(Host).where(Host.deleted_at==0))},
                'schedules':[scheduling.serialize(row) for row in s.scalars(select(scheduling.PatchSchedule).order_by(scheduling.PatchSchedule.updated.desc()))],
                'runs':[object_dict(row) for row in s.scalars(select(scheduling.PatchRun).order_by(scheduling.PatchRun.due.desc()).limit(100))]}

@app.get('/api/schedules/calendar')
def patch_calendar(start:float,end:float,user=Depends(auth)):
    with Session() as s: return {'events':scheduling.calendar(s,start,end)}

@app.post('/api/schedules')
def create_patch_schedule(body:scheduling.ScheduleInput,user=Depends(auth)):
    with scheduling.Lock('patch-schedules'),Session() as s:
        return scheduling.save(s,body,None,user['username'])

@app.put('/api/schedules/{schedule_id}')
def update_patch_schedule(schedule_id:str,body:scheduling.ScheduleInput,user=Depends(auth)):
    with scheduling.Lock('patch-schedules'),Session() as s:
        return scheduling.save(s,body,schedule_id,user['username'])

class ScheduleRevision(BaseModel): revision:int=Field(ge=1)

@app.delete('/api/schedules/{schedule_id}')
def delete_patch_schedule(schedule_id:str,body:ScheduleRevision,user=Depends(auth)):
    with scheduling.Lock('patch-schedules'),Session() as s:
        row=s.get(scheduling.PatchSchedule,schedule_id)
        if not row: raise HTTPException(404,'Schedule not found')
        if row.revision!=body.revision: raise HTTPException(409,'Schedule changed; reload before deleting')
        scheduling.cancel_pending(s,schedule_id,'Schedule deleted')
        s.delete(row);audit(s,'delete patch schedule',user['username']+' '+schedule_id);s.commit()
    return {'ok':True}

@app.get('/api/ai/runs')
def ai_run_list(purpose:str='',host_id:str='',offset:int=0,limit:int=50,user=Depends(auth)):
    if purpose not in ('','triage','update_scoring','connection_test','release_configuration','security_plan','worker') or offset<0 or not 1<=limit<=100:raise HTTPException(400,'Invalid log filter')
    with Session() as s:
        query=select(ai_runs.AIRun)
        if purpose:query=query.where(ai_runs.AIRun.purpose==purpose)
        if host_id:
            host_or_404(s,host_id)
            query=query.where((ai_runs.AIRun.host_id==host_id)|ai_runs.AIRun.id.in_(
                select(ai_runs.AIRunHost.run_id).where(ai_runs.AIRunHost.host_id==host_id))|ai_runs.AIRun.id.in_(
                select(update_scores.UpdateScore.run_id).where(update_scores.UpdateScore.host_id==host_id)))
        rows=list(s.scalars(query.order_by(ai_runs.AIRun.started.desc(),ai_runs.AIRun.id).offset(offset).limit(limit+1)))
        receipts=ai_runs.call_receipts(s,[r.id for r in rows[:limit]])
        members=ai_runs.run_hosts(s,[r.id for r in rows[:limit]])
        return {'items':[object_dict(r)|{'cost':ai_runs.cost_summary(r,receipts[r.id]),
            'shared_batch':len(members[r.id])>1} for r in rows[:limit]],'more':len(rows)>limit}

@app.get('/api/ai/runs/{run_id}')
def ai_run_detail(run_id:str,host_id:str='',user=Depends(auth)):
    with Session() as s:
        row=s.get(ai_runs.AIRun,run_id)
        if host_id:
            host_or_404(s,host_id)
            linked=row and (row.host_id==host_id or s.scalar(select(ai_runs.AIRunHost.run_id).where(ai_runs.AIRunHost.run_id==run_id,ai_runs.AIRunHost.host_id==host_id)) or s.scalar(select(update_scores.UpdateScore.id).where(update_scores.UpdateScore.run_id==run_id,update_scores.UpdateScore.host_id==host_id)))
            if not linked:raise HTTPException(404,'AI run not linked to this server')
        if not row:raise HTTPException(404,'AI run not found')
        receipts=ai_runs.call_receipts(s,[row.id])[row.id]
        return object_dict(row)|{'shared_batch':len(ai_runs.run_hosts(s,[row.id])[row.id])>1,'cost':ai_runs.cost_summary(row,receipts), 'api_calls':[object_dict(r) for r in receipts],
            'events':[object_dict(r) for r in s.scalars(select(ai_runs.AIEvent).where(ai_runs.AIEvent.run_id==run_id).order_by(ai_runs.AIEvent.id))]}

@app.post('/api/investigations/{behavior_id}/retry')
def retry_investigation(behavior_id:str,user=Depends(auth)):
    from . import ai_claims
    lock=worker.Lock('ai-triage')
    if not lock.acquire(False):raise HTTPException(409,'An investigation is running. Retry when it finishes.')
    try:
        with Session() as s:
            claim=s.get(ai_claims.Claim,behavior_id)
            if claim and claim.expires>time.time():raise HTTPException(409,'This investigation is running. Retry when it finishes.')
            row=s.get(Behavior,behavior_id)
            if not row or row.approved or row.verdict not in ('error','pending'):raise HTTPException(409,'Only unapproved failed/pending investigations can be retried')
            with host_lifecycle.activity([row.host_id],'queue'):
                from . import ai_retry
                try:ai_retry.manual(s,row)
                except ValueError as error:raise HTTPException(409,str(error)) from None
                row.attempted=0;row.verdict='pending';row.analysis='Retry requested by an administrator; hourly limits still apply.'
                audit(s,'retry AI investigation',user['username']+' '+row.id);s.commit()
        return {'ok':True,'detail':'Investigation queued. AI must be enabled and a worker available; hourly limits still apply.'}
    finally:lock.release()

@app.get('/api/package-history')
def package_history_list(host_id:str='',q:str='',offset:int=0,limit:int=100,user=Depends(auth)):
    if offset<0 or not 1<=limit<=200:raise HTTPException(400,'Invalid history pagination')
    with Session() as s:
        query=select(package_history.PackageEvent)
        if host_id:host_or_404(s,host_id);query=query.where(package_history.PackageEvent.host_id==host_id)
        if q:query=query.where(package_history.PackageEvent.name.contains(q[:200],autoescape=True))
        rows=list(s.scalars(query.order_by(package_history.PackageEvent.recorded.desc(),package_history.PackageEvent.id.desc()).offset(offset).limit(limit+1)))
        saved=update_scores.historical_cache(s,[(r.host_id,r.name,v) for r in rows[:limit] if r.action=='version_changed' for v in r.after])
        return {'items':[object_dict(r)|{'assessment':update_scores.historical(s,r.host_id,r.name,r.after,r.before,r.observed,cache=saved) if r.action=='version_changed' else None} for r in rows[:limit]],'more':len(rows)>limit}


@app.get('/api/security/coverage')
def fleet_security_coverage(offset:int=0,limit:int=50,q:str='',user=Depends(auth)):
    from . import security_coverage
    if offset<0 or not 1<=limit<=100 or len(q)>200:raise HTTPException(400,'Invalid coverage pagination or search')
    with Session() as s:return security_coverage.page(s,offset,limit,q)

class SecurityScanInput(BaseModel):
    paths:list[str]=Field(min_length=1,max_length=16)

@app.get('/api/hosts/{host_id}/security')
def security_status(host_id:str,user=Depends(auth)):
    with Session() as s:
        host_or_404(s,host_id)
        row=s.scalar(select(incidents.Scan).where(incidents.Scan.host_id==host_id).order_by(incidents.Scan.created.desc()).limit(1))
        if row:return {'scan_id':row.id,**row.report}
        legacy=s.get(Setting,'security-scan:'+host_id)
        return legacy.value if legacy else {'state':'not_scanned','findings':[],'gaps':['No security scan has completed']}

@app.post('/api/hosts/{host_id}/security')
def security_scan_queue(host_id:str,body:SecurityScanInput,user=Depends(auth)):
    for path in body.paths:
        if not path.startswith('/') or '..' in Path(path).parts or len(path)>4096:raise ValueError('Invalid scan directory')
    with worker.Lock('security-scan-queue'):
        with Session() as s:
            host_or_404(s,host_id)
            pending=s.scalar(select(Job).where(Job.host_id==host_id,Job.action.in_(['security-scan','yara-scan','execution-scan']),Job.state.in_(['queued','running'])))
            if pending:raise HTTPException(409,'A security scan is already queued or running')
            return {'job_id':worker.enqueue(s,host_id,'security-scan',body.model_dump())}

class YaraScanInput(SecurityScanInput):
    bundle_id:str=Field(pattern=r'^[A-Za-z0-9_-]{1,64}$')

@app.post('/api/hosts/{host_id}/security/yara')
def yara_scan_queue(host_id:str,body:YaraScanInput,user=Depends(auth)):
    for path in body.paths:
        if not path.startswith('/') or path.startswith('//') or '..' in Path(path).parts or len(path)>4096:raise ValueError('Invalid scan directory')
    with worker.Lock('security-scan-queue'),Session() as s:
        host_or_404(s,host_id)
        if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.action.in_(['security-scan','yara-scan','execution-scan']),Job.state.in_(['queued','running'])).limit(1)):
            raise HTTPException(409,'A security scan is already queued or running')
        return {'job_id':worker.enqueue(s,host_id,'yara-scan',body.model_dump())}

class ExecutionScanPolicy(SecurityScanInput):
    enabled:bool=False
    debounce_seconds:int=Field(default=30,ge=15,le=300)
    cooldown_minutes:int=Field(default=15,ge=5,le=60)
    max_per_hour:int=Field(default=4,ge=1,le=12)
    expected_revision:str=Field(default='',max_length=36)
    reason:str=Field(min_length=10,max_length=4000)

@app.get('/api/hosts/{host_id}/security/execution-scans')
def execution_scan_status(host_id:str,offset:int=0,user=Depends(auth)):
    from . import execution_scans
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        host_or_404(s,host_id)
        rows=list(s.scalars(select(execution_scans.Trigger).where(execution_scans.Trigger.host_id==host_id).order_by(execution_scans.Trigger.created.desc(),execution_scans.Trigger.id).offset(offset).limit(21)))
        return execution_scans.status(s,host_id)|{'items':[object_dict(row) for row in rows[:20]],'more':len(rows)>20}

@app.put('/api/hosts/{host_id}/security/execution-scans')
def execution_scan_policy_save(host_id:str,body:ExecutionScanPolicy,user=Depends(auth)):
    from . import execution_scans
    with host_change(host_id,allow_quarantined=True),worker.Lock('security-scan-queue'),Session() as s:
        host=host_or_404(s,host_id);value=execution_scans.save(s,host,body,user['username']);s.commit()
        return value

class ScannerRecordExport(BaseModel):
    reason:str=Field(min_length=10,max_length=4000)

@app.post('/api/hosts/{host_id}/security/export')
def export_scanner_record(host_id:str,body:ScannerRecordExport,user=Depends(auth)):
    from . import scanner_records,response_records
    reason=body.reason.strip()
    if len(reason)<10:raise ValueError('Provide a meaningful export reason')
    with host_change(host_id,allow_quarantined=True,allow_inactive=True),Session() as s:
        host=host_or_404(s,host_id)
        try:identifier,data,digest=scanner_records.build(s,host,user['username'],reason)
        except response_records.ExportLimit as error:raise HTTPException(413,str(error).replace('Response','Scanner')) from None
        audit(s,'scanner record exported',host_id+' '+identifier+' '+digest+' '+user['username']);s.commit()
        return Response(data,media_type='application/json',headers={
            'Content-Disposition':'attachment; filename="mrpatchy-scanner-'+identifier+'.json"',
            'X-Scanner-Record-SHA256':digest,'Cache-Control':'no-store'})

@app.get('/api/hosts/{host_id}/security/history')
def security_history(host_id:str,offset:int=0,user=Depends(auth)):
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        host_or_404(s,host_id)
        rows=list(s.scalars(select(incidents.Scan).where(incidents.Scan.host_id==host_id).order_by(incidents.Scan.created.desc(),incidents.Scan.id).offset(offset).limit(21)))
        return {'items':[object_dict(r) for r in rows[:20]],'more':len(rows)>20}

@app.get('/api/hosts/{host_id}/security/incidents')
def security_incidents(host_id:str,offset:int=0,user=Depends(auth)):
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        host_or_404(s,host_id)
        rows=list(s.scalars(select(incidents.Incident).where(incidents.Incident.host_id==host_id).order_by(incidents.Incident.updated.desc(),incidents.Incident.id).offset(offset).limit(21)))
        return {'items':[object_dict(r)|{'plans':[object_dict(p) for p in s.scalars(select(incidents.Plan).where(incidents.Plan.incident_id==r.id).order_by(incidents.Plan.created.desc()).limit(10))]} for r in rows[:20]],'more':len(rows)>20}

class EvidenceApproval(BaseModel):
    snapshot_digest:str
    reason:str=Field(min_length=10,max_length=4000)
    confirmation:str

@app.post('/api/hosts/{host_id}/security/incidents/{incident_id}/preservation')
def prepare_evidence_copy(host_id:str,incident_id:str,user=Depends(auth)):
    from . import evidence_vault as vault
    with host_change(host_id),Session() as s:
        row=vault.incident(s,host_id,incident_id)
        if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.action.in_(['evidence-prepare','evidence-preserve','evidence-status']),Job.state.in_(['queued','running'])).limit(1)):raise HTTPException(409,'Evidence work is already pending')
        return {'job_id':worker.enqueue(s,host_id,'evidence-prepare',{'incident_id':row.id,'evidence_digest':incidents.digest(row.evidence)})}

@app.get('/api/hosts/{host_id}/security/evidence-copies')
def evidence_copies(host_id:str,offset:int=0,user=Depends(auth)):
    from .evidence_vault import EvidenceCopy
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        host_or_404(s,host_id)
        rows=list(s.scalars(select(EvidenceCopy).where(EvidenceCopy.host_id==host_id).order_by(EvidenceCopy.created.desc(),EvidenceCopy.id).offset(offset).limit(21)))
        return {'items':[object_dict(r)|{'snapshot_digest':incidents.digest(r.snapshot)} for r in rows[:20]],'more':len(rows)>20}

@app.post('/api/hosts/{host_id}/security/evidence-copies/{copy_id}/execute')
def approve_evidence_copy(host_id:str,copy_id:str,body:EvidenceApproval,user=Depends(auth)):
    from . import evidence_vault as vault
    if body.confirmation!='PRESERVE':raise ValueError('Type PRESERVE to approve copying evidence; the original remains in place')
    if len(body.reason.strip())<10:raise ValueError('Provide a meaningful preservation reason')
    with host_change(host_id),Session() as s:
        copy=s.get(vault.EvidenceCopy,copy_id)
        if not copy or copy.host_id!=host_id:raise HTTPException(404,'Evidence operation not found')
        row=vault.incident(s,host_id,copy.incident_id)
        if copy.state!='prepared' or time.time()-copy.created>900 or incidents.digest(copy.snapshot)!=body.snapshot_digest or incidents.digest(row.evidence)!=copy.evidence_digest:raise HTTPException(409,'Preparation expired, changed or was already approved')
        copy.state='queued';copy.actor=user['username'];copy.reason=body.reason.strip();copy.expires=time.time()+300
        job_id=worker.enqueue(s,host_id,'evidence-preserve',{'copy_id':copy.id})
        audit(s,'evidence preservation approved',host_id+' '+copy.id+' '+copy.actor+' '+copy.reason);s.commit()
        return {'job_id':job_id,'original_not_removed':True}

@app.post('/api/hosts/{host_id}/security/evidence-copies/{copy_id}/status')
def reconcile_evidence_copy(host_id:str,copy_id:str,user=Depends(auth)):
    from .evidence_vault import EvidenceCopy
    with host_change(host_id),Session() as s:
        copy=s.get(EvidenceCopy,copy_id)
        if not copy or copy.host_id!=host_id:raise HTTPException(404,'Evidence operation not found')
        if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.action.in_(['evidence-preserve','evidence-status']),Job.state.in_(['queued','running'])).limit(1)):raise HTTPException(409,'Evidence work is still pending')
        return {'job_id':worker.enqueue(s,host_id,'evidence-status',{'copy_id':copy.id})}

@app.post('/api/hosts/{host_id}/security/evidence-copies/{copy_id}/acquire')
def acquire_evidence_copy(host_id:str,copy_id:str,body:EvidenceApproval,user=Depends(auth)):
    from . import evidence_archive as archive
    from .evidence_vault import EvidenceCopy,EvidenceArchive
    if body.confirmation!='ACQUIRE':raise ValueError('Type ACQUIRE to approve transferring preserved file contents to the controller')
    if len(body.reason.strip())<10:raise ValueError('Provide a meaningful acquisition reason')
    with host_change(host_id),Session() as s:
        host=host_or_404(s,host_id);copy=s.get(EvidenceCopy,copy_id)
        if not copy or copy.host_id!=host_id:raise HTTPException(404,'Evidence operation not found')
        if copy.state!='preserved' or incidents.digest(copy.snapshot)!=body.snapshot_digest:raise HTTPException(409,'A matching preserved snapshot is required')
        if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.action.in_(['evidence-acquire','evidence-archive-status']),Job.state.in_(['queued','running'])).limit(1)):raise HTTPException(409,'Evidence acquisition work is already pending')
        now=time.time();row=EvidenceArchive(id=str(uuid.uuid4()),host_id=host_id,copy_id=copy.id,created=now,state='queued',snapshot=copy.snapshot,fingerprint=host.fingerprint,actor=user['username'],reason=body.reason.strip(),expires=now+300)
        s.add(row);archive.observe(s,row,'approved')
        job_id=worker.enqueue(s,host_id,'evidence-acquire',{'archive_id':row.id})
        return {'job_id':job_id,'archive_id':row.id}

@app.get('/api/hosts/{host_id}/security/evidence-archives')
def evidence_archives(host_id:str,offset:int=0,user=Depends(auth)):
    from .evidence_vault import EvidenceArchive,ArchiveObservation
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        host_or_404(s,host_id)
        rows=list(s.scalars(select(EvidenceArchive).where(EvidenceArchive.host_id==host_id).order_by(EvidenceArchive.created.desc(),EvidenceArchive.id).offset(offset).limit(21)))
        items=[]
        for row in rows[:20]:
            latest=s.scalar(select(ArchiveObservation).where(ArchiveObservation.archive_id==row.id).order_by(ArchiveObservation.created.desc(),ArchiveObservation.id).limit(1))
            items.append(object_dict(row)|{'last_observation':object_dict(latest) if latest else None})
        return {'items':items,'more':len(rows)>20}

@app.get('/api/hosts/{host_id}/security/evidence-archives/{archive_id}/history')
def evidence_archive_history(host_id:str,archive_id:str,offset:int=0,user=Depends(auth)):
    from .evidence_vault import EvidenceArchive,ArchiveObservation
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        row=s.get(EvidenceArchive,archive_id)
        if not row or row.host_id!=host_id:raise HTTPException(404,'Evidence acquisition not found')
        rows=list(s.scalars(select(ArchiveObservation).where(ArchiveObservation.archive_id==row.id,ArchiveObservation.host_id==host_id).order_by(ArchiveObservation.created.desc(),ArchiveObservation.id).offset(offset).limit(21)))
        return {'items':[object_dict(r) for r in rows[:20]],'more':len(rows)>20}

@app.post('/api/hosts/{host_id}/security/evidence-archives/{archive_id}/status')
def verify_evidence_archive(host_id:str,archive_id:str,user=Depends(auth)):
    from .evidence_vault import EvidenceArchive
    with host_change(host_id,allow_quarantined=True),Session() as s:
        row=s.get(EvidenceArchive,archive_id)
        if not row or row.host_id!=host_id:raise HTTPException(404,'Evidence acquisition not found')
        if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.action.in_(['evidence-acquire','evidence-archive-status']),Job.state.in_(['queued','running'])).limit(1)):raise HTTPException(409,'Evidence acquisition work is still pending')
        return {'job_id':worker.enqueue(s,host_id,'evidence-archive-status',{'archive_id':row.id,'_actor':user['username']})}

def response_row(s,host_id,quarantine_id):
    from .quarantine import Quarantine
    row=s.get(Quarantine,quarantine_id)
    if not row or row.host_id!=host_id:raise HTTPException(404,'File response not found')
    return row

class ResponseRecordExport(BaseModel):
    plan_digest:str=Field(pattern=r'^[a-f0-9]{64}$')
    reason:str=Field(min_length=10,max_length=4000)

class ResponseServiceHealth(BaseModel):
    plan_digest:str=Field(pattern=r'^[a-f0-9]{64}$')
    units:list[str]=Field(min_length=1,max_length=16)
    reason:str=Field(min_length=10,max_length=4000)
    baseline_id:str=Field(default='',max_length=36)

@app.get('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/service-health')
def response_service_health_history(host_id:str,quarantine_id:str,offset:int=0,user=Depends(auth)):
    from .response_health import Observation
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        row=response_row(s,host_id,quarantine_id)
        rows=list(s.scalars(select(Observation).where(Observation.host_id==host_id,Observation.quarantine_id==row.id).order_by(Observation.created.desc(),Observation.id).offset(offset).limit(21)))
        return {'items':[object_dict(item)|{'report_digest':incidents.digest(item.report)} for item in rows[:20]],'more':len(rows)>20}

@app.post('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/service-health')
def observe_response_service_health(host_id:str,quarantine_id:str,body:ResponseServiceHealth,user=Depends(auth)):
    from . import response_health,quarantine
    response_health.response_service_units(body.units);reason=body.reason.strip()
    if len(reason)<10:raise ValueError('Provide a meaningful service review reason')
    with host_change(host_id,allow_quarantined=True),Session() as s:
        host=host_or_404(s,host_id);row=response_row(s,host_id,quarantine_id)
        if row.fingerprint!=host.fingerprint or incidents.digest(row.plan)!=body.plan_digest or row.state in ('queued','restore_queued'):raise HTTPException(409,'Response scope changed; refresh before checking services')
        if operations.host_quarantined(s,host_id,response_id=row.id,read_only_response_id=row.id,service_response_id=row.id):raise HTTPException(409,'Another operation or response requires reconciliation')
        deferred=select(Job.id).where(Job.host_id==host_id,Job.action=='response-service-health',Job.state=='queued',Job.payload['_service_watch'].as_boolean()==True)
        if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.action.in_(quarantine.ACTIONS),Job.state.in_(['queued','running']),Job.id.not_in(deferred)).limit(1)):raise HTTPException(409,'Response work is pending; wait before checking services')
        previous=response_health.baseline(s,host,row,body.baseline_id,body.units) if body.baseline_id else None
        payload={'quarantine_id':row.id,**response_health.binding(s,host,row),'units':body.units,'reason':reason,'baseline_id':body.baseline_id,
                 'baseline_digest':incidents.digest(previous.report) if previous else '', '_actor':user['username']}
        return {'job_id':worker.enqueue(s,host_id,response_health.ACTION,payload),'read_only':True}

class ServiceWatchInput(BaseModel):
    expected_revision:str=Field(default='',max_length=36)
    plan_digest:str=Field(pattern=r'^[a-f0-9]{64}$')
    enabled:bool=False
    interval_minutes:int=Field(default=15,ge=5,le=1440)
    pause_on_problem:bool=False
    baseline_id:str=Field(default='',max_length=36)
    report_digest:str=Field(default='',max_length=64)
    reason:str=Field(min_length=10,max_length=4000)

@app.get('/api/hosts/{host_id}/security/service-monitor')
def service_monitor_status(host_id:str,user=Depends(auth)):
    from . import service_monitor
    with Session() as s:
        host_or_404(s,host_id);status=service_monitor.assessment(s,host_id);status.pop('eligible')
        pending=s.scalar(select(Job).where(Job.host_id==host_id,Job.action=='response-service-health',Job.payload['_service_watch'].as_boolean()==True,Job.state.in_(['queued','running'])).order_by(Job.created).limit(1))
        return status|{'pending':{'id':pending.id,'state':pending.state} if pending else None,'server_changes_paused':operations.host_quarantined(s,host_id)}

@app.get('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/service-watch')
def get_service_watch(host_id:str,quarantine_id:str,user=Depends(auth)):
    from . import service_monitor
    with Session() as s:
        row=response_row(s,host_id,quarantine_id);host=host_or_404(s,host_id);watch=s.get(service_monitor.Watch,row.id)
        if watch and watch.host_id!=host_id:raise HTTPException(404,'Service watch not found')
        return service_monitor.view(watch)|{'scope_current':service_monitor.current(s,host,row,watch)}

@app.put('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/service-watch')
def save_service_watch(host_id:str,quarantine_id:str,body:ServiceWatchInput,user=Depends(auth)):
    from . import service_monitor
    with host_change(host_id,allow_quarantined=True),Session() as s:
        host=host_or_404(s,host_id);row=response_row(s,host_id,quarantine_id)
        if incidents.digest(row.plan)!=body.plan_digest:raise HTTPException(409,'File response changed; refresh before saving')
        watch=service_monitor.save(s,host,row,body,user['username']);s.commit()
        return service_monitor.view(watch)

class ServicePauseReview(BaseModel):
    expected_revision:str=Field(max_length=36)
    confirmation:str=Field(max_length=40)
    observation_id:str=Field(default='',max_length=36)
    report_digest:str=Field(default='',max_length=64)
    reason:str=Field(min_length=10,max_length=4000)

@app.post('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/service-watch/release')
def release_service_pause(host_id:str,quarantine_id:str,body:ServicePauseReview,user=Depends(auth)):
    from . import service_monitor
    with host_change(host_id,allow_quarantined=True),Session() as s:
        host=host_or_404(s,host_id);row=response_row(s,host_id,quarantine_id)
        service_monitor.release(s,host,row,body,user['username']);s.commit()
        return {'service_hold':False,'server_changes_paused':operations.host_quarantined(s,host_id),'incident_not_resolved':True}

@app.post('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/export')
def export_response_record(host_id:str,quarantine_id:str,body:ResponseRecordExport,user=Depends(auth)):
    from . import response_records
    reason=body.reason.strip()
    if len(reason)<10:raise ValueError('Provide a meaningful export reason')
    # Export is available through response holds, including uncertain/recovered
    # states, but cannot race a cooperating worker changing this host's records.
    with host_change(host_id,allow_quarantined=True,allow_inactive=True),Session() as s:
        host=host_or_404(s,host_id);row=response_row(s,host_id,quarantine_id)
        if incidents.digest(row.plan)!=body.plan_digest:raise HTTPException(409,'Response plan changed; refresh before exporting')
        try:identifier,data,digest=response_records.build(s,host,row,user['username'],reason)
        except response_records.ExportLimit as error:raise HTTPException(413,str(error)) from None
        # The current export event is outside its snapshot to avoid a self hash.
        # Retain its whole-file digest independently in both custody and audit.
        from . import quarantine
        quarantine.event(s,row,'record_exported',user['username'],{'export_id':identifier,'sha256':digest,'bytes':len(data),'reason':reason})
        audit(s,'response record exported',host_id+' '+row.id+' '+identifier+' '+digest+' '+user['username'])
        s.commit()
        return Response(data,media_type='application/json',headers={
            'Content-Disposition':'attachment; filename="mrpatchy-response-'+identifier+'.json"',
            'X-Response-Record-SHA256':digest,'Cache-Control':'no-store'})

def response_idle(s,host_id,response_id=None):
    from .quarantine import ACTIONS
    if operations.host_quarantined(s,host_id,response_id=response_id):raise HTTPException(409,'Another operation or file response requires reconciliation')
    if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.action.in_(ACTIONS),Job.state.in_(['queued','running'])).limit(1)):raise HTTPException(409,'File response work is pending; reconcile interrupted running jobs in Activity first')

@app.post('/api/hosts/{host_id}/security/evidence-archives/{archive_id}/quarantine')
def prepare_quarantine(host_id:str,archive_id:str,user=Depends(auth)):
    from . import quarantine
    from .evidence_vault import EvidenceArchive,EvidenceCopy,incident
    with host_change(host_id),Session() as s:
        host_or_404(s,host_id);archive=s.get(EvidenceArchive,archive_id)
        if not archive or archive.host_id!=host_id:raise HTTPException(404,'Evidence acquisition not found')
        copy=s.get(EvidenceCopy,archive.copy_id)
        if not copy or copy.host_id!=host_id or archive.state!='verified':raise HTTPException(409,'A verified same-host evidence acquisition is required')
        current=incident(s,host_id,copy.incident_id)
        if incidents.digest(current.evidence)!=copy.evidence_digest:raise HTTPException(409,'Incident evidence changed; acquire and review current evidence')
        response_idle(s,host_id)
        return {'job_id':worker.enqueue(s,host_id,'quarantine-prepare',{'archive_id':archive.id,'evidence_digest':copy.evidence_digest,'_actor':user['username']})}

@app.get('/api/hosts/{host_id}/security/quarantines')
def quarantines(host_id:str,offset:int=0,user=Depends(auth)):
    from .quarantine import Quarantine
    from . import response_monitor,response_processes,repair_publication,response_health,service_monitor
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        host_or_404(s,host_id)
        rows=list(s.scalars(select(Quarantine).where(Quarantine.host_id==host_id).order_by(Quarantine.created.desc(),Quarantine.id).offset(offset).limit(21)))
        watches,latest,_=response_monitor.context(s,rows[:20])
        processes=response_processes.latest(s,rows[:20])
        publications=repair_publication.latest(s,rows[:20])
        services=response_health.latest(s,rows[:20])
        service_watches={item.id:item for item in s.scalars(select(service_monitor.Watch).where(service_monitor.Watch.host_id==host_id,service_monitor.Watch.id.in_([row.id for row in rows[:20]])))}
        return {'items':[object_dict(r)|{'plan_digest':incidents.digest(r.plan),'receipt_digest':incidents.digest(r.receipt),
            'publication_id':publications[r.id].id if r.id in publications else None,
            'service_observation':{'id':services[r.id].id,'state':services[r.id].state,'created':services[r.id].created} if r.id in services else None,
            'service_watch':service_monitor.view(service_watches.get(r.id)),
            'process_observation':{'id':processes[r.id].id,'state':processes[r.id].state,'created':processes[r.id].created,'scope_current':processes[r.id].report['scope_current']} if r.id in processes else None,
            'monitor':{'watch':watches[r.id],'eligible':response_monitor.eligible(r),'last_check':object_dict(latest[r.id]) if r.id in latest else None}} for r in rows[:20]],'more':len(rows)>20}

class RepairPreparationInput(BaseModel):
    bundle_id:str=Field(pattern=r'^[A-Za-z0-9_-]{1,64}$')
    plan_digest:str=Field(pattern=r'^[a-f0-9]{64}$')

@app.post('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/repair-preparations')
def prepare_trusted_replacement(host_id:str,quarantine_id:str,body:RepairPreparationInput,user=Depends(auth)):
    from . import repair_preparation,quarantine
    with host_change(host_id,allow_quarantined=True),Session() as s:
        host=host_or_404(s,host_id);row=response_row(s,host_id,quarantine_id)
        if operations.host_quarantined(s,host_id,response_id=row.id,read_only_response_id=row.id):raise HTTPException(409,'An unrelated response or recovery operation requires reconciliation')
        actions=tuple(action for action in quarantine.ACTIONS if action!='quarantine-audit')
        if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.action.in_(actions),Job.state.in_(['queued','running'])).limit(1)):raise HTTPException(409,'Response work is pending')
        preparation=repair_preparation.Preparation(id=str(uuid.uuid4()),host_id=host_id,quarantine_id=row.id,bundle_id=body.bundle_id,
            path=row.plan['file']['path'],actor=user['username'],fingerprint=host.fingerprint,response_plan_digest=body.plan_digest)
        repair_preparation.source(s,host,preparation);s.add(preparation)
        return {'job_id':worker.enqueue(s,host_id,repair_preparation.ACTION,{'preparation_id':preparation.id,'quarantine_id':row.id,'_actor':user['username']}),
                'preparation_id':preparation.id,'read_only':True,'publication':'not_implemented'}

@app.get('/api/hosts/{host_id}/security/repair-preparations')
def trusted_replacement_history(host_id:str,offset:int=0,user=Depends(auth)):
    from .repair_preparation import Preparation
    from .repair_staging import Stage
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        host_or_404(s,host_id)
        rows=list(s.scalars(select(Preparation).where(Preparation.host_id==host_id).order_by(Preparation.created.desc(),Preparation.id).offset(offset).limit(21)))
        stages={r.preparation_id:r.id for r in s.scalars(select(Stage).where(Stage.host_id==host_id,Stage.preparation_id.in_([r.id for r in rows[:20]])))}
        return {'items':[object_dict(r)|{'report_digest':incidents.digest(r.report),'stage_id':stages.get(r.id)} for r in rows[:20]],'more':len(rows)>20}

def staging_idle(s,host_id,quarantine_id):
    from .quarantine import ACTIONS
    if operations.host_quarantined(s,host_id,response_id=quarantine_id,staging_response_id=quarantine_id):raise HTTPException(409,'An unrelated response or recovery operation requires reconciliation')
    actions=tuple(action for action in ACTIONS if action!='quarantine-audit')
    if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.action.in_(actions),Job.state.in_(['queued','running'])).limit(1)):raise HTTPException(409,'Response work is pending; reconcile interrupted work in Activity first')

class RepairStagingApproval(BaseModel):
    report_digest:str=Field(pattern=r'^[a-f0-9]{64}$')
    confirmation:str
    reason:str=Field(min_length=10,max_length=4000)

@app.post('/api/hosts/{host_id}/security/repair-preparations/{preparation_id}/stage')
def approve_replacement_staging(host_id:str,preparation_id:str,body:RepairStagingApproval,user=Depends(auth)):
    from . import repair_staging,repair_preparation
    if body.confirmation!='STAGE' or len(body.reason.strip())<10:raise ValueError('Type STAGE and provide a meaningful review reason')
    with host_change(host_id,allow_quarantined=True),Session() as s:
        host=host_or_404(s,host_id);prepared=s.get(repair_preparation.Preparation,preparation_id)
        if not prepared or prepared.host_id!=host_id:raise HTTPException(404,'Replacement preparation not found')
        staging_idle(s,host_id,prepared.quarantine_id)
        if s.scalar(select(repair_staging.Stage.id).where(repair_staging.Stage.preparation_id==prepared.id).limit(1)):raise HTTPException(409,'This preparation already has a staging approval; review its history')
        row=repair_staging.approve(s,host,prepared.id,body.report_digest,user['username'],body.reason.strip())
        return {'stage_id':row.id,'publication':'not_authorized','job_id':worker.enqueue(s,host_id,'trusted-repair-stage',{'stage_id':row.id,'quarantine_id':row.quarantine_id,'_actor':user['username']})}

def staging_row(s,host_id,stage_id):
    from .repair_staging import Stage
    row=s.get(Stage,stage_id)
    if not row or row.host_id!=host_id:raise HTTPException(404,'Replacement staging not found')
    return row

@app.get('/api/hosts/{host_id}/security/repair-stages')
def replacement_staging_history(host_id:str,offset:int=0,user=Depends(auth)):
    from .repair_staging import Stage
    from . import repair_publication
    from .quarantine import Quarantine
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        host_or_404(s,host_id)
        rows=list(s.scalars(select(Stage).where(Stage.host_id==host_id).order_by(Stage.created.desc(),Stage.id).offset(offset).limit(21)))
        original=list(s.scalars(select(Quarantine).where(Quarantine.host_id==host_id,Quarantine.id.in_([r.quarantine_id for r in rows[:20]]))))
        publications=repair_publication.latest(s,original)
        return {'items':[object_dict(r)|{'plan_digest':incidents.digest(r.plan),'report_digest':incidents.digest(r.report),'publication_id':publications[r.quarantine_id].id if r.quarantine_id in publications and publications[r.quarantine_id].stage_id==r.id else None} for r in rows[:20]],'more':len(rows)>20}

@app.post('/api/hosts/{host_id}/security/repair-stages/{stage_id}/status')
def verify_replacement_stage(host_id:str,stage_id:str,user=Depends(auth)):
    from . import repair_publication
    with host_change(host_id,allow_quarantined=True),Session() as s:
        host_or_404(s,host_id);row=staging_row(s,host_id,stage_id)
        publication=repair_publication.active(s,row.quarantine_id)
        if publication and publication.stage_id==row.id:
            publication_idle(s,publication)
            return {'job_id':worker.enqueue(s,host_id,'trusted-repair-publish-status',{'publication_id':publication.id,'quarantine_id':publication.quarantine_id,'_actor':user['username']})}
        staging_idle(s,host_id,row.quarantine_id)
        if row.state=='queued':raise HTTPException(409,'Staging is still queued')
        return {'job_id':worker.enqueue(s,host_id,'trusted-repair-stage-status',{'stage_id':row.id,'quarantine_id':row.quarantine_id,'_actor':user['username']})}

@app.get('/api/hosts/{host_id}/security/repair-stages/{stage_id}/history')
def replacement_stage_events(host_id:str,stage_id:str,offset:int=0,user=Depends(auth)):
    from .repair_staging import Event
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        row=staging_row(s,host_id,stage_id)
        records=list(s.scalars(select(Event).where(Event.stage_id==row.id,Event.host_id==host_id).order_by(Event.created.desc(),Event.id).offset(offset).limit(21)))
        return {'items':[object_dict(r) for r in records[:20]],'more':len(records)>20}

def publication_row(s,host_id,publication_id):
    from .repair_publication import Publication
    row=s.get(Publication,publication_id)
    if not row or row.host_id!=host_id:raise HTTPException(404,'Replacement publication not found')
    return row

def publication_idle(s,row):
    from .quarantine import ACTIONS
    if operations.host_quarantined(s,row.host_id,response_id=row.quarantine_id,publication_id=row.id,publication_response_id=row.quarantine_id):raise HTTPException(409,'Another operation or response requires reconciliation')
    actions=tuple(a for a in ACTIONS if a!='quarantine-audit')
    if s.scalar(select(Job.id).where(Job.host_id==row.host_id,Job.action.in_(actions),Job.state.in_(['queued','running'])).limit(1)):raise HTTPException(409,'Response work is pending; reconcile interrupted jobs in Activity first')

@app.post('/api/hosts/{host_id}/security/repair-stages/{stage_id}/publish')
def approve_replacement_publication(host_id:str,stage_id:str,body:RepairStagingApproval,user=Depends(auth)):
    from . import repair_publication
    if body.confirmation!='PUBLISH' or len(body.reason.strip())<10:raise ValueError('Type PUBLISH and provide a meaningful reason')
    with host_change(host_id,allow_quarantined=True),Session() as s:
        host=host_or_404(s,host_id);staged=staging_row(s,host_id,stage_id)
        # Before a publication exists, use its response scope without bypassing
        # any existing publication hold. Related process pauses remain active.
        if operations.host_quarantined(s,host_id,response_id=staged.quarantine_id,publication_response_id=staged.quarantine_id):raise HTTPException(409,'An unrelated operation or response requires reconciliation')
        from .quarantine import ACTIONS
        if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.action.in_(tuple(a for a in ACTIONS if a!='quarantine-audit')),Job.state.in_(['queued','running'])).limit(1)):raise HTTPException(409,'Response work is pending')
        row=repair_publication.approve(s,host,stage_id,body.report_digest,user['username'],body.reason.strip())
        return {'publication_id':row.id,'publication_hold':True,'job_id':worker.enqueue(s,host_id,'trusted-repair-publish',{'publication_id':row.id,'quarantine_id':row.quarantine_id,'_actor':user['username']})}

@app.get('/api/hosts/{host_id}/security/repair-publications')
def replacement_publications(host_id:str,offset:int=0,user=Depends(auth)):
    from .repair_publication import Publication
    from .quarantine import Quarantine
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        host_or_404(s,host_id)
        records=list(s.scalars(select(Publication).where(Publication.host_id==host_id).order_by(Publication.created.desc(),Publication.id).offset(offset).limit(21)))
        originals={r.id:r.hold for r in s.scalars(select(Quarantine).where(Quarantine.host_id==host_id,Quarantine.id.in_([r.quarantine_id for r in records[:20]])))}
        return {'items':[object_dict(r)|{'plan_digest':incidents.digest(r.plan),'receipt_digest':incidents.digest(r.receipt),'file_hold':originals.get(r.quarantine_id,False)} for r in records[:20]],'more':len(records)>20}

@app.post('/api/hosts/{host_id}/security/repair-publications/{publication_id}/status')
def verify_replacement_publication(host_id:str,publication_id:str,user=Depends(auth)):
    with host_change(host_id,allow_quarantined=True),Session() as s:
        row=publication_row(s,host_id,publication_id);publication_idle(s,row)
        if row.state in ('queued','rejected','console_recovered'):raise HTTPException(409,'Publication is queued, unstarted or archived by console review')
        return {'job_id':worker.enqueue(s,host_id,'trusted-repair-publish-status',{'publication_id':row.id,'quarantine_id':row.quarantine_id,'_actor':user['username']})}

@app.get('/api/hosts/{host_id}/security/repair-publications/{publication_id}/history')
def replacement_publication_events(host_id:str,publication_id:str,offset:int=0,user=Depends(auth)):
    from .repair_publication import Event
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        row=publication_row(s,host_id,publication_id)
        records=list(s.scalars(select(Event).where(Event.publication_id==row.id,Event.host_id==host_id).order_by(Event.created.desc(),Event.id).offset(offset).limit(21)))
        return {'items':[object_dict(r) for r in records[:20]],'more':len(records)>20}

class PublicationReview(BaseModel):
    plan_digest:str=Field(pattern=r'^[a-f0-9]{64}$')
    receipt_digest:str=Field(pattern=r'^[a-f0-9]{64}$')
    reason:str=Field(min_length=10,max_length=4000)
    confirmation:str

@app.post('/api/hosts/{host_id}/security/repair-publications/{publication_id}/release')
def review_publication_pause(host_id:str,publication_id:str,body:PublicationReview,user=Depends(auth)):
    from . import repair_publication,quarantine
    with host_change(host_id,allow_quarantined=True),Session() as s:
        host=host_or_404(s,host_id);row=publication_row(s,host_id,publication_id);publication_idle(s,row)
        if row.state in ('rejected','console_recovered'):raise HTTPException(409,'This rejected or archived publication has no active publication review')
        original=response_row(s,host_id,row.quarantine_id)
        if len(body.reason.strip())<10 or incidents.digest(row.plan)!=body.plan_digest or incidents.digest(row.receipt)!=body.receipt_digest or not (row.hold or original.hold):raise HTTPException(409,'Publication pause or reviewed receipt changed')
        if body.confirmation=='KEEP REPLACEMENT':
            if not repair_publication.bound(s,host,row) or not repair_publication.positive(original,row) or not row.report.get('scope_current') or not row.report.get('trust_current') or not 0<=time.time()-row.observed<=300:raise HTTPException(409,'Fresh verified publication and current vendor trust are required')
            original.hold=False
        elif body.confirmation=='CONSOLE RECOVERED':
            row.state='console_recovered'
            if repair_publication.bound(s,host,row):original.state='console_recovered'
        else:raise ValueError('Type KEEP REPLACEMENT or CONSOLE RECOVERED after service and console review')
        row.hold=False;repair_publication.event(s,row,'hold_released',user['username'],{'reason':body.reason.strip(),'confirmation':body.confirmation,'receipt_digest':body.receipt_digest})
        quarantine.event(s,original,'publication_reviewed',user['username'],{'publication_id':row.id,'confirmation':body.confirmation,'reason':body.reason.strip()});s.commit()
        return {'publication_hold':False,'file_hold':original.hold,'server_changes_paused':operations.host_quarantined(s,host_id),'incident_not_resolved':True}

class ResponseProcessRequest(BaseModel):
    plan_digest:str=Field(pattern=r'^[a-f0-9]{64}$')

@app.post('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/processes')
def inspect_response_processes(host_id:str,quarantine_id:str,body:ResponseProcessRequest,user=Depends(auth)):
    from . import response_processes
    with host_change(host_id,allow_quarantined=True),Session() as s:
        host=host_or_404(s,host_id);row=response_row(s,host_id,quarantine_id)
        response_idle(s,host_id,response_id=row.id)
        if row.state not in response_processes.STATES or row.fingerprint!=host.fingerprint or incidents.digest(row.plan)!=body.plan_digest:raise HTTPException(409,'Retained response evidence or pinned host changed; refresh before inspecting processes')
        return {'job_id':worker.enqueue(s,host_id,'quarantine-processes',{'quarantine_id':row.id,'plan_digest':body.plan_digest,'fingerprint':host.fingerprint,'_actor':user['username']})}

@app.get('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/processes')
def response_process_history(host_id:str,quarantine_id:str,offset:int=0,user=Depends(auth)):
    from .response_processes import Observation
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        row=response_row(s,host_id,quarantine_id)
        records=list(s.scalars(select(Observation).where(Observation.host_id==host_id,Observation.quarantine_id==row.id).order_by(Observation.created.desc(),Observation.id).offset(offset).limit(21)))
        return {'items':[object_dict(r) for r in records[:20]],'more':len(records)>20}

class ProcessPreparationRequest(BaseModel):
    observation_id:str
    pid:int=Field(strict=True,gt=1,le=2147483647)
    plan_digest:str=Field(pattern=r'^[a-f0-9]{64}$')

@app.post('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/process-preparations')
def prepare_process_response(host_id:str,quarantine_id:str,body:ProcessPreparationRequest,user=Depends(auth)):
    from . import process_response
    with host_change(host_id,allow_quarantined=True),Session() as s:
        host=host_or_404(s,host_id);response_row(s,host_id,quarantine_id);response_idle(s,host_id,response_id=quarantine_id)
        payload={**body.model_dump(),'quarantine_id':quarantine_id,'fingerprint':host.fingerprint,'_actor':user['username']}
        process_response.source(s,host,payload)
        return {'job_id':worker.enqueue(s,host_id,'process-prepare',payload)}

def process_row(s,host_id,process_id):
    from .process_response import ProcessResponse
    row=s.get(ProcessResponse,process_id)
    if not row or row.host_id!=host_id:raise HTTPException(404,'Process response not found')
    return row

def process_idle(s,row):
    from .quarantine import ACTIONS
    if operations.host_quarantined(s,row.host_id,response_id=row.quarantine_id,process_id=row.id):raise HTTPException(409,'Another operation or response requires reconciliation')
    # A scheduler can enqueue a read while approval commits its new hold. That
    # deferred automatic read must not deadlock explicit process recovery.
    actions=tuple(a for a in ACTIONS if not (row.hold and a=='quarantine-audit'))
    if s.scalar(select(Job.id).where(Job.host_id==row.host_id,Job.action.in_(actions),Job.state.in_(['queued','running'])).limit(1)):raise HTTPException(409,'Response work is pending; reconcile interrupted jobs in Activity first')

@app.get('/api/hosts/{host_id}/security/process-responses')
def process_responses(host_id:str,offset:int=0,user=Depends(auth)):
    from .process_response import ProcessResponse
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        host_or_404(s,host_id)
        rows=list(s.scalars(select(ProcessResponse).where(ProcessResponse.host_id==host_id).order_by(ProcessResponse.created.desc(),ProcessResponse.id).offset(offset).limit(21)))
        return {'items':[object_dict(r)|{'plan_digest':incidents.digest(r.plan),'receipt_digest':incidents.digest(r.receipt)} for r in rows[:20]],'more':len(rows)>20}

class ProcessApprovalRequest(BaseModel):
    plan_digest:str=Field(pattern=r'^[a-f0-9]{64}$')
    receipt_digest:str=''
    reason:str=Field(min_length=10,max_length=4000)
    confirmation:str

@app.post('/api/hosts/{host_id}/security/process-responses/{process_id}/actions/{action}')
def review_process_response(host_id:str,process_id:str,action:str,body:ProcessApprovalRequest,user=Depends(auth)):
    from . import process_response
    if action not in ('suspend','resume','release'):raise HTTPException(404,'Process response action not found')
    with host_change(host_id,allow_quarantined=True),Session() as s:
        host=host_or_404(s,host_id);row=process_row(s,host_id,process_id);reason=body.reason.strip()
        if len(reason)<10:raise ValueError('Provide a meaningful process response review reason')
        if incidents.digest(row.plan)!=body.plan_digest:raise HTTPException(409,'Process plan changed; refresh before reviewing')
        if action=='release':
            if not row.hold or incidents.digest(row.receipt)!=body.receipt_digest:raise HTTPException(409,'Process hold or receipt changed; refresh before reviewing')
            if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.payload['process_id'].as_string()==row.id,Job.state.in_(['queued','running'])).limit(1)):raise HTTPException(409,'Process response work is pending')
            if body.confirmation=='ACCEPT PROCESS EXIT':
                if row.state!='exited' or not 0<=time.time()-row.observed<=300:raise HTTPException(409,'Fresh observed process exit is required')
            elif body.confirmation=='CONSOLE RECOVERED':row.state='console_recovered'
            else:raise ValueError('Type ACCEPT PROCESS EXIT or CONSOLE RECOVERED after console and service review')
            row.hold=False;process_response.event(s,row,'hold_released',user['username'],{'reason':reason,'confirmation':body.confirmation,'receipt_digest':body.receipt_digest});s.commit()
            return {'state':row.state,'process_hold':False,'server_changes_paused':operations.host_quarantined(s,host_id)}
        process_idle(s,row)
        if not process_response.bound(s,host,row):raise HTTPException(409,'Process response or pinned host changed')
        if body.confirmation!=('RESUME' if action=='resume' else 'SUSPEND'):raise ValueError('Type '+('RESUME' if action=='resume' else 'SUSPEND')+' to approve this process action')
        if action=='suspend':
            if row.state!='prepared' or not 0<=time.time()-row.created<=900:raise HTTPException(409,'Process preparation expired or changed')
        elif row.state!='suspended' or not row.receipt.get('resume_ready') or row.receipt.get('resume_attempted') or not 0<=time.time()-row.observed<=300 or incidents.digest(row.receipt)!=body.receipt_digest:raise HTTPException(409,'Fresh verified suspension is required before separate recovery approval')
        approval=process_response.Approval(id=str(uuid.uuid4()),process_id=row.id,action=action,expires=time.time()+300,plan_digest=body.plan_digest,actor=user['username'],reason=reason,before_state=row.state,before_hold=row.hold)
        s.add(approval);row.approval_id=approval.id;row.state='resume_queued' if action=='resume' else 'queued';row.hold=True
        process_response.event(s,row,action+'_approved',user['username'],{'approval_id':approval.id})
        return {'job_id':worker.enqueue(s,host_id,'process-'+action,{'process_id':row.id,'quarantine_id':row.quarantine_id,'_actor':user['username']}),'process_hold':True}

@app.post('/api/hosts/{host_id}/security/process-responses/{process_id}/verify')
def verify_process_response(host_id:str,process_id:str,user=Depends(auth)):
    with host_change(host_id,allow_quarantined=True),Session() as s:
        row=process_row(s,host_id,process_id);process_idle(s,row)
        if row.state in ('prepared','rejected'):raise HTTPException(409,'This preparation has not requested process suspension')
        return {'job_id':worker.enqueue(s,host_id,'process-status',{'process_id':row.id,'quarantine_id':row.quarantine_id,'_actor':user['username']})}

@app.get('/api/hosts/{host_id}/security/process-responses/{process_id}/history')
def process_response_history(host_id:str,process_id:str,offset:int=0,user=Depends(auth)):
    from .process_response import Approval,Event
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        row=process_row(s,host_id,process_id)
        events=list(s.scalars(select(Event).where(Event.process_id==row.id).order_by(Event.created.desc(),Event.id).offset(offset).limit(21)))
        approvals=list(s.scalars(select(Approval).where(Approval.process_id==row.id).order_by(Approval.created.desc(),Approval.id).offset(offset).limit(21)))
        return {'events':[object_dict(r) for r in events[:20]],'approvals':[object_dict(r) for r in approvals[:20]],'more':len(events)>20 or len(approvals)>20}

class ResponseMonitorPolicy(BaseModel):
    enabled:bool=False
    interval_minutes:int=Field(default=15,ge=5,le=1440)
    pause_on_problem:bool=False
    expected_revision:str=''

@app.get('/api/hosts/{host_id}/security/response-monitor')
def response_monitor_policy(host_id:str,user=Depends(auth)):
    from . import response_monitor
    with Session() as s:
        host_or_404(s,host_id);return response_monitor.assessment(s,host_id)

@app.put('/api/hosts/{host_id}/security/response-monitor')
def save_response_monitor_policy(host_id:str,body:ResponseMonitorPolicy,user=Depends(auth)):
    from . import response_monitor
    with host_change(host_id,allow_quarantined=True),Session() as s:
        host_or_404(s,host_id)
        if response_monitor.policy(s,host_id)['revision']!=body.expected_revision:raise HTTPException(409,'Response monitoring policy changed; refresh before saving')
        cfg={**body.model_dump(exclude={'expected_revision'}),'revision':str(uuid.uuid4())}
        s.merge(Setting(key='response-monitor:'+host_id,value=cfg))
        audit(s,'response monitoring policy',host_id+' '+user['username']+' '+json.dumps(cfg));s.commit()
        return cfg

class ResponseWatchReview(BaseModel):
    enabled:bool
    expected_revision:str=''
    plan_digest:str=Field(pattern=r'^[a-f0-9]{64}$')
    reason:str=Field(min_length=10,max_length=4000)

@app.put('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/watch')
def review_response_watch(host_id:str,quarantine_id:str,body:ResponseWatchReview,user=Depends(auth)):
    from . import response_monitor,quarantine
    with host_change(host_id,allow_quarantined=True),Session() as s:
        row=response_row(s,host_id,quarantine_id)
        if row.state in ('prepared','rejected') or (body.enabled and not response_monitor.eligible(row)):raise HTTPException(409,'Only retained or uncertain responses can be watched')
        if incidents.digest(row.plan)!=body.plan_digest or response_monitor.watch(s,row)['revision']!=body.expected_revision:raise HTTPException(409,'Response evidence or watch changed; refresh before reviewing')
        reason=body.reason.strip()
        if len(reason)<10:raise ValueError('Provide a meaningful watch review reason')
        cfg={'enabled':body.enabled,'revision':str(uuid.uuid4())}
        s.merge(Setting(key='response-watch:'+row.id,value=cfg))
        quarantine.event(s,row,'watch_reviewed',user['username'],{**cfg,'reason':reason});s.commit()
        return cfg

@app.get('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/checks')
def response_check_history(host_id:str,quarantine_id:str,offset:int=0,user=Depends(auth)):
    from .response_monitor import Check
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        row=response_row(s,host_id,quarantine_id)
        checks=list(s.scalars(select(Check).where(Check.host_id==host_id,Check.quarantine_id==row.id).order_by(Check.created.desc(),Check.id).offset(offset).limit(21)))
        return {'items':[object_dict(r) for r in checks[:20]],'more':len(checks)>20}

@app.get('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/history')
def quarantine_history(host_id:str,quarantine_id:str,offset:int=0,user=Depends(auth)):
    from .quarantine import Event,Approval
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        row=response_row(s,host_id,quarantine_id)
        events=list(s.scalars(select(Event).where(Event.quarantine_id==row.id).order_by(Event.created.desc(),Event.id).offset(offset).limit(21)))
        approvals=list(s.scalars(select(Approval).where(Approval.quarantine_id==row.id).order_by(Approval.created.desc(),Approval.id).offset(offset).limit(21)))
        return {'events':[object_dict(r) for r in events[:20]],'approvals':[object_dict(r) for r in approvals[:20]],'more':len(events)>20 or len(approvals)>20}

class ResponseApproval(BaseModel):
    plan_digest:str
    receipt_digest:str=''
    reason:str=Field(min_length=10,max_length=4000)
    confirmation:str

def queue_file_response(s,host,row,body,user,restore=False):
    from . import quarantine
    if body.confirmation!=('RESTORE' if restore else 'QUARANTINE') or len(body.reason.strip())<10:raise ValueError('Provide a meaningful reason and type '+('RESTORE' if restore else 'QUARANTINE'))
    if incidents.digest(row.plan)!=body.plan_digest or row.fingerprint!=host.fingerprint:raise HTTPException(409,'Prepared evidence or pinned host changed')
    response_idle(s,host.id,response_id=row.id)
    if restore:
        if row.state not in ('quarantined','uncertain') or not row.receipt.get('restore_ready') or row.receipt.get('restore_attempted') or time.time()-row.observed>300 or incidents.digest(row.receipt)!=body.receipt_digest:raise HTTPException(409,'Fresh verified restoration readiness is required; verify response state first')
    else:
        current=quarantine.incident(s,host.id,row.incident_id)
        if row.state!='prepared' or time.time()-row.created>900 or incidents.digest(current.evidence)!=row.evidence_digest:raise HTTPException(409,'Quarantine preparation expired or incident changed')
    approval=quarantine.Approval(id=str(uuid.uuid4()),quarantine_id=row.id,action='restore' if restore else 'quarantine',expires=time.time()+300,plan_digest=body.plan_digest,actor=user['username'],reason=body.reason.strip(),before_state=row.state,before_hold=row.hold)
    s.add(approval);row.approval_id=approval.id;row.state='restore_queued' if restore else 'queued';row.hold=True
    quarantine.event(s,row,'restore_approved' if restore else 'quarantine_approved',user['username'],{'approval_id':approval.id})
    return {'job_id':worker.enqueue(s,host.id,'quarantine-restore' if restore else 'quarantine-apply',{'quarantine_id':row.id,'_actor':user['username']}),'server_changes_paused':True}

@app.post('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/execute')
def approve_quarantine(host_id:str,quarantine_id:str,body:ResponseApproval,user=Depends(auth)):
    with host_change(host_id),Session() as s:
        return queue_file_response(s,host_or_404(s,host_id),response_row(s,host_id,quarantine_id),body,user)

@app.post('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/restore')
def approve_quarantine_restore(host_id:str,quarantine_id:str,body:ResponseApproval,user=Depends(auth)):
    with host_change(host_id,allow_quarantined=True),Session() as s:
        return queue_file_response(s,host_or_404(s,host_id),response_row(s,host_id,quarantine_id),body,user,restore=True)

@app.post('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/status')
def reconcile_quarantine(host_id:str,quarantine_id:str,user=Depends(auth)):
    from . import repair_publication
    with host_change(host_id,allow_quarantined=True),Session() as s:
        row=response_row(s,host_id,quarantine_id)
        publication=repair_publication.active(s,row.id)
        if publication:
            publication_idle(s,publication)
            return {'job_id':worker.enqueue(s,host_id,'trusted-repair-publish-status',{'publication_id':publication.id,'quarantine_id':row.id,'_actor':user['username']})}
        response_idle(s,host_id,response_id=row.id)
        if row.state=='prepared':raise HTTPException(409,'Preparation has not been approved for execution')
        return {'job_id':worker.enqueue(s,host_id,'quarantine-status',{'quarantine_id':row.id,'_actor':user['username']})}

@app.post('/api/hosts/{host_id}/security/quarantines/{quarantine_id}/release')
def release_quarantine_hold(host_id:str,quarantine_id:str,body:ResponseApproval,user=Depends(auth)):
    from . import quarantine,repair_publication
    with host_change(host_id,allow_quarantined=True),Session() as s:
        row=response_row(s,host_id,quarantine_id)
        if repair_publication.active(s,row.id):raise HTTPException(409,'Review the independent publication pause and receipt in Replacement publications')
        response_idle(s,host_id,response_id=row.id)
        if not row.hold or len(body.reason.strip())<10 or incidents.digest(row.plan)!=body.plan_digest or incidents.digest(row.receipt)!=body.receipt_digest:raise HTTPException(409,'Hold or reviewed evidence changed; provide a meaningful review reason')
        if body.confirmation=='KEEP QUARANTINED':
            if row.state!='quarantined' or time.time()-row.observed>300:raise HTTPException(409,'Verify quarantine state before accepting the operational impact')
        elif body.confirmation=='CONSOLE RECOVERED':row.state='console_recovered'
        else:raise ValueError('Type KEEP QUARANTINED or CONSOLE RECOVERED after reviewing target and service state')
        row.hold=False;quarantine.event(s,row,'hold_released',user['username'],{'reason':body.reason.strip(),'confirmation':body.confirmation,'receipt':row.receipt});s.commit()
        return {'state':row.state,'server_changes_paused':False,'incident_not_resolved':True}

class SecurityPlanInput(BaseModel):
    include_related:bool=False

@app.post('/api/hosts/{host_id}/security/incidents/{incident_id}/plan')
def security_plan_queue(host_id:str,incident_id:str,body:SecurityPlanInput|None=None,user=Depends(auth)):
    with worker.Lock('security-plan-queue'):
        with Session() as s:
            host_or_404(s,host_id);row=s.get(incidents.Incident,incident_id)
            if not row or row.host_id!=host_id:raise HTTPException(404,'Incident not found')
            pending=s.scalar(select(Job).where(Job.action.in_(['security-plan','startup-plan']),Job.host_id==host_id,Job.state.in_(['queued','running'])))
            if pending:raise HTTPException(409,'An incident plan is already queued or running for this server')
            # Legacy installations retain this hidden allowance until their
            # explicit shared-admission migration is saved.
            if config(s)['ai_control_mode']=='legacy':
                recent=s.scalar(select(func.count()).select_from(Job).where(Job.action.in_(['security-plan','startup-plan']),Job.created>time.time()-3600))
                if recent>=10:raise HTTPException(429,'Legacy incident plan limit is 10 per hour across the fleet')
            payload={'incident_id':row.id}
            if body and body.include_related:payload['include_related']=True
            job_id=worker.enqueue(s,host_id,'security-plan',payload)
            audit(s,'security AI evidence scope selected',host_id+' '+row.id+' '+user['username']+' related='+str(bool(payload.get('include_related'))));s.commit()
            return {'job_id':job_id}

class SecurityPlanApproval(BaseModel):
    evidence_digest:str

@app.post('/api/hosts/{host_id}/security/plans/{plan_id}/approve')
def security_plan_approve(host_id:str,plan_id:str,body:SecurityPlanApproval,user=Depends(auth)):
    with host_change(host_id,allow_quarantined=True):
        with Session() as s:
            plan=s.get(incidents.Plan,plan_id)
            row=s.get(incidents.Incident,plan.incident_id) if plan else None
            if not row or row.host_id!=host_id:raise HTTPException(404,'Plan not found')
            from . import plan_evidence
            try:current=incidents.digest(plan_evidence.evidence(s,row,plan.content.get('evidence_scope')))
            except (ValueError,KeyError,TypeError):raise HTTPException(409,'Related evidence is unavailable or changed; generate a new plan')
            if plan.state!='draft' or current!=plan.evidence_digest or body.evidence_digest!=current or time.time()-plan.created>86400:
                raise HTTPException(409,'Plan is stale or already reviewed; generate a new plan')
            plan.state='approved';plan.approved_by=user['username'];plan.expires=time.time()+3600
            incidents.event(s,row.id,user['username'],'plan_approved',{'plan_id':plan.id,'expires':plan.expires,'execution':'manual_only'})
            audit(s,'security plan approved for manual response',plan.id+' '+user['username']);s.commit()
            return {'ok':True,'expires':plan.expires,'execution':'manual_only'}

class SecurityScanPolicy(SecurityScanInput):
    enabled:bool=False
    auto_ai_plan:bool=False
    interval_hours:int=Field(default=24,ge=1,le=720)

@app.get('/api/hosts/{host_id}/security/policy')
def security_policy(host_id:str,user=Depends(auth)):
    with Session() as s:
        host_or_404(s,host_id);row=s.get(Setting,'security-policy:'+host_id)
        return row.value if row else {'enabled':False,'interval_hours':24,'paths':['/usr/local/bin','/tmp']}

@app.put('/api/hosts/{host_id}/security/policy')
def security_policy_save(host_id:str,body:SecurityScanPolicy,user=Depends(auth)):
    for path in body.paths:
        if not path.startswith('/') or '..' in Path(path).parts or len(path)>4096 or '\x00' in path:raise ValueError('Invalid scan directory')
    with worker.Lock('security-scan-queue'):
        with Session() as s:
            host_or_404(s,host_id);s.merge(Setting(key='security-policy:'+host_id,value=body.model_dump()))
            audit(s,'security scan policy saved',host_id+' '+user['username']);s.commit()
    return body.model_dump()


class IncidentReview(BaseModel):
    state:str=Field(pattern=r'^(open|acknowledged|false_positive|resolved)$')
    reason:str=Field(min_length=10,max_length=4000)
    expected_updated:float=Field(ge=0,allow_inf_nan=False)

@app.put('/api/hosts/{host_id}/security/incidents/{incident_id}')
def security_incident_review(host_id:str,incident_id:str,body:IncidentReview,user=Depends(auth)):
    with host_change(host_id,allow_quarantined=True):
        with Session() as s:
            row=s.get(incidents.Incident,incident_id)
            if not row or row.host_id!=host_id:raise HTTPException(404,'Incident not found')
            if row.updated!=body.expected_updated:raise HTTPException(409,'Incident changed; refresh before reviewing')
            incidents.review(s,row,body.state,body.reason,user['username'],body.expected_updated)
            s.commit();return object_dict(row)

@app.get('/api/hosts/{host_id}/security/incidents/{incident_id}/related')
def security_related_evidence(host_id:str,incident_id:str,offset:int=0,as_of:float|None=None,expected_digest:str='',user=Depends(auth)):
    from . import security_correlation
    if offset<0 or offset>1_000_000 or len(expected_digest)>64:raise ValueError('Invalid evidence page')
    with Session() as s:
        host_or_404(s,host_id)
        row=s.get(incidents.Incident,incident_id)
        if not row or row.host_id!=host_id:raise HTTPException(404,'Incident not found')
        return security_correlation.page(s,row,offset,as_of,expected_digest)

@app.get('/api/hosts/{host_id}/security/incidents/{incident_id}/timeline')
def security_incident_timeline(host_id:str,incident_id:str,offset:int=0,user=Depends(auth)):
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        row=s.get(incidents.Incident,incident_id)
        if not row or row.host_id!=host_id:raise HTTPException(404,'Incident not found')
        events=list(s.scalars(select(incidents.IncidentEvent).where(incidents.IncidentEvent.incident_id==row.id).order_by(incidents.IncidentEvent.created.desc(),incidents.IncidentEvent.id).offset(offset).limit(51)))
        return {'items':[object_dict(e) for e in events[:50]],'more':len(events)>50,'note':'Timeline recording begins with this version; older receipts and plans remain available.'}

@app.get('/api/security/indicators/{sha256}')
def security_indicator_matches(sha256:str,offset:int=0,user=Depends(auth)):
    if not re.fullmatch('[a-f0-9]{64}',sha256) or offset<0:raise ValueError('Invalid hash or offset')
    with Session() as s:
        rows=list(s.scalars(select(incidents.Incident).where(incidents.Incident.evidence['sha256'].as_string()==sha256).order_by(incidents.Incident.updated.desc(),incidents.Incident.id).offset(offset).limit(51)))
        return {'items':[{'id':r.id,'host_id':r.host_id,'state':r.state,'path':r.evidence['path'],'updated':r.updated,'scan_id':r.scan_id} for r in rows[:50]],'more':len(rows)>50,'scope':'Recorded detections only; this does not perform a fleet scan.'}


class SecurityInspectionInput(BaseModel):
    custom_paths:list[str]=Field(default_factory=list,max_length=16)
    packages:list[str]=Field(default_factory=list,max_length=16)
    persistence:bool=True

@app.post('/api/hosts/{host_id}/security/inspections')
def queue_security_inspection(host_id:str,body:SecurityInspectionInput,user=Depends(auth)):
    from target.agent import validate_inspection
    validate_inspection(body.packages,body.persistence,body.custom_paths)
    with worker.Lock('security-inspection-queue'), Session() as s:
        host_or_404(s,host_id)
        if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.action.in_(['security-inspect','vendor-inspect']),Job.state.in_(['queued','running'])).limit(1)):
            raise HTTPException(409,'A security inspection is already queued or running for this server')
        return {'job_id':worker.enqueue(s,host_id,'security-inspect',body.model_dump())}

class VendorInspectionInput(BaseModel):
    bundle_id:str=Field(pattern=r'^[A-Za-z0-9_-]{1,64}$')

@app.post('/api/hosts/{host_id}/security/vendor-inspections')
def queue_vendor_inspection(host_id:str,body:VendorInspectionInput,user=Depends(auth)):
    # Authentication and archive parsing happen on the worker, outside HTTP requests.
    with worker.Lock('security-inspection-queue'),Session() as s:
        host_or_404(s,host_id)
        if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.action.in_(['security-inspect','vendor-inspect']),Job.state.in_(['queued','running'])).limit(1)):
            raise HTTPException(409,'An inspection is already queued or running for this server')
        return {'job_id':worker.enqueue(s,host_id,'vendor-inspect',body.model_dump())}

@app.get('/api/hosts/{host_id}/security/inspections')
def security_inspections(host_id:str,offset:int=0,user=Depends(auth)):
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        host_or_404(s,host_id)
        rows=list(s.scalars(select(incidents.Inspection).where(incidents.Inspection.host_id==host_id).order_by(incidents.Inspection.created.desc(),incidents.Inspection.id).offset(offset).limit(7)))
        return {'items':[object_dict(r) for r in rows[:6]],'more':len(rows)>6}


@app.get('/api/hosts/{host_id}/security/inspections/{inspection_id}/comparison')
def persistence_comparison(host_id:str,inspection_id:str,user=Depends(auth)):
    from .persistence import compare
    with Session() as s:
        host_or_404(s,host_id)
        row=s.get(incidents.Inspection,inspection_id)
        if not row or row.host_id!=host_id:raise HTTPException(404,'Inspection not found')
        # Skip package-only inspections, but never skip an incomplete inventory:
        # doing so would conceal the coverage gap between observations.
        table=incidents.Inspection
        previous=s.scalar(select(table).where(table.host_id==host_id,
            (table.created<row.created)|((table.created==row.created)&(table.id<row.id)),
            table.report['persistence']['state'].as_string().in_(['collected','incomplete']))
            .order_by(table.created.desc(),table.id.desc()).limit(1))
        result=compare(previous.report.get('persistence') if previous else None,row.report.get('persistence'))
        return {**result,'inspection_id':row.id,'previous_id':previous.id if previous else None,
                'created':row.created,'previous_created':previous.created if previous else None}


class AgentPolicyInput(BaseModel):
    auto_upgrade:bool=False
    auto_repair:bool=False
    expected:dict

@app.get('/api/hosts/{host_id}/security/agent')
def agent_state(host_id:str,user=Depends(auth)):
    from . import agent_maintenance
    with Session() as s:return agent_maintenance.public(s,host_or_404(s,host_id))

@app.put('/api/hosts/{host_id}/security/agent')
def agent_policy(host_id:str,body:AgentPolicyInput,user=Depends(auth)):
    from . import agent_maintenance
    with host_change(host_id):
        with Session() as s:
            host_or_404(s,host_id)
            if body.expected!=agent_maintenance.policy(s,host_id):raise HTTPException(409,'Agent policy changed; refresh before saving')
            value={'auto_upgrade':body.auto_upgrade,'auto_repair':body.auto_repair}
            row=s.get(Setting,'agent-policy:'+host_id)
            if row:row.value=value
            else:s.add(Setting(key='agent-policy:'+host_id,value=value))
            audit(s,'agent policy updated',host_id+' '+json.dumps(value));s.commit()
            return value

@app.post('/api/hosts/{host_id}/security/agent/{action}')
def agent_action(host_id:str,action:str,user=Depends(auth)):
    from . import agent_maintenance
    if action not in ('check','update'):raise HTTPException(404,'Unknown agent operation')
    with host_change(host_id):
        with Session() as s:
            host=host_or_404(s,host_id)
            if not host.fingerprint:raise HTTPException(409,'Pin the host identity first')
            if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.action.in_(['agent-check','agent-update']),Job.state.in_(['queued','running'])).limit(1)):
                raise HTTPException(409,'Agent maintenance is already queued')
            return {'job_id':worker.enqueue(s,host_id,'agent-'+action,{'release':agent_maintenance.release_id(host),'automatic':False})}


class PersistenceApproval(BaseModel):
    inspection_id:str=Field(max_length=36)
    evidence_digest:str=Field(pattern=r'^[a-f0-9]{64}$')
    expected:str=Field(default='',max_length=36)
    reason:str=Field(min_length=10,max_length=4000)

@app.get('/api/hosts/{host_id}/security/baseline')
def get_persistence_baseline(host_id:str,user=Depends(auth)):
    from . import persistence
    with Session() as s:
        host_or_404(s,host_id)
        return persistence.status(s,host_id)

@app.post('/api/hosts/{host_id}/security/baseline')
def approve_persistence_baseline(host_id:str,body:PersistenceApproval,user=Depends(auth)):
    from . import persistence
    with host_change(host_id,allow_quarantined=True),Session() as s:
        host_or_404(s,host_id)
        try:identifier=persistence.approve(s,host_id,body.inspection_id,body.evidence_digest,body.expected,body.reason,user['username'])
        except ValueError as error:raise HTTPException(409,str(error)) from None
        s.commit()
        return {'id':identifier}

@app.get('/api/hosts/{host_id}/security/baseline/history')
def persistence_baseline_history(host_id:str,offset:int=0,user=Depends(auth)):
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        host_or_404(s,host_id)
        table=incidents.PersistenceBaseline
        rows=list(s.scalars(select(table).where(table.host_id==host_id).order_by(table.created.desc(),table.id).offset(offset).limit(21)))
        return {'items':[object_dict(row) for row in rows[:20]],'more':len(rows)>20}


class PersistenceMonitorInput(BaseModel):
    custom_paths:list[str]=Field(default_factory=list,max_length=16)
    enabled:bool=False
    interval_hours:int=Field(default=12,ge=1,le=168)
    link_incidents:bool=False
    expected_revision:str=Field(default='',max_length=36)

@app.get('/api/hosts/{host_id}/security/persistence-monitor')
def get_persistence_monitor(host_id:str,user=Depends(auth)):
    from .persistence import monitor_policy
    with Session() as s:
        host_or_404(s,host_id)
        return monitor_policy(s,host_id)

@app.put('/api/hosts/{host_id}/security/persistence-monitor')
def save_persistence_monitor(host_id:str,body:PersistenceMonitorInput,user=Depends(auth)):
    from .persistence import monitor_policy
    from target.agent import validate_custom_paths
    validate_custom_paths(body.custom_paths)
    with worker.Lock('security-inspection-queue'),Session() as s:
        host_or_404(s,host_id)
        if monitor_policy(s,host_id)['revision']!=body.expected_revision:raise HTTPException(409,'Monitoring policy changed; refresh before saving')
        value={k:v for k,v in body.model_dump().items() if k!='expected_revision'}
        value['revision']=str(uuid.uuid4())
        s.merge(Setting(key='persistence-monitor:'+host_id,value=value))
        audit(s,'persistence monitoring policy',host_id+' '+user['username']+' '+json.dumps(value));s.commit()
        return value

@app.get('/api/hosts/{host_id}/security/persistence-incidents')
def startup_incidents(host_id:str,offset:int=0,user=Depends(auth)):
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        host_or_404(s,host_id);table=incidents.PersistenceIncident
        rows=list(s.scalars(select(table).where(table.host_id==host_id).order_by(table.updated.desc(),table.id).offset(offset).limit(11)))
        from .startup_ai import plans
        return {'items':[object_dict(row)|{'plans':plans(s,row)} for row in rows[:10]],'more':len(rows)>10}

@app.get('/api/hosts/{host_id}/security/persistence-incidents/{incident_id}/history')
def startup_incident_history(host_id:str,incident_id:str,offset:int=0,user=Depends(auth)):
    if offset<0:raise ValueError('Invalid offset')
    with Session() as s:
        row=s.get(incidents.PersistenceIncident,incident_id)
        if not row or row.host_id!=host_id:raise HTTPException(404,'Startup incident not found')
        detections=list(s.scalars(select(incidents.PersistenceDetection).where(incidents.PersistenceDetection.incident_id==incident_id).order_by(incidents.PersistenceDetection.created.desc(),incidents.PersistenceDetection.inspection_id).offset(offset).limit(21)))
        reviews=list(s.scalars(select(incidents.PersistenceReview).where(incidents.PersistenceReview.incident_id==incident_id).order_by(incidents.PersistenceReview.created.desc(),incidents.PersistenceReview.id).offset(offset).limit(21)))
        return {'baseline_id':row.baseline_id,'detections':[object_dict(r) for r in detections[:20]],'reviews':[object_dict(r) for r in reviews[:20]],'more':len(detections)>20 or len(reviews)>20}

@app.put('/api/hosts/{host_id}/security/persistence-incidents/{incident_id}')
def review_startup_incident(host_id:str,incident_id:str,body:IncidentReview,user=Depends(auth)):
    with host_change(host_id,allow_quarantined=True),Session() as s:
        row=s.get(incidents.PersistenceIncident,incident_id)
        if not row or row.host_id!=host_id:raise HTTPException(404,'Startup incident not found')
        if row.updated!=body.expected_updated:raise HTTPException(409,'Startup incident changed; refresh before reviewing')
        reason=body.reason.strip()
        if len(reason)<10:raise ValueError('Provide a review reason of at least 10 characters')
        if row.state==body.state:raise HTTPException(409,'Incident already has this state')
        row.state=body.state;row.updated=max(time.time(),row.updated+.000001)
        s.add(incidents.PersistenceReview(id=str(uuid.uuid4()),incident_id=row.id,actor=user['username'],state=row.state,reason=reason))
        audit(s,'startup incident reviewed',row.id+' '+user['username']+' '+row.state);s.commit()
        return object_dict(row)


class StartupPlanRequest(BaseModel):
    expected_updated:float=Field(ge=0,allow_inf_nan=False)

@app.post('/api/hosts/{host_id}/security/persistence-incidents/{incident_id}/plan')
def queue_startup_plan(host_id:str,incident_id:str,body:StartupPlanRequest,user=Depends(auth)):
    from . import startup_ai
    with worker.Lock('security-plan-queue'),host_change(host_id,allow_quarantined=True),Session() as s:
        host_or_404(s,host_id);row=s.get(incidents.PersistenceIncident,incident_id)
        if not row or row.host_id!=host_id:raise HTTPException(404,'Startup incident not found')
        if row.updated!=body.expected_updated:raise HTTPException(409,'Incident changed; refresh before requesting a plan')
        startup_ai.evidence(s,row)
        if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.action.in_(['security-plan','startup-plan']),Job.state.in_(['queued','running'])).limit(1)):
            raise HTTPException(409,'An incident plan is already queued or running for this server')
        if config(s)['ai_control_mode']=='legacy':
            count=s.scalar(select(func.count()).select_from(Job).where(Job.action.in_(['security-plan','startup-plan']),Job.created>time.time()-3600))
            if count>=10:raise HTTPException(429,'Legacy incident plan limit is 10 per hour across the fleet')
        # Preserve the exact revision through MySQL's JSON number serialization.
        return {'job_id':worker.enqueue(s,host_id,'startup-plan',{'incident_id':row.id,'expected_updated':repr(row.updated)})}

@app.post('/api/hosts/{host_id}/security/persistence-incidents/{incident_id}/plans/{plan_id}/approve')
def approve_startup_plan(host_id:str,incident_id:str,plan_id:str,body:SecurityPlanApproval,user=Depends(auth)):
    from . import startup_ai
    with host_change(host_id,allow_quarantined=True),Session() as s:
        row=s.get(incidents.PersistenceIncident,incident_id);plan=s.get(incidents.Plan,plan_id)
        if not row or row.host_id!=host_id or not plan or plan.incident_id!=row.id:raise HTTPException(404,'Startup plan not found')
        try:current=incidents.digest(startup_ai.evidence(s,row))
        except ValueError as error:raise HTTPException(409,str(error)) from None
        if plan.state!='draft' or plan.evidence_digest!=current or body.evidence_digest!=current or time.time()-plan.created>86400:
            raise HTTPException(409,'Startup plan is stale or already reviewed')
        plan.state='approved';plan.approved_by=user['username'];plan.expires=time.time()+3600
        audit(s,'startup plan approved for manual response',host_id+' '+plan.id+' '+user['username']);s.commit()
        return {'execution':'manual_only','expires':plan.expires}


@app.get('/api/hosts/{host_id}/security/startup-inventory')
def startup_inventory(host_id:str,offset:int=0,q:str='',expected_digest:str='',user=Depends(auth)):
    from . import startup_inventory as inventory
    if offset<0 or offset>256 or len(q)>200 or (expected_digest and not re.fullmatch('[a-f0-9]{64}',expected_digest)):
        raise ValueError('Invalid startup inventory page')
    with Session() as s:
        host_or_404(s,host_id)
        return inventory.page(s,host_id,offset,q,expected_digest)
