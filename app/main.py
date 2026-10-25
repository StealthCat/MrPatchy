import base64
import json
from contextlib import asynccontextmanager, contextmanager
import hashlib
import os
from pathlib import Path
import re
import secrets
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
from . import ssh, apt, worker, tls
from .http_security import RequestSizeLimit
from . import operations
from .identity import User,actor,consume_otp,new_secret
from .security import unseal

@asynccontextmanager
async def lifespan(app):
    init()
    with Session() as s:
        if not s.get(Setting,'admin'):
            password=os.getenv('ADMIN_PASSWORD','')
            if len(password)<12 or password=='replace-with-a-long-unique-password': raise RuntimeError('Set ADMIN_PASSWORD to at least 12 characters before first start')
            s.add(Setting(key='admin',value={'hash':password_hash(password)})); s.commit()
    with Session() as s:
        if not s.get(User,'admin'):
            s.add(User(username='admin',password=s.get(Setting,'admin').value['hash'],role='admin'));s.commit()
    if os.getenv('DISABLE_SCHEDULER')!='1': worker.start()
    yield
    worker.stop.set()
app=FastAPI(title='Mr Patchy',version='0.2.0',lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
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
        sensitive_read=('/history' in path or path.endswith(('/installer','/backups','/repository-access','/repositories'))) or path.startswith(('/api/users','/api/settings','/api/audit','/api/operations'))
        if not self_service:
            if sensitive_read and identity.role!='admin': raise HTTPException(403,'Administrator access required')
            if request.method not in ('GET','HEAD') and identity.role!='admin':
                if identity.role!='operator' or not operator_action: raise HTTPException(403,'This role cannot perform that operation')
        request.state.actor=identity.username
        return {**row.value,'username':identity.username,'role':identity.role,'mfa':bool(identity.otp_secret)}

@contextmanager
def host_change(host_id):
    lock=worker.host_lock(host_id)
    if not lock.acquire(False): raise HTTPException(409,'Server has an active operation. Retry this configuration change when it finishes.')
    try: yield
    finally: lock.release()

def host_or_404(s,host_id):
    h=s.get(Host,host_id)
    if not h: raise HTTPException(404,'Server not found')
    return h

def object_dict(obj,exclude=()): return {c.name:getattr(obj,c.name) for c in obj.__table__.columns if c.name not in exclude}
@app.get('/')
def index(): return FileResponse(static/'index.html')
@app.get('/healthz')
def health(): return {'status':'ok'}
class Login(BaseModel):
    username:str=Field(default='admin',pattern=r'^[A-Za-z0-9_.-]{1,64}$')
    password:str=Field(max_length=1024)
    otp:str=Field(default='',max_length=6)
login_attempts={}; login_lock=threading.Lock()
@app.post('/api/login')
def login(body:Login,request:Request,response:Response):
    ip=request.client.host; now=time.time()
    # Reserve an attempt before expensive password hashing; remove it only on success.
    bucket=ip+':'+body.username
    with login_lock:
        for key in list(login_attempts):
            login_attempts[key]=[x for x in login_attempts[key] if now-x<300]
            if not login_attempts[key]: del login_attempts[key]
        recent=login_attempts.get(bucket,[])
        ip_attempts=sum(len(v) for k,v in login_attempts.items() if k.startswith(ip+':'))
        if len(recent)>=10 or ip_attempts>=50 or len(login_attempts)>=10000: raise HTTPException(429,'Too many attempts. Try again in five minutes.')
        login_attempts[bucket]=recent+[now]
    with login_lock, Session() as s:
        identity=s.get(User,body.username)
        if not identity or not identity.enabled or not verify(body.password,identity.password):
            raise HTTPException(401,'Invalid credentials')
        if identity.otp_secret and not consume_otp(identity,body.otp): raise HTTPException(401,'Invalid credentials or MFA code')
        token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32)
        s.add(Setting(key='session:'+token_hash(token),value={'csrf':csrf,'expires':now+43200,'username':identity.username,'generation':identity.generation}))
        audit(s,'login',identity.username+' '+ip); s.commit()
        login_attempts[bucket]=[x for x in login_attempts.get(bucket,[]) if x!=now]
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
        cfg=config(s); hosts=list(s.scalars(select(Host))); packages=list(s.scalars(select(Package))); now=time.time()
        updates=[p for p in packages if p.candidate]
        return {'servers':len(hosts),'online':sum(h.state=='online' and now-h.last_seen<120 for h in hosts),'packages':len(packages),'updates':len(updates),'overdue':sum(now>p.available_since+cfg['deadlines'][p.priority]*3600 for p in updates),'integrity_alerts':sum(len(h.integrity) for h in hosts),'investigations':s.scalar(select(func.count()).select_from(Behavior).where(Behavior.approved==False)),'repo_minutes':cfg['repo_minutes']}
@app.get('/api/hosts')
def hosts(user=Depends(auth)):
    with Session() as s: return [object_dict(h,('inventory','telemetry','baseline'))|{'architecture':h.inventory.get('architecture',''),'os':h.inventory.get('os','')} for h in s.scalars(select(Host).order_by(Host.name))]
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
class Fingerprint(BaseModel): fingerprint:str=Field(pattern=r'^SHA256:[A-Za-z0-9+/]{43}$')
@app.put('/api/hosts/{host_id}/fingerprint')
def set_fingerprint(host_id:str,body:Fingerprint,user=Depends(auth)):
    with host_change(host_id), Session() as s:
        h=host_or_404(s,host_id); h.fingerprint=body.fingerprint; audit(s,'pin SSH host key',h.id+' '+h.fingerprint); s.commit(); return {'ok':True}
@app.get('/api/hosts/{host_id}/installer')
def installer(host_id:str,user=Depends(auth)):
    with Session() as s:
        h=host_or_404(s,host_id)
        return PlainTextResponse(ssh.bootstrap(h),headers={'Content-Disposition':'attachment; filename="mrpatchy-enroll.sh"'})
@app.post('/api/hosts/{host_id}/enrollment-link')
def enrollment_link(host_id:str,request:Request,user=Depends(auth)):
    with Session() as s:
        host_or_404(s,host_id); token=secrets.token_urlsafe(32)
        s.add(Setting(key='enroll:'+token_hash(token),value={'host_id':host_id,'expires':time.time()+3600})); s.commit()
        base=os.getenv('PUBLIC_URL',str(request.base_url).rstrip('/'))
        return {'url':base+'/enroll/'+token,'expires_in':3600}
@app.get('/enroll/{token}')
def enroll(token:str):
    with Session() as s:
        row=s.get(Setting,'enroll:'+token_hash(token))
        if not row or row.value['expires']<time.time(): raise HTTPException(404,'Enrollment link expired')
        h=host_or_404(s,row.value['host_id'])
        return PlainTextResponse(ssh.bootstrap(h))
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
        host_or_404(s,host_id); cfg=config(s)
        stmt=select(Package).where(Package.host_id==host_id).order_by(Package.name)
        if q: stmt=stmt.where(Package.name.contains(q[:200],autoescape=True))
        if updates: stmt=stmt.where(Package.candidate!='')
        return [object_dict(p)|{'due':p.available_since+cfg['deadlines'][p.priority]*3600 if p.candidate else None} for p in s.scalars(stmt)]
class PatchInput(BaseModel):
    packages:list[str]=Field(min_length=1,max_length=500)
    expected_versions:dict[str,str]|None=None
@app.post('/api/hosts/{host_id}/patch')
def patch(host_id:str,body:PatchInput,user=Depends(auth)):
    with Session() as s:
        h=host_or_404(s,host_id)
        if h.repo_error or not h.last_repo or time.time()-h.last_repo>config(s)['repo_minutes']*120: raise HTTPException(409,'Refresh repositories before patching; candidate data is stale')
        specs=[]
        if len(set(body.packages))!=len(body.packages): raise HTTPException(400,'Duplicate package selections')
        if body.expected_versions is not None and set(body.expected_versions)!=set(body.packages): raise HTTPException(400,'Expected versions must match selected packages')
        for name in body.packages:
            p=s.get(Package,host_id+':'+name)
            if not p or not p.candidate or p.held or p.dpkg_state.split()[-1]!='installed': raise HTTPException(400,'Package missing, held, broken, or has no available update: '+name)
            if body.expected_versions is not None and body.expected_versions[name]!=p.candidate: raise HTTPException(409,'Candidate changed; reload and review '+name)
            specs.append(p.name+'='+p.candidate)
        return {'job_id':worker.enqueue(s,host_id,'patch',{'packages':specs})}
@app.get('/api/hosts/{host_id}/repositories')
def repositories(host_id:str,user=Depends(auth)):
    with Session() as s:
        h=host_or_404(s,host_id)
        access=worker.repository_access(s,host_id);health=[]
        for path,content in h.inventory.get('files',{}).items():
            if not apt.source_path(path): continue
            try:
                rewritten=apt.rewrite(content,access)
                apt.validate_source(rewritten,path.endswith('.sources'))
                active=list(apt.source_options(rewritten,path.endswith('.sources')))
                state='disabled' if not active else ('check_failed' if h.repo_error else ('checked' if h.last_repo else 'unverified'))
                detail='Central APT check includes this source' if active else 'No active repositories'
            except ValueError as e: state='blocked';detail=str(e)
            health.append({'path':path,'state':state,'detail':detail})
        return {'files':h.inventory.get('files',{}),'keys':list(h.inventory.get('keys',{})),'last_checked':h.last_repo,'error':h.repo_error,'health':health}
class RepoInput(BaseModel):
    path:str=Field(max_length=300)
    content:str=Field(max_length=1_000_000)
@app.put('/api/hosts/{host_id}/repositories')
def repository(host_id:str,body:RepoInput,user=Depends(auth)):
    if not apt.source_path(body.path): raise HTTPException(400,'Unsupported repository path')
    try:
        with Session() as access_session: access=worker.repository_access(access_session,host_id)
        apt.validate_source(apt.rewrite(body.content,access),body.path.endswith('.sources'))
    except ValueError as e: raise HTTPException(400,str(e))
    with Session() as s:
        host_or_404(s,host_id); return {'job_id':worker.enqueue(s,host_id,'repository',body.model_dump())}
class KeyInput(BaseModel): name:str; data:str=Field(max_length=3_000_000)
@app.put('/api/hosts/{host_id}/keys')
def key_upload(host_id:str,body:KeyInput,user=Depends(auth)):
    if not re.fullmatch(r'[A-Za-z0-9_-]+\.(gpg|asc)',body.name): raise HTTPException(400,'Use a .gpg or .asc filename')
    try: base64.b64decode(body.data,validate=True)
    except ValueError: raise HTTPException(400,'Invalid base64 key data')
    with Session() as s:
        host_or_404(s,host_id); return {'job_id':worker.enqueue(s,host_id,'key',body.model_dump())}
@app.get('/api/investigations')
def investigations(host_id:str='',user=Depends(auth)):
    with Session() as s:
        stmt=select(Behavior).order_by(Behavior.approved,Behavior.last_seen.desc()).limit(500)
        if host_id: stmt=stmt.where(Behavior.host_id==host_id)
        return [object_dict(x) for x in s.scalars(stmt)]
class ApproveInput(BaseModel): approved:bool
@app.put('/api/investigations/{behavior_id}')
def approve(behavior_id:str,body:ApproveInput,user=Depends(auth)):
    with Session() as s:
        row=s.get(Behavior,behavior_id)
        if not row: raise HTTPException(404,'Behavior not found')
        row.approved=body.approved; audit(s,'approve behavior' if body.approved else 'revoke behavior',behavior_id); s.commit(); return {'ok':True}
@app.get('/api/jobs')
def jobs(user=Depends(auth)):
    with Session() as s: return [object_dict(x,('payload',)) for x in s.scalars(select(Job).order_by(Job.created.desc()).limit(100))]
@app.get('/api/audit')
def audit_log(user=Depends(auth)):
    with Session() as s: return [object_dict(x) for x in s.scalars(select(Audit).order_by(Audit.created.desc()).limit(200))]
@app.get('/api/settings')
def settings(user=Depends(auth)):
    with Session() as s:
        tlsrow=s.get(Setting,'tls')
        return config(s)|{'api_key_configured':s.get(Setting,'openai_key') is not None,'tls':tlsrow.value if tlsrow else {}}
class ConfigInput(BaseModel):
    repo_minutes:int=Field(ge=5,le=10080)
    deadlines:dict[str,int]
    ai_enabled:bool=False
    ai_model:str=Field(default='',max_length=100)
    ai_hourly_limit:int=Field(default=20,ge=1,le=1000)
    history_days:int=Field(default=30,ge=1,le=3650)
    api_key:str=Field(default='',max_length=1000)
@app.put('/api/settings')
def settings_save(body:ConfigInput,user=Depends(auth)):
    if set(body.deadlines)!={'critical','high','normal','low'} or any(v<1 or v>8760 for v in body.deadlines.values()): raise HTTPException(400,'Provide four priority deadlines, 1–8760 hours')
    with Session() as s:
        if body.ai_enabled and (not body.ai_model or not (body.api_key or s.get(Setting,'openai_key'))): raise HTTPException(400,'AI requires a model and an API key')
        s.merge(Setting(key='config',value=body.model_dump(exclude={'api_key'})))
        if body.api_key: s.merge(Setting(key='openai_key',value={'encrypted':seal(body.api_key)}))
        audit(s,'update settings','Patch policy, cadence or AI configuration changed'); s.commit(); return {'ok':True}
class TLSInput(BaseModel):
    domain:str
    mode:str
    acme_url:str=''
    certificate:str=Field(default='',max_length=100000)
    private_key:str=Field(default='',max_length=100000)
    ca:str=Field(default='',max_length=100000)
@app.put('/api/tls')
def tls_save(body:TLSInput,user=Depends(auth)):
    try: result=tls.apply(body.model_dump())
    except Exception as e: raise HTTPException(400,'TLS configuration rejected: '+str(e)[:1000])
    with Session() as s:
        s.merge(Setting(key='tls',value=result)); audit(s,'update TLS',result['domain']+' '+result['mode']); s.commit()
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
def job_detail(job_id:str,user=Depends(auth)):
    with Session() as s:
        job=s.get(Job,job_id)
        if not job: raise HTTPException(404,'Operation not found')
        return object_dict(job,('payload',))

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
        pending=s.scalar(select(func.count()).select_from(Behavior).where(Behavior.approved==False,Behavior.verdict.in_(['pending','error'])))
        oldest=s.scalar(select(func.min(Behavior.first_seen)).where(Behavior.approved==False,Behavior.verdict.in_(['pending','error'])))
        return {'pending':pending,'oldest':oldest,'hourly_limit':config(s)['ai_hourly_limit'],'enabled':config(s)['ai_enabled']}

@app.get('/api/hosts/{host_id}/history/{record_id}')
def history_detail(host_id:str,record_id:str,kind:str='inventory',user=Depends(auth)):
    if kind not in ('inventory','observations'): raise HTTPException(400,'Invalid history kind')
    model=InventoryRevision if kind=='inventory' else Observation
    with Session() as s:
        record=s.get(model,record_id)
        if not record or record.host_id!=host_id: raise HTTPException(404,'History record not found')
        return object_dict(record)

@app.get('/api/identity')
def identity_info(user=Depends(auth)): return {k:user[k] for k in ('username','role','mfa')}

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

def check_password(row,body):
    if not verify(body.password,row.password): raise HTTPException(401,'Invalid credentials')
    if row.otp_secret and not consume_otp(row,body.otp): raise HTTPException(401,'Invalid MFA code')

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
@app.put('/api/operations/notifications')
def notifications(body:NotificationInput,user=Depends(auth)):
    from urllib.parse import urlsplit
    url=urlsplit(body.url)
    if body.enabled and (url.scheme!='https' or not url.hostname or url.username or url.password or url.fragment):raise HTTPException(400,'Use an HTTPS webhook URL without embedded credentials')
    if any(c in body.token for c in '\r\n'):raise HTTPException(400,'Invalid token')
    with Session() as s:
        s.merge(Setting(key='notifications',value={'encrypted':seal(json.dumps(body.model_dump()))}));s.commit()
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
    with host_change(host_id),Session() as s:
        job=s.get(Job,job_id)
        if job.state!='queued':raise HTTPException(409,'Only queued operations can be cancelled')
        job.state='cancelled';audit(s,'cancel job',user['username']+' '+job_id);s.commit()
    return {'ok':True}

@app.get('/api/hosts/{host_id}/sbom')
def sbom(host_id:str,user=Depends(auth)):
    from urllib.parse import quote
    with Session() as s:
        host_or_404(s,host_id)
        return {'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'serialNumber':'urn:uuid:'+str(uuid.uuid4()),
            'components':[{'type':'library','name':p.name,'version':p.installed,'purl':'pkg:deb/'+quote(p.name.split(':')[0],safe='')+'@'+quote(p.installed,safe='')+'?arch='+p.name.split(':')[-1]} for p in s.scalars(select(Package).where(Package.host_id==host_id))]}

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
@app.post('/api/operations/rollouts')
def rollout(body:RolloutInput,user=Depends(auth)):
    if len(set(body.hosts))!=len(body.hosts):raise HTTPException(400,'Duplicate servers')
    with Session() as s:
        prepared=[]
        for host_id in body.hosts:
            h=host_or_404(s,host_id);specs=[]
            if s.scalar(select(func.count()).select_from(Job).where(Job.host_id==host_id,Job.state.in_(['queued','running'])))>=50:raise HTTPException(429,'Server queue is full')
            for name in body.packages:
                p=s.get(Package,host_id+':'+name)
                if not p or not p.candidate:raise HTTPException(400,'Missing candidate on '+h.name+': '+name)
                specs.append(name+'='+p.candidate)
            worker.validate_patch(s,h,specs);prepared.append((h.id,specs))
        # One transaction: no partial rollout submission. The first server is the canary.
        ids=[]
        for host_id,specs in prepared:
            job=Job(id=str(uuid.uuid4()),host_id=host_id,action='patch',payload={'packages':specs,'_depends_on':ids[-1:]})
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
@app.put('/api/operations/smtp')
def smtp_save(body:SMTPInput,user=Depends(auth)):
    from .mail import validate
    value=validate(body.model_dump());value['channel']='smtp'
    with Session() as s:s.merge(Setting(key='notifications',value={'encrypted':seal(json.dumps(value))}));s.commit()
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

class ReconcileInput(BaseModel): verified_target_state:bool=False
@app.post('/api/operations/jobs/{job_id}/reconcile')
def reconcile_job(job_id:str,body:ReconcileInput,user=Depends(auth)):
    if not body.verified_target_state:raise HTTPException(400,'Review the target state before reconciling an interrupted worker')
    with Session() as s:
        job=s.get(Job,job_id)
        if not job:raise HTTPException(404,'Job not found')
        host_id=job.host_id
    with host_change(host_id),Session() as s:
        job=s.get(Job,job_id);h=host_or_404(s,host_id)
        if job.state!='running':raise HTTPException(409,'Only orphaned running jobs require reconciliation')
        if ssh.call(h,{'action':'operation-status'}).get('busy'):raise HTTPException(409,'Target operation is still running')
        job.state='interrupted';job.output='Operator reviewed target after worker interruption; operation was not automatically replayed'
        audit(s,'reconcile job',user['username']+' '+job_id);s.commit()
    return {'ok':True}
