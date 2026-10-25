import base64
from contextlib import asynccontextmanager
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
from .db import Session, Host, Package, Behavior, Job, Setting, Audit, init, config, audit
from .security import password_hash, verify, token_hash, seal
from . import ssh, apt, worker, tls
from .http_security import RequestSizeLimit

@asynccontextmanager
async def lifespan(app):
    init()
    with Session() as s:
        if not s.get(Setting,'admin'):
            password=os.getenv('ADMIN_PASSWORD','')
            if len(password)<12 or password=='replace-with-a-long-unique-password': raise RuntimeError('Set ADMIN_PASSWORD to at least 12 characters before first start')
            s.add(Setting(key='admin',value={'hash':password_hash(password)})); s.commit()
    if os.getenv('DISABLE_SCHEDULER')!='1': worker.start()
    yield
    worker.stop.set()
app=FastAPI(title='Mr Patchy',version='0.1.1',lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
app.add_middleware(RequestSizeLimit)
static=Path(__file__).parent/'static'
app.mount('/static',StaticFiles(directory=static),name='static')

@app.middleware('http')
async def guard(request,call_next):
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if request.url.path.startswith(('/api','/enroll')): response.headers['Cache-Control']='no-store'
    return response

def auth(request:Request):
    token=request.cookies.get('mrpatchy','')
    with Session() as s:
        row=s.get(Setting,'session:'+token_hash(token))
        if not row or row.value['expires']<time.time(): raise HTTPException(401,'Sign in required')
        if request.method not in ['GET','HEAD'] and not secrets.compare_digest(request.headers.get('x-csrf-token',''),row.value['csrf']): raise HTTPException(403,'Invalid CSRF token')
        return row.value

def host_or_404(s,host_id):
    h=s.get(Host,host_id)
    if not h: raise HTTPException(404,'Server not found')
    return h

def object_dict(obj,exclude=()): return {c.name:getattr(obj,c.name) for c in obj.__table__.columns if c.name not in exclude}
@app.get('/')
def index(): return FileResponse(static/'index.html')
@app.get('/healthz')
def health(): return {'status':'ok'}
class Login(BaseModel): password:str=Field(max_length=1024)
login_attempts={}; login_lock=threading.Lock()
@app.post('/api/login')
def login(body:Login,request:Request,response:Response):
    ip=request.client.host; now=time.time()
    with login_lock:
        recent=[x for x in login_attempts.get(ip,[]) if now-x<300]
        if len(recent)>=10: raise HTTPException(429,'Too many attempts. Try again in five minutes.')
        login_attempts[ip]=recent+[now]
    with Session() as s:
        if not verify(body.password,s.get(Setting,'admin').value['hash']): raise HTTPException(401,'Incorrect password')
        token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32)
        s.add(Setting(key='session:'+token_hash(token),value={'csrf':csrf,'expires':now+43200})); audit(s,'login',ip); s.commit()
    response.set_cookie('mrpatchy',token,httponly=True,secure=os.getenv('COOKIE_SECURE','true').lower()=='true',samesite='strict',max_age=43200)
    return {'csrf':csrf}
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
    with Session() as s:
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
    if action not in ['deploy','refresh']: raise HTTPException(404,'Unknown action')
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
            if not p or not p.candidate or p.held: raise HTTPException(400,'Package missing, held, or has no available update: '+name)
            if body.expected_versions is not None and body.expected_versions[name]!=p.candidate: raise HTTPException(409,'Candidate changed; reload and review '+name)
            specs.append(p.name+'='+p.candidate)
        return {'job_id':worker.enqueue(s,host_id,'patch',{'packages':specs})}
@app.get('/api/hosts/{host_id}/repositories')
def repositories(host_id:str,user=Depends(auth)):
    with Session() as s:
        h=host_or_404(s,host_id)
        return {'files':h.inventory.get('files',{}),'keys':list(h.inventory.get('keys',{})),'last_checked':h.last_repo,'error':h.repo_error}
class RepoInput(BaseModel):
    path:str=Field(max_length=300)
    content:str=Field(max_length=1_000_000)
@app.put('/api/hosts/{host_id}/repositories')
def repository(host_id:str,body:RepoInput,user=Depends(auth)):
    if not apt.source_path(body.path): raise HTTPException(400,'Unsupported repository path')
    try: apt.validate_source(body.content,body.path.endswith('.sources'))
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
    with Session() as s:
        p=s.get(Package,host_id+':'+body.name)
        if not p: raise HTTPException(404,'Package not found')
        p.priority_manual=body.priority!='auto'
        p.priority=body.priority if p.priority_manual else ('high' if '-security' in p.origin or '/security' in p.origin else 'normal')
        audit(s,'set package priority',host_id+' '+body.name+' '+body.priority);s.commit();return {'ok':True}
