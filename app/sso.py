"""OIDC authorization-code + PKCE login; explicit issuer/subject account binding."""
import hashlib
import logging
import os
import secrets
import threading
import time
from fastapi import APIRouter,HTTPException,Request
from fastapi.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth
from sqlalchemy import delete,select,func
from .db import Session,Setting,audit
from .identity import User
from .security import token_hash

router=APIRouter()
log=logging.getLogger('mrpatchy.sso')
failure_logged={};failure_lock=threading.Lock()
oauth=OAuth()
issuer=os.getenv('OIDC_ISSUER','')
if issuer:
    if not issuer.startswith('https://'):raise RuntimeError('OIDC_ISSUER must use HTTPS')
    oauth.register('provider',client_id=os.environ['OIDC_CLIENT_ID'],client_secret=os.environ['OIDC_CLIENT_SECRET'],
        server_metadata_url=issuer.rstrip('/')+'/.well-known/openid-configuration',
        client_kwargs={'scope':'openid profile email','code_challenge_method':'S256'})

def binding_key(subject):return 'oidc:'+hashlib.sha256((issuer+'\0'+subject).encode()).hexdigest()
def resolve_identity(s,claims):
    if claims.get('iss')!=issuer or not claims.get('sub'):raise ValueError('OIDC issuer/subject mismatch')
    binding=s.get(Setting,binding_key(claims['sub']))
    identity=s.get(User,binding.value['username']) if binding else None
    if not identity or not identity.enabled:raise ValueError('SSO identity has no enabled account binding')
    return identity

def failure_reason(exc):
    # Fixed vocabulary only: provider error text can echo tokens, codes or attacker input.
    text=str(exc)
    if isinstance(exc,HTTPException):return 'provider discovery or endpoint validation failed'
    if isinstance(exc,ValueError):
        if 'issuer/subject' in text:return 'issuer or subject mismatch'
        if 'no enabled account binding' in text:return 'subject has no enabled account binding'
        if 'ID token' in text:return 'ID token missing'
    return 'token exchange or provider error'
def record_failure(exc,claims=None):
    reason=failure_reason(exc)
    log.warning('SSO callback rejected: %s (%s)',reason,type(exc).__name__)
    subject=(claims or {}).get('sub')
    digest=hashlib.sha256((issuer+'\0'+str(subject)).encode()).hexdigest()[:16] if subject else 'none'
    key=reason+':'+digest;now=time.time()
    with failure_lock:
        for k in [k for k,v in failure_logged.items() if now-v>=300]:del failure_logged[k]
        # One audit entry per reason/subject and window; unauthenticated callers cannot flood the log.
        if key in failure_logged or len(failure_logged)>=1000:return
        failure_logged[key]=now
    try:
        with Session() as s:
            audit(s,'SSO login failed','issuer '+issuer+' subject '+digest+' '+reason);s.commit()
    except Exception:log.exception('SSO failure audit could not be written')

async def validate_provider():
    from urllib.parse import urlsplit
    metadata=await oauth.provider.load_server_metadata()
    if metadata.get('issuer')!=issuer:raise HTTPException(400,'OIDC discovery issuer mismatch')
    for name in ('authorization_endpoint','token_endpoint','jwks_uri'):
        url=urlsplit(metadata.get(name,''))
        if url.scheme!='https' or not url.hostname or url.username or url.password:raise HTTPException(400,'OIDC endpoints must use HTTPS')
    return metadata

@router.get('/api/sso')
def info():return {'enabled':bool(issuer)}
@router.get('/auth/sso')
async def start(request:Request):
    if not issuer:raise HTTPException(404,'SSO is not configured')
    base=os.environ.get('PUBLIC_URL','').rstrip('/')
    if not base.startswith('https://'):raise HTTPException(503,'PUBLIC_URL must use HTTPS for SSO')
    await validate_provider()
    state=secrets.token_urlsafe(32)
    with Session() as s:
        for entry in s.scalars(select(Setting).where(Setting.key.like('oidc-state:%'))):
            if entry.value['expires']<time.time():s.delete(entry)
        s.flush()
        if s.scalar(select(func.count()).select_from(Setting).where(Setting.key.like('oidc-state:%')))>=1000:raise HTTPException(429,'Too many pending SSO logins')
        s.add(Setting(key='oidc-state:'+token_hash(state),value={'expires':time.time()+300}));s.commit()
    return await oauth.provider.authorize_redirect(request,base+'/auth/sso/callback',state=state)
@router.get('/auth/sso/callback')
async def callback(request:Request):
    if not issuer:raise HTTPException(404,'SSO is not configured')
    state=request.query_params.get('state','')
    with Session() as s:
        key='oidc-state:'+token_hash(state)
        row=s.get(Setting,key)
        if not row or row.value['expires']<time.time():raise HTTPException(400,'Expired or reused SSO state')
        # Consume exactly once, including across web processes.
        if s.execute(delete(Setting).where(Setting.key==key)).rowcount!=1:raise HTTPException(400,'SSO state already used')
        s.commit()
    claims=None
    try:
        await validate_provider()
        token=await oauth.provider.authorize_access_token(request)
        claims=token.get('userinfo')
        if not claims:raise ValueError('ID token is required')
        with Session() as s:
            identity=resolve_identity(s,claims)
            session=secrets.token_urlsafe(32)
            s.add(Setting(key='session:'+token_hash(session),value={'csrf':secrets.token_urlsafe(32),'expires':time.time()+43200,'username':identity.username,'generation':identity.generation}))
            audit(s,'SSO login',identity.username);s.commit()
        request.session.clear()
        response=RedirectResponse('/',status_code=303)
        response.set_cookie('mrpatchy',session,httponly=True,secure=True,samesite='strict',max_age=43200)
        return response
    except Exception as exc:
        record_failure(exc,claims if isinstance(claims,dict) else None)
        request.session.clear()
        raise HTTPException(400,'SSO validation failed or account is not assigned')
