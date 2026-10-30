"""Independent server AI controls, serialized with each outbound provider request."""
from contextlib import contextmanager,ExitStack
from contextvars import ContextVar
import time
import uuid
from sqlalchemy import select
from .db import Session,Setting,Host,config,audit
from .coordination import Lock

scope=ContextVar('ai_server_scope',default=())
PREFIX='server-ai:'


def paused_ids():
    return select(Host.id).join(Setting,Setting.key==PREFIX+Host.id).where(Setting.value['paused'].as_boolean()==True)


def status(s,host_id):
    row=s.get(Setting,PREFIX+host_id);value=row.value if row else {}
    paused=value.get('paused',False) is not False
    cfg=config(s)
    return {**value,'paused':paused,'revision':value.get('revision',''),
        'state':'paused' if paused else 'eligible' if cfg['ai_enabled'] else 'globally_disabled',
        'global_enabled':bool(cfg['ai_enabled'])}


def require(host_ids):
    from .ai import AIError
    with Session() as s:
        for identifier in set(host_ids):
            if status(s,identifier)['paused']:raise AIError('AI integration is paused for this server; no new provider call was sent.',policy_wait=True)
        if host_ids and not config(s)['ai_enabled']:raise AIError('AI integration is globally disabled; no new provider call was sent.',policy_wait=True)


@contextmanager
def provider():
    identifiers=sorted(set(scope.get()))
    with ExitStack() as stack:
        for identifier in identifiers:stack.enter_context(Lock('ai-provider:'+identifier))
        require(identifiers)
        yield


def save(s,host,paused,expected,reason,actor):
    if host.deleted_at:raise ValueError('Deleted server AI settings are read-only')
    current=status(s,host.id)
    if current['revision']!=expected:raise ValueError('AI state changed; refresh before saving')
    if len(reason.strip())<10:raise ValueError('Provide a meaningful reason')
    value={'paused':paused,'revision':str(uuid.uuid4()),'updated':time.time(),'actor':actor,'reason':reason.strip()}
    row=s.get(Setting,PREFIX+host.id)
    if row:row.value=value
    else:s.add(Setting(key=PREFIX+host.id,value=value))
    audit(s,'server AI paused' if paused else 'server AI resumed',host.id+' '+actor+' '+reason.strip());s.commit()
    return status(s,host.id)
