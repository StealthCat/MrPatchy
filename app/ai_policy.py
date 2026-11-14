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
POLICY_READ_BATCH=200
MIN_CONCURRENCY=1
DEFAULT_CONCURRENCY=2
MAX_CONCURRENCY=4


def investigation_limit(s,host_id):
    row=s.get(Setting,PREFIX+host_id)
    return investigation_limit_value(row.value if row else {})


def investigation_limit_value(value):
    raw=value.get('concurrency_limit')
    if raw is None:return DEFAULT_CONCURRENCY
    if type(raw) is int and MIN_CONCURRENCY<=raw<=MAX_CONCURRENCY:return raw
    # A manually corrupted policy must reduce admission rather than widen it.
    return MIN_CONCURRENCY


def paused_ids():
    return select(Host.id).join(Setting,Setting.key==PREFIX+Host.id).where(Setting.value['paused'].as_boolean()==True)


def stored_paused(value,present=True):
    """Return whether a stored policy value would make the provider gate refuse.

    Mirrors `require`: a missing policy is resumed, while a non-dict value or a
    `paused` field that is not exactly False is treated as paused (fail closed).
    Display only, never admission.
    """
    if not present:return False
    return not isinstance(value,dict) or value.get('paused',False) is not False


def status(s,host_id):
    row=s.get(Setting,PREFIX+host_id);value=row.value if row else {}
    paused=value.get('paused',False) is not False
    cfg=config(s)
    return {**value,'paused':paused,'revision':value.get('revision',''),
        'concurrency_limit':investigation_limit(s,host_id),
        'concurrency_limit_min':MIN_CONCURRENCY,'concurrency_limit_max':MAX_CONCURRENCY,
        'state':'paused' if paused else 'eligible' if cfg['ai_enabled'] else 'globally_disabled',
        'global_enabled':bool(cfg['ai_enabled'])}


def require(host_ids):
    from .ai import AIError
    keys = sorted({PREFIX + identifier for identifier in host_ids})
    if not keys:
        return
    with Session() as s:
        for start in range(0, len(keys), POLICY_READ_BATCH):
            batch = keys[start:start + POLICY_READ_BATCH]
            values = s.scalars(select(Setting.value).where(Setting.key.in_(batch)))
            # Keep corrupt stored policy closed without an unhandled exception.
            if any(not isinstance(value, dict) or value.get('paused', False) is not False for value in values):
                raise AIError('AI integration is paused for this server; no new provider call was sent.', policy_wait=True)
        if not config(s)['ai_enabled']:
            raise AIError('AI integration is globally disabled; no new provider call was sent.', policy_wait=True)


@contextmanager
def provider():
    identifiers=sorted(set(scope.get()))
    # A process-triage lease is the durable cross-worker in-flight fence. Use
    # the short policy-change gate only for admission so independent subjects
    # on one server can overlap. The administrator route rejects a policy
    # change while any such lease is live.
    from .ai_claims import current,check_current
    lease=current.get()
    if lease and identifiers==[lease.host_id]:
        with ExitStack() as stack:
            for identifier in identifiers:stack.enter_context(Lock('ai-policy-change:'+identifier))
            require(identifiers);check_current()
        yield
        return
    with ExitStack() as stack:
        for identifier in identifiers:stack.enter_context(Lock('ai-provider:'+identifier))
        require(identifiers)
        check_current()
        yield


def save(s,host,paused,expected,reason,actor,concurrency_limit=None):
    if host.deleted_at:raise ValueError('Deleted server AI settings are read-only')
    current=status(s,host.id)
    if current['revision']!=expected:raise ValueError('AI state changed; refresh before saving')
    if len(reason.strip())<10:raise ValueError('Provide a meaningful reason')
    if concurrency_limit is None:concurrency_limit=current['concurrency_limit']
    if type(concurrency_limit) is not int or not MIN_CONCURRENCY<=concurrency_limit<=MAX_CONCURRENCY:
        raise ValueError('Process investigation capacity is outside the supported range')
    value={'paused':paused,'concurrency_limit':concurrency_limit,'revision':str(uuid.uuid4()),
        'updated':time.time(),'actor':actor,'reason':reason.strip()}
    row=s.get(Setting,PREFIX+host.id)
    if row:row.value=value
    else:s.add(Setting(key=PREFIX+host.id,value=value))
    if paused!=current['paused']:action='server AI paused' if paused else 'server AI resumed'
    elif concurrency_limit!=current['concurrency_limit']:action='server AI concurrency changed'
    else:action='server AI policy reaffirmed'
    audit(s,action,host.id+' '+actor+' '+str(concurrency_limit)+' slot(s) '+reason.strip());s.commit()
    return status(s,host.id)
