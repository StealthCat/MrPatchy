"""Durable, redacted AI run diagnostics. Provider bodies and input evidence stay out."""
import math
import logging
import re
import time
import uuid
from decimal import Decimal
from contextvars import ContextVar
from contextlib import contextmanager
from sqlalchemy import String, Text, Double, Integer, JSON, select, func, and_
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base, Session, Setting, Behavior, Package, config
from . import ai_pricing

log = logging.getLogger('uvicorn.error')
active = ContextVar('ai_run', default=None)
pending_timings = ContextVar('ai_timings', default=None)

class AIRun(Base):
    __tablename__ = 'ai_runs'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(30), index=True)
    host_id: Mapped[str] = mapped_column(String(36), default='', index=True)
    subject: Mapped[str] = mapped_column(String(400), default='')
    model: Mapped[str] = mapped_column(String(100), default='')
    state: Mapped[str] = mapped_column(String(30), default='running')
    stage: Mapped[str] = mapped_column(String(80), default='starting')
    message: Mapped[str] = mapped_column(Text, default='')
    started: Mapped[float] = mapped_column(Double, default=time.time, index=True)
    finished: Mapped[float] = mapped_column(Double, default=0)
    calls: Mapped[int] = mapped_column(Integer, default=0)

class AIEvent(Base):
    __tablename__ = 'ai_events'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    created: Mapped[float] = mapped_column(Double, default=time.time)
    stage: Mapped[str] = mapped_column(String(80))
    message: Mapped[str] = mapped_column(Text)


class AICall(Base):
    """One durable usage receipt per attempted provider call, with no prompt/body."""
    __tablename__ = 'ai_calls'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    number: Mapped[int] = mapped_column(Integer)
    created: Mapped[float] = mapped_column(Double, default=time.time)
    requested_model: Mapped[str] = mapped_column(String(100))
    response_model: Mapped[str] = mapped_column(String(100), default='')
    service_tier: Mapped[str] = mapped_column(String(30), default='')
    usage: Mapped[dict] = mapped_column(JSON, default=dict)
    pricing: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(30), default='unavailable')
    reason: Mapped[str] = mapped_column(Text, default='No usage receipt was received. The call may still have incurred a charge.')


class AIRunHost(Base):
    """Durable membership survives a package score being superseded or retried."""
    __tablename__ = 'ai_run_hosts'
    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)


def run_hosts(s, run_ids):
    grouped = {identifier: set() for identifier in run_ids}
    if not grouped: return grouped
    from .update_scores import UpdateScore
    # Score links recover some historical batches created before durable membership.
    for model in (AIRunHost, UpdateScore):
        for run_id, host_id in s.execute(select(model.run_id, model.host_id).where(model.run_id.in_(grouped))):
            grouped[run_id].add(host_id)
    return grouped


# These diagnostic timings share ordinary run-history retention, not a budget or
# cache ledger. Monotonic elapsed time never depends on host wall-clock changes.
TIMING_STAGES = {'provider_admission','provider','receipt_persistence','usage_persistence',
                 'ssh_evidence','evidence_persistence','result_persistence','run','admission','queue_age',
                 'known_good_lookup'}


def timing(stage, seconds, outcome='complete'):
    run_id = active.get()
    if not run_id or stage not in TIMING_STAGES or outcome not in ('complete','error'):return
    if not isinstance(seconds,(int,float)) or not math.isfinite(seconds) or seconds<0:return
    buffer=pending_timings.get()
    if buffer is None:return
    message=f'{stage.replace("_"," ")}: {seconds*1000:.3f} ms; outcome={outcome}'
    buffer.append((stage,message,time.time()))
    if len(buffer)>=32:flush_timings()


def flush_timings():
    buffer=pending_timings.get();run_id=active.get()
    if not buffer or not run_id:return
    try:
        with Session() as s:
            if not s.get(AIRun,run_id):return
            s.add_all(AIEvent(run_id=run_id,stage='timing_'+stage,message=message,created=created) for stage,message,created in buffer)
            s.commit()
    except Exception:
        # Diagnostics never convert a validated result into a retry or mask the
        # original error. Bounded batches can be missing after a crash/failure.
        log.warning('AI timing could not be persisted; performance coverage is incomplete')
    finally:buffer.clear()


@contextmanager
def measure(stage):
    started=time.perf_counter();outcome='error'
    try:
        yield
        outcome='complete'
    finally:timing(stage,time.perf_counter()-started,outcome)


def request_started(model):
    run_id = active.get()
    if not run_id: return None
    message = 'Sending bounded structured-output request to OpenAI.'
    with Session() as s:
        row = s.get(AIRun, run_id)
        if not row: return None
        row.calls += 1; row.stage = 'api_request'; row.message = message
        receipt = AICall(id=str(uuid.uuid4()), run_id=run_id, number=row.calls, requested_model=ai_pricing.identifier(model))
        s.add(receipt)
        s.add(AIEvent(run_id=run_id, stage='api_request', message=message)); s.commit()
        return receipt.id


def record_usage(call_id, data, payload):
    values = ai_pricing.estimate(data, payload)
    if not call_id: return values
    with Session() as s:
        row = s.get(AICall, call_id)
        if not row: return values
        for key, value in values.items(): setattr(row, key, value)
        s.commit()
    return values


def call_receipts(s, run_ids):
    grouped = {identifier: [] for identifier in run_ids}
    if not grouped: return grouped
    for row in s.scalars(select(AICall).where(AICall.run_id.in_(grouped)).order_by(AICall.number)):
        grouped[row.run_id].append(row)
    return grouped


def cost_summary(run, receipts):
    priced = [r for r in receipts if r.status == 'estimated']
    amount = sum((Decimal(r.pricing['estimated_usd']) for r in priced), Decimal(0))
    calls = max(run.calls, len(receipts))
    status = ('no_calls' if not calls else 'estimated' if len(priced) == calls
              else 'partial' if priced else 'unavailable')
    usages = [r.usage for r in receipts if r.usage]
    tokens = {key: sum(u[key] for u in usages if u.get(key) is not None) for key in ai_pricing.TOKEN_FIELDS}
    return {'status': status, 'estimated_usd': format(amount, 'f') if priced or not calls else None,
            'currency': 'USD', 'priced_calls': len(priced), 'total_calls': calls,
            'usage_calls': len(usages), 'tokens': tokens, 'in_progress': run.state == 'running'}


def safe_error(error):
    from .ai import AIError
    if isinstance(error, AIError): return str(error)[:2000]
    # Never persist str(unexpected_error): request bodies, SQL parameters and
    # cryptographic failures may contain evidence or credentials.
    kind = type(error).__name__
    return 'Internal '+kind+' during AI processing. Check worker/database health; no provider result was accepted.'


def event(stage, message, *, state=None, call=False):
    run_id = active.get()
    if not run_id: return
    with Session() as s:
        row = s.get(AIRun, run_id)
        if not row or row.state!='running': return
        row.stage = stage; row.message = message[:2000]
        if call: row.calls += 1
        if state: row.state = state; row.finished = time.time()
        s.add(AIEvent(run_id=run_id, stage=stage, message=message[:2000])); s.commit()
    log.info('AI run=%s stage=%s %s', run_id, stage, message[:2000])


def defer(run_id,next_at):
    """Reclassify a controlled shared-eligibility refusal as retained queued work."""
    if not run_id or not isinstance(next_at,(int,float)) or not math.isfinite(next_at) or next_at<=0:return
    message='Work remains queued until shared AI eligibility; no provider request will bypass the saved floor.'
    with Session() as s:
        row=s.get(AIRun,run_id)
        if not row or row.state!='error':return
        row.state='deferred';row.stage='deferred';row.message=message;row.finished=time.time()
        s.add(AIEvent(run_id=run_id,stage='deferred',message=message));s.commit()


@contextmanager
def track(purpose, model, host_id='', subject='', host_ids=None, run_id=None):
    with Session() as s:
        if run_id:
            row=s.get(AIRun,run_id)
            if not row or (row.purpose,row.model,row.host_id,row.subject,row.state)!=(purpose,model,host_id,subject,'running'):
                raise ValueError('Pre-admitted AI run changed; refusing execution')
        else:
            row = AIRun(id=str(uuid.uuid4()), purpose=purpose, model=model, host_id=host_id, subject=subject)
            s.add(row)
            for member in set(host_ids or []) | ({host_id} if host_id else set()):
                s.add(AIRunHost(run_id=row.id,host_id=member))
            s.commit()
        identifier = row.id
    from . import ai_policy,ai_admission
    admission_token=ai_admission.begin_scope()
    policy_token=ai_policy.scope.set(tuple(set(host_ids or []) | ({host_id} if host_id else set())))
    token = active.set(identifier)
    timing_token=pending_timings.set([])
    started=time.perf_counter();outcome='error'
    try:
        event('starting', 'Run accepted by the worker.')
        yield identifier
    except Exception as error:
        event('failed', safe_error(error), state='error')
        raise
    else:
        event('complete', 'Structured result validated and processing completed.', state='complete');outcome='complete'
    finally:
        timing('run',time.perf_counter()-started,outcome)
        flush_timings()
        pending_timings.reset(timing_token);active.reset(token);ai_policy.scope.reset(policy_token);ai_admission.end_scope(admission_token)


def response_received(response):
    request_id = getattr(response,'headers',{}).get('x-request-id', '')
    suffix = '; request ID '+request_id if re.fullmatch(r'req_[A-Za-z0-9_-]{1,120}', request_id) else ''
    event('api_response', 'OpenAI HTTP '+str(getattr(response,'status_code','unknown'))+suffix)


def reconcile(purpose):
    """Called only while owning that purpose's distributed execution lock."""
    with Session() as s:
        for row in s.scalars(select(AIRun).where(AIRun.purpose==purpose, AIRun.state=='running')):
            row.state='interrupted'; row.finished=time.time(); row.stage='interrupted'
            row.message='Previous run lost its worker before completion. Normal retry limits still apply.'
            s.add(AIEvent(run_id=row.id, stage=row.stage, message=row.message))
        s.commit()


def heartbeat():
    with Session() as s:
        row=s.get(Setting,'worker:heartbeat'); now=time.time()
        if not row or now-row.value.get('seen',0)>=15:
            s.merge(Setting(key='worker:heartbeat',value={'seen':now})); s.commit()


def task_failure(error):
    with Session() as s:
        message=safe_error(error)
        s.add(AIRun(id=str(uuid.uuid4()),purpose='worker',state='error',stage='worker_failure',message=message,finished=time.time()))
        s.commit()
    log.error('AI worker task failed: %s',message)


def status(s):
    from . import ai_retry,ai_policy,host_lifecycle,ai_claims,ai_admission,ai_budget,ai_provider_backoff,worker_registry
    from .update_scores import UpdateScore
    now=time.time(); cfg=config(s)
    query=select(Behavior.attempted,Behavior.first_seen,Behavior.host_id,ai_retry.TriageRetry).outerjoin(ai_retry.TriageRetry,ai_retry.TriageRetry.subject==Behavior.id).where(Behavior.approved==False,Behavior.verdict.in_(('pending','error')),Behavior.host_id.not_in(host_lifecycle.inactive_ids()))
    rows=list(s.execute(query)); recent=list(s.scalars(select(Behavior.attempted).where(Behavior.attempted>now-3600)))
    heartbeat_row=s.get(Setting,'worker:heartbeat'); seen=heartbeat_row.value.get('seen',0) if heartbeat_row else 0
    running=s.scalar(select(AIRun).where(AIRun.purpose=='triage',AIRun.state=='running').order_by(AIRun.started.desc()).limit(1))
    active_count=s.scalar(select(func.count()).select_from(ai_claims.Claim).where(ai_claims.Claim.expires>now))
    reports=[r.value for r in s.scalars(select(Setting).where(Setting.key.startswith(worker_registry.PREFIX)))]
    capacity=sum(v['ai_capacity'] for v in reports if isinstance(v,dict) and worker_registry.report_state(v,now)[0] in ('reporting','draining','drained') and type(v.get('ai_capacity')) is int and 1<=v['ai_capacity']<=8)
    latest=s.scalar(select(AIRun).where(AIRun.purpose.in_(('triage','worker'))).order_by(AIRun.started.desc()).limit(1))
    run_count=s.scalar(select(func.count()).select_from(AIRun).where(AIRun.purpose=='triage',AIRun.started>now-3600))
    used=max(len(recent),run_count)
    oldest_run=s.scalar(select(func.min(AIRun.started)).where(AIRun.purpose=='triage',AIRun.started>now-3600))
    paused_ids=set(s.scalars(ai_policy.paused_ids()));signature=ai_retry.configuration(s)
    states=[ai_retry.summary(r.TriageRetry,signature,now,r.attempted) for r in rows if r.host_id not in paused_ids]
    ready=sum(r['state']=='ready' for r in states)
    blocked=sum(r['state']=='blocked' for r in states);paused=len(rows)-len(states)
    retry=min((r['next_at'] for r in states if r['state']!='blocked' and r['next_at']>now),default=None)
    admission=ai_admission.status(s)
    budget=ai_budget.status(s,now)
    provider_backoff=ai_provider_backoff.status(s,now)
    scoring_scope=and_(UpdateScore.host_id==Package.host_id,UpdateScore.name==Package.name,
        UpdateScore.installed==Package.installed,UpdateScore.candidate==Package.candidate)
    scoring_where=(UpdateScore.state=='deferred',Package.candidate!='',
        Package.host_id.not_in(host_lifecycle.inactive_ids()))
    scoring_deferred=s.scalar(select(func.count()).select_from(UpdateScore).join(Package,scoring_scope).where(*scoring_where))
    scoring_next=s.scalar(select(func.min(UpdateScore.next_at)).select_from(UpdateScore).join(Package,scoring_scope).where(*scoring_where))
    if scoring_next and scoring_next>now:retry=min([value for value in (retry,scoring_next) if value is not None])
    if provider_backoff['blocked']:
        retry=min([value for value in (retry,provider_backoff['next_at']) if value is not None])
    if admission['mode'] in ('rate','rate_and_daily') and admission['next_at'] and admission['next_at']>now:
        retry=min([value for value in (retry,admission['next_at']) if value is not None])
    if not cfg['ai_enabled']: reason='disabled'; message='Automatic AI triage is disabled in Settings.'
    elif not cfg['ai_model'] or not s.get(Setting,'openai_key'): reason='configuration'; message='Save a model ID and API key in Settings.'
    elif not seen or now-seen>90: reason='worker_unavailable'; message='No recent scheduler heartbeat. Check app/worker container logs and DISABLE_SCHEDULER.'
    elif running: reason='running'; message=str(active_count)+' process investigation(s) hold current leases. Latest stage: '+running.stage
    elif provider_backoff['blocked']:reason='backoff';message='Shared provider backoff is waiting for retry eligibility after a transient failure.'
    elif admission['mode']=='legacy' and used>=cfg['ai_hourly_limit']: reason='rate_limited'; message='Legacy hourly investigation limit reached.'; retry=min(recent+([oldest_run] if oldest_run else []))+3600
    elif admission['mode'] in ('rate','rate_and_daily') and admission['next_at'] and admission['next_at']>now: reason='rate_limited'; message='Shared smooth-rate admission is waiting for the next provider start.'
    elif budget['enabled'] and float(budget['remaining_usd'])<=0: reason='spend_limited'; message='The daily AI spend cap is fully reserved or settled until reset.';retry=budget['next_reset']
    elif not rows and scoring_deferred and scoring_next>now:reason='backoff';message='Update scoring is queued until shared AI eligibility.'
    elif not rows and scoring_deferred:reason='ready';message='Deferred update scoring is eligible for the next scheduler slot.'
    elif not rows: reason='idle'; message='No unapproved pending behaviors. Collectors must report observations before triage can run.'
    elif not ready and retry: reason='backoff'; message='Transient or interrupted investigations are waiting for retry eligibility. Configuration failures require review.'
    elif not ready: reason='blocked'; message='Investigations need configuration review, explicit retry or server AI resume. No automatic call is eligible.'
    else: reason='ready'; message='Pending behaviors are eligible; waiting for the next AI worker slot.'
    return {'pending':len(rows),'oldest':min((r.first_seen for r in rows),default=None),'hourly_limit':cfg['ai_hourly_limit'],
            'enabled':cfg['ai_enabled'],'reason':reason,'message':message,'ready':ready,'retry_at':retry,'worker_seen':seen,
            'blocked':blocked,'paused':paused,
            'active':active_count,'queued':max(0,len(rows)-active_count),'reported_capacity':capacity or None,'per_server_limit':1,
            'recent_attempts':used,'last_error':latest.message if latest and latest.state in ('error','interrupted') else '',
            'last_run':latest.id if latest else None,'admission':admission,'budget':budget,'provider_backoff':provider_backoff,
            'scoring_deferred':scoring_deferred,'scoring_next_at':scoring_next}
