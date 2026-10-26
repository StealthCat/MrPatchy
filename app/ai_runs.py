"""Durable, redacted AI run diagnostics. Provider bodies and input evidence stay out."""
import logging
import re
import time
import uuid
from contextvars import ContextVar
from contextlib import contextmanager
from sqlalchemy import String, Text, Double, Integer, select, func
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base, Session, Setting, Behavior, config

log = logging.getLogger('uvicorn.error')
active = ContextVar('ai_run', default=None)

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
        if not row: return
        row.stage = stage; row.message = message[:2000]
        if call: row.calls += 1
        if state: row.state = state; row.finished = time.time()
        s.add(AIEvent(run_id=run_id, stage=stage, message=message[:2000])); s.commit()
    log.info('AI run=%s stage=%s %s', run_id, stage, message[:2000])


@contextmanager
def track(purpose, model, host_id='', subject=''):
    with Session() as s:
        row = AIRun(id=str(uuid.uuid4()), purpose=purpose, model=model, host_id=host_id, subject=subject)
        s.add(row); s.commit(); identifier = row.id
    token = active.set(identifier)
    try:
        event('starting', 'Run accepted by the worker.')
        yield identifier
    except Exception as error:
        event('failed', safe_error(error), state='error')
        raise
    else: event('complete', 'Structured result validated and processing completed.', state='complete')
    finally: active.reset(token)


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
    now=time.time(); cfg=config(s)
    query=select(Behavior.attempted,Behavior.first_seen).where(Behavior.approved==False,Behavior.verdict.in_(('pending','error')))
    rows=list(s.execute(query)); recent=list(s.scalars(select(Behavior.attempted).where(Behavior.attempted>now-3600)))
    heartbeat_row=s.get(Setting,'worker:heartbeat'); seen=heartbeat_row.value.get('seen',0) if heartbeat_row else 0
    running=s.scalar(select(AIRun).where(AIRun.purpose=='triage',AIRun.state=='running').order_by(AIRun.started.desc()).limit(1))
    latest=s.scalar(select(AIRun).where(AIRun.purpose.in_(('triage','worker'))).order_by(AIRun.started.desc()).limit(1))
    run_count=s.scalar(select(func.count()).select_from(AIRun).where(AIRun.purpose=='triage',AIRun.started>now-3600))
    used=max(len(recent),run_count)
    oldest_run=s.scalar(select(func.min(AIRun.started)).where(AIRun.purpose=='triage',AIRun.started>now-3600))
    ready=sum(r.attempted<=now-3600 for r in rows)
    retry=min((r.attempted+3600 for r in rows if r.attempted>now-3600),default=None)
    if not cfg['ai_enabled']: reason='disabled'; message='Automatic AI triage is disabled in Settings.'
    elif not cfg['ai_model'] or not s.get(Setting,'openai_key'): reason='configuration'; message='Save a model ID and API key in Settings.'
    elif not seen or now-seen>90: reason='worker_unavailable'; message='No recent scheduler heartbeat. Check app/worker container logs and DISABLE_SCHEDULER.'
    elif running: reason='running'; message='Investigation in progress: '+running.stage
    elif used>=cfg['ai_hourly_limit']: reason='rate_limited'; message='Hourly investigation limit reached.'; retry=min(recent+([oldest_run] if oldest_run else []))+3600
    elif not rows: reason='idle'; message='No unapproved pending behaviors. Collectors must report observations before triage can run.'
    elif not ready: reason='backoff'; message='Failed or interrupted investigations are waiting for the one-hour retry interval.'
    else: reason='ready'; message='Pending behaviors are eligible; waiting for the next AI worker slot.'
    return {'pending':len(rows),'oldest':min((r.first_seen for r in rows),default=None),'hourly_limit':cfg['ai_hourly_limit'],
            'enabled':cfg['ai_enabled'],'reason':reason,'message':message,'ready':ready,'retry_at':retry,'worker_seen':seen,
            'recent_attempts':used,'last_error':latest.message if latest and latest.state in ('error','interrupted') else '',
            'last_run':latest.id if latest else None}
