"""Shared, durable admission for every billable AI provider call.

Rate mode is a smooth fleet-wide leaky bucket with no accumulated burst. Legacy
mode preserves the old purpose-specific limits until an administrator explicitly
migrates. Unthrottled removes only Mr Patchy's pacing, never provider, pause,
lifecycle, authorization, or finite-concurrency controls.
"""
import time
from contextvars import ContextVar

from sqlalchemy import String, Double, Integer
from sqlalchemy.orm import Mapped, mapped_column

from .coordination import Lock
from .db import Base, Session, config

current=ContextVar('ai_admission_scope',default=None)


def begin_scope():
    """Start one logical work item; nested scopes reuse the outer admission."""
    if current.get() is not None:return None
    return current.set({'admitted':False})


def end_scope(token):
    if token is not None:current.reset(token)


class Admission(Base):
    __tablename__='ai_admission'
    id: Mapped[str]=mapped_column(String(20),primary_key=True)
    next_at: Mapped[float]=mapped_column(Double,default=0)
    admitted: Mapped[int]=mapped_column(Integer,default=0)
    updated: Mapped[float]=mapped_column(Double,default=0)
    model: Mapped[str]=mapped_column(String(100),default='')


def admit(model):
    """Reserve one provider start or fail before any call receipt/body exists."""
    from .ai import AIError
    work=current.get()
    if work is not None and work['admitted']:
        return {'mode':'continuation','admitted':True,'next_at':None}
    with Lock('ai-shared-admission'):
        with Session() as session:
            settings=config(session);mode=settings['ai_control_mode']
            if mode not in ('rate','rate_and_daily'):
                if work is not None:work['admitted']=True
                return {'mode':mode,'admitted':True,'next_at':None}
            now=time.time();row=session.get(Admission,'global')
            if row and row.next_at>now:
                raise AIError('Shared AI rate throttle is waiting for the next start. No provider request was sent.',
                    policy_wait=True,retry_after=row.next_at-now)
            interval=3600.0/settings['ai_rate_per_hour']
            if not row:
                row=Admission(id='global');session.add(row)
            row.next_at=now+interval;row.admitted=(row.admitted or 0)+1
            row.updated=now;row.model=str(model)[:100]
            session.commit()
            if work is not None:work['admitted']=True
            return {'mode':'rate','admitted':True,'next_at':row.next_at}


def status(session):
    settings=config(session);row=session.get(Admission,'global')
    return {'mode':settings['ai_control_mode'],'rate_per_hour':settings['ai_rate_per_hour'],
        'next_at':row.next_at if row and settings['ai_control_mode'] in ('rate','rate_and_daily') else None,
        'admitted':row.admitted if row else 0}
