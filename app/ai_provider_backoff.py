"""Durable fleet-wide provider Retry-After and transient failure backoff."""
import random
import time

from sqlalchemy import String, Double, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from .coordination import Lock
from .db import Base, Session


class ProviderBackoff(Base):
    __tablename__='ai_provider_backoff'
    id: Mapped[str]=mapped_column(String(20),primary_key=True)
    blocked_until: Mapped[float]=mapped_column(Double,default=0,index=True)
    failures: Mapped[int]=mapped_column(Integer,default=0)
    updated: Mapped[float]=mapped_column(Double,default=0)
    reason: Mapped[str]=mapped_column(Text,default='')


def admit(now=None):
    """Fail before budget/rate admission while a shared provider floor is active."""
    from .ai import AIError
    now=time.time() if now is None else now
    with Session() as session:
        row=session.get(ProviderBackoff,'global')
        if row and row.blocked_until>now:
            raise AIError('Shared provider backoff is waiting for retry eligibility. No provider request was sent.',
                policy_wait=True,retry_after=row.blocked_until-now)


def failed(error,now=None):
    """Record a sanitized transient failure and return its shared delay in seconds."""
    if not getattr(error,'transient',False):return 0
    now=time.time() if now is None else now
    with Lock('ai-provider-backoff'):
        with Session() as session:
            row=session.get(ProviderBackoff,'global')
            if not row:
                row=ProviderBackoff(id='global');session.add(row)
            if not row.updated or now-row.updated>3600:row.failures=0
            row.failures=(row.failures or 0)+1
            provider=float(getattr(error,'retry_after',0) or 0)
            delay=provider if provider>0 else random.uniform(30,min(1800,60*2**(row.failures-1)))
            row.blocked_until=max(row.blocked_until or 0,now+delay)
            row.updated=now
            row.reason=('Provider Retry-After floor is active.' if provider>0 else
                'Transient provider or transport failure; bounded exponential backoff is active.')
            session.commit()
            return max(0,row.blocked_until-now)


def succeeded(request_started=None,now=None):
    """Clear escalation unless a parallel request recorded a newer failure."""
    now=time.time() if now is None else now
    with Lock('ai-provider-backoff'):
        with Session() as session:
            row=session.get(ProviderBackoff,'global')
            if row and (request_started is None or row.updated<=request_started):
                row.blocked_until=0;row.failures=0;row.updated=now;row.reason=''
                session.commit()


def status(session,now=None):
    now=time.time() if now is None else now;row=session.get(ProviderBackoff,'global')
    blocked=bool(row and row.blocked_until>now)
    return {'blocked':blocked,'next_at':row.blocked_until if blocked else None,
        'failures':row.failures if row else 0,'reason':row.reason if blocked else ''}
