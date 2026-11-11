"""Durable fleet-wide provider Retry-After and transient failure backoff."""
import hashlib
import hmac
import random
import time

from sqlalchemy import String, Double, Integer, Text, or_, select
from sqlalchemy.orm import Mapped, mapped_column

from .coordination import Lock
from .db import Base, Session


MAX_PROVIDER_DELAY=86400  # a longer provider Retry-After is capped and flagged for administrator review
FAILURE_WINDOW=3600  # consecutive transient failures reset after this idle period
CAPPED_REASON='Provider Retry-After exceeds 24 hours and was capped; an administrator may clear it after review.'
# In-app notification policy: a single short transient backoff is routine and
# silent. Only a capped (>24 h) floor or a sustained run of failures needs an
# administrator, so neither per-failure timing nor provider text is announced.
SUSTAINED_FAILURES=5
NOTIFICATION={'source':'ai-provider','kind':'provider-backoff','subject_type':'ai-provider','subject_id':'global'}
NOTIFICATION_TEXT={
    'capped':('high','The AI provider asked Mr Patchy to wait more than 24 hours. The wait was capped at 24 hours, '
        'and new paid AI work across the fleet is deferred until it lifts. Deferred work stays queued. Review the '
        'provider account, then clear the reviewed backoff in AI Settings if appropriate.'),
    'sustained':('medium','The AI provider has failed transiently several times in a row, so a shared backoff is '
        'deferring new paid AI work across the fleet. Deferred work stays queued and resumes automatically after a '
        'successful provider response. Review the provider status and AI Settings.'),
}


class ReviewConflict(Exception):
    """The reviewed provider-backoff state is no longer the active state."""


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
            error=AIError('Shared provider backoff is waiting for retry eligibility. No provider request was sent.',
                policy_wait=True,retry_after=row.blocked_until-now)
            error.provider_wait_until=row.blocked_until
            raise error


def waiting(session,now):
    """Read-only: the instant the shared provider floor lifts, or 0."""
    row=session.get(ProviderBackoff,'global')
    return row.blocked_until if row and row.blocked_until>now else 0


def failed(error,now=None):
    """Record a sanitized transient failure and return its shared delay in seconds."""
    if not getattr(error,'transient',False):return 0
    now=time.time() if now is None else now
    with Lock('ai-provider-backoff'):
        with Session() as session:
            row=session.get(ProviderBackoff,'global')
            if not row:
                row=ProviderBackoff(id='global');session.add(row)
            if not row.updated or now-row.updated>FAILURE_WINDOW:row.failures=0
            row.failures=(row.failures or 0)+1
            provider=float(getattr(error,'provider_retry_after',getattr(error,'retry_after',0)) or 0)
            capped=provider>MAX_PROVIDER_DELAY
            provider=min(provider,MAX_PROVIDER_DELAY)
            error.provider_retry_after=provider
            delay=provider if provider>0 else random.uniform(30,min(1800,60*2**(row.failures-1)))
            row.blocked_until=max(row.blocked_until or 0,now+delay)
            row.updated=now
            row.reason=(CAPPED_REASON if capped else
                'Provider Retry-After floor is active.' if provider>0 else
                'Transient provider or transport failure; bounded exponential backoff is active.')
            session.commit()
            return max(0,row.blocked_until-now)


def succeeded(request_started=None,now=None):
    """Clear escalation unless a parallel request recorded a newer failure."""
    now=time.time() if now is None else now
    clearable = select(ProviderBackoff).where(
        ProviderBackoff.id == 'global',
        or_(ProviderBackoff.failures != 0, ProviderBackoff.blocked_until != 0, ProviderBackoff.reason != ''),
    )
    if request_started is not None:
        clearable = clearable.where(ProviderBackoff.updated <= request_started)
    # Healthy responses need one bounded read. Close the read transaction before
    # taking the distributed lock so the reset sees any newly committed failure.
    with Session() as session:
        if session.scalar(clearable.with_only_columns(ProviderBackoff.id)) is None:
            return
    with Lock('ai-provider-backoff'):
        with Session() as session:
            row=session.scalar(clearable)
            if row:
                row.blocked_until=0;row.failures=0;row.updated=now;row.reason=''
                session.commit()


def _revision(row):
    if not row:return ''
    state='|'.join((float(row.blocked_until or 0).hex(),str(row.failures or 0),
        float(row.updated or 0).hex(),row.reason or ''))
    return hashlib.sha256(state.encode()).hexdigest()


def clear(now=None,expected_revision=None):
    """Reset a reviewed shared floor; reject changed/expired administrator reviews."""
    with Lock('ai-provider-backoff'):
        with Session() as session:
            row=session.get(ProviderBackoff,'global')
            now=time.time() if now is None else now
            active=bool(row and row.blocked_until>now)
            if expected_revision is not None and (not active or
                    not hmac.compare_digest(expected_revision,_revision(row))):
                raise ReviewConflict('Provider backoff changed or expired; refresh AI Settings before clearing it.')
            if row:
                row.blocked_until=0;row.failures=0;row.updated=now;row.reason=''
                session.commit()
    # Already-deferred investigations keep their own provider-only wait. Revoke
    # only that wait; attempt limits, claims and other admission gates remain.
    return revoke_item_waits(now) or active


def revoke_item_waits(now):
    from .ai_retry import TriageRetry
    from sqlalchemy import select
    with Lock('ai-triage'),Session() as session:
        rows=session.scalars(select(TriageRetry).where(TriageRetry.provider_until>now)).all()
        for retry in rows:
            # A later next_at belongs to the local retry gate, not the provider
            # floor. Compare before clearing the saved provider deadline.
            if retry.state=='deferred' and now<retry.next_at<=retry.provider_until:
                retry.next_at=now
            retry.provider_until=0
        session.commit()
        return bool(rows)


def status(session,now=None):
    now=time.time() if now is None else now;row=session.get(ProviderBackoff,'global')
    blocked=bool(row and row.blocked_until>now)
    return {'blocked':blocked,'next_at':row.blocked_until if blocked else None,
        'failures':row.failures if row else 0,'reason':row.reason if blocked else '',
        'updated_at':row.updated if blocked else None,'revision':_revision(row) if blocked else ''}


def notification_state(row,now):
    """Classify the shared floor for administrator attention: capped, sustained or ''."""
    if not row:return ''
    if row.blocked_until>now and row.reason==CAPPED_REASON:return 'capped'
    if (row.failures or 0)>=SUSTAINED_FAILURES and now-(row.updated or 0)<=FAILURE_WINDOW:return 'sustained'
    return ''


def publish_notification(session,cfg,now=None):
    """Publish or resolve the admin-only provider-backoff event in the caller's transaction.

    The payload is fixed text keyed by the attention state, so further failures
    within one episode add no revision; an escalation or a later episode does.
    """
    from . import notifications
    now=time.time() if now is None else now
    state=notification_state(session.get(ProviderBackoff,'global'),now) if cfg.get('ai_enabled') else ''
    if state:
        severity,reason=NOTIFICATION_TEXT[state]
        notifications.publish(session,**NOTIFICATION,subject_revision=state,severity=severity,reason=reason,
            deep_link='#settings/ai',minimum_role='admin',now=now)
        return
    Event=notifications.NotificationEvent
    exists=session.scalar(select(Event.id).where(Event.source==NOTIFICATION['source'],Event.kind==NOTIFICATION['kind'],
        Event.subject_type==NOTIFICATION['subject_type'],Event.subject_id==NOTIFICATION['subject_id']))
    if exists:
        notifications.publish(session,**NOTIFICATION,subject_revision='resolved',severity='info',
            reason='The shared AI provider backoff no longer needs administrator attention.',
            deep_link='#settings/ai',minimum_role='admin',lifecycle='resolved',now=now)
