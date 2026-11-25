"""Durable fleet-wide provider Retry-After and transient failure backoff."""
import hashlib
import hmac
import random
import time

from sqlalchemy import String, Double, Integer, Text, LargeBinary, and_, case, cast, or_, select, update
from sqlalchemy.orm import Mapped, mapped_column

from .coordination import Lock
from .db import Base, Session


MAX_PROVIDER_DELAY=86400  # a longer provider Retry-After is capped and flagged for administrator review
FAILURE_WINDOW=3600  # consecutive transient failures reset after this idle period
CAPPED_REASON='Provider Retry-After exceeds 24 hours and was capped; an administrator may clear it after review.'
RETRY_AFTER_REASON='Provider Retry-After floor is active.'
TRANSIENT_REASON='Transient provider or transport failure; bounded exponential backoff is active.'
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


def _active_deadline(session, now):
    return session.scalar(select(ProviderBackoff.blocked_until).where(
        ProviderBackoff.id == 'global', ProviderBackoff.blocked_until > now,
    ))


def admit(now=None):
    """Fail before budget/rate admission while a shared provider floor is active."""
    from .ai import AIError

    now = time.time() if now is None else now
    with Session() as session:
        deadline = _active_deadline(session, now)
        if deadline is not None:
            error = AIError('Shared provider backoff is waiting for retry eligibility. No provider request was sent.',
                            policy_wait=True, retry_after=deadline - now)
            error.provider_wait_until = deadline
            raise error


def waiting(session, now):
    """Read-only: the instant the shared provider floor lifts, or 0."""
    return _active_deadline(session, now) or 0


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
            deadline=now+delay
            previous_deadline=row.blocked_until or 0
            # Keep the reason for the deadline that still holds. A capped
            # request sharing that deadline takes precedence for review.
            if deadline>previous_deadline or (deadline==previous_deadline and capped):
                row.reason=CAPPED_REASON if capped else RETRY_AFTER_REASON if provider>0 else TRANSIENT_REASON
            row.blocked_until=max(previous_deadline,deadline)
            # Failure timestamps are sampled before lock acquisition. Preserve the
            # newest one so an in-flight success cannot clear its backoff floor.
            row.updated=max(row.updated or 0,now)
            session.commit()
            return max(0,row.blocked_until-now)


def succeeded(request_started=None,now=None):
    """Clear escalation unless a parallel request recorded a newer failure."""
    now=time.time() if now is None else now
    clearable = (
        ProviderBackoff.id == 'global',
        or_(ProviderBackoff.failures != 0, ProviderBackoff.blocked_until != 0, ProviderBackoff.reason != ''),
    )
    if request_started is not None:
        clearable += (ProviderBackoff.updated <= request_started,)
    # Healthy responses need one bounded read. Close the read transaction before
    # taking the distributed lock so the reset sees any newly committed failure.
    with Session() as session:
        if session.scalar(select(ProviderBackoff.id).where(*clearable)) is None:
            return
    with Lock('ai-provider-backoff'):
        with Session() as session:
            changed = session.execute(ProviderBackoff.__table__.update().where(*clearable).values(
                blocked_until=0, failures=0, updated=now, reason='',
            ))
            if changed.rowcount:
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

    # Keep the former exact state comparison under a case-insensitive DB
    # collation. A later retry time still belongs to the local retry gate.
    provider_only = and_(
        cast(TriageRetry.state, LargeBinary) == b'deferred',
        TriageRetry.next_at > now,
        TriageRetry.next_at <= TriageRetry.provider_until,
    )
    # MySQL applies assignments in order. Read the old floor before zeroing it.
    statement = (
        update(TriageRetry).where(TriageRetry.provider_until > now)
        .ordered_values(
            (TriageRetry.next_at, case((provider_only, now), else_=TriageRetry.next_at)),
            (TriageRetry.provider_until, 0),
        )
        .execution_options(synchronize_session=False)
    )
    with Lock('ai-triage'), Session() as session:
        changed = session.execute(statement).rowcount
        session.commit()
    return changed > 0


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
