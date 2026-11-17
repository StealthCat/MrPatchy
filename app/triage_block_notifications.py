"""Administrator notification while process triage is blocked by non-transient failures.

A non-transient failure leaves each affected investigation ``blocked`` with no
automatic retry until the model/key changes or an administrator retries it. The
cause may be the provider configuration (a rejected key, unavailable quota or an
unsupported model) or a local refusal such as evidence over the 64 KB sharing
limit, so the text stays cause-neutral and points to each investigation's own
retry reason (#1007). This producer surfaces that state in the notification
center. It reads state only: it never retries, unblocks, reserves spend or
changes authorization, and it adds no SMTP/webhook alert.
"""
import hashlib

from sqlalchemy import and_, func, or_, select

from . import ai_policy, ai_retry, host_lifecycle, notifications
from .db import Behavior

IDENTITY = dict(source='ai-triage', kind='configuration-blocked',
                subject_type='triage-configuration', subject_id='process-triage')
LINK = '#investigations'
MESSAGE = ('Process investigations are blocked by a non-transient failure, and no automatic retry is scheduled. '
           'Review each one on Investigations: its retry reason names the cause. A rejected key, unavailable quota '
           'or unsupported model is corrected in the AI settings, and changing the saved model or key makes those '
           'investigations eligible again. Evidence too large to share needs manual review instead; a model or key '
           'change does not help it. An administrator can also retry explicitly.')
RESOLVED = 'No process investigation remains blocked by the earlier non-transient failure.'


RETRY_LIMIT = 200
RETRY_ANALYSIS = 'Retry requested by an administrator; hourly limits still apply.'


def _blocked(signature, now):
    TR = ai_retry.TriageRetry
    return and_(Behavior.approved == False, Behavior.verdict.in_(('pending', 'error')),  # noqa: E712
                Behavior.host_id.in_(host_lifecycle.active_ids()),
                Behavior.host_id.not_in(ai_policy.paused_ids()),
                or_(TR.state == 'blocked', and_(TR.state == 'interrupted', TR.attempts >= ai_retry.MAX_ATTEMPTS)),
                ~ai_retry.eligible(signature, now))


def blocked_count(session, now, host_id=None):
    """Count pending, unpaused, active-server behaviors blocked under the current configuration.

    Uses the same blocked predicate as ``ai_runs.status()``: rows blocked under an
    earlier configuration are eligible again and are not counted. ``host_id``
    narrows the count to one server (#946); omitted, it is fleet-wide.
    """
    signature = ai_retry.configuration(session)
    query = select(func.count()).select_from(Behavior).join(
        ai_retry.TriageRetry, ai_retry.TriageRetry.subject == Behavior.id).where(_blocked(signature, now))
    if host_id is not None:
        query = query.where(Behavior.host_id == host_id)
    return session.scalar(query), signature


def retry_candidates(session, now, limit=RETRY_LIMIT, ids=None, host_id=None):
    """Return ``(id, host_id)`` pairs an administrator retry may re-queue now (#934).

    The notification predicate, minus rows with a live triage claim or an active
    provider Retry-After, which single-item retry also refuses. ``host_id``
    restricts candidates to one server (#946). Read-only.
    """
    from .ai_claims import Claim
    signature = ai_retry.configuration(session)
    TR = ai_retry.TriageRetry
    running = select(Claim.subject).where(Claim.subject == Behavior.id, Claim.expires > now).exists()
    query = select(Behavior.id, Behavior.host_id).join(TR, TR.subject == Behavior.id).where(
        _blocked(signature, now), TR.provider_until <= now, ~running).order_by(Behavior.id).limit(limit)
    if ids is not None:
        query = query.where(Behavior.id.in_(ids))
    if host_id is not None:
        query = query.where(Behavior.host_id == host_id)
    return list(session.execute(query))


def retry(session, ids, now):
    """Re-queue the given candidates exactly like single-item retry. Returns the count.

    The caller holds the ``ai-triage`` lock and the rows' ``queue`` activity
    locks and has discarded any pre-lock read transaction. Each row is re-checked
    against the current predicate, so a concurrent change is never overwritten.
    No provider request is sent: the scheduler still applies enablement, pause,
    lifecycle, data sharing and shared admission.
    """
    current = [row_id for row_id, _ in retry_candidates(session, now, limit=len(ids), ids=ids)] if ids else []
    retried = 0
    for row in session.scalars(select(Behavior).where(Behavior.id.in_(current))):
        ai_retry.manual(session, row, now)
        row.attempted = 0
        row.verdict = 'pending'
        row.analysis = RETRY_ANALYSIS
        retried += 1
    return retried


def publish(session, cfg, now):
    """Publish or resolve the admin event in the caller's transaction. Returns True while blocked."""
    count, signature = blocked_count(session, now) if cfg.get('ai_enabled') else (0, '')
    if count:
        # Re-hash so the retained revision never carries the retry signature itself.
        digest = hashlib.sha256(('triage-block-notification-v1\0' + signature).encode()).hexdigest()[:32]
        notifications.publish(session, **IDENTITY, subject_revision='blocked:' + digest, severity='medium',
                              reason=MESSAGE, deep_link=LINK, minimum_role='admin', now=now)
        return True
    event = session.scalar(select(notifications.NotificationEvent).where(
        *(getattr(notifications.NotificationEvent, key) == value for key, value in IDENTITY.items())))
    if event is not None:
        current = session.get(notifications.NotificationRevision, (event.id, event.revision))
        if current is None or current.lifecycle != 'resolved':
            notifications.publish(session, **IDENTITY, subject_revision='resolved', severity='info',
                                  reason=RESOLVED, deep_link=LINK, minimum_role='admin',
                                  lifecycle='resolved', now=now)
    return False
