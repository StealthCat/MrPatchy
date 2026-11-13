"""Administrator notification while process triage is blocked on AI configuration.

A non-transient provider failure (for example a rejected key, unavailable quota or
an unsupported model) leaves each affected investigation ``blocked`` with no
automatic retry until the model/key changes or an administrator retries it. This
producer surfaces that state in the notification center. It reads state only: it
never retries, unblocks, reserves spend or changes authorization, and it adds no
SMTP/webhook alert.
"""
import hashlib

from sqlalchemy import and_, func, or_, select

from . import ai_policy, ai_retry, host_lifecycle, notifications
from .db import Behavior

IDENTITY = dict(source='ai-triage', kind='configuration-blocked',
                subject_type='triage-configuration', subject_id='process-triage')
LINK = '#investigations'
MESSAGE = ('Process investigations are blocked by a non-transient AI provider failure under the current model '
           'and API key, for example a rejected key, unavailable quota or an unsupported model. No automatic '
           'retry is scheduled. Review the failure on Investigations, then correct the AI settings or explicitly '
           'retry. Changing the saved model or key makes blocked investigations eligible again. New behavior is '
           'not being triaged until then.')
RESOLVED = 'No process investigation remains blocked by the AI configuration that caused the earlier failure.'


def blocked_count(session, now):
    """Count pending, unpaused, active-server behaviors blocked under the current configuration.

    Uses the same blocked predicate as ``ai_runs.status()``: rows blocked under an
    earlier configuration are eligible again and are not counted.
    """
    TR = ai_retry.TriageRetry
    signature = ai_retry.configuration(session)
    blocked = and_(or_(TR.state == 'blocked', and_(TR.state == 'interrupted', TR.attempts >= ai_retry.MAX_ATTEMPTS)),
                   ~ai_retry.eligible(signature, now))
    return session.scalar(select(func.count()).select_from(Behavior).join(TR, TR.subject == Behavior.id).where(
        Behavior.approved == False, Behavior.verdict.in_(('pending', 'error')),  # noqa: E712
        Behavior.host_id.in_(host_lifecycle.active_ids()),
        Behavior.host_id.not_in(ai_policy.paused_ids()), blocked)), signature


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
