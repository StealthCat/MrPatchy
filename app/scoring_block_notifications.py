"""Administrator notification while update scoring is blocked on AI configuration.

A non-transient provider failure (for example a rejected key, unavailable quota or
an unsupported model) leaves the affected update-importance scores ``blocked``
under the current model/key signature, with no automatic retry until the saved
model or API key changes, or an administrator explicitly retries them (``retry``).
This producer surfaces that state in the notification center. ``publish`` reads state only: it never retries, unblocks, reserves spend or
changes authorization, and it adds no SMTP/webhook alert.
"""
import hashlib

from sqlalchemy import and_, func, select, update

from . import ai_policy, ai_retry, host_lifecycle, notifications
from .db import Package, Setting
from .update_scores import UpdateScore

IDENTITY = dict(source='ai-scoring', kind='configuration-blocked',
                subject_type='scoring-configuration', subject_id='update-scoring')
LINK = '#settings/ai'
MESSAGE = ('AI update-importance scoring is blocked by a non-transient AI provider failure under the current '
           'model and API key, for example a rejected key, unavailable quota or an unsupported model. No '
           'automatic retry is scheduled, so no further paid request is sent for the affected updates. Review '
           'the failure in AI activity, then correct the AI settings. Changing the saved model or key makes '
           'blocked updates eligible again; after resolving a provider-side cause such as quota, use Retry '
           'blocked scores in AI settings. Patching and package inventory are unaffected; scores are advisory.')
RESOLVED = 'No pending update score remains blocked by the AI configuration that caused the earlier failure.'
RETRY_EXPLANATION = ('Retry requested by an administrator; queued for the next scoring pass. AI pause, '
                     'shared rate and daily-cap admission still apply.')


def _blocked_query(session, cfg, columns):
    """Select current-candidate scores on active, unpaused servers blocked under the saved configuration."""
    key = session.get(Setting, 'openai_key')
    if not (cfg.get('ai_enabled') and cfg.get('ai_updates_enabled') and cfg.get('ai_model') and key):
        return None, ''
    signature = ai_retry.configuration_signature(cfg['ai_model'], key.value)
    # Only the exact installed/candidate pair still pending counts; superseded
    # evidence is rescored under a new identity and is not blocked.
    current = and_(UpdateScore.host_id == Package.host_id, UpdateScore.name == Package.name,
                   UpdateScore.installed == Package.installed, UpdateScore.candidate == Package.candidate)
    return select(*columns).select_from(UpdateScore).join(Package, current).where(
        UpdateScore.state == 'blocked', UpdateScore.configuration == signature, Package.candidate != '',
        UpdateScore.host_id.in_(host_lifecycle.active_ids()),
        UpdateScore.host_id.not_in(ai_policy.paused_ids())), signature


def blocked_count(session, cfg):
    """Count current-candidate scores on active, unpaused servers blocked under the saved configuration."""
    query, signature = _blocked_query(session, cfg, (func.count(),))
    return (session.scalar(query) or 0, signature) if query is not None else (0, '')


def retry(session, cfg):
    """Re-queue exactly the scores ``blocked_count`` reports, in the caller's transaction.

    No provider request is sent here. Re-queued scores return to the normal
    scheduler, which still applies AI/scoring enablement, pause, lifecycle,
    shared rate/daily-cap admission and reservations. Blocked scores on paused,
    disabled or deleted servers, superseded evidence and rows blocked under an
    earlier configuration are left unchanged. Returns the number re-queued.
    """
    query, signature = _blocked_query(session, cfg, (UpdateScore.id,))
    if query is None:
        return 0
    ids = list(session.scalars(query))
    retried = 0
    for start in range(0, len(ids), 400):
        # Re-check state and signature in the UPDATE so a concurrent change is never overwritten.
        retried += session.execute(update(UpdateScore).where(
            UpdateScore.id.in_(ids[start:start + 400]), UpdateScore.state == 'blocked',
            UpdateScore.configuration == signature).values(
            state='pending', configuration='', attempted=0, next_at=0,
            explanation=RETRY_EXPLANATION).execution_options(synchronize_session=False)).rowcount or 0
    return retried


def publish(session, cfg, now):
    """Publish or resolve the admin event in the caller's transaction. Returns True while blocked."""
    count, signature = blocked_count(session, cfg)
    if count:
        # Re-hash so the retained revision never carries the configuration signature itself.
        digest = hashlib.sha256(('scoring-block-notification-v1\0' + signature).encode()).hexdigest()[:32]
        notifications.publish(session, **IDENTITY, subject_revision='blocked:' + digest, severity='low',
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
