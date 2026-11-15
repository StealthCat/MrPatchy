"""In-app coverage notification while a server's AI integration is paused.

A per-server pause stops new provider calls for that server's triage, update
scoring and security response proposals. ``ai_policy.save`` calls ``sync``
inside the transaction that stores the policy, so a rejected or rolled-back
save never announces anything. Pausing publishes one admin-only, host-scoped
event; resuming or deleting the server resolves it. Reaffirming a pause or
changing only the investigation capacity adds no revision while the event is
already active.

The payload is fixed text plus identifiers. It excludes the administrator's
free-text reason, server names and any evidence. The notification is advisory
coverage information: it changes no AI or response state, acknowledges nothing
and authorizes no action.
"""

from sqlalchemy import select

from . import notifications

SOURCE = 'ai-pause'
KIND = 'server-paused'
SUBJECT_TYPE = 'server'
SEVERITY = 'low'
PAUSED = ('AI integration is paused for this server. Mr Patchy sends no new AI '
          'triage, update-scoring or response-proposal requests for it until an '
          'administrator resumes AI. Non-AI inventory, patching, scanning and '
          'monitoring continue. This notice is advisory and authorizes nothing.')
ENDED = {
    'resumed': ('AI integration was resumed for this server. Global AI settings, '
                'data sharing, quotas and eligibility still apply.'),
    'server-deleted': 'The server was deleted while its AI integration was paused.',
}


def _link(host_id):
    # The per-server AI integration panel is rendered on the Security tab.
    return '#servers/' + host_id + '/security'


def _active(session, host_id):
    event = notifications.NotificationEvent
    revision = notifications.NotificationRevision
    lifecycle = session.scalar(
        select(revision.lifecycle)
        .join(event, (revision.event_id == event.id) & (revision.revision == event.revision))
        .where(event.id == notifications._event_id(SOURCE, KIND, SUBJECT_TYPE, host_id, host_id)))
    return lifecycle == 'active'


def _resolve(session, host_id, cause, policy_revision, now):
    if not _active(session, host_id):
        return False
    notifications.publish(
        session, source=SOURCE, kind=KIND, subject_type=SUBJECT_TYPE,
        subject_id=host_id, host_id=host_id,
        subject_revision=(cause + ':' + policy_revision)[:128],
        severity='info', reason=ENDED[cause], deep_link=_link(host_id),
        minimum_role='admin', lifecycle='resolved', now=now)
    return True


def sync(session, host_id, paused, policy_revision, now=None):
    """Publish or resolve the pause event to match a just-saved policy.

    The caller owns the transaction. Returns ``True`` when a revision was added.
    """
    if not paused:
        return _resolve(session, host_id, 'resumed', policy_revision, now)
    if _active(session, host_id):
        return False
    _, created = notifications.publish(
        session, source=SOURCE, kind=KIND, subject_type=SUBJECT_TYPE,
        subject_id=host_id, host_id=host_id,
        subject_revision=('paused:' + policy_revision)[:128],
        severity=SEVERITY, reason=PAUSED, deep_link=_link(host_id),
        minimum_role='admin', now=now)
    return created


def resolve_host_notification(session, host_id, now=None):
    """Resolve a still-active pause event when its server is deleted."""
    return _resolve(session, host_id, 'server-deleted', 'deleted', now)
