"""In-app notifications for AI response plans awaiting administrator review.

A leader-only reconciler compares reviewable draft plans with the active
``ai-plans`` notification events.  It only publishes notification revisions:
it never approves, rejects, supersedes or expires a plan, and reading or
dismissing the notification grants nothing.  The AI's own severity and text
are never copied, so model significance stays advisory.
"""
import time

from sqlalchemy import select

from . import host_lifecycle, notifications
from .db import Host, Session
from .incidents import Incident, PersistenceIncident, Plan


SOURCE = 'ai-plans'
SUBJECT_TYPE = 'response-plan'
# Matches the approval routes, which refuse drafts older than 24 hours.
REVIEW_WINDOW = 86400
BATCH = 500
PENDING_REASON = {
    'security-plan': 'An AI-proposed security incident response plan awaits administrator review. '
                     'It is advisory and runs nothing; approval only permits manual response.',
    'startup-plan': 'An AI-proposed startup-change response plan awaits administrator review. '
                    'It is advisory and runs nothing; approval only permits manual response.',
}
RESOLVED_REASON = {
    'approved': 'An administrator approved this AI response plan for manual response.',
    'superseded': 'This AI response plan was superseded by newer incident evidence or a review.',
    'expired': 'This AI response plan expired before review; request a new plan if still needed.',
    'unavailable': 'This AI response plan is no longer reviewable because its incident or server is unavailable.',
}


def _link(host_id):
    return '#servers/' + host_id + '/security'


def _pending(session, now):
    """Return ``{plan_id: (kind, host_id)}`` for bounded reviewable drafts."""
    active_hosts = host_lifecycle.active_ids()
    found = {}
    for kind, model in (('security-plan', Incident), ('startup-plan', PersistenceIncident)):
        rows = session.execute(
            select(Plan.id, model.host_id)
            .join(model, model.id == Plan.incident_id)
            .where(Plan.state == 'draft', Plan.created > now - REVIEW_WINDOW,
                   model.host_id.in_(active_hosts))
            .order_by(Plan.created, Plan.id).limit(BATCH))
        for plan_id, host_id in rows:
            found.setdefault(plan_id, (kind, host_id))
    return found


def _active_events(session):
    current = (notifications.NotificationRevision.event_id == notifications.NotificationEvent.id) & (
        notifications.NotificationRevision.revision == notifications.NotificationEvent.revision)
    return session.execute(
        select(notifications.NotificationEvent)
        .join(notifications.NotificationRevision, current)
        .where(notifications.NotificationEvent.source == SOURCE,
               notifications.NotificationEvent.subject_type == SUBJECT_TYPE,
               notifications.NotificationRevision.lifecycle == 'active')
        .order_by(notifications.NotificationEvent.updated, notifications.NotificationEvent.id)
        .limit(BATCH)).scalars().all()


def _resolution(session, plan_id, now):
    plan = session.get(Plan, plan_id)
    if plan is None:
        return 'unavailable'
    if plan.state == 'approved':
        return 'approved'
    if plan.state == 'superseded':
        return 'superseded'
    if plan.state == 'draft':
        if plan.created <= now - REVIEW_WINDOW:
            return 'expired'
        if _host_active(session, plan):
            return None  # Still reviewable but beyond this pass's bounded window.
    return 'unavailable'


def _host_active(session, plan):
    for model in (Incident, PersistenceIncident):
        incident = session.get(model, plan.incident_id)
        if incident is not None:
            return host_lifecycle.active(session.get(Host, incident.host_id))
    return False


def sync(session, now=None):
    """Publish/resolve plan-review notifications. The caller commits.

    Returns ``(published, resolved)`` counts of new revisions.
    """
    now = time.time() if now is None else now
    pending = _pending(session, now)
    published = resolved = 0
    for plan_id, (kind, host_id) in pending.items():
        _, created = notifications.publish(
            session, source=SOURCE, kind=kind, subject_type=SUBJECT_TYPE,
            subject_id=plan_id, subject_revision=plan_id, severity='medium',
            reason=PENDING_REASON[kind], deep_link=_link(host_id), host_id=host_id,
            minimum_role='admin', now=now)
        published += created
    for event in _active_events(session):
        if event.subject_id in pending:
            continue
        outcome = _resolution(session, event.subject_id, now)
        if outcome is None:
            continue
        _, created = notifications.publish(
            session, source=SOURCE, kind=event.kind, subject_type=SUBJECT_TYPE,
            subject_id=event.subject_id, subject_revision=event.subject_id + ':' + outcome,
            severity='info', reason=RESOLVED_REASON[outcome],
            deep_link=_link(event.host_id) if event.host_id else '', host_id=event.host_id,
            minimum_role='admin', lifecycle='resolved', now=now)
        resolved += created
    return published, resolved


def tick(now=None):
    with Session() as session:
        sync(session, now)
        session.commit()
