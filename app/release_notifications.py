"""In-app notifications for distribution-upgrade release plans awaiting a GO/no-go decision.

A leader-only reconciler compares reviewable release plans with the active
``release-plans`` notification events.  It only publishes notification
revisions: it never approves, declines, regenerates or expires a plan, never
queues a job, and reading or dismissing the notification grants nothing.  The
GO route keeps its own digest, blocker, expiry and pending-job checks.

Payloads are fixed text.  AI review text, configuration content, package names
and file paths stay on the server's Maintenance page.
"""
import time

from sqlalchemy import select

from . import host_lifecycle, notifications, releases
from .db import Host, Session
from .plan_notifications import _rotate


SOURCE = 'release-plans'
KIND = 'release-plan'
SUBJECT_TYPE = 'release-plan'
BATCH = 200
# Plans expire 24 hours after planning starts; a generous lookback bounds the
# pending scan without missing plans whose AI review took unusually long.
LOOKBACK = 8 * 86400
PENDING_REASON = ('A distribution-upgrade release plan is ready for an administrator GO/no-go decision. '
                  'Review its package changes and configuration diffs before it expires; nothing runs without GO.')
RESOLVED_REASON = {
    'approved': 'An administrator recorded GO for this release plan; follow its progress on the Maintenance page.',
    'declined': 'An administrator declined this release plan.',
    'expired': 'This release plan expired before a decision; prepare a new plan if the upgrade is still needed.',
    'regenerating': 'This release plan is being regenerated or its review did not complete; no decision is pending.',
    'blocked': 'This release plan now has blockers and cannot receive GO until they are resolved.',
    'unavailable': 'This release plan is no longer reviewable because it or its server is unavailable.',
}
UNDECIDED = ('ready', 'planning', 'blocked', 'declined')


def _link(host_id):
    return '#servers/' + host_id + '/maintenance'


def _active_current():
    """Active release-plan events whose current revision is still active."""
    event, revision = notifications.NotificationEvent, notifications.NotificationRevision
    return (select(event, revision.subject_revision)
            .join(revision, (revision.event_id == event.id) & (revision.revision == event.revision))
            .where(event.source == SOURCE, event.subject_type == SUBJECT_TYPE,
                   revision.lifecycle == 'active'))


def _plan_state(session, row, now):
    """Return ``(outcome, digest)``: outcome is ``None`` while GO is still possible."""
    if row is None:
        return 'unavailable', ''
    if not host_lifecycle.active(session.get(Host, row.host_id)):
        return 'unavailable', row.digest
    if row.state == 'ready':
        try:
            plan = releases.body(row)
        except Exception:  # Unreadable sealed content cannot be approved either.
            return 'unavailable', row.digest
        if plan.get('blockers'):
            return 'blocked', row.digest
        if not row.digest or float(plan.get('expires') or 0) <= now:
            return 'expired', row.digest
        return None, row.digest
    if row.state == 'planning':
        return 'regenerating', row.digest
    if row.state in ('blocked', 'declined'):
        return row.state, row.digest
    return 'approved', row.digest


def _publish_pending(session, row, now):
    _, created = notifications.publish(
        session, source=SOURCE, kind=KIND, subject_type=SUBJECT_TYPE, subject_id=row.id,
        subject_revision=row.digest, severity='medium', reason=PENDING_REASON,
        deep_link=_link(row.host_id), host_id=row.host_id, minimum_role='admin', now=now)
    return created


def sync(session, now=None):
    """Publish/resolve release-plan decision notifications. The caller commits.

    Returns ``(published, resolved)`` counts of new revisions.
    """
    now = time.time() if now is None else now
    Plan, event = releases.ReleasePlan, notifications.NotificationEvent
    notified = _active_current().with_only_columns(event.subject_id)
    published = resolved = 0
    # Newest first: plans without an active event that are ready on an active server.
    pending = session.scalars(
        select(Plan).where(Plan.state == 'ready', Plan.created > now - LOOKBACK,
                           Plan.host_id.in_(host_lifecycle.active_ids()), Plan.id.not_in(notified))
        .order_by(Plan.created.desc(), Plan.id).limit(BATCH)).all()
    announced = set()
    for row in pending:
        outcome, _ = _plan_state(session, row, now)
        if outcome is None:
            published += _publish_pending(session, row, now)
            announced.add(row.id)
    # Rotate through active events so still-pending ones cannot hold the page.
    rows = _rotate(session, 'release-active', _active_current(), (event.updated, event.id),
                   lambda found: (found[0].updated, found[0].id))
    for current, revision in rows:
        if current.subject_id in announced:
            continue
        row = session.get(Plan, current.subject_id)
        outcome, digest = _plan_state(session, row, now)
        if outcome is None:
            if digest != revision:
                published += _publish_pending(session, row, now)  # Regenerated plan: resurface.
            continue
        _, created = notifications.publish(
            session, source=SOURCE, kind=KIND, subject_type=SUBJECT_TYPE, subject_id=current.subject_id,
            subject_revision=(digest or current.subject_id) + ':' + outcome, severity='info',
            reason=RESOLVED_REASON[outcome], deep_link=_link(current.host_id) if current.host_id else '',
            host_id=current.host_id, minimum_role='admin', lifecycle='resolved', now=now)
        resolved += created
    return published, resolved


def tick(now=None):
    with Session() as session:
        sync(session, now)
        session.commit()
