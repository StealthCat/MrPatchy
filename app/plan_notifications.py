"""In-app notifications for AI response plans awaiting administrator review.

A leader-only reconciler compares reviewable draft plans with the active
``ai-plans`` notification events.  It only publishes notification revisions:
it never approves, rejects, supersedes or expires a plan, and reading or
dismissing the notification grants nothing.  The AI's own severity and text
are never copied, so model significance stays advisory.
"""
import time

from sqlalchemy import and_, or_, select

from . import host_lifecycle, incidents, notifications
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
    'stale': 'This AI response plan can no longer be approved because its startup incident was closed or '
             'newer inspection evidence arrived; request a new plan if still needed.',
}
# The startup approval route only accepts plans for incidents in these states.
STARTUP_REVIEWABLE = ('open', 'acknowledged')


# Security plans are reviewed on the Security tab; startup-change plans are
# reviewed with their persistence incidents on the File integrity tab.
REVIEW_TAB = {'security-plan': 'security', 'startup-plan': 'integrity'}


# Leader-local keyset cursors for bounded scans whose rows can stay unchanged
# between passes (still-current startup events, stale-evidence startup drafts).
# Each pass reads one page after the saved key and wraps to the start after a
# short page, so every row is revisited within ceil(rows / BATCH) passes and
# unchanged rows can never hold the page.  A restart begins a new rotation.
_cursors = {}


def _rotate(session, name, query, keys, key_of):
    """Return one ``BATCH`` page of ``query`` ordered by ``keys`` after the saved cursor.

    ``key_of(row)`` returns the row's ``keys`` values as a 2-tuple.
    """
    after = _cursors.get(name)
    if after is not None:
        (first, second), (first_after, second_after) = keys, after
        query = query.where(or_(first > first_after, and_(first == first_after, second > second_after)))
    rows = session.execute(query.order_by(*keys).limit(BATCH)).all()
    _cursors[name] = tuple(key_of(rows[-1])) if len(rows) >= BATCH else None
    return rows


def _link(kind, host_id):
    return '#servers/' + host_id + '/' + REVIEW_TAB[kind]


def _active_current():
    """Active plan-review events whose current revision is still active."""
    event, revision = notifications.NotificationEvent, notifications.NotificationRevision
    return (select(event)
            .join(revision, (revision.event_id == event.id) & (revision.revision == event.revision))
            .where(event.source == SOURCE, event.subject_type == SUBJECT_TYPE,
                   revision.lifecycle == 'active'))


def _startup_digest(session, row):
    """Digest the startup approval route would compare, or ``None`` if it would refuse."""
    from . import startup_ai
    try:
        return incidents.digest(startup_ai.evidence(session, row))
    except ValueError:
        return None


def _startup_current(session, plan, cache):
    """True when the startup approval route's evidence check would still accept ``plan``.

    Mirrors ``approve_startup_plan``: the incident must be open or acknowledged
    and the plan's evidence digest must match current evidence (incident
    revision and the latest inspection).  Digests are cached per pass.
    """
    if plan.incident_id not in cache:
        cache[plan.incident_id] = _startup_digest(session, session.get(PersistenceIncident, plan.incident_id))
    current = cache[plan.incident_id]
    return current is not None and current == plan.evidence_digest


def _pending(session, now, cache):
    """Return ``{plan_id: (kind, host_id)}`` for bounded reviewable drafts.

    Drafts that already have an active notification are excluded in SQL, so
    each pass's bounded page only holds drafts that still need publishing and
    unchanged drafts can never starve newer ones.  Startup drafts that approval
    would refuse are skipped after the page is read, so that scan rotates and
    a page of stale-evidence drafts cannot hold it.
    """
    active_hosts = host_lifecycle.active_ids()
    notified = _active_current().with_only_columns(notifications.NotificationEvent.subject_id)
    found = {}
    for kind, model in (('security-plan', Incident), ('startup-plan', PersistenceIncident)):
        query = (select(Plan.id, model.host_id, Plan.created)
                 .join(model, model.id == Plan.incident_id)
                 .where(Plan.state == 'draft', Plan.created > now - REVIEW_WINDOW,
                        model.host_id.in_(active_hosts), Plan.id.not_in(notified)))
        if model is PersistenceIncident:
            query = query.where(model.state.in_(STARTUP_REVIEWABLE))
            rows = _rotate(session, 'pending-startup', query, (Plan.created, Plan.id), lambda row: (row[2], row[0]))
        else:
            rows = session.execute(query.order_by(Plan.created, Plan.id).limit(BATCH)).all()
        for plan_id, host_id, *_ in rows:
            if kind == 'startup-plan' and not _startup_current(session, session.get(Plan, plan_id), cache):
                continue  # Approval would already refuse it; never announce it.
            found.setdefault(plan_id, (kind, host_id))
    return found


def _active_events(session, now):
    """Return bounded active events whose plan may no longer be reviewable.

    Events for drafts that are still reviewable on an active server are
    excluded in SQL; every returned row is then resolved (or, in the rare
    host-mismatch case, rechecked), so unchanged events cannot hold the page.
    """
    event = notifications.NotificationEvent
    closed_startup = select(PersistenceIncident.id).where(PersistenceIncident.state.not_in(STARTUP_REVIEWABLE))
    reviewable = select(Plan.id).where(Plan.state == 'draft', Plan.created > now - REVIEW_WINDOW,
                                       Plan.incident_id.not_in(closed_startup))
    return session.execute(
        _active_current()
        .where(~(event.subject_id.in_(reviewable) & event.host_id.in_(host_lifecycle.active_ids())))
        .order_by(event.updated, event.id)
        .limit(BATCH)).scalars().all()


def _live_startup_events(session, now):
    """Bounded active startup-plan events that SQL still considers reviewable.

    Their evidence digest is rechecked each pass so a newer inspection or
    incident revision that makes approval refuse the plan resolves the event.
    Still-current events keep their sort key, so the scan rotates instead of
    rereading the same first page.
    """
    event = notifications.NotificationEvent
    reviewable = (select(Plan.id).join(PersistenceIncident, PersistenceIncident.id == Plan.incident_id)
                  .where(Plan.state == 'draft', Plan.created > now - REVIEW_WINDOW,
                         PersistenceIncident.state.in_(STARTUP_REVIEWABLE)))
    query = (_active_current()
             .where(event.kind == 'startup-plan', event.subject_id.in_(reviewable),
                    event.host_id.in_(host_lifecycle.active_ids())))
    rows = _rotate(session, 'live-startup', query, (event.updated, event.id),
                   lambda row: (row[0].updated, row[0].id))
    return [row[0] for row in rows]


def _resolution(session, plan_id, now, cache):
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
            startup = session.get(PersistenceIncident, plan.incident_id)
            if startup is not None and not _startup_current(session, plan, cache):
                return 'stale'  # The startup approval route would refuse it.
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
    cache = {}
    pending = _pending(session, now, cache)
    published = resolved = 0
    for plan_id, (kind, host_id) in pending.items():
        _, created = notifications.publish(
            session, source=SOURCE, kind=kind, subject_type=SUBJECT_TYPE,
            subject_id=plan_id, subject_revision=plan_id, severity='medium',
            reason=PENDING_REASON[kind], deep_link=_link(kind, host_id), host_id=host_id,
            minimum_role='admin', now=now)
        published += created
    seen = set()
    for event in [*_active_events(session, now), *_live_startup_events(session, now)]:
        if event.subject_id in pending or event.id in seen:
            continue
        seen.add(event.id)
        outcome = _resolution(session, event.subject_id, now, cache)
        if outcome is None:
            continue
        _, created = notifications.publish(
            session, source=SOURCE, kind=event.kind, subject_type=SUBJECT_TYPE,
            subject_id=event.subject_id, subject_revision=event.subject_id + ':' + outcome,
            severity='info', reason=RESOLVED_REASON[outcome],
            deep_link=_link(event.kind, event.host_id) if event.host_id else '', host_id=event.host_id,
            minimum_role='admin', lifecycle='resolved', now=now)
        resolved += created
    return published, resolved


def tick(now=None):
    with Session() as session:
        sync(session, now)
        session.commit()
