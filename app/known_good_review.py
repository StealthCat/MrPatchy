"""Administrator review completion for a revoked fleet known-good candidate.

Revoking a candidate (by an administrator or an AI contradiction) marks every
linked assessment as requiring review. This module records that an
administrator completed that review for one exact revocation.

A review is bound to the candidate fingerprint, version, revocation time and
the number of linked assessments the administrator reviewed. It is current only
while all four still match; a later revocation or an additional linked
assessment makes review required again. Recording a review never reactivates
the candidate, never approves a behavior, never rewrites an assessment and
authorizes no response. It also resolves any active fleet known-good bell
event for the candidate with fixed text.
"""

import time

from sqlalchemy import Double, Integer, String, func, select
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, audit

NOTIFICATION_SOURCE = 'ai-known-good'
NOTIFICATION_SUBJECT_TYPE = 'known-good-candidate'
RESOLVED_REASON = ('An administrator recorded review of the assessments linked to this '
                   'revoked fleet known-good candidate. The candidate stays revoked and '
                   'the review approves nothing and authorizes no response.')


class Review(Base):
    """Latest administrator review of one revoked candidate's linked assessments."""
    __tablename__ = 'ai_known_good_reviews'
    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[int] = mapped_column(Integer)
    revoked_at: Mapped[float] = mapped_column(Double)
    linked_assessments: Mapped[int] = mapped_column(Integer)
    reviewed_at: Mapped[float] = mapped_column(Double, default=time.time)
    reviewed_by: Mapped[str] = mapped_column(String(64))
    note: Mapped[str] = mapped_column(String(1000))


def _linked(s, fingerprint):
    from .known_good import Observation
    return s.scalar(select(func.count(Observation.assessment_id)).where(
        Observation.fingerprint == fingerprint)) or 0


def matches(review, entry, linked):
    """True when ``review`` covers the current revocation and linked set of ``entry``."""
    return bool(review and entry is not None and not entry.active and
                review.fingerprint == entry.fingerprint and
                review.version == entry.version and
                review.revoked_at == entry.revoked_at and
                review.linked_assessments >= linked)


def current(s, entry, linked):
    """Return the matching review fields for an inactive entry, or ``None``."""
    if entry is None or entry.active:
        return None
    review = s.get(Review, entry.fingerprint)
    if not matches(review, entry, linked):
        return None
    return {'review_completed_at': review.reviewed_at,
            'review_completed_by': review.reviewed_by,
            'review_note': review.note,
            'reviewed_linked_assessments': review.linked_assessments}


def pending_reuse(s):
    """Count retained reuse assessments on revoked candidates without a current review.

    One aggregate statement; no evidence or snapshots are loaded.
    """
    from sqlalchemy import and_, or_
    from .ai_assessments import Assessment
    from .known_good import Entry, Observation
    linked = select(Observation.fingerprint.label('fingerprint'),
                    func.count().label('linked')).group_by(Observation.fingerprint).subquery()
    reused = select(Observation.fingerprint.label('fingerprint'),
                    func.count().label('reused')).join(
        Assessment, Assessment.id == Observation.assessment_id).where(
        Assessment.source == 'known_good').group_by(Observation.fingerprint).subquery()
    reviewed = and_(Review.fingerprint.is_not(None), Review.version == Entry.version,
                    Review.revoked_at == Entry.revoked_at,
                    Review.linked_assessments >= linked.c.linked)
    statement = select(func.coalesce(func.sum(reused.c.reused), 0)).select_from(
        reused.join(Entry, Entry.fingerprint == reused.c.fingerprint).join(
            linked, linked.c.fingerprint == reused.c.fingerprint).outerjoin(
            Review, Review.fingerprint == reused.c.fingerprint)).where(
        Entry.active.is_(False), or_(Review.fingerprint.is_(None), ~reviewed))
    return int(s.scalar(statement) or 0)


def _resolve_notifications(s, fingerprint, now):
    from . import notifications
    events = s.scalars(select(notifications.NotificationEvent).where(
        notifications.NotificationEvent.source == NOTIFICATION_SOURCE,
        notifications.NotificationEvent.subject_type == NOTIFICATION_SUBJECT_TYPE,
        notifications.NotificationEvent.subject_id == fingerprint,
        notifications.NotificationEvent.host_id == ''))
    resolved = 0
    for event in list(events):
        latest = s.scalar(select(notifications.NotificationRevision).where(
            notifications.NotificationRevision.event_id == event.id,
            notifications.NotificationRevision.revision == event.revision))
        if latest is None or latest.lifecycle != 'active':
            continue
        _, created = notifications.publish(
            s, source=event.source, kind=event.kind, subject_type=event.subject_type,
            subject_id=event.subject_id, subject_revision=latest.subject_revision,
            severity=latest.severity, reason=RESOLVED_REASON, deep_link=latest.deep_link,
            host_id='', minimum_role=event.minimum_role, lifecycle='resolved', now=now)
        resolved += int(created)
    return resolved


def record(s, fingerprint, version, revoked_at, actor, note, now=None):
    """Record review completion for the exact current revocation of a candidate.

    Raises ``LookupError`` for an unknown candidate and ``ValueError`` when the
    candidate is active, its version or revocation changed, or the current
    revocation is already reviewed. The caller owns the transaction.
    """
    from .known_good import Entry
    entry = s.scalar(select(Entry).where(Entry.fingerprint == fingerprint).with_for_update())
    if entry is None:
        raise LookupError('Known-good candidate not found')
    if entry.active:
        raise ValueError('Known-good candidate is active; only a revoked candidate needs review')
    if entry.version != version or entry.revoked_at != revoked_at:
        raise ValueError('Known-good candidate revocation changed; reopen the assessment before recording review')
    linked = _linked(s, fingerprint)
    review = s.get(Review, fingerprint)
    if matches(review, entry, linked):
        raise ValueError('Review of this revocation is already recorded')
    timestamp = time.time() if now is None else now
    if review is None:
        review = Review(fingerprint=fingerprint)
        s.add(review)
    review.version = entry.version
    review.revoked_at = entry.revoked_at
    review.linked_assessments = linked
    review.reviewed_at = timestamp
    review.reviewed_by = actor
    review.note = note
    audit(s, 'review revoked known-good candidate',
          f'{actor} {fingerprint} linked={linked} note={note}')
    resolved = _resolve_notifications(s, fingerprint, timestamp)
    return {'fingerprint': fingerprint, 'version': entry.version,
            'revoked_at': entry.revoked_at, 'review_required': False,
            'linked_assessments': linked, 'review_completed_at': timestamp,
            'review_completed_by': actor, 'review_note': note,
            'resolved_notifications': resolved}
