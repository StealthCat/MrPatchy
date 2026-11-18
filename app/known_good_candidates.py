"""Read-only fleet list of known-good safe candidates.

Administrators reviewing the exact-match cache need to find a candidate without
already knowing an assessment that links to it. This module pages durable
candidate rows and adds bounded per-page link counts. It returns provenance
metadata only: never the canonical contract, saved result, snapshot,
observation JSON or evidence. Listing a candidate grants no approval and
authorizes no response.
"""
from __future__ import annotations

from sqlalchemy import func, select

from .db import Host
from . import host_lifecycle
from .known_good import Entry, Observation

PAGE_LIMIT = 50
STATES = ('active', 'revoked', 'all')


def page(s, state='active', offset=0, limit=20):
    """Return one newest-first page of candidates filtered by ``state``.

    Ordering is ``created`` descending with a fingerprint tie-break so pages
    stay stable. ``linked`` counts every retained observation bound to the
    candidate (origin included); ``reused`` counts the exact-match reuse
    assessments among them.
    """
    from .ai_assessments import Assessment

    if state not in STATES:
        raise ValueError('Invalid known-good candidate state')
    query = select(Entry.fingerprint, Entry.version, Entry.created,
        Entry.classification_source, Entry.model, Entry.assessment_id,
        Entry.source_host_id, Entry.active, Entry.revoked_at, Entry.revoked_by,
        Entry.revoked_reason)
    if state != 'all':
        query = query.where(Entry.active.is_(state == 'active'))
    rows = s.execute(query.order_by(Entry.created.desc(), Entry.fingerprint)
        .offset(offset).limit(limit + 1)).all()
    visible = rows[:limit]
    fingerprints = [row.fingerprint for row in visible]
    linked, reused, subjects, hosts = {}, {}, {}, {}
    if visible:
        linked = dict(s.execute(select(Observation.fingerprint,
            func.count(Observation.assessment_id)).where(
            Observation.fingerprint.in_(fingerprints)).group_by(Observation.fingerprint)).all())
        reused = dict(s.execute(select(Observation.fingerprint,
            func.count(Observation.assessment_id)).join(
            Assessment, Assessment.id == Observation.assessment_id).where(
            Observation.fingerprint.in_(fingerprints), Assessment.source == 'known_good',
        ).group_by(Observation.fingerprint)).all())
        subjects = dict(s.execute(select(Assessment.id, Assessment.subject).where(
            Assessment.id.in_([row.assessment_id for row in visible]))).all())
        host_ids = {row.source_host_id for row in visible}
        hosts = {host.id: host for host in s.scalars(select(Host).where(Host.id.in_(host_ids)))}
    items = []
    for row in visible:
        host = hosts.get(row.source_host_id)
        active = bool(row.active)
        items.append({
            'fingerprint': row.fingerprint, 'version': row.version, 'created': row.created,
            'classification_source': row.classification_source, 'model': row.model,
            'origin_assessment_id': row.assessment_id,
            # Empty when the origin assessment is no longer retained.
            'origin_subject': subjects.get(row.assessment_id, ''),
            'origin': {'host_id': row.source_host_id, 'host_name': host.name if host else '',
                'host_active': host_lifecycle.active(host)},
            'active': active,
            'revoked_at': 0 if active else row.revoked_at,
            'revoked_by': '' if active else row.revoked_by,
            'revoked_reason': '' if active else row.revoked_reason,
            'linked': linked.get(row.fingerprint, 0),
            'reused': reused.get(row.fingerprint, 0),
        })
    return {'state': state, 'offset': offset, 'items': items, 'more': len(rows) > limit}
