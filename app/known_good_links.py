"""Read-only per-server linkage for one fleet known-good candidate.

Administrators reviewing a published, reused or revoked candidate need to see
which servers and retained assessments are bound to that exact fingerprint.
This module returns identifiers and timestamps only: no observation JSON,
snapshot, evidence or result content. Linkage never implies approval and never
authorizes a response.
"""
from __future__ import annotations

from sqlalchemy import func, select

from .db import Host
from . import host_lifecycle
from .known_good import Entry, Observation

PAGE_LIMIT = 50


def page(s, fingerprint, offset=0, limit=20):
    """Return one newest-first page of observations linked to ``fingerprint``.

    Raises LookupError when no durable entry exists. Roles: ``origin`` is the
    assessment that published the entry, ``reuse`` is an exact-match reuse that
    made no provider call, and ``linked`` is an independent assessment bound to
    the same canonical fingerprint.
    """
    from .ai_assessments import Assessment

    entry = s.get(Entry, fingerprint)
    if entry is None:
        raise LookupError('Known-good candidate not found')
    total = s.scalar(select(func.count(Observation.assessment_id)).where(
        Observation.fingerprint == fingerprint)) or 0
    rows = s.execute(select(Observation.assessment_id, Observation.subject,
        Observation.host_id, Observation.created, Assessment.source).outerjoin(
        Assessment, Assessment.id == Observation.assessment_id).where(
        Observation.fingerprint == fingerprint).order_by(
        Observation.created.desc(), Observation.assessment_id).offset(offset).limit(limit + 1)).all()
    visible = rows[:limit]
    host_ids = {row.host_id for row in visible} | {entry.source_host_id}
    hosts = {host.id: host for host in s.scalars(select(Host).where(Host.id.in_(host_ids)))}

    def host_fields(host_id):
        host = hosts.get(host_id)
        return {'host_id': host_id, 'host_name': host.name if host else '',
            'host_active': host_lifecycle.active(host)}

    items = []
    for row in visible:
        role = ('origin' if row.assessment_id == entry.assessment_id
            else 'reuse' if row.source == 'known_good' else 'linked')
        items.append({'assessment_id': row.assessment_id, 'subject': row.subject,
            'created': row.created, 'role': role, **host_fields(row.host_id)})
    return {'fingerprint': entry.fingerprint, 'version': entry.version,
        'active': bool(entry.active), 'revoked_at': entry.revoked_at if not entry.active else 0,
        'origin_assessment_id': entry.assessment_id,
        'origin': host_fields(entry.source_host_id),
        'total': total, 'offset': offset, 'items': items, 'more': len(rows) > limit}
