"""Release a server's failed automatic AI plan attempts for retry (#1036).

Automatic AI plans make one attempt per incident scan (``incidents.awaiting_auto_plan``).
When that attempt fails, for example on a rejected key, unsupported model or invalid
structured result, the incident is never tried again automatically. This module lets an
administrator count those incidents for one server and *release* their failed
attempts.

Releasing only marks the failed ``security-plan`` job payload with
``retry_released``. It enqueues nothing and sends no provider request. A released
attempt no longer counts as attempted, so the existing ``auto_plan_tick`` plans the
incident again through its normal path: the policy opt-in, AI pause, response holds,
server lifecycle, one plan per server, the legacy hourly allowance and the shared AI
start gates all still apply. A new failure blocks the incident again until another
release.

Counted incidents are open, non-YARA, have no non-superseded plan, and have at least
one unreleased failed automatic attempt for their current scan and no other
unreleased attempt for it (queued, running or complete). Attempts the worker skipped
because the incident evidence changed are not counted: the next scan is owed
separately. Job output, incident evidence and provider text are never returned.
"""
import time

from sqlalchemy import and_, func, select

from . import host_lifecycle, incidents
from .db import Host, Job, audit

BATCH_LIMIT = 200
RELEASED = 'retry_released'
# The worker's fixed refusal when the incident's evidence changed before the call.
STALE_OUTPUT = 'Automatic incident evidence changed; no AI call sent'


def _attempts():
    """Unreleased automatic attempts for each incident's current scan."""
    return and_(Job.action == 'security-plan', Job.host_id == incidents.Incident.host_id,
                Job.payload['incident_id'].as_string() == incidents.Incident.id,
                Job.payload['scan_id'].as_string() == incidents.Incident.scan_id,
                incidents.unreleased_attempt())


def _candidates(host_id):
    failed = select(Job.id).where(
        _attempts(), Job.state == 'failed', Job.payload['automatic'].as_boolean() == True,  # noqa: E712
        func.coalesce(Job.output, '').notlike(STALE_OUTPUT + '%')).exists()
    other = select(Job.id).where(_attempts(), Job.state != 'failed').exists()
    planned = select(incidents.Plan.id).where(incidents.Plan.incident_id == incidents.Incident.id,
                                              incidents.Plan.state != 'superseded').exists()
    return (select(incidents.Incident.id)
            .where(incidents.Incident.host_id == host_id, incidents.Incident.state == 'open',
                   incidents.automatic_candidate_sql(), ~planned, failed, ~other)
            .order_by(incidents.Incident.updated, incidents.Incident.id))


def failed_count(session, host_id):
    """Count this server's incidents whose automatic attempt failed. Read-only."""
    return session.scalar(select(func.count()).select_from(_candidates(host_id).subquery())) or 0


def release(session, host_id, username, now=None):
    """Release up to ``BATCH_LIMIT`` incidents' failed attempts. Caller holds ``security-plan-queue``.

    Returns ``{'released', 'remaining'}``. An inactive (disabled or deleted) server
    releases nothing. Writes one audit row when anything was released.
    """
    now = time.time() if now is None else now
    if session.scalar(host_lifecycle.active_ids().where(Host.id == host_id)) is None:
        return {'released': 0, 'remaining': failed_count(session, host_id)}
    ids = list(session.scalars(_candidates(host_id).limit(BATCH_LIMIT)))
    if ids:
        rows = {row.id: row for row in session.scalars(
            select(incidents.Incident).where(incidents.Incident.id.in_(ids)))}
        jobs = session.scalars(select(Job).where(
            Job.action == 'security-plan', Job.host_id == host_id, Job.state == 'failed',
            Job.payload['incident_id'].as_string().in_(ids)))
        for job in jobs:
            payload = dict(job.payload or {})
            row = rows.get(payload.get('incident_id'))
            if row is None or payload.get('scan_id') != row.scan_id or payload.get(RELEASED) is True:
                continue
            if payload.get('automatic') is not True:
                continue
            payload.update({RELEASED: True, 'retry_released_at': now, 'retry_released_by': username})
            job.payload = payload
        audit(session, 'automatic AI plan retry released',
              f'{host_id} {username} incidents={len(ids)}')
        session.flush()
    return {'released': len(ids), 'remaining': failed_count(session, host_id)}
