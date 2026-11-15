"""Read-only automatic AI plan status for one server (#922).

The Security tab's scan policy can opt a server into automatic AI response
proposals for new detections (``incidents.auto_plan_tick``). This module explains,
for one server, whether that tick can currently enqueue a plan, how many open
incidents still wait for their one automatic attempt, whether a plan job already
occupies the server, the latest automatic attempt, and which pacing applies:

- ``legacy`` mode keeps the fixed fleet-wide allowance of ten plan jobs per
  rolling hour (counted exactly like the tick and the manual plan route);
- every other mode has no plan-specific hourly cap. The shared AI start gates
  (rate throttle, daily cap, provider backoff) pace the provider call instead.

The ``awaiting`` count uses ``incidents.awaiting_auto_plan`` and
``incidents.automatic_candidate``, the same predicates the tick uses. It reads at
most ``AWAITING_LIMIT + 1`` rows and reports truncation instead of loading an
unbounded history.

The payload contains fixed codes, counts, job states and timestamps only: no
incident evidence, paths, plan text, job output or key material. It sends no
provider request and writes nothing; admission, schema and response
authorization are unchanged and plans remain manual-only.
"""
import time

from sqlalchemy import select
from sqlalchemy.orm import load_only

from . import ai_control_status, ai_policy, host_lifecycle, incidents
from .db import Host, Job, Setting, config

AWAITING_LIMIT = 500
PLAN_ACTIONS = ('security-plan', 'startup-plan')
STATES = ('off', 'ai_disabled', 'not_configured', 'paused', 'held', 'inactive', 'ready')


def _state(session, host_id, policy, cfg):
    if not policy.get('auto_ai_plan'):
        return 'off'
    if not cfg['ai_enabled']:
        return 'ai_disabled'
    if not cfg['ai_model'] or session.get(Setting, 'openai_key') is None:
        return 'not_configured'
    if ai_policy.status(session, host_id)['paused']:
        return 'paused'
    from .operations import host_quarantined
    if host_quarantined(session, host_id):
        return 'held'
    if session.scalar(host_lifecycle.active_ids().where(Host.id == host_id)) is None:
        return 'inactive'
    return 'ready'


def _awaiting(session, host_id):
    query = (select(incidents.Incident)
             .options(load_only(incidents.Incident.id, incidents.Incident.updated, incidents.Incident.evidence))
             .where(incidents.Incident.host_id == host_id, *incidents.awaiting_auto_plan())
             .order_by(incidents.Incident.updated, incidents.Incident.id)
             .limit(AWAITING_LIMIT + 1))
    rows = list(session.scalars(query))
    truncated = len(rows) > AWAITING_LIMIT
    rows = [row for row in rows[:AWAITING_LIMIT] if incidents.automatic_candidate(row)]
    return len(rows), truncated, (float(rows[0].updated) if rows else None)


def _job(row):
    return None if row is None else {'state': row[0], 'created': float(row[1])}


def status(session, host_id, now=None):
    """Return this server's automatic AI plan status in the caller's session. Read-only."""
    now = time.time() if now is None else now
    cfg = config(session)
    row = session.get(Setting, 'security-policy:' + host_id)
    policy = row.value if row and isinstance(row.value, dict) else {}
    awaiting, truncated, oldest = _awaiting(session, host_id)
    active = session.execute(
        select(Job.state, Job.created).where(Job.host_id == host_id, Job.action.in_(PLAN_ACTIONS),
                                             Job.state.in_(('queued', 'running')))
        .order_by(Job.created).limit(1)).first()
    latest = session.execute(
        select(Job.state, Job.created).where(Job.host_id == host_id, Job.action == 'security-plan',
                                             Job.payload['automatic'].as_boolean() == True)  # noqa: E712
        .order_by(Job.created.desc(), Job.id.desc()).limit(1)).first()
    if cfg['ai_control_mode'] == 'legacy':
        limit = ai_control_status.AUTO_PLAN_HOURLY_LIMIT
        used, blocked, next_at = ai_control_status._window(
            session, Job.created, (Job.action.in_(PLAN_ACTIONS),), limit, now)
        pacing = {'mode': 'legacy', 'limit': limit, 'used': used, 'remaining': max(limit - used, 0),
                  'next_at': next_at if blocked else None}
    else:
        pacing = {'mode': cfg['ai_control_mode'], 'limit': None, 'used': None, 'remaining': None, 'next_at': None}
    return {
        'generated_at': now,
        'enabled': bool(policy.get('auto_ai_plan')),
        'state': _state(session, host_id, policy, cfg),
        'awaiting': awaiting,
        'awaiting_truncated': truncated,
        'oldest_awaiting_since': oldest,
        'active_plan': _job(active),
        'latest_automatic': _job(latest),
        'pacing': pacing,
    }
