"""Read-only automatic AI plan status for one server (#922) and the opted-in fleet (#936).

The Security tab's scan policy can opt a server into automatic AI response
proposals for new detections (``incidents.auto_plan_tick``). This module explains,
for one server, whether that tick can currently enqueue a plan, how many open
incidents still wait for their one automatic attempt, whether a plan job already
occupies the server, the latest automatic attempt, and which pacing applies:

- ``legacy`` mode keeps the fixed fleet-wide allowance of ten plan jobs per
  rolling hour (counted exactly like the tick and the manual plan route);
- every other mode has no plan-specific hourly cap. The shared AI start gates
  (rate throttle, daily cap, provider backoff) pace the provider call instead.

The ``awaiting`` count uses ``incidents.awaiting_auto_plan``, the predicate the tick
uses, and excludes YARA incidents in SQL with ``incidents.automatic_candidate_sql``
(the SQL form of the tick's ``automatic_candidate``), so YARA rows can never fill the
bounded window and hide owed incidents. It reads at most ``AWAITING_LIMIT + 1`` rows
and reports truncation instead of loading an unbounded history.

The payload contains fixed codes, counts, job states and timestamps only: no
incident evidence, paths, plan text, job output or key material. It sends no
provider request and writes nothing; admission, schema and response
authorization are unchanged and plans remain manual-only.
"""
import time

from sqlalchemy import literal, select
from sqlalchemy.orm import aliased

from . import ai_control_status, ai_policy, host_lifecycle, incidents
from .db import Host, Job, Setting, config

AWAITING_LIMIT = 500
FLEET_LIMIT = 100
POLICY_PREFIX = 'security-policy:'
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
    query = (select(incidents.Incident.updated)
             .where(incidents.Incident.host_id == host_id, *incidents.awaiting_auto_plan(),
                    incidents.automatic_candidate_sql())
             .order_by(incidents.Incident.updated, incidents.Incident.id)
             .limit(AWAITING_LIMIT + 1))
    rows = list(session.scalars(query))
    truncated = len(rows) > AWAITING_LIMIT
    rows = rows[:AWAITING_LIMIT]
    return len(rows), truncated, (float(rows[0]) if rows else None)


def _job(state, created):
    return None if state is None else {'state': state, 'created': float(created)}


def _plan_jobs(session, host_ids):
    """Project at most one active job and one automatic attempt per listed host."""
    if not host_ids:
        return {}
    active = aliased(Job)
    latest = aliased(Job)
    active_id = (
        select(Job.id).where(Job.host_id == Host.id, Job.action.in_(PLAN_ACTIONS),
                             Job.state.in_(('queued', 'running')))
        .order_by(Job.created, Job.id.desc()).limit(1).correlate(Host).scalar_subquery()
    )
    latest_id = (
        select(Job.id).where(Job.host_id == Host.id, Job.action == 'security-plan',
                             Job.payload['automatic'].as_boolean() == True)  # noqa: E712
        .order_by(Job.created.desc(), Job.id.desc()).limit(1).correlate(Host).scalar_subquery()
    )
    rows = session.execute(
        select(Host.id, active.state, active.created, latest.state, latest.created)
        .select_from(Host)
        .outerjoin(active, active.id == active_id)
        .outerjoin(latest, latest.id == latest_id)
        .where(Host.id.in_(host_ids))
    )
    return {
        host_id: (_job(active_state, active_created), _job(latest_state, latest_created))
        for host_id, active_state, active_created, latest_state, latest_created in rows
    }


def _pacing(session, cfg, now):
    if cfg['ai_control_mode'] == 'legacy':
        limit = ai_control_status.AUTO_PLAN_HOURLY_LIMIT
        used, blocked, next_at = ai_control_status._window(
            session, Job.created, (Job.action.in_(PLAN_ACTIONS),), limit, now)
        return {'mode': 'legacy', 'limit': limit, 'used': used, 'remaining': max(limit - used, 0),
                'next_at': next_at if blocked else None}
    return {'mode': cfg['ai_control_mode'], 'limit': None, 'used': None, 'remaining': None, 'next_at': None}


def _host(session, host_id, policy, cfg, jobs):
    awaiting, truncated, oldest = _awaiting(session, host_id)
    active, latest = jobs.get(host_id, (None, None))
    return {
        'enabled': bool(policy.get('auto_ai_plan')),
        'state': _state(session, host_id, policy, cfg),
        'awaiting': awaiting,
        'awaiting_truncated': truncated,
        'oldest_awaiting_since': oldest,
        'active_plan': active,
        'latest_automatic': latest,
    }


def status(session, host_id, now=None):
    """Return this server's automatic AI plan status in the caller's session. Read-only."""
    now = time.time() if now is None else now
    cfg = config(session)
    row = session.get(Setting, 'security-policy:' + host_id)
    policy = row.value if row and isinstance(row.value, dict) else {}
    jobs = _plan_jobs(session, [host_id])
    return {'generated_at': now, **_host(session, host_id, policy, cfg, jobs), 'pacing': _pacing(session, cfg, now)}


def fleet(session, now=None):
    """Return automatic AI plan status for every opted-in, non-deleted server (#936). Read-only.

    Rows reuse ``status`` field by field, ordered by server name then ID, and are
    bounded to ``FLEET_LIMIT``. Totals count only the listed rows; ``truncated`` says
    more opted-in servers exist. Pacing is fleet-wide and reported once.
    """
    now = time.time() if now is None else now
    cfg = config(session)
    hosts = session.execute(
        select(Host.id, Host.name, Setting.value)
        .join(Setting, Setting.key == literal(POLICY_PREFIX) + Host.id)
        .where(Host.deleted_at == 0)
        .order_by(Host.name, Host.id)).all()
    opted = [(host_id, name, value) for host_id, name, value in hosts
             if isinstance(value, dict) and value.get('auto_ai_plan')]
    listed = opted[:FLEET_LIMIT]
    jobs = _plan_jobs(session, [host_id for host_id, _, _ in listed])
    items = [{'host_id': host_id, 'host_name': name, **_host(session, host_id, value, cfg, jobs)}
             for host_id, name, value in listed]
    return {
        'generated_at': now,
        'items': items,
        'truncated': len(opted) > FLEET_LIMIT,
        'totals': {
            'servers': len(items),
            'ready': sum(item['state'] == 'ready' for item in items),
            'awaiting': sum(item['awaiting'] for item in items),
            'awaiting_truncated': any(item['awaiting_truncated'] for item in items),
            'active_plans': sum(item['active_plan'] is not None for item in items),
        },
        'pacing': _pacing(session, cfg, now),
    }
