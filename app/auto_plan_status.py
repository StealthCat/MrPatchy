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

from sqlalchemy import JSON, and_, func, literal, or_, select, type_coerce, union_all
from sqlalchemy.orm import aliased

from . import ai_control_status, ai_policy, host_lifecycle, incidents
from .db import Host, Job, Setting, config

AWAITING_LIMIT = 500
FLEET_LIMIT = 100
FLEET_POLICY_PAGE_SIZE = 512
POLICY_PREFIX = 'security-policy:'
PLAN_ACTIONS = ('security-plan', 'startup-plan')
STATES = ('off', 'ai_disabled', 'not_configured', 'paused', 'held', 'inactive', 'ready')


def _readiness(session, host_ids, cfg):
    """Classify the listed, opted-in servers without per-server database reads."""
    if not host_ids:
        return {}
    if not cfg['ai_enabled']:
        return dict.fromkeys(host_ids, 'ai_disabled')
    if not cfg['ai_model'] or session.scalar(select(Setting.key).where(Setting.key == 'openai_key')) is None:
        return dict.fromkeys(host_ids, 'not_configured')

    keys = {host_id: ai_policy.PREFIX + host_id for host_id in host_ids}
    policies = dict(session.execute(
        select(Setting.key, Setting.value).where(Setting.key.in_(keys.values()))
    ).all())
    paused = {
        host_id for host_id, key in keys.items()
        if ai_policy.stored_paused(policies.get(key), present=key in policies)
    }
    from .operations import quarantined_hosts
    held = quarantined_hosts(session, [host_id for host_id in host_ids if host_id not in paused])
    unchecked = [host_id for host_id in host_ids if host_id not in paused and host_id not in held]
    active = set(session.scalars(host_lifecycle.active_ids().where(Host.id.in_(unchecked)))) if unchecked else set()
    states = dict.fromkeys(host_ids, 'inactive')
    states.update(dict.fromkeys(active, 'ready'))
    states.update(dict.fromkeys(held, 'held'))
    states.update(dict.fromkeys(paused, 'paused'))
    return states


def _awaiting_candidates(host_id):
    incident = incidents.Incident
    return (
        select(incident.updated)
        .where(incident.host_id == host_id, *incidents.awaiting_auto_plan(),
               incidents.automatic_candidate_sql())
        .order_by(incident.updated, incident.id)
        .limit(AWAITING_LIMIT + 1)
    )


def _awaiting_query(host_ids, *, outer_references):
    # Cap the rows fed to each aggregate and include one extra match to detect truncation.
    if not outer_references:
        # MySQL before 8.0.14 cannot correlate a derived table. Each union
        # arm keeps the same limit without referring to an outer query.
        arms = []
        for host_id in host_ids:
            bounded = _awaiting_candidates(host_id).subquery()
            arms.append(select(literal(host_id), func.count(), func.min(bounded.c.updated)))
        return union_all(*arms) if len(arms) > 1 else arms[0]

    bounded = _awaiting_candidates(Host.id).correlate(Host).subquery()
    # Aggregate count and oldest in one bounded scan, returning both in a scalar.
    summary = select(func.json_array(func.count(), func.min(bounded.c.updated))).scalar_subquery()
    return select(Host.id, type_coerce(summary, JSON)).where(Host.id.in_(host_ids))


def _awaiting(session, host_ids):
    """Read capped counts and oldest matching timestamps in one statement."""
    if not host_ids:
        return {}
    dialect = session.connection().dialect
    outer_references = dialect.name != 'mysql' or dialect.server_version_info >= (8, 0, 14)
    rows = session.execute(_awaiting_query(host_ids, outer_references=outer_references))
    values = ((host_id, *summary) for host_id, summary in rows) if outer_references else rows
    return {
        host_id: (min(found, AWAITING_LIMIT), found > AWAITING_LIMIT,
                  float(first) if first is not None else None)
        for host_id, found, first in values
    }


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


def _host(host_id, state, jobs, summaries):
    awaiting, truncated, oldest = summaries.get(host_id, (0, False, None))
    active, latest = jobs.get(host_id, (None, None))
    return {
        'enabled': state != 'off',
        'state': state,
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
    row = session.get(Setting, POLICY_PREFIX + host_id)
    policy = row.value if row and isinstance(row.value, dict) else {}
    jobs = _plan_jobs(session, [host_id])
    state = _readiness(session, [host_id], cfg)[host_id] if policy.get('auto_ai_plan') else 'off'
    summaries = _awaiting(session, [host_id])
    return {'generated_at': now, **_host(host_id, state, jobs, summaries), 'pacing': _pacing(session, cfg, now)}


def _fleet_opted_in_hosts(session):
    """Read through the first extra opted-in server to determine truncation."""
    query = (
        select(Host.id, Host.name, Setting.value)
        .join(Setting, Setting.key == literal(POLICY_PREFIX) + Host.id)
        .where(Host.deleted_at == 0)
        .order_by(Host.name, Host.id)
        .limit(FLEET_POLICY_PAGE_SIZE)
    )
    page = query
    opted = []
    while True:
        rows = session.execute(page).all()
        for host_id, name, policy in rows:
            if isinstance(policy, dict) and policy.get('auto_ai_plan'):
                opted.append((host_id, name))
                if len(opted) > FLEET_LIMIT:
                    return opted
        if len(rows) < FLEET_POLICY_PAGE_SIZE:
            return opted
        host_id, name, _ = rows[-1]
        page = query.where(
            Host.name >= name,
            or_(Host.name > name, and_(Host.name == name, Host.id > host_id)),
        )


def fleet(session, now=None):
    """Return automatic AI plan status for every opted-in, non-deleted server (#936). Read-only.

    Rows reuse ``status`` field by field, ordered by server name then ID, and are
    bounded to ``FLEET_LIMIT``. Totals count only the listed rows; ``truncated`` says
    more opted-in servers exist. Pacing is fleet-wide and reported once.
    """
    now = time.time() if now is None else now
    cfg = config(session)
    opted = _fleet_opted_in_hosts(session)
    listed = opted[:FLEET_LIMIT]
    host_ids = [host_id for host_id, _ in listed]
    jobs = _plan_jobs(session, host_ids)
    states = _readiness(session, host_ids, cfg)
    summaries = _awaiting(session, host_ids)
    items = [{'host_id': host_id, 'host_name': name, **_host(host_id, states[host_id], jobs, summaries)}
             for host_id, name in listed]
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
