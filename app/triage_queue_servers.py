"""Read-only per-server process-triage queue breakdown for administrators (#975).

``/api/investigation-status`` reports fleet-wide totals. This module answers the
next question an administrator has when the queue is not draining: which servers
hold the backlog, and why each one is waiting.

Every unapproved ``pending``/``error`` behavior on an active (enabled, not
deleted) server is placed in exactly one class, using the predicates
``ai_runs.status()`` and ``ai_claims.acquire`` already use:

- ``active``: an unexpired claim holds it (an investigation is running);
- ``eligible``: retry-eligible under the saved model/key and unclaimed;
- ``blocked``: needs configuration review or an explicit retry;
- ``retry_wait``: waiting out a finite retry or provider wait.

A running claim takes precedence, so an investigation on its last attempt is
``active`` here although the fleet ``blocked`` total counts it until it ends.

``active_leases`` is the admission count: every unexpired claim on the server,
whether or not its behavior is still pending. ``at_investigation_limit``
compares that count, because that is what ``ai_claims.acquire`` enforces.

The payload carries server ID and name, counts, limits and timestamps only,
never evidence, paths, command lines, analysis, provider text or key material.
It sends no provider request, writes nothing, and changes no admission, claim,
pause, budget, schema or response authorization.
"""
import time

from sqlalchemy import and_, case, func, select

from . import ai_claims, ai_policy, ai_retry, ai_runs
from .db import Behavior, Host, Setting

MAX_SERVERS = 50
LIMITATIONS = (
    ('"Eligible" means retry-eligible and unclaimed. The shared AI start gates (rate throttle, daily cap, '
     'provider backoff, legacy hourly allowance), worker capacity and the per-server investigation limit still '
     'decide when an investigation starts, and nothing starts on a paused server until it is resumed.'),
    ('"Active leases" counts every unexpired claim on the server, as admission does. It can exceed "active" '
     'while an investigation that was approved or resolved in the meantime is still finishing.'),
    'A server with an invalid saved AI policy stays paused until an administrator repairs it.',
    ('The breakdown is a point-in-time read. The AI worker or a collector running at the same time can change '
     'the counts immediately afterwards.'),
)


def _counted(condition):
    return func.count(case((condition, 1)))


def status(session, now=None, limit=MAX_SERVERS):
    """Return the servers holding pending process investigations, largest backlog first."""
    now = time.time() if now is None else now
    limit = max(1, min(int(limit), MAX_SERVERS))
    retry, claim = ai_retry.TriageRetry, ai_claims.Claim
    signature = ai_retry.configuration(session)
    ready = ai_retry.eligible(signature, now)
    unclaimed = claim.subject.is_(None)
    blocked, wake = ai_retry.queue_waits(signature)
    # One ordered CASE places each row exactly once. `ready` is NULL (not false)
    # for a never-retried row inside its first hour, so negating it would drop
    # that row; falling through to the default keeps it in `retry_wait`.
    placed = case((~unclaimed, 'active'), (ready, 'eligible'), (blocked, 'blocked'), else_='retry_wait')
    pending = func.count().label('pending')
    scope = ai_runs._pending_behavior_scope()
    # Count grouped servers before LIMIT, then join details only for the selected page.
    backlog = (select(
        func.count().over().label('servers_with_backlog'),
        Behavior.host_id, pending,
        *(_counted(placed == name).label(name) for name in ('active', 'eligible', 'blocked', 'retry_wait')),
        func.min(Behavior.first_seen).label('oldest'),
        func.min(case((and_(placed == 'retry_wait', wake > now), wake))).label('next_retry'),
        func.max(case((Behavior.host_id.in_(ai_policy.paused_ids()), 1), else_=0)).label('paused'),
    ).select_from(Behavior).outerjoin(retry, retry.subject == Behavior.id)
        .outerjoin(claim, and_(claim.subject == Behavior.id, claim.expires > now)).where(*scope)
        .group_by(Behavior.host_id).order_by(pending.desc(), Behavior.host_id).limit(limit)
        .subquery('backlog'))
    # Count occupancy on each displayed host, including leases for subjects that
    # left the pending scope while the investigation was active.
    active_leases = (select(func.count()).select_from(claim)
        .where(claim.host_id == backlog.c.host_id, claim.expires > now)
        # MySQL can choose a full scan for each correlated lookup on a small
        # lease table. Use the existing host index to keep the lookup host-scoped.
        .with_hint(claim, 'FORCE INDEX FOR JOIN (ix_ai_triage_claims_host_id)', dialect_name='mysql')
        .correlate(backlog).scalar_subquery())
    rows = session.execute(
        select(backlog, Host.name, Setting.key.label('policy_key'), Setting.value,
               active_leases.label('active_leases'))
        .select_from(backlog)
        .outerjoin(Host, Host.id == backlog.c.host_id)
        .outerjoin(Setting, Setting.key == ai_policy.PREFIX + backlog.c.host_id)
        .order_by(backlog.c.pending.desc(), backlog.c.host_id)
    ).all()
    total = rows[0].servers_with_backlog if rows else 0
    servers = []
    for row in rows:
        # Distinguish missing policy from a saved null or non-object policy.
        policy = row.value if row.policy_key == ai_policy.PREFIX + row.host_id else {}
        allowed = ai_policy.investigation_limit_value(policy)
        servers.append({
            'host_id': row.host_id, 'name': row.name or '', 'pending': row.pending, 'active': row.active,
            'eligible': row.eligible, 'blocked': row.blocked, 'retry_wait': row.retry_wait, 'paused': bool(row.paused),
            'active_leases': row.active_leases, 'investigation_limit': allowed,
            'at_investigation_limit': row.active_leases >= allowed,
            'oldest_pending_observation_at': row.oldest, 'next_retry_at': row.next_retry,
        })
    return {'generated_at': now, 'servers': servers, 'servers_with_backlog': total,
            'truncated': total > len(servers), 'max_servers': limit, 'limitations': list(LIMITATIONS)}
