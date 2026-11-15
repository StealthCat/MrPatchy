"""Read-only update-importance scoring queue summary for administrators (#917).

Process triage reports its queue in ``/api/investigation-status``. This module
gives update scoring the same kind of summary: how many current pending updates
are scored, running, eligible now, deferred by shared admission, waiting out the
one-hour retry after an error, or blocked under the saved model/key (the #815
predicate), plus the next finite eligibility and the oldest unscored wait.

Each current candidate ``Package`` on an active, unpaused server is classified
once, using the same skip rules as ``update_scores.run_one``. A package can have
more than one score row matching its installed/candidate pair, for example after
an inventory context change. In that case the most advanced class wins, in this
order: complete, running, blocked, deferred, retry wait, eligible.

The summary returns fixed counts and timestamps only, never package names,
evidence, explanations, provider text or key material. It sends no provider
request and changes no schema, admission, reservation, retry or authorization.
"""
import time

from sqlalchemy import and_, case, func, literal, select

from . import ai_policy, ai_retry, host_lifecycle
from .db import Package, Setting
from .update_scores import UpdateScore

RETRY_SECONDS = 3600
CLASSES = ('eligible', 'retry_wait', 'deferred', 'blocked', 'running', 'complete')
LIMITATIONS = (
    ('Counts cover current pending updates on active, unpaused servers. Shared AI start gates (rate throttle, '
    'daily cap, provider backoff, legacy hourly allowance) and per-server pause still decide when a batch '
    'starts, so "eligible now" is not a promise that scoring starts immediately.'),
    ('A score row is matched to its update by server, package, installed and candidate version. The scheduler '
    'also binds scoring context such as the OS release, so an update whose context changed may be rescored '
    'even when it is counted here as complete.'),
)


def _signature(session, cfg):
    key = session.get(Setting, 'openai_key')
    if not cfg.get('ai_model') or key is None:
        return None
    return ai_retry.configuration_signature(cfg['ai_model'], key.value)


def _scheduler_state(session, cfg):
    if not cfg.get('ai_enabled'):
        return 'ai_disabled'
    if not cfg.get('ai_updates_enabled'):
        return 'scoring_disabled'
    if not cfg.get('ai_model') or session.get(Setting, 'openai_key') is None:
        return 'not_configured'
    return 'enabled'


def status(session, cfg, now=None):
    """Return the scoring queue summary in the caller's session. Read-only."""
    now = time.time() if now is None else now
    signature = _signature(session, cfg)
    recent = UpdateScore.attempted > now - RETRY_SECONDS
    blocked = (and_(UpdateScore.state == 'blocked', UpdateScore.configuration == signature)
               if signature is not None else literal(False))
    # Mirrors the skip order in update_scores.run_one; a missing row is eligible.
    rank = case(
        (UpdateScore.id.is_(None), 0),
        (UpdateScore.state == 'complete', 5),
        (and_(UpdateScore.state == 'running', recent), 4),
        (blocked, 3),
        (and_(UpdateScore.state == 'deferred', UpdateScore.next_at > now), 2),
        (and_(UpdateScore.state.not_in(('deferred', 'blocked')), recent), 1),
        else_=0)
    deferred_until = case((and_(UpdateScore.state == 'deferred', UpdateScore.next_at > now), UpdateScore.next_at))
    retry_until = case((and_(UpdateScore.state.not_in(('deferred', 'blocked', 'complete', 'running')), recent),
                        UpdateScore.attempted + RETRY_SECONDS))
    current = and_(UpdateScore.host_id == Package.host_id, UpdateScore.name == Package.name,
                   UpdateScore.installed == Package.installed, UpdateScore.candidate == Package.candidate,
                   UpdateScore.state != 'superseded')
    candidates = (Package.candidate != '', Package.host_id.in_(host_lifecycle.active_ids()))
    per_package = select(Package.id.label('package_id'), func.min(Package.available_since).label('since'),
                         func.max(rank).label('rank'), func.min(deferred_until).label('deferred_until'),
                         func.min(retry_until).label('retry_until')).select_from(Package).outerjoin(
        UpdateScore, current).where(*candidates, Package.host_id.not_in(ai_policy.paused_ids())).group_by(
        Package.id).subquery()
    # Per-class wait only counts packages whose winning class is that class.
    rows = session.execute(select(
        per_package.c.rank, func.count(), func.min(per_package.c.since),
        func.min(case((per_package.c.rank == 2, per_package.c.deferred_until))),
        func.min(case((per_package.c.rank == 1, per_package.c.retry_until)))).group_by(per_package.c.rank)).all()
    counts = dict.fromkeys(CLASSES, 0)
    oldest_waiting = None
    waits = []
    for rank_value, count, since, deferred_at, retry_at in rows:
        name = CLASSES[int(rank_value or 0)]
        counts[name] += count
        if name != 'complete' and since is not None and (oldest_waiting is None or since < oldest_waiting):
            oldest_waiting = since
        waits.extend(float(value) for value in (deferred_at, retry_at) if value is not None)
    paused = session.scalar(select(func.count()).select_from(Package).where(
        *candidates, Package.host_id.in_(ai_policy.paused_ids()))) or 0
    total = sum(counts.values())
    return {
        'scheduler': _scheduler_state(session, cfg),
        'current_updates': total,
        'counts': counts,
        'unscored': total - counts['complete'],
        'paused_server_updates': paused,
        'next_eligible_at': min(waits) if waits else None,
        'oldest_waiting_since': oldest_waiting,
        'limitations': list(LIMITATIONS),
    }
