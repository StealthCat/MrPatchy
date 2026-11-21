"""Read-only update-importance scoring queue summary for administrators (#917).

Process triage reports its queue in ``/api/investigation-status``. This module
gives update scoring the same kind of summary: how many current pending updates
are scored, running, eligible now, deferred by shared admission, waiting out the
one-hour retry after an error, or blocked under the saved model/key (the #815
predicate), plus the next finite eligibility and the oldest unscored wait.

Each current candidate ``Package`` on an active, unpaused server is classified
once against the score row with its exact scheduler identity
(``update_scores.identity``: versions plus held flag, priority, package state
and OS context), using the same skip rules as ``update_scores.run_one``. Rows
left from an earlier scoring context therefore never mask a pending rescore.

The pass reads packages in the scheduler's bounded keyset order but keeps its
version indexes and identity memo local to the request; it never mutates the
scheduler's shared memo or any score row. It is computed only on request from
``GET /api/update-scores/status``, not on every Settings load.

The summary returns fixed counts and timestamps only, never package names,
evidence, explanations, provider text or key material. It sends no provider
request and changes no schema, admission, reservation, retry or authorization.
"""
import time

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import load_only

from . import ai_policy, ai_retry, host_lifecycle, update_scores
from .ai_runs import AIRun
from .db import Host, Package, Setting
from .package_history import version_index
from .update_scores import UpdateScore

RETRY_SECONDS = 3600
CHUNK = 200
CLASSES = ('eligible', 'retry_wait', 'deferred', 'blocked', 'running', 'complete')
LIMITATIONS = (
    ('Counts cover current pending updates on active, unpaused servers. Shared AI start gates (rate throttle, '
     'daily cap, provider backoff, legacy hourly allowance) and per-server pause still decide when a batch '
     'starts, so "eligible now" is not a promise that scoring starts immediately.'),
    ('The summary is a point-in-time read. A scoring pass or inventory refresh that runs at the same time can '
     'change the counts immediately afterwards.'),
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


def classify(row, signature, now, *, interrupted=False):
    """Return (class, wait_until) for the exact current row, mirroring ``run_one``'s skip order."""
    if row is None:
        return 'eligible', None
    if row.state == 'complete':
        return 'complete', None
    if row.state == 'deferred' and row.next_at > now:
        return 'deferred', row.next_at
    if row.state == 'blocked' and signature is not None and row.configuration == signature:
        return 'blocked', None
    if row.state not in ('deferred', 'blocked') and row.attempted > now - RETRY_SECONDS:
        if row.state == 'running' and not interrupted:
            return 'running', None
        return 'retry_wait', row.attempted + RETRY_SECONDS
    return 'eligible', None


def _current_candidates(session):
    """Yield (package, exact identity) like ``update_scores.scoring_candidates``, without shared memo writes."""
    hosts = {}
    cursor = None
    while True:
        query = select(Package).where(Package.candidate != '', Package.host_id.not_in(ai_policy.paused_ids()),
                                      Package.host_id.in_(host_lifecycle.active_ids()))
        if cursor is not None:
            query = query.where(or_(Package.available_since > cursor[0],
                                    and_(Package.available_since == cursor[0], Package.id > cursor[1])))
        packages = list(session.scalars(query.order_by(Package.available_since, Package.id).limit(CHUNK)))
        if not packages:
            return
        cursor = (packages[-1].available_since, packages[-1].id)
        missing = list(dict.fromkeys(p.host_id for p in packages if p.host_id not in hosts))
        if missing:
            for host_id, inventory in session.execute(select(Host.id, Host.inventory).where(Host.id.in_(missing))):
                index = version_index(inventory)
                context = {key: inventory[key] for key in ('os', 'package_manager') if key in inventory}
                # Same shape as the scheduler's overflow path: a pass-local index and memo.
                hosts[host_id] = (update_scores._ScoringHost(host_id, context, index), (None, index, {}))
        for package in packages:
            entry = hosts.get(package.host_id)
            if entry is not None:
                yield package, update_scores.cached_identity(entry[0], package, entry[1])


def status(session, cfg, now=None):
    """Return the scoring queue summary in the caller's session. Read-only."""
    now = time.time() if now is None else now
    signature = _signature(session, cfg)
    counts = dict.fromkeys(CLASSES, 0)
    oldest_waiting = None
    waits = []
    # A new attempt can still reference a previous run while the worker links its new run.
    state = (
        select(UpdateScore, AIRun.id.is_not(None))
        .outerjoin(AIRun, and_(AIRun.id == UpdateScore.run_id, AIRun.purpose == 'update_scoring',
                              AIRun.state == 'interrupted', AIRun.started >= UpdateScore.attempted,
                              UpdateScore.state == 'running'))
        .options(load_only(UpdateScore.id, UpdateScore.state, UpdateScore.attempted,
                           UpdateScore.next_at, UpdateScore.configuration, raiseload=True))
    )
    batch = []

    def flush():
        nonlocal oldest_waiting
        rows = {row.id: (row, interrupted) for row, interrupted in
                session.execute(state.where(UpdateScore.id.in_([key for _, key in batch])))}
        for package, key in batch:
            row, interrupted = rows.get(key, (None, False))
            name, wait = classify(row, signature, now, interrupted=interrupted)
            counts[name] += 1
            if name != 'complete' and (oldest_waiting is None or package.available_since < oldest_waiting):
                oldest_waiting = package.available_since
            if wait is not None:
                waits.append(float(wait))
        batch.clear()

    for package, key in _current_candidates(session):
        batch.append((package, key))
        if len(batch) >= CHUNK:
            flush()
    if batch:
        flush()
    paused = session.scalar(select(func.count()).select_from(Package).where(
        Package.candidate != '', Package.host_id.in_(host_lifecycle.active_ids()),
        Package.host_id.in_(ai_policy.paused_ids()))) or 0
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
