"""Redacted, read-only status for shared AI provider-call controls."""
import time
from decimal import Decimal, InvalidOperation

from . import ai_admission, ai_budget, ai_pricing, ai_provider_backoff
from .db import Setting, config


LIMITATIONS = [
    'A call-specific conservative price quote can still refuse capped admission.',
    'Provider policy, finite concurrency, per-server pause and lifecycle checks still apply.',
]
LEGACY_LIMITATION = ('Legacy per-purpose hourly allowances (triage, update scoring and automatic plans) are listed '
                     'separately below. Each holds only its own purpose and does not change the shared gates above; '
                     'switch to an explicit control mode for one authoritative shared throttle.')
# Fixed legacy allowance for automatic incident/startup plans; mirrors
# incidents.auto_plan_tick, which counts both plan actions together.
AUTO_PLAN_HOURLY_LIMIT = 10
WINDOW_SECONDS = 3600


PRICING_MESSAGES = {
    'catalog': 'The bundled public-price catalog is not currently valid, so capped admission cannot reserve spend for any call.',
    'model': 'The saved model has no verified catalog price, so capped admission cannot reserve spend for it.',
}


def _money_exhausted(value):
    try:
        return Decimal(str(value)) <= 0
    except (InvalidOperation, TypeError, ValueError):
        # Malformed status must never be presented as permission to start a paid call.
        return True


def _window(session, column, conditions, limit, now):
    """Count one legacy sliding window and when it next drops below ``limit``.

    Admission counts entries with ``column > now - 3600``. Once ``count >= limit``
    the gate reopens only after the oldest ``count - limit + 1`` entries leave
    the window, so the opening time is that entry plus one hour, not merely the
    oldest entry plus one hour.
    """
    from sqlalchemy import func, select
    start = now - WINDOW_SECONDS
    where = (column > start, *conditions)
    used = session.scalar(select(func.count()).where(*where)) or 0
    if used < limit:
        return used, False, None
    if limit < 1:
        return used, True, None
    pivot = session.scalar(select(column).where(*where).order_by(column).offset(used - limit).limit(1))
    return used, True, None if pivot is None else float(pivot) + WINDOW_SECONDS


def _legacy_purpose_limits(session, settings, now):
    """Return the hidden legacy hourly allowances as counts and timestamps only."""
    from .ai_runs import AIRun
    from .db import Behavior, Job

    def entry(purpose, limit, used, blocked, next_at, state=None):
        return {'purpose': purpose, 'limit': limit, 'used': used,
                'state': state or ('exhausted' if blocked else 'available'),
                'next_at': next_at if blocked else None}

    limit = settings['ai_hourly_limit']
    # ai_claims.acquire refuses while either counter has reached the limit.
    attempts = _window(session, Behavior.attempted, (), limit, now)
    runs = _window(session, AIRun.started, (AIRun.purpose == 'triage',), limit, now)
    blocked = attempts[1] or runs[1]
    opens = [item[2] for item in (attempts, runs) if item[1]]
    triage_next = None if not blocked or None in opens else max(opens)
    limits = [entry('triage', limit, max(attempts[0], runs[0]), blocked, triage_next)]

    limit = settings['ai_update_hourly_limit']
    used, blocked, next_at = _window(session, AIRun.started, (AIRun.purpose == 'update_scoring',), limit, now)
    if settings['ai_updates_enabled']:
        limits.append(entry('update_scoring', limit, used, blocked, next_at))
    else:
        limits.append(entry('update_scoring', limit, used, False, None, state='disabled'))

    used, blocked, next_at = _window(session, Job.created, (Job.action.in_(('security-plan', 'startup-plan')),),
                                     AUTO_PLAN_HOURLY_LIMIT, now)
    limits.append(entry('automatic_plans', AUTO_PLAN_HOURLY_LIMIT, used, blocked, next_at))
    return limits


def snapshot(session, now=None):
    """Return every observable global blocker without exposing request data."""
    now = time.time() if now is None else now
    settings = config(session)
    admission = ai_admission.status(session)
    budget = ai_budget.status(session, now)
    provider = ai_provider_backoff.status(session, now)
    blockers = []

    def add(code, message, next_at=None, recheck_at=None):
        blockers.append({'code': code, 'message': message, 'next_at': next_at, 'recheck_at': recheck_at})

    if not settings['ai_enabled']:
        add('disabled', 'Central AI provider calls are disabled by an administrator.')
    if not settings['ai_model'] or session.get(Setting, 'openai_key') is None:
        add('configuration', 'A saved model and API key are required before provider calls can start.')
    if settings['ai_enabled'] and budget['enabled'] and settings['ai_model']:
        # Disabled AI is already explained by the `disabled` gate (#735 criterion 2).
        # Capped admission must quote every paid call from the bundled catalog;
        # an unpriced model or a stale catalog refuses all of them indefinitely.
        pricing = ai_pricing.model_status(settings['ai_model'], now)
        if not pricing['ok']:
            add('pricing', PRICING_MESSAGES[pricing['code']])
    if provider['blocked']:
        add('provider_backoff', 'Shared provider backoff is waiting after a transient failure.', provider['next_at'])
    if admission['mode'] in ('rate', 'rate_and_daily') and admission['next_at'] and admission['next_at'] > now:
        add('rate_throttle', 'The shared smooth-rate throttle is waiting for its next start.', admission['next_at'])
    if budget['enabled'] and _money_exhausted(budget['remaining_usd']):
        if budget['next_reset_authoritative']:
            add('daily_cap', 'The daily spend cap has no remaining recorded headroom.', budget['next_reset'])
        else:
            add('daily_cap', 'The daily spend cap has no remaining recorded headroom; retained prior windows make the configured reset a recheck boundary only.',
                recheck_at=budget['next_reset'])

    indefinite = any(item['next_at'] is None for item in blockers)
    finite = [item['next_at'] for item in blockers if item['next_at'] is not None]
    return {
        'generated_at': now,
        'mode': admission['mode'],
        'can_start_now': not blockers,
        'next_start_at': None if indefinite or not finite else max(finite),
        'blockers': blockers,
        # Per-purpose holds only; they never widen or narrow the global gates.
        'purpose_limits': _legacy_purpose_limits(session, settings, now) if admission['mode'] == 'legacy' else [],
        'limitations': LIMITATIONS + ([LEGACY_LIMITATION] if admission['mode'] == 'legacy' else []),
    }
