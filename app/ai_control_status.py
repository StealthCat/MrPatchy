"""Redacted, read-only status for shared AI provider-call controls."""
import time
from decimal import Decimal, InvalidOperation

from . import ai_admission, ai_budget, ai_credential_notifications, ai_pricing, ai_provider_backoff
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

CREDENTIAL_MESSAGE = ('The saved API key cannot be decrypted with this controller\'s encryption key. Restore the '
                      'matching encryption key or save the API key again before provider calls can start.')
PROVIDER_WAIT_REASONS = (
    ai_provider_backoff.RETRY_AFTER_REASON,
    ai_provider_backoff.TRANSIENT_REASON,
    ai_provider_backoff.CAPPED_REASON,
)
GENERIC_PROVIDER_WAIT = 'Shared provider backoff is waiting after a transient failure.'


def _money_exhausted(value):
    try:
        return Decimal(str(value)) <= 0
    except (InvalidOperation, TypeError, ValueError):
        # Malformed status must never be presented as permission to start a paid call.
        return True


def _window(session, column, conditions, limit, now):
    """Count one legacy sliding window and when it next drops below ``limit``.

    Admission counts entries with ``column > now - 3600``. Once ``count >= limit``
    the gate reopens when the ``limit``-th newest entry leaves the window. Read
    the count and that timestamp in the same statement. The ordered lookup is
    bounded by the allowance even when the window is heavily overfilled.
    """
    from sqlalchemy import case, func, select

    start = now - WINDOW_SECONDS
    where = (column > start, *conditions)
    count = select(func.count().label('used')).where(*where)
    if limit < 1:
        return session.scalar(count), True, None
    total = count.subquery()
    pivot = (
        select(column).where(*where)
        .order_by(column.desc()).offset(limit - 1).limit(1).scalar_subquery()
    )
    used, timestamp = session.execute(select(total.c.used, case((total.c.used >= limit, pivot)))).one()
    return used, used >= limit, None if timestamp is None else float(timestamp) + WINDOW_SECONDS


def legacy_triage_allowance(session, limit, now):
    """Return usage, the combined hold, and the earliest time both counters clear."""
    from .ai_runs import AIRun
    from .db import Behavior

    # ai_claims.acquire refuses while either counter has reached the limit.
    attempts = _window(session, Behavior.attempted, (), limit, now)
    runs = _window(session, AIRun.started, (AIRun.purpose == 'triage',), limit, now)
    openings = [opens_at for _, blocked, opens_at in (attempts, runs) if blocked]
    next_at = max(openings) if openings and None not in openings else None
    return max(attempts[0], runs[0]), bool(openings), next_at


def _legacy_purpose_limits(session, settings, now):
    """Return the hidden legacy hourly allowances as counts and timestamps only."""
    from .ai_runs import AIRun
    from .db import Job

    def entry(purpose, limit, used, blocked, next_at, state=None):
        return {'purpose': purpose, 'limit': limit, 'used': used,
                'state': state or ('exhausted' if blocked else 'available'),
                'next_at': next_at if blocked else None}

    limit = settings['ai_hourly_limit']
    used, blocked, next_at = legacy_triage_allowance(session, limit, now)
    limits = [entry('triage', limit, used, blocked, next_at)]

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
    elif ai_credential_notifications.state(session)[0] == 'unreadable':
        add('credential', CREDENTIAL_MESSAGE)
    if settings['ai_enabled'] and budget['enabled'] and settings['ai_model']:
        # Disabled AI is already explained by the `disabled` gate (#735 criterion 2).
        # Capped admission must quote every paid call from the bundled catalog;
        # an unpriced model or a stale catalog refuses all of them indefinitely.
        pricing = ai_pricing.model_status(settings['ai_model'], now)
        if not pricing['ok']:
            add('pricing', PRICING_MESSAGES[pricing['code']])
    if provider['blocked']:
        reason = provider['reason']
        message = reason if reason in PROVIDER_WAIT_REASONS else GENERIC_PROVIDER_WAIT
        add('provider_backoff', message, provider['next_at'])
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
