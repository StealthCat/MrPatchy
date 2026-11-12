"""Redacted, read-only status for shared AI provider-call controls."""
import time
from decimal import Decimal, InvalidOperation

from . import ai_admission, ai_budget, ai_provider_backoff
from .db import Setting, config


LIMITATIONS = [
    'A call-specific conservative price quote can still refuse capped admission.',
    'Provider policy, finite concurrency, per-server pause and lifecycle checks still apply.',
]
LEGACY_LIMITATION = ('Legacy per-purpose hourly limits (triage and update scoring) are enforced separately and are '
                     'not reflected in this snapshot; switch to an explicit control mode for an authoritative status.')


def _money_exhausted(value):
    try:
        return Decimal(str(value)) <= 0
    except (InvalidOperation, TypeError, ValueError):
        # Malformed status must never be presented as permission to start a paid call.
        return True


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
        'limitations': LIMITATIONS + ([LEGACY_LIMITATION] if admission['mode'] == 'legacy' else []),
    }
