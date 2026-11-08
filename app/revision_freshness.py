"""Pure config-revision freshness gate (first slice of #452).

Decides whether a controller may act on a cached security/config decision
(policy, hold, approval limit, AI budget) given the node's cached revision, the
authoritative revision and how recently the authoritative value was confirmed.
When freshness cannot be established the answer is a refusal; the gate never
fails open. It performs no I/O, caching or persistence and authorizes nothing
by itself: a ``fresh`` verdict only means the cached decision is not known to be
stale.
"""
from __future__ import annotations

import math
from typing import Any

CONTRACT_VERSION = 1
DEFAULT_MAX_AGE = 30.0

FRESH = 'fresh'
STALE_REVISION = 'stale_revision'
STALE_AGE = 'stale_age'
UNKNOWN = 'unknown'
VERDICTS = (FRESH, STALE_REVISION, STALE_AGE, UNKNOWN)
# Anything other than FRESH must make the caller refuse or re-read.
_REASONS = {
    FRESH: 'cached revision matches the authoritative revision and is recent',
    STALE_REVISION: 'cached revision is behind the authoritative revision',
    STALE_AGE: 'authoritative revision was not confirmed recently enough',
    UNKNOWN: 'freshness cannot be established; refuse the decision',
}


def _revision(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value):
        return None
    return float(value)


def check_freshness(cached_revision: Any, authoritative_revision: Any,
                    confirmed_at: Any, now: Any,
                    max_age: Any = DEFAULT_MAX_AGE) -> dict[str, Any]:
    """Classify a cached decision as fresh, stale or unknown.

    ``confirmed_at`` is when ``authoritative_revision`` was last read from the
    shared store. Missing, malformed, negative, or future-dated inputs yield
    ``unknown``. A cached revision ahead of the authoritative one is also
    ``unknown`` (a rollback or split view), never fresh.
    """
    cached = _revision(cached_revision)
    auth = _revision(authoritative_revision)
    confirmed = _number(confirmed_at)
    current = _number(now)
    limit = _number(max_age)
    verdict = UNKNOWN
    age = None
    if (None not in (cached, auth, confirmed, current, limit)
            and limit > 0 and confirmed <= current):
        age = current - confirmed
        if cached > auth:
            verdict = UNKNOWN
        elif cached < auth:
            verdict = STALE_REVISION
        elif age > limit:
            verdict = STALE_AGE
        else:
            verdict = FRESH
    return {
        'contract_version': CONTRACT_VERSION,
        'verdict': verdict,
        'usable': verdict == FRESH,
        'reason': _REASONS[verdict],
        'cached_revision': cached,
        'authoritative_revision': auth,
        'age_seconds': age,
    }


def require_fresh(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Like :func:`check_freshness` but raises ``ValueError`` unless fresh."""
    result = check_freshness(*args, **kwargs)
    if not result['usable']:
        raise ValueError(result['reason'])
    return result
