"""Shared test helpers that keep capped-AI tests independent of the catalog's calendar expiry (#741).

The bundled price catalog is deliberately short-lived (ai_pricing.EXPIRES_AT). Its runtime
expiry must stay fail-closed, but the test suite must not start failing on that date.
Tests see a catalog window that always covers both the bundled reviewed window (tests
that pin historic clocks inside it) and the real clock. Import from here, not conftest.
"""
import time

from app import ai_pricing

BUNDLED_PRICING_WINDOW = (ai_pricing.VERIFIED_AT, ai_pricing.EXPIRES_AT)
FRESH_PRICING_MARGIN = 30 * 86400


def fresh_pricing_window(now, bundled=BUNDLED_PRICING_WINDOW):
    """Return a (verified_at, expires_at) window fresh at `now` and across the bundled window."""
    return min(bundled[0], int(now) - 86400), max(bundled[1], int(now) + FRESH_PRICING_MARGIN)


def pin_fresh_pricing_catalog(monkeypatch, now=None, bundled=BUNDLED_PRICING_WINDOW):
    verified, expires = fresh_pricing_window(time.time() if now is None else now, bundled)
    monkeypatch.setattr(ai_pricing, 'VERIFIED_AT', verified)
    monkeypatch.setattr(ai_pricing, 'EXPIRES_AT', expires)
    return verified, expires
