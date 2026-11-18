"""Shared test helpers that keep capped-AI tests independent of the catalog's calendar expiry (#741).

The bundled price catalog is deliberately short-lived (ai_pricing.EXPIRES_AT). Its runtime
expiry must stay fail-closed, but the test suite must not start failing on that date.
Tests see a catalog window that always covers the bundled reviewed window, the real
clock and the historic clocks some tests pin. Import from here, not conftest.

A catalog refresh moves ai_pricing.VERIFIED_AT forward (#966). Tests written against an
earlier catalog pin clocks from its window (for example 2026-10-31), so the test window
also reaches back to the first catalog's verification date. Runtime semantics are
unchanged: a real clock before VERIFIED_AT still reports `not_yet_valid`.
"""
import time

from app import ai_pricing

BUNDLED_PRICING_WINDOW = (ai_pricing.VERIFIED_AT, ai_pricing.EXPIRES_AT)
FRESH_PRICING_MARGIN = 30 * 86400
# 2026-10-26T00:00:00Z, the first bundled catalog's VERIFIED_AT. Never move this forward.
HISTORIC_CLOCK_FLOOR = 1792972800


def fresh_pricing_window(now, bundled=BUNDLED_PRICING_WINDOW):
    """Return a (verified_at, expires_at) window fresh at `now` and across the bundled window."""
    return min(bundled[0], HISTORIC_CLOCK_FLOOR, int(now) - 86400), max(bundled[1], int(now) + FRESH_PRICING_MARGIN)


def pin_fresh_pricing_catalog(monkeypatch, now=None, bundled=BUNDLED_PRICING_WINDOW):
    verified, expires = fresh_pricing_window(time.time() if now is None else now, bundled)
    monkeypatch.setattr(ai_pricing, 'VERIFIED_AT', verified)
    monkeypatch.setattr(ai_pricing, 'EXPIRES_AT', expires)
    return verified, expires
