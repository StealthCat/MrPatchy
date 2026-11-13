"""Regression guard for #741: capped-AI tests must not depend on the calendar.

The bundled price catalog expires on a fixed date by design (fail-closed capped
admission). The shared `fresh_pricing_catalog` fixture in conftest.py keeps the
test suite independent of that date without changing runtime semantics.
"""
from decimal import Decimal

import pytest

from app import ai, ai_budget, ai_pricing
from app.db import Session, Setting
from tests.pricing_catalog import BUNDLED_PRICING_WINDOW, fresh_pricing_window, pin_fresh_pricing_catalog

DAY = 86400
# A clock well after the bundled catalog expiry (and any plausible near-term refresh).
AFTER_EXPIRY = BUNDLED_PRICING_WINDOW[1] + 400 * DAY
INSIDE_BUNDLED = BUNDLED_PRICING_WINDOW[0] + 5 * DAY  # historic clocks some tests pin


def payload():
    return {'model': 'gpt-6-luna', 'input': 'bounded evidence', 'max_output_tokens': 1000,
            'store': False, 'service_tier': 'default'}


def configure():
    with Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': True, 'ai_model': 'gpt-6-luna', 'ai_control_mode': 'daily_cap',
            'ai_rate_per_hour': 20, 'ai_daily_cap_usd': 1.0, 'ai_budget_timezone': 'UTC',
        }))
        session.commit()


def test_window_covers_real_clock_and_bundled_window_without_shrinking():
    for now in (INSIDE_BUNDLED, BUNDLED_PRICING_WINDOW[1], AFTER_EXPIRY):
        verified, expires = fresh_pricing_window(now)
        assert verified <= BUNDLED_PRICING_WINDOW[0] and expires >= BUNDLED_PRICING_WINDOW[1]
        assert verified <= now < expires
        assert verified <= INSIDE_BUNDLED < expires


def test_runtime_catalog_dates_are_not_changed_by_the_fixture():
    # The fixture only patches the module attributes for the test's duration.
    import ast
    import pathlib
    source = pathlib.Path(ai_pricing.__file__).read_text()
    constants = {node.targets[0].id: node.value.value for node in ast.parse(source).body
                 if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                 and node.targets[0].id in ('VERIFIED_AT', 'EXPIRES_AT')}
    assert (constants['VERIFIED_AT'], constants['EXPIRES_AT']) == BUNDLED_PRICING_WINDOW


@pytest.mark.bundled_pricing_catalog
def test_opt_out_marker_sees_the_bundled_window():
    assert (ai_pricing.VERIFIED_AT, ai_pricing.EXPIRES_AT) == BUNDLED_PRICING_WINDOW


@pytest.mark.parametrize('now', [INSIDE_BUNDLED, AFTER_EXPIRY])
def test_capped_reservation_after_bundled_expiry_needs_only_the_fixture(admin, monkeypatch, now):
    """Fails closed without the fixture's window, succeeds with it, at any clock."""
    configure()
    monkeypatch.setattr(ai_budget.time, 'time', lambda: float(now))
    monkeypatch.setattr(ai_pricing, 'VERIFIED_AT', BUNDLED_PRICING_WINDOW[0])
    monkeypatch.setattr(ai_pricing, 'EXPIRES_AT', BUNDLED_PRICING_WINDOW[1])
    if now >= BUNDLED_PRICING_WINDOW[1]:
        # Runtime semantics are unchanged: the real expired catalog refuses capped admission.
        with pytest.raises(ai.AIError, match='expired'):
            ai_budget.reserve(payload())
        with Session() as session:
            assert not session.query(ai_budget.BudgetEntry).count()
    pin_fresh_pricing_catalog(monkeypatch, now)
    entry = ai_budget.reserve(payload())
    assert entry is not None
    with Session() as session:
        state = ai_budget.status(session)
        assert state['pricing_catalog']['fresh']
        assert Decimal(state['reserved_usd']) == ai_pricing.reservation(payload())['amount_usd']
