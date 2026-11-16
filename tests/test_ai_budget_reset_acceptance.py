"""Daily spend cap reset acceptance across DST days and local midnight (#984, roadmap A milestone 4).

Budget days are local calendar days, so they are 23 or 25 hours long when the clocks
change, and a few zones change their clocks at local midnight itself. These tests pin the
real reservation path on such days. They change no runtime behavior.
"""
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from zoneinfo import ZoneInfo

import pytest

from app import ai, ai_budget, ai_pricing
from app.db import Session
from tests.pricing_catalog import pin_fresh_pricing_catalog
from tests.test_ai_budget import configure, payload

HOUR = 3600
PERIOD = (datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp(),
          datetime(2027, 6, 1, tzinfo=timezone.utc).timestamp())
# Zones whose DST rules are long-standing: ordinary DST in both hemispheres, a 30-minute
# step (Lord Howe) and a 45-minute offset (Chatham). Each must yield a short and a long day.
STABLE_DST = ('America/New_York', 'Europe/London', 'Australia/Sydney', 'Australia/Lord_Howe',
              'Pacific/Chatham')
# Zones that change their clocks at local midnight. Their governments revise the rules
# often, so nothing here assumes the installed tz database still has a change for them.
MIDNIGHT_DST = ('America/Havana', 'America/Santiago', 'Asia/Beirut', 'Africa/Cairo')
# Fixed-offset controls at both ends of the date line.
FIXED_OFFSET = ('Pacific/Kiritimati', 'Pacific/Pago_Pago', 'UTC')
ZONES = STABLE_DST + MIDNIGHT_DST + FIXED_OFFSET


def at(*parts):
    return datetime(*parts, tzinfo=timezone.utc).timestamp()


def offset_changes(name):
    """Return the hours in PERIOD whose UTC offset differs from the hour before."""
    zone = ZoneInfo(name)
    def offset(moment):
        return datetime.fromtimestamp(moment, timezone.utc).astimezone(zone).utcoffset()
    return [moment for moment in range(int(PERIOD[0]), int(PERIOD[1]), HOUR)
            if offset(moment) != offset(moment - HOUR)]


@pytest.mark.parametrize('name', ZONES)
def test_budget_windows_tile_time_across_every_clock_change(name):
    changes = offset_changes(name)
    assert not changes if name in FIXED_OFFSET else changes or name in MIDNIGHT_DST
    lengths = set()
    # Fixed-offset zones have no change to centre on; sample the start of the period.
    for change in changes or [int(PERIOD[0]) + 72 * HOUR]:
        # Three days either side of the change, every 15 minutes, plus the seconds
        # immediately around each boundary found.
        for now in range(change - 72 * HOUR, change + 72 * HOUR, 900):
            start, reset = ai_budget._window(now, name)
            assert start <= now < reset
            # The instant before the reset is still this window; the reset starts the next.
            assert ai_budget._window(reset - 1, name) == (start, reset)
            following = ai_budget._window(reset, name)
            assert following[0] == reset and following[1] > reset
            # The retained history recovers the same start from the stored reset alone.
            assert ai_budget._window_start(reset, name) == start
            lengths.add(reset - start)
    assert 22 * HOUR <= min(lengths) and max(lengths) <= 26 * HOUR
    if name in FIXED_OFFSET:
        assert lengths == {24 * HOUR}
    elif name in STABLE_DST:
        # These zones must have produced a short and a long budget day, otherwise the
        # sampling missed the days this test exists for.
        assert min(lengths) < 24 * HOUR < max(lengths)


def offset_step(name, moment):
    """Return how far the UTC offset moved in the hour ending at moment."""
    zone = ZoneInfo(name)
    def offset(instant):
        return datetime.fromtimestamp(instant, timezone.utc).astimezone(zone).utcoffset()
    return offset(moment) - offset(moment - HOUR)


def dst_day(name, kind):
    """Return the first short or long budget day in PERIOD.

    Whether such a day exists is decided from the tz database alone: a rising offset makes
    that local day short and a falling one makes it long. Only a zone with no change in that
    direction is skipped. When the tz database has one, ``_window`` (the code under test) must
    report the matching day, so a window regression fails instead of turning into a skip.
    """
    wanted = [change for change in offset_changes(name)
              if (offset_step(name, change) > timedelta(0)) == (kind == 'short')]
    if not wanted:
        if name in STABLE_DST:
            pytest.fail(f'{name} has no {kind} day in the installed tz database for the test period')
        pytest.skip(f'the installed tz database has no {kind} day for {name} in the test period')
    for change in wanted:
        # The hour scan reports the hour after the change; step back to the change itself.
        for moment in (change, change - HOUR):
            start, reset = ai_budget._window(moment, name)
            if (reset - start < 24 * HOUR) if kind == 'short' else (reset - start > 24 * HOUR):
                return start, reset
    pytest.fail(f'the tz database has {len(wanted)} {kind}-day clock change(s) for {name}, '
                f'but no budget window around them is {kind}')


@pytest.mark.parametrize('name', ('America/New_York', 'Australia/Lord_Howe') + MIDNIGHT_DST)
@pytest.mark.parametrize('kind', ('short', 'long'))
def test_exhausted_cap_defers_to_the_reset_of_a_short_or_long_day(admin, monkeypatch, name, kind):
    start, reset = dst_day(name, kind)
    clock = [start]
    monkeypatch.setattr(ai_budget.time, 'time', lambda: clock[0])
    pin_fresh_pricing_catalog(monkeypatch, now=start)
    quote = ai_pricing.reservation(payload())['amount_usd']
    configure(cap=quote, timezone=name)

    # The first second of the day belongs to this window, including when local midnight
    # is skipped or repeated.
    first = ai_budget.reserve(payload())
    with Session() as session:
        row = session.get(ai_budget.BudgetEntry, first)
        assert row.reset_at == reset and row.timezone == name
        state = ai_budget.status(session, clock[0])
        assert state['remaining_usd'] == '0' and state['next_reset'] == reset
        assert state['next_reset_authoritative']

    # Refused for the whole day, and the deferral always ends exactly at the reset.
    for moment in (start + 1, start + (reset - start) // 2, reset - 1):
        clock[0] = moment
        with pytest.raises(ai.AIError) as refused:
            ai_budget.reserve(payload())
        assert refused.value.policy_wait and refused.value.retry_after == reset - moment
        with Session() as session:
            assert ai_budget.waiting(session, moment, payload()) == reset

    # Admitted at the reset instant, into the next local day.
    clock[0] = reset
    with Session() as session:
        assert ai_budget.waiting(session, reset, payload()) == 0
    second = ai_budget.reserve(payload())
    following = ai_budget._window(reset, name)[1]
    with Session() as session:
        assert session.get(ai_budget.BudgetEntry, second).reset_at == following
        state = ai_budget.status(session, reset)
        assert Decimal(state['counted_usd']) == quote and state['next_reset'] == following
        # The failed attempts left no charge behind: one row per admitted call.
        assert session.query(ai_budget.BudgetEntry).count() == 2


@pytest.mark.parametrize('name,kind', [
    ('UTC', None), ('America/New_York', 'long'), ('America/New_York', 'short'),
    ('America/Havana', 'short'), ('America/Santiago', 'long'),
])
def test_call_in_flight_at_the_reset_stays_in_the_window_that_admitted_it(admin, monkeypatch, name, kind):
    start, reset = dst_day(name, kind) if kind else ai_budget._window(at(2026, 11, 20, 12), name)
    clock = [reset - 5]
    monkeypatch.setattr(ai_budget.time, 'time', lambda: clock[0])
    pin_fresh_pricing_catalog(monkeypatch, now=start)
    quote = ai_pricing.reservation(payload())['amount_usd']
    configure(cap=quote, timezone=name)

    early = ai_budget.reserve(payload())
    ai_budget.mark_sent(early, 'call-before-reset')
    with Session() as session:
        before = ai_budget.status(session, clock[0])
        assert Decimal(before['uncertain_usd']) == quote and before['remaining_usd'] == '0'

    # After the reset the unanswered call is still on the ledger, but not in the new
    # window: the new day starts with its full headroom.
    clock[0] = reset + 5
    with Session() as session:
        after = ai_budget.status(session, clock[0])
        assert after['counted_usd'] == '0' and Decimal(after['remaining_usd']) == quote
        row = session.get(ai_budget.BudgetEntry, early)
        assert row.status == 'sent' and row.reset_at == reset
    late = ai_budget.reserve(payload())

    # A late receipt settles the call under the window that admitted it.
    clock[0] = reset + 60
    ai_budget.reconcile(early, {'status': 'estimated', 'pricing': {'estimated_usd': '0.000123'}})
    following = ai_budget._window(reset, name)[1]
    with Session() as session:
        row = session.get(ai_budget.BudgetEntry, early)
        assert row.status == 'settled' and row.reset_at == reset and row.actual_usd == Decimal('0.000123')
        state = ai_budget.status(session, clock[0])
        assert Decimal(state['counted_usd']) == quote and state['settled_usd'] == '0'
        assert Decimal(state['reserved_usd']) == quote
        history = ai_budget.history(session, days=7, now=clock[0])
    windows = {row['reset_at']: row for row in history['windows']}
    assert set(windows) == {reset, following}
    assert windows[reset]['window_start'] == start and windows[reset]['call_count'] == 1
    assert windows[reset]['settled_usd'] == '0.000123' and windows[reset]['counted_usd'] == '0.000123'
    assert windows[following]['window_start'] == reset and windows[following]['call_count'] == 1
    assert Decimal(windows[following]['reserved_usd']) == quote
    with Session() as session:
        assert session.get(ai_budget.BudgetEntry, late).reset_at == following
