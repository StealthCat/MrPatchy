"""Roadmap A milestone 4: simultaneous daily-cap admissions racing settings saves (#990).

Many threads reserve shared daily-cap spend while an administrator saves AI settings
through the real settings API. Each admission is checked against the settings snapshot
it read inside the shared budget lock, and the counted spend it saw must equal every
reservation admitted before it. A reservation that starts after the save has returned
must use the saved settings. A save must never rewrite, release or re-grant ledger spend.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from decimal import Decimal
import threading
import time as real_time
import types

import pytest

from app import ai, ai_budget, ai_pricing
from app.db import Session
from tests.ai_settings_helpers import confirmed_put
from tests.test_ai_budget import configure, payload

# Mid-day UTC, so no window boundary is crossed while a race runs.
NOON = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc).timestamp()
THREADS = 8
ATTEMPTS = 6
MAX_ATTEMPTS = 400


@pytest.fixture
def clock(monkeypatch):
    """A fixed day for the budget module only, advancing with real elapsed time."""
    started = real_time.monotonic()
    monkeypatch.setattr(ai_budget, 'time', types.SimpleNamespace(time=lambda: NOON + real_time.monotonic() - started))


@pytest.fixture
def admissions(monkeypatch):
    """Record, in lock order, what each reservation saw inside the shared budget lock."""
    seen, local, guard = [], threading.local(), threading.Lock()
    original = ai_budget._state

    def observe(session, cfg, now, **options):
        result = original(session, cfg, now, **options)
        if getattr(local, 'attempt', None) is not None and not options:
            # reserve() reads _state once per attempt, after it holds the shared lock.
            with guard:
                local.attempt.update(mode=cfg['ai_control_mode'], cap=result[6], counted=result[5],
                    timezone=cfg['ai_budget_timezone'], order=len(seen))
                seen.append(local.attempt)
        return result

    monkeypatch.setattr(ai_budget, '_state', observe)
    return types.SimpleNamespace(seen=seen, local=local)


def body(mode, cap, zone='UTC'):
    return {'ai_model': 'gpt-6-luna', 'ai_enabled': True, 'ai_updates_enabled': True,
            'ai_hourly_limit': 20, 'ai_update_hourly_limit': 20, 'ai_control_mode': mode,
            'ai_rate_per_hour': 1000, 'ai_daily_cap_usd': float(cap), 'ai_budget_timezone': zone}


def ledger():
    with Session() as session:
        return {row.id: (row.status, row.reservation_usd, row.actual_usd, row.reset_at, row.timezone, row.created)
                for row in session.query(ai_budget.BudgetEntry)}


def counted_now():
    with Session() as session:
        return Decimal(ai_budget.status(session)['counted_usd'])


def race(admin, admissions, new_body):
    """Run THREADS x ATTEMPTS reservations while one settings save lands mid-race."""
    barrier, saved, done = threading.Barrier(THREADS + 1), {}, threading.Event()
    attempts = []

    def worker(index):
        barrier.wait(timeout=10)
        after_save = 0
        for count in range(MAX_ATTEMPTS):
            # Keep racing until the save has returned and this thread has also started
            # attempts after it, however long the save takes on this database.
            if count >= ATTEMPTS and after_save >= 2:
                break
            if done.is_set():
                after_save += 1
            attempt = {'started': real_time.monotonic(), 'thread': index}
            admissions.local.attempt = attempt
            try:
                attempt['id'] = ai_budget.reserve(payload())
            except ai.AIError as error:
                attempt['refused'] = str(error)
            finally:
                admissions.local.attempt = None
            attempts.append(attempt)
            real_time.sleep(0.002)

    def save():
        barrier.wait(timeout=10)
        real_time.sleep(0.01)
        result = confirmed_put(admin, '/api/settings/ai', new_body)
        saved['status'] = result.status_code
        saved['returned'] = real_time.monotonic()
        done.set()

    with ThreadPoolExecutor(max_workers=THREADS + 1) as pool:
        futures = [pool.submit(worker, index) for index in range(THREADS)] + [pool.submit(save)]
        for future in futures:
            future.result(timeout=120)
    assert saved['status'] == 200
    assert len(attempts) >= THREADS * ATTEMPTS
    return attempts, saved['returned']


def assert_each_admission_fit_its_snapshot(admissions, quote):
    """Lock-ordered consistency: each admission saw exactly the spend admitted before it."""
    admitted = Decimal(0)
    for attempt in sorted(admissions.seen, key=lambda item: item['order']):
        if attempt['mode'] not in ai_pricing.CAP_MODES:
            continue
        assert attempt['counted'] == admitted
        if attempt.get('id'):
            assert attempt['counted'] + quote <= attempt['cap']
            admitted += quote
        else:
            assert 'no remaining safe reservation' in attempt['refused']
            assert attempt['counted'] + quote > attempt['cap']
    return admitted


def assert_rows_are_untouched_reservations(rows, quote):
    for status, reservation, actual, *_ in rows.values():
        assert (status, reservation, actual) == ('reserved', quote, None)


@pytest.mark.usefixtures('clock')
def test_lowering_the_cap_mid_race_never_overspends_and_applies_after_save(admin, admissions):
    quote = ai_pricing.reservation(payload())['amount_usd']
    configure(mode='daily_cap', cap=quote * 20)
    attempts, returned = race(admin, admissions, body('daily_cap', quote * 5))
    admitted = assert_each_admission_fit_its_snapshot(admissions, quote)
    rows = ledger()
    assert admitted == quote * len(rows)
    assert 0 < len(rows) <= 20
    assert_rows_are_untouched_reservations(rows, quote)
    late = [attempt for attempt in attempts if attempt['started'] > returned]
    assert late, 'the race must include reservations that start after the save'
    for attempt in late:
        assert attempt['cap'] == quote * 5
        if attempt.get('id'):
            assert attempt['counted'] + quote <= quote * 5
    # Saved spend is not re-granted: after the race the lower cap still refuses beyond it.
    assert counted_now() == admitted
    if admitted >= quote * 5:
        with pytest.raises(ai.AIError, match='no remaining safe reservation'):
            ai_budget.reserve(payload())


@pytest.mark.usefixtures('clock')
def test_raising_the_cap_mid_race_admits_no_more_than_the_new_cap(admin, admissions):
    quote = ai_pricing.reservation(payload())['amount_usd']
    configure(mode='daily_cap', cap=quote * 3)
    attempts, returned = race(admin, admissions, body('daily_cap', quote * 10))
    admitted = assert_each_admission_fit_its_snapshot(admissions, quote)
    rows = ledger()
    assert admitted == quote * len(rows)
    assert len(rows) <= 10
    assert_rows_are_untouched_reservations(rows, quote)
    for attempt in attempts:
        if attempt['started'] > returned:
            assert attempt['cap'] == quote * 10
    # The race makes more attempts than the raised cap allows, so admission stops exactly at it.
    assert len(rows) == 10
    assert counted_now() == quote * 10


@pytest.mark.usefixtures('clock')
@pytest.mark.parametrize('uncapped', ['rate', 'unthrottled'])
def test_switching_to_an_uncapped_mode_mid_race_keeps_admitted_spend(admin, admissions, uncapped):
    quote = ai_pricing.reservation(payload())['amount_usd']
    configure(mode='rate_and_daily', cap=quote * 40)
    attempts, returned = race(admin, admissions, body(uncapped, quote * 40))
    admitted = assert_each_admission_fit_its_snapshot(admissions, quote)
    rows = ledger()
    assert admitted == quote * len(rows)
    assert_rows_are_untouched_reservations(rows, quote)
    late = [attempt for attempt in attempts if attempt['started'] > returned]
    assert late, 'the race must include reservations that start after the save'
    # Uncapped reservations return before any capped read and write no ledger row.
    assert all(attempt.get('id') is None and 'refused' not in attempt and 'cap' not in attempt for attempt in late)
    assert len(rows) == sum(1 for attempt in attempts if attempt.get('id'))
    # Re-enabling the cap counts everything admitted before the switch; nothing was released.
    assert confirmed_put(admin, '/api/settings/ai', body('daily_cap', quote * 40)).status_code == 200
    assert ledger() == rows
    assert counted_now() == admitted


@pytest.mark.usefixtures('clock')
@pytest.mark.parametrize('zone', ['Pacific/Kiritimati', 'Pacific/Pago_Pago', 'America/New_York'])
def test_timezone_change_mid_race_never_regrants_the_open_window(admin, admissions, zone):
    quote = ai_pricing.reservation(payload())['amount_usd']
    configure(mode='daily_cap', cap=quote * 12)
    attempts, returned = race(admin, admissions, body('daily_cap', quote * 12, zone))
    admitted = assert_each_admission_fit_its_snapshot(admissions, quote)
    rows = ledger()
    # Rows admitted under the UTC window stay counted in the new timezone, so the
    # shared cap is never exceeded across the change.
    assert admitted == quote * len(rows) == quote * 12
    assert_rows_are_untouched_reservations(rows, quote)
    assert {row[4] for row in rows.values()} <= {'UTC', zone}
    for attempt in attempts:
        if attempt['started'] > returned:
            assert attempt['timezone'] == zone
    assert counted_now() == quote * 12


@pytest.mark.usefixtures('clock')
@pytest.mark.parametrize('change', [
    lambda quote: body('daily_cap', quote),
    lambda quote: body('daily_cap', quote * 100),
    lambda quote: body('rate_and_daily', quote * 4, 'Asia/Tokyo'),
    lambda quote: body('rate', quote * 4),
    lambda quote: body('unthrottled', quote * 4),
])
def test_settings_saves_never_rewrite_or_release_ledger_rows(admin, change):
    quote = ai_pricing.reservation(payload())['amount_usd']
    configure(mode='daily_cap', cap=quote * 4)
    ids = [ai_budget.reserve(payload()) for _ in range(3)]
    ai_budget.mark_sent(ids[1], 'call-1')
    before = ledger()
    assert len(before) == 3
    assert confirmed_put(admin, '/api/settings/ai', change(quote)).status_code == 200
    assert ledger() == before
