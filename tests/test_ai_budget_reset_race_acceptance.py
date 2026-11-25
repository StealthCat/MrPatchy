"""Daily-cap admission races at the budget reset (#1275, roadmap A milestone 4).

#984 pinned the reset with one caller at a time and #1012 raced callers inside one window.
These tests race the authoritative ``ai_budget.reserve()`` admission across the reset
boundary itself: threads at the reset instant, threads (or skewed worker clocks) on both
sides of it, a late receipt for the old window during the race, and fresh processes. Each
budget window must stay within the cap independently, and no caller may borrow the other
window's headroom. Provider I/O is not involved; the reservation is the spending authority.
They change no runtime behavior.
"""
import json
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app import ai, ai_budget, ai_pricing
from app.db import Session, Setting
from app.security import seal
from tests.test_ai_claims_cap_contention_acceptance import CALL, MODEL, fixed_quote

DAY = 86400
# The cap has room for K calls and half a call more, so K fit and K + 1 does not.
K = 3
ZONES = ('UTC', 'Asia/Kolkata', 'America/New_York')
# A UTC midday well inside the pricing catalog's pinned window; its reset is that night.
MIDDAY = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc).timestamp()


def reset_for(zone):
    """The first reset after MIDDAY in `zone`, and the reset after that."""
    first = ai_budget._window(MIDDAY, zone)[1]
    second = ai_budget._window(first, zone)[1]
    assert MIDDAY + 3600 < first < second
    return first, second


class Clock:
    """A per-thread clock for ``ai_budget``; a thread without its own uses the default."""

    def __init__(self, default):
        self.default = default
        self.local = threading.local()

    def set(self, value):
        self.local.now = value

    def time(self):
        return getattr(self.local, 'now', self.default)


@pytest.fixture
def clock(monkeypatch):
    value = Clock(MIDDAY)
    monkeypatch.setattr(ai_budget, 'time', SimpleNamespace(time=value.time))
    monkeypatch.setattr(ai_pricing, 'reservation', fixed_quote(ai_pricing.reservation))
    return value


@pytest.fixture
def widened(monkeypatch):
    """Hold each reservation open between its spend read and its insert.

    Without the delay the read-then-commit window is too short for threads to interleave,
    so removing the shared budget lock would go unnoticed.
    """
    real = ai_budget._state
    delayed = []

    def state(*args, **kwargs):
        value = real(*args, **kwargs)
        if sys._getframe(1).f_code is ai_budget.reserve.__code__:
            delayed.append(1)
            time.sleep(0.03)
        return value
    monkeypatch.setattr(ai_budget, '_state', state)
    yield
    assert delayed, 'widened never delayed a reserve() spend read; update the frame check'


def configure(zone, calls=K):
    with Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': True, 'ai_model': MODEL, 'ai_control_mode': 'daily_cap',
            'ai_rate_per_hour': 1000, 'ai_daily_cap_usd': float(CALL * calls + CALL / 2),
            'ai_budget_timezone': zone}))
        session.merge(Setting(key='openai_key', value={'encrypted': seal('fixture')}))
        session.commit()


def payload():
    return {'model': MODEL, 'input': 'bounded evidence', 'max_output_tokens': 100,
            'store': False, 'service_tier': 'default'}


def fill(clock, at, count):
    """Reserve `count` calls at `at` through the real path, as one earlier caller."""
    clock.set(at)
    try:
        return [ai_budget.reserve(payload()) for _ in range(count)]
    finally:
        del clock.local.now


def attempt(clock, at):
    clock.set(at)
    try:
        return ('admitted', ai_budget.reserve(payload()))
    except ai.AIError as error:
        assert error.policy_wait, str(error)
        return ('wait', error.budget_wait_until, error.retry_after)


def race(clock, moments):
    """Start one thread per moment together; each reserves once with its own clock."""
    start = threading.Barrier(len(moments))
    results = [None] * len(moments)

    def run(index):
        start.wait(timeout=10)
        results[index] = attempt(clock, moments[index])

    threads = [threading.Thread(target=run, args=(index,)) for index in range(len(moments))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert all(result is not None for result in results)
    return results


def ledger():
    with Session() as session:
        return {row.id: row for row in session.scalars(select(ai_budget.BudgetEntry))}


def counted(at):
    with Session() as session:
        return Decimal(ai_budget.status(session, now=at)['counted_usd'])


def cap():
    with Session() as session:
        return Decimal(str(session.get(Setting, 'config').value['ai_daily_cap_usd']))


def exhaust_old_window(clock, reset):
    """Fill the old window: one call unanswered, one uncertain, one still reserved."""
    sent, uncertain, reserved = fill(clock, reset - 3600, K)
    clock.set(reset - 1800)
    ai_budget.mark_sent(sent, 'call-sent')
    ai_budget.mark_sent(uncertain, 'call-uncertain')
    ai_budget.mark_uncertain(uncertain, 'Timed out after transmission; the outcome is unknown.')
    del clock.local.now
    assert counted(reset - 1) == CALL * K
    return sent, uncertain, reserved


@pytest.mark.usefixtures('widened')
@pytest.mark.parametrize('zone', ZONES)
def test_threads_at_the_reset_instant_admit_exactly_the_new_window(admin, clock, zone):
    reset, following = reset_for(zone)
    configure(zone)
    old = set(exhaust_old_window(clock, reset))

    results = race(clock, [reset] * 10)

    admitted = [r[1] for r in results if r[0] == 'admitted']
    waits = [r for r in results if r[0] == 'wait']
    assert len(admitted) == K and len(waits) == 10 - K
    # A refused caller waits for the next reset, a full budget day away.
    assert all(until == following and retry == following - reset for _, until, retry in waits)
    rows = ledger()
    assert len(rows) == 2 * K
    assert all(rows[i].reset_at == following and rows[i].created == reset for i in admitted)
    # The old window's rows keep their window and statuses, and use no new headroom.
    assert {rows[i].reset_at for i in old} == {reset}
    assert sorted(rows[i].status for i in old) == ['reserved', 'sent', 'uncertain']
    assert counted(reset) == CALL * K <= cap()
    assert counted(reset - 1) == CALL * K
    # Another caller later the same new day is still refused.
    assert attempt(clock, reset + 60)[0] == 'wait'


@pytest.mark.usefixtures('widened')
@pytest.mark.parametrize('zone', ZONES)
@pytest.mark.parametrize('skew', [0.001, 0.75])
def test_callers_straddling_the_reset_use_only_their_own_window(admin, clock, zone, skew):
    """Callers a moment before the reset, or workers whose clocks lag by up to a second."""
    reset, following = reset_for(zone)
    configure(zone)
    # The old window keeps room for exactly one more call.
    fill(clock, reset - 3600, K - 1)

    before = [reset - skew] * 6
    after = [reset + skew] * 6
    # Interleave so that neither side reliably commits first.
    results = race(clock, [moment for pair in zip(before, after) for moment in pair])

    old_side, new_side = results[0::2], results[1::2]
    old_admitted = [r[1] for r in old_side if r[0] == 'admitted']
    new_admitted = [r[1] for r in new_side if r[0] == 'admitted']
    assert len(old_admitted) == 1
    assert len(new_admitted) == K
    rows = ledger()
    assert rows[old_admitted[0]].reset_at == reset
    assert all(rows[i].reset_at == following for i in new_admitted)
    # A refused pre-reset caller waits only until the reset it observed.
    for result in old_side:
        if result[0] == 'wait':
            assert result[1] == reset and result[2] == pytest.approx(skew, abs=1e-6)
    for result in new_side:
        if result[0] == 'wait':
            assert result[1] == following
    assert counted(reset - skew) == CALL * K <= cap()
    assert counted(reset + skew) == CALL * K <= cap()


@pytest.mark.usefixtures('widened')
def test_new_window_admits_first_then_a_lagging_caller_still_sees_old_headroom(admin, clock):
    """A worker whose clock lags the reset is admitted only into the old window's headroom.

    The new window is filled first, so a count that ignored when a row was created would
    charge those rows to the lagging caller's window and refuse it.
    """
    reset, following = reset_for('UTC')
    configure('UTC')
    fill(clock, reset - 3600, K - 1)
    assert [r[0] for r in race(clock, [reset + 0.5] * 5)].count('admitted') == K

    lagging = race(clock, [reset - 0.5] * 4)

    admitted = [r[1] for r in lagging if r[0] == 'admitted']
    assert len(admitted) == 1
    assert ledger()[admitted[0]].reset_at == reset
    assert all(r[1] == reset for r in lagging if r[0] == 'wait')
    assert counted(reset - 0.5) == CALL * K
    assert counted(reset + 0.5) == CALL * K


@pytest.mark.usefixtures('widened')
@pytest.mark.parametrize('receipt', ['settled', 'uncertain'])
def test_a_late_old_window_receipt_during_the_race_changes_no_new_admission(admin, clock, receipt):
    reset, following = reset_for('UTC')
    configure('UTC')
    sent, uncertain, reserved = exhaust_old_window(clock, reset)

    start = threading.Barrier(9)
    results = [None] * 8

    def settle():
        start.wait(timeout=10)
        clock.set(reset + 0.25)
        if receipt == 'settled':
            # A cheap late receipt frees old-window headroom only, never new-window headroom.
            ai_budget.reconcile(sent, {'status': 'estimated', 'pricing': {'estimated_usd': '0.01'}})
        else:
            ai_budget.mark_uncertain(sent, 'The reply was lost after transmission.')

    def run(index):
        start.wait(timeout=10)
        results[index] = attempt(clock, reset + 0.5)

    threads = [threading.Thread(target=settle)] + [
        threading.Thread(target=run, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert [r[0] for r in results].count('admitted') == K
    rows = ledger()
    assert rows[sent].status == receipt and rows[sent].reset_at == reset
    if receipt == 'settled':
        assert rows[sent].actual_usd == Decimal('0.01')
        assert counted(reset - 1) == CALL * (K - 1) + Decimal('0.01')
    else:
        assert counted(reset - 1) == CALL * K
    assert counted(reset + 1) == CALL * K <= cap()


CHILD = """
import json, sys, threading
from types import SimpleNamespace
import pytest
from app import ai, ai_budget, ai_pricing
from tests.pricing_catalog import pin_fresh_pricing_catalog
from tests.test_ai_claims_cap_contention_acceptance import fixed_quote
from tests.test_ai_budget_reset_race_acceptance import payload

now = float(sys.argv[1])
results = []
guard = threading.Lock()

def reserve():
    try:
        value = ('admitted', ai_budget.reserve(payload()))
    except ai.AIError as error:
        value = ('wait' if error.policy_wait else 'error', getattr(error, 'budget_wait_until', None))
    with guard:
        results.append(value)

with pytest.MonkeyPatch.context() as patch:
    pin_fresh_pricing_catalog(patch)
    patch.setattr(ai_pricing, 'reservation', fixed_quote(ai_pricing.reservation))
    patch.setattr(ai_budget, 'time', SimpleNamespace(time=lambda: now))
    print('ready', flush=True)
    sys.stdin.readline()
    threads = [threading.Thread(target=reserve) for _ in range(3)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
print(json.dumps(results), flush=True)
"""


def test_fresh_processes_racing_at_the_reset_admit_exactly_the_new_window(admin, clock):
    reset, following = reset_for('UTC')
    configure('UTC')
    old = set(exhaust_old_window(clock, reset))
    # Two processes are exactly at the reset and two run a little after it.
    moments = [reset, reset, reset + 0.2, reset + 1]
    children = [subprocess.Popen([sys.executable, '-c', CHILD, repr(moment)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                for moment in moments]
    try:
        for child in children:
            assert child.stdout.readline().strip() == 'ready'
        for child in children:
            child.stdin.write('\n')
            child.stdin.flush()
        results = []
        for child in children:
            out, err = child.communicate(timeout=120)
            assert child.returncode == 0, err
            results += [tuple(value) for value in json.loads(out.strip().splitlines()[-1])]
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()

    assert len(results) == 12
    assert not [r for r in results if r[0] == 'error']
    admitted = [r[1] for r in results if r[0] == 'admitted']
    assert len(admitted) == len(set(admitted)) == K
    assert all(r[1] == following for r in results if r[0] == 'wait')
    rows = ledger()
    assert len(rows) == 2 * K
    assert all(rows[i].reset_at == following for i in admitted)
    assert {rows[i].reset_at for i in old} == {reset}
    assert counted(reset + 1) == CALL * K <= cap()
