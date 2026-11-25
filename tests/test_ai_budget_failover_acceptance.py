"""Daily-cap admission failover when the admitting process dies (#1285, roadmap A milestone 4).

Every capped reservation is admitted under the fleet-wide ``ai-shared-budget`` lock. These
tests run the real ``ai_budget.reserve()`` in a child process, stop it while it holds that
lock, kill it with SIGKILL and let this process take over admission. The lock is a file
lock on SQLite and a ``GET_LOCK`` named lock on MySQL; both are released by the operating
system or the server when the holder dies, so nothing here clears it by hand.

They change no runtime behavior.
"""
import os
from pathlib import Path
import signal
import subprocess
import sys
import textwrap
import time

import pytest
from sqlalchemy import select

from app import ai, ai_budget, ai_pricing
from app.coordination import Lock
from app.db import Session
from tests.test_ai_budget import configure, payload

pytestmark = pytest.mark.skipif(not hasattr(signal, 'SIGKILL'), reason='needs POSIX SIGKILL')

ROOT = Path(__file__).resolve().parents[1]
WAIT = 60

# The child pins the same fresh price catalog as the suite, then wraps the session the
# reservation commits through. ``before`` stops after the row is added but before the
# commit; ``after`` stops after the commit, before the lock is released. Either way it
# reports its pid and then sleeps until it is killed.
CHILD = textwrap.dedent('''
    import os, sys, time
    import pytest
    from tests.pricing_catalog import pin_fresh_pricing_catalog
    from tests.test_ai_budget import payload
    from app import ai_budget

    stage, ready = sys.argv[1], sys.argv[2]
    patch = pytest.MonkeyPatch()
    pin_fresh_pricing_catalog(patch)
    real_session = ai_budget.Session

    def hold():
        with open(ready + '.tmp', 'w') as stream:
            stream.write(str(os.getpid()))
        os.replace(ready + '.tmp', ready)
        time.sleep(600)

    def held_session():
        session = real_session()
        commit = session.commit
        def stopping_commit():
            if stage == 'before':
                hold()
            commit()
            if stage == 'after':
                hold()
        session.commit = stopping_commit
        return session

    patch.setattr(ai_budget, 'Session', held_session)
    ai_budget.reserve(payload())
    sys.exit(3)
''')


def amount():
    quote = ai_pricing.reservation(payload())
    assert quote['ok'], quote
    return quote['amount_usd']


def rows():
    with Session() as session:
        return list(session.scalars(select(ai_budget.BudgetEntry).order_by(ai_budget.BudgetEntry.created)))


def lock_is_free():
    lock = Lock('ai-shared-budget')
    if not lock.acquire(blocking=False):
        return False
    lock.release()
    return True


def kill_while_holding(tmp_path, stage):
    """Start an admitting child, stop it inside the budget lock and SIGKILL it."""
    ready = tmp_path / ('ready-' + stage)
    child = subprocess.Popen([sys.executable, '-c', CHILD, stage, str(ready)], cwd=ROOT,
                             env=dict(os.environ), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + WAIT
        while not ready.exists():
            if child.poll() is not None:
                out, err = child.communicate()
                pytest.fail('admitting child exited early (%s): %s %s' % (child.returncode, out[-2000:], err[-2000:]))
            assert time.monotonic() < deadline, 'admitting child never reached the budget lock'
            time.sleep(0.02)
        assert int(ready.read_text()) == child.pid
        # The child really holds the fleet-wide admission lock at the moment it dies.
        assert not lock_is_free()
        child.send_signal(signal.SIGKILL)
        child.wait(WAIT)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(WAIT)
        child.stdout.close()
        child.stderr.close()
    assert child.returncode == -signal.SIGKILL


def take_over():
    """The successor's lock wait is bounded: a stranded lock fails here instead of hanging."""
    deadline = time.monotonic() + WAIT
    while not lock_is_free():
        assert time.monotonic() < deadline, 'the dead admitter stranded the shared budget lock'
        time.sleep(0.05)


def test_admitter_killed_before_commit_leaves_no_row_and_the_successor_admits(client, tmp_path):
    configure(cap=amount() * 3 / 2)
    kill_while_holding(tmp_path, 'before')
    assert rows() == []
    take_over()

    identifier = ai_budget.reserve(payload())

    entries = rows()
    assert [row.id for row in entries] == [identifier]
    assert entries[0].status == 'reserved' and entries[0].reservation_usd == amount()
    with Session() as session:
        summary = ai_budget.status(session)
    assert summary['counted_usd'] == ai_budget._money(amount())
    # The successor's own reservation fills the window; nothing from the dead process
    # was retained, so nothing else is counted and a further admission is refused.
    with pytest.raises(ai.AIError) as refused:
        ai_budget.reserve(payload())
    assert refused.value.policy_wait
    assert len(rows()) == 1


def test_admitter_killed_after_commit_keeps_its_reservation_counted(client, tmp_path):
    configure(cap=amount() * 3 / 2)
    kill_while_holding(tmp_path, 'after')
    take_over()

    entries = rows()
    assert len(entries) == 1
    dead = entries[0]
    assert dead.status == 'reserved' and dead.reservation_usd == amount()
    assert dead.reset_at > time.time()

    # Only one reservation fits the cap, and the dead process already holds it. The
    # successor is held until the reset, sends nothing and writes no row.
    with pytest.raises(ai.AIError) as refused:
        ai_budget.reserve(payload())
    assert refused.value.policy_wait
    assert refused.value.budget_wait_until == dead.reset_at
    assert 0 < refused.value.retry_after <= dead.reset_at - time.time() + 1

    after = rows()
    assert [(row.id, row.status) for row in after] == [(dead.id, 'reserved')]
    with Session() as session:
        summary = ai_budget.status(session)
    assert summary['counted_usd'] == ai_budget._money(amount())


def test_successor_admits_beside_a_dead_reservation_when_headroom_remains(client, tmp_path):
    configure(cap=amount() * 5 / 2)
    kill_while_holding(tmp_path, 'after')
    take_over()

    identifier = ai_budget.reserve(payload())

    after = rows()
    assert len(after) == 2 and identifier in {row.id for row in after}
    assert all(row.status == 'reserved' for row in after)
    with Session() as session:
        summary = ai_budget.status(session)
    # Both reservations count: the dead one is never released or double-counted.
    assert summary['counted_usd'] == ai_budget._money(amount() * 2)
    with pytest.raises(ai.AIError) as refused:
        ai_budget.reserve(payload())
    assert refused.value.policy_wait
