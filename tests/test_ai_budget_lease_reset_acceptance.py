"""Roadmap A milestone 4: a triage lease lost while its daily-cap call straddles the reset.

A worker reserves and sends a capped call in one budget window, then loses its lease
after the calendar-day reset. These tests drive the real worker path
(``worker.investigate_one``) with only the provider transport and SSH replaced. They
check that the lost call's charge stays in the window it was admitted under, that the
successor reserves only against the new window, that the late answer or failure is
reconciled into the lost call's own row without moving it, and that nothing from the
stale run is accepted.
"""
import time
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_assessments, ai_budget, ai_runs, worker
from app.db import Behavior, Session
from tests.test_ai_budget_lease_acceptance import (
    EVIDENCE,
    MODEL,
    SUBJECT,
    WAIT,
    Provider,
    expire_lease,
    first_quote,
    ledger,
    seed,
    ssh,  # noqa: F401 - pytest fixture
    start,
)


def cross_reset(monkeypatch):
    """Advance every thread's clock just past the current window's reset."""
    with Session() as s:
        reset=ai_budget.status(s)['next_reset']
    real=time.time;shift=reset-real()+5
    monkeypatch.setattr(time,'time',lambda:real()+shift)
    return reset


def new_window(s):
    state=ai_budget.status(s)
    return Decimal(state['counted_usd']),ai_budget.waiting(s,time.time(),ai.investigation_payload(EVIDENCE,MODEL))


@pytest.mark.parametrize('late',['answer','failure'])
def test_lost_call_keeps_its_window_and_successor_uses_only_the_new_one(admin,monkeypatch,ssh,late):  # noqa: F811
    # Each window has room for exactly one conservative reservation, so the successor
    # is admitted only if the lost call's charge is not counted in the new window.
    quote=first_quote();cap=quote*Decimal('1.5')
    seed(cap=cap)
    failure=httpx.ReadError('connection lost') if late=='failure' else None
    provider=Provider(hold_first=True,failure=failure);monkeypatch.setattr(ai.transport,'post',provider)
    lost=start(worker.investigate_one)
    assert provider.in_flight.wait(timeout=WAIT)
    with Session() as s:
        [held]=ledger(s);old_reset=held.reset_at;ceiling=held.reservation_usd
        assert held.status=='sent' and Decimal(ai_budget.status(s)['counted_usd'])==ceiling
        # A second reservation would not fit in this window.
        assert ceiling*2>cap
    # The reset passes while the call is still in flight, then the heartbeat is lost.
    assert cross_reset(monkeypatch)==old_reset
    lost_run=expire_lease()
    with Session() as s:
        state=ai_budget.status(s)
        assert state['next_reset']>old_reset and Decimal(state['counted_usd'])==0
    worker.investigate_one()
    with Session() as s:
        successor=s.scalars(select(ai_assessments.Assessment)).one().run_id
        assert successor!=lost_run and s.get(ai_runs.AIRun,lost_run).state=='interrupted'
        rows=ledger(s);new_reset=ai_budget.status(s)['next_reset']
        assert [(row.run_id,row.reset_at) for row in rows]==[(lost_run,old_reset),(successor,new_reset)]
        before=new_window(s)
        assert before[0]==rows[1].actual_usd
    # The late answer or failure reaches the lost worker only now.
    provider.release.set();lost.join(timeout=WAIT);assert not lost.is_alive()
    assert [run for run,_ in provider.sent]==[lost_run,successor]
    with Session() as s:
        rows=ledger(s)
        # The late outcome is reconciled into the lost call's own row, which keeps the
        # window it was admitted under; the reset never releases a possibly billed call.
        expected='settled' if late=='answer' else 'uncertain'
        assert [(row.run_id,row.status,row.reset_at) for row in rows]==[
            (lost_run,expected,old_reset),(successor,'settled',new_reset)]
        if late=='failure':assert rows[0].actual_usd is None
        # The new window's counted spend and next eligibility are unchanged by it.
        assert new_window(s)==before
        state=ai_budget.status(s)
        assert Decimal(state['uncertain_usd'])==0 and Decimal(state['reserved_usd'])==0
        # The old window still reports the lost call: its settled cost or full ceiling.
        windows={row['reset_at']:row for row in ai_budget.history(s,days=2)['windows']}
        old=windows[old_reset]
        assert old['call_count']==1
        if late=='answer':
            assert Decimal(old['settled_usd'])==rows[0].actual_usd==Decimal(old['counted_usd'])
        else:
            assert Decimal(old['uncertain_usd'])==ceiling==Decimal(old['counted_usd'])
        assert Decimal(windows[new_reset]['counted_usd'])==rows[1].actual_usd
        # Only the successor's result is accepted; the stale run changes nothing.
        assessment=s.scalars(select(ai_assessments.Assessment)).one()
        assert assessment.run_id==successor
        assert s.get(ai_runs.AIRun,lost_run).state=='interrupted'
        assert s.get(ai_runs.AIRun,successor).state=='complete'
        behavior=s.get(Behavior,SUBJECT);assert behavior.verdict=='low' and not behavior.approved
