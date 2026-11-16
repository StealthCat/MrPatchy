"""Acceptance: the daily spend ledger survives AI run-history pruning (#986).

Roadmap A milestone 4 requires "retained ledgers after history pruning". The
scheduler's hourly cleanup deletes finished AI runs and their calls, events and
host links. These tests run that exact deletion against ledger rows in every
status, linked to both pruned and retained runs, and check that capped
admission, reconciliation and retained spend history read the same afterwards.
"""
from datetime import datetime, timezone
from decimal import Decimal
import inspect

import pytest
from sqlalchemy import select

from app import ai_budget, ai_runs, worker
from app.ai_budget import BudgetEntry
from app.ai_runs import AICall, AIEvent, AIRun, AIRunHost
from app.db import Session, Setting

# A fixed afternoon so every entry's window is unambiguous.
NOW = datetime(2026, 11, 16, 15, 0, tzinfo=timezone.utc).timestamp()
DAY = 86400
CUTOFF = NOW - DAY  # history_days=1, the shortest retention an administrator can set
CAP = Decimal('1')


def configure(mode='daily_cap', cap=CAP):
    with Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': True, 'ai_model': 'gpt-6-luna', 'ai_control_mode': mode,
            'ai_rate_per_hour': 20, 'ai_daily_cap_usd': float(cap),
            'ai_budget_timezone': 'UTC', 'history_days': 1,
        }))
        session.commit()


def run(session, run_id, started, state='complete'):
    session.add(AIRun(id=run_id, purpose='triage', host_id='host-1', subject='fixture',
        model='gpt-6-luna', state=state, started=started, finished=started + 5, calls=1))
    session.add(AICall(id=f'call-{run_id}', run_id=run_id, number=1, created=started,
        requested_model='gpt-6-luna', status='estimated'))
    session.add(AIEvent(run_id=run_id, created=started, stage='complete', message='fixture'))
    session.add(AIRunHost(run_id=run_id, host_id='host-1'))


def entry(session, entry_id, run_id, created, status, reservation, actual=None):
    _start, reset = ai_budget._window(created, 'UTC')
    session.add(BudgetEntry(id=entry_id, run_id=run_id, call_id=f'call-{run_id}' if run_id else '',
        created=created, updated=created, reset_at=reset, timezone='UTC', model='gpt-6-luna',
        status=status, reservation_usd=Decimal(reservation),
        actual_usd=None if actual is None else Decimal(actual),
        pricing_version='fixture', pricing_source='fixture', reason='fixture'))


# Current window (UTC day of NOW) and an older retained window five days back.
# Runs started more than a day ago are pruned even when their spend is still in
# the current window or the 30-day history.
OLD_RUN = 'run-old'            # finished, started before the cutoff: pruned
OLD_RUNNING = 'run-old-live'   # still running, started before the cutoff: kept
RECENT_RUN = 'run-recent'      # started after the cutoff: kept
EARLIER_RUN = 'run-earlier'    # finished five days ago: pruned


def seed():
    early_today = datetime(2026, 11, 16, 0, 5, tzinfo=timezone.utc).timestamp()
    with Session() as session:
        run(session, OLD_RUN, CUTOFF - 3600)
        run(session, OLD_RUNNING, CUTOFF - 7200, state='running')
        run(session, RECENT_RUN, NOW - 600)
        run(session, EARLIER_RUN, NOW - 5 * DAY)
        # Today's window: every counted status, each linked to a run that is pruned.
        entry(session, 'settled-today', OLD_RUN, early_today, 'settled', '0.2', actual='0.05')
        entry(session, 'sent-today', OLD_RUN, early_today + 60, 'sent', '0.1')
        entry(session, 'sent-today-2', OLD_RUN, early_today + 90, 'sent', '0.1')
        entry(session, 'uncertain-today', OLD_RUN, early_today + 120, 'uncertain', '0.15')
        entry(session, 'reserved-today', OLD_RUNNING, early_today + 180, 'reserved', '0.25')
        entry(session, 'released-today', OLD_RUN, early_today + 240, 'released', '0.4')
        entry(session, 'settled-recent', RECENT_RUN, NOW - 600, 'settled', '0.3', actual='0.3')
        entry(session, 'unlinked-today', '', early_today + 300, 'settled', '0.05', actual='0.05')
        # Older retained window, linked to a pruned run.
        entry(session, 'settled-earlier', EARLIER_RUN, NOW - 5 * DAY, 'settled', '0.5', actual='0.45')
        entry(session, 'uncertain-earlier', EARLIER_RUN, NOW - 5 * DAY + 60, 'uncertain', '0.2')
        session.commit()


def ledger():
    with Session() as session:
        return {row.id: (row.run_id, row.call_id, row.created, row.updated, row.reset_at, row.timezone,
                         row.model, row.status, ai_budget._money(row.reservation_usd),
                         None if row.actual_usd is None else ai_budget._money(row.actual_usd),
                         row.pricing_version, row.pricing_source, row.reason)
                for row in session.scalars(select(BudgetEntry))}


def views():
    with Session() as session:
        state = ai_budget.status(session, NOW)
        retained = ai_budget.history(session, 30, NOW)
        return state, retained, ai_budget.history_csv(retained), ai_budget.waiting(session, NOW)


def prune():
    with Session() as session:
        ai_runs.prune_history(session, CUTOFF)
        session.commit()


def remaining_runs():
    with Session() as session:
        return ({row for row in session.scalars(select(AIRun.id))},
                {row for row in session.scalars(select(AICall.run_id))},
                {row for row in session.scalars(select(AIEvent.run_id))},
                {row for row in session.scalars(select(AIRunHost.run_id))})


@pytest.mark.parametrize('mode', ['daily_cap', 'rate_and_daily'])
def test_pruning_run_history_leaves_ledger_and_spend_views_unchanged(client, mode):
    configure(mode)
    seed()
    before_ledger, before_views = ledger(), views()

    prune()

    kept = {OLD_RUNNING, RECENT_RUN}
    assert remaining_runs() == (kept, kept, kept, kept)
    assert ledger() == before_ledger
    assert views() == before_views
    state, retained, _csv, _wait = before_views
    # Not a vacuous comparison: both windows and every counted status are present.
    # Today: settled 0.05+0.3+0.05, sent 0.1+0.1 and uncertain 0.15, reserved 0.25.
    assert (state['settled_usd'], state['uncertain_usd'], state['reserved_usd'], state['counted_usd']) == \
        ('0.4', '0.35', '0.25', '1')
    assert state['unreconciled_call_count'] == 3
    assert [window['counted_usd'] for window in retained['windows']] == ['1', '0.65']


def test_capped_admission_still_refuses_after_pruning_the_runs_that_spent(client):
    configure()
    seed()
    _start, reset = ai_budget._window(NOW, 'UTC')
    with Session() as session:
        assert ai_budget.waiting(session, NOW) == reset
    prune()
    with Session() as session:
        # The cap is reached by spend whose run history no longer exists.
        assert ai_budget.status(session, NOW)['remaining_usd'] == '0'
        assert ai_budget.waiting(session, NOW) == reset


def test_entries_whose_run_was_pruned_still_reconcile_release_and_mark_uncertain(client):
    configure()
    seed()
    prune()
    assert OLD_RUN not in remaining_runs()[0]

    ai_budget.reconcile('sent-today', {'status': 'estimated', 'pricing': {'estimated_usd': '0.02'}})
    ai_budget.mark_uncertain('sent-today-2', 'Worker restarted before a receipt arrived.')
    # A reservation whose run is still live can be released before transmission.
    ai_budget.release_unsent('reserved-today', 'Cancelled before provider transmission.')

    with Session() as session:
        settled = session.get(BudgetEntry, 'sent-today')
        assert (settled.status, ai_budget._money(settled.actual_usd)) == ('settled', '0.02')
        uncertain = session.get(BudgetEntry, 'sent-today-2')
        assert (uncertain.status, ai_budget._money(uncertain.reservation_usd)) == ('uncertain', '0.1')
        assert session.get(BudgetEntry, 'reserved-today').status == 'released'
        state = ai_budget.status(session, NOW)
    # 1 - 0.1 (reconciled down to 0.02) - 0.25 (released) = 0.67; the uncertain call stays counted in full.
    assert state['counted_usd'] == '0.67'
    assert state['uncertain_usd'] == '0.25'
    assert state['unreconciled_call_count'] == 2


def test_pruning_keeps_running_and_recent_runs_and_ignores_unlinked_ledger_rows(client):
    configure()
    seed()
    before = ledger()
    prune()
    prune()  # idempotent: a second hourly pass changes nothing
    assert remaining_runs()[0] == {OLD_RUNNING, RECENT_RUN}
    assert ledger() == before
    assert before['unlinked-today'][0] == ''


def test_scheduler_cleanup_uses_the_tested_prune_function():
    source = inspect.getsource(worker._loop)
    assert 'ai_runs.prune_history(s,cutoff)' in source
    # No second, untested copy of the run-history deletion remains in the scheduler.
    assert 'delete(ai_runs.' not in source
