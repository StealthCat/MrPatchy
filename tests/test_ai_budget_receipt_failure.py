"""Parsed provider usage can settle the ledger independently of its diagnostic receipt."""
from contextlib import contextmanager
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import event, select

from app import ai, ai_budget, ai_pricing, ai_runs
from app.db import Session, engine
from tests.test_ai_budget import configure, payload
from tests.test_ai_budget_unknown_usage_acceptance import body


class FixtureWriteFailure(RuntimeError):
    pass


@contextmanager
def reject_update(table, field):
    writes = []

    def reject(conn, cursor, statement, parameters, context, executemany):
        sql = statement.lower()
        if sql.startswith(f'update {table} set') and field in sql:
            writes.append(table)
            raise FixtureWriteFailure(f'Unable to persist {table}.')

    event.listen(engine, 'before_cursor_execute', reject)
    try:
        yield writes
    finally:
        event.remove(engine, 'before_cursor_execute', reject)


def stub_provider(monkeypatch, returned):
    calls = []

    def post(*args, **kwargs):
        calls.append(1)
        return httpx.Response(200, json=returned, request=httpx.Request('POST', ai.URL))

    monkeypatch.setattr(ai.transport, 'post', post)
    return calls


@pytest.mark.parametrize('mode', ['daily_cap', 'rate_and_daily'])
@pytest.mark.parametrize('priced', [True, False])
def test_diagnostic_write_failure_still_reconciles_provider_spend(admin, monkeypatch, mode, priced):
    request = payload()
    returned = body() if priced else body(usage=None)
    ceiling = ai_pricing.reservation(request)['amount_usd']
    cap = ceiling * Decimal('1.5')
    configure(mode=mode, cap=cap)
    calls = stub_provider(monkeypatch, returned)

    with reject_update('ai_calls', 'response_model') as writes:
        with pytest.raises(FixtureWriteFailure, match='Unable to persist ai_calls'):
            with ai_runs.track('connection_test', request['model']) as run_id:
                ai.request(request, 'fixture-key')

    assert calls == [1] and writes == ['ai_calls']
    with Session() as session:
        ledger = session.scalars(select(ai_budget.BudgetEntry)).one()
        diagnostic = session.get(ai_runs.AICall, ledger.call_id)
        run = session.get(ai_runs.AIRun, run_id)
        totals = ai_budget.status(session)
        assert run.state == 'error' and run.calls == 1
        assert diagnostic.status == 'unavailable' and not diagnostic.pricing
        if priced:
            actual = Decimal(ai_pricing.estimate(returned, request)['pricing']['estimated_usd'])
            assert Decimal(0) < actual < ceiling / 2
            assert (ledger.status, ledger.actual_usd) == ('settled', actual)
            assert Decimal(totals['counted_usd']) == actual
            assert totals['unreconciled_call_count'] == 0
        else:
            assert (ledger.status, ledger.actual_usd) == ('uncertain', None)
            assert Decimal(totals['counted_usd']) == ceiling
            assert totals['unreconciled_call_count'] == 1

    if priced:
        assert ai_budget.reserve(request)
    else:
        with pytest.raises(ai.AIError, match='no remaining safe reservation'):
            ai_budget.reserve(request)
    assert calls == [1]


def test_ledger_write_failure_keeps_sent_charge_and_saved_diagnostic(admin, monkeypatch):
    request = payload()
    returned = body()
    ceiling = ai_pricing.reservation(request)['amount_usd']
    configure(cap=ceiling)
    calls = stub_provider(monkeypatch, returned)

    with reject_update('ai_budget_entries', 'actual_usd') as writes:
        with pytest.raises(FixtureWriteFailure, match='Unable to persist ai_budget_entries'):
            with ai_runs.track('connection_test', request['model']) as run_id:
                ai.request(request, 'fixture-key')

    assert calls == [1] and writes == ['ai_budget_entries']
    with Session() as session:
        ledger = session.scalars(select(ai_budget.BudgetEntry)).one()
        diagnostic = session.get(ai_runs.AICall, ledger.call_id)
        assert session.get(ai_runs.AIRun, run_id).state == 'error'
        assert (ledger.status, ledger.actual_usd) == ('sent', None)
        assert Decimal(ai_budget.status(session)['counted_usd']) == ceiling
        assert diagnostic.status == 'estimated'
        assert diagnostic.pricing == ai_pricing.estimate(returned, request)['pricing']
    with pytest.raises(ai.AIError, match='no remaining safe reservation'):
        ai_budget.reserve(request)
