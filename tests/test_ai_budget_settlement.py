from decimal import Decimal

import httpx
import pytest
from sqlalchemy import event

from app import ai, ai_budget, ai_pricing, ai_runs
from app.db import Session, engine
from tests.test_ai_budget import configure, payload
from tests.test_ai_budget_unknown_usage_acceptance import body


@pytest.mark.parametrize('priced', [True, False])
def test_provider_receipt_settlement_uses_one_ledger_write(admin, monkeypatch, priced):
    configure(cap=Decimal(1))
    request = payload()
    response = body() if priced else body(usage=None)
    estimate = ai_pricing.estimate(response, request)
    settled = ai_budget.reconcile
    statements = []

    def observe(connection, cursor, statement, parameters, context, executemany):
        if 'ai_budget_entries' in statement.lower():
            statements.append(statement.split(maxsplit=1)[0].upper())

    def observe_settlement(*args):
        event.listen(engine, 'before_cursor_execute', observe)
        try:
            settled(*args)
        finally:
            event.remove(engine, 'before_cursor_execute', observe)

    monkeypatch.setattr(ai_budget, 'reconcile', observe_settlement)
    monkeypatch.setattr(ai.transport, 'post', lambda *args, **kwargs: httpx.Response(
        200, json=response, request=httpx.Request('POST', ai.URL),
    ))
    with ai_runs.track('test', request['model']):
        result = ai.request(request, 'fixture-key')
    assert result['explanation'] == 'Fixture'

    with Session() as session:
        row = session.query(ai_budget.BudgetEntry).one()
        counted = Decimal(ai_budget.status(session)['counted_usd'])
        if priced:
            assert row.status == 'settled'
            assert row.actual_usd == counted == Decimal(estimate['pricing']['estimated_usd'])
        else:
            assert row.status == 'uncertain'
            assert row.actual_usd is None and counted == row.reservation_usd
        assert row.call_id
    assert statements == ['UPDATE']


@pytest.mark.parametrize('amount', ['NaN', 'sNaN', 'Infinity', '-Infinity'])
def test_nonfinite_estimate_retains_uncertain_reservation(admin, amount):
    configure(cap=Decimal(1))
    identifier = ai_budget.reserve(payload())
    ai_budget.mark_sent(identifier, 'fixture')
    ai_budget.reconcile(identifier, {'status': 'estimated', 'pricing': {'estimated_usd': amount}})

    with Session() as session:
        row = session.get(ai_budget.BudgetEntry, identifier)
        assert row.status == 'uncertain'
        assert row.actual_usd is None
        assert Decimal(ai_budget.status(session)['counted_usd']) == row.reservation_usd


@pytest.mark.parametrize('status', ['reserved', 'released', 'settled', 'Sent', 'sent ', 'Uncertain'])
def test_settlement_preserves_ineligible_rows(admin, status):
    configure(cap=Decimal(1))
    identifier = ai_budget.reserve(payload())
    with Session() as session:
        row = session.get(ai_budget.BudgetEntry, identifier)
        row.status = status
        row.updated = 123.0
        row.reason = 'Original diagnosis.'
        session.commit()

    ai_budget.reconcile(identifier, {'status': 'estimated', 'pricing': {'estimated_usd': '0.00012'}})
    with Session() as session:
        row = session.get(ai_budget.BudgetEntry, identifier)
        assert (row.status, row.updated, row.reason, row.actual_usd) == (
            status, 123.0, 'Original diagnosis.', None,
        )


def test_late_usage_settles_uncertainty_and_later_reconciliation_is_ignored(admin):
    configure(cap=Decimal(1))
    identifier = ai_budget.reserve(payload())
    ai_budget.mark_sent(identifier, 'fixture')
    ai_budget.mark_uncertain(identifier, 'Provider outcome unknown.')
    ai_budget.reconcile(identifier, {'status': 'estimated', 'pricing': {'estimated_usd': '0.00012'}})
    with Session() as session:
        row = session.get(ai_budget.BudgetEntry, identifier)
        assert row.status == 'settled' and row.actual_usd == Decimal('0.00012')
        stable = row.updated, row.reason, row.actual_usd

    ai_budget.reconcile(identifier, {'status': 'unavailable', 'reason': 'Late duplicate.'})
    with Session() as session:
        row = session.get(ai_budget.BudgetEntry, identifier)
        assert row.status == 'settled'
        assert (row.updated, row.reason, row.actual_usd) == stable
