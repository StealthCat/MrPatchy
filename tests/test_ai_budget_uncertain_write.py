from decimal import Decimal

import httpx
import pytest
from sqlalchemy import event

from app import ai, ai_budget, ai_provider_backoff, ai_runs
from app.db import Session, engine
from tests.test_ai_budget import configure, payload


@pytest.mark.parametrize('failure,backoff_expected', [
    (httpx.ReadTimeout, True),
    (httpx.ReadError, True),
    (ai.transport.ResponseTooLarge, False),
    (ai.transport.ResponseDecodeError, False),
])
def test_provider_uncertainty_uses_one_ledger_write(admin, monkeypatch, failure, backoff_expected):
    configure(cap=Decimal(1))
    transition = ai_budget.mark_uncertain
    statements = []

    def observe(connection, cursor, statement, parameters, context, executemany):
        if 'ai_budget_entries' in statement.lower():
            statements.append(statement.split(maxsplit=1)[0].upper())

    def observe_transition(*args):
        event.listen(engine, 'before_cursor_execute', observe)
        try:
            transition(*args)
        finally:
            event.remove(engine, 'before_cursor_execute', observe)

    def post(*args, **kwargs):
        if failure in (ai.transport.ResponseTooLarge, ai.transport.ResponseDecodeError):
            raise failure(httpx.Response(200, request=httpx.Request('POST', ai.URL)))
        raise failure('Private fixture transport detail.')

    monkeypatch.setattr(ai_budget, 'mark_uncertain', observe_transition)
    monkeypatch.setattr(ai.transport, 'post', post)
    with pytest.raises(ai.AIError), ai_runs.track('test', payload()['model']):
        ai.request(payload(), 'fixture-key')

    with Session() as session:
        row = session.query(ai_budget.BudgetEntry).one()
        assert row.status == 'uncertain' and row.actual_usd is None
        assert row.call_id and 'Private fixture transport detail' not in row.reason
        assert Decimal(ai_budget.status(session)['uncertain_usd']) == row.reservation_usd
        assert ai_provider_backoff.status(session)['blocked'] is backoff_expected
    assert statements == ['UPDATE']


@pytest.mark.parametrize('state', ['Sent', 'sent ', 'reserved', 'released', 'settled', 'uncertain'])
def test_uncertainty_preserves_ineligible_rows(admin, state):
    configure(cap=Decimal(1))
    identifier = ai_budget.reserve(payload())
    with Session() as session:
        row = session.get(ai_budget.BudgetEntry, identifier)
        row.status = state
        row.call_id = 'fixture'
        row.actual_usd = Decimal('0.00012') if state == 'settled' else None
        row.updated = 123.0
        row.reason = 'Original diagnosis.'
        session.commit()
        original = row.actual_usd, row.reservation_usd

    ai_budget.mark_uncertain(identifier, 'A later outcome was unavailable.')
    with Session() as session:
        row = session.get(ai_budget.BudgetEntry, identifier)
        assert (row.status, row.call_id, row.updated, row.reason) == (state, 'fixture', 123.0, 'Original diagnosis.')
        assert (row.actual_usd, row.reservation_usd) == original


def test_uncertainty_cannot_replace_a_later_settlement(admin):
    configure(cap=Decimal(1))
    identifier = ai_budget.reserve(payload())
    ai_budget.mark_sent(identifier, 'fixture')
    ai_budget.mark_uncertain(identifier, 'Provider outcome unknown.')
    amount = Decimal('0.00012')
    ai_budget.reconcile(identifier, {'status': 'estimated', 'pricing': {'estimated_usd': str(amount)}})
    ai_budget.mark_uncertain(identifier, 'Late timeout.')

    with Session() as session:
        row = session.get(ai_budget.BudgetEntry, identifier)
        assert row.status == 'settled' and row.actual_usd == amount
        assert Decimal(ai_budget.status(session)['counted_usd']) == amount
