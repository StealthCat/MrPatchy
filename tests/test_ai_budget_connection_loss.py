"""Capped provider admission when a reservation commit loses its connection."""

from decimal import Decimal

import httpx
import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import DBAPIError

from app import ai, ai_budget, ai_pricing
from app.db import Session, engine
from tests.test_ai_budget import configure, payload


@pytest.mark.parametrize('commit_reached_database', [False, True], ids=['rollback', 'lost-acknowledgement'])
def test_capped_admission_recovers_after_reservation_connection_loss(
        client, monkeypatch, commit_reached_database):
    request = payload()
    quote = ai_pricing.reservation(request)['amount_usd']
    configure(cap=quote * 2)
    previous = ai_budget.reserve(request)
    ai_budget.mark_sent(previous, 'earlier-call')
    ai_budget.mark_uncertain(previous, 'The earlier provider outcome is unknown.')

    transmissions = []

    def respond(*args, **kwargs):
        transmissions.append(kwargs['json'])
        return httpx.Response(200, request=httpx.Request('POST', ai.URL), json={
            'status': 'completed',
            'model': request['model'],
            'service_tier': request['service_tier'],
            'usage': {
                'input_tokens': 10, 'output_tokens': 10, 'total_tokens': 20,
                'input_tokens_details': {'cached_tokens': 0, 'cache_write_tokens': 0},
            },
            'output': [{'content': [{'type': 'output_text', 'text': '{"accepted":true}'}]}],
        })

    monkeypatch.setattr(ai.transport, 'post', respond)
    commit = engine.dialect.do_commit
    reservation_connection = None

    def track_reservation(connection, cursor, statement, parameters, context, executemany):
        nonlocal reservation_connection
        if context.isinsert and context.compiled.statement.table is ai_budget.BudgetEntry.__table__:
            reservation_connection = connection.connection.dbapi_connection

    def lose_connection(connection):
        if connection.dbapi_connection is reservation_connection:
            if commit_reached_database:
                commit(connection)
            if engine.dialect.name == 'mysql':
                # End only the disposable session that inserted the reservation.
                # Using another connection lets the driver observe server-side loss.
                with engine.connect() as control:
                    control.exec_driver_sql('KILL CONNECTION %s', (reservation_connection.thread_id(),))
            else:
                reservation_connection.close()
        commit(connection)

    with monkeypatch.context() as commit_fault:
        commit_fault.setattr(engine.dialect, 'do_commit', lose_connection)
        event.listen(engine, 'before_cursor_execute', track_reservation)
        try:
            with pytest.raises(DBAPIError) as lost:
                ai.request(request, 'fixture-key')
        finally:
            event.remove(engine, 'before_cursor_execute', track_reservation)

    assert reservation_connection is not None
    assert lost.value.connection_invalidated
    assert transmissions == []
    with Session() as session:
        earlier = session.get(ai_budget.BudgetEntry, previous)
        assert (earlier.status, earlier.call_id) == ('uncertain', 'earlier-call')
        assert earlier.reservation_usd == quote
        state = ai_budget.status(session)
        assert Decimal(state['uncertain_usd']) == quote
        assert Decimal(state['remaining_usd']) == (0 if commit_reached_database else quote)
        pending = session.scalars(select(ai_budget.BudgetEntry).where(
            ai_budget.BudgetEntry.id != previous)).all()
        if commit_reached_database:
            assert len(pending) == 1
            assert (pending[0].status, pending[0].call_id, pending[0].reservation_usd) == ('reserved', '', quote)
            unconfirmed = pending[0].id
        else:
            assert pending == []

    if commit_reached_database:
        with pytest.raises(ai.AIError) as deferred:
            ai.request(request, 'fixture-key')
        assert deferred.value.policy_wait
        assert deferred.value.budget_wait_until == state['next_reset']
        assert transmissions == []
        with Session() as session:
            assert set(session.scalars(select(ai_budget.BudgetEntry.id))) == {previous, unconfirmed}
    else:
        assert ai.request(request, 'fixture-key') == {'accepted': True}
        assert transmissions == [request]
        with Session() as session:
            settled = session.scalars(select(ai_budget.BudgetEntry).where(
                ai_budget.BudgetEntry.id != previous)).one()
            assert settled.status == 'settled'
            assert 0 < settled.actual_usd <= quote
            assert Decimal(ai_budget.status(session)['counted_usd']) == quote + settled.actual_usd
