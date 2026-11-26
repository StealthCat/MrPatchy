from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from threading import Barrier

import httpx
import pytest
from sqlalchemy import event, select

from app import ai, ai_budget, ai_runs
from app.db import Session, engine
from tests.test_ai_budget import configure, payload


def test_capped_provider_starts_after_one_committed_sent_write(admin, monkeypatch):
    configure(cap=Decimal('1'))
    transitions = []
    transmitted = []
    mark_sent = ai_budget.mark_sent

    def observe(conn, cursor, statement, parameters, context, executemany):
        if 'ai_budget_entries' in statement.lower():
            transitions.append(statement.split()[0].upper())

    def track_sent_write(identifier, call_id):
        event.listen(engine, 'before_cursor_execute', observe)
        try:
            mark_sent(identifier, call_id)
        finally:
            event.remove(engine, 'before_cursor_execute', observe)

    def provider(*args, **kwargs):
        # A fresh connection can see the committed charge and its receipt.
        with Session() as session:
            row = session.scalars(select(ai_budget.BudgetEntry)).one()
            receipt = session.get(ai_runs.AICall, row.call_id)
            assert row.status == 'sent'
            assert row.updated >= row.created
            assert 'Provider transmission began' in row.reason
            assert receipt is not None and receipt.number == 1
            assert receipt.run_id == row.run_id
            transmitted.append(row.id)
        return httpx.Response(200, request=httpx.Request('POST', ai.URL), json={
            'status': 'completed', 'model': 'gpt-6-luna', 'service_tier': 'default',
            'usage': {'input_tokens': 100, 'output_tokens': 30,
                      'input_tokens_details': {'cached_tokens': 0, 'cache_write_tokens': 0}},
            'output': [{'type': 'message', 'content': [{'type': 'output_text', 'text': '{"ok":true}'}]}],
        })

    monkeypatch.setattr(ai_budget, 'mark_sent', track_sent_write)
    monkeypatch.setattr(ai.transport, 'post', provider)
    with ai_runs.track('connection_test', 'gpt-6-luna') as run_id:
        assert ai.request(payload(), 'fixture-key') == {'ok': True}
    assert len(transmitted) == 1
    with Session() as session:
        row = session.get(ai_budget.BudgetEntry, transmitted[0])
        assert row.status == 'settled' and row.run_id == run_id
        assert Decimal(0) < row.actual_usd < row.reservation_usd
    assert transitions == ['UPDATE']


@pytest.mark.parametrize('retained_status', [
    None, 'released', 'sent', 'settled', 'uncertain', 'RESERVED', 'reserved ', 'legacy_pending',
    pytest.param(b'reserved', id='sqlite-blob'),
])
def test_stale_or_ineligible_reservation_stops_provider(admin, monkeypatch, retained_status):
    if isinstance(retained_status, bytes) and engine.dialect.name != 'sqlite':
        pytest.skip('Only SQLite can retain a BLOB in the text status column.')
    configure(cap=Decimal('1'))
    reserve = ai_budget.reserve
    reservations = []
    transmitted = []

    def change_before_send(request):
        identifier = reserve(request)
        reservations.append(identifier)
        with Session() as session:
            row = session.get(ai_budget.BudgetEntry, identifier)
            if retained_status is None:
                session.delete(row)
            else:
                row.status = retained_status
            session.commit()
        return identifier

    monkeypatch.setattr(ai_budget, 'reserve', change_before_send)
    monkeypatch.setattr(ai.transport, 'post', lambda *args, **kwargs: transmitted.append(True))
    with pytest.raises(RuntimeError, match='reservation changed before provider transmission'):
        ai.request(payload(), 'fixture-key')
    assert transmitted == []
    with Session() as session:
        row = session.get(ai_budget.BudgetEntry, reservations[0])
        if retained_status is None:
            assert row is None
        else:
            assert row.status == retained_status
            assert row.call_id == ''


def test_two_workers_cannot_mark_one_reservation_sent_twice(admin):
    configure(cap=Decimal('1'))
    reservation = ai_budget.reserve(payload())
    barrier = Barrier(2)

    def mark(call_id):
        barrier.wait(timeout=10)
        try:
            ai_budget.mark_sent(reservation, call_id)
        except RuntimeError as error:
            assert 'reservation changed before provider transmission' in str(error)
            return None
        return call_id

    with ThreadPoolExecutor(max_workers=2) as workers:
        accepted = [call_id for call_id in workers.map(mark, ('call-a', 'call-b')) if call_id is not None]
    assert len(accepted) == 1
    with Session() as session:
        row = session.get(ai_budget.BudgetEntry, reservation)
        assert row.status == 'sent'
        assert row.call_id == accepted[0]
