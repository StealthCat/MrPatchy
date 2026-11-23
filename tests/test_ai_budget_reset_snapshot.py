from decimal import Decimal

import pytest
from sqlalchemy import event

from app import ai_budget
from app.db import Session
from tests.test_ai_budget import DAY, configure


def entry(identifier, created, reset, *, status='reserved', reserved='1', actual=None):
    return ai_budget.BudgetEntry(
        id=identifier, created=created, updated=created, reset_at=reset,
        timezone='America/New_York', model='fixture', status=status,
        reservation_usd=Decimal(reserved), actual_usd=Decimal(actual) if actual is not None else None,
        pricing_version='fixture', pricing_source='fixture',
    )


def test_budget_reset_and_counted_spend_share_one_snapshot(admin):
    configure(cap=Decimal('2'))
    now = DAY + 60
    reset = DAY + 86400
    with Session() as writer:
        writer.add_all([
            entry('carryover', DAY - 60, reset + 3600),
            entry('outstanding', now, reset, status='sent', reserved='0.25'),
        ])
        writer.commit()

    statements = []

    def release_after_first_ledger_read(state):
        if not state.is_select or 'FROM ai_budget_entries' not in str(state.statement):
            return None
        statements.append(state.statement)
        if len(statements) > 1:
            return None
        # Finish the first read before a separate connection commits the release.
        snapshot = state.invoke_statement().freeze()
        ai_budget.release_unsent('carryover', 'Fixture released before transmission.')
        return snapshot()

    with Session() as reader:
        if reader.get_bind().dialect.name == 'mysql':
            reader.connection(execution_options={'isolation_level': 'READ COMMITTED'})
        event.listen(reader, 'do_orm_execute', release_after_first_ledger_read, retval=True)
        result = ai_budget.status(reader, now)

    assert result['counted_usd'] == '1.25'
    assert result['reserved_usd'] == '1'
    assert result['unreconciled_call_count'] == 1
    assert result['oldest_unreconciled_reservation_at'] == now
    assert result['next_reset'] == reset
    assert result['next_reset_authoritative'] is False
    assert len(statements) == 1

    with Session() as reader:
        refreshed = ai_budget.status(reader, now)
    assert refreshed['counted_usd'] == '0.25'
    assert refreshed['reserved_usd'] == '0'
    assert refreshed['next_reset_authoritative'] is True


@pytest.mark.parametrize('status,reserved,actual,created_offset,reset_offset,expected', [
    ('reserved', '1', None, -60, 3600, False),
    ('legacy_pending', '1', None, -60, 3600, False),
    ('settled', '1', '0.000000001', -60, 3600, False),
    ('settled', '1', '0', -60, 3600, True),
    ('reserved', '0', None, -60, 3600, True),
    ('released', '1', None, -60, 3600, True),
    ('reserved', '1', None, -60, 0, True),
    ('reserved', '1', None, 61, 3600, True),
])
def test_only_observed_positive_spend_beyond_configured_reset_is_carryover(
    admin, status, reserved, actual, created_offset, reset_offset, expected,
):
    configure(cap=Decimal('2'))
    now = DAY + 60
    reset = DAY + 86400
    with Session() as session:
        session.add(entry('boundary', DAY + created_offset, reset + reset_offset,
                          status=status, reserved=reserved, actual=actual))
        session.commit()
        result = ai_budget.status(session, now)
    assert result['next_reset'] == reset
    assert result['next_reset_authoritative'] is expected
