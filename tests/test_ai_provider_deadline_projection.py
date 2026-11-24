"""Hot paths need only the active provider deadline."""

from contextlib import contextmanager

import pytest
from sqlalchemy import Select, event
from sqlalchemy.sql import visitors

from app import ai, ai_provider_backoff as backoff, worker
from app.db import Session, engine
from tests.test_ai_claims import result, seed


@contextmanager
def backoff_projections():
    projections = []
    table = backoff.ProviderBackoff.__table__

    def record(conn, cursor, statement, parameters, context, executemany):
        query = getattr(context.compiled, 'statement', None)
        if query is None or not query.is_select:
            return
        for select_node in visitors.iterate(query):
            if not isinstance(select_node, Select):
                continue
            columns = tuple(select_node.selected_columns)
            if any(getattr(column, 'table', None) is table for column in columns):
                projections.append(tuple(column.key for column in columns))

    event.listen(engine, 'before_cursor_execute', record)
    try:
        yield projections
    finally:
        event.remove(engine, 'before_cursor_execute', record)


@pytest.mark.parametrize(
    'deadline, expected', [(None, 0), (999.75, 0), (1000.0, 0), (1000.25, 1000.25)],
    ids=['missing', 'expired', 'at-boundary', 'active'],
)
def test_wait_and_admit_read_only_the_active_global_deadline(client, deadline, expected):
    now = 1000.0
    with Session() as session:
        session.add(backoff.ProviderBackoff(id='unrelated', blocked_until=3000.0))
        if deadline is not None:
            session.add(backoff.ProviderBackoff(id='global', blocked_until=deadline, failures=5,
                                                updated=900.0, reason=backoff.TRANSIENT_REASON))
        session.commit()

    with backoff_projections() as projections:
        with Session() as session:
            assert backoff.waiting(session, now) == expected
        if expected:
            with pytest.raises(ai.AIError) as refused:
                backoff.admit(now)
            assert refused.value.policy_wait
            assert refused.value.provider_wait_until == expected
            assert refused.value.retry_after == pytest.approx(expected - now)
        else:
            backoff.admit(now)

    assert projections == [('blocked_until',), ('blocked_until',)]
    if expected:
        with Session() as session:
            status = backoff.status(session, now)
        assert status['reason'] == backoff.TRANSIENT_REASON
        assert status['failures'] == 5 and status['updated_at'] == 900.0
        assert status['revision']


def test_legacy_triage_election_and_paid_request_read_only_the_deadline(client, monkeypatch):
    seed(count=1)
    sent = []

    def respond(*args, **kwargs):
        sent.append(kwargs['json'])
        return result()

    monkeypatch.setattr(ai.transport, 'post', respond)
    with backoff_projections() as projections:
        worker.investigate_one()

    assert len(sent) == 1
    # Triage can read the deadline directly or test existence inside the shared gate.
    # The provider guard still reads the deadline and success checks for a reset.
    assert len(projections) == 3
    assert projections[0] in (('blocked_until',), ('id',))
    assert projections[1:] == [('blocked_until',), ('id',)]
