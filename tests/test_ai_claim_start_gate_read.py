import pytest
from sqlalchemy import event

from app import ai_admission, ai_claims, ai_provider_backoff
from app.db import Session, Setting, engine
from tests.test_ai_claims import seed


@pytest.mark.parametrize('mode,rate_blocked,provider_blocked,claim_expected', [
    ('rate', False, False, True),
    ('rate', True, False, False),
    ('rate', False, True, False),
    ('rate', True, True, False),
    ('unthrottled', True, False, True),
    ('unthrottled', True, True, False),
    ('rate', None, None, True),
])
def test_claim_checks_both_shared_gates_with_one_read(
    admin, monkeypatch, mode, rate_blocked, provider_blocked, claim_expected,
):
    seed(count=1)
    now = 6000.0
    monkeypatch.setattr(ai_claims.time, 'time', lambda: now)
    with Session() as session:
        settings = session.get(Setting, 'config')
        settings.value = {**settings.value, 'ai_control_mode': mode}
        if rate_blocked is not None:
            session.add(ai_admission.Admission(id='global', next_at=now + 45 if rate_blocked else now))
        if provider_blocked is not None:
            session.add(ai_provider_backoff.ProviderBackoff(
                id='global', blocked_until=now + 60 if provider_blocked else now,
            ))
        session.commit()

    gate_reads = []

    def capture(conn, cursor, statement, params, context, many):
        sql = statement.lower()
        if sql.startswith('select') and ('ai_admission' in sql or 'ai_provider_backoff' in sql):
            gate_reads.append(sql)

    event.listen(engine, 'before_cursor_execute', capture)
    try:
        lease = ai_claims.acquire()
    finally:
        event.remove(engine, 'before_cursor_execute', capture)
    if lease:
        with lease:
            assert lease.subject == 'subject-0'
    assert (lease is not None) == claim_expected
    assert len(gate_reads) == 1
    assert 'ai_provider_backoff' in gate_reads[0]
    assert ('ai_admission' in gate_reads[0]) == (mode == 'rate')
