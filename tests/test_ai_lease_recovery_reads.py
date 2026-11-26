"""Triage admission reads expired leases and orphaned runs together."""
from sqlalchemy import event, select
from app import ai_claims, ai_runs
from app.coordination import Lock
from app.db import Session, engine
from tests.test_ai_claims import seed


def claim(subject, run_id, expires):
    return ai_claims.Claim(subject=subject, host_id='fixture', token=subject,
        worker_id='worker', boot_id='boot', run_id=run_id, revision='revision',
        configuration='config', created=1, renewed=1, expires=expires)


def test_recovery_reads_expired_claims_and_orphans_in_one_statement(admin):
    expired = [f'expired-{index}' for index in range(12)]
    with Session() as s:
        s.add_all(ai_runs.AIRun(id=identifier, purpose='triage')
            for identifier in [*expired, 'orphan', 'live'])
        s.add(ai_runs.AIRun(id='complete', purpose='triage', state='complete'))
        s.add(ai_runs.AIRun(id='scoring', purpose='update_scoring'))
        s.add_all(claim(identifier, identifier, 10) for identifier in [*expired, 'complete'])
        s.add(claim('missing', 'missing-run', 5))
        s.add(claim('also-expired', expired[0], 5))
        s.add(claim('live', 'live', 20))
        s.add(ai_runs.AICall(id='retained-receipt', run_id=expired[0], number=1, requested_model='fixture'))
        s.commit()

    reads = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith('SELECT') and ('FROM ai_runs' in statement or 'JOIN ai_runs' in statement):
            reads.append(statement)

    with Lock('ai-triage'), Session() as s:
        event.listen(engine, 'before_cursor_execute', capture)
        try:
            ai_claims.reconcile(s, 10)
            s.commit()
        finally:
            event.remove(engine, 'before_cursor_execute', capture)
        assert len(reads) == 1, reads
        assert 'LEFT OUTER JOIN ai_runs' in reads[0]
        ai_claims.reconcile(s, 10)
        s.commit()

    with Session() as s:
        assert list(s.scalars(select(ai_claims.Claim.subject))) == ['live']
        states = dict(s.execute(select(ai_runs.AIRun.id, ai_runs.AIRun.state)).all())
        assert states == {**dict.fromkeys([*expired, 'orphan'], 'interrupted'),
            'live': 'running', 'scoring': 'running', 'complete': 'complete'}
        events = list(s.scalars(select(ai_runs.AIEvent)))
        assert sorted(row.run_id for row in events) == sorted([*expired, 'orphan'])
        assert all(row.stage == 'interrupted' and 'billable' in row.message for row in events)
        assert s.get(ai_runs.AICall, 'retained-receipt').run_id == expired[0]


def test_healthy_admission_runs_one_recovery_read_and_preserves_live_claim(admin, monkeypatch):
    seed(count=2)
    first = ai_claims.acquire()
    assert first
    reads = []
    reconcile = ai_claims.reconcile

    def capture(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith('SELECT'):
            reads.append(statement)

    def capture_recovery(session, now):
        event.listen(engine, 'before_cursor_execute', capture)
        try:
            reconcile(session, now)
        finally:
            event.remove(engine, 'before_cursor_execute', capture)

    monkeypatch.setattr(ai_claims, 'reconcile', capture_recovery)
    second = ai_claims.acquire()
    assert second and second.subject != first.subject
    with Session() as session:
        assert session.get(ai_claims.Claim, first.subject).token == first.token
        assert session.get(ai_runs.AIRun, first.run_id).state == 'running'
        assert session.scalars(select(ai_runs.AIEvent)).first() is None
    assert len(reads) == 1, reads
