"""Expired AI claim recovery reads runs without per-claim queries."""
from sqlalchemy import event, select
from app import ai_claims, ai_runs
from app.coordination import Lock
from app.db import Session, engine


def claim(subject, run_id, expires):
    return ai_claims.Claim(subject=subject, host_id='fixture', token=subject,
        worker_id='worker', boot_id='boot', run_id=run_id, revision='revision',
        configuration='config', created=1, renewed=1, expires=expires)


def test_recovery_joins_expired_claims_and_keeps_run_history(admin):
    expired = [f'expired-{index}' for index in range(12)]
    with Session() as s:
        s.add_all(ai_runs.AIRun(id=identifier, purpose='triage')
            for identifier in [*expired, 'orphan', 'live'])
        s.add(ai_runs.AIRun(id='complete', purpose='triage', state='complete'))
        s.add(ai_runs.AIRun(id='scoring', purpose='update_scoring'))
        s.add_all(claim(identifier, identifier, 5) for identifier in [*expired, 'complete'])
        s.add(claim('missing', 'missing-run', 5))
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
        assert len(reads) == 2, len(reads)
        assert any('LEFT OUTER JOIN ai_runs' in statement for statement in reads)
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
