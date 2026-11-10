from types import SimpleNamespace

import pytest
from sqlalchemy import event, insert, inspect, select, text

from app import ai_claims, ai_runs, db, update_scores
from app.ai_runs import AIRun
from app.db import Behavior, Host, Setting
from app.security import seal


RUN_INDEX = 'ix_ai_runs_purpose_started'


def test_init_adds_recent_run_index_to_existing_table(admin):
    with db.Session() as session:
        session.add(AIRun(id='retained', purpose='triage', started=1234, state='complete'))
        session.commit()

    with db.engine.begin() as connection:
        for index in AIRun.__table__.indexes:
            if index.name == RUN_INDEX:
                index.drop(connection, checkfirst=True)
        before = {index['name'] for index in inspect(connection).get_indexes('ai_runs')}
        assert RUN_INDEX not in before

    db.init()
    db.init()

    with db.engine.connect() as connection:
        indexes = {index['name']: index for index in inspect(connection).get_indexes('ai_runs')}
        assert indexes.keys() == before | {RUN_INDEX}
        assert indexes[RUN_INDEX]['column_names'] == ['purpose', 'started']
        assert connection.execute(select(AIRun.id, AIRun.started)).one() == ('retained', 1234)


def test_recent_run_reads_use_purpose_and_time_range(admin, monkeypatch):
    now = 1_750_000_000
    clock = SimpleNamespace(time=lambda: now)
    for module in (ai_runs, ai_claims, update_scores):
        monkeypatch.setattr(module, 'time', clock)

    def unexpected_scoring_candidates(session):
        pytest.fail('Scoring inspected candidates despite reaching the hourly limit')

    monkeypatch.setattr(update_scores, 'scoring_candidates', unexpected_scoring_candidates)
    with db.Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': True, 'ai_model': 'fixture-model', 'ai_updates_enabled': True,
            'ai_control_mode': 'legacy', 'ai_hourly_limit': 2, 'ai_update_hourly_limit': 2,
        }))
        session.merge(Setting(key='openai_key', value={'encrypted': seal('fixture-key')}))
        session.merge(Setting(key='worker:heartbeat', value={'seen': now}))
        session.add(Host(id='host', name='Fixture', address='192.0.2.1', fingerprint=''))
        session.add(Behavior(id='eligible', host_id='host', attempted=0, evidence={}))
        session.execute(insert(AIRun), [
            {'id': f'history-{i}', 'purpose': 'triage' if i % 2 else 'update_scoring',
             'started': now - 7200, 'state': 'complete'}
            for i in range(5000)
        ])
        session.add_all([
            AIRun(id=f'{purpose}-{offset}', purpose=purpose, started=now - offset, state='complete')
            for purpose in ('triage', 'update_scoring')
            for offset in (3601, 3600, 3599, 45)
        ])
        session.add(AIRun(id='other-purpose', purpose='security_plan', started=now - 30, state='complete'))
        session.commit()

    with db.engine.begin() as connection:
        if connection.dialect.name == 'sqlite':
            connection.execute(text('ANALYZE ai_runs'))
        else:
            connection.execute(text('ANALYZE TABLE ai_runs')).all()

    queries = []

    def capture(connection, cursor, statement, parameters, context, executemany):
        if ('FROM ai_runs' in statement and 'ai_runs.purpose =' in statement
                and 'ai_runs.started >' in statement and 'count(' in statement.lower()):
            queries.append((statement, parameters))

    event.listen(db.engine, 'before_cursor_execute', capture)
    try:
        response = admin.get('/api/investigation-status')
        assert response.status_code == 200
        status = response.json()
        assert (status['recent_attempts'], status['reason'], status['retry_at']) == (
            2, 'rate_limited', now + 1,
        )
        assert ai_claims.acquire() is None
        update_scores.run_one()
    finally:
        event.remove(db.engine, 'before_cursor_execute', capture)

    assert len(queries) == 3
    assert 'min(' in queries[0][0].lower()
    assert all('min(' not in statement.lower() for statement, _ in queries[1:])
    with db.engine.connect() as connection:
        assert connection.scalars(select(ai_claims.Claim.subject)).all() == []
        expected = [(2, now - 3599), (2,), (2,)]
        for (statement, parameters), result in zip(queries, expected, strict=True):
            assert connection.exec_driver_sql(statement, parameters).one() == result
            if connection.dialect.name == 'sqlite':
                plan = connection.exec_driver_sql('EXPLAIN QUERY PLAN ' + statement, parameters).all()
                assert any(f'USING COVERING INDEX {RUN_INDEX} (purpose=? AND started>?)' in row[3]
                           for row in plan), plan
            else:
                plan = connection.exec_driver_sql('EXPLAIN ' + statement, parameters).mappings().all()
                run, = [row for row in plan if row['table'] == 'ai_runs']
                assert run['type'] == 'range' and run['key'] == RUN_INDEX, plan
