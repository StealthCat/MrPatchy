from types import SimpleNamespace

from sqlalchemy import event, insert, inspect, select, text

from app import ai_claims, ai_runs, db
from app.db import Behavior, Host, Setting
from app.security import seal


ATTEMPT_INDEX = 'ix_behaviors_attempted'


def test_init_adds_recent_attempt_index_to_existing_behaviors(admin):
    with db.Session() as session:
        session.add(Behavior(id='retained', host_id='host', attempted=1234, evidence={}))
        session.commit()

    with db.engine.begin() as connection:
        for index in Behavior.__table__.indexes:
            if index.name == ATTEMPT_INDEX:
                index.drop(connection, checkfirst=True)
        before = {index['name'] for index in inspect(connection).get_indexes('behaviors')}
        assert ATTEMPT_INDEX not in before

    db.init()
    db.init()

    with db.engine.connect() as connection:
        indexes = {index['name']: index for index in inspect(connection).get_indexes('behaviors')}
        assert indexes.keys() == before | {ATTEMPT_INDEX}
        assert indexes[ATTEMPT_INDEX]['column_names'] == ['attempted']
        assert connection.execute(select(Behavior.id, Behavior.attempted)).one() == ('retained', 1234)


def test_recent_attempt_reads_use_range_and_preserve_strict_cutoff(admin, monkeypatch):
    now = 1_750_000_000
    clock = SimpleNamespace(time=lambda: now)
    monkeypatch.setattr(ai_runs, 'time', clock)
    monkeypatch.setattr(ai_claims, 'time', clock)

    with db.Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': True, 'ai_model': 'fixture-model',
            'ai_control_mode': 'legacy', 'ai_hourly_limit': 2,
        }))
        session.merge(Setting(key='openai_key', value={'encrypted': seal('fixture-key')}))
        session.merge(Setting(key='worker:heartbeat', value={'seen': now}))
        session.add(Host(id='host', name='Fixture', address='192.0.2.1', fingerprint=''))
        session.execute(insert(Behavior), [
            {'id': f'history-{i}', 'host_id': 'host', 'verdict': 'low',
             'attempted': now - 7200, 'evidence': {}}
            for i in range(5000)
        ])
        session.add_all([
            Behavior(id=f'edge-{offset}', host_id='host', verdict='low',
                     attempted=now - offset, evidence={})
            for offset in (3601, 3600, 3599, 45)
        ])
        session.add(Behavior(id='eligible', host_id='host', attempted=0, evidence={}))
        session.commit()

    with db.engine.begin() as connection:
        if connection.dialect.name == 'sqlite':
            connection.execute(text('ANALYZE behaviors'))
        else:
            connection.execute(text('ANALYZE TABLE behaviors')).all()

    queries = []

    def capture(connection, cursor, statement, parameters, context, executemany):
        if 'FROM behaviors' in statement and 'WHERE behaviors.attempted >' in statement:
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
    finally:
        event.remove(db.engine, 'before_cursor_execute', capture)

    assert len(queries) == 2
    assert 'min(' in queries[0][0].lower()
    assert 'min(' not in queries[1][0].lower()
    with db.engine.connect() as connection:
        assert connection.scalars(select(ai_claims.Claim.subject)).all() == []
        assert connection.scalars(select(ai_runs.AIRun.id)).all() == []
        for statement, parameters in queries:
            if connection.dialect.name == 'sqlite':
                plan = connection.exec_driver_sql('EXPLAIN QUERY PLAN ' + statement, parameters)
                assert any(f'USING COVERING INDEX {ATTEMPT_INDEX} (attempted>?)' in row[3] for row in plan)
            else:
                plan = connection.exec_driver_sql('EXPLAIN ' + statement, parameters).mappings().all()
                behavior, = [row for row in plan if row['table'] == 'behaviors']
                assert behavior['type'] == 'range' and behavior['key'] == ATTEMPT_INDEX, plan
