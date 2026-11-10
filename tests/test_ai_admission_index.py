from sqlalchemy import event, inspect, insert, select, text

from app import ai_claims, db
from app.db import Behavior, Host, Setting
from app.security import seal


ADMISSION_INDEX = 'ix_behaviors_admission'


def test_init_adds_admission_index_to_existing_behaviors_table(admin):
    with db.Session() as session:
        session.add(Behavior(id='retained-behavior', host_id='retained-host', evidence={}))
        session.commit()

    with db.engine.begin() as connection:
        for index in Behavior.__table__.indexes:
            if index.name == ADMISSION_INDEX:
                index.drop(connection, checkfirst=True)
        before = {index['name'] for index in inspect(connection).get_indexes('behaviors')}
        assert ADMISSION_INDEX not in before

    db.init()
    db.init()

    with db.engine.connect() as connection:
        indexes = {index['name']: index for index in inspect(connection).get_indexes('behaviors')}
        assert indexes.keys() == before | {ADMISSION_INDEX}
        assert indexes[ADMISSION_INDEX]['column_names'] == ['approved', 'verdict', 'first_seen', 'id']
        assert connection.scalar(select(Behavior.id)) == 'retained-behavior'


def test_actual_admission_query_uses_index_with_retained_history(admin):
    with db.Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': True,
            'ai_model': 'fixture-model',
            'ai_hourly_limit': 20,
        }))
        session.merge(Setting(key='openai_key', value={'encrypted': seal('private-key')}))
        session.add(Host(id='admission-host', name='Admission', address='192.0.2.1', fingerprint=''))
        session.execute(insert(Behavior), [{
            'id': f'{index:064x}',
            'host_id': 'admission-host',
            'evidence': {},
            'verdict': 'low',
            'approved': False,
            'first_seen': float(index),
            'last_seen': float(index),
            'attempted': 0,
        } for index in range(5000)])
        session.add_all([
            Behavior(
                id='e' * 64,
                host_id='admission-host',
                evidence={},
                verdict='error',
                approved=False,
                first_seen=5001,
                last_seen=5001,
            ),
            Behavior(
                id='f' * 64,
                host_id='admission-host',
                evidence={},
                verdict='pending',
                approved=False,
                first_seen=5002,
                last_seen=5002,
            ),
        ])
        session.commit()

    with db.engine.begin() as connection:
        if connection.dialect.name == 'sqlite':
            connection.execute(text('ANALYZE behaviors'))
        else:
            connection.execute(text('ANALYZE TABLE behaviors')).all()

    queries = []

    def capture(connection, cursor, statement, parameters, context, executemany):
        if 'FROM behaviors LEFT OUTER JOIN ai_triage_retries' in statement:
            queries.append((statement, parameters))

    event.listen(db.engine, 'before_cursor_execute', capture)
    try:
        lease = ai_claims.acquire()
    finally:
        event.remove(db.engine, 'before_cursor_execute', capture)

    # Splitting the two equality ranges must retain their global oldest-first
    # result rather than preferring the pending branch.
    assert lease and lease.subject == 'e' * 64
    # Fair admission first elects a host (#389), then resolves that host's
    # oldest candidate through the indexed per-verdict shortlist.
    shortlist = [query for query in queries if 'UNION ALL' in query[0]]
    assert len(queries) == 2 and len(shortlist) == 1, queries
    statement, parameters = shortlist[0]
    with db.engine.connect() as connection:
        prefix = 'EXPLAIN QUERY PLAN ' if connection.dialect.name == 'sqlite' else 'EXPLAIN '
        plan = connection.exec_driver_sql(prefix + statement, parameters)
        if connection.dialect.name == 'sqlite':
            details = [row[3] for row in plan]
            assert any(ADMISSION_INDEX in detail for detail in details), details
            assert all('SCAN behaviors' not in detail for detail in details), details
        else:
            rows = plan.mappings().all()
            behavior_rows = [row for row in rows if row.get('table') == 'behaviors']
            # Each verdict-range subquery uses the admission index. The outer
            # query then resolves the winning identity through the primary key.
            indexed = [row for row in behavior_rows if row.get('key') == ADMISSION_INDEX]
            assert len(indexed) == 2, rows
            assert all(row.get('type') != 'ALL' for row in behavior_rows), rows
            assert all(row.get('key') in (ADMISSION_INDEX, 'PRIMARY') for row in behavior_rows), rows

    with lease:
        pass
