from sqlalchemy import insert, inspect, select, text

from app import ai_runs, db


ACTIVE_INDEX = 'ix_ai_runs_purpose_state_started'


def test_init_adds_active_run_index_to_existing_table(admin):
    with db.Session() as session:
        session.add(ai_runs.AIRun(id='retained', purpose='triage', state='complete'))
        session.commit()

    with db.engine.begin() as connection:
        for index in ai_runs.AIRun.__table__.indexes:
            if index.name == ACTIVE_INDEX:
                index.drop(connection, checkfirst=True)
        before = {index['name'] for index in inspect(connection).get_indexes('ai_runs')}
        assert ACTIVE_INDEX not in before

    db.init()
    db.init()

    with db.engine.connect() as connection:
        indexes = {index['name']: index for index in inspect(connection).get_indexes('ai_runs')}
        assert indexes.keys() == before | {ACTIVE_INDEX}
        assert indexes[ACTIVE_INDEX]['column_names'] == ['purpose', 'state', 'started']
        assert connection.scalar(select(ai_runs.AIRun.id)) == 'retained'


def test_active_status_and_recovery_queries_use_index_with_retained_history(admin):
    run = ai_runs.AIRun
    with db.Session() as session:
        session.execute(insert(run), [
            {'id': f'complete-{i}', 'purpose': 'triage', 'state': 'complete', 'started': i}
            for i in range(5000)
        ])
        session.add_all([
            run(id='live-old', purpose='triage', state='running', started=5001),
            run(id='live-new', purpose='triage', state='running', started=5002),
            run(id='other', purpose='update_scoring', state='running', started=5003),
        ])
        session.commit()

    active = select(run).where(run.purpose == 'triage', run.state == 'running')
    newest = active.order_by(run.started.desc()).limit(1)
    recovery = active.where(run.id.not_in(['live-old']))
    with db.Session() as session:
        assert session.scalars(newest).one().id == 'live-new'
        assert session.scalars(recovery).one().id == 'live-new'

    with db.engine.connect() as connection:
        sqlite = connection.dialect.name == 'sqlite'
        if not sqlite:
            connection.execute(text('ANALYZE TABLE ai_runs')).all()
        prefix = 'EXPLAIN QUERY PLAN ' if sqlite else 'EXPLAIN '
        for query in (newest, recovery):
            sql = str(query.compile(dialect=connection.dialect, compile_kwargs={'literal_binds': True}))
            result = connection.exec_driver_sql(prefix + sql)
            if sqlite:
                plan = [row[3] for row in result]
                assert any(ACTIVE_INDEX in detail for detail in plan), plan
                assert all('TEMP B-TREE' not in detail for detail in plan), plan
            else:
                plan = result.mappings().all()
                assert any(row['key'] == ACTIVE_INDEX for row in plan), plan
                assert all('filesort' not in str(row['Extra']).lower() for row in plan), plan
