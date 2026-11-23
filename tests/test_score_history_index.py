from sqlalchemy import event, insert, inspect, select, text

from app import db, update_scores


HISTORY_INDEX = 'ix_update_scores_host_name_state_candidate'
RUN_HOST_INDEX = 'ix_update_scores_run_id_host_id'


def test_startup_adds_score_history_index_without_losing_retained_scores(admin):
    score = update_scores.UpdateScore
    with db.Session() as session:
        session.add(score(id='retained', host_id='host', name='pkg', installed='1', candidate='2'))
        session.commit()
    with db.engine.begin() as connection:
        for index in score.__table__.indexes:
            if index.name == HISTORY_INDEX:
                index.drop(connection, checkfirst=True)
        before = {index['name'] for index in inspect(connection).get_indexes('update_scores')}
        assert HISTORY_INDEX not in before

    db.init()
    db.init()

    with db.engine.connect() as connection:
        indexes = {index['name']: index for index in inspect(connection).get_indexes('update_scores')}
        assert indexes.keys() == before | {HISTORY_INDEX}
        assert indexes[HISTORY_INDEX]['column_names'] == ['host_id', 'name', 'state', 'candidate']
        assert connection.scalar(select(score.id)) == 'retained'


def test_startup_restores_covering_run_membership_index(admin):
    score = update_scores.UpdateScore
    with db.Session() as session:
        session.execute(insert(score), [
            {'id': f'score-{number}', 'host_id': 'host', 'name': f'package-{number}',
             'installed': '1', 'candidate': '2', 'run_id': f'old-{number // 10}'}
            for number in range(3000)
        ])
        session.add(score(id='retained', host_id='host', name='pkg',
                          installed='1', candidate='2', run_id='target'))
        session.commit()

    with db.engine.begin() as connection:
        update_scores.SCORE_RUN_HOST_INDEX.drop(connection)
        before = {index['name'] for index in inspect(connection).get_indexes('update_scores')}
        assert RUN_HOST_INDEX not in before

    db.init()
    db.init()

    with db.engine.connect() as connection:
        indexes = {index['name']: index for index in inspect(connection).get_indexes('update_scores')}
        assert indexes.keys() == before | {RUN_HOST_INDEX}
        assert indexes[RUN_HOST_INDEX]['column_names'] == ['run_id', 'host_id']
        assert connection.scalar(select(score.id).where(score.run_id == 'target')) == 'retained'

        sqlite = connection.dialect.name == 'sqlite'
        if not sqlite:
            connection.execute(text('ANALYZE TABLE update_scores')).all()
        explain = 'EXPLAIN QUERY PLAN ' if sqlite else 'EXPLAIN '
        plan = connection.execute(text(explain +
            'SELECT run_id, host_id FROM update_scores WHERE run_id IN (:first, :second)'),
            {'first': 'target', 'second': 'old-7'})
        if sqlite:
            assert any(f'COVERING INDEX {RUN_HOST_INDEX}' in row[3] for row in plan)
        else:
            assert any(row['key'] == RUN_HOST_INDEX and 'Using index' in row['Extra']
                       for row in plan.mappings())


def test_score_history_and_deferred_lookup_use_package_index(admin):
    score = update_scores.UpdateScore
    with db.Session() as session:
        session.add(db.Host(id='host', name='Fixture', address='192.0.2.1', fingerprint=''))
        session.add(db.Package(id='host:target', host_id='host', name='target', installed='1', candidate='3'))
        session.execute(insert(score), [
            {'id': f'old-{i}', 'host_id': 'host', 'name': f'other-{i}', 'installed': '1',
             'candidate': '2', 'state': 'complete', 'score': 30, 'completed': i}
            for i in range(5000)
        ])
        session.add_all([
            score(id='history', host_id='host', name='target', installed='1', candidate='2',
                  state='complete', score=70, completed=100),
            score(id='deferred', host_id='host', name='target', installed='1', candidate='3', state='deferred'),
        ])
        session.commit()

    queries = {}

    def capture(connection, cursor, statement, parameters, context, executemany):
        query = statement.lower()
        if 'from update_scores' not in query:
            return
        if 'where update_scores.host_id =' in query:
            queries['history'] = statement, parameters
        if 'where update_scores.state =' in query and '(update_scores.host_id, update_scores.name) in' in query:
            queries['deferred'] = statement, parameters

    event.listen(db.engine, 'before_cursor_execute', capture)
    try:
        with db.Session() as session:
            history = update_scores.historical(session, 'host', 'target', ['2'], before=['1'])
            _, _, _, _, deferred = next(update_scores.scoring_candidates(session))
            assert history['score'] == 70 and history['from_version'] == '1' and history['to_version'] == '2'
            assert [row.id for row in deferred] == ['deferred']
    finally:
        event.remove(db.engine, 'before_cursor_execute', capture)

    assert queries.keys() == {'history', 'deferred'}
    plans = {}
    with db.engine.connect() as connection:
        sqlite = connection.dialect.name == 'sqlite'
        if not sqlite:
            connection.execute(text('ANALYZE TABLE update_scores')).all()
        for name, (sql, parameters) in queries.items():
            plan = connection.exec_driver_sql(('EXPLAIN QUERY PLAN ' if sqlite else 'EXPLAIN ') + sql, parameters)
            plans[name] = [row[3] for row in plan] if sqlite else [row['key'] for row in plan.mappings()]
    assert all(any(HISTORY_INDEX in (part or '') for part in plan) for plan in plans.values()), plans
