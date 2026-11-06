from sqlalchemy import create_engine, inspect, text

from app import ai_assessments, db


EXPECTED = {
    'ix_ai_assessments_subject_state_created',
    'ix_ai_assessments_subject_host_created',
}


def _sqlite_plan(connection, statement):
    compiled = statement.compile(connection, compile_kwargs={'literal_binds': True})
    rows = connection.exec_driver_sql('EXPLAIN QUERY PLAN ' + str(compiled)).all()
    return ' '.join(str(row[3]) for row in rows)


def test_init_adds_assessment_indexes_to_an_existing_table(tmp_path, monkeypatch):
    engine = create_engine('sqlite:///' + str(tmp_path / 'old.db'))
    monkeypatch.setattr(db, 'engine', engine)
    with engine.begin() as connection:
        connection.execute(text('''
            CREATE TABLE ai_behavior_assessments (
                id VARCHAR(36) PRIMARY KEY,
                subject VARCHAR(64),
                host_id VARCHAR(36),
                created DOUBLE,
                source VARCHAR(30),
                model VARCHAR(100),
                run_id VARCHAR(36),
                policy_hash VARCHAR(64),
                state_hash VARCHAR(64),
                result JSON,
                snapshot JSON,
                inputs JSON,
                refresh JSON
            )
        '''))
        connection.execute(text('''
            INSERT INTO ai_behavior_assessments
                (id, subject, host_id, created, source, model, run_id,
                 policy_hash, state_hash, result, snapshot, inputs, refresh)
            VALUES
                ('assessment', 'subject', 'host', 1, 'ai', '', '', '',
                 'state', '{}', '{}', '[]', '{}')
        '''))

    assert not {item['name'] for item in inspect(engine).get_indexes('ai_behavior_assessments')}
    db.init()
    db.init()  # idempotent

    assert EXPECTED <= {
        item['name'] for item in inspect(engine).get_indexes('ai_behavior_assessments')
    }
    with engine.connect() as connection:
        assert connection.execute(text('SELECT count(*) FROM ai_behavior_assessments')).scalar_one() == 1


def test_assessment_indexes_are_in_shared_metadata():
    db.register_models()
    assert EXPECTED <= {index.name for index in ai_assessments.Assessment.__table__.indexes}


def test_retained_assessment_queries_use_bounded_indexes():
    db.init()
    table = ai_assessments.Assessment.__table__
    exact = ai_assessments.exact_history_query('target', 'state').limit(1)
    history = ai_assessments.subject_history_query('target', 'target-host').limit(21)

    with db.engine.begin() as connection:
        connection.execute(table.delete())
        connection.execute(table.insert(), [
            {
                'id': f'unrelated-{item:05d}',
                'subject': f'unrelated-{item % 100}',
                'host_id': f'host-{item % 20}',
                'created': float(item),
                'source': 'ai',
                'model': '',
                'run_id': '',
                'policy_hash': '',
                'state_hash': f'state-{item % 10}',
                'result': {},
                'snapshot': {},
                'inputs': [],
                'refresh': {},
            }
            for item in range(5000)
        ] + [
            {
                'id': f'matching-{item:02d}',
                'subject': 'target',
                'host_id': 'target-host',
                'created': float(item),
                'source': 'ai',
                'model': '',
                'run_id': '',
                'policy_hash': '',
                'state_hash': 'state',
                'result': {},
                'snapshot': {},
                'inputs': [],
                'refresh': {},
            }
            for item in range(25)
        ])

        assert connection.execute(exact).mappings().one()['id'] == 'matching-24'
        assert [row['id'] for row in connection.execute(history).mappings()] == [
            f'matching-{item:02d}' for item in reversed(range(4, 25))
        ]

        if connection.dialect.name == 'sqlite':
            exact_plan = _sqlite_plan(connection, exact)
            history_plan = _sqlite_plan(connection, history)
            assert 'ix_ai_assessments_subject_state_created' in exact_plan
            assert 'ix_ai_assessments_subject_host_created' in history_plan
            assert 'TEMP B-TREE' not in exact_plan
            assert 'TEMP B-TREE' not in history_plan
        elif connection.dialect.name in ('mysql', 'mariadb'):
            for statement, expected in (
                (exact, 'ix_ai_assessments_subject_state_created'),
                (history, 'ix_ai_assessments_subject_host_created'),
            ):
                compiled = statement.compile(connection)
                rows = connection.exec_driver_sql(
                    'EXPLAIN ' + str(compiled), compiled.params
                ).mappings().all()
                assessment_plan = next(
                    row for row in rows if row.get('table') == 'ai_behavior_assessments'
                )
                assert assessment_plan.get('key') == expected, assessment_plan
                assert 'filesort' not in str(assessment_plan.get('Extra', '')).lower()
                assert f'FORCE INDEX FOR JOIN ({expected})' in str(compiled)
