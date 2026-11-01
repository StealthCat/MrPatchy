from sqlalchemy import create_engine, inspect, text

from app import db

EXPECTED = {'ix_jobs_host_state', 'ix_jobs_host_action_created', 'ix_jobs_host_created', 'ix_jobs_state_created'}


def plan(connection, sql):
    return ' '.join(str(row[3]) for row in connection.execute(text('EXPLAIN QUERY PLAN ' + sql)))


def test_init_adds_job_indexes_to_an_existing_jobs_table(tmp_path, monkeypatch):
    engine = create_engine('sqlite:///' + str(tmp_path / 'old.db'))
    monkeypatch.setattr(db, 'engine', engine)
    with engine.begin() as c:
        # Installed schema before the indexes: jobs table with only its primary key.
        c.execute(text('CREATE TABLE jobs (id VARCHAR(36) PRIMARY KEY, host_id VARCHAR(36), action VARCHAR(80), payload JSON, state VARCHAR(30), output TEXT, created DOUBLE, next_at DOUBLE NOT NULL DEFAULT 0)'))
        c.execute(text("INSERT INTO jobs (id,host_id,action,payload,state,output,created) VALUES ('j','h','refresh','{}','done','',1)"))
    assert not {i['name'] for i in inspect(engine).get_indexes('jobs')}
    db.init()
    db.init()  # idempotent
    assert EXPECTED <= {i['name'] for i in inspect(engine).get_indexes('jobs')}
    with engine.connect() as c:
        assert c.execute(text('SELECT count(*) FROM jobs')).scalar() == 1
        refresh = plan(c, "SELECT * FROM jobs WHERE host_id='h' AND action='refresh' ORDER BY created DESC LIMIT 1")
        assert 'SCAN jobs' not in refresh and 'TEMP B-TREE' not in refresh
        assert 'ix_jobs_host_action_created' in refresh
        assert 'ix_jobs_host_state' in plan(c, "SELECT id FROM jobs WHERE host_id='h' AND state IN ('queued','running') LIMIT 1")
        assert 'ix_jobs_state_created' in plan(c, "SELECT * FROM jobs WHERE state='queued' ORDER BY created")
        assert 'TEMP B-TREE' not in plan(c, "SELECT * FROM jobs WHERE host_id='h' ORDER BY created DESC LIMIT 50")


def test_job_indexes_are_in_shared_metadata_for_new_and_migrated_databases():
    db.register_models()
    assert EXPECTED <= {i.name for i in db.Job.__table__.indexes}
