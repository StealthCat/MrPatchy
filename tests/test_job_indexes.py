from sqlalchemy import create_engine, inspect, text, event

from app import db

EXPECTED = {'ix_jobs_host_state', 'ix_jobs_host_action_created', 'ix_jobs_host_history', 'ix_jobs_history', 'ix_jobs_state_created'}


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


def test_real_fleet_and_host_history_ordering_uses_bounded_indexes(admin):
    with db.Session() as session:
        session.add_all([db.Host(id='history-'+str(i),name='history',address='192.0.2.1',fingerprint='test') for i in range(20)])
        session.bulk_insert_mappings(db.Job,[{
            'id':f'history-{i:06d}','host_id':'history-'+str(i%20),
            'action':'refresh','state':'complete','created':float(i//100),
            'payload':{},'output':'retained history',
        } for i in range(10000)])
        session.commit()
    for host in ('','history-0'):
        queries=[]
        def capture(connection,cursor,statement,parameters,context,executemany):
            if 'FROM jobs' in statement and 'ORDER BY jobs.created DESC, jobs.id' in statement:
                queries.append((statement,parameters))
        event.listen(db.engine,'before_cursor_execute',capture)
        try:
            response=admin.get('/api/jobs',params={'host_id':host,'limit':50})
        finally:event.remove(db.engine,'before_cursor_execute',capture)
        assert response.status_code==200 and len(response.json())==50
        assert queries
        sql,parameters=queries[-1]
        with db.engine.connect() as connection:
            if connection.dialect.name=='sqlite':
                rows=connection.exec_driver_sql('EXPLAIN QUERY PLAN '+sql,parameters).all()
                details=' '.join(str(row[3]) for row in rows)
                assert 'TEMP B-TREE' not in details
                assert ('ix_jobs_host_history' if host else 'ix_jobs_history') in details
            else:
                rows=connection.exec_driver_sql('EXPLAIN '+sql,parameters).mappings().all()
                assert all('filesort' not in str(row.get('Extra','')).lower() for row in rows), (host or 'fleet', rows)
                if connection.dialect.name=='mysql':
                    history_index='ix_jobs_host_history' if host else 'ix_jobs_history'
                    job_plan=next(row for row in rows if row['table']=='jobs')
                    assert job_plan['key']==history_index, job_plan
                    assert f'FORCE INDEX FOR ORDER BY ({history_index})' in sql
        items=response.json()
        assert items==sorted(items,key=lambda item:(-item['created'],item['id']))
