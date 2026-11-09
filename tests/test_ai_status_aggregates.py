import time
import pytest
from sqlalchemy import event
from app import ai_runs, ai_retry
from app.db import Session, Setting, Behavior, Host, Job, engine
from app.security import seal

COUNT=3000


def seed(now):
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture','ai_hourly_limit':20}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        s.add(Host(id='host',name='Fixture',address='192.0.2.1',fingerprint=''))
        s.flush();signature=ai_retry.configuration(s)
        s.add_all(Behavior(id=f'b{i}',host_id='host',first_seen=now-10-i,attempted=0,evidence={}) for i in range(COUNT))
        s.add_all(ai_retry.TriageRetry(subject=f'b{i}',configuration=signature,attempts=1,state='deferred',next_at=now+600+i) for i in range(3))
        s.add_all(ai_retry.TriageRetry(subject=f'b{i}',configuration=signature,attempts=1,state='blocked') for i in range(3,5))
        s.commit()


def test_status_counts_without_loading_pending_rows(admin):
    now=time.time();seed(now);statements=[]
    def observe(conn,cursor,statement,parameters,context,executemany):statements.append(statement)
    event.listen(engine,'before_cursor_execute',observe)
    try:
        with Session() as s:status=ai_runs.status(s)
    finally:event.remove(engine,'before_cursor_execute',observe)
    assert status['pending']==COUNT and status['ready']==COUNT-5 and status['blocked']==2 and status['paused']==0
    assert status['queued']==COUNT and abs(status['oldest']-(now-10-(COUNT-1)))<1
    assert abs(status['retry_at']-(now+600))<5
    assert len(statements)<40
    assert not any('FROM behaviors' in q and 'count(' not in q.lower() and 'min(' not in q.lower() for q in statements)


def test_status_combines_run_and_scoring_aggregates(admin):
    """The polled status endpoint must not scan either aggregate dataset twice."""
    statements=[]
    def observe(conn,cursor,statement,parameters,context,executemany):statements.append(statement.lower())
    event.listen(engine,'before_cursor_execute',observe)
    try:
        with Session() as session:ai_runs.status(session)
    finally:event.remove(engine,'before_cursor_execute',observe)
    run_aggregates=[query for query in statements if 'from ai_runs' in query and ('count(' in query or 'min(' in query)]
    scoring_aggregates=[query for query in statements if 'from update_scores' in query and 'join packages' in query]
    assert len(run_aggregates)==1 and 'count(' in run_aggregates[0] and 'min(' in run_aggregates[0]
    assert len(scoring_aggregates)==1 and 'count(' in scoring_aggregates[0] and 'min(' in scoring_aggregates[0]


@pytest.mark.parametrize('role',['viewer','operator'])
def test_investigation_status_read_roles_skip_admin_aggregates(admin,role,capsys):
    from app.identity import User

    now=time.time()
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True}))
        s.add_all([
            Host(id='active',name='Active',address='192.0.2.1',fingerprint=''),
            Host(id='inactive',name='Inactive',address='192.0.2.2',fingerprint='',enabled=False),
        ])
        s.add_all([
            Behavior(id='pending',host_id='active',first_seen=now-10,evidence={}),
            Behavior(id='error',host_id='active',first_seen=now-20,verdict='error',evidence={}),
            Behavior(id='approved',host_id='active',first_seen=now-30,approved=True,evidence={}),
            Behavior(id='complete',host_id='active',first_seen=now-40,verdict='low',evidence={}),
            Behavior(id='inactive-pending',host_id='inactive',first_seen=now-50,evidence={}),
        ])
        s.commit()
    statements=[]
    def observe(conn,cursor,statement,parameters,context,executemany):
        if statement.lstrip().upper().startswith('SELECT'):
            statements.append(statement.lower())

    event.listen(engine,'before_cursor_execute',observe)
    try:
        response=admin.get('/api/investigation-status')
        assert response.status_code==200
        full=response.json()
        admin_query_count=len(statements)
        with Session() as s:
            s.get(User,'admin').role=role
            s.commit()
        statements.clear()
        response=admin.get('/api/investigation-status')
    finally:
        event.remove(engine,'before_cursor_execute',observe)

    assert response.status_code==200
    assert response.json()=={k:full[k] for k in ('pending','oldest','enabled')}
    assert response.json()=={'pending':2,'oldest':pytest.approx(now-20),'enabled':True}
    assert len(statements)<admin_query_count
    assert sum('from behaviors' in sql for sql in statements)==1
    assert not any(table in sql for sql in statements
        for table in ('ai_runs','ai_triage_claims','ai_triage_retries','ai_budget_entries','update_scores','jobs'))
    with capsys.disabled():
        print(f'Investigation status SELECTs: admin={admin_query_count}, {role}={len(statements)}')


def test_status_counts_share_one_snapshot_under_concurrent_insert(admin):
    now=time.time()
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture','ai_hourly_limit':20}))
        s.add(Host(id='race-host',name='Race',address='192.0.2.1',fingerprint=''))
        s.add(Behavior(id='race-1',host_id='race-host',first_seen=now-10,attempted=0,evidence={}))
        s.commit()
    inserted=[]
    def insert_after_first_count(conn,cursor,statement,parameters,context,executemany):
        # Commit a second unpaused pending behavior from another connection right
        # after the first behavior aggregate, as a concurrent collector would.
        if inserted or 'FROM behaviors' not in statement or 'count(' not in statement.lower():return
        inserted.append(statement)
        with Session() as other:
            other.add(Behavior(id='race-2',host_id='race-host',first_seen=now-5,attempted=0,evidence={}))
            other.commit()
    event.listen(engine,'after_cursor_execute',insert_after_first_count)
    try:
        with Session() as s:status=ai_runs.status(s)
    finally:event.remove(engine,'after_cursor_execute',insert_after_first_count)
    assert inserted
    assert status['paused']==0
    assert status['pending']==status['ready']==status['queued'] and status['blocked']==0


@pytest.mark.parametrize('marker', [True,False,1,1.0,'true',None,[],{}])
def test_deferred_plan_counts_only_native_json_true(admin,marker):
    now=time.time()
    with Session() as session:
        session.add(Host(id='marker-host',name='Marker',address='192.0.2.1',fingerprint=''))
        session.add(Job(id='marker-job',host_id='marker-host',action='security-plan',
            payload={'_ai_deferred':marker},next_at=now+600))
        session.commit()
        status=ai_runs.status(session)
    expected=1 if marker is True else 0
    assert status['plan_deferred']==expected
    assert (status['plan_next_at'] is not None)==bool(expected)
    response=admin.get('/api/jobs/marker-job',params={'host_id':'marker-host'})
    assert response.status_code==200 and response.json()['ai_deferred']==bool(expected)
