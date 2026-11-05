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
