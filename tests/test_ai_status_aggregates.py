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
    assert status['pending']==status['ready']==status['queued']==status['eligible_unclaimed'] and status['blocked']==0
    assert status['oldest_eligible_unclaimed_observation_at']==pytest.approx(now-10)


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
    assert status['plan_deferred_by_action']['security-plan']['deferred']==expected
    response=admin.get('/api/jobs/marker-job',params={'host_id':'marker-host'})
    assert response.status_code==200 and response.json()['ai_deferred']==bool(expected)


def test_admin_status_reports_eligible_unclaimed_observations(admin):
    from app.ai_claims import Claim

    now=time.time()
    with Session() as s:
        for host_id in ('active','paused','disabled'):
            s.add(Host(id=host_id,name=host_id,address='192.0.2.1',fingerprint='',enabled=host_id!='disabled'))
        s.flush()
        s.add(Setting(key='server-ai:paused',value={'paused':True}))
        observations=(
            ('delayed','active',100),
            ('blocked','active',90),
            ('leased','active',80),
            ('paused','paused',70),
            ('disabled','disabled',60),
            ('expired','active',30),
            ('waiting','active',20),
        )
        for subject,host_id,age in observations:
            s.add(Behavior(id=subject,host_id=host_id,first_seen=now-age,attempted=0,evidence={}))
        signature=ai_retry.configuration(s)
        s.add_all((
            ai_retry.TriageRetry(subject='delayed',configuration=signature,state='deferred',next_at=now+600),
            ai_retry.TriageRetry(subject='blocked',configuration=signature,state='blocked'),
        ))
        for subject,expires in (('leased',now+600),('expired',now-1)):
            s.add(Claim(subject=subject,host_id='active',token=subject,worker_id='fixture',boot_id='fixture',
                run_id=subject,revision='fixture',configuration=signature,created=now-60,renewed=now-60,expires=expires))
        s.commit()

    response=admin.get('/api/investigation-status')
    assert response.status_code==200
    status=response.json()
    assert status['oldest']==pytest.approx(now-100)
    assert status['eligible_unclaimed']==2
    assert status['oldest_eligible_unclaimed_observation_at']==pytest.approx(now-30)

    with Session() as s:
        for subject in ('expired','waiting'):
            s.get(Behavior,subject).approved=True
        s.commit()
    status=admin.get('/api/investigation-status').json()
    assert status['eligible_unclaimed']==0
    assert status['oldest_eligible_unclaimed_observation_at'] is None
