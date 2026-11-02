import time
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
