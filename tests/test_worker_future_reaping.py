import concurrent.futures
from types import SimpleNamespace

import pytest

from app import worker
from app.db import Session, Host


@pytest.mark.parametrize('completion_tick',[2,3,4])
def test_poll_and_notification_failures_are_logged_once_before_shutdown(admin,monkeypatch,caplog,completion_tick):
    with Session() as session:
        session.add(Host(id='poll-host',name='Poll',address='192.0.2.1',fingerprint=''))
        session.commit()
    tick=[0];pending=[]
    class Pool:
        def __init__(self,**kwargs):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def submit(self,callback,*args):
            future=concurrent.futures.Future()
            if callback in (worker.poll_host,worker.operations.deliver_one):
                pending.append((future,callback.__name__))
            else:future.set_result(None)
            return future
    class Stop:
        def wait(self,timeout):
            tick[0]+=1
            assert tick[0]<=4,'Scheduler failed to stop'
            if tick[0]==completion_tick:
                for future,name in pending:
                    if not future.done():future.set_exception(RuntimeError('fixture '+name+' failed'))
            if tick[0]==3 and completion_tick==4:
                for future,name in pending:
                    calls=[0]
                    def race(future=future,name=name,calls=calls,done=future.done):
                        calls[0]+=1
                        if calls[0]==1:return False
                        if not done():future.set_exception(RuntimeError('fixture '+name+' failed'))
                        return True
                    future.done=race
            return tick[0]>=3
    class Leader:
        def __init__(self,*args):pass
        def acquire(self,*args):return True
        def owned(self):return True
        def release(self):pass
    reporter=SimpleNamespace(capacity={'polls':1,'jobs':1,'ai':1},
        heartbeat=lambda *args:tick[0]>=2)
    monkeypatch.setattr(worker.concurrent.futures,'ThreadPoolExecutor',Pool)
    monkeypatch.setattr(worker,'stop',Stop())
    monkeypatch.setattr(worker,'Lock',Leader)
    monkeypatch.setattr(worker.time,'sleep',lambda *args:None)
    monkeypatch.setattr(worker,'periodic_ticks',lambda *args:None)
    monkeypatch.setattr(worker,'reconcile_interrupted_advisory_jobs',lambda:None)
    monkeypatch.setattr(worker.operations,'collect_alerts',lambda **_:None)
    monkeypatch.setattr(worker.ai_runs,'heartbeat',lambda:None)
    worker._loop(reporter)
    assert len(pending)==2
    messages=[record.getMessage() for record in caplog.records]
    assert messages.count('Host poll failed outside its handler')==1
    assert messages.count('Notification delivery failed outside its handler')==1
