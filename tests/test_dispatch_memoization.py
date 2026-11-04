"""Queued dispatch must not repeat host-wide eligibility work for sibling jobs."""
from concurrent.futures import Future
from types import SimpleNamespace

from sqlalchemy import event

from app import worker
from app.db import Host, Job, Session, Setting, engine


def dispatch_once(monkeypatch, capacity=4):
    class Pool:
        def __init__(self, **kwargs):pass
        def __enter__(self):return self
        def __exit__(self, *args):pass
        def submit(self, fn, *args):
            future=Future();future.set_result(None);return future
    class NotLeader:
        def __init__(self, *args):pass
        def acquire(self, *args):return False
        def release(self):pass
        def owned(self):return False

    waits=[False, True, True]
    monkeypatch.setattr(worker.concurrent.futures, 'ThreadPoolExecutor', Pool)
    monkeypatch.setattr(worker, 'Lock', NotLeader)
    monkeypatch.setattr(worker.stop, 'wait', lambda timeout:waits.pop(0))
    monkeypatch.setattr(worker.time, 'time', lambda:1762171200)  # Monday, 12:00 UTC.
    statements=[]
    def observe(conn,cursor,statement,*args):
        if statement.lstrip().upper().startswith('SELECT'):statements.append(statement)
    event.listen(engine, 'before_cursor_execute', observe)
    try:
        reporter=SimpleNamespace(capacity={'polls':1, 'jobs':capacity, 'ai':1}, stopping=False)
        reporter.heartbeat=lambda *args:reporter.stopping
        worker._loop(reporter)
    finally:event.remove(engine, 'before_cursor_execute', observe)
    return statements


def test_closed_window_is_checked_once_per_host_per_iteration(admin, monkeypatch):
    host_count = 10
    jobs_per_host = 4
    with Session() as session:
        for host_index in range(host_count):
            host_id = f'dispatch-{host_index}'
            session.add(Host(id=host_id, name=host_id, address='192.0.2.1', fingerprint=''))
            session.add(Setting(key='window:'+host_id,
                value={'windows':[{'days':[1], 'start':0, 'end':1}]}))
            for job_index in range(jobs_per_host):
                session.add(Job(id=f'job-{host_index}-{job_index}', host_id=host_id,
                    action='patch', payload={'packages':['fixture=2']}, created=job_index))
        session.commit()

    calls = {'holds':0, 'eligible':0}
    original_hold = worker.operations.host_quarantined
    original_eligible = worker.operations.eligible
    def hold(*args, **kwargs):
        calls['holds'] += 1
        return original_hold(*args, **kwargs)
    def eligible(*args, **kwargs):
        calls['eligible'] += 1
        return original_eligible(*args, **kwargs)
    monkeypatch.setattr(worker.operations, 'host_quarantined', hold)
    monkeypatch.setattr(worker.operations, 'eligible', eligible)

    statements=dispatch_once(monkeypatch)

    print(f"dispatch calls={calls}; SELECTs={len(statements)}")
    assert calls == {'holds':host_count, 'eligible':host_count}
    assert len(statements) <= 70, f'{len(statements)} SELECTs for {host_count*jobs_per_host} queued jobs'


def test_first_submission_marks_host_busy_before_later_hold_checks(admin, monkeypatch):
    with Session() as session:
        session.add(Host(id='busy-host', name='busy-host', address='192.0.2.1', fingerprint=''))
        for index in range(4):
            session.add(Job(id=f'busy-{index}', host_id='busy-host', action='refresh', created=index))
        session.commit()
    calls=[]
    original=worker.operations.host_quarantined
    def hold(*args, **kwargs):
        calls.append(args[1]);return original(*args, **kwargs)
    def submit(pool, job, active, busy):
        future=Future();future.set_result(None)
        active[job.id]=(future,job.host_id);busy.add(job.host_id);return True
    monkeypatch.setattr(worker.operations, 'host_quarantined', hold)
    monkeypatch.setattr(worker, 'submit_job', submit)

    dispatch_once(monkeypatch)

    assert calls==['busy-host']


def test_closed_patch_window_does_not_block_later_nonpatch_work(admin, monkeypatch):
    with Session() as session:
        session.add(Host(id='mixed-host', name='mixed-host', address='192.0.2.1', fingerprint=''))
        session.add(Setting(key='window:mixed-host', value={'windows':[{'days':[1], 'start':0, 'end':1}]}))
        session.add(Job(id='closed-patch', host_id='mixed-host', action='patch',
            payload={'packages':['fixture=2']}, created=0))
        session.add(Job(id='allowed-refresh', host_id='mixed-host', action='refresh', created=1))
        session.commit()
    submitted=[]
    def submit(pool, job, active, busy):
        submitted.append(job.id)
        future=Future();future.set_result(None)
        active[job.id]=(future,job.host_id);busy.add(job.host_id);return True
    monkeypatch.setattr(worker, 'submit_job', submit)

    dispatch_once(monkeypatch)

    assert submitted==['allowed-refresh']
