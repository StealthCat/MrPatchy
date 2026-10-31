"""A failing periodic producer must not stall independent scheduling/dispatch."""
from concurrent.futures import Future
from types import SimpleNamespace
import time

import pytest
from app import worker, persistence, response_monitor, service_monitor, execution_scans
from app.db import Session, Host, Job

TICKS = (
    ('patch schedules', worker.scheduling, 'tick'),
    ('scanner schedules', worker.incidents, 'schedule_tick'),
    ('startup schedules', persistence, 'schedule_tick'),
    ('incident AI plans', worker.incidents, 'auto_plan_tick'),
    ('response monitoring', response_monitor, 'schedule_tick'),
    ('service monitoring', service_monitor, 'schedule_tick'),
    ('execution scans', execution_scans, 'schedule_tick'),
)


@pytest.mark.parametrize('failed', range(len(TICKS)))
def test_failed_tick_does_not_skip_other_ticks_or_dispatch(admin, monkeypatch, caplog, failed):
    with Session() as s:
        s.add(Host(id='tick-host', name='Tick fixture', address='192.0.2.2', fingerprint=''))
        s.add(Job(id='tick-job', host_id='tick-host', action='refresh'))
        s.commit()
    offsets = [0, 1, 2, 30, 31, 60, 61, 90, 91]
    step = [-1]
    base = time.time()
    calls = {name: [] for name, _, _ in TICKS}
    for index, (name, module, attribute) in enumerate(TICKS):
        def tick(now, index=index, name=name):
            calls[name].append(offsets[step[0]])
            if index == failed:
                raise ValueError('Fixture invalid periodic policy')
        monkeypatch.setattr(module, attribute, tick)
    admitted = []
    submitted = []
    monkeypatch.setattr(worker, 'submit_job', lambda *args: admitted.append(step[0]) or False)
    monkeypatch.setattr(worker, 'reconcile_interrupted_advisory_jobs', lambda: None)
    monkeypatch.setattr(worker.operations, 'collect_alerts', lambda: None)

    class Pool:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def submit(self, fn, *args):
            submitted.append(fn)
            future = Future()
            future.set_result(None)
            return future

    def wait(_):
        step[0] += 1
        return step[0] >= len(offsets)

    monkeypatch.setattr(worker.concurrent.futures, 'ThreadPoolExecutor', Pool)
    monkeypatch.setattr(worker.stop, 'wait', wait)
    monkeypatch.setattr(worker.time, 'time', lambda: base + offsets[min(step[0], len(offsets)-1)])
    reporter = SimpleNamespace(capacity={'polls': 1, 'jobs': 1, 'ai': 1}, heartbeat=lambda *args: False)
    worker._loop(reporter)

    assert admitted == list(range(len(offsets))), 'Periodic failure must not skip queued-job dispatch'
    for index, (name, _, _) in enumerate(TICKS):
        assert calls[name] == ([0, 30, 90] if index == failed else [0, 30, 60, 90])
    assert worker.poll_host in submitted
    assert worker.operations.deliver_one in submitted
    assert worker.investigate_one in submitted and worker.update_scores.run_one in submitted
    assert caplog.text.count('retry in') == 3
    assert TICKS[failed][0] in caplog.text


def test_retry_backoff_is_bounded_and_success_restores_normal_cadence(monkeypatch):
    for _, module, attribute in TICKS:
        monkeypatch.setattr(module, attribute, lambda now: None)
    called = []
    def flaky(now):
        called.append(now)
        if now < 1000:
            raise OSError('Fixture unavailable')
    monkeypatch.setattr(worker.scheduling, 'tick', flaky)
    state = {}
    for now in [0, 1, 29, 30, 31, 89, 90, 209, 210, 449, 450, 749, 750, 1049, 1050, 1051, 1079, 1080]:
        worker.periodic_ticks(now, state)
    assert called == [0, 30, 90, 210, 450, 750, 1050, 1080]


def test_identity_loss_is_not_treated_as_a_retriable_producer_failure(monkeypatch):
    from app.worker_registry import IdentityLost
    called = []
    for _, module, attribute in TICKS:
        monkeypatch.setattr(module, attribute, lambda now: called.append(now))
    def lost(now):
        raise IdentityLost('Fixture identity changed')
    monkeypatch.setattr(worker.scheduling, 'tick', lost)
    with pytest.raises(IdentityLost):
        worker.periodic_ticks(100, {})
    assert called == []
