"""A failing periodic producer must not stall independent scheduling/dispatch."""
from concurrent.futures import Future
from types import SimpleNamespace
import time

import pytest
from app import worker, persistence, response_monitor, service_monitor, execution_scans, plan_notifications, release_notifications
from app.db import Session, Host, Job, Package, Setting

TICKS = (
    ('patch schedules', worker.scheduling, 'tick'),
    ('scanner schedules', worker.incidents, 'schedule_tick'),
    ('startup schedules', persistence, 'schedule_tick'),
    ('incident AI plans', worker.incidents, 'auto_plan_tick'),
    ('response monitoring', response_monitor, 'schedule_tick'),
    ('service monitoring', service_monitor, 'schedule_tick'),
    ('execution scans', execution_scans, 'schedule_tick'),
    ('plan review notifications', plan_notifications, 'tick'),
    ('release plan notifications', release_notifications, 'tick'),
)


@pytest.mark.parametrize('failed', range(len(TICKS)))
def test_failed_tick_does_not_skip_other_ticks_or_dispatch(admin, monkeypatch, caplog, failed):
    with Session() as s:
        s.add(Host(id='tick-host', name='Tick fixture', address='192.0.2.2', fingerprint=''))
        s.add(Job(id='tick-job', host_id='tick-host', action='refresh'))
        s.add(Package(id='tick-host:fixture', host_id='tick-host', name='fixture', installed='1', candidate='2'))
        s.merge(Setting(key='config', value={'ai_enabled': True, 'ai_updates_enabled': True,
                                             'ai_model': 'fixture-model'}))
        s.merge(Setting(key='openai_key', value={'encrypted': 'fixture'}))
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
    monkeypatch.setattr(worker.operations, 'collect_alerts', lambda **_: None)

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


@pytest.mark.parametrize(('leader', 'failed_pruner'), [
    (False, None), (True, None), (True, 'arrivals'), (True, 'resolved'),
])
def test_notification_retention_runs_only_in_hourly_leader_cleanup(
    admin, monkeypatch, caplog, leader, failed_pruner,
):
    from app.db import config

    offsets = iter([0, 5, 15, 3601, 3606])
    base = time.time()
    with Session() as session:
        retention = config(session)['history_days'] * 86400
    now = base
    calls = []
    dispatched = []

    class Pool:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def submit(self, fn, *args):
            if fn in (worker.investigate_one, worker.update_scores.run_one):
                dispatched.append(now)
            future = Future()
            future.set_result(None)
            return future

    def wait(_):
        nonlocal now
        offset = next(offsets, None)
        if offset is None:
            return True
        now = base + offset
        return False

    def prune(kind, cutoff):
        calls.append((kind, cutoff))
        if failed_pruner == kind:
            raise RuntimeError('Fixture notification cleanup failure')

    lock = SimpleNamespace(acquire=lambda _: leader, owned=lambda: leader, release=lambda: None)
    monkeypatch.setattr(worker, 'Lock', lambda _: lock)
    monkeypatch.setattr(worker.concurrent.futures, 'ThreadPoolExecutor', Pool)
    monkeypatch.setattr(worker.stop, 'wait', wait)
    monkeypatch.setattr(worker, 'time', SimpleNamespace(time=lambda: now, sleep=lambda _: None))
    monkeypatch.setattr(worker, 'periodic_ticks', lambda *_: None)
    monkeypatch.setattr(worker, 'reconcile_interrupted_advisory_jobs', lambda: None)
    monkeypatch.setattr(worker.operations, 'collect_alerts', lambda **_: None)
    monkeypatch.setattr(worker, 'prune_history', lambda *_: None)
    monkeypatch.setattr(worker.notifications, 'prune_arrivals', lambda cutoff: prune('arrivals', cutoff))
    monkeypatch.setattr(worker.notifications, 'prune_resolved', lambda cutoff: prune('resolved', cutoff))
    reporter = SimpleNamespace(capacity={'polls': 1, 'jobs': 1, 'ai': 1}, heartbeat=lambda *args: False)
    worker._loop(reporter)

    assert dispatched == [base + offset for offset in (0, 5, 15, 3601, 3606)]
    expected = [
        (kind, base + offset - retention)
        for offset in (0, 3601) for kind in ('arrivals', 'resolved')
    ]
    assert calls == (expected if leader else [])
    assert caplog.text.count('Notification arrival pruning failed') == (2 if failed_pruner == 'arrivals' else 0)
    assert caplog.text.count('Resolved notification pruning failed') == (2 if failed_pruner == 'resolved' else 0)
    assert 'UnboundLocalError' not in caplog.text


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


def test_optional_producer_import_failure_does_not_skip_other_producers(monkeypatch):
    called = []
    for name, module, attribute in TICKS:
        monkeypatch.setattr(module, attribute, lambda now, name=name: called.append(name))
    original = worker.importlib.import_module
    attempts = []
    def unavailable(name, package=None):
        if name == '.persistence':
            attempts.append(name)
            raise ImportError('Fixture producer dependency unavailable')
        return original(name, package)
    monkeypatch.setattr(worker.importlib, 'import_module', unavailable)
    state = {}
    worker.periodic_ticks(100, state)
    worker.periodic_ticks(101, state)
    assert called == [name for name, _, _ in TICKS if name != 'startup schedules']
    assert attempts == ['.persistence']


@pytest.mark.parametrize(('queue', 'expected'), [
    ('disabled', ['triage'] * 4),
    ('empty', ['triage'] * 4),
    ('paused', ['triage'] * 4),
    ('inactive', ['triage'] * 4),
    ('eligible', ['scoring', 'triage', 'scoring', 'triage']),
    ('recovery', ['scoring', 'triage', 'triage', 'triage']),
    ('warm', ['scoring', 'triage', 'triage', 'triage']),
    ('legacy-zero', ['triage'] * 4),
    ('legacy-full-warm', ['triage'] * 4),
    ('legacy-cutoff', ['triage', 'triage', 'scoring', 'triage']),
    ('legacy-recovery', ['scoring', 'triage', 'triage', 'triage']),
])
def test_serial_ai_dispatch_uses_scoring_turn_only_when_needed(admin, monkeypatch, queue, expected):
    enabled = queue not in ('disabled', 'recovery')
    memo = {'absent': (None, {}, {})} if queue in ('warm', 'legacy-full-warm') else {}
    legacy = queue.startswith('legacy-')
    recovery = queue in ('recovery', 'legacy-recovery')
    legacy_limit = 0 if queue in ('legacy-zero', 'legacy-recovery') else 1
    now = base = int(time.time())
    monkeypatch.setattr(worker.update_scores, '_MEMO', memo)
    with Session() as s:
        s.merge(Setting(key='config', value={'ai_enabled': True, 'ai_updates_enabled': enabled,
                                             'ai_model': 'fixture-model',
                                             'ai_control_mode': 'legacy' if legacy else 'unthrottled',
                                             'ai_update_hourly_limit': legacy_limit}))
        s.merge(Setting(key='openai_key', value={'encrypted': 'fixture'}))
        if queue in ('eligible', 'inactive', 'paused', 'legacy-zero', 'legacy-cutoff'):
            s.add(Host(id='score-host', name='Scoring fixture', address='192.0.2.1',
                       fingerprint='', enabled=queue != 'inactive'))
            s.add(Package(id='score-host:fixture', host_id='score-host', name='fixture',
                          installed='1', candidate='2'))
        if queue == 'paused':
            s.add(Setting(key='server-ai:score-host', value={'paused': True}))
        if recovery:
            s.add(worker.ai_runs.AIRun(id='orphan-score', purpose='update_scoring', state='running'))
        if queue in ('legacy-full-warm', 'legacy-cutoff'):
            started = base - 3590 if queue == 'legacy-cutoff' else base
            s.add(worker.ai_runs.AIRun(id='previous-score', purpose='update_scoring',
                                       started=started, state='complete'))
        s.commit()

    offsets = iter((0, 5, 10, 15))
    dispatched = []

    def wait(_):
        nonlocal now
        offset = next(offsets, None)
        if offset is None:
            return True
        now = base + offset
        return False

    class Pool:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def submit(self, fn, *args):
            if fn is worker.investigate_one:
                dispatched.append('triage')
            elif fn is worker.update_scores.run_one:
                dispatched.append('scoring')
                if recovery or queue == 'warm':
                    fn(*args)
            future = Future()
            future.set_result(None)
            return future

    monkeypatch.setattr(worker.concurrent.futures, 'ThreadPoolExecutor', Pool)
    monkeypatch.setattr(worker.stop, 'wait', wait)
    monkeypatch.setattr(worker, 'time', SimpleNamespace(time=lambda: now, sleep=lambda _: None))
    monkeypatch.setattr(worker.update_scores, 'time', SimpleNamespace(time=lambda: now))
    monkeypatch.setattr(worker, 'periodic_ticks', lambda *_: None)
    monkeypatch.setattr(worker, 'reconcile_interrupted_advisory_jobs', lambda: None)
    monkeypatch.setattr(worker, 'prune_history', lambda *_: None)
    monkeypatch.setattr(worker.operations, 'collect_alerts', lambda **_: None)
    reporter = SimpleNamespace(capacity={'polls': 1, 'jobs': 1, 'ai': 1}, heartbeat=lambda *args: False)
    worker._loop(reporter)

    assert dispatched == expected
    if queue == 'warm':
        assert not memo
    if recovery:
        with Session() as s:
            recovered = s.get(worker.ai_runs.AIRun, 'orphan-score')
            assert recovered.state == 'interrupted' and recovered.calls == 0
