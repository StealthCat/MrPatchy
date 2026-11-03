"""Leader 30 s work must not issue one query per host or per package (#181)."""
import time

import pytest
from sqlalchemy import event, select

from app import operations, scheduling as sched, worker
from app.db import Host, Package, Session, engine

HOSTS = 40


@pytest.fixture
def counted():
    box = []
    def observe(conn, cursor, statement, *args): box.append(statement)
    event.listen(engine, 'before_cursor_execute', observe)
    yield box
    event.remove(engine, 'before_cursor_execute', observe)


def seed(now):
    with Session() as s:
        for n in range(HOSTS):
            id = f'h{n:03d}'
            s.add(Host(id=id, name=id, address='192.0.2.10', fingerprint='SHA256:' + 'a' * 43, state='online',
                       last_seen=now, last_repo=now, inventory={'status': 'fixture'}))
            s.add(Package(id=id + ':bash', host_id=id, name='bash', installed='1', candidate='2', priority='critical',
                          available_since=now - 7200, dpkg_state='ii installed'))
        policy = sched.ScheduleInput(name='Fleet', enabled=True, approved=True, frequency='daily').model_dump(exclude={'revision', 'approved'})
        policy['critical'] = {**policy['critical'], 'enabled': True, 'after_minutes': 0}
        s.add(sched.PatchSchedule(id='schedule', policy=policy, revision=1, updated=now - 86400))
        s.commit()


def test_scheduler_tick_query_count_is_independent_of_host_count(admin, counted):
    now = time.time(); seed(now)
    sched.tick(now); counted.clear()
    sched.tick(now)
    package_reads = [sql for sql in counted if 'FROM packages' in sql]
    assert len(package_reads) <= 2, len(package_reads)
    # Deferred Host attributes must not turn into one SELECT per attribute per host (coordinator return on #275).
    host_reads = [sql for sql in counted if 'FROM hosts' in sql]
    assert len(host_reads) < HOSTS, len(host_reads)
    assert len(counted) < 15 * HOSTS, len(counted)
    with Session() as s:
        assert s.scalar(select(sched.PatchRun.id).where(sched.PatchRun.trigger == 'critical').limit(1))


def test_collect_alerts_query_count_grows_slowly_with_hosts(admin, counted):
    now = time.time(); seed(now)
    operations.collect_alerts(); counted.clear()
    operations.collect_alerts()
    assert len(counted) < 6 * HOSTS, len(counted)


def test_update_repos_loads_packages_once(admin, counted, monkeypatch):
    now = time.time(); seed(now)
    names = [{'name': f'pkg{n}', 'candidate': '3', 'origin': 'x', 'priority': 'normal'} for n in range(200)]
    with Session() as s:
        for item in names:
            s.add(Package(id='h000:' + item['name'], host_id='h000', name=item['name'], installed='1'))
        s.commit()
    monkeypatch.setattr(worker.package_backend, 'refresh', lambda *a: (names, ''))
    with Session() as s:
        h = s.get(Host, 'h000'); h.state = 'offline'
        counted.clear()
        worker.update_repos(s, h)
        assert len(counted) < 20, len(counted)
        assert s.get(Package, 'h000:pkg7').candidate == '3'


def test_scheduler_tick_with_open_window_issues_few_statements_per_host(admin, counted):
    # 02:30 UTC is inside the seeded daily 02:00 window, so every host gets a regular and a critical run (#330).
    import datetime as dt
    now = dt.datetime(2026, 11, 3, 2, 30, tzinfo=dt.timezone.utc).timestamp(); seed(now)
    sched.tick(now); counted.clear()
    sched.tick(now)
    assert len(counted) < 2 * HOSTS, len(counted)
    with Session() as s:
        runs = list(s.scalars(select(sched.PatchRun)))
    assert len(runs) == 2 * HOSTS and {r.state for r in runs} <= {'refreshing', 'waiting'}


def test_quarantined_hosts_matches_host_quarantined(admin):
    from app.db import Job
    now = time.time(); seed(now)
    with Session() as s:
        s.add(Job(id='held', host_id='h003', action='patch', payload={}, state='running'))
        s.add(Job(id='queued', host_id='h004', action='patch', payload={}, state='queued'))
        s.commit()
        ids = [f'h{n:03d}' for n in range(HOSTS)]
        assert operations.quarantined_hosts(s, ids) == {i for i in ids if operations.host_quarantined(s, i)} == {'h003'}
