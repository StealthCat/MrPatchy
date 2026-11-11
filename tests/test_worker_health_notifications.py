import json

from sqlalchemy import func, select

from app import notifications, worker_registry as registry
from app.db import Session, Setting
from app.identity import User
from app.main import APP_VERSION

NOW = 10_000
STARTED = NOW - 3600


def viewer():
    with Session() as s:
        s.add(User(username='viewer', password='x', role='viewer'))
        s.commit()


def report(identity, **values):
    data = {'id': identity, 'heartbeat': NOW, 'state': 'reporting', 'version': APP_VERSION}
    data.update(values)
    with Session() as s:
        s.merge(Setting(key=registry.record_key(identity), value=data))
        s.commit()


def events(username='admin'):
    with Session() as s:
        return {(row['kind'], row['subject_id']): row for row in notifications.list_for_user(s, username, include_dismissed=True)}


def revisions():
    with Session() as s:
        return s.scalar(select(func.count()).select_from(notifications.NotificationRevision))


def publish(now=NOW, started=STARTED):
    return registry.publish_notifications(now=now, started=started)


def test_attention_states_publish_admin_only_fixed_text_and_deduplicate(admin, monkeypatch):
    viewer()
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS', 'healthy,absent,old,gone,mismatch,future,drain')
    report('healthy')
    report('old', heartbeat=NOW - registry.FRESH_SECONDS - 1, api_key='must-not-leak')
    report('gone', state='stopped')
    report('mismatch', version='0.0.1')
    report('future', heartbeat=NOW + 60)
    report('drain', state='draining')
    assert publish() == 5
    rows = events()
    assert set(rows) == {('worker-health', name) for name in ('absent', 'old', 'gone', 'mismatch', 'future')}
    assert {name: rows[('worker-health', name)]['severity'] for name in ('absent', 'old', 'gone', 'mismatch', 'future')} == {
        'absent': 'high', 'old': 'high', 'gone': 'high', 'mismatch': 'medium', 'future': 'medium'}
    for row in rows.values():
        assert row['source'] == 'deployment' and row['lifecycle'] == 'active'
        assert row['deep_link'] == '#activity/workers' and row['host_id'] == ''
    assert 'must-not-leak' not in json.dumps(list(rows.values()))
    assert 'no matching registration' in rows[('worker-health', 'absent')]['reason']
    assert events('viewer') == {}
    before = revisions()
    assert publish(now=NOW + 1) == 0 and revisions() == before


def test_state_change_resurfaces_and_recovery_resolves(admin, monkeypatch):
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS', 'w1')
    report('w1', heartbeat=NOW - registry.FRESH_SECONDS - 1)
    assert publish() == 1
    with Session() as s:
        row = events()[('worker-health', 'w1')]
        notifications.mark_read(s, 'admin', row['id'], row['revision'])
        s.commit()
    report('w1', state='stopped')
    assert publish() == 1
    row = events()[('worker-health', 'w1')]
    assert row['revision'] == 2 and not row['read'] and 'graceful stop' in row['reason']
    report('w1')
    assert publish() == 1
    row = events()[('worker-health', 'w1')]
    assert row['lifecycle'] == 'resolved' and row['severity'] == 'info'
    assert publish() == 0
    report('w1', state='drained')
    assert publish() == 0
    report('w1', heartbeat=NOW - registry.FRESH_SECONDS - 1)
    assert publish() == 1 and events()[('worker-health', 'w1')]['lifecycle'] == 'active'
    report('w1', state='drained')
    assert publish() == 1 and events()[('worker-health', 'w1')]['lifecycle'] == 'resolved'


def test_healthy_or_unconfigured_workers_publish_nothing(admin, monkeypatch):
    monkeypatch.delenv('MRPATCHY_EXPECTED_WORKER_IDS', raising=False)
    report('unexpected', state='stopped')
    assert publish() == 0
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS', 'fine')
    report('fine')
    assert publish() == 0 and revisions() == 0


def test_removed_expectation_resolves_and_invalid_configuration_is_separate(admin, monkeypatch):
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS', 'keep,drop')
    assert publish() == 2
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS', 'bad id!')
    assert publish() == 1
    rows = events()
    assert rows[('worker-expectation', 'MRPATCHY_EXPECTED_WORKER_IDS')]['severity'] == 'medium'
    # Invalid configuration cannot prove removal: earlier worker events stay active.
    assert rows[('worker-health', 'drop')]['lifecycle'] == 'active'
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS', 'keep')
    assert publish() == 2
    rows = events()
    assert rows[('worker-expectation', 'MRPATCHY_EXPECTED_WORKER_IDS')]['lifecycle'] == 'resolved'
    assert rows[('worker-health', 'drop')]['lifecycle'] == 'resolved'
    assert 'no longer in the expected-worker configuration' in rows[('worker-health', 'drop')]['reason']
    assert rows[('worker-health', 'keep')]['lifecycle'] == 'active'


def test_startup_grace_suppresses_new_attention_but_not_resolution(admin, monkeypatch):
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS', 'late,back')
    report('back', heartbeat=NOW - registry.FRESH_SECONDS - 1)
    assert publish() == 2
    report('back')
    assert publish(started=NOW - 1) == 1
    rows = events()
    assert ('worker-health', 'late') in rows and rows[('worker-health', 'back')]['lifecycle'] == 'resolved'
    # A fresh controller does not announce a not-yet-registered co-started worker.
    with Session() as s:
        for model in (notifications.NotificationArrival, notifications.NotificationRevision, notifications.NotificationEvent):
            s.query(model).delete()
        s.commit()
    assert publish(started=NOW - 1) == 0 and revisions() == 0
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS', 'bad id!')
    assert publish(started=NOW - 1) == 0
    assert publish(now=NOW + registry.FRESH_SECONDS, started=NOW) == 1


def test_coordinator_tick_failure_is_contained(admin, monkeypatch):
    import inspect
    from app import worker
    source = inspect.getsource(worker)
    call = source.index('worker_registry.publish_notifications()')
    assert source.index('operations.collect_alerts()') < call
    assert 'except Exception:log.exception' in source[call:call + 200]
