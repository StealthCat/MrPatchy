import json

from sqlalchemy import func, select

from app import controller_registry as registry, notifications
from app.db import Session, Setting
from app.identity import User
from app.main import APP_VERSION

NOW = 10_000
STARTED = NOW - 3600
ENV = 'MRPATCHY_EXPECTED_CONTROLLER_IDS'


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


def events(username='admin', source='deployment'):
    with Session() as s:
        return {(row['kind'], row['subject_id']): row
                for row in notifications.list_for_user(s, username, include_dismissed=True) if row['source'] == source}


def revisions():
    with Session() as s:
        return s.scalar(select(func.count()).select_from(notifications.NotificationRevision))


def publish(now=NOW, started=STARTED):
    return registry.publish_notifications(now=now, started=started)


def test_attention_states_publish_admin_only_fixed_text_and_deduplicate(admin, monkeypatch):
    viewer()
    monkeypatch.setenv(ENV, 'healthy,absent,old,gone,mismatch,future,odd')
    report('healthy')
    report('old', heartbeat=NOW - registry.FRESH_SECONDS - 1, api_key='must-not-leak')
    report('gone', state='stopped')
    report('mismatch', version='0.0.1')
    report('future', heartbeat=NOW + 60)
    report('odd', state='<script>alert(1)</script>')
    assert publish() == 6
    rows = events()
    names = ('absent', 'old', 'gone', 'mismatch', 'future', 'odd')
    assert set(rows) == {('controller-health', name) for name in names}
    assert {name: rows[('controller-health', name)]['severity'] for name in names} == {
        'absent': 'high', 'old': 'high', 'gone': 'high', 'mismatch': 'medium', 'future': 'medium', 'odd': 'medium'}
    for row in rows.values():
        assert row['lifecycle'] == 'active' and row['deep_link'] == '#activity/workers' and row['host_id'] == ''
    dumped = json.dumps(list(rows.values()))
    assert 'must-not-leak' not in dumped and '<script>' not in dumped
    assert 'no matching registration' in rows[('controller-health', 'absent')]['reason']
    assert 'graceful stop' in rows[('controller-health', 'gone')]['reason']
    assert events('viewer') == {}
    before = revisions()
    assert publish(now=NOW + 1) == 0 and revisions() == before


def test_state_change_resurfaces_and_recovery_resolves(admin, monkeypatch):
    monkeypatch.setenv(ENV, 'c1')
    report('c1', heartbeat=NOW - registry.FRESH_SECONDS - 1)
    assert publish() == 1
    with Session() as s:
        row = events()[('controller-health', 'c1')]
        notifications.mark_read(s, 'admin', row['id'], row['revision'])
        s.commit()
    report('c1', state='stopped')
    assert publish() == 1
    row = events()[('controller-health', 'c1')]
    assert row['revision'] == 2 and not row['read'] and 'graceful stop' in row['reason']
    report('c1')
    assert publish() == 1
    row = events()[('controller-health', 'c1')]
    assert row['lifecycle'] == 'resolved' and row['severity'] == 'info'
    assert 'Serving readiness is not assessed' in row['reason']
    assert publish() == 0
    report('c1', heartbeat=NOW - registry.FRESH_SECONDS - 1)
    assert publish() == 1 and events()[('controller-health', 'c1')]['lifecycle'] == 'active'


def test_healthy_or_unconfigured_controllers_publish_nothing(admin, monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    report('unexpected', state='stopped')
    assert publish() == 0
    monkeypatch.setenv(ENV, 'fine')
    report('fine')
    assert publish() == 0 and events() == {}


def test_removed_expectation_resolves_and_invalid_configuration_is_separate(admin, monkeypatch):
    monkeypatch.setenv(ENV, 'keep,drop')
    assert publish() == 2
    monkeypatch.setenv(ENV, 'bad id!')
    assert publish() == 1
    rows = events()
    assert rows[('controller-expectation', ENV)]['severity'] == 'medium'
    # Invalid configuration cannot prove removal: earlier controller events stay active.
    assert rows[('controller-health', 'drop')]['lifecycle'] == 'active'
    assert publish(now=NOW + 1) == 0
    monkeypatch.setenv(ENV, 'keep')
    assert publish() == 2
    rows = events()
    assert rows[('controller-expectation', ENV)]['lifecycle'] == 'resolved'
    assert rows[('controller-health', 'drop')]['lifecycle'] == 'resolved'
    assert 'no longer in the expected-controller configuration' in rows[('controller-health', 'drop')]['reason']
    assert rows[('controller-health', 'keep')]['lifecycle'] == 'active'


def test_startup_grace_suppresses_new_attention_but_not_resolution(admin, monkeypatch):
    monkeypatch.setenv(ENV, 'late,back')
    report('back', heartbeat=NOW - registry.FRESH_SECONDS - 1)
    assert publish() == 2
    report('back')
    assert publish(started=NOW - 1) == 1
    rows = events()
    assert rows[('controller-health', 'late')]['lifecycle'] == 'active'
    assert rows[('controller-health', 'back')]['lifecycle'] == 'resolved'
    with Session() as s:
        for model in (notifications.NotificationArrival, notifications.NotificationRevision, notifications.NotificationEvent):
            s.query(model).delete()
        s.commit()
    # A freshly started coordinator does not announce a not-yet-registered co-started controller.
    assert publish(started=NOW - 1) == 0 and revisions() == 0
    monkeypatch.setenv(ENV, 'bad id!')
    assert publish(started=NOW - 1) == 0
    assert publish(now=NOW + registry.FRESH_SECONDS, started=NOW) == 1


def test_worker_and_controller_events_stay_separate(admin, monkeypatch):
    from app import worker_registry
    monkeypatch.setenv(ENV, 'shared-name')
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS', 'shared-name')
    assert publish() == 1
    assert worker_registry.publish_notifications(now=NOW, started=STARTED) == 1
    rows = events()
    assert set(rows) == {('controller-health', 'shared-name'), ('worker-health', 'shared-name')}
    report('shared-name')
    assert publish() == 1
    rows = events()
    assert rows[('controller-health', 'shared-name')]['lifecycle'] == 'resolved'
    assert rows[('worker-health', 'shared-name')]['lifecycle'] == 'active'


def test_coordinator_tick_failure_is_contained():
    import inspect
    from app import worker
    source = inspect.getsource(worker)
    call = source.index('controller_registry.publish_notifications()')
    assert source.index('worker_registry.publish_notifications()') < call
    assert "except Exception:log.exception('Expected-controller notifications failed')" in source[call:call + 200]
