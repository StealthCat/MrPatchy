"""Unified read-only deployment-health summary (issue #843, roadmap H slice)."""
import json
import time

import pytest

from app import controller_registry, worker_registry
from app import deployment_health as health
from app.db import Audit, Host, Job, Session, Setting
from app.identity import User

UNIT = '/etc/systemd/system/mrpatchy-agent.service'


@pytest.fixture(autouse=True)
def _clean(admin, monkeypatch):
    # The app lifespan registers this test controller; start each case from an empty registry.
    monkeypatch.delenv('MRPATCHY_EXPECTED_WORKER_IDS', raising=False)
    monkeypatch.delenv('MRPATCHY_EXPECTED_CONTROLLER_IDS', raising=False)
    with Session() as s:
        for row in s.query(Setting).filter(Setting.key.startswith(controller_registry.PREFIX)).all():
            s.delete(row)
        s.commit()


def worker(identity, now, state='reporting', age=5, version=None):
    with Session() as s:
        s.merge(Setting(key=worker_registry.record_key(identity), value={
            'id': identity, 'boot_id': 'a' * 32, 'state': state, 'heartbeat': now - age,
            'version': version or worker_registry.source_version()}))
        s.commit()


def controller(identity, now, state='reporting', age=5, version=None):
    with Session() as s:
        s.merge(Setting(key=controller_registry.record_key(identity), value={
            'id': identity, 'boot_id': 'b' * 32, 'state': state, 'heartbeat': now - age,
            'version': version or worker_registry.source_version(), 'deployment_type': 'docker'}))
        s.commit()


def agent(name, now, receipt_state='current'):
    with Session() as s:
        s.add(Host(id=name, name=name, address='192.0.2.9', fingerprint='', state='online',
                   telemetry={'collected': now - 10, 'processes': [{'cmd': 'secret-arg'}]}))
        s.add(Setting(key='agent-status:' + name, value={
            'state': receipt_state, 'checked': now - 10, 'issues': [{'path': '/etc/sudoers.d/x'}],
            'report': {'version': 1, 'unit_path': UNIT, 'files': {'/x': {'sha256': 'f' * 64}}}}))
        s.commit()


def test_empty_deployment_is_unknown_never_healthy():
    data = health.summary(time.time())
    assert data['overall']['state'] == 'unknown'
    assert all(row['state'] is None and row['total'] == 0 for row in data['components'].values())


def test_all_healthy_components_report_healthy():
    now = time.time()
    worker('w1', now)
    controller('c1', now)
    agent('web', now)
    data = health.summary(now)
    assert data['overall']['state'] == 'healthy'
    assert {name: row['state'] for name, row in data['components'].items()} == {
        'controllers': 'healthy', 'workers': 'healthy', 'endpoint_agents': 'healthy'}


def test_worker_states_are_normalized_and_worst_wins():
    now = time.time()
    worker('ok', now)
    worker('drain', now, state='draining')
    worker('old', now, age=10_000)
    worker('bump', now, version='0.0.1')
    row = health.summary(now)['components']['workers']
    assert row['counts'] == {'offline': 1, 'degraded': 1, 'unknown': 0, 'maintenance': 1, 'healthy': 1}
    assert row['state'] == 'offline' and row['source'] == 'registrations'
    data = health.summary(now)
    assert data['overall']['state'] == 'offline' and data['overall']['reason'].startswith('Workers:')


def test_maintenance_ranks_below_unknown_and_above_healthy():
    now = time.time()
    worker('drain', now, state='drained')
    agent('web', now)
    assert health.summary(now)['overall']['state'] == 'maintenance'
    agent('blocked', now, receipt_state='blocked')
    assert health.summary(now)['overall']['state'] == 'degraded'


def test_configured_missing_worker_is_offline(monkeypatch):
    now = time.time()
    worker('w1', now)
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS', 'w1,w2')
    row = health.summary(now)['components']['workers']
    assert row['source'] == 'configuration' and row['counts']['offline'] == 1 and row['counts']['healthy'] == 1


def test_invalid_worker_configuration_is_unknown(monkeypatch):
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS', 'bad id!')
    data = health.summary(time.time())
    row = data['components']['workers']
    assert row['state'] == 'unknown' and row['error'] and row['total'] == 0
    assert data['overall']['state'] == 'unknown'


def test_unconfigured_controller_history_is_not_offline():
    now = time.time()
    controller('live', now)
    controller('old-start', now, age=86_400)
    controller('quit', now, state='stopped')
    row = health.summary(now)['components']['controllers']
    assert row['source'] == 'registrations' and row['counts']['healthy'] == 1 and row['counts']['offline'] == 0
    assert any('cannot be detected' in gap for gap in row['gaps'])


def test_configured_controllers_report_missing_and_mismatch(monkeypatch):
    now = time.time()
    controller('c1', now, version='0.0.1')
    monkeypatch.setenv('MRPATCHY_EXPECTED_CONTROLLER_IDS', 'c1,c2')
    row = health.summary(now)['components']['controllers']
    assert row['source'] == 'configuration'
    assert row['counts']['offline'] == 1 and row['counts']['degraded'] == 1 and row['state'] == 'offline'


def test_invalid_controller_configuration_is_unknown(monkeypatch):
    monkeypatch.setenv('MRPATCHY_EXPECTED_CONTROLLER_IDS', 'bad id!')
    row = health.summary(time.time())['components']['controllers']
    assert row['state'] == 'unknown' and row['error']


def test_api_is_admin_redacted_and_read_only(admin):
    now = time.time()
    worker('w1', now)
    controller('c1', now)
    agent('web', now, receipt_state='blocked')
    with Session() as s:
        before = (s.query(Audit).count(), s.query(Job).count(), {r.key: r.value for r in s.query(Setting).all()})
    response = admin.get('/api/operations/deployment-health')
    assert response.status_code == 200
    data = response.json()
    assert data['overall']['state'] == 'degraded' and data['overall']['reason'].startswith('Endpoint agents:')
    text = json.dumps(data)
    for secret in ('sudoers', 'sha256', 'ffff', '192.0.2.9', 'secret-arg', 'aaaa', 'bbbb'):
        assert secret not in text, secret
    with Session() as s:
        after = (s.query(Audit).count(), s.query(Job).count(), {r.key: r.value for r in s.query(Setting).all()})
    assert before == after


@pytest.mark.parametrize('role', ['viewer', 'operator'])
def test_non_administrators_are_refused(admin, role):
    with Session() as s:
        s.get(User, 'admin').role = role
        s.commit()
    assert admin.get('/api/operations/deployment-health').status_code == 403
