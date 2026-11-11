import json
import pytest
from sqlalchemy import select
from app import controller_registry as registry
from app.db import Audit, Session, Setting
from app.identity import User
from app.main import APP_VERSION


def rows(admin, **params):
    response = admin.get('/api/operations/controllers', params=params)
    assert response.status_code == 200
    return response.json()


def test_lifespan_registers_this_controller_and_records_stop(admin):
    data = rows(admin)
    assert len(data['items']) == 1
    row = data['items'][0]
    assert row['state'] == 'reporting' and row['version'] == APP_VERSION
    assert row['scheduler'] == 'disabled' and row['deployment_type'] == 'process'
    assert row['readiness'] == 'not_assessed' and data['fresh_seconds'] == 120
    assert len(row['boot_id']) == 32 and row['uptime_seconds'] is not None
    with Session() as s:
        actions = [a.action for a in s.scalars(select(Audit))]
    assert 'controller registered' in actions


def test_presence_exclusive_heartbeat_and_graceful_stop(admin, monkeypatch):
    monkeypatch.setenv('MRPATCHY_CONTROLLER_ID', 'controller-east')
    monkeypatch.setenv('MRPATCHY_DEPLOYMENT_TYPE', 'docker')
    first = registry.Presence(True).start()
    try:
        with pytest.raises(ValueError, match='already in use'):
            registry.Presence(True).start()
        before = {r['id']: r for r in rows(admin)['items']}['controller-east']
        first.write('reporting')
        after = {r['id']: r for r in rows(admin)['items']}['controller-east']
        assert after['heartbeat'] >= before['heartbeat'] and after['scheduler'] == 'embedded'
        assert after['deployment_type'] == 'docker' and after['state'] == 'reporting'
    finally:
        first.close()
    assert {r['id']: r for r in rows(admin)['items']}['controller-east']['state'] == 'stopped'
    second = registry.Presence(False).start()
    try:
        assert second.boot != first.boot
    finally:
        second.close()


def test_record_key_fits_settings_column():
    from app.db import Setting
    assert len(registry.record_key('x' * 48)) <= Setting.__table__.c.key.type.length


def test_invalid_identity_and_deployment_are_refused(monkeypatch):
    monkeypatch.setenv('MRPATCHY_CONTROLLER_ID', 'bad id!')
    with pytest.raises(ValueError, match='MRPATCHY_CONTROLLER_ID'):
        registry.Presence(False)
    monkeypatch.setenv('MRPATCHY_CONTROLLER_ID', 'ok-id')
    monkeypatch.setenv('MRPATCHY_DEPLOYMENT_TYPE', 'kubernetes')
    with pytest.raises(ValueError, match='deployment type'):
        registry.Presence(False)


def test_states_and_secret_projection(admin):
    version = APP_VERSION
    values = [
        ('fresh', {'heartbeat': 1000, 'state': 'reporting', 'version': version}),
        ('stale', {'heartbeat': 879, 'state': 'reporting', 'version': version}),
        ('future', {'heartbeat': 1006, 'state': 'reporting', 'version': version}),
        ('mismatch', {'heartbeat': 1000, 'state': 'reporting', 'version': '0.0.1'}),
        ('stopped', {'heartbeat': 1000, 'state': 'stopped', 'version': version}),
        ('odd-state', {'heartbeat': 1000, 'state': 'serving', 'version': version}),
        ('broken', {'heartbeat': 'invalid', 'secret': 'must-not-leak'}),
    ]
    with Session() as s:
        for key, value in values:
            s.add(Setting(key=registry.record_key(key), value={**value, 'id': key, 'api_key': 'must-not-leak'}))
        s.add(Setting(key=registry.PREFIX + 'forged', value={'id': 'fresh', 'heartbeat': 1000, 'state': 'reporting', 'version': version}))
        s.commit()
    data = registry.page(now=1000)
    states = {}
    for r in data['items']:
        states.setdefault(r['id'], []).append(r['state'])
    assert states['stale'] == ['stale'] and states['future'] == ['unknown']
    assert states['mismatch'] == ['version_mismatch'] and states['stopped'] == ['stopped']
    assert states['odd-state'] == ['unknown'] and states['broken'] == ['unknown']
    # A record whose key does not match its claimed identity is never reported healthy.
    assert sorted(states['fresh']) == ['reporting', 'unknown']
    assert 'must-not-leak' not in json.dumps(data, allow_nan=False)


def test_expected_controllers(admin, monkeypatch):
    with Session() as s:
        s.add(Setting(key=registry.record_key('east'), value={'id': 'east', 'heartbeat': 1000, 'state': 'reporting', 'version': APP_VERSION}))
        s.commit()
    monkeypatch.setenv('MRPATCHY_EXPECTED_CONTROLLER_IDS', 'east, west')
    expected = {r['id']: r for r in registry.page(now=1000)['expected']}
    assert expected['east']['state'] == 'reporting' and expected['east']['registered']
    assert expected['west']['state'] == 'missing' and not expected['west']['registered']
    for raw in ('east,east', 'bad id', ','.join('c%d' % n for n in range(101))):
        monkeypatch.setenv('MRPATCHY_EXPECTED_CONTROLLER_IDS', raw)
        data = registry.page(now=1000)
        assert data['expected'] == [] and 'invalid' in data['expectation_error']


def test_live_controller_listed_before_retained_history(admin):
    # Default installs register a new random identity per start; retained stopped rows must not push
    # the reporting controller off the only page the UI fetches (keys sort as SHA-256, i.e. randomly).
    with Session() as s:
        for n in range(80):
            s.add(Setting(key=registry.record_key('old%d' % n), value={'id': 'old%d' % n, 'heartbeat': 100 + n, 'state': 'stopped', 'version': APP_VERSION}))
        s.add(Setting(key=registry.record_key('future'), value={'id': 'future', 'heartbeat': 5000, 'state': 'reporting', 'version': APP_VERSION}))
        s.add(Setting(key=registry.record_key('live'), value={'id': 'live', 'heartbeat': 999, 'state': 'reporting', 'version': APP_VERSION}))
        s.commit()
    data = registry.page(now=1000)
    assert data['items'][0]['id'] == 'live' and data['items'][0]['state'] == 'reporting'
    assert [r['id'] for r in data['items'][1:4]] == ['old79', 'old78', 'old77']
    assert data['more'] and not data['truncated']
    rest = registry.page(offset=50, now=1000)['items']
    # The app lifespan's own registration has a real-clock heartbeat, i.e. "future" relative to now=1000.
    ids = [r['id'] for r in data['items'] + rest if r['id'] == 'live' or r['id'] == 'future' or r['id'].startswith('old')]
    assert len(ids) == 82 and ids.index('future') > ids.index('old0')
    assert next(r for r in rest if r['id'] == 'future')['state'] == 'unknown'


def test_pagination_roles_and_no_network(admin, monkeypatch):
    from app import ai, ssh
    monkeypatch.setattr(ai, 'request', lambda *a, **k: pytest.fail('AI must not run'))
    monkeypatch.setattr(ssh, 'call', lambda *a, **k: pytest.fail('Target must not be contacted'))
    with Session() as s:
        for n in range(53):
            s.add(Setting(key=registry.PREFIX + '0' + str(n).zfill(3), value={}))
        s.commit()
    data = rows(admin)
    assert len(data['items']) == 50 and data['more']
    assert len(rows(admin, offset=50)['items']) == 4
    assert admin.get('/api/operations/controllers?offset=-1').status_code == 400
    for role in ('viewer', 'operator'):
        with Session() as s:
            s.get(User, 'admin').role = role
            s.commit()
        assert admin.get('/api/operations/controllers').status_code == 403
