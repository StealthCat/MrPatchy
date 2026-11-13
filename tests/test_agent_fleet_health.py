"""Read-only fleet endpoint-agent health (issue #737, roadmap H slice)."""
import json
import time

import pytest

from app import agent_fleet_health as fleet
from app.db import Host, Session, Setting, Audit, Job
from app.identity import User

NOW = 1_800_000_000.0
UNIT = '/etc/systemd/system/mrpatchy-agent.service'


def receipt(state='current', checked=NOW - 60, unit=UNIT, issues=()):
    return {'state': state, 'checked': checked, 'repairable': True, 'issues': list(issues),
            'report': {'version': 1, 'unit_path': unit, 'files': {'/usr/local/lib/mrpatchy/bridge.py': {'sha256': 'f' * 64}}}}


def host(state='online', collected=NOW - 30, **fields):
    return Host(id=fields.pop('id', 'h'), name=fields.pop('name', 'web'), state=state,
                telemetry={} if collected is None else {'collected': collected}, **fields)


def add(name, status=None, state='online', collected=NOW - 30, enabled=True, deleted_at=0):
    with Session() as s:
        s.add(Host(id=name, name=name, address='192.0.2.1', fingerprint='', state=state, enabled=enabled, deleted_at=deleted_at,
                   telemetry={} if collected is None else {'collected': collected, 'processes': [{'cmd': 'secret-arg'}]}))
        if status is not None:
            s.add(Setting(key='agent-status:' + name, value=status))
        s.commit()


@pytest.mark.parametrize('status,host_fields,health,needle', [
    (receipt(), {}, 'healthy', 'verified current'),
    (None, {}, 'unknown', 'No valid agent verification'),
    (receipt(checked=NOW - 601), {}, 'unknown', 'older than 600'),
    (receipt(checked=NOW + 500), {}, 'unknown', 'future'),
    (receipt(checked='bad'), {}, 'unknown', 'No valid'),
    (receipt(state='surprise'), {}, 'unknown', 'No valid'),
    (receipt(state='unavailable'), {}, 'offline', 'could not be completed'),
    (receipt(), {'state': 'offline'}, 'offline', 'marked offline'),
    (receipt(), {'state': 'enrolling'}, 'unknown', 'Enrollment is incomplete'),
    (receipt(state='blocked', issues=[{'path': '/etc/sudoers.d/mrpatchy', 'kind': 'x'}]), {}, 'degraded', 'administrator review'),
    (receipt(state='drifted'), {}, 'degraded', 'drift'),
    (receipt(state='outdated'), {}, 'degraded', 'outdated'),
    (receipt(), {'collected': NOW - 3600}, 'degraded', 'stale'),
    (receipt(), {'collected': None}, 'degraded', 'missing'),
    (receipt(), {'collected': NOW + 3600}, 'unknown', 'future collection'),
    (receipt(), {'collected': float('nan')}, 'degraded', 'missing'),
])
def test_classification_never_reports_stale_or_unsupported_as_healthy(status, host_fields, health, needle):
    row = fleet.classify(host(**host_fields), status, NOW)
    assert row['health'] == health and needle in row['reason']


def test_deployment_type_requires_the_verified_systemd_unit():
    assert fleet.classify(host(), receipt(), NOW)['deployment_type'] == 'systemd'
    assert fleet.classify(host(), receipt(unit='/run/other.service'), NOW)['deployment_type'] is None
    assert fleet.classify(host(), receipt(state='unavailable'), NOW)['deployment_type'] is None
    assert fleet.classify(host(), None, NOW)['deployment_type'] is None
    no_report = receipt(); no_report.pop('report')
    assert fleet.classify(host(), no_report, NOW)['deployment_type'] is None


def test_api_is_redacted_ordered_counted_and_read_only(admin):
    add('zeta', receipt(checked=time.time() - 10), collected=time.time())
    add('alpha', receipt(checked=time.time() - 10, state='blocked', issues=[{'path': '/etc/sudoers.d/mrpatchy', 'kind': 'unexpected'}]), collected=time.time())
    add('down', receipt(state='unavailable', checked=time.time()))
    add('new', None)
    add('off', receipt(), enabled=False)
    add('gone', receipt(), deleted_at=time.time())
    with Session() as s:
        before = (s.query(Audit).count(), s.query(Job).count(), {r.key: r.value for r in s.query(Setting).all()})
    response = admin.get('/api/operations/agents')
    assert response.status_code == 200
    data = response.json()
    assert [row['host_id'] for row in data['items']] == ['down', 'alpha', 'new', 'zeta']
    assert data['counts'] == {'offline': 1, 'degraded': 1, 'unknown': 1, 'healthy': 1} and data['total'] == 4
    assert data['items'][1]['verification']['issue_count'] == 1
    text = json.dumps(data)
    for secret in ('sudoers', 'sha256', 'ffff', '192.0.2.1', 'secret-arg', 'report', 'files'):
        assert secret not in text, secret
    with Session() as s:
        after = (s.query(Audit).count(), s.query(Job).count(), {r.key: r.value for r in s.query(Setting).all()})
    assert before == after


def test_pagination_and_invalid_offset(admin):
    for index in range(53):
        add(f'h{index:02d}', receipt(checked=time.time()), collected=time.time())
    first = admin.get('/api/operations/agents').json()
    assert len(first['items']) == 50 and first['more'] and first['total'] == 53
    second = admin.get('/api/operations/agents', params={'offset': 50}).json()
    assert len(second['items']) == 3 and not second['more']
    assert {r['host_id'] for r in first['items']}.isdisjoint(r['host_id'] for r in second['items'])
    assert admin.get('/api/operations/agents?offset=-1').status_code == 400


def test_batched_status_reads_do_not_query_per_host(monkeypatch):
    for index in range(7):
        add(f'b{index}', receipt())
    statements = []
    from sqlalchemy import event
    from app.db import engine

    def count(*args):
        statements.append(args[2])
    event.listen(engine, 'before_cursor_execute', count)
    try:
        fleet.page(0, NOW)
    finally:
        event.remove(engine, 'before_cursor_execute', count)
    assert len([sql for sql in statements if sql.lstrip().upper().startswith('SELECT')]) == 2


@pytest.mark.parametrize('role', ['viewer', 'operator'])
def test_non_administrators_are_refused(admin, role):
    add('h', receipt())
    with Session() as s:
        s.get(User, 'admin').role = role
        s.commit()
    assert admin.get('/api/operations/agents').status_code == 403
