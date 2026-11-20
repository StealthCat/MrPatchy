"""Read-only fleet endpoint-agent health (issue #737, roadmap H slice)."""
import json
import time

import pytest
from sqlalchemy.exc import DBAPIError

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


def device(total=1000, available=50, used=900, inodes=(100, 60, 40)):
    record = {'version': 1, 'collected': NOW - 30, 'source': 'statvfs', 'scope': {'kind': 'filesystem', 'path': '/'},
              'applicability': 'supported', 'gaps': [],
              'bytes': {'state': 'collected', 'unit': 'bytes', 'total': total, 'available': available, 'used': used}}
    if inodes is None:
        record['inodes'] = {'state': 'unknown', 'unit': 'inodes'}
    else:
        record['inodes'] = {'state': 'collected', 'unit': 'inodes', 'total': inodes[0], 'available': inodes[1], 'used': inodes[2]}
    return record


def pressure(total=8 * 2 ** 30, available=6 * 2 ** 30, cpu=1.25, memory=0.0):
    psi = lambda value: {'state': 'collected', 'unit': 'percent-stalled',  # noqa: E731
                         'some': {'avg10': 0.0, 'avg60': value, 'avg300': 0.0}}
    return {'version': 1, 'collected': NOW - 30, 'source': 'procfs', 'scope': {'kind': 'host'}, 'gaps': [],
            'applicability': 'supported', 'cpu': psi(cpu), 'memory': psi(memory),
            'memory_capacity': {'state': 'collected', 'unit': 'bytes', 'total': total, 'available': available}}


def test_resources_report_validated_metrics_and_advisory_attention():
    result = fleet.resources({'collected': NOW, 'device_health': device(), 'resource_pressure': pressure()}, 'fresh')
    assert result['state'] == 'present'
    assert result['disk'] == {'total': 1000, 'available': 50, 'available_percent': 5.0, 'used_percent': 90.0}
    assert result['inodes'] == {'total': 100, 'available': 60, 'available_percent': 60.0, 'used_percent': 40.0}
    assert result['memory'] == {'total': 8 * 2 ** 30, 'available': 6 * 2 ** 30, 'available_percent': 75.0}
    assert result['cpu_pressure_avg60'] == 1.25 and result['memory_pressure_avg60'] == 0.0
    assert result['attention'] == ['disk-space-low']
    low = fleet.resources({'device_health': device(available=500, inodes=(100, 10, 90)),
                           'resource_pressure': pressure(available=2 ** 29)}, 'stale')
    assert low['attention'] == ['disk-inodes-low', 'memory-low']


@pytest.mark.parametrize('mutate', [
    lambda t: t['device_health']['bytes'].update(available=2000),
    lambda t: t['device_health']['bytes'].update(total=0),
    lambda t: t['device_health']['bytes'].update(total=True),
    lambda t: t['device_health']['bytes'].update(available=-1),
    lambda t: t['device_health']['bytes'].update(available=1.5),
    lambda t: t['device_health']['bytes'].update(used=5000),
    lambda t: t['device_health']['bytes'].update(state='unknown'),
    lambda t: t['device_health']['bytes'].update(unit='inodes'),
    lambda t: t['device_health'].update(bytes='full'),
])
def test_malformed_disk_signals_are_unknown_not_guessed(mutate):
    telemetry = {'device_health': device(), 'resource_pressure': pressure()}
    mutate(telemetry)
    result = fleet.resources(telemetry, 'fresh')
    assert result['state'] == 'present' and result['disk'] is None and 'disk-space-low' not in result['attention']
    assert result['memory'] is not None


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -1, 101, True, '5', None])
def test_malformed_pressure_values_are_unknown(value):
    record = pressure()
    record['cpu']['some']['avg60'] = value
    assert fleet.resources({'resource_pressure': record}, 'fresh')['cpu_pressure_avg60'] is None


def test_unknown_states_versions_and_telemetry_withhold_metrics():
    record = pressure()
    record['memory_capacity'] = {'state': 'unknown', 'unit': 'bytes'}
    record['memory'] = {'state': 'unknown', 'unit': 'percent-stalled'}
    result = fleet.resources({'device_health': device(inodes=None), 'resource_pressure': record}, 'fresh')
    assert result['inodes'] is None and result['memory'] is None and result['memory_pressure_avg60'] is None
    assert fleet.resources({'collected': NOW}, 'fresh')['state'] == 'absent'
    assert fleet.resources({'device_health': {**device(), 'version': 2}}, 'fresh')['state'] == 'absent'
    for state in ('missing', 'invalid'):
        hidden = fleet.resources({'device_health': device(), 'resource_pressure': pressure()}, state)
        assert hidden['state'] == 'unavailable' and hidden['disk'] is None and hidden['attention'] == []
    assert fleet.resources('bad', 'fresh')['state'] == 'unavailable'


def test_resources_never_change_health_and_reach_the_api(admin):
    healthy = host(collected=NOW - 30)
    healthy.telemetry.update(device_health=device(), resource_pressure=pressure(available=1))
    row = fleet.classify(healthy, receipt(), NOW)
    assert row['health'] == 'healthy' and row['resources']['attention'] == ['disk-space-low', 'memory-low']
    future = host(collected=NOW + 3600)
    future.telemetry.update(device_health=device())
    assert fleet.classify(future, receipt(), NOW)['resources']['state'] == 'unavailable'
    add('res', receipt(checked=time.time() - 10), collected=time.time())
    with Session() as s:
        stored = s.get(Host, 'res')
        stored.telemetry = {**stored.telemetry, 'device_health': device(), 'resource_pressure': pressure()}
        s.commit()
    data = admin.get('/api/operations/agents').json()
    assert data['low_available_percent'] == 10
    resources = data['items'][0]['resources']
    assert resources['state'] == 'present' and resources['disk']['used_percent'] == 90.0
    text = json.dumps(data)
    for secret in ('statvfs', 'procfs', 'scope', 'secret-arg'):
        assert secret not in text, secret


# Issue #1195: integers beyond float range must degrade one host to unknown, never fail the fleet view.
HUGE = 10 ** 400


@pytest.mark.parametrize('value', [HUGE, -HUGE, 2 ** 1024, 100.0000001, -0.0001], ids=['huge', 'neg-huge', '2^1024', 'over-100', 'negative'])
def test_out_of_range_pressure_integers_are_unknown(value):
    for key in ('cpu', 'memory'):
        record = pressure()
        record[key]['some']['avg60'] = value
        assert fleet.resources({'resource_pressure': record}, 'fresh')[key + '_pressure_avg60'] is None


@pytest.mark.parametrize('value,expected', [(100, 100.0), (0, 0.0), (37, 37.0), (12.345, 12.35)])
def test_in_range_pressure_values_are_kept(value, expected):
    record = pressure(cpu=value)
    assert fleet.resources({'resource_pressure': record}, 'fresh')['cpu_pressure_avg60'] == expected


@pytest.mark.parametrize('value', [HUGE, -HUGE, 2 ** 1024, float('inf'), float('nan'), 0, -5, True, 'x'],
                         ids=['huge', 'neg-huge', '2^1024', 'inf', 'nan', 'zero', 'negative', 'bool', 'str'])
def test_out_of_range_timestamps_are_unknown(value):
    assert fleet._timestamp(value) is None


def test_timestamps_accept_valid_integers_and_floats():
    assert fleet._timestamp(1_800_000_000) == 1_800_000_000.0
    assert fleet._timestamp(NOW) == NOW
    # A large but representable integer is still a (future) time, exactly like the equivalent float.
    assert fleet._timestamp(10 ** 20) == fleet._timestamp(1e20) == 1e20
    assert fleet.classify(host(collected=10 ** 20), receipt(), NOW)['telemetry']['state'] == 'invalid'


def test_out_of_range_values_degrade_only_the_affected_host():
    pressure_record = pressure()
    pressure_record['cpu']['some']['avg60'] = HUGE
    bad_pressure = host(id='p', collected=NOW - 30)
    bad_pressure.telemetry['resource_pressure'] = pressure_record
    row = fleet.classify(bad_pressure, receipt(), NOW)
    assert row['health'] == 'healthy' and row['resources']['cpu_pressure_avg60'] is None
    assert row['resources']['memory_pressure_avg60'] == 0.0
    bad_collected = fleet.classify(host(id='c', collected=HUGE), receipt(), NOW)
    assert bad_collected['telemetry'] == {'state': 'missing', 'collected': None}
    assert bad_collected['health'] == 'degraded'
    bad_checked = fleet.classify(host(id='k'), receipt(checked=HUGE), NOW)
    assert bad_checked['health'] == 'unknown' and bad_checked['verification']['checked'] is None
    assert 'No valid agent verification' in bad_checked['reason']


def test_uninterpretable_host_record_does_not_fail_the_fleet_page(admin, monkeypatch):
    real = fleet.classify

    def explode(host_row, status, now):
        if host_row.id == 'boom':
            raise OverflowError('int too large to convert to float')
        return real(host_row, status, now)

    monkeypatch.setattr(fleet, 'classify', explode)
    now = time.time()
    add('boom', receipt(checked=now - 10), collected=now)
    add('fine', receipt(checked=now - 10), collected=now)
    data = fleet.page(0, now)
    rows = {row['host_id']: row for row in data['items']}
    assert rows['fine']['health'] == 'healthy'
    assert rows['boom']['health'] == 'unknown' and 'could not be interpreted' in rows['boom']['reason']
    assert rows['boom']['verification']['state'] is None and rows['boom']['resources']['state'] == 'unavailable'
    assert data['counts']['unknown'] >= 1 and data['counts']['healthy'] >= 1


def test_huge_stored_values_keep_both_fleet_pages_available(admin):
    now = time.time()
    add('ok', receipt(checked=now - 10), collected=now)
    record = pressure()
    record['cpu']['some']['avg60'] = HUGE
    # MySQL's JSON type refuses numbers beyond double range at write time; SQLite retains them.
    try:
        with Session() as s:
            s.add(Host(id='huge', name='huge', address='192.0.2.1', fingerprint='', state='online',
                       telemetry={'collected': HUGE, 'resource_pressure': record}))
            s.add(Setting(key='agent-status:huge', value={**receipt(), 'checked': HUGE}))
            s.commit()
    except DBAPIError as exc:
        # Only MySQL's JSON range rejection (ER_INVALID_JSON_TEXT, 3140) may skip; any other failure is real.
        args = getattr(exc.orig, 'args', ())
        if not (args and args[0] == 3140 and 'too big' in str(args[-1]).lower()):
            raise
        pytest.skip('this database refuses integers beyond float range')
    with Session() as s:
        if s.get(Host, 'huge').telemetry.get('collected') != HUGE:
            pytest.skip('this database cannot retain integers beyond float range')
    response = admin.get('/api/operations/agents')
    assert response.status_code == 200
    rows = {row['host_id']: row for row in response.json()['items']}
    assert rows['ok']['health'] == 'healthy'
    assert rows['huge']['health'] == 'unknown' and rows['huge']['telemetry']['collected'] is None
    assert admin.get('/api/operations/deployment-health').status_code == 200
