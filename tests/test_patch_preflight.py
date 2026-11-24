"""Advisory resource and clock preflight warnings for patch review (issue #1261, #342 slice)."""
import json
import time

import pytest

from app import patch_preflight as preflight
from app.db import Audit, Host, Job, Session, Setting
from app.identity import User

NOW = 1_800_000_000.0


def capacity(total, available, unit='bytes'):
    return {'state': 'collected', 'unit': unit, 'total': total, 'available': available, 'used': total - available}


def telemetry(collected=NOW - 30, disk=(1000, 500), inodes=(100, 60), memory=(1000, 600), synchronized=True, **extra):
    record = {'collected': collected,
              'device_health': {'version': 1, 'source': 'statvfs', 'bytes': capacity(*disk),
                                'inodes': capacity(*inodes, unit='inodes')},
              'resource_pressure': {'version': 1, 'source': 'procfs', 'memory_capacity': capacity(*memory)},
              'clock_sync': {'version': 1, 'state': 'synchronized' if synchronized else 'unsynchronized',
                             'unit': 'microseconds', 'kernel_unsync': not synchronized,
                             'max_error': 1000 if synchronized else 20_000_000, 'estimated_error': 10, 'offset': 5}}
    record.update(extra)
    return record


def codes(result):
    return [w['code'] for w in result['warnings']]


def test_healthy_fresh_telemetry_has_no_warnings_but_keeps_scope_gaps():
    result = preflight.assess(telemetry(), NOW)
    assert result['state'] == 'clear' and result['warnings'] == [] and result['collected'] == NOW - 30
    assert result['threshold_percent'] == 10 and any('advisory' in gap for gap in result['gaps'])
    assert any('/boot' in gap for gap in result['gaps'])


@pytest.mark.parametrize('fields,expected,percent', [
    ({'disk': (1000, 100)}, ['disk-space-low'], 10.0),
    ({'disk': (1000, 101)}, [], None),
    ({'inodes': (100, 3)}, ['disk-inodes-low'], 3.0),
    ({'memory': (1000, 50)}, ['memory-low'], 5.0),
    ({'synchronized': False}, ['clock-unsynchronized'], None),
])
def test_each_category_and_threshold_boundary(fields, expected, percent):
    result = preflight.assess(telemetry(**fields), NOW)
    assert codes(result) == expected
    assert result['state'] == ('attention' if expected else 'clear')
    if expected:
        warning = result['warnings'][0]
        assert warning['available_percent'] == percent and warning['title'] and warning['guidance']


def test_several_warnings_are_ordered_and_text_is_fixed():
    result = preflight.assess(telemetry(disk=(1000, 1), inodes=(100, 1), memory=(1000, 1), synchronized=False), NOW)
    assert codes(result) == ['disk-space-low', 'disk-inodes-low', 'memory-low', 'clock-unsynchronized']
    text = json.dumps(result)
    for leaked in ('statvfs', 'procfs', 'microseconds'):
        assert leaked not in text


@pytest.mark.parametrize('collected,needle', [
    (None, 'No telemetry collection time'),
    (NOW - 3600, 'older than'),
    (NOW + 3600, 'future collection time'),
    (float('nan'), 'No telemetry collection time'),
    ('soon', 'No telemetry collection time'),
    (10 ** 400, 'No telemetry collection time'),
])
def test_non_fresh_telemetry_is_unknown_never_clear(collected, needle):
    result = preflight.assess(telemetry(collected=collected, disk=(1000, 1)), NOW)
    assert result['state'] == 'unknown' and result['warnings'] == [] and needle in result['gaps'][0]
    # Stale data keeps its evidence time; missing and future-dated times are never shown.
    assert result['collected'] == (NOW - 3600 if collected == NOW - 3600 else None)


@pytest.mark.parametrize('value', [None, 'bad', [], {'collected': NOW}])
def test_absent_or_malformed_records_are_unknown(value):
    result = preflight.assess(value, NOW)
    assert result['state'] == 'unknown' and result['warnings'] == []


def test_uninterpretable_signals_are_partial_and_named():
    record = telemetry(disk=(1000, 1))
    record['device_health']['bytes']['available'] = 5000  # inconsistent, so unknown
    record.pop('clock_sync')
    result = preflight.assess(record, NOW)
    assert result['state'] == 'partial' and result['warnings'] == []
    assert 'root file system space' in result['gaps'][0] and 'clock synchronization' in result['gaps'][0]



@pytest.mark.parametrize('fields,expected,missing', [
    ({'disk': (1000, 50)}, ['disk-space-low'], 'clock synchronization'),
    ({'memory': (1000, 20)}, ['memory-low'], 'clock synchronization'),
])
def test_known_warning_with_unreadable_signal_is_partial_and_keeps_warning(fields, expected, missing):
    record = telemetry(**fields)
    record.pop('clock_sync')
    result = preflight.assess(record, NOW)
    assert result['state'] == 'partial'
    assert codes(result) == expected and result['warnings'][0]['available_percent'] is not None
    assert result['gaps'][0].startswith('Not reported or not interpretable:') and missing in result['gaps'][0]


def test_unsynchronized_clock_with_unreadable_disk_is_partial_and_keeps_clock_warning():
    record = telemetry(synchronized=False)
    record['device_health']['bytes']['available'] = 5000  # inconsistent, so unknown
    result = preflight.assess(record, NOW)
    assert result['state'] == 'partial' and codes(result) == ['clock-unsynchronized']
    assert 'root file system space' in result['gaps'][0]

def add_host(host_id, record, deleted_at=0):
    with Session() as s:
        s.add(Host(id=host_id, name=host_id, address='192.0.2.9', fingerprint='', state='online',
                   deleted_at=deleted_at, telemetry=record))
        s.commit()


def test_route_is_read_only_operator_gated_and_404s(admin):
    add_host('pre', telemetry(collected=time.time(), disk=(1000, 20)))
    add_host('pre-gone', telemetry(collected=time.time()), deleted_at=time.time())
    with Session() as s:
        before = (s.query(Audit).count(), s.query(Job).count(), {r.key: r.value for r in s.query(Setting).all()})
    response = admin.get('/api/hosts/pre/patch-preflight')
    assert response.status_code == 200
    data = response.json()
    assert data['state'] == 'attention' and [w['code'] for w in data['warnings']] == ['disk-space-low']
    with Session() as s:
        after = (s.query(Audit).count(), s.query(Job).count(), {r.key: r.value for r in s.query(Setting).all()})
    assert before == after
    assert admin.get('/api/hosts/missing/patch-preflight').status_code == 404
    assert admin.get('/api/hosts/pre-gone/patch-preflight').status_code == 404
    with Session() as s:
        s.get(User, 'admin').role = 'viewer'
        s.commit()
    assert admin.get('/api/hosts/pre/patch-preflight').status_code == 403
    with Session() as s:
        s.get(User, 'admin').role = 'operator'
        s.commit()
    assert admin.get('/api/hosts/pre/patch-preflight').status_code == 200
