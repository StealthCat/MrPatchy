"""Read-only kernel clock-discipline telemetry (#342 time-sync slice)."""
import json

import pytest

from app import agent_fleet_health as fleet
from app.db import Host
from target import agent

NOW = 1_800_000_000.0


def raw(**fields):
    base = {'state': 0, 'status': 0x2001, 'maxerror': 25_000, 'esterror': 300, 'offset': -12_500}
    base.update(fields)
    return lambda: base


def test_disciplined_clock_is_synchronized_with_nanosecond_offset():
    result = agent.clock_sync(raw(), 7.5)
    assert result['version'] == 1 and result['collected'] == 7.5 and result['source'] == 'adjtimex'
    assert result['applicability'] == 'supported' and result['gaps'] == []
    assert result['state'] == 'synchronized' and result['kernel_unsync'] is False and result['time_state'] == 'ok'
    assert result['unit'] == 'microseconds' and result['max_error'] == 25_000 and result['estimated_error'] == 300
    assert result['offset'] == -12.5  # STA_NANO: nanoseconds converted to microseconds


def test_microsecond_offset_without_sta_nano():
    assert agent.clock_sync(raw(status=0x0001, offset=-40), 1)['offset'] == -40.0


@pytest.mark.parametrize('fields', [
    {'status': 0x0041, 'state': 5, 'maxerror': 16_000_000},  # no NTP daemon: STA_UNSYNC, TIME_ERROR, maxerror capped
    {'status': 0x0001, 'maxerror': 16_000_000},  # error grew past the kernel's phase limit
])
def test_undisciplined_clock_is_unsynchronized(fields):
    result = agent.clock_sync(raw(**fields), 1)
    assert result['state'] == 'unsynchronized' and result['applicability'] == 'supported'


def test_sta_unsync_alone_does_not_mark_a_disciplined_clock_unsynchronized():
    # chrony/ntpd with RTC sync off keep STA_UNSYNC set while disciplining the clock; systemd timedated's
    # NTPSynchronized ignores the flag and uses maxerror < 16 s, so the agent must agree.
    result = agent.clock_sync(raw(status=0x2041, state=5, maxerror=40_000), 1)
    assert result['state'] == 'synchronized' and result['kernel_unsync'] is True and result['time_state'] == 'error'
    summary = fleet.resources({'clock_sync': agent.clock_sync(raw(status=0x2041, maxerror=40_000), NOW - 30)}, 'fresh')
    assert summary['clock']['synchronized'] is True and summary['attention'] == []


@pytest.mark.parametrize('error, reason', [
    (PermissionError('/secret'), 'permission-denied'),
    (OSError(38, 'Function not implemented'), 'unavailable-or-malformed'),
    (AttributeError('no adjtimex'), 'unavailable-or-malformed'),
])
def test_unavailable_call_is_unknown_with_typed_gap(error, reason):
    def read():
        raise error
    result = agent.clock_sync(read, 1)
    assert result['state'] == 'unknown' and result['applicability'] == 'unknown'
    assert result['gaps'] == [{'signal': 'clock-sync', 'reason': reason}]
    assert 'secret' not in repr(result) and 'max_error' not in result


@pytest.mark.parametrize('fields', [
    {'state': 9}, {'state': -1}, {'status': -1}, {'maxerror': -1}, {'esterror': True},
    {'offset': 1.5}, {'offset': 10 ** 13}, {'maxerror': None},
])
def test_malformed_kernel_values_are_unknown(fields):
    result = agent.clock_sync(raw(**fields), 1)
    assert result['state'] == 'unknown' and result['gaps'][0]['reason'] == 'unavailable-or-malformed'
    assert agent.clock_sync(lambda: 'bad', 1)['state'] == 'unknown'


def test_real_call_is_read_only_and_well_formed():
    result = agent.clock_sync(collected=1)
    assert result['state'] in ('synchronized', 'unsynchronized', 'unknown')
    if result['state'] != 'unknown':
        assert result['unit'] == 'microseconds' and result['max_error'] >= 0


def test_snapshot_includes_clock_sync_and_survives_its_failure():
    def broken(collected=None):
        return agent.clock_sync(lambda: (_ for _ in ()).throw(OSError(1, 'denied')), collected)
    snap = agent.telemetry_snapshot(5, {}, {}, [], [], lambda: 20, lambda path: (_ for _ in ()).throw(OSError()),
                                    lambda collected=None: {'version': 1}, broken)
    assert snap['clock_sync']['collected'] == 20 and snap['clock_sync']['state'] == 'unknown'
    good = agent.telemetry_snapshot(5, {}, {}, [], [], lambda: 20, lambda path: (_ for _ in ()).throw(OSError()),
                                    lambda collected=None: {'version': 1},
                                    lambda collected=None: agent.clock_sync(raw(), collected))
    assert good['clock_sync']['state'] == 'synchronized'


def record(**fields):
    return agent.clock_sync(raw(**fields), NOW - 30)


def test_fleet_summary_reports_clock_and_advisory_attention():
    result = fleet.resources({'clock_sync': record()}, 'fresh')
    assert result['state'] == 'present' and result['attention'] == []
    assert result['clock'] == {'synchronized': True, 'max_error_ms': 25.0, 'estimated_error_ms': 0.3, 'offset_ms': -0.013}
    unsync = fleet.resources({'clock_sync': record(status=0x0041, state=5, maxerror=16_000_000)}, 'stale')
    assert unsync['clock']['synchronized'] is False and unsync['attention'] == ['clock-unsynchronized']


@pytest.mark.parametrize('mutate', [
    lambda r: r.update(state='unknown'),
    lambda r: r.update(unit='seconds'),
    lambda r: r.update(kernel_unsync='no'),
    lambda r: r.update(max_error=16_000_000),        # contradicts "synchronized"
    lambda r: r.update(state='unsynchronized'),      # contradicts max_error below the phase limit
    lambda r: r.update(max_error=-1),
    lambda r: r.update(offset=float('nan')),
    lambda r: r.update(estimated_error=True),
    lambda r: r.update(max_error=float('inf')),
    lambda r: r.update(offset=float('-inf')),
    lambda r: r.update(offset=10 ** 13),
    # Integers beyond float range must be rejected, not raise OverflowError.
    lambda r: r.update(max_error=10 ** 400),
    lambda r: r.update(estimated_error=10 ** 400),
    lambda r: r.update(offset=-(10 ** 400)),
])
def test_malformed_or_contradictory_clock_records_are_unknown(mutate):
    entry = record()
    mutate(entry)
    result = fleet.resources({'clock_sync': entry}, 'fresh')
    assert result['clock'] is None and 'clock-unsynchronized' not in result['attention']


def test_clock_withheld_for_untrusted_telemetry_and_other_versions():
    assert fleet.resources({'clock_sync': {**record(), 'version': 2}}, 'fresh')['state'] == 'absent'
    for state in ('missing', 'invalid'):
        assert fleet.resources({'clock_sync': record(status=0x41, maxerror=16_000_000)}, state)['clock'] is None


def test_unsynchronized_clock_never_changes_health():
    healthy = Host(id='h', name='web', state='online', telemetry={'collected': NOW - 30, 'clock_sync': record(status=0x41, state=5, maxerror=16_000_000)})
    receipt = {'state': 'current', 'checked': NOW - 60, 'repairable': True, 'issues': [],
               'report': {'version': 1, 'unit_path': fleet.SYSTEMD_UNIT, 'files': {}}}
    row = fleet.classify(healthy, receipt, NOW)
    assert row['health'] == 'healthy' and row['resources']['attention'] == ['clock-unsynchronized']
    assert 'clock' in json.dumps(fleet.GAPS).lower()
