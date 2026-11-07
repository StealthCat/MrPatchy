from target import agent

PSI = 'some avg10=1.50 avg60=2.00 avg300=3.25 total=123\nfull avg10=0.10 avg60=0.20 avg300=0.30 total=9\n'
MEM = 'MemTotal:        2048 kB\nMemFree: 10 kB\nMemAvailable:    1024 kB\n'


def reader(files):
    def read(path):
        value = files[path]
        if isinstance(value, Exception):
            raise value
        return value
    return read


def healthy():
    return {'/proc/pressure/cpu': PSI, '/proc/pressure/memory': PSI, '/proc/meminfo': MEM}


def test_collects_pressure_and_memory_with_provenance():
    result = agent.resource_pressure(reader(healthy()), 7.5)
    assert result['applicability'] == 'supported' and result['gaps'] == []
    assert result['collected'] == 7.5 and result['source'] == 'procfs' and result['version'] == 1
    assert result['cpu']['some'] == {'avg10': 1.5, 'avg60': 2.0, 'avg300': 3.25}
    assert result['memory']['full']['avg300'] == 0.3 and result['cpu']['unit'] == 'percent-stalled'
    assert result['memory_capacity'] == {'state': 'collected', 'unit': 'bytes', 'total': 2048 * 1024, 'available': 1024 * 1024}


def test_cpu_without_full_line_is_still_collected():
    files = healthy(); files['/proc/pressure/cpu'] = PSI.splitlines()[0] + '\n'
    result = agent.resource_pressure(reader(files), 1)
    assert result['cpu']['state'] == 'collected' and 'full' not in result['cpu'] and result['gaps'] == []


def test_memory_without_full_line_is_unknown_with_gap():
    files = healthy(); files['/proc/pressure/memory'] = PSI.splitlines()[0] + '\n'
    result = agent.resource_pressure(reader(files), 1)
    assert result['memory'] == {'state': 'unknown', 'unit': 'percent-stalled'}
    assert {'signal': 'memory-pressure', 'reason': 'unavailable-or-malformed'} in result['gaps']
    assert result['applicability'] == 'partial'


def test_missing_psi_is_unknown_with_typed_gap():
    files = healthy(); files['/proc/pressure/cpu'] = FileNotFoundError(); files['/proc/pressure/memory'] = PermissionError('/secret/path')
    result = agent.resource_pressure(reader(files), 1)
    assert result['applicability'] == 'partial'
    assert result['cpu'] == {'state': 'unknown', 'unit': 'percent-stalled'}
    assert {'signal': 'cpu-pressure', 'reason': 'unsupported'} in result['gaps']
    assert {'signal': 'memory-pressure', 'reason': 'permission-denied'} in result['gaps']
    assert 'secret' not in repr(result)


def test_malformed_values_stay_unknown():
    files = healthy()
    files['/proc/pressure/cpu'] = 'some avg10=500 avg60=1 avg300=1 total=1\n'
    files['/proc/pressure/memory'] = 'garbage'
    files['/proc/meminfo'] = 'MemTotal: 0 kB\nMemAvailable: 1 kB\n'
    result = agent.resource_pressure(reader(files), 1)
    assert result['applicability'] == 'unknown'
    assert {g['reason'] for g in result['gaps']} == {'unavailable-or-malformed'} and len(result['gaps']) == 3


def test_available_memory_is_clamped_to_total():
    files = healthy(); files['/proc/meminfo'] = 'MemTotal: 10 kB\nMemAvailable: 99 kB\n'
    assert agent.resource_pressure(reader(files), 1)['memory_capacity']['available'] == 10 * 1024


def test_telemetry_snapshot_includes_pressure_and_survives_failure():
    def fs(path):
        raise OSError('no')
    result = agent.telemetry_snapshot(5, {}, {}, [], [], lambda: 20, fs, lambda collected=None: agent.resource_pressure(reader(healthy()), collected))
    assert result['resource_pressure']['collected'] == 20 and result['resource_pressure']['applicability'] == 'supported'
    broken = {k: OSError('x') for k in healthy()}
    result = agent.telemetry_snapshot(5, {}, {}, [], [], lambda: 20, fs, lambda collected=None: agent.resource_pressure(reader(broken), collected))
    assert result['resource_pressure']['applicability'] == 'unknown'
