import json
from pathlib import Path

import pytest

from tests.test_ai_benchmark_series import run_series


BENCHMARKS = Path(__file__).resolve().parents[1] / 'docs' / 'benchmarks'
SAME_SERVER_SOURCE = '3a06f2edb48d95f781f6758fe2a8500bb4f82197'
PACED_SOURCE = '1994e4ad7f50fec2773c95f146ef5dfeb8f143a2'
SLOW_PACED_SOURCE = '3beb4936ae7c4725c6d936b5864d547ef50ac1d5'


@pytest.fixture(params=[
    pytest.param(('ai-capped-v1110-sqlite-linux', 'sqlite', '3.45.1',
                  'e8ad2b901c2becdb0de3379ffef3790c0953c690', 8, 'daily_cap', None), id='sqlite'),
    pytest.param(('ai-capped-v1112-mysql-linux', 'mysql', '8.4.13',
                  '20c950d5bbbfce78aa8cbf42b36712d62ca68b5c', 8, 'daily_cap', None), id='mysql'),
    pytest.param(('ai-capped-v1118-sqlite-linux-same-server', 'sqlite', '3.45.1',
                  SAME_SERVER_SOURCE, 1, 'daily_cap', None), id='sqlite-same-server'),
    pytest.param(('ai-capped-v1118-mysql-linux-same-server', 'mysql', '8.4.13',
                  SAME_SERVER_SOURCE, 1, 'daily_cap', None), id='mysql-same-server'),
    pytest.param(('ai-paced-v1132-sqlite-linux', 'sqlite', '3.45.1',
                  PACED_SOURCE, 8, 'rate_and_daily', 150), id='sqlite-paced'),
    pytest.param(('ai-paced-v1132-mysql-linux', 'mysql', '8.4.13',
                  PACED_SOURCE, 8, 'rate_and_daily', 150), id='mysql-paced'),
    pytest.param(('ai-paced-slow-3beb493-sqlite-linux', 'sqlite', '3.45.1',
                  SLOW_PACED_SOURCE, 8, 'rate_and_daily', 4500), id='sqlite-paced-slow'),
    pytest.param(('ai-paced-slow-3beb493-mysql-linux', 'mysql', '8.4.13',
                  SLOW_PACED_SOURCE, 8, 'rate_and_daily', 4500), id='mysql-paced-slow'),
])
def archive(request):
    name, *configuration = request.param
    return (BENCHMARKS / name, *configuration)


@pytest.fixture
def pairs(archive):
    records = archive[0]
    return tuple(
        (records / f'pair-{index}-slots-1.json', records / f'pair-{index}-slots-4.json')
        for index in range(1, 7)
    )


def test_retained_native_pairs_replay(archive, pairs):
    result = run_series(pairs)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    expected = json.loads((archive[0] / 'series.json').read_text(encoding='utf-8'))
    # The original SQLite series predates the optional budget timing summary.
    if 'budget_timing_differences' not in expected:
        report.pop('budget_timing_differences', None)
    assert report == expected
    assert report['capability_equivalent'] and report['fixture_only']
    assert report['pair_count'] == 6


def test_retained_native_provenance_and_coverage(archive, pairs):
    records, backend, version, source, hosts, control_mode, delay_ms = archive
    expected = {'provenance.txt', 'series.json'} | {path.name for pair in pairs for path in pair}
    assert {path.name for path in records.iterdir()} == expected
    provenance = (records / 'provenance.txt').read_text(encoding='utf-8').splitlines()
    assert provenance[0] == f'commit={source}'
    assert provenance[1].startswith('Linux ')
    if control_mode == 'rate_and_daily':
        assert 'ai_control_mode=rate_and_daily' in provenance
        assert 'starts_per_hour=1000' in provenance
        assert f'fixture_hosts={hosts}' in provenance
        if delay_ms == 4500:
            assert f'provider_delay_ms={delay_ms}' in provenance
    if hosts == 1:
        assert 'fixture_hosts=1' in provenance
    if backend == 'sqlite':
        assert 'flock=fcntl' in provenance
        assert f'sqlite={version}' in provenance
    else:
        assert 'database=mysql' in provenance

    for pair in pairs:
        for slots, path in zip((1, 4), pair, strict=True):
            report = json.loads(path.read_text(encoding='utf-8'))
            assert report['source_commit'] == source
            assert report['database'] == backend and report['database_version'] == version
            assert report['concurrency'] == slots
            assert report['fixture_hosts'] == hosts
            if hosts == 1:
                assert report['single_server_slots'] == 4
                assert report['peak_provider_requests'] == slots
            assert report['ai_control_mode'] == control_mode
            if delay_ms is not None:
                assert report['provider_delay_ms'] == delay_ms
            if control_mode == 'rate_and_daily':
                rate = report['fixture_rate']
                assert rate['starts_per_hour'] == 1000
                assert rate['admitted_starts'] == 8
                expected_peak = 3 if delay_ms == 4500 and slots == 4 else 1
                assert report['peak_provider_requests'] == expected_peak
                assert report['persisted_assessments'] == {
                    'subjects': 8, 'input_stages': 12, 'follow_up_subjects': 4,
                }
            else:
                assert 'fixture_rate' not in report
            assert report['fixture_only'] and report['errors'] == 0
            assert report['completed_subjects'] == 8 and report['approved_subjects'] == 0
            assert report['stages']['two_stage']['count'] == 4
            assert report['stages']['ssh_evidence']['count'] == 4
            assert report['provider_calls'] == 12 and report['fixture_budget']['settled_calls'] == 12
            assert report['fixture_budget']['settled_microusd'] == 240
