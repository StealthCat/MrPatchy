import json
from pathlib import Path

import pytest

from tests.test_ai_benchmark_series import run_series


BENCHMARKS = Path(__file__).resolve().parents[1] / 'docs' / 'benchmarks'


@pytest.fixture(params=[
    pytest.param(('ai-capped-v1110-sqlite-linux', 'sqlite', '3.45.1',
                  'e8ad2b901c2becdb0de3379ffef3790c0953c690'), id='sqlite'),
    pytest.param(('ai-capped-v1112-mysql-linux', 'mysql', '8.4.13',
                  '20c950d5bbbfce78aa8cbf42b36712d62ca68b5c'), id='mysql'),
])
def archive(request):
    name, backend, version, source = request.param
    return BENCHMARKS / name, backend, version, source


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
    records, backend, version, source = archive
    expected = {'provenance.txt', 'series.json'} | {path.name for pair in pairs for path in pair}
    assert {path.name for path in records.iterdir()} == expected
    provenance = (records / 'provenance.txt').read_text(encoding='utf-8').splitlines()
    assert provenance[0] == f'commit={source}'
    assert provenance[1].startswith('Linux ')
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
            assert report['ai_control_mode'] == 'daily_cap'
            assert report['fixture_only'] and report['errors'] == 0
            assert report['completed_subjects'] == 8 and report['approved_subjects'] == 0
            assert report['stages']['two_stage']['count'] == 4
            assert report['stages']['ssh_evidence']['count'] == 4
            assert report['provider_calls'] == 12 and report['fixture_budget']['settled_calls'] == 12
            assert report['fixture_budget']['settled_microusd'] == 240
