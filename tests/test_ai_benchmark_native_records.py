import json
from pathlib import Path

from tests.test_ai_benchmark_series import run_series


RECORDS = Path(__file__).resolve().parents[1] / 'docs' / 'benchmarks' / 'ai-capped-v1110-sqlite-linux'
SOURCE = 'e8ad2b901c2becdb0de3379ffef3790c0953c690'
PAIRS = tuple(
    (RECORDS / f'pair-{index}-slots-1.json', RECORDS / f'pair-{index}-slots-4.json')
    for index in range(1, 7)
)


def test_retained_native_sqlite_pairs_replay():
    result = run_series(PAIRS)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    # The captured series predates the optional budget timing summary.
    report.pop('budget_timing_differences', None)
    assert report == json.loads((RECORDS / 'series.json').read_text(encoding='utf-8'))
    assert report['capability_equivalent'] and report['fixture_only']
    assert report['pair_count'] == 6


def test_retained_native_sqlite_provenance_and_coverage():
    expected = {'provenance.txt', 'series.json'} | {path.name for pair in PAIRS for path in pair}
    assert {path.name for path in RECORDS.iterdir()} == expected
    provenance = (RECORDS / 'provenance.txt').read_text(encoding='utf-8').splitlines()
    assert provenance[0] == f'commit={SOURCE}'
    assert provenance[1].startswith('Linux ')
    assert 'flock=fcntl' in provenance
    assert 'sqlite=3.45.1' in provenance

    for pair in PAIRS:
        for slots, path in zip((1, 4), pair, strict=True):
            report = json.loads(path.read_text(encoding='utf-8'))
            assert report['source_commit'] == SOURCE
            assert report['database'] == 'sqlite' and report['database_version'] == '3.45.1'
            assert report['concurrency'] == slots
            assert report['ai_control_mode'] == 'daily_cap'
            assert report['fixture_only'] and report['errors'] == 0
            assert report['completed_subjects'] == 8 and report['approved_subjects'] == 0
            assert report['stages']['two_stage']['count'] == 4
            assert report['stages']['ssh_evidence']['count'] == 4
            assert report['provider_calls'] == 12 and report['fixture_budget']['settled_calls'] == 12
