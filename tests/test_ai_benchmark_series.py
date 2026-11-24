import json
from pathlib import Path
import subprocess
import sys

import pytest

from tests.test_ai_benchmark_compare import report


TOOL = Path(__file__).resolve().parents[1] / 'tools' / 'compare_ai_benchmark_series.py'


def make_pairs(tmp_path, mutate=None):
    pairs = []
    for index, (serial_time, parallel_time) in enumerate(((2, 1), (4, 2), (8, 1)), 1):
        baseline = report()
        candidate = report('parallel', 4)
        for data, elapsed in ((baseline, serial_time), (candidate, parallel_time)):
            data.update(elapsed_seconds=elapsed, runs_per_second=8 / elapsed, database_version='3.50.4')
        candidate['stages']['provider']['p50_ms'] = 2 * index
        if mutate is not None:
            mutate(index, baseline, candidate)
        serial = tmp_path / f'serial-{index}.json'
        parallel = tmp_path / f'parallel-{index}.json'
        serial.write_text(json.dumps(baseline), encoding='utf-8')
        parallel.write_text(json.dumps(candidate), encoding='utf-8')
        pairs.append((serial, parallel))
    return pairs


def run_series(pairs):
    return subprocess.run(
        [sys.executable, str(TOOL), *(argument for pair in pairs for argument in ('--pair', *map(str, pair)))],
        text=True, capture_output=True, check=False,
    )


def test_series_reports_paired_medians_and_ranges(tmp_path):
    result = run_series(make_pairs(tmp_path))
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output['capability_equivalent'] and output['fixture_only']
    assert output['pair_count'] == 3
    assert output['serial']['concurrency'] == 1
    assert output['parallel']['concurrency'] == 4
    assert output['capability']['provider_calls'] == 12
    assert output['paired_differences']['elapsed_seconds']['absolute'] == {'median': -2, 'min': -7, 'max': -1}
    assert output['paired_differences']['elapsed_seconds']['percent']['median'] == -50
    assert output['paired_differences']['runs_per_second']['absolute'] == {'median': 4, 'min': 2, 'max': 7}
    assert output['stage_p50_ms_differences']['provider'] == {'median': -6, 'min': -8, 'max': -4}
    assert [pair['elapsed_seconds']['absolute'] for pair in output['pairs']] == [-1, -2, -7]
    if 'serial_peak_provider_requests' in output['pairs'][0]:
        assert all(pair['serial_peak_provider_requests'] is None for pair in output['pairs'])


@pytest.mark.parametrize('count', [2, 21])
def test_series_rejects_pair_counts_outside_the_bounds(tmp_path, count):
    pairs = make_pairs(tmp_path)
    result = run_series((pairs * count)[:count])
    assert result.returncode == 2
    assert 'provide 3 to 20 matched pairs' in result.stderr


def test_series_rejects_copies_of_a_report(tmp_path):
    pairs = make_pairs(tmp_path)
    serial, _ = pairs[0]
    copy, _ = pairs[1]
    copy.write_text(json.dumps(json.loads(serial.read_text()), indent=2, sort_keys=True), encoding='utf-8')
    result = run_series(pairs)
    assert result.returncode == 2
    assert 'pair 2: report reused' in result.stderr


@pytest.mark.parametrize(('field', 'value'), [
    ('database_version', '3.51.0'),
    ('provider_delay_ms', 40),
    ('workload_fingerprint', {'version': 1, 'sha256': 'b' * 64}),
])
def test_series_refuses_drift_across_pairs(tmp_path, field, value):
    def mutate(index, baseline, candidate):
        if index == 2:
            baseline[field] = candidate[field] = value

    result = run_series(make_pairs(tmp_path, mutate))
    assert result.returncode == 2
    assert 'pair 2: workload or execution settings differ' in result.stderr


def test_series_refuses_parallel_concurrency_changes(tmp_path):
    def mutate(index, baseline, candidate):
        if index == 2:
            candidate['concurrency'] = 3

    result = run_series(make_pairs(tmp_path, mutate))
    assert result.returncode == 2
    assert 'pair 2: workload or execution settings differ' in result.stderr


def test_series_uses_the_pairwise_capability_checks(tmp_path):
    def mutate(index, baseline, candidate):
        if index == 2:
            candidate['workload_fingerprint']['sha256'] = 'b' * 64

    result = run_series(make_pairs(tmp_path, mutate))
    assert result.returncode == 2
    assert 'pair 2: capability mismatch: workload_fingerprint differs' in result.stderr


@pytest.mark.parametrize('version', [None, '3.51.0'])
def test_series_needs_a_matching_recorded_database_version_in_each_pair(tmp_path, version):
    def mutate(index, baseline, candidate):
        if index == 2:
            candidate['database_version'] = version

    result = run_series(make_pairs(tmp_path, mutate))
    assert result.returncode == 2
    assert 'pair 2: both reports need the same recorded database version' in result.stderr


def test_series_requires_serial_then_parallel_in_each_pair(tmp_path):
    pairs = make_pairs(tmp_path)
    pairs[1] = pairs[1][::-1]
    result = run_series(pairs)
    assert result.returncode == 2
    assert 'pair 2: provide the serial report before the parallel report' in result.stderr



def test_series_allows_rate_wait_to_vary_between_repetitions(tmp_path):
    def mutate(index, baseline, candidate):
        for data in (baseline, candidate):
            data.update(elapsed_seconds=30 + index, runs_per_second=round(8 / (30 + index), 3),
                        ai_control_mode='rate')
            data['fixture_rate'] = {
                'starts_per_hour': 1000, 'admitted_starts': 8, 'dispatch_wait_seconds': 25 + index,
            }

    result = run_series(make_pairs(tmp_path, mutate))
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['serial']['fixture_rate'] == {
        'starts_per_hour': 1000, 'admitted_starts': 8,
    }


def test_series_omits_stages_without_samples(tmp_path):
    def mutate(index, baseline, candidate):
        for data in (baseline, candidate):
            data.update(provider_calls=8, input_tokens=800, output_tokens=160)
            stages = data['stages']
            for stage in ('two_stage', 'ssh_evidence'):
                stages[stage] = {'count': 0, 'p50_ms': None, 'p95_ms': None}
            for stage in ('one_stage', 'provider', 'receipt_persistence', 'usage_persistence'):
                stages[stage]['count'] = 8

    result = run_series(make_pairs(tmp_path, mutate))
    assert result.returncode == 0, result.stderr
    stages = json.loads(result.stdout)['stage_p50_ms_differences']
    assert 'two_stage' not in stages and 'ssh_evidence' not in stages


def test_series_preserves_observed_provider_overlap_without_requiring_it_to_match(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(TOOL.parent))
    import compare_ai_benchmark_series as series

    compare_pair = series.compare

    def compare_with_overlap(serial, parallel, serial_name, parallel_name):
        comparison = compare_pair(serial, parallel, serial_name, parallel_name)
        comparison['baseline']['peak_provider_requests'] = serial['peak_provider_requests']
        comparison['candidate']['peak_provider_requests'] = parallel['peak_provider_requests']
        return comparison

    def observed(index, serial, parallel):
        serial['peak_provider_requests'] = 1
        parallel['peak_provider_requests'] = (2, 4, 3)[index - 1]

    monkeypatch.setattr(series, 'compare', compare_with_overlap)
    output = series.compare_series(make_pairs(tmp_path, observed))
    assert 'peak_provider_requests' not in output['parallel']
    assert [pair['serial_peak_provider_requests'] for pair in output['pairs']] == [1, 1, 1]
    assert [pair['parallel_peak_provider_requests'] for pair in output['pairs']] == [2, 4, 3]
