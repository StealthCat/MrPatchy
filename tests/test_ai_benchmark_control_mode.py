"""The triage benchmark states and matches the AI control mode it measured (#1061)."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools import compare_ai_benchmarks
from tools.compare_ai_benchmarks import ComparisonError, compare


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / 'tools' / 'benchmark_ai.py'
RECORDS = ROOT / 'docs' / 'benchmarks' / 'ai-equivalence-c86141a'


def report(execution='serial', concurrency=1, **fields):
    counts = {
        'run': 8, 'one_stage': 4, 'two_stage': 4, 'provider': 12,
        'ssh_evidence': 4, 'admission': 8, 'queue_age': 8,
        'receipt_persistence': 12, 'usage_persistence': 12,
    }
    value = {
        'fixture_only': True, 'execution': execution, 'concurrency': concurrency,
        'provider_delay_ms': 20, 'ssh_delay_ms': 10, 'runs': 8,
        'provider_calls': 12, 'elapsed_seconds': 2.0 if concurrency == 1 else 0.75,
        'runs_per_second': 4.0 if concurrency == 1 else 10.667,
        'stages': {name: {'count': count, 'p50_ms': 10, 'p95_ms': 20} for name, count in counts.items()},
        'input_tokens': 1200, 'output_tokens': 240,
        'workload_fingerprint': {'version': 1, 'sha256': 'a' * 64},
        'cost_status': 'unavailable: synthetic model, no paid calls', 'errors': 0,
    }
    value.update(fields)
    return value


def run(*arguments, timeout=90):
    return subprocess.run([sys.executable, str(BENCHMARK), *arguments], cwd=ROOT,
                          capture_output=True, text=True, timeout=timeout, check=False)


def test_reports_without_a_mode_read_as_the_implicit_legacy_mode():
    result = compare(report(), report('parallel', 4))
    for side in ('baseline', 'candidate'):
        assert result[side]['ai_control_mode'] == 'legacy'
        assert result[side]['ai_control_mode_source'] == 'legacy implicit default'
    assert 'same AI control mode' in result['interpretation']['control_mode']


@pytest.mark.parametrize('mode', ['legacy', 'unthrottled'])
def test_reports_from_one_mode_compare_and_state_it(mode):
    result = compare(report(ai_control_mode=mode), report('parallel', 4, ai_control_mode=mode))
    assert result['capability_equivalent'] is True
    for side in ('baseline', 'candidate'):
        assert result[side]['ai_control_mode'] == mode
        assert result[side]['ai_control_mode_source'] == 'report'


@pytest.mark.parametrize('baseline_mode, candidate_mode', [
    ('legacy', 'unthrottled'), ('unthrottled', 'legacy'), (None, 'unthrottled'), ('unthrottled', None),
])
def test_reports_from_different_modes_are_refused(baseline_mode, candidate_mode):
    baseline = report() if baseline_mode is None else report(ai_control_mode=baseline_mode)
    candidate = report('parallel', 4)
    if candidate_mode is not None:
        candidate['ai_control_mode'] = candidate_mode
    with pytest.raises(ComparisonError, match='capability mismatch: ai_control_mode differs'):
        compare(baseline, candidate)


@pytest.mark.parametrize('value', ['Unthrottled', '', None, 1, ['legacy']])
def test_unknown_or_malformed_modes_are_refused(value):
    with pytest.raises(ComparisonError, match='candidate.ai_control_mode must be one of legacy, unthrottled, daily_cap, rate, rate_and_daily'):
        compare(report(ai_control_mode='legacy'), report('parallel', 4, ai_control_mode=value))


def test_comparator_modes_match_the_benchmark_choices():
    help_text = run('--help', timeout=30).stdout
    assert '--control-mode {legacy,unthrottled,daily_cap,rate,rate_and_daily}' in help_text
    assert compare_ai_benchmarks.CONTROL_MODES == ('legacy', 'unthrottled', 'daily_cap', 'rate', 'rate_and_daily')


@pytest.mark.parametrize('value', ['Rate', 'LEGACY', ''])
def test_benchmark_refuses_unsupported_modes_before_starting(value):
    result = run('--control-mode', value, timeout=30)
    assert result.returncode == 2 and result.stdout == ''
    assert 'invalid choice' in result.stderr


def test_retained_records_predate_the_flag_and_read_as_legacy():
    for name in ('cross-server', 'same-server'):
        for kind in ('serial', 'parallel'):
            assert 'ai_control_mode' not in json.loads((RECORDS / f'{name}-{kind}.json').read_text())
        recorded = json.loads((RECORDS / f'{name}-comparison.json').read_text())
        for side in ('baseline', 'candidate'):
            assert recorded[side]['ai_control_mode'] == 'legacy'
            assert recorded[side]['ai_control_mode_source'] == 'legacy implicit default'


def _benchmark(concurrency, *mode):
    result = run('--runs', '4', '--concurrency', str(concurrency), '--provider-delay-ms', '30',
                 '--ssh-delay-ms', '1', *mode)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_default_run_records_the_legacy_mode_it_applied():
    report_ = _benchmark(1)
    assert report_['ai_control_mode'] == 'legacy'
    assert report_['provider_calls'] == 6 and report_['errors'] == 0
    assert not {'budget_reservation', 'budget_reconciliation'} & report_['stages'].keys()


def assert_budget_timings(sample):
    for stage in ('budget_reservation', 'budget_reconciliation'):
        timing = sample['stages'][stage]
        assert timing['count'] == sample['provider_calls'] == sample['fixture_budget']['settled_calls']
        assert 0 <= timing['p50_ms'] <= timing['p95_ms'] <= sample['elapsed_seconds'] * 1000 + 1


def test_unthrottled_serial_and_parallel_pair_is_equivalent_and_keeps_the_workload():
    serial = _benchmark(1, '--control-mode', 'unthrottled')
    parallel = _benchmark(4, '--control-mode', 'unthrottled')
    legacy = _benchmark(4, '--control-mode', 'legacy')
    for item in (serial, parallel):
        assert item['ai_control_mode'] == 'unthrottled'
        assert item['runs'] == item['completed_subjects'] == 4 and item['approved_subjects'] == 0
        assert item['provider_calls'] == 6 and item['stages']['ssh_evidence']['count'] == 2
    assert serial['peak_provider_requests'] == 1 and parallel['peak_provider_requests'] > 1
    result = compare(serial, parallel)
    assert result['capability_equivalent'] is True
    assert result['baseline']['ai_control_mode'] == result['candidate']['ai_control_mode'] == 'unthrottled'
    # Removing Mr Patchy's pacing does not change what reaches the provider or SSH fixtures.
    assert legacy['workload_fingerprint'] == parallel['workload_fingerprint']
    with pytest.raises(ComparisonError, match='ai_control_mode differs'):
        compare(serial, legacy)


def capped_budget():
    return {'pricing_version': 'synthetic-v1', 'cap_usd': 10, 'timezone': 'UTC',
            'settled_calls': 12, 'settled_microusd': 240}


@pytest.mark.parametrize('budget', [
    None, {**capped_budget(), 'settled_calls': 11}, {**capped_budget(), 'settled_microusd': 0},
    {**capped_budget(), 'settled_microusd': 239}, {**capped_budget(), 'cap_usd': 100},
    {**capped_budget(), 'timezone': 'Europe/London'}, {**capped_budget(), 'pricing_version': 'deployment'},
])
def test_capped_comparison_requires_complete_synthetic_settlement(budget):
    baseline = report(ai_control_mode='daily_cap', fixture_budget=capped_budget())
    candidate = report('parallel', 4, ai_control_mode='daily_cap', fixture_budget=budget)
    with pytest.raises(ComparisonError, match=r'candidate\.fixture_budget'):
        compare(baseline, candidate)


def test_budget_evidence_cannot_be_attached_to_an_uncapped_report():
    with pytest.raises(ComparisonError, match='fixture_budget applies only to capped modes'):
        compare(report(), report('parallel', 4, fixture_budget=capped_budget()))


@pytest.mark.parametrize('layout', [(), ('--same-server',)], ids=['cross-server', 'same-server'])
def test_daily_cap_serial_and_parallel_settle_all_calls_without_changing_the_workload(layout):
    serial = _benchmark(1, '--control-mode', 'daily_cap', *layout)
    parallel = _benchmark(4, '--control-mode', 'daily_cap', *layout)
    for item in (serial, parallel):
        assert item['runs'] == item['completed_subjects'] == 4
        assert item['approved_subjects'] == item['errors'] == 0
        assert item['provider_calls'] == 6 and item['stages']['ssh_evidence']['count'] == 2
        assert item['fixture_budget'] == {**capped_budget(), 'settled_calls': 6, 'settled_microusd': 120}
        assert 'no paid API calls' in item['cost_status']
        assert_budget_timings(item)
    result = compare(serial, parallel)
    assert result['capability_equivalent'] is True
    assert result['capability']['fixture_budget'] == serial['fixture_budget']
    uncapped = _benchmark(1, '--control-mode', 'unthrottled', *layout)
    assert not {'budget_reservation', 'budget_reconciliation'} & uncapped['stages'].keys()
    assert uncapped['workload_fingerprint'] == parallel['workload_fingerprint']
    with pytest.raises(ComparisonError, match='ai_control_mode differs'):
        compare(uncapped, parallel)


@pytest.mark.parametrize('evidence', [
    None, {'starts_per_hour': 1001, 'admitted_starts': 8, 'dispatch_wait_seconds': 25},
    {'starts_per_hour': 1000, 'admitted_starts': 7, 'dispatch_wait_seconds': 25},
    {'starts_per_hour': 1000, 'admitted_starts': 8, 'dispatch_wait_seconds': 27},
])
def test_paced_comparisons_refuse_missing_or_inconsistent_evidence(evidence):
    pacing = {'starts_per_hour': 1000, 'admitted_starts': 8, 'dispatch_wait_seconds': 25}
    common = {'ai_control_mode': 'rate', 'elapsed_seconds': 26, 'runs_per_second': 0.308}
    with pytest.raises(ComparisonError, match=r'candidate\.fixture_rate'):
        compare(report(**common, fixture_rate=pacing),
                report('parallel', 4, **common, fixture_rate=evidence))


def test_custom_rates_must_match_for_a_valid_comparison():
    def paced(execution, concurrency, rate):
        return report(execution, concurrency, ai_control_mode='rate', elapsed_seconds=32,
                      runs_per_second=0.25, fixture_rate={
                          'starts_per_hour': rate, 'admitted_starts': 8, 'dispatch_wait_seconds': 29,
                      })

    serial = paced('serial', 1, 900)
    parallel = paced('parallel', 4, 900)
    assert compare(serial, parallel)['candidate']['fixture_rate']['starts_per_hour'] == 900
    with pytest.raises(ComparisonError, match='capability mismatch: fixture_rate.starts_per_hour differs'):
        compare(serial, paced('parallel', 4, 850))


@pytest.mark.parametrize('arguments, error', [
    (['--rate-per-hour', '900'], 'requires --control-mode rate or rate_and_daily'),
    (['--control-mode', 'daily_cap', '--rate-per-hour', '900'], 'requires --control-mode rate or rate_and_daily'),
    (['--control-mode', 'rate', '--rate-per-hour', '0'], 'must be between 1 and 1000'),
    (['--control-mode', 'rate', '--rate-per-hour', '1001'], 'must be between 1 and 1000'),
    (['--control-mode', 'rate', '--rate-per-hour', '11'], 'more than 300 seconds'),
])
def test_benchmark_refuses_invalid_custom_rate_before_opening_mysql(arguments, error):
    result = run('--database', 'mysql', '--runs', '2', *arguments, timeout=30)
    assert result.returncode == 2 and result.stdout == ''
    assert error in result.stderr


def test_rate_evidence_is_refused_when_the_report_could_not_have_waited_for_all_starts():
    pacing = {'starts_per_hour': 1000, 'admitted_starts': 8, 'dispatch_wait_seconds': 0.5}
    with pytest.raises(ComparisonError, match='elapsed time cannot contain the recorded pacing'):
        compare(report(ai_control_mode='rate', fixture_rate=pacing), report('parallel', 4))
    with pytest.raises(ComparisonError, match='fixture_rate applies only to paced modes'):
        compare(report(fixture_rate=pacing), report('parallel', 4))


@pytest.mark.parametrize('mode, custom_rate', [('rate', None), ('rate_and_daily', 900)])
def test_serial_and_parallel_fixtures_wait_for_real_paced_starts(mode, custom_rate):
    options = ['--control-mode', mode, '--same-server']
    if custom_rate is not None:
        options.extend(['--rate-per-hour', str(custom_rate)])
    serial = _benchmark(1, *options)
    parallel = _benchmark(4, *options)
    effective_rate = custom_rate or 1000
    for sample in (serial, parallel):
        pacing = sample['fixture_rate']
        assert pacing['starts_per_hour'] == effective_rate and pacing['admitted_starts'] == 4
        assert 0 < pacing['dispatch_wait_seconds'] <= sample['elapsed_seconds']
        assert sample['elapsed_seconds'] >= round(3 * 3600 / effective_rate, 3)
        assert sample['completed_subjects'] == 4 and sample['errors'] == 0
        assert sample['provider_calls'] == 6 and sample['stages']['ssh_evidence']['count'] == 2
        if mode == 'rate_and_daily':
            assert sample['fixture_budget']['settled_calls'] == 6
            assert_budget_timings(sample)
        else:
            assert 'fixture_budget' not in sample
            assert not {'budget_reservation', 'budget_reconciliation'} & sample['stages'].keys()
    result = compare(serial, parallel)
    assert result['capability_equivalent'] is True
    for side, sample in (('baseline', serial), ('candidate', parallel)):
        assert result[side]['fixture_rate'] == sample['fixture_rate']
