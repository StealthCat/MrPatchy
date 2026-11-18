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


@pytest.mark.parametrize('value', ['rate', 'daily_cap', 'rate_and_daily', 'Unthrottled', '', None, 1, ['legacy']])
def test_unknown_or_malformed_modes_are_refused(value):
    with pytest.raises(ComparisonError, match='candidate.ai_control_mode must be one of legacy, unthrottled'):
        compare(report(ai_control_mode='legacy'), report('parallel', 4, ai_control_mode=value))


def test_comparator_modes_match_the_benchmark_choices():
    help_text = run('--help', timeout=30).stdout
    assert '--control-mode {legacy,unthrottled}' in help_text
    assert compare_ai_benchmarks.CONTROL_MODES == ('legacy', 'unthrottled')


@pytest.mark.parametrize('value', ['rate', 'daily_cap', 'rate_and_daily', 'LEGACY', ''])
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
