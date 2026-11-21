"""Comparison of optional capped fixture timing evidence."""

import pytest

from tests.test_ai_benchmark_control_mode import capped_budget, report
from tools.compare_ai_benchmarks import ComparisonError, compare


def capped_report(execution='serial', concurrency=1, *, measured=True):
    sample = report(execution, concurrency, ai_control_mode='daily_cap', fixture_budget=capped_budget())
    if measured:
        sample['stages'].update(
            budget_reservation={'count': 12, 'p50_ms': 4, 'p95_ms': 10},
            budget_reconciliation={'count': 12, 'p50_ms': 3, 'p95_ms': 8},
        )
    return sample


@pytest.mark.parametrize('mode', ['daily_cap', 'rate_and_daily'])
def test_complete_reports_compare_both_budget_stages(mode):
    baseline = capped_report()
    candidate = capped_report('parallel', 4)
    candidate['stages']['budget_reservation']['p95_ms'] = 14
    candidate['stages']['budget_reconciliation']['p50_ms'] = 2
    if mode == 'rate_and_daily':
        for sample in (baseline, candidate):
            sample.update(
                ai_control_mode=mode, elapsed_seconds=26, runs_per_second=0.308,
                fixture_rate={'starts_per_hour': 1000, 'admitted_starts': 8, 'dispatch_wait_seconds': 25},
            )
    result = compare(baseline, candidate)
    timings = result['budget_timings']
    assert result['capability_equivalent']
    assert timings['baseline']['budget_reservation']['count'] == 12
    assert timings['candidate']['budget_reconciliation']['count'] == 12
    assert timings['deltas']['budget_reservation']['p95_ms']['absolute'] == 4
    assert timings['deltas']['budget_reconciliation']['p50_ms']['absolute'] == -1


@pytest.mark.parametrize('missing', ['baseline', 'candidate'])
def test_older_report_has_no_invented_timing_deltas(missing):
    baseline = capped_report(measured=missing != 'baseline')
    candidate = capped_report('parallel', 4, measured=missing != 'candidate')
    timings = compare(baseline, candidate)['budget_timings']
    assert timings[missing] is None
    present = 'candidate' if missing == 'baseline' else 'baseline'
    assert timings[present]['budget_reservation']['count'] == 12
    assert timings['deltas'] is None


def test_two_older_reports_keep_the_existing_comparison_shape():
    result = compare(capped_report(measured=False), capped_report('parallel', 4, measured=False))
    assert result['capability_equivalent']
    assert 'budget_timings' not in result


@pytest.mark.parametrize(('stage', 'value', 'message'), [
    ('budget_reservation', None, 'must be an object'),
    ('budget_reconciliation', {'count': 11, 'p50_ms': 1, 'p95_ms': 2}, 'must equal settled provider calls'),
    ('budget_reservation', {'count': True, 'p50_ms': 1, 'p95_ms': 2}, 'must be a finite number'),
    ('budget_reservation', {'count': 12, 'p50_ms': 3, 'p95_ms': 2}, 'must be between'),
    ('budget_reservation', {'count': 12, 'p50_ms': -1, 'p95_ms': 2}, 'must be non-negative'),
    ('budget_reconciliation', {'count': 12, 'p50_ms': 1, 'p95_ms': float('inf')}, 'must be a finite number'),
    ('budget_reconciliation', {'count': 12, 'p50_ms': 1, 'p95_ms': 900}, 'must be between'),
])
def test_invalid_timing_is_rejected_even_with_an_older_other_report(stage, value, message):
    candidate = capped_report('parallel', 4)
    candidate['stages'][stage] = value
    with pytest.raises(ComparisonError, match=rf'candidate\.stages\.{stage}.*{message}'):
        compare(capped_report(measured=False), candidate)


def test_partial_report_identifies_the_missing_stage():
    candidate = capped_report('parallel', 4)
    del candidate['stages']['budget_reconciliation']
    with pytest.raises(ComparisonError, match=r'candidate\.stages\.budget_reconciliation.*must be an object'):
        compare(capped_report(), candidate)


def test_uncapped_report_cannot_claim_budget_stage_timings():
    candidate = report('parallel', 4)
    candidate['stages']['budget_reservation'] = {'count': 12, 'p50_ms': 1, 'p95_ms': 2}
    with pytest.raises(ComparisonError, match='candidate budget timings apply only to capped modes'):
        compare(report(), candidate)
