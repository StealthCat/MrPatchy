"""Summarize paired timing differences over repeated AI triage fixture runs."""

import argparse
import hashlib
import json
from pathlib import Path
from statistics import median
import sys

from compare_ai_benchmarks import ComparisonError, _load, compare


MIN_PAIRS = 3
MAX_PAIRS = 20


def _report(path, seen):
    report = _load(path)
    # Canonical JSON also detects a copied report with different whitespace or key order.
    encoded = json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    digest = hashlib.sha256(encoded).digest()
    if digest in seen:
        raise ComparisonError(f'report reused: {path}')
    seen.add(digest)
    return report


def _configuration(side):
    controls = {
        key: value for key, value in side.items()
        if key not in ('name', 'fixture_rate', 'peak_provider_requests')
    }
    if 'fixture_rate' in side:
        controls['fixture_rate'] = {
            key: value for key, value in side['fixture_rate'].items() if key != 'dispatch_wait_seconds'
        }
    return controls


def _summary(values):
    return {'median': round(median(values), 6), 'min': min(values), 'max': max(values)}


def compare_series(pairs, *, fixed_concurrency=False):
    if not MIN_PAIRS <= len(pairs) <= MAX_PAIRS:
        raise ComparisonError(f'provide {MIN_PAIRS} to {MAX_PAIRS} matched pairs')

    seen = set()
    comparisons = []
    first_signature = None
    for index, (baseline_path, candidate_path) in enumerate(pairs, 1):
        try:
            result = compare(
                _report(baseline_path, seen), _report(candidate_path, seen),
                baseline_path.name, candidate_path.name, fixed_concurrency=fixed_concurrency,
            )
            baseline = _configuration(result['baseline'])
            candidate = _configuration(result['candidate'])
            if not fixed_concurrency and (baseline['execution'], candidate['execution']) != ('serial', 'parallel'):
                raise ComparisonError('provide the serial report before the parallel report')
            if not baseline['database_version'] or baseline['database_version'] != candidate['database_version']:
                raise ComparisonError('both reports need the same recorded database version')
            signature = (baseline, candidate, result['capability'])
            if first_signature is None:
                first_signature = signature
            elif signature != first_signature:
                raise ComparisonError('workload or execution settings differ from pair 1')
        except ValueError as error:
            raise ComparisonError(f'pair {index}: {error}') from error
        comparisons.append(result)

    baseline, candidate, capability = first_signature
    stage_summaries = {
        stage: _summary([
            result['deltas']['stages'][stage]['p50_ms']['absolute'] for result in comparisons
        ])
        for stage, count in capability['stage_samples'].items() if count
    }
    queue_differences = {}
    budget_differences = {}
    for result in comparisons:
        for stage, timing in result.get('queue_timing', {}).items():
            delta = timing['p50_ms']
            if delta is not None:
                queue_differences.setdefault(stage, []).append(delta['absolute'])
        # The pair comparator supplies deltas only when both reports have measurements.
        budget_deltas = result.get('budget_timings', {}).get('deltas')
        for stage, timings in (budget_deltas or {}).items():
            paired = budget_differences.setdefault(stage, {})
            for percentile, delta in timings.items():
                paired.setdefault(percentile, []).append(delta['absolute'])
    stage_summaries.update({
        stage: {'pair_count': len(differences), **_summary(differences)}
        for stage, differences in queue_differences.items()
    })
    budget_summaries = {
        stage: {
            percentile: {'pair_count': len(differences), **_summary(differences)}
            for percentile, differences in timings.items()
        }
        for stage, timings in budget_differences.items()
    }
    baseline_label, candidate_label = ('baseline', 'candidate') if fixed_concurrency else ('serial', 'parallel')
    return {
        'schema_version': 1,
        **({'comparison_mode': 'fixed_concurrency'} if fixed_concurrency else {}),
        'fixture_only': True,
        'capability_equivalent': True,
        'pair_count': len(comparisons),
        baseline_label: baseline,
        candidate_label: candidate,
        'capability': capability,
        'pairs': [
            {
                f'{baseline_label}_report': result['baseline']['name'],
                f'{candidate_label}_report': result['candidate']['name'],
                'elapsed_seconds': result['deltas']['elapsed_seconds'],
                'runs_per_second': result['deltas']['runs_per_second'],
                **({
                    f'{baseline_label}_peak_provider_requests': result['baseline']['peak_provider_requests'],
                    f'{candidate_label}_peak_provider_requests': result['candidate']['peak_provider_requests'],
                } if 'peak_provider_requests' in result['baseline'] else {}),
            }
            for result in comparisons
        ],
        'paired_differences': {
            metric: {
                field: _summary([result['deltas'][metric][field] for result in comparisons])
                for field in ('absolute', 'percent')
            }
            for metric in ('elapsed_seconds', 'runs_per_second')
        },
        'stage_p50_ms_differences': stage_summaries,
        **({'budget_timing_differences': budget_summaries} if budget_summaries else {}),
        'interpretation': (
            f'Each difference is {candidate_label} minus {baseline_label} within one pair. Median and range '
            'describe the spread in these disposable, synthetic fixture runs.'
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pair', type=Path, action='append', nargs=2, required=True,
                        metavar=('BASELINE', 'CANDIDATE'), help='Repeat for each independent fixture pair.')
    parser.add_argument('--fixed-concurrency', action='store_true',
                        help='compare baseline and candidate at the same worker count instead of serial and parallel')
    args = parser.parse_args(argv)
    try:
        output = json.dumps(compare_series(args.pair, fixed_concurrency=args.fixed_concurrency),
                            indent=2, sort_keys=True, allow_nan=False)
    except ComparisonError as error:
        print(f'comparison refused: {error}', file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
