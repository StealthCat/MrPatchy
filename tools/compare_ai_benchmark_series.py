"""Summarize paired serial/parallel timing differences over repeated AI fixture runs."""

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
    controls = {key: value for key, value in side.items() if key not in ('name', 'fixture_rate')}
    if 'fixture_rate' in side:
        controls['fixture_rate'] = {
            key: value for key, value in side['fixture_rate'].items() if key != 'dispatch_wait_seconds'
        }
    return controls


def _summary(values):
    return {'median': round(median(values), 6), 'min': min(values), 'max': max(values)}


def compare_series(pairs):
    if not MIN_PAIRS <= len(pairs) <= MAX_PAIRS:
        raise ComparisonError(f'provide {MIN_PAIRS} to {MAX_PAIRS} matched pairs')

    seen = set()
    comparisons = []
    first_signature = None
    for index, (serial, parallel) in enumerate(pairs, 1):
        try:
            result = compare(_report(serial, seen), _report(parallel, seen), serial.name, parallel.name)
            baseline = _configuration(result['baseline'])
            candidate = _configuration(result['candidate'])
            if baseline['execution'] != 'serial' or candidate['execution'] != 'parallel':
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
    return {
        'schema_version': 1,
        'fixture_only': True,
        'capability_equivalent': True,
        'pair_count': len(comparisons),
        'serial': baseline,
        'parallel': candidate,
        'capability': capability,
        'pairs': [
            {
                'serial_report': result['baseline']['name'],
                'parallel_report': result['candidate']['name'],
                'elapsed_seconds': result['deltas']['elapsed_seconds'],
                'runs_per_second': result['deltas']['runs_per_second'],
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
        'stage_p50_ms_differences': {
            stage: _summary([
                result['deltas']['stages'][stage]['p50_ms']['absolute'] for result in comparisons
            ])
            for stage, count in capability['stage_samples'].items() if count
        },
        'interpretation': (
            'Each difference is parallel minus serial within one pair. Median and range '
            'describe the spread in these disposable, synthetic fixture runs.'
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pair', type=Path, action='append', nargs=2, required=True,
                        metavar=('SERIAL', 'PARALLEL'), help='Repeat for each independent fixture pair.')
    args = parser.parse_args(argv)
    try:
        output = json.dumps(compare_series(args.pair), indent=2, sort_keys=True, allow_nan=False)
    except ComparisonError as error:
        print(f'comparison refused: {error}', file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
