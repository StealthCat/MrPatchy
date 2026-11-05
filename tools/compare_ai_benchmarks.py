"""Compare fixture-only AI benchmark reports without weakening capability."""

import argparse
import json
import math
from pathlib import Path
import sys


SCHEMA_VERSION = 1
MAX_REPORT_BYTES = 1_000_000
STAGES = (
    'run', 'one_stage', 'two_stage', 'provider', 'ssh_evidence', 'admission',
    'queue_age', 'receipt_persistence', 'usage_persistence',
)


class ComparisonError(ValueError):
    pass


def _number(value, field, *, positive=False):
    if (isinstance(value, bool) or not isinstance(value, (int, float)) or
            isinstance(value, float) and not math.isfinite(value)):
        raise ComparisonError(f'{field} must be a finite number')
    if value < 0 or positive and value == 0:
        qualifier = 'positive' if positive else 'non-negative'
        raise ComparisonError(f'{field} must be {qualifier}')
    return value


def _integer(value, field, *, positive=False):
    value = _number(value, field, positive=positive)
    if int(value) != value:
        raise ComparisonError(f'{field} must be an integer')
    return int(value)


def _bounded(value, field, minimum, maximum):
    value = _number(value, field)
    if not minimum <= value <= maximum:
        raise ComparisonError(f'{field} must be between {minimum} and {maximum}')
    return value


def _summary(report, stage):
    value = report['stages'].get(stage)
    if not isinstance(value, dict):
        raise ComparisonError(f'stages.{stage} must be an object')
    count = _integer(value.get('count'), f'stages.{stage}.count')
    p50 = _number(value.get('p50_ms'), f'stages.{stage}.p50_ms')
    p95 = _number(value.get('p95_ms'), f'stages.{stage}.p95_ms')
    if p95 < p50:
        raise ComparisonError(f'stages.{stage}.p95_ms must not be less than p50_ms')
    return {'count': count, 'p50_ms': p50, 'p95_ms': p95}


def _validate(report, label):
    if not isinstance(report, dict):
        raise ComparisonError(f'{label} report must be a JSON object')
    if report.get('fixture_only') is not True:
        raise ComparisonError(f'{label} must be a fixture-only report')
    execution = report.get('execution')
    if execution not in ('serial', 'parallel'):
        raise ComparisonError(f'{label}.execution must be serial or parallel')
    concurrency = _integer(report.get('concurrency'), f'{label}.concurrency', positive=True)
    if concurrency > 8:
        raise ComparisonError(f'{label}.concurrency must be between 1 and 8')
    if (execution == 'serial') != (concurrency == 1):
        raise ComparisonError(f'{label}.execution does not match concurrency')
    runs = _integer(report.get('runs'), f'{label}.runs', positive=True)
    if not 2 <= runs <= 20:
        raise ComparisonError(f'{label}.runs must be between 2 and 20')
    provider_delay = _bounded(report.get('provider_delay_ms'), f'{label}.provider_delay_ms', 1, 1000)
    provider_calls = _integer(report.get('provider_calls'), f'{label}.provider_calls', positive=True)
    input_tokens = _integer(report.get('input_tokens'), f'{label}.input_tokens', positive=True)
    output_tokens = _integer(report.get('output_tokens'), f'{label}.output_tokens', positive=True)
    errors = _integer(report.get('errors'), f'{label}.errors')
    if errors:
        raise ComparisonError(f'{label} contains {errors} benchmark error(s)')
    cost_status = report.get('cost_status')
    if not isinstance(cost_status, str) or not cost_status.strip():
        raise ComparisonError(f'{label}.cost_status must explain cost availability')
    elapsed = _number(report.get('elapsed_seconds'), f'{label}.elapsed_seconds', positive=True)
    throughput = _number(report.get('runs_per_second'), f'{label}.runs_per_second', positive=True)
    if not isinstance(report.get('stages'), dict):
        raise ComparisonError(f'{label}.stages must be an object')
    stages = {stage: _summary(report, stage) for stage in STAGES}
    if stages['run']['count'] != runs:
        raise ComparisonError(f'{label} run sample count does not match runs')
    if stages['one_stage']['count'] + stages['two_stage']['count'] != runs:
        raise ComparisonError(f'{label} one/two-stage sample counts do not match runs')
    if stages['provider']['count'] != provider_calls:
        raise ComparisonError(f'{label} provider sample count does not match provider calls')
    if provider_calls != runs + stages['two_stage']['count']:
        raise ComparisonError(f'{label} provider calls do not match the one/two-stage workload')
    if input_tokens != provider_calls * 100 or output_tokens != provider_calls * 20:
        raise ComparisonError(f'{label} token totals do not match provider calls')
    if stages['ssh_evidence']['count'] != stages['two_stage']['count']:
        raise ComparisonError(f'{label} SSH evidence count does not match two-stage runs')
    for stage in ('admission', 'queue_age'):
        if stages[stage]['count'] != runs:
            raise ComparisonError(f'{label} {stage} sample count does not match runs')
    for stage in ('receipt_persistence', 'usage_persistence'):
        if stages[stage]['count'] != provider_calls:
            raise ComparisonError(f'{label} {stage} sample count does not match provider calls')
    # Reports created before the configurable SSH-delay flag used a fixed 10 ms
    # fixture. Normalize only that documented legacy contract, never an unknown
    # arbitrary value.
    ssh_delay_source = 'report'
    if 'ssh_delay_ms' in report:
        ssh_delay = _bounded(report['ssh_delay_ms'], f'{label}.ssh_delay_ms', 0, 1000)
    else:
        ssh_delay = 10
        ssh_delay_source = 'legacy fixed default'
    return {
        'execution': execution, 'concurrency': concurrency, 'runs': runs,
        'provider_delay_ms': provider_delay, 'ssh_delay_ms': ssh_delay,
        'ssh_delay_source': ssh_delay_source,
        'provider_calls': provider_calls, 'input_tokens': input_tokens,
        'output_tokens': output_tokens, 'errors': errors,
        'elapsed_seconds': elapsed, 'runs_per_second': throughput,
        'cost_status': cost_status, 'stages': stages,
    }


def _delta(baseline, candidate):
    absolute = candidate - baseline
    return {
        'baseline': baseline,
        'candidate': candidate,
        'absolute': round(absolute, 6),
        'percent': None if baseline == 0 else round(absolute / baseline * 100, 3),
        'percent_unavailable': 'baseline is zero' if baseline == 0 else None,
    }


def compare(baseline, candidate, baseline_name='baseline', candidate_name='candidate'):
    base = _validate(baseline, 'baseline')
    current = _validate(candidate, 'candidate')
    if (base['execution'], base['concurrency']) == (current['execution'], current['concurrency']):
        raise ComparisonError('candidate must use a distinct execution configuration')
    controls = ('runs', 'provider_delay_ms', 'ssh_delay_ms', 'provider_calls', 'input_tokens', 'output_tokens')
    for field in controls:
        if base[field] != current[field]:
            raise ComparisonError(f'capability mismatch: {field} differs')
    for stage in STAGES:
        if base['stages'][stage]['count'] != current['stages'][stage]['count']:
            raise ComparisonError(f'capability mismatch: stages.{stage}.count differs')
    return {
        'schema_version': SCHEMA_VERSION,
        'fixture_only': True,
        'capability_equivalent': True,
        'baseline': {
            'name': baseline_name, 'execution': base['execution'],
            'concurrency': base['concurrency'], 'runs': base['runs'],
            'provider_delay_ms': base['provider_delay_ms'],
            'ssh_delay_ms': base['ssh_delay_ms'],
            'ssh_delay_source': base['ssh_delay_source'],
            'cost_status': base['cost_status'],
        },
        'candidate': {
            'name': candidate_name, 'execution': current['execution'],
            'concurrency': current['concurrency'], 'runs': current['runs'],
            'provider_delay_ms': current['provider_delay_ms'],
            'ssh_delay_ms': current['ssh_delay_ms'],
            'ssh_delay_source': current['ssh_delay_source'],
            'cost_status': current['cost_status'],
        },
        'capability': {
            'runs': base['runs'], 'provider_calls': base['provider_calls'],
            'input_tokens': base['input_tokens'], 'output_tokens': base['output_tokens'],
            'stage_samples': {stage: base['stages'][stage]['count'] for stage in STAGES},
        },
        'deltas': {
            'elapsed_seconds': _delta(base['elapsed_seconds'], current['elapsed_seconds']),
            'runs_per_second': _delta(base['runs_per_second'], current['runs_per_second']),
            'stages': {
                stage: {
                    'p50_ms': _delta(base['stages'][stage]['p50_ms'], current['stages'][stage]['p50_ms']),
                    'p95_ms': _delta(base['stages'][stage]['p95_ms'], current['stages'][stage]['p95_ms']),
                }
                for stage in STAGES
            },
        },
        'interpretation': {
            'latency': 'Negative elapsed/stage deltas indicate lower fixture latency.',
            'throughput': 'Positive throughput deltas indicate higher fixture throughput.',
            'scope': 'Disposable loopback fixture only; this comparison does not establish production performance.',
            'cost': 'Cost status is preserved from each report; unavailable cost is never treated as zero or a provider invoice.',
        },
    }


def _load(path):
    try:
        content = path.read_bytes()
    except OSError as error:
        raise ComparisonError(f'cannot read {path}: {error}') from error
    if len(content) > MAX_REPORT_BYTES:
        raise ComparisonError(f'{path} exceeds the {MAX_REPORT_BYTES}-byte report limit')
    try:
        return json.loads(content)
    except (UnicodeError, ValueError) as error:
        raise ComparisonError(f'cannot read {path}: {error}') from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args(argv)
    try:
        result = compare(_load(args.baseline), _load(args.candidate), args.baseline.name, args.candidate.name)
    except ComparisonError as error:
        print(f'comparison refused: {error}', file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
