"""Compare fixture-only AI benchmark reports without weakening capability."""

import argparse
from decimal import Decimal, localcontext
import json
import math
from pathlib import Path
import sys


SCHEMA_VERSION = 1
WORKLOAD_FINGERPRINT_VERSION = 1
MAX_REPORT_BYTES = 1_000_000
MAX_ELAPSED_SECONDS = 86_400
MAX_THROUGHPUT = 1_000_000
MAX_STAGE_MS = MAX_ELAPSED_SECONDS * 1000
MAX_QUEUE_AGE_SECONDS = 86_400
LEGACY_QUEUE_AGE_SECONDS = 2
REPORT_ROUNDING_RADIUS = Decimal('0.0005')
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


def _summary(report, stage, queue_age):
    value = report['stages'].get(stage)
    if not isinstance(value, dict):
        raise ComparisonError(f'stages.{stage} must be an object')
    count = _integer(value.get('count'), f'stages.{stage}.count')
    # Observed queue age includes the seed and time spent in the fixture.
    max_ms = MAX_STAGE_MS + queue_age * 1000 if stage == 'queue_age' else MAX_STAGE_MS
    p50 = _bounded(value.get('p50_ms'), f'stages.{stage}.p50_ms', 0, max_ms)
    p95 = _bounded(value.get('p95_ms'), f'stages.{stage}.p95_ms', 0, max_ms)
    if p95 < p50:
        raise ComparisonError(f'stages.{stage}.p95_ms must not be less than p50_ms')
    return {'count': count, 'p50_ms': p50, 'p95_ms': p95}


def _workload_fingerprint(report, label):
    value = report.get('workload_fingerprint')
    if not isinstance(value, dict) or set(value) != {'version', 'sha256'}:
        raise ComparisonError(
            f'{label}.workload_fingerprint must contain only version and sha256')
    version = _integer(
        value.get('version'), f'{label}.workload_fingerprint.version', positive=True)
    if version != WORKLOAD_FINGERPRINT_VERSION:
        raise ComparisonError(
            f'{label}.workload_fingerprint.version {version} is unsupported')
    digest = value.get('sha256')
    if (not isinstance(digest, str) or len(digest) != 64 or
            any(character not in '0123456789abcdef' for character in digest)):
        raise ComparisonError(
            f'{label}.workload_fingerprint.sha256 must be 64 lowercase hexadecimal characters')
    return {'version': version, 'sha256': digest}


def _validate_derived_throughput(runs, elapsed, throughput, label):
    """Reconcile two independently rounded values without a loose tolerance."""
    with localcontext() as context:
        context.prec = 50
        elapsed = Decimal(str(elapsed))
        throughput = Decimal(str(throughput))
        elapsed_low = elapsed - REPORT_ROUNDING_RADIUS
        elapsed_high = elapsed + REPORT_ROUNDING_RADIUS
        throughput_low = max(Decimal(0), throughput - REPORT_ROUNDING_RADIUS)
        throughput_high = throughput + REPORT_ROUNDING_RADIUS
        derived_low = Decimal(runs) / elapsed_high
        derived_high = None if elapsed_low <= 0 else Decimal(runs) / elapsed_low
    if (throughput_high < derived_low or
            derived_high is not None and throughput_low > derived_high):
        raise ComparisonError(
            f'{label}.runs_per_second is inconsistent with '
            f'{label}.runs / {label}.elapsed_seconds')


def _queue_age(report, label):
    """Return the seeded fixture queue age, which is an input, not a result.

    The configurable producer reports ``queue_age_seconds`` and mirrors it in
    ``initial_fixture_queue_age_seconds``. Earlier reports carried only the
    latter, and reports older than that used a fixed two-second seed. Normalize
    only those documented contracts and refuse any disagreement.
    """
    values = {}
    for key in ('queue_age_seconds', 'initial_fixture_queue_age_seconds'):
        if key in report:
            value = _integer(report[key], f'{label}.{key}')
            if value > MAX_QUEUE_AGE_SECONDS:
                raise ComparisonError(
                    f'{label}.{key} must be between 0 and {MAX_QUEUE_AGE_SECONDS}')
            values[key] = value
    if len(set(values.values())) > 1:
        raise ComparisonError(
            f'{label}.queue_age_seconds disagrees with '
            f'{label}.initial_fixture_queue_age_seconds')
    if 'queue_age_seconds' in values:
        return values['queue_age_seconds'], 'report'
    if values:
        return values['initial_fixture_queue_age_seconds'], 'report initial fixture field'
    return LEGACY_QUEUE_AGE_SECONDS, 'legacy fixed default'


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
    workload_fingerprint = _workload_fingerprint(report, label)
    elapsed = _bounded(report.get('elapsed_seconds'), f'{label}.elapsed_seconds', 0.000001, MAX_ELAPSED_SECONDS)
    throughput = _bounded(report.get('runs_per_second'), f'{label}.runs_per_second', 0.000001, MAX_THROUGHPUT)
    _validate_derived_throughput(runs, elapsed, throughput, label)
    if not isinstance(report.get('stages'), dict):
        raise ComparisonError(f'{label}.stages must be an object')
    queue_age, queue_age_source = _queue_age(report, label)
    stages = {stage: _summary(report, stage, queue_age) for stage in STAGES}
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
    # Reports created before the optional synthetic receipt/usage persistence
    # delay carried no field and ran with no added delay. Treat only that
    # documented legacy contract as zero; bound any reported value.
    persistence_delay_source = 'report'
    if 'persistence_delay_ms' in report:
        persistence_delay = _bounded(
            report['persistence_delay_ms'], f'{label}.persistence_delay_ms', 0, 1000)
    else:
        persistence_delay = 0
        persistence_delay_source = 'legacy zero default'
    # Older fixtures seeded only the subjects they investigated.
    retained_history_rows = _integer(report.get('retained_history_rows', 0),
                                     f'{label}.retained_history_rows')
    if retained_history_rows > 50_000:
        raise ComparisonError(f'{label}.retained_history_rows must be between 0 and 50000')
    return {
        'execution': execution, 'concurrency': concurrency, 'runs': runs,
        'provider_delay_ms': provider_delay, 'ssh_delay_ms': ssh_delay,
        'ssh_delay_source': ssh_delay_source,
        'persistence_delay_ms': persistence_delay,
        'persistence_delay_source': persistence_delay_source,
        'queue_age_seconds': queue_age, 'queue_age_source': queue_age_source,
        'retained_history_rows': retained_history_rows,
        'provider_calls': provider_calls, 'input_tokens': input_tokens,
        'output_tokens': output_tokens, 'errors': errors,
        'elapsed_seconds': elapsed, 'runs_per_second': throughput,
        'cost_status': cost_status, 'workload_fingerprint': workload_fingerprint,
        'stages': stages,
    }


def _delta(baseline, candidate):
    absolute = candidate - baseline
    percent = None if baseline == 0 else absolute / baseline * 100
    if not math.isfinite(absolute) or percent is not None and not math.isfinite(percent):
        raise ComparisonError('derived comparison metric is not finite')
    return {
        'baseline': baseline,
        'candidate': candidate,
        'absolute': round(absolute, 6),
        'percent': None if percent is None else round(percent, 3),
        'percent_unavailable': 'baseline is zero' if baseline == 0 else None,
    }


def compare(baseline, candidate, baseline_name='baseline', candidate_name='candidate'):
    base = _validate(baseline, 'baseline')
    current = _validate(candidate, 'candidate')
    if (base['execution'], base['concurrency']) == (current['execution'], current['concurrency']):
        raise ComparisonError('candidate must use a distinct execution configuration')
    controls = (
        'runs', 'provider_delay_ms', 'ssh_delay_ms', 'persistence_delay_ms',
        'queue_age_seconds', 'retained_history_rows',
        'provider_calls', 'input_tokens', 'output_tokens',
    )
    for field in controls:
        if base[field] != current[field]:
            raise ComparisonError(f'capability mismatch: {field} differs')
    if base['workload_fingerprint'] != current['workload_fingerprint']:
        raise ComparisonError('capability mismatch: workload_fingerprint differs')
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
            'persistence_delay_ms': base['persistence_delay_ms'],
            'persistence_delay_source': base['persistence_delay_source'],
            'queue_age_seconds': base['queue_age_seconds'],
            'queue_age_source': base['queue_age_source'],
            'retained_history_rows': base['retained_history_rows'],
            'cost_status': base['cost_status'],
        },
        'candidate': {
            'name': candidate_name, 'execution': current['execution'],
            'concurrency': current['concurrency'], 'runs': current['runs'],
            'provider_delay_ms': current['provider_delay_ms'],
            'ssh_delay_ms': current['ssh_delay_ms'],
            'ssh_delay_source': current['ssh_delay_source'],
            'persistence_delay_ms': current['persistence_delay_ms'],
            'persistence_delay_source': current['persistence_delay_source'],
            'queue_age_seconds': current['queue_age_seconds'],
            'queue_age_source': current['queue_age_source'],
            'retained_history_rows': current['retained_history_rows'],
            'cost_status': current['cost_status'],
        },
        'capability': {
            'runs': base['runs'], 'provider_calls': base['provider_calls'],
            'input_tokens': base['input_tokens'], 'output_tokens': base['output_tokens'],
            'workload_fingerprint': base['workload_fingerprint'],
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
        with path.open('rb') as report:
            content = report.read(MAX_REPORT_BYTES + 1)
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
    try:
        serialized = json.dumps(result, indent=2, sort_keys=True, allow_nan=False)
    except (ValueError, OverflowError) as error:
        print(f'comparison refused: output is not strict JSON: {error}', file=sys.stderr)
        return 2
    print(serialized)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
