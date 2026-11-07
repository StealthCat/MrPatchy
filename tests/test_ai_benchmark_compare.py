import copy
import importlib.util
import json
import math
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('compare_ai_benchmarks', ROOT / 'tools' / 'compare_ai_benchmarks.py')
compare_ai_benchmarks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compare_ai_benchmarks)


def report(execution='serial', concurrency=1):
    runs = 8
    counts = {
        'run': 8, 'one_stage': 4, 'two_stage': 4, 'provider': 12,
        'ssh_evidence': 4, 'admission': 8, 'queue_age': 8,
        'receipt_persistence': 12, 'usage_persistence': 12,
    }
    return {
        'fixture_only': True, 'execution': execution, 'concurrency': concurrency,
        'provider_delay_ms': 20, 'ssh_delay_ms': 10, 'runs': runs,
        'provider_calls': 12, 'elapsed_seconds': 2.0 if concurrency == 1 else 0.75,
        'runs_per_second': 4.0 if concurrency == 1 else 10.667,
        'stages': {name: {'count': count, 'p50_ms': 0 if name == 'queue_age' else 10,
                          'p95_ms': 0 if name == 'queue_age' else 20}
                   for name, count in counts.items()},
        'input_tokens': 1200, 'output_tokens': 240,
        'workload_fingerprint': {'version': 1, 'sha256': 'a' * 64},
        'cost_status': 'unavailable: synthetic model, no paid calls', 'errors': 0,
    }


def test_comparison_reports_equivalent_deltas_and_zero_percent():
    result = compare_ai_benchmarks.compare(report(), report('parallel', 4), 'serial.json', 'parallel.json')
    assert result['capability_equivalent'] is True
    assert result['baseline']['name'] == 'serial.json'
    assert result['capability']['provider_calls'] == 12
    assert result['capability']['workload_fingerprint'] == {
        'version': 1, 'sha256': 'a' * 64,
    }
    assert result['deltas']['elapsed_seconds']['percent'] == -62.5
    assert result['deltas']['runs_per_second']['percent'] == 166.675
    queue = result['deltas']['stages']['queue_age']['p50_ms']
    assert queue['percent'] is None
    assert queue['percent_unavailable'] == 'baseline is zero'
    assert 'production performance' in result['interpretation']['scope']
    assert 'never treated as zero' in result['interpretation']['cost']


def test_legacy_fixed_ssh_delay_matches_explicit_default():
    baseline = report()
    baseline.pop('ssh_delay_ms')
    result = compare_ai_benchmarks.compare(baseline, report('parallel', 4))
    assert result['baseline']['ssh_delay_ms'] == 10
    assert result['baseline']['ssh_delay_source'] == 'legacy fixed default'


def test_ssh_delay_mismatch_is_refused():
    candidate = report('parallel', 4)
    candidate['ssh_delay_ms'] = 15
    with pytest.raises(compare_ai_benchmarks.ComparisonError, match='ssh_delay_ms differs'):
        compare_ai_benchmarks.compare(report(), candidate)


def test_legacy_reports_use_fixed_two_second_queue_age():
    baseline = report()
    candidate = report('parallel', 4)
    candidate['initial_fixture_queue_age_seconds'] = 2
    result = compare_ai_benchmarks.compare(baseline, candidate)
    assert result['baseline']['queue_age_seconds'] == 2
    assert result['baseline']['queue_age_source'] == 'legacy fixed default'
    assert result['candidate']['queue_age_seconds'] == 2
    assert result['candidate']['queue_age_source'] == 'report initial fixture field'


def test_matching_configured_queue_age_is_accepted():
    baseline = report()
    candidate = report('parallel', 4)
    for item in (baseline, candidate):
        item['queue_age_seconds'] = 60
        item['initial_fixture_queue_age_seconds'] = 60
    result = compare_ai_benchmarks.compare(baseline, candidate)
    assert result['capability_equivalent'] is True
    assert result['candidate']['queue_age_seconds'] == 60
    assert result['candidate']['queue_age_source'] == 'report'


def test_maximum_seeded_queue_age_with_fixture_overhead_is_accepted():
    baseline = report()
    candidate = report('parallel', 4)
    for item in (baseline, candidate):
        item['queue_age_seconds'] = 86_400
        item['initial_fixture_queue_age_seconds'] = 86_400
        item['stages']['queue_age'].update(p50_ms=86_400_010, p95_ms=86_400_020)
    result = compare_ai_benchmarks.compare(baseline, candidate)
    assert result['capability_equivalent'] is True
    assert result['deltas']['stages']['queue_age']['p50_ms']['baseline'] == 86_400_010


def test_observed_queue_age_beyond_seed_plus_stage_limit_is_refused():
    candidate = report('parallel', 4)
    candidate['queue_age_seconds'] = 60
    candidate['stages']['queue_age'].update(p50_ms=0, p95_ms=86_460_001)
    baseline = report()
    baseline['queue_age_seconds'] = 60
    with pytest.raises(compare_ai_benchmarks.ComparisonError,
                       match=r'stages.queue_age.p95_ms must be between 0 and 86460000'):
        compare_ai_benchmarks.compare(baseline, candidate)


def test_seeded_queue_age_does_not_widen_other_stage_bounds():
    candidate = report('parallel', 4)
    candidate['queue_age_seconds'] = 60
    candidate['stages']['admission'].update(p95_ms=86_400_001)
    baseline = report()
    baseline['queue_age_seconds'] = 60
    with pytest.raises(compare_ai_benchmarks.ComparisonError,
                       match=r'stages.admission.p95_ms must be between 0 and 86400000'):
        compare_ai_benchmarks.compare(baseline, candidate)


@pytest.mark.parametrize('legacy_candidate', [False, True])
def test_queue_age_mismatch_is_refused_even_with_matching_fingerprint(legacy_candidate):
    baseline = report()
    baseline['queue_age_seconds'] = 60
    baseline['initial_fixture_queue_age_seconds'] = 60
    candidate = report('parallel', 4)
    if not legacy_candidate:
        candidate['queue_age_seconds'] = 2
        candidate['initial_fixture_queue_age_seconds'] = 2
    assert baseline['workload_fingerprint'] == candidate['workload_fingerprint']
    with pytest.raises(compare_ai_benchmarks.ComparisonError, match='queue_age_seconds differs'):
        compare_ai_benchmarks.compare(baseline, candidate)


def test_queue_age_fields_that_disagree_are_refused():
    candidate = report('parallel', 4)
    candidate['queue_age_seconds'] = 2
    candidate['initial_fixture_queue_age_seconds'] = 60
    with pytest.raises(compare_ai_benchmarks.ComparisonError, match='disagrees with'):
        compare_ai_benchmarks.compare(report(), candidate)


@pytest.mark.parametrize(('field', 'value', 'message'), [
    ('queue_age_seconds', -1, 'must be non-negative'),
    ('queue_age_seconds', 86_401, 'must be between 0 and 86400'),
    ('queue_age_seconds', 1.5, 'must be an integer'),
    ('queue_age_seconds', True, 'must be a finite number'),
    ('queue_age_seconds', '2', 'must be a finite number'),
    ('initial_fixture_queue_age_seconds', math.inf, 'must be a finite number'),
])
def test_malformed_queue_age_is_refused(field, value, message):
    candidate = report('parallel', 4)
    candidate[field] = value
    with pytest.raises(compare_ai_benchmarks.ComparisonError, match=message):
        compare_ai_benchmarks.compare(report(), candidate)


def test_workload_fingerprint_mismatch_is_refused_even_when_counts_match():
    candidate = report('parallel', 4)
    candidate['workload_fingerprint']['sha256'] = 'b' * 64
    with pytest.raises(compare_ai_benchmarks.ComparisonError, match='workload_fingerprint differs'):
        compare_ai_benchmarks.compare(report(), candidate)


@pytest.mark.parametrize(('fingerprint', 'message'), [
    (None, 'must contain only version and sha256'),
    ({'version': 1}, 'must contain only version and sha256'),
    ({'version': 1, 'sha256': 'a' * 64, 'requests': []}, 'must contain only version and sha256'),
    ({'version': 2, 'sha256': 'a' * 64}, 'version 2 is unsupported'),
    ({'version': 1, 'sha256': 'A' * 64}, '64 lowercase hexadecimal characters'),
    ({'version': 1, 'sha256': 'a' * 63}, '64 lowercase hexadecimal characters'),
])
def test_workload_fingerprint_is_required_and_bounded(fingerprint, message):
    baseline = report()
    if fingerprint is None:
        baseline.pop('workload_fingerprint')
    else:
        baseline['workload_fingerprint'] = fingerprint
    with pytest.raises(compare_ai_benchmarks.ComparisonError, match=message):
        compare_ai_benchmarks.compare(baseline, report('parallel', 4))


@pytest.mark.parametrize(('mutate', 'message'), [
    (lambda value: value.update(fixture_only=False), 'fixture-only'),
    (lambda value: value.update(errors=1), 'benchmark error'),
    (lambda value: value.update(provider_delay_ms=30), 'provider_delay_ms differs'),
    (lambda value: value.update(input_tokens=1300), 'token totals do not match'),
    (lambda value: value['stages']['provider'].update(count=11), 'provider sample count'),
    (lambda value: value['stages']['two_stage'].update(count=3), 'one/two-stage sample counts'),
    (lambda value: value['stages']['admission'].update(count=7), 'admission sample count'),
    (lambda value: value['stages']['usage_persistence'].update(count=11), 'usage_persistence sample count'),
    (lambda value: value['stages']['run'].update(p50_ms=float('nan')), 'finite number'),
])
def test_comparison_refuses_non_equivalent_or_invalid_reports(mutate, message):
    candidate = report('parallel', 4)
    mutate(candidate)
    with pytest.raises(compare_ai_benchmarks.ComparisonError, match=message):
        compare_ai_benchmarks.compare(report(), candidate)


def test_comparison_requires_distinct_execution_configuration():
    with pytest.raises(compare_ai_benchmarks.ComparisonError, match='distinct execution'):
        compare_ai_benchmarks.compare(report(), copy.deepcopy(report()))


@pytest.mark.parametrize('elapsed', [1.234500001, 1.234567, 1.235499999])
def test_comparison_accepts_producer_rounding_for_derived_throughput(elapsed):
    baseline = report()
    baseline['elapsed_seconds'] = round(elapsed, 3)
    baseline['runs_per_second'] = round(baseline['runs'] / elapsed, 3)

    result = compare_ai_benchmarks.compare(baseline, report('parallel', 4))

    assert result['capability_equivalent'] is True


def test_comparison_refuses_historical_fixture_pair_without_workload_fingerprint():
    retained = json.loads((ROOT / 'docs' / 'benchmarks' / 'ai-parallel-v1220.json').read_text())

    with pytest.raises(
            compare_ai_benchmarks.ComparisonError,
            match='baseline.workload_fingerprint must contain only version and sha256'):
        compare_ai_benchmarks.compare(retained['serial'], retained['parallel'])


@pytest.mark.parametrize('throughput', [6.4, 6.6])
def test_comparison_refuses_throughput_inconsistent_with_elapsed_time(throughput):
    baseline = report()
    baseline['elapsed_seconds'] = 1.235
    baseline['runs_per_second'] = throughput

    with pytest.raises(
            compare_ai_benchmarks.ComparisonError,
            match=r'baseline\.runs_per_second is inconsistent with '
                  r'baseline\.runs / baseline\.elapsed_seconds'):
        compare_ai_benchmarks.compare(baseline, report('parallel', 4))


def test_comparison_identifies_inconsistent_candidate_report():
    candidate = report('parallel', 4)
    candidate['runs_per_second'] = 100

    with pytest.raises(
            compare_ai_benchmarks.ComparisonError,
            match=r'candidate\.runs_per_second is inconsistent with '
                  r'candidate\.runs / candidate\.elapsed_seconds'):
        compare_ai_benchmarks.compare(report(), candidate)


def test_cli_emits_json_and_refuses_malformed_input(tmp_path, capsys):
    baseline = tmp_path / 'baseline.json'
    candidate = tmp_path / 'candidate.json'
    baseline.write_text(json.dumps(report()))
    candidate.write_text(json.dumps(report('parallel', 4)))
    assert compare_ai_benchmarks.main([str(baseline), str(candidate)]) == 0
    assert json.loads(capsys.readouterr().out)['schema_version'] == 1
    candidate.write_text('{bad')
    assert compare_ai_benchmarks.main([str(baseline), str(candidate)]) == 2
    assert 'comparison refused: cannot read' in capsys.readouterr().err


def test_cli_refuses_oversized_report(tmp_path, capsys):
    baseline = tmp_path / 'oversized.json'
    candidate = tmp_path / 'candidate.json'
    baseline.write_bytes(b' ' * (compare_ai_benchmarks.MAX_REPORT_BYTES + 1))
    candidate.write_text(json.dumps(report('parallel', 4)))
    assert compare_ai_benchmarks.main([str(baseline), str(candidate)]) == 2
    assert 'exceeds the 1000000-byte report limit' in capsys.readouterr().err


def test_cli_refuses_json_integer_over_interpreter_limit(tmp_path, capsys):
    baseline = tmp_path / 'huge.json'
    candidate = tmp_path / 'candidate.json'
    baseline.write_text('{"runs":' + '9' * 5000 + '}')
    candidate.write_text(json.dumps(report('parallel', 4)))
    assert compare_ai_benchmarks.main([str(baseline), str(candidate)]) == 2
    assert 'comparison refused: cannot read' in capsys.readouterr().err


@pytest.mark.parametrize('value', [1e-308, 1e308, 10 ** 400])
def test_comparison_refuses_out_of_range_elapsed_values(value):
    candidate = report('parallel', 4)
    candidate['elapsed_seconds'] = value
    with pytest.raises(compare_ai_benchmarks.ComparisonError, match='elapsed_seconds must be between'):
        compare_ai_benchmarks.compare(report(), candidate)


def test_delta_refuses_nonfinite_derived_metric():
    with pytest.raises(compare_ai_benchmarks.ComparisonError, match='derived comparison metric'):
        compare_ai_benchmarks._delta(1e-308, 1e308)


def test_load_reads_only_limit_plus_one(monkeypatch):
    sizes = []

    class Report:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size):
            sizes.append(size)
            return b' ' * size

    monkeypatch.setattr(Path, 'open', lambda *args, **kwargs: Report())
    with pytest.raises(compare_ai_benchmarks.ComparisonError, match='exceeds'):
        compare_ai_benchmarks._load(Path('oversized.json'))
    assert sizes == [compare_ai_benchmarks.MAX_REPORT_BYTES + 1]


def test_cli_uses_strict_json(monkeypatch, tmp_path, capsys):
    baseline = tmp_path / 'baseline.json'
    candidate = tmp_path / 'candidate.json'
    baseline.write_text(json.dumps(report()))
    candidate.write_text(json.dumps(report('parallel', 4)))
    original = compare_ai_benchmarks._delta
    monkeypatch.setattr(compare_ai_benchmarks, '_delta', lambda *args: {'percent': math.inf})
    try:
        assert compare_ai_benchmarks.main([str(baseline), str(candidate)]) == 2
    finally:
        monkeypatch.setattr(compare_ai_benchmarks, '_delta', original)
    assert 'output is not strict JSON' in capsys.readouterr().err
