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
        'cost_status': 'unavailable: synthetic model, no paid calls', 'errors': 0,
    }


def test_comparison_reports_equivalent_deltas_and_zero_percent():
    result = compare_ai_benchmarks.compare(report(), report('parallel', 4), 'serial.json', 'parallel.json')
    assert result['capability_equivalent'] is True
    assert result['baseline']['name'] == 'serial.json'
    assert result['capability']['provider_calls'] == 12
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
