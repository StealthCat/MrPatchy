"""Retained serial/parallel AI benchmark records must stay comparator-accepted.

Roadmap A milestone 4 requires recorded before/after performance and
capability-equivalence results. These checks re-run the fixture comparator
over every retained pair so an edited, mismatched or pre-fingerprint record
cannot silently stand in as evidence.
"""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RECORDS = ROOT / 'docs' / 'benchmarks' / 'ai-equivalence-c86141a'
SPEC = importlib.util.spec_from_file_location('compare_ai_benchmarks', ROOT / 'tools' / 'compare_ai_benchmarks.py')
compare_ai_benchmarks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compare_ai_benchmarks)

MANIFEST = json.loads((RECORDS / 'manifest.json').read_text())
WORKLOADS = sorted(MANIFEST['workloads'])


def _load(name):
    return json.loads((RECORDS / name).read_text())


def _pair(workload):
    return _load(f'{workload}-serial.json'), _load(f'{workload}-parallel.json')


def test_manifest_lists_every_retained_record():
    expected = {'manifest.json'} | {
        f'{workload}-{kind}.json' for workload in WORKLOADS for kind in ('serial', 'parallel', 'comparison')
    }
    assert {path.name for path in RECORDS.iterdir()} == expected
    assert WORKLOADS == ['cross-server', 'same-server']
    assert MANIFEST['fixture_only'] is True
    assert len(MANIFEST['base_commit']) == 40
    assert 'MySQL' in MANIFEST['limits'] and 'never zero' in MANIFEST['limits']


@pytest.mark.parametrize('workload', WORKLOADS)
def test_retained_pair_is_capability_equivalent_and_matches_recorded_comparison(workload):
    serial, parallel = _pair(workload)
    result = compare_ai_benchmarks.compare(
        serial, parallel, f'{workload}-serial.json', f'{workload}-parallel.json')
    assert result == _load(f'{workload}-comparison.json')
    assert result['capability_equivalent'] is True
    assert result['fixture_only'] is True


@pytest.mark.parametrize('workload', WORKLOADS)
def test_retained_pair_preserves_complete_results_and_full_evidence(workload):
    serial, parallel = _pair(workload)
    assert (serial['execution'], serial['concurrency']) == ('serial', 1)
    assert (parallel['execution'], parallel['concurrency']) == ('parallel', 4)
    for report in (serial, parallel):
        runs = report['runs']
        assert report['fixture_only'] is True and report['errors'] == 0
        assert report['completed_subjects'] == runs and report['approved_subjects'] == 0
        # Every second subject requests follow-up evidence: no follow-up was skipped.
        assert report['stages']['two_stage']['count'] == runs // 2
        assert report['stages']['ssh_evidence']['count'] == runs // 2
        assert report['provider_calls'] == runs + runs // 2
        assert report['cost_status'].startswith('unavailable')
    assert serial['workload_fingerprint'] == parallel['workload_fingerprint']
    assert parallel['peak_provider_requests'] > 1, 'parallel record never overlapped provider calls'
    assert serial['peak_provider_requests'] == 1
    if workload == 'same-server':
        assert serial['fixture_hosts'] == parallel['fixture_hosts'] == 1
        assert parallel['single_server_slots'] == 4
    else:
        assert serial['fixture_hosts'] == parallel['fixture_hosts'] == serial['runs']


@pytest.mark.parametrize('workload', WORKLOADS)
@pytest.mark.parametrize('mutation', ['fingerprint', 'missing_fingerprint', 'dropped_follow_up_call'])
def test_tampered_retained_record_is_refused(workload, mutation):
    serial, parallel = _pair(workload)
    candidate = copy.deepcopy(parallel)
    if mutation == 'fingerprint':
        candidate['workload_fingerprint']['sha256'] = '0' * 64
    elif mutation == 'missing_fingerprint':
        del candidate['workload_fingerprint']
    else:
        candidate['provider_calls'] -= 1
        candidate['stages']['provider']['count'] -= 1
    with pytest.raises(ValueError):
        compare_ai_benchmarks.compare(serial, candidate)
