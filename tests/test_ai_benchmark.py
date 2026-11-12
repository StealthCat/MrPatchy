import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.compare_ai_benchmarks import compare


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / 'tools' / 'benchmark_ai.py'


def test_ssh_delay_benchmark_preserves_the_followup(tmp_path):
    result = subprocess.run(
        [sys.executable, str(BENCHMARK), '--runs', '2', '--provider-delay-ms', '1',
         '--ssh-delay-ms', '40'],
        cwd=tmp_path, capture_output=True, text=True, timeout=60, check=True,
    )
    report = json.loads(result.stdout)
    assert report['fixture_only'] is True
    assert report['retained_history_rows'] == 0
    assert report['provider_delay_ms'] == 1 and report['ssh_delay_ms'] == 40
    assert report['runs'] == 2 and report['provider_calls'] == 3 and report['errors'] == 0
    assert report['stages']['ssh_evidence']['count'] == 1
    assert report['stages']['ssh_evidence']['p50_ms'] >= 40
    assert report['stages']['one_stage']['count'] == report['stages']['two_stage']['count'] == 1


def test_ssh_delay_is_bounded_before_starting_the_fixture():
    for delay in ('-1', '1001'):
        result = subprocess.run(
            [sys.executable, str(BENCHMARK), '--ssh-delay-ms', delay],
            capture_output=True, text=True, timeout=10, check=False,
        )
        assert result.returncode == 2
        assert '--ssh-delay-ms must be between 0 and 1000' in result.stderr


def test_queue_age_benchmark_reports_the_selected_fixture_age(tmp_path):
    result = subprocess.run(
        [sys.executable, str(BENCHMARK), '--runs', '2', '--provider-delay-ms', '1',
         '--ssh-delay-ms', '1', '--queue-age-seconds', '5'],
        cwd=tmp_path, capture_output=True, text=True, timeout=60, check=True,
    )
    report = json.loads(result.stdout)
    assert report['queue_age_seconds'] == report['initial_fixture_queue_age_seconds'] == 5
    assert report['provider_calls'] == 3 and report['errors'] == 0
    assert report['stages']['one_stage']['count'] == report['stages']['two_stage']['count'] == 1
    assert report['stages']['ssh_evidence']['count'] == 1
    assert report['stages']['queue_age']['count'] == 2
    assert report['stages']['queue_age']['p50_ms'] >= 5000
    assert report['stages']['queue_age']['p95_ms'] < 15000


def test_queue_age_is_bounded_before_starting_the_fixture():
    for age in ('-1', '86401'):
        result = subprocess.run(
            [sys.executable, str(BENCHMARK), '--queue-age-seconds', age],
            capture_output=True, text=True, timeout=10, check=False,
        )
        assert result.returncode == 2
        assert '--queue-age-seconds must be between 0 and 86400' in result.stderr


def run_benchmark(concurrency, retained_history_rows=0, *, same_server=False, follow_up_runs=None):
    layout = ['--same-server'] if same_server else []
    stage_mix = [] if follow_up_runs is None else ['--follow-up-runs', str(follow_up_runs)]
    result=subprocess.run(
        [sys.executable,str(BENCHMARK),'--runs','4','--concurrency',str(concurrency),
         '--provider-delay-ms','1','--persistence-delay-ms','5',
         '--retained-history-rows',str(retained_history_rows),*layout,*stage_mix],
        cwd=ROOT,capture_output=True,text=True,timeout=60,check=True)
    return json.loads(result.stdout)


@pytest.mark.parametrize('follow_up_runs', [0, 1, 4])
def test_configured_follow_up_runs_preserve_matched_workload(follow_up_runs):
    serial = run_benchmark(1, follow_up_runs=follow_up_runs)
    parallel = run_benchmark(4, follow_up_runs=follow_up_runs)
    comparison = compare(serial, parallel)
    assert comparison['capability_equivalent'] is True
    unobserved = {0: ('two_stage', 'ssh_evidence'), 4: ('one_stage',)}
    for stage in unobserved.get(follow_up_runs, ()):
        assert comparison['deltas']['stages'][stage] == {'p50_ms': None, 'p95_ms': None}
        assert serial['stages'][stage] == {'count': 0, 'p50_ms': None, 'p95_ms': None}
        assert parallel['stages'][stage] == serial['stages'][stage]
    for report in (serial, parallel):
        assert report['provider_calls'] == 4 + follow_up_runs
        assert report['stages']['ssh_evidence']['count'] == follow_up_runs
        assert report['stages']['two_stage']['count'] == follow_up_runs
        assert report['stages']['one_stage']['count'] == 4 - follow_up_runs


@pytest.mark.parametrize('follow_up_runs', ['-1', '3'])
def test_follow_up_runs_are_bounded_before_starting_the_fixture(follow_up_runs):
    result = subprocess.run(
        [sys.executable, str(BENCHMARK), '--runs', '2', '--follow-up-runs', follow_up_runs],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 2
    assert '--follow-up-runs must be between 0 and --runs' in result.stderr


def test_same_server_serial_and_parallel_preserve_workload():
    serial = run_benchmark(1, same_server=True)
    parallel = run_benchmark(4, same_server=True)
    assert compare(serial, parallel)['capability_equivalent'] is True
    for report in (serial, parallel):
        assert report['fixture_hosts'] == 1
        assert report['single_server_slots'] == 4
        assert report['completed_subjects'] == 4
        assert report['approved_subjects'] == 0
        assert report['provider_calls'] == 6
        assert report['stages']['ssh_evidence']['count'] == 2
        assert 1 <= report['peak_provider_requests'] <= report['concurrency']


def test_same_server_rejects_threads_above_the_fixture_slot_limit():
    result = subprocess.run(
        [sys.executable, str(BENCHMARK), '--same-server', '--concurrency', '5'],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 2
    assert '--same-server requires --concurrency at most 4' in result.stderr


def test_persistence_delay_is_bounded():
    for value in ('-1','1001'):
        result=subprocess.run(
            [sys.executable,str(BENCHMARK),'--runs','2','--persistence-delay-ms',value],
            cwd=ROOT,capture_output=True,text=True,timeout=10)
        assert result.returncode==2
        assert '--persistence-delay-ms must be between 0 and 1000' in result.stderr


def test_serial_and_parallel_persistence_delay_preserve_workload():
    serial=run_benchmark(1)
    parallel=run_benchmark(2)

    for result,execution in ((serial,'serial'),(parallel,'parallel')):
        assert result['fixture_only'] is True
        assert result['execution']==execution
        assert result['persistence_delay_ms']==5
        assert result['runs']==result['completed_subjects']==4
        assert result['approved_subjects']==0
        assert result['provider_calls']==6
        assert result['input_tokens']==600
        assert result['output_tokens']==120
        assert result['errors']==0
        assert result['stages']['receipt_persistence']['count']==6
        assert result['stages']['usage_persistence']['count']==6
        assert result['stages']['receipt_persistence']['p50_ms']>=5
        assert result['stages']['usage_persistence']['p50_ms']>=5
        assert 'no production/TLS/database speed claim' in result['notes']


def test_retained_history_is_bounded_before_starting_the_fixture():
    for count in ('-1', '50001'):
        result = subprocess.run(
            [sys.executable, str(BENCHMARK), '--retained-history-rows', count],
            capture_output=True, text=True, timeout=10, check=False,
        )
        assert result.returncode == 2
        assert '--retained-history-rows must be between 0 and 50000' in result.stderr


def test_retained_history_does_not_change_the_investigated_workload():
    empty = run_benchmark(1)
    retained = run_benchmark(2, retained_history_rows=5000)
    assert empty['retained_history_rows'] == 0
    assert retained['retained_history_rows'] == 5000
    for key in ('workload_fingerprint', 'provider_calls', 'completed_subjects',
                'approved_subjects', 'input_tokens', 'output_tokens'):
        assert retained[key] == empty[key]
    for stage in retained['stages']:
        assert retained['stages'][stage]['count'] == empty['stages'][stage]['count']
