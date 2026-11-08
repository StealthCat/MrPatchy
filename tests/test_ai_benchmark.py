import json
import subprocess
import sys
from pathlib import Path


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


def run_benchmark(concurrency):
    result=subprocess.run(
        [sys.executable,str(BENCHMARK),'--runs','4','--concurrency',str(concurrency),
         '--provider-delay-ms','1','--persistence-delay-ms','5'],
        cwd=ROOT,capture_output=True,text=True,timeout=60,check=True)
    return json.loads(result.stdout)


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
