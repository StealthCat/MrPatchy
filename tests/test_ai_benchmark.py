import json
import subprocess
import sys
from pathlib import Path


BENCHMARK = Path(__file__).resolve().parents[1] / 'tools' / 'benchmark_ai.py'


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
