import json
import subprocess
import sys
from pathlib import Path

from tools.benchmark_ai import workload_fingerprint


def test_fingerprint_normalizes_only_fixture_observation_and_dispatch_order():
    first = {'model': 'fixture-model', 'input': '{"executable":"/fixture"}'}
    followup = {'model': 'fixture-model', 'input': json.dumps({
        'executable': '/fixture', 'investigation': {'collected': 1, 'details': {'verified': True}},
    })}
    equivalent_followup = {**followup, 'input': json.dumps({
        'investigation': {'details': {'verified': True}, 'collected': 2}, 'executable': '/fixture',
    })}
    ssh = {'action': 'evidence', 'checks': ['package', 'executable']}
    fingerprint = workload_fingerprint([first, followup], [ssh])
    assert workload_fingerprint([equivalent_followup, first], [{**ssh, 'checks': list(reversed(ssh['checks']))}]) == fingerprint
    assert workload_fingerprint([{**first, 'model': 'different'}, followup], [ssh]) != fingerprint
    assert workload_fingerprint([{**first, 'input': '{"executable":"/different"}'}, followup], [ssh]) != fingerprint
    assert workload_fingerprint([first, followup], [{**ssh, 'checks': ['package']}]) != fingerprint
    assert workload_fingerprint([first, first, followup], [ssh]) != fingerprint


def test_serial_and_parallel_reports_share_the_observed_workload(tmp_path):
    benchmark = Path(__file__).resolve().parents[1] / 'tools' / 'benchmark_ai.py'
    reports = []
    for concurrency in ('1', '2'):
        result = subprocess.run(
            [sys.executable, str(benchmark), '--runs', '2', '--provider-delay-ms', '1',
             '--concurrency', concurrency], cwd=tmp_path, capture_output=True, text=True,
            timeout=60, check=True,
        )
        reports.append(json.loads(result.stdout))
    for report in reports:
        assert report['provider_calls'] == 3 and report['stages']['ssh_evidence']['count'] == 1
        assert report['workload_fingerprint']['version'] == 1
        assert len(report['workload_fingerprint']['sha256']) == 64
        assert 'fixture-model' not in json.dumps(report['workload_fingerprint'])
    assert reports[0]['workload_fingerprint'] == reports[1]['workload_fingerprint']
