import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tools import benchmark_ai
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


def test_source_commit_identifies_clean_tracked_source(tmp_path, monkeypatch):
    if not shutil.which('git'):
        pytest.skip('native Git is unavailable')

    def git(*arguments):
        return subprocess.run(['git', *arguments], cwd=tmp_path, check=True,
                              text=True, capture_output=True).stdout.strip()

    git('init', '--quiet', '--template=')
    source = tmp_path / 'fixture-source.py'
    source.write_text('value = 1\n', encoding='utf-8')
    git('add', source.name)
    git('-c', 'user.name=Benchmark Fixture', '-c', 'user.email=fixture@example.invalid',
        'commit', '--quiet', '--no-gpg-sign', '-m', 'Record fixture source')
    committed = git('rev-parse', 'HEAD')
    (tmp_path / 'capture.json').write_text('{}', encoding='utf-8')
    monkeypatch.setenv('GIT_DIR', str(tmp_path / 'unrelated-git-dir'))
    assert benchmark_ai.clean_source_commit(tmp_path) == committed
    source.write_text('value = 2\n', encoding='utf-8')
    assert benchmark_ai.clean_source_commit(tmp_path) is None


def test_source_commit_is_absent_without_a_checkout_or_git(tmp_path, monkeypatch):
    assert benchmark_ai.clean_source_commit(tmp_path) is None

    def unavailable(*args, **kwargs):
        raise FileNotFoundError('git')

    (tmp_path / '.git').mkdir()
    monkeypatch.setattr(benchmark_ai.subprocess, 'run', unavailable)
    assert benchmark_ai.clean_source_commit(tmp_path) is None
