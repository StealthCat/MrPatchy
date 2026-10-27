import json
import os
import shutil
import subprocess
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture
def installer(tmp_path):
    for name in ('install-gcp.sh','gcp-compose.sh'):shutil.copy(ROOT/name,tmp_path/name)
    binary=tmp_path/'bin';binary.mkdir()
    docker=binary/'docker'
    docker.write_text('#!/usr/bin/env python3\nimport json,os,sys\nwith open(os.environ["MOCK_LOG"],"a") as f:f.write(json.dumps(sys.argv[1:])+"\\n")\nif "print-access-token" in sys.argv:print("DISPOSABLE_SECRET")\n')
    docker.chmod(0o755)
    env={**os.environ,'PATH':str(binary)+':'+os.environ['PATH'],'MOCK_LOG':str(tmp_path/'commands')}
    def run(*extra):
        return subprocess.run(['bash',str(tmp_path/'install-gcp.sh'),'--project','test-project','--zone','us-central1-a','--instance','test-vm',*extra],env=env,capture_output=True,text=True)
    return tmp_path,run

def test_fresh_installer_configures_both_runtimes_without_leaking_token(installer):
    root,run=installer
    result=run('--public-url','https://patchy.example.test:8443')
    assert result.returncode==0,result.stderr
    assert 'DISPOSABLE_SECRET' not in result.stdout+result.stderr
    config=(root/'.env').read_text();assert 'HTTPS_PORT=8443' in config
    assert (root/'.env').stat().st_mode&0o777==0o600
    commands=[json.loads(line) for line in (root/'commands').read_text().splitlines()]
    for service in ('app','worker'):
        assert any(service in row and 'print-access-token' in row for row in commands)
        assert any(service in row and 'describe' in row and '--project=test-project' in row for row in commands)
    assert commands[-1][-3:]==['up','-d','--wait']
    again=run('--public-url','https://ignored.example.test')
    assert again.returncode==0 and (root/'.env').read_text()==config


def test_installer_rejects_environment_injection_before_writing(installer):
    root,run=installer
    result=run('--public-url','https://${ADMIN_PASSWORD}.example.test')
    assert result.returncode!=0 and not (root/'.env').exists()


def test_wif_mount_and_credentials_validation(installer):
    root,run=installer
    credentials=root.parent/(root.name+'-identity');credentials.mkdir()
    (credentials/'credentials.json').write_text(json.dumps({'type':'service_account','private_key':'never-use'}))
    assert run('--public-url','https://patchy.example.test','--credential-dir',str(credentials)).returncode!=0
    assert not (root/'.env').exists()
    (credentials/'credentials.json').write_text(json.dumps({'type':'external_account','credential_source':{'file':'/gcp/token'}}))
    result=run('--public-url','https://patchy.example.test','--credential-dir',str(credentials))
    assert result.returncode==0,result.stderr
    override=json.loads((root/'compose.gcp-auth.json').read_text())
    assert all(item['volumes'][0]['read_only'] for item in override['services'].values())
    assert run().returncode!=0
