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
    docker.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with open(os.environ["MOCK_LOG"],"a") as f:f.write(json.dumps(args)+"\\n")
running=Path(os.environ["MOCK_LOG"]).with_name("app-running")
if "run" in args and "app" in args and running.exists():
    sys.exit("failed to set up container networking: Address already in use")
if "up" in args:running.touch()
if "exec" in args and not running.exists():sys.exit("service is not running")
if "print-access-token" in args:print("DISPOSABLE_SECRET")
''')
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
    startup=next(i for i,row in enumerate(commands) if row[-3:]==['up','-d','--wait'])
    checks=[(i,row) for i,row in enumerate(commands) if 'gcloud' in row]
    assert all('worker' in row for i,row in checks if i<startup)
    for service in ('app','worker'):
        assert any(i>startup and row[-3:]==[service,'gcloud','version'] for i,row in checks)
        assert any(i>startup and 'exec' in row and service in row and 'print-access-token' in row for i,row in checks)
        assert any(i>startup and 'exec' in row and service in row and 'describe' in row for i,row in checks)
    for i,row in checks:
        if i>startup:
            assert row[row.index('exec'):row.index('exec')+6]==['exec','-T','--user','mrpatchy','-e','HOME=/home/mrpatchy']
    again=run('--public-url','https://ignored.example.test')
    assert again.returncode==0 and (root/'.env').read_text()==config


def test_installer_runs_while_app_owns_control_address(installer):
    root,run=installer
    (root/'app-running').touch()
    result=run('--public-url','https://patchy.example.test')
    assert result.returncode==0,result.stderr
    assert 'DISPOSABLE_SECRET' not in result.stdout+result.stderr
    commands=[json.loads(line) for line in (root/'commands').read_text().splitlines()]
    assert not any('run' in row and 'app' in row for row in commands)
    assert not any('down' in row or 'stop' in row for row in commands)


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
    commands=[json.loads(line) for line in (root/'commands').read_text().splitlines()]
    login=next(row for row in commands if 'login' in row)
    assert 'worker' in login and 'app' not in login
    assert 'compose.gcp-auth.json' in login
    assert run('--credential-dir',str(credentials)).returncode==0
    assert run().returncode!=0


@pytest.mark.parametrize('url',['https://patchy.example.test:0','https://patchy.example.test:','https://patchy.example.test:70000','https://[::1]:'])
def test_installer_rejects_invalid_public_ports_without_traceback(installer,url):
    root,run=installer
    result=run('--public-url',url)
    assert result.returncode!=0 and not (root/'.env').exists()
    assert 'Invalid public port' in result.stderr and 'Traceback' not in result.stderr


def test_installer_defaults_to_443_without_explicit_port(installer):
    root,run=installer
    assert run('--public-url','https://patchy.example.test').returncode==0
    assert 'HTTPS_PORT=443' in (root/'.env').read_text()


def test_installer_warns_when_public_url_is_ignored_for_existing_env(installer):
    root,run=installer
    assert run('--public-url','https://patchy.example.test').returncode==0
    config=(root/'.env').read_text()
    again=run('--public-url','https://other.example.test')
    assert again.returncode==0 and (root/'.env').read_text()==config
    assert '--public-url ignored' in again.stderr
    assert '--public-url ignored' not in run().stderr
