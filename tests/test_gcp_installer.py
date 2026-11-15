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


def test_installer_persists_gcp_compose_files_for_plain_compose(installer):
    root,run=installer
    (root/'.env').write_text('ADMIN_PASSWORD=x\nGCP_ZONE=old\n')
    result=run()
    assert result.returncode==0,result.stderr
    config=dict(line.split('=',1) for line in (root/'.env').read_text().splitlines())
    assert config['COMPOSE_FILE']=='compose.yaml:compose.gcp.yaml'
    assert config['GCP_PROJECT']=='test-project' and config['GCP_ZONE']=='us-central1-a'
    assert config['ADMIN_PASSWORD']=='x'
    before=(root/'.env').read_text()
    assert run().returncode==0 and (root/'.env').read_text()==before


def _commands(root):
    return [json.loads(line) for line in (root/'commands').read_text().splitlines()]


def _config(root,name='.env'):
    return dict(line.split('=',1) for line in (root/name).read_text().splitlines())


def test_controller_mode_starts_only_the_controller_and_checks_inside_app(installer):
    root,run=installer
    result=run('--mode','controller','--public-url','https://patchy.example.test')
    assert result.returncode==0,result.stderr
    assert 'DISPOSABLE_SECRET' not in result.stdout+result.stderr
    assert 'background jobs wait' in result.stdout
    assert _config(root)['COMPOSE_FILE']=='compose.controller.yaml:compose.controller.gcp.yaml'
    assert _config(root,'.env.gcp')['MRPATCHY_GCP_MODE']=='controller'
    assert (root/'.env.gcp').stat().st_mode&0o777==0o600
    commands=[row for row in _commands(root) if '--env-file' in row]
    for row in commands:
        files=[row[i+1] for i,arg in enumerate(row) if arg=='-f']
        assert files==['compose.controller.yaml','compose.controller.gcp.yaml']
    assert not any('worker' in row for row in commands)
    assert not any('run' in row for row in commands)
    build=next(row for row in commands if 'build' in row)
    assert build[-2:]==['build','app']
    startup=next(i for i,row in enumerate(commands) if row[-3:]==['up','-d','--wait'])
    checks=[(i,row) for i,row in enumerate(commands) if 'gcloud' in row]
    assert checks and all(i>startup for i,_ in checks)
    for i,row in checks:
        assert row[row.index('exec'):row.index('exec')+7]==['exec','-T','--user','mrpatchy','-e','HOME=/home/mrpatchy','app']
    assert any('print-access-token' in row for _,row in checks)
    assert any('describe' in row and '--project=test-project' in row for _,row in checks)
    config=(root/'.env').read_text()
    again=run('--mode','controller')
    assert again.returncode==0,again.stderr
    assert (root/'.env').read_text()==config


def test_controller_mode_runs_while_app_is_already_running(installer):
    root,run=installer
    (root/'app-running').touch()
    result=run('--mode','controller','--public-url','https://patchy.example.test')
    assert result.returncode==0,result.stderr
    assert not any('down' in row or 'stop' in row for row in _commands(root))


def test_controller_mode_wif_signs_in_inside_app_with_controller_overlay(installer):
    root,run=installer
    credentials=root.parent/(root.name+'-identity');credentials.mkdir()
    (credentials/'credentials.json').write_text(json.dumps({'type':'external_account','credential_source':{'file':'/gcp/token'}}))
    result=run('--mode','controller','--public-url','https://patchy.example.test','--credential-dir',str(credentials))
    assert result.returncode==0,result.stderr
    assert _config(root)['COMPOSE_FILE']=='compose.controller.yaml:compose.controller.gcp.yaml:compose.controller.gcp-auth.json'
    overlay=json.loads((root/'compose.controller.gcp-auth.json').read_text())
    assert list(overlay['services'])==['app']
    commands=_commands(root)
    login=next(row for row in commands if 'login' in row)
    assert 'exec' in login and login[login.index('exec')+6]=='app' and 'worker' not in login
    assert login[login.index('-f',login.index('compose.controller.gcp.yaml'))+1]=='compose.controller.gcp-auth.json'
    assert commands.index(login)>next(i for i,row in enumerate(commands) if row[-3:]==['up','-d','--wait'])
    # The retained controller mount must not be dropped by a run without --credential-dir.
    assert run('--mode','controller').returncode!=0


@pytest.mark.parametrize('first,second',[('complete','controller'),('controller','complete')])
def test_installer_refuses_to_switch_modes_before_writing(installer,first,second):
    root,run=installer
    assert run('--mode',first,'--public-url','https://patchy.example.test').returncode==0
    before={name:(root/name).read_text() for name in ('.env','.env.gcp')}
    calls=len(_commands(root))
    result=run('--mode',second)
    assert result.returncode!=0
    assert 'refusing to switch' in result.stderr and 'Traceback' not in result.stderr
    assert {name:(root/name).read_text() for name in before}==before
    assert not any('build' in row or 'up' in row for row in _commands(root)[calls:])


def test_controller_mode_refuses_legacy_complete_installation(installer):
    root,run=installer
    # Releases before --mode wrote .env.gcp without a mode for the complete stack only.
    (root/'.env').write_text('ADMIN_PASSWORD=x\n')
    (root/'.env.gcp').write_text('GCP_PROJECT=test-project\nGCP_ZONE=us-central1-a\n')
    result=run('--mode','controller')
    assert result.returncode!=0 and 'uses --mode complete' in result.stderr
    assert (root/'.env').read_text()=='ADMIN_PASSWORD=x\n'
    assert run().returncode==0
    assert _config(root,'.env.gcp')['MRPATCHY_GCP_MODE']=='complete'


def test_controller_mode_accepts_prepared_controller_env(installer):
    root,run=installer
    (root/'.env').write_text('ADMIN_PASSWORD=x\nMRPATCHY_EXPECTED_WORKER_IDS=\n')
    assert run('--mode','controller').returncode==0
    assert _config(root)['ADMIN_PASSWORD']=='x'
    (root/'.env').write_text('ADMIN_PASSWORD=x\nCOMPOSE_FILE=compose.custom.yaml\n')
    (root/'.env.gcp').unlink()
    result=run('--mode','controller')
    assert result.returncode!=0 and 'unrecognized COMPOSE_FILE' in result.stderr


def test_installer_rejects_unknown_mode(installer):
    root,run=installer
    result=run('--mode','worker','--public-url','https://patchy.example.test')
    assert result.returncode==2 and not (root/'.env').exists()


def test_compose_wrapper_follows_recorded_mode(installer):
    root,_=installer
    env={**os.environ,'PATH':str(root/'bin')+':'+os.environ['PATH'],'MOCK_LOG':str(root/'commands')}
    def files():
        subprocess.run(['bash',str(root/'gcp-compose.sh'),'ps'],env=env,check=True)
        row=_commands(root)[-1]
        return [row[i+1] for i,arg in enumerate(row) if arg=='-f']
    (root/'.env.gcp').write_text('GCP_PROJECT=p\nGCP_ZONE=z\n')
    assert files()==['compose.yaml','compose.gcp.yaml']
    (root/'.env.gcp').write_text('GCP_PROJECT=p\nGCP_ZONE=z\nMRPATCHY_GCP_MODE=controller\n')
    assert files()==['compose.controller.yaml','compose.controller.gcp.yaml']
    (root/'compose.gcp-auth.json').write_text('{}')
    assert files()==['compose.controller.yaml','compose.controller.gcp.yaml']
    (root/'compose.controller.gcp-auth.json').write_text('{}')
    assert files()==['compose.controller.yaml','compose.controller.gcp.yaml','compose.controller.gcp-auth.json']
