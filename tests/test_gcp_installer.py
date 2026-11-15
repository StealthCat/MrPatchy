import json
import os
import shutil
import subprocess
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture
def installer(tmp_path):
    for name in ('install-gcp.sh','gcp-compose.sh','.env.worker.example'):shutil.copy(ROOT/name,tmp_path/name)
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
if args[:2]==["volume","inspect"]:
    sys.exit(1 if os.environ.get("MOCK_MISSING_VOLUME") else 0)
if "config" in args and "--format" in args:
    files=[args[i+1] for i,a in enumerate(args) if a=="-f"]
    if "compose.worker.yaml" in files:
        env={}
        for i,a in enumerate(args):
            if a=="--env-file":
                for line in Path(args[i+1]).read_text().splitlines():
                    key,sep,value=line.partition("=")
                    if sep and not key.startswith("#"):env[key.strip()]=value.strip().strip("'")
        name=args[args.index("-p")+1]
        print(json.dumps({"name":name,"services":{"worker":{"environment":{"DATABASE_URL":env.get("DATABASE_URL","sqlite:////data/mrpatchy.db").replace("$","$$")}}},
                          "volumes":{"app-data":{"name":env.get("MRPATCHY_CONTROLLER_DATA_VOLUME")}}}))
    else:
        name=os.environ.get("MOCK_PROJECT","mrpatchy")
        print(json.dumps({"name":name,"services":{"app":{"environment":{"DATABASE_URL":os.environ.get("MOCK_DATABASE_URL","sqlite:////data/mrpatchy.db").replace("$","$$")}}},
                          "volumes":{"app-data":{"name":name+"_app-data"}}}))
''')
    docker.chmod(0o755)
    env={**os.environ,'PATH':str(binary)+':'+os.environ['PATH'],'MOCK_LOG':str(tmp_path/'commands')}
    def run(*extra,**overrides):
        return subprocess.run(['bash',str(tmp_path/'install-gcp.sh'),'--project','test-project','--zone','us-central1-a','--instance','test-vm',*extra],env={**env,**overrides},capture_output=True,text=True)
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
    result=run('--mode','remote','--public-url','https://patchy.example.test')
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


def _worker_env(root):
    rows=[line.split('=',1) for line in (root/'.env.worker').read_text().splitlines() if line and not line.startswith('#')]
    return dict(rows)


def _files(row):
    return [row[i+1] for i,arg in enumerate(row) if arg=='-f']


def _controller(run):
    result=run('--mode','controller','--public-url','https://patchy.example.test')
    assert result.returncode==0,result.stderr


def test_worker_mode_joins_controller_without_touching_it(installer):
    root,run=installer
    _controller(run)
    before={name:(root/name).read_text() for name in ('.env','.env.gcp')}
    calls=len(_commands(root))
    result=run('--mode','worker','--workers','3')
    assert result.returncode==0,result.stderr
    assert 'DISPOSABLE_SECRET' not in result.stdout+result.stderr
    assert '3 replica(s)' in result.stdout
    assert {name:(root/name).read_text() for name in before}==before
    worker=_worker_env(root)
    assert (root/'.env.worker').stat().st_mode&0o777==0o600
    assert worker['COMPOSE_PROJECT_NAME']=='mrpatchy-workers'
    assert worker['MRPATCHY_CONTROLLER_DATA_VOLUME']=='mrpatchy_app-data'
    assert worker['DATABASE_URL']=="'sqlite:////data/mrpatchy.db'"
    assert worker['MRPATCHY_JOB_CONCURRENCY']=='2'
    assert 'ADMIN_PASSWORD' not in (root/'.env.worker').read_text()
    commands=[row for row in _commands(root)[calls:] if 'compose' in row and row!=['compose','version']]
    # Only the controller render uses the controller files; every mutation uses the worker project.
    controller=[row for row in commands if 'compose.controller.yaml' in row]
    assert controller and all(row[-3:]==['config','--format','json'] for row in controller)
    workers=[row for row in commands if 'compose.worker.yaml' in row]
    for row in workers:
        assert row[row.index('-p')+1]=='mrpatchy-workers'
        assert _files(row)==['compose.worker.yaml','compose.worker.gcp.yaml']
        assert row[row.index('--env-file'):row.index('--env-file')+4]==['--env-file','.env.worker','--env-file','.env.gcp']
    assert len(controller)+len(workers)==len(commands)
    assert any(row[-2:]==['build','worker'] for row in workers)
    assert not any('app' in row for row in workers)
    assert not any(word in row for row in commands for word in ('down','stop','exec','--remove-orphans'))
    startup=next(i for i,row in enumerate(workers) if row[-5:]==['up','-d','--wait','--scale','worker=3'])
    checks=[(i,row) for i,row in enumerate(workers) if 'gcloud' in row]
    assert len(checks)==3 and all(i<startup and row[row.index('run'):row.index('run')+4]==['run','--rm','--no-deps','worker'] for i,row in checks)
    assert any('describe' in row and '--project=test-project' in row for _,row in checks)
    # A re-run keeps the prepared .env.worker and scales the same project.
    prepared=(root/'.env.worker').read_text()
    assert run('--mode','worker').returncode==0
    assert (root/'.env.worker').read_text()==prepared
    assert _commands(root)[-1][-1]=='worker=1'


def test_worker_mode_copies_controller_database_and_custom_project(installer):
    root,run=installer
    _controller(run)
    url='mysql+pymysql://mrpatchy:p$ss@db:3306/mrpatchy'
    result=run('--mode','worker',MOCK_DATABASE_URL=url,MOCK_PROJECT='patchy')
    assert result.returncode==0,result.stderr
    assert url not in result.stdout+result.stderr
    worker=_worker_env(root)
    assert worker['DATABASE_URL']=="'"+url+"'"
    assert worker['MRPATCHY_CONTROLLER_DATA_VOLUME']=='patchy_app-data'
    assert worker['COMPOSE_PROJECT_NAME']=='patchy-workers'


def test_worker_mode_refuses_mismatched_prepared_env_without_changes(installer):
    root,run=installer
    _controller(run)
    (root/'.env.worker').write_text('COMPOSE_PROJECT_NAME=mrpatchy-workers\nMRPATCHY_CONTROLLER_DATA_VOLUME=other_app-data\n')
    calls=len(_commands(root))
    result=run('--mode','worker')
    assert result.returncode!=0 and 'does not use the controller data volume' in result.stderr
    assert (root/'.env.worker').read_text()=='COMPOSE_PROJECT_NAME=mrpatchy-workers\nMRPATCHY_CONTROLLER_DATA_VOLUME=other_app-data\n'
    assert not any('build' in row or 'up' in row for row in _commands(root)[calls:])
    (root/'.env.worker').write_text('COMPOSE_PROJECT_NAME=mrpatchy-workers\nMRPATCHY_CONTROLLER_DATA_VOLUME=mrpatchy_app-data\n')
    result=run('--mode','worker',MOCK_DATABASE_URL='mysql+pymysql://u:p@db/x')
    assert result.returncode!=0 and 'DATABASE_URL' in result.stderr and 'u:p@' not in result.stderr
    for content,reason in (('MRPATCHY_CONTROLLER_DATA_VOLUME=mrpatchy_app-data\n','no COMPOSE_PROJECT_NAME'),
                           ('COMPOSE_PROJECT_NAME=mrpatchy\nMRPATCHY_CONTROLLER_DATA_VOLUME=mrpatchy_app-data\n','must differ')):
        (root/'.env.worker').write_text(content)
        result=run('--mode','worker')
        assert result.returncode!=0 and reason in result.stderr
    (root/'.env.worker').write_text('COMPOSE_PROJECT_NAME=mrpatchy-workers\nMRPATCHY_CONTROLLER_DATA_VOLUME=mrpatchy_app-data\n')
    assert run('--mode','worker').returncode==0


def test_worker_mode_refuses_without_controller_or_volume(installer):
    root,run=installer
    result=run('--mode','worker')
    assert result.returncode!=0 and '--mode controller first' in result.stderr
    assert not (root/'.env.worker').exists() and not (root/'.env').exists()
    assert run('--public-url','https://patchy.example.test').returncode==0
    result=run('--mode','worker')
    assert result.returncode!=0 and 'uses --mode complete' in result.stderr
    assert not (root/'.env.worker').exists()


def test_worker_mode_refuses_missing_volume_and_other_project(installer):
    root,run=installer
    _controller(run)
    result=run('--mode','worker',MOCK_MISSING_VOLUME='1')
    assert result.returncode!=0 and 'start the controller first' in result.stderr
    assert not (root/'.env.worker').exists()
    other=subprocess.run(['bash',str(root/'install-gcp.sh'),'--project','other-project','--zone','us-central1-a','--instance','test-vm','--mode','worker'],
                         env={**os.environ,'PATH':str(root/'bin')+':'+os.environ['PATH'],'MOCK_LOG':str(root/'commands')},capture_output=True,text=True)
    assert other.returncode!=0 and 'must match the controller' in other.stderr
    assert not (root/'.env.worker').exists()


@pytest.mark.parametrize('extra',[('--workers','0'),('--workers','17'),('--workers','x'),('--public-url','https://patchy.example.test'),('--credential-dir','/tmp')])
def test_worker_mode_rejects_invalid_options(installer,extra):
    root,run=installer
    result=run('--mode','worker',*extra)
    assert result.returncode==2 and not (root/'.env.worker').exists()


def test_workers_option_needs_worker_mode(installer):
    root,run=installer
    result=run('--workers','2','--public-url','https://patchy.example.test')
    assert result.returncode==2 and not (root/'.env').exists()


def test_worker_mode_uses_worker_wif_overlay(installer):
    root,run=installer
    credentials=root.parent/(root.name+'-identity');credentials.mkdir()
    (credentials/'credentials.json').write_text(json.dumps({'type':'external_account','credential_source':{'file':'/gcp/token'}}))
    assert run('--mode','controller','--public-url','https://patchy.example.test','--credential-dir',str(credentials)).returncode==0
    calls=len(_commands(root))
    result=run('--mode','worker')
    assert result.returncode==0,result.stderr
    workers=[row for row in _commands(root)[calls:] if 'compose.worker.yaml' in row]
    assert workers and all(_files(row)==['compose.worker.yaml','compose.worker.gcp.yaml','compose.worker.gcp-auth.json'] for row in workers)
    assert not any('login' in row for row in workers)
    (root/'compose.worker.gcp-auth.json').unlink()
    result=run('--mode','worker')
    assert result.returncode!=0 and 'compose.worker.gcp-auth.json is missing' in result.stderr


def test_compose_wrapper_worker_selector(installer):
    root,_=installer
    env={**os.environ,'PATH':str(root/'bin')+':'+os.environ['PATH'],'MOCK_LOG':str(root/'commands')}
    def wrapper():
        return subprocess.run(['bash',str(root/'gcp-compose.sh'),'--workers','ps'],env=env,capture_output=True,text=True)
    (root/'.env.gcp').write_text('GCP_PROJECT=p\nGCP_ZONE=z\n')
    (root/'.env.worker').write_text('COMPOSE_PROJECT_NAME=patchy-workers\n')
    assert wrapper().returncode==2
    (root/'.env.gcp').write_text('GCP_PROJECT=p\nGCP_ZONE=z\nMRPATCHY_GCP_MODE=controller\n')
    assert wrapper().returncode==0
    row=_commands(root)[-1]
    assert row[:3]==['compose','-p','patchy-workers'] and row[-1]=='ps'
    assert _files(row)==['compose.worker.yaml','compose.worker.gcp.yaml']
    (root/'.env.worker').write_text('COMPOSE_PROJECT_NAME=Bad Name\n')
    assert wrapper().returncode==2
    (root/'.env.worker').unlink()
    assert wrapper().returncode==2


def test_recorded_worker_files_render_with_compose(installer,tmp_path):
    # A real render of the files install-gcp.sh --mode worker records: exactly the worker,
    # on the controller's external volume, with a literal "$" in the quoted DATABASE_URL.
    if not shutil.which('docker') or subprocess.run(['docker','compose','version'],capture_output=True).returncode:
        pytest.skip('docker compose is unavailable')
    root,run=installer
    _controller(run)
    url='mysql+pymysql://mrpatchy:p$ss@db:3306/mrpatchy'
    assert run('--mode','worker',MOCK_DATABASE_URL=url).returncode==0
    for name in ('compose.worker.yaml','compose.worker.gcp.yaml','Dockerfile'):shutil.copy(ROOT/name,root/name)
    result=subprocess.run(['docker','compose','-p','mrpatchy-workers','--env-file',str(root/'.env.worker'),'--env-file',str(root/'.env.gcp'),
                           '-f',str(root/'compose.worker.yaml'),'-f',str(root/'compose.worker.gcp.yaml'),'config','--format','json'],
                          capture_output=True,text=True,cwd=root,env={k:v for k,v in os.environ.items() if not k.startswith(('MRPATCHY_','DATABASE_URL','GCP_','COMPOSE_'))})
    assert result.returncode==0,result.stderr
    config=json.loads(result.stdout)
    assert list(config['services'])==['worker']
    assert config['volumes']['app-data']['name']=='mrpatchy_app-data' and config['volumes']['app-data']['external']
    # Compose escapes "$" as "$$" in rendered output; the value itself is the literal URL.
    assert config['services']['worker']['environment']['DATABASE_URL']==url.replace('$','$$')
    assert config['services']['worker']['environment']['CLOUDSDK_CORE_PROJECT']=='test-project'
