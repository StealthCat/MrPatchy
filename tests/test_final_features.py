import json
import os
import subprocess
import sys
from types import SimpleNamespace
from pathlib import Path
import pytest
from app import sso,mail,ssh
from app.coordination import Lock
from app.db import Session,Setting
from app.identity import User
from app.security import password_hash
from target import bridge

def test_sso_binding_requires_exact_subject_and_enabled_account(admin,monkeypatch):
    monkeypatch.setattr(sso,'issuer','https://issuer.example')
    with Session() as s:
        s.add(User(username='sso-user',password=password_hash('not-used-password'),role='viewer'))
        s.add(Setting(key=sso.binding_key('subject'),value={'username':'sso-user'}));s.commit()
        assert sso.resolve_identity(s,{'iss':sso.issuer,'sub':'subject'}).role=='viewer'
        with pytest.raises(ValueError):sso.resolve_identity(s,{'iss':'https://evil.example','sub':'subject'})
        with pytest.raises(ValueError):sso.resolve_identity(s,{'iss':sso.issuer,'sub':'another'})
        s.get(User,'sso-user').enabled=False;s.commit()
        with pytest.raises(ValueError):sso.resolve_identity(s,{'iss':sso.issuer,'sub':'subject'})

def test_sso_disabled_and_replayed_state_rejected(client):
    assert client.get('/api/sso').json()=={'enabled':False}
    assert client.get('/auth/sso/callback?state=invalid').status_code==404

def test_smtp_requires_tls_and_prevents_header_injection():
    with pytest.raises(ValueError):mail.validate({'host':'mail','sender':'a@example.test','recipients':['b@example.test'],'mode':'plain','port':25})
    with pytest.raises(ValueError):mail.validate({'host':'mail','sender':'a@example.test\nBcc: evil','recipients':['b@example.test'],'mode':'tls','port':465})

def test_smtp_starttls_precedes_login(monkeypatch):
    events=[]
    class SMTP:
        def __init__(self,*a,**k):pass
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def ehlo(self):events.append('ehlo')
        def starttls(self,**kwargs):events.append('tls')
        def login(self,*args):events.append('login')
        def send_message(self,message):events.append('send');assert message['Message-ID']
    monkeypatch.setattr(mail.smtplib,'SMTP',SMTP)
    mail.send({'host':'mail','port':587,'mode':'starttls','sender':'a@example.test','recipients':['b@example.test'],'username':'u','password':'p'},SimpleNamespace(id='1',created=1,kind='test',host_id='host',message='alert'))
    assert events==['ehlo','tls','ehlo','login','send']

def test_cross_process_lock_excludes_other_worker():
    lock=Lock('test-process-exclusion')
    code="from app.coordination import Lock; l=Lock('test-process-exclusion'); print(l.acquire(False))"
    with lock:
        assert subprocess.check_output([sys.executable,'-c',code],text=True).strip()=='False'
    assert subprocess.check_output([sys.executable,'-c',code],text=True).strip()=='True'

def test_rotation_does_not_promote_key_before_new_login_works(tmp_path,monkeypatch):
    monkeypatch.setattr(ssh,'DATA',tmp_path)
    ssh.create_key('host');original=ssh.key_path('host').read_bytes()
    host=SimpleNamespace(id='host')
    def call(host,payload,**kwargs):
        if kwargs.get('key_file'):raise RuntimeError('New key authentication failed')
        return {}
    monkeypatch.setattr(ssh,'call',call)
    with pytest.raises(RuntimeError):ssh.rotate(host)
    assert ssh.key_path('host').read_bytes()==original
    assert ssh.key_path('host.next').exists()

def test_protected_patch_rolls_back_and_never_replays(tmp_path,monkeypatch):
    monkeypatch.setattr(bridge,'ROOT',tmp_path)
    calls=[]
    def hook(operation,identifier):
        calls.append(operation)
        return {'ready':True} if operation=='probe' else {'snapshot':'42'} if operation=='snapshot' else {'reboot_required':False}
    monkeypatch.setattr(bridge,'recovery_hook',hook)
    monkeypatch.setattr(bridge,'handle',lambda request:(_ for _ in ()).throw(RuntimeError('apt failure')))
    request={'job_id':'a'*36,'packages':['test=2'],'policy':{'rollback':True}}
    with pytest.raises(RuntimeError,match='recovery state'):bridge.protected_patch(request)
    assert calls==['probe','snapshot','rollback']
    with pytest.raises(RuntimeError,match='incomplete'):bridge.protected_patch(request)

def test_target_keys_reject_arbitrary_authorized_options(tmp_path,monkeypatch):
    monkeypatch.setattr(bridge,'ROOT',tmp_path)
    with pytest.raises(ValueError):bridge.handle({'action':'authorized-keys','keys':['command="evil" ssh-ed25519 AAAA']})

def test_provenance_does_not_export_arguments(tmp_path,monkeypatch):
    from target import agent
    proc=tmp_path/'process';proc.mkdir();(proc/'root').mkdir()
    script=proc/'root/script.py';script.write_text('print(1)')
    (proc/'maps').write_text('')
    (proc/'cmdline').write_bytes(b'python3\0/script.py\0secret-password\0')
    monkeypatch.setattr(agent.os,'readlink',lambda path:'/usr/bin/python3')
    result=agent.provenance(proc,{})
    assert result[0]['kind']=='script' and len(result[0]['sha256'])==64
    assert 'secret-password' not in json.dumps(result)

def test_encrypted_recovery_round_trip(tmp_path,monkeypatch):
    import importlib.util,sqlite3,shutil
    if not shutil.which('restic'):pytest.skip('restic is exercised in recovery CI')
    spec=importlib.util.spec_from_file_location('recovery',Path(__file__).parents[1]/'scripts/recovery.py')
    recovery=importlib.util.module_from_spec(spec);spec.loader.exec_module(recovery)
    data=tmp_path/'data';data.mkdir();(data/'ssh').mkdir();(data/'ssh/test.key').write_text('private fixture')
    (data/'secret.key').write_text('encryption fixture')
    with sqlite3.connect(data/'mrpatchy.db') as db:db.execute('CREATE TABLE example (value TEXT)');db.execute("INSERT INTO example VALUES ('restored')")
    dirs=[]
    for name in ['tls','caddy-data','caddy-config']:
        path=tmp_path/name;path.mkdir();(path/'fixture').write_text(name);dirs.append(path)
    password=tmp_path/'restic-password';password.write_text('long-random-test-password')
    monkeypatch.setenv('RESTIC_PASSWORD_FILE',str(password));monkeypatch.setenv('RESTIC_REPOSITORY',str(tmp_path/'repository'))
    monkeypatch.setenv('DATABASE_URL','sqlite:///'+str(data/'mrpatchy.db'))
    monkeypatch.setattr(recovery,'remote',lambda:None) # Local transport fixture; real restic encryption/verification.
    recovery.run(['restic','init'])
    recovery.backup(data,*dirs)
    bundle=recovery.restore('latest',tmp_path/'staging')
    recovery.activate(bundle,tmp_path/'restored-data',tmp_path/'restored-tls',tmp_path/'restored-caddy-data',tmp_path/'restored-caddy-config',uid=os.getuid())
    with sqlite3.connect(tmp_path/'restored-data/mrpatchy.db') as db:assert db.execute('SELECT value FROM example').fetchone()[0]=='restored'
    assert (tmp_path/'restored-caddy-data/fixture').read_text()=='caddy-data'

def test_remote_recovery_refuses_local_repository(monkeypatch):
    import importlib.util
    spec=importlib.util.spec_from_file_location('recovery',Path(__file__).parents[1]/'scripts/recovery.py')
    recovery=importlib.util.module_from_spec(spec);spec.loader.exec_module(recovery)
    monkeypatch.setenv('RESTIC_REPOSITORY','/tmp/local')
    with pytest.raises(ValueError):recovery.remote()
