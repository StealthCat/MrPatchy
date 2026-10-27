import socket
import subprocess
import sys
import time
from types import SimpleNamespace
import paramiko
import pytest
from app import connections, ssh, worker
from app.db import Session, Host, Setting
from app.identity import User

@pytest.fixture
def host(admin):
    with Session() as s:
        s.add(Host(id='connection-host',name='GCP',address='192.0.2.1',port=22,fingerprint='SHA256:'+'a'*43,state='offline'))
        s.commit()
    return '/api/hosts/connection-host/connection'

def test_edit_keeps_identity_and_history_and_rejects_stale(admin,host):
    old=admin.get(host).json()
    new={**old,'address':'192.0.2.2','port':2222}
    assert admin.put(host,json={'connection':new,'expected':old}).status_code==200
    assert admin.put(host,json={'connection':old,'expected':old}).status_code==409
    with Session() as s:
        h=s.get(Host,'connection-host')
        assert h.fingerprint=='SHA256:'+'a'*43 and h.address=='192.0.2.2'
    lock=worker.host_lock('connection-host');assert lock.acquire(False)
    try:assert admin.put(host,json={'connection':old,'expected':new}).status_code==409
    finally:lock.release()
    assert admin.get('/api/hosts/missing/connection').status_code==404

@pytest.mark.parametrize('role',['viewer','operator'])
def test_connection_is_admin_only(admin,host,role):
    old=admin.get(host).json()
    with Session() as s:s.get(User,'admin').role=role;s.commit()
    assert admin.get(host).status_code==403
    assert admin.put(host,json={'connection':old,'expected':old}).status_code==403
    assert admin.post(host+'/test').status_code==403

def test_iap_validation_and_test_does_not_change_pin(admin,host,monkeypatch):
    old=admin.get(host).json()
    for values in [{},{'project':'--bad','zone':'z','instance':'i'},{'project':'p','zone':'z','instance':'x;id'}]:
        assert admin.put(host,json={'connection':{**old,'transport':'gcp_iap',**values},'expected':old}).status_code==422
    new={**old,'transport':'gcp_iap','project':'test-project','zone':'us-central1-a','instance':'server-1'}
    assert admin.put(host,json={'connection':new,'expected':old}).status_code==200
    seen=[]
    monkeypatch.setattr(ssh,'call',lambda h,payload,timeout:seen.append((h.fingerprint,payload,timeout)) or {})
    assert admin.post(host+'/test').status_code==200
    assert seen==[('SHA256:'+'a'*43,{'action':'snapshot'},30)]
    def fail(*a,**k):raise RuntimeError('SSH host fingerprint mismatch')
    monkeypatch.setattr(ssh,'call',fail)
    assert admin.post(host+'/test').status_code==502
    with Session() as s:assert s.get(Host,'connection-host').fingerprint=='SHA256:'+'a'*43

def test_iap_missing_cli_is_actionable(monkeypatch):
    monkeypatch.setattr(connections.shutil,'which',lambda name:None)
    with pytest.raises(RuntimeError,match='runtime'):
        connections.IAPSocket(connections.Connection(address='host'),time.monotonic()+1)

@pytest.mark.parametrize('script',[
    'import sys;sys.stdout.buffer.write(b"hello");sys.stdout.flush()',
    'import time;time.sleep(60)',
])
def test_iap_pipe_eof_timeout_cleanup_and_arguments(monkeypatch,script):
    real_popen=subprocess.Popen;seen=[]
    def spawn(argv,**kwargs):
        seen.append(argv)
        return real_popen([sys.executable,'-c',script],**kwargs)
    monkeypatch.setattr(connections.shutil,'which',lambda name:'/usr/bin/gcloud')
    monkeypatch.setattr(connections.subprocess,'Popen',spawn)
    route=connections.Connection(address='unused',port=2222,transport='gcp_iap',project='my-project',zone='us-central1-a',instance='test-vm')
    stream=connections.IAPSocket(route,time.monotonic()+2)
    try:
        stream.settimeout(.2)
        if 'hello' in script:
            assert stream.recv(5)==b'hello'
            assert stream.recv(5)==b''
        else:
            with pytest.raises(socket.timeout):stream.recv(5)
    finally:stream.close();stream.close()
    assert stream.process.poll() is not None
    assert seen[0][3:5]==['test-vm','2222']
    assert '--project=my-project' in seen[0] and '--listen-on-stdin' in seen[0]

def test_keepalive_and_auth_diagnostic_do_not_retry(client,monkeypatch):
    calls=[]
    class FakeClient:
        def set_missing_host_key_policy(self,p):pass
        def connect(self,*a,**k):calls.append('connect')
        def get_transport(self):return SimpleNamespace(set_keepalive=lambda value:calls.append(value))
        def exec_command(self,*a,**k):raise paramiko.AuthenticationException('denied')
        def close(self):calls.append('close')
    monkeypatch.setattr(ssh.paramiko,'SSHClient',FakeClient)
    with pytest.raises(RuntimeError,match='drpatch'):
        ssh.call(SimpleNamespace(id='fake',address='host',port=22,fingerprint='pin'),{'action':'patch'})
    assert calls==['connect',20,'close']
