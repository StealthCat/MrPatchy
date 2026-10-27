import json
import socket
import threading
import time
from types import SimpleNamespace
import paramiko
import pytest
from app import ssh

@pytest.mark.parametrize('early_status',[False,True])
@pytest.mark.parametrize('iap',[False,True])
def test_real_ssh_drains_large_stderr_without_deadlock(client,monkeypatch,tmp_path,early_status,iap):
    monkeypatch.setattr(ssh,'DATA',tmp_path)
    host=SimpleNamespace(id='ssh-test',address='127.0.0.1',port=0,fingerprint='')
    ssh.create_key(host.id)
    allowed=paramiko.Ed25519Key.from_private_key_file(str(ssh.key_path(host.id)))
    server_key=paramiko.RSAKey.generate(2048)
    host.fingerprint=ssh.fingerprint(server_key)
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
    host.port=listener.getsockname()[1]
    failures=[];seen=[]
    expected={'os':'x'*490,'status':'package inventory '*200000,'keys':{'fixture':'a'*50000}} if early_status else {'ok':True}
    class Server(paramiko.ServerInterface):
        def check_auth_publickey(self,username,key):
            return paramiko.AUTH_SUCCESSFUL if username=='drpatch' and key==allowed else paramiko.AUTH_FAILED
        def get_allowed_auths(self,username): return 'publickey'
        def check_channel_request(self,kind,chanid): return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        def check_channel_exec_request(self,channel,command): return command==b'mrpatchy'
    def serve():
        transport=None
        try:
            conn,_=listener.accept();transport=paramiko.Transport(conn)
            transport.add_server_key(server_key);transport.start_server(server=Server())
            channel=transport.accept(5);assert channel is not None
            data=bytearray()
            while True:
                chunk=channel.recv(4096)
                if not chunk: break
                data.extend(chunk)
            seen.append(json.loads(data))
            channel.sendall_stderr(b'fixture' if early_status else b'x'*(3*1024*1024))
            payload=json.dumps(expected).encode()
            if early_status:
                channel.sendall(payload[:1024])
                # SSH exit-status is not an end-of-stream marker.
                channel.send_exit_status(0)
                time.sleep(.1)
                channel.sendall(payload[1024:])
            else:
                channel.sendall(payload);channel.send_exit_status(0)
            channel.shutdown_write()
            time.sleep(.1)
        except Exception as e: failures.append(e)
        finally:
            if transport: transport.close()
            listener.close()
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    if iap:
        import subprocess
        import sys
        from app import connections
        relay = """
import socket,sys,select,os
s=socket.create_connection(('127.0.0.1',int(sys.argv[1])))
while True:
    ready,_,_=select.select([s,sys.stdin.buffer],[],[])
    for source in ready:
        data=s.recv(32768) if source is s else os.read(sys.stdin.fileno(),32768)
        if not data:sys.exit(0)
        if source is s:
            sys.stdout.buffer.write(data);sys.stdout.buffer.flush()
        else:s.sendall(data)
"""
        spawn=subprocess.Popen
        monkeypatch.setattr(connections.shutil,'which',lambda name:'/usr/bin/gcloud')
        monkeypatch.setattr(connections.subprocess,'Popen',lambda args,**kwargs:spawn([sys.executable,'-c',relay,str(host.port)],**kwargs))
        monkeypatch.setattr(connections,'for_host',lambda host:connections.Connection(address=host.address,port=host.port,transport='gcp_iap',project='test-project',zone='us-central1-a',instance='vm'))
    result=ssh.call(host,{'action':'snapshot'},timeout=10)
    thread.join(2)
    assert result==expected and seen==[{'action':'snapshot'}] and not failures

class EndlessChannel:
    def recv_ready(self): return True
    def recv(self,n): return b' '
    def recv_stderr_ready(self): return False
    def exit_status_ready(self): return False

def test_total_deadline_bounds_continuously_streaming_peer():
    with pytest.raises(TimeoutError): ssh.read_channel(EndlessChannel(),time.monotonic()+.02)

def test_snapshot_byte_limit_is_enforced():
    with pytest.raises(ValueError,match='exceeds'): ssh.read_channel(EndlessChannel(),time.monotonic()+1,max_bytes=2)

def test_paramiko_has_no_sha1_rsa_signatures():
    assert 'ssh-rsa' not in paramiko.RSAKey.HASHES

class FinishedChannel:
    eof_received=True
    closed=True
    def __init__(self,data,status=0):self.data=data;self.status=status
    def recv_ready(self):return bool(self.data)
    def recv(self,n):result=self.data[:n];self.data=self.data[n:];return result
    def recv_stderr_ready(self):return False
    def exit_status_ready(self):return True
    def recv_exit_status(self):return self.status


def test_truncated_reply_has_safe_diagnostic_and_missing_status_is_not_success():
    with pytest.raises(ssh.RemoteProtocolError) as error:
        ssh.read_channel(FinishedChannel(b'{"inventory":"private-sensitive-value'),time.monotonic()+1)
    assert 'bytes received' in str(error.value) and 'private-sensitive-value' not in str(error.value)
    with pytest.raises(ssh.RemoteProtocolError,match='without an exit status'):
        ssh.read_channel(FinishedChannel(b'{"ok":true}',-1),time.monotonic()+1)
