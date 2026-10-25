import json
import socket
import threading
import time
from types import SimpleNamespace
import paramiko
import pytest
from app import ssh

def test_real_ssh_drains_large_stderr_without_deadlock(monkeypatch,tmp_path):
    monkeypatch.setattr(ssh,'DATA',tmp_path)
    host=SimpleNamespace(id='ssh-test',address='127.0.0.1',port=0,fingerprint='')
    ssh.create_key(host.id)
    allowed=paramiko.Ed25519Key.from_private_key_file(str(ssh.key_path(host.id)))
    server_key=paramiko.RSAKey.generate(2048)
    host.fingerprint=ssh.fingerprint(server_key)
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
    host.port=listener.getsockname()[1]
    failures=[];seen=[]
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
            channel.sendall_stderr(b'x'*(3*1024*1024))
            channel.sendall(b'{"ok":true}')
            channel.send_exit_status(0);channel.shutdown_write()
            time.sleep(.1)
        except Exception as e: failures.append(e)
        finally:
            if transport: transport.close()
            listener.close()
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    result=ssh.call(host,{'action':'snapshot'},timeout=10)
    thread.join(2)
    assert result=={'ok':True} and seen==[{'action':'snapshot'}] and not failures

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
