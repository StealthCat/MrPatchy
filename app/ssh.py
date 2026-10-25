import base64
import hashlib
import json
import os
import time
from pathlib import Path
import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .db import DATA
TARGET = Path(__file__).resolve().parent.parent/'target'
def key_path(host_id): return DATA/'ssh'/(host_id+'.key')
def create_key(host_id):
    path = key_path(host_id); path.parent.mkdir(mode=0o700, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    with open(path, 'xb') as f:
        os.chmod(path,0o600)
        f.write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.OpenSSH,serialization.NoEncryption()))
    return key.public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
def public_key(host_id):
    key = serialization.load_ssh_private_key(key_path(host_id).read_bytes(),password=None)
    return key.public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
def fingerprint(key): return 'SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
class Pinned(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected): self.expected = expected
    def missing_host_key(self, client, hostname, key):
        if fingerprint(key)!=self.expected: raise paramiko.SSHException('SSH host fingerprint mismatch; verify on target console')
def read_channel(channel, deadline, max_bytes=64*1024*1024):
    """Drain both streams; an idle timeout alone does not bound a trickling peer."""
    output=bytearray(); diagnostics=bytearray()
    while True:
        if time.monotonic()>=deadline:
            raise TimeoutError('SSH operation exceeded its total deadline; verify target state before retrying')
        if channel.recv_ready():
            chunk=channel.recv(32768)
            output.extend(chunk)
            if len(output)>max_bytes: raise ValueError('Snapshot exceeds 64 MiB')
        if channel.recv_stderr_ready():
            chunk=channel.recv_stderr(32768)
            diagnostics.extend(chunk[:max(0,16000-len(diagnostics))])
        if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
            status=channel.recv_exit_status()
            break
        time.sleep(0.005)
    if status:
        try: detail=json.loads(output).get('error')
        except (ValueError,AttributeError): detail=None
        raise RuntimeError(detail or diagnostics.decode(errors='replace') or 'Remote bridge failed')
    result=json.loads(output)
    if not isinstance(result,dict): raise ValueError('Remote bridge returned a non-object response')
    if result.get('error'): raise RuntimeError(result['error'])
    return result

def call(host, payload, timeout=60, key_file=None):
    deadline=time.monotonic()+timeout
    client=paramiko.SSHClient()
    client.set_missing_host_key_policy(Pinned(host.fingerprint))
    try:
        client.connect(host.address,port=host.port,username='drpatch',key_filename=str(key_file or key_path(host.id)),
                       look_for_keys=False,allow_agent=False,timeout=min(15,timeout),auth_timeout=min(15,timeout),banner_timeout=min(15,timeout),
                       disabled_algorithms={'keys':['ssh-rsa'],'pubkeys':['ssh-rsa'],
                                            'kex':['diffie-hellman-group1-sha1','diffie-hellman-group14-sha1','diffie-hellman-group-exchange-sha1']})
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError('SSH connection exceeded its total deadline')
        stdin,stdout,stderr=client.exec_command('mrpatchy',timeout=remaining)
        stdin.write(json.dumps(payload));stdin.flush();stdin.channel.shutdown_write()
        return read_channel(stdout.channel,deadline)
    finally:
        client.close()

def deploy(host):
    from target.bridge import UNIT
    code=(TARGET/'agent.py').read_bytes()
    bridge=(TARGET/'bridge.py').read_bytes()
    expected={'deployed':hashlib.sha256(code).hexdigest(),'bridge_sha256':hashlib.sha256(bridge).hexdigest(),'unit_sha256':hashlib.sha256(UNIT.encode()).hexdigest()}
    result=call(host,{'action':'deploy','agent':base64.b64encode(code).decode(),'sha256':expected['deployed'],
                      'bridge':base64.b64encode(bridge).decode(),'bridge_sha256':expected['bridge_sha256'],
                      'unit':UNIT,'unit_sha256':expected['unit_sha256']})
    if result.get('bridge_sha256') is None:
        raise RuntimeError('Target uses the legacy bootstrap bridge. Download and rerun its installer through a trusted console, then finish installation again.')
    if any(result.get(key)!=value for key,value in expected.items()):
        raise RuntimeError('Target deployment manifest does not match the central release')
    return result

def bootstrap(host):
    bridge = base64.b64encode((TARGET/'bridge.py').read_bytes()).decode()
    key = public_key(host.id)
    return f'''#!/bin/bash
set -euo pipefail
[ "$(id -u)" = 0 ] || {{ echo 'Run as root (sudo bash installer.sh)'; exit 1; }}
for command in python3 sshd sudo visudo useradd sha256sum openssl; do
  command -v "$command" >/dev/null || {{ echo "Missing prerequisite: $command. Install python3 openssh-server sudo first."; exit 1; }}
done
# Offline enrollment: no downloads, apt calls, or callbacks.
if id drpatch >/dev/null 2>&1 && [ ! -f /opt/drpatch/.mrpatchy-enrolled ]; then
  echo "Existing drpatch account is not managed by Mr Patchy; choose a clean target account before enrolling."; exit 1
fi
if ! id drpatch >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /opt/drpatch --shell /bin/sh drpatch
  # A random unknown password hash avoids sshd rejecting a locked account.
  python3 -c 'import secrets,subprocess; p=subprocess.run(["openssl","passwd","-6","-stdin"],input=secrets.token_urlsafe(64),text=True,capture_output=True,check=True); subprocess.run(["usermod","-p",p.stdout.strip(),"drpatch"],check=True)'
fi
[ "$(getent passwd drpatch | cut -d: -f6)" = /opt/drpatch ] || {{ echo 'Existing drpatch user has unexpected home'; exit 1; }}
for p in /opt/drpatch /opt/drpatch/.ssh /usr/local/lib/mrpatchy /etc/sudoers.d/mrpatchy; do
  [ ! -L "$p" ] || {{ echo "Refusing symlink: $p"; exit 1; }}
done
install -d -o root -g root -m 755 /opt/drpatch /usr/local/lib/mrpatchy
install -d -o root -g root -m 755 /opt/drpatch/.ssh
python3 - <<'PY'
import base64,os,tempfile
from pathlib import Path
def write_owned(path,data,mode):
    if path.is_symlink(): raise SystemExit('Refusing symlink: '+str(path))
    fd,name=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(data); os.fchmod(stream.fileno(),mode); os.fchown(stream.fileno(),0,0)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)
p=Path('/usr/local/lib/mrpatchy/bridge.py')
if p.is_symlink(): raise SystemExit('Refusing bridge symlink')
write_owned(p,base64.b64decode('{bridge}'),0o644)
p=Path('/opt/drpatch/.ssh/authorized_keys')
if p.is_symlink(): raise SystemExit('Refusing authorized_keys symlink')
write_owned(p,('restrict,command="/usr/bin/sudo -n /usr/bin/python3 -I /usr/local/lib/mrpatchy/bridge.py" {key} mrpatchy\\n').encode(),0o644)
PY
sudoers_tmp=$(mktemp /etc/sudoers.d/.mrpatchy.XXXXXX)
trap 'rm -f -- "$sudoers_tmp"' EXIT
printf '%s\n' 'drpatch ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/lib/mrpatchy/bridge.py' > "$sudoers_tmp"
chmod 440 "$sudoers_tmp"
visudo -cf "$sudoers_tmp"
mv -f -- "$sudoers_tmp" /etc/sudoers.d/mrpatchy
trap - EXIT
touch /opt/drpatch/.mrpatchy-enrolled
chmod 600 /opt/drpatch/.mrpatchy-enrolled
visudo -cf /etc/sudoers.d/mrpatchy
sshd -t
printf '\nEnrollment prepared. Add this verified host fingerprint in Mr Patchy:\n'
for key in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$key" -E sha256; done
printf '\nAllow SSH from your Mr Patchy server, then click Finish installation.\n'
'''

def rotate(host):
    """Add new key, prove it works, atomically promote, then revoke old key."""
    journal=DATA/'ssh'/(host.id+'.rotation.json')
    pending=key_path(host.id+'.next')
    if journal.exists():
        state=json.loads(journal.read_text())
        if state.get('complete'):journal.unlink()
    if not journal.exists():
        if pending.exists():pending.unlink()
        new=create_key(host.id+'.next')
        state={'old':public_key(host.id),'new':new}
        temporary=journal.with_suffix('.tmp');temporary.write_text(json.dumps(state));temporary.chmod(0o600);temporary.replace(journal)
    else:state=json.loads(journal.read_text())
    if pending.exists():
        call(host,{'action':'authorized-keys','keys':[state['old'],state['new']]})
        call(host,{'action':'snapshot'},key_file=pending)
        os.replace(pending,key_path(host.id))
    if public_key(host.id)!=state['new']:raise RuntimeError('Rotation journal/key mismatch; recover from a trusted console')
    result=call(host,{'action':'authorized-keys','keys':[state['new']]})
    call(host,{'action':'snapshot'})
    state['complete']=True
    temporary=journal.with_suffix('.tmp');temporary.write_text(json.dumps(state));temporary.chmod(0o600);temporary.replace(journal)
    return result
