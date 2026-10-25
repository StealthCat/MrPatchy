import base64
import hashlib
import json
import os
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
def call(host, payload, timeout=60):
    client = paramiko.SSHClient(); client.set_missing_host_key_policy(Pinned(host.fingerprint))
    try:
        client.connect(host.address, port=host.port, username='drpatch', key_filename=str(key_path(host.id)), look_for_keys=False, allow_agent=False, timeout=15, auth_timeout=15, banner_timeout=15)
        stdin, stdout, stderr = client.exec_command('mrpatchy',timeout=timeout)
        stdin.write(json.dumps(payload)); stdin.flush(); stdin.channel.shutdown_write()
        raw = stdout.read(64*1024*1024+1)
        if len(raw)>64*1024*1024: raise ValueError('Snapshot exceeds 64 MiB')
        result = json.loads(raw)
        if result.get('error'): raise RuntimeError(result['error'])
        if stdout.channel.recv_exit_status(): raise RuntimeError('Remote bridge failed')
        return result
    finally: client.close()
def deploy(host):
    code = (TARGET/'agent.py').read_bytes()
    return call(host,{'action':'deploy','agent':base64.b64encode(code).decode(),'sha256':hashlib.sha256(code).hexdigest()})
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
  useradd --system --home-dir /opt/drpatch --shell /bin/sh drpatch
  # A random unknown password hash avoids sshd rejecting a locked account.
  python3 -c 'import secrets,subprocess; p=subprocess.run(["openssl","passwd","-6","-stdin"],input=secrets.token_urlsafe(64),text=True,capture_output=True,check=True); subprocess.run(["usermod","-p",p.stdout.strip(),"drpatch"],check=True)'
fi
[ "$(getent passwd drpatch | cut -d: -f6)" = /opt/drpatch ] || {{ echo 'Existing drpatch user has unexpected home'; exit 1; }}
for p in /opt/drpatch /opt/drpatch/.ssh /usr/local/lib/mrpatchy /etc/sudoers.d/mrpatchy; do
  [ ! -L "$p" ] || {{ echo "Refusing symlink: $p"; exit 1; }}
done
install -d -o root -g root -m 755 /opt/drpatch /usr/local/lib/mrpatchy
install -d -o drpatch -g drpatch -m 700 /opt/drpatch/.ssh
# The home is root-owned. The authorized_keys file must not be replaceable by drpatch.
chown root:root /opt/drpatch/.ssh
chmod 755 /opt/drpatch/.ssh
python3 - <<'PY'
import base64,os
from pathlib import Path
p=Path('/usr/local/lib/mrpatchy/bridge.py')
if p.is_symlink(): raise SystemExit('Refusing bridge symlink')
p.write_bytes(base64.b64decode('{bridge}')); p.chmod(0o644)
p=Path('/opt/drpatch/.ssh/authorized_keys')
if p.is_symlink(): raise SystemExit('Refusing authorized_keys symlink')
p.write_text('restrict,command="/usr/bin/sudo -n /usr/bin/python3 -I /usr/local/lib/mrpatchy/bridge.py" {key} mrpatchy\\n'); p.chmod(0o644)
PY
printf '%s\n' 'drpatch ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/lib/mrpatchy/bridge.py' > /etc/sudoers.d/mrpatchy
chmod 440 /etc/sudoers.d/mrpatchy
touch /opt/drpatch/.mrpatchy-enrolled
chmod 600 /opt/drpatch/.mrpatchy-enrolled
visudo -cf /etc/sudoers.d/mrpatchy
sshd -t
printf '\nEnrollment prepared. Add this verified host fingerprint in Mr Patchy:\n'
for key in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$key" -E sha256; done
printf '\nAllow SSH from your Mr Patchy server, then click Finish installation.\n'
'''
