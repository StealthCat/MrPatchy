import base64
import hashlib
import json
import os
import socket
import time
from pathlib import Path
import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .db import DATA
TARGET = Path(__file__).resolve().parent.parent/'target'
# The UI pins ED25519. Inspect sshd's configured identities instead of globbing
# unrelated/stale .pub files (including obsolete DSA keys) under /etc/ssh.
HOST_FINGERPRINT_SCRIPT = r'''
sshd_config=$(sshd -T)
ed25519_enabled=0
while read -r directive value; do
  if [ "$directive" = hostkeyalgorithms ]; then
    case ",$value," in *,ssh-ed25519,*) ed25519_enabled=1 ;; esac
  fi
done <<< "$sshd_config"
host_fingerprint=''
if [ "$ed25519_enabled" = 1 ]; then
  while read -r directive value; do
    [ "$directive" = hostkey ] || continue
    # Derive the public identity without modifying keys or trusting a stale .pub.
    if host_public=$(ssh-keygen -y -P '' -f "$value" 2>/dev/null); then
      case "$host_public" in
        'ssh-ed25519 '*)
          if host_fingerprint=$(printf '%s\n' "$host_public" | ssh-keygen -lf - -E sha256 2>/dev/null); then
            break
          fi
          ;;
      esac
    fi
  done <<< "$sshd_config"
fi
if [ -z "$host_fingerprint" ]; then
  printf '%s\n' 'Enrollment files are prepared, but no usable enabled ED25519 host key was found in sshd -T.' 'Check the SSH server HostKey and HostKeyAlgorithms settings on this target before finishing enrollment.' >&2
  exit 1
fi
printf '\nEnrollment prepared. Add this verified ED25519 host fingerprint in Mr Patchy:\n%s\n' "$host_fingerprint"
'''
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
class RemoteProtocolError(RuntimeError):
    """A reply cannot be trusted as a complete remote operation receipt."""

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
        # Servers may send exit-status before the last stdout packets. Only EOF
        # (or channel close) tells us that no more response bytes can arrive.
        ended=getattr(channel,'eof_received',False) or getattr(channel,'closed',False)
        if ended and channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
            status=channel.recv_exit_status()
            break
        time.sleep(0.005)
    if status == -1:
        raise RemoteProtocolError('SSH stream closed without an exit status; verify target state before retrying')
    if status:
        try: detail=json.loads(output).get('error')
        except (ValueError,AttributeError): detail=None
        raise RuntimeError(detail or diagnostics.decode(errors='replace') or 'Remote bridge failed')
    try: result=json.loads(output)
    except (ValueError,UnicodeDecodeError) as error:
        # Never echo inventory/key material from a damaged response into logs/UI.
        position=getattr(error,'pos',None)
        location=(' at character '+str(position)) if position is not None else ''
        raise RemoteProtocolError('SSH returned incomplete or invalid JSON'+location+' ('+str(len(output))+' bytes received). Verify target state before retrying.') from None
    if not isinstance(result,dict): raise ValueError('Remote bridge returned a non-object response')
    if result.get('error'): raise RuntimeError(result['error'])
    return result

def call(host, payload, timeout=60, key_file=None):
    from . import host_lifecycle
    if not host_lifecycle.active(host):raise host_lifecycle.Inactive('Server management is disabled or deleted')
    kind='telemetry' if payload.get('action') in ('snapshot','events','ack') else 'control'
    with host_lifecycle.activity([host.id],kind):
        return _call(host,payload,timeout,key_file)

def _call(host, payload, timeout=60, key_file=None):
    deadline=time.monotonic()+timeout
    from . import connections
    route=connections.for_host(host)
    tunnel=None
    client=paramiko.SSHClient()
    client.set_missing_host_key_policy(Pinned(host.fingerprint))
    try:
        if route.transport=='gcp_iap': tunnel=connections.IAPSocket(route,deadline)
        client.connect(host.address,port=host.port,sock=tunnel,username='drpatch',key_filename=str(key_file or key_path(host.id)),
                       look_for_keys=False,allow_agent=False,timeout=min(15,timeout),auth_timeout=min(15,timeout),banner_timeout=min(15,timeout),
                       disabled_algorithms={'keys':['ssh-rsa'],'pubkeys':['ssh-rsa'],
                                            'kex':['diffie-hellman-group1-sha1','diffie-hellman-group14-sha1','diffie-hellman-group-exchange-sha1']})
        client.get_transport().set_keepalive(20)
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError('SSH connection exceeded its total deadline')
        stdin,stdout,stderr=client.exec_command('mrpatchy',timeout=remaining)
        stdin.write(json.dumps(payload));stdin.flush();stdin.channel.shutdown_write()
        try: return read_channel(stdout.channel,deadline)
        except RuntimeError as error:
            action=payload.get('action','request')
            raise type(error)('SSH '+str(action)+' failed: '+str(error)) from error
    except paramiko.AuthenticationException as error:
        raise RuntimeError('SSH authentication rejected for drpatch. Re-run this server’s installer from a trusted console and verify its local account/key. On GCP, check OS Login username/UID conflicts and guest-agent key management; IAP does not replace SSH authentication.') from error
    except (socket.timeout, paramiko.ssh_exception.NoValidConnectionsError, socket.gaierror) as error:
        hint=('Check the runtime gcloud identity, IAP tunnel permissions, VM state and IAP firewall rule.'
              if route.transport=='gcp_iap' else 'Check the saved address/port, VM state, routing and SSH firewall. GCP ephemeral external IPs can change after stop/start.')
        raise RuntimeError('SSH connection unavailable. '+hint+' Verify target operation state before retrying a patch.') from error
    except paramiko.SSHException as error:
        if route.transport=='gcp_iap' and 'fingerprint mismatch' not in str(error):
            raise RuntimeError('SSH over Google IAP failed. Check runtime gcloud authentication, IAP permissions, VM state, firewall and sshd. Verify target operation state before retrying.') from error
        raise
    finally:
        client.close()
        if tunnel is not None: tunnel.close()

def expected_files(host):
    from target.bridge import UNIT
    files={'/usr/local/lib/mrpatchy/'+name:hashlib.sha256((TARGET/name).read_bytes()).hexdigest() for name in ('agent.py','bridge.py','release.py','rpm_support.py')}
    auth=f'restrict,command="/usr/bin/sudo -n /usr/bin/python3 -I /usr/local/lib/mrpatchy/bridge.py" {public_key(host.id)} mrpatchy\n'
    sudo='drpatch ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/lib/mrpatchy/bridge.py\n'
    files.update({'/etc/systemd/system/mrpatchy-agent.service':hashlib.sha256(UNIT.encode()).hexdigest(),
                  '/opt/drpatch/.ssh/authorized_keys':hashlib.sha256(auth.encode()).hexdigest(),
                  '/etc/sudoers.d/mrpatchy':hashlib.sha256(sudo.encode()).hexdigest()})
    optional='/etc/systemd/system/mrpatchy-agent.service.d/observability.conf'
    if optional in host.baseline:files[optional]=host.baseline[optional]
    return files

def deploy(host):
    from target.bridge import UNIT
    code=(TARGET/'agent.py').read_bytes()
    bridge=(TARGET/'bridge.py').read_bytes()
    release=(TARGET/'release.py').read_bytes()
    rpm_code=(TARGET/'rpm_support.py').read_bytes()
    expected={'rpm_sha256':hashlib.sha256(rpm_code).hexdigest(),'release_sha256':hashlib.sha256(release).hexdigest(),'deployed':hashlib.sha256(code).hexdigest(),'bridge_sha256':hashlib.sha256(bridge).hexdigest(),'unit_sha256':hashlib.sha256(UNIT.encode()).hexdigest()}
    payload={'action':'deploy','rpm_support':base64.b64encode(rpm_code).decode(),'rpm_sha256':expected['rpm_sha256'],'agent':base64.b64encode(code).decode(),'sha256':expected['deployed'],
                      'bridge':base64.b64encode(bridge).decode(),'bridge_sha256':expected['bridge_sha256'],
                      'unit':UNIT,'unit_sha256':expected['unit_sha256'],'release':base64.b64encode(release).decode(),'release_sha256':expected['release_sha256']}
    result=call(host,payload)
    if result.get('bridge_sha256')==expected['bridge_sha256'] and ('release_sha256' not in result or 'rpm_sha256' not in result):
        # Older bridges accept their own replacement before understanding runner deployment.
        result=call(host,payload)
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
for command in python3 sshd ssh-keygen sudo visudo useradd sha256sum openssl; do
  command -v "$command" >/dev/null || {{ echo "Missing prerequisite: $command. Install python3 openssh-server sudo first."; exit 1; }}
done
if [ ! -f /var/lib/dpkg/status ]; then
  /usr/bin/python3 -c 'import dnf,rpm' || {{ echo 'RPM targets require Python 3 with python3-dnf and python3-rpm installed first (DNF4 bindings, including on DNF5 systems).'; exit 1; }}
fi
# Offline enrollment: no downloads, package metadata queries, or callbacks.
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
if command -v selinuxenabled >/dev/null && selinuxenabled; then
  command -v semanage >/dev/null || {{ echo 'Install policycoreutils-python-utils before enrollment on SELinux systems.'; exit 1; }}
  semanage fcontext -a -t user_home_dir_t '/opt/drpatch' 2>/dev/null || semanage fcontext -m -t user_home_dir_t '/opt/drpatch'
  semanage fcontext -a -t ssh_home_t '/opt/drpatch/[.]ssh(/.*)?' 2>/dev/null || semanage fcontext -m -t ssh_home_t '/opt/drpatch/[.]ssh(/.*)?'
  restorecon -RF /opt/drpatch /usr/local/lib/mrpatchy /etc/sudoers.d/mrpatchy
fi
sshd -t
{HOST_FINGERPRINT_SCRIPT}
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
